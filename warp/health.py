"""Asyncio background health monitor for the WARP tunnel.

Every ``INTERVAL`` seconds the monitor pings the tunnel target through the WARP
interface. After ``FAIL_THRESHOLD`` consecutive failures it pulls the routes
(traffic falls back to the direct path); after ``RECOVER_THRESHOLD`` consecutive
successes it restores them. The route-flip logic is self-contained and free of
I/O details so it can be unit-tested with injected callables.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass

from warp.constants import CHECK_INTERVAL, FAIL_THRESHOLD, PING_INTERFACE, PING_TARGET, RECOVER_THRESHOLD

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    """Outcome of a single health check, handed to the persistence callback."""

    tunnel_up: bool
    routes_active: bool
    fail_streak: int
    success_streak: int


async def ping_interface(
    target: str = PING_TARGET,
    interface: str = PING_INTERFACE,
    *,
    timeout: int = 3,
) -> bool:
    """Return True when a single ICMP echo through ``interface`` succeeds."""
    try:
        process = await asyncio.create_subprocess_exec(
            "ping",
            "-I",
            interface,
            "-c",
            "1",
            "-W",
            str(timeout),
            "-q",
            target,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError):
        logger.warning("WARP ping could not be launched (is iputils-ping installed?)", exc_info=True)
        return False
    try:
        returncode = await asyncio.wait_for(process.wait(), timeout=timeout + 2)
    except asyncio.TimeoutError:
        process.kill()
        with suppress(ProcessLookupError):
            await process.wait()
        return False
    return returncode == 0


class WarpHealthMonitor:
    INTERVAL = CHECK_INTERVAL
    FAIL_THRESHOLD = FAIL_THRESHOLD
    RECOVER_THRESHOLD = RECOVER_THRESHOLD

    def __init__(
        self,
        *,
        ping: Callable[[], Awaitable[bool]],
        activate_routes: Callable[[], Awaitable[None]],
        deactivate_routes: Callable[[], Awaitable[None]],
        on_update: Callable[[HealthSnapshot], Awaitable[None]],
        on_tunnel_down: Callable[[], Awaitable[None]] | None = None,
        on_tunnel_recovered: Callable[[], Awaitable[None]] | None = None,
        interval: int | None = None,
        fail_threshold: int | None = None,
        recover_threshold: int | None = None,
        initial_routes_active: bool = True,
    ) -> None:
        self._ping = ping
        self._activate_routes = activate_routes
        self._deactivate_routes = deactivate_routes
        self._on_update = on_update
        self._on_tunnel_down = on_tunnel_down
        self._on_tunnel_recovered = on_tunnel_recovered
        self._interval = self.INTERVAL if interval is None else interval
        self._fail_threshold = self.FAIL_THRESHOLD if fail_threshold is None else fail_threshold
        self._recover_threshold = self.RECOVER_THRESHOLD if recover_threshold is None else recover_threshold
        self._fail_streak = 0
        self._success_streak = 0
        self._routes_active = initial_routes_active
        self._running = False
        self._task: asyncio.Task[None] | None = None

    @property
    def routes_active(self) -> bool:
        return self._routes_active

    async def check_once(self) -> HealthSnapshot:
        """Run one probe, flip routes if a threshold is crossed, persist the result."""
        ok = await self._ping()
        if ok:
            self._success_streak += 1
            self._fail_streak = 0
            if not self._routes_active and self._success_streak >= self._recover_threshold:
                await self._deactivate_or_activate(activate=True)
        else:
            self._fail_streak += 1
            self._success_streak = 0
            if self._routes_active and self._fail_streak >= self._fail_threshold:
                await self._deactivate_or_activate(activate=False)
        snapshot = HealthSnapshot(
            tunnel_up=ok,
            routes_active=self._routes_active,
            fail_streak=self._fail_streak,
            success_streak=self._success_streak,
        )
        await self._on_update(snapshot)
        return snapshot

    async def _deactivate_or_activate(self, *, activate: bool) -> None:
        if activate:
            await self._activate_routes()
            self._routes_active = True
            logger.info(
                "WARP tunnel recovered after %d consecutive successes; routes restored",
                self._success_streak,
            )
            if self._on_tunnel_recovered is not None:
                with suppress(Exception):
                    await self._on_tunnel_recovered()
        else:
            await self._deactivate_routes()
            self._routes_active = False
            logger.warning(
                "WARP tunnel unreachable after %d consecutive failures; routes removed "
                "(traffic falls back to the direct path)",
                self._fail_streak,
            )
            if self._on_tunnel_down is not None:
                with suppress(Exception):
                    await self._on_tunnel_down()

    async def run(self) -> None:
        self._running = True
        while self._running:
            try:
                await self.check_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("WARP health check iteration failed", exc_info=True)
            try:
                await asyncio.sleep(self._interval)
            except asyncio.CancelledError:
                raise

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self.run(), name="warp-health-monitor")

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None
