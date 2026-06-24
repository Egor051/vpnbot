"""Asyncio background health monitor for the WARP tunnel.

The monitor pings the tunnel target through the WARP interface and tracks a
tunnel-health latch on a *time* basis: after ``FAIL_WINDOW`` seconds of continuous
no-response the tunnel is declared *down*, after ``RECOVER_WINDOW`` seconds of
continuous success it is declared *back up*. A single opposite probe resets the
running window, so the tunnel only flips on a sustained change — never on one
dropped (or one recovered) ICMP probe. Each latch crossing fires the corresponding
notification callback exactly once (anti-spam: only on an actual state change).

The probe cadence is adaptive: ``INTERVAL`` seconds while the last probe answered,
dropping to the faster ``FAST_INTERVAL`` the moment a probe gets no response so an
outage (and the start of recovery) is detected quickly.

In **observer mode** (the default for production) that is *all* the monitor does:
the ``out-warp`` interface and its policy routes are owned by systemd
(``awg-quick@out-warp`` + ``warp-routes.service``), so the route callbacks are
never invoked. In the legacy non-observer mode the same latch crossings also flip
the routes (the monitor pulls them on *down* and restores them on *up*). The
logic is self-contained and free of I/O details so it can be unit-tested with
injected callables.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass

from warp.constants import (
    CHECK_INTERVAL,
    FAIL_WINDOW_SECONDS,
    FAST_CHECK_INTERVAL,
    PING_INTERFACE,
    PING_TARGET,
    RECOVER_WINDOW_SECONDS,
)

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
    FAST_INTERVAL = FAST_CHECK_INTERVAL
    FAIL_WINDOW = FAIL_WINDOW_SECONDS
    RECOVER_WINDOW = RECOVER_WINDOW_SECONDS

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
        fast_interval: int | None = None,
        fail_window: float | None = None,
        recover_window: float | None = None,
        initial_routes_active: bool = True,
        observer_mode: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ping = ping
        self._activate_routes = activate_routes
        self._deactivate_routes = deactivate_routes
        self._on_update = on_update
        self._on_tunnel_down = on_tunnel_down
        self._on_tunnel_recovered = on_tunnel_recovered
        self._interval = self.INTERVAL if interval is None else interval
        self._fast_interval = self.FAST_INTERVAL if fast_interval is None else fast_interval
        self._fail_window = self.FAIL_WINDOW if fail_window is None else fail_window
        self._recover_window = self.RECOVER_WINDOW if recover_window is None else recover_window
        self._clock = clock
        self._observer_mode = observer_mode
        # Counters kept for the persisted state / admin display only; the latch decision
        # below is purely time-based.
        self._fail_streak = 0
        self._success_streak = 0
        # Monotonic timestamp marking the start of the current uninterrupted failure /
        # success run (``None`` while the opposite outcome was seen last). A single
        # opposite probe clears the relevant marker, so the windows require *continuous*
        # failure / success.
        self._fail_since: float | None = None
        self._success_since: float | None = None
        # Outcome of the last probe; drives the adaptive cadence (``None`` before the
        # first probe).
        self._last_ok: bool | None = None
        # ``_healthy`` is the tunnel-up latch that drives notifications (and, in the
        # legacy mode, the route flips). ``_routes_active`` is the value reported in
        # snapshots: in observer mode the routes are owned by systemd and stay up, so
        # it never changes; in legacy mode it tracks the latch.
        self._healthy = initial_routes_active
        self._routes_active = initial_routes_active
        self._running = False
        self._task: asyncio.Task[None] | None = None

    @property
    def routes_active(self) -> bool:
        return self._routes_active

    def _next_interval(self) -> float:
        """Cadence for the next probe: fast while the last probe failed, else normal."""
        return self._fast_interval if self._last_ok is False else self._interval

    async def check_once(self) -> HealthSnapshot:
        """Run one probe; on a latch crossing notify (and, if not observer, flip routes)."""
        now = self._clock()
        ok = await self._ping()
        self._last_ok = ok
        if ok:
            self._success_streak += 1
            self._fail_streak = 0
            self._fail_since = None
            if self._success_since is None:
                self._success_since = now
            if not self._healthy and (now - self._success_since) >= self._recover_window:
                await self._mark_recovered(now - self._success_since)
        else:
            self._fail_streak += 1
            self._success_streak = 0
            self._success_since = None
            if self._fail_since is None:
                self._fail_since = now
            if self._healthy and (now - self._fail_since) >= self._fail_window:
                await self._mark_down(now - self._fail_since)
        snapshot = HealthSnapshot(
            tunnel_up=ok,
            routes_active=self._routes_active,
            fail_streak=self._fail_streak,
            success_streak=self._success_streak,
        )
        await self._on_update(snapshot)
        return snapshot

    async def _mark_recovered(self, elapsed: float) -> None:
        self._healthy = True
        if not self._observer_mode:
            await self._activate_routes()
            self._routes_active = True
        logger.info(
            "WARP tunnel recovered after %.0fs of continuous success%s",
            elapsed,
            "" if self._observer_mode else "; routes restored",
        )
        if self._on_tunnel_recovered is not None:
            with suppress(Exception):
                await self._on_tunnel_recovered()

    async def _mark_down(self, elapsed: float) -> None:
        self._healthy = False
        if not self._observer_mode:
            await self._deactivate_routes()
            self._routes_active = False
        logger.warning(
            "WARP tunnel unreachable after %.0fs of no response%s",
            elapsed,
            ""
            if self._observer_mode
            else "; routes removed (traffic falls back to the direct path)",
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
                await asyncio.sleep(self._next_interval())
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
