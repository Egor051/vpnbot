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
the routes (the monitor pulls them on *down* and restores them on *up*) — unless
the operator's **kill-switch** is on, in which case a *down* keeps the routes in
place so masked traffic blackholes on the dead interface instead of leaking out
the real server IP.

Independently of the route decision, a **degraded** detector watches a sliding
window of recent probes: a tunnel that keeps dropping (but not *continuously*
failing) never trips the down latch, so this raises an observability-only alert
when the in-window loss ratio is high. It never touches routing, and a floor on
the sample count means a single isolated failure can never raise it.

The logic is self-contained and free of I/O details so it can be unit-tested with
injected callables.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass

from warp.constants import (
    CHECK_INTERVAL,
    DEGRADED_CLEAR_THRESHOLD,
    DEGRADED_LOSS_THRESHOLD,
    DEGRADED_MIN_SAMPLES,
    DEGRADED_WINDOW_SECONDS,
    FAIL_WINDOW_SECONDS,
    FAST_CHECK_INTERVAL,
    PING_INTERFACE,
    PING_TARGET,
    RECOVER_WINDOW_SECONDS,
)

logger = logging.getLogger(__name__)


def _no_kill_switch() -> bool:
    """Default kill-switch provider: OFF (legacy fallback-to-direct behaviour)."""
    return False


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    """Outcome of a single health check, handed to the persistence callback."""

    tunnel_up: bool
    routes_active: bool
    fail_streak: int
    success_streak: int
    degraded: bool = False


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
        on_degraded: Callable[[float], Awaitable[None]] | None = None,
        on_degraded_cleared: Callable[[], Awaitable[None]] | None = None,
        interval: int | None = None,
        fast_interval: int | None = None,
        fail_window: float | None = None,
        recover_window: float | None = None,
        initial_routes_active: bool = True,
        observer_mode: bool = False,
        kill_switch: Callable[[], bool] = _no_kill_switch,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ping = ping
        self._activate_routes = activate_routes
        self._deactivate_routes = deactivate_routes
        self._on_update = on_update
        self._on_tunnel_down = on_tunnel_down
        self._on_tunnel_recovered = on_tunnel_recovered
        self._on_degraded = on_degraded
        self._on_degraded_cleared = on_degraded_cleared
        self._interval = self.INTERVAL if interval is None else interval
        self._fast_interval = self.FAST_INTERVAL if fast_interval is None else fast_interval
        self._fail_window = self.FAIL_WINDOW if fail_window is None else fail_window
        self._recover_window = self.RECOVER_WINDOW if recover_window is None else recover_window
        self._clock = clock
        self._observer_mode = observer_mode
        # Kill-switch provider, read live on every down-latch crossing so an admin
        # toggle takes effect without restarting the monitor. When it returns True
        # (and we are not in observer mode), a tunnel-down keeps the routes in place
        # instead of tearing them down — traffic blackholes on the dead interface
        # rather than falling through to the real-IP direct path.
        self._kill_switch = kill_switch
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
        # Sliding window of recent (timestamp, ok) probe outcomes, used ONLY for the
        # observability-level degraded detector (never for the route decision).
        self._samples: deque[tuple[float, bool]] = deque()
        self._degraded = False
        self._running = False
        self._task: asyncio.Task[None] | None = None

    @property
    def routes_active(self) -> bool:
        return self._routes_active

    @property
    def degraded(self) -> bool:
        return self._degraded

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
        await self._evaluate_degraded(now, ok)
        snapshot = HealthSnapshot(
            tunnel_up=ok,
            routes_active=self._routes_active,
            fail_streak=self._fail_streak,
            success_streak=self._success_streak,
            degraded=self._degraded,
        )
        await self._on_update(snapshot)
        return snapshot

    async def _evaluate_degraded(self, now: float, ok: bool) -> None:
        """Update the sliding-window degraded flag (observability only, never routes).

        Records the probe outcome, prunes samples older than the window, and once
        there are enough in-window samples raises/clears a degraded flag on the
        loss ratio (with hysteresis). The MIN_SAMPLES floor is what guarantees a
        single isolated failure can never raise the alert. The raise is gated on
        the tunnel still being latched up so a fully-down tunnel does not stack a
        degraded alert on top of its down alert.
        """
        self._samples.append((now, ok))
        window_start = now - DEGRADED_WINDOW_SECONDS
        while self._samples and self._samples[0][0] < window_start:
            self._samples.popleft()
        total = len(self._samples)
        if total < DEGRADED_MIN_SAMPLES:
            return
        failures = sum(1 for _, sample_ok in self._samples if not sample_ok)
        loss = failures / total
        if not self._degraded and self._healthy and loss >= DEGRADED_LOSS_THRESHOLD:
            self._degraded = True
            logger.warning(
                "WARP tunnel degraded: %.0f%% probe loss over last %ds (%d/%d) — "
                "routes untouched, alerting only",
                loss * 100,
                DEGRADED_WINDOW_SECONDS,
                failures,
                total,
            )
            if self._on_degraded is not None:
                with suppress(Exception):
                    await self._on_degraded(loss)
        elif self._degraded and loss < DEGRADED_CLEAR_THRESHOLD:
            self._degraded = False
            logger.info("WARP tunnel degradation cleared: %.0f%% probe loss", loss * 100)
            if self._on_degraded_cleared is not None:
                with suppress(Exception):
                    await self._on_degraded_cleared()

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
        kill_switch_on = False
        if not self._observer_mode:
            kill_switch_on = bool(self._kill_switch())
            if kill_switch_on:
                # Kill-switch: leave the routes pointing at the (now-down) tunnel
                # interface. Packets to masked prefixes blackhole on the dead link
                # instead of falling through to a less-specific direct route that
                # would leak the real server IP. Routes stay "active".
                suffix = "; kill-switch ON: routes kept, masked traffic blackholed (no direct-IP leak)"
            else:
                await self._deactivate_routes()
                self._routes_active = False
                suffix = "; routes removed (traffic falls back to the direct path)"
        else:
            suffix = ""
        logger.warning(
            "WARP tunnel unreachable after %.0fs of no response%s",
            elapsed,
            suffix,
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
