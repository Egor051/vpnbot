import asyncio
from itertools import pairwise

import pytest

from services.auto_refresh import DEFAULT_INTERVAL_SECONDS, LiveRefreshManager


class FakeClock:
    """Monotonic clock that only advances when the injected sleep is awaited."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, dt: float) -> None:
        self.now += dt


def test_loop_refreshes_then_expires() -> None:
    clock = FakeClock()

    async def sleep(delay: float) -> None:
        clock.advance(delay)

    calls: list[float] = []
    expired: list[float] = []

    async def refresh() -> bool:
        calls.append(clock.now)
        return True

    async def on_expire() -> None:
        expired.append(clock.now)

    mgr = LiveRefreshManager(interval=1.0, duration=3.0, clock=clock, sleep=sleep)
    asyncio.run(mgr._run("k", refresh, on_expire))

    # Renders happen at t=1 and t=2; at t=3 the lifetime cap is hit and the
    # panel falls back to the admin panel exactly once.
    assert calls == [1.0, 2.0]
    assert expired == [3.0]


def test_loop_stops_when_target_gone_without_expiring() -> None:
    clock = FakeClock()

    async def sleep(delay: float) -> None:
        clock.advance(delay)

    calls: list[float] = []
    expired: list[float] = []

    async def refresh() -> bool:
        calls.append(clock.now)
        return len(calls) < 2  # the card disappears on the second tick

    async def on_expire() -> None:
        expired.append(clock.now)

    mgr = LiveRefreshManager(interval=1.0, duration=100.0, clock=clock, sleep=sleep)
    asyncio.run(mgr._run("k", refresh, on_expire))

    assert calls == [1.0, 2.0]
    assert expired == []  # no fallback when the user already closed the card


def test_failed_tick_does_not_abort_the_loop() -> None:
    clock = FakeClock()

    async def sleep(delay: float) -> None:
        clock.advance(delay)

    calls: list[float] = []

    async def refresh() -> bool:
        calls.append(clock.now)
        if len(calls) == 1:
            raise RuntimeError("transient failure")
        return True

    async def on_expire() -> None:
        pass

    mgr = LiveRefreshManager(interval=1.0, duration=3.0, clock=clock, sleep=sleep)
    asyncio.run(mgr._run("k", refresh, on_expire))

    # Both ticks ran even though the first one raised.
    assert calls == [1.0, 2.0]


def test_cancel_stops_running_loop() -> None:
    async def scenario() -> tuple[bool, bool]:
        started = asyncio.Event()
        release = asyncio.Event()
        expired = False

        async def sleep(_delay: float) -> None:
            return None

        async def refresh() -> bool:
            started.set()
            await release.wait()  # park here so the loop is mid-tick
            return True

        async def on_expire() -> None:
            nonlocal expired
            expired = True

        mgr = LiveRefreshManager(interval=0.0, duration=10_000.0, sleep=sleep)
        mgr.start("k", refresh=refresh, on_expire=on_expire)
        await asyncio.wait_for(started.wait(), timeout=1.0)
        was_active = mgr.active("k")
        mgr.cancel("k")
        # Let the cancellation propagate and the done-callback fire.
        for _ in range(5):
            await asyncio.sleep(0)
        return was_active, mgr.active("k"), expired  # type: ignore[return-value]

    was_active, still_active, expired = asyncio.run(scenario())
    assert was_active is True
    assert still_active is False
    assert expired is False


def test_start_replaces_previous_loop_for_same_key() -> None:
    async def scenario() -> tuple[int, int]:
        first_started = asyncio.Event()
        first_cancelled = 0
        second_started = asyncio.Event()
        release = asyncio.Event()

        async def sleep(_delay: float) -> None:
            return None

        def make_refresh(started: asyncio.Event) -> object:
            async def refresh() -> bool:
                started.set()
                await release.wait()
                return True

            return refresh

        async def on_expire() -> None:
            pass

        async def first_refresh() -> bool:
            nonlocal first_cancelled
            first_started.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                first_cancelled += 1
                raise
            return True

        mgr = LiveRefreshManager(interval=0.0, duration=10_000.0, sleep=sleep)
        mgr.start("k", refresh=first_refresh, on_expire=on_expire)
        await asyncio.wait_for(first_started.wait(), timeout=1.0)

        # Restarting for the same key cancels the first loop.
        mgr.start("k", refresh=make_refresh(second_started), on_expire=on_expire)  # type: ignore[arg-type]
        await asyncio.wait_for(second_started.wait(), timeout=1.0)
        for _ in range(5):
            await asyncio.sleep(0)
        active = mgr.active("k")
        mgr.cancel("k")
        for _ in range(5):
            await asyncio.sleep(0)
        return first_cancelled, int(active)

    first_cancelled, active = asyncio.run(scenario())
    assert first_cancelled == 1
    assert active == 1  # the replacement loop is the live one


@pytest.mark.parametrize("missing", [None])
def test_active_false_for_unknown_key(missing: None) -> None:
    mgr = LiveRefreshManager()
    assert mgr.active("never-started") is False


def test_default_interval_is_five_seconds() -> None:
    # A 1s cadence trips Telegram's per-message edit flood control; the panel is
    # served from a cached snapshot, so a slower 5s edit cadence stays "live" for
    # a human while staying well clear of the flood zone.
    assert DEFAULT_INTERVAL_SECONDS == pytest.approx(5.0)
    assert LiveRefreshManager()._interval == pytest.approx(5.0)


def test_run_no_catch_up_burst_after_long_refresh() -> None:
    """A tick whose ``refresh()`` stalls past the interval must not be followed
    by a burst of immediate catch-up refreshes.

    The schedule is recomputed relative to "now" after each refresh, so even a
    long 429 back-off absorbed inside a single tick cannot leave the loop firing
    several edits back-to-back the moment it recovers (which would re-trip the
    very flood control it just waited out).
    """
    clock = FakeClock()
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)
        clock.advance(delay)

    refresh_times: list[float] = []
    tick = 0

    async def refresh() -> bool:
        nonlocal tick
        refresh_times.append(clock.now)
        tick += 1
        if tick == 1:
            # Simulate a long back-off absorbed inside one tick (e.g. Telegram
            # asked us to wait out a flood penalty): the clock jumps far past
            # several scheduled ticks while this single refresh is in flight.
            clock.advance(30.0)
        return True

    async def on_expire() -> None:
        pass

    interval = 5.0
    mgr = LiveRefreshManager(interval=interval, duration=60.0, clock=clock, sleep=sleep)
    asyncio.run(mgr._run("k", refresh, on_expire))

    # Every consecutive pair of refreshes is at least one interval apart: the
    # loop always slept a full interval before the next edit, so there is no
    # zero-gap catch-up burst after the stalled tick.
    deltas = [later - earlier for earlier, later in pairwise(refresh_times)]
    assert deltas, "expected several refreshes"
    assert all(delta >= interval for delta in deltas), deltas
    # And every tick was actually preceded by a real (positive) sleep.
    assert all(s > 0 for s in sleeps), sleeps
