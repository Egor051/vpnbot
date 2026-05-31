"""State-transition tests for the WARP health monitor."""
from __future__ import annotations

from collections.abc import Iterator

import pytest

from warp.health import HealthSnapshot, WarpHealthMonitor


class _Recorder:
    def __init__(self, ping_results: list[bool]) -> None:
        self._results: Iterator[bool] = iter(ping_results)
        self.activations = 0
        self.deactivations = 0
        self.snapshots: list[HealthSnapshot] = []

    async def ping(self) -> bool:
        return next(self._results)

    async def activate(self) -> None:
        self.activations += 1

    async def deactivate(self) -> None:
        self.deactivations += 1

    async def on_update(self, snapshot: HealthSnapshot) -> None:
        self.snapshots.append(snapshot)


def _monitor(rec: _Recorder, *, initial_routes_active: bool = True) -> WarpHealthMonitor:
    return WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        fail_threshold=2,
        recover_threshold=3,
        initial_routes_active=initial_routes_active,
    )


async def test_two_failures_remove_routes_once() -> None:
    rec = _Recorder([False, False, False])
    monitor = _monitor(rec)

    s1 = await monitor.check_once()
    assert s1.fail_streak == 1 and monitor.routes_active is True
    assert rec.deactivations == 0

    s2 = await monitor.check_once()
    assert s2.fail_streak == 2 and monitor.routes_active is False
    assert rec.deactivations == 1

    # A third failure does not remove routes again (already down).
    s3 = await monitor.check_once()
    assert s3.fail_streak == 3 and rec.deactivations == 1


async def test_three_successes_restore_routes_once() -> None:
    # Start with routes already removed (tunnel was down).
    rec = _Recorder([True, True, True, True])
    monitor = _monitor(rec, initial_routes_active=False)

    s1 = await monitor.check_once()
    assert s1.success_streak == 1 and monitor.routes_active is False
    assert rec.activations == 0

    s2 = await monitor.check_once()
    assert s2.success_streak == 2 and monitor.routes_active is False

    s3 = await monitor.check_once()
    assert s3.success_streak == 3 and monitor.routes_active is True
    assert rec.activations == 1

    # A fourth success does not re-add routes.
    await monitor.check_once()
    assert rec.activations == 1


async def test_failure_resets_success_streak() -> None:
    rec = _Recorder([True, True, False, True])
    monitor = _monitor(rec, initial_routes_active=True)

    await monitor.check_once()
    await monitor.check_once()
    assert rec.snapshots[-1].success_streak == 2

    snap_fail = await monitor.check_once()
    assert snap_fail.success_streak == 0 and snap_fail.fail_streak == 1

    snap_ok = await monitor.check_once()
    assert snap_ok.success_streak == 1 and snap_ok.fail_streak == 0


async def test_full_outage_and_recovery_cycle() -> None:
    # 2 fails -> fallback, then 3 successes -> restored.
    rec = _Recorder([False, False, True, True, True])
    monitor = _monitor(rec, initial_routes_active=True)
    for _ in range(5):
        await monitor.check_once()
    assert rec.deactivations == 1
    assert rec.activations == 1
    assert monitor.routes_active is True
    # on_update is called once per probe.
    assert len(rec.snapshots) == 5


async def test_snapshot_reports_tunnel_state() -> None:
    rec = _Recorder([True, False])
    monitor = _monitor(rec)
    up = await monitor.check_once()
    assert up.tunnel_up is True
    down = await monitor.check_once()
    assert down.tunnel_up is False


def test_class_thresholds_match_spec() -> None:
    assert WarpHealthMonitor.INTERVAL == 10
    assert WarpHealthMonitor.FAIL_THRESHOLD == 2
    assert WarpHealthMonitor.RECOVER_THRESHOLD == 3
