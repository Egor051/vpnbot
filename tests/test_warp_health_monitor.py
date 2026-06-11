"""State-transition tests for the WARP health monitor."""
from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from models.dto import ShellResult
from warp.health import HealthSnapshot, WarpHealthMonitor
from warp.manager import WarpManager, _noop_route
from warp.state import WarpState


class _Recorder:
    def __init__(self, ping_results: list[bool]) -> None:
        self._results: Iterator[bool] = iter(ping_results)
        self.activations = 0
        self.deactivations = 0
        self.tunnel_down_calls = 0
        self.tunnel_recovered_calls = 0
        self.snapshots: list[HealthSnapshot] = []

    async def ping(self) -> bool:
        return next(self._results)

    async def activate(self) -> None:
        self.activations += 1

    async def deactivate(self) -> None:
        self.deactivations += 1

    async def on_update(self, snapshot: HealthSnapshot) -> None:
        self.snapshots.append(snapshot)

    async def on_tunnel_down(self) -> None:
        self.tunnel_down_calls += 1

    async def on_tunnel_recovered(self) -> None:
        self.tunnel_recovered_calls += 1


def _monitor(
    rec: _Recorder,
    *,
    initial_routes_active: bool = True,
    with_notify_callbacks: bool = False,
    observer_mode: bool = False,
) -> WarpHealthMonitor:
    return WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_down=rec.on_tunnel_down if with_notify_callbacks else None,
        on_tunnel_recovered=rec.on_tunnel_recovered if with_notify_callbacks else None,
        fail_threshold=2,
        recover_threshold=3,
        initial_routes_active=initial_routes_active,
        observer_mode=observer_mode,
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
    # The fail threshold is intentionally > 1 so a single dropped probe never flaps.
    assert WarpHealthMonitor.FAIL_THRESHOLD == 4
    assert WarpHealthMonitor.RECOVER_THRESHOLD == 3


# ── on_tunnel_down / on_tunnel_recovered callbacks ────────────────────────────

async def test_on_tunnel_down_called_when_threshold_crossed() -> None:
    rec = _Recorder([False, False, False])
    monitor = _monitor(rec, with_notify_callbacks=True)

    await monitor.check_once()
    assert rec.tunnel_down_calls == 0

    await monitor.check_once()
    assert rec.tunnel_down_calls == 1

    # Third failure: routes already removed, callback not called again.
    await monitor.check_once()
    assert rec.tunnel_down_calls == 1


async def test_on_tunnel_recovered_called_when_threshold_crossed() -> None:
    rec = _Recorder([True, True, True, True])
    monitor = _monitor(rec, initial_routes_active=False, with_notify_callbacks=True)

    await monitor.check_once()
    assert rec.tunnel_recovered_calls == 0
    await monitor.check_once()
    assert rec.tunnel_recovered_calls == 0

    await monitor.check_once()
    assert rec.tunnel_recovered_calls == 1

    # Fourth success: routes already active, callback not called again.
    await monitor.check_once()
    assert rec.tunnel_recovered_calls == 1


async def test_on_tunnel_down_exception_is_suppressed() -> None:
    async def boom() -> None:
        raise RuntimeError("notify failed")

    rec = _Recorder([False, False])
    monitor = WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_down=boom,
        fail_threshold=2,
        recover_threshold=3,
    )
    # Should not raise even though on_tunnel_down raises.
    await monitor.check_once()
    await monitor.check_once()
    assert rec.deactivations == 1


async def test_on_tunnel_recovered_exception_is_suppressed() -> None:
    async def boom() -> None:
        raise RuntimeError("notify failed")

    rec = _Recorder([True, True, True])
    monitor = WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_recovered=boom,
        fail_threshold=2,
        recover_threshold=3,
        initial_routes_active=False,
    )
    for _ in range(3):
        await monitor.check_once()
    assert rec.activations == 1


async def test_no_callbacks_when_none() -> None:
    # Passing None callbacks must not raise.
    rec = _Recorder([False, False, True, True, True])
    monitor = _monitor(rec, initial_routes_active=True, with_notify_callbacks=False)
    for _ in range(5):
        await monitor.check_once()
    assert rec.deactivations == 1 and rec.activations == 1


# ── observer mode: never touch routes, only observe + notify ──────────────────

async def test_observer_mode_down_notifies_without_route_calls() -> None:
    rec = _Recorder([False, False, False])
    monitor = _monitor(rec, observer_mode=True, with_notify_callbacks=True)

    await monitor.check_once()
    assert rec.tunnel_down_calls == 0

    # Threshold crossed: notify, but routes are NEVER touched (systemd owns them).
    await monitor.check_once()
    assert rec.tunnel_down_calls == 1
    assert rec.deactivations == 0 and rec.activations == 0
    # routes_active stays True throughout — the bot does not manage it in observer mode.
    assert monitor.routes_active is True
    assert all(s.routes_active is True for s in rec.snapshots)


async def test_observer_mode_recovery_notifies_without_route_calls() -> None:
    rec = _Recorder([False, False, True, True, True])
    monitor = _monitor(rec, observer_mode=True, with_notify_callbacks=True)
    for _ in range(5):
        await monitor.check_once()

    # 2 fails -> down notify, 3 successes -> recovered notify; no route calls at all.
    assert rec.tunnel_down_calls == 1
    assert rec.tunnel_recovered_calls == 1
    assert rec.deactivations == 0 and rec.activations == 0
    assert monitor.routes_active is True


async def test_observer_mode_notifies_only_on_state_change() -> None:
    # Four straight failures must produce exactly one "down" notification (anti-spam).
    rec = _Recorder([False, False, False, False])
    monitor = _monitor(rec, observer_mode=True, with_notify_callbacks=True)
    for _ in range(4):
        await monitor.check_once()
    assert rec.tunnel_down_calls == 1
    assert rec.deactivations == 0


async def test_fail_threshold_is_honoured_from_constructor() -> None:
    # With a higher threshold a single (or few) dropped probes do not trip a "down".
    rec = _Recorder([False, False, False, False])
    monitor = WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_down=rec.on_tunnel_down,
        fail_threshold=4,
        recover_threshold=3,
        observer_mode=True,
    )
    for _ in range(3):
        await monitor.check_once()
    assert rec.tunnel_down_calls == 0  # 3 < 4
    await monitor.check_once()
    assert rec.tunnel_down_calls == 1  # 4 == threshold


# ── WarpManager notification methods ─────────────────────────────────────────

def _make_manager(
    admin_ids: frozenset[int] = frozenset([111, 222]),
    *,
    observer_mode: bool = True,
) -> WarpManager:
    """Construct a WarpManager bypassing __init__, injecting only what the notify methods need."""
    manager = object.__new__(WarpManager)
    settings = MagicMock()
    settings.admin_ids = admin_ids
    manager._settings = settings
    manager._observer_mode = observer_mode
    manager.bot = None
    return manager


async def test_notify_tunnel_down_sends_to_all_admins() -> None:
    manager = _make_manager(frozenset([111, 222]))
    manager.bot = AsyncMock()

    await manager._notify_tunnel_down()

    assert manager.bot.send_message.call_count == 2
    call_ids = {c.args[0] for c in manager.bot.send_message.call_args_list}
    assert call_ids == {111, 222}


async def test_notify_tunnel_recovered_sends_to_all_admins() -> None:
    manager = _make_manager(frozenset([333]))
    manager.bot = AsyncMock()

    await manager._notify_tunnel_recovered()

    manager.bot.send_message.assert_awaited_once()
    assert manager.bot.send_message.call_args.args[0] == 333


async def test_notify_skipped_when_bot_is_none() -> None:
    manager = _make_manager()
    manager.bot = None
    # Must not raise.
    await manager._notify_tunnel_down()
    await manager._notify_tunnel_recovered()


async def test_notify_tunnel_down_tolerates_send_error() -> None:
    manager = _make_manager(frozenset([1, 2]))
    manager.bot = AsyncMock()
    manager.bot.send_message.side_effect = Exception("telegram error")

    # Should not raise even if send fails.
    await manager._notify_tunnel_down()


async def test_notify_tunnel_recovered_tolerates_send_error() -> None:
    manager = _make_manager(frozenset([1]))
    manager.bot = AsyncMock()
    manager.bot.send_message.side_effect = Exception("telegram error")

    await manager._notify_tunnel_recovered()


async def test_observer_down_notification_makes_no_route_promise() -> None:
    manager = _make_manager(frozenset([1]), observer_mode=True)
    manager.bot = AsyncMock()
    await manager._notify_tunnel_down()
    text = manager.bot.send_message.call_args.args[1]
    assert "Маршруты сняты" not in text
    assert "warp-routes.service" in text


async def test_legacy_down_notification_keeps_route_wording() -> None:
    manager = _make_manager(frozenset([1]), observer_mode=False)
    manager.bot = AsyncMock()
    await manager._notify_tunnel_down()
    text = manager.bot.send_message.call_args.args[1]
    assert "Маршруты сняты" in text


# ── WarpManager start/stop ownership (observer vs legacy) ─────────────────────

def _ok() -> ShellResult:
    return ShellResult(args=(), returncode=0, stdout="", stderr="")


def _lifecycle_manager(*, observer_mode: bool) -> WarpManager:
    """Build a WarpManager bypassing __init__ with mocked interface/routes/repo."""
    manager = object.__new__(WarpManager)
    manager._settings = MagicMock(admin_ids=frozenset())
    manager._observer_mode = observer_mode
    manager._fail_threshold = 4
    manager._recover_threshold = 3
    manager._running = False
    manager._monitor = None
    manager._last_error = None
    manager.bot = None
    manager._interface_name = "out-warp"
    manager._interface = AsyncMock()
    manager._interface.up.return_value = _ok()
    manager._interface.down.return_value = _ok()
    manager._interface.status.return_value = _ok()
    manager._routes = AsyncMock()
    manager._routes.add.return_value = _ok()
    manager._routes.remove.return_value = _ok()
    manager._repo = AsyncMock()
    manager._repo.get.return_value = WarpState(routes_count=1)
    manager._ping = AsyncMock(return_value=True)
    manager._safe_handshake = AsyncMock(return_value=123)
    return manager


async def test_observer_start_does_not_touch_interface_or_routes(monkeypatch) -> None:
    monkeypatch.setattr("warp.manager.WarpInterface.awg_quick_available", lambda: True)
    fake_monitor_cls = MagicMock(return_value=MagicMock())
    monkeypatch.setattr("warp.manager.WarpHealthMonitor", fake_monitor_cls)

    manager = _lifecycle_manager(observer_mode=True)
    await manager._start_locked()

    manager._interface.up.assert_not_called()
    manager._interface.down.assert_not_called()
    manager._routes.add.assert_not_called()
    manager._routes.remove.assert_not_called()
    assert manager._running is True
    # Monitor wired as an observer with no-op route callbacks and the configured threshold.
    kwargs = fake_monitor_cls.call_args.kwargs
    assert kwargs["observer_mode"] is True
    assert kwargs["activate_routes"] is _noop_route
    assert kwargs["deactivate_routes"] is _noop_route
    assert kwargs["fail_threshold"] == 4
    assert kwargs["recover_threshold"] == 3


async def test_legacy_start_brings_up_interface_and_routes(monkeypatch) -> None:
    monkeypatch.setattr("warp.manager.WarpInterface.awg_quick_available", lambda: True)
    fake_monitor_cls = MagicMock(return_value=MagicMock())
    monkeypatch.setattr("warp.manager.WarpHealthMonitor", fake_monitor_cls)

    manager = _lifecycle_manager(observer_mode=False)
    await manager._start_locked()

    manager._interface.up.assert_awaited()
    manager._routes.add.assert_awaited()
    assert manager._running is True
    # Legacy monitor keeps the real route callbacks (no observer flag forced on).
    kwargs = fake_monitor_cls.call_args.kwargs
    assert kwargs.get("observer_mode", False) is False
    # Legacy keeps the real (non no-op) route callbacks.
    assert kwargs["activate_routes"] is not _noop_route
    assert kwargs["activate_routes"] == manager._activate_routes


async def test_observer_stop_leaves_routes_and_interface_in_place() -> None:
    manager = _lifecycle_manager(observer_mode=True)
    manager._running = True
    manager._monitor = AsyncMock()

    await manager._stop_locked()

    manager._routes.remove.assert_not_called()
    manager._interface.down.assert_not_called()
    manager._repo.update_runtime.assert_awaited()  # runtime view still reset
    assert manager._running is False
    assert manager._monitor is None


async def test_legacy_stop_removes_routes_and_brings_interface_down() -> None:
    manager = _lifecycle_manager(observer_mode=False)
    manager._running = True
    manager._monitor = AsyncMock()

    await manager._stop_locked()

    manager._routes.remove.assert_awaited()
    manager._interface.down.assert_awaited()
    assert manager._running is False
