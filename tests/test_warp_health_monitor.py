"""State-transition tests for the WARP health monitor."""
from __future__ import annotations

import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from models.dto import ShellResult
from warp.health import HealthSnapshot, WarpHealthMonitor
from warp.manager import WarpManager, _noop_route
from warp.state import WarpState


class _Clock:
    """Controllable monotonic clock for deterministic time-based latch tests."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, dt: float) -> None:
        self.now += dt


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
    fail_window: float = 2,
    recover_window: float = 3,
    clock: _Clock | None = None,
) -> WarpHealthMonitor:
    return WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_down=rec.on_tunnel_down if with_notify_callbacks else None,
        on_tunnel_recovered=rec.on_tunnel_recovered if with_notify_callbacks else None,
        fail_window=fail_window,
        recover_window=recover_window,
        initial_routes_active=initial_routes_active,
        observer_mode=observer_mode,
        clock=clock if clock is not None else _Clock(),
    )


async def _check_at(monitor: WarpHealthMonitor, clk: _Clock, t: float) -> HealthSnapshot:
    """Run one probe with the clock pinned to ``t``."""
    clk.now = t
    return await monitor.check_once()


async def test_no_response_for_fail_window_removes_routes_once() -> None:
    clk = _Clock()
    rec = _Recorder([False, False, False])
    monitor = _monitor(rec, fail_window=2, clock=clk)

    s1 = await _check_at(monitor, clk, 0)
    assert s1.fail_streak == 1 and monitor.routes_active is True
    assert rec.deactivations == 0  # window not elapsed yet

    s2 = await _check_at(monitor, clk, 2)
    assert s2.fail_streak == 2 and monitor.routes_active is False
    assert rec.deactivations == 1  # 2s of continuous no response

    # A third failure does not remove routes again (already down).
    s3 = await _check_at(monitor, clk, 4)
    assert s3.fail_streak == 3 and rec.deactivations == 1


async def test_continuous_success_for_recover_window_restores_routes_once() -> None:
    # Start with routes already removed (tunnel was down).
    clk = _Clock()
    rec = _Recorder([True, True, True])
    monitor = _monitor(rec, initial_routes_active=False, recover_window=3, clock=clk)

    s1 = await _check_at(monitor, clk, 0)
    assert s1.success_streak == 1 and monitor.routes_active is False
    assert rec.activations == 0

    s2 = await _check_at(monitor, clk, 1)
    assert s2.success_streak == 2 and monitor.routes_active is False

    s3 = await _check_at(monitor, clk, 3)
    assert s3.success_streak == 3 and monitor.routes_active is True
    assert rec.activations == 1  # 3s of continuous success


async def test_single_success_resets_the_fail_window() -> None:
    # A lone success in the middle of an outage restarts the no-response window so the
    # tunnel is never declared down without a *continuous* fail run.
    clk = _Clock()
    rec = _Recorder([False, True, False, False])
    monitor = _monitor(rec, fail_window=2, with_notify_callbacks=True, clock=clk)

    await _check_at(monitor, clk, 0)  # fail, _fail_since=0
    await _check_at(monitor, clk, 1)  # success resets the window
    assert rec.tunnel_down_calls == 0

    await _check_at(monitor, clk, 2)  # fail again, _fail_since=2
    assert rec.tunnel_down_calls == 0  # only 0s into the fresh window
    await _check_at(monitor, clk, 4)  # 2s of continuous fail -> down
    assert rec.tunnel_down_calls == 1


async def test_failure_resets_success_streak() -> None:
    clk = _Clock()
    rec = _Recorder([True, True, False, True])
    monitor = _monitor(rec, initial_routes_active=True, clock=clk)

    await _check_at(monitor, clk, 0)
    await _check_at(monitor, clk, 1)
    assert rec.snapshots[-1].success_streak == 2

    snap_fail = await _check_at(monitor, clk, 2)
    assert snap_fail.success_streak == 0 and snap_fail.fail_streak == 1

    snap_ok = await _check_at(monitor, clk, 3)
    assert snap_ok.success_streak == 1 and snap_ok.fail_streak == 0


async def test_full_outage_and_recovery_cycle() -> None:
    # No response across the fail window -> fallback, then continuous success across the
    # recover window -> restored.
    clk = _Clock()
    rec = _Recorder([False, False, True, True, True])
    monitor = _monitor(rec, initial_routes_active=True, fail_window=2, recover_window=3, clock=clk)
    for t in (0, 2, 4, 6, 8):
        await _check_at(monitor, clk, t)
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


def test_class_constants_match_spec() -> None:
    assert WarpHealthMonitor.INTERVAL == 10
    assert WarpHealthMonitor.FAST_INTERVAL == 3
    # Time-based switch windows: 60s of continuous no-response / success to flip.
    assert WarpHealthMonitor.FAIL_WINDOW == 60
    assert WarpHealthMonitor.RECOVER_WINDOW == 60


# ── adaptive cadence ─────────────────────────────────────────────────────────


async def test_next_interval_adapts_to_last_probe() -> None:
    rec = _Recorder([True, False, True])
    monitor = _monitor(rec)
    # Defaults: 10s normal, 3s while failing.
    assert monitor._interval == 10
    assert monitor._fast_interval == 3
    # Before any probe: normal cadence.
    assert monitor._next_interval() == 10

    await monitor.check_once()  # success
    assert monitor._next_interval() == 10
    await monitor.check_once()  # no response -> speed up
    assert monitor._next_interval() == 3
    await monitor.check_once()  # response again -> relax
    assert monitor._next_interval() == 10


# ── on_tunnel_down / on_tunnel_recovered callbacks ────────────────────────────

async def test_on_tunnel_down_called_when_window_crossed() -> None:
    clk = _Clock()
    rec = _Recorder([False, False, False])
    monitor = _monitor(rec, fail_window=2, with_notify_callbacks=True, clock=clk)

    await _check_at(monitor, clk, 0)
    assert rec.tunnel_down_calls == 0

    await _check_at(monitor, clk, 2)
    assert rec.tunnel_down_calls == 1

    # Third failure: routes already removed, callback not called again.
    await _check_at(monitor, clk, 4)
    assert rec.tunnel_down_calls == 1


async def test_on_tunnel_recovered_called_when_window_crossed() -> None:
    clk = _Clock()
    rec = _Recorder([True, True, True, True])
    monitor = _monitor(rec, initial_routes_active=False, recover_window=3, with_notify_callbacks=True, clock=clk)

    await _check_at(monitor, clk, 0)
    assert rec.tunnel_recovered_calls == 0
    await _check_at(monitor, clk, 1)
    assert rec.tunnel_recovered_calls == 0

    await _check_at(monitor, clk, 3)
    assert rec.tunnel_recovered_calls == 1

    # Fourth success: routes already active, callback not called again.
    await _check_at(monitor, clk, 4)
    assert rec.tunnel_recovered_calls == 1


async def test_on_tunnel_down_exception_is_suppressed() -> None:
    async def boom() -> None:
        raise RuntimeError("notify failed")

    clk = _Clock()
    rec = _Recorder([False, False])
    monitor = WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_down=boom,
        fail_window=2,
        recover_window=3,
        clock=clk,
    )
    # Should not raise even though on_tunnel_down raises.
    await _check_at(monitor, clk, 0)
    await _check_at(monitor, clk, 2)
    assert rec.deactivations == 1


async def test_on_tunnel_recovered_exception_is_suppressed() -> None:
    async def boom() -> None:
        raise RuntimeError("notify failed")

    clk = _Clock()
    rec = _Recorder([True, True, True])
    monitor = WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_recovered=boom,
        fail_window=2,
        recover_window=3,
        initial_routes_active=False,
        clock=clk,
    )
    for t in (0, 1, 3):
        await _check_at(monitor, clk, t)
    assert rec.activations == 1


async def test_no_callbacks_when_none() -> None:
    # Passing None callbacks must not raise.
    clk = _Clock()
    rec = _Recorder([False, False, True, True, True])
    monitor = _monitor(rec, initial_routes_active=True, fail_window=2, recover_window=3, clock=clk)
    for t in (0, 2, 4, 6, 8):
        await _check_at(monitor, clk, t)
    assert rec.deactivations == 1 and rec.activations == 1


# ── observer mode: never touch routes, only observe + notify ──────────────────

async def test_observer_mode_down_notifies_without_route_calls() -> None:
    clk = _Clock()
    rec = _Recorder([False, False, False])
    monitor = _monitor(rec, observer_mode=True, fail_window=2, with_notify_callbacks=True, clock=clk)

    await _check_at(monitor, clk, 0)
    assert rec.tunnel_down_calls == 0

    # Window crossed: notify, but routes are NEVER touched (systemd owns them).
    await _check_at(monitor, clk, 2)
    assert rec.tunnel_down_calls == 1
    assert rec.deactivations == 0 and rec.activations == 0
    # routes_active stays True throughout — the bot does not manage it in observer mode.
    assert monitor.routes_active is True
    assert all(s.routes_active is True for s in rec.snapshots)


async def test_observer_mode_recovery_notifies_without_route_calls() -> None:
    clk = _Clock()
    rec = _Recorder([False, False, True, True, True])
    monitor = _monitor(rec, observer_mode=True, fail_window=2, recover_window=3, with_notify_callbacks=True, clock=clk)
    for t in (0, 2, 4, 6, 8):
        await _check_at(monitor, clk, t)

    # No response across the window -> down notify, continuous success across the window
    # -> recovered notify; no route calls at all.
    assert rec.tunnel_down_calls == 1
    assert rec.tunnel_recovered_calls == 1
    assert rec.deactivations == 0 and rec.activations == 0
    assert monitor.routes_active is True


async def test_observer_mode_notifies_only_on_state_change() -> None:
    # A sustained outage must produce exactly one "down" notification (anti-spam).
    clk = _Clock()
    rec = _Recorder([False, False, False, False])
    monitor = _monitor(rec, observer_mode=True, fail_window=2, with_notify_callbacks=True, clock=clk)
    for t in (0, 2, 4, 6):
        await _check_at(monitor, clk, t)
    assert rec.tunnel_down_calls == 1
    assert rec.deactivations == 0


async def test_fail_window_is_honoured_from_constructor() -> None:
    # With a longer window, a brief outage does not trip a "down".
    clk = _Clock()
    rec = _Recorder([False, False, False, False])
    monitor = WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_tunnel_down=rec.on_tunnel_down,
        fail_window=4,
        recover_window=3,
        observer_mode=True,
        clock=clk,
    )
    for t in (0, 1, 2):
        await _check_at(monitor, clk, t)
    assert rec.tunnel_down_calls == 0  # 2s < 4s window
    await _check_at(monitor, clk, 4)
    assert rec.tunnel_down_calls == 1  # 4s == window


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
    manager._kill_switch = False
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
    manager._fail_window = 60
    manager._recover_window = 60
    manager._interval = 10
    manager._fast_interval = 3
    manager._running = False
    manager._monitor = None
    manager._last_error = None
    manager._kill_switch = False
    manager._route_lock = asyncio.Lock()
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
    # Monitor wired as an observer with no-op route callbacks and the configured windows.
    kwargs = fake_monitor_cls.call_args.kwargs
    assert kwargs["observer_mode"] is True
    assert kwargs["activate_routes"] is _noop_route
    assert kwargs["deactivate_routes"] is _noop_route
    assert kwargs["fail_window"] == 60
    assert kwargs["recover_window"] == 60
    assert kwargs["interval"] == 10
    assert kwargs["fast_interval"] == 3


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


# ── P8-010: kill-switch (legacy route teardown gating) ────────────────────────


def _killswitch_monitor(rec: _Recorder, *, kill_switch: bool, observer_mode: bool, clk: _Clock) -> WarpHealthMonitor:
    return WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        fail_window=2,
        recover_window=3,
        initial_routes_active=True,
        observer_mode=observer_mode,
        kill_switch=lambda: kill_switch,
        clock=clk,
    )


async def test_kill_switch_on_keeps_routes_on_tunnel_down() -> None:
    """Legacy mode + kill-switch ON: a tunnel-down must NOT remove routes (masked
    traffic blackholes on the dead interface instead of leaking the real IP)."""
    clk = _Clock()
    rec = _Recorder([False, False])
    monitor = _killswitch_monitor(rec, kill_switch=True, observer_mode=False, clk=clk)
    await _check_at(monitor, clk, 0)
    await _check_at(monitor, clk, 3)  # continuous fail >= fail_window → mark down
    assert rec.deactivations == 0
    assert monitor.routes_active is True


async def test_kill_switch_off_removes_routes_on_tunnel_down() -> None:
    """Legacy mode + kill-switch OFF (default): tunnel-down removes routes as before."""
    clk = _Clock()
    rec = _Recorder([False, False])
    monitor = _killswitch_monitor(rec, kill_switch=False, observer_mode=False, clk=clk)
    await _check_at(monitor, clk, 0)
    await _check_at(monitor, clk, 3)
    assert rec.deactivations == 1
    assert monitor.routes_active is False


async def test_kill_switch_noop_in_observer_mode() -> None:
    """Observer mode never touches routes regardless of the kill-switch."""
    clk = _Clock()
    rec = _Recorder([False, False])
    monitor = _killswitch_monitor(rec, kill_switch=True, observer_mode=True, clk=clk)
    await _check_at(monitor, clk, 0)
    await _check_at(monitor, clk, 3)
    assert rec.deactivations == 0
    assert monitor.routes_active is True


# ── P8-017: sustained-degradation detector (alert-only, never removes routes) ──


class _DegradeRecorder(_Recorder):
    def __init__(self, ping_results: list[bool]) -> None:
        super().__init__(ping_results)
        self.degraded_losses: list[float] = []
        self.degraded_cleared = 0

    async def on_degraded(self, loss: float) -> None:
        self.degraded_losses.append(loss)

    async def on_degraded_cleared(self) -> None:
        self.degraded_cleared += 1


def _degrade_monitor(rec: _DegradeRecorder, clk: _Clock) -> WarpHealthMonitor:
    # Huge fail/recover windows so the continuous-fail latch never fires: this
    # isolates the sliding-window degraded detector from route teardown.
    return WarpHealthMonitor(
        ping=rec.ping,
        activate_routes=rec.activate,
        deactivate_routes=rec.deactivate,
        on_update=rec.on_update,
        on_degraded=rec.on_degraded,
        on_degraded_cleared=rec.on_degraded_cleared,
        fail_window=10_000,
        recover_window=10_000,
        initial_routes_active=True,
        observer_mode=False,
        clock=clk,
    )


async def test_degraded_fires_on_sustained_loss_without_touching_routes() -> None:
    clk = _Clock()
    rec = _DegradeRecorder([True, False] * 8)  # alternating → 50% loss, 16 samples
    monitor = _degrade_monitor(rec, clk)
    for i in range(16):
        await _check_at(monitor, clk, float(i))
    assert rec.degraded_losses, "degraded alert must fire on sustained ~50% loss"
    assert monitor.degraded is True
    # Observability only: routes are never activated/deactivated.
    assert rec.activations == 0 and rec.deactivations == 0
    assert monitor.routes_active is True


async def test_single_failure_never_raises_degraded() -> None:
    clk = _Clock()
    rec = _DegradeRecorder([True] * 9 + [False])  # 1 fail in 10 → 10% loss
    monitor = _degrade_monitor(rec, clk)
    for i in range(10):
        await _check_at(monitor, clk, float(i))
    assert rec.degraded_losses == []
    assert monitor.degraded is False


async def test_degraded_clears_after_recovery() -> None:
    clk = _Clock()
    # 10 straight fails (loss 1.0 → degraded), then a long run of successes drags
    # the windowed loss below the clear threshold.
    rec = _DegradeRecorder([False] * 10 + [True] * 50)
    monitor = _degrade_monitor(rec, clk)
    for i in range(60):
        await _check_at(monitor, clk, float(i))
    assert rec.degraded_losses  # raised at some point
    assert rec.degraded_cleared >= 1
    assert monitor.degraded is False
