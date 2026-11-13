"""WarpManager state machine, driven through its real constructor.

What is real: WarpManager.__init__, WarpInterface, WarpRoutes,
PrivilegedHelperRunner, WarpSettingsRepository and a bootstrapped SQLite
database in tmp_path — so every transition is asserted on the persisted
``warp_settings`` row, not on a mock.

What is faked (hermetic: no sudo, no awg, no ping, no /etc):
* ShellRunner — a scripted recorder; the "sudo -n <helper> ..." argv the
  manager builds is asserted, never executed;
* WarpHealthMonitor — a recorder of its wiring (start/stop and kwargs);
* ping_interface, the awg-quick presence check, ROUTES_LIST and the clock.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar
from unittest.mock import AsyncMock

import pytest
from conftest import wait_until_lock_contended

import warp.manager as manager_module
from db.database import Database
from models.dto import ShellResult
from repositories.warp_settings import WarpSettingsRepository
from warp.health import HealthSnapshot
from warp.manager import WarpError, WarpManager, _helper_error_message, _noop_route
from warp.state import WarpState

NOW = 1_767_225_600
IFACE = "out-warp"
LOGGER = "warp.manager"


def _ok(stdout: str = "") -> ShellResult:
    return ShellResult((), 0, stdout, "")


def _fail(stderr: str = "", stdout: str = "", rc: int = 1) -> ShellResult:
    return ShellResult((), rc, stdout, stderr)


class FakeShell:
    """Records every argv; answers from a script keyed by (helper name, verb)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.results: dict[tuple[str, str], ShellResult | BaseException] = {}
        self.gates: dict[tuple[str, str], asyncio.Event] = {}
        self.reached: dict[tuple[str, str], asyncio.Event] = {}

    @staticmethod
    def key(args: tuple[str, ...]) -> tuple[str, str]:
        if args[:2] == ("sudo", "-n"):
            return (Path(args[2]).name, args[3])
        return (args[0], " ".join(args[1:]))

    def verbs(self) -> list[tuple[str, str]]:
        return [self.key(call) for call in self.calls]

    async def run(self, args: list[str], **kwargs: Any) -> ShellResult:
        argv = tuple(args)
        self.calls.append(argv)
        key = self.key(argv)
        reached = self.reached.get(key)
        if reached is not None:
            reached.set()
        gate = self.gates.get(key)
        if gate is not None:
            await gate.wait()
        result = self.results.get(key, _ok())
        if isinstance(result, BaseException):
            raise result
        return result


class FakeMonitor:
    instances: ClassVar[list[FakeMonitor]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        FakeMonitor.instances.append(self)

    def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True


class World(SimpleNamespace):
    db: Database
    shell: FakeShell
    manager: WarpManager
    repo: WarpSettingsRepository
    env: SimpleNamespace
    routes_list: Path
    helpers: Path


def _settings(tmp_path: Path, *, observer: bool) -> SimpleNamespace:
    helpers = tmp_path / "helpers"
    return SimpleNamespace(
        warp_config_path=tmp_path / "out-warp.conf",
        awg_network="10.8.0.0/24",
        warp_interface=IFACE,
        warp_ping_target="198.51.100.1",
        warp_install_helper_path=helpers / "vpn-bot-warp-install",
        warp_helper_staging_dir=tmp_path / "staging",
        warp_iface_helper_path=helpers / "vpn-bot-warp-iface",
        warp_status_helper_path=helpers / "vpn-bot-warp-status",
        warp_routes_helper_path=helpers / "vpn-bot-warp-routes",
        warp_monitor_observer_mode=observer,
        warp_monitor_fail_window_seconds=60,
        warp_monitor_recover_window_seconds=90,
        warp_monitor_interval_seconds=10,
        warp_monitor_fast_interval_seconds=3,
        admin_ids=frozenset({101, 202}),
    )


async def _world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, observer: bool = False) -> World:
    FakeMonitor.instances = []
    env = SimpleNamespace(awg_quick=True, ping=True)
    routes_list = tmp_path / "out-warp-routes.list"
    monkeypatch.setattr(time, "time", lambda: float(NOW))
    monkeypatch.setattr(manager_module, "WarpHealthMonitor", FakeMonitor)
    monkeypatch.setattr(manager_module, "ROUTES_LIST", str(routes_list))
    monkeypatch.setattr(manager_module.WarpInterface, "awg_quick_available", staticmethod(lambda: env.awg_quick))

    async def fake_ping(target: str, interface: str) -> bool:
        return bool(env.ping)

    monkeypatch.setattr(manager_module, "ping_interface", fake_ping)
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    shell = FakeShell()
    settings = _settings(tmp_path, observer=observer)
    manager = WarpManager(db=db, settings=settings, shell=shell)  # type: ignore[arg-type]
    return World(
        db=db,
        shell=shell,
        manager=manager,
        repo=WarpSettingsRepository(db),
        env=env,
        routes_list=routes_list,
        helpers=tmp_path / "helpers",
    )


@pytest.fixture
async def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[World]:
    w = await _world(tmp_path, monkeypatch)
    try:
        yield w
    finally:
        await w.db.close()


@pytest.fixture
async def observer_world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[World]:
    w = await _world(tmp_path, monkeypatch, observer=True)
    try:
        yield w
    finally:
        await w.db.close()


async def _install_config(w: World, routes: int = 2) -> None:
    await w.repo.update_config(config_path=str(w.manager._config_path), interface_name=IFACE, routes_count=routes)


HANDSHAKE_STATUS = _ok("interface: out-warp\n  latest handshake: 1 minute, 5 seconds ago\n")


# ── start: guards ────────────────────────────────────────────────────────────


# Invariant: without the awg-quick binary the module refuses to start with a
# user-facing WarpError, records it as last_error, and runs no helper at all.
async def test_start_blocked_without_awg_quick(world: World) -> None:
    # Arrange
    await _install_config(world)
    world.env.awg_quick = False

    # Act / Assert
    with pytest.raises(WarpError, match="awg-quick"):
        await world.manager.start()
    assert world.manager.last_error is not None and "awg-quick" in world.manager.last_error
    assert world.shell.calls == []
    assert FakeMonitor.instances == []


# Invariant: without an installed config the module refuses to start and runs
# no helper.
async def test_start_blocked_without_config(world: World) -> None:
    # Arrange — fresh DB: no config installed

    # Act / Assert
    with pytest.raises(WarpError, match="Конфиг WARP не загружен"):
        await world.manager.start()
    assert world.shell.calls == []


# Invariant: a full-tunnel config (config_installed=1 but zero routes) is
# startable — config_present, not routes_count, gates start.
async def test_start_allows_zero_route_installed_config(world: World) -> None:
    # Arrange
    await _install_config(world, routes=0)

    # Act
    await world.manager.start()

    # Assert
    assert world.manager._running is True


# ── start: legacy (bot owns interface + routes) ──────────────────────────────


# Invariant: a legacy start runs stale-down → up → routes add, in that order,
# persists tunnel_up/routes_active plus the parsed handshake, and wires a
# started monitor with the real route callbacks and the configured windows.
async def test_legacy_start_happy_path(world: World) -> None:
    # Arrange
    await _install_config(world)
    world.shell.results["vpn-bot-warp-status", IFACE] = HANDSHAKE_STATUS

    # Act
    await world.manager.start()

    # Assert
    assert world.shell.verbs() == [
        ("vpn-bot-warp-iface", "down"),
        ("vpn-bot-warp-iface", "up"),
        ("vpn-bot-warp-routes", "add"),
        ("vpn-bot-warp-status", IFACE),
    ]
    assert world.shell.calls[1] == ("sudo", "-n", str(world.helpers / "vpn-bot-warp-iface"), "up",
                                    str(world.manager._config_path))
    state = await world.repo.get()
    assert (state.tunnel_up, state.routes_active, state.last_handshake) == (True, True, NOW - 65)
    assert world.manager.last_error is None
    (monitor,) = FakeMonitor.instances
    assert monitor.started is True
    assert monitor.kwargs["activate_routes"] == world.manager._activate_routes
    assert monitor.kwargs["initial_routes_active"] is True
    assert (monitor.kwargs["fail_window"], monitor.kwargs["recover_window"]) == (60, 90)
    assert "observer_mode" not in monitor.kwargs


# Invariant: a failing stale-interface cleanup (even one that raises) never
# blocks the start.
async def test_legacy_start_ignores_failing_stale_down(world: World) -> None:
    # Arrange
    await _install_config(world)
    world.shell.results["vpn-bot-warp-iface", "down"] = RuntimeError("helper crashed")

    # Act
    await world.manager.start()

    # Assert
    assert world.manager._running is True


# Invariant: if the interface cannot be brought up, start raises with the
# helper's stderr in the message, installs no routes, starts no monitor and
# leaves the module stopped.
async def test_legacy_start_up_failure(world: World) -> None:
    # Arrange
    await _install_config(world)
    world.shell.results["vpn-bot-warp-iface", "up"] = _fail("RTNETLINK answers: File exists")

    # Act / Assert
    with pytest.raises(WarpError, match="RTNETLINK answers: File exists"):
        await world.manager.start()
    assert ("vpn-bot-warp-routes", "add") not in world.shell.verbs()
    assert world.manager._running is False
    assert FakeMonitor.instances == []
    assert (await world.repo.get()).tunnel_up is False


# Invariant: a routes-add failure leaves a HALF-applied state that is surfaced,
# not hidden: running, interface up, routes_active=0 persisted, last_error set,
# and the monitor told routes are inactive so it can retry them.
async def test_legacy_start_routes_failure_is_half_applied(world: World) -> None:
    # Arrange
    await _install_config(world)
    world.shell.results["vpn-bot-warp-routes", "add"] = _fail("table busy")

    # Act
    await world.manager.start()

    # Assert
    assert world.manager._running is True
    assert world.manager.last_error is not None and "маршруты не установлены" in world.manager.last_error
    assert "table busy" in world.manager.last_error
    state = await world.repo.get()
    assert (state.tunnel_up, state.routes_active) == (True, False)
    assert FakeMonitor.instances[0].kwargs["initial_routes_active"] is False


# Invariant: a failed first probe is only a warning — the module still runs and
# the monitor keeps trying.
async def test_legacy_start_first_probe_failure_only_warns(world: World, caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    await _install_config(world)
    world.env.ping = False
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act
    await world.manager.start()

    # Assert
    assert world.manager._running is True
    assert "first tunnel probe failed" in caplog.text


# Invariant: start() on a running module is a no-op (idempotent; no second
# interface bring-up, no second monitor).
async def test_start_twice_is_noop(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.start()
    calls_after_first = len(world.shell.calls)

    # Act
    await world.manager.start()

    # Assert
    assert len(world.shell.calls) == calls_after_first
    assert len(FakeMonitor.instances) == 1


# ── start: observer (systemd owns interface + routes) ────────────────────────


# Invariant: observer start NEVER brings the interface up/down or touches
# routes; it only reads status, persists the observed state and wires no-op
# route callbacks plus the source-rule detector.
async def test_observer_start_only_observes(observer_world: World) -> None:
    # Arrange
    w = observer_world
    await _install_config(w)
    w.shell.results["vpn-bot-warp-status", IFACE] = HANDSHAKE_STATUS

    # Act
    await w.manager.start()

    # Assert
    assert {verb for verb in w.shell.verbs()} == {("vpn-bot-warp-status", IFACE)}
    state = await w.repo.get()
    assert (state.tunnel_up, state.routes_active, state.last_handshake) == (True, True, NOW - 65)
    (monitor,) = FakeMonitor.instances
    assert monitor.kwargs["observer_mode"] is True
    assert monitor.kwargs["activate_routes"] is _noop_route
    assert monitor.kwargs["check_source_rules"] == w.manager._check_source_rules
    assert await _noop_route() is None


# Invariant: in observer mode an interface that is not up is reported (warning,
# tunnel_up=0, routes_active=0) but the observer still starts.
async def test_observer_start_with_interface_down(observer_world: World, caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    w = observer_world
    await _install_config(w)
    w.shell.results["vpn-bot-warp-status", IFACE] = _fail("Unable to access interface", rc=1)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act
    await w.manager.start()

    # Assert
    assert w.manager._running is True
    state = await w.repo.get()
    assert (state.tunnel_up, state.routes_active, state.last_handshake) == (False, False, 0)
    assert "does not appear to be up" in caplog.text
    assert FakeMonitor.instances[0].kwargs["initial_routes_active"] is False


# Invariant: observer stop leaves the systemd-owned interface and routes alone
# but still stops the monitor and resets the runtime view.
async def test_observer_stop_touches_nothing(observer_world: World) -> None:
    # Arrange
    w = observer_world
    await _install_config(w)
    await w.manager.start()
    w.shell.calls.clear()

    # Act
    await w.manager.stop()

    # Assert
    assert w.shell.calls == []
    assert FakeMonitor.instances[0].stopped is True
    assert (await w.repo.get()).tunnel_up is False


# ── stop ─────────────────────────────────────────────────────────────────────


# Invariant: a legacy stop stops the monitor, removes routes, brings the
# interface down and zeroes the runtime columns.
async def test_legacy_stop_tears_down(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.start()
    world.shell.calls.clear()

    # Act
    await world.manager.stop()

    # Assert
    assert world.shell.verbs() == [("vpn-bot-warp-routes", "del"), ("vpn-bot-warp-iface", "down")]
    assert FakeMonitor.instances[0].stopped is True
    assert world.manager._monitor is None and world.manager._running is False
    state = await world.repo.get()
    assert (state.tunnel_up, state.routes_active, state.last_check_ts) == (False, False, NOW)


# Invariant: teardown failures are logged, never raised — stop always reaches
# the "stopped" state so a broken helper cannot wedge the module "running".
async def test_legacy_stop_failures_are_logged_not_raised(world: World, caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.start()
    world.shell.results["vpn-bot-warp-routes", "del"] = _fail("no such route")
    world.shell.results["vpn-bot-warp-iface", "down"] = _fail("no such device")
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act
    await world.manager.stop()

    # Assert
    assert world.manager._running is False
    assert "routes remove failed" in caplog.text and "interface down failed" in caplog.text


# Invariant: stopping a module that is not running runs no helper but still
# resets the runtime view.
async def test_stop_when_not_running_runs_no_helper(world: World) -> None:
    # Arrange
    await world.repo.update_runtime(
        tunnel_up=True, routes_active=True, fail_streak=4, success_streak=0, last_handshake=1, last_check_ts=1
    )

    # Act
    await world.manager.stop()

    # Assert
    assert world.shell.calls == []
    state = await world.repo.get()
    assert (state.tunnel_up, state.fail_streak) == (False, 0)


# Invariant: stopping a module that never started, with a clean runtime view,
# writes nothing — every bot shutdown on a host without WARP used to stamp
# last_check_ts, so a restart with nothing to change rewrote vpn.db.
async def test_stop_of_a_never_started_module_writes_nothing(world: World) -> None:
    # Arrange
    before = await world.repo.get()
    assert (before.tunnel_up, before.last_check_ts) == (False, 0)

    # Act
    await world.manager.stop()

    # Assert
    assert world.shell.calls == []
    assert await world.repo.get() == before


# ── enable / disable / restart / kill-switch ─────────────────────────────────


# Invariant: enable() persists enabled=1 only AFTER a successful start; a failed
# start leaves enabled=0.
async def test_enable_persists_only_after_successful_start(world: World) -> None:
    # Arrange
    failed_world_state_before = await world.repo.get()

    # Act
    with pytest.raises(WarpError):
        await world.manager.enable()
    after_failure = await world.repo.get()
    await _install_config(world)
    await world.manager.enable()
    after_success = await world.repo.get()

    # Assert
    assert failed_world_state_before.enabled is False
    assert after_failure.enabled is False
    assert after_success.enabled is True
    assert world.manager._running is True


# Invariant: disable() stops the module, persists enabled=0 and clears
# last_error.
async def test_disable_stops_and_clears_error(world: World) -> None:
    # Arrange
    await _install_config(world)
    world.shell.results["vpn-bot-warp-routes", "add"] = _fail("x")
    await world.manager.enable()
    assert world.manager.last_error is not None

    # Act
    await world.manager.disable()

    # Assert
    assert world.manager._running is False
    assert world.manager.last_error is None
    assert (await world.repo.get()).enabled is False


# Invariant: restart() is stop-then-start: the old monitor is stopped before a
# new one is created and the interface is cycled.
async def test_restart_cycles_interface_and_monitor(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.start()
    world.shell.calls.clear()

    # Act
    await world.manager.restart()

    # Assert
    assert world.shell.verbs()[:4] == [
        ("vpn-bot-warp-routes", "del"),
        ("vpn-bot-warp-iface", "down"),
        ("vpn-bot-warp-iface", "down"),
        ("vpn-bot-warp-iface", "up"),
    ]
    old, new = FakeMonitor.instances
    assert old.stopped is True and new.started is True and new.stopped is False


# Invariant: the kill-switch is persisted AND applied live — the running
# monitor's kill_switch callable reflects the change without a restart.
async def test_set_kill_switch_applies_live(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.start()
    kill_switch = FakeMonitor.instances[0].kwargs["kill_switch"]
    before = kill_switch()

    # Act
    await world.manager.set_kill_switch(True)

    # Assert
    assert before is False
    assert kill_switch() is True
    assert (await world.repo.get()).kill_switch is True
    assert len(FakeMonitor.instances) == 1


# Invariant: a persisted kill-switch is loaded on start.
async def test_start_loads_persisted_kill_switch(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.repo.set_kill_switch(True)

    # Act
    await world.manager.start()

    # Assert
    assert FakeMonitor.instances[0].kwargs["kill_switch"]() is True


# ── install_config ───────────────────────────────────────────────────────────


# Invariant: install on a stopped module writes the config to a private staging
# file, hands its path to the install helper, deletes the staging file, counts
# routes from routes.list (ignoring blanks/comments) and persists the config.
async def test_install_config_when_stopped(world: World) -> None:
    # Arrange
    world.routes_list.write_text("# header\n10.0.0.0/8\n\n172.16.0.0/12\n", encoding="utf-8")
    seen: dict[str, str] = {}
    original_run = world.shell.run

    async def capture(args: list[str], **kwargs: Any) -> ShellResult:
        if "install" in args:
            staging = Path(args[-1])
            seen["text"] = staging.read_text(encoding="utf-8")
            seen["mode"] = oct(staging.stat().st_mode & 0o777)
            seen["path"] = str(staging)
        return await original_run(args, **kwargs)

    world.shell.run = capture  # type: ignore[method-assign]

    # Act
    count = await world.manager.install_config("[Interface]\nPrivateKey = k\n")

    # Assert
    assert count == 2
    assert seen["text"] == "[Interface]\nPrivateKey = k\n"
    assert seen["mode"] == "0o600"
    assert not Path(seen["path"]).exists()
    state = await world.repo.get()
    assert (state.routes_count, state.config_installed) == (2, True)
    assert world.shell.verbs() == [("vpn-bot-warp-install", "install")]


# Invariant: when routes.list is absent the count falls back to the helper's
# "Installed: N routes" line, and to 0 when neither source has a number.
@pytest.mark.parametrize(("stdout", "expected"), [("Installed: 7 routes\n", 7), ("done\n", 0)])
async def test_install_config_route_count_fallback(world: World, stdout: str, expected: int) -> None:
    # Arrange
    world.shell.results["vpn-bot-warp-install", "install"] = _ok(stdout)

    # Act
    count = await world.manager.install_config("cfg")

    # Assert
    assert count == expected
    assert (await world.repo.get()).routes_count == expected


# Invariant: a failed install on a stopped module raises with the helper's
# detail, records last_error, still deletes the staging file, and leaves the
# persisted config untouched.
async def test_install_config_failure_when_stopped(world: World, tmp_path: Path) -> None:
    # Arrange
    world.shell.results["vpn-bot-warp-install", "install"] = _fail(stdout="bad AllowedIPs")

    # Act / Assert
    with pytest.raises(WarpError, match="bad AllowedIPs"):
        await world.manager.install_config("cfg")
    assert world.manager.last_error is not None and "bad AllowedIPs" in world.manager.last_error
    assert list((tmp_path / "staging").iterdir()) == []
    assert (await world.repo.get()).config_installed is False


# Invariant: install on a RUNNING module is stop → install → start, so the new
# config takes effect immediately.
async def test_install_config_when_running_restarts(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.start()
    world.shell.calls.clear()

    # Act
    await world.manager.install_config("cfg")

    # Assert
    assert world.shell.verbs()[:5] == [
        ("vpn-bot-warp-routes", "del"),
        ("vpn-bot-warp-iface", "down"),
        ("vpn-bot-warp-install", "install"),
        ("vpn-bot-warp-iface", "down"),
        ("vpn-bot-warp-iface", "up"),
    ]
    assert world.manager._running is True


# Invariant: rollback — a failed install on a running module restarts it on the
# OLD config and re-raises the install error.
async def test_install_config_failure_rolls_back_to_running(world: World) -> None:
    # Arrange
    await _install_config(world, routes=3)
    await world.manager.start()
    world.shell.results["vpn-bot-warp-install", "install"] = _fail("helper refused")

    # Act / Assert
    with pytest.raises(WarpError, match="helper refused"):
        await world.manager.install_config("cfg")
    assert world.manager._running is True
    assert (await world.repo.get()).routes_count == 3
    assert FakeMonitor.instances[-1].started is True and FakeMonitor.instances[-1].stopped is False


# Invariant: if the rollback restart ALSO fails, the ORIGINAL install error is
# what the caller sees (the restart error is suppressed) and the module is left
# stopped, not half-running.
async def test_install_config_failure_with_failed_rollback(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.start()
    world.shell.results["vpn-bot-warp-install", "install"] = _fail("install refused")
    world.shell.results["vpn-bot-warp-iface", "up"] = _fail("up refused")

    # Act / Assert
    with pytest.raises(WarpError, match="install refused"):
        await world.manager.install_config("cfg")
    assert world.manager._running is False


# ── delete_config ────────────────────────────────────────────────────────────


# Invariant: delete stops the module, removes the files via the helper, then
# disables and forgets the config in the DB.
async def test_delete_config_success(world: World) -> None:
    # Arrange
    await _install_config(world)
    await world.manager.enable()
    world.shell.calls.clear()

    # Act
    await world.manager.delete_config()

    # Assert
    assert world.shell.verbs()[-1] == ("vpn-bot-warp-install", "remove")
    state = await world.repo.get()
    assert (state.enabled, state.config_installed, state.routes_count) == (False, False, 0)
    assert world.manager._running is False and world.manager.last_error is None


# Invariant: if the helper cannot remove the files, delete raises and the DB
# keeps the config (the files may still be on disk).
async def test_delete_config_helper_failure_keeps_db(world: World) -> None:
    # Arrange
    await _install_config(world)
    world.shell.results["vpn-bot-warp-install", "remove"] = _fail("read-only fs")

    # Act / Assert
    with pytest.raises(WarpError, match="read-only fs"):
        await world.manager.delete_config()
    assert world.manager.last_error is not None
    assert (await world.repo.get()).config_installed is True


# ── serialisation under the lock ─────────────────────────────────────────────


# Invariant: every state transition is serialised behind one lock — a disable()
# issued while an install is mid-helper waits, and none of its helper calls
# interleave with the install.
async def test_transitions_are_serialised_under_lock(world: World) -> None:
    # Arrange
    gate = asyncio.Event()
    reached = asyncio.Event()
    world.shell.gates["vpn-bot-warp-install", "install"] = gate
    world.shell.reached["vpn-bot-warp-install", "install"] = reached
    install = asyncio.create_task(world.manager.install_config("cfg"))
    await asyncio.wait_for(reached.wait(), timeout=5)
    disable = asyncio.create_task(world.manager.disable())
    await wait_until_lock_contended(world.manager._lock)
    calls_while_blocked = list(world.shell.verbs())

    # Act
    gate.set()
    await asyncio.gather(install, disable)

    # Assert
    assert calls_while_blocked == [("vpn-bot-warp-install", "install")]
    state = await world.repo.get()
    assert state.config_installed is True and state.enabled is False


# Invariant: monitor-driven route changes share the route lock with teardown —
# an activate issued while the lock is held parks until it is released.
async def test_activate_routes_waits_for_route_lock(world: World) -> None:
    # Arrange
    await world.manager._route_lock.acquire()
    task = asyncio.create_task(world.manager._activate_routes())
    await wait_until_lock_contended(world.manager._route_lock)
    calls_while_held = list(world.shell.calls)

    # Act
    world.manager._route_lock.release()
    await task

    # Assert
    assert calls_while_held == []
    assert world.shell.verbs() == [("vpn-bot-warp-routes", "add")]


# Invariant: failed monitor-driven route changes are logged, never raised into
# the monitor loop.
async def test_route_callbacks_log_failures(world: World, caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    world.shell.results["vpn-bot-warp-routes", "add"] = _fail("e1")
    world.shell.results["vpn-bot-warp-routes", "del"] = _fail("e2")
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act
    await world.manager._activate_routes()
    await world.manager._deactivate_routes()

    # Assert
    assert "route restore failed" in caplog.text
    assert "route removal (fallback) failed" in caplog.text


# ── probes, health updates, accessors ────────────────────────────────────────


# Invariant: a successful ICMP probe is enough — no handshake read is made.
async def test_ping_icmp_success_skips_handshake(world: World) -> None:
    # Arrange
    world.env.ping = True

    # Act
    alive = await world.manager._ping()

    # Assert
    assert alive is True
    assert world.shell.calls == []


# Invariant: when ICMP fails, a handshake no older than HANDSHAKE_FRESH_SECONDS
# keeps the tunnel "up"; an older one, or none at all, does not.
@pytest.mark.parametrize(
    ("status", "alive"),
    [
        (_ok("latest handshake: 2 minutes, 59 seconds ago"), True),
        (_ok("latest handshake: 3 minutes ago"), True),
        (_ok("latest handshake: 3 minutes, 1 second ago"), False),
        (_ok("peer: abc\n"), False),
        (_fail("no such device"), False),
    ],
)
async def test_ping_falls_back_to_handshake_freshness(world: World, status: ShellResult, alive: bool) -> None:
    # Arrange
    world.env.ping = False
    world.shell.results["vpn-bot-warp-status", IFACE] = status

    # Act
    result = await world.manager._ping()

    # Assert
    assert result is alive


# Invariant: a handshake read that raises degrades to 0 ("unknown"), never
# propagates.
async def test_safe_handshake_swallows_errors(world: World) -> None:
    # Arrange
    world.shell.results["vpn-bot-warp-status", IFACE] = OSError("boom")

    # Act
    handshake = await world.manager._safe_handshake()

    # Assert
    assert handshake == 0


# Invariant: a health update persists the snapshot; the handshake is read only
# while the tunnel is up (0 otherwise, without a status call).
async def test_on_health_update_persists_snapshot(world: World) -> None:
    # Arrange
    world.shell.results["vpn-bot-warp-status", IFACE] = HANDSHAKE_STATUS
    up = HealthSnapshot(tunnel_up=True, routes_active=True, fail_streak=0, success_streak=5)
    down = HealthSnapshot(tunnel_up=False, routes_active=False, fail_streak=3, success_streak=0)

    # Act
    await world.manager._on_health_update(up)
    after_up = await world.repo.get()
    status_calls = len(world.shell.calls)
    await world.manager._on_health_update(down)
    after_down = await world.repo.get()

    # Assert
    assert (after_up.tunnel_up, after_up.success_streak, after_up.last_handshake) == (True, 5, NOW - 65)
    assert (after_down.tunnel_up, after_down.fail_streak, after_down.last_handshake) == (False, 3, 0)
    assert len(world.shell.calls) == status_calls


# Invariant: the read-only accessors reflect the persisted row.
async def test_accessors_read_persisted_state(world: World) -> None:
    # Arrange
    await world.repo.set_enabled(True)
    await world.repo.update_runtime(
        tunnel_up=True, routes_active=False, fail_streak=1, success_streak=0, last_handshake=0, last_check_ts=0
    )

    # Act
    enabled = await world.manager.is_enabled()
    state = await world.manager.get_state()
    await world.manager.reset_runtime_state()
    reset = await world.manager.get_state()

    # Assert
    assert enabled is True
    assert state.tunnel_up is True and state.fail_streak == 1
    assert reset.tunnel_up is False and reset.fail_streak == 0 and reset.enabled is True


# Invariant: alerts go to every admin; one admin's delivery failure is logged
# and does not stop delivery to the others; no bot means no-op.
async def test_broadcast_continues_after_one_failure(world: World, caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    no_bot_result = await world.manager._notify_degraded(0.5)
    bot = AsyncMock()
    bot.send_message.side_effect = [RuntimeError("blocked by user"), None]
    world.manager.bot = bot
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act
    await world.manager._notify_degraded(0.5)

    # Assert
    assert no_bot_result is None
    assert bot.send_message.await_count == 2
    assert "Failed to send WARP degraded alert" in caplog.text
    assert "50%" in bot.send_message.call_args.args[1]


# Invariant: the admin-facing helper error prefers stderr, falls back to
# stdout, and is just the fallback text when the helper printed nothing.
@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (ShellResult((), 1, "out", "err"), "base: err"),
        (ShellResult((), 1, " out \n", ""), "base: out"),
        (ShellResult((), 1, "  ", "\n"), "base"),
    ],
)
def test_helper_error_message(result: ShellResult, expected: str) -> None:
    # Arrange — parametrised

    # Act
    message = _helper_error_message(result, "base")

    # Assert
    assert message == expected


# Invariant: the persisted state type is the WarpState dataclass (the admin
# panel renders it directly).
async def test_get_state_returns_warpstate(world: World) -> None:
    # Arrange — fresh DB

    # Act
    state = await world.manager.get_state()

    # Assert
    assert isinstance(state, WarpState)
