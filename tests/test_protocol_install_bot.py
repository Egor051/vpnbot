"""«📦 Установить» seen from the bot (services/protocol_install.py, docs/protocol-install.md).

* A protocol's state on the host is the helper's probes (installed / partial / absent),
  an uninstall marker wins (uninstalled), and a service built without a root reads
  nothing (unknown) — no test reads the real host.
* «📦 Установить» starts a run of the wizard's «protocol» mode (its plan first) for a
  SUPERADMIN only, never for a protocol that is on the host.
* Once a run succeeded the firewall is converged before the report, and the report says
  so — also when the report is sent by the process that started after the bot's restart.
* The helper's step events become the run's progress (bot/progress.py's icons).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bot.keyboards.admin_modules import modules_panel_keyboard
from bot.wizard_views import final_text, plan_text, progress_text
from repositories.protocol_modules import PROTOCOL_NAMES, ProtocolModule
from services.errors import InvalidOperation
from services.protocol_install import HOST_PROBES, ProtocolInstallError, ProtocolInstallService
from services.ufw import UfwApplyResult
from services.wizard import parse_status

from collections.abc import AsyncIterator

from db.database import Database
from test_wizard_service import ADMIN, World

pytestmark = pytest.mark.timeout(60)


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    """tests/test_wizard_service.py's world: a real WizardService on a temp DB."""
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, role, created_at, updated_at) VALUES (?, 'SUPERADMIN', 'x', 'x')", (ADMIN,)
    )
    await db.commit()
    try:
        yield World(db, tmp_path)
    finally:
        await db.close()


class _Registry:
    def __init__(self, removed: set[str] | None = None) -> None:
        self.removed = removed or set()

    def is_uninstalled(self, name: str) -> bool:
        return name in self.removed


class _Users:
    def __init__(self) -> None:
        self.asked: list[int] = []

    async def require_superadmin(self, user_id: int) -> object:
        self.asked.append(user_id)
        if user_id != ADMIN:
            raise InvalidOperation("not a superadmin", key="access_denied")
        return object()


class _Firewall:
    def __init__(self, ok: bool = True) -> None:
        self.reasons: list[str] = []
        self.ok = ok

    async def apply(self, reason: str) -> UfwApplyResult:
        self.reasons.append(reason)
        return UfwApplyResult(self.ok, "+443/tcp (xray)", 0 if self.ok else 4)


def _lay(root: Path, *paths: str) -> None:
    for p in paths:
        f = root / p.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("x")


def test_host_state_follows_the_probes_and_the_marker(tmp_path: Path) -> None:
    reg = _Registry()
    svc = ProtocolInstallService(wizard=None, users=_Users(), registry=reg, root=tmp_path)
    assert svc.host_state("xray") == "absent" and svc.installable("xray")
    _lay(tmp_path, HOST_PROBES["xray"][0])
    assert svc.host_state("xray") == "partial" and svc.installable("xray")
    _lay(tmp_path, *HOST_PROBES["xray"])
    assert svc.host_state("xray") == "installed" and not svc.installable("xray")
    assert svc.missing() == frozenset()
    reg.removed.add("xray")
    assert svc.host_state("xray") == "uninstalled" and not svc.installable("xray")
    # A protocol the helper does not install (yet) is never offered.
    assert not svc.installable("awg")


def test_without_a_root_nothing_is_read_and_nothing_offered() -> None:
    svc = ProtocolInstallService(wizard=None, users=_Users(), registry=_Registry())
    assert svc.host_state("xray") == "unknown" and svc.missing() == frozenset()


async def test_install_starts_a_protocol_run_with_its_plan_first(world: World, tmp_path: Path) -> None:
    wizard = world.service()
    firewall = _Firewall()
    svc = ProtocolInstallService(wizard=wizard, users=_Users(), registry=_Registry(), firewall=firewall,
                                 root=tmp_path / "host")
    with pytest.raises(InvalidOperation):
        await svc.start(ADMIN + 1, "xray", chat_id=1, message_id=2)
    run = await svc.start(ADMIN, "xray", chat_id=1, message_id=2)
    assert run.mode == "protocol" and run.params == {"proto": "xray", "domain": ""}
    launch = world.runner.calls[-1]
    assert launch[1:] == ["launch", "--mode", "protocol", "--run", str(run.id), "--phase", "plan",
                          "--param", "domain=", "--param", "proto=xray"]


async def test_an_installed_protocol_is_not_offered(world: World, tmp_path: Path) -> None:
    _lay(tmp_path, *HOST_PROBES["xray"])
    svc = ProtocolInstallService(wizard=world.service(), users=_Users(), registry=_Registry(), root=tmp_path)
    with pytest.raises(ProtocolInstallError):
        await svc.start(ADMIN, "xray", chat_id=1, message_id=2)


async def test_a_successful_run_converges_the_firewall_before_the_report(world: World, tmp_path: Path) -> None:
    firewall = _Firewall()
    first = world.service()
    ProtocolInstallService(wizard=first, users=_Users(), registry=_Registry(), firewall=firewall, root=tmp_path)
    run = await first.start(ADMIN, "protocol", {"proto": "xray"}, chat_id=1, message_id=2)
    world.emit(run.id, "finished", phase="plan", outcome="planned")
    await first.poll_once()
    await first.confirm(ADMIN, run.id)
    world.emit(run.id, "launched", phase="execute")
    world.emit(run.id, "steps", steps={"nginx_pkg": "ok", "xray_bin": "ok"})
    world.emit(run.id, "result", text="xray works", verdict="ok")
    world.emit(run.id, "finished", phase="execute", outcome="succeeded")
    # The bot restarted (verify asks for it): a NEW process reports the run.
    second = world.service()
    captured: list[list[str]] = []

    async def finished(run: Any, snap: Any) -> bool:
        captured.append(list(snap.notes))
        return True

    world.notifier.finished = finished  # type: ignore[method-assign]
    ProtocolInstallService(wizard=second, users=_Users(), registry=_Registry(), firewall=firewall, root=tmp_path)
    await second.poll_once()
    await second.poll_once()
    assert firewall.reasons == ["installing xray"]
    assert captured == [["UFW: +443/tcp (xray)"]]


async def test_a_failed_run_does_not_touch_the_firewall(world: World, tmp_path: Path) -> None:
    firewall = _Firewall()
    svc = world.service()
    ProtocolInstallService(wizard=svc, users=_Users(), registry=_Registry(), firewall=firewall, root=tmp_path)
    run = await svc.start(ADMIN, "protocol", {"proto": "xray"}, chat_id=1, message_id=2)
    world.emit(run.id, "finished", phase="plan", outcome="failed")
    await svc.poll_once()
    await svc.poll_once()
    assert firewall.reasons == []


def test_steps_events_are_parsed_and_junk_is_dropped() -> None:
    lines = [
        {"event": "launched", "phase": "plan"},
        {"event": "steps", "steps": {"nginx_pkg": "wait", "xray_bin": "wait"}},
        {"event": "launched", "phase": "execute"},
        {"event": "steps", "steps": {"nginx_pkg": "ok", "xray_bin": "run", "Bad-Key": "ok", "env": "exploded"}},
    ]
    snap = parse_status("\n".join(json.dumps(line) for line in lines))
    assert snap.helper_steps == {"nginx_pkg": "ok", "xray_bin": "run"}


def _run(state: str, phase: str, *, active: bool, plan_ready: bool = False) -> Any:
    from models.dto import WizardRun

    return WizardRun(id=7, mode="protocol", state=state, phase=phase, current_step="apply", params={"proto": "xray"},
                     started_by=ADMIN, origin="manual", chat_id=1, message_id=2, log_path="/l/7.log", summary="",
                     plan_ready=plan_ready, active=active, created_at="2026-11-25T00:00:00", updated_at="x",
                     finished_at=None, reported_at=None)


def test_the_run_screen_shows_the_helpers_steps() -> None:
    lines = [{"event": "launched", "phase": "execute"},
             {"event": "steps", "steps": {"nginx_pkg": "ok", "xray_bin": "run", "env": "wait"}}]
    snap = parse_status("\n".join(json.dumps(line) for line in lines))
    text = progress_text(_run("running", "execute", active=True), snap)
    assert "✅ nginx" in text and "🔄 xray" in text and "⚪ .env" in text
    done = [*lines, {"event": "item", "level": "green", "key": "tls", "text": "TLSv1.3, ALPN h2"},
            {"event": "result", "text": "xray works", "verdict": "ok"}]
    snap = parse_status("\n".join(json.dumps(line) for line in done))
    snap.notes.append("UFW: +443/tcp (xray)")
    text = final_text(_run("succeeded", "execute", active=False), snap)
    assert "🔄" not in text and "TLSv1.3, ALPN h2" in text and "UFW: +443/tcp (xray)" in text


def test_the_plan_screen_lists_the_steps_to_come() -> None:
    lines = [{"event": "launched", "phase": "plan"}, {"event": "steps", "steps": {"nginx_pkg": "wait", "marker": "wait"}},
             {"event": "plan", "text": "Changes:\n  + package nginx"}]
    snap = parse_status("\n".join(json.dumps(line) for line in lines))
    text = plan_text(_run("planned", "plan", active=True, plan_ready=True), snap)
    assert "+ package nginx" in text and "⚪ nginx" in text


def test_the_panel_offers_install_for_a_protocol_not_on_the_host() -> None:
    modules = [ProtocolModule(name=n, enabled=True) for n in PROTOCOL_NAMES]
    markup = modules_panel_keyboard(modules, frozenset(), frozenset(), frozenset({"xray"}))
    rows = [[(b.text, b.callback_data) for b in row] for row in markup.inline_keyboard]
    xray = next(r for r in rows if r[0][0].endswith("Xray (VLESS+Reality)"))
    assert xray[0][0].startswith("📦") and xray[1][1] == "admin:module:install:xray"
    # Removed from the host (its marker): the locked «Enable», not an install (W2b offers the reinstall).
    markup = modules_panel_keyboard(modules, frozenset({"xray"}), frozenset(), frozenset({"xray"}))
    rows = [[b.callback_data for b in row] for row in markup.inline_keyboard]
    assert "admin:module:install:xray" not in {d for r in rows for d in r}


# --------------------------------------------------------------------------- #
# The handler: «📦 Установить» → TOTP → the run's plan on THIS message
# --------------------------------------------------------------------------- #
class _HandlerWizard:
    def __init__(self) -> None:
        from test_admin_wizard_handlers import FakeWizard

        self.inner = FakeWizard()
        self.hooks: dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def register_after_success(self, mode: str, hook: Any) -> None:
        self.hooks[mode] = hook


class _Totp:
    def __init__(self) -> None:
        self.enabled = True

    async def is_enabled(self, user_id: int) -> bool:
        return self.enabled

    def is_elevated(self, user_id: int) -> bool:
        return False


def _handler_world(tmp_path: Path, totp: Any = None) -> Any:
    from types import SimpleNamespace

    wizard = _HandlerWizard()
    users = _Users()
    install = ProtocolInstallService(wizard=wizard, users=users, registry=_Registry(), root=tmp_path)  # type: ignore[arg-type]
    return SimpleNamespace(protocol_install=install, wizard=wizard, users=users, totp=totp, settings=None)


@pytest.fixture
def _private(monkeypatch: pytest.MonkeyPatch) -> None:
    import bot.handlers.admin_modules as handlers

    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(handlers, "ensure_private_callback", yes)


async def test_the_install_button_starts_the_run_on_this_message(tmp_path: Path, _private: None) -> None:
    import bot.handlers.admin_modules as handlers
    from test_admin_fallback_ui import FakeCallback, _fsm

    services = _handler_world(tmp_path)
    cb = FakeCallback("admin:module:install:xray")
    cb.from_user.id = ADMIN
    await handlers.admin_module_install(cb, services, _fsm())  # type: ignore[arg-type]
    assert services.wizard.inner.started == [("protocol", {"chat_id": cb.message.chat.id, "message_id": cb.message.message_id})]
    assert cb.message.edits, "the run's screen replaces the panel"


async def test_the_install_button_asks_the_totp_code_first(tmp_path: Path, _private: None) -> None:
    import bot.handlers.admin_modules as handlers
    from test_admin_fallback_ui import FakeCallback, _fsm

    services = _handler_world(tmp_path, totp=_Totp())
    cb = FakeCallback("admin:module:install:xray")
    cb.from_user.id = ADMIN
    await handlers.admin_module_install(cb, services, _fsm())  # type: ignore[arg-type]
    assert services.wizard.inner.started == [], "no run before the code"


async def test_the_install_button_is_refused_for_an_installed_protocol(tmp_path: Path, _private: None) -> None:
    import bot.handlers.admin_modules as handlers
    from test_admin_fallback_ui import FakeCallback, _fsm

    _lay(tmp_path, *HOST_PROBES["xray"])
    services = _handler_world(tmp_path)
    cb = FakeCallback("admin:module:install:xray")
    cb.from_user.id = ADMIN
    await handlers.admin_module_install(cb, services, _fsm())  # type: ignore[arg-type]
    assert services.wizard.inner.started == [] and any(alert for alert, _ in cb.alerts)
