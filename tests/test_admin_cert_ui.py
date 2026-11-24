"""«🔐 Сертификат и DNS» (bot/handlers/admin_cert.py, services/cert.py).

Driven against the real DnsService of tests/test_fallback_mode.py (SQLite, the in-memory
Cloudflare), a fake privileged runner that answers ``vpn-bot-cert status --json`` with a
production-shaped report, and the fake wizard of tests/test_admin_wizard_handlers.py:
what the screen shows, which runs the buttons start (with which parameters), and that
the token typed into the chat is deleted at once, checked BEFORE it is stored and never
echoed back.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import InlineKeyboardMarkup
from test_admin_fallback_ui import FakeCallback, FakeMessage
from test_admin_wizard_handlers import FakeWizard
from test_fallback_mode import TOKEN, ZONE, Fallback
from test_relay import ADMIN

from bot.fsm.states import CertStates
from bot.handlers import admin_cert, admin_wizard
from bot.wizard_views import menu_keyboard
from models.dto import ShellResult
from services.cert import CertService
from utils.redact import forget_secret

pytestmark = pytest.mark.timeout(60)
NEW = "cfNEW_0123456789abcdefghijklmnopqrstuvw"


def report(*, adopted: bool = False, in_sync: bool = True) -> dict[str, Any]:
    """What vpn-bot-cert status says on the production host before / after adoption."""
    return {
        "version": 1, "reload_cmd": "/usr/local/sbin/vpn-bot-cert deploy",
        "acme": {"installed": True, "version": "3.1.1", "cron": True, "home": "/root/.acme.sh"},
        "domain": ZONE if adopted else None, "adopted": adopted, "candidate": None if adopted else ZONE, "ambiguous": [],
        "domains": [{
            "name": ZONE, "ecc": True, "names": [ZONE, f"www.{ZONE}"], "san": [ZONE, f"www.{ZONE}"],
            "keylength": "ec-256", "not_after": "2027-01-23T00:00:00Z", "days_left": 60.0, "key_ok": True,
            "reloadcmd": "/usr/local/sbin/vpn-bot-cert deploy" if adopted else "systemctl restart hysteria-server",
            "reloadcmd_kind": "ours" if adopted else "other", "real_paths": {},
            "token": {"source": "account", "fp": "deadbeef", "zone": None},
        }],
        "consumers": [
            {"name": "hysteria", "unit": "hysteria-server", "action": "restart", "installed": True, "why": "installed",
             "files": [], "in_sync": in_sync, "took_current": True, "reads_ok": True, "reads": ""},
            {"name": "nginx", "unit": "nginx", "action": "reload", "installed": True, "why": "installed",
             "files": [], "in_sync": True, "took_current": True, "reads_ok": None, "reads": ""},
            {"name": "subscription", "unit": "vpn-bot-subscription", "action": "try-restart", "installed": False,
             "why": "vpn-bot-subscription is not installed", "files": [], "in_sync": None, "took_current": None},
        ],
        "token": {"present": True, "fp": "abcd1234", "error": None},
        "problems": [] if adopted else [
            {"level": "red", "key": "reloadcmd", "text": f"{ZONE}: acme.sh's reloadcmd is 'systemctl restart hysteria-server'"},
        ],
        "verdict": "ok" if adopted else "fail",
    }


class Runner:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.calls: list[tuple[str, list[str]]] = []

    async def run(self, helper: Path, args: list[str], **_: Any) -> ShellResult:
        self.calls.append((str(helper), list(args)))
        return ShellResult(args=tuple(args), returncode=0, stdout=json.dumps(self.data) + "\n", stderr="")


def _fsm() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=ADMIN, user_id=ADMIN))


def _callbacks(markup: InlineKeyboardMarkup) -> list[str]:
    return [str(button.callback_data) for row in markup.inline_keyboard for button in row]


@pytest.fixture(autouse=True)
def _private_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_cert, "ensure_private_callback", yes)
    monkeypatch.setattr(admin_cert, "ensure_private_message", yes)
    monkeypatch.setattr(admin_wizard, "ensure_private_callback", yes)


class World:
    def __init__(self, fb: Fallback, tmp: Path, data: dict[str, Any]) -> None:
        self.fb = fb
        helper = tmp / "vpn-bot-cert"
        helper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.runner = Runner(data)
        self.wizard = FakeWizard()
        self.cert = CertService(runner=self.runner, wizard=self.wizard, dns=fb.dns_service,  # type: ignore[arg-type]
                                users=fb.service.users, settings=fb.settings, helper=helper)
        self.services = SimpleNamespace(cert=self.cert, dns=fb.dns_service, wizard=self.wizard,
                                        users=fb.service.users, totp=None, settings=fb.settings)


@pytest.fixture
async def world(tmp_path: Path) -> Any:
    fb = await Fallback(tmp_path).start()
    yield World(fb, tmp_path, report())
    forget_secret(NEW)
    await fb.close()


async def test_the_screen_shows_the_certificate_its_readers_and_offers_adoption(world: World) -> None:
    cb = FakeCallback("cert:menu")
    await admin_cert.cert_menu(cb, _fsm(), world.services)  # type: ignore[arg-type]
    text, markup = cb.message.edits[-1]
    assert ZONE in text and "2027-01-23" in text and "ec-256" in text
    assert "hysteria" in text and "vpn-bot-subscription is not installed" in text
    assert "systemctl restart hysteria-server" in text  # the reloadcmd that reaches only a part
    data = _callbacks(markup)
    assert "cert:go:adopt" in data and "cert:go:renew" not in data and "cert:token" in data
    assert world.runner.calls == [(str(world.cert.helper), ["status", "--json"])]


async def test_an_adopted_certificate_offers_the_renewal_and_a_lay_out_when_a_copy_differs(world: World) -> None:
    world.runner.data = report(adopted=True, in_sync=False)
    cb = FakeCallback("cert:menu")
    await admin_cert.cert_menu(cb, _fsm(), world.services)  # type: ignore[arg-type]
    data = _callbacks(cb.message.edits[-1][1])
    assert "cert:go:adopt" not in data and "cert:go:renew" in data and "cert:go:deploy" in data


async def test_adopt_starts_a_cert_run_with_its_plan_on_this_message(world: World) -> None:
    cb = FakeCallback("cert:go:adopt")
    await admin_cert.cert_go(cb, _fsm(), world.services)  # type: ignore[arg-type]
    assert world.wizard.started == [("cert", {"chat_id": ADMIN, "message_id": 10})]
    assert cb.message.edits, "the run's screen replaces this one"


async def test_issue_uses_the_typed_names_and_the_zone_the_token_sees(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, Any]] = []
    original = world.wizard.start

    async def start(actor: int, mode: str, raw: Any = None, **kw: Any) -> Any:
        seen.append(dict(raw or {}))
        return await original(actor, mode, raw, **kw)

    monkeypatch.setattr(world.wizard, "start", start)
    state = _fsm()
    await state.set_state(CertStates.names)
    await admin_cert.cert_names_input(FakeMessage(f"{ZONE}, API.{ZONE}"), state, world.services)  # type: ignore[arg-type]
    await admin_cert.cert_go(FakeCallback("cert:go:issue"), _fsm(), world.services)  # type: ignore[arg-type]
    assert seen == [{"action": "issue", "names": f"{ZONE},api.{ZONE}", "zone": ZONE}]
    # The defaults again afterwards: no status here, so HYSTERIA2_SNI.
    assert world.cert.chosen_names(ADMIN, None) == [ZONE]


async def test_bad_names_are_refused_and_asked_again(world: World) -> None:
    state = _fsm()
    await state.set_state(CertStates.names)
    msg = FakeMessage("not a name!, x")
    await admin_cert.cert_names_input(msg, state, world.services)  # type: ignore[arg-type]
    assert await state.get_state() == CertStates.names.state
    assert world.cert.chosen_names(ADMIN, None) == [ZONE]  # unchanged: the defaults


async def test_a_run_is_not_started_while_another_is_active(world: World) -> None:
    from test_admin_wizard_handlers import wizard_run

    world.wizard.running = wizard_run(mode="update")
    cb = FakeCallback("cert:go:renew")
    await admin_cert.cert_go(cb, _fsm(), world.services)  # type: ignore[arg-type]
    assert world.wizard.started == [] and cb.alerts and cb.alerts[-1][1] is True


async def test_the_token_is_deleted_first_checked_before_it_is_stored_and_never_echoed(world: World) -> None:
    world.fb.token_file.delete()
    world.fb.cf.no_edit = True  # a token that can read the zone but not edit it
    state = _fsm()
    await state.set_state(CertStates.token)
    msg = FakeMessage(NEW)
    await admin_cert.cert_token_input(msg, state, world.services)  # type: ignore[arg-type]
    assert msg.deleted and not world.fb.token_file.exists()
    assert "Zone · DNS · Edit" in msg.everything() or "DNS · Edit" in msg.everything()
    world.fb.cf.no_edit = False
    msg2 = FakeMessage(NEW)
    await admin_cert.cert_token_input(msg2, state, world.services)  # type: ignore[arg-type]
    assert msg2.deleted and world.fb.token_file.load() == NEW
    assert await state.get_state() is None
    for m in (msg, msg2):
        assert NEW not in m.everything() and TOKEN not in m.everything()
    assert world.fb.dns_service.token_fingerprint() in msg2.everything()


async def test_the_wizard_menu_opens_the_certificate_screen_not_a_bare_run(world: World) -> None:
    data = _callbacks(menu_keyboard(active=None, daily=False))
    assert "cert:menu" in data and "wiz:start:cert" not in data
    cb = FakeCallback("wiz:start:cert")
    services = SimpleNamespace(wizard=world.wizard, users=world.fb.service.users, totp=None)
    await admin_wizard.wizard_start(cb, _fsm(), services)  # type: ignore[arg-type]
    assert world.wizard.started == [] and cb.alerts[-1][1] is True
