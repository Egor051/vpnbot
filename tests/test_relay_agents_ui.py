"""«🧙 Мастер настройки → 🛰 Relay» (bot/handlers/admin_relay_agents.py).

Driven against the REAL RelayAgentService on SQLite (tests/test_relay_agents.py's
World: a fake SSH client, injected probes):

* the wizard menu offers «🛰 Relay»; SUPERADMIN only;
* «Добавить» asks the TOTP code first (when TOTP is on), then name → target → the
  pairing screen with the one command;
* «Подключить» → the relay's address → registered; a failed check offers a retry;
* «Порты / цель» checks the elevation again at the typed step;
* «Удалить» → uninstall; a relay that does not answer offers «only the record».
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from test_relay import ADMIN
from test_relay_agents import RELAY_IP, TARGET, World

from bot.fsm.states import RelayWizardStates, TotpStates
from bot.handlers import admin_relay_agents as ui
from bot.totp_gate import DANGEROUS_ACTIONS
from bot.wizard_views import menu_keyboard
from i18n import t
from services.errors import AccessDenied, ServiceError
from services.relay_health import ProbeResult
from services.relay_ssh import AgentReply

pytestmark = pytest.mark.timeout(60)


class FakeTotp:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.elevated = False

    async def is_enabled(self, user_id: int) -> bool:
        return self.enabled

    def is_elevated(self, user_id: int) -> bool:
        return self.elevated


class Users:
    def __init__(self, superadmin: bool = True) -> None:
        self.superadmin = superadmin

    async def require_superadmin(self, user_id: int) -> object:
        if not self.superadmin:
            raise AccessDenied("Недостаточно прав", key="err_insufficient_rights")
        return object()


class Health:
    def last_probe(self, relay_id: int) -> ProbeResult | None:
        return None


class Msg:
    def __init__(self, text: str = "") -> None:
        self.message_id = 10
        self.text = text
        self.chat = SimpleNamespace(id=ADMIN, type="private")
        self.from_user = SimpleNamespace(id=ADMIN)
        self.edits: list[str] = []
        self.answers: list[Msg] = []
        self.markups: list[Any] = []
        self.body = ""

    async def answer(self, text: str, reply_markup: Any = None, **_: Any) -> Msg:
        reply = Msg()
        reply.body = text
        reply.markups.append(reply_markup)
        self.answers.append(reply)
        return reply


class Callback:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=ADMIN)
        self.message = Msg()
        self.alerts: list[tuple[str | None, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **_: Any) -> None:
        self.alerts.append((text, show_alert))


@pytest.fixture(autouse=True)
def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(*_: Any) -> bool:
        return True

    async def edit(message: Any, text: str, reply_markup: Any = None, **_: Any) -> bool:
        message.edits.append(text)
        message.markups.append(reply_markup)
        return True

    monkeypatch.setattr(ui, "ensure_private_callback", ok)
    monkeypatch.setattr(ui, "ensure_private_message", ok)
    monkeypatch.setattr(ui, "safe_edit_message_text", edit)


def fsm() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=ADMIN, user_id=ADMIN))


@pytest.fixture
async def env(tmp_path: Any) -> Any:
    world = await World(tmp_path).start()
    services = SimpleNamespace(
        relay_agents=world.service, relays=world.relays, relay_health=Health(), totp=FakeTotp(False), users=Users()
    )
    yield world, services
    await world.close()


def _buttons(markup: Any) -> list[str]:
    return [b.callback_data for row in markup.inline_keyboard for b in row]


def test_the_wizard_menu_offers_relay() -> None:
    assert "wrl:menu" in _buttons(menu_keyboard(active=None, daily=False))


def test_relay_actions_are_dangerous() -> None:
    assert {"relay_pair", "relay_update", "relay_apply", "relay_uninstall"} <= set(DANGEROUS_ACTIONS)


async def test_only_a_superadmin_sees_the_section(env: Any) -> None:
    _, services = env
    services.users.superadmin = False
    cb = Callback("wrl:menu")
    await ui.relay_menu(cb, fsm(), services)  # type: ignore[arg-type]
    assert cb.alerts and cb.alerts[-1][1] is True
    assert cb.message.edits == []


async def test_add_asks_the_totp_code_first(env: Any) -> None:
    _, services = env
    services.totp.enabled = True
    state = fsm()
    await ui.relay_add(Callback("wrl:add"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.gate_code.state


async def _issue_via_ui(services: Any, state: FSMContext) -> str:
    cb = Callback("wrl:add")
    await ui.relay_add(cb, state, services)  # type: ignore[arg-type]
    assert await state.get_state() == RelayWizardStates.add_name.state
    assert "wrl:nm" in _buttons(cb.message.markups[-1])
    await ui.relay_add_name(Msg("ru2"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == RelayWizardStates.add_target.state
    cb = Callback("wrl:tg")
    await ui.relay_add_default_target(cb, state, services)  # type: ignore[arg-type]
    assert await state.get_state() is None
    return cb.message.edits[-1]


async def test_add_flow_shows_the_command(env: Any) -> None:
    world, services = env
    text = await _issue_via_ui(services, fsm())
    pending = await world.repo.list_pending()
    assert len(pending) == 1 and pending[0].name == "ru2" and pending[0].target_host == TARGET
    assert "install.sh --relay" in text and "sha256sum -c" in text
    assert pending[0].token not in text or "printf" in text  # the token travels only inside the code


async def test_connect_registers_the_relay(env: Any) -> None:
    world, services = env
    await _issue_via_ui(services, fsm())
    pairing = (await world.repo.list_pending())[0]
    state = fsm()
    await ui.relay_connect(Callback(f"wrl:pc:{pairing.id}"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == RelayWizardStates.pair_address.state
    msg = Msg(f"{RELAY_IP}:22")
    await ui.relay_connect_address(msg, state, services)  # type: ignore[arg-type]
    progress = msg.answers[-1]
    assert "ru2" in progress.edits[-1] and t("relay_wiz_health_on", interval=300) in progress.edits[-1]
    assert await state.get_state() is None
    assert await world.relay_repo.count() == 1


async def test_a_failed_check_offers_a_retry(env: Any) -> None:
    world, services = env
    await _issue_via_ui(services, fsm())
    pairing = (await world.repo.list_pending())[0]
    world.tcp[0] = False
    state = fsm()
    await state.set_state(RelayWizardStates.pair_address)
    await state.update_data(relay_wiz_pairing=pairing.id)
    msg = Msg(RELAY_IP)
    await ui.relay_connect_address(msg, state, services)  # type: ignore[arg-type]
    progress = msg.answers[-1]
    assert "TCP FAIL" in progress.edits[-1]
    assert f"wrl:pc:{pairing.id}" in _buttons(progress.markups[-1])
    assert await world.relay_repo.count() == 0


async def _paired(world: World) -> int:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    return (await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)).relay.id


async def test_forward_rechecks_the_elevation(env: Any) -> None:
    world, services = env
    relay_id = await _paired(world)
    services.totp.enabled = True
    services.totp.elevated = True
    state = fsm()
    await ui.relay_forward(Callback(f"wrl:fw:{relay_id}"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == RelayWizardStates.forward.state
    services.totp.elevated = False  # five minutes later
    msg = Msg("new.example.com tcp=443 udp=443")
    calls = len(world.client.calls)
    await ui.relay_forward_input(msg, state, services)  # type: ignore[arg-type]
    assert msg.answers[-1].body == t("relay_wiz_reauth")
    assert len(world.client.calls) == calls, "nothing reached the relay"


async def test_forward_applies(env: Any) -> None:
    world, services = env
    relay_id = await _paired(world)
    world.client.replies["apply"] = AgentReply(0, {"ok": True})
    state = fsm()
    await ui.relay_forward(Callback(f"wrl:fw:{relay_id}"), state, services)  # type: ignore[arg-type]
    msg = Msg("new.example.com udp=443")
    await ui.relay_forward_input(msg, state, services)  # type: ignore[arg-type]
    assert world.client.calls[-1]["request"] == "apply target=new.example.com tcp=443 udp=443"
    assert t("relay_wiz_forward_done") in msg.answers[-1].edits[-1]


@pytest.mark.parametrize(
    ("text", "expected"),
    [("a.example.com", ("a.example.com", "", "")), ("a.example.com tcp=443,8443", ("a.example.com", "443,8443", "")),
     ("a.example.com udp=443 tcp=443", ("a.example.com", "443", "443"))],
)
def test_parse_forward_input(text: str, expected: tuple[str, str, str]) -> None:
    assert ui.parse_forward_input(text) == expected


@pytest.mark.parametrize("text", ["", "a b c d", "a.example.com sctp=1", "a.example.com tcp=1 tcp=2"])
def test_parse_forward_input_refuses(text: str) -> None:
    with pytest.raises(ServiceError):
        ui.parse_forward_input(text)


async def test_delete_unreachable_offers_the_record_only(env: Any) -> None:
    world, services = env
    relay_id = await _paired(world)
    world.client.replies["uninstall"] = AgentReply(4, {"ok": False, "error": "connection refused"})
    cb = Callback(f"wrl:dk:{relay_id}:0")
    await ui.relay_delete_confirm(cb, fsm(), services)  # type: ignore[arg-type]
    assert f"wrl:dr:{relay_id}:0" in _buttons(cb.message.markups[-1])
    assert await world.relay_repo.get_by_id(relay_id) is not None
    cb = Callback(f"wrl:dr:{relay_id}:0")
    await ui.relay_delete_confirm(cb, fsm(), services)  # type: ignore[arg-type]
    assert await world.relay_repo.get_by_id(relay_id) is None


async def test_delete_asks_the_totp_code(env: Any) -> None:
    world, services = env
    relay_id = await _paired(world)
    services.totp.enabled = True
    state = fsm()
    await ui.relay_delete_confirm(Callback(f"wrl:dk:{relay_id}:0"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.gate_code.state
    assert await world.relay_repo.get_by_id(relay_id) is not None


async def test_card_and_status(env: Any) -> None:
    world, services = env
    relay_id = await _paired(world)
    world.client.replies["status"] = AgentReply(0, {"ok": True, "agent": "1", "live_target": "192.0.2.10",
                                                    "check": {"rc": 0, "lines": []}})
    cb = Callback(f"wrl:st:{relay_id}")
    await ui.relay_status(cb, services)  # type: ignore[arg-type]
    text = cb.message.edits[-1]
    assert "192.0.2.10" in text and "exit 0" in text
    buttons = _buttons(cb.message.markups[-1])
    assert {f"wrl:up:{relay_id}", f"wrl:fw:{relay_id}", f"wrl:del:{relay_id}"} <= set(buttons)
    assert all(len(b.encode()) <= 64 for b in buttons)
