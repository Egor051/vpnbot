"""The «🛟 Режим фолбэка» screens (bot/handlers/admin_fallback.py, bot/fallback.py).

Driven against the real FallbackService of tests/test_fallback_mode.py (SQLite,
the in-memory Cloudflare, the hub's fake agent): what the admin sees, what each
button does, and — above all — that the DNS API token typed into the chat is
deleted at once and never echoed back.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import InlineKeyboardMarkup
from test_fallback_mode import HUB, MAIN, ORIGIN, TOKEN, ZONE, Fallback, _ready
from test_relay import ADMIN

from bot.fallback import fallback_state_line, fallback_text, names_text, preflight_text, report_text
from bot.fsm.states import AdminFallbackStates
from bot.handlers import admin_fallback
from bot.keyboards.admin_fallback import fallback_keyboard, name_tag, names_keyboard
from bot.keyboards.admin_relays import relay_card_keyboard, relays_list_keyboard
from bot.relays import relay_card_text
from services.fallback import NameResult, Preflight, PreflightItem, SwitchReport

pytestmark = pytest.mark.timeout(60)


class FakeMessage:
    def __init__(self, text: str = "", message_id: int = 10) -> None:
        self.text = text
        self.message_id = message_id
        self.chat = SimpleNamespace(id=ADMIN, type="private")
        self.from_user = SimpleNamespace(id=ADMIN, username="admin")
        self.answers: list[tuple[str, Any]] = []
        self.edits: list[tuple[str, Any]] = []
        self.deleted = False
        self.children: list[FakeMessage] = []

    async def answer(self, text: str, reply_markup: Any = None, **_: Any) -> FakeMessage:
        self.answers.append((text, reply_markup))
        child = FakeMessage(message_id=self.message_id + 1 + len(self.children))
        self.children.append(child)
        return child

    async def edit_text(self, text: str, reply_markup: Any = None, **_: Any) -> None:
        self.edits.append((text, reply_markup))

    async def delete(self) -> None:
        self.deleted = True

    def everything(self) -> str:
        texts = [t for t, _ in self.answers] + [t for t, _ in self.edits]
        texts += [child.everything() for child in self.children]
        return "\n".join(texts)


class FakeCallback:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=ADMIN, username="admin")
        self.message = FakeMessage()
        self.alerts: list[tuple[str | None, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **_: Any) -> None:
        self.alerts.append((text, show_alert))


def _fsm() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=ADMIN, user_id=ADMIN))


def _services(world: Fallback) -> Any:
    return SimpleNamespace(fallback=world.service, users=world.service.users, totp=None, settings=world.settings)


def _callbacks(markup: InlineKeyboardMarkup) -> list[str]:
    return [str(button.callback_data) for row in markup.inline_keyboard for button in row]


@pytest.fixture(autouse=True)
def _private_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fakes are not aiogram Messages; the private-chat guard is tested elsewhere."""

    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_fallback, "ensure_private_callback", yes)
    monkeypatch.setattr(admin_fallback, "ensure_private_message", yes)


@pytest.fixture
async def world(tmp_path: Any) -> Any:
    w = await Fallback(tmp_path).start()
    yield w
    await w.close()


# ── the token: deleted at once, never echoed ──────────────────────────────────


async def test_the_token_message_is_deleted_first_and_never_echoed(world: Fallback) -> None:
    world.token_file.delete()
    state = _fsm()
    await state.set_state(AdminFallbackStates.token)
    message = FakeMessage(TOKEN)
    await admin_fallback.fallback_token_input(message, state, _services(world))  # type: ignore[arg-type]
    assert message.deleted
    assert world.token_file.load() == TOKEN
    assert TOKEN not in message.everything()
    assert await state.get_state() is None
    assert TOKEN not in json.dumps([row["details"] for row in world.audit.rows], default=str)


async def test_a_refused_token_is_deleted_too_and_the_step_asks_again(world: Fallback) -> None:
    world.token_file.delete()
    world.cf.reject_token = True
    state = _fsm()
    await state.set_state(AdminFallbackStates.token)
    message = FakeMessage(TOKEN)
    await admin_fallback.fallback_token_input(message, state, _services(world))  # type: ignore[arg-type]
    assert message.deleted and not world.token_file.exists()
    assert TOKEN not in message.everything()
    assert await state.get_state() == AdminFallbackStates.token.state


async def test_a_message_that_cannot_be_deleted_says_so(world: Fallback) -> None:
    class Stuck(FakeMessage):
        async def delete(self) -> None:
            raise RuntimeError("message can't be deleted")

    state = _fsm()
    await state.set_state(AdminFallbackStates.token)
    message = Stuck(TOKEN)
    await admin_fallback.fallback_token_input(message, state, _services(world))  # type: ignore[arg-type]
    assert "удалите его вручную" in message.everything() or "delete it by hand" in message.everything()
    assert TOKEN not in message.everything()


# ── the screen and its buttons ────────────────────────────────────────────────


async def test_the_panel_and_every_callback_fits_telegram(world: Fallback) -> None:
    await _ready(world)
    callback = FakeCallback("admin:fb")
    await admin_fallback.fallback_panel(callback, _fsm(), _services(world))  # type: ignore[arg-type]
    text, markup = callback.message.edits[-1]
    assert "he1" in text and ORIGIN in text and ZONE in text and MAIN in text and HUB in text
    for data in _callbacks(markup):
        assert len(data.encode()) <= 64, data
    overview = await world.service.overview(ADMIN)
    candidates = ["a" * 60 + ".example.net"]
    for data in _callbacks(names_keyboard(overview, candidates)):
        assert len(data.encode()) <= 64, data


async def test_enable_through_the_buttons_then_the_relay_list_says_so(world: Fallback) -> None:
    await _ready(world)
    services = _services(world)
    confirm = FakeCallback("admin:fb:on")
    await admin_fallback.fallback_confirm(confirm, services)  # type: ignore[arg-type]
    assert _callbacks(confirm.message.edits[-1][1])[0] == "admin:fb:on:ok"
    run = FakeCallback("admin:fb:on:ok")
    await admin_fallback.fallback_switch(run, _fsm(), services)  # type: ignore[arg-type]
    final = run.message.edits[-1][0]
    assert ZONE in final and HUB in final
    overview = await world.service.overview(ADMIN)
    assert overview.state == "on"
    assert "he1" in fallback_state_line(overview)
    assert "admin:fb:off" in _callbacks(fallback_keyboard(overview))
    off = FakeCallback("admin:fb:off:ok")
    await admin_fallback.fallback_switch(off, _fsm(), services)  # type: ignore[arg-type]
    assert (await world.service.overview(ADMIN)).state == "off"


async def test_a_failing_preflight_is_shown_and_nothing_is_switched(world: Fallback) -> None:
    await _ready(world)
    world.cf.token_status = "disabled"
    callback = FakeCallback("admin:fb:pf")
    await admin_fallback.fallback_preflight(callback, _services(world))  # type: ignore[arg-type]
    assert "❌" in callback.message.edits[-1][0]
    run = FakeCallback("admin:fb:on:ok")
    await admin_fallback.fallback_switch(run, _fsm(), _services(world))  # type: ignore[arg-type]
    assert (await world.service.overview(ADMIN)).state == "off"


async def test_names_through_the_buttons(world: Fallback) -> None:
    await world.hub()
    services = _services(world)
    screen = FakeCallback("admin:fb:names")
    await admin_fallback.fallback_names(screen, _fsm(), services)  # type: ignore[arg-type]
    assert f"admin:fb:nadd:{name_tag(ZONE)}" in _callbacks(screen.message.edits[-1][1])
    add = FakeCallback(f"admin:fb:nadd:{name_tag(ZONE)}")
    await admin_fallback.fallback_name_add_suggested(add, _fsm(), services)  # type: ignore[arg-type]
    names = await world.repo.list_names()
    assert [n.name for n in names] == [ZONE]
    stale = FakeCallback(f"admin:fb:nadd:{name_tag('gone.example.net')}")
    await admin_fallback.fallback_name_add_suggested(stale, _fsm(), services)  # type: ignore[arg-type]
    assert stale.alerts and stale.alerts[0][1] is True
    state = _fsm()
    await state.set_state(AdminFallbackStates.name)
    typed = FakeMessage(ORIGIN)
    await admin_fallback.fallback_name_input(typed, state, services)  # type: ignore[arg-type]
    assert [n.name for n in await world.repo.list_names()] == [ZONE], "the origin can never join the set"
    assert await state.get_state() == AdminFallbackStates.name.state
    remove = FakeCallback(f"admin:fb:nrm:{names[0].id}")
    await admin_fallback.fallback_name_remove(remove, _fsm(), services)  # type: ignore[arg-type]
    assert await world.repo.list_names() == []


async def test_make_hub_from_the_card_with_the_suggested_origin(world: Fallback) -> None:
    relay = await world.relay("he1")
    card = relay_card_keyboard(relay, fallback=True)
    assert f"admin:fb:hub:{relay.id}" in _callbacks(card)
    assert f"admin:fb:hub:{relay.id}" not in _callbacks(relay_card_keyboard(relay))
    services = _services(world)
    start = FakeCallback(f"admin:fb:hub:{relay.id}")
    await admin_fallback.fallback_hub_start(start, _fsm(), services)  # type: ignore[arg-type]
    assert ORIGIN in start.message.answers[-1][0]
    go = FakeCallback(f"admin:fb:hub:{relay.id}:sug")
    await admin_fallback.fallback_hub_suggested(go, _fsm(), services)  # type: ignore[arg-type]
    hub = await world.relays_repo.get_by_id(relay.id)
    assert hub is not None and hub.is_hub
    assert f"admin:fb:unhub:{relay.id}" in _callbacks(relay_card_keyboard(hub, fallback=True))
    assert ORIGIN in relay_card_text(hub, active_keys=0, probe=None)
    unhub = FakeCallback(f"admin:fb:unhub:{relay.id}")
    await admin_fallback.fallback_hub_clear(unhub, _fsm(), services)  # type: ignore[arg-type]
    assert not (await world.relays_repo.get_by_id(relay.id)).is_hub  # type: ignore[union-attr]


async def test_origin_typed_by_hand_and_a_refusal(world: Fallback) -> None:
    relay = await world.relay("he1")
    await world.repo.add_name(ORIGIN, now="x", created_by=None)
    state = _fsm()
    await state.set_state(AdminFallbackStates.origin)
    await state.update_data({"relay_id": relay.id})
    message = FakeMessage(ORIGIN)
    await admin_fallback.fallback_origin_input(message, state, _services(world))  # type: ignore[arg-type]
    assert "❌" in message.everything()
    assert not (await world.relays_repo.get_by_id(relay.id)).is_hub  # type: ignore[union-attr]


async def test_settings_steps(world: Fallback) -> None:
    services = _services(world)
    world.cf.add(ZONE, MAIN)
    for which, value in (("main", "8.8.8.8"), ("hub", "-")):
        state = _fsm()
        await state.set_state(AdminFallbackStates.main_ipv4 if which == "main" else AdminFallbackStates.hub_ipv4)
        await admin_fallback.fallback_address_input(FakeMessage(value), state, services)  # type: ignore[arg-type]
        assert await state.get_state() is None
    assert await world.service.main_ipv4() == "8.8.8.8"
    state = _fsm()
    await state.set_state(AdminFallbackStates.main_ipv4)
    await admin_fallback.fallback_address_input(FakeMessage("10.1.1.1"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminFallbackStates.main_ipv4.state
    await world.service.set_address(ADMIN, "main", "-")
    state = _fsm()
    await state.set_state(AdminFallbackStates.direct_host)
    message = FakeMessage(ZONE)
    await admin_fallback.fallback_direct_input(message, state, services)  # type: ignore[arg-type]
    assert world.catalog.snapshot.direct_host == ZONE
    header = FakeCallback("admin:fb:subfb")
    await admin_fallback.fallback_sub_header(header, _fsm(), services)  # type: ignore[arg-type]
    assert await world.repo.sub_fallback_url() is True


async def test_the_relay_list_offers_the_screen_only_when_wired(world: Fallback) -> None:
    assert "admin:fb" in _callbacks(relays_list_keyboard([], fallback=True))
    assert "admin:fb" not in _callbacks(relays_list_keyboard([]))


async def test_unknown_fallback_buttons_lead_back_to_the_screen(world: Fallback) -> None:
    callback = FakeCallback("admin:fb:nonsense")
    await admin_fallback.stale_fallback_callback(callback, _fsm(), _services(world))  # type: ignore[arg-type]
    assert callback.alerts and callback.message.edits


# ── rendering ─────────────────────────────────────────────────────────────────


def test_reports_and_preflight_render() -> None:
    preflight = Preflight((
        PreflightItem("fb_pf_names", True, {"count": 2}),
        PreflightItem("fb_pf_record_aaaa", False, {"name": "<x>", "count": 1}, warning=True),
        PreflightItem("fb_pf_record_proxied", False, {"name": ZONE}),
    ))
    text = preflight_text(preflight)
    assert "❌" in text and "⚠️" in text and "&lt;x&gt;" in text
    blocked = report_text(SwitchReport(target="failover", preflight=preflight))
    assert ZONE in blocked
    done = report_text(SwitchReport(target="failover", preflight=None, results=(
        NameResult(name=ZONE, ok=True, ipv4=HUB),
        NameResult(name="relay.example.net", ok=False, ipv4=HUB, error="boom <b>"),
    )))
    assert "relay.example.net" in done and "boom &lt;b&gt;" in done


async def test_texts_of_a_partial_switch(world: Fallback) -> None:
    await _ready(world)
    world.cf.fail_writes.add("relay.example.net")
    await world.service.enable(ADMIN)
    overview = await world.service.overview(ADMIN)
    assert "⚠️" in fallback_text(overview) and "⚠️" in fallback_state_line(overview)
    assert "admin:fb:retry" in _callbacks(fallback_keyboard(overview))
    assert "relay.example.net" in names_text(overview, [])


async def test_cancelling_the_origin_step_from_the_relay_card_clears_it() -> None:
    """«Отмена» of «🛟 Сделать hub» opens the relay's page; the page abandons the
    origin step, so the next message is not taken as an origin."""
    from bot.handlers.admin_relays import _leave_relay_wizard

    state = _fsm()
    await state.set_state(AdminFallbackStates.origin)
    await state.update_data({"relay_id": 7})
    await _leave_relay_wizard(state)
    assert await state.get_state() is None
    assert await state.get_data() == {}
