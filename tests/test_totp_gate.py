"""The TOTP gate in front of dangerous actions (bot/totp_gate.py, bot/handlers/security.py).

* Open without TOTP, open while elevated, a prompt otherwise — and closed (refused)
  when a code is required but cannot be asked.
* A correct code turns the prompt into «▶️ Продолжить» carrying the very callback that
  was gated; a wrong one keeps asking; a lockout ends the dialog.
* The message carrying the code is deleted.
* Every gated call site names a registered action with a label; every dangerous
  wizard mode has its action.
* The protocol removal really stops at the gate.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage

from bot.fsm.states import TotpStates
from bot.handlers import admin_modules, security
from bot.totp_gate import (
    ACTION_KEY,
    DANGEROUS_ACTIONS,
    IN_PLACE_KEY,
    PROMPT_KEY,
    RESUME_KEY,
    UNDO_DATA,
    Resume,
    register_resume,
    require_totp,
    require_totp_in_place,
    screen_message,
)
from i18n import _CATALOGS
from services.totp import TotpError, TotpLocked, VerifyResult
from services.wizard_modes import MODES

ROOT = Path(__file__).resolve().parents[1]
UID = 555
pytestmark = pytest.mark.timeout(30)


class FakeTotp:
    def __init__(self, *, enabled: bool = True, elevated: bool = False) -> None:
        self.enabled = enabled
        self.elevated = elevated
        self.verify_result: Any = VerifyResult("totp", 10)
        self.verified: list[tuple[int, str, str]] = []

    async def is_enabled(self, user_id: int) -> bool:
        return self.enabled

    def is_elevated(self, user_id: int) -> bool:
        return self.elevated

    async def verify(self, user_id: int, code: str, *, purpose: str, allow_backup: bool = True) -> VerifyResult:
        self.verified.append((user_id, code, purpose))
        if isinstance(self.verify_result, Exception):
            raise self.verify_result
        self.elevated = True
        return self.verify_result  # type: ignore[no-any-return]


class FakeMessage:
    def __init__(self, message_id: int = 10, text: str = "") -> None:
        self.message_id = message_id
        self.text = text
        self.chat = SimpleNamespace(id=UID, type="private")
        self.from_user = SimpleNamespace(id=UID, username="op")
        self.answers: list[tuple[str, Any]] = []
        self.deleted = False
        self.edits: list[str] = []

    async def answer(self, text: str, reply_markup: Any = None, **_: Any) -> "FakeMessage":
        self.answers.append((text, reply_markup))
        return FakeMessage(message_id=self.message_id + 100)

    async def delete(self) -> None:
        self.deleted = True

    async def edit_text(self, text: str, reply_markup: Any = None, **_: Any) -> None:
        self.edits.append(text)


class FakeCallback:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=UID, username="op")
        self.message = FakeMessage()
        self.alerts: list[tuple[str | None, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **_: Any) -> None:
        self.alerts.append((text, show_alert))


class FakeBot:
    def __init__(self) -> None:
        self.edited: list[tuple[str, Any]] = []
        self.sent: list[tuple[str, Any]] = []

    async def edit_message_text(self, text: str, *, chat_id: int, message_id: int, reply_markup: Any = None) -> None:
        self.edited.append((text, reply_markup))

    async def send_message(self, chat_id: int, text: str, reply_markup: Any = None, **_: Any) -> FakeMessage:
        self.sent.append((text, reply_markup))
        return FakeMessage()


class FakeUsers:
    async def require_superadmin(self, user_id: int) -> object:
        return SimpleNamespace(telegram_user_id=user_id)


def fsm() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=UID, user_id=UID))


def services(totp: FakeTotp | None) -> Any:
    return SimpleNamespace(totp=totp, users=FakeUsers())


def _buttons(markup: Any) -> list[str]:
    return [b.callback_data for row in markup.inline_keyboard for b in row]


async def test_gate_is_open_without_totp_or_while_elevated() -> None:
    for totp in (None, FakeTotp(enabled=False), FakeTotp(elevated=True)):
        callback = FakeCallback("admin:module:uninst:xray:x:0123456789ab")
        state = fsm()
        assert await require_totp(callback, state, services(totp), action="protocol_uninstall")  # type: ignore[arg-type]
        assert await state.get_state() is None and callback.message.answers == []


async def test_gate_prompts_and_remembers_the_gated_button() -> None:
    callback = FakeCallback("admin:module:uninst:xray:x:0123456789ab")
    state = fsm()
    assert not await require_totp(callback, state, services(FakeTotp()), action="protocol_uninstall")  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.gate_code.state
    data = await state.get_data()
    assert data[RESUME_KEY] == callback.data and data[ACTION_KEY] == "protocol_uninstall"
    assert isinstance(data[PROMPT_KEY], int)
    (_text, markup), = callback.message.answers
    assert _buttons(markup) == ["sec:gate:cancel"]


async def test_gate_fails_closed_without_a_dialog() -> None:
    callback = FakeCallback("admin:module:uninst:xray:x:0123456789ab")
    assert not await require_totp(callback, None, services(FakeTotp()), action="protocol_uninstall")  # type: ignore[arg-type]
    assert callback.alerts and callback.alerts[-1][1] is True


async def test_gate_refuses_an_unregistered_action() -> None:
    with pytest.raises(ValueError):
        await require_totp(FakeCallback("x"), fsm(), services(FakeTotp()), action="format_disk")  # type: ignore[arg-type]


async def _prompted(totp: FakeTotp) -> FSMContext:
    state = fsm()
    await require_totp(FakeCallback("admin:relay:7:del:keys"), state, services(totp), action="relay_delete_keys")  # type: ignore[arg-type]
    return state


async def test_a_correct_code_gives_continue_with_the_original_callback() -> None:
    totp = FakeTotp()
    state = await _prompted(totp)
    message = FakeMessage(text="123 456")
    bot = FakeBot()
    await security.totp_gate_code(message, state, services(totp), bot)  # type: ignore[arg-type]
    assert message.deleted
    assert totp.verified == [(UID, "123 456", "gate:relay_delete_keys")]
    assert await state.get_state() is None
    _text, markup = bot.edited[-1]
    assert _buttons(markup) == ["admin:relay:7:del:keys"]


async def test_a_backup_code_says_how_many_are_left() -> None:
    totp = FakeTotp()
    totp.verify_result = VerifyResult("backup", 4)
    state = await _prompted(totp)
    bot = FakeBot()
    await security.totp_gate_code(FakeMessage(text="abcde-fghjk"), state, services(totp), bot)  # type: ignore[arg-type]
    assert "4" in bot.edited[-1][0]


async def test_a_wrong_code_keeps_asking() -> None:
    totp = FakeTotp()
    totp.verify_result = TotpError("bad", key="totp_invalid_code")
    state = await _prompted(totp)
    bot = FakeBot()
    message = FakeMessage(text="000000")
    await security.totp_gate_code(message, state, services(totp), bot)  # type: ignore[arg-type]
    assert message.deleted
    assert await state.get_state() == TotpStates.gate_code.state
    assert _buttons(bot.edited[-1][1]) == ["sec:gate:cancel"]


async def test_a_lockout_ends_the_dialog() -> None:
    totp = FakeTotp()
    totp.verify_result = TotpLocked(1_000_000_900, 1_000_000_000)
    state = await _prompted(totp)
    bot = FakeBot()
    await security.totp_gate_code(FakeMessage(text="000000"), state, services(totp), bot)  # type: ignore[arg-type]
    assert await state.get_state() is None
    assert bot.edited[-1][1] is None and "15" in bot.edited[-1][0]


async def test_protocol_removal_stops_at_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    applied: list[str] = []

    async def private(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_modules, "ensure_private_callback", private)
    monkeypatch.setattr(admin_modules, "uninstall_report_text", lambda report: "removed")

    class Uninstall:
        registry = SimpleNamespace(names=frozenset())

        def resolve_sha(self, *_: Any) -> str:
            return "0" * 64

        async def apply(self, name: str, sha: str, actor: int) -> Any:
            applied.append(name)
            return SimpleNamespace()

    class Modules:
        async def get_all(self) -> list[Any]:
            return []

    svc = SimpleNamespace(totp=FakeTotp(), users=FakeUsers(), protocol_uninstall=Uninstall(), modules=Modules(), settings=None)
    callback = FakeCallback("admin:module:uninst:xray:x:0123456789ab")
    state = fsm()
    await admin_modules.admin_module_uninstall_exec(callback, svc, state)  # type: ignore[arg-type]
    assert applied == []
    assert await state.get_state() == TotpStates.gate_code.state
    # elevated (a code was typed): the same button now goes through
    svc.totp.elevated = True
    await admin_modules.admin_module_uninstall_exec(FakeCallback(callback.data), svc, fsm())  # type: ignore[arg-type]
    assert applied == ["xray"]


def test_every_gated_call_site_names_a_registered_action() -> None:
    sites: list[tuple[str, str]] = []
    for path in (ROOT / "bot").rglob("*.py"):
        for m in re.finditer(r'require_totp(?:_in_place)?\([^)]*action="([a-z_]+)"', path.read_text(encoding="utf-8")):
            sites.append((path.name, m.group(1)))
    names = {action for _, action in sites}
    assert {"protocol_uninstall", "protocol_disable", "relay_delete_keys"} <= names, sites
    # Every relay action (one screen, every change gated) has a call site of its own.
    assert {action for action in DANGEROUS_ACTIONS if action.startswith("relay_")} <= names, sites
    assert names <= set(DANGEROUS_ACTIONS), sites
    for key, mode in MODES.items():
        if mode.dangerous:
            assert f"wizard_{key}" in DANGEROUS_ACTIONS, key
    for label in DANGEROUS_ACTIONS.values():
        for locale in ("ru", "en"):
            assert label in _CATALOGS[locale], (locale, label)


# ── in place: the code asked on the screen it confirms (one message, one confirmation) ──
_RESUMED: list[tuple[int, str]] = []


@register_resume(r"test:inplace:\d+")
async def _test_resume(resume: Resume) -> None:
    _RESUMED.append((resume.message.message_id, resume.data))


async def _in_place(totp: FakeTotp) -> tuple[FSMContext, FakeCallback]:
    state = fsm()
    callback = FakeCallback("test:inplace:1")

    async def edit(message: Any, text: str, reply_markup: Any = None, **_: Any) -> bool:
        message.edits.append(text)
        message.markup = reply_markup
        return True

    assert not await require_totp_in_place(  # type: ignore[arg-type]
        callback, state, services(totp), action="relay_update", screen="PLAN ⚪", resume="test:inplace:1",
        back="admin:relay:1", edit=edit,
    )
    return state, callback


async def test_in_place_the_code_is_asked_on_the_screen_itself() -> None:
    state, callback = await _in_place(FakeTotp())
    assert callback.message.answers == [], "no second message"
    assert callback.message.edits[-1].startswith("PLAN ⚪") and "🔐" in callback.message.edits[-1]
    assert _buttons(callback.message.markup) == [UNDO_DATA]  # type: ignore[attr-defined]
    data = await state.get_data()
    assert data[PROMPT_KEY] == callback.message.message_id and data[IN_PLACE_KEY] is True


async def test_in_place_a_correct_code_runs_the_action_on_that_screen() -> None:
    _RESUMED.clear()
    totp = FakeTotp()
    state, callback = await _in_place(totp)
    bot = FakeBot()
    await security.totp_gate_code(FakeMessage(text="123456"), state, services(totp), bot)  # type: ignore[arg-type]
    assert _RESUMED == [(callback.message.message_id, "test:inplace:1")], "the code was the confirmation"
    assert bot.edited == [], "no «▶️ Продолжить»"
    assert await state.get_state() is None


async def test_in_place_a_wrong_code_keeps_the_screen() -> None:
    _RESUMED.clear()
    totp = FakeTotp()
    totp.verify_result = TotpError("bad", key="totp_invalid_code")
    state, _ = await _in_place(totp)
    bot = FakeBot()
    await security.totp_gate_code(FakeMessage(text="000000"), state, services(totp), bot)  # type: ignore[arg-type]
    text, markup = bot.edited[-1]
    assert text.startswith("PLAN ⚪") and _buttons(markup) == [UNDO_DATA] and _RESUMED == []
    assert await state.get_state() == TotpStates.gate_code.state


async def test_in_place_cancel_clears_the_gate_and_leads_back(monkeypatch: pytest.MonkeyPatch) -> None:
    state, _ = await _in_place(FakeTotp())
    edits: list[tuple[str, Any]] = []

    async def edit(message: Any, text: str, reply_markup: Any = None, **_: Any) -> bool:
        edits.append((text, reply_markup))
        return True

    monkeypatch.setattr(security, "safe_edit_message_text", edit)
    await security.totp_gate_undo(FakeCallback(UNDO_DATA), state)  # type: ignore[arg-type]
    assert await state.get_state() is None
    assert _buttons(edits[-1][1]) == ["admin:relay:1"]


def test_the_screen_message_is_bound_to_the_bot() -> None:
    message = screen_message(FakeBot(), UID, 42)  # type: ignore[arg-type]
    assert (message.message_id, message.chat.id) == (42, UID)
