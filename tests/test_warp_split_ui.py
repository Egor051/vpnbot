"""Tests for the WARP selective-split inline GUI (bot/handlers/admin_warp_split_ui).

These exercise the presentation layer with a mocked WarpSplitManager and mocked
aiogram CallbackQuery/Message/FSMContext — no real Telegram, no shell, no helper.

Covered:
  * panel renders the list straight from the manager
  * add: FSM input is parsed and passed to manager.process_add_tokens + apply_list
  * delete: confirm then execute calls manager.process_del_tokens + apply_list
  * del-to-empty refusal is shown in the UI without crashing
  * pagination splits the list into pages with prev/next
  * apply re-applies the current list
  * superadmin gate on a callback and on the FSM input handler
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import bot.handlers.admin_warp_split_ui as mod
from bot.fsm.states import WarpSplitStates
from bot.handlers.admin_warp_split_ui import (
    warp_split_add_receive,
    warp_split_add_start,
    warp_split_apply,
    warp_split_del_confirm,
    warp_split_del_execute,
    warp_split_panel,
)
from i18n import t
from services.errors import AccessDenied
from warp.split_manager import CidrResult, WarpSplitError


# ── manager + aiogram mocks ──────────────────────────────────────────────────


class FakeSplit:
    """Records the manager calls the GUI makes; never touches a shell or file."""

    def __init__(self, entries: list[str] | None = None, *, del_error: Exception | None = None) -> None:
        self._entries = list(entries or [])
        self.add_calls: list[tuple[list[str], set[str]]] = []
        self.del_calls: list[tuple[list[str], list[str]]] = []
        self.apply_calls: list[list[str]] = []
        self._del_error = del_error

    def read_list(self) -> list[str]:
        return list(self._entries)

    def process_add_tokens(self, tokens: list[str], current: set[str]) -> tuple[list[CidrResult], list[str]]:
        self.add_calls.append((list(tokens), set(current)))
        results = [CidrResult(raw=tok, canonical=tok, status="added") for tok in tokens]
        return results, list(tokens)

    def process_del_tokens(self, tokens: list[str], current: list[str]) -> tuple[list[CidrResult], list[str]]:
        self.del_calls.append((list(tokens), list(current)))
        if self._del_error is not None:
            raise self._del_error
        drop = set(tokens)
        results = [CidrResult(raw=tok, canonical=tok, status="removed") for tok in tokens]
        remaining = [c for c in current if c not in drop]
        return results, remaining

    async def apply_list(self, cidr_list: list[str]) -> None:
        self.apply_calls.append(list(cidr_list))


class _Message:
    def __init__(self, text: str | None = None) -> None:
        self.text = text
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.chat = SimpleNamespace(id=1, type="private")
        self.edits: list[tuple[str, object]] = []
        self.answers: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))

    async def answer(self, text: str, reply_markup: object = None) -> None:
        self.answers.append((text, reply_markup))


class _Callback:
    def __init__(self, data: str) -> None:
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _State:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self.data = data or {}
        self.cleared = False
        self.state: object = None

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def update_data(self, **kwargs: object) -> None:
        self.data.update(kwargs)

    async def set_state(self, state: object) -> None:
        self.state = state

    async def clear(self) -> None:
        self.cleared = True
        self.state = None
        self.data.clear()


async def _ok_cb(callback: object, text: str | None = None) -> bool:
    return True


async def _ok_msg(message: object, text: str | None = None) -> bool:
    return True


def _services(split: FakeSplit, *, superadmin: bool = True) -> SimpleNamespace:
    class Users:
        async def require_superadmin(self, user_id: int) -> object:
            if not superadmin:
                raise AccessDenied("Нет доступа")
            return SimpleNamespace(id=user_id)

    return SimpleNamespace(users=Users(), warp_split=split)


def _buttons(markup: object) -> list[tuple[str, str | None]]:
    return [(b.text, b.callback_data) for row in markup.inline_keyboard for b in row]


# ── panel ────────────────────────────────────────────────────────────────────


def test_panel_renders_entries_from_manager(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit(["1.0.0.0/24", "2.0.0.0/24"])
    cb = _Callback("wsplit:p:0")
    st = _State()

    asyncio.run(warp_split_panel(cb, st, _services(split)))  # type: ignore[arg-type]

    assert st.cleared is True
    text, markup = cb.message.edits[-1]
    assert "префиксов: 2" in text
    btns = _buttons(markup)
    assert ("1.0.0.0/24", "noop") in btns
    assert ("🗑", "wsplit:del:1.0.0.0/24") in btns
    assert any(data == "wsplit:add" for _, data in btns)
    # Split GUI is entered from WARP settings, so Back returns there.
    assert ("‹ К настройкам", "admin:warp:settings") in btns


def test_empty_panel_has_no_apply_button(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit([])
    cb = _Callback("wsplit:p:0")

    asyncio.run(warp_split_panel(cb, _State(), _services(split)))  # type: ignore[arg-type]

    btns = _buttons(cb.message.edits[-1][1])
    assert any(data == "wsplit:add" for _, data in btns)
    assert all(data != "wsplit:apply" for _, data in btns)
    assert "префиксов: 0" in cb.message.edits[-1][0]


# ── add (FSM) ────────────────────────────────────────────────────────────────


def test_add_start_sets_state_and_prompts(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    cb = _Callback("wsplit:add")
    st = _State()

    asyncio.run(warp_split_add_start(cb, st, _services(FakeSplit([]))))  # type: ignore[arg-type]

    assert st.state == WarpSplitStates.waiting_cidrs
    text, markup = cb.message.edits[-1]
    assert "CIDR" in text
    assert _buttons(markup) == [(t("btn_cancel"), "wsplit:p:0")]


def test_add_receive_parses_and_applies(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_message", _ok_msg)
    split = FakeSplit(["9.9.9.0/24"])
    msg = _Message("91.108.4.0/22, 142.250.0.0/15")
    st = _State()

    asyncio.run(warp_split_add_receive(msg, st, _services(split)))  # type: ignore[arg-type]

    assert split.add_calls
    tokens, current = split.add_calls[-1]
    assert tokens == ["91.108.4.0/22", "142.250.0.0/15"]
    assert current == {"9.9.9.0/24"}
    assert split.apply_calls
    assert set(split.apply_calls[-1]) == {"9.9.9.0/24", "91.108.4.0/22", "142.250.0.0/15"}
    assert st.cleared is True
    # panel re-sent as a fresh message after the report
    assert msg.answers
    assert "split-маршруты" in msg.answers[-1][0]


def test_add_receive_no_tokens_keeps_waiting(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_message", _ok_msg)
    split = FakeSplit(["9.9.9.0/24"])
    msg = _Message("   ")
    st = _State()

    asyncio.run(warp_split_add_receive(msg, st, _services(split)))  # type: ignore[arg-type]

    assert split.add_calls == []
    assert split.apply_calls == []
    assert st.cleared is False
    assert msg.answers


# ── delete (confirm → execute) ───────────────────────────────────────────────


def test_del_confirm_shows_yes_no(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit(["1.0.0.0/24", "2.0.0.0/24"])
    cb = _Callback("wsplit:del:1.0.0.0/24")

    asyncio.run(warp_split_del_confirm(cb, _services(split)))  # type: ignore[arg-type]

    text, markup = cb.message.edits[-1]
    assert "1.0.0.0/24" in text
    assert _buttons(markup) == [
        ("✅ Да", "wsplit:delok:1.0.0.0/24"),
        ("❌ Нет", "wsplit:p:0"),
    ]
    assert split.apply_calls == []  # confirm must not mutate


def test_del_execute_removes_via_manager(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit(["1.0.0.0/24", "2.0.0.0/24"])
    cb = _Callback("wsplit:delok:1.0.0.0/24")

    asyncio.run(warp_split_del_execute(cb, _services(split)))  # type: ignore[arg-type]

    assert split.del_calls
    tokens, current = split.del_calls[-1]
    assert tokens == ["1.0.0.0/24"]
    assert current == ["1.0.0.0/24", "2.0.0.0/24"]
    assert split.apply_calls == [["2.0.0.0/24"]]


def test_del_to_empty_shows_refusal(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit(
        ["1.0.0.0/24"],
        del_error=WarpSplitError("удаление опустошит список — отказано."),
    )
    cb = _Callback("wsplit:delok:1.0.0.0/24")

    asyncio.run(warp_split_del_execute(cb, _services(split)))  # type: ignore[arg-type]

    assert split.apply_calls == []  # nothing applied
    text, _markup = cb.message.edits[-1]
    assert "Отказ" in text
    assert "опустош" in text.lower()


# ── pagination ───────────────────────────────────────────────────────────────


def test_pagination_splits_into_pages(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    entries = [f"10.0.{i}.0/24" for i in range(20)]  # 3 pages of 8/8/4
    split = FakeSplit(entries)

    cb0 = _Callback("wsplit:p:0")
    asyncio.run(warp_split_panel(cb0, _State(), _services(split)))  # type: ignore[arg-type]
    btns0 = _buttons(cb0.message.edits[-1][1])
    del_btns = [data for _, data in btns0 if data and data.startswith("wsplit:del:")]
    assert len(del_btns) == 8  # one 🗑 per prefix on the page
    assert (t("btn_next"), "wsplit:p:1") in btns0  # next exists
    assert all(data != "wsplit:p:-1" for _, data in btns0)  # no prev on first page
    # First page omits the prev control entirely — no placeholder "·" dot, matching
    # the main-menu FAQ pagination style.
    assert all(text != "·" for text, _ in btns0)
    assert all(text != t("btn_prev") for text, _ in btns0)

    cb1 = _Callback("wsplit:p:1")
    asyncio.run(warp_split_panel(cb1, _State(), _services(split)))  # type: ignore[arg-type]
    btns1 = _buttons(cb1.message.edits[-1][1])
    assert (t("btn_prev"), "wsplit:p:0") in btns1  # prev
    assert (t("btn_next"), "wsplit:p:2") in btns1  # next

    cb2 = _Callback("wsplit:p:2")
    asyncio.run(warp_split_panel(cb2, _State(), _services(split)))  # type: ignore[arg-type]
    btns2 = _buttons(cb2.message.edits[-1][1])
    # Last page omits the next control entirely — again, no placeholder dot.
    assert all(text != "·" for text, _ in btns2)
    assert all(text != t("btn_next") for text, _ in btns2)
    assert (t("btn_prev"), "wsplit:p:1") in btns2


# ── apply ────────────────────────────────────────────────────────────────────


def test_apply_reloads_current_list(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit(["1.0.0.0/24", "2.0.0.0/24"])
    cb = _Callback("wsplit:apply")

    asyncio.run(warp_split_apply(cb, _services(split)))  # type: ignore[arg-type]

    assert split.apply_calls == [["1.0.0.0/24", "2.0.0.0/24"]]
    assert "перезапущен" in cb.message.edits[-1][0]


def test_apply_empty_list_is_noop(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit([])
    cb = _Callback("wsplit:apply")

    asyncio.run(warp_split_apply(cb, _services(split)))  # type: ignore[arg-type]

    assert split.apply_calls == []
    assert "пуст" in cb.message.edits[-1][0].lower()


# ── superadmin gate ──────────────────────────────────────────────────────────


def test_gate_blocks_non_superadmin_callback(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit(["1.0.0.0/24"])
    cb = _Callback("wsplit:p:0")

    asyncio.run(warp_split_panel(cb, _State(), _services(split, superadmin=False)))  # type: ignore[arg-type]

    assert cb.message.edits == []  # nothing rendered
    assert cb.answers[-1] == ("Нет доступа", True)


def test_gate_blocks_non_superadmin_delete(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = FakeSplit(["1.0.0.0/24", "2.0.0.0/24"])
    cb = _Callback("wsplit:delok:1.0.0.0/24")

    asyncio.run(warp_split_del_execute(cb, _services(split, superadmin=False)))  # type: ignore[arg-type]

    assert split.del_calls == []
    assert split.apply_calls == []
    assert cb.message.edits == []
    assert cb.answers[-1] == ("Нет доступа", True)


def test_gate_blocks_non_superadmin_fsm_input(monkeypatch) -> None:
    monkeypatch.setattr(mod, "ensure_private_message", _ok_msg)
    split = FakeSplit(["1.0.0.0/24"])
    msg = _Message("91.108.4.0/22")
    st = _State()

    asyncio.run(warp_split_add_receive(msg, st, _services(split, superadmin=False)))  # type: ignore[arg-type]

    assert split.add_calls == []
    assert split.apply_calls == []
    assert st.cleared is True
    assert msg.answers  # an error reply was sent
