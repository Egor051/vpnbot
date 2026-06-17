"""Tests for the main WARP panel after the split-routing rewire.

The On/Off/Restart buttons now drive the split ROUTES (WarpSplitManager), the
toggle label flips on the route intent (marker), the status lines come from
``status()``, and the Split-list entry moved into «Настройки WARP». These use
mocked aiogram objects + a fake WarpSplitManager — no Telegram, shell or helper.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import bot.handlers.admin_warp as mod
from bot.handlers.admin_warp import warp_disable, warp_enable, warp_main_text, warp_restart
from bot.keyboards.warp_keyboard import warp_main_keyboard, warp_settings_keyboard
from i18n import t
from services.errors import AccessDenied
from warp.split_manager import SplitStatus
from warp.state import WarpState


def _split_status(intended: str = "on", *, tunnel_up: bool = True, n_list: int = 2,
                  n_table: int | None = 2, in_sync: bool = True) -> SplitStatus:
    return SplitStatus(
        tunnel_up=tunnel_up,
        intended_state=intended,
        n_list=n_list,
        n_table=n_table,
        in_sync=in_sync,
    )


def _buttons(markup: object) -> list[tuple[str, str | None]]:
    return [(b.text, b.callback_data) for row in markup.inline_keyboard for b in row]


# ── keyboard: toggle flip + Split moved ───────────────────────────────────────


def test_main_keyboard_on_shows_disable() -> None:
    state = WarpState(enabled=True, routes_count=2)  # config_present (routes_count>0)
    kb = warp_main_keyboard(state, _split_status("on"))
    btns = _buttons(kb)
    assert (t("btn_warp_disable"), "admin:warp:disable") in btns
    assert (t("btn_warp_restart"), "admin:warp:restart") in btns
    assert all(d != "admin:warp:enable" for _, d in btns)
    # Split entry no longer on the main panel.
    assert all(d != "wsplit:p:0" for _, d in btns)


def test_main_keyboard_off_shows_enable() -> None:
    state = WarpState(enabled=True, routes_count=2)
    kb = warp_main_keyboard(state, _split_status("off", n_table=0, n_list=2))
    btns = _buttons(kb)
    assert (t("btn_warp_enable"), "admin:warp:enable") in btns
    assert (t("btn_warp_restart"), "admin:warp:restart") in btns
    assert all(d != "admin:warp:disable" for _, d in btns)


def test_main_keyboard_no_config_shows_upload_only() -> None:
    state = WarpState(routes_count=0)  # not config_present
    kb = warp_main_keyboard(state, _split_status("on"))
    btns = _buttons(kb)
    assert (t("btn_warp_upload"), "admin:warp:upload") in btns
    assert all(d not in ("admin:warp:enable", "admin:warp:disable") for _, d in btns)
    # Settings is still reachable (it hosts the Split entry).
    assert any(d == "admin:warp:settings" for _, d in btns)


def test_settings_keyboard_hosts_split_entry() -> None:
    btns = _buttons(warp_settings_keyboard())
    assert (t("btn_warp_split"), "wsplit:p:0") in btns
    assert (t("btn_warp_replace"), "admin:warp:upload") in btns
    assert (t("btn_warp_delete"), "admin:warp:delete") in btns
    # Split sits above the Back button.
    datas = [d for _, d in btns]
    assert datas.index("wsplit:p:0") < datas.index("admin:warp")


# ── text: routes line from status() ───────────────────────────────────────────


def test_text_on_shows_active_count() -> None:
    state = WarpState(enabled=True, routes_count=2)
    text = warp_main_text(state, _split_status("on", n_list=3, n_table=3))
    assert "3 CIDR" in text
    assert "table T" in text  # the routes-not-tunnel hint


def test_text_off_shows_disabled() -> None:
    state = WarpState(enabled=True, routes_count=2)
    text = warp_main_text(state, _split_status("off", n_table=0, n_list=2))
    assert "direct" in text.lower()


def test_text_drift_shown_as_warning() -> None:
    state = WarpState(enabled=True, routes_count=2)
    text = warp_main_text(state, _split_status("on", n_list=2, n_table=1, in_sync=False))
    assert "⚠️" in text


# ── handlers: buttons call the split manager ──────────────────────────────────


class _FakeSplit:
    def __init__(self, status: SplitStatus) -> None:
        self._status = status
        self.calls: list[str] = []

    async def enable(self) -> None:
        self.calls.append("enable")

    async def disable(self) -> None:
        self.calls.append("disable")

    async def restart_routes(self) -> None:
        self.calls.append("restart_routes")

    async def status(self) -> SplitStatus:
        return self._status


class _FakeWarp:
    def __init__(self, state: WarpState) -> None:
        self._state = state
        self.last_error: str | None = None

    async def get_state(self) -> WarpState:
        return self._state


class _Message:
    def __init__(self) -> None:
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.chat = SimpleNamespace(id=1, type="private")
        self.message_id = 7
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))


class _Callback:
    def __init__(self, data: str) -> None:
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kw: object) -> None:
        self.answers.append((text or "", show_alert))


def _services(split: _FakeSplit, warp: _FakeWarp, *, superadmin: bool = True) -> SimpleNamespace:
    class Users:
        async def require_superadmin(self, user_id: int) -> object:
            if not superadmin:
                raise AccessDenied("Нет доступа")
            return SimpleNamespace(id=user_id)

    return SimpleNamespace(users=Users(), warp=warp, warp_split=split)


async def _ok_cb(callback: object, text: str | None = None) -> bool:
    return True


def _run_handler(handler, data, monkeypatch, *, intended="on", superadmin=True):
    monkeypatch.setattr(mod, "ensure_private_callback", _ok_cb)
    split = _FakeSplit(_split_status(intended))
    warp = _FakeWarp(WarpState(enabled=True, routes_count=2))
    cb = _Callback(data)
    asyncio.run(handler(cb, _services(split, warp, superadmin=superadmin)))  # type: ignore[arg-type]
    return split, cb


def test_enable_handler_calls_split_enable(monkeypatch) -> None:
    split, cb = _run_handler(warp_enable, "admin:warp:enable", monkeypatch, intended="on")
    assert split.calls == ["enable"]
    assert cb.message.edits  # panel re-rendered


def test_disable_handler_calls_split_disable(monkeypatch) -> None:
    split, cb = _run_handler(warp_disable, "admin:warp:disable", monkeypatch, intended="off")
    assert split.calls == ["disable"]
    assert cb.message.edits


def test_restart_handler_calls_restart_routes(monkeypatch) -> None:
    split, cb = _run_handler(warp_restart, "admin:warp:restart", monkeypatch, intended="on")
    assert split.calls == ["restart_routes"]
    assert cb.message.edits


def test_enable_gate_blocks_non_superadmin(monkeypatch) -> None:
    split, cb = _run_handler(warp_enable, "admin:warp:enable", monkeypatch, superadmin=False)
    assert split.calls == []  # nothing toggled
    assert cb.answers[-1] == ("Нет доступа", True)
