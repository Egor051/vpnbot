"""The chat side of «🧭 Первичная настройка»: bot/handlers/first_setup.py and bot/setup_views.py
on the service of tests/test_first_setup.py (a real wizard_runs table, fakes of what it drives).

* Every button reaches the service and the message shows where the setup stands.
* The Cloudflare token's message is deleted FIRST, before anything reads it; when it cannot
  be deleted the superadmin is told to do it by hand. The token is in no reply.
* A wrong answer keeps the prompt (the FSM state stays) and says to try again.
* The steps, the waits, a failure, the end — rendered in ru and en, with the buttons each
  state needs, and only those.
* SetupNotifier edits the setup's own message, or sends a new one when it is gone.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.types import InlineKeyboardMarkup

import bot.handlers.first_setup as handlers
from bot.fsm.states import SetupStates
from bot.setup_views import offer_keyboard, setup_keyboard, setup_text
from db.database import Database
from i18n import t, use_locale
from services.first_setup import STEPS, SetupView
from test_admin_fallback_ui import FakeCallback, FakeMessage, _fsm
from test_first_setup import ADMIN, DOMAIN, HOST_IP, TOKEN, FakeUsers, World

pytestmark = pytest.mark.timeout(60)


@pytest.fixture
async def setup_world(tmp_path: Path) -> AsyncIterator[World]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, role, created_at, updated_at) VALUES (?, 'SUPERADMIN', 'x', 'x')", (ADMIN,)
    )
    await db.commit()
    try:
        yield World(db)
    finally:
        await db.close()


@pytest.fixture(autouse=True)
def _private(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fakes are not aiogram objects; the private-chat guard is tested elsewhere."""

    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(handlers, "ensure_private_callback", yes)
    monkeypatch.setattr(handlers, "ensure_private_message", yes)


def _services(svc: Any) -> Any:
    return SimpleNamespace(first_setup=svc, users=FakeUsers(), totp=None, settings=None)


def _cb(data: str) -> FakeCallback:
    cb = FakeCallback(data)
    cb.from_user.id = ADMIN
    return cb


def _msg(text: str) -> FakeMessage:
    m = FakeMessage(text)
    m.from_user.id = ADMIN
    return m


def _callbacks(markup: InlineKeyboardMarkup | None) -> list[str]:
    assert markup is not None
    return [str(b.callback_data) for row in markup.inline_keyboard for b in row]


def _view(**kw: Any) -> SetupView:
    base: dict[str, Any] = {"run_id": 7, "started_by": ADMIN, "chat_id": ADMIN, "message_id": 3, "step": "domain",
                            "states": {s: "wait" for s in STEPS}, "domain": "", "protocols": [], "child": None,
                            "waiting": "", "note": "", "notes": {}, "finished": ""}
    base.update(kw)
    return SetupView(**base)


# --------------------------------------------------------------------------- #
# The buttons and the typed answers
# --------------------------------------------------------------------------- #
async def test_start_shows_the_setup_on_this_message_and_asks_the_domain(setup_world: World) -> None:
    svc = setup_world.service()
    cb = _cb("setup:start")
    await handlers.setup_start(cb, _fsm(), _services(svc))  # type: ignore[arg-type]
    text, markup = cb.message.edits[-1]
    view = await svc.current()
    assert view is not None and view.message_id == cb.message.message_id
    assert t("setup_title", id=view.run_id) in text
    assert _callbacks(markup)[0] == f"setup:ask:domain:{view.run_id}"


async def test_the_domain_then_the_token_take_the_setup_to_the_protocols(setup_world: World) -> None:
    setup_world.resolved[DOMAIN] = [HOST_IP]
    setup_world.cert.covered = True
    svc = setup_world.service()
    services = _services(svc)
    state = _fsm()
    await handlers.setup_start(_cb("setup:start"), state, services)  # type: ignore[arg-type]
    view = await svc.current()
    assert view is not None
    rid = view.run_id

    ask = _cb(f"setup:ask:domain:{rid}")
    await handlers.setup_ask(ask, state, services)  # type: ignore[arg-type]
    assert await state.get_state() == SetupStates.domain.state
    assert ask.message.answers[-1][0] == t("setup_type_domain")
    typed = _msg(DOMAIN)
    await handlers.setup_domain_input(typed, state, services)  # type: ignore[arg-type]
    assert await state.get_state() is None
    assert _callbacks(typed.answers[-1][1])[0] == f"setup:ask:token:{rid}"

    await handlers.setup_ask(_cb(f"setup:ask:token:{rid}"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == SetupStates.token.state
    secret = _msg(TOKEN)
    await handlers.setup_token_input(secret, state, services)  # type: ignore[arg-type]
    assert secret.deleted, "the token's message goes away first"
    assert setup_world.dns.token == TOKEN
    _, markup = secret.answers[-1]
    assert TOKEN not in secret.everything()
    assert f"setup:go:{rid}" in _callbacks(markup), "the protocols are asked next"
    view = await svc.current()
    assert view is not None and view.message_id == secret.children[-1].message_id


async def test_a_wrong_domain_keeps_the_prompt(setup_world: World) -> None:
    svc = setup_world.service()
    services = _services(svc)
    state = _fsm()
    await handlers.setup_start(_cb("setup:start"), state, services)  # type: ignore[arg-type]
    view = await svc.current()
    assert view is not None
    await handlers.setup_ask(_cb(f"setup:ask:domain:{view.run_id}"), state, services)  # type: ignore[arg-type]
    typed = _msg("not a domain")
    await handlers.setup_domain_input(typed, state, services)  # type: ignore[arg-type]
    assert t("setup_try_again") in typed.answers[-1][0]
    assert await state.get_state() == SetupStates.domain.state


async def test_a_token_that_cannot_be_deleted_is_reported_and_still_never_echoed(setup_world: World) -> None:
    setup_world.resolved[DOMAIN] = [HOST_IP]
    svc = setup_world.service()
    services = _services(svc)
    state = _fsm()
    view = await svc.begin(ADMIN, chat_id=ADMIN)
    await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    await state.set_state(SetupStates.token)
    await state.update_data(setup_run=view.run_id)

    class Sticky(FakeMessage):
        async def delete(self) -> None:
            raise RuntimeError("message can't be deleted")

    secret = Sticky(TOKEN)
    secret.from_user.id = ADMIN
    await handlers.setup_token_input(secret, state, services)  # type: ignore[arg-type]
    assert secret.answers[0][0] == t("cert_token_delete_by_hand")
    assert TOKEN not in secret.everything()


async def test_the_protocol_toggles_and_the_confirmation_start_the_installs(setup_world: World) -> None:
    setup_world.dns.token = TOKEN
    setup_world.resolved[DOMAIN] = [HOST_IP]
    setup_world.cert.covered = True
    svc = setup_world.service()
    services = _services(svc)
    view = await svc.begin(ADMIN, chat_id=ADMIN)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    assert view.step == "protocols"
    rid = view.run_id

    cb = _cb(f"setup:proto:hysteria2:{rid}")
    await handlers.setup_toggle(cb, services)  # type: ignore[arg-type]
    buttons = cb.message.edits[-1][1].inline_keyboard
    marks = {str(b.callback_data): b.text for row in buttons for b in row}
    assert marks[f"setup:proto:hysteria2:{rid}"].startswith("⬜")
    assert marks[f"setup:proto:xray:{rid}"].startswith("☑️")

    go = _cb(f"setup:go:{rid}")
    await handlers.setup_confirm(go, _fsm(), services)  # type: ignore[arg-type]
    assert (t("setup_running"), None) in go.alerts
    assert [m for m, _, _ in setup_world.wizard.started] == ["protocol"]
    assert t("setup_step_install") in go.message.edits[-1][0]


async def test_refresh_later_cancel_and_an_unknown_run(setup_world: World) -> None:
    svc = setup_world.service()
    services = _services(svc)
    view = await svc.begin(ADMIN, chat_id=ADMIN)
    rid = view.run_id

    show = _cb(f"setup:show:{rid}")
    await handlers.setup_show(show, services)  # type: ignore[arg-type]
    assert t("setup_title", id=rid) in show.message.edits[-1][0]

    later = _cb("setup:later")
    await handlers.setup_later(later, services)  # type: ignore[arg-type]
    assert later.alerts == [(t("setup_later_hint"), True)]

    cancel = _cb(f"setup:cancel:{rid}")
    await handlers.setup_cancel(cancel, services)  # type: ignore[arg-type]
    text, markup = cancel.message.edits[-1]
    assert t("setup_cancelled") in text and _callbacks(markup) == ["admin:panel"]
    assert await svc.current() is None

    stale = _cb("setup:show:999")
    await handlers.setup_show(stale, services)  # type: ignore[arg-type]
    assert stale.alerts and stale.alerts[-1][1] is True, "an alert, not a crash"


async def test_a_failed_step_offers_retry_and_the_retry_runs_it_again(setup_world: World) -> None:
    setup_world.dns.token = TOKEN
    setup_world.resolved[DOMAIN] = [HOST_IP]
    svc = setup_world.service()
    services = _services(svc)
    view = await svc.begin(ADMIN, chat_id=ADMIN)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    assert view.step == "cert" and view.child is not None
    await setup_world.finish_child(svc, "failed", "nginx: reload failed")
    view = await svc.current()  # type: ignore[assignment]
    assert view is not None and view.waiting == "retry"
    assert _callbacks(setup_keyboard(view))[0] == f"setup:retry:{view.run_id}"
    assert "nginx: reload failed" in setup_text(view)

    retry = _cb(f"setup:retry:{view.run_id}")
    await handlers.setup_retry(retry, _fsm(), services)  # type: ignore[arg-type]
    assert [m for m, _, _ in setup_world.wizard.started] == ["cert", "cert"]
    assert f"setup:show:{view.run_id}" in _callbacks(retry.message.edits[-1][1])


async def test_the_totp_step_skip(setup_world: World) -> None:
    svc = setup_world.service()
    services = _services(svc)
    view = await svc.begin(ADMIN, chat_id=ADMIN)
    rid = view.run_id
    await setup_world.db.conn.execute("UPDATE wizard_runs SET current_step = 'totp', params_json = ? WHERE id = ?",
                                      ('{"domain": "%s", "waiting": "input"}' % DOMAIN, rid))
    await setup_world.db.commit()
    view = await svc.get(rid)
    assert _callbacks(setup_keyboard(view))[:3] == ["sec:totp:on", f"setup:totp:done:{rid}", f"setup:totp:skip:{rid}"]
    cb = _cb(f"setup:totp:skip:{rid}")
    await handlers.setup_totp(cb, services)  # type: ignore[arg-type]
    after = await svc.get(rid)
    assert after.states["totp"] == "skip" and after.step == "selfcheck"


async def test_without_the_service_every_button_says_so() -> None:
    services = SimpleNamespace(first_setup=None, users=FakeUsers(), totp=None, settings=None)
    cb = _cb("setup:start")
    await handlers.setup_start(cb, _fsm(), services)  # type: ignore[arg-type]
    assert cb.alerts and cb.alerts[-1][1] is True and not cb.message.edits


# --------------------------------------------------------------------------- #
# The views
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("locale", ["ru", "en"])
def test_every_state_renders_with_the_buttons_it_needs(locale: str) -> None:
    with use_locale(locale):
        ask_domain = _view(waiting="input")
        assert _callbacks(setup_keyboard(ask_domain)) == ["setup:ask:domain:7", "setup:cancel:7"]
        assert t("setup_ask_domain", domain="") in setup_text(ask_domain)

        protocols = _view(step="protocols", waiting="input", domain=DOMAIN, protocols=["xray"])
        cbs = _callbacks(setup_keyboard(protocols))
        assert "setup:go:7" in cbs and "setup:proto:hysteria2:7" in cbs and cbs[-1] == "setup:cancel:7"
        assert t("setup_protocols_chosen", chosen="VLESS").split(":")[0] in setup_text(protocols)

        running = _view(step="install", waiting="run", note="waiting for run #3 (protocol)",
                        states={**{s: "ok" for s in STEPS[:5]}, "install": "run"}, notes={"dns": "a <b> note"})
        text = setup_text(running)
        assert "waiting for run #3" in text and "a &lt;b&gt; note" in text, "notes are escaped"
        assert _callbacks(setup_keyboard(running)) == ["setup:show:7", "setup:cancel:7"]

        failed = _view(step="ufw", waiting="retry", note="ufw <failed>")
        assert "ufw &lt;failed&gt;" in setup_text(failed)
        assert _callbacks(setup_keyboard(failed)) == ["setup:retry:7", "setup:cancel:7"]

        for end, key in (("succeeded", "setup_done"), ("cancelled", "setup_cancelled")):
            done = _view(step="selfcheck", finished=end)
            assert t(key) in setup_text(done)
            assert _callbacks(setup_keyboard(done)) == ["admin:panel"]

        assert _callbacks(offer_keyboard()) == ["setup:start", "setup:later"]


# --------------------------------------------------------------------------- #
# SetupNotifier
# --------------------------------------------------------------------------- #
class _Bot:
    def __init__(self, edit_fails: bool = False) -> None:
        self.edit_fails = edit_fails
        self.edited: list[tuple[int, int]] = []
        self.sent: list[int] = []

    async def edit_message_text(self, text: str, *, chat_id: int, message_id: int, reply_markup: Any) -> None:
        if self.edit_fails:
            raise RuntimeError("message to edit not found")
        self.edited.append((chat_id, message_id))

    async def send_message(self, chat_id: int, text: str, reply_markup: Any) -> Any:
        self.sent.append(chat_id)
        return SimpleNamespace(message_id=50 + len(self.sent))


async def test_the_notifier_edits_its_message_or_sends_a_new_one(setup_world: World) -> None:
    svc = setup_world.service()
    view = await svc.begin(ADMIN, chat_id=ADMIN)
    await svc.attach_message(view.run_id, 9)
    view = await svc.get(view.run_id)

    bot = _Bot()
    await handlers.SetupNotifier(bot, svc)(view, False)  # type: ignore[arg-type]
    assert bot.edited == [(ADMIN, 9)] and bot.sent == []

    gone = _Bot(edit_fails=True)
    await handlers.SetupNotifier(gone, svc)(view, False)  # type: ignore[arg-type]
    assert gone.sent == [ADMIN]
    assert (await svc.get(view.run_id)).message_id == 51, "the new message is the setup's from now on"

    fresh = _Bot()
    await handlers.SetupNotifier(fresh, svc)(await svc.get(view.run_id), True)  # type: ignore[arg-type]
    assert fresh.edited == [] and fresh.sent == [ADMIN]
