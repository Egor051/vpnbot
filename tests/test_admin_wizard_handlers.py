"""The «🧙 Мастер настройки» handlers (bot/handlers/admin_wizard.py).

* SUPERADMIN only: anyone else is refused before the service is touched.
* A dangerous mode (dump, update) asks the TOTP code before it starts; a read-only,
  non-dangerous mode (selfcheck) starts at once.
* «⬆️ Обновить бота» is one message and one confirmation: the button turns THAT message
  into the plan (steps ⚪, «✅ Подтвердить» / «✖️ Отменить») — with TOTP, into the code
  prompt, the code starting the run by itself; the run starts confirmed.
* A press while a run is active: «уже идёт, запуск #N», nothing started, nothing edited.
* The run remembers the message it was started from, so the monitor edits THAT one.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage

from bot.fsm.states import TotpStates
from bot.handlers import admin_wizard
from bot.totp_gate import Resume, resumer_for
from i18n import t
from models.dto import WizardRun
from services.errors import AccessDenied
from services.wizard import StatusSnapshot

UID = 77
pytestmark = pytest.mark.timeout(30)


def wizard_run(**over: Any) -> WizardRun:
    base: dict[str, Any] = dict(
        id=5, mode="selfcheck", state="running", phase="execute", current_step="apply", params={}, started_by=UID,
        origin="manual", chat_id=UID, message_id=10, log_path="", summary="", plan_ready=False, active=True,
        created_at="t", updated_at="t", finished_at=None, reported_at=None,
    )
    base.update(over)
    return WizardRun(**base)


class FakeWizard:
    def __init__(self) -> None:
        import asyncio

        self.lock = asyncio.Lock()
        self.started: list[tuple[str, dict[str, Any]]] = []
        self.confirmed: list[int] = []
        self.planned = wizard_run(mode="update", state="planned", phase="plan", plan_ready=True)
        self.running: WizardRun | None = None

    def exclusive(self) -> Any:
        return self.lock

    async def active(self) -> WizardRun | None:
        return self.running

    async def start(self, actor: int, mode: str, raw: Any = None, **kw: Any) -> WizardRun:
        self.started.append((mode, kw))
        return wizard_run(mode=mode, message_id=kw.get("message_id"))

    async def get(self, run_id: int) -> WizardRun:
        return self.planned

    async def confirm(self, actor: int, run_id: int) -> WizardRun:
        self.confirmed.append(run_id)
        return wizard_run(mode="update", state="running")

    async def attach_message(self, *_: Any) -> None:
        return None

    async def snapshot(self, run_id: int) -> StatusSnapshot:
        return StatusSnapshot()


class FakeTotp:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    async def is_enabled(self, user_id: int) -> bool:
        return self.enabled

    def is_elevated(self, user_id: int) -> bool:
        return False


class Users:
    def __init__(self, superadmin: bool = True) -> None:
        self.superadmin = superadmin

    async def require_superadmin(self, user_id: int) -> object:
        if not self.superadmin:
            raise AccessDenied("Недостаточно прав", key="err_insufficient_rights")
        return object()


class Msg:
    def __init__(self) -> None:
        self.message_id = 10
        self.chat = SimpleNamespace(id=UID, type="private")
        self.edits: list[str] = []
        self.answers: list[str] = []

    async def edit_text(self, text: str, reply_markup: Any = None, **_: Any) -> None:
        self.edits.append(text)

    async def answer(self, text: str, reply_markup: Any = None, **_: Any) -> "Msg":
        self.answers.append(text)
        return Msg()


class Callback:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=UID)
        self.message = Msg()
        self.alerts: list[tuple[str | None, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **_: Any) -> None:
        self.alerts.append((text, show_alert))


@pytest.fixture(autouse=True)
def _private(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(*_: Any) -> bool:
        return True

    async def edit(message: Any, text: str, **_: Any) -> bool:
        message.edits.append(text)
        return True

    monkeypatch.setattr(admin_wizard, "ensure_private_callback", ok)
    monkeypatch.setattr(admin_wizard, "safe_edit_message_text", edit)


def fsm() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=UID, user_id=UID))


def services(*, totp: bool = True, superadmin: bool = True) -> Any:
    return SimpleNamespace(wizard=FakeWizard(), totp=FakeTotp(totp), users=Users(superadmin))


async def test_only_a_superadmin_reaches_the_wizard() -> None:
    svc = services(superadmin=False)
    cb = Callback("wiz:start:selfcheck")
    await admin_wizard.wizard_start(cb, fsm(), svc)  # type: ignore[arg-type]
    assert svc.wizard.started == [] and cb.alerts[-1][1] is True


async def test_selfcheck_starts_at_once_and_remembers_its_message() -> None:
    svc = services()
    cb = Callback("wiz:start:selfcheck")
    await admin_wizard.wizard_start(cb, fsm(), svc)  # type: ignore[arg-type]
    assert svc.wizard.started == [("selfcheck", {"chat_id": UID, "message_id": 10})]
    assert cb.message.edits  # the menu became the progress message


async def test_a_dangerous_mode_asks_the_code_first() -> None:
    svc = services()
    state = fsm()
    await admin_wizard.wizard_start(Callback("wiz:start:dump"), state, svc)  # type: ignore[arg-type]
    assert svc.wizard.started == []
    assert await state.get_state() == TotpStates.gate_code.state


async def test_update_with_totp_asks_the_code_in_the_same_message() -> None:
    """The code prompt is THIS message (the plan with its steps ⚪); no second message,
    no run before the code."""
    svc = services()
    state = fsm()
    cb = Callback("wiz:start:update")
    await admin_wizard.wizard_update_plan(cb, state, svc)  # type: ignore[arg-type]
    assert svc.wizard.started == [] and cb.message.answers == []
    assert await state.get_state() == TotpStates.gate_code.state
    data = await state.get_data()
    assert data["totp_resume"] == "wiz:go:update" and data["totp_prompt_id"] == cb.message.message_id
    assert "⚪" in cb.message.edits[-1] and t("wizard_update_confirm_code") in cb.message.edits[-1]


async def test_the_code_is_the_confirmation_the_run_starts_on_the_plan() -> None:
    svc = services()
    msg = Msg()
    resume = Resume(message=msg, user=SimpleNamespace(id=UID), state=fsm(), services=svc,  # type: ignore[arg-type]
                    bot=None, data="wiz:go:update")  # type: ignore[arg-type]
    assert resumer_for("wiz:go:update") is admin_wizard.wizard_update_resume
    await admin_wizard.wizard_update_resume(resume)
    assert svc.wizard.started == [("update", {"chat_id": UID, "message_id": 10, "confirmed": True})]
    assert msg.edits, "the plan became the run's progress message"


async def test_without_totp_update_shows_the_plan_then_starts_on_one_confirmation() -> None:
    svc = services(totp=False)
    cb = Callback("wiz:start:update")
    await admin_wizard.wizard_update_plan(cb, fsm(), svc)  # type: ignore[arg-type]
    assert svc.wizard.started == [], "the plan first, in the same message"
    assert t("wizard_update_confirm_hint") in cb.message.edits[-1]
    go = Callback("wiz:go:update")
    await admin_wizard.wizard_update_go(go, fsm(), svc)  # type: ignore[arg-type]
    assert svc.wizard.started == [("update", {"chat_id": UID, "message_id": 10, "confirmed": True})]


@pytest.mark.parametrize("data", ["wiz:start:update", "wiz:go:update", "wiz:start:selfcheck"])
async def test_a_press_while_a_run_is_active_says_so_and_starts_nothing(data: str) -> None:
    svc = services(totp=False)
    svc.wizard.running = wizard_run(id=6, mode="update")
    cb = Callback(data)
    handler = {"wiz:start:update": admin_wizard.wizard_update_plan, "wiz:go:update": admin_wizard.wizard_update_go,
               "wiz:start:selfcheck": admin_wizard.wizard_start}[data]
    await handler(cb, fsm(), svc)  # type: ignore[operator]
    assert svc.wizard.started == [] and cb.message.edits == [] and cb.message.answers == []
    assert cb.alerts[-1] == (t("wizard_already_running", id=6, mode=t("wizard_mode_update")), True)


async def test_applying_the_update_plan_asks_the_code_again() -> None:
    svc = services()
    state = fsm()
    await admin_wizard.wizard_confirm(Callback("wiz:ok:5"), state, svc)  # type: ignore[arg-type]
    assert svc.wizard.confirmed == []
    assert await state.get_state() == TotpStates.gate_code.state
    svc.totp.enabled = False
    await admin_wizard.wizard_confirm(Callback("wiz:ok:5"), fsm(), svc)  # type: ignore[arg-type]
    assert svc.wizard.confirmed == [5]


async def test_an_unknown_mode_is_refused() -> None:
    svc = services()
    cb = Callback("wiz:start:shell")
    await admin_wizard.wizard_start(cb, fsm(), svc)  # type: ignore[arg-type]
    assert svc.wizard.started == [] and cb.alerts[-1][1] is True
