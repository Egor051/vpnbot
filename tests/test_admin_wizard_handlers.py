"""The «🧙 Мастер настройки» handlers (bot/handlers/admin_wizard.py).

* SUPERADMIN only: anyone else is refused before the service is touched.
* A dangerous mode (dump, update) asks the TOTP code before it starts and before a
  plan is applied; a read-only, non-dangerous mode (selfcheck) starts at once.
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

    def exclusive(self) -> Any:
        return self.lock

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


@pytest.mark.parametrize("mode", ["dump", "update"])
async def test_a_dangerous_mode_asks_the_code_first(mode: str) -> None:
    svc = services()
    state = fsm()
    await admin_wizard.wizard_start(Callback(f"wiz:start:{mode}"), state, svc)  # type: ignore[arg-type]
    assert svc.wizard.started == []
    assert await state.get_state() == TotpStates.gate_code.state


async def test_without_totp_a_dangerous_mode_starts() -> None:
    svc = services(totp=False)
    await admin_wizard.wizard_start(Callback("wiz:start:update"), fsm(), svc)  # type: ignore[arg-type]
    assert [m for m, _ in svc.wizard.started] == ["update"]


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
