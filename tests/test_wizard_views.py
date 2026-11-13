"""The wizard's messages (bot/wizard_views.py, bot/wizard_notifier.py).

* Whatever a helper wrote into the status file is HTML-escaped before it reaches
  Telegram (parse_mode=HTML): a `<` in a log line must not break the message.
* A progress message that can no longer be edited is replaced by a new one, which
  becomes the run's message (so the report after a restart lands somewhere).
* The dump's file follows the report; the scheduled alert goes to every superadmin.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from aiogram.exceptions import TelegramBadRequest
from aiogram.methods import EditMessageText

from bot.wizard_notifier import TelegramWizardNotifier
from bot.wizard_views import final_text, plan_text, progress_text, run_view, scheduled_alert_text
from models.dto import WizardRun
from services.wizard import Item, StatusSnapshot, parse_status

pytestmark = pytest.mark.timeout(30)


def run(**over: Any) -> WizardRun:
    base: dict[str, Any] = dict(
        id=3, mode="selfcheck", state="running", phase="execute", current_step="apply", params={}, started_by=9,
        origin="manual", chat_id=9, message_id=50, log_path="", summary="", plan_ready=False, active=True,
        created_at="2026-11-13T10:00:00+00:00", updated_at="2026-11-13T10:00:00+00:00", finished_at=None,
        reported_at=None,
    )
    base.update(over)
    return WizardRun(**base)


def test_helper_text_is_escaped_everywhere() -> None:
    snap = StatusSnapshot(progress=["<b>bold</b> & co"], plan_text="a <script>", result_text="x < y")
    snap.items = [Item("red", "perms", "<.env> is 0644")]
    assert "&lt;b&gt;bold&lt;/b&gt; &amp; co" in progress_text(run(), snap)
    assert "a &lt;script&gt;" in plan_text(run(mode="update", state="planned", plan_ready=True), snap)
    assert "&lt;.env&gt;" in final_text(run(state="succeeded", active=False), snap)
    assert "x &lt; y" in final_text(run(mode="update", state="succeeded", active=False), snap)
    assert "&lt;.env&gt;" in scheduled_alert_text(run(origin="scheduled", state="succeeded"), snap)


def test_run_view_picks_the_screen_by_state() -> None:
    snap = parse_status("")
    _, plan_kb = run_view(run(mode="update", state="planned", plan_ready=True), snap)
    assert [b.callback_data for r in plan_kb.inline_keyboard for b in r][:2] == ["wiz:ok:3", "wiz:no:3"]
    _, progress_kb = run_view(run(), snap)
    assert "wiz:run:3" in [b.callback_data for r in progress_kb.inline_keyboard for b in r]
    snap.artifact = "dump.txt"
    _, final_kb = run_view(run(mode="dump", state="succeeded", active=False), snap)
    assert "wiz:art:3" in [b.callback_data for r in final_kb.inline_keyboard for b in r]


class FakeService:
    def __init__(self) -> None:
        self.attached: list[tuple[int, int, int]] = []

    async def attach_message(self, run_id: int, chat_id: int, message_id: int) -> None:
        self.attached.append((run_id, chat_id, message_id))

    async def artifact_document(self, run: WizardRun, name: str) -> tuple[str, bytes] | None:
        return (f"wizard-{run.id}-{name}", b"dump")


@dataclass
class Sent:
    message_id: int


class FakeBot:
    def __init__(self, *, editable: bool = True) -> None:
        self.editable = editable
        self.sent: list[tuple[int, str]] = []
        self.documents: list[tuple[int, str]] = []
        self.edits = 0

    async def edit_message_text(self, text: str, **_: Any) -> None:
        self.edits += 1
        if not self.editable:
            raise TelegramBadRequest(method=EditMessageText(text=text), message="Bad Request: message to edit not found")

    async def send_message(self, chat_id: int, text: str, **_: Any) -> Sent:
        self.sent.append((chat_id, text))
        return Sent(700 + len(self.sent))

    async def send_document(self, chat_id: int, document: Any, **_: Any) -> None:
        self.documents.append((chat_id, document.filename))


async def test_an_uneditable_message_is_replaced_and_remembered() -> None:
    bot, service = FakeBot(editable=False), FakeService()
    notifier = TelegramWizardNotifier(bot=bot, service=service, admin_ids={9})  # type: ignore[arg-type]
    ok = await notifier.finished(run(state="succeeded", active=False), parse_status(""))
    assert ok and bot.edits == 1 and len(bot.sent) == 1
    assert service.attached == [(3, 9, 701)]


async def test_progress_waits_for_the_handler_to_attach_a_message() -> None:
    bot = FakeBot()
    notifier = TelegramWizardNotifier(bot=bot, service=FakeService(), admin_ids={9})  # type: ignore[arg-type]
    await notifier.progress(run(message_id=None), parse_status(""))
    assert bot.edits == 0 and bot.sent == []


async def test_the_dump_file_follows_the_report() -> None:
    bot = FakeBot()
    notifier = TelegramWizardNotifier(bot=bot, service=FakeService(), admin_ids={9})  # type: ignore[arg-type]
    snap = parse_status('{"event": "artifact", "name": "dump.txt"}\n{"event": "finished", "outcome": "succeeded"}')
    assert await notifier.finished(run(mode="dump", state="succeeded", active=False), snap)
    assert bot.documents == [(9, "wizard-3-dump.txt")]


async def test_the_scheduled_alert_reaches_every_superadmin() -> None:
    bot = FakeBot()
    notifier = TelegramWizardNotifier(bot=bot, service=FakeService(), admin_ids={9, 10})  # type: ignore[arg-type]
    snap = StatusSnapshot(items=[Item("yellow", "reboot", "a reboot is required")])
    assert await notifier.scheduled_alert(run(origin="scheduled", state="succeeded", active=False), snap)
    assert sorted(chat for chat, _ in bot.sent) == [9, 10]
