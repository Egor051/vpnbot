"""The setup wizard's Telegram side of the background monitor (services/wizard.py).

One progress message per run: edited in place while the run moves, turned into the
plan (with «Применить» / «Отменить») or into the final report. When the message can
no longer be edited — deleted, too old, the bot was restarted by the very deploy it
reports on and the chat moved on — a new one is sent and remembered instead.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from collections.abc import Set as AbstractSet

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import BufferedInputFile, InlineKeyboardMarkup

from bot.messages import cap_telegram_html
from bot.wizard_views import final_keyboard, final_text, plan_keyboard, plan_text, progress_keyboard, progress_text, scheduled_alert_text
from i18n import t
from models.dto import WizardRun
from services.wizard import StatusSnapshot, WizardService

logger = logging.getLogger(__name__)


class TelegramWizardNotifier:
    def __init__(self, *, bot: Bot, service: WizardService, admin_ids: AbstractSet[int] | Callable[[], AbstractSet[int]]) -> None:
        self.bot = bot
        self.service = service
        self._admin_ids = admin_ids

    def admins(self) -> AbstractSet[int]:
        return self._admin_ids() if callable(self._admin_ids) else self._admin_ids

    def _chat(self, run: WizardRun) -> int | None:
        return run.chat_id if run.chat_id is not None else run.started_by

    async def _show(self, run: WizardRun, text: str, markup: InlineKeyboardMarkup | None) -> bool:
        """Edit the run's message; send a new one when that is impossible."""
        text = cap_telegram_html(text)
        chat = self._chat(run)
        if chat is None:
            return False
        if run.message_id is not None:
            try:
                await self.bot.edit_message_text(text, chat_id=chat, message_id=run.message_id, reply_markup=markup)
                return True
            except TelegramBadRequest as exc:
                if "message is not modified" in str(exc).lower():
                    return True
                logger.info("wizard run %d: progress message not editable (%s) — sending a new one", run.id, exc)
            except Exception as exc:
                logger.warning("wizard run %d: progress edit failed — sending a new one (%s: %s)", run.id, type(exc).__name__, exc)
        try:
            sent = await self.bot.send_message(chat, text, reply_markup=markup)
        except Exception as exc:
            logger.warning("wizard run %d: cannot send the progress message (%s: %s)", run.id, type(exc).__name__, exc)
            return False
        await self.service.attach_message(run.id, chat, sent.message_id)
        return True

    async def progress(self, run: WizardRun, snap: StatusSnapshot) -> None:
        if run.message_id is None:
            return  # the handler that started it attaches the message right after
        await self._show(run, progress_text(run, snap), progress_keyboard(run))

    async def plan_ready(self, run: WizardRun, snap: StatusSnapshot) -> None:
        await self._show(run, plan_text(run, snap), plan_keyboard(run))

    async def finished(self, run: WizardRun, snap: StatusSnapshot) -> bool:
        ok = await self._show(run, final_text(run, snap), final_keyboard(run, artifact=snap.artifact is not None))
        chat = self._chat(run)
        if ok and chat is not None and snap.artifact and run.state == "succeeded":
            await self.send_artifact(chat, run, snap.artifact)
        return ok

    async def send_artifact(self, chat_id: int, run: WizardRun, name: str) -> bool:
        doc = await self.service.artifact_document(run, name)
        if doc is None:
            await self.bot.send_message(chat_id, t("wizard_artifact_missing", id=run.id))
            return False
        filename, data = doc
        await self.bot.send_document(chat_id, BufferedInputFile(data, filename=filename), caption=t("wizard_artifact_caption", id=run.id))
        return True

    async def scheduled_alert(self, run: WizardRun, snap: StatusSnapshot) -> bool:
        text = cap_telegram_html(scheduled_alert_text(run, snap))
        markup = final_keyboard(run)
        delivered = False
        for admin_id in self.admins():
            try:
                await self.bot.send_message(admin_id, text, reply_markup=markup)
                delivered = True
            except Exception as exc:
                logger.warning("Failed to send the self-check alert to admin %d (%s: %s)", admin_id, type(exc).__name__, exc)
        return delivered or not self.admins()
