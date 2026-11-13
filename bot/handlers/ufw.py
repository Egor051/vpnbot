"""«Подтвердить» under the UFW dead-man message (services/ufw.py).

SUPERADMIN only: the button is sent to the superadmins, but a callback can be fired
by anyone who can see the message, so the handler checks it, never the keyboard.
The change's arming time travels in the callback data; the helper refuses a button
of any other change (docs/host-state.md#the-firewall-ufw).
"""

from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.types import CallbackQuery, Message

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error
from bot.messages import safe_callback_answer
from i18n import t
from services.ufw import CALLBACK_PREFIX, parse_callback_data
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


@router.callback_query(F.data.startswith(CALLBACK_PREFIX))
async def ufw_deadman_confirm(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        armed_at = parse_callback_data(callback.data)
        if armed_at is None or services.ufw_deadman is None:
            await safe_callback_answer(callback, t("ufw_confirm_stale"), show_alert=True)
            return
        line = await services.ufw_deadman.confirm(callback.from_user.id, armed_at)
        logger.info("UFW policy change of %d confirmed by superadmin %d: %s", armed_at, callback.from_user.id, line)
        await safe_callback_answer(callback, t("ufw_confirmed_alert"), show_alert=True)
        if isinstance(callback.message, Message):
            await callback.message.answer(t("ufw_confirmed", line=h(line)))
    except Exception as exc:
        await answer_callback_error(callback, exc)
