"""«Подтвердить» under the SSH port migration message (services/ssh_port.py).

SUPERADMIN only: the button is sent to the superadmins, but a callback can be fired
by anyone who can see the message, so the handler checks it, never the keyboard.
The port and the migration's start travel in the callback data; the helper refuses
a button of any other migration (docs/host-state.md#the-ssh-port).
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
from services.ssh_port import CALLBACK_PREFIX, parse_callback_data
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


@router.callback_query(F.data.startswith(CALLBACK_PREFIX))
async def ssh_port_confirm(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        parsed = parse_callback_data(callback.data)
        if parsed is None or services.ssh_port is None:
            await safe_callback_answer(callback, t("ssh_port_confirm_stale"), show_alert=True)
            return
        port, since = parsed
        line = await services.ssh_port.confirm(callback.from_user.id, port, since)
        logger.info("SSH port %d confirmed by superadmin %d: %s", port, callback.from_user.id, line)
        await safe_callback_answer(callback, t("ssh_port_confirmed_alert", port=port), show_alert=True)
        if isinstance(callback.message, Message):
            await callback.message.answer(t("ssh_port_confirmed", port=port, line=h(line)))
    except Exception as exc:
        await answer_callback_error(callback, exc)
