"""The TOTP gate in front of dangerous actions (docs/wizard.md#totp).

A handler of a dangerous action calls :func:`require_totp` after its role check and
before it changes anything. When the superadmin has TOTP enabled and is not elevated
(a code typed in the last 5 minutes, services/totp.py), the gate asks for a code
instead and returns False: the handler stops. A correct code elevates the user and
turns the prompt into «▶️ Продолжить», whose callback data is the very button that
was pressed — so the action continues through its own handler, which this time
passes the gate. Without TOTP enabled the gate is open: the factor is opt-in.

The message with the code is deleted as soon as it is read.
"""

from __future__ import annotations

import logging

from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fsm.states import TotpStates
from bot.messages import safe_callback_answer
from i18n import t

logger = logging.getLogger(__name__)

# Every action that asks for the code, with its i18n label. Adding an action here is
# not enough — its handler must call require_totp() — but every call names one of
# these, so the list is the inventory the docs (docs/wizard.md#totp) mirror.
DANGEROUS_ACTIONS: dict[str, str] = {
    "protocol_uninstall": "dangerous_protocol_uninstall",
    "protocol_disable": "dangerous_protocol_disable",
    "relay_delete_keys": "dangerous_relay_delete_keys",
    "wizard_dump": "dangerous_wizard_dump",
    "wizard_update": "dangerous_wizard_update",
    "relay_pair": "dangerous_relay_pair",
    "relay_update": "dangerous_relay_update",
    "relay_apply": "dangerous_relay_apply",
    "relay_uninstall": "dangerous_relay_uninstall",
}

RESUME_KEY = "totp_resume"
ACTION_KEY = "totp_action"
PROMPT_KEY = "totp_prompt_id"


def gate_cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data="sec:gate:cancel")]])


def resume_keyboard(resume: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=t("btn_totp_continue"), callback_data=resume)]])


async def require_totp(
    callback: CallbackQuery, state: FSMContext | None, services: Services, *, action: str
) -> bool:
    """True: go on. False: a code prompt was shown instead; the handler must stop.

    Fails closed: when the code is required but cannot be asked (no FSM context, no
    message to answer under), the action is refused with an alert.
    """
    if action not in DANGEROUS_ACTIONS:
        raise ValueError(f"unknown dangerous action {action!r}")
    totp = getattr(services, "totp", None)
    if totp is None or callback.from_user is None:
        return True
    user_id = callback.from_user.id
    if not await totp.is_enabled(user_id) or totp.is_elevated(user_id):
        return True
    if state is None or callback.message is None or callback.data is None:
        await safe_callback_answer(callback, t("totp_gate_required"), show_alert=True)
        return False
    await state.set_state(TotpStates.gate_code)
    prompt = await callback.message.answer(
        t("totp_gate_prompt", action=t(DANGEROUS_ACTIONS[action])), reply_markup=gate_cancel_keyboard()
    )
    await state.update_data({RESUME_KEY: callback.data, ACTION_KEY: action, PROMPT_KEY: prompt.message_id})
    await safe_callback_answer(callback, t("totp_gate_required"))
    return False


async def delete_quietly(message: Message) -> None:
    try:
        await message.delete()
    except Exception:
        logger.debug("could not delete message %s", message.message_id, exc_info=True)
