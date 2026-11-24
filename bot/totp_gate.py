"""The TOTP gate in front of dangerous actions (docs/wizard.md#totp).

A handler of a dangerous action calls :func:`require_totp` after its role check and
before it changes anything. When the superadmin has TOTP enabled and is not elevated
(a code typed in the last 5 minutes, services/totp.py), the gate asks for a code
instead and returns False: the handler stops. A correct code elevates the user and
turns the prompt into «▶️ Продолжить», whose callback data is the very button that
was pressed — so the action continues through its own handler, which this time
passes the gate. Without TOTP enabled the gate is open: the factor is opt-in.

The message with the code is deleted as soon as it is read.

IN PLACE (:func:`require_totp_in_place`): one message, one confirmation. A screen whose
own job is to confirm (the plan of «⬆️ Обновить бота», «Обновить агент», «Убрать чужой
override») does not get a second message with a code prompt and a «▶️ Продолжить» after
it: the prompt goes into THAT message («введите код — он и есть подтверждение» and
«✖️ Отмена»), and a correct code starts the action right there through its resume
function (:func:`register_resume`, keyed by the button the code stands for). A wrong
code keeps the screen and adds the error; «✖️ Отмена» clears the gate.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    CallbackQuery,
    Chat,
    InaccessibleMessage,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    User,
)

from bot.container import Services
from bot.fsm.states import TotpStates
from bot.messages import safe_callback_answer, safe_edit_message_text
from i18n import t

logger = logging.getLogger(__name__)

# Every action that asks for the code, with its i18n label. Adding an action here is
# not enough — its handler must call require_totp() — but every call names one of
# these, so the list is the inventory the docs (docs/wizard.md#totp) mirror.
DANGEROUS_ACTIONS: dict[str, str] = {
    "protocol_uninstall": "dangerous_protocol_uninstall",
    "protocol_disable": "dangerous_protocol_disable",
    "wizard_dump": "dangerous_wizard_dump",
    "wizard_update": "dangerous_wizard_update",
    # Every change of a relay (admin panel → «🛰 Relay», bot/handlers/admin_relays.py).
    "relay_edit": "dangerous_relay_edit",
    "relay_delete": "dangerous_relay_delete",
    "relay_delete_keys": "dangerous_relay_delete_keys",
    "relay_pair": "dangerous_relay_pair",
    "relay_connect": "dangerous_relay_connect",
    "relay_update": "dangerous_relay_update",
    "relay_apply": "dangerous_relay_apply",
    "relay_detach": "dangerous_relay_detach",
    "relay_uninstall": "dangerous_relay_uninstall",
    # The relay's SSH port (bot/handlers/ssh_port.py): close the old port, keep it, move.
    "relay_ssh_port": "dangerous_relay_ssh_port",
    # «Довести relay до нормы» (bot/handlers/relay_hardening.py): the input filter on, SSH off 22.
    "relay_harden": "dangerous_relay_harden",
    # «🧹 Убрать чужой override» (bot/handlers/relay_sshd.py): a file of sshd_config.d to the attic.
    "relay_sshd_override": "dangerous_relay_sshd_override",
    # «📣 Разослать новую ссылку прокси» (bot/handlers/admin_fallback.py): a broadcast to proxy users.
    "fallback_proxy_notice": "dangerous_fallback_proxy_notice",
    # «🔁 Довести прокси до hub» (bot/handlers/admin_fallback.py): the agent's apply on the hub.
    "fallback_proxy_reconcile": "dangerous_fallback_proxy_reconcile",
    # The fallback mode (bot/handlers/admin_fallback.py): the switch itself, the hub
    # role, the DNS API token and the settings the switch writes.
    "fallback_switch": "dangerous_fallback_switch",
    "fallback_hub": "dangerous_fallback_hub",
    "fallback_token": "dangerous_fallback_token",
    "fallback_settings": "dangerous_fallback_settings",
    # «🔐 Сертификат и DNS» (bot/handlers/admin_cert.py): a run of the wizard's «cert»
    # mode (issue / renew / adopt / deploy) and the bot's ONE Cloudflare token.
    "wizard_cert": "dangerous_wizard_cert",
    "dns_token": "dangerous_dns_token",
}

RESUME_KEY = "totp_resume"
ACTION_KEY = "totp_action"
PROMPT_KEY = "totp_prompt_id"
# In place: the screen the code is asked on (its text, kept on a wrong code) and where
# «✖️ Отмена» leads back to.
IN_PLACE_KEY = "totp_in_place"
SCREEN_KEY = "totp_screen"
BACK_KEY = "totp_back"
UNDO_DATA = "sec:gate:undo"


@dataclass(frozen=True, slots=True)
class Resume:
    """What a resume function gets: the screen (the message the code was asked on,
    bound to the bot), who typed the code, and the button it stands for."""

    message: Message
    user: User
    state: FSMContext
    services: Services
    bot: Bot
    data: str


ResumeFn = Callable[[Resume], Awaitable[None]]
EditFn = Callable[..., Awaitable[bool]]
_RESUMERS: list[tuple[re.Pattern[str], ResumeFn]] = []


def register_resume(pattern: str) -> Callable[[ResumeFn], ResumeFn]:
    """The action an in-place code starts for a button whose data fully matches *pattern*."""

    def wrap(fn: ResumeFn) -> ResumeFn:
        _RESUMERS.append((re.compile(pattern), fn))
        return fn

    return wrap


def resumer_for(data: str) -> ResumeFn | None:
    for pattern, fn in _RESUMERS:
        if pattern.fullmatch(data):
            return fn
    return None


def screen_message(bot: Bot, chat_id: int, message_id: int) -> Message:
    """The screen a code was asked on, as a Message the edit helpers can use."""
    message = Message(
        message_id=message_id, date=datetime.now(timezone.utc), chat=Chat(id=chat_id, type="private"),
    )
    return message.as_(bot)


def in_place_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=t("btn_gate_cancel"), callback_data=UNDO_DATA)]])


async def code_required(services: Services, user_id: int) -> bool:
    """The code would be asked now (TOTP on, not elevated)."""
    totp = getattr(services, "totp", None)
    if totp is None:
        return False
    return bool(await totp.is_enabled(user_id)) and not totp.is_elevated(user_id)


async def require_totp_in_place(
    callback: CallbackQuery, state: FSMContext | None, services: Services, *,
    action: str, screen: str, resume: str, back: str, edit: EditFn | None = None,
) -> bool:
    """True: go on (no code needed). False: THIS message now shows *screen* with the
    code prompt and «✖️ Отмена»; a correct code runs the resume function of *resume*
    on this message (the code is the confirmation). *back*: where «✖️ Отмена» leads;
    *edit*: the caller's edit helper (default :func:`bot.messages.safe_edit_message_text`)."""
    if action not in DANGEROUS_ACTIONS:
        raise ValueError(f"unknown dangerous action {action!r}")
    if callback.from_user is None or not await code_required(services, callback.from_user.id):
        return True
    if state is None or callback.message is None or isinstance(callback.message, InaccessibleMessage):
        await safe_callback_answer(callback, t("totp_gate_required"), show_alert=True)
        return False
    await state.set_state(TotpStates.gate_code)
    await state.update_data({
        RESUME_KEY: resume, ACTION_KEY: action, PROMPT_KEY: callback.message.message_id,
        IN_PLACE_KEY: True, SCREEN_KEY: screen, BACK_KEY: back,
    })
    await safe_callback_answer(callback, t("totp_gate_required"))
    text = screen + "\n\n" + t("totp_gate_in_place", action=t(DANGEROUS_ACTIONS[action]))
    await (edit or safe_edit_message_text)(callback.message, text, reply_markup=in_place_keyboard())
    return False


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
