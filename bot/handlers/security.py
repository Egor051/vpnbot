"""«🔐 Безопасность»: the superadmin's TOTP second factor (docs/wizard.md#totp).

SUPERADMIN only — every handler checks the role itself; a button can be pressed by
anyone who can see it.

Enrollment: «Включить TOTP» → the secret as a QR (otpauth://) and as base32 text →
the user types the current code → TOTP is on and 10 backup codes are shown ONCE →
«Я сохранил коды». The messages with the secret, the QR and the codes are deleted
once they did their job, and every message carrying a code the user typed is deleted
as soon as it is read.
"""

from __future__ import annotations

import logging
from typing import Any

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import BufferedInputFile, CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fsm.states import TotpStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from bot.totp_gate import ACTION_KEY, PROMPT_KEY, RESUME_KEY, delete_quietly, resume_keyboard
from i18n import t
from services.errors import ServiceError
from services.totp import TotpLocked, TotpService
from utils.formatting import h
from utils.qr import render_config_qr
from utils.totp import grouped_secret

router = Router()
logger = logging.getLogger(__name__)

SECRET_MSGS_KEY = "totp_secret_msgs"  # noqa: S105 - an FSM data key, not a secret


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


async def security_view(totp: TotpService, user_id: int) -> tuple[str, InlineKeyboardMarkup]:
    status = await totp.status(user_id)
    rows: list[list[InlineKeyboardButton]] = []
    if status.enabled:
        text = t("security_totp_on", left=status.backup_left)
        rows.append(_row(t("btn_totp_reissue"), "sec:totp:codes"))
        rows.append(_row(t("btn_totp_disable"), "sec:totp:off"))
    else:
        text = t("security_totp_off")
        rows.append(_row(t("btn_totp_enable"), "sec:totp:on"))
    if status.locked_until:
        text += "\n\n" + t("security_totp_locked")
    rows.append(_row(t("btn_admin_panel"), "admin:panel"))
    return t("security_title") + "\n\n" + text, InlineKeyboardMarkup(inline_keyboard=rows)


def _totp(services: Services) -> TotpService:
    if services.totp is None:
        raise ServiceError("TOTP не подключён", key="totp_unavailable")
    return services.totp


def codes_text(codes: list[str], left_title: str) -> str:
    body = "\n".join(f"<code>{h(code)}</code>" for code in codes)
    return f"{left_title}\n\n{body}\n\n" + t("totp_codes_warning")


def codes_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_totp_codes_saved"), "sec:codes:saved")])


def prompt_cancel_keyboard(data: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cancel"), data)])


@router.callback_query(F.data == "sec:menu")
async def security_menu(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.clear()
        text, markup = await security_view(_totp(services), callback.from_user.id)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── enrollment ───────────────────────────────────────────────────────────────
@router.callback_query(F.data == "sec:totp:on")
async def totp_enable_start(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        totp = _totp(services)
        account = callback.from_user.username or str(callback.from_user.id)
        enrollment = await totp.begin_enrollment(callback.from_user.id, account)
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return
    await safe_callback_answer(callback)
    chat_id = callback.message.chat.id
    sent: list[int] = []
    try:
        png = render_config_qr(enrollment.uri)
        photo = await bot.send_photo(chat_id, BufferedInputFile(png, filename="totp.png"), caption=t("totp_qr_caption"))
        sent.append(photo.message_id)
    except Exception:
        # The text below carries everything the QR does: an app can take the
        # otpauth URI or the base32 secret by hand.
        logger.warning("TOTP QR could not be rendered/sent; falling back to text", exc_info=True)
    secret_msg = await bot.send_message(
        chat_id,
        t("totp_secret_text", secret=h(grouped_secret(enrollment.secret_b32)), uri=h(enrollment.uri)),
        reply_markup=prompt_cancel_keyboard("sec:totp:cancel"),
    )
    sent.append(secret_msg.message_id)
    await state.set_state(TotpStates.enroll_code)
    await state.update_data({SECRET_MSGS_KEY: sent, PROMPT_KEY: secret_msg.message_id})


async def _delete_ids(bot: Bot, chat_id: int, ids: list[int]) -> None:
    for message_id in ids:
        try:
            await bot.delete_message(chat_id, message_id)
        except Exception:
            logger.debug("could not delete message %s", message_id, exc_info=True)


@router.callback_query(F.data == "sec:totp:cancel")
async def totp_enable_cancel(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot) -> None:
    if callback.from_user is None or callback.message is None:
        return
    data = await state.get_data()
    await state.clear()
    await _delete_ids(bot, callback.message.chat.id, [int(i) for i in data.get(SECRET_MSGS_KEY, [])])
    try:
        await require_superadmin(services, callback.from_user.id)
        await _totp(services).cancel_enrollment(callback.from_user.id)
        await safe_callback_answer(callback, t("totp_enroll_cancelled"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _edit_prompt(bot: Bot, chat_id: int, data: dict[str, Any], text: str, markup: InlineKeyboardMarkup | None) -> None:
    prompt = data.get(PROMPT_KEY)
    if isinstance(prompt, int):
        try:
            await bot.edit_message_text(text, chat_id=chat_id, message_id=prompt, reply_markup=markup)
            return
        except Exception:
            logger.debug("prompt %s not editable", prompt, exc_info=True)
    await bot.send_message(chat_id, text, reply_markup=markup)


@router.message(TotpStates.enroll_code)
async def totp_enroll_code(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    if message.from_user is None:
        return
    code = message.text or ""
    await delete_quietly(message)
    data = await state.get_data()
    chat_id = message.chat.id
    try:
        await require_superadmin(services, message.from_user.id)
        codes = await _totp(services).confirm_enrollment(message.from_user.id, code)
    except TotpLocked as exc:
        await state.clear()
        await _delete_ids(bot, chat_id, [int(i) for i in data.get(SECRET_MSGS_KEY, [])])
        await bot.send_message(chat_id, service_error_text(exc))
        return
    except ServiceError as exc:
        await _edit_prompt(
            bot,
            chat_id,
            data,
            t("totp_secret_retry", error=service_error_text(exc)),
            prompt_cancel_keyboard("sec:totp:cancel"),
        )
        return
    except Exception as exc:
        logger.exception("TOTP enrollment failed")
        await bot.send_message(chat_id, service_error_text(exc))
        return
    await state.clear()
    await _delete_ids(bot, chat_id, [int(i) for i in data.get(SECRET_MSGS_KEY, [])])
    await bot.send_message(chat_id, codes_text(codes, t("totp_enabled_codes_title")), reply_markup=codes_keyboard())


@router.callback_query(F.data == "sec:codes:saved")
async def totp_codes_saved(callback: CallbackQuery, services: Services) -> None:
    """The codes were written down: the message that shows them goes away."""
    if callback.from_user is None or callback.message is None:
        return
    await safe_callback_answer(callback, t("totp_codes_deleted"))
    try:
        await callback.message.delete()  # type: ignore[union-attr]
    except Exception:
        logger.debug("codes message not deletable", exc_info=True)
    try:
        await require_superadmin(services, callback.from_user.id)
        text, markup = await security_view(_totp(services), callback.from_user.id)
        await callback.bot.send_message(callback.from_user.id, text, reply_markup=markup)  # type: ignore[union-attr]
    except Exception:
        logger.debug("security view after codes not sent", exc_info=True)


@router.callback_query(F.data == "sec:later")
async def totp_later(callback: CallbackQuery) -> None:
    await safe_callback_answer(callback)
    if callback.message is not None:
        try:
            await callback.message.delete()  # type: ignore[union-attr]
        except Exception:
            logger.debug("offer not deletable", exc_info=True)


# ── disable / reissue: both ask for a code first ─────────────────────────────
@router.callback_query(F.data.in_({"sec:totp:off", "sec:totp:codes"}))
async def totp_code_prompt(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if not await _totp(services).is_enabled(callback.from_user.id):
            await safe_callback_answer(callback, t("totp_not_enabled"), show_alert=True)
            return
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return
    disable = callback.data == "sec:totp:off"
    await state.set_state(TotpStates.disable_code if disable else TotpStates.reissue_code)
    await safe_callback_answer(callback)
    await safe_edit_message_text(
        callback.message,
        t("totp_disable_prompt") if disable else t("totp_reissue_prompt"),
        reply_markup=prompt_cancel_keyboard("sec:menu"),
    )
    await state.update_data({PROMPT_KEY: callback.message.message_id})


@router.message(TotpStates.disable_code)
async def totp_disable_code(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    if message.from_user is None:
        return
    code = message.text or ""
    await delete_quietly(message)
    data = await state.get_data()
    try:
        await require_superadmin(services, message.from_user.id)
        totp = _totp(services)
        await totp.disable(message.from_user.id, code)
    except TotpLocked as exc:
        await state.clear()
        await _edit_prompt(bot, message.chat.id, data, service_error_text(exc), None)
        return
    except ServiceError as exc:
        await _edit_prompt(bot, message.chat.id, data, t("totp_disable_prompt") + "\n\n" + service_error_text(exc), prompt_cancel_keyboard("sec:menu"))
        return
    await state.clear()
    text, markup = await security_view(totp, message.from_user.id)
    await _edit_prompt(bot, message.chat.id, data, t("totp_disabled_ok") + "\n\n" + text, markup)


@router.message(TotpStates.reissue_code)
async def totp_reissue_code(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    if message.from_user is None:
        return
    code = message.text or ""
    await delete_quietly(message)
    data = await state.get_data()
    try:
        await require_superadmin(services, message.from_user.id)
        codes = await _totp(services).reissue_backup_codes(message.from_user.id, code)
    except TotpLocked as exc:
        await state.clear()
        await _edit_prompt(bot, message.chat.id, data, service_error_text(exc), None)
        return
    except ServiceError as exc:
        await _edit_prompt(bot, message.chat.id, data, t("totp_reissue_prompt") + "\n\n" + service_error_text(exc), prompt_cancel_keyboard("sec:menu"))
        return
    await state.clear()
    await _edit_prompt(bot, message.chat.id, data, t("totp_reissued_ok"), None)
    await bot.send_message(message.chat.id, codes_text(codes, t("totp_reissued_codes_title")), reply_markup=codes_keyboard())


# ── the gate's code (bot/totp_gate.py) ───────────────────────────────────────
@router.message(TotpStates.gate_code)
async def totp_gate_code(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    if message.from_user is None:
        return
    code = message.text or ""
    await delete_quietly(message)
    data = await state.get_data()
    action = str(data.get(ACTION_KEY) or "")
    resume = data.get(RESUME_KEY)
    try:
        await require_superadmin(services, message.from_user.id)
        result = await _totp(services).verify(message.from_user.id, code, purpose=f"gate:{action}")
    except TotpLocked as exc:
        await state.clear()
        await _edit_prompt(bot, message.chat.id, data, service_error_text(exc), None)
        return
    except ServiceError as exc:
        await _edit_prompt(
            bot,
            message.chat.id,
            data,
            t("totp_gate_retry", error=service_error_text(exc)),
            InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cancel"), "sec:gate:cancel")]),
        )
        return
    await state.clear()
    text = t("totp_gate_ok")
    if result.method == "backup":
        text += "\n" + t("totp_backup_used", left=result.backup_left)
    await _edit_prompt(bot, message.chat.id, data, text, resume_keyboard(resume) if isinstance(resume, str) else None)


@router.callback_query(F.data == "sec:gate:cancel")
async def totp_gate_cancel(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await safe_callback_answer(callback, t("totp_gate_cancelled"))
    if callback.message is not None:
        try:
            await callback.message.delete()  # type: ignore[union-attr]
        except Exception:
            logger.debug("gate prompt not deletable", exc_info=True)


def claim_offer_keyboard() -> InlineKeyboardMarkup:
    """The optional first-setup step after a successful claim."""
    return InlineKeyboardMarkup(
        inline_keyboard=[_row(t("btn_totp_enable"), "sec:totp:on"), _row(t("btn_totp_later"), "sec:later")]
    )
