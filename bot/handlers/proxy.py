from __future__ import annotations

import secrets
from typing import Any

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.formatters import main_menu_text, proxy_access_text
from bot.fsm.states import ProxyStates
from bot.handlers.common import answer_callback_error, answer_message_error, is_admin, profile_from_tg
from bot.keyboards.common import main_menu
from bot.keyboards.proxy import proxy_back_keyboard, proxy_confirm_keyboard, proxy_menu_keyboard
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from models.enums import ProxyAccessType
from services.user_locks import UserLockManager

router = Router()
_proxy_confirm_locks = UserLockManager()


@router.message(F.text == "Прокси")
async def show_proxy_message(message: Message, services: Any) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        text, markup = await _proxy_menu_view(services, message.from_user.id)
        await message.answer(text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data.in_({"proxy:show", "proxy:menu"}))
async def show_proxy(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        text, markup = await _proxy_menu_view(services, callback.from_user.id)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.in_({"proxy:get:socks5", "proxy:get:mtproto"}))
async def proxy_get_prompt(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        access_type = callback.data.rsplit(":", 1)[-1]
        accesses = await services.proxy.list_user_accesses(callback.from_user.id)
        if _has_access(accesses, access_type):
            await safe_callback_answer(callback)
            text, markup = await _proxy_menu_view(services, callback.from_user.id, accesses=accesses)
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
            return
        if access_type == ProxyAccessType.SOCKS5.value and not services.settings.socks5_enabled:
            text, markup = await _proxy_menu_view(services, callback.from_user.id, accesses=accesses)
            await safe_callback_answer(callback, "SOCKS5 сейчас недоступен", show_alert=True)
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
            return
        if access_type == ProxyAccessType.MTPROTO.value and not services.settings.mtproto_enabled:
            text, markup = await _proxy_menu_view(services, callback.from_user.id, accesses=accesses)
            await safe_callback_answer(callback, "MTProto сейчас недоступен", show_alert=True)
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
            return
        nonce = secrets.token_urlsafe(8)
        await state.set_state(ProxyStates.confirming)
        await state.update_data(proxy_type=access_type, nonce=nonce)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            _confirm_text(access_type, getattr(services.settings, "mtproto_mode", "static")),
            reply_markup=proxy_confirm_keyboard(access_type, nonce),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^proxy:confirm:(socks5|mtproto):[-_A-Za-z0-9]+$"))
async def proxy_confirm(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        _prefix, _confirm, access_type, nonce = callback.data.split(":", 3)
        async with _proxy_confirm_locks.lock(callback.from_user.id):
            data = await state.get_data()
            accesses = await services.proxy.list_user_accesses(callback.from_user.id)
            stale = data.get("proxy_type") != access_type or data.get("nonce") != nonce
            if stale and _has_access(accesses, access_type):
                await state.clear()
                await safe_callback_answer(callback)
                text, markup = await _proxy_menu_view(services, callback.from_user.id, accesses=accesses)
                await safe_edit_message_text(callback.message, text, reply_markup=markup)
                return
            if stale and not _has_access(accesses, access_type):
                await state.clear()
                await safe_callback_answer(callback, "Действие устарело", show_alert=True)
                await safe_edit_message_text(
                    callback.message,
                    "Действие устарело. Вернитесь в раздел «Прокси» и попробуйте снова.",
                    reply_markup=proxy_back_keyboard(),
                )
                return

            await state.clear()
            await safe_callback_answer(callback, "Выполняю...")
            profile = profile_from_tg(callback.from_user)
            if access_type == ProxyAccessType.SOCKS5.value:
                await services.socks5.issue_socks5_proxy(callback.from_user.id, profile)
            elif access_type == ProxyAccessType.MTPROTO.value:
                await services.mtproto.issue_mtproto_proxy(callback.from_user.id, profile)
            else:
                await safe_edit_message_text(callback.message, "Неизвестный тип прокси.", reply_markup=proxy_back_keyboard())
                return

            text, markup = await _proxy_menu_view(services, callback.from_user.id)
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "proxy:cancel")
async def proxy_cancel(callback: CallbackQuery, state: FSMContext, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await state.clear()
    await safe_callback_answer(callback, "Отменено")
    if callback.from_user is None or callback.message is None:
        return
    try:
        text, markup = await _proxy_menu_view(services, callback.from_user.id)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "proxy:back")
async def proxy_back(callback: CallbackQuery, services: Any) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    await safe_edit_message_text(
        callback.message,
        main_menu_text(callback.from_user),
        reply_markup=main_menu(await is_admin(services, callback.from_user.id)),
    )


async def _proxy_menu_view(services: Any, user_id: int, accesses: list[Any] | None = None) -> tuple[str, Any]:
    if accesses is None:
        accesses = await services.proxy.list_user_accesses(user_id)
    if not accesses and not services.settings.socks5_enabled and not services.settings.mtproto_enabled:
        text = "<b>Прокси</b>\n\nПрокси сейчас недоступны."
    elif not accesses:
        text = "<b>Прокси</b>\n\nУ вас пока нет прокси-доступов."
    else:
        text = proxy_access_text(accesses)
    return text, proxy_menu_keyboard(
        accesses,
        socks5_enabled=services.settings.socks5_enabled,
        mtproto_enabled=services.settings.mtproto_enabled,
    )


def _has_access(accesses: list[Any], access_type: str) -> bool:
    for access in accesses:
        value = getattr(access, "access_type", None)
        if getattr(value, "value", value) == access_type:
            return True
    return False


def _confirm_text(access_type: str, mtproto_mode: str = "static") -> str:
    if access_type == ProxyAccessType.SOCKS5.value:
        return (
            "<b>Подтвердите выдачу SOCKS5</b>\n\n"
            "Будет создан персональный Linux-пользователь Dante и пароль для SOCKS5-доступа."
        )
    if mtproto_mode == "managed":
        return (
            "<b>Подтвердите выдачу MTProto</b>\n\n"
            "Будет создан индивидуальный MTProto secret. После применения MTProxy пользователь получит обычную ссылку "
            "и ссылку с random padding dd."
        )
    return (
        "<b>Подтвердите выдачу MTProto</b>\n\n"
        "Бот покажет статические ссылки Telegram MTProto Proxy. "
        "При общем secret индивидуальный серверный revoke для MTProto невозможен."
    )
