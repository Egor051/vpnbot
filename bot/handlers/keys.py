
from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.formatters import (
    NOTE_CREATE_WARNING,
    ONE_KEY_ONE_DEVICE_WARNING,
    create_confirm_text,
    key_detail_text,
    keys_page_text,
    note_confirm_text,
    traffic_stats_text,
    xray_config_text,
)
from bot.container import Services
from bot.fsm.states import CreateKeyStates, EditNoteStates
from bot.handlers.common import answer_callback_error, answer_message_error, profile_from_tg
from bot.keyboards.common import cancel_keyboard, confirm_cancel_keyboard
from bot.keyboards.keys import (
    after_key_deleted_keyboard,
    confirm_keyboard,
    create_key_keyboard,
    key_actions_keyboard,
    keys_list_keyboard,
)
from bot.messages import awg_config_filename, safe_callback_answer, safe_edit_message_text, send_awg_config
from bot.pagination import page_offset
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimiter
from models.enums import AuditEntityType, VpnKeyType
from services.errors import AccessDenied, NotFound

router = Router()
KEYS_PAGE_SIZE = 5


@router.callback_query(F.data.regexp(r"^keys:list(?::\d+)?$"))
async def list_keys(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    page = _page_from_callback(callback.data, default=0)
    try:
        keys, current_page, total_pages, has_next = await _load_keys_page(
            services,
            callback.from_user.id,
            page=page,
            page_size=KEYS_PAGE_SIZE,
        )
        text = keys_page_text(keys, current_page, viewer_user_id=callback.from_user.id)
        await safe_edit_message_text(
            callback.message,
            text,
            reply_markup=keys_list_keyboard(keys, page=current_page, has_next=has_next, total_pages=total_pages),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(F.text == "Мои ключи")
async def list_keys_message(message: Message, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        keys, current_page, total_pages, has_next = await _load_keys_page(
            services,
            message.from_user.id,
            page=0,
            page_size=KEYS_PAGE_SIZE,
        )
        await message.answer(
            keys_page_text(keys, current_page, viewer_user_id=message.from_user.id),
            reply_markup=keys_list_keyboard(keys, page=current_page, has_next=has_next, total_pages=total_pages),
        )
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data == "keys:create")
async def create_key_menu(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    try:
        if callback.from_user is None:
            return
        await _ensure_can_enter_create(callback.from_user.id, services)
        await safe_callback_answer(callback)
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return
    if callback.message:
        await safe_edit_message_text(
            callback.message,
            f"{ONE_KEY_ONE_DEVICE_WARNING}\n\nВыберите тип ключа:",
            reply_markup=create_key_keyboard(),
        )


@router.message(F.text == "Создать ключ")
async def create_key_menu_message(message: Message, services: Services) -> None:
    if not await ensure_private_message(message):
        return
    if message.from_user is None:
        return
    try:
        await _ensure_can_enter_create(message.from_user.id, services)
        await message.answer(f"{ONE_KEY_ONE_DEVICE_WARNING}\n\nВыберите тип ключа:", reply_markup=create_key_keyboard())
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data.in_({"keys:create:xray", "keys:create:awg"}))
async def create_key_choose(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        await safe_callback_answer(callback)
        key_type = callback.data.rsplit(":", 1)[-1]
        await state.set_state(CreateKeyStates.waiting_note)
        await state.update_data(key_type=key_type)
        await safe_edit_message_text(
            callback.message,
            f"{NOTE_CREATE_WARNING}\n\nВведите заметку для ключа или отправьте <code>-</code>, чтобы оставить пустой.",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(CreateKeyStates.waiting_note)
async def create_key_note(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    try:
        await _ensure_can_enter_create(message.from_user.id, services)
        data = await state.get_data()
        key_type = str(data.get("key_type") or "")
        note = _clean_note(message.text)
        await state.update_data(note=note)
        await state.set_state(CreateKeyStates.confirming)
        await message.answer(
            create_confirm_text(key_type, note),
            reply_markup=confirm_cancel_keyboard("create:confirm"),
        )
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(CreateKeyStates.confirming, F.data == "create:confirm")
async def create_key_confirm(callback: CallbackQuery, state: FSMContext, services: Services, rate_limiter: RateLimiter) -> None:
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback):
        return
    data = await state.get_data()
    key_type = str(data.get("key_type") or "")
    note = data.get("note")
    try:
        await _ensure_can_enter_create(callback.from_user.id, services)
        profile = profile_from_tg(callback.from_user)
        rate_limiter.check(callback.from_user.id, "key_create", 20)
        await state.clear()
        await safe_callback_answer(callback, "Создаю ключ...")
        if key_type == VpnKeyType.XRAY.value:
            result = await services.xray.create_xray_key(callback.from_user.id, profile, note)
        elif key_type == VpnKeyType.AWG.value:
            result = await services.awg.create_awg_key(callback.from_user.id, profile, note)
        else:
            await safe_edit_message_text(callback.message, "Неизвестный тип ключа.")
            return
        if result.key.key_type == VpnKeyType.AWG:
            config = await services.awg.get_awg_client_config_plain(callback.from_user.id, result.key.id, audit=False)
            await send_awg_config(
                callback.message,
                title=f"AWG-ключ #{result.key.id}",
                config_text=config,
                filename=awg_config_filename(result.key),
                reply_markup=key_actions_keyboard(result.key, owner_user_id=_admin_owner_context(result.key, callback.from_user.id)),
                edit_text=True,
            )
        else:
            await safe_edit_message_text(
                callback.message,
                result.config_text,
                reply_markup=key_actions_keyboard(result.key, owner_user_id=_admin_owner_context(result.key, callback.from_user.id)),
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:open:"))
async def open_key(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id, owner_context, page_context = _parse_key_context(callback.data, "key:open")
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            key_detail_text(key, viewer_user_id=callback.from_user.id),
            reply_markup=key_actions_keyboard(
                key,
                owner_user_id=owner_context or _admin_owner_context(key, callback.from_user.id),
                page=page_context,
            ),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:show:"))
async def show_key_config(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter) -> None:
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        rate_limiter.check(callback.from_user.id, "key_show", 5)
        await safe_callback_answer(callback)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        if key.key_type == VpnKeyType.XRAY:
            text = xray_config_text(await services.xray.get_xray_key_config(callback.from_user.id, key_id))
            await safe_edit_message_text(
                callback.message,
                text,
                reply_markup=key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id)),
            )
        else:
            config = await services.awg.get_awg_client_config_plain(callback.from_user.id, key_id)
            await send_awg_config(
                callback.message,
                title=f"AWG-ключ #{key.id}",
                config_text=config,
                filename=awg_config_filename(key),
                reply_markup=key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id)),
                edit_text=True,
                send_document=False,
            )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:stats:"))
async def show_key_stats(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        await safe_callback_answer(callback, "Обновляю статистику...")
        view = await services.traffic_stats.refresh_for_actor(callback.from_user.id, key_id)
        owner = view.owner
        await services.audit.write(
            actor_user_id=callback.from_user.id,
            action="stats_viewed",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={
                "target_user_id": view.key.owner_user_id,
                "target_username": owner.username if owner else view.key.username,
                "key_type": view.key.key_type.value,
                "label": view.key.email_label,
            },
        )
        await safe_edit_message_text(
            callback.message,
            traffic_stats_text(view, viewer_user_id=callback.from_user.id),
            reply_markup=key_actions_keyboard(view.key, owner_user_id=_admin_owner_context(view.key, callback.from_user.id)),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:revoke:"))
async def revoke_key_prompt(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id, owner_context, page_context = _parse_key_context(callback.data, "key:revoke")
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        owner_context = owner_context or _admin_owner_context(key, callback.from_user.id)
        if owner_context is not None and owner_context != key.owner_user_id:
            raise AccessDenied("Контекст отзыва устарел, откройте список ключей заново")
        await safe_edit_message_text(
            callback.message,
            f"Отозвать ключ #{key_id}? Доступ по нему будет отключён.",
            reply_markup=confirm_keyboard("revoke", key_id, owner_user_id=owner_context, page=page_context),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:delete:"))
async def delete_key_prompt(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id, owner_context, page_context = _parse_key_context(callback.data, "key:delete")
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        owner_context = owner_context or _admin_owner_context(key, callback.from_user.id)
        if owner_context is not None and owner_context != key.owner_user_id:
            raise AccessDenied("Контекст удаления устарел, откройте список ключей заново")
        await safe_edit_message_text(
            callback.message,
            (
                f"Полностью удалить ключ #{key_id}? Доступ будет отключён на сервере, "
                "запись ключа и его статистика будут удалены из бота. Это действие нельзя отменить."
            ),
            reply_markup=confirm_keyboard("delete", key_id, owner_user_id=owner_context, page=page_context),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("confirm:"))
async def confirm_key_action(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter) -> None:
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    if not await ensure_private_callback(callback):
        return
    try:
        action, key_id, owner_context_from_callback, page_context = _parse_confirm_context(callback.data)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        if action == "revoke":
            rate_limiter.check(callback.from_user.id, "key_revoke", 10)
            await safe_callback_answer(callback, "Выполняю...")
            updated = (
                await services.xray.revoke_xray_key(callback.from_user.id, key_id)
                if key.key_type == VpnKeyType.XRAY
                else await services.awg.revoke_awg_key(callback.from_user.id, key_id)
            )
            await safe_edit_message_text(
                callback.message,
                "Ключ отозван.",
                reply_markup=key_actions_keyboard(updated, owner_user_id=_admin_owner_context(updated, callback.from_user.id)),
            )
        elif action == "delete":
            rate_limiter.check(callback.from_user.id, "key_delete", 10)
            await safe_callback_answer(callback, "Выполняю...")
            owner_context = owner_context_from_callback or _admin_owner_context(key, callback.from_user.id)
            if owner_context is not None and owner_context != key.owner_user_id:
                raise AccessDenied("Контекст удаления устарел, откройте список ключей заново")
            if key.key_type == VpnKeyType.XRAY:
                await services.xray.delete_xray_key(callback.from_user.id, key_id)
            else:
                await services.awg.delete_awg_key(callback.from_user.id, key_id)
            if owner_context is not None:
                keys, current_page, total_pages, has_next = await _load_keys_page(
                    services,
                    callback.from_user.id,
                    owner_user_id=owner_context,
                    page=page_context,
                    page_size=KEYS_PAGE_SIZE,
                )
                await safe_edit_message_text(
                    callback.message,
                    (
                        "Ключ полностью удалён.\n\n"
                        f"{keys_page_text(keys, current_page, viewer_user_id=callback.from_user.id, owner_user_id=owner_context)}"
                    ),
                    reply_markup=keys_list_keyboard(
                        keys,
                        page=current_page,
                        has_next=has_next,
                        owner_user_id=owner_context,
                        total_pages=total_pages,
                    ),
                )
                return
            await safe_edit_message_text(
                callback.message,
                "Ключ полностью удалён.",
                reply_markup=after_key_deleted_keyboard(),
            )
        else:
            await safe_callback_answer(callback, "Неизвестное действие", show_alert=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("key:note:"))
async def edit_note_prompt(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        key_id = int(callback.data.rsplit(":", 1)[-1])
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await state.set_state(EditNoteStates.waiting_note)
        await state.update_data(key_id=key_id)
        await safe_edit_message_text(
            callback.message,
            f"Новая заметка для {key.key_type.value.upper()} #{key.id}. Отправьте <code>-</code>, чтобы очистить.",
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(EditNoteStates.waiting_note)
async def edit_note_waiting(message: Message, state: FSMContext, services: Services) -> None:
    if message.from_user is None:
        return
    if not await ensure_private_message(message):
        return
    data = await state.get_data()
    try:
        key_id = int(data["key_id"])
        key = await services.vpn_keys.get_for_actor(message.from_user.id, key_id)
        note = _clean_note(message.text)
        await state.update_data(note=note)
        await state.set_state(EditNoteStates.confirming)
        await message.answer(note_confirm_text(key, note), reply_markup=confirm_cancel_keyboard("note:confirm"))
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


@router.callback_query(EditNoteStates.confirming, F.data == "note:confirm")
async def edit_note_confirm(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    if callback.from_user is None or callback.message is None:
        return
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback, "Сохраняю...")
    data = await state.get_data()
    await state.clear()
    try:
        key_id = int(data["key_id"])
        note = data.get("note")
        await services.notes.update_key_note(callback.from_user.id, key_id, note)
        key = await services.vpn_keys.get_for_actor(callback.from_user.id, key_id)
        await safe_edit_message_text(
            callback.message,
            "Заметка обновлена.",
            reply_markup=key_actions_keyboard(key, owner_user_id=_admin_owner_context(key, callback.from_user.id)),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _clean_note(value: str | None) -> str | None:
    if value is None:
        return None
    note = value.strip()
    return None if note in {"", "-"} else note


def _admin_owner_context(key, actor_user_id: int) -> int | None:
    return key.owner_user_id if key.owner_user_id != actor_user_id else None


async def _ensure_can_enter_create(actor_user_id: int, services: Services) -> None:
    try:
        await services.users.require_approved_or_admin(actor_user_id)
    except NotFound as exc:
        raise AccessDenied("Сначала отправьте /start, чтобы создать заявку на доступ") from exc
    except AccessDenied as exc:
        if "не одобрен" in str(exc):
            raise AccessDenied("Доступ ещё не одобрен. Дождитесь решения администратора.") from exc
        raise


def _parse_key_context(data: str | None, prefix: str) -> tuple[int, int | None, int]:
    if not data:
        raise ValueError("Некорректная callback-кнопка")
    parts = data.split(":")
    expected = prefix.split(":")
    if parts[: len(expected)] != expected or len(parts) not in {len(expected) + 1, len(expected) + 3}:
        raise ValueError("Некорректная callback-кнопка")
    key_id = int(parts[len(expected)])
    if len(parts) == len(expected) + 1:
        return key_id, None, 0
    return key_id, int(parts[len(expected) + 1]), max(int(parts[len(expected) + 2]), 0)


def _parse_confirm_context(data: str) -> tuple[str, int, int | None, int]:
    parts = data.split(":")
    if len(parts) not in {3, 5} or parts[0] != "confirm":
        raise ValueError("Некорректная callback-кнопка")
    action = parts[1]
    key_id = int(parts[2])
    if len(parts) == 3:
        return action, key_id, None, 0
    return action, key_id, int(parts[3]), max(int(parts[4]), 0)


async def _load_keys_page(
    services: Services,
    actor_user_id: int,
    *,
    owner_user_id: int | None = None,
    page: int,
    page_size: int,
):
    total_count = await services.vpn_keys.count_for_actor(actor_user_id, owner_user_id=owner_user_id)
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    current_page = min(max(page, 0), total_pages - 1)
    keys = await services.vpn_keys.list_for_actor(
        actor_user_id,
        owner_user_id=owner_user_id,
        limit=page_size,
        offset=page_offset(current_page, page_size),
    )
    if not keys and current_page > 0:
        total_count = await services.vpn_keys.count_for_actor(actor_user_id, owner_user_id=owner_user_id)
        total_pages = max(1, (total_count + page_size - 1) // page_size)
        current_page = max(0, min(current_page - 1, total_pages - 1))
        keys = await services.vpn_keys.list_for_actor(
            actor_user_id,
            owner_user_id=owner_user_id,
            limit=page_size,
            offset=page_offset(current_page, page_size),
        )
    has_next = current_page + 1 < total_pages
    return keys, current_page, total_pages, has_next


def _page_from_callback(data: str | None, default: int = 0) -> int:
    if not data:
        return default
    parts = data.split(":")
    if parts and parts[-1].isdigit():
        return max(int(parts[-1]), 0)
    return default
