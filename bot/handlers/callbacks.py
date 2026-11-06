
from aiogram import Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardMarkup

from bot.availability import current_availability
from bot.bundles import (
    bundle_detail_text,
    bundle_has_vless,
    require_subscription_ui,
)
from bot.container import Services
from bot.formatters import key_screen_text
from bot.handlers.admin import group_view_for_actor, staff_panel_view, user_card_view, users_list_view
from bot.handlers.common import admin_owner_context, parse_int_callback, stats_views_for_screen
from bot.handlers.keys import create_key_menu_view
from bot.keyboards.common import back_to_menu
from bot.keyboards.key_bundles import bundle_actions_keyboard
from bot.keyboards.keys import key_actions_keyboard
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from bot.rate_limit import RateLimiter
from i18n import t

router = Router()


async def admin_cancel_view(
    services: Services | None, user_id: int | None, target: str
) -> tuple[str, InlineKeyboardMarkup] | None:
    """The screen an admin «Отмена» returns to, or None if *target* is not an admin one.

    ``admin:panel`` is the panel of the actor's role, ``admin:grp:<g>`` a section
    of it, ``admin:user:<id>`` a user's card and ``admin:users`` the user list —
    each wizard stores the screen it was started from. Every one of them checks
    the role again: FSM data is not proof of it.
    """
    if services is None or user_id is None:
        return None
    if target == "admin:panel":
        return await staff_panel_view(services, user_id)
    if target.startswith("admin:grp:"):
        return await group_view_for_actor(services, user_id, target.rsplit(":", 1)[-1])
    if target.startswith("admin:user:"):
        target_id = parse_int_callback(target.rsplit(":", 1)[-1])
        if target_id is None:
            return None
        return await user_card_view(services, user_id, target_id)
    if target == "admin:users":
        return await users_list_view(services, user_id, 0)
    return None


@router.callback_query(lambda callback: callback.data == "cancel")
async def cancel_callback(
    callback: CallbackQuery,
    state: FSMContext,
    rate_limiter: RateLimiter,
    services: Services | None = None,
) -> None:
    """Cancel the current FSM flow and return the user to the relevant screen."""
    if not await ensure_private_callback(callback):
        return
    data = await state.get_data()
    cancel_target = data.get("cancel_target", "menu:main")
    await state.clear()
    await safe_callback_answer(callback, t("cancel_done"))
    if callback.message is None:
        return
    if cancel_target.startswith("admin:"):
        try:
            view = await admin_cancel_view(
                services, callback.from_user.id if callback.from_user else None, cancel_target
            )
        except Exception:
            view = None
        if view is None:
            await safe_edit_message_text(callback.message, t("cancel_done"), reply_markup=back_to_menu())
        else:
            await safe_edit_message_text(callback.message, view[0], reply_markup=view[1])
    elif cancel_target == "keys:create" and services is not None:
        # The very same screen «Создать ключ» renders, built from availability read
        # now — so cancelling out of the wizard never brings back a protocol that
        # was switched off (this branch used to show Xray/AWG unconditionally).
        text, markup = await create_key_menu_view(services)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    elif cancel_target and cancel_target.startswith("bundle:open:"):
        try:
            bundle_id = int(cancel_target.rsplit(":", 1)[-1])
            user_id = callback.from_user.id if callback.from_user else None
            if user_id is None or services is None:
                raise ValueError
            require_subscription_ui(services)
            bundle = await services.key_bundle_views.get_for_actor(user_id, bundle_id)
            keys = await services.key_bundle_views.list_keys_for_actor(user_id, bundle_id)
            views = await stats_views_for_screen(services, rate_limiter, user_id, keys)
            await safe_edit_message_text(
                callback.message,
                bundle_detail_text(
                    bundle,
                    keys,
                    viewer_user_id=user_id,
                    available=await current_availability(services),
                    views=views,
                    relays=services.relays.snapshot,
                ),
                reply_markup=bundle_actions_keyboard(bundle, has_vless=bundle_has_vless(keys)),
            )
        except Exception:
            await safe_edit_message_text(callback.message, t("cancel_done"), reply_markup=back_to_menu())
    elif cancel_target and cancel_target.startswith("key:open:"):
        try:
            key_id = int(cancel_target.rsplit(":", 1)[-1])
            user_id = callback.from_user.id if callback.from_user else None
            if user_id is None or services is None:
                raise ValueError
            key = await services.vpn_keys.get_for_actor(user_id, key_id)
            views = await stats_views_for_screen(services, rate_limiter, user_id, [key])
            await safe_edit_message_text(
                callback.message,
                key_screen_text(key, viewer_user_id=user_id, stats=views[0].stats if views else None),
                # Same owner context the direct entry point computes: a key card
                # reached by cancelling out of a wizard is the same screen as one
                # reached by tapping it, and must not offer a different keyboard.
                reply_markup=key_actions_keyboard(key, owner_user_id=admin_owner_context(key, user_id)),
            )
        except Exception:
            await safe_edit_message_text(callback.message, t("cancel_done"), reply_markup=back_to_menu())
    else:
        await safe_edit_message_text(callback.message, t("cancel_done"), reply_markup=back_to_menu())


@router.callback_query()
async def unknown_callback(callback: CallbackQuery) -> None:
    """Reject any unrecognized callback as stale."""
    if not await ensure_private_callback(callback):
        return
    await safe_callback_answer(callback, t("action_stale"), show_alert=True)
