"""Bot handlers for all-in-one subscription bundles (``bundle:*`` callbacks).

The whole router is gated on ``SUBSCRIPTION_ENABLED``: every handler calls
:func:`bot.bundles.require_subscription_ui` before touching a service, so with the
flag off a replayed or hand-crafted callback is refused rather than merely
unreachable through the UI. The create wizard itself lives in
:mod:`bot.handlers.keys` — a bundle is one more choice in the existing flow, not a
second one.

Nothing here duplicates a lifecycle path: revoke and delete go through
``KeyBundleService`` (which cascades to the children and rotates the token), reads
go through ``KeyBundleViewService``, and traffic comes from the same
``TrafficStatsService`` the per-key screen uses.
"""

from __future__ import annotations

import logging

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery

from bot.bundles import (
    bundle_config_text,
    bundle_detail_text,
    bundle_has_vless,
    require_subscription_ui,
    subscription_url,
)
from bot.container import Services
from bot.fsm.states import EditFpStates, EditNoteStates
from bot.handlers.common import (
    InvalidCallbackData,
    answer_callback_error,
    parse_int_callback,
    stats_views_for_screen,
)
from bot.keyboards.common import cancel_keyboard
from bot.keyboards.key_bundles import bundle_actions_keyboard, bundle_confirm_keyboard
from bot.keyboards.keys import after_key_deleted_keyboard, fp_choice_keyboard
from bot.messages import (
    CONFIG_DOC_KIND_BUNDLE,
    config_document_present,
    discard_config_document,
    safe_callback_answer,
    safe_edit_message_text,
    send_config_with_qr,
)
from bot.private_chat import ensure_private_callback
from bot.rate_limit import RateLimiter
from i18n import t

router = Router()
logger = logging.getLogger(__name__)


@router.callback_query(F.data.startswith("bundle:open:"))
async def open_bundle(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter) -> None:
    """Show the card of a single all-in-one bundle, traffic included.

    The traffic used to sit behind a «Статистика» button; it is part of the card
    now, so this screen samples it (softly rate-limited, cached fallback) rather
    than making the user ask for it.
    """
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        require_subscription_ui(services)
        bundle_id = _bundle_id(callback.data)
        await safe_callback_answer(callback)
        bundle = await services.key_bundle_views.get_for_actor(callback.from_user.id, bundle_id)
        keys = await services.key_bundle_views.list_keys_for_actor(callback.from_user.id, bundle_id)
        views = await stats_views_for_screen(services, rate_limiter, callback.from_user.id, keys)
        await safe_edit_message_text(
            callback.message,
            bundle_detail_text(bundle, keys, viewer_user_id=callback.from_user.id, views=views),
            reply_markup=bundle_actions_keyboard(bundle, has_vless=bundle_has_vless(keys)),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("bundle:show:"))
async def show_bundle_config(
    callback: CallbackQuery, state: FSMContext, services: Services, rate_limiter: RateLimiter, bot: Bot
) -> None:
    """Show the subscription URL of a bundle, plus a QR code of it.

    The URL carries the bundle's token — the only credential of the whole
    subscription — so it is written to the chat and NOWHERE else: no log line here
    or downstream ever formats it, and the audit entry records the bundle id only.
    The QR encodes that same URL, so it is exactly as sensitive and gets exactly the
    same lifetime: tracked via ``remember_config_document`` and removed by the
    config-cleanup middleware on the user's next tap, like the AWG config file.

    The QR is the sub-URL and nothing else — never the aggregated subscription body
    the endpoint serves behind it — so a bundle with many children encodes the same
    short string as a bundle with one.
    """
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        require_subscription_ui(services)
        bundle_id = _bundle_id(callback.data)
        rate_limiter.check(callback.from_user.id, "bundle_show", 5)
        bundle = await services.key_bundle_views.get_for_actor(callback.from_user.id, bundle_id)
        keys = await services.key_bundle_views.list_keys_for_actor(callback.from_user.id, bundle_id)
        url = subscription_url(services.settings, bundle.token)
        # One ack per tap, carrying the duplicate-press notice when there is one — a
        # callback query answers only once, so the notice has to *be* the ack.
        duplicate = url is not None and await config_document_present(
            state, bundle_id, CONFIG_DOC_KIND_BUNDLE
        )
        await safe_callback_answer(callback, t("config_already_sent") if duplicate else None)
        await safe_edit_message_text(
            callback.message,
            bundle_config_text(bundle, services.settings),
            reply_markup=bundle_actions_keyboard(bundle, has_vless=bundle_has_vless(keys)),
        )
        if url is None:
            # No reachable listener — the card already says so; there is no URL to
            # encode, and a QR of a half-built one would be worse than none.
            return
        # The QR is still on screen — the card is refreshed above either way.
        if duplicate:
            return
        await discard_config_document(state, bot, callback.message.chat.id)
        await send_config_with_qr(
            callback.message,
            state,
            entity_id=bundle_id,
            qr_content=url,
            kind=CONFIG_DOC_KIND_BUNDLE,
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("bundle:fp:"))
async def change_bundle_fp_prompt(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Start the fingerprint wizard for every VLESS child of a bundle.

    Reuses ``EditFpStates`` — the states the per-key fingerprint flow uses — and
    marks the target with ``bundle_id`` in the FSM data, exactly as the note wizard
    does; the shared selection step in :mod:`bot.handlers.keys` branches on it.
    """
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        require_subscription_ui(services)
        bundle_id = _bundle_id(callback.data)
        await safe_callback_answer(callback)
        bundle = await services.key_bundle_views.get_for_actor(callback.from_user.id, bundle_id)
        await state.set_state(EditFpStates.waiting_fp)
        await state.update_data(bundle_id=bundle.id, key_id=None, cancel_target=f"bundle:open:{bundle.id}")
        await safe_edit_message_text(
            callback.message,
            t("bundle_fp_change_prompt"),
            reply_markup=fp_choice_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("bundle:revoke:"))
async def revoke_bundle_prompt(callback: CallbackQuery, services: Services) -> None:
    """Ask for confirmation before revoking a bundle."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        require_subscription_ui(services)
        bundle_id = _bundle_id(callback.data)
        await safe_callback_answer(callback)
        bundle = await services.key_bundle_views.get_for_actor(callback.from_user.id, bundle_id)
        await safe_edit_message_text(
            callback.message,
            t("bundle_revoke_prompt", bundle_id=bundle.id),
            reply_markup=bundle_confirm_keyboard("revoke", bundle.id),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("bundle:delete:"))
async def delete_bundle_prompt(callback: CallbackQuery, services: Services) -> None:
    """Ask for confirmation before deleting a bundle."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        require_subscription_ui(services)
        bundle_id = _bundle_id(callback.data)
        await safe_callback_answer(callback)
        bundle = await services.key_bundle_views.get_for_actor(callback.from_user.id, bundle_id)
        await safe_edit_message_text(
            callback.message,
            t("bundle_delete_prompt", bundle_id=bundle.id),
            reply_markup=bundle_confirm_keyboard("delete", bundle.id),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("bundle:confirm:"))
async def confirm_bundle_action(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter) -> None:
    """Execute the confirmed revoke or delete on a bundle."""
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        require_subscription_ui(services)
        action, bundle_id = _confirm_context(callback.data)
        if action == "revoke":
            rate_limiter.check(callback.from_user.id, "bundle_revoke", 10)
            await safe_callback_answer(callback, t("executing"))
            bundle = await services.key_bundles.revoke_bundle(callback.from_user.id, bundle_id)
            await safe_edit_message_text(
                callback.message,
                t("bundle_revoked"),
                reply_markup=bundle_actions_keyboard(bundle),
            )
            return
        if action == "delete":
            rate_limiter.check(callback.from_user.id, "bundle_delete", 10)
            await safe_callback_answer(callback, t("executing"))
            await services.key_bundles.delete_bundle(callback.from_user.id, bundle_id)
            await safe_edit_message_text(
                callback.message,
                t("bundle_deleted"),
                reply_markup=after_key_deleted_keyboard(),
            )
            return
        await safe_callback_answer(callback, t("unknown_action"), show_alert=True)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("bundle:note:"))
async def edit_bundle_note_prompt(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Start the note wizard for a bundle.

    Reuses ``EditNoteStates`` — the very states the per-key note flow uses — and
    marks the target with ``bundle_id`` in the FSM data; the shared steps in
    :mod:`bot.handlers.keys` branch on that.
    """
    if not await ensure_private_callback(callback):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        require_subscription_ui(services)
        bundle_id = _bundle_id(callback.data)
        await safe_callback_answer(callback)
        bundle = await services.key_bundle_views.get_for_actor(callback.from_user.id, bundle_id)
        await state.set_state(EditNoteStates.waiting_note)
        await state.update_data(
            bundle_id=bundle.id,
            key_id=None,
            cancel_target=f"bundle:open:{bundle.id}",
            note_prompt_msg_id=callback.message.message_id,
        )
        await safe_edit_message_text(
            callback.message,
            t("edit_note_prompt", type=t("bundle_type_label"), id=bundle.id),
            reply_markup=cancel_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _bundle_id(data: str) -> int:
    """Parse the trailing bundle id of a ``bundle:<verb>:<id>`` callback."""
    parts = data.split(":")
    if len(parts) != 3:
        raise InvalidCallbackData(t("invalid_callback_btn"))
    bundle_id = parse_int_callback(parts[2])
    if bundle_id is None:
        raise InvalidCallbackData(t("invalid_callback_btn"))
    return bundle_id


def _confirm_context(data: str) -> tuple[str, int]:
    """Parse ``bundle:confirm:<action>:<id>``."""
    parts = data.split(":")
    if len(parts) != 4 or parts[0] != "bundle" or parts[1] != "confirm":
        raise InvalidCallbackData(t("invalid_callback_btn"))
    bundle_id = parse_int_callback(parts[3])
    if bundle_id is None:
        raise InvalidCallbackData(t("invalid_callback_btn"))
    return parts[2], bundle_id
