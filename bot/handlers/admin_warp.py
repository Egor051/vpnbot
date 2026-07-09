
import logging
from contextlib import suppress
from io import BytesIO

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.container import Services
from bot.fsm.states import WarpConfigStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error
from bot.keyboards.warp_keyboard import (
    warp_delete_confirm_keyboard,
    warp_main_keyboard,
    warp_settings_keyboard,
    warp_upload_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.rate_limit import RateLimitExceeded, RateLimiter
from i18n import t
from utils.formatting import code, h
from warp.config_validator import WarpConfigError, validate_amnezia_config
from warp.split_manager import SplitStatus
from warp.state import WarpState

router = Router()
logger = logging.getLogger(__name__)

_SEP = "─────────────────────────"
_MAX_CONFIG_BYTES = 64 * 1024


# ── text builders ──────────────────────────────────────────────────────────


def _split_routes_value(split_status: SplitStatus) -> str:
    """Render the «Маршруты» line from the split-routing status.

    marker=on  & table==list → «✅ Активны (N CIDR)»
    marker=off & table empty → «⚪ Выключены (все direct)»
    drift (table ≠ intent)   → «⚠️ Рассинхрон …» shown as-is, never an error
    """
    if not split_status.in_sync:
        table = "?" if split_status.n_table is None else str(split_status.n_table)
        return t(
            "warp_routes_drift",
            marker=split_status.intended_state,
            table=table,
            count=split_status.n_list,
        )
    if split_status.intended_state == "on":
        base = t("warp_routes_active", count=split_status.n_list)
    else:
        base = t("warp_routes_off")
    # in_sync is True here — but when the table could not be read it is an
    # "assumed in sync", not a verified one. Flag that so the panel never presents
    # an unproven state as confirmed.
    if split_status.n_table is None:
        return f"{base} {t('warp_routes_unverified')}"
    return base


def warp_main_text(
    state: WarpState, split_status: SplitStatus, *, last_error: str | None = None
) -> str:
    lines = [t("warp_title"), _SEP]
    if not state.config_present:
        lines.append(t("warp_status_disabled"))
        lines.append("")
        lines.append(t("warp_intro"))
        lines.append("")
        lines.append(t("warp_no_config_hint"))
    else:
        # Tunnel is an observer-only signal (systemd owns the interface) and is
        # independent of the split on/off state.
        lines.append(
            f"{t('warp_label_tunnel')} {t('warp_tunnel_up') if split_status.tunnel_up else t('warp_tunnel_down')}"
        )
        lines.append(f"{t('warp_label_routes')} {_split_routes_value(split_status)}")
        lines.append("")
        lines.append(t("warp_routes_hint"))
    if last_error:
        lines.append("")
        lines.append(t("warp_last_error", error=h(last_error)))
    return "\n".join(lines)


def warp_settings_text(state: WarpState) -> str:
    kill_value = t("warp_killswitch_on") if state.kill_switch else t("warp_killswitch_off")
    lines = [
        t("warp_settings_title"),
        _SEP,
        f"{t('warp_settings_config')} {code(state.config_path)}",
        f"{t('warp_settings_iface')} {code(state.interface_name)}",
        f"{t('warp_settings_routes')} {state.routes_count}",
        f"{t('warp_settings_killswitch')} {kill_value}",
        "",
        t("warp_killswitch_hint"),
    ]
    return "\n".join(lines)


async def _render_main(callback: CallbackQuery, services: Services) -> None:
    state = await services.warp.get_state()
    split_status = await services.warp_split.status()
    await safe_edit_message_text(
        callback.message,
        warp_main_text(state, split_status, last_error=services.warp.last_error),
        reply_markup=warp_main_keyboard(state, split_status),
    )


# ── navigation ─────────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:warp")
async def warp_panel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Show the WARP main screen (live status from WarpState, no new probes)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.clear()
        await _render_main(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:warp:settings")
async def warp_settings(callback: CallbackQuery, services: Services) -> None:
    """Show the WARP settings screen."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        state = await services.warp.get_state()
        await safe_edit_message_text(
            callback.message,
            warp_settings_text(state),
            reply_markup=warp_settings_keyboard(state),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:warp:killswitch:toggle")
async def warp_killswitch_toggle(
    callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None
) -> None:
    """Flip the WARP kill-switch (fail-closed on tunnel-down) and re-render settings."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        state = await services.warp.get_state()
        await services.warp.set_kill_switch(not state.kill_switch)
        await safe_callback_answer(callback)
        new_state = await services.warp.get_state()
        await safe_edit_message_text(
            callback.message,
            warp_settings_text(new_state),
            reply_markup=warp_settings_keyboard(new_state),
        )
    except RateLimitExceeded as exc:
        await answer_callback_error(callback, exc)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── enable / disable / restart ─────────────────────────────────────────────


@router.callback_query(F.data == "admin:warp:enable")
async def warp_enable(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None) -> None:
    """Turn split ROUTING on: reconcile table T → saved list (never touches the tunnel)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        await safe_callback_answer(callback, t("warp_processing"))
        await services.warp_split.enable()
        await _render_main(callback, services)
    except RateLimitExceeded as exc:
        await answer_callback_error(callback, exc)
    except Exception as exc:
        # Re-render so the operator sees the failure banner alongside the controls.
        await _safe_render_after_error(callback, services)
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:warp:disable")
async def warp_disable(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None) -> None:
    """Turn split ROUTING off: reconcile table T → empty (all direct); list preserved."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        await safe_callback_answer(callback, t("warp_processing"))
        await services.warp_split.disable()
        await _render_main(callback, services)
    except Exception as exc:
        await _safe_render_after_error(callback, services)
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:warp:restart")
async def warp_restart(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None) -> None:
    """Restart split ROUTING: off-reconcile then on-reconcile (final state: on)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        await safe_callback_answer(callback, t("warp_processing"))
        await services.warp_split.restart_routes()
        await _render_main(callback, services)
    except Exception as exc:
        await _safe_render_after_error(callback, services)
        await answer_callback_error(callback, exc)


# ── config upload ──────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:warp:upload")
async def warp_upload_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Prompt the admin to send the AmneziaWG config as a document."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.set_state(WarpConfigStates.waiting_config)
        await state.update_data(cancel_target="admin:warp", upload_prompt_msg_id=callback.message.message_id)
        await safe_edit_message_text(
            callback.message,
            t("warp_upload_prompt"),
            reply_markup=warp_upload_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(WarpConfigStates.waiting_config)
async def warp_upload_receive(message: Message, state: FSMContext, services: Services, bot: Bot, rate_limiter: RateLimiter | None = None) -> None:
    """Validate and install an uploaded AmneziaWG config."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(message.from_user.id, "warp_upload", 30)
        document = message.document
        if document is None:
            await message.answer(t("warp_upload_not_document"), reply_markup=warp_upload_keyboard())
            return
        if (document.file_size or 0) > _MAX_CONFIG_BYTES:
            await message.answer(t("warp_upload_too_large"), reply_markup=warp_upload_keyboard())
            return
        try:
            buffer = BytesIO()
            await bot.download(document, destination=buffer)
            if len(buffer.getvalue()) > _MAX_CONFIG_BYTES:
                await message.answer(t("warp_upload_too_large"), reply_markup=warp_upload_keyboard())
                return
            config_text = buffer.getvalue().decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            await message.answer(t("warp_upload_read_failed"), reply_markup=warp_upload_keyboard())
            return
        try:
            validate_amnezia_config(config_text)
        except WarpConfigError as exc:
            await message.answer(
                t("warp_config_invalid", error=h(str(exc))),
                reply_markup=warp_upload_keyboard(),
            )
            return
        data = await state.get_data()
        upload_prompt_msg_id = data.get("upload_prompt_msg_id")
        count = await services.warp.install_config(config_text)
        await state.clear()
        if upload_prompt_msg_id:
            with suppress(Exception):
                await bot.delete_message(chat_id=message.chat.id, message_id=upload_prompt_msg_id)
        new_state = await services.warp.get_state()
        split_status = await services.warp_split.status()
        await message.answer(
            f"{t('warp_config_installed', count=count)}\n\n"
            f"{warp_main_text(new_state, split_status, last_error=services.warp.last_error)}",
            reply_markup=warp_main_keyboard(new_state, split_status),
        )
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


# ── delete config ──────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:warp:delete")
async def warp_delete_confirm(callback: CallbackQuery, services: Services) -> None:
    """Ask the admin to confirm deleting the WARP config."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_edit_message_text(
            callback.message,
            t("warp_delete_confirm"),
            reply_markup=warp_delete_confirm_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:warp:delete:confirm")
async def warp_delete(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None) -> None:
    """Delete the WARP config and disable the module."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        await safe_callback_answer(callback, t("warp_processing"))
        await services.warp.delete_config()
        state = await services.warp.get_state()
        split_status = await services.warp_split.status()
        await safe_edit_message_text(
            callback.message,
            f"{t('warp_deleted')}\n\n{warp_main_text(state, split_status, last_error=services.warp.last_error)}",
            reply_markup=warp_main_keyboard(state, split_status),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _safe_render_after_error(callback: CallbackQuery, services: Services) -> None:
    try:
        await _render_main(callback, services)
    except Exception:
        logger.debug("Failed to re-render WARP panel after error", exc_info=True)
