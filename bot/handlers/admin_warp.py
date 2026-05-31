
import logging
import time
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
from warp.health import WarpHealthMonitor
from warp.state import WarpState

router = Router()
logger = logging.getLogger(__name__)

_SEP = "─────────────────────────"
_MAX_CONFIG_BYTES = 64 * 1024


# ── text builders ──────────────────────────────────────────────────────────


def _format_ago(last_handshake: int) -> str:
    if last_handshake <= 0:
        return t("warp_handshake_never")
    seconds = int(time.time()) - last_handshake
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return t("warp_ago_seconds", n=seconds)
    if seconds < 3600:
        return t("warp_ago_minutes", n=seconds // 60)
    if seconds < 86400:
        return t("warp_ago_hours", n=seconds // 3600)
    return t("warp_ago_days", n=seconds // 86400)


def _routes_value(state: WarpState) -> str:
    if state.routes_active:
        return t("warp_routes_active", count=state.routes_count)
    if not state.tunnel_up:
        return t("warp_routes_fallback")
    return t("warp_routes_inactive")


def warp_main_text(state: WarpState, *, last_error: str | None = None) -> str:
    lines = [t("warp_title"), _SEP]
    if not state.config_present:
        lines.append(t("warp_status_disabled"))
        lines.append("")
        lines.append(t("warp_intro"))
        lines.append("")
        lines.append(t("warp_no_config_hint"))
    elif not state.enabled:
        lines.append(f"{t('warp_label_module')} {t('warp_module_off')}")
        lines.append(f"{t('warp_settings_routes')} {state.routes_count}")
        lines.append("")
        lines.append(t("warp_intro"))
    else:
        lines.append(f"{t('warp_label_module')} {t('warp_module_on')}")
        lines.append(
            f"{t('warp_label_tunnel')} {t('warp_tunnel_up') if state.tunnel_up else t('warp_tunnel_down')}"
        )
        lines.append(f"{t('warp_label_routes')} {_routes_value(state)}")
        lines.append(f"{t('warp_label_handshake')} {_format_ago(state.last_handshake)}")
        lines.append(f"{t('warp_label_fails')} {state.fail_streak} / {WarpHealthMonitor.FAIL_THRESHOLD}")
    if last_error:
        lines.append("")
        lines.append(t("warp_last_error", error=h(last_error)))
    return "\n".join(lines)


def warp_settings_text(state: WarpState) -> str:
    return "\n".join(
        [
            t("warp_settings_title"),
            _SEP,
            f"{t('warp_settings_config')} {code(state.config_path)}",
            f"{t('warp_settings_iface')} {code(state.interface_name)}",
            f"{t('warp_settings_routes')} {state.routes_count}",
        ]
    )


async def _render_main(callback: CallbackQuery, services: Services) -> None:
    state = await services.warp.get_state()
    await safe_edit_message_text(
        callback.message,
        warp_main_text(state, last_error=services.warp.last_error),
        reply_markup=warp_main_keyboard(state),
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
            reply_markup=warp_settings_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── enable / disable / restart ─────────────────────────────────────────────


@router.callback_query(F.data == "admin:warp:enable")
async def warp_enable(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None) -> None:
    """Enable the WARP module (bring up the tunnel and add routes)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        await safe_callback_answer(callback, t("warp_processing"))
        await services.warp.enable()
        await _render_main(callback, services)
    except RateLimitExceeded as exc:
        await answer_callback_error(callback, exc)
    except Exception as exc:
        # Re-render so the operator sees the failure banner alongside the controls.
        await _safe_render_after_error(callback, services)
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:warp:disable")
async def warp_disable(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None) -> None:
    """Disable the WARP module (remove routes and bring the tunnel down)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        await safe_callback_answer(callback, t("warp_processing"))
        await services.warp.disable()
        await _render_main(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:warp:restart")
async def warp_restart(callback: CallbackQuery, services: Services, rate_limiter: RateLimiter | None = None) -> None:
    """Restart the WARP module."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        if rate_limiter is not None:
            rate_limiter.check(callback.from_user.id, "warp_toggle", 10)
        await safe_callback_answer(callback, t("warp_processing"))
        await services.warp.restart()
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
        await state.update_data(cancel_target="admin:warp")
        await safe_edit_message_text(
            callback.message,
            t("warp_upload_prompt"),
            reply_markup=warp_upload_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(WarpConfigStates.waiting_config)
async def warp_upload_receive(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    """Validate and install an uploaded AmneziaWG config."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        if message.document is None:
            await message.answer(t("warp_upload_not_document"), reply_markup=warp_upload_keyboard())
            return
        if (message.document.file_size or 0) > _MAX_CONFIG_BYTES:
            await message.answer(t("warp_upload_too_large"), reply_markup=warp_upload_keyboard())
            return
        try:
            buffer = BytesIO()
            await bot.download(message.document, destination=buffer)
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
        count = await services.warp.install_config(config_text)
        await state.clear()
        new_state = await services.warp.get_state()
        await message.answer(
            f"{t('warp_config_installed', count=count)}\n\n"
            f"{warp_main_text(new_state, last_error=services.warp.last_error)}",
            reply_markup=warp_main_keyboard(new_state),
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
        await safe_edit_message_text(
            callback.message,
            f"{t('warp_deleted')}\n\n{warp_main_text(state, last_error=services.warp.last_error)}",
            reply_markup=warp_main_keyboard(state),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _safe_render_after_error(callback: CallbackQuery, services: Services) -> None:
    try:
        await _render_main(callback, services)
    except Exception:
        logger.debug("Failed to re-render WARP panel after error", exc_info=True)
