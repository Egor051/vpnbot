
import logging

from aiogram import F, Router
from aiogram.types import CallbackQuery, InlineKeyboardMarkup

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, service_error_text
from bot.keyboards.admin_modules import (
    module_disable_confirm1_keyboard,
    module_disable_confirm2_keyboard,
    module_enable_confirm_keyboard,
    module_uninstall_plan_keyboard,
    modules_panel_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from bot.uninstall_texts import uninstall_plan_text, uninstall_report_text
from i18n import t
from repositories.protocol_modules import PROTOCOL_DISPLAY, PROTOCOL_NAMES, ProtocolModule
from services.errors import ServiceError
from services.protocol_uninstall import PlanChangedError, ProtocolUninstallService, UninstallPlan

router = Router()
logger = logging.getLogger(__name__)


def _uninstall(services: Services) -> ProtocolUninstallService | None:
    return getattr(services, "protocol_uninstall", None)


def _uninstalled(services: Services) -> frozenset[str]:
    """Protocols removed from the host (their marker), for the panel."""
    uninstall = _uninstall(services)
    return uninstall.registry.names if uninstall is not None else frozenset()


# The .env flag that gates each protocol (Xray and AWG have none).
_ENV_FLAGS: dict[str, str] = {
    "hysteria2": "HYSTERIA2_ENABLED",
    "socks5": "SOCKS5_ENABLED",
    "mtproto": "MTPROTO_ENABLED",
}


def _env_off(services: Services) -> frozenset[str]:
    """Protocols switched off in ``.env`` — the toggle cannot turn those on."""
    settings = getattr(services, "settings", None)
    if settings is None:
        return frozenset()
    off: set[str] = set()
    hy2_ready = getattr(settings, "is_hysteria2_ready", None)
    if not (getattr(settings, "hysteria2_enabled", False) and callable(hy2_ready) and hy2_ready()):
        off.add("hysteria2")
    if not getattr(settings, "socks5_enabled", False):
        off.add("socks5")
    if not getattr(settings, "mtproto_enabled", False):
        off.add("mtproto")
    return frozenset(off)


def _panel_markup(services: Services, modules: list[ProtocolModule]) -> InlineKeyboardMarkup:
    return modules_panel_keyboard(modules, _uninstalled(services), _env_off(services))


@router.callback_query(F.data == "admin:modules")
async def admin_modules_panel(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        modules = await services.modules.get_all()
        await safe_edit_message_text(
            callback.message,
            t("modules_panel_title"),
            reply_markup=_panel_markup(services, modules),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:disable:[a-z0-9]+$"))
async def admin_module_disable_step1(callback: CallbackQuery, services: Services) -> None:
    """First disable confirmation step."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-1]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await safe_edit_message_text(
            callback.message,
            t("module_disable_confirm1", label=label),
            reply_markup=module_disable_confirm1_keyboard(name),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:disable:[a-z0-9]+:2$"))
async def admin_module_disable_step2(callback: CallbackQuery, services: Services) -> None:
    """Second disable confirmation step."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-2]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await safe_edit_message_text(
            callback.message,
            t("module_disable_confirm2", label=label),
            reply_markup=module_disable_confirm2_keyboard(name),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:disable:[a-z0-9]+:exec$"))
async def admin_module_disable_exec(callback: CallbackQuery, services: Services) -> None:
    """Execute protocol disable: delete all data and mark as disabled."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("module_disabling"))
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-2]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        deleted, failed = await services.modules.disable_protocol(name, callback.from_user.id)
        modules = await services.modules.get_all()
        text = t("module_disabled_ok", label=label, deleted=deleted)
        if failed > 0:
            text += "\n\n" + t("module_disabled_partial", failed=failed)
        await safe_edit_message_text(
            callback.message,
            text,
            reply_markup=_panel_markup(services, modules),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:enable:[a-z0-9]+$"))
async def admin_module_enable_confirm(callback: CallbackQuery, services: Services) -> None:
    """Show enable confirmation."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-1]
        if name not in PROTOCOL_NAMES:
            return
        if name in _uninstalled(services):
            # Removed from the host: switching the toggle back would offer a
            # backend that is not there. Only a reinstall (and the marker gone) helps.
            await safe_callback_answer(callback, t("module_enable_blocked_uninstalled"), show_alert=True)
            return
        if name in _env_off(services):
            await safe_callback_answer(
                callback, t("module_env_off_alert", label=PROTOCOL_DISPLAY.get(name, name), flag=_ENV_FLAGS[name]), show_alert=True
            )
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await safe_edit_message_text(
            callback.message,
            t("module_enable_confirm", label=label),
            reply_markup=module_enable_confirm_keyboard(name),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:enable:[a-z0-9]+:exec$"))
async def admin_module_enable_exec(callback: CallbackQuery, services: Services) -> None:
    """Execute protocol enable."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("module_enabling"))
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-2]
        if name not in PROTOCOL_NAMES:
            return
        label = PROTOCOL_DISPLAY.get(name, name)
        await services.modules.enable_protocol(name, callback.from_user.id)
        modules = await services.modules.get_all()
        await safe_edit_message_text(
            callback.message,
            t("module_enabled_ok", label=label),
            reply_markup=_panel_markup(services, modules),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:envoff:[a-z0-9]+$"))
async def admin_module_env_off(callback: CallbackQuery, services: Services) -> None:
    """The «.env» info button next to a protocol that ``.env`` switches off: say which flag."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-1]
        if name not in _ENV_FLAGS:
            await safe_callback_answer(callback)
            return
        await safe_callback_answer(
            callback, t("module_env_off_alert", label=PROTOCOL_DISPLAY.get(name, name), flag=_ENV_FLAGS[name]), show_alert=True
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── Removal from the server (protocol uninstall) ─────────────────────────────────
def _plan_markup(name: str, plan: UninstallPlan) -> InlineKeyboardMarkup:
    applicable = not plan.nothing_to_do and not plan.blocking
    return module_uninstall_plan_keyboard(name, plan.sha_prefix if applicable else None)


@router.callback_query(F.data.regexp(r"^admin:module:uninst:[a-z0-9]+$"))
async def admin_module_uninstall_plan(callback: CallbackQuery, services: Services) -> None:
    """Show the helper's plan for removing the protocol from the server."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback, t("module_uninstall_planning"))
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        name = callback.data.split(":")[-1]
        uninstall = _uninstall(services)
        if name not in PROTOCOL_NAMES or uninstall is None:
            return
        plan = await uninstall.plan(name, callback.from_user.id)
        await safe_edit_message_text(
            callback.message, uninstall_plan_text(plan), reply_markup=_plan_markup(name, plan)
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:module:uninst:[a-z0-9]+:x:[0-9a-f]{12}$"))
async def admin_module_uninstall_exec(callback: CallbackQuery, services: Services) -> None:
    """Apply the plan the admin confirmed: purge, then the helper's removal.

    The callback is answered at once — the removal takes minutes and a late answer
    is rejected by Telegram — so every outcome, failures included, is written into
    the message itself rather than an alert.
    """
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        await safe_callback_answer(callback)
        return
    parts = callback.data.split(":")
    name, prefix = parts[3], parts[5]
    uninstall = _uninstall(services)
    if name not in PROTOCOL_NAMES or uninstall is None:
        await safe_callback_answer(callback)
        return
    try:
        await require_superadmin(services, callback.from_user.id)
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return
    sha = uninstall.resolve_sha(callback.from_user.id, name, prefix)
    if sha is None:
        await safe_callback_answer(callback, t("module_uninstall_plan_expired"), show_alert=True)
        return
    await safe_callback_answer(callback, t("module_uninstall_running"))
    await safe_edit_message_text(callback.message, t("module_uninstall_running"))
    try:
        report = await uninstall.apply(name, sha, callback.from_user.id)
    except PlanChangedError as exc:
        await safe_edit_message_text(
            callback.message,
            service_error_text(exc) + "\n\n" + uninstall_plan_text(exc.plan),
            reply_markup=_plan_markup(name, exc.plan),
        )
        return
    except ServiceError as exc:
        modules = await services.modules.get_all()
        await safe_edit_message_text(
            callback.message,
            service_error_text(exc),
            reply_markup=_panel_markup(services, modules),
        )
        return
    except Exception:
        logger.exception("Protocol %s uninstall crashed", name)
        modules = await services.modules.get_all()
        await safe_edit_message_text(
            callback.message,
            t("internal_error"),
            reply_markup=_panel_markup(services, modules),
        )
        return
    modules = await services.modules.get_all()
    await safe_edit_message_text(
        callback.message,
        uninstall_report_text(report),
        reply_markup=_panel_markup(services, modules),
    )
