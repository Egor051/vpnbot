"""«🌐 Сайт» — the wizard's screen of the decoy site (docs/site.md).

SUPERADMIN only. The screen reads ``vpn-bot-site status`` (services/site.py): where the site
is (the docroot of the nginx vhost on 127.0.0.1:8443) and its domain, the version that is
live (its tree's sha256, when and by which run it was deployed — or that it was put there by
hand —, pages, files, size), the kept versions, whether the spiderX pool names pages of the
site, and how Hysteria2's masquerade reaches it. Every change is a run of the wizard's
``site`` mode — a plan with the diff, then «✅ Применить» (both behind TOTP), apply → verify →
rollback:

  «⬆️ Загрузить архив»           TOTP, then a zip / tar.gz sent as a document: staged where
                                  root reads it (services/site.py), the run's plan unpacks
                                  and checks it in isolation and shows what changes
  «↩️ Откатить на предыдущую»    the newest kept version back, the same run
  «📄 Список страниц»            the pages of the live site (what the spiderX pool follows)
"""

from __future__ import annotations

import logging
from io import BytesIO
from typing import cast

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fsm.states import SiteStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.site_views import (
    PAGES_PER_SCREEN,
    pages_keyboard,
    pages_text,
    screen_keyboard,
    screen_text,
    upload_keyboard,
    upload_text,
)
from bot.totp_gate import require_totp
from bot.wizard_views import mode_title, run_view
from i18n import t
from services.errors import InvalidOperation, ServiceError
from services.site import MAX_ARCHIVE_BYTES, SiteService, SiteStatus
from services.wizard import WizardService
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


def _site(services: Services) -> SiteService:
    site = getattr(services, "site", None)
    if site is None:
        raise ServiceError("сайт не подключён", key="site_unavailable")
    return cast(SiteService, site)


def _wizard(services: Services) -> WizardService:
    if services.wizard is None:
        raise ServiceError("мастер не подключён", key="wizard_unavailable")
    return services.wizard


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


async def _still_elevated(services: Services, user_id: int) -> bool:
    totp = getattr(services, "totp", None)
    if totp is None:
        return True
    return not await totp.is_enabled(user_id) or totp.is_elevated(user_id)


async def _status(services: Services, actor: int) -> tuple[SiteStatus | None, str | None]:
    try:
        return await _site(services).status(actor), None
    except ServiceError as exc:
        return None, h(service_error_text(exc))


async def site_view(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    status, error = await _status(services, actor)
    return screen_text(status, error=error, notice=notice), screen_keyboard(status)


async def _already_running(callback: CallbackQuery, wizard: WizardService) -> bool:
    active = await wizard.active()
    if active is None:
        return False
    await safe_callback_answer(
        callback, t("wizard_already_running", id=active.id, mode=mode_title(active.mode)), show_alert=True
    )
    return True


@router.callback_query(F.data == "site:menu")
async def site_menu(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await state.clear()
        text, markup = await site_view(services, callback.from_user.id)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^site:pages:\d{1,4}$"))
async def site_pages(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        status, error = await _status(services, callback.from_user.id)
        if status is None:
            await safe_callback_answer(callback, error or t("site_status_unavailable"), show_alert=True)
            return
        last = max(0, (len(status.pages) - 1) // PAGES_PER_SCREEN)
        page = min(int(callback.data.rsplit(":", 1)[-1]), last)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, pages_text(status, page), reply_markup=pages_keyboard(status, page))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── «⬆️ Загрузить архив» ───────────────────────────────────────────────────────


@router.callback_query(F.data == "site:upload")
async def site_upload(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """TOTP first (the run is dangerous), then the prompt: the next document is the archive."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.message is not None
        if await _already_running(callback, _wizard(services)):
            return
        if not await require_totp(callback, state, services, action="wizard_site"):
            return
        status, _ = await _status(services, callback.from_user.id)
        await state.set_state(SiteStates.archive)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, upload_text(status), reply_markup=upload_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(SiteStates.archive)
async def site_archive_input(message: Message, state: FSMContext, services: Services, bot: Bot) -> None:
    """The archive: size and kind checked before and after the download, staged for root,
    and the run's plan starts on a message of its own."""
    try:
        if message.from_user is None:
            return
        if not await ensure_private_message(message, t("admin_private_only_text")):
            return
        await require_superadmin(services, message.from_user.id)
        actor = message.from_user.id
        if not await _still_elevated(services, actor):
            await state.clear()
            await message.answer(t("relay_reauth"), reply_markup=upload_keyboard())
            return
        document = message.document
        if document is None:
            await message.answer(t("site_upload_not_document"), reply_markup=upload_keyboard())
            return
        if (document.file_size or 0) > MAX_ARCHIVE_BYTES:
            await message.answer(t("site_err_too_large", max=MAX_ARCHIVE_BYTES // (1 << 20)), reply_markup=upload_keyboard())
            return
        wizard = _wizard(services)
        active = await wizard.active()
        if active is not None:
            await state.clear()
            await message.answer(t("wizard_already_running", id=active.id, mode=h(mode_title(active.mode))))
            return
        buffer = BytesIO()
        await bot.download(document, destination=buffer)
        site = _site(services)
        try:
            digest = site.stage(buffer.getvalue())
        except InvalidOperation as exc:
            await message.answer(f"{h(service_error_text(exc))}\n{t('cert_try_again')}", reply_markup=upload_keyboard())
            return
        await state.clear()
        holder = await message.answer(t("site_upload_received", name=h(document.file_name or "archive"), digest=digest))
        async with wizard.exclusive():
            busy = await wizard.active()
            if busy is not None:
                site.discard_upload()
                await safe_edit_message_text(holder, t("wizard_already_running", id=busy.id, mode=h(mode_title(busy.mode))))
                return
            run = await site.start(actor, "deploy", digest=digest, chat_id=holder.chat.id, message_id=holder.message_id)
            text, markup = run_view(run, await wizard.snapshot(run.id))
            await safe_edit_message_text(holder, text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


# ── «↩️ Откатить на предыдущую» ────────────────────────────────────────────────


@router.callback_query(F.data == "site:revert")
async def site_revert(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """A run of the «site» mode back to the newest kept version: its plan on this message."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.message is not None
        wizard = _wizard(services)
        if await _already_running(callback, wizard):
            return
        if not await require_totp(callback, state, services, action="wizard_site"):
            return
        status, _ = await _status(services, callback.from_user.id)
        if status is None or not status.revert_to:
            await safe_callback_answer(callback, t("site_nothing_to_revert"), show_alert=True)
            return
        async with wizard.exclusive():
            run = await _site(services).start(
                callback.from_user.id, "revert", chat_id=callback.message.chat.id, message_id=callback.message.message_id,
            )
            await safe_callback_answer(callback, t("wizard_started", id=run.id))
            text, markup = run_view(run, await wizard.snapshot(run.id))
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)
