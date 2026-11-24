"""«🔐 Сертификат и DNS» — the wizard's screen of the bot's TLS certificate (docs/certificate.md).

SUPERADMIN only. The screen reads ``vpn-bot-cert status`` (services/cert.py): the
certificate (SAN, expiry, key, the reloadcmd acme.sh calls), every reader of the
registry and whether it holds the current pair, the bot's Cloudflare token and the DNS
records the bot owns. Every change is a run of the wizard's ``cert`` mode — a plan with
the diff, then «✅ Применить» (both behind TOTP), apply → verify → rollback:

  «🔁 Принять текущий сертификат»  adopt the hand-made acme.sh setup (no reissue)
  «🆕 Выпустить / перевыпустить»   issue for the names shown («✏️ Другие имена» to change)
  «🔄 Проверить продление»        acme.sh --renew --force, end to end
  «📦 Разложить заново»           the current pair to a reader whose copy differs
  «🔑 Токен Cloudflare»           the bot's ONE token (services/dns.py): typed into the
                                  chat — the message is deleted the moment it is read —,
                                  checked against the zone (verify, read, a TXT probe
                                  written and deleted) BEFORE it is stored
"""

from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardMarkup, Message

from bot.cert_views import (
    cancel_keyboard,
    issue_keyboard,
    issue_text,
    screen_keyboard,
    screen_text,
    token_keyboard,
    token_text,
)
from bot.container import Services
from bot.fsm.states import CertStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.totp_gate import require_totp
from bot.wizard_views import mode_title, run_view
from i18n import t
from services.cert import CertService, CertStatus
from services.dns import DnsService
from services.errors import InvalidOperation, ServiceError
from utils.formatting import code, h

router = Router()
logger = logging.getLogger(__name__)


def _cert(services: Services) -> CertService:
    if services.cert is None:
        raise ServiceError("сертификат не подключён", key="cert_unavailable")
    return services.cert


def _dns(services: Services) -> DnsService:
    if services.dns is None:
        raise ServiceError("DNS не подключён", key="cert_unavailable")
    return services.dns


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


async def _guard_message(message: Message, services: Services) -> bool:
    if message.from_user is None:
        return False
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return False
    await require_superadmin(services, message.from_user.id)
    return True


async def _still_elevated(services: Services, user_id: int) -> bool:
    totp = getattr(services, "totp", None)
    if totp is None:
        return True
    return not await totp.is_enabled(user_id) or totp.is_elevated(user_id)


async def _status(services: Services, actor: int) -> tuple[CertStatus | None, str | None]:
    try:
        return await _cert(services).status(actor), None
    except ServiceError as exc:
        return None, h(service_error_text(exc))


async def cert_view(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    status, error = await _status(services, actor)
    dns = _dns(services)
    text = screen_text(status, await dns.owned(), token_fp=dns.token_fingerprint(), error=error, notice=notice)
    return text, screen_keyboard(status)


@router.callback_query(F.data == "cert:menu")
async def cert_menu(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await state.clear()
        text, markup = await cert_view(services, callback.from_user.id)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── «🆕 Выпустить / перевыпустить» ─────────────────────────────────────────────


@router.callback_query(F.data == "cert:issue")
async def cert_issue(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await state.clear()
        status, _ = await _status(services, callback.from_user.id)
        names = _cert(services).chosen_names(callback.from_user.id, status)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, issue_text(names, status), reply_markup=issue_keyboard(bool(names)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "cert:names")
async def cert_names(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.message is not None
        await state.set_state(CertStates.names)
        await safe_callback_answer(callback)
        await callback.message.answer(t("cert_ask_names"), reply_markup=cancel_keyboard("cert:issue"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(CertStates.names)
async def cert_names_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        cert = _cert(services)
        try:
            names = cert.set_names(message.from_user.id, message.text or "")
        except InvalidOperation as exc:
            await message.answer(f"{h(service_error_text(exc))}\n{t('cert_try_again')}", reply_markup=cancel_keyboard("cert:issue"))
            return
        await state.clear()
        status, _ = await _status(services, message.from_user.id)
        await message.answer(issue_text(names, status), reply_markup=issue_keyboard(True))
    except Exception as exc:
        await answer_message_error(message, exc)


# ── the runs ──────────────────────────────────────────────────────────────────


@router.callback_query(F.data.regexp(r"^cert:go:(issue|renew|adopt|deploy)$"))
async def cert_go(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """A run of the wizard's «cert» mode: its plan first (the diff), then «✅ Применить»."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.from_user is not None and callback.message is not None
        action = callback.data.rsplit(":", 1)[-1]
        wizard = services.wizard
        if wizard is None:
            raise ServiceError("мастер не подключён", key="wizard_unavailable")
        active = await wizard.active()
        if active is not None:
            await safe_callback_answer(
                callback, t("wizard_already_running", id=active.id, mode=mode_title(active.mode)), show_alert=True
            )
            return
        if not await require_totp(callback, state, services, action="wizard_cert"):
            return
        cert = _cert(services)
        status, _ = await _status(services, callback.from_user.id)
        names = cert.chosen_names(callback.from_user.id, status) if action == "issue" else (status.names if status else [])
        async with wizard.exclusive():
            run = await cert.start(
                callback.from_user.id, action, names=names,
                chat_id=callback.message.chat.id, message_id=callback.message.message_id,
            )
            await safe_callback_answer(callback, t("wizard_started", id=run.id))
            text, markup = run_view(run, await wizard.snapshot(run.id))
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── «🔑 Токен Cloudflare» ──────────────────────────────────────────────────────


async def _token_screen(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    dns = _dns(services)
    status, _ = await _status(services, actor)
    fp = dns.token_fingerprint()
    return token_text(fp, status, str(dns.token_file.path), notice), token_keyboard(dns.token_set())


@router.callback_query(F.data == "cert:token")
async def cert_token(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await state.clear()
        text, markup = await _token_screen(services, callback.from_user.id)
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "cert:tok:set")
async def cert_token_set(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.message is not None
        if not await require_totp(callback, state, services, action="dns_token"):
            return
        await state.set_state(CertStates.token)
        await safe_callback_answer(callback)
        await callback.message.answer(t("cert_ask_token"), reply_markup=cancel_keyboard("cert:token"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "cert:tok:del")
async def cert_token_delete(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="dns_token"):
            return
        removed = await _dns(services).delete_token(callback.from_user.id)
        await safe_callback_answer(callback, t("cert_token_deleted") if removed else t("cert_token_none"))
        text, markup = await _token_screen(services, callback.from_user.id)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(CertStates.token)
async def cert_token_input(message: Message, state: FSMContext, services: Services) -> None:
    """The token: the message goes away FIRST, whatever it holds — then the check."""
    raw = message.text or ""
    try:
        await message.delete()
    except Exception:
        logger.warning("Certificate: the message with the Cloudflare token could not be deleted — delete it by hand")
        await message.answer(t("cert_token_delete_by_hand"))
    try:
        if not await _guard_message(message, services):
            return
        assert message.from_user is not None
        actor = message.from_user.id
        if not await _still_elevated(services, actor):
            await state.clear()
            await message.answer(t("relay_reauth"), reply_markup=cancel_keyboard("cert:token"))
            return
        status, _ = await _status(services, actor)
        try:
            name = _cert(services).token_check_name(status)
            check = await _dns(services).set_token(actor, raw, name)
        except InvalidOperation as exc:
            await message.answer(f"{h(service_error_text(exc))}\n{t('cert_try_again')}", reply_markup=cancel_keyboard("cert:token"))
            return
        await state.clear()
        notice = t("cert_token_saved", fp=code(check.fingerprint), zone=code(check.zone.name))
        text, markup = await _token_screen(services, actor, notice)
        await message.answer(text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)
