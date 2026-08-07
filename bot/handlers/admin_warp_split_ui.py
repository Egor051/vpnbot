"""Inline GUI for WARP selective-split list management.

Presentation layer over :class:`~warp.split_manager.WarpSplitManager`: every
mutation goes through the manager (``process_*_tokens`` + ``apply_list``),
exactly like the ``/warp_split_*`` commands do. This module never touches
ip/route/iptables, never writes the list file, and never calls the privileged
helper directly — all of that already lives behind the manager.

The split list is governed by its own ``vpn-bot-warp-split`` service, so this GUI
is reachable from the WARP section regardless of the WARP tunnel-module state.

Every callback and the FSM input handler is superadmin-gated: a callback can be
fired by anyone who can see the message, so the gate is enforced server-side and
never relies on a button being hidden.
"""
from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.container import Services
from bot.fsm.states import WarpSplitStates
from bot.guards import require_superadmin
from bot.handlers.admin_warp_split import _format_add_report, _format_del_report
from bot.handlers.common import answer_callback_error, answer_message_error
from bot.keyboards.warp_split_keyboard import (
    split_clamp_page,
    split_page_slice,
    warp_split_add_keyboard,
    warp_split_del_confirm_keyboard,
    warp_split_panel_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from i18n import t
from services.errors import InvalidOperation
from utils.formatting import code, h
from warp.split_manager import parse_cidr_tokens
from warp.split_merge import resolve_origins

router = Router()
logger = logging.getLogger(__name__)


# ── text / render helpers ────────────────────────────────────────────────────


def _panel_text(entries: list[str]) -> str:
    lines = [t("warp_split_panel_title", count=len(entries))]
    if not entries:
        lines.append("")
        lines.append(t("warp_split_empty_hint"))
    return "\n".join(lines)


def _with_prefix(text: str, prefix: str) -> str:
    return f"{prefix}\n\n{text}" if prefix else text


async def _page_origins(services: Services, entries: list[str], page: int) -> dict[str, tuple[str, ...]]:
    """Resolve origins for the prefixes on *page* only.

    Per page rather than per list because the lookup is O(prefixes x stored
    contributions) and a single subtract source contributes ~1000 networks —
    resolving all 269 prefixes on every redraw would cost a quarter-million
    overlap tests to render eight buttons.
    """
    try:
        contributions = await services.warp_split_feeds.contributions()
    except Exception:
        logger.debug("warp-split: origin lookup unavailable", exc_info=True)
        return {}
    return resolve_origins(split_page_slice(entries, page), contributions)


async def _render_panel(callback: CallbackQuery, services: Services, page: int, *, prefix: str = "") -> None:
    """Re-read the list from the manager and (re)draw the panel by editing in place."""
    entries = services.warp_split.read_list()
    page = split_clamp_page(page, len(entries))
    origins = await _page_origins(services, entries, page)
    await safe_edit_message_text(
        callback.message,
        _with_prefix(_panel_text(entries), prefix),
        reply_markup=warp_split_panel_keyboard(entries, page, origins),
    )


async def _answer_panel(message: Message, services: Services, *, prefix: str = "") -> None:
    """Send the panel as a new message (used after FSM text input)."""
    entries = services.warp_split.read_list()
    origins = await _page_origins(services, entries, 0)
    await message.answer(
        _with_prefix(_panel_text(entries), prefix),
        reply_markup=warp_split_panel_keyboard(entries, 0, origins),
    )


def _page_from_data(data: str | None) -> int:
    if not data:
        return 0
    try:
        return int(data.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return 0


def _cidr_from_data(data: str) -> str:
    # data is "wsplit:del:<cidr>" or "wsplit:delok:<cidr>"; an IPv4 CIDR has no colon.
    return data.split(":", 2)[2]


# ── panel / pagination ───────────────────────────────────────────────────────


@router.callback_query(F.data.startswith("wsplit:p:"))
async def warp_split_panel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Open the split panel (also the cancel/back target, so it clears any FSM)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.clear()
        await _render_panel(callback, services, _page_from_data(callback.data))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── add (FSM) ────────────────────────────────────────────────────────────────


@router.callback_query(F.data == "wsplit:add")
async def warp_split_add_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Prompt for one or more CIDRs and enter the waiting state."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.set_state(WarpSplitStates.waiting_cidrs)
        await safe_edit_message_text(callback.message, t("warp_split_add_prompt"), reply_markup=warp_split_add_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(WarpSplitStates.waiting_cidrs)
async def warp_split_add_receive(message: Message, state: FSMContext, services: Services) -> None:
    """Parse the CIDR input, add via the manager, report per-line, return to panel."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        tokens = parse_cidr_tokens(message.text or "")
        if not tokens:
            await message.answer(
                t("warp_split_no_cidr"),
                reply_markup=warp_split_add_keyboard(),
            )
            return

        # Through the feed service, not the manager: a hand-typed prefix has to be
        # recorded as origin='manual' in the database, or the next merge — which
        # builds the list from stored origins — would drop it again. The service
        # validates via the same manager and applies under the same lock.
        results, outcome = await services.warp_split_feeds.add_manual(
            tokens, actor_user_id=message.from_user.id
        )
        changed = outcome is not None and outcome.changed

        await state.clear()
        await _answer_panel(message, services, prefix=_format_add_report(results, changed=changed))
    except InvalidOperation as exc:
        await state.clear()
        await _answer_panel(message, services, prefix=t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


# ── delete (confirm → execute) ───────────────────────────────────────────────


@router.callback_query(F.data.startswith("wsplit:delok:"))
async def warp_split_del_execute(callback: CallbackQuery, services: Services) -> None:
    """Remove the confirmed prefix via the manager and redraw the panel."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        cidr = _cidr_from_data(callback.data)
        mgr = services.warp_split
        # process_del_tokens raises (del-to-empty) before returning — surfaced below.
        results, _remaining = mgr.process_del_tokens([cidr], mgr.read_list())
        changed = any(r.status == "removed" for r in results)
        if changed:
            # Drop the manual row and re-merge, rather than writing the remaining
            # list directly: a prefix also supplied by a feed must come back on
            # the next refresh, and only the merge knows that. Feed-only prefixes
            # never reach this handler — the panel routes them to 🚫 (exclude).
            await services.warp_split_feeds.remove_manual(
                cidr, actor_user_id=callback.from_user.id
            )
        await _render_panel(callback, services, 0, prefix=_format_del_report(results, changed=changed))
    except InvalidOperation as exc:
        # guard-reject / del-to-empty / helper failure — show it, don't crash.
        await _render_panel(callback, services, 0, prefix=t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("wsplit:del:"))
async def warp_split_del_confirm(callback: CallbackQuery, services: Services) -> None:
    """Ask to confirm deleting a single prefix."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        cidr = _cidr_from_data(callback.data)
        await safe_edit_message_text(
            callback.message,
            t("warp_split_delete_confirm", cidr=code(cidr)),
            reply_markup=warp_split_del_confirm_keyboard(cidr),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── apply (reload) ───────────────────────────────────────────────────────────


@router.callback_query(F.data == "wsplit:apply")
async def warp_split_apply(callback: CallbackQuery, services: Services) -> None:
    """Re-apply the current list (recovery after manual edits / restart)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        mgr = services.warp_split
        current = mgr.read_list()
        if not current:
            await _render_panel(callback, services, 0, prefix=t("warp_split_apply_empty"))
            return
        # reapply() forces the helper call even when the file is unchanged: this
        # button exists precisely to re-run it after a manual edit or a restart
        # and let it reconcile table T, so the byte-identity short-circuit that
        # protects the automatic paths must not apply here.
        await mgr.reapply()
        await _render_panel(callback, services, 0, prefix=t("warp_split_applied", count=len(current)))
    except InvalidOperation as exc:
        await _render_panel(callback, services, 0, prefix=t("warp_split_apply_error", error=h(exc)))
    except Exception as exc:
        await answer_callback_error(callback, exc)
