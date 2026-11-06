"""Telegram command handlers for WARP selective-split list management.

Admin-only commands (superadmin gate via require_superadmin):
  /warp_split_list    — show current list (sorted) + prefix count
  /warp_split_add     — add one or more IPv4 CIDRs
  /warp_split_del     — remove one or more CIDRs
  /warp_split_reload  — re-apply the current file (recovery after manual edits)

Add and delete go through :class:`services.warp_split_feeds.WarpSplitFeedService`,
exactly like the panel's buttons, so a prefix typed here is stored as
origin='manual' and survives the next merge. The bot never calls
ip/route/iptables/awg-quick — all of that lives in the privileged helpers.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import BufferedInputFile, Message

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_message_error
from bot.private_chat import ensure_private_message
from i18n import t
from services.errors import InvalidOperation
from utils.formatting import code, h
from warp.split_manager import WarpSplitError, parse_cidr_tokens

router = Router()
logger = logging.getLogger(__name__)

# Above this rendered length /warp_split_list ships the prefixes as a document
# instead of a message. Telegram's own cap is 4096 characters, and the list grew
# past it the moment the feeds went on: 269 prefixes render to 8115 characters,
# so `message.answer` came back as TelegramBadRequest("message is too long") and
# the admin got no list at all. The margin below the cap absorbs the header and
# the per-line HTML the message form adds around each prefix.
WARP_SPLIT_LIST_MESSAGE_LIMIT = 3500

# Filename of the document form. Plain text, one prefix per line, no markup — it
# is meant to be greppable and to paste straight back into /warp_split_add.
WARP_SPLIT_LIST_FILENAME = "warp-split-list.txt"


# ── /warp_split_list ───────────────────────────────────────────────────────────


@router.message(Command("warp_split_list"))
async def warp_split_list_cmd(message: Message, services: Services) -> None:
    """Show the current selective-split list (sorted, with count)."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        mgr = services.warp_split
        entries = mgr.read_list()
        if not entries:
            await message.answer(t("warp_split_list_empty"))
            return
        lines = [t("warp_split_list_header", count=len(entries))]
        lines.extend(f"  {code(e)}" for e in entries)
        text = "\n".join(lines)
        if len(text) > WARP_SPLIT_LIST_MESSAGE_LIMIT:
            await message.answer_document(
                BufferedInputFile(
                    ("\n".join(entries) + "\n").encode("utf-8"),
                    filename=WARP_SPLIT_LIST_FILENAME,
                ),
                caption=t("warp_split_list_file_caption", count=len(entries)),
            )
            return
        await message.answer(text)
    except Exception as exc:
        await answer_message_error(message, exc)


# ── /warp_split_add ────────────────────────────────────────────────────────────


@router.message(Command("warp_split_add"))
async def warp_split_add_cmd(message: Message, services: Services) -> None:
    """Add one or more IPv4 CIDRs to the selective-split list.

    Usage: /warp_split_add 1.2.3.0/24 5.6.0.0/16
    Tokens may be separated by spaces, commas or newlines.
    Mask is mandatory — bare IPs are rejected.
    """
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)

        raw_args = _extract_args(message.text or "", "/warp_split_add")
        if not raw_args.strip():
            await message.answer(t("warp_split_add_usage"))
            return

        tokens = parse_cidr_tokens(raw_args)
        if not tokens:
            await message.answer(t("warp_split_no_tokens"))
            return

        # The same path as the panel's «Добавить» button: the prefix is recorded as
        # origin='manual' in the database before the list is re-merged. Writing
        # the file directly (as this command used to) lost the prefix on the next
        # merge, which builds the list from the stored origins.
        results, outcome = await services.warp_split_feeds.add_manual(
            tokens, actor_user_id=message.from_user.id
        )
        changed = outcome is not None and outcome.changed
        await message.answer(_format_add_report(results, changed=changed))

    except WarpSplitError as exc:
        await message.answer(t("warp_split_apply_error", error=h(exc)))
    except InvalidOperation as exc:
        await message.answer(t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_message_error(message, exc)


# ── /warp_split_del ────────────────────────────────────────────────────────────


@router.message(Command("warp_split_del"))
async def warp_split_del_cmd(message: Message, services: Services) -> None:
    """Remove one or more CIDRs from the selective-split list.

    Usage: /warp_split_del 1.2.3.0/24
    Refuses to empty the list entirely.
    """
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)

        raw_args = _extract_args(message.text or "", "/warp_split_del")
        if not raw_args.strip():
            await message.answer(t("warp_split_del_usage"))
            return

        tokens = parse_cidr_tokens(raw_args)
        if not tokens:
            await message.answer(t("warp_split_no_tokens"))
            return

        mgr = services.warp_split
        results, _remaining = mgr.process_del_tokens(tokens, mgr.read_list())

        # A prefix a feed supplies cannot be deleted — the next refresh brings it
        # back — so, like the panel (🚫 instead of 🗑), the command leaves it in
        # place and says where it comes from. Only hand-typed prefixes are
        # removed, through the database, so the next merge does not undo it.
        manual: list[str] = []
        for r in results:
            if r.status != "removed":
                continue
            origins = await services.warp_split_feeds.feed_origins(r.canonical)
            if origins:
                r.status = "feed"
                r.note = ", ".join(origins)
            else:
                manual.append(r.canonical)

        if not manual:
            await message.answer(_format_del_report(results, changed=False))
            return

        outcome = await services.warp_split_feeds.remove_manual_many(
            manual, actor_user_id=message.from_user.id
        )
        await message.answer(_format_del_report(results, changed=outcome.changed))

    except WarpSplitError as exc:
        await message.answer(t("warp_split_reject", error=h(exc)))
    except InvalidOperation as exc:
        await message.answer(t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_message_error(message, exc)


# ── /warp_split_reload ─────────────────────────────────────────────────────────


@router.message(Command("warp_split_reload"))
async def warp_split_reload_cmd(message: Message, services: Services) -> None:
    """Re-apply the current warp-split list (recovery after manual file edits)."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)

        mgr = services.warp_split
        current_list = mgr.read_list()
        if not current_list:
            await message.answer(t("warp_split_reload_empty"))
            return

        # reapply() forces the helper even on an unchanged file — the same call as
        # the panel's «🔄 Применить». apply_list() short-circuits on a byte-identical
        # file, so this command used to report a reload that never ran.
        await mgr.reapply()
        await message.answer(t("warp_split_reloaded", count=len(current_list)))

    except WarpSplitError as exc:
        await message.answer(t("warp_split_reload_error", error=h(exc)))
    except Exception as exc:
        await answer_message_error(message, exc)


# ── report formatters ─────────────────────────────────────────────────────────


def _format_add_report(results: list, *, changed: bool) -> str:  # type: ignore[type-arg]
    lines: list[str] = []
    for r in results:
        if r.status == "added":
            if r.note:
                lines.append(t("warp_split_report_added_note", cidr=code(r.canonical), note=h(r.note)))
            else:
                lines.append(t("warp_split_report_added", cidr=code(r.canonical)))
        elif r.status == "dup":
            lines.append(t("warp_split_report_dup", cidr=code(r.canonical or r.raw)))
        elif r.status == "rejected":
            lines.append(t("warp_split_report_rejected", cidr=code(r.raw), note=h(r.note)))

    if not changed:
        lines.append("\n" + t("warp_split_report_unchanged"))
    else:
        added_count = sum(1 for r in results if r.status == "added")
        lines.append("\n" + t("warp_split_report_applied_add", count=added_count))

    return "\n".join(lines)


def _format_del_report(results: list, *, changed: bool) -> str:  # type: ignore[type-arg]
    lines: list[str] = []
    for r in results:
        if r.status == "removed":
            lines.append(t("warp_split_report_removed", cidr=code(r.canonical)))
        elif r.status == "not_found":
            note = f" ({h(r.note)})" if r.note else ""
            lines.append(t("warp_split_report_not_found", cidr=code(r.canonical or r.raw), note=note))
        elif r.status == "feed":
            lines.append(t("warp_split_report_from_feed", cidr=code(r.canonical), origin=h(r.note)))

    if not changed:
        lines.append("\n" + t("warp_split_report_unchanged"))
    else:
        removed_count = sum(1 for r in results if r.status == "removed")
        lines.append("\n" + t("warp_split_report_applied_del", count=removed_count))

    return "\n".join(lines)


# ── utils ──────────────────────────────────────────────────────────────────────


def _extract_args(text: str, command: str) -> str:
    """Return the part of *text* after the command token (handles /cmd@botname)."""
    # Strip leading slash and any @botname suffix from the command
    parts = text.strip().split(None, 1)
    if len(parts) < 2:
        return ""
    return parts[1]
