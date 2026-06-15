"""Telegram command handlers for WARP selective-split list management.

Admin-only commands (superadmin gate via require_superadmin):
  /warp_split_list    — show current list (sorted) + prefix count
  /warp_split_add     — add one or more IPv4 CIDRs
  /warp_split_del     — remove one or more CIDRs
  /warp_split_reload  — re-apply the current file (recovery after manual edits)

The bot is a thin controller: it reads the list file directly (0644) and writes
exclusively through the privileged helper (vpnbot-warp-split-apply). It never
calls ip/route/iptables/awg-quick — all of that lives in the helper script.
"""
from __future__ import annotations

import logging

from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_message_error
from bot.private_chat import ensure_private_message
from i18n import t
from services.errors import InvalidOperation
from warp.split_manager import WarpSplitError, parse_cidr_tokens

router = Router()
logger = logging.getLogger(__name__)


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
            await message.answer("Список WARP split пуст или файл не существует.")
            return
        lines = [f"<b>WARP split-list</b> ({len(entries)} prefix'ов):"]
        lines.extend(f"  <code>{e}</code>" for e in entries)
        await message.answer("\n".join(lines))
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
            await message.answer(
                "Использование: /warp_split_add <cidr> [<cidr> ...]\n"
                "Пример: /warp_split_add 91.108.4.0/22 142.250.0.0/15\n"
                "Маска обязательна (голый IP отклоняется)."
            )
            return

        tokens = parse_cidr_tokens(raw_args)
        if not tokens:
            await message.answer("Не найдено ни одного токена для разбора.")
            return

        mgr = services.warp_split
        current_list = mgr.read_list()
        current_set = set(current_list)

        results, accepted = mgr.process_add_tokens(tokens, current_set)

        if not accepted and all(r.status == "dup" for r in results):
            await message.answer(_format_add_report(results, changed=False))
            return

        if not accepted:
            await message.answer(_format_add_report(results, changed=False))
            return

        new_list = sorted(
            current_set | set(accepted),
            key=lambda s: __import__("ipaddress").ip_network(s),
        )
        await mgr.apply_list(new_list)
        await message.answer(_format_add_report(results, changed=True))

    except WarpSplitError as exc:
        await message.answer(f"Ошибка применения: {exc}")
    except InvalidOperation as exc:
        await message.answer(f"Отказ: {exc}")
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
            await message.answer(
                "Использование: /warp_split_del <cidr> [<cidr> ...]\n"
                "Пример: /warp_split_del 91.108.4.0/22"
            )
            return

        tokens = parse_cidr_tokens(raw_args)
        if not tokens:
            await message.answer("Не найдено ни одного токена для разбора.")
            return

        mgr = services.warp_split
        current_list = mgr.read_list()

        results, remaining = mgr.process_del_tokens(tokens, current_list)

        removed = [r for r in results if r.status == "removed"]
        if not removed:
            await message.answer(_format_del_report(results, changed=False))
            return

        await mgr.apply_list(remaining)
        await message.answer(_format_del_report(results, changed=True))

    except WarpSplitError as exc:
        await message.answer(f"Отказ: {exc}")
    except InvalidOperation as exc:
        await message.answer(f"Отказ: {exc}")
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
            await message.answer(
                "Список пуст или файл не существует — перезагрузка невозможна.\n"
                "Добавь хотя бы один префикс командой /warp_split_add."
            )
            return

        await mgr.apply_list(current_list)
        await message.answer(
            f"vpnbot-warp-split перезапущен.\n"
            f"Применено {len(current_list)} prefix'ов из текущего файла."
        )

    except WarpSplitError as exc:
        await message.answer(f"Ошибка перезагрузки: {exc}")
    except Exception as exc:
        await answer_message_error(message, exc)


# ── report formatters ─────────────────────────────────────────────────────────


def _format_add_report(results: list, *, changed: bool) -> str:  # type: ignore[type-arg]
    lines: list[str] = []
    for r in results:
        if r.status == "added":
            if r.note:
                lines.append(f"✓ добавлен <code>{r.canonical}</code> ({r.note})")
            else:
                lines.append(f"✓ добавлен <code>{r.canonical}</code>")
        elif r.status == "dup":
            lines.append(f"— уже есть <code>{r.canonical or r.raw}</code>")
        elif r.status == "rejected":
            lines.append(f"✗ отклонён <code>{r.raw}</code> — {r.note}")

    if not changed:
        lines.append("\nСписок не изменён.")
    else:
        added_count = sum(1 for r in results if r.status == "added")
        lines.append(f"\nПрименено: +{added_count} prefix'ов, vpnbot-warp-split перезапущен.")

    return "\n".join(lines)


def _format_del_report(results: list, *, changed: bool) -> str:  # type: ignore[type-arg]
    lines: list[str] = []
    for r in results:
        if r.status == "removed":
            lines.append(f"✓ удалён <code>{r.canonical}</code>")
        elif r.status == "not_found":
            note = f" ({r.note})" if r.note else ""
            lines.append(f"— не найден <code>{r.canonical or r.raw}</code>{note}")

    if not changed:
        lines.append("\nСписок не изменён.")
    else:
        removed_count = sum(1 for r in results if r.status == "removed")
        lines.append(f"\nПрименено: -{removed_count} prefix'ов, vpnbot-warp-split перезапущен.")

    return "\n".join(lines)


# ── utils ──────────────────────────────────────────────────────────────────────


def _extract_args(text: str, command: str) -> str:
    """Return the part of *text* after the command token (handles /cmd@botname)."""
    # Strip leading slash and any @botname suffix from the command
    parts = text.strip().split(None, 1)
    if len(parts) < 2:
        return ""
    return parts[1]
