"""«Довести relay до нормы» in the bot (services/relay_hardening.py, docs/relay.md#bringing-a-relay-to-the-defaults).

* «🛡 Довести до нормы» (``rhard:go:<id>``) — under the superadmins' alert, on the relay's
  card, in the wizard's «🔑 SSH-порт relay» and «🛡 Входной фильтр relay»: the plan (each
  step ⚪) and «✅ Подтвердить» (bot/progress.py, D); an agent too old for it says
  «сначала обновите агент» with the button that does it.
* «✅ Подтвердить» (``rhard:ok:<id>``) — :meth:`services.relays.RelayService.harden`, its
  steps moving in the same message; the result with the steps as they ended.
* «Позже» (``rhard:later:<id>``) — remembered for this pairing: not asked again.
* «🛡 Входной фильтр relay» (``admin:rfilt``, the wizard's menu) — every relay with an
  agent, its filter, and «Довести» for each one that is not at the defaults.

SUPERADMIN only: the alert goes to the superadmins, but a callback can be fired by
anyone who can see the message, so every handler checks it. «Довести» changes the relay:
the TOTP gate (``relay_harden``) on the plan AND on the run (a button in the chat
history stays a button).
"""

from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from bot.progress import ProgressMessage, render_steps, steps_of
from bot.totp_gate import require_totp
from i18n import t
from models.dto import Relay
from services.errors import ServiceError
from services.relay_hardening import CALLBACK_PREFIX, what_text
from services.relays import (
    HARDEN_SSH_PORT,
    RelayHardening,
    agent_older_than,
    agent_release,
    agent_uninstalled,
    hardening_of,
)
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)


def harden_steps(hardening: RelayHardening) -> list[tuple[str, str]]:
    """The steps of «Довести» for what is left, in their order (filter first)."""
    keys = (["filter_on", "filter_confirm"] if hardening.filter_off else []) + (
        ["ssh_set", "ssh_finish"] if hardening.ssh_on_22 else []
    )
    return [(key, t(f"relay_harden_step_{key}", port=HARDEN_SSH_PORT)) for key in keys]


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def harden_button(relay_id: int) -> list[InlineKeyboardButton]:
    return _row(t("btn_relay_harden"), f"{CALLBACK_PREFIX}go:{relay_id}")


def _back_rows(relay_id: int) -> list[list[InlineKeyboardButton]]:
    return [_row(t("btn_relay_harden_to_card"), f"admin:relay:{relay_id}"), _row(t("btn_wizard_menu"), "wiz:menu")]


def plan_screen(relay: Relay) -> tuple[str, InlineKeyboardMarkup]:
    """«Довести»: the plan — or why there is none (at the defaults, an old agent)."""
    title = t("relay_harden_title", name=h(relay.name))
    hardening = hardening_of(relay)
    if hardening is None or not hardening.needed:
        return (f"{title}\n\n" + t("relay_harden_nothing", name=h(relay.name)),
                InlineKeyboardMarkup(inline_keyboard=_back_rows(relay.id)))
    if agent_older_than(relay.agent, hardening.agent_version):
        rows = [_row(t("btn_relay_agent_update"), f"admin:relay:{relay.id}:ag:up"), *_back_rows(relay.id)]
        return (f"{title}\n\n" + t("relay_harden_agent_old", name=h(relay.name), version=h(agent_release(relay.agent))),
                InlineKeyboardMarkup(inline_keyboard=rows))
    steps = render_steps(t("relay_harden_plan_steps", what=what_text(hardening)), steps_of(harden_steps(hardening)))
    text = f"{title}\n\n{steps.strip()}\n\n" + t("relay_harden_plan_note", port=HARDEN_SSH_PORT)
    rows = [
        _row(t("btn_relay_harden_confirm"), f"{CALLBACK_PREFIX}ok:{relay.id}"),
        _row(t("btn_relay_harden_later"), f"{CALLBACK_PREFIX}later:{relay.id}"),
        *_back_rows(relay.id),
    ]
    return text, InlineKeyboardMarkup(inline_keyboard=rows)


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


def _relay_id(data: str) -> int:
    return int(data.rsplit(":", 1)[1])


async def _progress_edit(message: object, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> bool:
    return await safe_edit_message_text(message, text, reply_markup=reply_markup)  # type: ignore[arg-type]


@router.callback_query(F.data.regexp(rf"^{CALLBACK_PREFIX}go:\d+$"))
async def relay_harden_plan(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="relay_harden"):
            return
        relay = await services.relays.get(callback.from_user.id, _relay_id(callback.data))
        await safe_callback_answer(callback)
        text, markup = plan_screen(relay)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(rf"^{CALLBACK_PREFIX}ok:\d+$"))
async def relay_harden_run(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """The run: :meth:`RelayService.harden` with its steps moving in this message."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="relay_harden"):
            return
        actor, relay_id = callback.from_user.id, _relay_id(callback.data)
        relay = await services.relays.get(actor, relay_id)
        hardening = hardening_of(relay)
        if hardening is None or not hardening.needed or agent_older_than(relay.agent, hardening.agent_version):
            await safe_callback_answer(callback)
            text, markup = plan_screen(relay)
            await safe_edit_message_text(callback.message, text, reply_markup=markup)
            return
        await safe_callback_answer(callback, t("relay_harden_working"))
        title = t("relay_harden_title", name=h(relay.name))
        view = ProgressMessage(callback.message, title, steps_of(harden_steps(hardening)), edit=_progress_edit)
        await view.push(force=True)

        async def on_progress(step: str, step_state: str) -> None:
            view.set(step, step_state)
            await view.push()

        try:
            await view.run(services.relays.harden(actor, relay_id, on_progress))
            notice = t("relay_harden_done", name=h(relay.name), port=HARDEN_SSH_PORT)
        except ServiceError as exc:
            if not any(step.state == "fail" for step in view.steps):
                view.fail_running()
            notice = t("relay_harden_failed", error=h(service_error_text(exc)))
        await view.finish(notice, InlineKeyboardMarkup(inline_keyboard=_back_rows(relay_id)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(rf"^{CALLBACK_PREFIX}later:\d+$"))
async def relay_harden_later(callback: CallbackQuery, services: Services) -> None:
    """«Позже»: remembered for this pairing; the way back stays."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay = await services.relays.get(callback.from_user.id, _relay_id(callback.data))
        monitor = getattr(services, "relay_hardening", None)
        if monitor is not None:
            await monitor.later(relay)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message, t("relay_harden_later_done", name=h(relay.name)),
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[harden_button(relay.id), *_back_rows(relay.id)]),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── «🛡 Входной фильтр relay» (the wizard's menu) ───────────────────────────────


def _filter_status(relay: Relay) -> str:
    status: dict[str, Any] = dict(relay.agent.last_status or {}) if relay.agent is not None else {}
    value = status.get("input_status")
    return str(value)[:120] if isinstance(value, str) and value else ""


def filter_screen(relays: list[Relay]) -> tuple[str, InlineKeyboardMarkup]:
    lines = [t("relay_filter_title"), "", t("relay_filter_intro"), ""]
    rows: list[list[InlineKeyboardButton]] = []
    managed = [r for r in relays if r.agent is not None and not agent_uninstalled(r.agent)]
    if not managed:
        lines.append(t("relay_filter_none"))
    for relay in managed:
        status = _filter_status(relay)
        line = (t("relay_filter_line", name=h(relay.name), status=h(status)) if status
                else t("relay_filter_line_unknown", name=h(relay.name)))
        hardening = hardening_of(relay)
        if hardening is not None and hardening.needed:
            line += " — ⚠️ " + what_text(hardening)
            rows.append(_row(t("btn_relay_harden_named", name=relay.name), f"{CALLBACK_PREFIX}go:{relay.id}"))
        lines.append(line)
    rows.append(_row(t("btn_wizard_menu"), "wiz:menu"))
    return "\n".join(lines), InlineKeyboardMarkup(inline_keyboard=rows)


@router.callback_query(F.data == "admin:rfilt")
async def relay_filter_list(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await safe_callback_answer(callback)
        relays = [o.relay for o in await services.relays.list_overview(callback.from_user.id)]
        text, markup = filter_screen(relays)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)
