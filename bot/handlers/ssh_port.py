"""The SSH port migration in the bot (services/ssh_port.py, docs/host-state.md#the-ssh-port).

* «Подтвердить» under the MAIN server's migration message: runs the root helper.
* A RELAY's migration (its agent's status): «Подтвердить» — the bot reaches the agent
  on the NEW port and phase 2 runs in that call (``RelayService.finish_ssh_port``);
  «Оставить <old>» holds phase 1 on the relay; «Вернуться к переезду» releases it.
* «🔑 SSH-порт relay» in the setup wizard's menu: every relay with an agent, its port
  and migration; per relay the buttons above and «Сменить порт» (a typed port:
  ``RelayService.set_ssh_port`` — phase 1 right away, no deploy).

SUPERADMIN only: the buttons go to the superadmins, but a callback can be fired by
anyone who can see the message, so every handler checks it, never the keyboard. A
relay's change is a dangerous action behind the TOTP gate (``relay_ssh_port``). The
relay id, the port and the migration's start travel in the button; the relay's helper
refuses a button of any other migration.
"""

from __future__ import annotations

import logging
from typing import Any

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fsm.states import RelaySshPortStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.progress import ProgressMessage, render_steps, steps_of
from bot.totp_gate import require_totp
from i18n import t
from models.dto import Relay
from services.errors import ServiceError
from services.relay_hardening import warning_line as hardening_warning_line
from services.relays import agent_uninstalled, hardening_of
from services.ssh_port import (
    CALLBACK_PREFIX,
    RELAY_CALLBACK_PREFIX,
    Migration,
    migration_from_plan,
    parse_callback_data,
    parse_relay_callback,
    relay_callback_data,
)
from utils.formatting import code, h

router = Router()
logger = logging.getLogger(__name__)


@router.callback_query(F.data.startswith(CALLBACK_PREFIX))
async def ssh_port_confirm(callback: CallbackQuery, services: Services) -> None:
    if callback.from_user is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        parsed = parse_callback_data(callback.data)
        if parsed is None or services.ssh_port is None:
            await safe_callback_answer(callback, t("ssh_port_confirm_stale"), show_alert=True)
            return
        port, since = parsed
        line = await services.ssh_port.confirm(callback.from_user.id, port, since)
        logger.info("SSH port %d confirmed by superadmin %d: %s", port, callback.from_user.id, line)
        await safe_callback_answer(callback, t("ssh_port_confirmed_alert", port=port), show_alert=True)
        if isinstance(callback.message, Message):
            await callback.message.answer(t("ssh_port_confirmed", port=port, line=h(line)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── a relay's migration ───────────────────────────────────────────────────────


def _migration(relay: Relay) -> tuple[Migration, bool] | None:
    status: dict[str, Any] = dict(relay.agent.last_status or {}) if relay.agent is not None else {}
    return migration_from_plan(status.get("ssh_migration"))


def _plan(relay: Relay) -> dict[str, Any]:
    status: dict[str, Any] = dict(relay.agent.last_status or {}) if relay.agent is not None else {}
    plan = status.get("ssh_migration")
    return plan if isinstance(plan, dict) else {}


def relay_ssh_line(relay: Relay) -> str:
    """One relay of the «🔑 SSH-порт relay» screen."""
    assert relay.agent is not None
    found = _migration(relay)
    if found is not None:
        m, held = found
        key = "relay_ssh_port_line_held" if held else "relay_ssh_port_line_phase1"
        return t(key, name=h(relay.name), old=h(m.old), new=m.to)
    plan = _plan(relay)
    if not plan:
        return t("relay_ssh_port_line_unknown", name=h(relay.name), port=relay.agent.ssh_port)
    return t("relay_ssh_port_line_steady", name=h(relay.name), port=h(str(plan.get("ssh_port") or relay.agent.ssh_port)))


def relay_ssh_keyboard(relay: Relay) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    found = _migration(relay)
    if found is not None:
        m, held = found
        if held:
            rows.append([InlineKeyboardButton(text=t("btn_relay_ssh_port_resume"),
                                              callback_data=relay_callback_data("resume", relay.id, m))])
        else:
            rows.append([InlineKeyboardButton(text=t("btn_relay_ssh_port_confirm", old=m.old),
                                              callback_data=relay_callback_data("ok", relay.id, m))])
            rows.append([InlineKeyboardButton(text=t("btn_relay_ssh_port_keep", old=m.old),
                                              callback_data=relay_callback_data("keep", relay.id, m))])
    hardening = hardening_of(relay)
    if hardening is not None and hardening.needed:
        # SSH on 22 / no input filter: «Довести» (bot/handlers/relay_hardening.py) — also after «Позже».
        rows.append([InlineKeyboardButton(text=t("btn_relay_harden"), callback_data=f"rhard:go:{relay.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_relay_ssh_port_set"), callback_data=f"admin:sshp:{relay.id}:set")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:sshp")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def _managed(services: Services, actor: int) -> list[Relay]:
    relays = [r.relay for r in await services.relays.list_overview(actor)]
    return [r for r in relays if r.agent is not None and not agent_uninstalled(r.agent)]


def _list_screen(relays: list[Relay]) -> tuple[str, InlineKeyboardMarkup]:
    lines = [t("relay_ssh_port_title"), "", t("relay_ssh_port_intro"), ""]
    if relays:
        lines.extend(relay_ssh_line(r) for r in relays)
    else:
        lines.append(t("relay_ssh_port_none"))
    rows = [[InlineKeyboardButton(text=f"🔑 {r.name}", callback_data=f"admin:sshp:{r.id}")] for r in relays]
    rows.append([InlineKeyboardButton(text=t("btn_wizard_menu"), callback_data="wiz:menu")])
    return "\n".join(lines), InlineKeyboardMarkup(inline_keyboard=rows)


async def _relay_screen(services: Services, actor: int, relay_id: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    relay = await services.relays.get(actor, relay_id)
    lines = [notice, ""] if notice else []
    lines += [t("relay_ssh_port_relay_title", name=h(relay.name)), relay_ssh_line(relay)]
    warning = hardening_warning_line(relay)
    if warning:
        lines.append(warning)
    if relay.agent is not None:
        lines.append(t("relay_ssh_port_bot_port", port=code(str(relay.agent.ssh_port))))
        found = _migration(relay)
        if found is not None and not found[1] and notice is None:
            # The plan of «Подтвердить»: every step ⚪ (bot/progress.py).
            lines += ["", render_steps(t("relay_ssh_port_plan_title"), steps_of(ssh_port_steps())).strip()]
        status = _plan(relay).get("status")
        if status:
            lines.append(f"<i>{h(str(status))}</i>")
    return "\n".join(lines), relay_ssh_keyboard(relay)


def ssh_port_steps() -> list[tuple[str, str]]:
    """«Подтвердить» of a relay's migration, as bot/progress.py steps."""
    return [(key, t(f"relay_ssh_port_step_{key}")) for key in ("probe", "phase2", "jump", "filter")]


async def _progress_edit(message: object, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> bool:
    return await safe_edit_message_text(message, text, reply_markup=reply_markup)  # type: ignore[arg-type]


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


@router.callback_query(F.data == "admin:sshp")
async def relay_ssh_port_list(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if await state.get_state() == RelaySshPortStates.port.state:
            await state.clear()
        await safe_callback_answer(callback)
        text, markup = _list_screen(await _managed(services, callback.from_user.id))
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:sshp:\d+$"))
async def relay_ssh_port_card(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        # The port prompt's «Отмена» leads here: a number typed afterwards is no port.
        if await state.get_state() == RelaySshPortStates.port.state:
            await state.clear()
        await safe_callback_answer(callback)
        text, markup = await _relay_screen(services, callback.from_user.id, int(callback.data.rsplit(":", 1)[1]))
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:sshp:\d+:set$"))
async def relay_ssh_port_set_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None and callback.message is not None
        if not await require_totp(callback, state, services, action="relay_ssh_port"):
            return
        relay_id = int(callback.data.split(":")[2])
        await state.set_state(RelaySshPortStates.port)
        await state.update_data({"relay_id": relay_id})
        await safe_callback_answer(callback)
        await callback.message.answer(
            t("relay_ssh_port_ask"),
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"admin:sshp:{relay_id}")]]),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(RelaySshPortStates.port)
async def relay_ssh_port_set_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if message.from_user is None or not await ensure_private_message(message, t("admin_private_only_text")):
            return
        await require_superadmin(services, message.from_user.id)
        totp = getattr(services, "totp", None)
        if totp is not None and await totp.is_enabled(message.from_user.id) and not totp.is_elevated(message.from_user.id):
            await state.clear()
            await message.answer(t("relay_reauth"))
            return
        relay_id = int((await state.get_data()).get("relay_id") or 0)
        raw = (message.text or "").strip()
        if not raw.isdigit() or not 1 <= int(raw) <= 65535:
            await message.answer(t("relay_ssh_port_bad", value=h(raw[:20])))
            return
        await state.clear()
        progress = await message.answer(t("relay_ssh_port_working"))
        try:
            await services.relays.set_ssh_port(message.from_user.id, relay_id, port=int(raw))
            notice = t("relay_ssh_port_set_done", port=int(raw))
        except ServiceError as exc:
            notice = t("relay_ssh_port_failed", error=h(service_error_text(exc)))
        text, markup = await _relay_screen(services, message.from_user.id, relay_id, notice)
        await safe_edit_message_text(progress, text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.callback_query(F.data.startswith(RELAY_CALLBACK_PREFIX))
async def relay_ssh_port_button(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """«Подтвердить» / «Оставить» / «Вернуться к переезду» of a relay's migration."""
    if callback.from_user is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        parsed = parse_relay_callback(callback.data)
        if parsed is None:
            await safe_callback_answer(callback, t("ssh_port_confirm_stale"), show_alert=True)
            return
        if not await require_totp(callback, state, services, action="relay_ssh_port"):
            return
        verb, relay_id, port, since = parsed
        actor = callback.from_user.id
        await safe_callback_answer(callback, t("relay_ssh_port_working"))
        try:
            if verb == "ok":
                view = ProgressMessage(callback.message, t("relay_ssh_port_progress", port=port),
                                       steps_of(ssh_port_steps()), edit=_progress_edit)
                await view.push(force=True)

                async def on_progress(step: str, state: str) -> None:
                    view.set(step, state)
                    await view.push()

                try:
                    await view.run(services.relays.finish_ssh_port(
                        actor, relay_id, port=port, since=since, on_progress=on_progress))
                except ServiceError:
                    if not any(s.state == "fail" for s in view.steps):
                        view.fail_running()
                    raise
                finally:
                    steps_text = view.text(activity=False).split("\n", 2)[-1].strip()
                notice = f"{steps_text}\n\n" + t("relay_ssh_port_finished", port=port)
            else:
                await services.relays.keep_ssh_port(actor, relay_id, since=since, keep=verb == "keep")
                notice = t("relay_ssh_port_kept") if verb == "keep" else t("relay_ssh_port_resumed")
        except ServiceError as exc:
            notice = t("relay_ssh_port_failed", error=h(service_error_text(exc)))
            if verb == "ok":
                notice = f"{steps_text}\n\n{notice}"
        text, markup = await _relay_screen(services, actor, relay_id, notice)
        await safe_edit_message_text(callback.message, text, reply_markup=markup)
    except Exception as exc:
        await answer_callback_error(callback, exc)
