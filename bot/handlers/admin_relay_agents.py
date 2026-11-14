"""«🧙 Мастер настройки → 🛰 Relay»: relays the bot installs and manages (docs/relay.md).

SUPERADMIN only. Adding a relay issues a pairing code and shows ONE command for the
relay (scripts/install.sh --relay); the operator then sends the relay's address and
the bot completes the pairing over SSH (services/relay_agents.py). A managed relay's
card runs ``status``, ``update``, ``apply`` (ports / target) and delete (``uninstall``
on the relay + the relay row). Issuing a code, updating, changing the forward and
deleting are dangerous: the TOTP gate (bot/totp_gate.py) asks first, and a step that
waits for typed input checks the elevation again before it acts.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fsm.states import RelayWizardStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.totp_gate import require_totp
from i18n import t
from models.dto import Relay, RelayAgent
from services.errors import ServiceError
from services.relay_agents import IssuedPairing, PairingCheckFailed, PairingOutcome, RelayAgentService
from services.relay_pairing import format_port_specs, format_ports
from utils.formatting import code, h

router = Router()
logger = logging.getLogger(__name__)


def _svc(services: Services) -> RelayAgentService:
    if services.relay_agents is None:
        raise ServiceError("relay-агенты не подключены", key="relay_agent_unavailable")
    return services.relay_agents


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def _tail_id(data: str, index: int = -1) -> int:
    part = data.split(":")[index]
    if not part.isdigit() or not 0 < int(part) < 10**9:
        raise ServiceError("плохой идентификатор", key="relay_pair_not_pending")
    return int(part)


def _until(epoch: int) -> str:
    return time.strftime("%H:%M UTC", time.gmtime(epoch))


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


async def _still_elevated(services: Services, user_id: int) -> bool:
    """A typed step of a dangerous action: TOTP (when on) must still be fresh."""
    totp = getattr(services, "totp", None)
    if totp is None:
        return True
    return not await totp.is_enabled(user_id) or totp.is_elevated(user_id)


# ── screens ───────────────────────────────────────────────────────────────────


def _status_icon(agent: RelayAgent) -> str:
    status = agent.last_status or {}
    check = status.get("check")
    if isinstance(check, dict):
        return "🟢" if check.get("rc") in (0, 13, 14) else "🔴"
    return "⚪️"


async def menu_screen(services: Services, user_id: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    svc = _svc(services)
    managed = await svc.managed(user_id)
    pending = await svc.pending(user_id)
    lines = [t("relay_wiz_title")]
    if notice:
        lines = [notice, "", *lines]
    if not managed and not pending:
        lines += ["", t("relay_wiz_empty")]
    for relay, agent in managed:
        lines.append(t("relay_wiz_managed_line", icon=_status_icon(agent), label=h(relay.label), name=h(relay.name), host=h(relay.host)))
    for pairing in pending:
        lines.append(t("relay_wiz_pending_line", name=h(pairing.name), target=h(pairing.target_host), until=_until(pairing.expires_at)))
    rows = [_row(f"{_status_icon(a)} {r.label} · {r.name}", f"wrl:r:{r.id}") for r, a in managed]
    rows += [_row(f"⏳ {p.name}", f"wrl:p:{p.id}") for p in pending]
    rows.append(_row(t("btn_relay_wiz_add"), "wrl:add"))
    rows.append(_row(t("btn_wizard_menu"), "wiz:menu"))
    return "\n".join(lines), InlineKeyboardMarkup(inline_keyboard=rows)


def pairing_screen(issued: IssuedPairing) -> tuple[str, InlineKeyboardMarkup]:
    p = issued.pairing
    text = t(
        "relay_wiz_pairing",
        name=h(p.name),
        target=h(p.target_host),
        ports=h(format_port_specs(p.tcp_ports, p.udp_ports)),
        until=_until(p.expires_at),
        command=code(issued.command),
    )
    markup = InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_relay_wiz_connect"), f"wrl:pc:{p.id}"),
            _row(t("btn_relay_wiz_cancel_pairing"), f"wrl:px:{p.id}"),
            _row(t("btn_relay_wiz_back"), "wrl:menu"),
        ]
    )
    return text, markup


def _status_lines(agent: RelayAgent) -> list[str]:
    status: dict[str, Any] = dict(agent.last_status or {})
    if not status:
        return [t("relay_wiz_status_none")]
    lines = [t("relay_wiz_status_at", at=h((agent.last_status_at or "?")[:16].replace("T", " ")))]
    live = status.get("live_target")
    if live:
        lines.append(t("relay_wiz_status_live", target=h(str(live))))
    units = status.get("units")
    if isinstance(units, dict):
        lines.append(t("relay_wiz_status_units", units=h(", ".join(f"{k} {v}" for k, v in sorted(units.items())))))
    check = status.get("check")
    if isinstance(check, dict):
        lines.append(t("relay_wiz_status_check", rc=h(str(check.get("rc")))))
    checkout = status.get("checkout")
    if isinstance(checkout, dict) and checkout.get("describe"):
        lines.append(t("relay_wiz_status_version", version=h(str(checkout["describe"]))))
    update = status.get("update")
    if isinstance(update, dict) and update.get("state"):
        lines.append(t("relay_wiz_status_update", state=h(str(update["state"])), message=h(str(update.get("message", "")))))
    return lines


async def card_screen(services: Services, user_id: int, relay_id: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    relay, agent = await _svc(services).get(user_id, relay_id)
    probe = services.relay_health.last_probe(relay.id)
    lines = [
        t(
            "relay_wiz_card",
            label=h(relay.label),
            name=h(relay.name),
            host=h(relay.host),
            ssh=h(f"{agent.ssh_host}:{agent.ssh_port}"),
            target=h(agent.target_host),
            ports=h(format_port_specs(agent.tcp_ports, agent.udp_ports)),
            state=t("relay_state_on") if relay.enabled else t("relay_state_off"),
        ),
        "",
        *_status_lines(agent),
    ]
    if probe is not None:
        lines.append(t("relay_wiz_probe", ok="✅" if probe.ok else "❌", at=h(probe.checked_at[:16].replace("T", " "))))
    if notice:
        lines = [notice, "", *lines]
    markup = InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_relay_wiz_status"), f"wrl:st:{relay.id}"),
            _row(t("btn_relay_wiz_update"), f"wrl:up:{relay.id}"),
            _row(t("btn_relay_wiz_forward"), f"wrl:fw:{relay.id}"),
            _row(t("btn_relay_wiz_delete"), f"wrl:del:{relay.id}"),
            _row(t("btn_relay_wiz_panel_card"), f"admin:relay:{relay.id}"),
            _row(t("btn_relay_wiz_back"), "wrl:menu"),
        ]
    )
    return "\n".join(lines), markup


def outcome_text(outcome: PairingOutcome) -> str:
    relay = outcome.relay
    health = (
        t("relay_wiz_health_on", interval=outcome.health_interval)
        if outcome.health_interval > 0
        else t("relay_wiz_health_off")
    )
    return t(
        "relay_wiz_paired",
        label=h(relay.label),
        name=h(relay.name),
        host=h(relay.host),
        checks=h(outcome.checks.describe()),
        sources=h(", ".join(str(n) for n in relay.source_ips)),
        health=health,
    )


async def _edit(callback: CallbackQuery, text: str, markup: InlineKeyboardMarkup) -> None:
    await safe_edit_message_text(callback.message, text, reply_markup=markup)


def _back_markup(relay_id: int | None = None) -> InlineKeyboardMarkup:
    rows = []
    if relay_id is not None:
        rows.append(_row(t("btn_relay_wiz_card"), f"wrl:r:{relay_id}"))
    rows.append(_row(t("btn_relay_wiz_back"), "wrl:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


# ── menu, pending pairings ────────────────────────────────────────────────────


@router.callback_query(F.data == "wrl:menu")
async def relay_menu(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await state.clear()
        await safe_callback_answer(callback)
        await _edit(callback, *await menu_screen(services, callback.from_user.id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wrl:p:\d+$"))
async def relay_pairing_view(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        issued = await _svc(services).show(callback.from_user.id, _tail_id(callback.data))
        await safe_callback_answer(callback)
        await _edit(callback, *pairing_screen(issued))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wrl:px:\d+$"))
async def relay_pairing_cancel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        await state.clear()
        await _svc(services).cancel(callback.from_user.id, _tail_id(callback.data))
        await safe_callback_answer(callback, t("relay_wiz_pairing_cancelled"))
        await _edit(callback, *await menu_screen(services, callback.from_user.id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── add: name -> target -> the code and the command ──────────────────────────


@router.callback_query(F.data == "wrl:add")
async def relay_add(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="relay_pair"):
            return
        suggestion = await _suggest_name(services, callback.from_user.id)
        await state.set_state(RelayWizardStates.add_name)
        await state.update_data(relay_wiz_suggestion=suggestion)
        rows = [_row(t("btn_relay_wiz_use_name", name=suggestion), "wrl:nm")] if suggestion else []
        rows.append(_row(t("btn_cancel"), "wrl:menu"))
        await safe_callback_answer(callback)
        await _edit(callback, t("relay_wiz_ask_name"), InlineKeyboardMarkup(inline_keyboard=rows))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _suggest_name(services: Services, user_id: int) -> str | None:
    svc = _svc(services)
    for n in range(1, 50):
        candidate = f"relay{n}"
        try:
            return await svc.check_name(user_id, candidate)
        except ServiceError:
            continue
    return None


async def _after_name(message: Message, state: FSMContext, services: Services, user_id: int, raw: str, *, edit: bool) -> None:
    svc = _svc(services)
    name = await svc.check_name(user_id, raw)
    await state.update_data(relay_wiz_name=name)
    await state.set_state(RelayWizardStates.add_target)
    target = svc.default_target()
    rows = [_row(t("btn_relay_wiz_use_target", target=target), "wrl:tg")] if target else []
    rows.append(_row(t("btn_cancel"), "wrl:menu"))
    text = t("relay_wiz_ask_target", name=h(name)) if target else t("relay_wiz_ask_target_none", name=h(name))
    markup = InlineKeyboardMarkup(inline_keyboard=rows)
    if edit:
        await safe_edit_message_text(message, text, reply_markup=markup)
    else:
        await message.answer(text, reply_markup=markup)


@router.callback_query(F.data == "wrl:nm", RelayWizardStates.add_name)
async def relay_add_suggested_name(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.message is not None
        data = await state.get_data()
        await safe_callback_answer(callback)
        await _after_name(callback.message, state, services, callback.from_user.id, str(data.get("relay_wiz_suggestion") or ""), edit=True)  # type: ignore[arg-type]
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(RelayWizardStates.add_name)
async def relay_add_name(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await ensure_private_message(message, t("admin_private_only_text")) or message.from_user is None:
            return
        await require_superadmin(services, message.from_user.id)
        await _after_name(message, state, services, message.from_user.id, message.text or "", edit=False)
    except Exception as exc:
        await answer_message_error(message, exc)


async def _issue(message: Message, state: FSMContext, services: Services, user_id: int, target: str, *, edit: bool) -> None:
    if not await _still_elevated(services, user_id):
        await state.clear()
        await message.answer(t("relay_wiz_reauth"), reply_markup=_back_markup())
        return
    data = await state.get_data()
    issued = await _svc(services).issue(user_id, name=str(data.get("relay_wiz_name") or ""), target_host=target)
    await state.clear()
    text, markup = pairing_screen(issued)
    if edit:
        await safe_edit_message_text(message, text, reply_markup=markup)
    else:
        await message.answer(text, reply_markup=markup)


@router.callback_query(F.data == "wrl:tg", RelayWizardStates.add_target)
async def relay_add_default_target(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.message is not None
        target = _svc(services).default_target() or ""
        await safe_callback_answer(callback)
        await _issue(callback.message, state, services, callback.from_user.id, target, edit=True)  # type: ignore[arg-type]
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(RelayWizardStates.add_target)
async def relay_add_target(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await ensure_private_message(message, t("admin_private_only_text")) or message.from_user is None:
            return
        await require_superadmin(services, message.from_user.id)
        await _issue(message, state, services, message.from_user.id, (message.text or "").strip(), edit=False)
    except Exception as exc:
        await answer_message_error(message, exc)


# ── complete: the relay's address -> hello, checks, registration ──────────────


@router.callback_query(F.data.regexp(r"^wrl:pc:\d+$"))
async def relay_connect(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        pairing_id = _tail_id(callback.data)
        await _svc(services).show(callback.from_user.id, pairing_id)  # still pending?
        await state.set_state(RelayWizardStates.pair_address)
        await state.update_data(relay_wiz_pairing=pairing_id)
        await safe_callback_answer(callback)
        await callback.message.answer(  # type: ignore[union-attr]
            t("relay_wiz_ask_address"),
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cancel"), "wrl:menu")]),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(RelayWizardStates.pair_address)
async def relay_connect_address(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await ensure_private_message(message, t("admin_private_only_text")) or message.from_user is None:
            return
        await require_superadmin(services, message.from_user.id)
        data = await state.get_data()
        pairing_id = int(data.get("relay_wiz_pairing") or 0)
        progress = await message.answer(t("relay_wiz_connecting"))
        try:
            outcome = await _svc(services).complete(message.from_user.id, pairing_id, message.text or "")
        except PairingCheckFailed as exc:
            await safe_edit_message_text(
                progress,
                t("relay_wiz_check_failed", checks=h(exc.checks.describe())),
                reply_markup=InlineKeyboardMarkup(
                    inline_keyboard=[_row(t("btn_relay_wiz_retry"), f"wrl:pc:{pairing_id}"), _row(t("btn_relay_wiz_back"), "wrl:menu")]
                ),
            )
            return
        except ServiceError as exc:
            await safe_edit_message_text(
                progress,
                t("relay_wiz_connect_failed", error=h(service_error_text(exc))),
                reply_markup=InlineKeyboardMarkup(
                    inline_keyboard=[_row(t("btn_relay_wiz_retry"), f"wrl:pc:{pairing_id}"), _row(t("btn_relay_wiz_back"), "wrl:menu")]
                ),
            )
            return
        await state.clear()
        await safe_edit_message_text(progress, outcome_text(outcome), reply_markup=_back_markup(outcome.relay.id))
    except Exception as exc:
        await answer_message_error(message, exc)


# ── a managed relay ───────────────────────────────────────────────────────────


@router.callback_query(F.data.regexp(r"^wrl:r:\d+$"))
async def relay_card(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        await state.clear()
        await safe_callback_answer(callback)
        await _edit(callback, *await card_screen(services, callback.from_user.id, _tail_id(callback.data)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wrl:st:\d+$"))
async def relay_status(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _tail_id(callback.data)
        await safe_callback_answer(callback, t("relay_wiz_status_running"))
        notice = None
        try:
            await _svc(services).status(callback.from_user.id, relay_id)
        except ServiceError as exc:
            notice = t("relay_wiz_status_failed", error=h(service_error_text(exc)))
        await _edit(callback, *await card_screen(services, callback.from_user.id, relay_id, notice))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wrl:up:\d+$"))
async def relay_update(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="relay_update"):
            return
        relay_id = _tail_id(callback.data)
        await safe_callback_answer(callback, t("relay_wiz_updating"))
        try:
            reply = await _svc(services).update(callback.from_user.id, relay_id)
            raw_update = reply.payload.get("update")
            update: dict[str, Any] = raw_update if isinstance(raw_update, dict) else {}
            notice = t("relay_wiz_updated", state=h(str(update.get("state", "?"))), message=h(str(update.get("message", ""))))
        except ServiceError as exc:
            notice = t("relay_wiz_update_failed", error=h(service_error_text(exc)))
        await _edit(callback, *await card_screen(services, callback.from_user.id, relay_id, notice))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^wrl:fw:\d+$"))
async def relay_forward(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None and callback.message is not None
        if not await require_totp(callback, state, services, action="relay_apply"):
            return
        relay_id = _tail_id(callback.data)
        _, agent = await _svc(services).get(callback.from_user.id, relay_id)
        await state.set_state(RelayWizardStates.forward)
        await state.update_data(relay_wiz_relay=relay_id)
        await safe_callback_answer(callback)
        await callback.message.answer(
            t(
                "relay_wiz_ask_forward",
                current=code(f"{agent.target_host} tcp={format_ports(agent.tcp_ports)} udp={format_ports(agent.udp_ports)}"),
            ),
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cancel"), f"wrl:r:{relay_id}")]),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def parse_forward_input(text: str) -> tuple[str, str, str]:
    """``<target> tcp=443[,…] udp=443[,…]`` — the words in any order after the target."""
    words = (text or "").split()
    if not words or len(words) > 3:
        raise ServiceError("формат: <имя> tcp=443 udp=443", key="relay_wiz_forward_format")
    target, tcp, udp = words[0], "", ""
    for word in words[1:]:
        key, _, value = word.partition("=")
        if key == "tcp" and not tcp:
            tcp = value
        elif key == "udp" and not udp:
            udp = value
        else:
            raise ServiceError("формат: <имя> tcp=443 udp=443", key="relay_wiz_forward_format")
    return target, tcp, udp


@router.message(RelayWizardStates.forward)
async def relay_forward_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        if not await ensure_private_message(message, t("admin_private_only_text")) or message.from_user is None:
            return
        await require_superadmin(services, message.from_user.id)
        data = await state.get_data()
        relay_id = int(data.get("relay_wiz_relay") or 0)
        if not await _still_elevated(services, message.from_user.id):
            await state.clear()
            await message.answer(t("relay_wiz_reauth"), reply_markup=_back_markup(relay_id))
            return
        svc = _svc(services)
        _, agent = await svc.get(message.from_user.id, relay_id)
        target, tcp, udp = parse_forward_input(message.text or "")
        progress = await message.answer(t("relay_wiz_applying"))
        try:
            await svc.change_forward(
                message.from_user.id, relay_id, target_host=target,
                tcp=tcp or format_ports(agent.tcp_ports), udp=udp or format_ports(agent.udp_ports),
            )
            notice = t("relay_wiz_forward_done")
        except ServiceError as exc:
            notice = t("relay_wiz_forward_failed", error=h(service_error_text(exc)))
        await state.clear()
        text, markup = await card_screen(services, message.from_user.id, relay_id, notice)
        await safe_edit_message_text(progress, text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


# ── delete ────────────────────────────────────────────────────────────────────


@router.callback_query(F.data.regexp(r"^wrl:del:\d+$"))
async def relay_delete(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = _tail_id(callback.data)
        relay, usage = await services.relays.usage(callback.from_user.id, relay_id)
        rows = []
        if usage.keys:
            rows.append(_row(t("btn_relay_wiz_delete_with_keys"), f"wrl:dk:{relay_id}:1"))
        else:
            rows.append(_row(t("btn_relay_wiz_delete_confirm"), f"wrl:dk:{relay_id}:0"))
        rows.append(_row(t("btn_relay_wiz_card"), f"wrl:r:{relay_id}"))
        await safe_callback_answer(callback)
        await _edit(
            callback,
            t("relay_wiz_delete_impact", label=h(relay.label), name=h(relay.name), keys=usage.keys, bundles=usage.bundles),
            InlineKeyboardMarkup(inline_keyboard=rows),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _report_deletion(callback: CallbackQuery, services: Services, relay: Relay, deleted: bool, uninstalled: bool, remaining: int) -> None:
    assert callback.from_user is not None
    if deleted:
        notice = t("relay_wiz_deleted", name=h(relay.name)) + ("" if uninstalled else "\n" + t("relay_wiz_deleted_record_only"))
        await _edit(callback, *await menu_screen(services, callback.from_user.id, notice))
    else:
        await _edit(callback, t("relay_wiz_delete_incomplete", name=h(relay.name), remaining=remaining), _back_markup())


@router.callback_query(F.data.regexp(r"^wrl:(dk|dr):\d+:[01]$"))
async def relay_delete_confirm(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="relay_uninstall"):
            return
        kind, relay_id, with_keys = callback.data.split(":")[1], _tail_id(callback.data, 2), callback.data.endswith(":1")
        relay_side = kind == "dk"
        await safe_callback_answer(callback, t("relay_wiz_deleting"))
        try:
            report = await _svc(services).remove(callback.from_user.id, relay_id, with_keys=with_keys, relay_side=relay_side)
        except ServiceError as exc:
            if not relay_side:
                raise
            await _edit(
                callback,
                t("relay_wiz_unreachable", error=h(service_error_text(exc))),
                InlineKeyboardMarkup(
                    inline_keyboard=[
                        _row(t("btn_relay_wiz_delete_record"), f"wrl:dr:{relay_id}:{int(with_keys)}"),
                        _row(t("btn_relay_wiz_card"), f"wrl:r:{relay_id}"),
                    ]
                ),
            )
            return
        await _report_deletion(
            callback, services, report.relay, report.deletion.deleted, report.uninstalled, report.deletion.remaining_keys
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)
