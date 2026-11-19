"""Admin panel → «🛰 Relay» → «🛟 Режим фолбэка» (docs/relay.md «Режим фолбэка (hub)»).

The screen of the fallback mode: its state, the hub, the addresses, the DNS API
token, the failover set and the two settings (direct links' host, the
subscription's ``fallback-url``); «Включить» / «Выключить» / «Повторить» and a
preflight that changes nothing. The hub role is given from a relay's card
(``admin:fb:hub:<id>``) — this module owns those callbacks too, under its own
prefix, so the relay screen's catch-all never swallows them.

SUPERADMIN only — every handler checks it and the service checks it again. Every
change is a dangerous action behind the TOTP gate; a typed step checks the
elevation again before it acts. The DNS API token is typed into the chat: that
message is deleted the moment it is read, whatever it holds, and the token is
never echoed back (services/fallback.py, adapters/cloudflare_dns.py).
"""

from __future__ import annotations

import logging
from typing import cast

from aiogram import Bot, F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.fallback import (
    candidates_text,
    proxy_notice_text,
    failure_keys,
    fallback_text,
    names_text,
    not_configured_text,
    preflight_text,
    report_text,
    setup_step_title,
    switch_step_titles,
)
from bot.fsm.states import AdminFallbackStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error, service_error_text
from bot.keyboards.admin_fallback import (
    back_keyboard,
    cancel_keyboard,
    candidates_keyboard,
    confirm_keyboard,
    fallback_keyboard,
    fix_keyboard,
    hub_choice_keyboard,
    name_tag,
    names_keyboard,
    origin_keyboard,
    proxy_notice_keyboard,
    settings_keyboard,
    setup_origin_keyboard,
    token_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from bot.progress import ProgressMessage, steps_of
from bot.totp_gate import require_totp
from i18n import t
from services.errors import InvalidOperation, NotFound, ServiceError
from models.dto import RecipientFilter
from services.fallback import FallbackOverview, FallbackService
from services.proxy_endpoint import PROXY_KINDS
from services.relays import host_is_ipv4
from utils.formatting import code, h

router = Router()
logger = logging.getLogger(__name__)

# Typed steps: state → (prompt key, what the service does with the text).
_ADDRESS_STATES = {"main": AdminFallbackStates.main_ipv4, "hub": AdminFallbackStates.hub_ipv4}


def _service(services: Services) -> FallbackService:
    fallback = getattr(services, "fallback", None)
    if fallback is None:
        raise ServiceError("режим фолбэка не подключён", key="fb_err_unavailable")
    return cast(FallbackService, fallback)


def _message(callback: CallbackQuery) -> Message:
    return cast(Message, callback.message)


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


async def _screen(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    """The main screen: set up — state, hub, names; not set up — what is missing."""
    fallback = _service(services)
    overview = await fallback.overview(actor)
    if not await fallback.configured():
        return not_configured_text(overview, notice), fallback_keyboard(overview, configured=False)
    return fallback_text(overview, notice), fallback_keyboard(overview)


async def _settings_screen(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    fallback = _service(services)
    overview = await fallback.overview(actor)
    auto_on = await fallback.auto_switch()
    lines = [notice, ""] if notice else []
    lines += [t("fb_settings_title"), ""]
    lines.append(t("fb_addresses", main=code(overview.main_ipv4 or "—"), hub=code(overview.hub_ipv4 or "—")))
    lines.append(
        t("fb_token_set", fp=code(overview.token_fingerprint or "?")) if overview.token_set else t("fb_token_none")
    )
    if overview.direct_host:
        lines.append(t("fb_direct_name", host=code(overview.direct_host), count=overview.single_direct_keys))
    else:
        lines.append(t("fb_direct_ipv4", count=overview.single_direct_keys))
    lines.append(t("fb_sub_header_on") if overview.sub_fallback_url else t("fb_sub_header_off"))
    lines += ["", t("fb_auto_line_on") if auto_on else t("fb_auto_line_off")]
    return "\n".join(lines), settings_keyboard(overview, auto_on=auto_on)


async def _edit(callback: CallbackQuery, screen: tuple[str, InlineKeyboardMarkup]) -> None:
    text, markup = screen
    await safe_edit_message_text(callback.message, text, reply_markup=markup)


async def _show(callback: CallbackQuery, services: Services, notice: str | None = None) -> None:
    assert callback.from_user is not None
    await _edit(callback, await _screen(services, callback.from_user.id, notice))


async def _leave(state: FSMContext) -> None:
    current = await state.get_state()
    if current is not None and current in AdminFallbackStates.__all_states_names__:
        await state.clear()


def _hub_id(overview: FallbackOverview) -> int | None:
    return overview.hub.id if overview.hub is not None else None


# ── the screen ────────────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:fb")
async def fallback_panel(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        await _leave(state)
        await safe_callback_answer(callback)
        await _show(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:set")
async def fallback_settings(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await _leave(state)
        await safe_callback_answer(callback)
        await _edit(callback, await _settings_screen(services, callback.from_user.id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:pf")
async def fallback_preflight(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await safe_callback_answer(callback, t("fb_checking"))
        fallback = _service(services)
        preflight = await fallback.preflight(callback.from_user.id)
        overview = await fallback.overview(callback.from_user.id)
        keys = [item.key for item in preflight.failures]
        await safe_edit_message_text(
            callback.message, preflight_text(preflight), reply_markup=fix_keyboard(keys, hub_id=_hub_id(overview))
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _progress_edit(message: object, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> bool:
    """bot/progress.py's edit through this module's ``safe_edit_message_text``."""
    return await safe_edit_message_text(message, text, reply_markup=reply_markup)  # type: ignore[arg-type]


def _switch_progress(callback: CallbackQuery, action: str, *, proxies: bool = False) -> ProgressMessage:
    return ProgressMessage(callback.message, t(f"fb_progress_{action}"), steps_of(switch_step_titles(proxies=proxies)),
                           edit=_progress_edit)


@router.callback_query(F.data.regexp(r"^admin:fb:(on|off)$"))
async def fallback_confirm(callback: CallbackQuery, services: Services, state: FSMContext | None = None) -> None:
    """«Включить» / «Выключить»: the plan (every step ⚪) and «✅ Да». «Включить» with an
    empty failover set opens the names to switch with — never a silent refusal (C4)."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        action = callback.data.rsplit(":", 1)[1]
        fallback = _service(services)
        overview = await fallback.overview(callback.from_user.id)
        await safe_callback_answer(callback)
        if action == "on" and not await fallback.configured():
            await safe_edit_message_text(
                callback.message, t("fb_on_not_configured"),
                reply_markup=fix_keyboard(["fb_err_not_configured"], hub_id=None),
            )
            return
        if action == "on" and not overview.names:
            await _edit(callback, await _candidates_screen(services, callback.from_user.id, state, ctx="o"))
            return
        if action == "on":
            text = t(
                "fb_confirm_on", count=len(overview.names), hub=h(overview.hub.name if overview.hub else "—"),
                ip=code(overview.hub_ipv4 or "—"),
            )
        else:
            text = t("fb_confirm_off", count=len(overview.names), ip=code(overview.main_ipv4 or "—"))
        plan = _switch_progress(callback, action, proxies=bool(overview.proxies))
        plan.footer = text
        await plan.show_plan(confirm_keyboard(action))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _run_switch(callback: CallbackQuery, services: Services, action: str) -> None:
    """THE switch with its progress (D) — then the screen, with the report and, for a
    refusal, the cause and the button that removes it (C4)."""
    assert callback.from_user is not None
    fallback = _service(services)
    actor = callback.from_user.id
    view = _switch_progress(callback, action, proxies=bool(await fallback.proxy_ports()))
    keys = {step.key for step in view.steps}

    async def on_progress(step: str, step_state: str, done: int | None, total: int | None) -> None:
        if step not in keys:
            return
        view.set(step, step_state, done=done, total=total)
        await view.push()

    run = {"on": fallback.enable, "off": fallback.disable, "retry": fallback.repeat}[action]
    view.start("preflight")
    await view.push(force=True)
    try:
        report = await view.run(run(actor, on_progress=on_progress))
    except ServiceError as exc:
        view.fail_running()
        overview = await fallback.overview(actor)
        await view.finish(t("fb_switch_failed", error=h(service_error_text(exc))),
                          fix_keyboard([exc.key or ""], hub_id=_hub_id(overview)))
        return
    if not report.started:
        view.set("preflight", "fail")
        overview = await fallback.overview(actor)
        await view.finish(report_text(report), fix_keyboard(failure_keys(report), hub_id=_hub_id(overview)))
        return
    if report.complete:
        view.complete()
    steps = view.text(activity=False).split("\n", 2)[-1].strip()
    await _show(callback, services, f"{steps}\n\n{report_text(report)}")


@router.callback_query(F.data.regexp(r"^admin:fb:(on:ok|off:ok|retry)$"))
async def fallback_switch(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_switch"):
            return
        await safe_callback_answer(callback, t("fb_switching"))
        action = callback.data.split(":")[2]
        await _run_switch(callback, services, action)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── «📣 Разослать новую ссылку»: the proxies a switch moved (docs/proxy.md) ─────


def _proxy_filter(kinds: tuple[str, ...]) -> RecipientFilter:
    return RecipientFilter.create(protocols=[PROXY_KINDS[kind].value for kind in kinds if kind in PROXY_KINDS])


@router.callback_query(F.data == "admin:fb:pxn")
async def fallback_proxy_notice(callback: CallbackQuery, services: Services) -> None:
    """The broadcast's confirmation: who gets it (the users with an active access of a
    proxy that moved) and exactly what they get. Optional — never sent by itself."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        fallback = _service(services)
        kinds = await fallback.proxy_notice()
        await safe_callback_answer(callback)
        if not kinds:
            await _show(callback, services, t("fb_proxy_notice_none"))
            return
        count = await services.announcements.count_recipients(callback.from_user.id, recipient_filter=_proxy_filter(kinds))
        text = "\n".join([
            t("fb_proxy_notice_confirm", count=count), "", proxy_notice_text(kinds, fallback.endpoints),
        ])
        await safe_edit_message_text(callback.message, text, reply_markup=proxy_notice_keyboard())
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:pxn:ok")
async def fallback_proxy_notice_send(callback: CallbackQuery, state: FSMContext, services: Services, bot: Bot) -> None:
    """The broadcast, through the announcements (their ledger and their resume): the
    message below is posted here and copied to every recipient as it is."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.message is not None
        if not await require_totp(callback, state, services, action="fallback_proxy_notice"):
            return
        fallback = _service(services)
        kinds = await fallback.proxy_notice()
        if not kinds:
            await safe_callback_answer(callback)
            await _show(callback, services, t("fb_proxy_notice_none"))
            return
        await safe_callback_answer(callback, t("announce_sending"))
        source = await bot.send_message(callback.message.chat.id, proxy_notice_text(kinds, fallback.endpoints))
        result = await services.announcements.send_to_all(
            actor_user_id=callback.from_user.id, bot=bot, from_chat_id=callback.message.chat.id,
            message_id=source.message_id, recipient_filter=_proxy_filter(kinds),
        )
        await fallback.clear_proxy_notice(callback.from_user.id)
        await _show(callback, services, t("fb_proxy_notice_sent", total=result.total, success=result.success,
                                          failed=result.failed))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:pxn:no")
async def fallback_proxy_notice_skip(callback: CallbackQuery, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await _service(services).clear_proxy_notice(callback.from_user.id)
        await safe_callback_answer(callback)
        await _show(callback, services, t("fb_proxy_notice_skipped"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:subfb")
async def fallback_sub_header(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        fallback = _service(services)
        overview = await fallback.overview(callback.from_user.id)
        on = await fallback.set_sub_fallback_url(callback.from_user.id, not overview.sub_fallback_url)
        await safe_callback_answer(callback)
        notice = t("fb_sub_header_switched_on") if on else t("fb_sub_header_switched_off")
        if on and overview.hub is not None and host_is_ipv4(overview.hub.host):
            notice += "\n" + t("fb_sub_header_ip_warning")
        await _edit(callback, await _settings_screen(services, callback.from_user.id, notice))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:auto")
async def fallback_auto_toggle(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """«Автопереключение» (services/fallback_auto.py): off by default."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        fallback = _service(services)
        on = await fallback.set_auto_switch(callback.from_user.id, not await fallback.auto_switch())
        await safe_callback_answer(callback)
        await _edit(callback, await _settings_screen(
            services, callback.from_user.id, t("fb_auto_switched_on") if on else t("fb_auto_switched_off")
        ))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── the candidates: «Включить» with an empty set, and the setup (C1, C4) ──────

_UNCHECKED = {"o": "fb_unchecked_on", "s": "fb_unchecked_setup"}


async def _unchecked(state: FSMContext | None, ctx: str) -> list[str]:
    if state is None:
        return []
    value = (await state.get_data()).get(_UNCHECKED[ctx])
    return [str(v) for v in value] if isinstance(value, list) else []


async def _candidates_screen(
    services: Services, actor: int, state: FSMContext | None, *, ctx: str, notice: str | None = None
) -> tuple[str, InlineKeyboardMarkup]:
    fallback = _service(services)
    candidates = await fallback.explained_candidates(actor)
    unchecked = await _unchecked(state, ctx)
    if ctx == "o":
        title = t("fb_cand_title_on")
        markup = candidates_keyboard(candidates, unchecked, ctx="o", confirm_text=t("btn_fb_on_with_names"),
                                     confirm_data="admin:fb:on:names")
    else:
        title = f"{setup_step_title(4)}\n{t('fb_cand_title_setup')}"
        markup = candidates_keyboard(candidates, unchecked, ctx="s", confirm_text=t("btn_fb_cand_add"),
                                     confirm_data="admin:fb:setup:names:ok", skip_data="admin:fb:setup:pf")
    text = candidates_text(title, candidates, unchecked)
    return (f"{notice}\n\n{text}" if notice else text), markup


async def _selected(services: Services, actor: int, state: FSMContext | None, ctx: str) -> list[str]:
    unchecked = set(await _unchecked(state, ctx))
    return [c.name for c in await _service(services).explained_candidates(actor) if name_tag(c.name) not in unchecked]


@router.callback_query(F.data.regexp(r"^admin:fb:cand:(o|s):[0-9a-f]{10}$"))
async def fallback_candidate_toggle(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        _, _, _, ctx, tag = callback.data.split(":")
        unchecked = await _unchecked(state, ctx)
        unchecked = [u for u in unchecked if u != tag] if tag in unchecked else [*unchecked, tag]
        await state.update_data({_UNCHECKED[ctx]: unchecked})
        await safe_callback_answer(callback)
        await _edit(callback, await _candidates_screen(services, callback.from_user.id, state, ctx=ctx))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:on:names")
async def fallback_on_with_names(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """«🛟 Enable with these names» (btn_fb_on_with_names): the checked candidates join the set, and the SAME
    action goes on — the switch, without a detour through the screen (C4)."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="fallback_switch"):
            return
        actor = callback.from_user.id
        names = await _selected(services, actor, state, "o")
        if not names:
            await safe_callback_answer(callback, t("fb_cand_nothing_checked"), show_alert=True)
            return
        try:
            await _service(services).add_names(actor, names)
        except InvalidOperation as exc:
            await safe_callback_answer(callback)
            await _edit(callback, await _candidates_screen(
                services, actor, state, ctx="o", notice=t("fb_switch_failed", error=h(service_error_text(exc)))
            ))
            return
        await state.update_data({_UNCHECKED["o"]: []})
        await safe_callback_answer(callback, t("fb_switching"))
        await _run_switch(callback, services, "on")
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── «⚙️ Настроить фолбэк»: token → hub → origin → names → preflight (C1) ───────


async def _setup_screen(services: Services, actor: int, state: FSMContext, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup] | None:
    """The next step of the setup; None — the token step (asked by a message)."""
    fallback = _service(services)
    overview = await fallback.overview(actor)
    prefix = f"{notice}\n\n" if notice else ""
    if not overview.token_set:
        return None
    if overview.hub is None:
        candidates = await fallback.hub_candidates(actor)
        lines = [setup_step_title(2), t("fb_setup_hub_intro")]
        if candidates:
            lines += ["", *[
                f"• {h(c.relay.name)} — {code(c.address or '—')} · " + (c.country or t("fb_setup_country_unknown"))
                for c in candidates
            ]]
        else:
            lines += ["", t("fb_setup_hub_none")]
        return prefix + "\n".join(lines), hub_choice_keyboard(candidates)
    if not overview.names:
        return await _candidates_screen(services, actor, state, ctx="s", notice=notice)
    preflight = await fallback.preflight(actor)
    keys = [item.key for item in preflight.failures]
    text = f"{setup_step_title(5)}\n{preflight_text(preflight)}\n\n" + (
        t("fb_setup_done") if preflight.passed else t("fb_setup_fix")
    )
    return prefix + text, fix_keyboard(keys, hub_id=_hub_id(overview))


async def _setup_show(callback: CallbackQuery, services: Services, state: FSMContext, notice: str | None = None) -> None:
    assert callback.from_user is not None
    screen = await _setup_screen(services, callback.from_user.id, state, notice)
    if screen is None:
        await _ask_token(callback, state, setup=True)
        return
    await _edit(callback, screen)


@router.callback_query(F.data.in_({"admin:fb:setup", "admin:fb:setup:pf"}))
async def fallback_setup(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        await safe_callback_answer(callback)
        if callback.data.endswith(":pf"):
            overview = await _service(services).overview(callback.from_user.id)
            preflight = await _service(services).preflight(callback.from_user.id)
            text = f"{setup_step_title(5)}\n{preflight_text(preflight)}\n\n" + (
                t("fb_setup_done") if preflight.passed else t("fb_setup_fix")
            )
            await safe_edit_message_text(callback.message, text, reply_markup=fix_keyboard(
                [item.key for item in preflight.failures], hub_id=_hub_id(overview)))
            return
        await _setup_show(callback, services, state)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:setup:hub:\d+$"))
async def fallback_setup_hub(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Step 3: the origin for the chosen hub — ``origin.<zone>`` offered, one tap."""
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        relay_id = int(callback.data.rsplit(":", 1)[1])
        suggestion = _service(services).suggest_origin()
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message,
            f"{setup_step_title(3)}\n" + t("fb_ask_origin", suggestion=code(suggestion or "origin.<зона>")),
            reply_markup=setup_origin_keyboard(relay_id, suggestion),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:setup:origin:\d+(:type)?$"))
async def fallback_setup_origin(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        relay_id = int(callback.data.split(":")[4])
        if callback.data.endswith(":type"):
            await _ask(callback, state, AdminFallbackStates.origin, t("fb_ask_origin_typed"),
                       cancel_keyboard("admin:fb:setup"), relay_id=relay_id, setup=True)
            return
        suggestion = _service(services).suggest_origin()
        if suggestion is None:
            await safe_callback_answer(callback, t("action_stale"), show_alert=True)
            return
        await safe_callback_answer(callback, t("fb_hub_assigning"))
        await safe_edit_message_text(callback.message, t("fb_hub_assigning"))
        notice, ok = await _assign(services, callback.from_user.id, relay_id, suggestion)
        if not ok:
            await safe_edit_message_text(callback.message, notice, reply_markup=setup_origin_keyboard(relay_id, suggestion))
            return
        await _setup_show(callback, services, state, notice)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:setup:names:ok")
async def fallback_setup_names(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        actor = callback.from_user.id
        names = await _selected(services, actor, state, "s")
        if not names:
            await safe_callback_answer(callback, t("fb_cand_nothing_checked"), show_alert=True)
            return
        try:
            await _service(services).add_names(actor, names)
        except InvalidOperation as exc:
            await safe_callback_answer(callback)
            await _edit(callback, await _candidates_screen(
                services, actor, state, ctx="s", notice=h(service_error_text(exc))))
            return
        await state.update_data({_UNCHECKED["s"]: []})
        await safe_callback_answer(callback, t("fb_name_added"))
        await _setup_show(callback, services, state, t("fb_setup_names_added", count=len(names)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── the failover set ──────────────────────────────────────────────────────────


async def _names_screen(services: Services, actor: int, notice: str | None = None) -> tuple[str, InlineKeyboardMarkup]:
    fallback = _service(services)
    overview = await fallback.overview(actor)
    candidates = await fallback.candidates(actor)
    text = names_text(overview, candidates)
    if notice:
        text = f"{notice}\n\n{text}"
    return text, names_keyboard(overview, candidates)


@router.callback_query(F.data == "admin:fb:names")
async def fallback_names(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await _leave(state)
        await safe_callback_answer(callback)
        await _edit(callback, await _names_screen(services, callback.from_user.id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:nadd:[0-9a-f]{10}$"))
async def fallback_name_add_suggested(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        actor = callback.from_user.id
        fallback = _service(services)
        tag = callback.data.rsplit(":", 1)[1]
        match = [name for name in await fallback.candidates(actor) if name_tag(name) == tag]
        if not match:
            await safe_callback_answer(callback, t("action_stale"), show_alert=True)
        else:
            try:
                await fallback.add_name(actor, match[0])
                await safe_callback_answer(callback, t("fb_name_added"))
            except InvalidOperation as exc:
                await safe_callback_answer(callback, service_error_text(exc), show_alert=True)
        await _edit(callback, await _names_screen(services, actor))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:nrm:\d+$"))
async def fallback_name_remove(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        actor = callback.from_user.id
        try:
            removed = await _service(services).remove_name(actor, int(callback.data.rsplit(":", 1)[1]))
            await safe_callback_answer(callback, t("fb_name_removed", name=removed.name))
        except (InvalidOperation, NotFound) as exc:
            await safe_callback_answer(callback, service_error_text(exc), show_alert=True)
        await _edit(callback, await _names_screen(services, actor))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── typed steps ───────────────────────────────────────────────────────────────


async def _ask(
    callback: CallbackQuery, state: FSMContext, target: object, prompt: str,
    markup: InlineKeyboardMarkup | None = None, **data: object,
) -> None:
    await state.set_state(target)  # type: ignore[arg-type]
    if data:
        await state.update_data(dict(data))
    await safe_callback_answer(callback)
    await _message(callback).answer(prompt, reply_markup=markup or cancel_keyboard())


@router.callback_query(F.data == "admin:fb:nnew")
async def fallback_name_new(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        await _ask(callback, state, AdminFallbackStates.name, t("fb_ask_name"), cancel_keyboard("admin:fb:names"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:addr:(main|hub)$"))
async def fallback_address(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        which = callback.data.rsplit(":", 1)[1]
        await _ask(callback, state, _ADDRESS_STATES[which], t(f"fb_ask_{which}_ipv4"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:direct")
async def fallback_direct(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        if not await require_totp(callback, state, services, action="fallback_settings"):
            return
        await _ask(callback, state, AdminFallbackStates.direct_host, t("fb_ask_direct_host"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:token")
async def fallback_token(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        await _leave(state)
        overview = await _service(services).overview(callback.from_user.id)
        text = t("fb_token_screen", path=code(str(_service(services).token_file.path)))
        status = t("fb_token_set", fp=code(overview.token_fingerprint or "?")) if overview.token_set else t("fb_token_none")
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, f"{text}\n\n{status}", reply_markup=token_keyboard(overview.token_set))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _ask_token(callback: CallbackQuery, state: FSMContext, *, setup: bool) -> None:
    """The DNS API token step (the setup's step 1, or «✏️ Задать токен»)."""
    prompt = f"{setup_step_title(1)}\n{t('fb_ask_token')}" if setup else t("fb_ask_token")
    await _ask(callback, state, AdminFallbackStates.token, prompt,
               cancel_keyboard("admin:fb" if setup else "admin:fb:token"), setup=setup)


@router.callback_query(F.data == "admin:fb:tok:set")
async def fallback_token_set(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        if not await require_totp(callback, state, services, action="fallback_token"):
            return
        await _ask_token(callback, state, setup=False)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "admin:fb:tok:del")
async def fallback_token_delete(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None
        if not await require_totp(callback, state, services, action="fallback_token"):
            return
        removed = await _service(services).delete_token(callback.from_user.id)
        await safe_callback_answer(callback, t("fb_token_deleted") if removed else t("fb_token_none"))
        await _edit(callback, await _settings_screen(services, callback.from_user.id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _typed(message: Message, state: FSMContext, services: Services) -> int | None:
    """The common start of a typed step: guard, elevation still fresh. The actor, or None."""
    if not await _guard_message(message, services):
        return None
    assert message.from_user is not None
    if not await _still_elevated(services, message.from_user.id):
        await state.clear()
        await message.answer(t("relay_reauth"), reply_markup=back_keyboard())
        return None
    return message.from_user.id


async def _done(message: Message, state: FSMContext, services: Services, actor: int, notice: str) -> None:
    """A typed setting is saved: back to «⚙️ Настройки» with the notice."""
    await state.clear()
    text, markup = await _settings_screen(services, actor, notice)
    await message.answer(text, reply_markup=markup)


async def _retry(message: Message, exc: ServiceError, cancel: str = "admin:fb") -> None:
    await message.answer(f"{h(service_error_text(exc))}\n{t('relay_try_again')}", reply_markup=cancel_keyboard(cancel))


@router.message(AdminFallbackStates.token)
async def fallback_token_input(message: Message, state: FSMContext, services: Services) -> None:
    """The DNS API token: the message goes away FIRST, whatever it holds."""
    raw = message.text or ""
    try:
        await message.delete()
    except Exception:
        logger.warning("Fallback: the message with the DNS API token could not be deleted — delete it by hand")
        await message.answer(t("fb_token_delete_by_hand"))
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        setup = bool((await state.get_data()).get("setup"))
        fallback = _service(services)
        try:
            status = await fallback.set_token(actor, raw)
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:fb" if setup else "admin:fb:token")
            return
        notice = t("fb_token_saved", status=h(status))
        try:
            # Checked against the zone right away: a token for another zone would
            # only fail at the switch.
            notice += "\n" + t("fb_token_zone_ok", zone=code(await fallback.check_zone(actor)))
        except InvalidOperation as exc:
            notice += "\n" + h(service_error_text(exc))
        if not setup:
            await _done(message, state, services, actor, notice)
            return
        await state.clear()
        screen = await _setup_screen(services, actor, state, notice)
        if screen is not None:
            await message.answer(screen[0], reply_markup=screen[1])
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminFallbackStates.name)
async def fallback_name_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        try:
            await _service(services).add_name(actor, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc, "admin:fb:names")
            return
        await state.clear()
        text, markup = await _names_screen(services, actor, t("fb_name_added"))
        await message.answer(text, reply_markup=markup)
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminFallbackStates.main_ipv4)
@router.message(AdminFallbackStates.hub_ipv4)
async def fallback_address_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        which = "main" if await state.get_state() == AdminFallbackStates.main_ipv4.state else "hub"
        try:
            await _service(services).set_address(actor, which, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc)
            return
        await _done(message, state, services, actor, t("relay_saved"))
    except Exception as exc:
        await answer_message_error(message, exc)


@router.message(AdminFallbackStates.direct_host)
async def fallback_direct_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        try:
            host = await _service(services).set_direct_host(actor, message.text or "")
        except InvalidOperation as exc:
            await _retry(message, exc)
            return
        notice = t("fb_direct_set", host=code(host)) if host else t("fb_direct_cleared")
        await _done(message, state, services, actor, notice)
    except Exception as exc:
        await answer_message_error(message, exc)


# ── the hub role (buttons on a relay's card) ──────────────────────────────────


@router.callback_query(F.data.regexp(r"^admin:fb:hub:\d+$"))
async def fallback_hub_start(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.data is not None
        relay_id = int(callback.data.rsplit(":", 1)[1])
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        suggestion = _service(services).suggest_origin()
        await _ask(
            callback, state, AdminFallbackStates.origin, t("fb_ask_origin", suggestion=code(suggestion or "origin.<зона>")),
            origin_keyboard(relay_id, suggestion), relay_id=relay_id,
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


async def _assign(services: Services, actor: int, relay_id: int, origin: str) -> tuple[str, bool]:
    try:
        outcome = await _service(services).assign_hub(actor, relay_id, origin)
    except ServiceError as exc:
        return t("fb_hub_failed", error=h(service_error_text(exc))), False
    return t(
        "fb_hub_assigned", name=h(outcome.relay.name), origin=code(outcome.origin), ip=code(outcome.main_ipv4),
        created=t("fb_hub_record_created") if outcome.created_record else t("fb_hub_record_checked"),
    ), True


@router.callback_query(F.data.regexp(r"^admin:fb:hub:\d+:sug$"))
async def fallback_hub_suggested(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = int(callback.data.split(":")[3])
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        suggestion = _service(services).suggest_origin()
        if suggestion is None:
            await safe_callback_answer(callback, t("action_stale"), show_alert=True)
            return
        await state.clear()
        await safe_callback_answer(callback, t("fb_hub_assigning"))
        await safe_edit_message_text(callback.message, t("fb_hub_assigning"))
        notice, _ = await _assign(services, callback.from_user.id, relay_id, suggestion)
        await safe_edit_message_text(callback.message, notice, reply_markup=_hub_back(relay_id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(AdminFallbackStates.origin)
async def fallback_origin_input(message: Message, state: FSMContext, services: Services) -> None:
    try:
        actor = await _typed(message, state, services)
        if actor is None:
            return
        data = await state.get_data()
        relay_id = int(data.get("relay_id") or 0)
        setup = bool(data.get("setup"))
        await state.clear()
        progress = await message.answer(t("fb_hub_assigning"))
        notice, ok = await _assign(services, actor, relay_id, message.text or "")
        if setup and ok:
            screen = await _setup_screen(services, actor, state, notice)
            if screen is not None:
                await safe_edit_message_text(progress, screen[0], reply_markup=screen[1])
                return
        await safe_edit_message_text(progress, notice, reply_markup=_hub_back(relay_id))
    except Exception as exc:
        await answer_message_error(message, exc)


def _hub_back(relay_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_relay_page"), callback_data=f"admin:relay:{relay_id}")],
        [InlineKeyboardButton(text=t("btn_fb_open"), callback_data="admin:fb")],
    ])


@router.callback_query(F.data.regexp(r"^admin:fb:unhub:\d+$"))
async def fallback_hub_clear(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None
        relay_id = int(callback.data.rsplit(":", 1)[1])
        if not await require_totp(callback, state, services, action="fallback_hub"):
            return
        try:
            relay = await _service(services).clear_hub(callback.from_user.id, relay_id)
            notice = t("fb_hub_cleared", name=h(relay.name))
        except ServiceError as exc:
            notice = t("fb_hub_failed", error=h(service_error_text(exc)))
        await safe_callback_answer(callback)
        await safe_edit_message_text(callback.message, notice, reply_markup=_hub_back(relay_id))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.regexp(r"^admin:fb:"))
async def stale_fallback_callback(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    """Anything else under ``admin:fb:`` (an old button): a short note and the screen."""
    try:
        if not await _guard(callback, services):
            return
        await _leave(state)
        await safe_callback_answer(callback, t("action_stale"), show_alert=True)
        await _show(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)
