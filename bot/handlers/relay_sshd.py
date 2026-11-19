"""«🧹 Убрать чужой override» (services/relay_sshd_override.py, docs/relay.md «Чужой sshd-override»).

* ``rsov:go:<relay>:<tag>`` — under the superadmins' alert and under a failed «Обновить
  агент» whose host check named the file: THIS message becomes the plan (what moves
  where, the precondition, what is checked) with «✅ Подтвердить» / «✖️ Отмена» — or,
  with TOTP, the code prompt, the code being the confirmation (bot/totp_gate.py, in place).
* ``rsov:ok:<relay>:<tag>`` — the agent's ``sshd-override-off``, in this message; the
  result with «⬅️ Назад» to the relay's card.

The tag is a hash of the path (callback data is 64 bytes); the path itself is one the
bot learned for the relay (:meth:`SshdOverrideMonitor.resolve`) — and the agent moves it
only when its own fresh host check names it. SUPERADMIN only, every handler checks it.
"""

from __future__ import annotations

import logging
from typing import cast

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, service_error_text
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from bot.progress import ProgressMessage, steps_of
from bot.totp_gate import Resume, register_resume, require_totp_in_place
from i18n import t
from models.dto import Relay
from services.errors import NotFound, ServiceError
from services.relay_sshd_override import CALLBACK_PREFIX, SshdOverrideMonitor, parse_callback, path_tag
from services.relays import AGENT_SSHD_OVERRIDE, agent_older_than, agent_release
from utils.formatting import code, h

router = Router()
logger = logging.getLogger(__name__)
_PATTERN = rf"^{CALLBACK_PREFIX}(go|ok):\d+:[0-9a-f]{{10}}$"


def _back(relay_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_back"), callback_data=f"admin:relay:{relay_id}")],
    ])


def plan_text(relay: Relay, path: str, *, needs_code: bool = False) -> str:
    lines = [
        t("relay_sshd_override_title", name=h(relay.name)),
        "",
        t("relay_sshd_override_plan", path=code(path), attic=code("/root/attic/")),
        "",
        t("relay_sshd_override_confirm_code") if needs_code else t("relay_sshd_override_confirm_hint"),
    ]
    return "\n".join(lines)


def _monitor(services: Services) -> SshdOverrideMonitor | None:
    monitor = getattr(services, "sshd_override", None)
    return monitor if isinstance(monitor, SshdOverrideMonitor) else None


async def _target(services: Services, actor: int, data: str) -> tuple[Relay, str | None]:
    parsed = parse_callback(data)
    if parsed is None:
        raise NotFound("кнопка устарела", key="relay_sshd_override_stale")
    _, relay_id, tag = parsed
    relay = await services.relays.get(actor, relay_id)
    monitor = _monitor(services)
    path = await monitor.resolve(relay, tag) if monitor is not None else None
    return relay, path


async def _guard(callback: CallbackQuery, services: Services) -> bool:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return False
    if callback.from_user is None or callback.message is None or callback.data is None:
        return False
    await require_superadmin(services, callback.from_user.id)
    return True


async def _progress_edit(message: object, text: str, *, reply_markup: InlineKeyboardMarkup | None = None) -> bool:
    return await safe_edit_message_text(message, text, reply_markup=reply_markup)  # type: ignore[arg-type]


async def _run(message: Message, actor: int, relay: Relay, path: str, services: Services) -> None:
    """``sshd-override-off`` with one step moving in *message*; the result and «⬅️ Назад»."""
    view = ProgressMessage(message, t("relay_sshd_override_title", name=h(relay.name)),
                           steps_of([("move", t("relay_sshd_override_step", path=path))]), edit=_progress_edit)
    view.start("move")
    await view.push(force=True)
    try:
        result = await view.run(services.relays.remove_sshd_override(actor, relay.id, path))
    except ServiceError as exc:
        view.fail_running()
        await view.finish(t("relay_sshd_override_failed", error=h(service_error_text(exc))), _back(relay.id))
        return
    view.complete()
    notice = t("relay_sshd_override_done", path=code(path), moved=code(str(result.get("moved_to") or "?")))
    still = result.get("still_beaten_by")
    if isinstance(still, list) and still:
        notice += "\n" + t("relay_sshd_override_still", paths=", ".join(code(str(p)) for p in still[:4]))
    await view.finish(notice, _back(relay.id))


@router.callback_query(F.data.regexp(_PATTERN))
async def relay_sshd_override(callback: CallbackQuery, state: FSMContext, services: Services) -> None:
    try:
        if not await _guard(callback, services):
            return
        assert callback.from_user is not None and callback.data is not None and callback.message is not None
        actor = callback.from_user.id
        relay, path = await _target(services, actor, callback.data)
        if path is None:
            await safe_callback_answer(callback, t("relay_sshd_override_stale"), show_alert=True)
            return
        if agent_older_than(relay.agent, AGENT_SSHD_OVERRIDE):
            await safe_callback_answer(callback)
            await safe_edit_message_text(
                callback.message,
                t("relay_sshd_override_title", name=h(relay.name)) + "\n\n" + t(
                    "relay_sshd_override_manual", version=h(agent_release(relay.agent)), commands=h(f"mv {path} /root/attic/")
                ),
                reply_markup=_back(relay.id),
            )
            return
        resume = f"{CALLBACK_PREFIX}ok:{relay.id}:{path_tag(path)}"
        if not await require_totp_in_place(
            callback, state, services, action="relay_sshd_override", screen=plan_text(relay, path, needs_code=True),
            resume=resume, back=f"admin:relay:{relay.id}", edit=safe_edit_message_text,
        ):
            return
        if callback.data.startswith(f"{CALLBACK_PREFIX}go:"):
            await safe_callback_answer(callback)
            await safe_edit_message_text(callback.message, plan_text(relay, path), reply_markup=InlineKeyboardMarkup(
                inline_keyboard=[
                    [InlineKeyboardButton(text=t("btn_relay_harden_confirm"), callback_data=resume)],
                    [InlineKeyboardButton(text=t("btn_relay_update_cancel"), callback_data=f"admin:relay:{relay.id}")],
                ]))
            return
        await safe_callback_answer(callback, t("relay_sshd_override_working"))
        await _run(cast(Message, callback.message), actor, relay, path, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


@register_resume(rf"{CALLBACK_PREFIX}ok:\d+:[0-9a-f]{{10}}")
async def relay_sshd_override_resume(resume: Resume) -> None:
    """A correct TOTP code on the plan: it was the confirmation — the move starts here."""
    try:
        await require_superadmin(resume.services, resume.user.id)
        relay, path = await _target(resume.services, resume.user.id, resume.data)
        if path is None:
            await safe_edit_message_text(resume.message, t("relay_sshd_override_stale"), reply_markup=_back(relay.id))
            return
        await _run(resume.message, resume.user.id, relay, path, resume.services)
    except ServiceError as exc:
        await safe_edit_message_text(resume.message, h(service_error_text(exc)), reply_markup=None)
