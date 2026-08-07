"""Inline GUI for the WARP split-list prefix sources.

Presentation over :class:`services.warp_split_feeds.WarpSplitFeedService`. Like
the rest of the split panel, this module never touches ip/route/iptables, never
writes the list file and never calls a privileged helper — the service owns the
merge and the manager owns the write.

Two interaction rules are deliberate and worth keeping:

* **A manual refresh previews and asks.** Fetching is separated from applying, so
  the operator sees the delta — including the fragmentation a subtraction causes —
  before the routing policy for every client changes. Only the unattended
  scheduler applies without asking, and it notifies past
  ``WARP_SPLIT_FEED_ALERT_DELTA_PCT``.
* **Every callback is superadmin-gated server-side.** A callback can be fired by
  anyone who can see the message, so the gate never relies on a hidden button.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.container import Services
from bot.fsm.states import WarpSplitStates
from bot.guards import require_superadmin
from bot.handlers.common import answer_callback_error, answer_message_error
from bot.keyboards.warp_split_sources_keyboard import (
    warp_split_back_keyboard,
    warp_split_confirm_keyboard,
    warp_split_pending_keyboard,
    warp_split_source_add_keyboard,
    warp_split_sources_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback, ensure_private_message
from i18n import t
from services.errors import InvalidOperation
from services.warp_split_feeds import (
    MergePlan,
    WarpFeedStaleCandidate,
    WarpSplitFeedService,
)
from utils.formatting import code, h
from warp.feed_state import PendingCandidate, SplitRun, SplitSource

router = Router()
logger = logging.getLogger(__name__)

# How many changed prefixes to spell out in a preview before truncating. Enough
# to recognise what is happening, short enough to survive Telegram's message cap
# when a subtraction adds 163 entries at once.
_PREVIEW_SAMPLE = 6


# ── rendering ─────────────────────────────────────────────────────────────────


def _timestamp(value: int) -> str:
    if value <= 0:
        return t("warp_split_source_never")
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _mode_text(source: SplitSource) -> str:
    if not source.is_subtract:
        return t("warp_split_source_mode_add")
    if source.scope_slug is None:
        return t("warp_split_source_mode_subtract_all")
    return t("warp_split_source_mode_subtract_scope", scope=source.scope_slug)


def _source_lines(sources: list[SplitSource]) -> list[str]:
    lines: list[str] = [t("warp_split_sources_title", count=len(sources))]
    if not sources:
        lines.append("")
        lines.append(t("warp_split_sources_empty"))
        return lines
    for source in sources:
        lines.append("")
        lines.append(
            t(
                "warp_split_source_line",
                state="✅" if source.enabled else "⛔",
                title=h(source.title),
                slug=source.slug,
                mode=_mode_text(source),
                count=source.prefix_count,
                updated=_timestamp(source.last_success_ts),
            )
        )
        if source.last_error:
            lines.append(t("warp_split_source_error_line", error=h(source.last_error[:160])))
    return lines


def _advisories(sources: list[SplitSource], migratable: int) -> list[str]:
    """Warnings that depend on the current combination of sources.

    The goog-without-cloud warning exists because enabling the base source alone
    is a silent, plausible-looking mistake with a large blast radius: it routes
    every GCP customer range through the tunnel and nothing about the panel would
    otherwise say so.
    """
    notes: list[str] = []
    by_slug = {source.slug: source for source in sources}
    goog = by_slug.get("google-goog")
    cloud = by_slug.get("google-cloud")
    if goog is not None and goog.enabled and (cloud is None or not cloud.enabled):
        notes.append(t("warp_split_source_goog_warning"))
    # A scoped subtraction whose target is also duplicated in manual does nothing
    # at all; say so where the operator is looking, not only in the docs.
    if migratable > 0 and any(
        source.enabled and source.is_subtract and source.scope_slug is not None
        for source in sources
    ):
        notes.append(t("warp_split_source_scope_inert"))
    return notes


async def _count_migratable(service: WarpSplitFeedService) -> int:
    """How many manual prefixes an enabled add-source already covers."""
    stored = await service.contributions()
    covered: list[ipaddress.IPv4Network] = []
    for source in await service.list_sources():
        if source.contributes_to_list:
            for item in stored.get(source.slug, ()):
                try:
                    covered.append(ipaddress.IPv4Network(item))
                except ValueError:
                    continue
    total = 0
    for item in stored.get("manual", ()):
        try:
            net = ipaddress.IPv4Network(item)
        except ValueError:
            continue
        if any(net.subnet_of(other) for other in covered):
            total += 1
    return total


async def _render_sources(callback: CallbackQuery, services: Services, *, prefix: str = "") -> None:
    service = services.warp_split_feeds
    sources = await service.list_sources()
    migratable = await _count_migratable(service)
    lines = _source_lines(sources)
    lines.extend("\n" + note for note in _advisories(sources, migratable))
    body = "\n".join(lines)
    await safe_edit_message_text(
        callback.message,
        f"{prefix}\n\n{body}" if prefix else body,
        reply_markup=warp_split_sources_keyboard(sources, has_migratable=migratable > 0),
    )


def _plan_text(plan: MergePlan) -> str:
    """Render a delta preview, including what the subtraction cost."""
    lines = [t("warp_split_preview_title")]
    if plan.identical:
        lines.append(t("warp_split_preview_identical"))
        return "\n".join(lines)

    lines.append(
        t(
            "warp_split_preview_counts",
            before=len(plan.current),
            after=len(plan.prefixes),
            delta=f"+{len(plan.added)}/-{len(plan.removed)}",
        )
    )
    report = plan.report
    if report.subtraction_applied:
        # Requirement of the feature, not decoration: a subtraction that removes
        # 19M addresses while ADDING 163 prefixes is the surprising part, and it
        # has to be on screen before the operator confirms.
        lines.append(
            t(
                "warp_split_preview_subtract",
                addresses=f"{report.addresses_removed:,}",
                prefixes=f"{report.prefixes_added_by_subtraction:+d}",
                before=report.n_before_subtract,
                after=report.n_after_subtract,
                collapsed=report.n_after_collapse,
            )
        )
    if plan.added:
        lines.append(
            t(
                "warp_split_preview_added",
                count=len(plan.added),
                sample=", ".join(plan.added[:_PREVIEW_SAMPLE]) + ("…" if len(plan.added) > _PREVIEW_SAMPLE else ""),
            )
        )
    if plan.removed:
        lines.append(
            t(
                "warp_split_preview_removed",
                count=len(plan.removed),
                sample=", ".join(plan.removed[:_PREVIEW_SAMPLE]) + ("…" if len(plan.removed) > _PREVIEW_SAMPLE else ""),
            )
        )
    lines.append("")
    lines.append(t("warp_split_preview_confirm"))
    return "\n".join(lines)


# ── panel ─────────────────────────────────────────────────────────────────────


@router.callback_query(F.data == "wsplit:src")
async def warp_split_sources_panel(
    callback: CallbackQuery, state: FSMContext, services: Services
) -> None:
    """Open the sources sub-panel (also the cancel target, so it clears any FSM)."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.clear()
        await _render_sources(callback, services)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── enable / disable ──────────────────────────────────────────────────────────


@router.callback_query(F.data.startswith("wsplit:srcon:"))
async def warp_split_source_on(callback: CallbackQuery, services: Services) -> None:
    await _toggle(callback, services, enabled=True)


@router.callback_query(F.data.startswith("wsplit:srcoff:"))
async def warp_split_source_off(callback: CallbackQuery, services: Services) -> None:
    await _toggle(callback, services, enabled=False)


async def _toggle(callback: CallbackQuery, services: Services, *, enabled: bool) -> None:
    """Flip a source on or off.

    Nothing is applied here on purpose: enabling a source changes what the NEXT
    refresh will compute, and the operator gets to preview that before it lands.
    """
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        slug = _tail(callback.data)
        await services.warp_split_feeds.set_enabled(slug, enabled)
        note = t("warp_split_source_enabled" if enabled else "warp_split_source_disabled", slug=slug)
        await _render_sources(callback, services, prefix=note)
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── refresh (preview → confirm) ───────────────────────────────────────────────


@router.callback_query(F.data.startswith("wsplit:srcref:"))
async def warp_split_source_refresh(callback: CallbackQuery, services: Services) -> None:
    """Fetch one source and show the resulting delta, without applying it."""
    await _refresh_preview(callback, services, slug=_tail(callback.data or ""))


@router.callback_query(F.data == "wsplit:srcrefall")
async def warp_split_sources_refresh_all(callback: CallbackQuery, services: Services) -> None:
    await _refresh_preview(callback, services, slug=None)


async def _refresh_preview(
    callback: CallbackQuery, services: Services, *, slug: str | None
) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        result = await services.warp_split_feeds.refresh(
            slugs=None if slug is None else [slug], apply=False
        )
        summary = ", ".join(
            f"{item.slug}: {item.status}" + (f" ({item.prefix_count})" if item.ok else "")
            for item in result.sources
        )
        header = t("warp_split_refresh_sources", summary=h(summary)) if summary else ""
        if result.blocked_reason is not None or result.plan is None:
            reason = result.blocked_reason or "no plan"
            await _render_sources(
                callback,
                services,
                prefix=f"{header}\n{t('warp_split_refresh_blocked', reason=h(reason))}".strip(),
            )
            return
        plan = result.plan
        if plan.identical:
            await _render_sources(
                callback, services, prefix=f"{header}\n{t('warp_split_preview_identical')}".strip()
            )
            return
        await safe_edit_message_text(
            callback.message,
            f"{header}\n\n{_plan_text(plan)}".strip(),
            reply_markup=warp_split_confirm_keyboard("wsplit:srcapply"),
        )
    except InvalidOperation as exc:
        await _render_sources(callback, services, prefix=t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "wsplit:srcapply")
async def warp_split_sources_apply(callback: CallbackQuery, services: Services) -> None:
    """Apply the previewed merge.

    The plan is recomputed inside the manager's lock rather than replayed from
    the preview: between preview and confirmation someone may have added a
    prefix in another chat, and applying a stale snapshot would silently drop it.
    """
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        service = services.warp_split_feeds
        plan = await service.build_plan()
        outcome = await service.apply_plan(plan, actor_user_id=callback.from_user.id)
        note = (
            t("warp_split_report_unchanged_identical")
            if outcome.unchanged
            else t("warp_split_refresh_done", delta=outcome.delta_text, count=outcome.count)
        )
        await _render_sources(callback, services, prefix=note)
    except InvalidOperation as exc:
        await _render_sources(callback, services, prefix=t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── add / delete a source ─────────────────────────────────────────────────────


@router.callback_query(F.data == "wsplit:srcadd")
async def warp_split_source_add_start(
    callback: CallbackQuery, state: FSMContext, services: Services
) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await state.set_state(WarpSplitStates.waiting_source)
        await safe_edit_message_text(
            callback.message,
            t("warp_split_source_add_prompt"),
            reply_markup=warp_split_source_add_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.message(WarpSplitStates.waiting_source)
async def warp_split_source_add_receive(
    message: Message, state: FSMContext, services: Services
) -> None:
    """Parse the four-or-five-line source description and store it, disabled."""
    if message.from_user is None:
        return
    if not await ensure_private_message(message, t("admin_private_only_text")):
        return
    try:
        await require_superadmin(services, message.from_user.id)
        fields = [line.strip() for line in (message.text or "").splitlines() if line.strip()]
        if len(fields) < 4:
            await message.answer(
                t("warp_split_source_add_usage"), reply_markup=warp_split_source_add_keyboard()
            )
            return
        slug, title, url, kind = fields[0], fields[1], fields[2], fields[3]
        mode, scope = _parse_mode(fields[4] if len(fields) > 4 else "")
        await services.warp_split_feeds.add_source(
            slug=slug, title=title, url=url, kind=kind, mode=mode, scope_slug=scope
        )
        await state.clear()
        await message.answer(t("warp_split_source_added", slug=slug))
    except InvalidOperation as exc:
        await state.clear()
        await message.answer(t("warp_split_source_add_error", error=h(exc)))
    except Exception as exc:
        await state.clear()
        await answer_message_error(message, exc)


def _parse_mode(raw: str) -> tuple[str, str | None]:
    """Read the optional mode line: ``subtract`` or ``subtract:<slug>``."""
    value = raw.strip().lower()
    if not value or value == "add":
        return "add", None
    if value == "subtract":
        return "subtract", None
    if value.startswith("subtract:"):
        return "subtract", value.split(":", 1)[1].strip() or None
    # Anything else is passed through so the service's validator produces the
    # error message, keeping one place that decides what a valid mode is.
    return value, None


@router.callback_query(F.data.startswith("wsplit:srcdel:"))
async def warp_split_source_delete_confirm(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        slug = _tail(callback.data)
        await safe_edit_message_text(
            callback.message,
            t("warp_split_source_delete_confirm", slug=slug),
            reply_markup=warp_split_confirm_keyboard(f"wsplit:srcdelok:{slug}"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("wsplit:srcdelok:"))
async def warp_split_source_delete(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        slug = _tail(callback.data)
        await services.warp_split_feeds.delete_source(slug)
        await _render_sources(callback, services, prefix=t("warp_split_source_deleted", slug=slug))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── manual → feed migration ───────────────────────────────────────────────────


@router.callback_query(F.data == "wsplit:mig")
async def warp_split_migrate_confirm(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        count = await _count_migratable(services.warp_split_feeds)
        if count == 0:
            await _render_sources(callback, services, prefix=t("warp_split_migrate_none"))
            return
        await safe_edit_message_text(
            callback.message,
            t("warp_split_migrate_confirm", count=count),
            reply_markup=warp_split_confirm_keyboard("wsplit:migok"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "wsplit:migok")
async def warp_split_migrate_execute(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        moved, _outcome = await services.warp_split_feeds.migrate_manual_into_feeds(
            actor_user_id=callback.from_user.id
        )
        await _render_sources(callback, services, prefix=t("warp_split_migrated", count=moved))
    except InvalidOperation as exc:
        await _render_sources(callback, services, prefix=t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── exclusions ────────────────────────────────────────────────────────────────


@router.callback_query(F.data.startswith("wsplit:excl:"))
async def warp_split_exclude_confirm(callback: CallbackQuery, services: Services) -> None:
    """Explain that 🗑 on a feed prefix records an exclusion rather than deleting."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    await safe_callback_answer(callback)
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        cidr = callback.data.split(":", 2)[2]
        contributions = await services.warp_split_feeds.contributions()
        origins = [
            origin
            for origin, items in contributions.items()
            if origin != "manual" and cidr in items
        ]
        await safe_edit_message_text(
            callback.message,
            t(
                "warp_split_exclude_confirm",
                cidr=code(cidr),
                origin=", ".join(origins) or "feed",
            ),
            reply_markup=warp_split_confirm_keyboard(f"wsplit:exclok:{cidr}"),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("wsplit:exclok:"))
async def warp_split_exclude_execute(callback: CallbackQuery, services: Services) -> None:
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        cidr = callback.data.split(":", 2)[2]
        await services.warp_split_feeds.exclude_prefix(cidr, actor_user_id=callback.from_user.id)
        await _render_sources(callback, services, prefix=t("warp_split_excluded", cidr=code(cidr)))
    except InvalidOperation as exc:
        await _render_sources(callback, services, prefix=t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


# ── the approval queue ────────────────────────────────────────────────────────


@router.callback_query(F.data == "wsplit:pend:ok")
async def warp_split_pending_apply(callback: CallbackQuery, services: Services) -> None:
    """Apply the queued candidate from the card.

    Nothing about this path is special-cased: the same merge is recomputed, the
    same guards run, the same lock is held and the same byte-identity check
    applies. The one addition is the hash check, which refuses a card the world
    has moved past instead of applying "whatever the merge says now" under an
    approval that was given for something else.
    """
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback, t("warp_processing"))
        outcome = await services.warp_split_feeds.apply_pending(
            actor_user_id=callback.from_user.id
        )
        note = (
            t("warp_split_report_unchanged_identical")
            if outcome.unchanged
            else t("warp_split_pending_applied", delta=outcome.delta_text, count=outcome.count)
        )
        await safe_edit_message_text(callback.message, note)
    except WarpFeedStaleCandidate as exc:
        await safe_edit_message_text(callback.message, t("warp_split_pending_stale", error=h(exc)))
    except InvalidOperation as exc:
        await safe_edit_message_text(callback.message, t("warp_split_reject", error=h(exc)))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "wsplit:pend:no")
async def warp_split_pending_reject(callback: CallbackQuery, services: Services) -> None:
    """Discard the queued candidate. The baseline stays where it is."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback)
        await services.warp_split_feeds.reject_pending(actor_user_id=callback.from_user.id)
        await safe_edit_message_text(callback.message, t("warp_split_pending_declined"))
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data == "wsplit:pend:full")
async def warp_split_pending_full(callback: CallbackQuery, services: Services) -> None:
    """Spell out every added and removed prefix of the queued candidate."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback)
        pending = await services.warp_split_feeds.pending()
        if pending is None:
            await safe_edit_message_text(callback.message, t("warp_split_pending_none"))
            return
        await safe_edit_message_text(
            callback.message,
            _pending_full_text(pending),
            reply_markup=warp_split_pending_keyboard(),
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _pending_full_text(pending: PendingCandidate) -> str:
    """Render the stored delta in full, capped to what Telegram will accept."""
    deltas = pending.deltas
    added = [str(item) for item in deltas.get("added", [])]
    removed = [str(item) for item in deltas.get("removed", [])]
    lines = [
        t("warp_split_pending_full_title", count=len(pending.prefixes)),
        t(
            "warp_split_pending_full_counts",
            added=int(deltas.get("added_total", len(added))),
            removed=int(deltas.get("removed_total", len(removed))),
        ),
    ]
    if added:
        lines.append("")
        lines.append(t("warp_split_pending_full_added"))
        lines.append(code(", ".join(added)))
    if removed:
        lines.append("")
        lines.append(t("warp_split_pending_full_removed"))
        lines.append(code(", ".join(removed)))
    return "\n".join(lines)


# ── run history ───────────────────────────────────────────────────────────────


@router.callback_query(F.data == "wsplit:hist")
async def warp_split_history(callback: CallbackQuery, services: Services) -> None:
    """Show the last ten unattended runs.

    This is the evidence for the decision the modes exist to support: after a
    fortnight in review, "were all the changes safe?" is answered by reading this
    rather than by remembering.
    """
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        await safe_callback_answer(callback)
        runs = await services.warp_split_feeds.recent_runs(10)
        if not runs:
            await _render_sources(callback, services, prefix=t("warp_split_history_empty"))
            return
        lines = [t("warp_split_history_title", mode=services.warp_split_feeds.mode)]
        lines.extend(_history_line(run) for run in runs)
        await safe_edit_message_text(
            callback.message, "\n".join(lines), reply_markup=warp_split_back_keyboard()
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


def _history_line(run: SplitRun) -> str:
    metrics = run.metrics
    detail = ""
    if "prefixes_before" in metrics and "prefixes_after" in metrics:
        detail = f" {metrics['prefixes_before']}→{metrics['prefixes_after']}"
    return t(
        "warp_split_history_line",
        ts=_timestamp(run.ts),
        mode=run.mode,
        decision=run.decision,
        detail=h(f"{detail} {run.reason}".strip()),
    )


def _tail(data: str) -> str:
    """Last colon-separated field of a callback payload (a slug — never a CIDR)."""
    return data.rsplit(":", 1)[-1]
