"""Admin «All-in-One» section: bring every active bundle to the target composition.

Two bulk operations, both :meth:`services.key_bundles.KeyBundleService.reconcile_all`:

* «switch every subscription to basic» — ``target_kind=basic``: the XHTTP
  children go, the missing members (relay ones too, while ``RELAY_ENABLED``) are
  created, the kind becomes basic;
* «top every subscription up» — ``target_kind=None``: the same without a kind
  change, e.g. to add the relay members after ``RELAY_ENABLED`` was switched on.

Each starts with a dry run over every active bundle and a plan screen; nothing
is written before the confirmation. The run itself takes one Xray apply per
VLESS key it creates or deletes, so it goes to a background task: the callback
is answered at once, a progress message is edited at most once per
:data:`PROGRESS_EDIT_INTERVAL_SECONDS`, and the final report replaces it. Only
one run per process at a time.

Superadmin only, and inert while ``SUBSCRIPTION_ENABLED`` is false — every
handler checks both itself, so a replayed callback is refused, not just hidden.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

from aiogram import F, Router
from aiogram.types import CallbackQuery, InaccessibleMessage, Message

from bot.bundles import require_subscription_ui
from bot.container import Services
from bot.guards import require_superadmin
from bot.handlers.common import InvalidCallbackData, answer_callback_error, service_error_text
from bot.keyboards.admin_bundles import (
    MODE_BASIC,
    RECONCILE_MODES,
    admin_bundles_back_keyboard,
    admin_bundles_confirm_keyboard,
    admin_bundles_panel_keyboard,
)
from bot.messages import safe_callback_answer, safe_edit_message_text
from bot.private_chat import ensure_private_callback
from i18n import t
from models.enums import KeyBundleKind
from services.key_bundles import ReconcileOutcome, ReconcileResult, ReconcileSummary
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)

# The progress message is edited no more often than this (Telegram throttles
# edits of one message, and a bundle can take well under a second).
PROGRESS_EDIT_INTERVAL_SECONDS = 3.0
# Entries per skipped/failed list in a plan or report; the rest are counted.
_LIST_LIMIT = 15


class ReconcileRunner:
    """Holds the one bulk run of this process.

    The strong reference also keeps the task from being garbage-collected
    mid-run (asyncio keeps only weak references to tasks).
    """

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def task(self) -> asyncio.Task[None] | None:
        return self._task

    def start(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task = asyncio.create_task(coro)
        self._task = task
        return task


runner = ReconcileRunner()


# ── handlers ─────────────────────────────────────────────────────────────────


@router.callback_query(F.data == "admin:aio")
async def admin_bundles_panel(callback: CallbackQuery, services: Services) -> None:
    """The section screen with the two bulk operations."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        require_subscription_ui(services)
        await safe_callback_answer(callback)
        await safe_edit_message_text(
            callback.message, t("aio_panel_title"), reply_markup=admin_bundles_panel_keyboard()
        )
    except Exception as exc:
        await answer_callback_error(callback, exc)


@router.callback_query(F.data.startswith("admin:aio:plan:"))
async def admin_bundles_plan(callback: CallbackQuery, services: Services) -> None:
    """Dry-run every active bundle and show what the operation would change."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        require_subscription_ui(services)
        mode = _mode(callback.data, "plan")
        if runner.running:
            await safe_callback_answer(callback, t("aio_already_running"), show_alert=True)
            return
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return

    await safe_callback_answer(callback, t("aio_planning"))
    try:
        summary = await services.key_bundles.reconcile_all(
            actor_user_id=callback.from_user.id, target_kind=_target_kind(mode), dry_run=True
        )
    except Exception as exc:
        logger.warning("All-in-one reconcile dry run failed", exc_info=True)
        await safe_edit_message_text(
            callback.message,
            t("aio_failed", title=_mode_title(mode), error=h(service_error_text(exc))),
            reply_markup=admin_bundles_back_keyboard(),
        )
        return
    has_changes = bool(summary.with_outcome(ReconcileOutcome.PLANNED))
    await safe_edit_message_text(
        callback.message,
        aio_plan_text(mode, summary),
        reply_markup=admin_bundles_confirm_keyboard(mode) if has_changes else admin_bundles_back_keyboard(),
    )


@router.callback_query(F.data.startswith("admin:aio:run:"))
async def admin_bundles_run(callback: CallbackQuery, services: Services) -> None:
    """Start the confirmed bulk run in the background and return at once."""
    if not await ensure_private_callback(callback, t("admin_private_only_text")):
        return
    if callback.from_user is None or callback.message is None or callback.data is None:
        return
    try:
        await require_superadmin(services, callback.from_user.id)
        require_subscription_ui(services)
        mode = _mode(callback.data, "run")
    except Exception as exc:
        await answer_callback_error(callback, exc)
        return
    # The check and the start have no await between them, so a double tap
    # cannot start two runs.
    if runner.running:
        await safe_callback_answer(callback, t("aio_already_running"), show_alert=True)
        return
    runner.start(run_reconcile(services, callback.message, callback.from_user.id, mode))
    await safe_callback_answer(callback, t("aio_started"))


# ── the background run ───────────────────────────────────────────────────────


class ProgressReporter:
    """Edits the progress message, at most once per *interval* seconds."""

    def __init__(
        self,
        message: Message | InaccessibleMessage,
        title: str,
        *,
        interval: float = PROGRESS_EDIT_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._message = message
        self._title = title
        self._interval = interval
        self._clock = clock
        self._last: float | None = None
        self.edits = 0

    async def start(self) -> None:
        await safe_edit_message_text(self._message, t("aio_run_started", title=self._title))
        self._last = self._clock()
        self.edits += 1

    async def __call__(self, done: int, total: int) -> None:
        # The final report replaces the message right after the last bundle.
        if done >= total:
            return
        now = self._clock()
        if self._last is not None and now - self._last < self._interval:
            return
        self._last = now
        self.edits += 1
        await safe_edit_message_text(
            self._message, t("aio_run_progress", title=self._title, done=done, total=total)
        )


async def run_reconcile(
    services: Services,
    message: Message | InaccessibleMessage,
    actor_user_id: int,
    mode: str,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """The bulk run: progress while it goes, the report when it is done.

    Never raises — a background task's exception would only surface as an
    «exception was never retrieved» log line; the admin gets the error instead.
    """
    title = _mode_title(mode)
    try:
        progress = ProgressReporter(message, title, clock=clock)
        await progress.start()
        summary = await services.key_bundles.reconcile_all(
            actor_user_id=actor_user_id, target_kind=_target_kind(mode), on_progress=progress
        )
        await safe_edit_message_text(
            message, aio_report_text(mode, summary), reply_markup=admin_bundles_back_keyboard()
        )
    except Exception as exc:
        logger.exception("All-in-one bulk reconcile failed")
        await safe_edit_message_text(
            message,
            t("aio_failed", title=title, error=h(service_error_text(exc))),
            reply_markup=admin_bundles_back_keyboard(),
        )


# ── text ─────────────────────────────────────────────────────────────────────


def aio_plan_text(mode: str, summary: ReconcileSummary) -> str:
    """The plan screen: what a confirmed run would do, from a dry run."""
    planned = summary.with_outcome(ReconcileOutcome.PLANNED)
    skipped = summary.with_outcome(ReconcileOutcome.SKIPPED)
    failed = summary.with_outcome(ReconcileOutcome.FAILED, ReconcileOutcome.PARTIAL)
    parts = [
        t(
            "aio_plan_header",
            title=_mode_title(mode),
            total=len(summary.results),
            planned=len(planned),
            create=summary.keys_to_create,
            delete=summary.keys_to_delete,
            kinds=summary.kind_changes,
            noop=len(summary.with_outcome(ReconcileOutcome.NOOP)),
            skipped=len(skipped),
        )
    ]
    if skipped:
        parts.append(_list_block("aio_skipped_title", [_skip_line(result) for result in skipped]))
    if failed:
        parts.append(_list_block("aio_failed_title", [_failure_line(result) for result in failed]))
    if planned:
        parts.append(t(f"aio_plan_note_{mode}"))
    else:
        parts.append(t("aio_plan_nothing"))
    return "\n\n".join(parts)


def aio_report_text(mode: str, summary: ReconcileSummary) -> str:
    """The final report of a run: ok / skipped (with reasons) / errors."""
    applied = summary.with_outcome(ReconcileOutcome.APPLIED)
    skipped = summary.with_outcome(ReconcileOutcome.SKIPPED)
    failed = summary.with_outcome(ReconcileOutcome.FAILED, ReconcileOutcome.PARTIAL)
    parts = [
        t(
            "aio_report_header",
            title=_mode_title(mode),
            total=len(summary.results),
            applied=len(applied),
            created=summary.keys_created,
            deleted=summary.keys_deleted,
            noop=len(summary.with_outcome(ReconcileOutcome.NOOP)),
            skipped=len(skipped),
            failed=len(failed),
        )
    ]
    if skipped:
        parts.append(_list_block("aio_skipped_title", [_skip_line(result) for result in skipped]))
    if failed:
        parts.append(_list_block("aio_failed_title", [_failure_line(result) for result in failed]))
        parts.append(t("aio_report_retry_hint"))
    return "\n\n".join(parts)


def _list_block(title_key: str, lines: list[str]) -> str:
    shown = lines[:_LIST_LIMIT]
    if len(lines) > _LIST_LIMIT:
        shown.append(t("aio_list_more", count=len(lines) - _LIST_LIMIT))
    return "\n".join([t(title_key), *shown])


def _bundle_label(result: ReconcileResult) -> str:
    return h(t("bundle_title", id=result.display_no))


def _skip_line(result: ReconcileResult) -> str:
    reason = t(f"aio_reason_{result.skip_reason.value}") if result.skip_reason else "?"
    details = f" ({h(', '.join(result.anomalies))})" if result.anomalies else ""
    return f"• {_bundle_label(result)} — {reason}{details}"


def _failure_line(result: ReconcileResult) -> str:
    error = h(service_error_text(result.error)) if result.error is not None else ""
    if result.outcome is ReconcileOutcome.PARTIAL:
        state = t("aio_state_partial", done=len(result.deleted_key_ids), total=len(result.to_delete))
    elif result.rollback_failed_key_ids:
        ids = ", ".join(f"#{key_id}" for key_id in result.rollback_failed_key_ids)
        state = t("aio_state_rollback_failed", ids=ids)
    else:
        state = t("aio_state_failed")
    return f"• {_bundle_label(result)} — {state}" + (f": {error}" if error else "")


# ── parsing ──────────────────────────────────────────────────────────────────


def _mode(data: str, verb: str) -> str:
    """Parse ``admin:aio:<verb>:<mode>`` into one of :data:`RECONCILE_MODES`."""
    parts = data.split(":")
    if len(parts) != 4 or parts[:3] != ["admin", "aio", verb] or parts[3] not in RECONCILE_MODES:
        raise InvalidCallbackData(t("invalid_callback_btn"))
    return parts[3]


def _target_kind(mode: str) -> KeyBundleKind | None:
    return KeyBundleKind.BASIC if mode == MODE_BASIC else None


def _mode_title(mode: str) -> str:
    return t(f"aio_mode_{mode}")
