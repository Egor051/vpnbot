"""Admin «All-in-One» section: bring every active bundle to the target composition.

Two bulk operations, both :meth:`services.key_bundles.KeyBundleService.reconcile_all`:

* «switch every subscription to basic» — ``target_kind=basic``: the XHTTP
  children go, the missing members (relay ones too, for every relay that is
  enabled and «в подписках») are created, the kind becomes basic;
* «top every subscription up» — ``target_kind=None``: the same without a kind
  change, e.g. to add the relay members after a relay was added in «🛰 Relay».

Each starts with a dry run over every active bundle and a plan screen; nothing
is written before the confirmation. The run itself takes one Xray apply per
VLESS key it creates or deletes, so it goes to a background task: the callback
is answered at once, and the progress message (bot/progress.py) lists the steps —
the dry run ✅, «Применение» with N of M subscriptions and its percentage, the report —
edited at most once per :data:`PROGRESS_EDIT_INTERVAL_SECONDS`; the report closes it.
Only one run per process at a time.

Superadmin only, and inert while ``SUBSCRIPTION_ENABLED`` is false — every
handler checks both itself, so a replayed callback is refused, not just hidden.

The relay card's «Добавить в подписки» / «Убрать из подписок»
(bot/handlers/admin_relays.py) run a scoped twin of these operations through the
SAME :data:`runner`, so only one bulk run of either kind goes at a time.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

from aiogram import F, Router
from aiogram.types import CallbackQuery, InaccessibleMessage, InlineKeyboardMarkup, Message

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
from bot.progress import PROGRESS_EDIT_INTERVAL_SECONDS as PROGRESS_INTERVAL
from bot.progress import ProgressMessage, steps_of
from i18n import t
from models.enums import KeyBundleKind
from services.key_bundles import ReconcileOutcome, ReconcileResult, ReconcileSummary
from utils.formatting import h

router = Router()
logger = logging.getLogger(__name__)

# bot/progress.py's interval (one edit per message per 3 s), kept importable here.
PROGRESS_EDIT_INTERVAL_SECONDS = PROGRESS_INTERVAL
# Entries per skipped/failed list in a plan or report; the rest are counted.
_LIST_LIMIT = 15
# How long bot shutdown waits for a run to finish the bundle it is on. One bundle
# is a handful of Xray applies; this stays under systemd's default 90 s stop
# timeout so the wait ends before the unit is killed.
SHUTDOWN_TIMEOUT_SECONDS = 60.0


class ReconcileRunner:
    """Holds the one bulk run of this process.

    The strong reference also keeps the task from being garbage-collected
    mid-run (asyncio keeps only weak references to tasks). :meth:`shutdown` is
    called by ``main.py`` before the database and the bot session close.
    """

    def __init__(self) -> None:
        self._task: asyncio.Task[None] | None = None
        self._stop = False

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def task(self) -> asyncio.Task[None] | None:
        return self._task

    def start(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        self._stop = False
        task = asyncio.create_task(coro)
        self._task = task
        return task

    def stop_requested(self) -> bool:
        return self._stop

    async def shutdown(self, timeout: float = SHUTDOWN_TIMEOUT_SECONDS) -> None:
        """Let a running bulk run finish its current bundle, then stop it.

        The run checks the stop flag only between bundles, so the bundle it is
        on completes — or rolls back — against a still-open database and live
        backends. Cancelling it instead could interrupt a create between the
        backend apply and the attach. Only past *timeout* is the task cancelled,
        as a last resort before the process is killed anyway.
        """
        task = self._task
        if task is None or task.done():
            return
        self._stop = True
        logger.info("Stopping the All-in-One bulk reconcile after its current bundle")
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout)
        except TimeoutError:
            logger.critical("All-in-One bulk reconcile did not stop within %.0f s; cancelling it", timeout)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


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
    runner.start(
        run_reconcile(services, callback.message, callback.from_user.id, mode, should_stop=runner.stop_requested)
    )
    await safe_callback_answer(callback, t("aio_started"))


# ── the background run ───────────────────────────────────────────────────────


class ProgressReporter:
    """A reconcile's progress message (bot/progress.py): «Проверка (dry run)» ✅,
    «Применение» with N of M subscriptions (and its percentage), «Отчёт».

    Called with (done, total) after every bundle; edits at most once per *interval*
    (the animation between bundles too, through :meth:`run`).
    """

    def __init__(
        self,
        message: Message | InaccessibleMessage,
        title: str,
        *,
        interval: float = PROGRESS_EDIT_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.view = ProgressMessage(
            message, f"<b>{h(title)}</b>",
            steps_of(reconcile_steps(), plan="ok"), interval=interval, clock=clock,
        )

    @property
    def edits(self) -> int:
        return self.view.edits

    async def start(self) -> None:
        self.view.start("apply")
        await self.view.push(force=True)

    async def __call__(self, done: int, total: int) -> None:
        self.view.set("apply", "run", done=done, total=total)
        await self.view.push()

    async def finish(self, report: str, markup: InlineKeyboardMarkup | None, *, ok: bool = True) -> None:
        if ok:
            self.view.complete()
        else:
            self.view.fail_running()
        await self.view.finish(report, markup)


def reconcile_steps() -> list[tuple[str, str]]:
    return [("plan", t("aio_step_plan")), ("apply", t("aio_step_apply")), ("report", t("aio_step_report"))]


def reconcile_plan_steps_text() -> str:
    """The steps under a plan screen (all ⚪): what «Выполнить» will run."""
    from bot.progress import render_steps

    return render_steps(t("aio_steps_title"), steps_of(reconcile_steps(), plan="ok"))


async def run_reconcile(
    services: Services,
    message: Message | InaccessibleMessage,
    actor_user_id: int,
    mode: str,
    *,
    clock: Callable[[], float] = time.monotonic,
    should_stop: Callable[[], bool] | None = None,
) -> None:
    """The bulk run: progress while it goes, the report when it is done.

    Never raises — a background task's exception would only surface as an
    «exception was never retrieved» log line; the admin gets the error instead.
    """
    title = _mode_title(mode)
    progress = ProgressReporter(message, title, clock=clock)
    try:
        await progress.start()
        summary = await progress.view.run(services.key_bundles.reconcile_all(
            actor_user_id=actor_user_id,
            target_kind=_target_kind(mode),
            on_progress=progress,
            should_stop=should_stop,
        ))
        await progress.finish(aio_report_text(mode, summary), admin_bundles_back_keyboard())
    except Exception as exc:
        logger.exception("All-in-one bulk reconcile failed")
        await progress.finish(
            t("aio_failed", title=title, error=h(service_error_text(exc))), admin_bundles_back_keyboard(), ok=False
        )


# ── text ─────────────────────────────────────────────────────────────────────


def aio_plan_text(mode: str, summary: ReconcileSummary) -> str:
    """The plan screen: what a confirmed run would do, from a dry run."""
    planned = summary.with_outcome(ReconcileOutcome.PLANNED)
    skipped = summary.with_outcome(ReconcileOutcome.SKIPPED)
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
    parts.extend(reconcile_issue_blocks(summary))
    if planned:
        parts.append(t(f"aio_plan_note_{mode}"))
        parts.append(reconcile_plan_steps_text())
    else:
        parts.append(t("aio_plan_nothing"))
    return "\n\n".join(parts)


def aio_report_text(mode: str, summary: ReconcileSummary) -> str:
    """The final report of a run: ok / skipped (with reasons) / errors."""
    return reconcile_report_text(_mode_title(mode), summary)


def reconcile_issue_blocks(summary: ReconcileSummary) -> list[str]:
    """The «Пропущены» (with reasons) and «Ошибки» blocks of a plan or a report.

    Shared with the relay card's scoped runs (bot/handlers/admin_relays.py), so a
    skipped or failed bundle reads the same in both sections.
    """
    skipped = summary.with_outcome(ReconcileOutcome.SKIPPED)
    failed = summary.with_outcome(ReconcileOutcome.FAILED, ReconcileOutcome.PARTIAL)
    blocks: list[str] = []
    if skipped:
        blocks.append(_list_block("aio_skipped_title", [_skip_line(result) for result in skipped]))
    if failed:
        blocks.append(_list_block("aio_failed_title", [_failure_line(result) for result in failed]))
    return blocks


def reconcile_report_text(title: str, summary: ReconcileSummary) -> str:
    """The final report of a bulk run titled *title*: ok / skipped / errors / stop."""
    applied = summary.with_outcome(ReconcileOutcome.APPLIED)
    skipped = summary.with_outcome(ReconcileOutcome.SKIPPED)
    failed = summary.with_outcome(ReconcileOutcome.FAILED, ReconcileOutcome.PARTIAL)
    parts = [
        t(
            "aio_report_header",
            title=title,
            total=len(summary.results),
            applied=len(applied),
            created=summary.keys_created,
            deleted=summary.keys_deleted,
            noop=len(summary.with_outcome(ReconcileOutcome.NOOP)),
            skipped=len(skipped),
            failed=len(failed),
        )
    ]
    parts.extend(reconcile_issue_blocks(summary))
    if summary.remaining:
        parts.append(t("aio_report_stopped", remaining=summary.remaining))
    if failed or summary.remaining:
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
