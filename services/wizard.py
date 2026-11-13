"""The setup wizard: runs of fixed, root-owned helper modes (docs/wizard.md).

What the bot does, and what it never does
    It never executes a mode and never runs a command it was given. It records a run
    in ``wizard_runs`` (the global lock: one active run, enforced by a UNIQUE index),
    asks ``/usr/local/sbin/vpn-bot-wizard launch`` — through sudo in the helper model
    (exact-path grant), directly as root otherwise — to start one phase of it, and
    from then on only READS: the run's status file
    (``/var/lib/vpn-bot-wizard/<id>.status``, JSON lines written by the root helpers)
    and whether the transient unit ``vpn-bot-wizard-<id>`` is still alive
    (``systemctl show``, no privilege needed).

Phases
    plan     the mode's ``plan`` step (dry run: what would change). A mode with
             ``needs_confirmation`` stops here: the run is ``planned`` with
             ``plan_ready`` until a superadmin confirms or cancels (or 30 minutes pass).
    execute  ``apply`` → ``verify``; on a failure ``rollback``. ``running`` /
             ``verifying`` while it runs; ``succeeded`` / ``rolled_back`` / ``failed``
             at the end. A read-only mode goes straight to this phase.

A restart of the bot changes nothing for the run: it lives in its own unit. At start
the monitor finds the active run, reads where the status file got to, and carries on
— including the final report, which is delivered exactly once (``reported_at``).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol

from adapters.clock import ClockProvider
from adapters.privileged_helpers import PrivilegedHelperRunner
from adapters.shell_runner import ShellRunner
from models.dto import WizardRun
from models.enums import AuditEntityType
from repositories.wizard_runs import WizardBusy, WizardRunRepository
from services.audit import AuditService
from services.errors import InvalidOperation, NotFound
from services.wizard_modes import WizardMode, get_mode
from utils.redact import redact_text, redact_value

logger = logging.getLogger(__name__)

HELPER_PATH = Path("/usr/local/sbin/vpn-bot-wizard")
STATE_DIR = Path("/var/lib/vpn-bot-wizard")
LOG_DIR = Path("/var/log/vpn-bot-wizard")
UNIT_PREFIX = "vpn-bot-wizard-"
LAUNCH_TIMEOUT_SECONDS = 60.0
# An unconfirmed plan holds the global lock; it is released after this long.
PLAN_TTL = timedelta(minutes=30)
# A unit that is gone right after the launch may simply not have written yet.
LAUNCH_GRACE = timedelta(seconds=20)
POLL_ACTIVE_SECONDS = 3
POLL_IDLE_SECONDS = 30
SCHEDULE_META_KEY = "wizard_selfcheck_daily"
SCHEDULE_EVERY = timedelta(hours=24)
# A report that cannot be delivered (the chat is gone) is retried on every pass for
# this long, then dropped — the run stays in the history either way.
REPORT_GIVE_UP = timedelta(hours=24)
MAX_LOG_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_ALIVE = frozenset({"active", "activating", "deactivating", "reloading", "refreshing"})


class WizardError(InvalidOperation):
    """A refused wizard operation; ``key`` is the i18n message."""


# Logging here never carries a traceback (no exc_info): this monitor runs inside the
# very window in which deploy.sh scans bot.log for "Traceback"/ERROR after the
# restart it caused, and a failed Telegram edit must not roll back a good deploy.

# --------------------------------------------------------------------------- #
# The status file
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class Item:
    level: str  # green | yellow | red
    key: str
    text: str


@dataclass(slots=True)
class StatusSnapshot:
    """What the status file says about the CURRENT phase (events after its launch)."""

    phase: str | None = None
    step: str = ""
    step_states: dict[str, str] = field(default_factory=dict)
    progress: list[str] = field(default_factory=list)
    plan_text: str | None = None
    plan_noop: bool = False
    items: list[Item] = field(default_factory=list)
    counts: dict[str, int] | None = None
    artifact: str | None = None
    result_text: str | None = None
    result_verdict: str | None = None
    outcome: str | None = None
    finish_summary: str = ""
    failed_step_text: str = ""
    events: int = 0

    @property
    def finished(self) -> bool:
        return self.outcome is not None

    @property
    def deviations(self) -> list[Item]:
        return [item for item in self.items if item.level in ("yellow", "red")]


def parse_status(text: str) -> StatusSnapshot:
    """Fold the JSON lines of a status file. Junk lines are skipped, never fatal."""
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("event"), str):
            records.append(obj)
    start = 0
    for i, rec in enumerate(records):
        if rec["event"] == "launched":
            start = i
    snap = StatusSnapshot(events=len(records))
    for rec in records[start:]:
        kind = rec["event"]
        if kind == "launched":
            snap.phase = str(rec.get("phase") or "") or None
        elif kind == "step":
            step = str(rec.get("step") or "")
            state = str(rec.get("state") or "")
            snap.step = step
            snap.step_states[step] = state
            if state == "fail":
                snap.failed_step_text = str(rec.get("text") or "")
        elif kind == "progress":
            snap.progress.append(str(rec.get("text") or ""))
        elif kind == "plan":
            snap.plan_text = str(rec.get("text") or "")
            snap.plan_noop = bool(rec.get("noop"))
        elif kind == "item":
            level = str(rec.get("level") or "")
            if level in ("green", "yellow", "red"):
                snap.items.append(Item(level, str(rec.get("key") or ""), str(rec.get("text") or "")))
        elif kind == "summary":
            snap.counts = {k: int(rec.get(k) or 0) for k in ("green", "yellow", "red")}
        elif kind == "artifact":
            snap.artifact = str(rec.get("name") or "") or None
        elif kind == "result":
            snap.result_text = str(rec.get("text") or "")
            snap.result_verdict = str(rec.get("verdict") or "") or None
        elif kind == "finished":
            outcome = str(rec.get("outcome") or "")
            if outcome in ("planned", "succeeded", "rolled_back", "failed"):
                snap.outcome = outcome
                snap.finish_summary = str(rec.get("summary") or "")
    return snap


# --------------------------------------------------------------------------- #
# Who renders: the bot layer implements this (bot/wizard_notifier.py)
# --------------------------------------------------------------------------- #
class WizardNotifier(Protocol):
    async def progress(self, run: WizardRun, snap: StatusSnapshot) -> None: ...

    async def plan_ready(self, run: WizardRun, snap: StatusSnapshot) -> bool: ...

    async def finished(self, run: WizardRun, snap: StatusSnapshot) -> bool: ...

    async def scheduled_alert(self, run: WizardRun, snap: StatusSnapshot) -> bool: ...


class MetaStore(Protocol):
    async def get_meta(self, key: str) -> str | None: ...

    async def set_meta(self, key: str, value: str) -> None: ...


def _parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class WizardService:
    def __init__(
        self,
        *,
        repo: WizardRunRepository,
        audit: AuditService,
        clock: ClockProvider,
        shell: ShellRunner,
        runner: PrivilegedHelperRunner | None,
        store: MetaStore,
        helper: Path = HELPER_PATH,
        state_dir: Path = STATE_DIR,
        log_dir: Path = LOG_DIR,
        notifier: WizardNotifier | None = None,
    ) -> None:
        self.repo = repo
        self.audit = audit
        self.clock = clock
        self.shell = shell
        self.runner = runner
        self.store = store
        self.helper = helper
        self.state_dir = state_dir
        self.log_dir = log_dir
        self.notifier = notifier
        self._seen: dict[int, tuple[int, str]] = {}
        # Plans whose confirmation screen reached the chat in THIS process. Empty after
        # a restart on purpose: the screen is shown again (an edit to the same text is a
        # no-op), so neither a failed delivery nor a restart leaves a stale screen.
        self._plan_shown: set[int] = set()
        self._poll_lock = asyncio.Lock()

    # ------------------------------------------------------------- helpers
    def installed(self) -> bool:
        return self.helper.is_file()

    def status_path(self, run_id: int) -> Path:
        return self.state_dir / f"{run_id}.status"

    def artifact_path(self, run_id: int, name: str) -> Path:
        return self.state_dir / f"{run_id}.{name}"

    async def snapshot(self, run_id: int) -> StatusSnapshot:
        try:
            text = await asyncio.to_thread(self.status_path(run_id).read_text, encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return StatusSnapshot()
        except OSError as exc:
            logger.warning("wizard run %d: status file unreadable: %s", run_id, exc)
            return StatusSnapshot()
        return parse_status(text)

    async def unit_alive(self, run_id: int) -> bool | None:
        """Whether vpn-bot-wizard-<id>.service still runs; None when systemctl did not answer."""
        result = await self.shell.run(
            ["systemctl", "show", "--property=ActiveState", "--value", f"{UNIT_PREFIX}{run_id}.service"],
            timeout=15,
        )
        if result.returncode != 0:
            return None
        return result.stdout.strip() in _ALIVE

    async def _launch(self, run: WizardRun, phase: str) -> tuple[bool, str]:
        if self.runner is None:
            return False, "no runner for vpn-bot-wizard"
        args = ["launch", "--mode", run.mode, "--run", str(run.id), "--phase", phase]
        for name in sorted(run.params):
            args += ["--param", f"{name}={run.params[name]}"]
        try:
            result = await self.runner.run(self.helper, args, timeout=LAUNCH_TIMEOUT_SECONDS, max_output_chars=2000)
        except Exception as exc:
            logger.warning("wizard run %d: launch could not run (%s: %s)", run.id, type(exc).__name__, exc)
            return False, f"vpn-bot-wizard could not run: {type(exc).__name__}"
        text = ((result.stdout or "") + (result.stderr or "")).strip()
        if result.returncode != 0:
            logger.warning("wizard run %d: launch refused (rc %s): %s", run.id, result.returncode, text)
            return False, text.splitlines()[-1] if text else f"exit {result.returncode}"
        return True, text

    # ------------------------------------------------------------- lifecycle
    async def start(
        self,
        actor_user_id: int | None,
        mode_key: str,
        raw_params: dict[str, object] | None = None,
        *,
        chat_id: int | None = None,
        message_id: int | None = None,
        origin: str = "manual",
    ) -> WizardRun:
        """Validate, take the global lock (a row), launch the first phase.

        Authorisation (SUPERADMIN, TOTP for a dangerous mode) is the caller's job.
        """
        mode = get_mode(mode_key)
        params = mode.validate(raw_params or {})
        if not self.installed():
            raise WizardError("helper не установлен", key="wizard_not_installed")
        now = self.clock.now()
        try:
            run = await self.repo.create(
                mode=mode.key,
                params={k: redact_value(v) for k, v in params.items()},
                started_by=actor_user_id,
                origin=origin,
                chat_id=chat_id,
                message_id=message_id,
                log_path_template=str(self.log_dir / "{id}.log"),
                now=now,
            )
        except WizardBusy:
            active = await self.repo.active()
            raise WizardError(
                "уже идёт запуск",
                key="wizard_busy",
                params={"id": active.id if active else "?", "mode": active.mode if active else "?"},
            ) from None
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action="wizard_run_started",
            entity_type=AuditEntityType.WIZARD,
            entity_id=run.id,
            details={"mode": mode.key, "params": params, "origin": origin},
        )
        phase = "plan" if mode.needs_confirmation else "execute"
        if phase == "execute":
            await self.repo.update(run.id, now, phase="execute", state="running", current_step="apply")
        ok, detail = await self._launch(run, phase)
        if not ok:
            await self._finish(run.id, "failed", f"launch: {detail}", actor_user_id)
            raise WizardError("запуск не удался", key="wizard_launch_failed", params={"detail": detail[:200]})
        fresh = await self.repo.get(run.id)
        assert fresh is not None
        return fresh

    def exclusive(self) -> asyncio.Lock:
        """Held by a monitor pass; a handler that starts/confirms a run and renders its
        message holds it too, so a fast run cannot be reported in between and then
        overwritten with a stale progress screen."""
        return self._poll_lock

    async def attach_message(self, run_id: int, chat_id: int, message_id: int) -> None:
        await self.repo.set_message(run_id, chat_id, message_id, self.clock.now())

    async def confirm(self, actor_user_id: int, run_id: int) -> WizardRun:
        run = await self.repo.get(run_id)
        if run is None:
            raise NotFound("нет запуска", key="wizard_run_not_found")
        if not run.active or run.state != "planned" or not run.plan_ready:
            raise WizardError("план не ждёт подтверждения", key="wizard_not_awaiting")
        now = self.clock.now()
        await self.repo.update(run.id, now, state="running", phase="execute", plan_ready=False, current_step="apply")
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action="wizard_run_confirmed",
            entity_type=AuditEntityType.WIZARD,
            entity_id=run.id,
            details={"mode": run.mode},
        )
        ok, detail = await self._launch(run, "execute")
        if not ok:
            await self._finish(run.id, "failed", f"launch: {detail}", actor_user_id)
            raise WizardError("запуск не удался", key="wizard_launch_failed", params={"detail": detail[:200]})
        fresh = await self.repo.get(run.id)
        assert fresh is not None
        return fresh

    async def cancel(self, actor_user_id: int, run_id: int) -> WizardRun:
        run = await self.repo.get(run_id)
        if run is None:
            raise NotFound("нет запуска", key="wizard_run_not_found")
        if not run.active or run.state != "planned" or not run.plan_ready:
            raise WizardError("отменить можно только готовый план", key="wizard_not_awaiting")
        await self._finish(run.id, "cancelled", "cancelled by a superadmin", actor_user_id)
        await self.repo.mark_reported(run.id, self.clock.now())
        fresh = await self.repo.get(run.id)
        assert fresh is not None
        return fresh

    async def _finish(self, run_id: int, state: str, summary: str, actor: int | None = None) -> bool:
        done = await self.repo.finish(run_id, state, redact_text(summary)[:2000], self.clock.now())
        if done:
            run = await self.repo.get(run_id)
            await self.audit.write_best_effort(
                actor_user_id=actor,
                action="wizard_run_finished",
                entity_type=AuditEntityType.WIZARD,
                entity_id=run_id,
                details={"mode": run.mode if run else "?", "state": state, "summary": summary[:200]},
            )
        self._seen.pop(run_id, None)
        self._plan_shown.discard(run_id)
        return done

    # ---------------------------------------------------------------- monitor
    async def resume_on_startup(self) -> None:
        """Log what a restart found; the monitor loop does the rest."""
        run = await self.repo.active()
        if run is not None:
            logger.info(
                "Setup wizard: resuming run #%d (%s, state %s, phase %s) after a restart",
                run.id,
                run.mode,
                run.state,
                run.phase,
            )
        pending = await self.repo.unreported()
        if pending:
            logger.info("Setup wizard: %d finished run(s) still owe their report", len(pending))

    async def poll_once(self) -> bool:
        """One pass over the active run and the undelivered reports. True while a run is active."""
        async with self._poll_lock:
            run = await self.repo.active()
            if run is not None:
                await self._drive(run)
            for done in await self.repo.unreported():
                await self._report(done)
            return (await self.repo.active()) is not None

    async def _drive(self, run: WizardRun) -> None:
        now = datetime.now(timezone.utc)
        if run.state == "planned" and run.plan_ready:
            updated = _parse_iso(run.updated_at)
            if updated is not None and now - updated > PLAN_TTL:
                await self._finish(run.id, "cancelled", "the plan was not confirmed within 30 minutes")
                return
            if run.id not in self._plan_shown:
                await self._show_plan(run, await self.snapshot(run.id))
            return
        alive = await self.unit_alive(run.id)
        snap = await self.snapshot(run.id)
        if snap.finished and snap.phase in (None, run.phase):
            await self._on_finished(run, snap)
            return
        if alive is None:
            return
        if not alive:
            created = _parse_iso(run.updated_at)
            if created is not None and now - created < LAUNCH_GRACE:
                return
            snap = await self.snapshot(run.id)  # it may have finished between the two reads
            if snap.finished and snap.phase in (None, run.phase):
                await self._on_finished(run, snap)
                return
            await self._finish(run.id, "failed", f"the unit {UNIT_PREFIX}{run.id} ended without a final status (killed?)")
            return
        new_state = {"verify": "verifying"}.get(snap.step, "running") if run.phase == "execute" else "planned"
        if snap.step and (snap.step != run.current_step or new_state != run.state):
            await self.repo.update(run.id, self.clock.now(), state=new_state, current_step=snap.step)
            run = await self.repo.get(run.id) or run
        marker = (snap.events, run.state)
        if self._seen.get(run.id) != marker:
            self._seen[run.id] = marker
            if self.notifier is not None:
                try:
                    await self.notifier.progress(run, snap)
                except Exception as exc:
                    logger.warning("wizard run %d: progress message failed (%s: %s)", run.id, type(exc).__name__, exc)

    async def _on_finished(self, run: WizardRun, snap: StatusSnapshot) -> None:
        if run.phase == "plan":
            if snap.outcome == "planned" and not snap.plan_noop:
                await self.repo.update(
                    run.id, self.clock.now(), plan_ready=True, current_step="plan", summary=(snap.plan_text or "")[:3000]
                )
                await self.audit.write_best_effort(
                    actor_user_id=None,
                    action="wizard_plan_ready",
                    entity_type=AuditEntityType.WIZARD,
                    entity_id=run.id,
                    details={"mode": run.mode},
                )
                await self._show_plan(await self.repo.get(run.id) or run, snap)
                return
            if snap.outcome == "planned":
                await self._finish(run.id, "succeeded", snap.plan_text or "nothing to do")
                return
            await self._finish(run.id, "failed", snap.plan_text or snap.finish_summary or snap.failed_step_text or "plan failed")
            return
        summary = snap.result_text or snap.finish_summary or snap.failed_step_text or ""
        if snap.counts is not None:
            summary = f"green={snap.counts['green']} yellow={snap.counts['yellow']} red={snap.counts['red']}"
        await self._finish(run.id, snap.outcome or "failed", summary)

    async def _show_plan(self, run: WizardRun, snap: StatusSnapshot) -> None:
        """The confirmation screen; retried on every pass until it reached the chat."""
        if self.notifier is None:
            return
        try:
            shown = await self.notifier.plan_ready(run, snap)
        except Exception as exc:
            logger.warning("wizard run %d: plan message failed (%s: %s)", run.id, type(exc).__name__, exc)
            shown = False
        if shown:
            self._plan_shown.add(run.id)

    async def _report(self, run: WizardRun) -> None:
        snap = await self.snapshot(run.id)
        delivered = True
        if self.notifier is not None:
            try:
                if run.origin == "scheduled":
                    # The daily self-check speaks only when something deviates.
                    if snap.deviations or run.state != "succeeded":
                        delivered = await self.notifier.scheduled_alert(run, snap)
                else:
                    delivered = await self.notifier.finished(run, snap)
            except Exception as exc:
                logger.warning("wizard run %d: final report failed (%s: %s)", run.id, type(exc).__name__, exc)
                delivered = False
        if not delivered:
            finished = _parse_iso(run.finished_at or "")
            if finished is None or datetime.now(timezone.utc) - finished < REPORT_GIVE_UP:
                return  # the next pass tries again
            logger.warning("wizard run %d: report undeliverable for %s — giving up", run.id, REPORT_GIVE_UP)
        await self.repo.mark_reported(run.id, self.clock.now())

    # ---------------------------------------------------------------- reading
    async def get(self, run_id: int) -> WizardRun:
        run = await self.repo.get(run_id)
        if run is None:
            raise NotFound("нет запуска", key="wizard_run_not_found")
        return run

    async def history(self, limit: int = 8, offset: int = 0) -> tuple[list[WizardRun], int]:
        return await self.repo.list_recent(limit, offset), await self.repo.count()

    async def active(self) -> WizardRun | None:
        return await self.repo.active()

    async def log_document(self, actor_user_id: int, run_id: int) -> tuple[str, bytes]:
        run = await self.get(run_id)
        path = self.log_dir / f"{run.id}.log"
        try:
            data = await asyncio.to_thread(_read_tail, path, MAX_LOG_BYTES)
        except FileNotFoundError:
            raise WizardError("нет лога", key="wizard_log_missing") from None
        except OSError as exc:
            logger.warning("wizard run %d: log unreadable: %s", run.id, exc)
            raise WizardError("лог недоступен", key="wizard_log_missing") from exc
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action="wizard_log_sent",
            entity_type=AuditEntityType.WIZARD,
            entity_id=run.id,
            details={"bytes": len(data)},
        )
        return f"wizard-{run.id}-{run.mode}.log", redact_text(data).encode("utf-8")

    async def artifact_document(self, run: WizardRun, name: str) -> tuple[str, bytes] | None:
        path = self.artifact_path(run.id, name)
        try:
            data = await asyncio.to_thread(_read_tail, path, MAX_ARTIFACT_BYTES)
        except OSError:
            return None
        return f"wizard-{run.id}-{name}", redact_text(data).encode("utf-8")

    # ---------------------------------------------------------------- schedule
    async def daily_selfcheck_enabled(self) -> bool:
        return (await self.store.get_meta(SCHEDULE_META_KEY)) == "1"

    async def set_daily_selfcheck(self, actor_user_id: int, enabled: bool) -> None:
        await self.store.set_meta(SCHEDULE_META_KEY, "1" if enabled else "0")
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action="wizard_schedule_changed",
            entity_type=AuditEntityType.WIZARD,
            entity_id="selfcheck",
            details={"daily": enabled},
        )

    async def maybe_run_scheduled(self) -> WizardRun | None:
        """The daily self-check, when it is switched on, due and nothing else runs."""
        if not await self.daily_selfcheck_enabled() or not self.installed():
            return None
        if await self.repo.active() is not None:
            return None
        last = await self.repo.last_scheduled("selfcheck")
        if last is not None:
            created = _parse_iso(last.created_at)
            if created is not None and datetime.now(timezone.utc) - created < SCHEDULE_EVERY:
                return None
        try:
            return await self.start(None, "selfcheck", origin="scheduled")
        except WizardError as exc:
            logger.warning("Scheduled self-check not started: %s", exc)
            return None

    def mode(self, key: str) -> WizardMode:
        return get_mode(key)


def _read_tail(path: Path, limit: int) -> str:
    with path.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - limit))
        return fh.read().decode("utf-8", errors="replace")


async def wizard_loop(service: WizardService, *, active_interval: int = POLL_ACTIVE_SECONDS, idle_interval: int = POLL_IDLE_SECONDS) -> None:
    """Drive the active run often, look for the daily self-check rarely."""
    await service.resume_on_startup()
    while True:
        busy = False
        try:
            busy = await service.poll_once()
            if not busy:
                started = await service.maybe_run_scheduled()
                busy = started is not None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Setup wizard pass failed (%s: %s)", type(exc).__name__, exc)
        await asyncio.sleep(active_interval if busy else idle_interval)

