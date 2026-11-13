"""The setup wizard's bot side (services/wizard.py, repositories/wizard_runs.py).

* The global lock is a database invariant: a second run cannot start while one is
  active, whoever asks; a finished run releases it.
* Parameters are typed before anything is launched; the launch goes to the root
  helper only as `vpn-bot-wizard launch --mode M --run N --phase P --param k=v`.
* The monitor reads the status file and the unit: plan → plan_ready → confirm →
  execute → a terminal state; a unit that died without a final line is `failed`;
  an unconfirmed plan expires after 30 minutes.
* Resume after a restart: a NEW service object (what the restarted bot builds) finds
  the active run, follows it to the end and delivers the report exactly once.
* The daily self-check starts when due and alerts only on a deviation.
* Logs are redacted before they leave as a file.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from adapters.clock import ClockProvider
from db.database import Database
from models.dto import ShellResult, WizardRun
from repositories.audit_log import AuditLogRepository
from repositories.users import UserRepository
from repositories.wizard_runs import WizardBusy, WizardRunRepository
from services.audit import AuditService
from services.wizard import StatusSnapshot, WizardError, WizardService, parse_status
from services.wizard_modes import WizardParamError

ADMIN = 1001
pytestmark = pytest.mark.timeout(60)


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.rc = 0

    async def run(self, helper: Path, args: list[str], **_: Any) -> ShellResult:
        self.calls.append([str(helper), *args])
        return ShellResult(tuple(args), self.rc, "launched" if self.rc == 0 else "", "" if self.rc == 0 else "busy")


class FakeShell:
    def __init__(self) -> None:
        self.alive: dict[str, str] = {}

    async def run(self, args: list[str], **_: Any) -> ShellResult:
        unit = args[-1]
        return ShellResult(tuple(args), 0, self.alive.get(unit, "inactive") + "\n", "")


class Notifier:
    def __init__(self) -> None:
        self.events: list[tuple[str, int, str]] = []
        self.deliver_plan = True

    async def progress(self, run: WizardRun, snap: StatusSnapshot) -> None:
        self.events.append(("progress", run.id, run.state))

    async def plan_ready(self, run: WizardRun, snap: StatusSnapshot) -> bool:
        self.events.append(("plan_ready", run.id, snap.plan_text or ""))
        return self.deliver_plan

    async def finished(self, run: WizardRun, snap: StatusSnapshot) -> bool:
        self.events.append(("finished", run.id, run.state))
        return True

    async def scheduled_alert(self, run: WizardRun, snap: StatusSnapshot) -> bool:
        self.events.append(("alert", run.id, ",".join(i.key for i in snap.deviations)))
        return True

    def kinds(self) -> list[str]:
        return [e[0] for e in self.events]


class World:
    def __init__(self, db: Database, tmp: Path) -> None:
        self.db = db
        self.tmp = tmp
        self.state_dir = tmp / "state"
        self.log_dir = tmp / "log"
        self.state_dir.mkdir()
        self.log_dir.mkdir()
        self.helper = tmp / "vpn-bot-wizard"
        self.helper.write_text("#!/bin/sh\n", encoding="utf-8")
        self.runner = FakeRunner()
        self.shell = FakeShell()
        self.notifier = Notifier()

    def service(self) -> WizardService:
        """A fresh service object — what a restarted bot builds."""
        return WizardService(
            repo=WizardRunRepository(self.db),
            audit=AuditService(AuditLogRepository(self.db), ClockProvider(), UserRepository(self.db)),
            clock=ClockProvider(),
            shell=self.shell,  # type: ignore[arg-type]
            runner=self.runner,  # type: ignore[arg-type]
            store=self.db,
            helper=self.helper,
            state_dir=self.state_dir,
            log_dir=self.log_dir,
            notifier=self.notifier,
        )

    def emit(self, run_id: int, event: str, **fields: Any) -> None:
        with (self.state_dir / f"{run_id}.status").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": "x", "run": run_id, "event": event, **fields}) + "\n")

    def alive(self, run_id: int, state: str = "active") -> None:
        self.shell.alive[f"vpn-bot-wizard-{run_id}.service"] = state

    async def age(self, run_id: int, minutes: int) -> None:
        past = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).replace(microsecond=0).isoformat()
        await self.db.conn.execute("UPDATE wizard_runs SET updated_at = ?, created_at = ? WHERE id = ?", (past, past, run_id))
        await self.db.commit()

    async def actions(self) -> list[str]:
        rows = await self.db.conn.execute_fetchall("SELECT action FROM audit_log WHERE entity_type = 'wizard' ORDER BY id")
        return [str(r["action"]) for r in rows]


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, role, created_at, updated_at) VALUES (?, 'SUPERADMIN', 'x', 'x')", (ADMIN,)
    )
    await db.commit()
    try:
        yield World(db, tmp_path)
    finally:
        await db.close()


# --------------------------------------------------------------------------- #
def test_parse_status_follows_the_current_phase_only() -> None:
    lines = [
        {"event": "launched", "phase": "plan"},
        {"event": "plan", "text": "two commits"},
        {"event": "finished", "phase": "plan", "outcome": "planned"},
        {"event": "launched", "phase": "execute"},
        {"event": "step", "step": "apply", "state": "start"},
        {"event": "progress", "text": "deploying"},
        "not json",
        {"event": "item", "level": "red", "key": "disk", "text": "full"},
        {"event": "item", "level": "purple", "key": "x", "text": "ignored"},
    ]
    text = "\n".join(line if isinstance(line, str) else json.dumps(line) for line in lines)
    snap = parse_status(text)
    assert snap.phase == "execute" and snap.step == "apply" and not snap.finished
    assert snap.progress == ["deploying"]
    assert [i.key for i in snap.deviations] == ["disk"]
    assert snap.plan_text is None  # the plan belongs to the previous phase


async def test_one_active_run_is_a_database_invariant(world: World) -> None:
    repo = WizardRunRepository(world.db)
    first = await repo.create(mode="selfcheck", params={}, started_by=ADMIN, origin="manual", chat_id=1, log_path_template="/l/{id}.log", now="t")
    assert first.log_path == f"/l/{first.id}.log"
    with pytest.raises(WizardBusy):
        await repo.create(mode="dump", params={}, started_by=ADMIN, origin="manual", chat_id=1, log_path_template="/l/{id}.log", now="t")
    assert await repo.finish(first.id, "succeeded", "ok", "t")
    assert not await repo.finish(first.id, "failed", "again", "t")  # a finished run never changes
    second = await repo.create(mode="dump", params={}, started_by=ADMIN, origin="manual", chat_id=1, log_path_template="/l/{id}.log", now="t")
    assert second.active and (await repo.get(first.id)).state == "succeeded"  # type: ignore[union-attr]


async def test_start_validates_launches_and_refuses_a_second_run(world: World) -> None:
    svc = world.service()
    with pytest.raises(WizardParamError):
        await svc.start(ADMIN, "dump", {"lines": 5})
    with pytest.raises(WizardParamError):
        await svc.start(ADMIN, "dump", {"lines": "200; rm -rf /"})
    with pytest.raises(WizardParamError):
        await svc.start(ADMIN, "update", {"command": "id"})
    with pytest.raises(WizardParamError):
        await svc.start(ADMIN, "shell")
    assert world.runner.calls == []
    run = await svc.start(ADMIN, "dump", {"lines": 50}, chat_id=5)
    assert run.state == "running" and run.phase == "execute"  # read-only: no plan to confirm
    assert world.runner.calls == [
        [str(world.helper), "launch", "--mode", "dump", "--run", str(run.id), "--phase", "execute", "--param", "lines=50"]
    ]
    with pytest.raises(WizardError) as busy:
        await svc.start(ADMIN, "selfcheck")
    assert busy.value.key == "wizard_busy"
    assert "wizard_run_started" in await world.actions()


async def test_a_refused_launch_fails_the_run_and_releases_the_lock(world: World) -> None:
    svc = world.service()
    world.runner.rc = 3
    with pytest.raises(WizardError) as exc:
        await svc.start(ADMIN, "selfcheck")
    assert exc.value.key == "wizard_launch_failed"
    assert await svc.active() is None
    world.runner.rc = 0
    assert (await svc.start(ADMIN, "selfcheck")).active


async def test_no_helper_no_run(world: World) -> None:
    world.helper.unlink()
    with pytest.raises(WizardError) as exc:
        await world.service().start(ADMIN, "selfcheck")
    assert exc.value.key == "wizard_not_installed"


async def test_update_plan_confirm_execute_and_a_restart_in_the_middle(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "update", chat_id=5)
    assert run.state == "planned" and run.phase == "plan"
    assert world.runner.calls[-1][world.runner.calls[-1].index("--phase") + 1] == "plan"
    world.alive(run.id)
    world.emit(run.id, "launched", phase="plan")
    world.emit(run.id, "step", step="plan", state="start")
    assert await svc.poll_once() is True
    assert world.notifier.kinds() == ["progress"]
    world.emit(run.id, "plan", text="HEAD a → origin/main b: 2 commit(s)")
    world.emit(run.id, "finished", phase="plan", outcome="planned")
    world.alive(run.id, "inactive")
    await svc.poll_once()
    planned = await svc.get(run.id)
    assert planned.plan_ready and planned.state == "planned" and "2 commit(s)" in planned.summary
    assert world.notifier.events[-1][0] == "plan_ready"
    await svc.poll_once()  # nothing new: no second plan message
    assert world.notifier.kinds().count("plan_ready") == 1

    confirmed = await svc.confirm(ADMIN, run.id)
    assert confirmed.state == "running" and confirmed.phase == "execute"
    assert world.runner.calls[-1][-3:] == ["execute", "--param", "force=0"]
    world.alive(run.id)
    world.emit(run.id, "launched", phase="execute")
    world.emit(run.id, "step", step="apply", state="start")
    await svc.poll_once()

    # deploy.sh restarts the bot: a NEW service object, the run goes on meanwhile
    world.emit(run.id, "step", step="apply", state="ok")
    world.emit(run.id, "step", step="verify", state="start")
    restarted = world.service()
    await restarted.resume_on_startup()
    await restarted.poll_once()
    assert (await restarted.get(run.id)).state == "verifying"
    world.emit(run.id, "step", step="verify", state="ok")
    world.emit(run.id, "result", text="===== DEPLOY OK =====", verdict="deploy_ok")
    world.emit(run.id, "finished", phase="execute", outcome="succeeded")
    world.alive(run.id, "inactive")
    assert await restarted.poll_once() is False
    done = await restarted.get(run.id)
    assert done.state == "succeeded" and not done.active and done.reported_at is not None
    assert "DEPLOY OK" in done.summary
    assert world.notifier.kinds().count("finished") == 1
    await restarted.poll_once()
    await world.service().poll_once()
    assert world.notifier.kinds().count("finished") == 1  # delivered exactly once
    actions = await world.actions()
    for action in ("wizard_run_started", "wizard_plan_ready", "wizard_run_confirmed", "wizard_run_finished"):
        assert action in actions


async def test_the_report_owed_before_a_crash_is_sent_after_it(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "selfcheck", chat_id=5)
    world.emit(run.id, "launched", phase="execute")
    world.emit(run.id, "finished", phase="execute", outcome="rolled_back")
    await svc.repo.finish(run.id, "rolled_back", "x", "t")  # finished, the bot died before reporting
    assert (await svc.get(run.id)).reported_at is None
    await world.service().poll_once()
    assert world.notifier.kinds() == ["finished"]
    assert (await svc.get(run.id)).reported_at is not None


async def test_a_unit_that_died_without_a_final_line_is_failed(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "selfcheck", chat_id=5)
    world.emit(run.id, "launched", phase="execute")
    world.emit(run.id, "step", step="apply", state="start")
    world.alive(run.id, "inactive")
    await svc.poll_once()
    assert (await svc.get(run.id)).active  # inside the launch grace
    await world.age(run.id, 5)
    await svc.poll_once()
    dead = await svc.get(run.id)
    assert dead.state == "failed" and "without a final status" in dead.summary
    assert world.notifier.kinds()[-1] == "finished"


async def test_systemctl_silence_is_not_a_verdict(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "selfcheck", chat_id=5)
    await world.age(run.id, 5)

    async def broken(args: list[str], **_: Any) -> ShellResult:
        return ShellResult(tuple(args), 1, "", "Failed to connect to bus")

    world.shell.run = broken  # type: ignore[method-assign]
    await svc.poll_once()
    assert (await svc.get(run.id)).active


async def test_an_unconfirmed_plan_expires(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "update", chat_id=5)
    world.emit(run.id, "launched", phase="plan")
    world.emit(run.id, "plan", text="p")
    world.emit(run.id, "finished", phase="plan", outcome="planned")
    await svc.poll_once()
    await world.age(run.id, 31)
    await svc.poll_once()
    expired = await svc.get(run.id)
    assert expired.state == "cancelled" and not expired.active
    with pytest.raises(WizardError):
        await svc.confirm(ADMIN, run.id)


async def test_a_noop_plan_finishes_without_a_confirmation(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "update", chat_id=5)
    world.emit(run.id, "launched", phase="plan")
    world.emit(run.id, "plan", text="already at origin/main", noop=True)
    world.emit(run.id, "finished", phase="plan", outcome="planned")
    await svc.poll_once()
    done = await svc.get(run.id)
    assert done.state == "succeeded" and not done.active


async def test_cancel_only_a_ready_plan(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "update", chat_id=5)
    with pytest.raises(WizardError):
        await svc.cancel(ADMIN, run.id)  # the plan is still being computed
    world.emit(run.id, "launched", phase="plan")
    world.emit(run.id, "finished", phase="plan", outcome="planned")
    world.emit(run.id, "plan", text="p")
    await svc.poll_once()
    cancelled = await svc.cancel(ADMIN, run.id)
    assert cancelled.state == "cancelled" and cancelled.reported_at is not None
    assert "wizard_run_finished" in await world.actions()


async def test_daily_selfcheck_starts_when_due_and_alerts_only_on_deviation(world: World) -> None:
    svc = world.service()
    assert await svc.maybe_run_scheduled() is None  # off by default
    await svc.set_daily_selfcheck(ADMIN, True)
    run = await svc.maybe_run_scheduled()
    assert run is not None and run.origin == "scheduled" and run.started_by is None
    assert await svc.maybe_run_scheduled() is None  # one at a time
    world.emit(run.id, "launched", phase="execute")
    world.emit(run.id, "item", level="green", key="disk", text="ok")
    world.emit(run.id, "summary", green=1, yellow=0, red=0)
    world.emit(run.id, "finished", phase="execute", outcome="succeeded")
    await svc.poll_once()
    assert world.notifier.events == []  # all green: silence
    assert await svc.maybe_run_scheduled() is None  # not due for 24 h
    await world.age(run.id, 25 * 60)
    second = await svc.maybe_run_scheduled()
    assert second is not None
    world.emit(second.id, "launched", phase="execute")
    world.emit(second.id, "item", level="red", key="failed_units", text="xray.service")
    world.emit(second.id, "finished", phase="execute", outcome="succeeded")
    await svc.poll_once()
    assert world.notifier.events == [("alert", second.id, "failed_units")]
    await svc.set_daily_selfcheck(ADMIN, False)
    assert not await svc.daily_selfcheck_enabled()
    assert "wizard_schedule_changed" in await world.actions()


async def test_log_document_is_redacted_and_audited(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "selfcheck", chat_id=5)
    (world.log_dir / f"{run.id}.log").write_text(
        "deploy with bot_token=123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA done\n", encoding="utf-8"
    )
    name, data = await svc.log_document(ADMIN, run.id)
    assert name == f"wizard-{run.id}-selfcheck.log"
    assert b"AAAAAAAA" not in data and b"bot_token=***" in data
    assert "wizard_log_sent" in await world.actions()
    (world.log_dir / f"{run.id}.log").unlink()
    with pytest.raises(WizardError) as missing:
        await svc.log_document(ADMIN, run.id)
    assert missing.value.key == "wizard_log_missing"


async def test_artifact_is_redacted_again_on_the_way_out(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "dump", chat_id=5)
    (world.state_dir / f"{run.id}.dump.txt").write_text("password=hunter2\n", encoding="utf-8")
    doc = await svc.artifact_document(run, "dump.txt")
    assert doc is not None and b"hunter2" not in doc[1]
    assert await svc.artifact_document(run, "missing.txt") is None


def test_the_monitor_never_logs_a_traceback() -> None:
    """deploy.sh rolls back on "Traceback" in bot.log after the restart it caused —
    and this monitor runs in exactly that window (the `update` mode)."""
    root = Path(__file__).resolve().parents[1]
    for rel in ("services/wizard.py", "bot/wizard_notifier.py"):
        text = (root / rel).read_text(encoding="utf-8")
        assert "exc_info" not in text.replace("no exc_info", ""), rel
        assert "logger.exception" not in text and "logger.error" not in text, rel


async def test_an_undeliverable_report_is_retried_then_dropped(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "selfcheck", chat_id=5)
    world.emit(run.id, "launched", phase="execute")
    world.emit(run.id, "finished", phase="execute", outcome="succeeded")

    async def refuse(run: WizardRun, snap: StatusSnapshot) -> bool:
        world.notifier.events.append(("refused", run.id, run.state))
        return False

    world.notifier.finished = refuse  # type: ignore[method-assign]
    await svc.poll_once()
    await svc.poll_once()
    assert world.notifier.kinds() == ["refused", "refused"]
    assert (await svc.get(run.id)).reported_at is None
    past = (datetime.now(timezone.utc) - timedelta(hours=25)).replace(microsecond=0).isoformat()
    await world.db.conn.execute("UPDATE wizard_runs SET finished_at = ? WHERE id = ?", (past, run.id))
    await world.db.commit()
    await svc.poll_once()
    assert (await svc.get(run.id)).reported_at is not None
    await svc.poll_once()
    assert world.notifier.kinds().count("refused") == 3


def test_param_specs_type_every_kind() -> None:
    from services.wizard_modes import ParamSpec

    flag = ParamSpec("bool", "0")
    assert flag.coerce("f", True) == "1" and flag.coerce("f", 0) == "0" and flag.coerce("f", "1") == "1"
    for bad in ("yes", 2, None):
        with pytest.raises(WizardParamError):
            flag.coerce("f", bad)
    choice = ParamSpec("enum", "a", choices=("a", "b"))
    assert choice.coerce("c", "b") == "b"
    with pytest.raises(WizardParamError):
        choice.coerce("c", "z")
    number = ParamSpec("int", "5", minimum=1, maximum=9)
    assert number.coerce("n", "07") == "7"
    for bad in (True, 3.5, "10", "x"):
        with pytest.raises(WizardParamError):
            number.coerce("n", bad)
    with pytest.raises(WizardParamError):
        ParamSpec("float", "0").coerce("x", "1")


async def test_the_confirmation_screen_is_retried_until_delivered_and_after_a_restart(world: World) -> None:
    svc = world.service()
    run = await svc.start(ADMIN, "update", chat_id=5)
    world.emit(run.id, "launched", phase="plan")
    world.emit(run.id, "plan", text="HEAD a → origin/main b: 1 commit(s)")
    world.emit(run.id, "finished", phase="plan", outcome="planned")
    world.notifier.deliver_plan = False  # Telegram refuses the edit and the new message
    await svc.poll_once()
    await svc.poll_once()
    assert world.notifier.kinds().count("plan_ready") == 2
    world.notifier.deliver_plan = True
    await svc.poll_once()
    await svc.poll_once()
    assert world.notifier.kinds().count("plan_ready") == 3  # delivered once, then quiet
    await world.service().poll_once()  # a restart shows it once more
    assert world.notifier.kinds().count("plan_ready") == 4
    assert (await svc.get(run.id)).plan_ready


async def _ready_plan(world: World, svc: WizardService) -> WizardRun:
    run = await svc.start(ADMIN, "update", chat_id=5)
    world.emit(run.id, "launched", phase="plan")
    world.emit(run.id, "plan", text="p")
    world.emit(run.id, "finished", phase="plan", outcome="planned")
    await svc.poll_once()
    return await svc.get(run.id)


async def test_a_cancel_that_wins_means_nothing_is_launched(world: World) -> None:
    svc = world.service()
    run = await _ready_plan(world, svc)
    stale = await svc.get(run.id)  # what a concurrent «Применить» read before the cancel
    await svc.cancel(ADMIN, run.id)
    launches = len(world.runner.calls)
    assert not await svc.repo.claim_plan(stale.id, "t")
    with pytest.raises(WizardError) as exc:
        await svc.confirm(ADMIN, run.id)
    assert exc.value.key == "wizard_not_awaiting"
    assert len(world.runner.calls) == launches  # no execute phase
    assert (await svc.get(run.id)).state == "cancelled"


async def test_a_confirmation_that_wins_cannot_be_cancelled(world: World) -> None:
    svc = world.service()
    run = await _ready_plan(world, svc)
    assert await svc.repo.claim_plan(run.id, "t")  # «Применить» claimed it
    assert not await svc.repo.claim_plan(run.id, "t")  # a second tap does not
    assert not await svc.repo.finish(run.id, "cancelled", "x", "t", only_ready_plan=True)
    with pytest.raises(WizardError):
        await svc.cancel(ADMIN, run.id)
    assert (await svc.get(run.id)).state == "running"
