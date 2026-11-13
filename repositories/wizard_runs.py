"""``wizard_runs``: the setup wizard's runs (services/wizard.py, docs/wizard.md).

The global lock is the table itself: ``active = 1`` on the one run that holds it and
a UNIQUE index on ``active`` (NULLs do not collide), so a second ``create`` while a
run is active fails inside SQLite — two concurrent taps cannot both win.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from db.database import Database
from models.dto import WizardRun
from repositories._helpers import _clamp_limit, _clamp_offset

ACTIVE_STATES = frozenset({"planned", "running", "verifying"})
TERMINAL_STATES = frozenset({"succeeded", "rolled_back", "failed", "cancelled"})
ALL_STATES = ACTIVE_STATES | TERMINAL_STATES


class WizardBusy(Exception):
    """Another run holds the global lock."""


def _params(raw: object) -> dict[str, str]:
    try:
        data = json.loads(str(raw or "{}"))
    except json.JSONDecodeError:
        return {}
    return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}


def _run(row: Any) -> WizardRun:
    return WizardRun(
        id=int(row["id"]),
        mode=str(row["mode"]),
        state=str(row["state"]),
        phase=str(row["phase"]),
        current_step=str(row["current_step"] or ""),
        params=_params(row["params_json"]),
        started_by=int(row["started_by"]) if row["started_by"] is not None else None,
        origin=str(row["origin"]),
        chat_id=int(row["chat_id"]) if row["chat_id"] is not None else None,
        message_id=int(row["message_id"]) if row["message_id"] is not None else None,
        log_path=str(row["log_path"] or ""),
        summary=str(row["summary"] or ""),
        plan_ready=bool(row["plan_ready"]),
        active=row["active"] is not None,
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        finished_at=row["finished_at"],
        reported_at=row["reported_at"],
    )


class WizardRunRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(
        self,
        *,
        mode: str,
        params: dict[str, str],
        started_by: int | None,
        origin: str,
        chat_id: int | None,
        log_path_template: str,
        now: str,
        message_id: int | None = None,
    ) -> WizardRun:
        """Insert an active ``planned`` run; raises :class:`WizardBusy` when one is active."""
        try:
            async with self.db.transaction():
                cursor = await self.db.conn.execute(
                    """
                    INSERT INTO wizard_runs (mode, state, phase, params_json, started_by, origin, chat_id,
                                             message_id, active, created_at, updated_at)
                    VALUES (?, 'planned', 'plan', ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (mode, json.dumps(params, sort_keys=True), started_by, origin, chat_id, message_id, now, now),
                )
                run_id = int(cursor.lastrowid or 0)
                await self.db.conn.execute(
                    "UPDATE wizard_runs SET log_path = ? WHERE id = ?",
                    (log_path_template.format(id=run_id), run_id),
                )
        except sqlite3.IntegrityError as exc:
            raise WizardBusy(str(exc)) from exc
        run = await self.get(run_id)
        assert run is not None
        return run

    async def get(self, run_id: int) -> WizardRun | None:
        row = await self.db.conn.execute_fetchone("SELECT * FROM wizard_runs WHERE id = ?", (run_id,))
        return _run(row) if row is not None else None

    async def active(self) -> WizardRun | None:
        row = await self.db.conn.execute_fetchone("SELECT * FROM wizard_runs WHERE active = 1")
        return _run(row) if row is not None else None

    async def unreported(self) -> list[WizardRun]:
        """Finished runs whose final report has not been delivered yet."""
        rows = await self.db.conn.execute_fetchall(
            "SELECT * FROM wizard_runs WHERE active IS NULL AND reported_at IS NULL ORDER BY id"
        )
        return [_run(row) for row in rows]

    async def list_recent(self, limit: int = 10, offset: int = 0) -> list[WizardRun]:
        rows = await self.db.conn.execute_fetchall(
            "SELECT * FROM wizard_runs ORDER BY id DESC LIMIT ? OFFSET ?",
            (_clamp_limit(limit, 50), _clamp_offset(offset)),
        )
        return [_run(row) for row in rows]

    async def count(self) -> int:
        row = await self.db.conn.execute_fetchone("SELECT COUNT(*) AS n FROM wizard_runs")
        return int(row["n"]) if row is not None else 0

    async def last_scheduled(self, mode: str) -> WizardRun | None:
        row = await self.db.conn.execute_fetchone(
            "SELECT * FROM wizard_runs WHERE mode = ? AND origin = 'scheduled' ORDER BY id DESC LIMIT 1", (mode,)
        )
        return _run(row) if row is not None else None

    async def update(self, run_id: int, now: str, **fields: object) -> None:
        """Update the given columns of an ACTIVE run (a finished run never changes)."""
        allowed = {"state", "phase", "current_step", "summary", "plan_ready", "message_id", "chat_id"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"not updatable: {sorted(unknown)}")
        state = fields.get("state")
        if state is not None and state not in ACTIVE_STATES:
            raise ValueError(f"use finish() for the terminal state {state!r}")
        sets = ", ".join(f"{name} = ?" for name in fields)
        values = [int(v) if isinstance(v, bool) else v for v in fields.values()]
        await self.db.conn.execute(
            f"UPDATE wizard_runs SET {sets}, updated_at = ? WHERE id = ? AND active = 1",
            (*values, now, run_id),
        )
        await self.db.commit()

    async def set_message(self, run_id: int, chat_id: int, message_id: int, now: str) -> None:
        """The progress message — also for a finished run (its report is edited in)."""
        await self.db.conn.execute(
            "UPDATE wizard_runs SET chat_id = ?, message_id = ?, updated_at = ? WHERE id = ?",
            (chat_id, message_id, now, run_id),
        )
        await self.db.commit()

    async def finish(self, run_id: int, state: str, summary: str, now: str) -> bool:
        """Terminal state + release the lock. False when the run was already finished."""
        if state not in TERMINAL_STATES:
            raise ValueError(f"{state!r} is not a terminal state")
        cursor = await self.db.conn.execute(
            """
            UPDATE wizard_runs
            SET state = ?, summary = ?, active = NULL, finished_at = ?, updated_at = ?
            WHERE id = ? AND active = 1
            """,
            (state, summary, now, now, run_id),
        )
        await self.db.commit()
        return int(cursor.rowcount or 0) == 1

    async def mark_reported(self, run_id: int, now: str) -> None:
        await self.db.conn.execute("UPDATE wizard_runs SET reported_at = ? WHERE id = ?", (now, run_id))
        await self.db.commit()
