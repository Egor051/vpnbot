"""Persistence for the single-row ``maintenance_settings`` table.

The table holds one row (``id = 1``) with the global maintenance-mode toggle:
the ``enabled`` flag, an optional custom banner ``message`` shown to non-admin
users while works are in progress, and who/when turned it on. Writes stamp
``updated_at`` (and ``started_at`` on enable) with the current unix time.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from db.database import Database


@dataclass(frozen=True, slots=True)
class MaintenanceState:
    enabled: bool
    message: str | None
    started_at: int
    started_by: int | None


_DISABLED = MaintenanceState(enabled=False, message=None, started_at=0, started_by=None)


class MaintenanceSettingsRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get(self) -> MaintenanceState:
        """Return the current maintenance state (default: disabled)."""
        row = await self.db.conn.execute_fetchone(
            "SELECT enabled, message, started_at, started_by FROM maintenance_settings WHERE id = 1"
        )
        if row is None:
            return _DISABLED
        return MaintenanceState(
            enabled=bool(row["enabled"]),
            message=row["message"],
            started_at=int(row["started_at"] or 0),
            started_by=row["started_by"],
        )

    async def set_state(
        self,
        *,
        enabled: bool,
        message: str | None,
        started_by: int | None,
    ) -> None:
        now = int(time.time())
        # Stamp started_at only when turning maintenance on; clear it on disable.
        started_at = now if enabled else 0
        await self.db.conn.execute(
            "UPDATE maintenance_settings "
            "SET enabled = ?, message = ?, started_at = ?, started_by = ?, updated_at = ? "
            "WHERE id = 1",
            (1 if enabled else 0, message, started_at, started_by, now),
        )
        await self.db.conn.commit()
