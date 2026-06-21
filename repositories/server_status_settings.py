"""Persistence for the single-row ``server_status_settings`` table.

The table holds one row (``id = 1``) with the real-time server-status panel's
"detailed metrics" toggle. When enabled, the background sampler additionally
collects load average, uptime and a network-history ring buffer; when disabled
it does none of that extra work. Writes stamp ``updated_at`` with the current
unix time.
"""

from __future__ import annotations

import time

from db.database import Database


class ServerStatusSettingsRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get(self) -> bool:
        """Return whether the detailed-metrics mode is enabled (default ``False``)."""
        row = await self.db.conn.execute_fetchone(
            "SELECT detailed_enabled FROM server_status_settings WHERE id = 1"
        )
        if row is None:
            return False
        return bool(row["detailed_enabled"])

    async def set_detailed(self, enabled: bool) -> None:
        await self.db.conn.execute(
            "UPDATE server_status_settings SET detailed_enabled = ?, updated_at = ? WHERE id = 1",
            (1 if enabled else 0, int(time.time())),
        )
        await self.db.conn.commit()
