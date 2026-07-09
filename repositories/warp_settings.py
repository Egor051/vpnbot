"""Persistence for the single-row ``warp_settings`` table.

The table holds one row (``id = 1``). Persisted columns describe the configured
module; runtime columns mirror the live tunnel state and are reset on every bot
restart. All writes stamp ``updated_at`` with the current unix time.
"""

from __future__ import annotations

import time

from aiosqlite import Row

from db.database import Database
from warp.state import WarpState


def _row_to_state(row: Row | None) -> WarpState:
    if row is None:
        return WarpState()
    return WarpState(
        enabled=bool(row["enabled"]),
        config_path=str(row["config_path"]),
        interface_name=str(row["interface_name"]),
        routes_count=int(row["routes_count"]),
        config_installed=bool(row["config_installed"]),
        kill_switch=bool(row["kill_switch"]),
        tunnel_up=bool(row["tunnel_up"]),
        routes_active=bool(row["routes_active"]),
        fail_streak=int(row["fail_streak"]),
        success_streak=int(row["success_streak"]),
        last_handshake=int(row["last_handshake"]),
        last_check_ts=int(row["last_check_ts"]),
        updated_at=int(row["updated_at"]),
    )


class WarpSettingsRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get(self) -> WarpState:
        row = await self.db.conn.execute_fetchone(
            """
            SELECT enabled, config_path, interface_name, routes_count,
                   config_installed, kill_switch,
                   tunnel_up, routes_active, fail_streak, success_streak,
                   last_handshake, last_check_ts, updated_at
            FROM warp_settings WHERE id = 1
            """
        )
        return _row_to_state(row)

    async def set_enabled(self, enabled: bool) -> None:
        await self.db.conn.execute(
            "UPDATE warp_settings SET enabled = ?, updated_at = ? WHERE id = 1",
            (1 if enabled else 0, int(time.time())),
        )
        await self.db.conn.commit()

    async def set_kill_switch(self, enabled: bool) -> None:
        await self.db.conn.execute(
            "UPDATE warp_settings SET kill_switch = ?, updated_at = ? WHERE id = 1",
            (1 if enabled else 0, int(time.time())),
        )
        await self.db.conn.commit()

    async def update_config(self, *, config_path: str, interface_name: str, routes_count: int) -> None:
        await self.db.conn.execute(
            """
            UPDATE warp_settings
            SET config_path = ?, interface_name = ?, routes_count = ?,
                config_installed = 1, updated_at = ?
            WHERE id = 1
            """,
            (config_path, interface_name, routes_count, int(time.time())),
        )
        await self.db.conn.commit()

    async def clear_config(self) -> None:
        await self.db.conn.execute(
            "UPDATE warp_settings SET routes_count = 0, config_installed = 0, updated_at = ? WHERE id = 1",
            (int(time.time()),),
        )
        await self.db.conn.commit()

    async def update_runtime(
        self,
        *,
        tunnel_up: bool,
        routes_active: bool,
        fail_streak: int,
        success_streak: int,
        last_handshake: int,
        last_check_ts: int,
    ) -> None:
        await self.db.conn.execute(
            """
            UPDATE warp_settings
            SET tunnel_up = ?, routes_active = ?, fail_streak = ?, success_streak = ?,
                last_handshake = ?, last_check_ts = ?, updated_at = ?
            WHERE id = 1
            """,
            (
                1 if tunnel_up else 0,
                1 if routes_active else 0,
                fail_streak,
                success_streak,
                last_handshake,
                last_check_ts,
                int(time.time()),
            ),
        )
        await self.db.conn.commit()

    async def reset_runtime(self) -> None:
        """Zero all runtime columns (called on bot startup)."""
        await self.db.conn.execute(
            """
            UPDATE warp_settings
            SET tunnel_up = 0, routes_active = 0, fail_streak = 0, success_streak = 0,
                last_handshake = 0, last_check_ts = 0, updated_at = ?
            WHERE id = 1
            """,
            (int(time.time()),),
        )
        await self.db.conn.commit()
