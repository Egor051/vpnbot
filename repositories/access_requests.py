from __future__ import annotations

import sqlite3

from aiosqlite import Row

from db.database import Database
from models.dto import AccessRequest
from models.enums import AccessRequestStatus


def _row_to_access_request(row: Row | None) -> AccessRequest | None:
    if row is None:
        return None
    return AccessRequest(
        id=int(row["id"]),
        telegram_user_id=int(row["telegram_user_id"]),
        username=row["username"],
        status=AccessRequestStatus(row["status"]),
        requested_at=row["requested_at"],
        decided_by=row["decided_by"],
        decided_at=row["decided_at"],
        decision_note=row["decision_note"],
    )


class AccessRequestRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(self, telegram_user_id: int, username: str | None, now: str) -> AccessRequest:
        cursor = await self.db.conn.execute(
            """
            INSERT INTO access_requests (telegram_user_id, username, status, requested_at)
            VALUES (?, ?, ?, ?)
            """,
            (telegram_user_id, username, AccessRequestStatus.PENDING.value, now),
        )
        await self.db.commit()
        request = await self.get_by_id(int(cursor.lastrowid))
        if request is None:
            raise RuntimeError("Access request insert failed")
        return request

    async def create_pending_idempotent(self, telegram_user_id: int, username: str | None, now: str) -> tuple[AccessRequest, bool]:
        try:
            return await self.create(telegram_user_id, username, now), True
        except sqlite3.IntegrityError as exc:
            if not _is_pending_request_unique_conflict(exc):
                raise
            pending = await self.get_pending_for_user(telegram_user_id)
            if pending is None:
                raise
            return pending, False

    async def get_by_id(self, request_id: int) -> AccessRequest | None:
        cursor = await self.db.conn.execute("SELECT * FROM access_requests WHERE id = ?", (request_id,))
        row = await cursor.fetchone()
        return _row_to_access_request(row)

    async def get_pending_for_user(self, telegram_user_id: int) -> AccessRequest | None:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM access_requests
            WHERE telegram_user_id = ? AND status = ?
            ORDER BY requested_at DESC
            LIMIT 1
            """,
            (telegram_user_id, AccessRequestStatus.PENDING.value),
        )
        row = await cursor.fetchone()
        return _row_to_access_request(row)

    async def get_latest_for_user(self, telegram_user_id: int) -> AccessRequest | None:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM access_requests
            WHERE telegram_user_id = ?
            ORDER BY requested_at DESC
            LIMIT 1
            """,
            (telegram_user_id,),
        )
        row = await cursor.fetchone()
        return _row_to_access_request(row)

    async def set_status_if_pending(
        self,
        request_id: int,
        status: AccessRequestStatus,
        actor_user_id: int,
        now: str,
        decision_note: str | None = None,
    ) -> bool:
        cursor = await self.db.conn.execute(
            """
            UPDATE access_requests
            SET status = ?, decided_by = ?, decided_at = ?, decision_note = ?
            WHERE id = ? AND status = ?
            """,
            (
                status.value,
                actor_user_id,
                now,
                decision_note,
                request_id,
                AccessRequestStatus.PENDING.value,
            ),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def list_by_status(self, status: AccessRequestStatus, limit: int = 20, offset: int = 0) -> list[AccessRequest]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM access_requests
            WHERE status = ?
            ORDER BY requested_at ASC
            LIMIT ? OFFSET ?
            """,
            (status.value, limit, offset),
        )
        rows = await cursor.fetchall()
        return [request for row in rows if (request := _row_to_access_request(row)) is not None]


def _is_pending_request_unique_conflict(exc: sqlite3.IntegrityError) -> bool:
    message = str(exc).lower()
    if "idx_access_requests_one_pending" in message:
        return True
    return "unique constraint failed: access_requests.telegram_user_id" in message
