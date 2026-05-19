
from aiosqlite import Row

from db.database import Database
from models.dto import TrialKeyRequest
from models.enums import VpnKeyType
from repositories._helpers import enum_value


def _row_to_request(row: Row | None) -> TrialKeyRequest | None:
    if row is None:
        return None
    return TrialKeyRequest(
        id=int(row["id"]),
        telegram_user_id=int(row["telegram_user_id"]),
        key_type=enum_value(VpnKeyType, row["key_type"], "trial_key_requests.key_type"),
        status=str(row["status"]),
        key_id=int(row["key_id"]) if row["key_id"] is not None else None,
        requested_at=str(row["requested_at"]),
        decided_by=int(row["decided_by"]) if row["decided_by"] is not None else None,
        decided_at=row["decided_at"],
    )


class TrialKeyRequestRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(self, *, telegram_user_id: int, key_type: VpnKeyType, requested_at: str) -> TrialKeyRequest:
        cursor = await self.db.conn.execute(
            """
            INSERT INTO trial_key_requests (telegram_user_id, key_type, status, requested_at)
            VALUES (?, ?, 'pending', ?)
            """,
            (telegram_user_id, key_type.value, requested_at),
        )
        await self.db.commit()
        assert cursor.lastrowid is not None
        req = await self.get_by_id(int(cursor.lastrowid))
        if req is None:
            raise RuntimeError("trial_key_requests insert failed")
        return req

    async def get_by_id(self, request_id: int) -> TrialKeyRequest | None:
        cursor = await self.db.conn.execute(
            "SELECT * FROM trial_key_requests WHERE id = ?",
            (request_id,),
        )
        row = await cursor.fetchone()
        return _row_to_request(row)

    async def list_pending(self, limit: int = 20, offset: int = 0) -> list[TrialKeyRequest]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM trial_key_requests
            WHERE status = 'pending'
            ORDER BY requested_at ASC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [r for row in rows if (r := _row_to_request(row)) is not None]

    async def count_used_since_reset(self, telegram_user_id: int, reset_at: str | None) -> int:
        threshold = reset_at or "1970-01-01T00:00:00"
        cursor = await self.db.conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM trial_key_requests
            WHERE telegram_user_id = ? AND requested_at > ?
            """,
            (telegram_user_id, threshold),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def approve(self, *, request_id: int, key_id: int, decided_by: int, decided_at: str) -> None:
        await self.db.conn.execute(
            """
            UPDATE trial_key_requests
            SET status = 'approved', key_id = ?, decided_by = ?, decided_at = ?
            WHERE id = ?
            """,
            (key_id, decided_by, decided_at, request_id),
        )
        await self.db.commit()

    async def reject(self, *, request_id: int, decided_by: int, decided_at: str) -> None:
        await self.db.conn.execute(
            """
            UPDATE trial_key_requests
            SET status = 'rejected', decided_by = ?, decided_at = ?
            WHERE id = ?
            """,
            (decided_by, decided_at, request_id),
        )
        await self.db.commit()
