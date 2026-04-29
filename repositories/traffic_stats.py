from __future__ import annotations

from aiosqlite import Row

from db.database import Database
from models.dto import TrafficStats


def _row_to_traffic_stats(row: Row | None) -> TrafficStats | None:
    if row is None:
        return None
    return TrafficStats(
        key_id=int(row["key_id"]),
        downloaded_bytes=int(row["downloaded_bytes"]),
        uploaded_bytes=int(row["uploaded_bytes"]),
        last_raw_downloaded_bytes=row["last_raw_downloaded_bytes"],
        last_raw_uploaded_bytes=row["last_raw_uploaded_bytes"],
        last_success_at=row["last_success_at"],
        last_attempt_at=row["last_attempt_at"],
        available=bool(row["available"]),
        unavailable_reason=row["unavailable_reason"],
        source=row["source"],
    )


class TrafficStatsRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get_by_key_id(self, key_id: int) -> TrafficStats | None:
        cursor = await self.db.conn.execute(
            "SELECT * FROM vpn_key_traffic_stats WHERE key_id = ?",
            (key_id,),
        )
        row = await cursor.fetchone()
        return _row_to_traffic_stats(row)

    async def list_by_key_ids(self, key_ids: list[int]) -> dict[int, TrafficStats]:
        if not key_ids:
            return {}
        placeholders = ",".join("?" for _ in key_ids)
        cursor = await self.db.conn.execute(
            f"SELECT * FROM vpn_key_traffic_stats WHERE key_id IN ({placeholders})",
            tuple(key_ids),
        )
        rows = await cursor.fetchall()
        result: dict[int, TrafficStats] = {}
        for row in rows:
            stats = _row_to_traffic_stats(row)
            if stats is not None:
                result[stats.key_id] = stats
        return result

    async def upsert_success(
        self,
        *,
        key_id: int,
        downloaded_bytes: int,
        uploaded_bytes: int,
        raw_downloaded_bytes: int | None,
        raw_uploaded_bytes: int | None,
        now: str,
        source: str,
    ) -> TrafficStats:
        await self.db.conn.execute(
            """
            INSERT INTO vpn_key_traffic_stats (
              key_id, downloaded_bytes, uploaded_bytes,
              last_raw_downloaded_bytes, last_raw_uploaded_bytes,
              last_success_at, last_attempt_at, available,
              unavailable_reason, source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, NULL, ?)
            ON CONFLICT(key_id) DO UPDATE SET
              downloaded_bytes = excluded.downloaded_bytes,
              uploaded_bytes = excluded.uploaded_bytes,
              last_raw_downloaded_bytes = excluded.last_raw_downloaded_bytes,
              last_raw_uploaded_bytes = excluded.last_raw_uploaded_bytes,
              last_success_at = excluded.last_success_at,
              last_attempt_at = excluded.last_attempt_at,
              available = 1,
              unavailable_reason = NULL,
              source = excluded.source
            """,
            (
                key_id,
                max(downloaded_bytes, 0),
                max(uploaded_bytes, 0),
                max(raw_downloaded_bytes, 0) if raw_downloaded_bytes is not None else None,
                max(raw_uploaded_bytes, 0) if raw_uploaded_bytes is not None else None,
                now,
                now,
                source,
            ),
        )
        await self.db.commit()
        stats = await self.get_by_key_id(key_id)
        if stats is None:
            raise RuntimeError("Traffic stats upsert failed")
        return stats

    async def upsert_unavailable(
        self,
        *,
        key_id: int,
        reason: str,
        now: str,
        source: str,
    ) -> TrafficStats:
        await self.db.conn.execute(
            """
            INSERT INTO vpn_key_traffic_stats (
              key_id, downloaded_bytes, uploaded_bytes,
              last_attempt_at, available, unavailable_reason, source
            )
            VALUES (?, 0, 0, ?, 0, ?, ?)
            ON CONFLICT(key_id) DO UPDATE SET
              last_attempt_at = excluded.last_attempt_at,
              available = 0,
              unavailable_reason = excluded.unavailable_reason,
              source = excluded.source
            """,
            (key_id, now, reason[:512], source),
        )
        await self.db.commit()
        stats = await self.get_by_key_id(key_id)
        if stats is None:
            raise RuntimeError("Traffic stats unavailable upsert failed")
        return stats
