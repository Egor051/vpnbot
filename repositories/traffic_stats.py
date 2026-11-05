
from dataclasses import dataclass
from datetime import datetime, timezone

from aiosqlite import Row

from db.database import Database
from models.dto import TrafficStats

#: Buckets older than this are deleted by :meth:`TrafficStatsRepository.prune_hourly`.
#: A little over the longest dashboard window (365 days).
TRAFFIC_HOURLY_RETENTION_DAYS = 400


def hour_utc_from_iso(timestamp: str) -> int:
    """Return the ``traffic_hourly.hour_utc`` bucket (``unix_time // 3600``) of a timestamp.

    ``timestamp`` is an ISO-8601 string as produced by ``ClockProvider.now()``;
    one without an offset is read as UTC, never as local time.
    """
    moment = datetime.fromisoformat(timestamp)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp()) // 3600


@dataclass(frozen=True, slots=True)
class HourlyTrafficDelta:
    """The bytes one successful poll added to a key's lifetime totals.

    Recorded into ``traffic_hourly`` by :meth:`TrafficStatsRepository.upsert_success`
    together with the totals themselves, so the hourly history and the totals
    cannot disagree.
    """

    protocol: str
    downloaded_bytes: int
    uploaded_bytes: int


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
        """Return traffic stats for a VPN key, or None if not recorded."""
        cursor = await self.db.conn.execute(
            "SELECT * FROM vpn_key_traffic_stats WHERE key_id = ?",
            (key_id,),
        )
        row = await cursor.fetchone()
        return _row_to_traffic_stats(row)

    async def list_by_key_ids(self, key_ids: list[int]) -> dict[int, TrafficStats]:
        """Return traffic stats for the given key ids keyed by key id."""
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
        hourly: HourlyTrafficDelta | None = None,
    ) -> TrafficStats:
        """Upsert successful traffic stats for a key and return the stored stats.

        ``hourly`` is the delta this poll adds to the totals. When it moves any
        bytes it is added to the key's ``traffic_hourly`` bucket for the hour of
        ``now`` — by the same call, so inside the caller's transaction the bucket
        and the totals commit or roll back together. ``None`` writes the totals
        only (seeding a key's lifetime figures has no hour to put them in).
        """
        downloaded = max(downloaded_bytes, 0)
        uploaded = max(uploaded_bytes, 0)
        raw_down = max(raw_downloaded_bytes, 0) if raw_downloaded_bytes is not None else None
        raw_up = max(raw_uploaded_bytes, 0) if raw_uploaded_bytes is not None else None
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
            (key_id, downloaded, uploaded, raw_down, raw_up, now, now, source),
        )
        if hourly is not None and (hourly.downloaded_bytes > 0 or hourly.uploaded_bytes > 0):
            await self.db.conn.execute(
                """
                INSERT INTO traffic_hourly (hour_utc, key_id, protocol, downloaded_bytes, uploaded_bytes)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(hour_utc, key_id, protocol) DO UPDATE SET
                  downloaded_bytes = downloaded_bytes + excluded.downloaded_bytes,
                  uploaded_bytes = uploaded_bytes + excluded.uploaded_bytes
                """,
                (
                    hour_utc_from_iso(now),
                    key_id,
                    hourly.protocol,
                    max(hourly.downloaded_bytes, 0),
                    max(hourly.uploaded_bytes, 0),
                ),
            )
        await self.db.commit()
        return TrafficStats(
            key_id=key_id,
            downloaded_bytes=downloaded,
            uploaded_bytes=uploaded,
            last_raw_downloaded_bytes=raw_down,
            last_raw_uploaded_bytes=raw_up,
            last_success_at=now,
            last_attempt_at=now,
            available=True,
            unavailable_reason=None,
            source=source,
        )

    async def touch_attempt(self, *, key_id: int, now: str, source: str) -> TrafficStats:
        """Record a poll that reached the backend but found no counter for this key.

        Updates ``last_attempt_at`` and nothing else — the accumulated totals, the
        raw counters, ``available`` and ``last_success_at`` all survive untouched.
        A missing counter is not a backend failure: xray creates its per-user
        counters lazily, on the key's first traffic (right after a restart
        ``statsquery`` lists none at all), and hysteria2's ``/traffic`` only lists
        ids that have moved data. Recording that as "unavailable" is what blanked
        the figures on keys that had simply not been used yet.

        A key polled before it ever had a counter gets a fresh zero row that is
        ``available`` — the backend answered, and its answer was "no traffic".
        """
        await self.db.conn.execute(
            """
            INSERT INTO vpn_key_traffic_stats (
              key_id, downloaded_bytes, uploaded_bytes,
              last_attempt_at, available, unavailable_reason, source
            )
            VALUES (?, 0, 0, ?, 1, NULL, ?)
            ON CONFLICT(key_id) DO UPDATE SET
              last_attempt_at = excluded.last_attempt_at
            """,
            (key_id, now, source),
        )
        await self.db.commit()
        stats = await self.get_by_key_id(key_id)
        if stats is None:
            raise RuntimeError("Traffic stats attempt touch failed")
        return stats

    async def upsert_unavailable(
        self,
        *,
        key_id: int,
        reason: str,
        now: str,
        source: str,
    ) -> TrafficStats:
        """Upsert a key's traffic stats as unavailable with the given reason and return them."""
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

    async def prune_hourly(self, *, current_hour_utc: int, retention_days: int = TRAFFIC_HOURLY_RETENTION_DAYS) -> int:
        """Delete ``traffic_hourly`` buckets that fell out of the retention window.

        Keeps exactly what a ``retention_days`` dashboard window would count —
        ``hour_utc >= current_hour_utc - retention_days * 24 + 1`` — and deletes the
        rest. Returns the number of buckets removed.
        """
        cursor = await self.db.conn.execute(
            "DELETE FROM traffic_hourly WHERE hour_utc <= ?",
            (current_hour_utc - retention_days * 24,),
        )
        await self.db.commit()
        return max(cursor.rowcount, 0)
