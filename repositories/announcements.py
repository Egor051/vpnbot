
from dataclasses import dataclass

from aiosqlite import Row

from db.database import Database
from models.dto import RecipientFilter
from repositories._helpers import _clamp_limit
from services.errors import InvalidTransition


@dataclass(frozen=True, slots=True)
class AnnouncementBatch:
    id: int
    actor_user_id: int
    from_chat_id: int
    message_id: int
    status: str
    total_count: int
    success_count: int
    failed_count: int
    skipped_count: int
    created_at: str
    updated_at: str
    completed_at: str | None
    scheduled_at: str | None = None
    # Segmentation filter for targeted broadcasts; None for an unsegmented batch.
    recipient_filter: RecipientFilter | None = None


@dataclass(frozen=True, slots=True)
class AnnouncementDelivery:
    announcement_id: int
    user_id: int
    status: str
    error_text: str | None
    created_at: str
    updated_at: str


def _row_to_batch(row: Row | None) -> AnnouncementBatch | None:
    if row is None:
        return None
    return AnnouncementBatch(
        id=int(row["id"]),
        actor_user_id=int(row["actor_user_id"]),
        from_chat_id=int(row["from_chat_id"]),
        message_id=int(row["message_id"]),
        status=str(row["status"]),
        total_count=int(row["total_count"]),
        success_count=int(row["success_count"]),
        failed_count=int(row["failed_count"]),
        skipped_count=int(row["skipped_count"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        completed_at=row["completed_at"],
        scheduled_at=row["scheduled_at"] if "scheduled_at" in row.keys() else None,
        recipient_filter=(
            RecipientFilter.from_json(row["recipient_filter_json"])
            if "recipient_filter_json" in row.keys()
            else None
        ),
    )


def _row_to_delivery(row: Row | None) -> AnnouncementDelivery | None:
    if row is None:
        return None
    return AnnouncementDelivery(
        announcement_id=int(row["announcement_id"]),
        user_id=int(row["user_id"]),
        status=str(row["status"]),
        error_text=row["error_text"],
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


class AnnouncementRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create_batch(
        self,
        *,
        actor_user_id: int,
        from_chat_id: int,
        message_id: int,
        recipient_ids: list[int],
        now: str,
        scheduled_at: str | None = None,
        recipient_filter: RecipientFilter | None = None,
    ) -> AnnouncementBatch:
        """Create an announcement batch with per-recipient delivery rows and return it."""
        status = "scheduled" if scheduled_at is not None else "pending"
        recipient_filter_json = recipient_filter.to_json() if recipient_filter is not None else None
        async with self.db.transaction():
            cursor = await self.db.conn.execute(
                """
                INSERT INTO announcement_batches (
                  actor_user_id, from_chat_id, message_id, status, total_count,
                  created_at, updated_at, scheduled_at, recipient_filter_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    actor_user_id,
                    from_chat_id,
                    message_id,
                    status,
                    len(recipient_ids),
                    now,
                    now,
                    scheduled_at,
                    recipient_filter_json,
                ),
            )
            assert cursor.lastrowid is not None
            batch_id = int(cursor.lastrowid)
            if recipient_ids:
                # recipient_ids come from the announcement-recipient query and
                # reference existing users; users are never hard-deleted (only
                # blocked), so the user_id FK cannot dangle here. Note OR IGNORE
                # suppresses only the PK/unique conflict on (announcement_id,
                # user_id) — SQLite does NOT apply it to FK violations, so a
                # genuinely missing user would abort the batch transaction.
                await self.db.conn.executemany(
                    """
                    INSERT OR IGNORE INTO announcement_deliveries (
                      announcement_id, user_id, status, created_at, updated_at
                    )
                    VALUES (?, ?, 'pending', ?, ?)
                    """,
                    [(batch_id, user_id, now, now) for user_id in recipient_ids],
                )
        batch = await self.get_batch(batch_id)
        if batch is None:
            raise RuntimeError("Announcement batch insert failed")
        return batch

    async def get_batch(self, announcement_id: int) -> AnnouncementBatch | None:
        """Return an announcement batch by id, or None if not found."""
        cursor = await self.db.conn.execute("SELECT * FROM announcement_batches WHERE id = ?", (announcement_id,))
        return _row_to_batch(await cursor.fetchone())

    async def list_incomplete_batches(self, *, limit: int = 10) -> list[AnnouncementBatch]:
        """Return batches that are not yet completed, most recently updated first."""
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM announcement_batches
            WHERE completed_at IS NULL
              AND status IN ('pending', 'sending', 'failed', 'scheduled')
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            (_clamp_limit(limit),),
        )
        rows = await cursor.fetchall()
        return [batch for row in rows if (batch := _row_to_batch(row)) is not None]

    async def list_due_scheduled_batches(self, now: str, *, limit: int = 10) -> list[AnnouncementBatch]:
        """Return scheduled batches whose scheduled time is now due, earliest first."""
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM announcement_batches
            WHERE status = 'scheduled'
              AND scheduled_at <= ?
            ORDER BY scheduled_at ASC, id ASC
            LIMIT ?
            """,
            (now, _clamp_limit(limit)),
        )
        rows = await cursor.fetchall()
        return [batch for row in rows if (batch := _row_to_batch(row)) is not None]

    async def list_pending_deliveries(
        self,
        announcement_id: int,
        limit: int,
        *,
        after_user_id: int = 0,
        retry_failed: bool = False,
    ) -> list[AnnouncementDelivery]:
        """Return pending (and optionally failed) deliveries for a batch, keyset-paginated by user id."""
        statuses = ("pending", "failed") if retry_failed else ("pending",)
        placeholders = ",".join("?" for _ in statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM announcement_deliveries
            WHERE announcement_id = ?
              AND status IN ({placeholders})
              AND user_id > ?
            ORDER BY user_id ASC
            LIMIT ?
            """,
            (announcement_id, *statuses, after_user_id, _clamp_limit(limit)),
        )
        rows = await cursor.fetchall()
        return [delivery for row in rows if (delivery := _row_to_delivery(row)) is not None]

    async def set_batch_status(self, announcement_id: int, status: str, now: str, *, completed: bool = False) -> None:
        """Update a batch's status, optionally marking it completed, unless already cancelled."""
        await self.db.conn.execute(
            """
            UPDATE announcement_batches
            SET status = ?, updated_at = ?, completed_at = CASE WHEN ? THEN ? ELSE completed_at END
            WHERE id = ? AND status != 'cancelled'
            """,
            (status, now, 1 if completed else 0, now, announcement_id),
        )
        await self.db.commit()

    async def mark_cancelled(self, announcement_id: int, now: str) -> None:
        """Mark an announcement batch as cancelled."""
        await self.db.conn.execute(
            """
            UPDATE announcement_batches
            SET status = 'cancelled', updated_at = ?, completed_at = COALESCE(completed_at, ?)
            WHERE id = ?
            """,
            (now, now, announcement_id),
        )
        await self.db.commit()

    async def mark_delivery(self, announcement_id: int, user_id: int, status: str, now: str, error_text: str | None = None) -> None:
        """Update a single delivery's status, raising InvalidTransition if it was not pending/failed."""
        cursor = await self.db.conn.execute(
            """
            UPDATE announcement_deliveries
            SET status = ?, error_text = ?, updated_at = ?
            WHERE announcement_id = ? AND user_id = ? AND status IN ('pending', 'failed')
            """,
            (status, _truncate_error(error_text), now, announcement_id, user_id),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise InvalidTransition(f"Announcement delivery {announcement_id}/{user_id} is not in pending/failed state")

    async def refresh_batch_counts(self, announcement_id: int, now: str) -> None:
        """Recompute a batch's success, failed, and skipped counts from its deliveries."""
        await self.db.conn.execute(
            """
            UPDATE announcement_batches
            SET
              success_count = agg.sent,
              failed_count = agg.failed,
              skipped_count = agg.skipped,
              updated_at = ?
            FROM (
              SELECT
                COALESCE(SUM(status = 'sent'), 0) AS sent,
                COALESCE(SUM(status = 'failed'), 0) AS failed,
                COALESCE(SUM(status = 'skipped'), 0) AS skipped
              FROM announcement_deliveries
              WHERE announcement_id = ?
            ) AS agg
            WHERE id = ?
            """,
            (now, announcement_id, announcement_id),
        )
        await self.db.commit()

    async def delivery_user_ids_grouped(
        self, announcement_id: int
    ) -> dict[str, tuple[int, ...]]:
        """Return delivery user ids for a batch grouped by delivery status."""
        cursor = await self.db.conn.execute(
            """
            SELECT user_id, status FROM announcement_deliveries
            WHERE announcement_id = ?
            ORDER BY user_id ASC
            """,
            (announcement_id,),
        )
        rows = await cursor.fetchall()
        grouped: dict[str, list[int]] = {}
        for row in rows:
            grouped.setdefault(str(row["status"]), []).append(int(row["user_id"]))
        return {status: tuple(ids) for status, ids in grouped.items()}


def _truncate_error(value: str | None, limit: int = 256) -> str | None:
    if value is None:
        return None
    clean = value.replace("\r", " ").replace("\n", " ").strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3].rstrip() + "..."
