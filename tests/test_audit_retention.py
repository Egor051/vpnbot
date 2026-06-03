
import asyncio
from pathlib import Path

from db.database import Database
from models.enums import AuditEntityType
from repositories.audit_log import AuditLogRepository


def _ts(day: int) -> str:
    # Same shape as adapters/clock.py: UTC ISO-8601 with +00:00, no microseconds.
    return f"2026-01-{day:02d}T00:00:00+00:00"


def test_prune_older_than_uses_plain_comparison_on_offset_timestamps(tmp_path: Path) -> None:
    """prune_older_than deletes only rows strictly older than the cutoff, using a
    direct lexicographic comparison on '+00:00'-suffixed timestamps (regression
    guard for the removed REPLACE() workaround / P2)."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            audit = AuditLogRepository(db)
            for day in (1, 5, 10, 15):
                await audit.create(
                    actor_user_id=None,
                    action="x",
                    entity_type=AuditEntityType.SYSTEM,
                    entity_id=str(day),
                    details=None,
                    now=_ts(day),
                )
            assert await audit.count_all() == 4

            # Cutoff at day 10 → days 1 and 5 are strictly older and removed.
            removed = await audit.prune_older_than(_ts(10))
            assert removed == 2
            assert await audit.count_all() == 2

            remaining = await audit.list_recent(limit=10)
            kept = sorted(int(row["entity_id"]) for row in remaining)
            assert kept == [10, 15]
        finally:
            await db.close()

    asyncio.run(run())
