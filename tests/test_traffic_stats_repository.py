"""TrafficStatsRepository against a real bootstrapped SQLite database.

vpn_key_traffic_stats has a foreign key to vpn_keys, so each test inserts the
owning user and key rows directly (no service layer) and then drives the
repository on its own.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from db.database import Database
from repositories.traffic_stats import (
    TRAFFIC_HOURLY_RETENTION_DAYS,
    HourlyTrafficDelta,
    TrafficStatsRepository,
    hour_utc_from_iso,
)

NOW = "2026-03-01T10:15:00+00:00"
LATER = "2026-03-01T11:45:00+00:00"
HOUR = hour_utc_from_iso(NOW)


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "vpn.db")
    await database.connect()
    await database.bootstrap()
    await database.conn.execute(
        """
        INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
        VALUES (1, 'owner', 'Owner', 'SUPERADMIN', ?, ?)
        """,
        (NOW, NOW),
    )
    for key_id in (10, 11, 12):
        await database.conn.execute(
            """
            INSERT INTO vpn_keys (id, owner_user_id, key_type, status, payload_json, public_payload_json,
                                  created_at, updated_at, created_by)
            VALUES (?, 1, 'xray', 'active', '{}', '{}', ?, ?, 1)
            """,
            (key_id, NOW, NOW),
        )
    await database.commit()
    try:
        yield database
    finally:
        await database.close()


async def _buckets(db: Database) -> list[tuple[int, int, str, int, int]]:
    rows = await db.conn.execute_fetchall(
        "SELECT hour_utc, key_id, protocol, downloaded_bytes, uploaded_bytes FROM traffic_hourly ORDER BY hour_utc, key_id"
    )
    return [(int(r[0]), int(r[1]), str(r[2]), int(r[3]), int(r[4])) for r in rows]


# Invariant: a timestamp with an explicit offset is bucketed by its UTC instant,
# and one WITHOUT an offset is read as UTC — never as the host's local time.
def test_hour_utc_from_iso_treats_naive_as_utc() -> None:
    # Arrange
    aware = "2026-03-01T13:15:00+03:00"
    naive = "2026-03-01T10:15:00"

    # Act
    aware_hour = hour_utc_from_iso(aware)
    naive_hour = hour_utc_from_iso(naive)

    # Assert
    assert aware_hour == naive_hour == HOUR
    assert HOUR == 1_772_360_100 // 3600


# Invariant: get_by_key_id() returns None for a key that has never been polled.
async def test_get_by_key_id_missing_returns_none(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    # Act
    stats = await repo.get_by_key_id(10)

    # Assert
    assert stats is None


# Invariant: list_by_key_ids([]) short-circuits to {} (no "IN ()" SQL error).
async def test_list_by_key_ids_empty_input(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    # Act
    result = await repo.list_by_key_ids([])

    # Assert
    assert result == {}


# Invariant: list_by_key_ids() returns only the requested keys that have a row,
# keyed by key id; unknown or unpolled ids are simply absent.
async def test_list_by_key_ids_returns_only_known_rows(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)
    await repo.upsert_success(
        key_id=10, downloaded_bytes=1, uploaded_bytes=2, raw_downloaded_bytes=1, raw_uploaded_bytes=2,
        now=NOW, source="xray",
    )
    await repo.upsert_success(
        key_id=12, downloaded_bytes=3, uploaded_bytes=4, raw_downloaded_bytes=3, raw_uploaded_bytes=4,
        now=NOW, source="xray",
    )

    # Act
    result = await repo.list_by_key_ids([10, 11, 999])

    # Assert
    assert set(result) == {10}
    assert result[10].downloaded_bytes == 1


# Invariant: upsert_success() clamps negative totals and raw counters to 0 and
# the returned object equals what is persisted.
async def test_upsert_success_clamps_negatives_and_round_trips(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    # Act
    returned = await repo.upsert_success(
        key_id=10, downloaded_bytes=-5, uploaded_bytes=-1, raw_downloaded_bytes=-9, raw_uploaded_bytes=-3,
        now=NOW, source="xray",
    )
    stored = await repo.get_by_key_id(10)

    # Assert
    assert stored == returned
    assert (returned.downloaded_bytes, returned.uploaded_bytes) == (0, 0)
    assert (returned.last_raw_downloaded_bytes, returned.last_raw_uploaded_bytes) == (0, 0)
    assert returned.available is True and returned.unavailable_reason is None


# Invariant: raw counters of None stay NULL (a backend that reports no raw
# counter must not be recorded as "raw = 0").
async def test_upsert_success_keeps_null_raw_counters(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    # Act
    await repo.upsert_success(
        key_id=10, downloaded_bytes=7, uploaded_bytes=8, raw_downloaded_bytes=None, raw_uploaded_bytes=None,
        now=NOW, source="hysteria2",
    )
    stored = await repo.get_by_key_id(10)

    # Assert
    assert stored is not None
    assert (stored.last_raw_downloaded_bytes, stored.last_raw_uploaded_bytes) == (None, None)
    assert stored.source == "hysteria2"


# Invariant: a success after an unavailable poll restores available=1 and clears
# the reason (ON CONFLICT branch), overwriting the totals.
async def test_upsert_success_recovers_from_unavailable(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)
    await repo.upsert_unavailable(key_id=10, reason="down", now=NOW, source="xray")

    # Act
    await repo.upsert_success(
        key_id=10, downloaded_bytes=100, uploaded_bytes=50, raw_downloaded_bytes=100, raw_uploaded_bytes=50,
        now=LATER, source="xray",
    )
    stored = await repo.get_by_key_id(10)

    # Assert
    assert stored is not None
    assert stored.available is True and stored.unavailable_reason is None
    assert (stored.downloaded_bytes, stored.uploaded_bytes) == (100, 50)
    assert stored.last_success_at == stored.last_attempt_at == LATER


# Invariant: the hourly delta accumulates into ONE bucket per (hour, key,
# protocol) — two polls in the same hour add up instead of overwriting.
async def test_upsert_success_accumulates_hourly_bucket(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)
    common = {"key_id": 10, "raw_downloaded_bytes": None, "raw_uploaded_bytes": None, "source": "xray"}

    # Act
    await repo.upsert_success(
        downloaded_bytes=10, uploaded_bytes=1, now=NOW, hourly=HourlyTrafficDelta("xray", 10, 1), **common
    )
    await repo.upsert_success(
        downloaded_bytes=30, uploaded_bytes=4, now=NOW, hourly=HourlyTrafficDelta("xray", 20, 3), **common
    )

    # Assert
    assert await _buckets(db) == [(HOUR, 10, "xray", 30, 4)]


# Invariant: a zero delta writes the totals but creates no hourly bucket, and a
# delta with one negative direction is clamped to 0 in the bucket.
async def test_upsert_success_skips_zero_delta_and_clamps_negative(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)
    common = {"raw_downloaded_bytes": None, "raw_uploaded_bytes": None, "source": "xray", "now": NOW}

    # Act
    await repo.upsert_success(key_id=10, downloaded_bytes=5, uploaded_bytes=5,
                              hourly=HourlyTrafficDelta("xray", 0, 0), **common)
    await repo.upsert_success(key_id=11, downloaded_bytes=5, uploaded_bytes=5,
                              hourly=HourlyTrafficDelta("xray", 6, -2), **common)

    # Assert
    assert await _buckets(db) == [(HOUR, 11, "xray", 6, 0)]
    assert (await repo.get_by_key_id(10)) is not None


# Invariant: touch_attempt() on a never-polled key creates an AVAILABLE zero row
# ("backend answered: no traffic"), not an unavailable one.
async def test_touch_attempt_creates_available_zero_row(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    # Act
    stats = await repo.touch_attempt(key_id=10, now=NOW, source="xray")

    # Assert
    assert stats.available is True
    assert (stats.downloaded_bytes, stats.uploaded_bytes) == (0, 0)
    assert stats.last_attempt_at == NOW and stats.last_success_at is None


# Invariant: touch_attempt() on an existing row updates last_attempt_at ONLY —
# totals, raw counters, last_success_at and availability survive.
async def test_touch_attempt_preserves_existing_figures(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)
    before = await repo.upsert_success(
        key_id=10, downloaded_bytes=100, uploaded_bytes=50, raw_downloaded_bytes=100, raw_uploaded_bytes=50,
        now=NOW, source="xray",
    )

    # Act
    after = await repo.touch_attempt(key_id=10, now=LATER, source="other")

    # Assert
    assert after.last_attempt_at == LATER
    assert after.last_success_at == before.last_success_at == NOW
    assert (after.downloaded_bytes, after.uploaded_bytes) == (100, 50)
    assert after.source == "xray"


# Invariant: touch_attempt() raises if the row cannot be read back after the
# write (defensive guard against a silently failed upsert).
async def test_touch_attempt_raises_when_row_vanishes(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    async def _missing(key_id: int) -> None:
        return None

    monkeypatch.setattr(repo, "get_by_key_id", _missing)

    # Act / Assert
    with pytest.raises(RuntimeError, match="attempt touch failed"):
        await repo.touch_attempt(key_id=10, now=NOW, source="xray")


# Invariant: upsert_unavailable() keeps previously accumulated totals, flips
# available to 0, and truncates the stored reason to 512 characters.
async def test_upsert_unavailable_keeps_totals_and_truncates_reason(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)
    await repo.upsert_success(
        key_id=10, downloaded_bytes=100, uploaded_bytes=50, raw_downloaded_bytes=100, raw_uploaded_bytes=50,
        now=NOW, source="xray",
    )

    # Act
    stats = await repo.upsert_unavailable(key_id=10, reason="x" * 2000, now=LATER, source="xray-api")

    # Assert
    assert stats.available is False
    assert stats.unavailable_reason == "x" * 512
    assert (stats.downloaded_bytes, stats.uploaded_bytes) == (100, 50)
    assert stats.last_attempt_at == LATER and stats.last_success_at == NOW
    assert stats.source == "xray-api"


# Invariant: upsert_unavailable() on a never-polled key creates a zero row that
# is marked unavailable with the reason.
async def test_upsert_unavailable_creates_row(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    # Act
    stats = await repo.upsert_unavailable(key_id=11, reason="timeout", now=NOW, source="xray")

    # Assert
    assert stats.available is False and stats.unavailable_reason == "timeout"
    assert (stats.downloaded_bytes, stats.uploaded_bytes) == (0, 0)


# Invariant: upsert_unavailable() raises if the row cannot be read back.
async def test_upsert_unavailable_raises_when_row_vanishes(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)

    async def _missing(key_id: int) -> None:
        return None

    monkeypatch.setattr(repo, "get_by_key_id", _missing)

    # Act / Assert
    with pytest.raises(RuntimeError, match="unavailable upsert failed"):
        await repo.upsert_unavailable(key_id=10, reason="r", now=NOW, source="xray")


# Invariant: prune_hourly() deletes exactly the buckets outside the retention
# window (boundary: current - days*24 is deleted, current - days*24 + 1 kept) and
# returns the number removed.
async def test_prune_hourly_boundary(db: Database) -> None:
    # Arrange
    cutoff = HOUR - TRAFFIC_HOURLY_RETENTION_DAYS * 24
    for hour in (cutoff - 5, cutoff, cutoff + 1, HOUR):
        await db.conn.execute(
            "INSERT INTO traffic_hourly (hour_utc, key_id, protocol, downloaded_bytes, uploaded_bytes) "
            "VALUES (?, 10, 'xray', 1, 1)",
            (hour,),
        )
    await db.commit()
    repo = TrafficStatsRepository(db)

    # Act
    removed = await repo.prune_hourly(current_hour_utc=HOUR)

    # Assert
    assert removed == 2
    assert [b[0] for b in await _buckets(db)] == [cutoff + 1, HOUR]


# Invariant: prune_hourly() with a custom retention honours it, and on an empty
# table returns 0.
async def test_prune_hourly_custom_retention_and_empty(db: Database) -> None:
    # Arrange
    repo = TrafficStatsRepository(db)
    empty_removed = await repo.prune_hourly(current_hour_utc=HOUR)
    await db.conn.execute(
        "INSERT INTO traffic_hourly (hour_utc, key_id, protocol, downloaded_bytes, uploaded_bytes) "
        "VALUES (?, 10, 'xray', 1, 1)",
        (HOUR - 24,),
    )
    await db.commit()

    # Act
    removed = await repo.prune_hourly(current_hour_utc=HOUR, retention_days=1)

    # Assert
    assert empty_removed == 0
    assert removed == 1
