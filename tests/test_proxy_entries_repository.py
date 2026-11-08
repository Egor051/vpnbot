"""ProxyRepository against a real bootstrapped SQLite database.

Every test runs on a fresh ``Database`` in ``tmp_path`` built by the production
``bootstrap()`` (schema.sql + migrations + indexes.sql), so the CHECK constraints,
defaults and AUTOINCREMENT behaviour asserted here are the ones the bot ships.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from db.database import Database
from models.enums import ProxyStatus
from repositories.proxy_entries import ProxyRepository

NOW = "2026-01-01T00:00:00+00:00"
LATER = "2026-01-02T00:00:00+00:00"


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "vpn.db")
    await database.connect()
    await database.bootstrap()
    try:
        yield database
    finally:
        await database.close()


async def _insert_raw(db: Database, *, host: str, status: str) -> int:
    cursor = await db.conn.execute(
        """
        INSERT INTO proxy_entries (proxy_type, host, port, login, password, note, status, created_at, updated_at)
        VALUES ('socks5', ?, 1080, NULL, NULL, NULL, ?, ?, ?)
        """,
        (host, status, NOW, NOW),
    )
    await db.commit()
    assert cursor.lastrowid is not None
    return int(cursor.lastrowid)


# Invariant: create() persists every field verbatim, forces status=ACTIVE and
# stamps created_at == updated_at == now, and returns the row as re-read from disk.
async def test_create_round_trips_all_fields(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)

    # Act
    entry = await repo.create("http", "proxy.example", 3128, "alice", "s3cret", "office", NOW)

    # Assert
    assert entry.id > 0
    assert (entry.proxy_type, entry.host, entry.port) == ("http", "proxy.example", 3128)
    assert (entry.login, entry.password, entry.note) == ("alice", "s3cret", "office")
    assert entry.status is ProxyStatus.ACTIVE
    assert entry.created_at == entry.updated_at == NOW
    assert await repo.get_by_id(entry.id) == entry


# Invariant: anonymous proxies (no login/password/note) are stored as NULLs and
# read back as None, not as empty strings.
async def test_create_keeps_optional_credentials_null(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)

    # Act
    entry = await repo.create("socks5", "10.0.0.1", 1080, None, None, None, NOW)

    # Assert
    assert (entry.login, entry.password, entry.note) == (None, None, None)


# Invariant: the password is an upstream credential and never appears in repr(),
# so logging a ProxyEntry cannot leak it.
async def test_entry_repr_redacts_password(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)

    # Act
    entry = await repo.create("socks5", "h", 1, "u", "do-not-log-me", None, NOW)

    # Assert
    assert "do-not-log-me" not in repr(entry)


# Invariant: get_by_id() returns None for an id that does not exist instead of
# raising.
async def test_get_by_id_missing_returns_none(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)

    # Act
    result = await repo.get_by_id(424242)

    # Assert
    assert result is None


# Invariant: get_by_id() does NOT filter by status — a disabled entry is still
# returned so the caller can decide (documented contract).
async def test_get_by_id_returns_disabled_entries(db: Database) -> None:
    # Arrange
    proxy_id = await _insert_raw(db, host="off.example", status="disabled")

    # Act
    entry = await ProxyRepository(db).get_by_id(proxy_id)

    # Assert
    assert entry is not None
    assert entry.status is ProxyStatus.DISABLED


# Invariant: list_active() returns only ACTIVE rows, ordered by id ascending,
# and skips disabled ones wherever they sit in the id sequence.
async def test_list_active_filters_and_orders_by_id(db: Database) -> None:
    # Arrange
    first = await _insert_raw(db, host="a", status="active")
    await _insert_raw(db, host="b", status="disabled")
    third = await _insert_raw(db, host="c", status="active")

    # Act
    entries = await ProxyRepository(db).list_active()

    # Assert
    assert [e.id for e in entries] == [first, third]
    assert all(e.status is ProxyStatus.ACTIVE for e in entries)


# Invariant: list_active() paginates with LIMIT/OFFSET over the active subset.
async def test_list_active_paginates(db: Database) -> None:
    # Arrange
    ids = [await _insert_raw(db, host=f"h{i}", status="active") for i in range(5)]
    repo = ProxyRepository(db)

    # Act
    page = await repo.list_active(limit=2, offset=2)

    # Assert
    assert [e.id for e in page] == ids[2:4]


# Invariant: out-of-range pagination arguments are clamped (negative limit -> 0
# rows, negative offset -> 0, huge limit -> capped) instead of reaching SQLite as
# "LIMIT -1" (which SQLite reads as "unbounded").
async def test_list_active_clamps_pagination(db: Database) -> None:
    # Arrange
    ids = [await _insert_raw(db, host=f"h{i}", status="active") for i in range(3)]
    repo = ProxyRepository(db)

    # Act
    negative_limit = await repo.list_active(limit=-1)
    negative_offset = await repo.list_active(limit=10, offset=-5)
    huge_limit = await repo.list_active(limit=10**9)

    # Assert
    assert negative_limit == []
    assert [e.id for e in negative_offset] == ids
    assert [e.id for e in huge_limit] == ids


# Invariant: count() counts every row regardless of status, and is 0 on an
# empty table.
async def test_count_includes_all_statuses(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)
    empty = await repo.count()
    await _insert_raw(db, host="a", status="active")
    await _insert_raw(db, host="b", status="disabled")

    # Act
    total = await repo.count()

    # Assert
    assert empty == 0
    assert total == 2


# Invariant: update_note() rewrites only note and updated_at; it can also clear
# the note back to NULL, and created_at is never touched.
async def test_update_note_sets_and_clears(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)
    entry = await repo.create("socks5", "h", 1, None, None, "old", NOW)

    # Act
    await repo.update_note(entry.id, "new", LATER)
    after_set = await repo.get_by_id(entry.id)
    await repo.update_note(entry.id, None, LATER)
    after_clear = await repo.get_by_id(entry.id)

    # Assert
    assert after_set is not None and after_clear is not None
    assert (after_set.note, after_set.updated_at, after_set.created_at) == ("new", LATER, NOW)
    assert after_clear.note is None


# Invariant: update_note() on a missing id is a silent no-op (no row is created).
async def test_update_note_missing_id_is_noop(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)

    # Act
    await repo.update_note(999, "ghost", LATER)

    # Assert
    assert await repo.count() == 0


# Invariant: the schema CHECK rejects an unknown proxy_type at INSERT time, so
# create() cannot persist a type the rest of the bot does not understand.
async def test_create_rejects_unknown_proxy_type(db: Database) -> None:
    # Arrange
    repo = ProxyRepository(db)

    # Act / Assert
    with pytest.raises(Exception, match="CHECK constraint failed"):
        await repo.create("ftp", "h", 21, None, None, None, NOW)


# Invariant: a row whose status is outside ProxyStatus (on-disk corruption that
# bypassed the CHECK) surfaces as a RuntimeError naming the column, never as a
# silently mis-typed entry.
async def test_corrupted_status_raises_runtime_error(db: Database) -> None:
    # Arrange
    await db.conn.execute("PRAGMA ignore_check_constraints = ON")
    proxy_id = await _insert_raw(db, host="bad", status="exploded")
    await db.conn.execute("PRAGMA ignore_check_constraints = OFF")

    # Act / Assert
    with pytest.raises(RuntimeError, match="proxy_entries.status"):
        await ProxyRepository(db).get_by_id(proxy_id)
