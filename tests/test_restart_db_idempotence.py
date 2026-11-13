"""A restart with nothing to change must leave vpn.db byte-for-byte as it was.

scripts/install.sh repairs an existing install by reinstalling the unit and
restarting the bot, and its CI job proves the repair never touches the database by
comparing sha256 before and after. That only means something if the bot's own
startup does not write either. It used to, every time:

* db/schema.sql seeded warp_split_sources with INSERT OR IGNORE — in an
  AUTOINCREMENT table an ignored insert still advances sqlite_sequence;
* WarpSettingsRepository.reset_runtime() rewrote updated_at even when every
  runtime column was already zero.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from db.database import Database
from repositories.warp_settings import WarpSettingsRepository


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _start_and_stop(path: Path) -> None:
    """What bot startup does to the DB on a host with nothing to change."""
    db = Database(path)
    await db.connect()
    try:
        await db.bootstrap()
        await WarpSettingsRepository(db).reset_runtime()
    finally:
        await db.close()


async def test_second_start_leaves_the_database_byte_identical(tmp_path: Path) -> None:
    path = tmp_path / "vpn.db"
    await _start_and_stop(path)
    first = _sha256(path)

    await _start_and_stop(path)
    await _start_and_stop(path)

    assert _sha256(path) == first


async def _seed_state(path: Path) -> tuple[list[str], int]:
    db = Database(path)
    await db.connect()
    try:
        slugs = await db.conn.execute_fetchall("SELECT slug FROM warp_split_sources ORDER BY id")
        seq = await db.conn.execute_fetchone("SELECT seq FROM sqlite_sequence WHERE name = 'warp_split_sources'")
    finally:
        await db.close()
    assert seq is not None
    return [str(row["slug"]) for row in slugs], int(seq["seq"])


async def test_seed_rows_exist_and_restarts_do_not_burn_autoincrement_ids(tmp_path: Path) -> None:
    path = tmp_path / "vpn.db"
    await _start_and_stop(path)
    slugs, seq_after_first_start = await _seed_state(path)

    await _start_and_stop(path)
    await _start_and_stop(path)

    assert slugs == ["telegram-cidr", "google-goog", "google-cloud"]
    assert await _seed_state(path) == (slugs, seq_after_first_start)


async def test_a_deleted_seed_source_comes_back_like_before(tmp_path: Path) -> None:
    """The guarded seed keeps INSERT OR IGNORE's behaviour: a missing seed row is re-added."""
    path = tmp_path / "vpn.db"
    await _start_and_stop(path)
    db = Database(path)
    await db.connect()
    try:
        await db.conn.execute("DELETE FROM warp_split_sources WHERE slug = 'google-goog'")
        await db.commit()
    finally:
        await db.close()

    await _start_and_stop(path)

    db = Database(path)
    await db.connect()
    try:
        row = await db.conn.execute_fetchone("SELECT 1 AS found FROM warp_split_sources WHERE slug = 'google-goog'")
    finally:
        await db.close()
    assert row is not None


async def test_reset_runtime_still_zeroes_a_dirty_row(tmp_path: Path) -> None:
    path = tmp_path / "vpn.db"
    db = Database(path)
    await db.connect()
    try:
        await db.bootstrap()
        repo = WarpSettingsRepository(db)
        await repo.update_runtime(
            tunnel_up=True, routes_active=True, fail_streak=2, success_streak=5, last_handshake=9, last_check_ts=7
        )
        await repo.reset_runtime()
        state = await repo.get()
    finally:
        await db.close()
    assert (state.tunnel_up, state.routes_active, state.fail_streak) == (False, False, 0)
