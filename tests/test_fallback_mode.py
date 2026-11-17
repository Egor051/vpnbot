"""The fallback mode (hub) — docs/relay.md «Режим фолбэка».

Schema v46 (relays.role, failover_names) and the failover repository. The service,
the DNS adapter and the screens have their own sections below / files.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import aiosqlite
import pytest

from config import validators
from db.database import CURRENT_SCHEMA_VERSION, Database
from repositories.failover import FailoverRepository
from repositories.relays import RelayRepository

SNAPSHOT_DIR = Path(__file__).resolve().parent / "schema_snapshots"
NOW = "2026-11-17T10:00:00+00:00"


async def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    return db


# ── schema v46 ────────────────────────────────────────────────────────────────


async def test_v45_relays_come_out_as_edges_with_every_value_kept(tmp_path: Path) -> None:
    path = tmp_path / "v45.db"
    async with aiosqlite.connect(path) as conn:
        await conn.executescript((SNAPSHOT_DIR / "v45.sql").read_text(encoding="utf-8"))
        await conn.executescript((SNAPSHOT_DIR / "v45.seed.sql").read_text(encoding="utf-8"))
        await conn.execute("INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '45')")
        await conn.commit()
        conn.row_factory = aiosqlite.Row
        before = [dict(row) for row in await conn.execute_fetchall("SELECT * FROM relays ORDER BY id")]
    db = Database(path)
    await db.connect()
    try:
        await db.bootstrap()
        assert await db.get_meta("schema_version") == str(CURRENT_SCHEMA_VERSION)
        after = [dict(row) for row in await db.conn.execute_fetchall("SELECT * FROM relays ORDER BY id")]
        assert [row.pop("role") for row in after] == ["edge", "edge", "edge"]
        assert after == before
        relays = await RelayRepository(db).list_all()
        assert [(r.name, r.role, r.is_hub) for r in relays] == [
            ("ru1", "edge", False), ("he2", "edge", False), ("manual", "edge", False),
        ]
        assert await FailoverRepository(db).list_names() == []
        assert await FailoverRepository(db).mode_on() is False
    finally:
        await db.close()


async def test_role_is_checked_by_the_database(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        relays = RelayRepository(db)
        relay = await relays.create(
            name="he1", label="he1", host="hub.example.net",
            source_ips=validators.parse_ipv4_networks("s", "203.0.113.9/32"), now=NOW,
        )
        assert relay.role == "edge"
        assert await relays.set_role(relay.id, "hub", now=NOW, updated_by=None) is True
        assert [r.name for r in await relays.list_hubs()] == ["he1"]
        assert (await relays.get_by_id(relay.id)).is_hub  # type: ignore[union-attr]
        with pytest.raises(ValueError):
            await relays.set_role(relay.id, "core", now=NOW, updated_by=None)
        with pytest.raises(sqlite3.IntegrityError):
            await db.conn.execute("UPDATE relays SET role = 'core' WHERE id = ?", (relay.id,))
        await db.rollback()
        assert await relays.set_role(999, "hub", now=NOW, updated_by=None) is False
    finally:
        await db.close()


# ── the failover repository ───────────────────────────────────────────────────


async def test_names_are_unique_and_keep_what_the_last_write_did(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        repo = FailoverRepository(db)
        first = await repo.add_name("example.net", now=NOW, created_by=None)
        assert first is not None and first.applied is None
        assert await repo.add_name("example.net", now=NOW, created_by=None) is None
        second = await repo.add_name("relay.example.net", now=NOW, created_by=None)
        assert second is not None
        await repo.record_error(first.id, "boom " * 200)
        stored = await repo.get_name(first.id)
        assert stored is not None and stored.applied is None and len(stored.last_error or "") == 300
        await repo.record_applied(first.id, applied="failover", ipv4="203.0.113.9", now=NOW)
        stored = await repo.get_name(first.id)
        assert stored is not None
        assert (stored.applied, stored.applied_ipv4, stored.applied_at, stored.last_error) == (
            "failover", "203.0.113.9", NOW, None,
        )
        with pytest.raises(ValueError):
            await repo.record_applied(first.id, applied="sideways", ipv4="1.2.3.4", now=NOW)
        assert [n.name for n in await repo.list_names()] == ["example.net", "relay.example.net"]
        removed = await repo.remove_name(second.id)
        assert removed is not None and removed.name == "relay.example.net"
        assert await repo.remove_name(second.id) is None
    finally:
        await db.close()


async def test_runtime_settings_default_off(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        repo = FailoverRepository(db)
        assert (await repo.mode_on(), await repo.sub_fallback_url(), await repo.direct_host()) == (False, False, None)
        await repo.set_mode(True, now=NOW)
        assert await repo.mode_on() is True
        assert await repo.mode_changed_at() == NOW
        await repo.set_setting("failover_sub_fallback_url", "1")
        await repo.set_setting("failover_direct_host", " example.net ")
        assert await repo.sub_fallback_url() is True
        assert await repo.direct_host() == "example.net"
        assert await repo.get_setting("failover_main_ipv4") == ""
        await repo.set_mode(False, now=NOW)
        assert await repo.mode_on() is False
    finally:
        await db.close()
