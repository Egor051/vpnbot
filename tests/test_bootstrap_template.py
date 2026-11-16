"""The session bootstrap template (tests/conftest.py::_bootstrap_from_template).

Most tests get their fresh database by copying a template that ONE real bootstrap
produced, instead of running schema.sql + the whole migration chain + indexes.sql
again. That is only sound if the copy is indistinguishable from a real fresh
bootstrap, and if every situation where a test could observe the difference still
runs the real chain. Both halves are pinned here.
"""

from __future__ import annotations

import sqlite3
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import conftest
from db.database import CURRENT_SCHEMA_VERSION, Database


class _RealChain(Database):
    """A subclass is never served from the template: this is a real bootstrap."""


@pytest.fixture
def template_copies(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Records every template copy (the shortcut), without touching anything the
    fingerprint watches — the hook lives in conftest, not in db.database."""
    copies: list[Path] = []
    real = conftest._template_backup_into

    def counting(raw: Any, template: Path) -> Callable[[], None]:
        copies.append(template)
        return real(raw, template)

    monkeypatch.setattr(conftest, "_template_backup_into", counting)
    return copies


async def _fresh(path: Path, cls: type[Database] = Database) -> None:
    db = cls(path)
    await db.connect()
    try:
        await db.bootstrap()
    finally:
        await db.close()


def _describe(path: Path) -> dict[str, Any]:
    conn = sqlite3.connect(path)
    try:
        pragmas = {
            name: conn.execute(f"PRAGMA {name}").fetchone()[0]
            for name in ("journal_mode", "page_size", "user_version", "application_id", "auto_vacuum", "encoding")
        }
        return {"dump": list(conn.iterdump()), "pragmas": pragmas, "mode": stat.S_IMODE(path.stat().st_mode)}
    finally:
        conn.close()


async def test_the_template_copy_equals_a_real_fresh_bootstrap(tmp_path: Path, template_copies: list[Path]) -> None:
    await _fresh(tmp_path / "copy.db")
    assert len(template_copies) == 1, "a fresh default bootstrap must be served from the template"
    await _fresh(tmp_path / "real.db", _RealChain)
    assert len(template_copies) == 1, "a Database subclass must run the real chain"

    copy, real = _describe(tmp_path / "copy.db"), _describe(tmp_path / "real.db")
    assert copy["pragmas"] == real["pragmas"]
    assert copy["pragmas"]["journal_mode"] == "wal"
    assert copy["dump"] == real["dump"]
    assert copy["mode"] == real["mode"] == 0o600
    assert f"INSERT INTO \"schema_meta\" VALUES('schema_version','{CURRENT_SCHEMA_VERSION}');" in copy["dump"]


async def test_the_copy_is_a_normal_writable_database(tmp_path: Path, template_copies: list[Path]) -> None:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    try:
        await db.bootstrap()
        await db.conn.execute("INSERT INTO schema_meta(key, value) VALUES ('probe', 'x')")
        await db.commit()
        await db.bootstrap()  # a second bootstrap on the same file: real, idempotent
    finally:
        await db.close()
    assert len(template_copies) == 1
    conn = sqlite3.connect(tmp_path / "vpn.db")
    try:
        assert conn.execute("SELECT value FROM schema_meta WHERE key = 'probe'").fetchone() == ("x",)
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    finally:
        conn.close()


async def test_a_database_with_anything_in_it_runs_the_real_chain(tmp_path: Path, template_copies: list[Path]) -> None:
    """A copy would wipe what is there; the real chain keeps it."""
    path = tmp_path / "vpn.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE keep_me (x INTEGER)")
    conn.execute("INSERT INTO keep_me VALUES (7)")
    conn.commit()
    conn.close()
    await _fresh(path)
    assert template_copies == []
    conn = sqlite3.connect(path)
    try:
        assert conn.execute("SELECT x FROM keep_me").fetchone() == (7,)
    finally:
        conn.close()


async def test_explicit_schema_files_run_the_real_chain(tmp_path: Path, template_copies: list[Path]) -> None:
    schema = Path(__file__).resolve().parents[1] / "db" / "schema.sql"
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    try:
        await db.bootstrap(schema)
    finally:
        await db.close()
    assert template_copies == []


async def _boom(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("migration exploded")


async def test_a_patched_migration_runs_the_real_chain_and_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, template_copies: list[Path]
) -> None:
    monkeypatch.setattr(Database, f"_migrate_v{CURRENT_SCHEMA_VERSION}", _boom)
    with pytest.raises(RuntimeError, match="migration exploded"):
        await _fresh(tmp_path / "vpn.db")
    assert template_copies == []


async def test_a_patched_module_global_runs_the_real_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, template_copies: list[Path]
) -> None:
    import db.database as db_module

    monkeypatch.setattr(db_module, "CURRENT_SCHEMA_VERSION", CURRENT_SCHEMA_VERSION + 1)
    await _fresh(tmp_path / "vpn.db")
    assert template_copies == []


async def test_an_instance_override_runs_the_real_chain(tmp_path: Path, template_copies: list[Path]) -> None:
    db = Database(tmp_path / "vpn.db")
    setattr(db, f"_migrate_v{CURRENT_SCHEMA_VERSION}", _boom)
    await db.connect()
    try:
        with pytest.raises(RuntimeError, match="migration exploded"):
            await db.bootstrap()
    finally:
        await db.close()
    assert template_copies == []


@pytest.mark.real_bootstrap
async def test_the_marker_opts_out(tmp_path: Path, template_copies: list[Path]) -> None:
    await _fresh(tmp_path / "vpn.db")
    assert template_copies == []


# --------------------------------------------------------------------------- #
# synchronous=NORMAL for test databases (tests/conftest.py::_relaxed_sqlite_sync)
# --------------------------------------------------------------------------- #
def test_the_production_default_stays_full() -> None:
    """The fixture only swaps the DEFAULT for the test session; the shipped default
    (what a bare Database(path) gets on the host) must remain FULL."""
    import inspect

    source = inspect.getsource(Database.__init__)
    assert 'synchronous: str = "FULL"' in source


async def test_a_bare_database_runs_normal_and_an_explicit_value_wins(tmp_path: Path) -> None:
    from conftest import TEST_SQLITE_SYNCHRONOUS

    for path, kwargs, expected in (
        (tmp_path / "bare.db", {}, TEST_SQLITE_SYNCHRONOUS),
        (tmp_path / "full.db", {"synchronous": "FULL"}, "FULL"),
    ):
        db = Database(path, **kwargs)
        await db.connect()
        try:
            cursor = await db.conn.execute("PRAGMA synchronous")
            row = await cursor.fetchone()
        finally:
            await db.close()
        # PRAGMA synchronous reads back 1 for NORMAL, 2 for FULL.
        assert row[0] == {"NORMAL": 1, "FULL": 2}[expected]
