"""Shared pytest fixtures for CLI and integration tests."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import re
import sys
from collections.abc import Callable, Generator
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple

import aiosqlite
import pytest

ROOT = Path(__file__).resolve().parents[1]

# Prod env-var families the settings loader reads. In tests a Settings build must
# come only from what the test sets explicitly (monkeypatch.setenv or an explicit
# env_path), NEVER from the host's ambient environment or the production
# /opt/vpn-service/.env that python-dotenv would auto-discover from the cwd. See
# _isolate_settings_env below. ANOMALY_ is included because
# ANOMALY_HYSTERIA2_MAX_CONN cross-validates against HYSTERIA2_STATS_SECRET (a
# Hysteria2-family value) — the two must be cleared together or a leaked
# HYSTERIA2_STATS_SECRET-less-but-ANOMALY_HYSTERIA2_MAX_CONN-set combination raises
# a spurious SettingsError.
_ISOLATED_ENV_PREFIXES: tuple[str, ...] = (
    "HYSTERIA2_",
    "SOCKS5_",
    "XRAY_",
    "MTPROTO_",
    "WARP_",
    "ANOMALY_",
    # SUBSCRIPTION_* for the same reason: the box's live .env sets the endpoint's
    # bind/TLS values, and a test asserting the documented defaults would read the
    # host's ports instead (green in CI, red on the box).
    "SUBSCRIPTION_",
)


@pytest.fixture(autouse=True)
def _isolate_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Settings construction deterministic and host-independent.

    Two leaks, both a host-only class (cf. #239/#241/#242 — green in clean CI, red
    on the box, because the box's live state bleeds in):

    1. ``load_settings()`` with no explicit path calls ``load_dotenv(None)``, which
       walks up from the cwd (``/opt/vpn-service`` in the test run) and slurps the
       **production** ``.env`` into ``os.environ`` — so a test that carefully
       ``delenv``'d ``SOCKS5_ENABLED`` gets it (and every other prod value) handed
       right back. We block ONLY dotenv auto-discovery: an **explicit** ``env_path``
       (used by tests that genuinely exercise .env-file parsing) is still honoured.
       ``hy2_auth/config.py`` has its own independent ``load_dotenv()`` call (it
       cannot import config.settings — see its module docstring) and must be
       blocked the same way, or a single test that reaches it (e.g.
       ``test_hy2_auth.py``) permanently pollutes ``os.environ`` with the live
       ``.env`` for every test that runs afterward in the same session — this is
       exactly how ``ANOMALY_HYSTERIA2_MAX_CONN``/``HYSTERIA2_STATS_SECRET`` from
       the box's real ``.env`` were observed leaking into unrelated later tests.

    2. Any of the prod control-var families already exported in the ambient
       environment would likewise leak. We strip them up-front so each test starts
       from the documented defaults.

    This is deliberately narrow. It does NOT stop the loader from reading the
    environment: a test that sets a var (this autouse fixture runs *before* the
    test body's ``monkeypatch.setenv``) still sees it, so "the loader reads X from
    the environment" tests keep their teeth.
    """
    for key in list(os.environ):
        if key.startswith(_ISOLATED_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)

    import dotenv

    real_dotenv_load_dotenv = dotenv.load_dotenv

    def _no_autodiscovery_load_dotenv(dotenv_path: Any = None, *args: Any, **kwargs: Any) -> bool:
        # Falsy path == python-dotenv auto-discovery (the prod-.env leak): no-op,
        # mirroring load_dotenv's "nothing loaded" return. An explicit path is
        # forwarded to the real loader untouched.
        if not dotenv_path:
            return False
        return bool(real_dotenv_load_dotenv(dotenv_path, *args, **kwargs))

    # Patch every module-local `load_dotenv` name bound via `from dotenv import
    # load_dotenv` — patching the `dotenv` package attribute alone would not reach
    # these, since `from ... import ...` copies the reference at import time.
    import config.settings as settings_module
    import hy2_auth.config as hy2_auth_config_module

    monkeypatch.setattr(settings_module, "load_dotenv", _no_autodiscovery_load_dotenv)
    monkeypatch.setattr(hy2_auth_config_module, "load_dotenv", _no_autodiscovery_load_dotenv)


def _load_module(module_name: str, path: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@contextlib.contextmanager
def _capture_stdout() -> Generator[io.StringIO, None, None]:
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old_stdout


@pytest.fixture
def checker() -> ModuleType:
    """Load check-nonroot-helper-mode.py CLI script as a fresh module per test."""
    return _load_module("check_nonroot", ROOT / "deploy" / "check-nonroot-helper-mode.py")


@pytest.fixture
def load_helper() -> Callable[[str], ModuleType]:
    """Factory fixture: call with a helper script name to get a fresh module."""
    def _load(name: str) -> ModuleType:
        return _load_module(name.replace("-", "_"), ROOT / "deploy" / "helpers" / name)
    return _load


@pytest.fixture
def captured_cli_output() -> Callable[[], contextlib.AbstractContextManager[io.StringIO]]:
    """Fixture providing a context manager that captures sys.stdout during CLI calls."""
    return _capture_stdout


@pytest.fixture(autouse=True)
def _isolate_i18n_locale() -> Generator[None, None, None]:
    """Restore global i18n locale state after every test.

    ``i18n.configure()`` mutates the process-wide default locale (a module global)
    and ``i18n.set_locale()`` mutates a ContextVar; tests that switch locale would
    otherwise leak that choice into later tests via collection order. Snapshot the
    default on entry and reset both on teardown so each test starts from a clean,
    order-independent locale state.
    """
    import i18n

    default_before = i18n._default_locale
    try:
        yield
    finally:
        i18n._default_locale = default_before
        i18n._current_locale.set(None)


async def wait_until_lock_contended(lock: asyncio.Lock, *, timeout: float = 5.0) -> None:
    """Wait until ``lock`` is held and at least one task is waiting to acquire it,
    then return.

    Preferred over ``await asyncio.sleep(0.05); assert not task.done()``: it
    returns the instant the contended state is observed (lock held + a waiter
    present), which is race-free, and only ever blocks until that happens.

    A launched task parks on ``lock.acquire()`` only after any *preceding* awaits
    resolve. Some of those awaits (e.g. aiosqlite queries) complete on a worker
    thread and therefore need wall-clock time, not just event-loop turns — so a
    fixed number of ``asyncio.sleep(0)`` spins can exhaust its budget in
    microseconds before the thread finishes and the task ever reaches the lock,
    which made this flaky on loaded CI runners. Poll against a wall-clock
    ``timeout`` instead, yielding briefly between checks. Raises if no task parks
    within ``timeout`` seconds.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if lock.locked() and lock._waiters:  # type: ignore[attr-defined]
            return
        if loop.time() >= deadline:
            raise AssertionError("no task parked on the lock")
        await asyncio.sleep(0.001)


async def wait_until_write_parked(db: object, *, timeout: float = 5.0) -> None:
    """Convenience wrapper: wait until a competing write/read has parked on the
    ``Database`` transaction serialization lock."""
    await wait_until_lock_contended(db._transaction_lock, timeout=timeout)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Schema shape helpers
#
# One definition of "what a database looks like", shared by the two schema
# guards: test_schema_drift.py (fresh bootstrap vs the SQL files) and
# test_schema_upgrade_path.py (an old snapshot upgraded through bootstrap vs a
# fresh bootstrap). Both compare SchemaShape values, so a divergence either
# construction path can produce is caught by whichever guard sees it first.
# --------------------------------------------------------------------------- #
class SchemaShape(NamedTuple):
    """Everything the schema guards compare between two databases.

    tables:  user table names.
    columns: table -> column name -> (type, notnull, default, pk). Keyed by column
             NAME so a legitimate column-ORDER divergence (an ALTER appends at the
             end while schema.sql lists the column mid-table — e.g. spider_x,
             bundle_id) is not treated as drift, while any type / nullability /
             default / primary-key difference still is.
    fks:     table -> {(from_col, parent_table, to_col, on_update, on_delete)}, a
             SET so ON DELETE actions (e.g. bundle_id RESTRICT vs user_id CASCADE)
             are compared regardless of the order SQLite reports them in.
    indexes: index name -> (unique, partial, columns). Compared structurally rather
             than by sqlite_master SQL text, because the same index is created by
             different statements on different paths (a table-rebuild migration
             re-creates it with its own formatting), and the whitespace difference
             is not drift.
    checks:  table -> {normalised CHECK expression}. No PRAGMA exposes CHECK
             constraints, so these come out of the sqlite_master DDL — and they
             have to be compared, because a CHECK is the one part of a table that
             ONLY a full rebuild can change. A migration that widens an enum in
             schema.sql but forgets the rebuild leaves every column, foreign key
             and index identical and still rejects the new value at INSERT time,
             which is exactly how the Hysteria2 trial button stayed broken.
    """

    tables: frozenset[str]
    columns: dict[str, dict[str, tuple[str, int, object, int]]]
    fks: dict[str, set[tuple[str, str, str, str, str]]]
    indexes: dict[str, tuple[int, int, tuple[str, ...]]]
    checks: dict[str, frozenset[str]]


async def table_names(conn: aiosqlite.Connection) -> frozenset[str]:
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    return frozenset(str(row[0]) for row in await cursor.fetchall())


async def named_indexes(conn: aiosqlite.Connection) -> set[str]:
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
    )
    return {str(row[0]) for row in await cursor.fetchall()}


async def column_details(
    conn: aiosqlite.Connection, table: str
) -> dict[str, tuple[str, int, object, int]]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    return {
        str(row[1]): (str(row[2]).upper(), int(row[3]), row[4], int(row[5]))
        for row in await cursor.fetchall()
    }


async def foreign_keys(conn: aiosqlite.Connection, table: str) -> set[tuple[str, str, str, str, str]]:
    cursor = await conn.execute(f"PRAGMA foreign_key_list({table})")
    return {
        (str(row[3]), str(row[2]), str(row[4]), str(row[5]), str(row[6]))
        for row in await cursor.fetchall()
    }


async def index_details(
    conn: aiosqlite.Connection, tables: frozenset[str]
) -> dict[str, tuple[int, int, tuple[str, ...]]]:
    details: dict[str, tuple[int, int, tuple[str, ...]]] = {}
    for table in tables:
        cursor = await conn.execute(f"PRAGMA index_list({table})")
        for row in await cursor.fetchall():
            name = str(row[1])
            if not name.startswith("idx_"):
                continue  # sqlite_autoindex_* — implied by UNIQUE/PK, not our DDL
            info = await conn.execute(f"PRAGMA index_info({name})")
            # index_list columns: (seq, name, unique, origin, partial). An
            # expression index reports NULL column names, which str() renders as
            # 'None' — stable across both construction paths.
            columns = tuple(str(col[2]) for col in await info.fetchall())
            details[name] = (int(row[2]), int(row[4]), columns)
    return details


_SQL_COMMENT = re.compile(r"--[^\n]*")
_SQL_WHITESPACE = re.compile(r"\s+")


def _normalise_check(body: str) -> str:
    """Strip formatting from a CHECK body so only its meaning is compared.

    The same constraint is written differently on the two construction paths —
    schema.sql indents it, a rebuild migration inlines it — and that difference
    is not drift.
    """
    body = _SQL_WHITESPACE.sub(" ", body).strip()
    return re.sub(r"\s*([(),])\s*", r"\1", body)


def _table_checks(create_sql: str) -> frozenset[str]:
    """Every CHECK expression in a CREATE TABLE statement, normalised.

    Parses the parentheses rather than regexing the body, so a nested one
    (``CHECK(x IN ('a','b'))``) is captured whole instead of cut at its first
    closing bracket.
    """
    sql = _SQL_COMMENT.sub(" ", create_sql or "")
    checks: list[str] = []
    for match in re.finditer(r"\bCHECK\s*\(", sql, re.IGNORECASE):
        start = match.end() - 1
        depth = 0
        for pos in range(start, len(sql)):
            if sql[pos] == "(":
                depth += 1
            elif sql[pos] == ")":
                depth -= 1
                if depth == 0:
                    checks.append(_normalise_check(sql[start + 1 : pos]))
                    break
    return frozenset(checks)


async def table_checks(conn: aiosqlite.Connection, tables: frozenset[str]) -> dict[str, frozenset[str]]:
    cursor = await conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    found = {str(row[0]): _table_checks(str(row[1] or "")) for row in await cursor.fetchall()}
    return {table: found.get(table, frozenset()) for table in tables}


async def schema_shape(conn: aiosqlite.Connection) -> SchemaShape:
    tables = await table_names(conn)
    return SchemaShape(
        tables=tables,
        columns={table: await column_details(conn, table) for table in tables},
        fks={table: await foreign_keys(conn, table) for table in tables},
        indexes=await index_details(conn, tables),
        checks=await table_checks(conn, tables),
    )


def assert_same_shape(actual: SchemaShape, expected: SchemaShape, context: str) -> None:
    """Compare two shapes field by field, failing on the smallest difference first
    so the message names the table/index at fault instead of dumping both schemas."""
    assert actual.tables == expected.tables, f"{context}: table set differs"
    for table in sorted(expected.tables):
        assert actual.columns[table] == expected.columns[table], f"{context}: column drift in {table}"
        assert actual.fks[table] == expected.fks[table], f"{context}: foreign-key drift in {table}"
        assert actual.checks[table] == expected.checks[table], f"{context}: CHECK drift in {table}"
    assert set(actual.indexes) == set(expected.indexes), f"{context}: index set differs"
    for name in sorted(expected.indexes):
        assert actual.indexes[name] == expected.indexes[name], f"{context}: index {name} differs"
