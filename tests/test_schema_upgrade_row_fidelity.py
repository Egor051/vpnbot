"""Upgrade path, row by row: every pre-existing row survives bootstrap() unchanged.

test_schema_upgrade_path.py proves an old database comes out of bootstrap()
with the CURRENT schema and no FEWER rows. That leaves two holes this module
closes:

* Most snapshots (v29, v30, v31, v33, v35) have no seed, so their whole
  migration chain — including the v36 trial_key_requests rebuild and the v30
  backfill — only ever ran against EMPTY tables. A migration that only works on
  an empty table is exactly the class of #269 (green CI on a fresh DB, crash on
  the box).
* A row count cannot see a row whose VALUES changed: a rebuild that swapped two
  columns, an INSERT OR REPLACE that reset an operator's setting, a backfill that
  overwrote instead of filling NULLs — all keep the count.

For every snapshot version this loads the historical DDL (+ its seed, if any),
adds one realistic dataset touching every table that exists at that version,
runs the production bootstrap() and then asserts: the version is
CURRENT_SCHEMA_VERSION; every row is still there under its primary key; every
column the row had before still holds the same value; the columns migrations
added carry their documented values; and the database passes integrity and
foreign-key checks. A second bootstrap must leave the data byte-identical.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import aiosqlite
import pytest
from test_schema_upgrade_path import _materialise, _snapshot_versions

from db.database import CURRENT_SCHEMA_VERSION, Database

Row = dict[str, Any]
TableRows = dict[tuple[Any, ...], Row]
T0 = "2025-06-01T00:00:00+00:00"

# One dataset, written against the newest column set and inserted with whatever
# subset of columns the table has at the snapshot's version. Ids live in the 5xxx
# range so they never collide with the hand-written .seed.sql files.
DATASET: list[tuple[str, Row]] = [
    ("users", {"telegram_user_id": 5001, "username": "fid_owner", "first_name": "Owner", "role": "SUPERADMIN",
               "created_at": T0, "updated_at": T0}),
    ("users", {"telegram_user_id": 5002, "username": "fid_member", "first_name": "Ann", "role": "APPROVED_USER",
               "created_at": T0, "updated_at": T0, "note": "vip", "language": "en",
               "trial_quota_reset_at": T0, "expiry_notifications_enabled": 0}),
    ("users", {"telegram_user_id": 5003, "username": None, "first_name": "Blocked", "role": "BLOCKED_USER",
               "created_at": T0, "updated_at": T0, "blocked_at": T0}),
    ("access_requests", {"id": 5301, "telegram_user_id": 5003, "username": None, "status": "approved",
                         "requested_at": T0, "decided_by": 5001, "decided_at": T0, "decision_note": "ok"}),
    ("key_bundles", {"id": 5201, "user_id": 5002, "label": "Fidelity bundle", "note": "n", "status": "active",
                     "token": "tok-fidelity", "created_at": T0, "updated_at": T0,
                     # The repository always writes display_no from v33 on; on an
                     # older snapshot the column is absent and _migrate_v33 must
                     # assign it.
                     "display_no": 6001}),
    ("vpn_keys", {"id": 5101, "owner_user_id": 5002, "username": "fid_member", "key_type": "xray",
                  "status": "active", "note": "laptop", "uuid": "5101aaaa-0000-4000-8000-000000005101",
                  "email_label": "xray_tcp_Fid01", "payload_json": '{"short_id": "ab12", "flow": "x"}',
                  "public_payload_json": '{"email_label": "xray_tcp_Fid01"}', "created_at": T0,
                  "updated_at": T0, "expires_at": "2026-01-01T00:00:00+00:00",
                  "expiry_notified_days": "[7, 3]", "transport": "tcp", "xhttp_profile": "base",
                  "spider_x": "/fid", "created_by": 5001}),
    ("vpn_keys", {"id": 5102, "owner_user_id": 5002, "key_type": "awg", "status": "active",
                  "public_key": "fidelityAwgPublicKey0000000000000000000002=", "client_ip": "10.66.0.2",
                  "payload_json": '{"private_key": "redacted"}', "public_payload_json": "{}",
                  "created_at": T0, "updated_at": T0, "created_by": 5001, "bundle_id": 5201}),
    ("vpn_keys", {"id": 5103, "owner_user_id": 5003, "key_type": "hysteria2", "status": "revoked",
                  "email_label": "hy2_Fid03", "payload_json": "{}", "public_payload_json": "{}",
                  "created_at": T0, "updated_at": T0, "revoked_at": T0, "created_by": 5001, "revoked_by": 5001}),
    ("vpn_keys", {"id": 5104, "owner_user_id": 5002, "key_type": "xray", "status": "deleted",
                  "uuid": "5104aaaa-0000-4000-8000-000000005104", "email_label": "xray_tcp_Fid04",
                  "payload_json": "{}", "public_payload_json": "{}", "created_at": T0, "updated_at": T0,
                  "deleted_at": T0, "created_by": 5001, "deleted_by": 5001}),
    ("vpn_key_traffic_stats", {"key_id": 5101, "downloaded_bytes": 123_456_789, "uploaded_bytes": 9_876,
                               "last_raw_downloaded_bytes": 1000, "last_raw_uploaded_bytes": None,
                               "last_success_at": T0, "last_attempt_at": T0, "available": 1,
                               "unavailable_reason": None, "source": "xray statsquery"}),
    ("vpn_key_traffic_stats", {"key_id": 5102, "downloaded_bytes": 0, "uploaded_bytes": 0, "available": 0,
                               "unavailable_reason": "peer missing", "source": "awg/wg transfer",
                               "last_attempt_at": T0}),
    ("deleted_key_traffic_archive", {"id": 5401, "key_id": 5104, "owner_user_id": 5002, "key_type": "xray",
                                     "downloaded_bytes": 42, "uploaded_bytes": 7, "deleted_at": T0}),
    # Pre-v36 the CHECK only allows xray/awg, so the dataset sticks to those.
    ("trial_key_requests", {"id": 5501, "telegram_user_id": 5002, "key_type": "xray", "status": "approved",
                            "key_id": 5101, "requested_at": T0, "decided_by": 5001, "decided_at": T0}),
    ("trial_key_requests", {"id": 5502, "telegram_user_id": 5003, "key_type": "awg", "status": "rejected",
                            "key_id": None, "requested_at": T0, "decided_by": 5001, "decided_at": T0}),
    ("trial_key_requests", {"id": 5503, "telegram_user_id": 5002, "key_type": "awg", "status": "pending",
                            "requested_at": "2025-06-02T00:00:00+00:00"}),
    ("proxy_entries", {"id": 5601, "proxy_type": "http", "host": "proxy.example", "port": 3128, "login": "u",
                       "password": "p", "note": "office", "status": "disabled", "created_at": T0, "updated_at": T0}),
    ("proxy_accesses", {"id": 5701, "owner_user_id": 5002, "username": "fid_member", "access_type": "socks5",
                        "status": "active", "apply_generation": 4,
                        "payload_json": '{"login": "vpn_socks_5002_ab", "password": "pw"}',
                        "public_payload_json": '{"login": "vpn_socks_5002_ab"}', "created_at": T0,
                        "updated_at": T0, "activated_at": T0, "last_shown_at": T0, "created_by": 5001}),
    ("proxy_accesses", {"id": 5702, "owner_user_id": 5003, "access_type": "mtproto", "status": "revoked",
                        "secret_fingerprint": "fp5702", "payload_json": "{}", "public_payload_json": "{}",
                        "created_at": T0, "updated_at": T0, "revoked_at": T0, "created_by": 5001,
                        "revoked_by": 5001, "reason": "blocked", "error": None}),
    ("audit_log", {"id": 5801, "actor_user_id": 5001, "action": "user_approved", "entity_type": "user",
                   "entity_id": "5002", "details_json": '{"k": 1}', "created_at": T0}),
    ("announcement_batches", {"id": 5901, "actor_user_id": 5001, "from_chat_id": 5001, "message_id": 77,
                              "status": "completed", "total_count": 1, "success_count": 1, "created_at": T0,
                              "updated_at": T0, "completed_at": T0}),
    ("announcement_deliveries", {"announcement_id": 5901, "user_id": 5002, "status": "sent", "created_at": T0,
                                 "updated_at": T0}),
    # Operator state on singleton / seeded tables. schema.sql re-seeds these with
    # INSERT OR IGNORE on every start — an INSERT OR REPLACE there would reset them.
    ("protocol_modules", {"name": "awg", "enabled": 0, "disabled_at": T0, "disabled_by": 5001}),
    ("warp_settings", {"id": 1, "enabled": 1, "config_path": "/etc/amnezia/custom.conf",
                       "interface_name": "out-warp", "routes_count": 7, "kill_switch": 1,
                       # update_config() always sets it from v30 on; on v29 the column
                       # is absent and the v30 backfill must derive it from routes_count.
                       "config_installed": 1}),
    ("server_status_settings", {"id": 1, "detailed_enabled": 1, "updated_at": 11}),
    ("maintenance_settings", {"id": 1, "enabled": 1, "message": "back soon", "started_at": 12,
                              "started_by": 5001, "updated_at": 12}),
    ("warp_split_sources", {"slug": "telegram-cidr", "title": "Telegram (operator renamed)",
                            "url": "https://core.telegram.org/resources/cidr.txt", "kind": "cidr_text",
                            "mode": "add", "enabled": 0, "include_in_list": 1, "prefix_count": 13}),
    ("warp_split_prefixes", {"origin": "fidelity-manual", "prefix": "192.0.2.128/25", "added_at": 99}),
    ("warp_split_exclusions", {"prefix": "192.0.2.64/26", "created_at": 98}),
    ("warp_split_baseline", {"scope": "list", "addresses": 256, "prefixes": 1, "list_hash": "h", "applied_ts": 97}),
    ("warp_split_runs", {"id": 5951, "ts": 96, "mode": "auto", "decision": "applied"}),
    ("relays", {"id": 5961, "name": "fid1", "label": "fid", "host": "relay.example", "source_ips": "192.0.2.7",
                "created_at": T0, "updated_at": T0, "created_by": 5001}),
    ("traffic_hourly", {"hour_utc": 490_000, "key_id": 5101, "protocol": "xray", "downloaded_bytes": 5,
                        "uploaded_bytes": 6}),
]


async def _columns(conn: aiosqlite.Connection, table: str) -> list[str]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    return [str(row[1]) for row in await cursor.fetchall()]


async def _pk_columns(conn: aiosqlite.Connection, table: str) -> list[str]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    pk = sorted((int(row[5]), str(row[1])) for row in await cursor.fetchall() if int(row[5]) > 0)
    return [name for _, name in pk]


# Singleton / seeded tables: the version's .seed.sql may already hold the row,
# so the dataset's operator state replaces it. Nothing references these tables,
# so REPLACE cannot cascade.
_STATE_TABLES = frozenset(
    {"protocol_modules", "warp_settings", "server_status_settings", "maintenance_settings", "warp_split_sources"}
)


async def _seed_dataset(db_path: Path) -> set[str]:
    """Insert DATASET with the columns this version has; return the tables touched."""
    touched: set[str] = set()
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        for table, row in DATASET:
            columns = set(await _columns(conn, table))
            if not columns:
                continue  # the table does not exist yet at this version
            data = {key: value for key, value in row.items() if key in columns}
            names = ", ".join(data)
            marks = ", ".join("?" for _ in data)
            verb = "INSERT OR REPLACE" if table in _STATE_TABLES else "INSERT"
            await conn.execute(f"{verb} INTO {table} ({names}) VALUES ({marks})", tuple(data.values()))  # noqa: S608
            touched.add(table)
        await conn.commit()
    return touched


async def _dump(db_path: Path) -> dict[str, TableRows]:
    """Every row of every user table, keyed by primary key (rowid when none)."""
    dump: dict[str, TableRows] = {}
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        cursor = await conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
        for (table,) in [tuple(r) for r in await cursor.fetchall()]:
            pk = await _pk_columns(conn, table)
            select = "*" if pk else "rowid AS __rowid__, *"
            rows = await (await conn.execute(f"SELECT {select} FROM {table}")).fetchall()  # noqa: S608
            key_cols = pk or ["__rowid__"]
            dump[table] = {tuple(r[c] for c in key_cols): dict(r) for r in rows}
    return dump


async def _bootstrap(db_path: Path) -> int:
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
        row = await db.conn.execute_fetchone("SELECT value FROM schema_meta WHERE key = 'schema_version'")
        assert row is not None
        return int(row["value"])
    finally:
        await db.close()


def _diff(before: dict[str, TableRows], after: dict[str, TableRows]) -> list[str]:
    """Human-readable list of every lost row and every changed pre-existing value."""
    problems: list[str] = []
    for table, rows in before.items():
        if table == "schema_meta":
            continue  # schema_version is SUPPOSED to change
        after_rows = after.get(table)
        if after_rows is None:
            problems.append(f"table {table} disappeared")
            continue
        for key, old in rows.items():
            new = after_rows.get(key)
            if new is None:
                problems.append(f"{table}{key}: row lost")
                continue
            for column, value in old.items():
                if column in new and new[column] != value:
                    problems.append(f"{table}{key}.{column}: {value!r} -> {new[column]!r}")
    return problems


async def _prepare(tmp_path: Path, version: int) -> tuple[Path, set[str], dict[str, TableRows]]:
    db_path = tmp_path / f"v{version}.db"
    await _materialise(db_path, version)
    touched = await _seed_dataset(db_path)
    before = await _dump(db_path)
    return db_path, touched, before


# Invariant: the harness exercises at least three historical versions,
# including the oldest one captured — "3+ old schema versions" is enforced, not
# hoped for.
def test_fidelity_harness_covers_three_or_more_versions() -> None:
    # Arrange
    versions = _snapshot_versions()

    # Act
    old_versions = [v for v in versions if v < CURRENT_SCHEMA_VERSION]

    # Assert
    assert len(old_versions) >= 3
    assert min(old_versions) == 29


# Invariant: for every historical version, bootstrap() reaches
# CURRENT_SCHEMA_VERSION on a POPULATED database and every pre-existing row
# keeps every value it had — no row lost, no column rewritten.
@pytest.mark.parametrize("version", _snapshot_versions())
async def test_upgrade_preserves_every_row_and_value(tmp_path: Path, version: int) -> None:
    # Arrange
    db_path, touched, before = await _prepare(tmp_path, version)

    # Act
    after_version = await _bootstrap(db_path)
    after = await _dump(db_path)

    # Assert
    assert after_version == CURRENT_SCHEMA_VERSION
    assert {"users", "vpn_keys", "trial_key_requests", "proxy_accesses", "warp_settings"} <= touched
    problems = _diff(before, after)
    assert not problems, f"v{version} -> v{CURRENT_SCHEMA_VERSION}:\n" + "\n".join(problems)


# Invariant: the columns migrations ADD to existing rows carry their documented
# values — relay NULL (a direct key), bundle kind 'extended', a display_no for
# every bundle (unique), config_installed backfilled from routes_count, and no
# uninstall markers.
@pytest.mark.parametrize("version", _snapshot_versions())
async def test_upgrade_fills_added_columns_as_documented(tmp_path: Path, version: int) -> None:
    # Arrange
    db_path, _, before = await _prepare(tmp_path, version)

    # Act
    await _bootstrap(db_path)
    after = await _dump(db_path)

    # Assert
    keys = after["vpn_keys"]
    for key in before["vpn_keys"]:
        if "relay" not in before["vpn_keys"][key]:
            assert keys[key]["relay"] is None
    bundles = after["key_bundles"]
    display_numbers = [row["display_no"] for row in bundles.values()]
    assert None not in display_numbers
    assert len(set(display_numbers)) == len(display_numbers)
    for key, row in bundles.items():
        if key in before.get("key_bundles", {}) and "kind" not in before["key_bundles"][key]:
            assert row["kind"] == "extended"
    warp = after["warp_settings"][1,]
    assert warp["routes_count"] == 7
    assert warp["config_installed"] == 1  # v30 backfill: routes > 0 means "a config is installed"
    for row in after["protocol_modules"].values():
        assert (row["uninstalled_at"], row["uninstalled_by"], row["uninstall_backup"]) == (None, None, None)
    assert after["protocol_modules"]["awg",]["enabled"] == 0


# Invariant: the upgraded database is structurally sound — SQLite's integrity
# check passes and no foreign key dangles (a rebuild with FK enforcement off is
# exactly where an orphan would slip in).
@pytest.mark.parametrize("version", _snapshot_versions())
async def test_upgraded_database_passes_integrity_and_fk_checks(tmp_path: Path, version: int) -> None:
    # Arrange
    db_path, _, _ = await _prepare(tmp_path, version)

    # Act
    await _bootstrap(db_path)
    async with aiosqlite.connect(db_path) as conn:
        integrity = [tuple(r) for r in await (await conn.execute("PRAGMA integrity_check")).fetchall()]
        dangling = [tuple(r) for r in await (await conn.execute("PRAGMA foreign_key_check")).fetchall()]

    # Assert
    assert integrity == [("ok",)]
    assert dangling == []


# Invariant: restarting the bot on the upgraded database changes NO data — the
# second bootstrap is a no-op on rows, not only on the schema.
@pytest.mark.parametrize("version", _snapshot_versions())
async def test_second_bootstrap_leaves_data_identical(tmp_path: Path, version: int) -> None:
    # Arrange
    db_path, _, _ = await _prepare(tmp_path, version)
    await _bootstrap(db_path)
    first = await _dump(db_path)

    # Act
    await _bootstrap(db_path)
    second = await _dump(db_path)

    # Assert
    assert second == first


# Invariant: the spiderX backfill bootstrap() re-runs on every start fills ONLY
# xray keys whose spider_x is NULL — an already-assigned value is never
# overwritten, and non-xray keys are never touched.
async def test_spider_x_backfill_only_fills_nulls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    db_path, _, _ = await _prepare(tmp_path, 31)
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("UPDATE vpn_keys SET spider_x = NULL WHERE id = 5104")
        await conn.commit()
    monkeypatch.setenv("XRAY_SPIDER_X_POOL", "/pool-a,/pool-b")

    # Act
    await _bootstrap(db_path)
    after = await _dump(db_path)

    # Assert
    keys = after["vpn_keys"]
    assert keys[5101,]["spider_x"] == "/fid"
    assert keys[5104,]["spider_x"] in {"/pool-a", "/pool-b"}
    assert keys[5102,]["spider_x"] is None and keys[5103,]["spider_x"] is None


# Invariant: the comparison has teeth — a lost row, a rewritten value and a
# dropped table are each reported, while schema_version changes and newly added
# columns are not.
def test_diff_reports_loss_and_rewrites_only() -> None:
    # Arrange
    before: dict[str, TableRows] = {
        "schema_meta": {("schema_version",): {"key": "schema_version", "value": "29"}},
        "users": {(1,): {"id": 1, "role": "SUPERADMIN"}, (2,): {"id": 2, "role": "APPROVED_USER"}},
        "gone": {(1,): {"id": 1}},
    }
    after: dict[str, TableRows] = {
        "schema_meta": {("schema_version",): {"key": "schema_version", "value": "40"}},
        "users": {(1,): {"id": 1, "role": "PENDING_USER", "language": None}},
    }

    # Act
    problems = _diff(before, after)

    # Assert
    assert problems == [
        "users(1,).role: 'SUPERADMIN' -> 'PENDING_USER'",
        "users(2,): row lost",
        "table gone disappeared",
    ]
