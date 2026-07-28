
import asyncio
import re
import sqlite3
from pathlib import Path

import pytest

from db.database import CURRENT_SCHEMA_VERSION, Database
from db.exceptions import ConcurrentModificationError
from models.enums import KeyBundleStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from repositories.vpn_keys import VpnKeyRepository

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "db" / "schema.sql"

_INSERT_USERS = """
INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
VALUES (1, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now'),
       (100, 'user', 'User', 'APPROVED_USER', 'now', 'now')
"""


def _schema_without_v32() -> str:
    """Reconstruct the schema exactly as it was at v31 by stripping every v32 object
    (the key_bundles table, its indexes, and the vpn_keys.bundle_id column)."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    schema = re.sub(r"\nCREATE TABLE IF NOT EXISTS key_bundles \(.*?\n\);\n", "\n", schema, flags=re.S)
    schema = re.sub(r"\nCREATE INDEX IF NOT EXISTS idx_vpn_keys_bundle_id [^;]+;", "", schema)
    schema = re.sub(r"\nCREATE INDEX IF NOT EXISTS idx_key_bundles_[^;]+;", "", schema)
    schema = re.sub(
        r",\n(?:  --.*\n)*  bundle_id INTEGER REFERENCES key_bundles\(id\) ON DELETE RESTRICT",
        "",
        schema,
    )
    return schema


def test_v31_schema_fixture_is_clean() -> None:
    old = _schema_without_v32()
    # Ignore SQL comment lines (the migration-only-index note legitimately mentions
    # bundle_id); only executable DDL must be free of every v32 object.
    executable = "\n".join(line for line in old.splitlines() if not line.strip().startswith("--"))
    assert "key_bundles" not in executable
    assert "bundle_id" not in executable


def test_v32_migration_adds_key_bundles_and_preserves_keys(tmp_path: Path) -> None:
    """Migrating a real v31 DB to v32 creates key_bundles, adds a NULL bundle_id to
    every existing key, bumps the version, and loses no data. Idempotent."""
    old_schema = _schema_without_v32()
    old_path = tmp_path / "schema_v31.sql"
    old_path.write_text(old_schema, encoding="utf-8")

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.conn.executescript(old_schema)
            await db.conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '31') "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )
            await db.conn.execute(_INSERT_USERS)
            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, username, key_type, status, uuid,
                  payload_json, public_payload_json, created_at, updated_at, created_by
                )
                VALUES (100, 'user', 'xray', 'active', 'uuid-1',
                        '{"k":1}', '{"k":1}', 'now', 'now', 1)
                """
            )
            await db.commit()

            # bootstrap runs the migrations up to CURRENT_SCHEMA_VERSION; a second
            # bootstrap proves the whole path is idempotent.
            await db.bootstrap(old_path)
            await db.bootstrap(old_path)

            version = await db.conn.execute_fetchone(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            )
            assert version is not None
            assert int(version["value"]) == CURRENT_SCHEMA_VERSION == 32

            table = await db.conn.execute_fetchone(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'key_bundles'"
            )
            assert table is not None

            columns = {
                str(row["name"]) for row in await db.conn.execute_fetchall("PRAGMA table_info(vpn_keys)")
            }
            assert "bundle_id" in columns

            key = await db.conn.execute_fetchone("SELECT id, uuid, bundle_id FROM vpn_keys")
            assert key is not None
            assert key["uuid"] == "uuid-1"          # data preserved
            assert key["bundle_id"] is None          # existing rows become standalone

            count = await db.conn.execute_fetchone("SELECT COUNT(*) AS cnt FROM vpn_keys")
            assert int(count["cnt"]) == 1            # nothing lost
        finally:
            await db.close()

    asyncio.run(run())


def test_bundle_delete_restricted_while_child_attached(tmp_path: Path) -> None:
    """ON DELETE RESTRICT: a bundle cannot be deleted while a key still points at it;
    after the child is detached the delete succeeds."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(_INSERT_USERS)
            await db.conn.execute(
                "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                "VALUES (100, 'sub-1', 'active', 'tok-1', 'now', 'now')"
            )
            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, key_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by, bundle_id
                )
                VALUES (100, 'xray', 'active', '{}', '{}', 'now', 'now', 1, 1)
                """
            )
            await db.commit()

            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute("DELETE FROM key_bundles WHERE id = 1")
            await db.rollback()

            # Detach the child, then the bundle can be removed.
            await db.conn.execute("UPDATE vpn_keys SET bundle_id = NULL WHERE bundle_id = 1")
            await db.commit()
            await db.conn.execute("DELETE FROM key_bundles WHERE id = 1")
            await db.commit()

            remaining = await db.conn.execute_fetchone("SELECT COUNT(*) AS cnt FROM key_bundles")
            assert int(remaining["cnt"]) == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_no_hard_delete_path_for_users_exists(tmp_path: Path) -> None:
    """Users are never hard-deleted — removal is a role flip (``block_user``).

    This is what keeps the CASCADE/RESTRICT asymmetry below latent:
    ``key_bundles.user_id`` cascades from ``users`` while ``vpn_keys.bundle_id``
    restricts, so a hard user delete could hit the RESTRICT depending on the order
    SQLite happens to process the two foreign keys in. There is no such path in
    the codebase, and this test fails the moment one is added — whoever adds it
    must make it bundle-aware first (revoke/delete the user's bundles through
    ``KeyBundleService`` before removing the user row).
    """
    root = SCHEMA_PATH.parents[1]
    pattern = re.compile(r"DELETE\s+FROM\s+users\b", re.I)
    offenders = [
        str(path.relative_to(root))
        for directory in ("db", "repositories", "services", "bot", "adapters", "hy2_auth", "warp")
        for path in sorted((root / directory).rglob("*.py"))
        if pattern.search(path.read_text(encoding="utf-8"))
    ]
    assert not offenders, (
        "a hard-delete path for users appeared; make it bundle-aware "
        f"(children -> bundle -> user) before landing it: {offenders}"
    )
    # The schema states the same invariant, and vpn_keys.created_by depends on it.
    assert "users are NEVER hard-deleted" in SCHEMA_PATH.read_text(encoding="utf-8")


def test_hard_deleting_a_user_with_a_live_bundle_never_orphans(tmp_path: Path) -> None:
    """If a hard user delete is ever attempted at the SQL level it fails CLOSED.

    ``users`` -> ``key_bundles`` is CASCADE, ``key_bundles`` -> ``vpn_keys`` is
    RESTRICT, and SQLite does not specify the order in which it processes the two.
    Either way the invariant holds and is what this pins: the delete either fails
    entirely (nothing removed) or removes the user with everything below it —
    never a bundle or key left behind without its owner.
    """

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(_INSERT_USERS)
            await db.conn.execute(
                "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                "VALUES (100, 'sub-1', 'active', 'tok-1', 'now', 'now')"
            )
            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, key_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by, bundle_id
                )
                VALUES (100, 'xray', 'active', '{}', '{}', 'now', 'now', 1, 1)
                """
            )
            await db.commit()

            failed_closed = False
            try:
                await db.conn.execute("DELETE FROM users WHERE telegram_user_id = 100")
                await db.commit()
            except sqlite3.IntegrityError:
                failed_closed = True
                await db.rollback()

            async def count(table: str) -> int:
                row = await db.conn.execute_fetchone(f"SELECT COUNT(*) AS cnt FROM {table}")  # noqa: S608
                assert row is not None
                return int(row["cnt"])

            if failed_closed:
                # Nothing was removed: the operator must clear the bundles first.
                assert await count("users") == 2
                assert await count("key_bundles") == 1
                assert await count("vpn_keys") == 1
            else:
                # Everything below the user went with it; no orphan survives.
                assert await count("key_bundles") == 0
                assert await count("vpn_keys") == 0

            # Either way: no bundle may reference a user row that is gone.
            orphans = await db.conn.execute_fetchone(
                "SELECT COUNT(*) AS cnt FROM key_bundles b "
                "LEFT JOIN users u ON u.telegram_user_id = b.user_id WHERE u.telegram_user_id IS NULL"
            )
            assert orphans is not None and int(orphans["cnt"]) == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_clearing_bundles_first_makes_the_owner_row_removable(tmp_path: Path) -> None:
    """The bundle-aware order (children -> bundle -> user) leaves nothing behind."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(_INSERT_USERS)
            await db.conn.execute(
                "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                "VALUES (100, 'sub-1', 'active', 'tok-1', 'now', 'now')"
            )
            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, key_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by, bundle_id
                )
                VALUES (100, 'xray', 'active', '{}', '{}', 'now', 'now', 1, 1)
                """
            )
            await db.commit()

            # What KeyBundleService.delete_bundle does: children first, then the
            # bundle row — after which the user row is no longer blocked.
            await db.conn.execute("DELETE FROM vpn_keys WHERE bundle_id = 1")
            await db.conn.execute("DELETE FROM key_bundles WHERE id = 1")
            await db.conn.execute("DELETE FROM users WHERE telegram_user_id = 100")
            await db.commit()

            for table in ("key_bundles", "vpn_keys"):
                row = await db.conn.execute_fetchone(f"SELECT COUNT(*) AS cnt FROM {table}")  # noqa: S608
                assert row is not None and int(row["cnt"]) == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_bundle_token_and_label_are_unique(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(_INSERT_USERS)
            await db.conn.execute(
                "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                "VALUES (100, 'sub-1', 'active', 'dup-token', 'now', 'now')"
            )
            await db.commit()

            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute(
                    "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                    "VALUES (100, 'sub-2', 'active', 'dup-token', 'now', 'now')"
                )
            await db.rollback()

            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute(
                    "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                    "VALUES (100, 'sub-1', 'active', 'other-token', 'now', 'now')"
                )
        finally:
            await db.close()

    asyncio.run(run())


def test_bundle_status_check_rejects_key_only_states(tmp_path: Path) -> None:
    """The bundle CHECK shares VpnKeyStatus's vocabulary but omits the apply-side
    states, so a value valid for a key (pending_apply) is rejected for a bundle."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(_INSERT_USERS)
            await db.commit()
            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute(
                    "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                    "VALUES (100, 'sub-1', 'pending_apply', 'tok-x', 'now', 'now')"
                )
        finally:
            await db.close()

    asyncio.run(run())


def test_key_bundle_repository_crud(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(_INSERT_USERS)
            await db.commit()

            deletable = await KeyBundleRepository(db).create(user_id=100, label="sub-del", now="t0")
            await KeyBundleRepository(db).delete(deletable.id)
            assert await KeyBundleRepository(db).get_by_id(deletable.id) is None

            repo = KeyBundleRepository(db)
            vpn_repo = VpnKeyRepository(db)

            bundle = await repo.create(user_id=100, label="sub-1", now="t0", note="first")
            assert bundle.id > 0
            assert bundle.status is KeyBundleStatus.ACTIVE
            assert bundle.note == "first"
            assert bundle.token
            assert bundle.revoked_at is None and bundle.deleted_at is None
            # The secret token must never leak through repr.
            assert bundle.token not in repr(bundle)

            assert await repo.get_by_id(bundle.id) == bundle
            fetched = await repo.get_by_token(bundle.token)
            assert fetched is not None and fetched.id == bundle.id
            assert await repo.get_by_token("does-not-exist") is None

            second = await repo.create(user_id=100, label="sub-2", now="t1")
            listed = await repo.list_by_user(100)
            assert [b.id for b in listed] == [bundle.id, second.id]
            assert await repo.list_by_user(1) == []

            key = await vpn_repo.create_key(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={},
                public_payload={},
                created_by=1,
                now="t2",
            )
            assert await repo.list_keys_of_bundle(bundle.id) == []
            await repo.attach_key_to_bundle(key.id, bundle.id, "t3")
            attached = await repo.list_keys_of_bundle(bundle.id)
            assert [k.id for k in attached] == [key.id]

            # Guarded transition succeeds from the allowed source status...
            await repo.set_status(
                bundle.id,
                KeyBundleStatus.PENDING_REVOKE,
                "t4",
                allowed_from_statuses=(KeyBundleStatus.ACTIVE,),
            )
            moved = await repo.get_by_id(bundle.id)
            assert moved is not None and moved.status is KeyBundleStatus.PENDING_REVOKE

            # ...and raises when the current status is not among the allowed ones.
            with pytest.raises(ConcurrentModificationError):
                await repo.set_status(
                    bundle.id,
                    KeyBundleStatus.REVOKED,
                    "t5",
                    allowed_from_statuses=(KeyBundleStatus.ACTIVE,),
                )

            # revoked/deleted transitions stamp their timestamps once.
            await repo.set_status(bundle.id, KeyBundleStatus.REVOKED, "t6")
            revoked = await repo.get_by_id(bundle.id)
            assert revoked is not None and revoked.status is KeyBundleStatus.REVOKED
            assert revoked.revoked_at == "t6"

            await repo.set_status(bundle.id, KeyBundleStatus.DELETED, "t7")
            deleted = await repo.get_by_id(bundle.id)
            assert deleted is not None and deleted.status is KeyBundleStatus.DELETED
            assert deleted.deleted_at == "t7"
            assert deleted.revoked_at == "t6"  # earlier stamp preserved

            # rotate_token swaps the secret and re-points get_by_token.
            old_token = second.token
            new_token = await repo.rotate_token(second.id, "t8")
            assert new_token != old_token
            assert await repo.get_by_token(old_token) is None
            rotated = await repo.get_by_token(new_token)
            assert rotated is not None and rotated.id == second.id

            with pytest.raises(RuntimeError):
                await repo.rotate_token(999999, "t9")
        finally:
            await db.close()

    asyncio.run(run())


# --------------------------------------------------------------------------- #
# bundle_id IS NULL is AMBIGUOUS — it is not a "standalone key" marker
# --------------------------------------------------------------------------- #
def test_null_bundle_id_cannot_distinguish_standalone_from_unfinished_child(tmp_path: Path) -> None:
    """A NULL ``bundle_id`` means one of TWO things, and the row does not say which.

    ``create_bundle`` provisions each child first and attaches it second
    (``_provision_child`` -> ``attach_key_to_bundle``). When a child's own apply
    fails, its row is already in ``vpn_keys`` — ``apply_failed``, never attached —
    and the rollback deliberately leaves it there, exactly like the trace a failed
    standalone create leaves behind. ``test_key_bundle_service.py::
    test_create_bundle_rolls_back_children_on_midway_failure`` pins that the real
    service path produces such a row.

    So ``bundle_id IS NULL`` covers BOTH:

    * an ordinary standalone key (every pre-v32 row, plus every key created
      outside a bundle), and
    * a bundle child whose apply died before the attach.

    Nothing may delete or "clean up" a row on the strength of that NULL alone.
    Both kinds can still own a live client on a backend that startup
    reconciliation is expected to find, and the second kind is not garbage — it is
    the same recoverable wreckage a standalone failure leaves.

    This test states the invariant so that a future change which tries to make
    NULL mean "standalone" (e.g. by back-filling it, or by adding a sweep) has to
    come here and argue with it first. The companion static guard below fails on
    the SQL such a sweep would be written in.
    """

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(_INSERT_USERS)
            # A live bundle with one attached, healthy child ...
            await db.conn.execute(
                "INSERT INTO key_bundles (user_id, label, status, token, created_at, updated_at) "
                "VALUES (100, 'bundle_00001', 'active', 'tok-1', 'now', 'now')"
            )
            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, key_type, status, email_label,
                  payload_json, public_payload_json, created_at, updated_at, created_by, bundle_id
                )
                VALUES (100, 'xray', 'active', 'xray_tcp_aaaa',
                        '{}', '{}', 'now', 'now', 1, 1)
                """
            )
            # ... a sibling whose apply died BEFORE the attach (bundle_id never set) ...
            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, key_type, status, email_label,
                  payload_json, public_payload_json, created_at, updated_at, created_by
                )
                VALUES (100, 'xray', 'apply_failed', 'xray_http_bbbb',
                        '{}', '{}', 'now', 'now', 1)
                """
            )
            # ... and an ordinary standalone key that failed to apply.
            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, key_type, status, email_label,
                  payload_json, public_payload_json, created_at, updated_at, created_by
                )
                VALUES (100, 'xray', 'apply_failed', 'xray_tcp_cccc',
                        '{}', '{}', 'now', 'now', 1)
                """
            )
            await db.commit()

            null_rows = await db.conn.execute_fetchall(
                "SELECT id, email_label, status FROM vpn_keys WHERE bundle_id IS NULL ORDER BY id"
            )
            # The predicate catches the unfinished child and the standalone key
            # alike, and the two rows are indistinguishable in every column a
            # cleanup could key on: same status, same NULL bundle_id. The child's
            # label is a normal child label, and standalone keys carry those too.
            assert [row["email_label"] for row in null_rows] == ["xray_http_bbbb", "xray_tcp_cccc"]
            assert {row["status"] for row in null_rows} == {"apply_failed"}

            # Re-running the migrations must not sweep either of them: bootstrap is
            # the one place a "tidy up the orphans" step would plausibly be added.
            await db.bootstrap()
            after = await db.conn.execute_fetchone("SELECT COUNT(*) AS cnt FROM vpn_keys")
            assert int(after["cnt"]) == 3, "a migration deleted a bundle_id IS NULL row"
        finally:
            await db.close()

    asyncio.run(run())


def test_no_production_query_selects_keys_by_bundle_id_is_null() -> None:
    """No production SQL may treat ``bundle_id IS NULL`` as "this is a standalone key".

    The tripwire for the invariant above. A cleanup/reconcile/listing sweep that
    wanted "the keys that are not in a bundle" would be written exactly as
    ``WHERE bundle_id IS NULL``, and it would silently include bundle children
    whose apply failed before the attach.

    There is currently **no** such query — the guard starts from zero, with no
    allow-list. ``bundle_id IS NOT NULL`` stays allowed: that direction is
    unambiguous (a set bundle_id really does mean "attached child"), and the
    partial index in ``db/schema.sql`` uses it.

    If you are here because this test failed: the fix is not to add your file to
    an exception list. Decide what your query actually needs — usually "children
    of THIS bundle" (``bundle_id = ?``, which is exact) — or make the row itself
    unambiguous first.
    """
    root = SCHEMA_PATH.parents[1]
    offenders: list[str] = []
    for directory in ("db", "repositories", "services", "bot", "adapters", "hy2_auth", "warp", "subscription_server"):
        for path in sorted((root / directory).rglob("*")):
            if path.suffix not in {".py", ".sql"}:
                continue
            marker = "#" if path.suffix == ".py" else "--"
            for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = raw.split(marker, 1)[0]
                # `IS NOT NULL` is the unambiguous direction and is explicitly fine.
                code = re.sub(r"bundle_id\s+IS\s+NOT\s+NULL", "", code, flags=re.I)
                if re.search(r"bundle_id\s+IS\s+NULL", code, flags=re.I):
                    offenders.append(f"{path.relative_to(root)}:{lineno}: {raw.strip()}")
    assert not offenders, (
        "a query classifies keys by `bundle_id IS NULL`, but that also matches a "
        "bundle child whose apply failed before it was attached — such a row must "
        "not be treated as a known-standalone key: " + "; ".join(offenders)
    )
