
import asyncio
import json
import logging
import os
import re
import secrets
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import AsyncIterator
from typing import Any, ClassVar

import aiosqlite

from utils.spider_x import parse_spider_x_pool, pick_spider_x


CURRENT_SCHEMA_VERSION = 31
logger = logging.getLogger(__name__)

# Transport/profile-aware Xray email scheme (see _migrate_v28). A label already on
# one of these prefixes is left untouched, making the relabel idempotent.
_V28_NEW_PREFIXES = ("xray_tcp_", "xray_http_base_", "xray_http_antisib_", "xray_http_multi_")
_V28_SUFFIX_RE = re.compile(r"^[A-Za-z0-9]{5}$")
# Mirrors adapters.id_generator.KEY_NAME_ALPHABET (kept local to avoid a db->adapters import).
_V28_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_ACTIVE_TRANSACTION_DB: ContextVar["Database | None"] = ContextVar("active_transaction_db", default=None)


def _proxy_access_default_expr(column: str) -> str:
    defaults = {
        "secret_fingerprint": "NULL AS secret_fingerprint",
        "apply_generation": "0 AS apply_generation",
        "activated_at": "NULL AS activated_at",
        "last_apply_at": "NULL AS last_apply_at",
    }
    try:
        return defaults[column]
    except KeyError as exc:
        raise RuntimeError(f"Unsupported proxy_accesses migration column: {column}") from exc


def _normalize_synchronous(value: str) -> str:
    normalized = value.strip().upper()
    if normalized not in {"FULL", "NORMAL", "EXTRA"}:
        raise ValueError("SQLite synchronous must be FULL, NORMAL, or EXTRA")
    return normalized


class Database:
    def __init__(self, path: Path, synchronous: str = "FULL") -> None:
        self.path = path
        self.synchronous = _normalize_synchronous(synchronous)
        self._conn: aiosqlite.Connection | None = None
        self._conn_proxy = _ConnectionProxy(self)
        self._transaction_lock = asyncio.Lock()
        self._transaction_owner: asyncio.Task[object] | None = None
        self._transaction_depth = 0
        self._implicit_write_owner: asyncio.Task[object] | None = None
        self._implicit_write_depth = 0

    @property
    def conn(self) -> "_ConnectionProxy":
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn_proxy

    def _raw_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database is not connected")
        return self._conn

    async def connect(self) -> None:
        created = not self.path.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._chmod_private_dir(self.path.parent)
        if created:
            # Create the database file with private permissions BEFORE aiosqlite
            # opens it, so there is no window where the freshly created DB is
            # world-readable. The -wal/-shm files SQLite creates later are still
            # covered by the 0700 parent directory set above.
            self._precreate_private_file(self.path)
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._raw_conn().execute("PRAGMA foreign_keys = ON")
        await self._raw_conn().execute("PRAGMA journal_mode = WAL")
        await self._raw_conn().execute(f"PRAGMA synchronous = {self.synchronous}")
        await self._raw_conn().execute("PRAGMA busy_timeout = 5000")
        await self._raw_conn().commit()
        if created or os.name == "posix":
            self._chmod_sqlite_files()

    async def close(self) -> None:
        if self._conn is not None:
            # Truncate the WAL on a clean shutdown so it does not grow unbounded
            # across long-running deployments. Best-effort: a checkpoint can fail
            # if a transaction is still open at close time (e.g. tests that never
            # commit) — that is benign, so it is logged at debug and must not
            # prevent the connection from closing.
            try:
                await self._raw_conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                logger.debug("wal_checkpoint при закрытии SQLite пропущен", exc_info=True)
            await self._raw_conn().close()
            self._conn = None

    async def bootstrap(self, schema_path: Path | None = None) -> None:
        if schema_path is None:
            schema_path = Path(__file__).with_name("schema.sql")
        sql = schema_path.read_text(encoding="utf-8")
        try:
            await self.conn.executescript(sql)
            await self._apply_migrations()
            await self.commit()
            self._chmod_sqlite_files()
        except Exception:
            await self.rollback()
            raise

    async def _apply_migrations(self) -> None:
        version = await self._schema_version()
        if version > CURRENT_SCHEMA_VERSION:
            raise RuntimeError(
                f"SQLite schema version {version} новее поддерживаемой {CURRENT_SCHEMA_VERSION}"
            )
        if version < 1:
            await self._set_schema_version(1)
            version = 1
        if version < 2:
            await self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner_type_status "
                "ON vpn_keys(owner_user_id, key_type, status)"
            )
            await self._set_schema_version(2)
            version = 2
        if version < 3:
            await self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vpn_key_traffic_stats (
                  key_id INTEGER PRIMARY KEY,
                  downloaded_bytes INTEGER NOT NULL DEFAULT 0,
                  uploaded_bytes INTEGER NOT NULL DEFAULT 0,
                  last_raw_downloaded_bytes INTEGER,
                  last_raw_uploaded_bytes INTEGER,
                  last_success_at TEXT,
                  last_attempt_at TEXT,
                  available INTEGER NOT NULL DEFAULT 0,
                  unavailable_reason TEXT,
                  source TEXT,
                  FOREIGN KEY(key_id) REFERENCES vpn_keys(id) ON DELETE CASCADE
                )
                """
            )
            await self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_vpn_key_traffic_stats_success "
                "ON vpn_key_traffic_stats(last_success_at)"
            )
            await self._set_schema_version(3)
            version = 3
        if version < 4:
            now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
            await self._collapse_duplicate_pending_access_requests(now)
            await self.conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_access_requests_one_pending
                ON access_requests(telegram_user_id)
                WHERE status = 'pending'
                """
            )
            await self.conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_access_requests_pending_created
                ON access_requests(status, requested_at)
                """
            )
            await self.conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_vpn_keys_status_type
                ON vpn_keys(status, key_type)
                """
            )
            await self._set_schema_version(4)
            version = 4
        if version < 5:
            await self._validate_reserved_awg_client_ip_duplicates()
            await self.conn.execute("DROP INDEX IF EXISTS idx_vpn_keys_client_ip_active")
            await self.conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_client_ip_reserved
                ON vpn_keys(client_ip)
                WHERE client_ip IS NOT NULL
                  AND key_type = 'awg'
                  AND status IN ('pending_apply','active','pending_revoke','pending_delete','delete_failed')
                """
            )
            await self._set_schema_version(5)
            version = 5
        if version < 6:
            await self._validate_reserved_awg_client_ip_duplicates()
            await self.conn.execute("DROP INDEX IF EXISTS idx_vpn_keys_client_ip_reserved")
            await self.conn.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_client_ip_reserved
                ON vpn_keys(client_ip)
                WHERE client_ip IS NOT NULL
                  AND key_type = 'awg'
                  AND status IN ('pending_apply','active','apply_failed','pending_revoke','pending_delete','delete_failed')
                """
            )
            await self._set_schema_version(6)
            version = 6
        if version < 7:
            await self._create_announcement_tables()
            await self._set_schema_version(7)
            version = 7
        if version < 8:
            await self._create_proxy_access_tables()
            await self._set_schema_version(8)
            version = 8
        if version < 9:
            await self._migrate_proxy_accesses_v9()
            await self._set_schema_version(9)
            version = 9
        if version < 10:
            await self._create_proxy_access_live_unique_index()
            await self._set_schema_version(10)
            version = 10
        if version < 11:
            await self._normalize_user_roles()
            await self._set_schema_version(11)
            version = 11
        if version < 12:
            await self._create_performance_indexes()
            await self._set_schema_version(12)
            version = 12
        if version < 13:
            await self._migrate_v13()
            await self._set_schema_version(13)
            version = 13
        if version < 14:
            await self._migrate_v14()
            await self._set_schema_version(14)
            version = 14
        if version < 15:
            await self._migrate_v15()
            await self._set_schema_version(15)
            version = 15
        if version < 16:
            await self._migrate_v16()
            await self._set_schema_version(16)
            version = 16
        if version < 17:
            await self._migrate_v17()
            await self._set_schema_version(17)
            version = 17
        if version < 18:
            await self._migrate_v18()
            await self._set_schema_version(18)
            version = 18
        if version < 19:
            await self._migrate_v19()
            await self._set_schema_version(19)
            version = 19
        if version < 20:
            await self._migrate_v20()
            await self._set_schema_version(20)
            version = 20
        if version < 21:
            await self._migrate_v21()
            await self._set_schema_version(21)
            version = 21
        if version < 22:
            await self._migrate_v22()
            await self._set_schema_version(22)
            version = 22
        if version < 23:
            await self._migrate_v23()
            await self._set_schema_version(23)
            version = 23
        if version < 24:
            await self._migrate_v24()
            await self._set_schema_version(24)
            version = 24
        if version < 25:
            await self._migrate_v25()
            await self._set_schema_version(25)
            version = 25
        if version < 26:
            await self._migrate_v26()
            await self._set_schema_version(26)
            version = 26
        if version < 27:
            await self._migrate_v27()
            await self._set_schema_version(27)
            version = 27
        if version < 28:
            await self._migrate_v28()
            await self._set_schema_version(28)
            version = 28
        if version < 29:
            await self._migrate_v29()
            await self._set_schema_version(29)
            version = 29
        if version < 30:
            await self._migrate_v30()
            await self._set_schema_version(30)
            version = 30
        if version < 31:
            await self._migrate_v31()
            await self._set_schema_version(31)
            version = 31
        await self._validate_reference_integrity()
        await self._validate_enum_values()

    async def _create_announcement_tables(self) -> None:
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS announcement_batches (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              actor_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE RESTRICT,
              from_chat_id INTEGER NOT NULL,
              message_id INTEGER NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('pending','sending','completed','failed','cancelled')),
              total_count INTEGER NOT NULL DEFAULT 0,
              success_count INTEGER NOT NULL DEFAULT 0,
              failed_count INTEGER NOT NULL DEFAULT 0,
              skipped_count INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              completed_at TEXT
            )
            """
        )
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS announcement_deliveries (
              announcement_id INTEGER NOT NULL REFERENCES announcement_batches(id) ON DELETE CASCADE,
              user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
              status TEXT NOT NULL CHECK(status IN ('pending','sent','failed','skipped')),
              error_text TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (announcement_id, user_id)
            )
            """
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_announcement_batches_status "
            "ON announcement_batches(status, updated_at)"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_announcement_deliveries_status "
            "ON announcement_deliveries(announcement_id, status, user_id)"
        )

    async def _create_proxy_access_tables(self) -> None:
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS proxy_accesses (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
              username TEXT,
              access_type TEXT NOT NULL CHECK(access_type IN ('socks5','mtproto')),
              status TEXT NOT NULL CHECK(status IN (
                'pending_apply','active','apply_failed','pending_revoke','revoked','revoke_failed','inactive',
                'pending_delete','delete_failed','deleted'
              )),
              secret_fingerprint TEXT,
              apply_generation INTEGER NOT NULL DEFAULT 0,
              payload_json TEXT NOT NULL,
              public_payload_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              activated_at TEXT,
              last_apply_at TEXT,
              last_shown_at TEXT,
              revoked_at TEXT,
              deleted_at TEXT,
              created_by INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE RESTRICT,
              revoked_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL,
              deleted_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL,
              reason TEXT,
              error TEXT
            )
            """
        )
        await self._create_proxy_access_indexes()

    async def _create_proxy_access_indexes(self) -> None:
        await self.conn.execute("CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner ON proxy_accesses(owner_user_id)")
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proxy_accesses_owner_type_status "
            "ON proxy_accesses(owner_user_id, access_type, status)"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proxy_accesses_status_type "
            "ON proxy_accesses(status, access_type)"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proxy_accesses_login "
            "ON proxy_accesses(json_extract(payload_json, '$.login')) WHERE access_type = 'socks5'"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_proxy_accesses_mtproto_fingerprint "
            "ON proxy_accesses(secret_fingerprint) "
            "WHERE access_type = 'mtproto' AND secret_fingerprint IS NOT NULL"
        )

    async def _create_proxy_access_live_unique_index(self) -> None:
        await self._validate_proxy_live_duplicates()
        await self.conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_accesses_one_live_per_user_type
            ON proxy_accesses(owner_user_id, access_type)
            WHERE status IN ('pending_apply','active','pending_revoke')
            """
        )

    async def _migrate_proxy_accesses_v9(self) -> None:
        table = await self.conn.execute_fetchone(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'proxy_accesses'"
        )
        if table is None:
            await self._create_proxy_access_tables()
            return
        sql = str(table["sql"] or "")
        columns = await self._table_columns("proxy_accesses")
        required_columns = {"secret_fingerprint", "apply_generation", "activated_at", "last_apply_at"}
        if required_columns.issubset(columns) and "revoke_failed" in sql:
            await self._create_proxy_access_indexes()
            return

        await self.conn.execute("DROP INDEX IF EXISTS idx_proxy_accesses_owner")
        await self.conn.execute("DROP INDEX IF EXISTS idx_proxy_accesses_owner_type_status")
        await self.conn.execute("DROP INDEX IF EXISTS idx_proxy_accesses_status_type")
        await self.conn.execute("DROP INDEX IF EXISTS idx_proxy_accesses_login")
        await self.conn.execute("DROP INDEX IF EXISTS idx_proxy_accesses_mtproto_fingerprint")
        await self.conn.execute("ALTER TABLE proxy_accesses RENAME TO proxy_accesses_v8")
        await self._create_proxy_access_tables()

        target_columns = [
            "id",
            "owner_user_id",
            "username",
            "access_type",
            "status",
            "secret_fingerprint",
            "apply_generation",
            "payload_json",
            "public_payload_json",
            "created_at",
            "updated_at",
            "activated_at",
            "last_apply_at",
            "last_shown_at",
            "revoked_at",
            "deleted_at",
            "created_by",
            "revoked_by",
            "deleted_by",
            "reason",
            "error",
        ]
        source_expressions = [
            column if column in columns else _proxy_access_default_expr(column) for column in target_columns
        ]
        await self.conn.execute(
            f"""
            INSERT INTO proxy_accesses ({",".join(target_columns)})
            SELECT {",".join(source_expressions)}
            FROM proxy_accesses_v8
            """
        )
        await self.conn.execute("DROP TABLE proxy_accesses_v8")
        await self._create_proxy_access_indexes()

    async def _table_columns(self, table_name: str) -> set[str]:
        cursor = await self.conn.execute(f"PRAGMA table_info({table_name})")
        rows = await cursor.fetchall()
        return {str(row["name"]) for row in rows}

    async def _schema_version(self) -> int:
        await self.conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        cursor = await self.conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'")
        row = await cursor.fetchone()
        if row is None:
            return 0
        try:
            return int(row["value"])
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Некорректное значение schema_meta.schema_version") from exc

    async def _set_schema_version(self, version: int) -> None:
        await self.conn.execute(
            """
            INSERT INTO schema_meta (key, value)
            VALUES ('schema_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (str(version),),
        )

    async def get_meta(self, key: str) -> str | None:
        cursor = await self.conn.execute("SELECT value FROM schema_meta WHERE key = ?", (key,))
        row = await cursor.fetchone()
        return str(row["value"]) if row is not None else None

    async def set_meta(self, key: str, value: str) -> None:
        await self.conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        await self.conn.commit()

    async def _collapse_duplicate_pending_access_requests(self, now: str) -> None:
        await self.conn.execute(
            """
            UPDATE access_requests
            SET status = 'rejected',
                decided_at = COALESCE(decided_at, ?),
                decision_note = COALESCE(decision_note, 'Автоматически закрыта миграцией: дубликат pending-заявки')
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY telegram_user_id
                            ORDER BY requested_at ASC, id ASC
                        ) AS rn
                    FROM access_requests
                    WHERE status = 'pending'
                )
                WHERE rn > 1
            )
            """,
            (now,),
        )

    async def _validate_reference_integrity(self) -> None:
        checks = (
            ("access_requests", "telegram_user_id", False),
            ("access_requests", "decided_by", True),
            ("vpn_keys", "owner_user_id", False),
            ("vpn_keys", "created_by", False),
            ("vpn_keys", "revoked_by", True),
            ("vpn_keys", "deleted_by", True),
            ("proxy_accesses", "owner_user_id", False),
            ("proxy_accesses", "created_by", False),
            ("proxy_accesses", "revoked_by", True),
            ("proxy_accesses", "deleted_by", True),
        )
        for table, column, nullable in checks:
            null_filter = f"{table}.{column} IS NOT NULL AND " if nullable else ""
            cursor = await self.conn.execute(
                f"""
                SELECT COUNT(*) AS cnt
                FROM {table}
                LEFT JOIN users ON users.telegram_user_id = {table}.{column}
                WHERE {null_filter}users.telegram_user_id IS NULL
                """
            )
            row = await cursor.fetchone()
            count = int(row["cnt"]) if row is not None else 0
            if count:
                raise RuntimeError(
                    "Найдены записи без связанного пользователя: "
                    f"table={table} column={column} count={count}. "
                    "Остановите запуск, сделайте backup SQLite DB и вручную восстановите владельца "
                    "или удалите orphan-записи после проверки."
                )
        cursor = await self.conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM vpn_key_traffic_stats
            LEFT JOIN vpn_keys ON vpn_keys.id = vpn_key_traffic_stats.key_id
            WHERE vpn_keys.id IS NULL
            """
        )
        row = await cursor.fetchone()
        count = int(row["cnt"]) if row is not None else 0
        if count:
            raise RuntimeError(
                "Найдены orphan-записи traffic stats: table=vpn_key_traffic_stats "
                f"column=key_id count={count}. Остановите запуск, сделайте backup SQLite DB "
                "и вручную удалите/восстановите статистику после проверки."
            )

    async def _validate_enum_values(self) -> None:
        enum_checks = (
            (
                "users",
                "role",
                ("SUPERADMIN", "MODERATOR", "APPROVED_USER", "PENDING_USER", "BLOCKED_USER"),
            ),
            ("access_requests", "status", ("pending", "approved", "rejected")),
            (
                "vpn_keys",
                "key_type",
                ("xray", "awg", "hysteria2"),
            ),
            ("vpn_keys", "transport", ("tcp", "http")),
            (
                "vpn_keys",
                "status",
                (
                    "pending_apply",
                    "active",
                    "apply_failed",
                    "pending_revoke",
                    "revoked",
                    "pending_delete",
                    "delete_failed",
                    "deleted",
                    "failed",
                ),
            ),
            ("proxy_entries", "proxy_type", ("socks5", "socks4", "http", "https")),
            ("proxy_entries", "status", ("active", "disabled")),
            ("proxy_accesses", "access_type", ("socks5", "mtproto")),
            (
                "proxy_accesses",
                "status",
                (
                    "pending_apply",
                    "active",
                    "apply_failed",
                    "pending_revoke",
                    "revoked",
                    "revoke_failed",
                    "inactive",
                    "pending_delete",
                    "delete_failed",
                    "deleted",
                ),
            ),
            ("announcement_batches", "status", ("pending", "sending", "completed", "failed", "cancelled", "scheduled")),
            ("announcement_deliveries", "status", ("pending", "sent", "failed", "skipped")),
        )
        for table, column, allowed_values in enum_checks:
            placeholders = ",".join("?" for _ in allowed_values)
            cursor = await self.conn.execute(
                f"SELECT COUNT(*) AS cnt FROM {table} WHERE {column} NOT IN ({placeholders})",
                allowed_values,
            )
            row = await cursor.fetchone()
            count = int(row["cnt"]) if row is not None else 0
            if count:
                raise RuntimeError(
                    "Найдены некорректные enum-значения в SQLite: "
                    f"table={table} column={column} count={count}. "
                    "Остановите запуск, сделайте backup SQLite DB и исправьте значения вручную."
                )

    async def _validate_reserved_awg_client_ip_duplicates(self) -> None:
        cursor = await self.conn.execute(
            """
            SELECT client_ip, COUNT(*) AS cnt
            FROM vpn_keys
            WHERE key_type = 'awg'
              AND client_ip IS NOT NULL
              AND status IN ('pending_apply','active','apply_failed','pending_revoke','pending_delete','delete_failed')
            GROUP BY client_ip
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        )
        row = await cursor.fetchone()
        if row is not None:
            raise RuntimeError(
                "Найдены дубли AWG client_ip в reserved статусах: "
                f"client_ip={row['client_ip']} count={row['cnt']}. "
                "Остановите запуск, сделайте backup SQLite DB и вручную разберите конфликт перед миграцией."
            )

    async def _migrate_v13(self) -> None:
        vpn_cols = await self._table_columns("vpn_keys")
        if "expires_at" not in vpn_cols:
            await self.conn.execute("ALTER TABLE vpn_keys ADD COLUMN expires_at TEXT DEFAULT NULL")
        user_cols = await self._table_columns("users")
        if "trial_quota_reset_at" not in user_cols:
            await self.conn.execute("ALTER TABLE users ADD COLUMN trial_quota_reset_at TEXT DEFAULT NULL")
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trial_key_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              telegram_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
              key_type TEXT NOT NULL CHECK(key_type IN ('xray','awg')),
              status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
              key_id INTEGER REFERENCES vpn_keys(id) ON DELETE SET NULL,
              requested_at TEXT NOT NULL,
              decided_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL,
              decided_at TEXT
            )
            """
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vpn_keys_expires_at "
            "ON vpn_keys(expires_at) WHERE expires_at IS NOT NULL AND status = 'active'"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_trial_requests_user "
            "ON trial_key_requests(telegram_user_id, status)"
        )

    async def _migrate_v14(self) -> None:
        user_cols = await self._table_columns("users")
        if "note" not in user_cols:
            await self.conn.execute("ALTER TABLE users ADD COLUMN note TEXT DEFAULT NULL")

    async def _migrate_v15(self) -> None:
        vpn_cols = await self._table_columns("vpn_keys")
        if "expiry_notified_days" not in vpn_cols:
            await self.conn.execute(
                "ALTER TABLE vpn_keys ADD COLUMN expiry_notified_days TEXT DEFAULT NULL"
            )

    async def _migrate_v16(self) -> None:
        cols = await self._table_columns("announcement_batches")
        if "scheduled_at" in cols:
            return
        # SQLite always rewrites FK references in sibling tables when renaming,
        # regardless of PRAGMA foreign_keys state in 3.26+. Instead we:
        # 1. create a _new table with the updated schema;
        # 2. copy data;
        # 3. drop the old table (FK OFF to avoid cascade complications);
        # 4. rename _new → original (no sibling FK references _new, so nothing to rewrite).
        #
        # All statements run on the RAW connection (mirroring _migrate_v17): the
        # pragma toggles only take effect outside an open transaction, so we
        # commit() first, then run the rebuild on a single raw transaction, and
        # re-enable FK in `finally` AFTER the raw.commit() closes that
        # transaction — otherwise PRAGMA foreign_keys = ON would be silently
        # ignored and FK enforcement would stay OFF.
        await self.commit()
        raw = self._raw_conn()
        await raw.execute("PRAGMA foreign_keys = OFF")
        try:
            # One explicit transaction so a crash mid-rebuild rolls back atomically;
            # the DROP IF EXISTS guard makes a re-run self-healing if an older build
            # ever left an orphan _new table behind (see _migrate_v29 for the full
            # rationale on sqlite3 legacy autocommit-of-leading-DDL).
            await raw.execute("BEGIN")
            await raw.execute("DROP TABLE IF EXISTS announcement_batches_new")
            await raw.execute("DROP INDEX IF EXISTS idx_announcement_batches_status")
            await raw.execute(
                """
                CREATE TABLE announcement_batches_new (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  actor_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE RESTRICT,
                  from_chat_id INTEGER NOT NULL,
                  message_id INTEGER NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('pending','sending','completed','failed','cancelled','scheduled')),
                  total_count INTEGER NOT NULL DEFAULT 0,
                  success_count INTEGER NOT NULL DEFAULT 0,
                  failed_count INTEGER NOT NULL DEFAULT 0,
                  skipped_count INTEGER NOT NULL DEFAULT 0,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  completed_at TEXT,
                  scheduled_at TEXT
                )
                """
            )
            await raw.execute(
                """
                INSERT INTO announcement_batches_new (
                  id, actor_user_id, from_chat_id, message_id, status,
                  total_count, success_count, failed_count, skipped_count,
                  created_at, updated_at, completed_at, scheduled_at
                )
                SELECT id, actor_user_id, from_chat_id, message_id, status,
                       total_count, success_count, failed_count, skipped_count,
                       created_at, updated_at, completed_at, NULL
                FROM announcement_batches
                """
            )
            await raw.execute("DROP TABLE announcement_batches")
            await raw.execute("ALTER TABLE announcement_batches_new RENAME TO announcement_batches")
            await raw.execute(
                "CREATE INDEX IF NOT EXISTS idx_announcement_batches_status "
                "ON announcement_batches(status, updated_at)"
            )
            await raw.execute(
                "CREATE INDEX IF NOT EXISTS idx_announcement_batches_scheduled "
                "ON announcement_batches(scheduled_at) "
                "WHERE status = 'scheduled' AND scheduled_at IS NOT NULL"
            )
            await raw.commit()
        except Exception:
            await raw.rollback()
            raise
        finally:
            # Re-enable FK after committing so the pragma actually takes effect
            # (SQLite ignores it inside a transaction).
            await raw.execute("PRAGMA foreign_keys = ON")

    async def _migrate_v17(self) -> None:
        # Commit any writes buffered by previous migrations so that
        # PRAGMA foreign_keys = OFF takes effect (SQLite silently ignores
        # the pragma when a transaction is already open).
        await self.commit()
        raw = self._raw_conn()
        await raw.execute("PRAGMA foreign_keys = OFF")
        try:
            # One explicit transaction so a crash mid-rebuild rolls back atomically;
            # the DROP IF EXISTS guard makes a re-run self-healing if an older build
            # ever left an orphan _new table behind (see _migrate_v29 for the full
            # rationale on sqlite3 legacy autocommit-of-leading-DDL).
            await raw.execute("BEGIN")
            await raw.execute("DROP TABLE IF EXISTS users_new")
            await raw.execute("DROP INDEX IF EXISTS idx_users_role")
            await raw.execute("DROP INDEX IF EXISTS idx_users_active_role")
            await raw.execute(
                """
                CREATE TABLE users_new (
                  telegram_user_id INTEGER PRIMARY KEY,
                  username TEXT,
                  first_name TEXT,
                  role TEXT NOT NULL CHECK(role IN ('SUPERADMIN','MODERATOR','APPROVED_USER','PENDING_USER','BLOCKED_USER')),
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  blocked_at TEXT,
                  trial_quota_reset_at TEXT DEFAULT NULL,
                  note TEXT DEFAULT NULL
                )
                """
            )
            # Explicit column list (not SELECT *) so a future divergence in
            # column order between schema.sql and this rebuild cannot silently
            # misalign data.
            await raw.execute(
                """
                INSERT INTO users_new (
                  telegram_user_id, username, first_name, role,
                  created_at, updated_at, blocked_at, trial_quota_reset_at, note
                )
                SELECT
                  telegram_user_id, username, first_name, role,
                  created_at, updated_at, blocked_at, trial_quota_reset_at, note
                FROM users
                """
            )
            await raw.execute("DROP TABLE users")
            await raw.execute("ALTER TABLE users_new RENAME TO users")
            await raw.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
            await raw.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_active_role ON users(role) WHERE blocked_at IS NULL"
            )
            await raw.commit()
        except Exception:
            await raw.rollback()
            raise
        finally:
            # Re-enable FK after committing so the pragma takes effect
            # (SQLite ignores it inside a transaction).
            await raw.execute("PRAGMA foreign_keys = ON")

    async def _migrate_v18(self) -> None:
        # Prevents double-grant at the DB level: a second INSERT while a pending
        # row already exists for the same user raises IntegrityError instead of
        # silently creating a duplicate pending trial request.
        await self.conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_trial_requests_one_pending
            ON trial_key_requests(telegram_user_id)
            WHERE status = 'pending'
            """
        )

    async def _migrate_v19(self) -> None:
        # Repair installations where the IP allocator reused the client_ip of a
        # revoked-but-not-deleted AWG key before that key was cleaned up.  When
        # such a row later transitions from 'revoked' (outside the partial unique
        # index) to 'pending_delete' (inside it) it would collide with the active
        # key that now owns the same IP.  Nulling the IP here is safe: the AWG
        # peer was already removed from the config when the key was revoked.
        await self.conn.execute(
            """
            UPDATE vpn_keys
            SET client_ip = NULL
            WHERE key_type = 'awg'
              AND status = 'revoked'
              AND client_ip IS NOT NULL
              AND client_ip IN (
                SELECT client_ip FROM vpn_keys
                WHERE key_type = 'awg'
                  AND status IN (
                    'pending_apply','active','apply_failed',
                    'pending_revoke','pending_delete','delete_failed'
                  )
                  AND client_ip IS NOT NULL
              )
            """
        )

    async def _migrate_v20(self) -> None:
        # WARP outbound-IP masking module settings (single-row table, id = 1).
        # Disabled by default; runtime columns are reset on every bot restart.
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS warp_settings (
              id              INTEGER PRIMARY KEY DEFAULT 1,
              enabled         INTEGER NOT NULL DEFAULT 0,
              config_path     TEXT    NOT NULL DEFAULT '/etc/amnezia/out-warp.conf',
              interface_name  TEXT    NOT NULL DEFAULT 'out-warp',
              routes_count    INTEGER NOT NULL DEFAULT 0,
              tunnel_up       INTEGER NOT NULL DEFAULT 0,
              routes_active   INTEGER NOT NULL DEFAULT 0,
              fail_streak     INTEGER NOT NULL DEFAULT 0,
              success_streak  INTEGER NOT NULL DEFAULT 0,
              last_handshake  INTEGER NOT NULL DEFAULT 0,
              last_check_ts   INTEGER NOT NULL DEFAULT 0,
              updated_at      INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        await self.conn.execute("INSERT OR IGNORE INTO warp_settings (id) VALUES (1)")

    async def _migrate_v21(self) -> None:
        # Protocol modules table — tracks which protocols are enabled/disabled.
        # All four protocols are seeded as enabled.
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS protocol_modules (
              name        TEXT PRIMARY KEY,
              enabled     INTEGER NOT NULL DEFAULT 1,
              disabled_at TEXT,
              disabled_by INTEGER REFERENCES users(telegram_user_id) ON DELETE SET NULL
            )
            """
        )
        for name in ("xray", "awg", "socks5", "mtproto"):
            await self.conn.execute(
                "INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES (?, 1)",
                (name,),
            )

    async def _migrate_v22(self) -> None:
        # Archive of traffic bytes for hard-deleted VPN keys, so dashboard
        # lifetime totals keep counting traffic from keys that no longer exist.
        # The covering indexes let the dashboard aggregations run as index-only
        # scans. The table is also declared in schema.sql (re-ensured on every
        # bootstrap); this migration backfills the object on legacy databases.
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deleted_key_traffic_archive (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              key_id INTEGER NOT NULL,
              owner_user_id INTEGER NOT NULL,
              key_type TEXT NOT NULL,
              downloaded_bytes INTEGER NOT NULL DEFAULT 0,
              uploaded_bytes INTEGER NOT NULL DEFAULT 0,
              deleted_at TEXT NOT NULL
            )
            """
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_deleted_key_traffic_archive_type "
            "ON deleted_key_traffic_archive(key_type, downloaded_bytes, uploaded_bytes)"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_deleted_key_traffic_archive_owner "
            "ON deleted_key_traffic_archive(owner_user_id, downloaded_bytes, uploaded_bytes)"
        )

    async def _migrate_v23(self) -> None:
        # VLESS transport selector on vpn_keys: 'tcp' (vless-in, flow=xtls-rprx-vision)
        # or 'http' (vless-xhttp-reality, no flow). Adding the column with a NOT NULL
        # DEFAULT 'tcp' backfills every existing row to 'tcp' (all pre-XHTTP keys are
        # TCP), which is exactly the desired migration. Guarded by a column check so
        # the migration is idempotent. Also declared in schema.sql for fresh DBs.
        vpn_cols = await self._table_columns("vpn_keys")
        if "transport" not in vpn_cols:
            await self.conn.execute(
                "ALTER TABLE vpn_keys ADD COLUMN transport TEXT NOT NULL DEFAULT 'tcp'"
            )

    async def _migrate_v24(self) -> None:
        # Server-status panel settings (single-row table, id = 1). Holds the
        # "detailed metrics" toggle (load average, uptime, network smoothing),
        # disabled by default. Also declared in schema.sql for fresh DBs.
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS server_status_settings (
              id               INTEGER PRIMARY KEY DEFAULT 1,
              detailed_enabled INTEGER NOT NULL DEFAULT 0,
              updated_at       INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        await self.conn.execute("INSERT OR IGNORE INTO server_status_settings (id) VALUES (1)")

    async def _migrate_v25(self) -> None:
        # Maintenance-mode settings (single-row table, id = 1). Holds the global
        # maintenance toggle, an optional custom banner message, and who/when it
        # was turned on. Disabled by default. Also declared in schema.sql for
        # fresh DBs.
        await self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS maintenance_settings (
              id         INTEGER PRIMARY KEY DEFAULT 1,
              enabled    INTEGER NOT NULL DEFAULT 0,
              message    TEXT,
              started_at INTEGER NOT NULL DEFAULT 0,
              started_by INTEGER,
              updated_at INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        await self.conn.execute("INSERT OR IGNORE INTO maintenance_settings (id) VALUES (1)")

    async def _migrate_v26(self) -> None:
        # Per-user settings on the users table:
        #  - language: NULL means "follow the global BOT_LANGUAGE default"; values
        #    'ru'/'en' override it for that user.
        #  - expiry_notifications_enabled: opt-out toggle for the "key expires in N
        #    days" reminders (1 = receive, default). Guarded by column checks so the
        #    migration is idempotent. Also declared in schema.sql for fresh DBs.
        user_cols = await self._table_columns("users")
        if "language" not in user_cols:
            await self.conn.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT NULL")
        if "expiry_notifications_enabled" not in user_cols:
            await self.conn.execute(
                "ALTER TABLE users ADD COLUMN expiry_notifications_enabled INTEGER NOT NULL DEFAULT 1"
            )

    async def _migrate_v27(self) -> None:
        # Segmented announcements: persist the audience filter (roles/protocols/
        # transports as JSON) on each batch so scheduled/resumed sends re-validate
        # against the chosen segment instead of the default approved-users audience.
        # NULL means an unsegmented (legacy "send to all") batch. Guarded by a
        # column check so the migration is idempotent. Also declared in schema.sql
        # for fresh DBs.
        batch_cols = await self._table_columns("announcement_batches")
        if "recipient_filter_json" not in batch_cols:
            await self.conn.execute(
                "ALTER TABLE announcement_batches ADD COLUMN recipient_filter_json TEXT"
            )

    async def _migrate_v28(self) -> None:
        # Transport/profile-aware Xray key naming. Two idempotent parts:
        #  1) Add the xhttp_profile column (NOT NULL DEFAULT 'base') — meaningful
        #     only for http keys; tcp/AWG/legacy rows stay 'base'. Also declared in
        #     schema.sql for fresh DBs.
        #  2) Rewrite Xray email labels into the scheme that encodes transport+
        #     profile: tcp -> xray_tcp_<rnd>, http -> xray_http_base_<rnd> (every
        #     pre-profile http key is base). UUIDs are NEVER touched (client
        #     identity). The live Xray config is reconciled to match on the next
        #     startup (XrayService.reconcile_email_labels). NOTE: Xray stats are
        #     keyed by email, so the rename resets accumulated per-label stats — an
        #     accepted trade-off.
        vpn_cols = await self._table_columns("vpn_keys")
        if "xhttp_profile" not in vpn_cols:
            await self.conn.execute(
                "ALTER TABLE vpn_keys ADD COLUMN xhttp_profile TEXT NOT NULL DEFAULT 'base'"
            )
        await self._relabel_xray_emails_v28()

    async def _migrate_v29(self) -> None:
        # Hysteria2 integration. Two idempotent parts:
        #  1) Allow 'hysteria2' as a vpn_keys.key_type. SQLite cannot ALTER a CHECK
        #     constraint, so the table is rebuilt when the legacy CHECK is present.
        #     Skipped when the CHECK already lists hysteria2 (fresh DBs created from
        #     schema.sql already include it), so the migration is a no-op there.
        #  2) Seed the 'hysteria2' protocol module row (mirrors schema.sql).
        await self._migrate_v29_vpn_keys_key_type_check()
        await self.conn.execute(
            "INSERT OR IGNORE INTO protocol_modules (name, enabled) VALUES ('hysteria2', 1)"
        )

    async def _migrate_v29_vpn_keys_key_type_check(self) -> None:
        table = await self.conn.execute_fetchone(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'vpn_keys'"
        )
        if table is None:
            return
        if "hysteria2" in str(table["sql"] or ""):
            # CHECK already lists hysteria2 (fresh DB / re-run) — nothing to rebuild.
            return
        # Rebuild vpn_keys to widen the key_type CHECK. UUIDs and every other column
        # are copied verbatim (client identity is never touched). Same approach as
        # _migrate_v16/_migrate_v17: run on the RAW connection with FK enforcement
        # OFF so dropping the old table does not cascade into vpn_key_traffic_stats
        # / trial_key_requests, then re-enable FK AFTER the commit (SQLite ignores
        # the pragma inside a transaction).
        #
        # Crash safety: the whole rebuild runs inside one explicit BEGIN…COMMIT.
        # Without it the leading `CREATE TABLE vpn_keys_new` (DDL) would autocommit
        # under sqlite3's legacy isolation mode — an implicit transaction only opens
        # before the first DML — so a crash between that CREATE and the final commit
        # would leave an orphan vpn_keys_new behind and the re-run would die on
        # "table vpn_keys_new already exists". The `DROP TABLE IF EXISTS` guard makes
        # the re-run self-healing even for a DB orphaned by an older build, and the
        # explicit transaction makes the rebuild atomic going forward.
        #
        # FORWARD-NOTE (not implemented here): if the connection default ever flips
        # to PRAGMA foreign_keys=ON *without* this local OFF toggle, the RENAME step
        # would have to keep foreign_keys=OFF for the duration anyway, because
        # vpn_key_traffic_stats holds an FK → vpn_keys(id). Today the toggle above
        # already guarantees that, so it does not bite.
        await self.commit()
        raw = self._raw_conn()
        await raw.execute("PRAGMA foreign_keys = OFF")
        try:
            await raw.execute("BEGIN")
            await raw.execute("DROP TABLE IF EXISTS vpn_keys_new")
            for index_name in (
                "idx_vpn_keys_owner",
                "idx_vpn_keys_type_status",
                "idx_vpn_keys_status_type",
                "idx_vpn_keys_owner_type_status",
                "idx_vpn_keys_uuid",
                "idx_vpn_keys_email_label",
                "idx_vpn_keys_public_key",
                "idx_vpn_keys_short_id",
                "idx_vpn_keys_client_ip_reserved",
                "idx_vpn_keys_expires_at",
            ):
                await raw.execute(f"DROP INDEX IF EXISTS {index_name}")
            await raw.execute(
                """
                CREATE TABLE vpn_keys_new (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  owner_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
                  username TEXT,
                  key_type TEXT NOT NULL CHECK(key_type IN ('xray','awg','hysteria2')),
                  status TEXT NOT NULL CHECK(status IN ('pending_apply','active','apply_failed','pending_revoke','revoked','pending_delete','delete_failed','deleted','failed')),
                  note TEXT,
                  uuid TEXT,
                  email_label TEXT,
                  public_key TEXT,
                  client_ip TEXT,
                  payload_json TEXT NOT NULL,
                  public_payload_json TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  revoked_at TEXT,
                  expires_at TEXT DEFAULT NULL,
                  expiry_notified_days TEXT DEFAULT NULL,
                  transport TEXT NOT NULL DEFAULT 'tcp',
                  xhttp_profile TEXT NOT NULL DEFAULT 'base',
                  deleted_at TEXT,
                  created_by INTEGER NOT NULL,
                  revoked_by INTEGER,
                  deleted_by INTEGER
                )
                """
            )
            # Explicit column list (not SELECT *) so a future column-order divergence
            # between schema.sql and this rebuild cannot silently misalign data.
            await raw.execute(
                """
                INSERT INTO vpn_keys_new (
                  id, owner_user_id, username, key_type, status, note, uuid, email_label,
                  public_key, client_ip, payload_json, public_payload_json, created_at,
                  updated_at, revoked_at, expires_at, expiry_notified_days, transport,
                  xhttp_profile, deleted_at, created_by, revoked_by, deleted_by
                )
                SELECT
                  id, owner_user_id, username, key_type, status, note, uuid, email_label,
                  public_key, client_ip, payload_json, public_payload_json, created_at,
                  updated_at, revoked_at, expires_at, expiry_notified_days, transport,
                  xhttp_profile, deleted_at, created_by, revoked_by, deleted_by
                FROM vpn_keys
                """
            )
            await raw.execute("DROP TABLE vpn_keys")
            await raw.execute("ALTER TABLE vpn_keys_new RENAME TO vpn_keys")
            # Recreate every vpn_keys index so a single bootstrap ends with the full
            # set (mirrors schema.sql plus the migration-only partials from v5/v6/v13).
            await raw.execute("CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner ON vpn_keys(owner_user_id)")
            await raw.execute("CREATE INDEX IF NOT EXISTS idx_vpn_keys_type_status ON vpn_keys(key_type, status)")
            await raw.execute("CREATE INDEX IF NOT EXISTS idx_vpn_keys_status_type ON vpn_keys(status, key_type)")
            await raw.execute(
                "CREATE INDEX IF NOT EXISTS idx_vpn_keys_owner_type_status ON vpn_keys(owner_user_id, key_type, status)"
            )
            await raw.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_uuid ON vpn_keys(uuid) WHERE uuid IS NOT NULL"
            )
            await raw.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_email_label ON vpn_keys(email_label) WHERE email_label IS NOT NULL"
            )
            await raw.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_public_key ON vpn_keys(public_key) WHERE public_key IS NOT NULL"
            )
            await raw.execute(
                "CREATE INDEX IF NOT EXISTS idx_vpn_keys_short_id "
                "ON vpn_keys(json_extract(payload_json, '$.short_id')) "
                "WHERE key_type = 'xray' AND json_valid(payload_json) AND json_extract(payload_json, '$.short_id') IS NOT NULL"
            )
            await raw.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_keys_client_ip_reserved "
                "ON vpn_keys(client_ip) "
                "WHERE client_ip IS NOT NULL AND key_type = 'awg' "
                "AND status IN ('pending_apply','active','apply_failed','pending_revoke','pending_delete','delete_failed')"
            )
            await raw.execute(
                "CREATE INDEX IF NOT EXISTS idx_vpn_keys_expires_at "
                "ON vpn_keys(expires_at) WHERE expires_at IS NOT NULL AND status = 'active'"
            )
            await raw.commit()
        except Exception:
            await raw.rollback()
            raise
        finally:
            # Re-enable FK after committing so the pragma actually takes effect
            # (SQLite ignores PRAGMA foreign_keys while a transaction is open).
            await raw.execute("PRAGMA foreign_keys = ON")

    async def _migrate_v30(self) -> None:
        # WARP module: two new warp_settings columns, both idempotent and also
        # declared in schema.sql for fresh DBs.
        #  1) kill_switch — operator opt-in fail-closed. When ON (and the monitor
        #     runs in legacy non-observer mode) the health monitor keeps the tunnel
        #     routes on a tunnel-down instead of removing them, so masked traffic
        #     blackholes on the down interface rather than leaking out the real IP.
        #     Defaults OFF (0) to preserve the existing fallback-to-direct behaviour.
        #  2) config_installed — decouples "a config is installed" from "routes_count
        #     > 0". A full-tunnel AllowedIPs (0.0.0.0/0) is stripped by the routes
        #     helper, leaving routes_count == 0, which previously made the module
        #     refuse to start. Backfilled to 1 for any row that already produced
        #     routes so existing installs keep their "config present" state.
        warp_cols = await self._table_columns("warp_settings")
        if "kill_switch" not in warp_cols:
            await self.conn.execute(
                "ALTER TABLE warp_settings ADD COLUMN kill_switch INTEGER NOT NULL DEFAULT 0"
            )
        if "config_installed" not in warp_cols:
            await self.conn.execute(
                "ALTER TABLE warp_settings ADD COLUMN config_installed INTEGER NOT NULL DEFAULT 0"
            )
            await self.conn.execute(
                "UPDATE warp_settings SET config_installed = 1 WHERE routes_count > 0"
            )

    async def _migrate_v31(self) -> None:
        # Per-key REALITY spiderX (spx) for VLESS client links. Purely client-side:
        # the value is emitted into the client link only, never into the server
        # inbound, so xray is never touched or restarted. Two idempotent parts:
        #  1) Add the nullable spider_x column. NULL means "do not emit spx", so
        #     every pre-v31 row (and every non-xray row) stays fully backward
        #     compatible. Guarded by a column check; also declared in schema.sql
        #     for fresh DBs.
        #  2) If XRAY_SPIDER_X_POOL is set, backfill xray keys whose spider_x is
        #     still NULL with a value picked deterministically from the pool by
        #     hashing the key UUID (reproducible, never random). An empty/unset
        #     pool leaves every row NULL and the bot behaves exactly as before.
        #     Only NULL rows are filled, so a re-run never overwrites an already
        #     assigned value. Runs in bootstrap()'s transaction — a failure rolls
        #     the whole thing back, so no partial state and no separate rollback
        #     mechanism is needed.
        vpn_cols = await self._table_columns("vpn_keys")
        if "spider_x" not in vpn_cols:
            await self.conn.execute("ALTER TABLE vpn_keys ADD COLUMN spider_x TEXT")
        # Defensive: settings already rejects any pool entry not starting with '/',
        # but the migration re-reads the raw env, so filter here too so a malformed
        # value can never reach a stored link.
        pool = tuple(p for p in parse_spider_x_pool(os.getenv("XRAY_SPIDER_X_POOL")) if p.startswith("/"))
        if not pool:
            return
        cursor = await self.conn.execute(
            "SELECT id, uuid, payload_json FROM vpn_keys "
            "WHERE key_type = 'xray' AND spider_x IS NULL"
        )
        rows = await cursor.fetchall()
        for row in rows:
            uuid_value = str(row["uuid"] or self._v28_load_json(row["payload_json"]).get("uuid") or "").strip()
            if not uuid_value:
                continue
            value = pick_spider_x(uuid_value, pool)
            if value is None:
                continue
            await self.conn.execute(
                "UPDATE vpn_keys SET spider_x = ? WHERE id = ?",
                (value, int(row["id"])),
            )

    async def _relabel_xray_emails_v28(self) -> None:
        cursor = await self.conn.execute(
            "SELECT id, email_label, transport, payload_json, public_payload_json "
            "FROM vpn_keys WHERE key_type = 'xray'"
        )
        rows = await cursor.fetchall()
        for row in rows:
            old_email = row["email_label"]
            # Idempotency: a label already on the new scheme is left as-is so a
            # re-run never double-prefixes and never regenerates a fresh suffix.
            if old_email and str(old_email).startswith(_V28_NEW_PREFIXES):
                continue
            transport = str(row["transport"] or "tcp").strip().lower()
            prefix = "xray_http_base" if transport == "http" else "xray_tcp"
            new_email = f"{prefix}_{self._v28_suffix_for(old_email)}"
            payload = self._v28_load_json(row["payload_json"])
            public_payload = self._v28_load_json(row["public_payload_json"])
            payload["email_label"] = new_email
            public_payload["email_label"] = new_email
            if old_email:
                display_name = public_payload.get("display_name")
                if isinstance(display_name, str):
                    public_payload["display_name"] = display_name.replace(f"#{old_email}", f"#{new_email}")
                link = public_payload.get("link")
                if isinstance(link, str) and "#" in link:
                    # The label is ASCII (alnum + '_'), so the link fragment is the
                    # bare label; rebuild it. The link itself is re-rendered on the
                    # next config view, this just keeps the stored copy consistent.
                    public_payload["link"] = f"{link.rsplit('#', 1)[0]}#{new_email}"
            await self.conn.execute(
                "UPDATE vpn_keys SET email_label = ?, payload_json = ?, public_payload_json = ? WHERE id = ?",
                (
                    new_email,
                    json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                    json.dumps(public_payload, ensure_ascii=False, separators=(",", ":")),
                    int(row["id"]),
                ),
            )

    @staticmethod
    def _v28_suffix_for(email: object) -> str:
        """Reuse an existing 5-char suffix if it matches the alphabet; else fresh."""
        if email:
            text = str(email)
            candidate = text[5:] if text.startswith("xray_") else text.rsplit("_", 1)[-1]
            if _V28_SUFFIX_RE.fullmatch(candidate):
                return candidate
        return "".join(secrets.choice(_V28_ALPHABET) for _ in range(5))

    @staticmethod
    def _v28_load_json(value: object) -> dict[str, Any]:
        if not isinstance(value, (str, bytes, bytearray)):
            return {}
        try:
            data = json.loads(value)
        except (TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    async def _create_performance_indexes(self) -> None:
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_active_role "
            "ON users(role) WHERE blocked_at IS NULL"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vpn_keys_short_id "
            "ON vpn_keys(json_extract(payload_json, '$.short_id')) "
            "WHERE key_type = 'xray' AND json_valid(payload_json) AND json_extract(payload_json, '$.short_id') IS NOT NULL"
        )

    async def _normalize_user_roles(self) -> None:
        legacy_map = {
            "superadmin": "SUPERADMIN",
            "super_admin": "SUPERADMIN",
            "approved": "APPROVED_USER",
            "approved_user": "APPROVED_USER",
            "pending": "PENDING_USER",
            "pending_user": "PENDING_USER",
            "blocked": "BLOCKED_USER",
            "blocked_user": "BLOCKED_USER",
            "banned": "BLOCKED_USER",
            "ban": "BLOCKED_USER",
            "revoked": "BLOCKED_USER",
        }
        for legacy, canonical in legacy_map.items():
            await self.conn.execute(
                "UPDATE users SET role = ? WHERE role = ?",
                (canonical, legacy),
            )

    async def _validate_proxy_live_duplicates(self) -> None:
        cursor = await self.conn.execute(
            """
            SELECT owner_user_id, access_type, COUNT(*) AS cnt
            FROM proxy_accesses
            WHERE status IN ('pending_apply','active','pending_revoke')
            GROUP BY owner_user_id, access_type
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        )
        row = await cursor.fetchone()
        if row is not None:
            raise RuntimeError(
                "Найдены дубли live proxy_accesses перед созданием unique index: "
                f"owner_user_id={row['owner_user_id']} access_type={row['access_type']} count={row['cnt']}. "
                "Остановите запуск, сделайте backup SQLite DB и вручную разберите конфликт перед миграцией."
            )

    async def commit(self) -> None:
        # A commit()/rollback() issued by a task that owns neither an explicit
        # transaction nor the implicit-write slot is an intentional safe no-op
        # (it waits for any in-flight transaction to finish, then commits the
        # autocommit-empty connection). This lets repository helpers call
        # commit() unconditionally without corrupting another task's transaction.
        current_task = asyncio.current_task()
        if self._transaction_owner is current_task and self._transaction_depth > 0:
            return
        if self._implicit_write_owner is current_task:
            try:
                await self._raw_conn().commit()
            finally:
                self._clear_implicit_write_owner()
            return
        if self._transaction_lock.locked():
            await self._wait_for_connection_turn()
        await self._raw_conn().commit()

    async def rollback(self) -> None:
        current_task = asyncio.current_task()
        if self._transaction_owner is current_task and self._transaction_depth > 0:
            return
        if self._implicit_write_owner is current_task:
            try:
                await self._raw_conn().rollback()
            finally:
                self._clear_implicit_write_owner()
            return
        if self._transaction_lock.locked():
            await self._wait_for_connection_turn()
        await self._raw_conn().rollback()

    @asynccontextmanager
    async def transaction(self, immediate: bool = True) -> AsyncIterator[aiosqlite.Connection]:
        # Nested transactions are intentionally FLATTENED (join semantics), NOT
        # implemented with SAVEPOINTs: a nested `transaction()` in the same task
        # joins the outer transaction, and only the outermost commits/rolls back.
        # This makes repository writes (whose internal `commit()` is a no-op while
        # an explicit transaction is open) composable into one atomic unit — see
        # test_approve_rolls_back_request_if_role_update_fails. A consequence is
        # that an exception caught *inside* an inner block is NOT independently
        # rolled back; callers needing partial rollback must use explicit SAVEPOINTs.
        current_task = asyncio.current_task()
        if current_task is None:
            raise RuntimeError("Database transaction requires an asyncio task")

        outermost = self._transaction_owner is not current_task
        context_token = None
        if outermost:
            if self._implicit_write_owner is current_task:
                raise RuntimeError("Нельзя открыть явную транзакцию после записи без commit/rollback")
            await self._transaction_lock.acquire()
            try:
                self._transaction_owner = current_task
                self._transaction_depth = 0
                await self._raw_conn().execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                context_token = _ACTIVE_TRANSACTION_DB.set(self)
            except Exception:
                self._transaction_owner = None
                self._transaction_depth = 0
                self._transaction_lock.release()
                raise
        self._transaction_depth += 1
        try:
            yield self.conn  # type: ignore[misc]
        except Exception:
            self._transaction_depth -= 1
            if outermost:
                try:
                    await self._raw_conn().rollback()
                finally:
                    if context_token is not None:
                        _ACTIVE_TRANSACTION_DB.reset(context_token)
                    self._transaction_owner = None
                    self._transaction_lock.release()
            raise
        else:
            self._transaction_depth -= 1
            if outermost:
                try:
                    await self._raw_conn().commit()
                finally:
                    if context_token is not None:
                        _ACTIVE_TRANSACTION_DB.reset(context_token)
                    self._transaction_owner = None
                    self._transaction_lock.release()

    async def _before_connection_execute(self, sql: str, *, write: bool | None = None) -> bool:
        current_task = asyncio.current_task()
        if current_task is None:
            raise RuntimeError("Database operation requires an asyncio task")
        is_write = _is_write_statement(sql) if write is None else write
        if self._transaction_owner is current_task:
            return False
        # Intentional, covered by test_connection_proxy_select_during_active_transaction_does_not_wait:
        # a task that INHERITED the active-transaction ContextVar (i.e. an asyncio
        # child task spawned within the owner's `async with transaction()` scope)
        # is treated as part of that transaction. Its reads proceed immediately
        # (read-your-writes) instead of waiting on the lock — this also prevents a
        # parent→child read deadlock when the owner awaits such a child before
        # committing. Independent reader tasks (which did NOT inherit the context)
        # fall through to the lock wait below, so they never see uncommitted data.
        if _ACTIVE_TRANSACTION_DB.get() is self and not is_write:
            return False
        if self._implicit_write_owner is current_task:
            if is_write:
                self._implicit_write_depth += 1
                return True
            return False

        if is_write:
            await self._transaction_lock.acquire()
            self._implicit_write_owner = current_task
            self._implicit_write_depth = 1
            return True

        if self._transaction_lock.locked():
            await self._wait_for_connection_turn()
        return False

    async def _wait_for_connection_turn(self) -> None:
        await self._transaction_lock.acquire()
        self._transaction_lock.release()

    async def _rollback_implicit_write_owner(self) -> None:
        try:
            await self._raw_conn().rollback()
        except Exception:
            logger.warning("Не удалось откатить неявную SQLite-транзакцию после ошибки", exc_info=True)
        finally:
            self._clear_implicit_write_owner()

    def _clear_implicit_write_owner(self) -> None:
        if self._implicit_write_owner is not None:
            self._implicit_write_owner = None
            self._implicit_write_depth = 0
            if self._transaction_lock.locked():
                self._transaction_lock.release()

    def _chmod_private_dir(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            path.chmod(0o700)
        except OSError:
            logger.warning("Не удалось выставить права 700 на директорию %s", path, exc_info=True)

    def _precreate_private_file(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        except OSError:
            logger.warning("Не удалось предсоздать файл SQLite с правами 600 %s", path, exc_info=True)

    def _chmod_private_file(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            path.chmod(0o600)
        except OSError:
            logger.warning("Не удалось выставить права 600 на файл SQLite %s", path, exc_info=True)

    def _chmod_sqlite_files(self) -> None:
        if os.name != "posix":
            return
        for path in (self.path, self.path.with_name(self.path.name + "-wal"), self.path.with_name(self.path.name + "-shm")):
            if path.exists():
                self._chmod_private_file(path)


class _ConnectionProxy:
    _GATED_METHODS: ClassVar[set[str]] = {
        "execute",
        "executemany",
        "executescript",
        "execute_insert",
        "execute_fetchall",
        "execute_fetchone",
        "commit",
        "rollback",
    }

    def __init__(self, db: Database) -> None:
        self._db = db

    async def execute(self, sql: str, parameters: Any = None, /) -> aiosqlite.Cursor:
        implicit_write = await self._db._before_connection_execute(sql)
        try:
            if parameters is None:
                return await self._db._raw_conn().execute(sql)
            return await self._db._raw_conn().execute(sql, parameters)
        except Exception:
            if implicit_write:
                await self._db._rollback_implicit_write_owner()
            raise

    async def executemany(self, sql: str, parameters: Any, /) -> aiosqlite.Cursor:
        implicit_write = await self._db._before_connection_execute(sql)
        try:
            return await self._db._raw_conn().executemany(sql, parameters)
        except Exception:
            if implicit_write:
                await self._db._rollback_implicit_write_owner()
            raise

    async def executescript(self, sql_script: str) -> aiosqlite.Cursor:
        implicit_write = await self._db._before_connection_execute(sql_script, write=True)
        try:
            return await self._db._raw_conn().executescript(sql_script)
        except Exception:
            if implicit_write:
                await self._db._rollback_implicit_write_owner()
            raise

    async def execute_insert(self, sql: str, parameters: Any = None, /) -> aiosqlite.Row | None:
        implicit_write = await self._db._before_connection_execute(sql, write=True)
        try:
            if parameters is None:
                return await self._db._raw_conn().execute_insert(sql)
            return await self._db._raw_conn().execute_insert(sql, parameters)
        except Exception:
            if implicit_write:
                await self._db._rollback_implicit_write_owner()
            raise

    async def execute_fetchall(self, sql: str, parameters: Any = None, /) -> list[aiosqlite.Row]:
        cursor = await self.execute(sql) if parameters is None else await self.execute(sql, parameters)
        try:
            return await cursor.fetchall()  # type: ignore[return-value]
        except Exception:
            if self._db._implicit_write_owner is asyncio.current_task():
                await self._db._rollback_implicit_write_owner()
            raise

    async def execute_fetchone(self, sql: str, parameters: Any = None, /) -> aiosqlite.Row | None:
        cursor = await self.execute(sql) if parameters is None else await self.execute(sql, parameters)
        try:
            return await cursor.fetchone()
        except Exception:
            if self._db._implicit_write_owner is asyncio.current_task():
                await self._db._rollback_implicit_write_owner()
            raise

    async def commit(self) -> None:
        await self._db.commit()

    async def rollback(self) -> None:
        await self._db.rollback()

    def __getattr__(self, name: str) -> Any:
        if name in self._GATED_METHODS:
            raise AttributeError(f"Database connection method {name!r} is gated by Database.conn proxy")
        return getattr(self._db._raw_conn(), name)


def _is_write_statement(sql: str) -> bool:
    stripped = _strip_leading_sql_noise(sql)
    if not stripped:
        return False
    first = stripped.split(None, 1)[0].rstrip(";").upper()
    if first in {"SELECT", "EXPLAIN"}:
        return False
    if first == "PRAGMA":
        return _pragma_mutates(stripped)
    if first == "WITH":
        return _cte_is_write(stripped)
    if first in {
        "INSERT",
        "UPDATE",
        "DELETE",
        "REPLACE",
        "CREATE",
        "DROP",
        "ALTER",
        "VACUUM",
        "REINDEX",
        "ANALYZE",
        "ATTACH",
        "DETACH",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
    }:
        return True
    return True


def _strip_leading_sql_noise(sql: str) -> str:
    stripped = sql.lstrip()
    while True:
        if stripped.startswith("--"):
            newline = stripped.find("\n")
            if newline == -1:
                return ""
            stripped = stripped[newline + 1 :].lstrip()
            continue
        if stripped.startswith("/*"):
            end = stripped.find("*/", 2)
            if end == -1:
                return stripped
            stripped = stripped[end + 2 :].lstrip()
            continue
        return stripped


def _cte_is_write(sql: str) -> bool:
    """Return True if a WITH/CTE statement's final DML clause is a write operation.

    Walks past balanced parentheses (CTE bodies) and inspects the first token
    of the statement that follows.  A read-only ``WITH … SELECT`` returns False;
    ``WITH … INSERT/UPDATE/DELETE/REPLACE`` returns True.
    """
    depth = 0
    i = 0
    n = len(sql)
    while i < n:
        c = sql[i]
        if c in ("'", '"', "`"):
            # Skip quoted string / identifier — they may contain parens.
            q = c
            i += 1
            while i < n:
                if sql[i] == q:
                    # SQLite uses doubled-quote for escaping.
                    if i + 1 < n and sql[i + 1] == q:
                        i += 2
                        continue
                    break
                i += 1
        elif c == "[":
            # SQLite bracket-quoted identifier.
            while i < n and sql[i] != "]":
                i += 1
        elif c == "-" and i + 1 < n and sql[i + 1] == "-":
            while i < n and sql[i] != "\n":
                i += 1
            continue
        elif c == "/" and i + 1 < n and sql[i + 1] == "*":
            i += 2
            while i < n - 1 and not (sql[i] == "*" and sql[i + 1] == "/"):
                i += 1
            i += 2
            continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                rest = sql[i + 1 :].lstrip()
                if rest.startswith(","):
                    # Comma separates CTE definitions — keep scanning.
                    i += 1
                    continue
                # Whatever follows is the main DML statement.
                first_token = rest.split(None, 1)[0].upper().rstrip(";") if rest else ""
                return first_token in {"INSERT", "UPDATE", "DELETE", "REPLACE"}
        i += 1
    return True  # Cannot parse — conservatively treat as write.


def _pragma_mutates(sql: str) -> bool:
    parts = sql.split(None, 1)
    body = parts[1].strip() if len(parts) > 1 else ""
    if "=" in body:
        return True
    name = body.split("(", 1)[0].split(";", 1)[0].strip().lower()
    name = name.split(None, 1)[0] if name else ""
    return name in {
        "application_id",
        "auto_vacuum",
        "busy_timeout",
        "foreign_keys",
        "incremental_vacuum",
        "journal_mode",
        "locking_mode",
        "optimize",
        "synchronous",
        "user_version",
        "vacuum",
        "wal_checkpoint",
    }
