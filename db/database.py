from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite


CURRENT_SCHEMA_VERSION = 10
logger = logging.getLogger(__name__)
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
                (
                    "SUPERADMIN",
                    "APPROVED_USER",
                    "PENDING_USER",
                    "BLOCKED_USER",
                    "superadmin",
                    "super_admin",
                    "approved",
                    "approved_user",
                    "pending",
                    "pending_user",
                    "blocked",
                    "blocked_user",
                    "banned",
                    "ban",
                    "revoked",
                ),
            ),
            ("access_requests", "status", ("pending", "approved", "rejected")),
            (
                "vpn_keys",
                "key_type",
                ("xray", "awg"),
            ),
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
            ("announcement_batches", "status", ("pending", "sending", "completed", "failed", "cancelled")),
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
            yield self.conn
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
    _GATED_METHODS = {
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
            return await cursor.fetchall()
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
        return True
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
