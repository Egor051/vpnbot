from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import aiosqlite


CURRENT_SCHEMA_VERSION = 4
logger = logging.getLogger(__name__)


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
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
        await self._raw_conn().execute("PRAGMA synchronous = NORMAL")
        await self._raw_conn().execute("PRAGMA busy_timeout = 5000")
        await self._raw_conn().commit()
        if created or os.name == "posix":
            self._chmod_private_file(self.path)

    async def close(self) -> None:
        if self._conn is not None:
            await self._raw_conn().close()
            self._conn = None

    async def bootstrap(self, schema_path: Path | None = None) -> None:
        if schema_path is None:
            schema_path = Path(__file__).with_name("schema.sql")
        sql = schema_path.read_text(encoding="utf-8")
        await self.conn.executescript(sql)
        await self._apply_migrations()
        await self.commit()

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
            await self._validate_reference_integrity()

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
        for table, column in (("access_requests", "telegram_user_id"), ("vpn_keys", "owner_user_id")):
            cursor = await self.conn.execute(
                f"""
                SELECT COUNT(*) AS cnt
                FROM {table}
                LEFT JOIN users ON users.telegram_user_id = {table}.{column}
                WHERE users.telegram_user_id IS NULL
                """
            )
            row = await cursor.fetchone()
            count = int(row["cnt"]) if row is not None else 0
            if count:
                logger.warning(
                    "Найдены записи без связанного пользователя: table=%s column=%s count=%s",
                    table,
                    column,
                    count,
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

    @asynccontextmanager
    async def transaction(self, immediate: bool = True) -> AsyncIterator[aiosqlite.Connection]:
        current_task = asyncio.current_task()
        if current_task is None:
            raise RuntimeError("Database transaction requires an asyncio task")

        outermost = self._transaction_owner is not current_task
        if outermost:
            if self._implicit_write_owner is current_task:
                raise RuntimeError("Нельзя открыть явную транзакцию после записи без commit/rollback")
            await self._transaction_lock.acquire()
            try:
                self._transaction_owner = current_task
                self._transaction_depth = 0
                await self._raw_conn().execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
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
                    self._transaction_owner = None
                    self._transaction_lock.release()
            raise
        else:
            self._transaction_depth -= 1
            if outermost:
                try:
                    await self._raw_conn().commit()
                finally:
                    self._transaction_owner = None
                    self._transaction_lock.release()

    async def _before_connection_execute(self, sql: str, *, write: bool | None = None) -> bool:
        current_task = asyncio.current_task()
        if current_task is None:
            raise RuntimeError("Database operation requires an asyncio task")
        is_write = _is_write_statement(sql) if write is None else write
        if self._transaction_owner is current_task:
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


class _ConnectionProxy:
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

    async def executescript(self, sql_script: str) -> aiosqlite.Cursor:
        implicit_write = await self._db._before_connection_execute(sql_script, write=True)
        try:
            return await self._db._raw_conn().executescript(sql_script)
        except Exception:
            if implicit_write:
                await self._db._rollback_implicit_write_owner()
            raise

    def __getattr__(self, name: str) -> Any:
        return getattr(self._db._raw_conn(), name)


def _is_write_statement(sql: str) -> bool:
    stripped = sql.lstrip()
    if not stripped:
        return False
    first = stripped.split(None, 1)[0].upper()
    return first not in {"SELECT", "PRAGMA", "WITH", "EXPLAIN"}
