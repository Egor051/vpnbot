from __future__ import annotations

import json
import logging
from typing import Any

from aiosqlite import Row

from db.database import Database
from models.dto import ProxyAccess, ProxyLifecycleStats
from models.enums import ProxyAccessStatus, ProxyAccessType

logger = logging.getLogger(__name__)


def _json_loads(value: str) -> dict[str, object]:
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        logger.warning("Некорректный JSON в proxy_accesses payload/public_payload")
        return {"_corrupted": True}
    return data if isinstance(data, dict) else {}


def _enum_value(
    enum_cls: type[ProxyAccessType] | type[ProxyAccessStatus],
    value: str,
    field: str,
) -> ProxyAccessType | ProxyAccessStatus:
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise RuntimeError(
            f"Некорректное значение {field} в SQLite: {value!r}. "
            "Сделайте backup DB и исправьте повреждённую запись вручную."
        ) from exc


def _row_to_proxy_access(row: Row | None) -> ProxyAccess | None:
    if row is None:
        return None
    keys = set(row.keys())
    return ProxyAccess(
        id=int(row["id"]),
        owner_user_id=int(row["owner_user_id"]),
        username=row["username"],
        access_type=_enum_value(ProxyAccessType, row["access_type"], "proxy_accesses.access_type"),  # type: ignore[arg-type]
        status=_enum_value(ProxyAccessStatus, row["status"], "proxy_accesses.status"),  # type: ignore[arg-type]
        payload=_json_loads(row["payload_json"]),
        public_payload=_json_loads(row["public_payload_json"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_shown_at=row["last_shown_at"],
        revoked_at=row["revoked_at"],
        deleted_at=row["deleted_at"],
        created_by=int(row["created_by"]),
        revoked_by=row["revoked_by"],
        deleted_by=row["deleted_by"],
        reason=row["reason"],
        error=row["error"],
        secret_fingerprint=row["secret_fingerprint"] if "secret_fingerprint" in keys else None,
        apply_generation=int(row["apply_generation"] or 0) if "apply_generation" in keys else 0,
        activated_at=row["activated_at"] if "activated_at" in keys else None,
        last_apply_at=row["last_apply_at"] if "last_apply_at" in keys else None,
    )


class ProxyAccessRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(
        self,
        *,
        owner_user_id: int,
        username: str | None,
        access_type: ProxyAccessType,
        status: ProxyAccessStatus,
        payload: dict[str, Any],
        public_payload: dict[str, Any],
        created_by: int,
        now: str,
        secret_fingerprint: str | None = None,
        apply_generation: int = 0,
    ) -> ProxyAccess:
        cursor = await self.db.conn.execute(
            """
            INSERT INTO proxy_accesses (
              owner_user_id, username, access_type, status,
              secret_fingerprint, apply_generation,
              payload_json, public_payload_json,
              created_at, updated_at, created_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_user_id,
                username,
                access_type.value,
                status.value,
                secret_fingerprint,
                apply_generation,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                json.dumps(public_payload, ensure_ascii=False, separators=(",", ":")),
                now,
                now,
                created_by,
            ),
        )
        await self.db.commit()
        access = await self.get_by_id(int(cursor.lastrowid))
        if access is None:
            raise RuntimeError("Proxy access insert failed")
        return access

    async def get_by_id(self, access_id: int) -> ProxyAccess | None:
        cursor = await self.db.conn.execute("SELECT * FROM proxy_accesses WHERE id = ?", (access_id,))
        row = await cursor.fetchone()
        return _row_to_proxy_access(row)

    async def list_by_owner(
        self,
        owner_user_id: int,
        *,
        include_deleted: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ProxyAccess]:
        deleted_filter = "" if include_deleted else "AND status != ?"
        params: list[object] = [owner_user_id]
        if not include_deleted:
            params.append(ProxyAccessStatus.DELETED.value)
        params.extend([limit, offset])
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM proxy_accesses
            WHERE owner_user_id = ?
              {deleted_filter}
            ORDER BY created_at ASC, id ASC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        rows = await cursor.fetchall()
        return [access for row in rows if (access := _row_to_proxy_access(row)) is not None]

    async def list_by_owner_statuses(
        self,
        owner_user_id: int,
        statuses: set[ProxyAccessStatus],
        *,
        limit: int = 500,
        offset: int = 0,
    ) -> list[ProxyAccess]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM proxy_accesses
            WHERE owner_user_id = ? AND status IN ({placeholders})
            ORDER BY updated_at ASC, id ASC
            LIMIT ? OFFSET ?
            """,
            (owner_user_id, *(status.value for status in statuses), limit, offset),
        )
        rows = await cursor.fetchall()
        return [access for row in rows if (access := _row_to_proxy_access(row)) is not None]

    async def find_user_access_by_type_statuses(
        self,
        owner_user_id: int,
        access_type: ProxyAccessType,
        statuses: set[ProxyAccessStatus],
    ) -> ProxyAccess | None:
        if not statuses:
            return None
        placeholders = ",".join("?" for _ in statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM proxy_accesses
            WHERE owner_user_id = ?
              AND access_type = ?
              AND status IN ({placeholders})
            ORDER BY id ASC
            LIMIT 1
            """,
            (owner_user_id, access_type.value, *(status.value for status in statuses)),
        )
        row = await cursor.fetchone()
        return _row_to_proxy_access(row)

    async def find_by_socks5_login(self, login: str) -> ProxyAccess | None:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM proxy_accesses
            WHERE access_type = ?
              AND json_extract(payload_json, '$.login') = ?
            LIMIT 1
            """,
            (ProxyAccessType.SOCKS5.value, login),
        )
        row = await cursor.fetchone()
        return _row_to_proxy_access(row)

    async def find_by_secret_fingerprint(self, fingerprint: str) -> ProxyAccess | None:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM proxy_accesses
            WHERE access_type = ?
              AND secret_fingerprint = ?
            LIMIT 1
            """,
            (ProxyAccessType.MTPROTO.value, fingerprint),
        )
        row = await cursor.fetchone()
        return _row_to_proxy_access(row)

    async def list_by_type_statuses(
        self,
        access_type: ProxyAccessType,
        statuses: set[ProxyAccessStatus],
        *,
        limit: int = 500,
        after_id: int = 0,
    ) -> list[ProxyAccess]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM proxy_accesses
            WHERE access_type = ?
              AND status IN ({placeholders})
              AND id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (access_type.value, *(status.value for status in statuses), after_id, limit),
        )
        rows = await cursor.fetchall()
        return [access for row in rows if (access := _row_to_proxy_access(row)) is not None]

    async def mark_active(
        self,
        access_id: int,
        now: str,
        *,
        payload: dict[str, Any] | None = None,
        public_payload: dict[str, Any] | None = None,
        apply_generation: int | None = None,
    ) -> None:
        current = await self.get_by_id(access_id)
        if current is None:
            raise RuntimeError("Proxy access not found")
        await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?,
                updated_at = ?,
                activated_at = COALESCE(activated_at, ?),
                last_apply_at = ?,
                apply_generation = COALESCE(?, apply_generation),
                error = NULL,
                payload_json = ?,
                public_payload_json = ?
            WHERE id = ?
            """,
            (
                ProxyAccessStatus.ACTIVE.value,
                now,
                now,
                now,
                apply_generation,
                json.dumps(payload if payload is not None else current.payload, ensure_ascii=False, separators=(",", ":")),
                json.dumps(
                    public_payload if public_payload is not None else current.public_payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                access_id,
            ),
        )
        await self.db.commit()

    async def update_payloads(
        self,
        access_id: int,
        now: str,
        *,
        payload: dict[str, Any],
        public_payload: dict[str, Any],
        secret_fingerprint: str | None = None,
    ) -> None:
        await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET payload_json = ?,
                public_payload_json = ?,
                secret_fingerprint = COALESCE(?, secret_fingerprint),
                updated_at = ?
            WHERE id = ?
            """,
            (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                json.dumps(public_payload, ensure_ascii=False, separators=(",", ":")),
                secret_fingerprint,
                now,
                access_id,
            ),
        )
        await self.db.commit()

    async def set_status(
        self,
        access_id: int,
        status: ProxyAccessStatus,
        now: str,
        *,
        error: str | None = None,
        reason: str | None = None,
    ) -> None:
        await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?, updated_at = ?, error = ?, reason = COALESCE(?, reason)
            WHERE id = ?
            """,
            (status.value, now, error[:512] if error else None, reason, access_id),
        )
        await self.db.commit()

    async def mark_shown(self, access_id: int, now: str) -> None:
        await self.db.conn.execute(
            "UPDATE proxy_accesses SET last_shown_at = ?, updated_at = ? WHERE id = ?",
            (now, now, access_id),
        )
        await self.db.commit()

    async def mark_revoked(self, access_id: int, actor_user_id: int, now: str, *, reason: str | None = None) -> None:
        await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?,
                updated_at = ?,
                revoked_at = COALESCE(revoked_at, ?),
                revoked_by = COALESCE(revoked_by, ?),
                reason = COALESCE(?, reason),
                last_apply_at = ?,
                error = NULL
            WHERE id = ?
            """,
            (ProxyAccessStatus.REVOKED.value, now, now, actor_user_id, reason, now, access_id),
        )
        await self.db.commit()

    async def mark_inactive(self, access_id: int, actor_user_id: int, now: str, *, reason: str | None = None) -> None:
        await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?,
                updated_at = ?,
                revoked_at = COALESCE(revoked_at, ?),
                revoked_by = COALESCE(revoked_by, ?),
                reason = COALESCE(?, reason),
                error = NULL
            WHERE id = ?
            """,
            (ProxyAccessStatus.INACTIVE.value, now, now, actor_user_id, reason, access_id),
        )
        await self.db.commit()

    async def mark_deleted(self, access_id: int, actor_user_id: int, now: str, *, reason: str | None = None) -> None:
        await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?,
                updated_at = ?,
                deleted_at = COALESCE(deleted_at, ?),
                deleted_by = COALESCE(deleted_by, ?),
                reason = COALESCE(?, reason),
                error = NULL
            WHERE id = ?
            """,
            (ProxyAccessStatus.DELETED.value, now, now, actor_user_id, reason, access_id),
        )
        await self.db.commit()

    async def lifecycle_stats(self) -> ProxyLifecycleStats:
        cursor = await self.db.conn.execute(
            """
            SELECT access_type, status, COUNT(*) AS cnt
            FROM proxy_accesses
            GROUP BY access_type, status
            """
        )
        rows = await cursor.fetchall()
        counts: dict[tuple[str, str], int] = {
            (str(row["access_type"]), str(row["status"])): int(row["cnt"]) for row in rows
        }
        inactive_statuses = {
            ProxyAccessStatus.REVOKED.value,
            ProxyAccessStatus.INACTIVE.value,
            ProxyAccessStatus.DELETED.value,
        }

        def count(access_type: ProxyAccessType, statuses: set[str] | None = None) -> int:
            if statuses is None:
                return sum(value for (item_type, _status), value in counts.items() if item_type == access_type.value)
            return sum(
                value
                for (item_type, status), value in counts.items()
                if item_type == access_type.value and status in statuses
            )

        mode_cursor = await self.db.conn.execute(
            """
            SELECT
              COALESCE(json_extract(payload_json, '$.mode'), 'static') AS mode,
              status,
              COUNT(*) AS cnt
            FROM proxy_accesses
            WHERE access_type = ?
            GROUP BY mode, status
            """,
            (ProxyAccessType.MTPROTO.value,),
        )
        mode_rows = await mode_cursor.fetchall()
        mode_counts: dict[tuple[str, str], int] = {
            (str(row["mode"]), str(row["status"])): int(row["cnt"]) for row in mode_rows
        }

        def mtproto_mode_count(mode: str, statuses: set[str] | None = None) -> int:
            if statuses is None:
                return sum(value for (item_mode, _status), value in mode_counts.items() if item_mode == mode)
            return sum(
                value
                for (item_mode, status), value in mode_counts.items()
                if item_mode == mode and status in statuses
            )

        return ProxyLifecycleStats(
            socks5_issued=count(ProxyAccessType.SOCKS5),
            socks5_active=count(ProxyAccessType.SOCKS5, {ProxyAccessStatus.ACTIVE.value}),
            socks5_revoked=count(ProxyAccessType.SOCKS5, inactive_statuses),
            mtproto_issued=count(ProxyAccessType.MTPROTO),
            mtproto_active=count(ProxyAccessType.MTPROTO, {ProxyAccessStatus.ACTIVE.value}),
            mtproto_deactivated=count(ProxyAccessType.MTPROTO, inactive_statuses),
            mtproto_managed_issued=mtproto_mode_count("managed"),
            mtproto_managed_active=mtproto_mode_count("managed", {ProxyAccessStatus.ACTIVE.value}),
            mtproto_managed_revoked=mtproto_mode_count("managed", inactive_statuses),
            mtproto_legacy_static=mtproto_mode_count("static"),
            mtproto_apply_failed=count(ProxyAccessType.MTPROTO, {ProxyAccessStatus.APPLY_FAILED.value}),
            mtproto_revoke_failed=count(ProxyAccessType.MTPROTO, {ProxyAccessStatus.REVOKE_FAILED.value}),
        )
