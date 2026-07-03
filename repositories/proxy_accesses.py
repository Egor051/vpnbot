
import json
import logging
from typing import Any

from aiosqlite import Row

from db.database import Database
from db.exceptions import ConcurrentModificationError
from models.dto import (
    ProxyAccess,
    ProxyAccessStatsItem,
    ProxyActiveAccessRef,
    ProxyAdminStats,
    ProxyAdminUserStats,
    ProxyLifecycleStats,
    ProxyUserStats,
)
from models.enums import ProxyAccessStatus, ProxyAccessType
from repositories._helpers import _clamp_limit, _clamp_offset, enum_value, json_loads_dict
from services.errors import InvalidTransition

logger = logging.getLogger(__name__)


def _json_loads(value: str) -> dict[str, object]:
    return json_loads_dict(value, "proxy_accesses payload/public_payload")


def _row_to_proxy_access(row: Row | None) -> ProxyAccess | None:
    if row is None:
        return None
    keys = set(row.keys())
    return ProxyAccess(
        id=int(row["id"]),
        owner_user_id=int(row["owner_user_id"]),
        username=row["username"],
        access_type=enum_value(ProxyAccessType, row["access_type"], "proxy_accesses.access_type"),
        status=enum_value(ProxyAccessStatus, row["status"], "proxy_accesses.status"),
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


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)  # type: ignore[call-overload, no-any-return]
    except (TypeError, ValueError, OverflowError):
        return None


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    result = str(value)
    return result if result else None


def _row_to_proxy_stats_item(row: Row | None) -> ProxyAccessStatsItem | None:
    if row is None:
        return None
    return ProxyAccessStatsItem(
        id=int(row["id"]),
        owner_user_id=int(row["owner_user_id"]),
        username=row["username"],
        access_type=enum_value(ProxyAccessType, row["access_type"], "proxy_accesses.access_type"),
        status=enum_value(ProxyAccessStatus, row["status"], "proxy_accesses.status"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        activated_at=row["activated_at"],
        last_shown_at=row["last_shown_at"],
        revoked_at=row["revoked_at"],
        deleted_at=row["deleted_at"],
        host=_optional_str(row["host"]),
        port=_optional_int(row["port"]),
        login=_optional_str(row["login"]),
        mtproto_mode=_optional_str(row["mtproto_mode"]),
        mtproto_source=_optional_str(row["mtproto_source"]),
        secret_fingerprint=_optional_str(row["secret_fingerprint"]),
    )


_SANITIZED_STATS_SELECT = """
SELECT
  pa.id,
  pa.owner_user_id,
  COALESCE(u.username, pa.username) AS username,
  pa.access_type,
  pa.status,
  pa.created_at,
  pa.updated_at,
  pa.activated_at,
  pa.last_shown_at,
  pa.revoked_at,
  pa.deleted_at,
  COALESCE(
    json_extract(pa.public_payload_json, '$.host'),
    json_extract(pa.payload_json, '$.host')
  ) AS host,
  COALESCE(
    json_extract(pa.public_payload_json, '$.port'),
    json_extract(pa.payload_json, '$.port')
  ) AS port,
  COALESCE(
    json_extract(pa.public_payload_json, '$.login'),
    json_extract(pa.payload_json, '$.login')
  ) AS login,
  COALESCE(
    json_extract(pa.public_payload_json, '$.mode'),
    json_extract(pa.payload_json, '$.mode')
  ) AS mtproto_mode,
  COALESCE(
    json_extract(pa.public_payload_json, '$.source'),
    json_extract(pa.payload_json, '$.source')
  ) AS mtproto_source,
  COALESCE(
    pa.secret_fingerprint,
    json_extract(pa.public_payload_json, '$.fingerprint'),
    json_extract(pa.payload_json, '$.fingerprint')
  ) AS secret_fingerprint
FROM proxy_accesses pa
LEFT JOIN users u ON u.telegram_user_id = pa.owner_user_id
"""


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
        """Insert a new proxy access record and return it."""
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
        assert cursor.lastrowid is not None
        access = await self.get_by_id(int(cursor.lastrowid))
        if access is None:
            raise RuntimeError("Proxy access insert failed")
        return access

    async def get_by_id(self, access_id: int) -> ProxyAccess | None:
        """Return proxy access by primary key, or None if not found.

        Does NOT filter by status — caller must check access.status when
        only non-deleted accesses are acceptable.
        """
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
        """Return a paginated list of proxy accesses for an owner, excluding deleted by default."""
        deleted_filter = "" if include_deleted else "AND status != ?"
        params: list[object] = [owner_user_id]
        if not include_deleted:
            params.append(ProxyAccessStatus.DELETED.value)
        params.extend([_clamp_limit(limit), _clamp_offset(offset)])
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
        """Return a paginated list of an owner's proxy accesses filtered by the given statuses."""
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
            (owner_user_id, *(status.value for status in statuses), _clamp_limit(limit), _clamp_offset(offset)),
        )
        rows = await cursor.fetchall()
        return [access for row in rows if (access := _row_to_proxy_access(row)) is not None]

    async def find_user_access_by_type_statuses(
        self,
        owner_user_id: int,
        access_type: ProxyAccessType,
        statuses: set[ProxyAccessStatus],
    ) -> ProxyAccess | None:
        """Return the first proxy access matching the owner, type, and statuses, or None."""
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
        """Return the most recent non-deleted/inactive SOCKS5 proxy access by login, or None."""
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM proxy_accesses
            WHERE access_type = ?
              AND json_extract(payload_json, '$.login') = ?
              AND status NOT IN (?, ?)
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (ProxyAccessType.SOCKS5.value, login,
             ProxyAccessStatus.DELETED.value, ProxyAccessStatus.INACTIVE.value),
        )
        row = await cursor.fetchone()
        return _row_to_proxy_access(row)

    async def find_by_secret_fingerprint(self, fingerprint: str) -> ProxyAccess | None:
        """Return the most recent non-deleted/inactive MTProto proxy access by fingerprint, or None."""
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM proxy_accesses
            WHERE access_type = ?
              AND secret_fingerprint = ?
              AND status NOT IN (?, ?)
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (ProxyAccessType.MTPROTO.value, fingerprint,
             ProxyAccessStatus.DELETED.value, ProxyAccessStatus.INACTIVE.value),
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
        """Return proxy accesses of a type with the given statuses, keyset-paginated by id."""
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
            (access_type.value, *(status.value for status in statuses), after_id, _clamp_limit(limit)),
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
        """Transition a pending or apply-failed proxy access to active, updating payloads.

        payload/public_payload are written ONLY when provided; when omitted the
        stored JSON is left byte-for-byte untouched. This avoids clobbering an
        already-corrupt payload_json with the ``{"_corrupted": true}`` sentinel
        that ``json_loads_dict`` substitutes on a parse failure — re-serializing
        the parsed DTO would otherwise overwrite the recoverable original bytes.
        """
        async with self.db.transaction():
            current = await self.get_by_id(access_id)
            if current is None:
                raise RuntimeError("Proxy access not found")
            # Only column-name fragments (internal constants) are interpolated;
            # every value is bound via a placeholder — no user input reaches SQL.
            set_parts = [
                "status = ?",
                "updated_at = ?",
                "activated_at = COALESCE(activated_at, ?)",
                "last_apply_at = ?",
                "apply_generation = COALESCE(?, apply_generation)",
                "error = NULL",
            ]
            params: list[object] = [ProxyAccessStatus.ACTIVE.value, now, now, now, apply_generation]
            if payload is not None:
                set_parts.append("payload_json = ?")
                params.append(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
            if public_payload is not None:
                set_parts.append("public_payload_json = ?")
                params.append(json.dumps(public_payload, ensure_ascii=False, separators=(",", ":")))
            params.extend([access_id, ProxyAccessStatus.PENDING_APPLY.value, ProxyAccessStatus.APPLY_FAILED.value])
            cursor = await self.db.conn.execute(
                f"""
                UPDATE proxy_accesses
                SET {", ".join(set_parts)}
                WHERE id = ? AND status IN (?, ?)
                """,
                tuple(params),
            )
            if cursor.rowcount == 0:
                logger.warning(
                    "mark_active: proxy access %s skipped — not in a transitionable status (concurrent modification?)",
                    access_id,
                )

    async def update_payloads(
        self,
        access_id: int,
        now: str,
        *,
        payload: dict[str, Any],
        public_payload: dict[str, Any],
        secret_fingerprint: str | None = None,
    ) -> None:
        """Replace a proxy access's payload and public payload, optionally setting its fingerprint."""
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
        allowed_from_statuses: tuple[ProxyAccessStatus, ...] | None = None,
    ) -> None:
        """Set a proxy access's status, raising if it is not in an allowed source status."""
        if allowed_from_statuses:
            placeholders = ",".join("?" for _ in allowed_from_statuses)
            cursor = await self.db.conn.execute(
                f"""
                UPDATE proxy_accesses
                SET status = ?, updated_at = ?, error = ?, reason = COALESCE(?, reason)
                WHERE id = ? AND status IN ({placeholders})
                """,
                (status.value, now, error[:512] if error else None, reason, access_id,
                 *(s.value for s in allowed_from_statuses)),
            )
            await self.db.commit()
            if cursor.rowcount == 0:
                raise ConcurrentModificationError(
                    f"Proxy access {access_id} is not in an allowed status for this transition "
                    f"(concurrent modification?)"
                )
        else:
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
        """Record the time a proxy access was last shown to its owner."""
        await self.db.conn.execute(
            "UPDATE proxy_accesses SET last_shown_at = ?, updated_at = ? WHERE id = ?",
            (now, now, access_id),
        )
        await self.db.commit()

    async def mark_revoked(self, access_id: int, actor_user_id: int, now: str, *, reason: str | None = None) -> None:
        """Mark a proxy access as revoked, raising if already revoked or deleted."""
        cursor = await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?,
                updated_at = ?,
                revoked_at = COALESCE(revoked_at, ?),
                revoked_by = COALESCE(revoked_by, ?),
                reason = COALESCE(?, reason),
                last_apply_at = ?,
                error = NULL
            WHERE id = ? AND status NOT IN (?, ?)
            """,
            (ProxyAccessStatus.REVOKED.value, now, now, actor_user_id, reason, now, access_id,
             ProxyAccessStatus.REVOKED.value, ProxyAccessStatus.DELETED.value),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise InvalidTransition(f"Proxy access {access_id} is already revoked or deleted")

    async def mark_inactive(self, access_id: int, actor_user_id: int, now: str, *, reason: str | None = None) -> None:
        """Mark a proxy access as inactive, raising if already inactive, revoked, or deleted."""
        cursor = await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?,
                updated_at = ?,
                revoked_at = COALESCE(revoked_at, ?),
                revoked_by = COALESCE(revoked_by, ?),
                reason = COALESCE(?, reason),
                error = NULL
            WHERE id = ? AND status NOT IN (?, ?, ?)
            """,
            (ProxyAccessStatus.INACTIVE.value, now, now, actor_user_id, reason, access_id,
             ProxyAccessStatus.INACTIVE.value, ProxyAccessStatus.REVOKED.value, ProxyAccessStatus.DELETED.value),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise InvalidTransition(f"Proxy access {access_id} is already inactive, revoked or deleted")

    async def mark_deleted(self, access_id: int, actor_user_id: int, now: str, *, reason: str | None = None) -> None:
        """Mark a proxy access as deleted, raising if already deleted."""
        cursor = await self.db.conn.execute(
            """
            UPDATE proxy_accesses
            SET status = ?,
                updated_at = ?,
                deleted_at = COALESCE(deleted_at, ?),
                deleted_by = COALESCE(deleted_by, ?),
                reason = COALESCE(?, reason),
                error = NULL
            WHERE id = ? AND status != ?
            """,
            (ProxyAccessStatus.DELETED.value, now, now, actor_user_id, reason, access_id,
             ProxyAccessStatus.DELETED.value),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise InvalidTransition(f"Proxy access {access_id} is already deleted")

    async def lifecycle_stats(self) -> ProxyLifecycleStats:
        """Return aggregate proxy lifecycle counts broken down by type, status, and MTProto mode."""
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

    async def get_user_proxy_stats(self, owner_user_id: int) -> ProxyUserStats:
        """Return sanitized proxy access stats for a single user, ordered by type and status."""
        cursor = await self.db.conn.execute(
            _SANITIZED_STATS_SELECT
            + """
            WHERE pa.owner_user_id = ?
            ORDER BY
              CASE pa.access_type WHEN 'socks5' THEN 0 WHEN 'mtproto' THEN 1 ELSE 2 END,
              CASE pa.status WHEN 'active' THEN 0 ELSE 1 END,
              pa.created_at DESC,
              pa.id DESC
            """,
            (owner_user_id,),
        )
        rows = await cursor.fetchall()
        accesses = tuple(item for row in rows if (item := _row_to_proxy_stats_item(row)) is not None)
        return ProxyUserStats(owner_user_id=owner_user_id, accesses=accesses)

    async def list_proxy_accesses_for_admin(self, *, limit: int = 50, offset: int = 0) -> list[ProxyAccessStatsItem]:
        """Return a paginated list of sanitized proxy access stats items for admin views, newest first."""
        cursor = await self.db.conn.execute(
            _SANITIZED_STATS_SELECT
            + """
            ORDER BY pa.created_at DESC, pa.id DESC
            LIMIT ? OFFSET ?
            """,
            (_clamp_limit(limit), _clamp_offset(offset)),
        )
        rows = await cursor.fetchall()
        return [item for row in rows if (item := _row_to_proxy_stats_item(row)) is not None]

    async def count_by_type_status(self) -> dict[ProxyAccessType, dict[ProxyAccessStatus, int]]:
        """Return proxy access counts grouped by access type and status."""
        cursor = await self.db.conn.execute(
            """
            SELECT access_type, status, COUNT(*) AS cnt
            FROM proxy_accesses
            GROUP BY access_type, status
            """
        )
        rows = await cursor.fetchall()
        result: dict[ProxyAccessType, dict[ProxyAccessStatus, int]] = {}
        for row in rows:
            access_type = enum_value(ProxyAccessType, row["access_type"], "proxy_accesses.access_type")
            status = enum_value(ProxyAccessStatus, row["status"], "proxy_accesses.status")
            result.setdefault(access_type, {})[status] = int(row["cnt"])
        return result

    async def count_users_with_active_proxies(self) -> int:
        """Return the number of distinct users with at least one active proxy access."""
        row = await self.db.conn.execute_fetchone(
            """
            SELECT COUNT(DISTINCT owner_user_id) AS cnt
            FROM proxy_accesses
            WHERE status = ?
            """,
            (ProxyAccessStatus.ACTIVE.value,),
        )
        return int(row["cnt"]) if row is not None else 0

    async def latest_timestamps(self) -> dict[str, str | None]:
        """Return the most recent issued and failed proxy access timestamps."""
        failed_statuses = (
            ProxyAccessStatus.APPLY_FAILED.value,
            ProxyAccessStatus.REVOKE_FAILED.value,
            ProxyAccessStatus.DELETE_FAILED.value,
        )
        row = await self.db.conn.execute_fetchone(
            """
            SELECT
              MAX(created_at) AS last_issued_at,
              MAX(CASE WHEN status IN (?, ?, ?) THEN updated_at ELSE NULL END) AS last_failed_at
            FROM proxy_accesses
            """,
            failed_statuses,
        )
        if row is None:
            return {"last_issued_at": None, "last_failed_at": None}
        return {
            "last_issued_at": row["last_issued_at"],
            "last_failed_at": row["last_failed_at"],
        }

    async def get_admin_proxy_stats(self, *, user_limit: int = 12, user_offset: int = 0) -> ProxyAdminStats:
        """Return aggregated proxy stats plus a paginated per-user breakdown for the admin dashboard."""
        type_status_counts = await self.count_by_type_status()

        def count(access_type: ProxyAccessType | None, statuses: set[ProxyAccessStatus]) -> int:
            total = 0
            type_items = (
                type_status_counts.items()
                if access_type is None
                else ((access_type, type_status_counts.get(access_type, {})),)
            )
            for _item_type, status_counts in type_items:
                total += sum(value for status, value in status_counts.items() if status in statuses)
            return total

        total_accesses = sum(
            value
            for status_counts in type_status_counts.values()
            for value in status_counts.values()
        )
        active_statuses = {ProxyAccessStatus.ACTIVE}
        inactive_statuses = {ProxyAccessStatus.REVOKED, ProxyAccessStatus.INACTIVE}
        pending_statuses = {
            ProxyAccessStatus.PENDING_APPLY,
            ProxyAccessStatus.PENDING_REVOKE,
            ProxyAccessStatus.PENDING_DELETE,
        }

        timestamps = await self.latest_timestamps()
        users_with_active = await self.count_users_with_active_proxies()
        total_users_row = await self.db.conn.execute_fetchone(
            "SELECT COUNT(DISTINCT owner_user_id) AS cnt FROM proxy_accesses"
        )
        total_users = int(total_users_row["cnt"]) if total_users_row is not None else 0

        mode_cursor = await self.db.conn.execute(
            """
            SELECT
              COALESCE(
                json_extract(public_payload_json, '$.mode'),
                json_extract(payload_json, '$.mode'),
                'static'
              ) AS mode,
              COUNT(*) AS cnt
            FROM proxy_accesses
            WHERE access_type = ?
            GROUP BY mode
            """,
            (ProxyAccessType.MTPROTO.value,),
        )
        mode_rows = await mode_cursor.fetchall()
        mtproto_mode_counts = {str(row["mode"] or "static"): int(row["cnt"]) for row in mode_rows}

        user_rows = await self._admin_user_rows(limit=user_limit, offset=user_offset)
        active_refs = await self._active_refs_for_users([row.telegram_user_id for row in user_rows])
        users = tuple(
            ProxyAdminUserStats(
                telegram_user_id=row.telegram_user_id,
                username=row.username,
                active_socks5_count=row.active_socks5_count,
                active_mtproto_count=row.active_mtproto_count,
                failed_count=row.failed_count,
                last_proxy_issued_at=row.last_proxy_issued_at,
                active_accesses=tuple(active_refs.get(row.telegram_user_id, ())),
            )
            for row in user_rows
        )
        hidden_users = max(total_users - user_offset - len(users), 0)

        return ProxyAdminStats(
            total_accesses=total_accesses,
            active_total=count(None, active_statuses),
            active_socks5=count(ProxyAccessType.SOCKS5, active_statuses),
            active_mtproto=count(ProxyAccessType.MTPROTO, active_statuses),
            apply_failed=count(None, {ProxyAccessStatus.APPLY_FAILED}),
            revoked=count(None, inactive_statuses),
            deleted=count(None, {ProxyAccessStatus.DELETED}),
            pending=count(None, pending_statuses),
            users_with_active_proxies=users_with_active,
            last_issued_at=timestamps["last_issued_at"],
            last_failed_at=timestamps["last_failed_at"],
            type_status_counts=type_status_counts,
            mtproto_mode_counts=mtproto_mode_counts,
            users=users,
            total_users=total_users,
            hidden_users=hidden_users,
        )

    async def _admin_user_rows(self, *, limit: int, offset: int) -> tuple[ProxyAdminUserStats, ...]:
        cursor = await self.db.conn.execute(
            """
            SELECT
              pa.owner_user_id AS telegram_user_id,
              COALESCE(u.username, MAX(pa.username)) AS username,
              SUM(CASE WHEN pa.access_type = ? AND pa.status = ? THEN 1 ELSE 0 END) AS active_socks5_count,
              SUM(CASE WHEN pa.access_type = ? AND pa.status = ? THEN 1 ELSE 0 END) AS active_mtproto_count,
              SUM(CASE WHEN pa.status IN (?, ?, ?) THEN 1 ELSE 0 END) AS failed_count,
              MAX(pa.created_at) AS last_proxy_issued_at
            FROM proxy_accesses pa
            LEFT JOIN users u ON u.telegram_user_id = pa.owner_user_id
            GROUP BY pa.owner_user_id
            ORDER BY last_proxy_issued_at DESC, pa.owner_user_id ASC
            LIMIT ? OFFSET ?
            """,
            (
                ProxyAccessType.SOCKS5.value,
                ProxyAccessStatus.ACTIVE.value,
                ProxyAccessType.MTPROTO.value,
                ProxyAccessStatus.ACTIVE.value,
                ProxyAccessStatus.APPLY_FAILED.value,
                ProxyAccessStatus.REVOKE_FAILED.value,
                ProxyAccessStatus.DELETE_FAILED.value,
                _clamp_limit(limit),
                _clamp_offset(offset),
            ),
        )
        rows = await cursor.fetchall()
        return tuple(
            ProxyAdminUserStats(
                telegram_user_id=int(row["telegram_user_id"]),
                username=row["username"],
                active_socks5_count=int(row["active_socks5_count"] or 0),
                active_mtproto_count=int(row["active_mtproto_count"] or 0),
                failed_count=int(row["failed_count"] or 0),
                last_proxy_issued_at=row["last_proxy_issued_at"],
            )
            for row in rows
        )

    async def _active_refs_for_users(self, user_ids: list[int]) -> dict[int, tuple[ProxyActiveAccessRef, ...]]:
        if not user_ids:
            return {}
        placeholders = ",".join("?" for _ in user_ids)
        cursor = await self.db.conn.execute(
            f"""
            SELECT owner_user_id, id, access_type
            FROM proxy_accesses
            WHERE status = ?
              AND owner_user_id IN ({placeholders})
            ORDER BY owner_user_id ASC, id ASC
            """,
            (ProxyAccessStatus.ACTIVE.value, *user_ids),
        )
        rows = await cursor.fetchall()
        refs: dict[int, list[ProxyActiveAccessRef]] = {}
        for row in rows:
            user_id = int(row["owner_user_id"])
            access_type = enum_value(ProxyAccessType, row["access_type"], "proxy_accesses.access_type")
            refs.setdefault(user_id, []).append(ProxyActiveAccessRef(id=int(row["id"]), access_type=access_type))
        return {user_id: tuple(items) for user_id, items in refs.items()}
