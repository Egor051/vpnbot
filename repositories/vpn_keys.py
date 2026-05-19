
import json
from typing import Any

from aiosqlite import Row

from db.database import Database
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType
from repositories._helpers import enum_value, json_loads_dict
from services.errors import InvalidTransition


def _json_loads(value: str) -> dict[str, object]:
    return json_loads_dict(value, "vpn_keys payload/public_payload")


def _row_to_vpn_key(row: Row | None) -> VpnKey | None:
    if row is None:
        return None
    keys = row.keys() if hasattr(row, "keys") else []
    return VpnKey(
        id=int(row["id"]),
        owner_user_id=int(row["owner_user_id"]),
        username=row["username"],
        key_type=enum_value(VpnKeyType, row["key_type"], "vpn_keys.key_type"),
        status=enum_value(VpnKeyStatus, row["status"], "vpn_keys.status"),
        note=row["note"],
        uuid=row["uuid"],
        email_label=row["email_label"],
        public_key=row["public_key"],
        client_ip=row["client_ip"],
        payload=_json_loads(row["payload_json"]),
        public_payload=_json_loads(row["public_payload_json"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        revoked_at=row["revoked_at"],
        expires_at=row["expires_at"] if "expires_at" in keys else None,
        deleted_at=row["deleted_at"],
        created_by=int(row["created_by"]),
        revoked_by=row["revoked_by"],
        deleted_by=row["deleted_by"],
    )


class VpnKeyRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create_pending(
        self,
        *,
        owner_user_id: int,
        username: str | None,
        key_type: VpnKeyType,
        note: str | None,
        payload: dict[str, Any],
        public_payload: dict[str, Any],
        created_by: int,
        now: str,
        uuid: str | None = None,
        email_label: str | None = None,
        public_key: str | None = None,
        client_ip: str | None = None,
        expires_at: str | None = None,
    ) -> VpnKey:
        cursor = await self.db.conn.execute(
            """
            INSERT INTO vpn_keys (
              owner_user_id, username, key_type, status, note,
              uuid, email_label, public_key, client_ip,
              payload_json, public_payload_json,
              created_at, updated_at, created_by, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                owner_user_id,
                username,
                key_type.value,
                VpnKeyStatus.PENDING_APPLY.value,
                note,
                uuid,
                email_label,
                public_key,
                client_ip,
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
                json.dumps(public_payload, ensure_ascii=False, separators=(",", ":")),
                now,
                now,
                created_by,
                expires_at,
            ),
        )
        await self.db.commit()
        assert cursor.lastrowid is not None
        key = await self.get_by_id(int(cursor.lastrowid))
        if key is None:
            raise RuntimeError("VPN key insert failed")
        return key

    async def create_key(
        self,
        *,
        owner_user_id: int,
        username: str | None,
        key_type: VpnKeyType,
        note: str | None,
        payload: dict[str, Any],
        public_payload: dict[str, Any],
        created_by: int,
        now: str,
        uuid: str | None = None,
        email_label: str | None = None,
        public_key: str | None = None,
        client_ip: str | None = None,
        expires_at: str | None = None,
    ) -> VpnKey:
        return await self.create_pending(
            owner_user_id=owner_user_id,
            username=username,
            key_type=key_type,
            note=note,
            payload=payload,
            public_payload=public_payload,
            created_by=created_by,
            now=now,
            uuid=uuid,
            email_label=email_label,
            public_key=public_key,
            client_ip=client_ip,
            expires_at=expires_at,
        )

    async def get_by_id(self, key_id: int) -> VpnKey | None:
        """Return VPN key by primary key, or None if not found.

        Does NOT filter by status. Caller must check key.status when only
        ACTIVE or non-revoked keys are acceptable.
        """
        cursor = await self.db.conn.execute("SELECT * FROM vpn_keys WHERE id = ?", (key_id,))
        row = await cursor.fetchone()
        return _row_to_vpn_key(row)

    async def get_key_by_id(self, key_id: int) -> VpnKey | None:
        return await self.get_by_id(key_id)

    async def list_by_owner(self, owner_user_id: int, limit: int = 20, offset: int = 0) -> list[VpnKey]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM vpn_keys
            WHERE owner_user_id = ? AND status != ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (owner_user_id, VpnKeyStatus.DELETED.value, limit, offset),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def list_traffic_supported(self, limit: int = 20, offset: int = 0) -> list[VpnKey]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM vpn_keys
            WHERE key_type IN (?, ?) AND status != ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (VpnKeyType.XRAY.value, VpnKeyType.AWG.value, VpnKeyStatus.DELETED.value, limit, offset),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def count_by_owner(self, owner_user_id: int) -> int:
        cursor = await self.db.conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM vpn_keys
            WHERE owner_user_id = ? AND status != ?
            """,
            (owner_user_id, VpnKeyStatus.DELETED.value),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def count_by_owner_and_type(self, owner_user_id: int, key_type: VpnKeyType) -> int:
        cursor = await self.db.conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM vpn_keys
            WHERE owner_user_id = ? AND key_type = ? AND status != ?
            """,
            (owner_user_id, key_type.value, VpnKeyStatus.DELETED.value),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def count_by_owners(self, owner_user_ids: list[int]) -> dict[int, int]:
        if not owner_user_ids:
            return {}
        placeholders = ",".join("?" for _ in owner_user_ids)
        cursor = await self.db.conn.execute(
            f"""
            SELECT owner_user_id, COUNT(*) AS cnt
            FROM vpn_keys
            WHERE owner_user_id IN ({placeholders}) AND status != ?
            GROUP BY owner_user_id
            """,
            (*owner_user_ids, VpnKeyStatus.DELETED.value),
        )
        rows = await cursor.fetchall()
        return {int(row["owner_user_id"]): int(row["cnt"]) for row in rows}

    async def count_by_owner_statuses(self, owner_user_id: int, statuses: set[VpnKeyStatus]) -> int:
        if not statuses:
            return 0
        placeholders = ",".join("?" for _ in statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM vpn_keys
            WHERE owner_user_id = ? AND status IN ({placeholders})
            """,
            (owner_user_id, *(status.value for status in statuses)),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def list_recent_by_owner(self, owner_user_id: int, limit: int = 10) -> list[VpnKey]:
        return await self.list_by_owner(owner_user_id, limit=limit, offset=0)

    async def list_keys_by_owner_and_type(
        self,
        owner_user_id: int,
        key_type: VpnKeyType,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        return await self.list_by_owner_and_type(owner_user_id, key_type, limit=limit, offset=offset)

    async def list_by_owner_and_type(
        self,
        owner_user_id: int,
        key_type: VpnKeyType,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM vpn_keys
            WHERE owner_user_id = ? AND key_type = ? AND status != ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (owner_user_id, key_type.value, VpnKeyStatus.DELETED.value, limit, offset),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def list_by_owner_statuses(
        self,
        owner_user_id: int,
        statuses: set[VpnKeyStatus],
        limit: int = 100,
        offset: int = 0,
    ) -> list[VpnKey]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM vpn_keys
            WHERE owner_user_id = ? AND status IN ({placeholders})
            ORDER BY created_at ASC
            LIMIT ? OFFSET ?
            """,
            (owner_user_id, *(status.value for status in statuses), limit, offset),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def list_by_statuses(
        self,
        statuses: set[VpnKeyStatus],
        limit: int = 500,
        offset: int = 0,
    ) -> list[VpnKey]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM vpn_keys
            WHERE status IN ({placeholders})
            ORDER BY updated_at ASC, id ASC
            LIMIT ? OFFSET ?
            """,
            (*(status.value for status in statuses), limit, offset),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def list_by_type_statuses(
        self,
        key_type: VpnKeyType,
        statuses: set[VpnKeyStatus],
        limit: int = 500,
        offset: int = 0,
        after_id: int | None = None,
    ) -> list[VpnKey]:
        if not statuses:
            return []
        placeholders = ",".join("?" for _ in statuses)
        after_sql = ""
        params: list[object] = [key_type.value, *(status.value for status in statuses)]
        if after_id is not None:
            after_sql = "AND id > ?"
            params.append(after_id)
        params.extend([limit, offset])
        cursor = await self.db.conn.execute(
            f"""
            SELECT * FROM vpn_keys
            WHERE key_type = ? AND status IN ({placeholders})
              {after_sql}
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def mark_active(
        self,
        key_id: int,
        now: str,
        payload: dict[str, Any] | None = None,
        public_payload: dict[str, Any] | None = None,
    ) -> None:
        async with self.db.transaction():
            current = await self.get_by_id(key_id)
            if current is None:
                raise RuntimeError("VPN key not found")
            await self.db.conn.execute(
                """
                UPDATE vpn_keys
                SET status = ?, updated_at = ?, payload_json = ?, public_payload_json = ?
                WHERE id = ?
                """,
                (
                    VpnKeyStatus.ACTIVE.value,
                    now,
                    json.dumps(payload if payload is not None else current.payload, ensure_ascii=False, separators=(",", ":")),
                    json.dumps(
                        public_payload if public_payload is not None else current.public_payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    key_id,
                ),
            )

    async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
        await self.db.conn.execute(
            "UPDATE vpn_keys SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, now, key_id),
        )
        await self.db.commit()

    async def update_key_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
        await self.set_status(key_id, status, now)

    async def mark_revoked(self, key_id: int, actor_user_id: int, now: str) -> None:
        cursor = await self.db.conn.execute(
            """
            UPDATE vpn_keys
            SET status = ?, updated_at = ?, revoked_at = COALESCE(revoked_at, ?), revoked_by = COALESCE(revoked_by, ?)
            WHERE id = ? AND status NOT IN (?, ?)
            """,
            (VpnKeyStatus.REVOKED.value, now, now, actor_user_id, key_id,
             VpnKeyStatus.REVOKED.value, VpnKeyStatus.DELETED.value),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise InvalidTransition(f"VPN key {key_id} is already revoked or deleted")

    async def mark_deleted(self, key_id: int, actor_user_id: int, now: str) -> None:
        cursor = await self.db.conn.execute(
            """
            UPDATE vpn_keys
            SET status = ?, updated_at = ?, deleted_at = COALESCE(deleted_at, ?), deleted_by = COALESCE(deleted_by, ?)
            WHERE id = ? AND status != ?
            """,
            (VpnKeyStatus.DELETED.value, now, now, actor_user_id, key_id, VpnKeyStatus.DELETED.value),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise InvalidTransition(f"VPN key {key_id} is already deleted")

    async def soft_delete_key(self, key_id: int, actor_user_id: int, now: str) -> None:
        await self.mark_deleted(key_id, actor_user_id, now)

    async def hard_delete_with_stats(self, key_id: int) -> None:
        async with self.db.transaction():
            await self.db.conn.execute(
                "DELETE FROM vpn_key_traffic_stats WHERE key_id = ?",
                (key_id,),
            )
            await self.db.conn.execute(
                "DELETE FROM vpn_keys WHERE id = ?",
                (key_id,),
            )

    async def update_note(self, key_id: int, note: str | None, now: str) -> None:
        await self.db.conn.execute(
            "UPDATE vpn_keys SET note = ?, updated_at = ? WHERE id = ?",
            (note, now, key_id),
        )
        await self.db.commit()

    async def get_occupied_awg_ips(self) -> set[str]:
        reserved_statuses = (
            VpnKeyStatus.PENDING_APPLY,
            VpnKeyStatus.ACTIVE,
            VpnKeyStatus.APPLY_FAILED,
            VpnKeyStatus.PENDING_REVOKE,
            VpnKeyStatus.PENDING_DELETE,
            VpnKeyStatus.DELETE_FAILED,
        )
        placeholders = ",".join("?" for _ in reserved_statuses)
        cursor = await self.db.conn.execute(
            f"""
            SELECT client_ip FROM vpn_keys
            WHERE key_type = ? AND client_ip IS NOT NULL AND status IN ({placeholders})
            """,
            (VpnKeyType.AWG.value, *(status.value for status in reserved_statuses)),
        )
        rows = await cursor.fetchall()
        return {str(row["client_ip"]) for row in rows}

    async def find_active_awg_ips(self) -> set[str]:
        return await self.get_occupied_awg_ips()

    async def find_by_uuid(self, uuid_value: str) -> VpnKey | None:
        """Return VPN key by UUID, or None if not found.

        Does NOT filter by status — caller must check key.status when only
        active or non-revoked keys are acceptable.
        """
        cursor = await self.db.conn.execute(
            "SELECT * FROM vpn_keys WHERE uuid = ? LIMIT 1",
            (uuid_value,),
        )
        row = await cursor.fetchone()
        return _row_to_vpn_key(row)

    async def find_by_email_label(self, email_label: str) -> VpnKey | None:
        """Return VPN key by email label, or None if not found.

        Does NOT filter by status — caller must check key.status when only
        active or non-revoked keys are acceptable.
        """
        cursor = await self.db.conn.execute(
            "SELECT * FROM vpn_keys WHERE email_label = ? LIMIT 1",
            (email_label,),
        )
        row = await cursor.fetchone()
        return _row_to_vpn_key(row)

    async def find_by_public_key(self, public_key: str) -> VpnKey | None:
        """Return VPN key by WireGuard public key, or None if not found.

        Does NOT filter by status — caller must check key.status when only
        active or non-revoked keys are acceptable.
        """
        cursor = await self.db.conn.execute(
            "SELECT * FROM vpn_keys WHERE public_key = ? LIMIT 1",
            (public_key,),
        )
        row = await cursor.fetchone()
        return _row_to_vpn_key(row)

    async def find_by_client_ip(self, client_ip: str) -> VpnKey | None:
        """Return VPN key by assigned client IP, or None if not found.

        Does NOT filter by status — caller must check key.status when only
        active or non-revoked keys are acceptable.
        """
        cursor = await self.db.conn.execute("SELECT * FROM vpn_keys WHERE client_ip = ? LIMIT 1", (client_ip,))
        row = await cursor.fetchone()
        return _row_to_vpn_key(row)

    async def list_expired_active(self, now: str, limit: int = 100) -> list[VpnKey]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM vpn_keys
            WHERE status = ? AND expires_at IS NOT NULL AND expires_at <= ?
            ORDER BY expires_at ASC
            LIMIT ?
            """,
            (VpnKeyStatus.ACTIVE.value, now, limit),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def list_active_trial_by_owner(self, owner_user_id: int) -> list[VpnKey]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM vpn_keys
            WHERE owner_user_id = ? AND status = ? AND expires_at IS NOT NULL
            ORDER BY created_at DESC
            """,
            (owner_user_id, VpnKeyStatus.ACTIVE.value),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def count_active_managed_short_id(self, short_id: str, exclude_key_id: int | None = None) -> int:
        statuses = (
            VpnKeyStatus.ACTIVE,
            VpnKeyStatus.PENDING_APPLY,
            VpnKeyStatus.APPLY_FAILED,
            VpnKeyStatus.PENDING_REVOKE,
            VpnKeyStatus.PENDING_DELETE,
            VpnKeyStatus.DELETE_FAILED,
        )
        placeholders = ",".join("?" for _ in statuses)
        params: list[object] = [
            VpnKeyType.XRAY.value,
            *(status.value for status in statuses),
            short_id,
        ]
        exclude_sql = ""
        if exclude_key_id is not None:
            exclude_sql = "AND id != ?"
            params.append(exclude_key_id)
        cursor = await self.db.conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM vpn_keys
            WHERE key_type = ?
              AND status IN ({placeholders})
              AND json_extract(payload_json, '$.short_id') = ?
              AND json_extract(payload_json, '$.short_id_managed') = 1
              {exclude_sql}
            """,
            tuple(params),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0
