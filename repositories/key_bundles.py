
import logging
import secrets

from aiosqlite import Row

from db.database import Database
from db.exceptions import ConcurrentModificationError
from models.dto import KeyBundle, VpnKey
from models.enums import KeyBundleStatus
from repositories._helpers import _clamp_limit, _clamp_offset, enum_value
from repositories.vpn_keys import _row_to_vpn_key

logger = logging.getLogger(__name__)


def _generate_token() -> str:
    """Generate a fresh URL-safe subscription token (256 bits of entropy)."""
    return secrets.token_urlsafe(32)


def _row_to_key_bundle(row: Row | None) -> KeyBundle | None:
    if row is None:
        return None
    return KeyBundle(
        id=int(row["id"]),
        user_id=int(row["user_id"]),
        label=row["label"],
        note=row["note"],
        status=enum_value(KeyBundleStatus, row["status"], "key_bundles.status"),
        token=row["token"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        revoked_at=row["revoked_at"],
        deleted_at=row["deleted_at"],
    )


class KeyBundleRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(
        self,
        *,
        user_id: int,
        label: str,
        now: str,
        note: str | None = None,
        status: KeyBundleStatus = KeyBundleStatus.ACTIVE,
    ) -> KeyBundle:
        """Insert a new bundle with a freshly generated secret token and return it."""
        token = _generate_token()
        cursor = await self.db.conn.execute(
            """
            INSERT INTO key_bundles (user_id, label, note, status, token, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, label, note, status.value, token, now, now),
        )
        await self.db.commit()
        assert cursor.lastrowid is not None
        bundle = await self.get_by_id(int(cursor.lastrowid))
        if bundle is None:
            raise RuntimeError("Key bundle insert failed")
        return bundle

    async def get_by_id(self, bundle_id: int) -> KeyBundle | None:
        """Return a bundle by primary key, or None if not found."""
        cursor = await self.db.conn.execute("SELECT * FROM key_bundles WHERE id = ?", (bundle_id,))
        row = await cursor.fetchone()
        return _row_to_key_bundle(row)

    async def get_by_token(self, token: str) -> KeyBundle | None:
        """Return the bundle addressed by a subscription token, or None if unknown."""
        cursor = await self.db.conn.execute("SELECT * FROM key_bundles WHERE token = ?", (token,))
        row = await cursor.fetchone()
        return _row_to_key_bundle(row)

    async def list_by_user(self, user_id: int, limit: int = 50, offset: int = 0) -> list[KeyBundle]:
        """Return a user's bundles, oldest first, paginated."""
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM key_bundles
            WHERE user_id = ?
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """,
            (user_id, _clamp_limit(limit), _clamp_offset(offset)),
        )
        rows = await cursor.fetchall()
        return [bundle for row in rows if (bundle := _row_to_key_bundle(row)) is not None]

    async def attach_key_to_bundle(self, key_id: int, bundle_id: int, now: str) -> None:
        """Point a VPN key at a bundle. The FK (RESTRICT) guarantees the bundle exists."""
        await self.db.conn.execute(
            "UPDATE vpn_keys SET bundle_id = ?, updated_at = ? WHERE id = ?",
            (bundle_id, now, key_id),
        )
        await self.db.commit()

    async def list_keys_of_bundle(self, bundle_id: int) -> list[VpnKey]:
        """Return every VPN key attached to a bundle, oldest first."""
        cursor = await self.db.conn.execute(
            "SELECT * FROM vpn_keys WHERE bundle_id = ? ORDER BY id ASC",
            (bundle_id,),
        )
        rows = await cursor.fetchall()
        return [key for row in rows if (key := _row_to_vpn_key(row)) is not None]

    async def set_status(
        self,
        bundle_id: int,
        status: KeyBundleStatus,
        now: str,
        *,
        allowed_from_statuses: tuple[KeyBundleStatus, ...] | None = None,
    ) -> None:
        """Set a bundle's status, stamping revoked_at/deleted_at on the matching
        transition. When ``allowed_from_statuses`` is given the update is guarded
        against a concurrent status change and raises if it matches no row."""
        # Only column-name fragments (internal constants) are interpolated; every
        # value is bound via a placeholder — no user input reaches SQL.
        set_parts = ["status = ?", "updated_at = ?"]
        params: list[object] = [status.value, now]
        if status is KeyBundleStatus.REVOKED:
            set_parts.append("revoked_at = COALESCE(revoked_at, ?)")
            params.append(now)
        elif status is KeyBundleStatus.DELETED:
            set_parts.append("deleted_at = COALESCE(deleted_at, ?)")
            params.append(now)
        where = "WHERE id = ?"
        params.append(bundle_id)
        if allowed_from_statuses:
            placeholders = ",".join("?" for _ in allowed_from_statuses)
            where += f" AND status IN ({placeholders})"
            params.extend(s.value for s in allowed_from_statuses)
        cursor = await self.db.conn.execute(
            f"UPDATE key_bundles SET {', '.join(set_parts)} {where}",
            tuple(params),
        )
        await self.db.commit()
        if allowed_from_statuses and cursor.rowcount == 0:
            raise ConcurrentModificationError(
                f"Key bundle {bundle_id} is not in an allowed status for this transition "
                "(concurrent modification?)"
            )

    async def delete(self, bundle_id: int) -> None:
        """Hard-delete a bundle row.

        Raises ``sqlite3.IntegrityError`` while any VPN key still points at the
        bundle: ``vpn_keys.bundle_id`` is ON DELETE RESTRICT, so the wrong order
        (bundle before its children) is impossible by construction rather than by
        convention. Callers must remove the children first — see
        :meth:`services.key_bundles.KeyBundleService.delete_bundle`.
        """
        await self.db.conn.execute("DELETE FROM key_bundles WHERE id = ?", (bundle_id,))
        await self.db.commit()

    async def rotate_token(self, bundle_id: int, now: str) -> str:
        """Replace a bundle's secret token with a fresh one and return it."""
        token = _generate_token()
        cursor = await self.db.conn.execute(
            "UPDATE key_bundles SET token = ?, updated_at = ? WHERE id = ?",
            (token, now, bundle_id),
        )
        await self.db.commit()
        if cursor.rowcount == 0:
            raise RuntimeError(f"Key bundle {bundle_id} not found")
        return token
