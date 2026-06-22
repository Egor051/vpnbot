
from collections.abc import Iterable

from aiosqlite import Row

from db.database import Database
from models.dto import TARGETABLE_ROLES, RecipientFilter, TelegramUserProfile, User
from models.enums import ProxyAccessType, UserRole, VpnKeyType, parse_user_role
from repositories._helpers import _clamp_limit, _clamp_offset
from services.errors import NotFound


_ANNOUNCEMENT_ROLE_SQL_VALUES = (
    UserRole.APPROVED_USER.value,
    UserRole.SUPERADMIN.value,
)
_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS = ", ".join("?" for _ in _ANNOUNCEMENT_ROLE_SQL_VALUES)


def _row_to_user(row: Row | None) -> User | None:
    if row is None:
        return None
    try:
        role = parse_user_role(row["role"])
    except ValueError as exc:
        raise RuntimeError(
            f"Некорректное значение users.role в SQLite: {row['role']!r}. "
            "Сделайте backup DB и исправьте повреждённую запись вручную."
        ) from exc
    keys = row.keys()
    return User(
        telegram_user_id=int(row["telegram_user_id"]),
        username=row["username"],
        first_name=row["first_name"],
        role=role,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        blocked_at=row["blocked_at"],
        note=row["note"] if "note" in keys else None,
        language=row["language"] if "language" in keys else None,
        expiry_notifications_enabled=(
            bool(row["expiry_notifications_enabled"])
            if "expiry_notifications_enabled" in keys and row["expiry_notifications_enabled"] is not None
            else True
        ),
    )


def _build_segment_where(recipient_filter: RecipientFilter) -> tuple[str, list[object]]:
    """Build the parameterized WHERE body for a segmented recipient query.

    Only whitelisted enum values reach the SQL: roles/transports flow through
    placeholders, and protocol branches are selected by exact-match comparison
    against the closed protocol set, so no caller-supplied string is interpolated.
    """
    clauses = ["u.blocked_at IS NULL"]
    params: list[object] = []
    roles = recipient_filter.roles or TARGETABLE_ROLES
    role_placeholders = ", ".join("?" for _ in roles)
    clauses.append(f"u.role IN ({role_placeholders})")
    params.extend(roles)
    if recipient_filter.protocols:
        protocol_clauses: list[str] = []
        for protocol in recipient_filter.protocols:
            if protocol == VpnKeyType.XRAY.value:
                sub = (
                    "EXISTS (SELECT 1 FROM vpn_keys k WHERE k.owner_user_id = u.telegram_user_id "
                    "AND k.key_type = 'xray' AND k.status = 'active'"
                )
                if recipient_filter.transports:
                    transport_placeholders = ", ".join("?" for _ in recipient_filter.transports)
                    sub += f" AND k.transport IN ({transport_placeholders})"
                    params.extend(recipient_filter.transports)
                sub += ")"
                protocol_clauses.append(sub)
            elif protocol == VpnKeyType.AWG.value:
                protocol_clauses.append(
                    "EXISTS (SELECT 1 FROM vpn_keys k WHERE k.owner_user_id = u.telegram_user_id "
                    "AND k.key_type = 'awg' AND k.status = 'active')"
                )
            elif protocol == ProxyAccessType.SOCKS5.value:
                protocol_clauses.append(
                    "EXISTS (SELECT 1 FROM proxy_accesses p WHERE p.owner_user_id = u.telegram_user_id "
                    "AND p.access_type = 'socks5' AND p.status = 'active')"
                )
            elif protocol == ProxyAccessType.MTPROTO.value:
                protocol_clauses.append(
                    "EXISTS (SELECT 1 FROM proxy_accesses p WHERE p.owner_user_id = u.telegram_user_id "
                    "AND p.access_type = 'mtproto' AND p.status = 'active')"
                )
        if protocol_clauses:
            clauses.append("(" + " OR ".join(protocol_clauses) + ")")
    return " AND ".join(clauses), params


class UserRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get_by_id(self, telegram_user_id: int) -> User | None:
        """Return a user by Telegram user id, or None if not found."""
        cursor = await self.db.conn.execute(
            "SELECT * FROM users WHERE telegram_user_id = ?",
            (telegram_user_id,),
        )
        row = await cursor.fetchone()
        return _row_to_user(row)

    async def upsert_profile(self, profile: TelegramUserProfile, role: UserRole, now: str) -> User:
        """Insert or update a user's profile and return the stored user."""
        await self.db.conn.execute(
            """
            INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(telegram_user_id) DO UPDATE SET
              username = excluded.username,
              first_name = excluded.first_name,
              updated_at = excluded.updated_at
            """,
            (
                profile.telegram_user_id,
                profile.username,
                profile.first_name,
                role.value,
                now,
                now,
            ),
        )
        await self.db.commit()
        user = await self.get_by_id(profile.telegram_user_id)
        if user is None:
            raise RuntimeError("User upsert failed")
        return user

    async def create_admin_placeholders(self, admin_ids: Iterable[int], now: str) -> None:
        """Insert placeholder superadmin rows for the given admin ids if absent."""
        rows = [(admin_id, UserRole.SUPERADMIN.value, now, now) for admin_id in admin_ids]
        if not rows:
            return
        async with self.db.transaction():
            await self.db.conn.executemany(
                """
                INSERT OR IGNORE INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                VALUES (?, NULL, NULL, ?, ?, ?)
                """,
                rows,
            )

    async def set_role(self, telegram_user_id: int, role: UserRole, now: str, blocked_at: str | None = None) -> None:
        """Set a user's role and blocked timestamp, raising NotFound if absent."""
        cursor = await self.db.conn.execute(
            """
            UPDATE users
            SET role = ?, updated_at = ?, blocked_at = ?
            WHERE telegram_user_id = ?
            """,
            (role.value, now, blocked_at, telegram_user_id),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise NotFound("Пользователь не найден")

    async def count_users(self) -> int:
        """Return the total number of users."""
        cursor = await self.db.conn.execute("SELECT COUNT(*) AS cnt FROM users")
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def list_users(self, limit: int = 20, offset: int = 0) -> list[User]:
        """Return a paginated list of users, most recently updated first."""
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM users
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?
            """,
            (_clamp_limit(limit), _clamp_offset(offset)),
        )
        rows = await cursor.fetchall()
        return [user for row in rows if (user := _row_to_user(row)) is not None]

    async def count_announcement_recipients(self) -> int:
        """Return the number of non-blocked users eligible to receive announcements."""
        cursor = await self.db.conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM users
            WHERE blocked_at IS NULL
              AND role IN ({_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS})
            """,
            _ANNOUNCEMENT_ROLE_SQL_VALUES,
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def list_announcement_recipients_after(self, last_seen_id: int | None, limit: int = 100) -> list[User]:
        """Return announcement-eligible users keyset-paginated by user id after last_seen_id."""
        safe_limit = _clamp_limit(limit)
        if last_seen_id is None:
            cursor = await self.db.conn.execute(
                f"""
                SELECT * FROM users
                WHERE blocked_at IS NULL
                  AND role IN ({_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS})
                ORDER BY telegram_user_id ASC
                LIMIT ?
                """,
                (*_ANNOUNCEMENT_ROLE_SQL_VALUES, safe_limit),
            )
        else:
            cursor = await self.db.conn.execute(
                f"""
                SELECT * FROM users
                WHERE blocked_at IS NULL
                  AND role IN ({_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS})
                  AND telegram_user_id > ?
                ORDER BY telegram_user_id ASC
                LIMIT ?
                """,
                (*_ANNOUNCEMENT_ROLE_SQL_VALUES, last_seen_id, safe_limit),
            )
        rows = await cursor.fetchall()
        return [user for row in rows if (user := _row_to_user(row)) is not None]

    async def is_announcement_recipient(self, telegram_user_id: int) -> bool:
        """Return whether the user is currently eligible to receive announcements."""
        cursor = await self.db.conn.execute(
            f"""
            SELECT 1 FROM users
            WHERE telegram_user_id = ?
              AND blocked_at IS NULL
              AND role IN ({_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS})
            """,
            (telegram_user_id, *_ANNOUNCEMENT_ROLE_SQL_VALUES),
        )
        return await cursor.fetchone() is not None

    async def count_segment_recipients(self, recipient_filter: RecipientFilter) -> int:
        """Return the number of non-blocked users matching the segmentation filter."""
        where, params = _build_segment_where(recipient_filter)
        cursor = await self.db.conn.execute(
            f"SELECT COUNT(*) AS cnt FROM users u WHERE {where}",
            tuple(params),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def list_segment_recipients_after(
        self, recipient_filter: RecipientFilter, last_seen_id: int | None, limit: int = 100
    ) -> list[User]:
        """Return segment-matching users keyset-paginated by user id after last_seen_id."""
        safe_limit = _clamp_limit(limit)
        where, params = _build_segment_where(recipient_filter)
        if last_seen_id is None:
            sql = f"SELECT u.* FROM users u WHERE {where} ORDER BY u.telegram_user_id ASC LIMIT ?"
            query_params = [*params, safe_limit]
        else:
            sql = (
                f"SELECT u.* FROM users u WHERE {where} AND u.telegram_user_id > ? "
                "ORDER BY u.telegram_user_id ASC LIMIT ?"
            )
            query_params = [*params, last_seen_id, safe_limit]
        cursor = await self.db.conn.execute(sql, tuple(query_params))
        rows = await cursor.fetchall()
        return [user for row in rows if (user := _row_to_user(row)) is not None]

    async def is_segment_recipient(self, telegram_user_id: int, recipient_filter: RecipientFilter) -> bool:
        """Return whether the user currently matches the segmentation filter."""
        where, params = _build_segment_where(recipient_filter)
        cursor = await self.db.conn.execute(
            f"SELECT 1 FROM users u WHERE {where} AND u.telegram_user_id = ? LIMIT 1",
            (*params, telegram_user_id),
        )
        return await cursor.fetchone() is not None

    async def update_note(self, telegram_user_id: int, note: str | None, now: str) -> None:
        """Update a user's note, raising NotFound if the user is absent."""
        cursor = await self.db.conn.execute(
            "UPDATE users SET note = ?, updated_at = ? WHERE telegram_user_id = ?",
            (note, now, telegram_user_id),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise NotFound("Пользователь не найден")

    async def set_language(self, telegram_user_id: int, language: str | None, now: str) -> None:
        """Set a user's language override, raising NotFound if the user is absent."""
        cursor = await self.db.conn.execute(
            "UPDATE users SET language = ?, updated_at = ? WHERE telegram_user_id = ?",
            (language, now, telegram_user_id),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise NotFound("Пользователь не найден")

    async def set_expiry_notifications_enabled(self, telegram_user_id: int, enabled: bool, now: str) -> None:
        """Toggle a user's expiry-reminder opt-out, raising NotFound if absent."""
        cursor = await self.db.conn.execute(
            "UPDATE users SET expiry_notifications_enabled = ?, updated_at = ? WHERE telegram_user_id = ?",
            (1 if enabled else 0, now, telegram_user_id),
        )
        await self.db.commit()
        if cursor.rowcount != 1:
            raise NotFound("Пользователь не найден")

    async def reset_trial_quota(self, telegram_user_id: int, now: str) -> None:
        """Reset a user's trial quota by recording the current reset time."""
        await self.db.conn.execute(
            "UPDATE users SET trial_quota_reset_at = ?, updated_at = ? WHERE telegram_user_id = ?",
            (now, now, telegram_user_id),
        )
        await self.db.commit()

    async def get_trial_quota_reset_at(self, telegram_user_id: int) -> str | None:
        """Return a user's trial quota reset timestamp, or None if unset."""
        cursor = await self.db.conn.execute(
            "SELECT trial_quota_reset_at FROM users WHERE telegram_user_id = ?",
            (telegram_user_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return row["trial_quota_reset_at"]  # type: ignore[no-any-return]

    async def list_by_ids(self, telegram_user_ids: list[int]) -> dict[int, User]:
        """Return users for the given Telegram user ids keyed by user id."""
        if not telegram_user_ids:
            return {}
        placeholders = ",".join("?" for _ in telegram_user_ids)
        cursor = await self.db.conn.execute(
            f"SELECT * FROM users WHERE telegram_user_id IN ({placeholders})",
            tuple(telegram_user_ids),
        )
        rows = await cursor.fetchall()
        users: dict[int, User] = {}
        for row in rows:
            user = _row_to_user(row)
            if user is not None:
                users[user.telegram_user_id] = user
        return users
