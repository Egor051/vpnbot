from __future__ import annotations

from typing import Iterable

from aiosqlite import Row

from db.database import Database
from models.dto import TelegramUserProfile, User
from models.enums import UserRole, parse_user_role
from services.errors import NotFound


_ANNOUNCEMENT_ROLE_SQL_VALUES = (
    UserRole.APPROVED_USER.value.lower(),
    UserRole.SUPERADMIN.value.lower(),
    "approved",
    "superadmin",
    "super_admin",
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
    return User(
        telegram_user_id=int(row["telegram_user_id"]),
        username=row["username"],
        first_name=row["first_name"],
        role=role,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        blocked_at=row["blocked_at"],
    )


class UserRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get_by_id(self, telegram_user_id: int) -> User | None:
        cursor = await self.db.conn.execute(
            "SELECT * FROM users WHERE telegram_user_id = ?",
            (telegram_user_id,),
        )
        row = await cursor.fetchone()
        return _row_to_user(row)

    async def upsert_profile(self, profile: TelegramUserProfile, role: UserRole, now: str) -> User:
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
        for admin_id in admin_ids:
            await self.db.conn.execute(
                """
                INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                VALUES (?, NULL, NULL, ?, ?, ?)
                ON CONFLICT(telegram_user_id) DO UPDATE SET
                  role = excluded.role,
                  blocked_at = NULL,
                  updated_at = excluded.updated_at
                """,
                (admin_id, UserRole.SUPERADMIN.value, now, now),
            )
        await self.db.commit()

    async def set_role(self, telegram_user_id: int, role: UserRole, now: str, blocked_at: str | None = None) -> None:
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

    async def list_users(self, limit: int = 20, offset: int = 0) -> list[User]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM users
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [user for row in rows if (user := _row_to_user(row)) is not None]

    async def count_announcement_recipients(self) -> int:
        cursor = await self.db.conn.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM users
            WHERE blocked_at IS NULL
              AND LOWER(role) IN ({_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS})
            """,
            _ANNOUNCEMENT_ROLE_SQL_VALUES,
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def list_announcement_recipients_after(self, last_seen_id: int | None, limit: int = 100) -> list[User]:
        if last_seen_id is None:
            cursor = await self.db.conn.execute(
                f"""
                SELECT * FROM users
                WHERE blocked_at IS NULL
                  AND LOWER(role) IN ({_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS})
                ORDER BY telegram_user_id ASC
                LIMIT ?
                """,
                (*_ANNOUNCEMENT_ROLE_SQL_VALUES, limit),
            )
        else:
            cursor = await self.db.conn.execute(
                f"""
                SELECT * FROM users
                WHERE blocked_at IS NULL
                  AND LOWER(role) IN ({_ANNOUNCEMENT_ROLE_SQL_PLACEHOLDERS})
                  AND telegram_user_id > ?
                ORDER BY telegram_user_id ASC
                LIMIT ?
                """,
                (*_ANNOUNCEMENT_ROLE_SQL_VALUES, last_seen_id, limit),
            )
        rows = await cursor.fetchall()
        return [user for row in rows if (user := _row_to_user(row)) is not None]

    async def list_by_ids(self, telegram_user_ids: list[int]) -> dict[int, User]:
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
