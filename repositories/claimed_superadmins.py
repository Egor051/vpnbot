"""The ``claimed_superadmins`` table: who claimed the bot with the install link.

Read once at startup (into services.superadmins.SuperadminSet) and written only by
a successful claim (services.superadmin_claim), inside that claim's transaction.
"""

from __future__ import annotations

from db.database import Database
from models.enums import UserRole


class ClaimedSuperadminRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def list_ids(self) -> frozenset[int]:
        """Every Telegram user id that claimed the bot."""
        rows = await self.db.conn.execute_fetchall("SELECT telegram_user_id FROM claimed_superadmins")
        return frozenset(int(row["telegram_user_id"]) for row in rows)

    async def add(self, telegram_user_id: int, now: str) -> None:
        """Record a claim. Raises on a duplicate: a user claims at most once."""
        await self.db.conn.execute(
            "INSERT INTO claimed_superadmins (telegram_user_id, claimed_at) VALUES (?, ?)",
            (telegram_user_id, now),
        )
        await self.db.commit()

    async def any_superadmin(self) -> bool:
        """Whether the DATABASE already knows a superadmin, claimed or not.

        A claim is a way to get the FIRST superadmin, never another one. Besides the
        claim table this also counts users already holding the SUPERADMIN role — on
        a host whose ADMIN_IDS was emptied by mistake, the superadmins from before
        are still in ``users``, and a stray claim file must not add one more.
        """
        row = await self.db.conn.execute_fetchone(
            """
            SELECT EXISTS (SELECT 1 FROM claimed_superadmins)
                OR EXISTS (SELECT 1 FROM users WHERE role = ?) AS found
            """,
            (UserRole.SUPERADMIN.value,),
        )
        return row is not None and bool(row["found"])
