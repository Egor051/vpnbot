"""``totp_credentials`` and ``totp_backup_codes``: storage only (services/totp.py decides).

Everything secret arrives here already transformed: the TOTP secret as a Fernet token,
a backup code as scrypt(salt, code). Nothing in this module can produce a code.
"""

from __future__ import annotations

from typing import Any

from db.database import Database
from models.dto import TotpBackupCode, TotpCredential


def _credential(row: Any) -> TotpCredential:
    return TotpCredential(
        telegram_user_id=int(row["telegram_user_id"]),
        secret_enc=str(row["secret_enc"]),
        enabled=bool(row["enabled"]),
        created_at=str(row["created_at"]),
        enabled_at=row["enabled_at"],
        last_used_step=int(row["last_used_step"]),
        failed_attempts=int(row["failed_attempts"]),
        locked_until=int(row["locked_until"]),
    )


class TotpRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get(self, user_id: int) -> TotpCredential | None:
        row = await self.db.conn.execute_fetchone(
            "SELECT * FROM totp_credentials WHERE telegram_user_id = ?", (user_id,)
        )
        return _credential(row) if row is not None else None

    async def count_credentials(self) -> int:
        row = await self.db.conn.execute_fetchone("SELECT COUNT(*) AS n FROM totp_credentials WHERE enabled = 1")
        return int(row["n"]) if row is not None else 0

    async def save_pending(self, user_id: int, secret_enc: str, now: str) -> None:
        """Start (or restart) an enrollment: a new, not yet enabled secret.

        Refuses to overwrite an ENABLED credential — re-enrolling goes through
        «disable» first, which needs a code.
        """
        async with self.db.transaction():
            row = await self.db.conn.execute_fetchone(
                "SELECT enabled FROM totp_credentials WHERE telegram_user_id = ?", (user_id,)
            )
            if row is not None and int(row["enabled"]) == 1:
                raise ValueError("TOTP is already enabled for this user")
            await self.db.conn.execute(
                "DELETE FROM totp_credentials WHERE telegram_user_id = ?", (user_id,)
            )
            await self.db.conn.execute(
                """
                INSERT INTO totp_credentials (telegram_user_id, secret_enc, enabled, created_at)
                VALUES (?, ?, 0, ?)
                """,
                (user_id, secret_enc, now),
            )

    async def enable(
        self, user_id: int, *, secret_enc: str, step: int, codes: list[tuple[str, str]], now: str
    ) -> bool:
        """Confirm THIS pending enrollment (matched by its ciphertext) and store the
        backup codes, in one transaction. False when that enrollment is gone or was
        replaced meanwhile — nothing is changed then."""
        async with self.db.transaction():
            cursor = await self.db.conn.execute(
                """
                UPDATE totp_credentials
                SET enabled = 1, enabled_at = ?, last_used_step = ?, failed_attempts = 0, locked_until = 0
                WHERE telegram_user_id = ? AND enabled = 0 AND secret_enc = ?
                """,
                (now, step, user_id, secret_enc),
            )
            if int(cursor.rowcount or 0) != 1:
                return False
            await self._replace_codes(user_id, codes, now)
        return True

    async def replace_backup_codes(self, user_id: int, codes: list[tuple[str, str]], now: str) -> None:
        async with self.db.transaction():
            await self._replace_codes(user_id, codes, now)

    async def _replace_codes(self, user_id: int, codes: list[tuple[str, str]], now: str) -> None:
        await self.db.conn.execute("DELETE FROM totp_backup_codes WHERE telegram_user_id = ?", (user_id,))
        for salt_hex, hash_hex in codes:
            await self.db.conn.execute(
                """
                INSERT INTO totp_backup_codes (telegram_user_id, salt_hex, hash_hex, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (user_id, salt_hex, hash_hex, now),
            )

    async def unused_backup_codes(self, user_id: int) -> list[TotpBackupCode]:
        rows = await self.db.conn.execute_fetchall(
            """
            SELECT id, telegram_user_id, salt_hex, hash_hex, used_at FROM totp_backup_codes
            WHERE telegram_user_id = ? AND used_at IS NULL ORDER BY id
            """,
            (user_id,),
        )
        return [
            TotpBackupCode(
                id=int(row["id"]),
                telegram_user_id=int(row["telegram_user_id"]),
                salt_hex=str(row["salt_hex"]),
                hash_hex=str(row["hash_hex"]),
                used_at=row["used_at"],
            )
            for row in rows
        ]

    async def count_unused_backup_codes(self, user_id: int) -> int:
        row = await self.db.conn.execute_fetchone(
            "SELECT COUNT(*) AS n FROM totp_backup_codes WHERE telegram_user_id = ? AND used_at IS NULL",
            (user_id,),
        )
        return int(row["n"]) if row is not None else 0

    async def redeem_backup_code(self, code_id: int, now: str) -> bool:
        """Mark one code used. False when it was already used (a race lost)."""
        cursor = await self.db.conn.execute(
            "UPDATE totp_backup_codes SET used_at = ? WHERE id = ? AND used_at IS NULL", (now, code_id)
        )
        await self.db.commit()
        return int(cursor.rowcount or 0) == 1

    async def record_success(self, user_id: int, step: int | None) -> None:
        """Reset the failure counter; with a TOTP *step*, advance the replay guard."""
        if step is None:
            await self.db.conn.execute(
                "UPDATE totp_credentials SET failed_attempts = 0, locked_until = 0 WHERE telegram_user_id = ?",
                (user_id,),
            )
        else:
            await self.db.conn.execute(
                """
                UPDATE totp_credentials
                SET failed_attempts = 0, locked_until = 0, last_used_step = MAX(last_used_step, ?)
                WHERE telegram_user_id = ?
                """,
                (step, user_id),
            )
        await self.db.commit()

    async def record_failure(self, user_id: int, *, max_failures: int, lock_until: int) -> tuple[int, bool]:
        """Count one wrong code. Returns (consecutive failures, locked now?).

        The failure that reaches *max_failures* sets ``locked_until`` and resets the
        counter, so the next lockout needs another full series.
        """
        async with self.db.transaction():
            row = await self.db.conn.execute_fetchone(
                "SELECT failed_attempts FROM totp_credentials WHERE telegram_user_id = ?", (user_id,)
            )
            if row is None:
                return 0, False
            failures = int(row["failed_attempts"]) + 1
            if failures >= max_failures:
                await self.db.conn.execute(
                    "UPDATE totp_credentials SET failed_attempts = 0, locked_until = ? WHERE telegram_user_id = ?",
                    (lock_until, user_id),
                )
                return failures, True
            await self.db.conn.execute(
                "UPDATE totp_credentials SET failed_attempts = ? WHERE telegram_user_id = ?",
                (failures, user_id),
            )
            return failures, False

    async def delete_pending(self, user_id: int) -> bool:
        """Drop a not-yet-enabled enrollment; an enabled credential is never touched."""
        cursor = await self.db.conn.execute(
            "DELETE FROM totp_credentials WHERE telegram_user_id = ? AND enabled = 0", (user_id,)
        )
        await self.db.commit()
        return int(cursor.rowcount or 0) > 0

    async def delete(self, user_id: int) -> bool:
        cursor = await self.db.conn.execute("DELETE FROM totp_credentials WHERE telegram_user_id = ?", (user_id,))
        await self.db.commit()
        return int(cursor.rowcount or 0) > 0
