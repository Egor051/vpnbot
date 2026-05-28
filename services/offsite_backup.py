
import asyncio
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from aiogram import Bot
from aiogram.types import BufferedInputFile

from adapters.clock import ClockProvider
from db.database import Database

logger = logging.getLogger(__name__)


class OffsiteBackupService:
    """Encrypted offsite backup service.

    Key rotation recommendation: rotate OFFSITE_BACKUP_ENCRYPTION_KEY periodically
    (e.g. every 90 days) to limit the window of compromise.  To rotate:
      1. Generate a new key:
           python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
      2. Update OFFSITE_BACKUP_ENCRYPTION_KEY in the environment / .env file.
      3. Re-download the latest backup and re-encrypt it with the new key if
         you want to be able to restore from it after the old key is discarded.
      4. Restart the bot — the next scheduled backup will use the new key.
    """

    # Backups older than this are rejected by decrypt_backup() to reduce the
    # window during which a compromised key can be used to decrypt old data.
    BACKUP_MAX_AGE_DAYS = 30

    _META_KEY = "last_offsite_backup"

    def __init__(self, *, db: Database, db_path: Path, encryption_key: str, clock: ClockProvider) -> None:
        self.db_path = db_path
        self.clock = clock
        self._encryption_key = encryption_key
        self._db = db

    async def get_last_backup_time(self) -> datetime | None:
        value = await self._db.get_meta(self._META_KEY)
        if value is None:
            return None
        return datetime.fromisoformat(value)

    async def record_backup_sent(self) -> None:
        await self._db.set_meta(self._META_KEY, datetime.now(timezone.utc).replace(microsecond=0).isoformat())

    @property
    def enabled(self) -> bool:
        return bool(self._encryption_key)

    async def create_encrypted_backup(self) -> tuple[bytes, str]:
        """Create an encrypted snapshot of the database and return it with a filename."""
        if not self._encryption_key:
            raise RuntimeError("OFFSITE_BACKUP_ENCRYPTION_KEY не настроен")

        raw_data = await asyncio.to_thread(self._snapshot_db)

        from cryptography.fernet import Fernet
        fernet = Fernet(self._encryption_key.encode())
        encrypted = fernet.encrypt(raw_data)

        # The Fernet token already embeds a creation timestamp used by
        # decrypt_backup() to enforce the TTL; the filename stamp is for
        # human reference only.
        stamp = self.clock.now().replace(":", "").replace("+", "_").replace(".", "")[:15]
        filename = f"vpnbot_backup_{stamp}.db.enc"
        return encrypted, filename

    def decrypt_backup(self, encrypted_data: bytes, *, max_age_days: int = BACKUP_MAX_AGE_DAYS) -> bytes:
        """Decrypt a backup blob and enforce a TTL based on the Fernet timestamp.

        Raises RuntimeError if the backup is older than *max_age_days* or if
        decryption fails.  Rotate OFFSITE_BACKUP_ENCRYPTION_KEY before the TTL
        expires to ensure you can always restore from recent backups.
        """
        import time

        from cryptography.fernet import Fernet, InvalidToken

        if not self._encryption_key:
            raise RuntimeError("OFFSITE_BACKUP_ENCRYPTION_KEY не настроен")

        fernet = Fernet(self._encryption_key.encode())
        try:
            token_ts = fernet.extract_timestamp(encrypted_data)
        except (InvalidToken, Exception) as exc:
            raise RuntimeError(f"Не удалось прочитать метку времени из бэкапа: {exc}") from exc

        age_seconds = time.time() - token_ts
        max_age_seconds = max_age_days * 86400
        if age_seconds > max_age_seconds:
            age_days = age_seconds / 86400
            raise RuntimeError(
                f"Бэкап устарел: возраст {age_days:.1f} д. (лимит {max_age_days} д.). "
                "Ротируйте OFFSITE_BACKUP_ENCRYPTION_KEY и создайте новый бэкап."
            )

        try:
            return fernet.decrypt(encrypted_data)
        except InvalidToken as exc:
            raise RuntimeError("Не удалось расшифровать бэкап: неверный ключ или повреждённые данные") from exc

    def _snapshot_db(self) -> bytes:
        # Backup into an in-memory database so no plaintext ever touches disk.
        # serialize() is available since Python 3.12 (required by this project).
        src = sqlite3.connect(str(self.db_path))
        try:
            dst = sqlite3.connect(":memory:")
            try:
                src.backup(dst)
                return dst.serialize()
            finally:
                dst.close()
        finally:
            src.close()

    async def send_to_admins(self, bot: Bot, admin_ids: frozenset[int]) -> dict[str, int]:
        """Send an encrypted backup to all admins and return delivery counts."""
        encrypted, filename = await self.create_encrypted_backup()
        success = 0
        failed = 0
        for admin_id in admin_ids:
            try:
                await bot.send_document(
                    admin_id,
                    document=BufferedInputFile(encrypted, filename=filename),
                    caption=(
                        f"Зашифрованный бэкап БД: <code>{filename}</code>\n"
                        "Для расшифровки используйте ключ из <code>OFFSITE_BACKUP_ENCRYPTION_KEY</code>."
                    ),
                )
                success += 1
            except Exception:
                logger.warning("Не удалось отправить бэкап администратору %s", admin_id, exc_info=True)
                failed += 1
        return {"success": success, "failed": failed, "total": len(admin_ids)}


async def offsite_backup_loop(
    service: OffsiteBackupService,
    bot: Bot,
    admin_ids: frozenset[int],
    interval: int,
) -> None:
    """Send encrypted offsite backups to admins repeatedly at the given interval."""
    # Short startup delay so the bot finishes initialising before the first backup.
    await asyncio.sleep(60)
    while True:
        last_sent = await service.get_last_backup_time()
        if last_sent is not None:
            elapsed = (datetime.now(timezone.utc) - last_sent).total_seconds()
            remaining = interval - elapsed
            if remaining > 0:
                logger.info("Offsite backup: следующий через %.0f с (последний %.0f с назад)", remaining, elapsed)
                await asyncio.sleep(remaining)

        try:
            result = await service.send_to_admins(bot, admin_ids)
            await service.record_backup_sent()
            logger.info(
                "Offsite backup sent: success=%d failed=%d total=%d",
                result["success"],
                result["failed"],
                result["total"],
            )
        except Exception:
            logger.warning("Offsite backup job упал с ошибкой", exc_info=True)
        await asyncio.sleep(interval)
