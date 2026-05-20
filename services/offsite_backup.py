
import asyncio
import logging
import sqlite3
import tempfile
from pathlib import Path

from aiogram import Bot
from aiogram.types import BufferedInputFile

from adapters.clock import ClockProvider

logger = logging.getLogger(__name__)


class OffsiteBackupService:
    def __init__(self, *, db_path: Path, encryption_key: str, clock: ClockProvider) -> None:
        self.db_path = db_path
        self.clock = clock
        self._encryption_key = encryption_key

    @property
    def enabled(self) -> bool:
        return bool(self._encryption_key)

    async def create_encrypted_backup(self) -> tuple[bytes, str]:
        if not self._encryption_key:
            raise RuntimeError("OFFSITE_BACKUP_ENCRYPTION_KEY не настроен")

        raw_data = await asyncio.to_thread(self._snapshot_db)

        from cryptography.fernet import Fernet
        fernet = Fernet(self._encryption_key.encode())
        encrypted = fernet.encrypt(raw_data)

        stamp = self.clock.now().replace(":", "").replace("+", "_").replace(".", "")[:15]
        filename = f"vpnbot_backup_{stamp}.db.enc"
        return encrypted, filename

    def _snapshot_db(self) -> bytes:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            src = sqlite3.connect(str(self.db_path))
            try:
                dst = sqlite3.connect(str(tmp_path))
                try:
                    src.backup(dst)
                finally:
                    dst.close()
            finally:
                src.close()
            return tmp_path.read_bytes()
        finally:
            tmp_path.unlink(missing_ok=True)

    async def send_to_admins(self, bot: Bot, admin_ids: frozenset[int]) -> dict[str, int]:
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
    while True:
        await asyncio.sleep(interval)
        try:
            result = await service.send_to_admins(bot, admin_ids)
            logger.info(
                "Offsite backup sent: success=%d failed=%d total=%d",
                result["success"],
                result["failed"],
                result["total"],
            )
        except Exception:
            logger.warning("Offsite backup job упал с ошибкой", exc_info=True)
