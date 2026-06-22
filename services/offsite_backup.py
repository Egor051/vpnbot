
import asyncio
import hashlib
import io
import json
import logging
import sqlite3
import tarfile
from collections.abc import Sequence
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

    def __init__(
        self,
        *,
        db: Database,
        db_path: Path,
        encryption_key: str,
        clock: ClockProvider,
        recovery_sources: Sequence[Path] = (),
        include_recovery: bool = False,
    ) -> None:
        self.db_path = db_path
        self.clock = clock
        self._encryption_key = encryption_key
        self._db = db
        # De-duplicated, order-preserving list of files bundled into the recovery
        # archive (.env + service configs). Read best-effort at backup time.
        seen: set[Path] = set()
        sources: list[Path] = []
        for source in recovery_sources:
            if source not in seen:
                seen.add(source)
                sources.append(source)
        self._recovery_sources = tuple(sources)
        self._include_recovery = include_recovery

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

    @property
    def recovery_enabled(self) -> bool:
        """Whether a recovery bundle (.env + configs) can be produced and sent."""
        return self.enabled and self._include_recovery and bool(self._recovery_sources)

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
        except Exception as exc:  # InvalidToken and any malformed-token error
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

    async def create_recovery_bundle(self) -> tuple[bytes, str] | None:
        """Create an encrypted tar.gz of .env + service configs and a filename.

        Returns None when nothing could be read (e.g. all sources missing or
        unreadable), so the caller can skip sending an empty bundle. Raises
        RuntimeError when the encryption key is not configured — callers gate on
        :attr:`recovery_enabled` before invoking this. The same Fernet key (and
        therefore the same TTL enforced by :meth:`decrypt_backup`) protects both
        the DB backup and this bundle.
        """
        if not self._encryption_key:
            raise RuntimeError("OFFSITE_BACKUP_ENCRYPTION_KEY не настроен")

        tar_bytes = await asyncio.to_thread(self._build_recovery_tar)
        if tar_bytes is None:
            return None

        from cryptography.fernet import Fernet
        fernet = Fernet(self._encryption_key.encode())
        encrypted = fernet.encrypt(tar_bytes)

        stamp = self.clock.now().replace(":", "").replace("+", "_").replace(".", "")[:15]
        filename = f"vpnbot_recovery_{stamp}.tar.gz.enc"
        return encrypted, filename

    def _build_recovery_tar(self) -> bytes | None:
        """Build an in-memory tar.gz of the recovery sources plus MANIFEST.json.

        Best-effort: a missing/unreadable source is skipped (recorded in the
        manifest with a reason) so a partial bundle stays useful and its gaps are
        visible. Returns None if no source file could be read at all. No plaintext
        is ever written to disk — the archive is assembled entirely in memory,
        mirroring :meth:`_snapshot_db`.
        """
        created_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        manifest_files: list[dict[str, object]] = []
        blobs: list[tuple[str, bytes]] = []
        for source in self._recovery_sources:
            entry: dict[str, object] = {"path": str(source)}
            try:
                data = source.read_bytes()
            except OSError as exc:
                entry["included"] = False
                entry["reason"] = exc.__class__.__name__
                manifest_files.append(entry)
                logger.warning("Recovery bundle: пропускаю недоступный файл %s: %s", source, exc)
                continue
            member = "files/" + self._safe_arcname(source)
            entry["included"] = True
            entry["member"] = member
            entry["size"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            manifest_files.append(entry)
            blobs.append((member, data))

        if not blobs:
            return None

        manifest = {"created_at": created_at, "files": manifest_files}
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")

        buffer = io.BytesIO()
        # mtime=0 (no embedded gzip timestamp) keeps the archive reproducible for
        # a given input set, which makes the round-trip tests deterministic.
        with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            self._add_tar_bytes(tar, "MANIFEST.json", manifest_bytes)
            for member, data in blobs:
                self._add_tar_bytes(tar, member, data)
        return buffer.getvalue()

    @staticmethod
    def _safe_arcname(source: Path) -> str:
        """Map an absolute source path to a safe, relative tar member name.

        Leading slashes and any ``..``/``.`` components are stripped so extraction
        can never escape the destination directory. The remaining path preserves
        the file's origin (e.g. ``home/user/vpnbot/.env``), and the original
        absolute path is also recorded in MANIFEST.json.
        """
        parts = [part for part in source.as_posix().split("/") if part not in ("", ".", "..")]
        return "/".join(parts) or source.name

    @staticmethod
    def _add_tar_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
        info = tarfile.TarInfo(name=name)
        info.size = len(data)
        info.mtime = 0
        info.mode = 0o600
        tar.addfile(info, io.BytesIO(data))

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

    async def send_recovery_to_admins(self, bot: Bot, admin_ids: frozenset[int]) -> dict[str, int] | None:
        """Send the encrypted recovery bundle to all admins and return delivery counts.

        Returns None when the bundle is disabled or no source file could be read,
        so callers can distinguish "not sent" from a zero-success delivery.
        """
        if not self.recovery_enabled:
            return None
        built = await self.create_recovery_bundle()
        if built is None:
            return None
        encrypted, filename = built
        success = 0
        failed = 0
        for admin_id in admin_ids:
            try:
                await bot.send_document(
                    admin_id,
                    document=BufferedInputFile(encrypted, filename=filename),
                    caption=(
                        f"Зашифрованный бандл восстановления (.env + конфиги): <code>{filename}</code>\n"
                        "Расшифруйте тем же ключом <code>OFFSITE_BACKUP_ENCRYPTION_KEY</code>, "
                        "затем распакуйте: <code>tar xzf</code>. Хранить ключ нужно отдельно от бандла."
                    ),
                )
                success += 1
            except Exception:
                logger.warning("Не удалось отправить бандл восстановления администратору %s", admin_id, exc_info=True)
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
        try:
            last_sent = await service.get_last_backup_time()
        except Exception:
            logger.warning("Offsite backup: не удалось прочитать метку времени, считаем как первый запуск", exc_info=True)
            last_sent = None
        if last_sent is not None:
            elapsed = (datetime.now(timezone.utc) - last_sent).total_seconds()
            remaining = interval - elapsed
            if remaining > 0:
                logger.info("Offsite backup: следующий через %.0f с (последний %.0f с назад)", remaining, elapsed)
                await asyncio.sleep(remaining)

        try:
            result = await service.send_to_admins(bot, admin_ids)
            if result["success"] > 0:
                await service.record_backup_sent()
            logger.info(
                "Offsite backup sent: success=%d failed=%d total=%d",
                result["success"],
                result["failed"],
                result["total"],
            )
        except Exception:
            logger.warning("Offsite backup job упал с ошибкой", exc_info=True)

        # The recovery bundle is sent independently so a DB-backup failure never
        # suppresses it (and vice versa). It does not update last_offsite_backup —
        # the DB backup remains the scheduling anchor.
        if service.recovery_enabled:
            try:
                recovery = await service.send_recovery_to_admins(bot, admin_ids)
                if recovery is None:
                    logger.info("Offsite recovery bundle: нет доступных файлов, пропуск")
                else:
                    logger.info(
                        "Offsite recovery bundle sent: success=%d failed=%d total=%d",
                        recovery["success"],
                        recovery["failed"],
                        recovery["total"],
                    )
            except Exception:
                logger.warning("Offsite recovery bundle job упал с ошибкой", exc_info=True)
        await asyncio.sleep(interval)
