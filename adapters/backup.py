
import os
import secrets
import shutil
import time
from pathlib import Path

from adapters.clock import ClockProvider
from adapters.errors import AdapterError
from adapters.file_ops import copy_stat, fsync_parent


class BackupAdapter:
    def __init__(self, clock: ClockProvider, keep_last: int = 20) -> None:
        self.clock = clock
        self.keep_last = max(0, keep_last)

    def create_backup(self, target: Path) -> Path:
        """Create a timestamped private backup copy of the target file."""
        if not target.exists():
            raise AdapterError(f"Файл не найден для backup: {target}")
        stamp = self.clock.now().replace(":", "").replace("+", "_").replace(".", "")
        for _ in range(10):
            backup_path = target.with_name(f"{target.name}.{stamp}.{time.time_ns()}.{secrets.token_urlsafe(16)}.bak")
            if not backup_path.exists():
                break
        else:
            raise AdapterError(f"Не удалось создать уникальное имя backup для {target}")
        shutil.copy2(target, backup_path)
        self._chmod_private_file(backup_path)
        if self.keep_last:
            self.cleanup_old_backups(target.parent, pattern=f"{target.name}.*.bak", keep_last=self.keep_last)
        return backup_path

    def restore(self, backup_path: Path, target: Path, mode_from: Path | None = None) -> None:
        """Atomically restore the target file from a backup copy."""
        if not backup_path.exists():
            raise AdapterError(f"Backup не найден: {backup_path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target.with_name(f".{target.name}.restore.{time.time_ns()}.{secrets.token_urlsafe(16)}")
        try:
            shutil.copy2(backup_path, tmp_path)
            if mode_from is not None and mode_from.exists():
                copy_stat(mode_from, tmp_path)
            else:
                self._chmod_private_file(tmp_path)
            with tmp_path.open("rb+") as file:
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_path, target)
            fsync_parent(target)
        finally:
            tmp_path.unlink(missing_ok=True)

    def atomic_write_text(self, target: Path, content: str, mode_from: Path | None = None) -> None:
        """Atomically write text content to the target file."""
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target.with_name(f".{target.name}.{time.time_ns()}.{secrets.token_urlsafe(16)}.tmp")
        data = content.encode("utf-8")
        try:
            with tmp_path.open("wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            if mode_from and mode_from.exists():
                copy_stat(mode_from, tmp_path)
            else:
                self._chmod_private_file(tmp_path)
            os.replace(tmp_path, target)
            fsync_parent(target)
        finally:
            tmp_path.unlink(missing_ok=True)

    def cleanup_old_backups(self, directory: Path, pattern: str = "*.bak", keep_last: int = 20) -> int:
        """Delete old backup files, keeping only the most recent ones."""
        backups = sorted(
            (path for path in directory.glob(pattern) if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        removed = 0
        for path in backups[keep_last:]:
            path.unlink(missing_ok=True)
            removed += 1
        return removed

    def _chmod_private_file(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            path.chmod(0o600)
        except OSError:
            pass
