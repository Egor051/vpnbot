from __future__ import annotations

import os
import secrets
import shutil
import time
from pathlib import Path

from adapters.clock import ClockProvider
from adapters.errors import AdapterError


class BackupAdapter:
    def __init__(self, clock: ClockProvider) -> None:
        self.clock = clock

    def create_backup(self, target: Path) -> Path:
        if not target.exists():
            raise AdapterError(f"Файл не найден для backup: {target}")
        stamp = self.clock.now().replace(":", "").replace("+", "_").replace(".", "")
        for _ in range(10):
            backup_path = target.with_name(f"{target.name}.{stamp}.{time.time_ns()}.{secrets.token_hex(4)}.bak")
            if not backup_path.exists():
                break
        else:
            raise AdapterError(f"Не удалось создать уникальное имя backup для {target}")
        shutil.copy2(target, backup_path)
        return backup_path

    def restore(self, backup_path: Path, target: Path) -> None:
        if not backup_path.exists():
            raise AdapterError(f"Backup не найден: {backup_path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target.with_name(f".{target.name}.restore.{time.time_ns()}.{secrets.token_hex(4)}")
        try:
            shutil.copy2(backup_path, tmp_path)
            with tmp_path.open("rb+") as file:
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_path, target)
            self._fsync_parent(target)
        finally:
            tmp_path.unlink(missing_ok=True)

    def atomic_write_text(self, target: Path, content: str, mode_from: Path | None = None) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target.with_name(f".{target.name}.{time.time_ns()}.{secrets.token_hex(4)}.tmp")
        data = content.encode("utf-8")
        try:
            with tmp_path.open("wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            if mode_from and mode_from.exists():
                shutil.copystat(mode_from, tmp_path)
            os.replace(tmp_path, target)
            self._fsync_parent(target)
        finally:
            tmp_path.unlink(missing_ok=True)

    def cleanup_old_backups(self, directory: Path, pattern: str = "*.bak", keep_last: int = 20) -> int:
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

    def _fsync_parent(self, target: Path) -> None:
        if os.name == "nt":
            return
        fd = os.open(str(target.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
