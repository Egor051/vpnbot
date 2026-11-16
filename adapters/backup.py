
import glob
import os
import re
import secrets
import shutil
import time
from pathlib import Path

from adapters.clock import ClockProvider
from adapters.errors import AdapterError
from adapters.file_ops import copy_stat, fsync_parent


# The name create_backup gives a copy of <name>: "<name>.<stamp>.<time_ns>.<token>.bak".
# <stamp> is ClockProvider.now() (ISO 8601, seconds, with an offset) with ":" and "."
# dropped and "+" turned into "_" (2026-11-16T123456_0000); <token> is
# secrets.token_urlsafe(16), always 22 characters. prune_backups deletes ONLY names
# that match this whole template, so an operator's own config.json.pre-x.bak, the
# privileged helpers' "<name>.<time_ns>.bak" and anything else in the directory are
# never touched.
_STAMP_RE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}(?:[_-][0-9]{4}|Z)?"
_NONCE_RE = r"[A-Za-z0-9_-]{22}"  # secrets.token_urlsafe(16): a random file-name suffix


class BackupAdapter:
    def __init__(self, clock: ClockProvider, keep_last: int = 20) -> None:
        self.clock = clock
        self.keep_last = max(0, keep_last)

    @staticmethod
    def backup_name_re(target: Path) -> re.Pattern[str]:
        """The exact name template of the backups create_backup writes for ``target``."""
        return re.compile(rf"{re.escape(target.name)}\.{_STAMP_RE}\.[0-9]+\.{_NONCE_RE}\.bak")

    def create_backup(self, target: Path, *, prune: bool = True) -> Path:
        """Create a timestamped private backup copy of the target file.

        ``prune=False`` leaves retention to the caller (XrayConfigAdapter prunes its own
        copies with prune_backups once a mutation succeeded); otherwise the copies of
        ``target`` beyond ``keep_last`` are deleted right here, as before.
        """
        if not target.exists():
            raise AdapterError(f"Файл не найден для backup: {target}")
        stamp = self.clock.now().replace(":", "").replace("+", "_").replace(".", "")
        # _copy_private opens the destination with O_CREAT|O_EXCL, so a name collision
        # surfaces as FileExistsError rather than silently overwriting; retry with a fresh
        # (time_ns + 128-bit token) name. Collisions are astronomically unlikely.
        backup_path: Path | None = None
        for _ in range(10):
            candidate = target.with_name(f"{target.name}.{stamp}.{time.time_ns()}.{secrets.token_urlsafe(16)}.bak")
            try:
                self._copy_private(target, candidate)
            except FileExistsError:
                continue
            backup_path = candidate
            break
        if backup_path is None:
            raise AdapterError(f"Не удалось создать уникальное имя backup для {target}")
        if prune and self.keep_last:
            self.cleanup_old_backups(target.parent, pattern=f"{target.name}.*.bak", keep_last=self.keep_last)
        return backup_path

    def prune_backups(self, target: Path, keep_last: int) -> int:
        """Keep the newest ``keep_last`` backups create_backup wrote for ``target``.

        Only files whose whole name matches backup_name_re(target) are candidates —
        never another file in the directory, whatever its name. Returns how many were
        deleted. ``keep_last`` below 1 is treated as 1: the newest copy always stays.
        """
        return self.cleanup_old_backups(
            target.parent,
            pattern=f"{glob.escape(target.name)}.*.bak",
            keep_last=max(1, keep_last),
            name_re=self.backup_name_re(target),
        )

    def restore(self, backup_path: Path, target: Path, mode_from: Path | None = None) -> None:
        """Atomically restore the target file from a backup copy."""
        if not backup_path.exists():
            raise AdapterError(f"Backup не найден: {backup_path}")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target.with_name(f".{target.name}.restore.{time.time_ns()}.{secrets.token_urlsafe(16)}")
        try:
            self._copy_private(backup_path, tmp_path)
            if mode_from is not None and mode_from.exists():
                copy_stat(mode_from, tmp_path)
            else:
                self._chmod_private_file(tmp_path)
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
            self._write_private(tmp_path, data)
            if mode_from and mode_from.exists():
                copy_stat(mode_from, tmp_path)
            else:
                self._chmod_private_file(tmp_path)
            os.replace(tmp_path, target)
            fsync_parent(target)
        finally:
            tmp_path.unlink(missing_ok=True)

    def cleanup_old_backups(
        self,
        directory: Path,
        pattern: str = "*.bak",
        keep_last: int = 20,
        *,
        name_re: re.Pattern[str] | None = None,
    ) -> int:
        """Delete old backup files, keeping only the most recent ones.

        ``name_re``: only files whose whole name matches it are considered at all.
        """
        backups = sorted(
            (
                path
                for path in directory.glob(pattern)
                if path.is_file() and (name_re is None or name_re.fullmatch(path.name))
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        removed = 0
        for path in backups[keep_last:]:
            path.unlink(missing_ok=True)
            removed += 1
        return removed

    def _copy_private(self, source: Path, dest: Path) -> None:
        """Copy source into a freshly created, fsync'd, private (0600) destination.

        The destination is created with O_CREAT|O_EXCL and mode 0600 so a secret-bearing
        config (e.g. AWG [Interface] PrivateKey) is never momentarily group/world-readable
        between creation and chmod.
        """
        if os.name == "posix":
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out, source.open("rb") as src:
                shutil.copyfileobj(src, out)
                out.flush()
                os.fsync(out.fileno())
        else:
            shutil.copyfile(source, dest)

    def _write_private(self, dest: Path, data: bytes) -> None:
        """Write bytes to a freshly created, fsync'd, private (0600) destination."""
        if os.name == "posix":
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
        else:
            with dest.open("wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())

    def _chmod_private_file(self, path: Path) -> None:
        if os.name != "posix":
            return
        try:
            path.chmod(0o600)
        except OSError:
            pass
