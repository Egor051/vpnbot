
import os
from pathlib import Path
from types import TracebackType
from typing import Self, TextIO


class SingleInstanceError(RuntimeError):
    pass


class SingleInstanceLock:
    def __init__(self, lock_path: Path) -> None:
        self.lock_path = lock_path
        self._file: TextIO | None = None

    def __enter__(self) -> Self:
        if os.name != "posix":
            # Fail before touching the filesystem so we don't leave an orphan
            # lock file on platforms where flock() is unavailable.
            raise SingleInstanceError(
                "Single-instance lock поддерживается только на Linux/POSIX через fcntl.flock"
            )
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        file = self.lock_path.open("a+", encoding="utf-8")
        try:
            self._lock_file(file)
            file.seek(0)
            file.truncate()
            file.write(f"{os.getpid()}\n")
            file.flush()
            os.fsync(file.fileno())
        except Exception:
            file.close()
            raise
        self._file = file
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._file is None:
            return
        try:
            self._unlock_file(self._file)
        finally:
            self._file.close()
            self._file = None

    def _lock_file(self, file: TextIO) -> None:
        if os.name != "posix":
            raise SingleInstanceError("Single-instance lock поддерживается только на Linux/POSIX через fcntl.flock")
        import errno
        import fcntl

        try:
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise SingleInstanceError(
                    f"Бот уже запущен: lock занят ({self.lock_path}). Завершите первый экземпляр перед запуском второго."
                ) from exc
            raise

    def _unlock_file(self, file: TextIO) -> None:
        if os.name != "posix":
            return
        import fcntl

        fcntl.flock(file.fileno(), fcntl.LOCK_UN)
