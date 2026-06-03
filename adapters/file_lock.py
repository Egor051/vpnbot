
import asyncio
import os
import time
from pathlib import Path
from types import TracebackType
from typing import Self, TextIO


class ConfigLockBusyError(TimeoutError):
    pass


class ConfigFileLock:
    def __init__(
        self,
        target: Path,
        timeout: float = 5.0,
        poll_interval: float = 0.05,
        *,
        lock_dir: Path | None = None,
    ) -> None:
        if lock_dir is not None:
            self.lock_path = lock_dir / f".{target.name}.lock"
            self._lock_dir_private = True
        else:
            self.lock_path = target.with_name(f".{target.name}.lock")
            self._lock_dir_private = False
        self.timeout = max(timeout, 0.0)
        self.poll_interval = max(poll_interval, 0.01)
        self._file: TextIO | None = None

    def _ensure_lock_dir(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        if self._lock_dir_private and os.name == "posix":
            os.chmod(self.lock_path.parent, 0o700)

    def _acquire_sync(self) -> None:
        self._ensure_lock_dir()
        file = self.lock_path.open("a+", encoding="utf-8")
        if os.name == "posix":
            import fcntl

            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    if time.monotonic() >= deadline:
                        file.close()
                        raise ConfigLockBusyError("config lock busy: другой процесс уже изменяет конфигурацию") from exc
                    time.sleep(min(self.poll_interval, max(deadline - time.monotonic(), 0.0)))
        self._file = file

    def _release_sync(self) -> None:
        if self._file is None:
            return
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None

    def __enter__(self) -> Self:
        self._acquire_sync()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._release_sync()

    async def __aenter__(self) -> Self:
        await asyncio.to_thread(self._ensure_lock_dir)
        file = self.lock_path.open("a+", encoding="utf-8")
        if os.name == "posix":
            import fcntl

            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    # LOCK_NB makes flock non-blocking, so it is safe to call directly on the
                    # event loop without an executor (avoids the deprecated get_event_loop()).
                    fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        file.close()
                        raise ConfigLockBusyError("config lock busy: другой процесс уже изменяет конфигурацию") from exc
                    await asyncio.sleep(min(self.poll_interval, remaining))
        self._file = file
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._release_sync()
