
import asyncio
import os
import time
from pathlib import Path
from types import TracebackType
from typing import Self, TextIO


class ConfigLockBusyError(TimeoutError):
    pass


class ConfigFileLock:
    def __init__(self, target: Path, timeout: float = 5.0, poll_interval: float = 0.05) -> None:
        self.lock_path = target.with_name(f".{target.name}.lock")
        self.timeout = max(timeout, 0.0)
        self.poll_interval = max(poll_interval, 0.01)
        self._file: TextIO | None = None

    def _acquire_sync(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
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
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        file = self.lock_path.open("a+", encoding="utf-8")
        if os.name == "posix":
            import fcntl

            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, lambda: fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    )
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
