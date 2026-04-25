from __future__ import annotations

import os
from pathlib import Path
from types import TracebackType
from typing import TextIO


class ConfigFileLock:
    def __init__(self, target: Path) -> None:
        self.lock_path = target.with_name(f".{target.name}.lock")
        self._file: TextIO | None = None

    def __enter__(self) -> ConfigFileLock:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        file = self.lock_path.open("a+", encoding="utf-8")
        if os.name == "posix":
            import fcntl

            fcntl.flock(file.fileno(), fcntl.LOCK_EX)
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
            if os.name == "posix":
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
        finally:
            self._file.close()
            self._file = None
