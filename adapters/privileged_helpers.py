from __future__ import annotations

import os
import secrets
import shutil
import tempfile
from pathlib import Path
from collections.abc import Sequence

from adapters.shell_runner import ShellRunner
from models.dto import ShellResult


class PrivilegedHelperError(RuntimeError):
    pass


class PrivilegedHelperRunner:
    def __init__(self, *, shell: ShellRunner, use_sudo: bool = True) -> None:
        self.shell = shell
        self.use_sudo = use_sudo

    async def run(
        self,
        helper_path: Path,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        sensitive_values: Sequence[str] = (),
        timeout: float = 60.0,
        max_output_chars: int = 2048,
    ) -> ShellResult:
        if not helper_path.is_absolute():
            raise PrivilegedHelperError("Privileged helper path must be absolute")
        command = [str(helper_path), *args]
        if self.use_sudo:
            command = ["sudo", "-n", *command]
        return await self.shell.run(
            command,
            input_text=input_text,
            sensitive_values=sensitive_values,
            timeout=timeout,
            max_output_chars=max_output_chars,
        )


def write_private_staging_file(staging_dir: Path, *, prefix: str, suffix: str, content: str) -> Path:
    staging_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        staging_dir.chmod(0o700)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=staging_dir,
        prefix=prefix,
        suffix=suffix,
        delete=False,
    ) as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())
        path = Path(file.name)
    if os.name == "posix":
        path.chmod(0o600)
    return path


def create_private_staging_dir(staging_root: Path, *, prefix: str) -> Path:
    staging_root.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        staging_root.chmod(0o700)
    path = staging_root / f"{prefix}{secrets.token_hex(8)}"
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def cleanup_staging_path(path: Path | None) -> None:
    if path is None:
        return
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
        return
    path.unlink(missing_ok=True)
