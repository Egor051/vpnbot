
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
    """Invokes fixed sudo helper scripts that perform privileged VPN/proxy operations.

    Allowed commands: only absolute-path scripts listed in the sudo policy file
    (typically /etc/sudoers.d/vpnbot or a drop-in under /etc/sudoers.d/).  Each
    script must be owned by root:root with mode 0o755 and must not be writable by
    the bot user.

    Sudo policy template (non-interactive, no-password for specific scripts):
        vpnbot ALL=(root) NOPASSWD: /opt/vpnbot/scripts/awg_apply.sh, \\
                                    /opt/vpnbot/scripts/xray_apply.sh, \\
                                    ...

    To add a new helper: (1) write the script, (2) chmod/chown it, (3) add it to
    the sudoers drop-in, (4) pass its absolute path to `PrivilegedHelperRunner.run`.
    """

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
        """Run the helper at helper_path with optional sudo; raises PrivilegedHelperError on bad path.

        The real security boundary is the sudoers exact-path allowlist; these checks are
        defence-in-depth so a buggy caller cannot smuggle a relative path or ``..`` segment
        into a sudo invocation.
        """
        if not helper_path.is_absolute():
            raise PrivilegedHelperError("Privileged helper path must be absolute")
        if ".." in helper_path.parts:
            raise PrivilegedHelperError("Privileged helper path must not contain '..'")
        if helper_path.is_symlink():
            raise PrivilegedHelperError("Privileged helper path must not be a symlink")
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


def _mkdir_private(path: Path) -> None:
    """Create path and all missing ancestors, chmoding each to 0700 immediately.

    Also re-asserts 0700 on the leaf when it already exists, so a pre-created staging
    directory with lax permissions is tightened instead of being trusted as-is.
    """
    if path.is_symlink():
        raise PrivilegedHelperError(f"Staging path must not be a symlink: {path}")
    to_create: list[Path] = []
    p = path
    while not p.exists():
        to_create.append(p)
        p = p.parent
    for d in reversed(to_create):
        d.mkdir(mode=0o700, exist_ok=True)
        if os.name == "posix":
            os.chmod(d, 0o700)
    if os.name == "posix" and not to_create:
        # Leaf already existed: enforce private permissions rather than trust them.
        os.chmod(path, 0o700)


def write_private_staging_file(staging_dir: Path, *, prefix: str, suffix: str, content: str) -> Path:
    """Write content to a new private (0600) staging file and return its path."""
    if os.name == "posix":
        _mkdir_private(staging_dir)
    else:
        staging_dir.mkdir(parents=True, exist_ok=True)
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
    """Create and return a new private (0700) staging directory under the root."""
    if os.name == "posix":
        _mkdir_private(staging_root)
    else:
        staging_root.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(staging_root, 0o700)
    path = staging_root / f"{prefix}{secrets.token_hex(8)}"
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def cleanup_staging_path(path: Path | None) -> None:
    """Remove the given staging file or directory, ignoring missing paths."""
    if path is None:
        return
    # Check symlink first: is_dir() follows links, so a symlinked staging path must be
    # unlinked (never rmtree'd through, which would also fail and leak the target).
    if path.is_symlink():
        path.unlink(missing_ok=True)
        return
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
        return
    path.unlink(missing_ok=True)
