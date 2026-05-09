#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path


HELPERS = (
    Path("/usr/local/sbin/vpnbot-socks5-user"),
    Path("/usr/local/sbin/vpnbot-xray-apply"),
    Path("/usr/local/sbin/vpnbot-awg-apply"),
    Path("/usr/local/sbin/vpnbot-mtproxy-apply"),
)
FORBIDDEN_WRITE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/.pwd.lock",
    "/usr/local/etc/xray",
    "/etc/amnezia/amneziawg",
    "/etc/mtproxy",
    "/etc/systemd/system",
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CheckError(f"{path}: cannot read: {exc}") from exc


class CheckError(Exception):
    pass


class Reporter:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []

    def ok(self, message: str) -> None:
        print(f"OK: {message}")

    def fail(self, message: str) -> None:
        self.failures.append(message)
        print(f"FAIL: {message}")

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        print(f"WARN: {message}")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _uid_gid_for_user(user: str) -> tuple[int, int] | None:
    if os.name != "posix":
        return None
    try:
        uid = int(subprocess.check_output(["id", "-u", user], text=True).strip())
        gid = int(subprocess.check_output(["id", "-g", user], text=True).strip())
    except (OSError, subprocess.CalledProcessError, ValueError):
        return None
    return uid, gid


def _would_be_writable(path: Path, uid: int, gid: int) -> bool:
    st = path.stat()
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid == uid:
        return bool(mode & stat.S_IWUSR)
    if st.st_gid == gid:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


def _resolve_unit_path(raw_path: str | None, repo_root: Path) -> Path:
    if raw_path:
        return Path(raw_path)
    installed = Path("/etc/systemd/system/vpn-bot.service")
    if installed.exists():
        return installed
    return repo_root / "deploy" / "vpn-bot.service"


def check_unit(path: Path, reporter: Reporter) -> None:
    try:
        text = _read(path)
    except CheckError as exc:
        reporter.fail(str(exc))
        return

    required = (
        "User=vpn-bot",
        "Group=vpn-bot",
        "Environment=BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock",
        "RuntimeDirectory=vpn-bot",
        "RuntimeDirectoryMode=0700",
        "ProtectSystem=strict",
    )
    for item in required:
        if item in text:
            reporter.ok(f"{path}: contains {item}")
        else:
            reporter.fail(f"{path}: missing {item}")

    forbidden = ("User=root", "Group=root", "NoNewPrivileges=true", "future example")
    for item in forbidden:
        if item in text:
            reporter.fail(f"{path}: contains forbidden {item}")
        else:
            reporter.ok(f"{path}: does not contain {item}")

    read_write = "\n".join(line for line in text.splitlines() if line.startswith("ReadWritePaths="))
    if not read_write:
        reporter.fail(f"{path}: missing ReadWritePaths")
        return
    for item in FORBIDDEN_WRITE_PATHS:
        if item in read_write:
            reporter.fail(f"{path}: ReadWritePaths includes forbidden {item}")
    reporter.ok(f"{path}: ReadWritePaths checked")


def check_sudoers(path: Path, reporter: Reporter) -> None:
    try:
        text = _read(path)
    except CheckError as exc:
        reporter.fail(str(exc))
        return

    forbidden = ("NOPASSWD: ALL", "ALL=(ALL) ALL", "ALL=(ALL:ALL) ALL")
    for item in forbidden:
        if item in text:
            reporter.fail(f"{path}: contains forbidden {item}")
        else:
            reporter.ok(f"{path}: does not contain {item}")
    for helper in HELPERS:
        if str(helper) in text:
            reporter.ok(f"{path}: grants {helper}")
        else:
            reporter.fail(f"{path}: missing {helper}")

    if os.name == "posix" and path.exists():
        st = path.stat()
        if st.st_uid == 0 and st.st_gid == 0 and _mode(path) == 0o440:
            reporter.ok(f"{path}: root:root 0440")
        else:
            reporter.fail(f"{path}: expected root:root 0440")


def check_helpers(reporter: Reporter) -> None:
    for helper in HELPERS:
        if not helper.exists():
            reporter.fail(f"{helper}: missing")
            continue
        if os.name != "posix":
            reporter.warn(f"{helper}: ownership/mode check skipped on non-POSIX host")
            continue
        st = helper.stat()
        if st.st_uid == 0 and st.st_gid == 0 and _mode(helper) == 0o755:
            reporter.ok(f"{helper}: root:root 0755")
        else:
            reporter.fail(f"{helper}: expected root:root 0755")


def check_runtime_ownership(repo_path: Path, reporter: Reporter) -> None:
    ids = _uid_gid_for_user("vpn-bot")
    if ids is None:
        reporter.warn("vpn-bot user not found; skipped code writability checks")
        return
    uid, gid = ids
    for relative in (".", ".venv", "deploy"):
        path = repo_path / relative
        if not path.exists():
            reporter.warn(f"{path}: missing; skipped writability check")
            continue
        if _would_be_writable(path, uid, gid):
            reporter.fail(f"{path}: writable by vpn-bot")
        else:
            reporter.ok(f"{path}: not writable by vpn-bot")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate production non-root sudo-helper deployment")
    parser.add_argument("--unit", help="systemd unit path; defaults to installed unit or deploy/vpn-bot.service")
    parser.add_argument("--sudoers", default="/etc/sudoers.d/vpnbot", help="installed sudoers file")
    parser.add_argument("--repo", default="/opt/vpn-service", help="production checkout path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = Path(__file__).resolve().parents[1]
    reporter = Reporter()

    check_unit(_resolve_unit_path(args.unit, repo_root), reporter)
    check_sudoers(Path(args.sudoers), reporter)
    check_helpers(reporter)
    if os.name == "posix":
        check_runtime_ownership(Path(args.repo), reporter)
    else:
        reporter.warn("runtime ownership checks skipped on non-POSIX host")

    if reporter.failures:
        print(f"\n{len(reporter.failures)} failure(s), {len(reporter.warnings)} warning(s)")
        return 1
    print(f"\nAll non-root helper-mode checks passed ({len(reporter.warnings)} warning(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
