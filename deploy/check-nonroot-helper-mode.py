#!/usr/bin/env python3

import argparse
import json as _json_mod
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path


HELPERS = (
    Path("/usr/local/sbin/vpn-bot-socks5-user"),
    Path("/usr/local/sbin/vpn-bot-xray-apply"),
    Path("/usr/local/sbin/vpn-bot-awg-apply"),
    Path("/usr/local/sbin/vpn-bot-mtproxy-apply"),
)
# Optional WARP routing helpers (only used when the WARP module is enabled).
WARP_HELPERS = (
    Path("/usr/local/sbin/vpn-bot-warp-install"),
    Path("/usr/local/sbin/vpn-bot-warp-iface"),
    Path("/usr/local/sbin/vpn-bot-warp-routes"),
    Path("/usr/local/sbin/vpn-bot-warp-status"),
    # Split-list management helper (reads new list from stdin, writes atomically,
    # restarts vpn-bot-warp-split). Required when bot-controlled split is in use.
    Path("/usr/local/sbin/vpn-bot-warp-split-apply"),
    # Split-routing on/off/restart/status helper (manages table T + the disabled
    # marker). Required when the bot-controlled split toggle is in use.
    Path("/usr/local/sbin/vpn-bot-warp-split-state"),
)
FORBIDDEN_WRITE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/.pwd.lock",
    "/etc/systemd/system",
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CheckError(f"{path}: cannot read: {exc}") from exc


def _active_text(text: str) -> str:
    """Return only non-blank, non-comment lines.

    Substring checks must not match a directive that is merely mentioned in a
    comment (e.g. a helper path documented in the sudoers header, or a sample
    ``User=root`` line), which would otherwise yield a false OK/FAIL.
    """
    return "\n".join(
        line
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("#", ";"))
    )


class CheckError(Exception):
    pass


class Reporter:
    def __init__(self, json_mode: bool = False) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self._json_mode = json_mode
        self._checks: list[dict] = []

    def ok(self, message: str) -> None:
        self._checks.append({"status": "ok", "message": message})
        if not self._json_mode:
            print(f"OK: {message}")

    def fail(self, message: str) -> None:
        self.failures.append(message)
        self._checks.append({"status": "failed", "message": message})
        if not self._json_mode:
            print(f"FAIL: {message}")

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        self._checks.append({"status": "warning", "message": message})
        if not self._json_mode:
            print(f"WARN: {message}")

    def to_json(self) -> str:
        overall = "failed" if self.failures else ("warning" if self.warnings else "ok")
        return _json_mod.dumps(
            {
                "overall": overall,
                "failures": len(self.failures),
                "warnings": len(self.warnings),
                "checks": self._checks,
            },
            indent=2,
        )


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
    # This tool validates the NON-ROOT helper-mode deployment. The shipped
    # deploy/vpn-bot.service runs in root+api mode and intentionally would not pass
    # these checks, so fall back to the non-root reference unit when no installed
    # unit is present (e.g. running from a repo checkout).
    return repo_root / "deploy" / "vpn-bot.nonroot.example.service"


def check_unit(path: Path, reporter: Reporter) -> None:
    try:
        text = _read(path)
    except CheckError as exc:
        reporter.fail(str(exc))
        return

    # Ignore comments so a directive mentioned only in a comment never satisfies a
    # required check nor trips a forbidden one.
    active = _active_text(text)

    required = (
        "User=vpn-bot",
        "Group=vpn-bot",
        "Environment=BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock",
        "RuntimeDirectory=vpn-bot",
        "RuntimeDirectoryMode=0700",
        "ProtectSystem=strict",
    )
    for item in required:
        if item in active:
            reporter.ok(f"{path}: contains {item}")
        else:
            reporter.fail(f"{path}: missing {item}")

    # "future example" is a sentinel: it guards against installing a placeholder /
    # example unit that still carries that marker line as its active (non-comment)
    # content. The other three reject the root+api directives in a non-root unit.
    forbidden = ("User=root", "Group=root", "NoNewPrivileges=true", "future example")
    for item in forbidden:
        if item in active:
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

    # Ignore comments so the helper paths documented in the sudoers header cannot
    # satisfy the grant checks — only real Cmnd_Alias/grant lines count.
    active = _active_text(text)

    forbidden = ("NOPASSWD: ALL", "ALL=(ALL) ALL", "ALL=(ALL:ALL) ALL")
    for item in forbidden:
        if item in active:
            reporter.fail(f"{path}: contains forbidden {item}")
        else:
            reporter.ok(f"{path}: does not contain {item}")
    for helper in HELPERS:
        if str(helper) in active:
            reporter.ok(f"{path}: grants {helper}")
        else:
            reporter.fail(f"{path}: missing {helper}")
    # WARP helpers are optional (only when the WARP module is enabled); a partial
    # set is suspicious, so warn rather than fail when some-but-not-all are present.
    warp_present = [h for h in WARP_HELPERS if str(h) in active]
    if warp_present and len(warp_present) != len(WARP_HELPERS):
        missing = [str(h) for h in WARP_HELPERS if str(h) not in active]
        reporter.warn(f"{path}: partial WARP helper grants; missing {', '.join(missing)}")

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


def check_run_dir(reporter: Reporter, mode: str) -> None:
    run_dir = Path("/run/vpn-bot")
    if not run_dir.exists():
        if mode == "post-start":
            reporter.fail(f"{run_dir}: missing — expected after 'systemctl start vpn-bot'")
        else:
            reporter.warn(
                f"{run_dir}: does not exist (expected before service start; "
                "systemd creates RuntimeDirectory on service start)"
            )
        return
    ids = _uid_gid_for_user("vpn-bot")
    if ids is None:
        reporter.warn(f"{run_dir}: vpn-bot user not found; skipped writability check")
        return
    uid, gid = ids
    if _would_be_writable(run_dir, uid, gid):
        reporter.ok(f"{run_dir}: writable by vpn-bot")
    else:
        reporter.fail(f"{run_dir}: exists but not writable by vpn-bot")


def check_env_file(repo_path: Path, reporter: Reporter) -> None:
    env_path = repo_path / ".env"
    if not env_path.exists():
        reporter.warn(f"{env_path}: not found; skipped")
        return
    if os.name != "posix":
        reporter.warn(f"{env_path}: permission check skipped on non-POSIX")
        return
    st = env_path.stat()
    file_mode = stat.S_IMODE(st.st_mode)
    if file_mode & stat.S_IROTH:
        reporter.fail(f"{env_path}: world-readable (mode={oct(file_mode)}) — must not be world-readable")
    else:
        reporter.ok(f"{env_path}: not world-readable (mode={oct(file_mode)})")
    ids = _uid_gid_for_user("vpn-bot")
    if ids is None:
        reporter.warn(f"{env_path}: vpn-bot user not found; skipped readability check")
        return
    uid, gid = ids
    can_read = False
    if st.st_uid == uid and (file_mode & stat.S_IRUSR):
        can_read = True
    elif st.st_gid == gid and (file_mode & stat.S_IRGRP):
        can_read = True
    if can_read:
        reporter.ok(f"{env_path}: readable by vpn-bot")
    else:
        reporter.warn(f"{env_path}: may not be readable by vpn-bot — check manually")


def check_sqlite(db_path: Path, reporter: Reporter) -> None:
    if not db_path.exists():
        reporter.warn(f"{db_path}: not found; skipped SQLite quick_check")
        return
    if os.name == "posix":
        ids = _uid_gid_for_user("vpn-bot")
        if ids is not None:
            uid, gid = ids
            for suffix in ("", "-wal", "-shm"):
                p = db_path.parent / (db_path.name + suffix)
                if p.exists() and not _would_be_writable(p, uid, gid):
                    reporter.fail(
                        f"{p}: not writable by vpn-bot — run setup-nonroot-helper-mode.sh to fix ownership"
                    )
                elif p.exists():
                    reporter.ok(f"{p}: writable by vpn-bot")
    try:
        with sqlite3.connect(str(db_path), timeout=5) as conn:
            row = conn.execute("PRAGMA quick_check").fetchone()
            result = str(row[0]) if row else "no result"
        if result == "ok":
            reporter.ok(f"{db_path}: PRAGMA quick_check OK")
        else:
            reporter.fail(f"{db_path}: PRAGMA quick_check: {result[:80]}")
    except Exception as exc:
        reporter.fail(f"{db_path}: PRAGMA quick_check failed: {type(exc).__name__}: {str(exc)[:80]}")


def check_xray_config(config_path: Path, reporter: Reporter) -> None:
    if not config_path.exists():
        reporter.warn(f"{config_path}: not found; skipped xray config test")
        return
    try:
        result = subprocess.run(
            ["xray", "run", "-test", "-config", str(config_path)],
            capture_output=True,
            timeout=15,
        )
        if result.returncode == 0:
            reporter.ok(f"{config_path}: xray config test OK")
        else:
            reporter.fail(f"{config_path}: xray config test failed (rc={result.returncode})")
    except FileNotFoundError:
        reporter.warn(f"{config_path}: xray binary not found; skipped config test")
    except subprocess.TimeoutExpired:
        reporter.warn(f"{config_path}: xray config test timed out")
    except OSError as exc:
        reporter.warn(f"{config_path}: xray config test error: {type(exc).__name__}")


def check_awg_config(config_path: Path, reporter: Reporter) -> None:
    if not config_path.exists():
        reporter.warn(f"{config_path}: not found; skipped AWG config strip")
        return
    for binary in ("awg-quick", "wg-quick"):
        try:
            result = subprocess.run(
                [binary, "strip", str(config_path)],
                capture_output=True,
                timeout=15,
            )
            if result.returncode == 0:
                reporter.ok(f"{config_path}: {binary} strip OK")
            else:
                reporter.fail(f"{config_path}: {binary} strip failed (rc={result.returncode})")
            return
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            reporter.warn(f"{config_path}: {binary} strip timed out")
            return
        except OSError as exc:
            reporter.warn(f"{config_path}: {binary} strip error: {type(exc).__name__}")
            return
    reporter.warn(f"{config_path}: awg-quick/wg-quick not found; skipped AWG config strip")


def check_mtproxy_managed_files(managed_dir: Path, reporter: Reporter) -> None:
    if not managed_dir.exists():
        reporter.warn(f"{managed_dir}: not found; skipped MTProxy managed files check")
        return
    secrets_file = managed_dir / "managed-secrets.json"
    env_file = managed_dir / "mtproxy.env"
    for path in (secrets_file, env_file):
        if not path.exists():
            reporter.warn(f"{path}: not found")
            continue
        try:
            content = path.read_text(encoding="utf-8")
            if path.suffix == ".json":
                _json_mod.loads(content)
                reporter.ok(f"{path}: readable, valid JSON")
            else:
                reporter.ok(f"{path}: readable")
        except _json_mod.JSONDecodeError:
            reporter.fail(f"{path}: invalid JSON")
        except OSError as exc:
            reporter.fail(f"{path}: cannot read: {type(exc).__name__}")


def check_sudo_helpers(reporter: Reporter) -> None:
    if os.name != "posix":
        reporter.warn("sudo helper checks skipped on non-POSIX")
        return
    for helper in HELPERS:
        try:
            result = subprocess.run(
                ["sudo", "-n", str(helper), "status"],
                capture_output=True,
                timeout=10,
            )
            # rc=0: service active; rc=3: service inactive but helper reachable via sudo
            if result.returncode in (0, 3):
                reporter.ok(f"sudo -n {helper} status: accessible (rc={result.returncode})")
            else:
                reporter.warn(f"sudo -n {helper} status: rc={result.returncode} (check sudoers/helper)")
        except FileNotFoundError:
            reporter.warn("sudo not found; skipped helper accessibility check")
            return
        except subprocess.TimeoutExpired:
            reporter.warn(f"sudo -n {helper} status: timed out")
        except OSError as exc:
            reporter.warn(f"sudo -n {helper} status: {type(exc).__name__}")


def check_active_services(reporter: Reporter) -> None:
    if os.name != "posix":
        reporter.warn("systemctl service checks skipped on non-POSIX")
        return
    services = ("vpn-bot", "xray", "awg-quick@awg0", "danted", "mtproxy")
    for service in services:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", service],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                reporter.ok(f"systemctl: {service} active")
            else:
                reporter.warn(f"systemctl: {service} not active (rc={result.returncode})")
        except FileNotFoundError:
            reporter.warn("systemctl not found; skipped service checks")
            return
        except subprocess.TimeoutExpired:
            reporter.warn(f"systemctl: {service} check timed out")
        except OSError as exc:
            reporter.warn(f"systemctl: {service} check error: {type(exc).__name__}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate production non-root sudo-helper deployment")
    parser.add_argument(
        "--unit",
        help="systemd unit path; defaults to the installed unit or, from a checkout, "
        "deploy/vpn-bot.nonroot.example.service (the shipped deploy/vpn-bot.service is "
        "root+api and intentionally fails these non-root checks)",
    )
    parser.add_argument("--sudoers", default="/etc/sudoers.d/vpn-bot", help="installed sudoers file")
    parser.add_argument("--repo", default="/opt/vpn-service", help="production checkout path")
    parser.add_argument("--db", help="SQLite DB path (default: <repo>/data/vpn.db)")
    parser.add_argument(
        "--mode",
        choices=["pre-start", "post-start"],
        default="pre-start",
        help=(
            "pre-start: /run/vpn-bot absence is expected (service not yet started); "
            "post-start: /run/vpn-bot must exist and be writable by vpn-bot"
        ),
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="machine-readable JSON output (overall/failures/warnings/checks[])",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo_root = Path(__file__).resolve().parents[1]
    reporter = Reporter(json_mode=args.json_output)

    # Unit / sudoers / helper ownership checks
    check_unit(_resolve_unit_path(args.unit, repo_root), reporter)
    check_sudoers(Path(args.sudoers), reporter)
    check_helpers(reporter)
    if os.name == "posix":
        check_runtime_ownership(Path(args.repo), reporter)
    else:
        reporter.warn("runtime ownership checks skipped on non-POSIX host")

    # Runtime state / DB / backend config checks
    check_run_dir(reporter, args.mode)
    check_env_file(Path(args.repo), reporter)
    db_path = Path(args.db) if args.db else Path(args.repo) / "data" / "vpn.db"
    check_sqlite(db_path, reporter)
    check_xray_config(Path("/usr/local/etc/xray/config.json"), reporter)
    check_awg_config(Path("/etc/amnezia/amneziawg/awg0.conf"), reporter)
    check_mtproxy_managed_files(Path("/etc/mtproxy/vpn-bot"), reporter)
    check_sudo_helpers(reporter)
    check_active_services(reporter)

    if args.json_output:
        print(reporter.to_json())
    elif reporter.failures:
        print(f"\n{len(reporter.failures)} failure(s), {len(reporter.warnings)} warning(s)")
    else:
        print(f"\nAll non-root helper-mode checks passed ({len(reporter.warnings)} warning(s)).")

    return 1 if reporter.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
