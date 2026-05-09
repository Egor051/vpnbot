#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


APP_USER = "vpn-bot"
APP_GROUP = "vpn-bot"
ENV_PATH = Path("/opt/vpn-service/.env")
SUDOERS_EXAMPLE = Path(__file__).resolve().parent / "sudoers.d" / "vpnbot.example"
SUDOERS_INSTALLED = Path("/etc/sudoers.d/vpnbot")
HELPERS = {
    "socks5": Path("/usr/local/sbin/vpnbot-socks5-user"),
    "xray": Path("/usr/local/sbin/vpnbot-xray-apply"),
    "awg": Path("/usr/local/sbin/vpnbot-awg-apply"),
    "mtproxy": Path("/usr/local/sbin/vpnbot-mtproxy-apply"),
}
DEFAULT_PATHS = {
    "DB_PATH": "/opt/vpn-service/data/vpn.db",
    "LOG_DIR": "/opt/vpn-service/logs",
    "HELPER_STAGING_ROOT": "/run/vpn-bot",
    "XRAY_CONFIG_PATH": "/usr/local/etc/xray/config.json",
    "AWG_CONFIG_PATH": "/etc/amnezia/amneziawg/awg0.conf",
    "MTPROTO_MANAGED_SECRETS_PATH": "/etc/mtproxy/vpnbot/managed-secrets.json",
    "MTPROTO_MANAGED_ENV_PATH": "/etc/mtproxy/vpnbot/mtproxy.env",
}
SAFE_ENV_KEYS = set(DEFAULT_PATHS) | {
    "PRIVILEGE_HELPERS_ENABLED",
    "XRAY_HELPER_STAGING_DIR",
    "AWG_HELPER_STAGING_DIR",
    "MTPROTO_HELPER_STAGING_DIR",
}


@dataclass(slots=True)
class CheckSummary:
    failures: int = 0
    warnings: int = 0

    def ok(self, message: str) -> None:
        print(f"[OK] {message}")

    def warn(self, message: str) -> None:
        self.warnings += 1
        print(f"[WARN] {message}")

    def fail(self, message: str) -> None:
        self.failures += 1
        print(f"[FAIL] {message}")


def run(args: list[str], *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except FileNotFoundError:
        return subprocess.CompletedProcess(args, 127, "", "command not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, "", "timeout")


def current_user() -> str:
    result = run(["id", "-un"])
    if result.returncode == 0:
        return result.stdout.strip()
    return ""


def run_as_vpn_bot(args: list[str], *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    if current_user() == APP_USER:
        return run(args, timeout=timeout)
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid) and geteuid() == 0 and shutil.which("runuser"):
        return run(["runuser", "-u", APP_USER, "--", *args], timeout=timeout)
    return run(["sudo", "-n", "-u", APP_USER, *args], timeout=timeout)


def run_helper_as_vpn_bot(helper: Path, args: list[str], *, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return run_as_vpn_bot(["sudo", "-n", str(helper), *args], timeout=timeout)


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return values
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in SAFE_ENV_KEYS:
            values[key] = value.strip().strip("'\"")
    return values


def path_from_env(env: dict[str, str], key: str) -> Path:
    return Path(env.get(key) or DEFAULT_PATHS[key])


def check_user(summary: CheckSummary) -> None:
    user = run(["id", "-u", APP_USER])
    group = run(["getent", "group", APP_GROUP])
    if user.returncode == 0 and group.returncode == 0:
        summary.ok(f"{APP_USER} user and group exist")
    else:
        summary.fail(f"{APP_USER} user/group missing")


def check_helper_files(summary: CheckSummary) -> None:
    for name, path in HELPERS.items():
        try:
            st = path.stat()
        except FileNotFoundError:
            summary.fail(f"{name} helper missing at {path}")
            continue
        mode = st.st_mode & 0o777
        if st.st_uid != 0 or st.st_gid != 0:
            summary.fail(f"{name} helper must be root:root: {path}")
            continue
        if mode & 0o022:
            summary.fail(f"{name} helper must not be group/other writable: {path} mode {mode:o}")
            continue
        if mode & 0o100 == 0:
            summary.fail(f"{name} helper must be executable by root: {path} mode {mode:o}")
            continue
        summary.ok(f"{name} helper ownership/mode look constrained: {path} mode {mode:o}")


def check_sudoers(summary: CheckSummary) -> None:
    visudo = shutil.which("visudo")
    if not visudo:
        summary.warn("visudo not found; sudoers syntax was not validated")
        return
    for path in (SUDOERS_EXAMPLE, SUDOERS_INSTALLED):
        if not path.exists():
            if path == SUDOERS_INSTALLED:
                summary.warn(f"installed sudoers file not found yet: {path}")
            else:
                summary.fail(f"sudoers example missing: {path}")
            continue
        result = run([visudo, "-cf", str(path)])
        if result.returncode == 0:
            summary.ok(f"sudoers syntax valid: {path}")
        else:
            summary.fail(f"sudoers syntax invalid: {path}")


def check_path_access(summary: CheckSummary, path: Path, flag: str, label: str) -> None:
    result = run_as_vpn_bot(["test", flag, str(path)])
    if result.returncode == 0:
        summary.ok(f"{label}: vpn-bot access ok ({flag})")
    else:
        summary.fail(f"{label}: vpn-bot access failed ({flag})")


def ensure_staging_file(source: Path, staging_dir: Path, name: str) -> Path | None:
    try:
        staging_dir.mkdir(parents=True, exist_ok=True)
        target = staging_dir / name
        target.write_bytes(source.read_bytes())
        os.chmod(target, 0o600)
        try:
            shutil.chown(staging_dir, user=APP_USER, group=APP_GROUP)
            shutil.chown(target, user=APP_USER, group=APP_GROUP)
        except LookupError:
            return None
        return target
    except OSError:
        return None


def check_helper_actions(summary: CheckSummary, env: dict[str, str]) -> None:
    socks = run_helper_as_vpn_bot(HELPERS["socks5"], ["exists", "vpn_socks_preflight"])
    if socks.returncode in {0, 2}:
        summary.ok("SOCKS5 helper safe exists check works through sudo -n")
    else:
        summary.fail("SOCKS5 helper safe exists check failed through sudo -n")

    xray_config = path_from_env(env, "XRAY_CONFIG_PATH")
    xray_staging = Path(env.get("XRAY_HELPER_STAGING_DIR") or "/run/vpn-bot/xray")
    xray_candidate = ensure_staging_file(xray_config, xray_staging, "preflight-config.json")
    if xray_candidate is None:
        summary.fail("Xray candidate staging failed")
    else:
        try:
            xray = run_helper_as_vpn_bot(HELPERS["xray"], ["validate", str(xray_candidate)], timeout=60)
            if xray.returncode == 0:
                summary.ok("Xray helper validate works through sudo -n")
            else:
                summary.fail("Xray helper validate failed through sudo -n")
        finally:
            xray_candidate.unlink(missing_ok=True)
    xray_status = run_helper_as_vpn_bot(HELPERS["xray"], ["status"])
    if xray_status.returncode == 0:
        summary.ok("Xray helper status works through sudo -n")
    else:
        summary.fail("Xray helper status failed through sudo -n")

    awg_config = path_from_env(env, "AWG_CONFIG_PATH")
    awg_staging = Path(env.get("AWG_HELPER_STAGING_DIR") or "/run/vpn-bot/awg")
    awg_candidate = ensure_staging_file(awg_config, awg_staging, "preflight-awg0.conf")
    if awg_candidate is None:
        summary.fail("AWG candidate staging failed")
    else:
        try:
            awg = run_helper_as_vpn_bot(HELPERS["awg"], ["validate", str(awg_candidate)], timeout=60)
            if awg.returncode == 0:
                summary.ok("AWG helper validate works through sudo -n")
            else:
                summary.fail("AWG helper validate failed through sudo -n")
        finally:
            awg_candidate.unlink(missing_ok=True)
    awg_status = run_helper_as_vpn_bot(HELPERS["awg"], ["status"])
    if awg_status.returncode == 0:
        summary.ok("AWG helper status works through sudo -n")
    else:
        summary.fail("AWG helper status failed through sudo -n")

    mtproxy_status = run_helper_as_vpn_bot(HELPERS["mtproxy"], ["status"])
    if mtproxy_status.returncode == 0:
        summary.ok("MTProxy helper status works through sudo -n")
    else:
        summary.fail("MTProxy helper status failed through sudo -n")


def main() -> int:
    summary = CheckSummary()
    env = parse_env_file(ENV_PATH)

    check_user(summary)
    check_helper_files(summary)
    check_sudoers(summary)

    check_path_access(summary, ENV_PATH, "-r", "/opt/vpn-service/.env")
    staging_root = path_from_env(env, "HELPER_STAGING_ROOT")
    check_path_access(summary, staging_root, "-w", str(staging_root))
    check_path_access(summary, path_from_env(env, "DB_PATH").parent, "-w", "SQLite data directory")
    check_path_access(summary, path_from_env(env, "LOG_DIR"), "-w", "log directory")
    check_path_access(summary, path_from_env(env, "XRAY_CONFIG_PATH"), "-r", "Xray canonical config")
    check_path_access(summary, path_from_env(env, "AWG_CONFIG_PATH"), "-r", "AWG canonical config")
    check_path_access(summary, path_from_env(env, "MTPROTO_MANAGED_SECRETS_PATH"), "-r", "MTProxy managed secrets")
    check_path_access(summary, path_from_env(env, "MTPROTO_MANAGED_ENV_PATH"), "-r", "MTProxy managed env")
    check_helper_actions(summary, env)

    if env.get("PRIVILEGE_HELPERS_ENABLED") != "true":
        summary.warn("PRIVILEGE_HELPERS_ENABLED is not true in parsed environment")

    print(f"preflight completed: failures={summary.failures} warnings={summary.warnings}")
    return 1 if summary.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
