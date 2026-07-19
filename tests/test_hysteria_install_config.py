"""Behavioural + structural coverage for deploy/hysteria/install-config.sh.

The tracked deploy/hysteria/config.yaml carries a placeholder
`secret: "<random-secret>"` in its trafficStats block. A bare
`cp deploy/hysteria/config.yaml /etc/hysteria/config.yaml` overwrites the live
Traffic Stats secret with that placeholder, so hysteria-server starts
rejecting the bot's stats/online/kick calls with 401 — silently, since the
data plane itself still starts fine. install-config.sh is the only supported
way to (re)install the file: it copies the repo config AND injects
HYSTERIA2_STATS_SECRET from .env, so the placeholder never reaches disk.

These tests drive the REAL shipped script via subprocess, using the
INSTALL_CONFIG_REQUIRE_ROOT=0 / INSTALL_CONFIG_OWNER / INSTALL_CONFIG_GROUP
test seam documented in the script itself, so the full
transform -> backup -> install path runs without root or the `hysteria`
system user — the same reason tests/test_hy2_warp_mark_helper.py drives
scripts/vpnbot-hy2-warp-mark under a stubbed PATH instead of the real network
tools.
"""

import grp
import json
import os
import pwd
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = ROOT / "deploy" / "hysteria" / "install-config.sh"
REPO_CONFIG = ROOT / "deploy" / "hysteria" / "config.yaml"

_CURRENT_USER = pwd.getpwuid(os.getuid()).pw_name
_CURRENT_GROUP = grp.getgrgid(os.getgid()).gr_name


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _run_install(
    tmp_path: Path,
    env_content: str,
    target_initial: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real install-config.sh against a temp .env/target, unprivileged."""
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")
    target = tmp_path / "config.yaml"
    if target_initial is not None:
        target.write_text(target_initial, encoding="utf-8")

    env = dict(os.environ)
    env["INSTALL_CONFIG_REQUIRE_ROOT"] = "0"
    env["INSTALL_CONFIG_OWNER"] = _CURRENT_USER
    env["INSTALL_CONFIG_GROUP"] = _CURRENT_GROUP

    return subprocess.run(
        ["bash", str(INSTALL_SCRIPT), "--env", str(env_file), "--target", str(target)],
        env=env,
        capture_output=True,
        text=True,
    )


def _secret_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if re.match(r"^[ \t]+secret:", line)]


# --------------------------------------------------------------------------- #
# structural
# --------------------------------------------------------------------------- #
def test_install_config_script_exists_and_is_executable() -> None:
    assert INSTALL_SCRIPT.exists()
    assert os.access(INSTALL_SCRIPT, os.X_OK), "install-config.sh must be executable (git mode 0755)"


def test_repo_config_still_has_placeholder_for_install_config_to_fill() -> None:
    # If the placeholder ever disappears from the tracked file, install-config.sh
    # has nothing left to inject and its reason to exist evaporates.
    text = _read(REPO_CONFIG)
    assert "<random-secret>" in text
    assert len(_secret_lines(text)) == 1


def test_install_config_selftest_passes() -> None:
    proc = subprocess.run(
        ["bash", str(INSTALL_SCRIPT), "--selftest"], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert "all checks passed" in proc.stderr


# --------------------------------------------------------------------------- #
# behavioural: real install against a temp .env / temp target
# --------------------------------------------------------------------------- #
def test_install_config_injects_secret_and_removes_placeholder(tmp_path: Path) -> None:
    secret = "known-test-secret-abc123"
    proc = _run_install(tmp_path, f"HYSTERIA2_STATS_SECRET={secret}\n")
    assert proc.returncode == 0, proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert "<random-secret>" not in installed

    lines = _secret_lines(installed)
    assert len(lines) == 1, f"expected exactly one secret: line, got {lines!r}"
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == secret


def test_install_config_backs_up_existing_target_before_overwrite(tmp_path: Path) -> None:
    proc = _run_install(
        tmp_path,
        "HYSTERIA2_STATS_SECRET=fresh-secret\n",
        target_initial="stale placeholder content\n",
    )
    assert proc.returncode == 0, proc.stderr

    backups = list(tmp_path.glob("config.yaml.bak.*"))
    assert len(backups) == 1, f"expected exactly one backup file, got {backups!r}"
    assert backups[0].read_text(encoding="utf-8") == "stale placeholder content\n"


def test_install_config_never_invokes_systemctl(tmp_path: Path) -> None:
    # install-config.sh must never restart hysteria-server itself — the
    # operator runs preflight-udp443.sh and restarts by hand. Stub systemctl on
    # PATH so an accidental restart call would be caught, not silently succeed.
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    systemctl_log = tmp_path / "systemctl.log"
    stub = stub_dir / "systemctl"
    stub.write_text(f'#!/bin/bash\necho "$*" >> "{systemctl_log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)

    env_file = tmp_path / ".env"
    env_file.write_text("HYSTERIA2_STATS_SECRET=some-secret\n", encoding="utf-8")
    target = tmp_path / "config.yaml"

    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}:{env['PATH']}"
    env["INSTALL_CONFIG_REQUIRE_ROOT"] = "0"
    env["INSTALL_CONFIG_OWNER"] = _CURRENT_USER
    env["INSTALL_CONFIG_GROUP"] = _CURRENT_GROUP

    proc = subprocess.run(
        ["bash", str(INSTALL_SCRIPT), "--env", str(env_file), "--target", str(target)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert not systemctl_log.exists(), "install-config.sh must never invoke systemctl itself"
    # It must still tell the operator to do so by hand.
    assert "systemctl restart hysteria-server" in proc.stderr


# --------------------------------------------------------------------------- #
# fail-closed
# --------------------------------------------------------------------------- #
def test_install_config_fails_closed_without_secret_in_env(tmp_path: Path) -> None:
    proc = _run_install(tmp_path, "SOME_OTHER_VAR=1\n")
    assert proc.returncode != 0
    assert "HYSTERIA2_STATS_SECRET" in proc.stderr
    assert not (tmp_path / "config.yaml").exists()


def test_install_config_warns_but_proceeds_on_empty_secret(tmp_path: Path) -> None:
    proc = _run_install(tmp_path, "HYSTERIA2_STATS_SECRET=\n")
    assert proc.returncode == 0, proc.stderr
    assert "WARNING" in proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    lines = _secret_lines(installed)
    assert len(lines) == 1
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == ""


def test_install_config_last_assignment_wins(tmp_path: Path) -> None:
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=first\nHYSTERIA2_STATS_SECRET=second\n"
    )
    assert proc.returncode == 0, proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    lines = _secret_lines(installed)
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == "second"


# --------------------------------------------------------------------------- #
# quoting: special characters must round-trip through json.dumps() exactly
# --------------------------------------------------------------------------- #
def test_install_config_injects_secret_with_quotes_backslash_and_hash(tmp_path: Path) -> None:
    # Unquoted values are taken verbatim to end of line (see install-config.sh's
    # dequote()) specifically so a secret containing '#' is not silently
    # truncated as an inline comment. This also covers embedded double/single
    # quotes and a literal backslash — all of which must survive intact and be
    # re-quoted correctly by json.dumps() in the installed YAML.
    secret = "ab\"cd\\ef#gh'ij"
    proc = _run_install(tmp_path, f"HYSTERIA2_STATS_SECRET={secret}\n")
    assert proc.returncode == 0, proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert "<random-secret>" not in installed

    lines = _secret_lines(installed)
    assert len(lines) == 1
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == secret
