from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def _read_write_paths(unit_text: str) -> set[str]:
    paths: set[str] = set()
    for line in unit_text.splitlines():
        if line.startswith("ReadWritePaths="):
            paths.update(line.removeprefix("ReadWritePaths=").split())
    return paths


def test_active_service_still_root_until_helpers_are_wired() -> None:
    service_path = ROOT / "deploy" / "vpn-bot.service"
    assert service_path.exists()

    text = _read("deploy/vpn-bot.service")
    assert "User=root" in text
    assert "Group=root" in text
    assert "ReadWritePaths=" in text


def test_future_nonroot_service_uses_unprivileged_user_and_hardening() -> None:
    text = _read("deploy/vpn-bot.nonroot.example.service")

    assert "User=vpn-bot" in text
    assert "Group=vpn-bot" in text
    assert "User=root" not in text
    assert "Group=root" not in text
    assert "NoNewPrivileges=true" not in text
    assert "sudo-based helpers require privilege elevation" in text.lower()
    assert "PrivateTmp=true" in text
    assert "ProtectHome=true" in text
    assert "ProtectSystem=strict" in text
    assert "RuntimeDirectory=vpn-bot" in text
    assert "UMask=0077" in text


def test_future_nonroot_service_readwrite_paths_exclude_account_databases() -> None:
    text = _read("deploy/vpn-bot.nonroot.example.service")
    read_write_paths = _read_write_paths(text)

    forbidden_paths = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/.pwd.lock",
    }
    for path in forbidden_paths:
        assert path not in read_write_paths


def test_future_nonroot_service_readwrite_paths_cover_helper_backends_narrowly() -> None:
    text = _read("deploy/vpn-bot.nonroot.example.service")
    read_write_paths = _read_write_paths(text)

    required_paths = {
        "/opt/vpn-service/data",
        "/opt/vpn-service/logs",
        "/run/vpn-bot",
        "/usr/local/etc/xray",
        "/etc/amnezia/amneziawg",
        "/etc/mtproxy/vpnbot",
    }
    assert required_paths <= read_write_paths
    assert "/etc" not in read_write_paths
    assert "/usr/local/etc" not in read_write_paths
    assert "/etc/amnezia" not in read_write_paths
    assert "/etc/mtproxy" not in read_write_paths


def test_sudoers_example_grants_only_fixed_helpers() -> None:
    text = _read("deploy/sudoers.d/vpnbot.example")

    assert "NOPASSWD: ALL" not in text
    assert "ALL=(ALL)" not in text
    for forbidden in ("systemctl", "useradd", "chpasswd", "userdel", "passwd -l"):
        assert forbidden not in text
    assert "/usr/local/sbin/vpnbot-socks5-user" in text
    assert "/usr/local/sbin/vpnbot-xray-apply" in text
    assert "/usr/local/sbin/vpnbot-awg-apply" in text
    assert "/usr/local/sbin/vpnbot-mtproxy-apply" in text
    assert re.search(r"vpn-bot\s+ALL=\(root\)\s+NOPASSWD:", text)


def test_create_user_script_is_non_destructive_scaffold() -> None:
    text = _read("deploy/create-vpn-bot-user.sh")

    assert "set -euo pipefail" in text
    assert "vpn-bot.service" in text
    assert "groupadd --system" in text
    assert "useradd" in text
    assert "chown -R /opt/vpn-service" not in text
    assert "systemctl" not in text


def test_package5c_setup_and_preflight_assets_cover_cutover_controls() -> None:
    setup = _read("deploy/setup-nonroot-helper-mode.sh")
    preflight = _read("deploy/check-nonroot-helper-mode.py")

    assert "install -o root -g root -m 0750" in setup
    assert "visudo -cf" in setup
    assert "PRIVILEGE_HELPERS_ENABLED=true" in setup
    assert "did not restart vpn-bot or switch the active systemd unit" in setup
    assert "run_helper_as_vpn_bot" in preflight
    assert '"sudo", "-n"' in preflight
    assert '"validate"' in preflight
    assert '"status"' in preflight
    assert "MTPROTO_MANAGED_SECRETS_PATH" in preflight


def test_privilege_plan_mentions_required_components() -> None:
    text = _read("docs/security/privilege-separation-plan.md").lower()

    for term in (
        "xray",
        "awg",
        "socks5",
        "mtproto",
        "sqlite",
        ".env",
        "systemd",
        "nonewprivileges=true",
        "privilege elevation",
        "visudo -cf",
    ):
        assert term in text


def test_helper_contracts_require_socks5_prefix_password_stdin_and_secret_redaction() -> None:
    text = (
        _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    ).lower()

    assert "configured login prefix" in text
    assert "password read from stdin" in text or "password remains stdin-only" in text
    assert "never print passwords" in text
    assert "never prints raw mtproto secrets" in text or "never print raw mtproto secrets" in text
    assert "redact" in text
