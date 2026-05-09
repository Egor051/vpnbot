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


def test_recommended_service_uses_unprivileged_user_and_hardening() -> None:
    text = _read("deploy/vpn-bot.service")

    assert "Description=VPN Telegram Bot" in text
    assert "User=vpn-bot" in text
    assert "Group=vpn-bot" in text
    assert "User=root" not in text
    assert "Group=root" not in text
    assert "Environment=BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock" in text
    assert "NoNewPrivileges=true" not in text
    assert "PrivateTmp=true" in text
    assert "ProtectHome=true" in text
    assert "ProtectSystem=strict" in text
    assert "RuntimeDirectory=vpn-bot" in text
    assert "RuntimeDirectoryMode=0700" in text
    assert "UMask=0077" in text


def test_recommended_service_has_no_misleading_cutover_wording() -> None:
    text = _read("deploy/vpn-bot.service").lower()

    for forbidden in (
        "future non-root",
        "cutover example",
        "do not install as the active",
        "active production unit remains root",
    ):
        assert forbidden not in text


def test_compat_nonroot_template_has_no_misleading_cutover_wording() -> None:
    text = _read("deploy/vpn-bot.nonroot.example.service").lower()

    for forbidden in (
        "future non-root",
        "cutover example",
        "do not install as the active",
        "active production unit remains root",
    ):
        assert forbidden not in text


def test_legacy_root_unit_is_fallback_only() -> None:
    text = _read("deploy/vpn-bot.root-legacy.example.service")

    assert "legacy root/direct fallback" in text
    assert "User=root" in text
    assert "Group=root" in text


def test_recommended_service_readwrite_paths_include_socks5_account_databases() -> None:
    text = _read("deploy/vpn-bot.service")
    read_write_paths = _read_write_paths(text)

    required_paths = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/.pwd.lock",
    }
    assert required_paths <= read_write_paths
    assert "SOCKS5 helper" in text
    assert "mount namespace" in text


def test_recommended_service_readwrite_paths_cover_helper_backends_narrowly() -> None:
    text = _read("deploy/vpn-bot.service")
    read_write_paths = _read_write_paths(text)

    required_paths = {
        "/opt/vpn-service/data",
        "/opt/vpn-service/logs",
        "/run/vpn-bot",
        "/usr/local/etc/xray",
        "/etc/amnezia/amneziawg",
        "/etc/mtproxy/vpnbot",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/.pwd.lock",
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

    assert "install -o root -g root -m 0755" in setup
    assert "visudo -cf" in setup
    assert "PRIVILEGE_HELPERS_ENABLED=true" in setup
    assert "did not restart vpn-bot or replace the active systemd unit" in setup
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
        "post-reboot backup",
    ):
        assert term in text


def test_docs_record_production_helper_install_and_runtime_permissions() -> None:
    text = (
        _read("README.md")
        + "\n"
        + _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    ).lower()

    for term in (
        "root:root` mode `0755`",
        "root:vpn-bot` mode `0640`",
        "/etc/sudoers.d/vpnbot` is `root:root` mode `0440`",
        "runtimedirectorymode=0700",
        "bot_lock_path=/run/vpn-bot/vpn-bot.lock",
        "reboot verification passed",
        "post-reboot backup",
    ):
        assert term in text


def test_env_example_uses_recommended_nonroot_helper_defaults() -> None:
    text = _read(".env.example")

    assert "BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock" in text
    assert "PRIVILEGE_HELPERS_ENABLED=true" in text
    assert "HELPER_STAGING_ROOT=/run/vpn-bot" in text


def test_docs_and_sudoers_do_not_advise_broad_sudo_access() -> None:
    text = (
        _read("deploy/sudoers.d/vpnbot.example")
        + "\n"
        + _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    )

    assert "NOPASSWD: ALL" not in text
    assert "ALL=(ALL)" not in text
    for forbidden in (
        "NOPASSWD: /bin/systemctl",
        "NOPASSWD: /usr/bin/systemctl",
        "NOPASSWD: /usr/sbin/useradd",
        "NOPASSWD: /usr/sbin/chpasswd",
        "NOPASSWD: /usr/bin/passwd",
        "NOPASSWD: /usr/sbin/passwd",
    ):
        assert forbidden not in text


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
