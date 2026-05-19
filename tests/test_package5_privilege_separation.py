
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_production_service_uses_root_api_mode() -> None:
    service_path = ROOT / "deploy" / "vpn-bot.service"
    assert service_path.exists()

    text = _read("deploy/vpn-bot.service")
    assert "User=root" in text
    assert "Group=root" in text
    assert "User=vpn-bot" not in text
    assert "Group=vpn-bot" not in text
    assert "future example" not in text.lower()
    assert "NoNewPrivileges=true" not in text
    assert "Environment=BOT_LOCK_PATH=/run/vpn-bot/vpn-bot.lock" in text
    assert "RuntimeDirectory=vpn-bot" in text
    assert "RuntimeDirectoryMode=0700" in text
    assert "PrivateTmp=true" in text
    assert "ProtectHome=true" in text
    assert "ProtectSystem=false" in text
    assert "UMask=0077" in text
    # Root mode needs no ReadWritePaths restrictions
    assert "ReadWritePaths=" not in text


def test_nonroot_example_is_compatibility_reference_not_future_cutover() -> None:
    text = _read("deploy/vpn-bot.nonroot.example.service")

    assert "User=vpn-bot" in text
    assert "Group=vpn-bot" in text
    assert "User=root" not in text
    assert "Group=root" not in text
    assert "future" not in text.lower()
    assert "NoNewPrivileges=true" not in text
    assert "PrivateTmp=true" in text
    assert "ProtectHome=true" in text
    assert "ProtectSystem=strict" in text
    assert "RuntimeDirectory=vpn-bot" in text
    assert "UMask=0077" in text


def test_production_service_root_mode_has_no_readwrite_paths() -> None:
    # Root+api mode runs as root with ProtectSystem=false, so no ReadWritePaths
    # restrictions are needed or present.
    text = _read("deploy/vpn-bot.service")
    read_write_lines = [line for line in text.splitlines() if line.startswith("ReadWritePaths=")]
    assert read_write_lines == [], (
        "deploy/vpn-bot.service should have no ReadWritePaths in root+api mode"
    )

    # The nonroot example still carries the narrow list for reference.
    nonroot_text = _read("deploy/vpn-bot.nonroot.example.service")
    nonroot_rw = "\n".join(
        line for line in nonroot_text.splitlines() if line.startswith("ReadWritePaths=")
    )
    forbidden_paths = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/.pwd.lock",
        "/etc/systemd/system",
    }
    for path in forbidden_paths:
        assert path not in nonroot_rw


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


def test_readme_and_security_docs_do_not_recommend_recursive_user_chown() -> None:
    text = (
        _read("README.md")
        + "\n"
        + _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    )

    forbidden = re.compile(
        r"chown -R\s+(?:\"\$USER\":\"\$USER\"|\$USER:\$USER|vpn-bot:vpn-bot)\s+/opt/vpn-service(?:\s|$)"
    )
    assert forbidden.search(text) is None


def test_docs_require_nonroot_helper_preflight_postflight() -> None:
    check_path = ROOT / "deploy" / "check-nonroot-helper-mode.py"
    assert check_path.exists()

    text = (
        _read("README.md")
        + "\n"
        + _read("docs/security/privilege-separation-plan.md")
        + "\n"
        + _read("deploy/helpers/README.md")
    )

    assert text.count("deploy/check-nonroot-helper-mode.py") >= 3
    assert "mandatory preflight and postflight" in text.lower()


def test_helper_install_docs_pin_ownership_and_modes() -> None:
    text = _read("deploy/helpers/README.md") + "\n" + _read("deploy/sudoers.d/vpnbot.example")

    assert "root:root" in text
    assert "0755" in text
    assert "0440" in text
    assert "not a generic root shell" in text


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
