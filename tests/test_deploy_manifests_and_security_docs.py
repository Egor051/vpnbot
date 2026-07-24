"""Guards for the shipped deploy manifests (systemd units, sudoers grant, setup and
user-creation scripts).

These assert the content of artifacts that actually ship under deploy/, so an
accidental weakening of the systemd sandbox, an over-broad sudoers grant, or a
destructive setup step fails CI. Documentation-wording guards live separately in
test_documentation_content; privileged-helper behaviour in
test_privileged_helper_scripts.
"""

import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_production_service_uses_root_api_mode() -> None:
    # The production unit deliberately runs as root ("root+api" mode): the bot
    # applies Xray/AWG/MTProxy config and reloads services directly, so User=root
    # with ProtectSystem=false and no NoNewPrivileges is the intended posture, not
    # an oversight. The hardened, sandboxed alternative is the separately shipped
    # vpn-bot.nonroot.example.service (helper mode). See
    # docs/security/privilege-separation-plan.md. This test pins that intent so a
    # silent switch away from root+api is caught.
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
    text = _read("deploy/sudoers.d/vpn-bot.example")

    assert "NOPASSWD: ALL" not in text
    assert "ALL=(ALL)" not in text
    for forbidden in ("systemctl", "useradd", "chpasswd", "userdel", "passwd -l"):
        assert forbidden not in text
    assert "/usr/local/sbin/vpn-bot-socks5-user" in text
    assert "/usr/local/sbin/vpn-bot-xray-apply" in text
    assert "/usr/local/sbin/vpn-bot-awg-apply" in text
    assert "/usr/local/sbin/vpn-bot-mtproxy-apply" in text
    assert re.search(r"vpn-bot\s+ALL=\(root\)\s+NOPASSWD:", text)


def test_setup_removes_stale_legacy_tg_warp_files() -> None:
    """The WARP interface/files were renamed tg-warp → out-warp; servers upgraded
    across the rename keep orphaned tg-warp.conf (with a stale key) and
    tg-warp-routes.list. The setup script removes both idempotently and must never
    touch the active out-warp files."""
    text = _read("deploy/setup-nonroot-helper-mode.sh")

    # Both legacy files are removed, each guarded by an -f existence check so the
    # cleanup is idempotent (no error when the file is already gone).
    assert "if [[ -f /etc/amnezia/tg-warp.conf ]]; then" in text
    assert "rm -f /etc/amnezia/tg-warp.conf" in text
    assert "if [[ -f /etc/amnezia/tg-warp-routes.list ]]; then" in text
    assert "rm -f /etc/amnezia/tg-warp-routes.list" in text

    # Invariant: no rm command may target the active out-warp path. Scan only the
    # executable lines — comments legitimately mention out-warp.conf for context.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("rm "):
            assert "out-warp" not in stripped, f"setup must not rm active out-warp file: {line!r}"


def test_create_user_script_is_non_destructive_scaffold() -> None:
    text = _read("deploy/create-vpn-bot-user.sh")

    assert "set -euo pipefail" in text
    assert "vpn-bot.service" in text
    assert "groupadd --system" in text
    assert "useradd" in text
    assert "chown -R /opt/vpn-service" not in text
    assert "systemctl" not in text


# NOTE: behavioral validation of the privilege helpers (validate_login rejecting
# reserved/malformed names, path-traversal rejection, secret redaction) lives in
# test_privileged_helper_scripts.py, which loads the helper modules via the
# load_helper fixture and runs unconditionally. Earlier PRIVILEGE_HELPERS_ENABLED-
# gated copies here were skipped in CI and duplicated that coverage, so they were
# removed. This module only guards the shipped deploy manifests and security docs.


def test_hysteria_config_yaml_has_no_obfs_and_listens_on_udp_443() -> None:
    # Salamander obfuscation was dropped and Hysteria2 moved from UDP/15650 to
    # plain QUIC on UDP/443 — this pins the two structural facts a regression
    # could silently break, without asserting cert/key paths, TLS details or
    # secrets (those are host-specific / operator-filled).
    text = _read("deploy/hysteria/config.yaml")

    assert re.search(r"^listen:\s*:443\s*$", text, re.MULTILINE), "listen must be :443"
    # No `obfs:` config key — comments are allowed to explain the absence.
    assert not re.search(r"^\s*obfs\s*:", text, re.MULTILINE), "salamander obfuscation must not be configured"
    assert re.search(r"^\s*cert:\s*/etc/hysteria/cert\.pem\s*$", text, re.MULTILINE)
    assert re.search(r"^\s*key:\s*/etc/hysteria/key\.pem\s*$", text, re.MULTILINE)
    # Cert is a valid Let's Encrypt cert managed by acme.sh outside this repo —
    # no lingering "self-signed" language from before the domain/ACME switch.
    assert "self-signed" not in text.lower()


def test_hysteria_config_yaml_has_file_masquerade_no_http_listeners() -> None:
    # File-based masquerade decoys Hysteria2 probes that never complete the
    # handshake, served over the existing UDP/443 QUIC path. listenHTTP/
    # listenHTTPS must stay absent: those bind separate plaintext TCP :80/:443
    # listeners, and TCP/443 on this host is already held by Xray REALITY.
    text = _read("deploy/hysteria/config.yaml")

    assert re.search(r"^\s*type:\s*file\s*$", text, re.MULTILINE), "masquerade.type must be file"
    assert re.search(r"^\s*dir:\s*/etc/hysteria/masq\s*$", text, re.MULTILINE), (
        "masquerade.file.dir must be /etc/hysteria/masq"
    )
    assert not re.search(r"^\s*listenHTTP\s*:", text, re.MULTILINE), "listenHTTP must not be configured"
    assert not re.search(r"^\s*listenHTTPS\s*:", text, re.MULTILINE), "listenHTTPS must not be configured"


def test_hysteria_preflight_script_is_present_and_fail_closed() -> None:
    # Static guard only — the script's own `--selftest` mode (canned ss(8)
    # input, no real socket) is the source of truth for its runtime behaviour
    # and is exercised by hand / in CI shell steps, not reimplemented here.
    script_path = ROOT / "deploy" / "hysteria" / "preflight-udp443.sh"
    assert script_path.exists()
    assert os.access(script_path, os.X_OK), "preflight-udp443.sh must be executable"

    text = _read("deploy/hysteria/preflight-udp443.sh")
    assert text.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in text
    assert "--selftest" in text
    # TCP/443 (Xray) must be irrelevant to the UDP/443 verdict.
    assert "netid" in text.lower()


def test_hysteria_docs_reference_install_config_not_bare_cp() -> None:
    # A bare `cp deploy/hysteria/config.yaml /etc/hysteria/config.yaml` clobbers
    # the live trafficStats secret with the tracked placeholder, so
    # hysteria-server starts returning 401 on the bot's stats/online/kick calls.
    # Every doc/manifest that tells the operator how to install the file must
    # point at install-config.sh instead — full behavioural coverage of the
    # script itself lives in test_hysteria_install_config.py.
    bare_cp = re.compile(r"cp\s+deploy/hysteria/config\.yaml\s+/etc/hysteria/config\.yaml")
    for relative_path in (
        "docs/deployment.md",
        "docs/deployment.ru.md",
        "docs/hysteria.md",
        "docs/hysteria.ru.md",
        "deploy/hysteria/config.yaml",
    ):
        text = _read(relative_path)
        assert "install-config.sh" in text, f"{relative_path} must reference install-config.sh"
        assert not bare_cp.search(text), (
            f"{relative_path} must not instruct a bare cp of the hysteria config"
        )


# --------------------------------------------------------------------------- #
# WARP reassert units + systemd-networkd foreign-rule drop-in (2026-07-24 fix)
# --------------------------------------------------------------------------- #
def test_warp_reassert_service_is_oneshot_and_never_tears_down() -> None:
    """The reassert service runs the ADD-ONLY `reassert` verb and has NO ExecStop.
    A `del`/ExecStop would drop live clients' routing on every stop — the exact
    reason this is a separate verb from restarting warp-routes.service."""
    text = _read("deploy/warp-routes-reassert.service")
    assert "Type=oneshot" in text
    assert "ExecStart=/usr/local/sbin/vpn-bot-warp-routes reassert out-warp" in text
    # No ExecStop directive on any DIRECTIVE line (a comment may explain why a restart
    # of warp-routes.service would be destructive — matched on real directives only).
    directives = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert not any(ln.startswith("ExecStop") for ln in directives)
    for ln in directives:
        if ln.startswith("ExecStart="):
            assert ln.endswith("reassert out-warp"), f"unexpected ExecStart: {ln!r}"
            assert " del " not in ln and not ln.endswith(" del")
    # Ordered AFTER the boot-time warp-routes.service (rides on the same table).
    assert "After=" in text
    after_line = next(ln for ln in text.splitlines() if ln.startswith("After="))
    assert "warp-routes.service" in after_line


def test_warp_reassert_timer_fires_every_five_minutes_spread_out() -> None:
    """5-minute cadence, jittered so it never lines up with the other periodic jobs,
    and Persistent=false (a missed reassert is worthless; re-assert live state next tick)."""
    text = _read("deploy/warp-routes-reassert.timer")
    assert "OnUnitActiveSec=5min" in text
    assert re.search(r"^AccuracySec=", text, re.MULTILINE), "timer must set AccuracySec"
    assert re.search(r"^RandomizedDelaySec=", text, re.MULTILINE), "timer must set RandomizedDelaySec"
    assert "Persistent=false" in text
    assert "Unit=warp-routes-reassert.service" in text
    assert "WantedBy=timers.target" in text


def test_warp_reassert_units_registered_in_managed_units_list() -> None:
    """Phase 1 must see both units — they are listed in managed-units.list so the
    UNIT_SET assembly and the report pick them up (the 15 July gap was units deploy.sh
    could not see)."""
    text = _read("deploy/managed-units.list")
    assert "warp-routes-reassert.service" in text
    assert "warp-routes-reassert.timer" in text


def test_networkd_keep_foreign_rules_dropin_content_is_exact() -> None:
    """The drop-in must set BOTH foreign-management flags to no; anything else would
    let systemd-networkd flush WARP's ip rules again (the 2026-07-24 incident)."""
    text = _read("deploy/networkd/10-keep-foreign-rules.conf")
    assert "[Network]" in text
    assert re.search(r"^ManageForeignRoutingPolicyRules=no\s*$", text, re.MULTILINE)
    assert re.search(r"^ManageForeignRoutes=no\s*$", text, re.MULTILINE)
    # The dangerous `=yes` value must never appear as an active setting.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            continue
        assert not stripped.endswith("=yes"), f"drop-in must not enable foreign management: {line!r}"


def test_deploy_sh_checks_networkd_dropin_informationally() -> None:
    """deploy.sh Phase 1 verifies the drop-in is present AND active via
    `systemd-analyze cat-config systemd/networkd.conf`, and the check is never fatal."""
    text = _read("scripts/deploy.sh")
    assert "networkd_foreign_rules_ok" in text
    assert "systemd-analyze cat-config systemd/networkd.conf" in text
    assert "ManageForeignRoutingPolicyRules" in text
    # It is wired as an informational warn (never a die) in the live Phase 1 path.
    idx = text.index("networkd_foreign_rules_ok")
    # A `die` must not be the handler for a failed networkd check.
    window = text[idx : idx + 1200]
    assert "die " not in window or "warn " in window
