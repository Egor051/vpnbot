"""Integrity checks for the WARP sudo helper scripts."""
from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
WARP_HELPERS = (
    "vpnbot-warp-install",
    "vpnbot-warp-iface",
    "vpnbot-warp-routes",
    "vpnbot-warp-status",
)

# The AmneziaWG client subnet is a SOURCE selector (which clients' traffic to
# divert through WARP), not a routing destination. It is the only literal CIDR the
# routes helper may bake in; all destination CIDRs still come from routes.list.
AWG_CLIENTS_SUBNET = "10.0.0.0/24"


def _routes_text() -> str:
    return (SCRIPTS / "vpnbot-warp-routes").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", WARP_HELPERS)
def test_helper_exists_with_bash_shebang(name: str) -> None:
    path = SCRIPTS / name
    assert path.exists(), f"missing helper: {name}"
    assert path.read_text(encoding="utf-8").startswith("#!/bin/bash")


@pytest.mark.parametrize("name", WARP_HELPERS)
def test_helper_is_executable(name: str) -> None:
    mode = (SCRIPTS / name).stat().st_mode
    assert mode & stat.S_IXUSR


def test_uses_awg_quick_not_wg_quick() -> None:
    """The module must drive AmneziaWG (awg-quick/awg), never plain wg-quick."""
    for name in ("vpnbot-warp-iface", "vpnbot-warp-status"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert "awg-quick" in text or "awg show" in text
        # "wg-quick"/"wg show" must not appear except as part of "awg-quick"/"awg show".
        assert re.search(r"(?<![a-z])wg-quick", text) is None
        assert re.search(r"(?<![a-z])wg show", text) is None


def test_routes_helper_reads_list_and_has_no_unexpected_cidrs() -> None:
    text = _routes_text()
    assert "out-warp-routes.list" in text
    # The only permitted literal CIDRs are the default-route guards (0.0.0.0/0 and
    # ::/0) that protect the host from accidental isolation and the AWG client
    # SOURCE subnet. No other literal CIDRs may be baked in — every routing
    # destination must come from routes.list.
    stripped = (
        text.replace("0.0.0.0/0", "")
        .replace("::/0", "")
        .replace(AWG_CLIENTS_SUBNET, "")
    )
    assert re.search(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", stripped) is None


def test_install_helper_preprocessing_rules() -> None:
    text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    # Validates AmneziaWG markers.
    for marker in ("Jc", "S1", "S2", "AllowedIPs"):
        assert marker in text
    # Strips DNS, adds Table=off and PersistentKeepalive, writes routes.list.
    assert "DNS" in text
    assert "Table = off" in text
    assert "PersistentKeepalive = 25" in text
    assert "out-warp-routes.list" in text


def test_no_helper_uses_shell_injection_patterns() -> None:
    for name in WARP_HELPERS:
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert "eval " not in text

    # The install helper must use a quoted here-doc delimiter so the shell does
    # not interpolate $SOURCE/$DEST/$ROUTES_LIST into the Python source code.
    install_text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    assert "<<'PYEOF'" in install_text or "<< 'PYEOF'" in install_text


def test_install_helper_validates_source_path() -> None:
    text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    assert "ALLOWED_DIR" in text or "realpath" in text


# ── policy-routing: divert all VPN-client egress through WARP ──────────────────


def test_routes_helper_warp_table_default() -> None:
    """add installs a default route via the WARP iface in the dedicated table 200."""
    text = _routes_text()
    assert re.search(
        r'ip route replace default dev "\$IFACE" table 200', text
    ) is not None
    # del removes the table-200 default route.
    assert re.search(
        r'ip route del default dev "\$IFACE" table 200', text
    ) is not None


def test_routes_helper_anti_loop_route() -> None:
    """The encrypted WARP endpoint is pinned to the real gateway on eth0."""
    text = _routes_text()
    # Resolve the gateway and the endpoint, then route the endpoint via eth0.
    assert "ip route show default dev eth0" in text
    assert "awg show" in text
    assert re.search(
        r'ip route replace "\$WARP_ENDPOINT/32" via "\$MAIN_GW" dev eth0', text
    ) is not None


def test_routes_helper_source_rule_for_awg_clients() -> None:
    """AWG client traffic is selected into table 200 by a source rule."""
    text = _routes_text()
    assert re.search(
        r'ip rule add from "\$AWG_CLIENTS_SUBNET" lookup 200 priority 100', text
    ) is not None
    assert f'AWG_CLIENTS_SUBNET="{AWG_CLIENTS_SUBNET}"' in text
    # del removes the source rule.
    assert re.search(
        r'ip rule del from "\$AWG_CLIENTS_SUBNET" lookup 200 priority 100', text
    ) is not None


def test_routes_helper_fwmark_rule() -> None:
    """Marked packets (mark 200) are selected into table 200."""
    text = _routes_text()
    assert re.search(r"ip rule add fwmark 200 lookup 200 priority 101", text) is not None
    assert re.search(r"ip rule del fwmark 200 lookup 200 priority 101", text) is not None


def test_routes_helper_dante_mark() -> None:
    """Dante SOCKS5 (uid nobody) egress is marked for WARP."""
    text = _routes_text()
    assert 'DANTE_USER="nobody"' in text
    # add: mark by owning uid nobody.
    assert re.search(
        r'iptables -t mangle -A OUTPUT -m owner --uid-owner "\$DANTE_USER" -j MARK --set-mark 200',
        text,
    ) is not None
    # del: paired removal.
    assert re.search(
        r'iptables -t mangle -D OUTPUT -m owner --uid-owner "\$DANTE_USER" -j MARK --set-mark 200',
        text,
    ) is not None


def test_routes_helper_mtproto_mark() -> None:
    """MTProto egress is marked by owning uid, independent of the bot module toggle."""
    text = _routes_text()
    assert 'MTPROTO_SERVICE="mtproxy"' in text
    # add + del mark by the resolved MTProto run-user.
    assert re.search(
        r'iptables -t mangle -A OUTPUT -m owner --uid-owner "\$MTPROTO_USER" -j MARK --set-mark 200',
        text,
    ) is not None
    assert re.search(
        r'iptables -t mangle -D OUTPUT -m owner --uid-owner "\$MTPROTO_USER" -j MARK --set-mark 200',
        text,
    ) is not None


def test_routes_helper_xray_mark() -> None:
    """Xray egress is marked by owning uid (non-root) or a WARP-IP source rule (root)."""
    text = _routes_text()
    assert 'XRAY_SERVICE="xray"' in text
    assert re.search(
        r'iptables -t mangle -A OUTPUT -m owner --uid-owner "\$XRAY_USER" -j MARK --set-mark 200',
        text,
    ) is not None
    # root fallback: bind-to-WARP-IP source rule.
    assert re.search(r'ip rule add from "\$WARP_IP" lookup 200 priority 102', text) is not None


def test_routes_helper_masquerade_rules() -> None:
    text = _routes_text()
    # add: MASQUERADE on the WARP interface.
    assert re.search(r'iptables -t nat -A POSTROUTING -o "\$IFACE" -j MASQUERADE', text) is not None
    # del: MASQUERADE removed.
    assert re.search(r'iptables -t nat -D POSTROUTING -o "\$IFACE" -j MASQUERADE', text) is not None


def test_routes_helper_forward_rules() -> None:
    text = _routes_text()
    # add: forwarding permitted both ways across the WARP interface.
    assert re.search(r'iptables -t filter -A FORWARD -o "\$IFACE" -j ACCEPT', text) is not None
    assert re.search(r'iptables -t filter -A FORWARD -i "\$IFACE" -j ACCEPT', text) is not None
    # del: both FORWARD rules removed.
    assert re.search(r'iptables -t filter -D FORWARD -o "\$IFACE" -j ACCEPT', text) is not None
    assert re.search(r'iptables -t filter -D FORWARD -i "\$IFACE" -j ACCEPT', text) is not None


def test_routes_helper_add_ordering() -> None:
    """add order: anti-loop/table route → ip rule → mangle mark → MASQUERADE → FORWARD."""
    text = _routes_text()
    add_section = text[text.index("    add)") : text.index("    del)")]
    i_table = add_section.index('ip route replace default dev "$IFACE" table 200')
    i_rule = add_section.index('ip rule add from "$AWG_CLIENTS_SUBNET" lookup 200')
    i_mangle = add_section.index("iptables -t mangle -A OUTPUT")
    i_masq = add_section.index("iptables -t nat -A POSTROUTING")
    i_forward = add_section.index("iptables -t filter -A FORWARD")
    assert i_table < i_rule < i_mangle < i_masq < i_forward


def test_routes_helper_del_is_reverse_and_safe() -> None:
    """del runs in reverse and every teardown tolerates a missing rule."""
    text = _routes_text()
    del_section = text[text.index("    del)") :]
    # Reverse order: FORWARD removed before MASQUERADE before the route table.
    i_forward = del_section.index("iptables -t filter -D FORWARD")
    i_masq = del_section.index("iptables -t nat -D POSTROUTING")
    i_route = del_section.index('ip route del default dev "$IFACE" table 200')
    assert i_forward < i_masq < i_route
    # Every iptables teardown swallows "rule not present"; every ip teardown too.
    for line in del_section.splitlines():
        stripped = line.strip()
        if stripped.startswith("iptables") and "-D" in stripped:
            assert "2>/dev/null" in stripped and "true" in stripped
        if stripped.startswith("ip rule del") or stripped.startswith("ip route del"):
            assert "2>/dev/null" in stripped


def test_routes_helper_is_idempotent_on_add() -> None:
    """Every add step checks for the rule before installing it."""
    text = _routes_text()
    add_section = text[text.index("    add)") : text.index("    del)")]
    # iptables rules guard with -C ... || -A before installing.
    assert add_section.count("-C OUTPUT") >= 1
    assert "iptables -t nat -C POSTROUTING" in add_section
    assert "iptables -t filter -C FORWARD" in add_section
    # ip rules/routes guard with "show | grep -q ... ||".
    assert add_section.count("grep -q") >= 3
    assert 'ip route show table 200 | grep -q "^default"' in add_section


def test_routes_helper_does_not_touch_host_default_or_ssh() -> None:
    """The host's own default route is never replaced; SSH stays on the direct path."""
    text = _routes_text()
    # No rule ever rewrites the MAIN-table default route to the WARP interface.
    assert re.search(r'ip route (replace|add) default dev "\$IFACE"(?! table)', text) is None
    # The default route the script does create is confined to table 200.
    assert 'table 200' in text
    # The script must not special-case or divert port 22.
    assert "dport 22" not in text and "sport 22" not in text
