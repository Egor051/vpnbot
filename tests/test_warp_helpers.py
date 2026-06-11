"""Integrity and behaviour checks for the WARP sudo helper scripts.

The ``vpnbot-warp-routes`` helper implements the production-proven recipe: the
tunnel is brought up by ``awg-quick@out-warp`` with ``Table = auto`` (which sets
an fwmark on the WG socket and creates a DYNAMIC routing table plus host-bypass
rules), and the helper then strips the host-bypass and diverts only the client
subnet through the tunnel. The table number and the WARP endpoint are read at
runtime — never hardcoded.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import textwrap
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
# divert through WARP), not a routing destination. It is the only literal CIDR
# the routes helper bakes in; the table number and the endpoint are dynamic.
CLIENT_SUBNET = "10.0.0.0/24"


def _routes_text() -> str:
    return (SCRIPTS / "vpnbot-warp-routes").read_text(encoding="utf-8")


# ── generic helper integrity ──────────────────────────────────────────────────


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
    for name in ("vpnbot-warp-iface", "vpnbot-warp-status", "vpnbot-warp-routes"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert "awg-quick" in text or "awg show" in text
        # "wg-quick"/"wg show" must not appear except as part of "awg-quick"/"awg show".
        assert re.search(r"(?<![a-z])wg-quick", text) is None
        assert re.search(r"(?<![a-z])wg show", text) is None


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


def test_install_helper_preprocessing_rules() -> None:
    text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    # Validates AmneziaWG markers.
    for marker in ("Jc", "S1", "S2", "AllowedIPs"):
        assert marker in text
    # Strips DNS, forces Table=auto (NOT off — "off" broke the routing loop),
    # adds PersistentKeepalive, writes routes.list.
    assert "DNS" in text
    assert "Table = auto" in text
    assert "Table = off" not in text
    assert "PersistentKeepalive = 25" in text
    assert "out-warp-routes.list" in text


def test_install_helper_creates_amneziawg_symlink() -> None:
    """awg-quick@out-warp resolves the config by name from the amneziawg dir."""
    text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    assert "/etc/amnezia/amneziawg/out-warp.conf" in text
    assert "ln -sf" in text
    # remove tears the symlink down too.
    assert re.search(r"rm -f .*amneziawg/out-warp\.conf", text) is not None


# ── routes helper: dynamic table / endpoint (never hardcoded) ─────────────────


def test_routes_table_is_dynamic_from_awg_fwmark() -> None:
    """The routing table is read from ``awg show <iface> fwmark`` at runtime."""
    text = _routes_text()
    assert 'awg show "$IFACE" fwmark' in text
    # The hex fwmark is converted to the decimal table number via arithmetic.
    assert 'echo "$((fw))"' in text
    # The old hardcoded table/mark "200" scheme must be gone entirely.
    assert "lookup 200" not in text
    assert "table 200" not in text
    assert "fwmark 200" not in text
    assert "--set-mark 200" not in text
    # No literal awg-quick table number (51820+) is baked in either.
    assert re.search(r"\b5182[0-9]\b", text) is None


def test_routes_endpoint_is_dynamic_not_hardcoded() -> None:
    """The anti-loop endpoint is read from ``awg show <iface> endpoints``."""
    text = _routes_text()
    assert 'awg show "$IFACE" endpoints' in text
    # No literal endpoint/CIDR may appear beyond the client SOURCE subnet and the
    # default-route guards (mentioned only in a comment / error message).
    stripped = (
        text.replace(CLIENT_SUBNET, "")
        .replace("0.0.0.0/0", "")
        .replace("::/0", "")
    )
    assert re.search(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", stripped) is None
    assert f'CLIENT_SUBNET="{CLIENT_SUBNET}"' in text


# ── routes helper: add installs the working recipe ────────────────────────────


def test_routes_add_strips_host_bypass() -> None:
    """add removes the awg-quick host-bypass so the host stays on the direct path."""
    text = _routes_text()
    add_section = text[text.index("    add)") : text.index("    del)")]
    # strip_host_bypass is invoked before the narrow client rule is installed.
    i_strip = add_section.index('strip_host_bypass "$TABLE"')
    i_rule = add_section.index('ip -4 rule add from "$CLIENT_SUBNET" lookup "$TABLE"')
    assert i_strip < i_rule
    # The two host-bypass rules are deleted (both families handled in the helper).
    assert 'ip "$fam" rule del not fwmark "$t" table "$t"' in text
    assert 'ip "$fam" rule del table main suppress_prefixlength 0' in text
    assert "for fam in -4 -6" in text


def test_routes_add_narrow_client_rule() -> None:
    """Only the client subnet is diverted, via a single narrow rule at prio 1000."""
    text = _routes_text()
    assert 'ip -4 rule add from "$CLIENT_SUBNET" lookup "$TABLE" priority "$CLIENT_RULE_PRIO"' in text
    assert "CLIENT_RULE_PRIO=1000" in text


def test_routes_add_anti_loop_endpoint_in_both_tables() -> None:
    """The WARP endpoint is pinned to the WAN gateway in BOTH main and table T."""
    text = _routes_text()
    assert 'ip route replace "$WARP_ENDPOINT/32" via "$WAN_GW" dev "$WAN_DEV"' in text
    assert 'ip route replace "$WARP_ENDPOINT/32" via "$WAN_GW" dev "$WAN_DEV" table "$TABLE"' in text
    # The WAN gateway/device are resolved at runtime, not hardcoded.
    assert 'WAN_DEV="$(wan_dev)"' in text
    assert 'WAN_GW="$(wan_gw)"' in text


def test_routes_add_nat_swaps_to_out_warp() -> None:
    """add drops the direct client MASQUERADE and adds the out-warp MASQUERADE."""
    text = _routes_text()
    # Direct client masquerade on the WAN device is removed.
    assert 'iptables -t nat -D POSTROUTING -s "$CLIENT_SUBNET" -o "$WAN_DEV" -j MASQUERADE' in text
    # out-warp masquerade is added (idempotent guard).
    assert 'iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE' in text
    assert 'iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE' in text


def test_routes_add_forward_above_ufw() -> None:
    """FORWARD accepts are inserted at position 1, above UFW's DROP policy."""
    text = _routes_text()
    assert 'iptables -I FORWARD 1 -i "$CLIENT_IFACE" -o "$IFACE" -j ACCEPT' in text
    assert 'iptables -I FORWARD 1 -i "$IFACE" -o "$CLIENT_IFACE" -j ACCEPT' in text
    # Idempotent guards.
    assert 'iptables -C FORWARD -i "$CLIENT_IFACE" -o "$IFACE" -j ACCEPT' in text
    assert 'iptables -C FORWARD -i "$IFACE" -o "$CLIENT_IFACE" -j ACCEPT' in text


def test_routes_add_sets_loose_rp_filter() -> None:
    text = _routes_text()
    assert 'sysctl -w "net.ipv4.conf.$rp.rp_filter=2"' in text
    assert 'for rp in all "$IFACE" "$CLIENT_IFACE"' in text


def test_routes_add_self_check_and_rollback() -> None:
    """add verifies host=direct + client=tunnel and rolls back on failure."""
    text = _routes_text()
    # Host must NOT be in the tunnel; client 10.0.0.4 must route via the tunnel.
    assert "ip route get 1.1.1.1" in text
    assert "from 10.0.0.4" in text
    assert "warp=" in text  # host curl trace check
    # On failure the add path rolls back to direct client egress.
    add_section = text[text.index("    add)") : text.index("    del)")]
    assert "self_check" in add_section
    assert "teardown_client_routing" in add_section
    assert 'strip_host_bypass "$TABLE"' in add_section[add_section.index("self_check") :]


def test_routes_add_is_idempotent() -> None:
    """Every add mutation guards with a presence check or uses replace."""
    text = _routes_text()
    add_section = text[text.index("    add)") : text.index("    del)")]
    # ip rule add guarded by a show|grep -q check.
    assert 'ip -4 rule show | grep -q "from $CLIENT_SUBNET lookup $TABLE"' in add_section
    # endpoint pin uses replace (idempotent by nature).
    assert "ip route replace" in add_section
    # iptables rules guard with -C before -A/-I.
    assert "iptables -t nat -C POSTROUTING" in add_section
    assert "iptables -C FORWARD" in add_section


# ── routes helper: del is the reverse and is safe ─────────────────────────────


def test_routes_del_restores_direct_egress() -> None:
    """del removes the WARP path and restores the direct WAN MASQUERADE."""
    text = _routes_text()
    del_section = text[text.index("    del)") :]
    assert "teardown_client_routing" in del_section
    # Teardown removes the out-warp masquerade and restores the direct one.
    assert 'iptables -t nat -D POSTROUTING -o "$IFACE" -j MASQUERADE' in text
    assert "restore_direct_masquerade" in text
    assert 'iptables -t nat -A POSTROUTING -s "$CLIENT_SUBNET" -o "$dev" -j MASQUERADE' in text
    # del never restores the host-bypass (the host must stay direct).
    assert "rule add not fwmark" not in text
    assert "rule add table main suppress_prefixlength" not in text


def test_routes_del_is_reverse_and_safe() -> None:
    """Teardown runs FORWARD → NAT → rule → route and tolerates missing rules."""
    text = _routes_text()
    teardown = text[text.index("teardown_client_routing() {") : text.index("# Self-check")]
    i_forward = teardown.index("iptables -D FORWARD")
    i_masq = teardown.index("iptables -t nat -D POSTROUTING")
    i_rule = teardown.index("ip -4 rule del from")
    i_route = teardown.index("ip route del")
    assert i_forward < i_masq < i_rule < i_route
    # Every iptables teardown swallows "rule not present"; every ip teardown too.
    for line in teardown.splitlines():
        stripped = line.strip()
        if stripped.startswith("iptables") and "-D" in stripped:
            assert "2>/dev/null" in stripped and "true" in stripped
        if stripped.startswith("ip route del"):
            assert "2>/dev/null" in stripped


def test_routes_does_not_touch_host_default_or_ssh() -> None:
    """The host's own default route is never replaced; SSH stays on the direct path."""
    text = _routes_text()
    # The helper never installs a default route via the tunnel interface; the
    # tunnel-table default is created by awg-quick (Table=auto), not here.
    assert re.search(r'ip route (replace|add) default dev "\$IFACE"', text) is None
    # The script must not special-case or divert the SSH port.
    assert "dport 22" not in text and "sport 22" not in text
    assert "54321" not in text


# ── functional: run the helper against mocked ip/awg/iptables/sysctl/curl ──────

_MOCK_IP = textwrap.dedent(
    r"""
    #!/bin/bash
    printf 'ip %s\n' "$*" >> "$CMD_LOG"
    fam=""
    if [[ "${1:-}" == "-4" || "${1:-}" == "-6" ]]; then fam="$1"; shift; fi
    obj="${1:-}"; shift || true
    case "$obj" in
      rule)
        sub="${1:-}"; shift || true
        case "$sub" in
          show) cat "$IP_RULES" 2>/dev/null || true ;;
          add)  printf 'RULE %s %s\n' "$fam" "$*" >> "$IP_RULES" ;;
          del)
            spec="$*"; tmp="$(mktemp)"
            if [[ "$spec" == *"suppress_prefixlength 0"* ]]; then
              grep -v "suppress_prefixlength 0" "$IP_RULES" > "$tmp" 2>/dev/null || true
            elif [[ "$spec" == *"not fwmark"* ]]; then
              grep -vE "not.*fwmark" "$IP_RULES" > "$tmp" 2>/dev/null || true
            elif [[ "$spec" == *"from 10.0.0.0/24"* ]]; then
              grep -v "from 10.0.0.0/24" "$IP_RULES" > "$tmp" 2>/dev/null || true
            else
              cp "$IP_RULES" "$tmp" 2>/dev/null || true
            fi
            if [[ -f "$IP_RULES" ]] && ! cmp -s "$IP_RULES" "$tmp"; then
              mv "$tmp" "$IP_RULES"; exit 0
            fi
            rm -f "$tmp"; exit 2 ;;
        esac ;;
      route)
        sub="${1:-}"; shift || true; rest="$*"
        case "$sub" in
          show)
            if [[ "$rest" == *"table"* ]]; then echo "default dev out-warp";
            elif [[ "$rest" == *"default"* ]]; then echo "default via 203.0.113.1 dev eth0"; fi ;;
          get)
            if [[ "$rest" == *"from 10.0.0.4"* ]]; then echo "1.1.1.1 from 10.0.0.4 dev out-warp";
            else echo "1.1.1.1 via 203.0.113.1 dev eth0"; fi ;;
        esac ;;
    esac
    exit 0
    """
).lstrip()

_MOCK_AWG = textwrap.dedent(
    r"""
    #!/bin/bash
    printf 'awg %s\n' "$*" >> "$CMD_LOG"
    if [[ "${1:-}" == "show" && "${3:-}" == "fwmark" ]]; then echo "${MOCK_FWMARK:-0xca6c}"; exit 0; fi
    if [[ "${1:-}" == "show" && "${3:-}" == "endpoints" ]]; then
      [[ -n "${MOCK_ENDPOINT:-162.159.195.1}" ]] && printf 'PUBKEY\t%s:2408\n' "${MOCK_ENDPOINT:-162.159.195.1}"
      exit 0
    fi
    exit 0
    """
).lstrip()

_MOCK_IPTABLES = textwrap.dedent(
    r"""
    #!/bin/bash
    printf 'iptables %s\n' "$*" >> "$CMD_LOG"
    # -C (check) always reports the rule is absent so the script installs it.
    for a in "$@"; do [[ "$a" == "-C" ]] && exit 1; done
    exit 0
    """
).lstrip()

_MOCK_SYSCTL = textwrap.dedent(
    r"""
    #!/bin/bash
    printf 'sysctl %s\n' "$*" >> "$CMD_LOG"
    exit 0
    """
).lstrip()

_MOCK_CURL = textwrap.dedent(
    r"""
    #!/bin/bash
    printf 'curl %s\n' "$*" >> "$CMD_LOG"
    echo "warp=off"
    exit 0
    """
).lstrip()

# Fresh post-`awg-quick up` state: the Table=auto host-bypass rules are present.
_INITIAL_RULES = textwrap.dedent(
    """\
    0:\tfrom all lookup local
    32764:\tnot from all fwmark 0xca6c lookup 51820
    32765:\tfrom all lookup main suppress_prefixlength 0
    32766:\tfrom all lookup main
    """
)

# Already-applied state: host-bypass stripped, narrow client rule installed.
_APPLIED_RULES = textwrap.dedent(
    """\
    0:\tfrom all lookup local
    32766:\tfrom all lookup main
    RULE -4 from 10.0.0.0/24 lookup 51820 priority 1000
    """
)


def _make_bin(tmp_path: Path) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (
        ("ip", _MOCK_IP),
        ("awg", _MOCK_AWG),
        ("iptables", _MOCK_IPTABLES),
        ("sysctl", _MOCK_SYSCTL),
        ("curl", _MOCK_CURL),
    ):
        p = bindir / name
        p.write_text(body, encoding="utf-8")
        p.chmod(0o755)
    return bindir


def _run_routes(
    tmp_path: Path,
    action: str,
    *,
    initial_rules: str = "",
    fwmark: str = "0xca6c",
    endpoint: str = "162.159.195.1",
) -> tuple[int, str, str]:
    bindir = _make_bin(tmp_path)
    cmd_log = tmp_path / "cmd.log"
    ip_rules = tmp_path / "rules"
    ip_rules.write_text(initial_rules, encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "CMD_LOG": str(cmd_log),
        "IP_RULES": str(ip_rules),
        "MOCK_FWMARK": fwmark,
        "MOCK_ENDPOINT": endpoint,
    }
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "vpnbot-warp-routes"), action, "out-warp"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    log = cmd_log.read_text(encoding="utf-8") if cmd_log.exists() else ""
    return proc.returncode, log, proc.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_add_applies_recipe_with_dynamic_table(tmp_path: Path) -> None:
    rc, log, stderr = _run_routes(tmp_path, "add", initial_rules=_INITIAL_RULES)
    assert rc == 0, stderr
    # Dynamic table 51820 was derived from the fwmark 0xca6c.
    assert "awg show out-warp fwmark" in log
    # Host-bypass stripped (using the dynamic table number, not a hardcode).
    assert "ip -4 rule del not fwmark 51820 table 51820" in log
    assert "ip -4 rule del table main suppress_prefixlength 0" in log
    # Narrow client rule installed at priority 1000.
    assert "ip -4 rule add from 10.0.0.0/24 lookup 51820 priority 1000" in log
    # Anti-loop endpoint pinned in BOTH tables.
    assert "ip route replace 162.159.195.1/32 via 203.0.113.1 dev eth0" in log
    assert "ip route replace 162.159.195.1/32 via 203.0.113.1 dev eth0 table 51820" in log
    # NAT + FORWARD + rp_filter.
    assert "iptables -t nat -A POSTROUTING -o out-warp -j MASQUERADE" in log
    assert "iptables -I FORWARD 1 -i awg0 -o out-warp -j ACCEPT" in log
    assert "iptables -I FORWARD 1 -i out-warp -o awg0 -j ACCEPT" in log
    assert "net.ipv4.conf.out-warp.rp_filter=2" in log


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_add_is_idempotent(tmp_path: Path) -> None:
    """Re-running add over already-applied state succeeds (no loop, no error)."""
    rc1, _, err1 = _run_routes(tmp_path, "add", initial_rules=_INITIAL_RULES)
    assert rc1 == 0, err1
    # The rules file now holds the narrow rule; the host-bypass is gone.
    rules_after = (tmp_path / "rules").read_text(encoding="utf-8")
    assert "from 10.0.0.0/24 lookup 51820" in rules_after
    assert "not from all fwmark" not in rules_after
    # Second add over the same state must still exit cleanly.
    bindir = tmp_path / "bin"
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "vpnbot-warp-routes"), "add", "out-warp"],
        env={
            **os.environ,
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "CMD_LOG": str(tmp_path / "cmd2.log"),
            "IP_RULES": str(tmp_path / "rules"),
            "MOCK_FWMARK": "0xca6c",
            "MOCK_ENDPOINT": "162.159.195.1",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_del_restores_direct_and_is_safe_on_clean_system(tmp_path: Path) -> None:
    # del on an applied system.
    applied = tmp_path / "applied"
    applied.mkdir()
    rc, log, err = _run_routes(applied, "del", initial_rules=_APPLIED_RULES)
    assert rc == 0, err
    assert "iptables -t nat -D POSTROUTING -o out-warp -j MASQUERADE" in log
    # Direct client egress restored on the WAN device.
    assert "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE" in log
    assert "ip -4 rule del from 10.0.0.0/24 priority 1000" in log

    # del on a clean system (interface down → fwmark off, no rules) is a no-op-safe.
    clean = tmp_path / "clean"
    clean.mkdir()
    rc2, _, err2 = _run_routes(clean, "del", initial_rules="", fwmark="off", endpoint="")
    assert rc2 == 0, err2


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_add_aborts_when_no_auto_table(tmp_path: Path) -> None:
    """Without a Table=auto fwmark the helper refuses to run (no unsafe state)."""
    rc, _, stderr = _run_routes(tmp_path, "add", initial_rules="", fwmark="off")
    assert rc != 0
    assert "Table = auto" in stderr or "no auto routing table" in stderr
