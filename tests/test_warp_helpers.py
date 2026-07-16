"""Integrity and behaviour checks for the WARP sudo helper scripts.

The ``vpn-bot-warp-routes`` helper implements the production-proven recipe: the
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
    "vpn-bot-warp-install",
    "vpn-bot-warp-iface",
    "vpn-bot-warp-routes",
    "vpn-bot-warp-status",
)

# The AmneziaWG client subnet is a SOURCE selector (which clients' traffic to
# divert through WARP), not a routing destination. It is the only literal CIDR
# the routes helper bakes in; the table number and the endpoint are dynamic.
CLIENT_SUBNET = "10.0.0.0/24"


def _routes_text() -> str:
    return (SCRIPTS / "vpn-bot-warp-routes").read_text(encoding="utf-8")


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
    for name in ("vpn-bot-warp-iface", "vpn-bot-warp-status", "vpn-bot-warp-routes"):
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
    install_text = (SCRIPTS / "vpn-bot-warp-install").read_text(encoding="utf-8")
    assert "<<'PYEOF'" in install_text or "<< 'PYEOF'" in install_text


def test_install_helper_validates_source_path() -> None:
    text = (SCRIPTS / "vpn-bot-warp-install").read_text(encoding="utf-8")
    assert "ALLOWED_DIR" in text or "realpath" in text


def test_install_helper_preprocessing_rules() -> None:
    text = (SCRIPTS / "vpn-bot-warp-install").read_text(encoding="utf-8")
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
    text = (SCRIPTS / "vpn-bot-warp-install").read_text(encoding="utf-8")
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
    """add verifies host=direct + client routing installed, and rolls back on failure."""
    text = _routes_text()
    # Host must NOT be in the tunnel — a HOST route (no conntrack) probes correctly.
    assert "ip route get 1.1.1.1" in text
    assert "warp=" in text  # host curl trace check
    # On failure the add path rolls back to direct client egress.
    add_section = text[text.index("    add)") : text.index("    del)")]
    assert "self_check" in add_section
    assert "teardown_client_routing" in add_section
    assert 'strip_host_bypass "$TABLE"' in add_section[add_section.index("self_check") :]


def test_routes_self_check_never_simulates_the_client_path() -> None:
    """The client mark is set FROM CONNTRACK (nft `ct mark set meta mark`); a
    stateless `ip route get` cannot reproduce it and returns false negatives. The
    self-check must therefore NEVER probe the client path with any form of
    `ip route get` (``iif`` / ``mark`` / ``from <client>``) and must instead OBSERVE
    real tunnel byte counters. It must also not hardcode a client IP — the live peer
    comes from ``awg show <iface> latest-handshakes``. This test guards against a
    regression back to the ip-route-get-based client probe."""
    text = _routes_text()
    # No ip-route-get form that simulates the CLIENT path may appear in actual CODE
    # (comments explaining what we deliberately avoid are fine). The bare host probe
    # `ip route get 1.1.1.1` (no from/iif/mark) is the only one kept.
    code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert re.search(r"ip route get[^\n]*\biif\b", code) is None
    assert re.search(r"ip route get[^\n]*\bmark\b", code) is None
    assert re.search(r"ip route get[^\n]*\bfrom\b", code) is None
    # The client data plane is verified by OBSERVING real counters, not simulating.
    assert "warp_bytes" in text
    assert 'awg show "$IFACE" transfer' in text
    assert "statistics/rx_bytes" in text and "statistics/tx_bytes" in text
    # No hardcoded client address anywhere; the live peer is read from awg.
    assert "10.0.0.4" not in text
    assert "latest-handshakes" in text
    # Absence of traffic must SKIP, not fail (an idle tunnel is not a broken one).
    assert "have_active_clients" in text
    assert "skipping data-plane" in text


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


# ── routes helper: local-proxy egress through the tunnel ──────────────────────


def test_routes_tunnel_ip_read_from_interface_address() -> None:
    """The tunnel IP is read from the config's [Interface] Address, never hardcoded."""
    text = _routes_text()
    # Parsed from the config file (default /etc/amnezia/out-warp.conf, overridable).
    assert 'WARP_CONFIG="${WARP_CONFIG:-/etc/amnezia/out-warp.conf}"' in text
    assert "Address" in text and "tunnel_ip()" in text
    # No literal tunnel IP/CIDR is baked in (the bare-IP regex used to validate the
    # parsed value carries no /mask, so it is not a hardcoded CIDR).
    stripped = text.replace(CLIENT_SUBNET, "").replace("0.0.0.0/0", "").replace("::/0", "")
    assert re.search(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", stripped) is None


def test_routes_add_source_bind_proxy_rule() -> None:
    """A single `from <tunnel-ip>` rule diverts the source-bind proxies (no NAT)."""
    text = _routes_text()
    assert 'ip -4 rule add from "$tip" lookup "$t" priority "$PROXY_RULE_PRIO"' in text
    assert "PROXY_RULE_PRIO=999" in text
    # Guarded for idempotency.
    assert 'ip -4 rule show | grep -q "from $tip lookup $t"' in text


def test_routes_add_mtproto_fwmark_cgroup_mark_and_snat() -> None:
    """MTProto: fwmark rule + cgroup-mark + explicit SNAT to the tunnel IP."""
    text = _routes_text()
    assert "MTPROTO_MARK=\"0x2\"" in text
    assert "MTPROTO_RULE_PRIO=998" in text
    # a. marked packets use the tunnel table.
    assert 'ip -4 rule add fwmark "$MTPROTO_MARK" lookup "$t" priority "$MTPROTO_RULE_PRIO"' in text
    # b. cgroup-mark the daemon's own packets by its unit cgroup path.
    assert 'iptables -t mangle -A OUTPUT -m cgroup --path "$cgpath" -j MARK --set-mark "$MTPROTO_MARK"' in text
    assert 'cgpath="system.slice/${unit}.service"' in text
    # c. explicit SNAT to the tunnel IP.
    assert '-m mark --mark "$MTPROTO_MARK" -j SNAT --to-source "$tip"' in text


def test_routes_mtproto_snat_inserted_above_masquerade() -> None:
    """The SNAT is INSERTED at position 1 (above the appended broad masquerade)."""
    text = _routes_text()
    assert 'iptables -t nat -I POSTROUTING 1 -o "$IFACE" -m mark --mark "$MTPROTO_MARK" -j SNAT --to-source "$tip"' in text
    # The broad out-warp masquerade is APPENDED, so a position-1 insert sits above it.
    assert 'iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE' in text


def test_routes_mtproto_only_when_unit_exists() -> None:
    """The MTProto step is gated on the unit existing and is safe when it is absent."""
    text = _routes_text()
    assert "mtproxy_unit_exists" in text
    assert 'systemctl cat -- "${1}.service"' in text
    # The unit name is resolved (default mtproxy), never a hardcoded cgroup literal.
    assert 'u="${MTPROXY_UNIT-mtproxy}"' in text
    # cgroup-mark add is non-fatal so a not-yet-running daemon never breaks the host.
    assert "could not cgroup-mark" in text


def test_routes_proxy_subactions_exist() -> None:
    """proxy-add/proxy-del apply only the proxy egress (no host/client routing)."""
    text = _routes_text()
    assert "proxy-add)" in text
    assert "proxy-del)" in text
    assert "{add|del|proxy-add|proxy-del}" in text
    # proxy-add must not strip the host-bypass or run the destructive self-check.
    proxy_add = text[text.index("proxy-add)") : text.index("proxy-del)")]
    assert "strip_host_bypass" not in proxy_add
    assert "self_check" not in proxy_add
    assert "apply_proxy_routing" in proxy_add


def test_routes_add_applies_proxy_routing_before_self_check() -> None:
    """add diverts proxy egress, then self-checks the host is still direct."""
    text = _routes_text()
    add_section = text[text.index("    add)") : text.index("    del)")]
    i_proxy = add_section.index('apply_proxy_routing "$TABLE"')
    i_check = add_section.index("self_check")
    assert i_proxy < i_check


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
            elif [[ "$spec" == *"fwmark"* ]]; then
              m="$(awk '{for(i=1;i<=NF;i++) if($i=="fwmark") print $(i+1)}' <<<"$spec")"
              grep -v "fwmark $m" "$IP_RULES" > "$tmp" 2>/dev/null || true
            elif [[ "$spec" == *"from "* ]]; then
              s="$(awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' <<<"$spec")"
              grep -v "from $s" "$IP_RULES" > "$tmp" 2>/dev/null || true
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
            # A conntrack-mark simulation is structurally unreachable — mirror the
            # real bug so a reintroduced `mark` probe fails the self-check.
            if [[ "$rest" == *"mark"* ]]; then
              echo "RTNETLINK answers: Network is unreachable" >&2; exit 2
            # A client-path simulation (`iif …` / `from <addr>`) reports whatever
            # MOCK_ROUTE_GET_CLIENT_DEV says (default out-warp). Set it to eth0 to
            # model the false-negative the counter-based check must survive.
            elif [[ "$rest" == *"iif"* || "$rest" == *"from 10."* ]]; then
              echo "1.1.1.1 dev ${MOCK_ROUTE_GET_CLIENT_DEV:-out-warp}";
            # The bare host probe resolves to the WAN (host stays direct) unless the
            # host has (wrongly) been captured by the tunnel.
            elif [[ "${MOCK_HOST_IN_TUNNEL:-0}" == "1" ]]; then
              echo "1.1.1.1 dev out-warp";
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
    # latest-handshakes → "<pubkey>\t<unix-ts>". A live client is emitted only when
    # MOCK_HANDSHAKE_AGE (seconds-ago) is set, so by default there are no active
    # clients and the data-plane check SKIPS. This is how have_active_clients reads
    # the live peer instead of hardcoding a client IP.
    if [[ "${1:-}" == "show" && "${3:-}" == "latest-handshakes" ]]; then
      if [[ -n "${MOCK_HANDSHAKE_AGE:-}" ]]; then
        printf 'CLIENTPUBKEY\t%s\n' "$(( $(date +%s) - MOCK_HANDSHAKE_AGE ))"
      fi
      exit 0
    fi
    # transfer → "<pubkey>\t<rx>\t<tx>". Counters GROW across successive calls when
    # MOCK_TRANSFER_STEP>0 (call count tracked in TRANSFER_STATE), so the second
    # sample exceeds the first — the real-traffic signal the self-check observes.
    if [[ "${1:-}" == "show" && "${3:-}" == "transfer" ]]; then
      step="${MOCK_TRANSFER_STEP:-0}"; n=0
      if [[ -n "${TRANSFER_STATE:-}" ]]; then
        n="$(cat "$TRANSFER_STATE" 2>/dev/null || echo 0)"
        echo "$((n + 1))" > "$TRANSFER_STATE"
      fi
      val="$(( 1000 + step * n ))"
      printf 'CLIENTPUBKEY\t%s\t%s\n' "$val" "$val"
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

# `systemctl cat <unit>` decides whether the MTProto egress step runs. The mock
# reports the unit present only when MOCK_MTPROXY_PRESENT=1 (absent by default), so
# the proxy step is exercised on demand and stays a safe no-op otherwise.
_MOCK_SYSTEMCTL = textwrap.dedent(
    r"""
    #!/bin/bash
    printf 'systemctl %s\n' "$*" >> "$CMD_LOG"
    if [[ "${1:-}" == "cat" ]]; then
      [[ "${MOCK_MTPROXY_PRESENT:-0}" == "1" ]] && exit 0 || exit 1
    fi
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
        ("systemctl", _MOCK_SYSTEMCTL),
    ):
        p = bindir / name
        p.write_text(body, encoding="utf-8")
        p.chmod(0o755)
    return bindir


# A WARP config whose [Interface] Address is the tunnel IP the proxy egress is
# sourced from. The helper reads it at runtime — never hardcoded.
_WARP_CONFIG = textwrap.dedent(
    """\
    [Interface]
    PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    Address = 172.16.0.2/32
    Table = auto

    [Peer]
    PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
    Endpoint = 162.159.195.1:2408
    AllowedIPs = 0.0.0.0/0
    """
)


def _run_routes(
    tmp_path: Path,
    action: str,
    *,
    initial_rules: str = "",
    fwmark: str = "0xca6c",
    endpoint: str = "162.159.195.1",
    warp_config: str | None = None,
    mtproxy_present: bool = False,
    extra_env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    bindir = _make_bin(tmp_path)
    cmd_log = tmp_path / "cmd.log"
    ip_rules = tmp_path / "rules"
    ip_rules.write_text(initial_rules, encoding="utf-8")
    # WARP_CONFIG always points inside tmp_path; the file exists only when a fixture
    # is supplied, so by default tunnel_ip resolves empty and the proxy step is a
    # no-op (matching a host that has not enabled proxy egress).
    warp_config_path = tmp_path / "out-warp.conf"
    if warp_config is not None:
        warp_config_path.write_text(warp_config, encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "CMD_LOG": str(cmd_log),
        "IP_RULES": str(ip_rules),
        "MOCK_FWMARK": fwmark,
        "MOCK_ENDPOINT": endpoint,
        "WARP_CONFIG": str(warp_config_path),
        "MOCK_MTPROXY_PRESENT": "1" if mtproxy_present else "0",
        **(extra_env or {}),
    }
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "vpn-bot-warp-routes"), action, "out-warp"],
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
        ["bash", str(SCRIPTS / "vpn-bot-warp-routes"), "add", "out-warp"],
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


# ── self-check: conntrack-mark data plane (real traffic, not `ip route get`) ───


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_self_check_passes_on_conntrack_false_negative(tmp_path: Path) -> None:
    """The exact production regression. The client mark is set from CONNTRACK, so a
    stateless `ip route get … iif` mis-reports the client path as ``eth0`` even
    though real client traffic IS riding out-warp (its byte counters grow). The
    counter-based self-check must PASS (rc 0, no rollback) instead of tearing down
    working routing. A return to the ip-route-get client probe would resolve the
    (mocked) path to eth0 and fail this assertion — that is the regression guard."""
    rc, log, stderr = _run_routes(
        tmp_path,
        "add",
        initial_rules=_INITIAL_RULES,
        warp_config=_WARP_CONFIG,
        extra_env={
            # A live client (handshake 10s ago): there IS traffic to observe.
            "MOCK_HANDSHAKE_AGE": "10",
            # out-warp byte counters grow across the two samples → egress via tunnel.
            "MOCK_TRANSFER_STEP": "500",
            "TRANSFER_STATE": str(tmp_path / "transfer.state"),
            # The stateless client-path simulation would (wrongly) resolve to eth0…
            "MOCK_ROUTE_GET_CLIENT_DEV": "eth0",
            # …and keep the two-sample probe instant.
            "SELF_CHECK_INTERVAL": "0",
        },
    )
    assert rc == 0, stderr
    assert "rolling back" not in stderr
    # The pass came from OBSERVED counter growth, not a route-get simulation.
    assert "counters grew" in stderr
    assert "awg show out-warp transfer" in log


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_self_check_skips_data_plane_without_clients(tmp_path: Path) -> None:
    """No live client (no recent handshake) → nothing to measure, so the data-plane
    check SKIPS and the unit stays active. Absence of traffic is not a breakage."""
    rc, _, stderr = _run_routes(
        tmp_path,
        "add",
        initial_rules=_INITIAL_RULES,
        warp_config=_WARP_CONFIG,
        # No MOCK_HANDSHAKE_AGE → have_active_clients is false.
        extra_env={"SELF_CHECK_INTERVAL": "0"},
    )
    assert rc == 0, stderr
    assert "rolling back" not in stderr
    assert "skipping data-plane check" in stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_self_check_still_fails_when_host_is_tunneled(tmp_path: Path) -> None:
    """The host-safety teeth remain: if the host's OWN egress resolves to out-warp
    (SSH would be tunneled) the self-check fails and rolls back to direct egress."""
    rc, log, stderr = _run_routes(
        tmp_path,
        "add",
        initial_rules=_INITIAL_RULES,
        warp_config=_WARP_CONFIG,
        extra_env={"MOCK_HOST_IN_TUNNEL": "1", "SELF_CHECK_INTERVAL": "0"},
    )
    assert rc != 0
    assert "host egress is inside the WARP tunnel" in stderr
    assert "rolling back" in stderr
    # Rollback restored the direct client MASQUERADE.
    assert "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE" in log


# ── routes helper: del reverses the proxy egress ──────────────────────────────


def test_routes_del_reverses_proxy_routing() -> None:
    """teardown removes the proxy egress (it calls remove_proxy_routing)."""
    text = _routes_text()
    teardown = text[text.index("teardown_client_routing() {") : text.index("# Self-check")]
    assert 'remove_proxy_routing "$t"' in teardown
    # remove_proxy_routing tears down SNAT, cgroup-mark and both policy rules, safely.
    remove = text[text.index("remove_proxy_routing() {") :]
    remove = remove[: remove.index("\n}\n")]
    assert '-m mark --mark "$MTPROTO_MARK" -j SNAT --to-source "$tip"' in remove
    assert 'iptables -t mangle -D OUTPUT -m cgroup --path "$cgpath"' in remove
    assert 'ip -4 rule del fwmark "$MTPROTO_MARK"' in remove
    assert 'ip -4 rule del from "$tip"' in remove
    # Every deletion swallows "rule not present" so del is safe on a clean system.
    for line in remove.splitlines():
        s = line.strip()
        if s.startswith("iptables") and "-D" in s:
            assert "2>/dev/null" in s and "true" in s


# ── functional: proxy egress against mocked ip/awg/iptables/systemctl ──────────


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_add_applies_proxy_routing(tmp_path: Path) -> None:
    """With a tunnel IP + an mtproxy unit, add installs the full proxy egress recipe."""
    rc, log, stderr = _run_routes(
        tmp_path, "add", initial_rules=_INITIAL_RULES, warp_config=_WARP_CONFIG, mtproxy_present=True
    )
    assert rc == 0, stderr
    # Source-bind proxies: one rule, src == tunnel IP, no NAT, prio above the client rule.
    assert "ip -4 rule add from 172.16.0.2 lookup 51820 priority 999" in log
    # MTProto: fwmark rule + cgroup-mark + explicit SNAT to the tunnel IP.
    assert "ip -4 rule add fwmark 0x2 lookup 51820 priority 998" in log
    assert (
        "iptables -t mangle -A OUTPUT -m cgroup --path system.slice/mtproxy.service "
        "-j MARK --set-mark 0x2" in log
    )
    # SNAT INSERTED at position 1 (above the appended broad masquerade).
    assert (
        "iptables -t nat -I POSTROUTING 1 -o out-warp -m mark --mark 0x2 "
        "-j SNAT --to-source 172.16.0.2" in log
    )
    assert "iptables -t nat -A POSTROUTING -o out-warp -j MASQUERADE" in log
    # The host stays direct (self-check passed → rc 0, no rollback).
    assert "rolling back" not in stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_add_proxy_egress_safe_without_mtproxy(tmp_path: Path) -> None:
    """No mtproxy unit → only the source-bind rule is added; MTProto step is skipped."""
    rc, log, stderr = _run_routes(
        tmp_path, "add", initial_rules=_INITIAL_RULES, warp_config=_WARP_CONFIG, mtproxy_present=False
    )
    assert rc == 0, stderr
    # Source-bind proxies (Dante/Xray) still work...
    assert "ip -4 rule add from 172.16.0.2 lookup 51820 priority 999" in log
    # ...but no MTProto cgroup-mark / fwmark rule / SNAT is installed.
    assert "fwmark 0x2" not in log
    assert "cgroup" not in log
    assert "SNAT" not in log


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_add_proxy_routing_is_idempotent(tmp_path: Path) -> None:
    """Re-running add over already-applied proxy state adds no duplicate ip rules."""
    rc1, _, err1 = _run_routes(
        tmp_path, "add", initial_rules=_INITIAL_RULES, warp_config=_WARP_CONFIG, mtproxy_present=True
    )
    assert rc1 == 0, err1
    rules_after = (tmp_path / "rules").read_text(encoding="utf-8")
    assert rules_after.count("from 172.16.0.2 lookup 51820") == 1
    assert rules_after.count("fwmark 0x2 lookup 51820") == 1

    bindir = tmp_path / "bin"
    proc = subprocess.run(
        ["bash", str(SCRIPTS / "vpn-bot-warp-routes"), "add", "out-warp"],
        env={
            **os.environ,
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "CMD_LOG": str(tmp_path / "cmd2.log"),
            "IP_RULES": str(tmp_path / "rules"),
            "MOCK_FWMARK": "0xca6c",
            "MOCK_ENDPOINT": "162.159.195.1",
            "WARP_CONFIG": str(tmp_path / "out-warp.conf"),
            "MOCK_MTPROXY_PRESENT": "1",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    rules_after2 = (tmp_path / "rules").read_text(encoding="utf-8")
    assert rules_after2.count("from 172.16.0.2 lookup 51820") == 1
    assert rules_after2.count("fwmark 0x2 lookup 51820") == 1


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")
def test_functional_proxy_del_reverses_and_is_safe(tmp_path: Path) -> None:
    """proxy-del (and del) remove every proxy rule; safe on a clean system."""
    applied = (
        _APPLIED_RULES
        + "RULE -4 from 172.16.0.2 lookup 51820 priority 999\n"
        + "RULE -4 fwmark 0x2 lookup 51820 priority 998\n"
    )
    work = tmp_path / "applied"
    work.mkdir()
    rc, log, err = _run_routes(
        work, "proxy-del", initial_rules=applied, warp_config=_WARP_CONFIG, mtproxy_present=True
    )
    assert rc == 0, err
    assert (
        "iptables -t nat -D POSTROUTING -o out-warp -m mark --mark 0x2 "
        "-j SNAT --to-source 172.16.0.2" in log
    )
    assert (
        "iptables -t mangle -D OUTPUT -m cgroup --path system.slice/mtproxy.service "
        "-j MARK --set-mark 0x2" in log
    )
    assert "ip -4 rule del fwmark 0x2 priority 998" in log
    assert "ip -4 rule del from 172.16.0.2 priority 999" in log
    rules_after = (work / "rules").read_text(encoding="utf-8")
    assert "from 172.16.0.2" not in rules_after
    assert "fwmark 0x2" not in rules_after

    # proxy-del on a clean system (no config, no rules) is a safe no-op.
    clean = tmp_path / "clean"
    clean.mkdir()
    rc2, _, err2 = _run_routes(clean, "proxy-del", initial_rules="", fwmark="off", endpoint="")
    assert rc2 == 0, err2


# ── Xray config generator: sendThrough emitted only when WARP egress is on ─────


def _freedom_config() -> dict:
    """A hybrid-build config: REALITY vless-in + freedom/blackhole outbounds."""
    return {
        "inbounds": [
            {
                "tag": "vless-in",
                "protocol": "vless",
                "settings": {"clients": []},
                "streamSettings": {"security": "reality", "realitySettings": {"shortIds": []}},
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
    }


def test_xray_send_through_emitted_when_warp_on() -> None:
    from adapters.xray_config import apply_warp_send_through

    config = _freedom_config()
    assert apply_warp_send_through(config, "172.16.0.2") is True
    freedom = config["outbounds"][0]
    assert freedom["sendThrough"] == "172.16.0.2"
    # Idempotent: a second pass with the same IP changes nothing.
    assert apply_warp_send_through(config, "172.16.0.2") is False


def test_xray_send_through_absent_when_warp_off() -> None:
    from adapters.xray_config import apply_warp_send_through

    config = _freedom_config()
    # Off / non-WARP deploy: nothing is added.
    assert apply_warp_send_through(config, None) is False
    assert "sendThrough" not in config["outbounds"][0]
    # And a previously-set value is stripped when WARP is turned off.
    config["outbounds"][0]["sendThrough"] = "172.16.0.2"
    assert apply_warp_send_through(config, None) is True
    assert "sendThrough" not in config["outbounds"][0]


def test_xray_send_through_only_touches_freedom_outbound() -> None:
    from adapters.xray_config import apply_warp_send_through

    config = _freedom_config()
    apply_warp_send_through(config, "172.16.0.2")
    # The blackhole outbound and the (REALITY) inbound are never touched.
    assert "sendThrough" not in config["outbounds"][1]
    assert "sendThrough" not in config["inbounds"][0]
    assert "sendThrough" not in config["inbounds"][0]["streamSettings"]
    # No outbounds key at all → safe no-op.
    assert apply_warp_send_through({"inbounds": []}, "172.16.0.2") is False


def test_read_tunnel_address_from_interface_address(tmp_path: Path) -> None:
    from warp.proxy_egress import make_send_through_provider, read_tunnel_address

    conf = tmp_path / "out-warp.conf"
    conf.write_text(_WARP_CONFIG, encoding="utf-8")
    assert read_tunnel_address(conf) == "172.16.0.2"
    # Missing file / IPv6-only address → None (no egress source to bind).
    assert read_tunnel_address(tmp_path / "nope.conf") is None
    (tmp_path / "v6.conf").write_text("[Interface]\nAddress = fd00::2/128\n", encoding="utf-8")
    assert read_tunnel_address(tmp_path / "v6.conf") is None

    # P8-011: a dual-stack Address with IPv6 listed FIRST must still yield the IPv4
    # tunnel IP (scan all tokens), not silently disable egress and leak the real IP.
    (tmp_path / "dual.conf").write_text(
        "[Interface]\nAddress = fd00::2/128, 172.16.0.2/32\n", encoding="utf-8"
    )
    assert read_tunnel_address(tmp_path / "dual.conf") == "172.16.0.2"

    # The provider gates on the enabled flag and reads the tunnel IP live.
    assert make_send_through_provider(enabled=True, config_path=conf)() == "172.16.0.2"
    assert make_send_through_provider(enabled=False, config_path=conf)() is None


def test_wan_network_uses_default_route_iface(monkeypatch) -> None:
    """P8-012: the SSH-subnet guard follows the default-route interface, not a
    hardcoded eth0, so modern predictable names (ens3/enp1s0) keep the guard."""
    import ipaddress

    from warp import split_manager

    monkeypatch.setattr(split_manager, "_default_route_iface", lambda: "ens3")
    monkeypatch.setattr(
        split_manager,
        "_iface_network",
        lambda iface: ipaddress.IPv4Network("192.168.0.0/24") if iface == "ens3" else None,
    )
    assert split_manager._wan_network() == (ipaddress.IPv4Network("192.168.0.0/24"), "ens3")


def test_default_route_iface_parses_proc_net_route(monkeypatch, tmp_path: Path) -> None:
    """_default_route_iface picks the row whose destination and mask are both zero."""
    from warp import split_manager

    proc_route = (
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "enp1s0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        "enp1s0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    )
    fake = tmp_path / "route"
    fake.write_text(proc_route, encoding="utf-8")

    class _FakePath:
        def __init__(self, *_a, **_k) -> None:
            pass

        def read_text(self, encoding: str = "utf-8") -> str:
            return fake.read_text(encoding=encoding)

    monkeypatch.setattr(split_manager, "Path", _FakePath)
    assert split_manager._default_route_iface() == "enp1s0"


async def test_xray_adapter_writes_send_through_only_when_provider_set(tmp_path: Path) -> None:
    """End-to-end: a config write emits sendThrough when WARP egress is enabled."""
    import json

    from adapters.backup import BackupAdapter
    from adapters.clock import ClockProvider
    from adapters.xray_config import XrayConfigAdapter
    from models.dto import ShellResult

    class _Systemctl:
        async def xray_test_config(self, path: Path) -> ShellResult:
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "-test"), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "reload", service_name), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    def _adapter(send_through):
        return XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="reload",
            inbound_tag="vless-in",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider(), keep_last=0),
            systemctl=_Systemctl(),  # type: ignore[arg-type]
            warp_send_through=send_through,
        )

    config_path = tmp_path / "config.json"

    # WARP on: the freedom outbound is bound to the tunnel IP after a client write.
    config_path.write_text(json.dumps(_freedom_config()), encoding="utf-8")
    await _adapter(lambda: "172.16.0.2").add_client(
        uuid_value="11111111-1111-1111-1111-111111111111",
        email_label="user1",
        short_id="",
        flow="",
        manage_short_id=False,
    )
    written = json.loads(config_path.read_text(encoding="utf-8"))
    assert written["outbounds"][0]["sendThrough"] == "172.16.0.2"
    assert "sendThrough" not in written["outbounds"][1]

    # WARP off (no provider): the freedom outbound is left clean.
    config_path.write_text(json.dumps(_freedom_config()), encoding="utf-8")
    await _adapter(None).add_client(
        uuid_value="22222222-2222-2222-2222-222222222222",
        email_label="user2",
        short_id="",
        flow="",
        manage_short_id=False,
    )
    written_off = json.loads(config_path.read_text(encoding="utf-8"))
    assert "sendThrough" not in written_off["outbounds"][0]
