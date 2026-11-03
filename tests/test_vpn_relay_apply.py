"""scripts/vpn-relay-apply — the data plane of an L4 relay host (NODE_ROLE=relay).

What is pinned here, all by running the real shipped script:

1. **1:1 with the hand-made relay.** For 443/443 and the captured upstream the
   rendered file is byte-identical to the ruleset captured from the live relay
   (tests/fixtures/relay/vpn-relay.nft, /etc/vpn-relay.nft on 2026-11-03), whether
   the WAN interface comes from RELAY_WAN_IFACE or from the default route.
2. **Port lists.** Comma-separated, de-duplicated, sorted, one DNAT rule per port,
   each forwarded to the SAME port on the upstream.
3. **Fail-closed validation.** Every bad value exits 3 (4 for an unresolvable
   interface) before anything is rendered, let alone applied.
4. **INPUT/OUTPUT are never touched**: no `hook input` / `hook output` in any
   rendered ruleset or anywhere in the script.
5. **apply** is one `nft -f` of the rendered file and only then forwarding; a
   rejected ruleset leaves forwarding alone.
6. **check** compares the live table with the render (counters ignored), checks
   ip_forward, TCP-connects every forwarded TCP port and, when RELAY_CHECK_SNI is
   set, does a verified TLS handshake on 443 — each failure with its own exit code.
7. The Python probe itself, against real local TCP and TLS listeners.

External commands (`nft`, `sysctl`, `id`, `ip`, `python3` for the probes) are stubs
on PATH, except in the probe tests, which run the embedded probe for real.
"""

from __future__ import annotations

import datetime
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpn-relay-apply"
FIXTURES = ROOT / "tests" / "fixtures" / "relay"
CAPTURED_RULESET = FIXTURES / "vpn-relay.nft"
# `nft list table ip vpnrelay` of that ruleset as nft 1.0.9 (Ubuntu 24.04) prints it:
# tabs, blank lines between chains, live counters. Format verified by loading the
# captured file into a scratch network namespace and listing it.
LIVE_LISTING = FIXTURES / "nft-list-live.txt"

UPSTREAM = "150.251.152.243"
# `ip -4 route show default` on the live relay (one interface, eth0).
DEFAULT_ROUTE = "default via 191.223.140.1 dev eth0 proto static\n"

pytestmark = pytest.mark.timeout(60)


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


class Relay:
    """A sandbox for one helper run: .env, stubs on PATH, call logs."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.env_file = tmp_path / "relay.env"
        self.sysctl_file = tmp_path / "90-vpn-relay.conf"
        self.log = tmp_path / "calls.log"
        self.nft_input = tmp_path / "nft-input.nft"
        self.uid = "0"
        self.default_route = DEFAULT_ROUTE
        self.live_listing: str | None = LIVE_LISTING.read_text(encoding="utf-8")
        self.forward = "1"
        self.nft_rc = 0
        self.tcp_rc = 0
        self.tls_rc = 0

    def write_env(self, text: str) -> None:
        self.env_file.write_text(text, encoding="utf-8")

    def _install_stubs(self) -> None:
        log = self.log
        _stub(self.bin / "id", f'[[ "$1" == "-u" ]] && echo {self.uid}\n')
        route = self.tmp / "route.txt"
        route.write_text(self.default_route, encoding="utf-8")
        _stub(self.bin / "ip", f'echo "ip $*" >> "{log}"\ncat "{route}"\n')
        listing = self.tmp / "listing.txt"
        if self.live_listing is not None:
            listing.write_text(self.live_listing, encoding="utf-8")
        _stub(
            self.bin / "nft",
            f'echo "nft $*" >> "{log}"\n'
            'case "$1" in\n'
            f'  -f) cp "$2" "{self.nft_input}"; exit {self.nft_rc} ;;\n'
            f'  -c) cp "$3" "{self.nft_input}"; exit {self.nft_rc} ;;\n'
            f'  list) [[ -f "{listing}" ]] && cat "{listing}" && exit 0; exit 1 ;;\n'
            "esac\n",
        )
        _stub(
            self.bin / "sysctl",
            f'echo "sysctl $*" >> "{log}"\n'
            f'if [[ "$1" == "-n" ]]; then echo {self.forward}; fi\n',
        )
        # The probes run as `python3 -I -c <code> <mode> <host> <port> <timeout> [sni]`.
        _stub(
            self.bin / "python3",
            f'echo "probe $4 $5 $6${{8:+ $8}}" >> "{log}"\n'
            f'if [[ "$4" == "tls" ]]; then exit {self.tls_rc}; fi\n'
            f"exit {self.tcp_rc}\n",
        )

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        self._install_stubs()
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        env["RELAY_ENV"] = str(self.env_file)
        env["RELAY_SYSCTL_FILE"] = str(self.sysctl_file)
        return subprocess.run(
            ["bash", str(HELPER), *args], env=env, capture_output=True, text=True, check=False
        )

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


@pytest.fixture
def relay(tmp_path: Path) -> Relay:
    r = Relay(tmp_path)
    r.write_env(f"NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4={UPSTREAM}\n")
    return r


# --------------------------------------------------------------------------- #
# Structure
# --------------------------------------------------------------------------- #
def test_helper_is_executable_strict_bash() -> None:
    assert os.access(HELPER, os.X_OK), "git mode must be 0755 (it is installed with 0755)"
    text = HELPER.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_helper_never_names_an_input_or_output_hook() -> None:
    """The relay's INPUT (SSH :22) and OUTPUT are not this helper's business. Code
    only: the header comment says exactly this in words."""
    code = "\n".join(
        ln for ln in HELPER.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")
    )
    assert "printf" in code and "chain relayfwd" in code, "comment filter ate the code"
    assert not re.search(r"hook\s+(input|output)", code)


@pytest.mark.parametrize("args", [(), ("bogus",), ("apply", "x"), ("check", "--wet"), ("show", "x")])
def test_usage_errors_exit_2(relay: Relay, args: tuple[str, ...]) -> None:
    assert relay.run(*args).returncode == 2


# --------------------------------------------------------------------------- #
# Rendering: 1:1 with the captured relay
# --------------------------------------------------------------------------- #
def test_render_for_443_is_byte_identical_to_the_captured_ruleset(relay: Relay) -> None:
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == CAPTURED_RULESET.read_text(encoding="utf-8")


def test_explicit_defaults_and_explicit_iface_render_the_same_file(relay: Relay) -> None:
    relay.write_env(
        f"NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4={UPSTREAM}\n"
        "RELAY_FORWARD_TCP_PORTS=443\nRELAY_FORWARD_UDP_PORTS=443\nRELAY_WAN_IFACE=eth0\n"
    )
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == CAPTURED_RULESET.read_text(encoding="utf-8")
    assert not any(c.startswith("ip ") for c in relay.calls()), "RELAY_WAN_IFACE wins over detection"


def test_render_is_atomic_replace_of_one_table(relay: Relay) -> None:
    lines = relay.run("show").stdout.splitlines()
    assert lines[:3] == ["table ip vpnrelay", "delete table ip vpnrelay", "table ip vpnrelay {"]
    assert sum(1 for ln in lines if ln.startswith("table ")) == 2
    assert all("vpnrelay" in ln for ln in lines if ln.startswith(("table", "delete")))


def test_the_interface_comes_from_the_default_route(relay: Relay) -> None:
    relay.default_route = "default via 10.0.0.1 dev ens3 proto dhcp src 10.0.0.5 metric 100\n"
    out = relay.run("show").stdout
    assert 'iifname "ens3" tcp dport 443' in out
    assert 'oifname "ens3" ip daddr' in out
    assert '"eth0"' not in out


@pytest.mark.parametrize(
    "routes",
    [
        "",  # no IPv4 default route
        "default via 10.0.0.1 dev ens3\ndefault via 10.1.0.1 dev ens4 metric 200\n",
    ],
)
def test_an_ambiguous_default_route_is_refused(relay: Relay, routes: str) -> None:
    relay.default_route = routes
    proc = relay.run("show")
    assert proc.returncode == 4, proc.stderr
    assert "RELAY_WAN_IFACE" in proc.stderr
    assert proc.stdout == ""


def test_two_default_routes_through_one_interface_are_fine(relay: Relay) -> None:
    relay.default_route = "default via 10.0.0.1 dev eth0\ndefault via 10.0.0.2 dev eth0 metric 50\n"
    assert relay.run("show").returncode == 0


# --------------------------------------------------------------------------- #
# Port lists
# --------------------------------------------------------------------------- #
def _dnat_rules(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if " dnat to " in ln]


def test_port_lists_render_one_rule_per_port_forwarded_1_to_1(relay: Relay) -> None:
    relay.write_env(
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n"
        "RELAY_FORWARD_TCP_PORTS=443,2096\nRELAY_FORWARD_UDP_PORTS=443,8443\n"
    )
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert _dnat_rules(proc.stdout) == [
        f'iifname "eth0" tcp dport 443 counter dnat to {UPSTREAM}:443',
        f'iifname "eth0" tcp dport 2096 counter dnat to {UPSTREAM}:2096',
        f'iifname "eth0" udp dport 443 counter dnat to {UPSTREAM}:443',
        f'iifname "eth0" udp dport 8443 counter dnat to {UPSTREAM}:8443',
    ]


def test_port_lists_are_sorted_and_deduplicated(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS= 2096 , 443,443 \n")
    a = relay.run("show").stdout
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=443,2096\n")
    b = relay.run("show").stdout
    assert a == b
    assert [r for r in _dnat_rules(a) if " tcp " in r] == [
        f'iifname "eth0" tcp dport 443 counter dnat to {UPSTREAM}:443',
        f'iifname "eth0" tcp dport 2096 counter dnat to {UPSTREAM}:2096',
    ]


def test_masquerade_and_forward_accept_follow_the_upstream_not_the_ports(relay: Relay) -> None:
    relay.write_env("RELAY_UPSTREAM_IPV4=198.51.100.7\nRELAY_FORWARD_TCP_PORTS=443,2096\n")
    out = relay.run("show").stdout
    assert out.count("masquerade") == 1
    assert 'oifname "eth0" ip daddr 198.51.100.7 ct status dnat counter masquerade' in out
    assert "ct status dnat ip daddr 198.51.100.7 accept" in out
    assert "type filter hook forward priority filter; policy drop;" in out
    assert "tcp flags syn tcp option maxseg size set rt mtu" in out


@pytest.mark.parametrize(
    "env",
    [
        "RELAY_FORWARD_TCP_PORTS=443,2096\nRELAY_FORWARD_UDP_PORTS=443,8443,51820\n",
        "RELAY_WAN_IFACE=ens3\nRELAY_FORWARD_TCP_PORTS=1,65535\n",
        "",
    ],
)
def test_no_rendered_ruleset_has_an_input_or_output_hook(relay: Relay, env: str) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n{env}")
    out = relay.run("show").stdout
    assert out, "render failed"
    hooks = re.findall(r"hook\s+(\w+)", out)
    assert hooks == ["prerouting", "postrouting", "forward"]


# --------------------------------------------------------------------------- #
# .env parsing (same sed parser as deploy.sh / vpnbot-hy2-warp-mark)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "line",
    [
        f'RELAY_UPSTREAM_IPV4="{UPSTREAM}"',
        f"RELAY_UPSTREAM_IPV4='{UPSTREAM}'",
        f"  export RELAY_UPSTREAM_IPV4 = {UPSTREAM}   # the main server",
        f'RELAY_UPSTREAM_IPV4="{UPSTREAM}"  # quoted + comment',
        f"RELAY_UPSTREAM_IPV4=192.0.2.1\nRELAY_UPSTREAM_IPV4={UPSTREAM}",  # last wins
        f"# RELAY_UPSTREAM_IPV4=192.0.2.1\nRELAY_UPSTREAM_IPV4={UPSTREAM}",  # comment ignored
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\r",  # CRLF file
    ],
)
def test_env_syntax_variants_resolve_the_same_upstream(relay: Relay, line: str) -> None:
    relay.write_env(line + "\n")
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == CAPTURED_RULESET.read_text(encoding="utf-8")


def test_an_empty_port_value_means_the_default(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=\nRELAY_FORWARD_UDP_PORTS= # none\n")
    assert relay.run("show").stdout == CAPTURED_RULESET.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Fail-closed validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "env",
    [
        "",  # upstream missing
        "RELAY_UPSTREAM_IPV4=\n",
        "RELAY_UPSTREAM_IPV4=256.1.1.1\n",
        "RELAY_UPSTREAM_IPV4=01.2.3.4\n",
        "RELAY_UPSTREAM_IPV4=1.2.3\n",
        "RELAY_UPSTREAM_IPV4=127.0.0.1\n",
        "RELAY_UPSTREAM_IPV4=0.1.2.3\n",
        "RELAY_UPSTREAM_IPV4=224.0.0.1\n",
        "RELAY_UPSTREAM_IPV4=255.255.255.255\n",
        "RELAY_UPSTREAM_IPV4=2001:db8::1\n",
        "RELAY_UPSTREAM_IPV4=main.example.com\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=0\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=65536\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=0443\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=443,\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=,443\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=443,,2096\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=443;2096\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=443-450\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_UDP_PORTS=https\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_UDP_PORTS=4 43\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_WAN_IFACE=eth 0\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_WAN_IFACE=averyveryverylongname\n",
        f'RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_WAN_IFACE=eth0"\n',
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CHECK_SNI=bad_host\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CHECK_SNI=-x.example.com\n",
    ],
)
def test_invalid_values_are_refused_before_anything_renders(relay: Relay, env: str) -> None:
    relay.write_env(env)
    for args in (("show",), ("check", "--dry-run"), ("apply",)):
        proc = relay.run(*args)
        assert proc.returncode == 3, (args, proc.stdout, proc.stderr)
        assert "table ip" not in proc.stdout
    assert not any(c.startswith("nft") for c in relay.calls()), "nothing may reach nft"
    assert not any(c.startswith("sysctl") for c in relay.calls()), "forwarding untouched"


def test_a_missing_env_file_is_refused(relay: Relay) -> None:
    relay.env_file.unlink()
    proc = relay.run("show")
    assert proc.returncode == 3
    assert "relay.env.example" in proc.stderr


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #
def test_apply_is_one_nft_transaction_then_forwarding(relay: Relay) -> None:
    proc = relay.run("apply")
    assert proc.returncode == 0, proc.stderr
    calls = relay.calls()
    nft_calls = [c for c in calls if c.startswith("nft")]
    assert len(nft_calls) == 1 and nft_calls[0].startswith("nft -f ")
    assert relay.nft_input.read_text(encoding="utf-8") == CAPTURED_RULESET.read_text(encoding="utf-8")
    sysctl_calls = [c for c in calls if c.startswith("sysctl")]
    assert sysctl_calls == ["sysctl -q -w net.ipv4.ip_forward=1"]
    assert calls.index(nft_calls[0]) < calls.index(sysctl_calls[0]), (
        "forwarding goes on only after the forward chain (policy drop) is in place"
    )
    assert relay.sysctl_file.read_text(encoding="utf-8") == "net.ipv4.ip_forward = 1\n"
    assert oct(relay.sysctl_file.stat().st_mode & 0o777) == "0o644"


def test_apply_leaves_an_identical_sysctl_file_alone(relay: Relay) -> None:
    relay.sysctl_file.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    inode = relay.sysctl_file.stat().st_ino
    assert relay.run("apply").returncode == 0
    assert relay.sysctl_file.stat().st_ino == inode, "the captured host file must stay as it is"


def test_a_rejected_ruleset_leaves_forwarding_alone(relay: Relay) -> None:
    relay.nft_rc = 1
    proc = relay.run("apply")
    assert proc.returncode == 6, proc.stderr
    assert "unchanged" in proc.stderr
    assert not any(c.startswith("sysctl") for c in relay.calls())
    assert not relay.sysctl_file.exists()


def test_apply_requires_root(relay: Relay) -> None:
    relay.uid = "1000"
    proc = relay.run("apply")
    assert proc.returncode == 5
    assert relay.calls() == []


# --------------------------------------------------------------------------- #
# check --dry-run (deploy.sh Phase 1)
# --------------------------------------------------------------------------- #
def test_dry_run_as_root_syntax_checks_and_applies_nothing(relay: Relay) -> None:
    proc = relay.run("check", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert [c.split()[:2] for c in relay.calls() if c.startswith("nft")] == [["nft", "-c"]]
    assert relay.nft_input.read_text(encoding="utf-8") == CAPTURED_RULESET.read_text(encoding="utf-8")
    assert not any(c.startswith(("sysctl", "probe")) for c in relay.calls())
    assert "nothing applied" in proc.stdout


def test_dry_run_reports_an_nft_rejection(relay: Relay) -> None:
    relay.nft_rc = 1
    assert relay.run("check", "--dry-run").returncode == 6


def test_dry_run_without_root_still_validates_and_renders(relay: Relay) -> None:
    relay.uid = "1000"
    proc = relay.run("check", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert "nft -c skipped" in proc.stdout
    assert not any(c.startswith("nft") for c in relay.calls())


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #
def test_check_passes_on_the_live_relay(relay: Relay) -> None:
    """The live listing (tabs, blank lines, growing counters) equals the render."""
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check OK" in proc.stdout
    assert "probe tcp 150.251.152.243 443" in relay.calls()
    assert not any(c.startswith("probe tls") for c in relay.calls()), "no SNI -> no handshake"
    assert "RELAY_CHECK_SNI not set" in proc.stdout


def test_check_is_read_only(relay: Relay) -> None:
    relay.run("check")
    assert [c for c in relay.calls() if c.startswith("nft")] == ["nft list table ip vpnrelay"]
    assert [c for c in relay.calls() if c.startswith("sysctl")] == ["sysctl -n net.ipv4.ip_forward"]
    assert not relay.sysctl_file.exists()


def test_check_absent_table_is_10(relay: Relay) -> None:
    relay.live_listing = None
    proc = relay.run("check")
    assert proc.returncode == 10
    assert "absent" in proc.stderr


def test_check_different_table_is_11_with_a_diff(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=443,2096\n")
    proc = relay.run("check")
    assert proc.returncode == 11
    assert "+iifname \"eth0\" tcp dport 2096 counter dnat to 150.251.152.243:2096" in proc.stderr


def test_check_forwarding_off_is_12(relay: Relay) -> None:
    relay.forward = "0"
    assert relay.run("check").returncode == 12


def test_check_unreachable_upstream_is_13(relay: Relay) -> None:
    relay.tcp_rc = 1
    assert relay.run("check").returncode == 13


def test_check_probes_every_forwarded_tcp_port(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=443,2096\n")
    relay.live_listing = LIVE_LISTING.read_text(encoding="utf-8").replace(
        "\t\tiifname \"eth0\" udp",
        "\t\tiifname \"eth0\" tcp dport 2096 counter packets 1 bytes 60 dnat to 150.251.152.243:2096\n"
        "\t\tiifname \"eth0\" udp",
    )
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stderr
    probes = [c for c in relay.calls() if c.startswith("probe")]
    assert probes == [f"probe tcp {UPSTREAM} 443", f"probe tcp {UPSTREAM} 2096"]


def test_check_tls_handshake_uses_the_configured_sni(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CHECK_SNI=www.example.com\n")
    assert relay.run("check").returncode == 0
    assert f"probe tls {UPSTREAM} 443 www.example.com" in relay.calls()


def test_check_failed_tls_handshake_is_14(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CHECK_SNI=www.example.com\n")
    relay.tls_rc = 1
    assert relay.run("check").returncode == 14


def test_no_tls_handshake_without_tcp_443(relay: Relay) -> None:
    relay.write_env(
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=8443\nRELAY_CHECK_SNI=www.example.com\n"
    )
    relay.run("check")
    assert not any(c.startswith("probe tls") for c in relay.calls())


def test_check_reports_every_failure_and_exits_with_the_first(relay: Relay) -> None:
    relay.live_listing = None
    relay.forward = "0"
    relay.tcp_rc = 1
    proc = relay.run("check")
    assert proc.returncode == 10
    for fragment in ("is absent", "ip_forward = 0", "TCP connect"):
        assert fragment in proc.stderr


def test_check_requires_root(relay: Relay) -> None:
    relay.uid = "1000"
    assert relay.run("check").returncode == 5


# --------------------------------------------------------------------------- #
# The embedded probe, for real
# --------------------------------------------------------------------------- #
def _probe_code() -> str:
    text = HELPER.read_text(encoding="utf-8")
    m = re.search(r"^PROBE_PY='\n(.*?)^'$", text, re.S | re.M)
    assert m, "PROBE_PY block not found"
    return m.group(1)


def _probe(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-c", _probe_code(), *args],
        capture_output=True, text=True, env=env, check=False, timeout=30,
    )


def test_probe_tcp_connects_and_reports_a_refused_port() -> None:
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        assert _probe("tcp", "127.0.0.1", str(port), "3").returncode == 0
    refused = _probe("tcp", "127.0.0.1", str(port), "3")
    assert refused.returncode == 1
    assert "ConnectionRefusedError" in refused.stderr


def _make_ca_and_leaf(tmp: Path, hostname: str) -> tuple[Path, Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "relay-test-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                          crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(ca_name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem, cert_pem, key_pem = tmp / "ca.pem", tmp / "leaf.pem", tmp / "leaf.key"
    ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    )
    return ca_pem, cert_pem, key_pem


def _tls_server(cert: Path, key: Path) -> tuple[socket.socket, int]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


def test_probe_tls_verifies_the_certificate_against_the_sni(tmp_path: Path) -> None:
    ca, cert, key = _make_ca_and_leaf(tmp_path, "decoy.example.test")
    srv, port = _tls_server(cert, key)
    env = {"SSL_CERT_FILE": str(ca), "PATH": os.environ.get("PATH", "")}
    try:
        ok = _probe("tls", "127.0.0.1", str(port), "5", "decoy.example.test", env=env)
        assert ok.returncode == 0, ok.stderr
        assert ok.stdout.startswith("TLS")
        wrong_name = _probe("tls", "127.0.0.1", str(port), "5", "other.example.test", env=env)
        assert wrong_name.returncode == 1
        assert "certificate" in wrong_name.stderr.lower()
        untrusted = _probe("tls", "127.0.0.1", str(port), "5", "decoy.example.test",
                           env={"PATH": os.environ.get("PATH", "")})
        assert untrusted.returncode == 1, "an unverifiable certificate must fail the check"
    finally:
        srv.close()
