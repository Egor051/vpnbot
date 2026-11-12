"""scripts/vpn-relay-apply — the data plane of an L4 relay host (NODE_ROLE=relay).

What is pinned here, all by running the real shipped script:

1. **1:1 with the hand-made relay.** For 443/443 and the captured upstream the
   forwarding table `ip vpnrelay` is byte-identical to the ruleset captured from
   the live relay (tests/fixtures/relay/vpn-relay.nft, /etc/vpn-relay.nft on
   2026-11-03) — in every render and every `nft -f`, whatever the input filter does.
2. **Port lists.** Comma-separated, de-duplicated, sorted, one DNAT rule per port,
   each forwarded to the SAME port on the upstream.
3. **Fail-closed validation.** Every bad value exits 3 (4 for an unresolvable
   interface) before anything is rendered, let alone applied.
4. **Hooks.** The forwarding table has no `input`/`output` hook; the input filter is
   the separate `table inet vpnrelay_input` (one `hook input` chain, policy drop:
   lo, established/related, invalid drop, ICMP, ICMPv6, DHCPv6 client, the SSH ports,
   RELAY_INPUT_EXTRA_*); nothing ever hooks `output`.
5. **SSH ports are discovered, never hardcoded**: `ss -Hltunp` listeners of sshd on a
   non-loopback address, or held by systemd for a port ssh.socket declares. None
   found -> exit 8 and nothing applied.
6. **apply** is one `nft -f` of both tables and only then the sysctls: the file
   /etc/sysctl.d/90-vpn-relay.conf rendered whole (ip_forward + the two conntrack
   values, atomic, only when it differs), then `sysctl -w` of the conntrack values
   and ip_forward last. A missing nf_conntrack_max key gets one `modprobe nf_conntrack`
   and a retry, then exit 7. A rejected ruleset leaves every sysctl alone.
7. **The dead-man.** A TCP port set that is not the confirmed one (no marker, or a
   different hash) arms `systemd-run --on-active=300 --unit=vpn-relay-input-deadman
   <helper> input-off` BEFORE `nft -f` and leaves a pending note; the confirmed set
   arms nothing. input-confirm (from a NEW ssh session only) stops the timer and
   writes the marker; input-off removes only `table inet vpnrelay_input`.
8. **check** compares both live tables with the render (counters ignored), flags a
   port that listens on a public address but is filtered (18), checks ip_forward and
   the conntrack values (15), TCP-connects every forwarded TCP port and, when
   RELAY_CHECK_SNI is set, does a verified TLS handshake on 443 — each failure with
   its own exit code. A conntrack table over 80% full is a warning.
9. The Python probe itself, against real local TCP and TLS listeners.

External commands (`nft`, `sysctl`, `modprobe`, `id`, `ip`, `ss`, `systemctl`,
`systemd-run`, `ps`, `logger`, `python3` for the probes) are stubs on PATH, except in
the probe tests, which run the embedded probe for real. The sysctl stub keeps one file
per key, so a key can be absent (as the net.netfilter.* keys are while nf_conntrack is
not loaded) and a test can read back what apply set; the nft stub keeps the live
`table inet vpnrelay_input` in a file, so apply / input-off / check see one state.
The sandbox pins every RELAY_* override and JOURNAL_STREAM itself: nothing of the
environment the suite runs in (deploy.sh's Phase 1 gate, on the relay) reaches a run.
"""

from __future__ import annotations

import datetime
import hashlib
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
# `nft list table inet vpnrelay_input` of the render for ssh on 22, the same way
# (nft 1.0.9 in a scratch netns; only the counter values edited to non-zero).
INPUT_LIVE_LISTING = FIXTURES / "nft-list-input-live.txt"
# `ss -Hltunp` on the relay: the listeners measured 2026-11-11 (tcp 0.0.0.0:22,
# tcp [::]:22, udp [fe80::...]%eth0:546, resolved on loopback), process column as
# ss prints it while sshd runs behind ssh.socket.
SS_LISTEN = FIXTURES / "ss-listen.txt"

UPSTREAM = "150.251.152.243"
# `ip -4 route show default` on the live relay (one interface, eth0).
DEFAULT_ROUTE = "default via 191.223.140.1 dev eth0 proto static\n"
SOCKET_LISTEN_22 = "Listen=0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)\n"

FORWARD = "net.ipv4.ip_forward"
CT_MAX = "net.netfilter.nf_conntrack_max"
CT_EST = "net.netfilter.nf_conntrack_tcp_timeout_established"
CT_COUNT = "net.netfilter.nf_conntrack_count"
# The rendered /etc/sysctl.d/90-vpn-relay.conf with the .env defaults.
DEFAULT_SYSCTL_FILE = (
    "net.ipv4.ip_forward = 1\n"
    "net.netfilter.nf_conntrack_max = 65536\n"
    "net.netfilter.nf_conntrack_tcp_timeout_established = 86400\n"
)
# What `modprobe nf_conntrack` brings up in the stub: kernel defaults, not .env's.
KERNEL_CT = {CT_MAX: "262144", CT_EST: "432000", CT_COUNT: "0"}

DEADMAN = "vpn-relay-input-deadman"
DEADMAN_TIMER = f"{DEADMAN}.timer"
INPUT_HEAD = (
    "table inet vpnrelay_input\n"
    "delete table inet vpnrelay_input\n"
)
INPUT_RULES_HEAD = (
    "table inet vpnrelay_input {\n"
    "  chain input {\n"
    "    type filter hook input priority filter; policy drop;\n"
    '    iif "lo" accept\n'
    "    ct state established,related accept\n"
    "    ct state invalid drop\n"
    "    ip protocol icmp accept\n"
    "    meta l4proto ipv6-icmp accept\n"
    '    ip6 saddr fe80::/10 udp dport 546 accept comment "dhcpv6 client"\n'
)
INPUT_TAIL = "    counter\n  }\n}\n"
# The input filter of the live relay: ssh on 22, nothing else.
INPUT_RENDER_22 = INPUT_HEAD + INPUT_RULES_HEAD + '    tcp dport 22 accept comment "ssh"\n' + INPUT_TAIL


def input_hash(*tcp: int) -> str:
    """The confirmation hash, computed independently of the helper."""
    text = "vpnrelay_input/1\ntcp " + " ".join(str(p) for p in sorted(set(tcp))) + "\n"
    return hashlib.sha256(text.encode()).hexdigest()


def forward_part(text: str) -> str:
    """The `table ip vpnrelay` part of a rendered file (everything before the input table)."""
    return text.split(INPUT_HEAD, 1)[0]


SYSCTL_STUB = r"""
echo "sysctl $*" >> "@LOG@"
d="@PROC@"
nokey() { echo "sysctl: cannot stat /proc/sys/${1//.//}: No such file or directory" >&2; exit 255; }
if [[ "$1" == "-n" ]]; then
  [[ -f "$d/$2" ]] || nokey "$2"
  cat "$d/$2"; exit 0
fi
kv="${!#}"; k="${kv%%=*}"
[[ -f "$d/$k" ]] || nokey "$k"
[[ -f "$d/$k.ro" ]] && { echo "sysctl: permission denied on key \"$k\"" >&2; exit 255; }
# procps when the write fails at close(2): an error line, the value unchanged, exit 0.
[[ -f "$d/$k.eperm" ]] && { echo "sysctl: setting key \"$k\": Operation not permitted" >&2; exit 0; }
echo "${kv#*=}" > "$d/$k"
"""

MODPROBE_STUB = r"""
echo "modprobe $*" >> "@LOG@"
if [[ "@LOADS@" == "1" && "$*" == "nf_conntrack" ]]; then
  @CREATE@
  exit 0
fi
echo "modprobe: FATAL: Module $* not found in directory /lib/modules/6.8.0-generic" >&2
exit 1
"""

# Every `nft -f` file is kept (numbered) so a test can check all of them; the live
# input table follows what the files do to it.
NFT_STUB = r"""
echo "nft $*" >> "@LOG@"
case "$1" in
  -f)
    n="$(find "@APPLIED@" -type f | wc -l)"
    cp "$2" "@APPLIED@/$(printf '%03d' "$n").nft"
    cp "$2" "@NFT_INPUT@"
    [[ "@RC@" == "0" ]] || exit "@RC@"
    if grep -q '^table inet vpnrelay_input {$' "$2"; then
      sed -n '/^table inet vpnrelay_input {$/,$p' "$2" > "@INPUT_LIVE@"
    elif grep -q '^delete table inet vpnrelay_input$' "$2"; then
      rm -f "@INPUT_LIVE@"
    fi
    exit 0 ;;
  -c) cp "$3" "@NFT_INPUT@"; exit "@RC@" ;;
  list)
    if [[ "$3" == "inet" ]]; then [[ -f "@INPUT_LIVE@" ]] && cat "@INPUT_LIVE@" && exit 0; exit 1; fi
    [[ -f "@LISTING@" ]] && cat "@LISTING@" && exit 0; exit 1 ;;
esac
exit 0
"""

# Units are files under @UNITS@ holding their ActiveState; `<unit>.stuck` = stop does nothing.
SYSTEMCTL_STUB = r"""
echo "systemctl $*" >> "@LOG@"
u="@UNITS@"
case "$1" in
  show) [[ "$*" == "show -p Listen ssh.socket" ]] && cat "@LISTEN@"; exit 0 ;;
  is-active)
    if [[ -f "$u/$2" ]]; then s="$(cat "$u/$2")"; echo "$s"; [[ "$s" == "active" ]]; exit; fi
    echo inactive; exit 3 ;;
  stop) shift; for x in "$@"; do [[ -f "$u/$x.stuck" ]] || rm -f "$u/$x"; done; exit 0 ;;
esac
exit 0
"""

SYSTEMD_RUN_STUB = r"""
echo "systemd-run $*" >> "@LOG@"
if [[ "@RC@" != "0" ]]; then
  echo "Failed to start transient timer unit: Unit vpn-relay-input-deadman.timer was already loaded" >&2
  exit 1
fi
echo active > "@UNITS@/vpn-relay-input-deadman.timer"
"""

# `ps -o ppid=,etimes=,comm= -p PID` over a table "pid ppid etimes comm"; a pid the
# table does not know is the helper itself (row "self").
PS_STUB = r"""
pid="${!#}"
row="$(awk -v p="$pid" '$1 == p {print $2, $3, $4; exit}' "@TABLE@")"
[[ -n "$row" ]] || row="$(awk '$1 == "self" {print $2, $3, $4; exit}' "@TABLE@")"
[[ -n "$row" ]] && echo "$row"
exit 0
"""

# The process tree of the confirming command: shell <- per-session sshd <- listener.
SESSIONS = {
    # a session opened after the filter was applied (sshd started 0 s ago)
    "new": "self 500 0 bash\n500 400 0 bash\n400 300 0 sshd\n300 1 86400 sshd\n",
    # the operator's session from before the deploy (sshd up for a day)
    "old": "self 500 0 bash\n500 400 86400 bash\n400 300 86400 sshd\n300 1 86400 sshd\n",
    # run inside a tmux server that was started earlier: no sshd among the ancestors
    "tmux": "self 500 0 bash\n500 1 86400 tmux:\n",
    # via sudo in a new session (OpenSSH 9.8+ names the per-session process sshd-session)
    "sudo-new": "self 600 0 sudo\n600 500 0 bash\n500 400 0 sshd-session\n400 1 86400 sshd\n",
}

pytestmark = pytest.mark.timeout(60)


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


class Relay:
    """A sandbox for helper runs: .env, stubs on PATH, call logs, the host state
    (live input table, units, state dirs) that persists across the runs of a test."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.env_file = tmp_path / "relay.env"
        self.sysctl_file = tmp_path / "90-vpn-relay.conf"
        self.log = tmp_path / "calls.log"
        self.nft_input = tmp_path / "nft-input.nft"
        self.applied = tmp_path / "nft-applied"
        self.applied.mkdir()
        self.input_state = tmp_path / "input-live.nft"
        self.input_state.write_text(INPUT_LIVE_LISTING.read_text(encoding="utf-8"), encoding="utf-8")
        self.units = tmp_path / "units"
        self.units.mkdir()
        self.state_dir = tmp_path / "etc-vpn-relay"
        self.run_dir = tmp_path / "run-vpn-relay"
        self.marker = self.state_dir / "input.confirmed"
        self.pending = self.run_dir / "input.pending"
        self.reverted = self.run_dir / "input.reverted"
        self.uid = "0"
        self.default_route = DEFAULT_ROUTE
        self.live_listing: str | None = LIVE_LISTING.read_text(encoding="utf-8")
        self.ss_text = SS_LISTEN.read_text(encoding="utf-8")
        self.socket_listen = SOCKET_LISTEN_22
        self.session = "new"
        self.journal_stream = False
        self.proc = tmp_path / "proc-sys"
        # Runtime sysctls before the run; None = the key does not exist.
        self.sysctls: dict[str, str | None] = {
            FORWARD: "1", CT_MAX: "65536", CT_EST: "86400", CT_COUNT: "1200",
        }
        self.read_only: set[str] = set()   # keys whose `sysctl -w` fails
        self.silent_eperm: set[str] = set()  # keys whose `sysctl -w` exits 0 but sets nothing
        self.modprobe_loads = True         # `modprobe nf_conntrack` creates the keys
        self.nft_rc = 0
        self.systemd_run_rc = 0
        self.tcp_rc = 0
        self.tls_rc = 0

    @property
    def forward(self) -> str | None:
        return self.sysctls[FORWARD]

    @forward.setter
    def forward(self, value: str) -> None:
        self.sysctls[FORWARD] = value

    def write_env(self, text: str) -> None:
        self.env_file.write_text(text, encoding="utf-8")

    def now(self, key: str) -> str | None:
        """A runtime sysctl after the run (None = the key does not exist)."""
        path = self.proc / key
        return path.read_text(encoding="utf-8").strip() if path.exists() else None

    # --- the input filter's host state ---------------------------------------
    def input_live(self) -> str | None:
        return self.input_state.read_text(encoding="utf-8") if self.input_state.exists() else None

    def set_input_live(self, text: str | None) -> None:
        if text is None:
            self.input_state.unlink(missing_ok=True)
        else:
            self.input_state.write_text(text, encoding="utf-8")

    def deadman_armed(self) -> bool:
        p = self.units / DEADMAN_TIMER
        return p.exists() and p.read_text(encoding="utf-8").strip() == "active"

    def unit_state(self, unit: str, state: str) -> None:
        (self.units / unit).write_text(state + "\n", encoding="utf-8")

    def write_marker(self, *tcp: int) -> None:
        self.state_dir.mkdir(exist_ok=True)
        ports = " ".join(str(p) for p in sorted(set(tcp)))
        self.marker.write_text(
            f"sha256={input_hash(*tcp)}\ntcp={ports}\nconfirmed_at=2026-11-11T10:00:00Z\n", encoding="utf-8"
        )

    def kv(self, path: Path) -> dict[str, str]:
        return dict(ln.split("=", 1) for ln in path.read_text(encoding="utf-8").splitlines()
                    if "=" in ln and not ln.startswith("#"))

    def applied_files(self) -> list[str]:
        return [p.read_text(encoding="utf-8") for p in sorted(self.applied.iterdir())]

    def _install_stubs(self) -> None:
        log = self.log
        _stub(self.bin / "id", f'[[ "$1" == "-u" ]] && echo {self.uid}\n')
        route = self.tmp / "route.txt"
        route.write_text(self.default_route, encoding="utf-8")
        _stub(self.bin / "ip", f'echo "ip $*" >> "{log}"\ncat "{route}"\n')
        listing = self.tmp / "listing.txt"
        if self.live_listing is not None:
            listing.write_text(self.live_listing, encoding="utf-8")
        else:
            listing.unlink(missing_ok=True)
        _stub(
            self.bin / "nft",
            NFT_STUB.replace("@LOG@", str(log)).replace("@APPLIED@", str(self.applied))
            .replace("@NFT_INPUT@", str(self.nft_input)).replace("@RC@", str(self.nft_rc))
            .replace("@INPUT_LIVE@", str(self.input_state)).replace("@LISTING@", str(listing)),
        )
        ss = self.tmp / "ss.txt"
        ss.write_text(self.ss_text, encoding="utf-8")
        _stub(self.bin / "ss", f'echo "ss $*" >> "{log}"\ncat "{ss}"\n')
        listen = self.tmp / "socket-listen.txt"
        listen.write_text(self.socket_listen, encoding="utf-8")
        _stub(
            self.bin / "systemctl",
            SYSTEMCTL_STUB.replace("@LOG@", str(log)).replace("@UNITS@", str(self.units))
            .replace("@LISTEN@", str(listen)),
        )
        _stub(
            self.bin / "systemd-run",
            SYSTEMD_RUN_STUB.replace("@LOG@", str(log)).replace("@UNITS@", str(self.units))
            .replace("@RC@", str(self.systemd_run_rc)),
        )
        table = self.tmp / "ps-table.txt"
        table.write_text(SESSIONS[self.session], encoding="utf-8")
        _stub(self.bin / "ps", PS_STUB.replace("@TABLE@", str(table)))
        _stub(self.bin / "logger", f'echo "logger $*" >> "{log}"\n')
        self.proc.mkdir(exist_ok=True)
        for key, value in self.sysctls.items():
            path = self.proc / key
            if value is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(value + "\n", encoding="utf-8")
            if key in self.read_only:
                (self.proc / f"{key}.ro").touch()
            if key in self.silent_eperm:
                (self.proc / f"{key}.eperm").touch()
        _stub(self.bin / "sysctl", SYSCTL_STUB.replace("@LOG@", str(log)).replace("@PROC@", str(self.proc)))
        create = "; ".join(
            f'[[ -f "{self.proc / k}" ]] || echo {v} > "{self.proc / k}"' for k, v in KERNEL_CT.items()
        )
        _stub(
            self.bin / "modprobe",
            MODPROBE_STUB.replace("@LOG@", str(log)).replace("@LOADS@", "1" if self.modprobe_loads else "0")
            .replace("@CREATE@", create),
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
        # Pinned, never inherited: every override the helper reads and the journal hint.
        env = {k: v for k, v in os.environ.items() if not k.startswith("RELAY_") and k != "JOURNAL_STREAM"}
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        env["RELAY_ENV"] = str(self.env_file)
        env["RELAY_SYSCTL_FILE"] = str(self.sysctl_file)
        env["RELAY_STATE_DIR"] = str(self.state_dir)
        env["RELAY_RUN_DIR"] = str(self.run_dir)
        env["RELAY_PROBE_TIMEOUT"] = "5"
        if self.journal_stream:
            env["JOURNAL_STREAM"] = "8:4711"
        return subprocess.run(
            ["bash", str(HELPER), *args], env=env, capture_output=True, text=True, check=False
        )

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def clear_calls(self) -> None:
        self.log.unlink(missing_ok=True)


@pytest.fixture
def relay(tmp_path: Path) -> Relay:
    r = Relay(tmp_path)
    r.write_env(f"NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4={UPSTREAM}\n")
    return r


@pytest.fixture
def confirmed(relay: Relay) -> Relay:
    """The relay after the first enable was confirmed: marker for tcp 22, no pending."""
    relay.write_marker(22)
    return relay


# --------------------------------------------------------------------------- #
# Structure
# --------------------------------------------------------------------------- #
def test_helper_is_executable_strict_bash() -> None:
    assert os.access(HELPER, os.X_OK), "git mode must be 0755 (it is installed with 0755)"
    text = HELPER.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def _code() -> str:
    """The helper without its comment lines (the header talks about hooks in words)."""
    return "\n".join(
        ln for ln in HELPER.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")
    )


def test_the_forwarding_table_never_names_an_input_or_output_hook() -> None:
    """INPUT is the separate table inet vpnrelay_input; OUTPUT is nobody's business."""
    code = _code()
    forward = code[code.index("render_forward() {") :]
    forward = forward[: forward.index("\n}\n")]
    assert "chain relayfwd" in forward, "render_forward not found"
    assert not re.search(r"hook\s+(input|output)", forward)
    assert not re.search(r"hook\s+output", code)
    assert len(re.findall(r"hook\s+input", code)) == 1, "one input chain, in render_input"


def test_the_helper_never_pipes_into_head_or_evaluates() -> None:
    code = _code()
    assert not re.search(r"\|\s*head\b", code), "no `| head` (the SIGPIPE class)"
    assert not re.search(r"\beval\b", code)


@pytest.mark.parametrize(
    "args",
    [(), ("bogus",), ("apply", "x"), ("check", "--wet"), ("show", "x"), ("input-confirm", "x"),
     ("input-off", "--now"), ("input-status", "x")],
)
def test_usage_errors_exit_2(relay: Relay, args: tuple[str, ...]) -> None:
    assert relay.run(*args).returncode == 2


# --------------------------------------------------------------------------- #
# Rendering: 1:1 with the captured relay, plus the input filter
# --------------------------------------------------------------------------- #
def test_render_is_the_captured_ruleset_plus_the_input_filter(relay: Relay) -> None:
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == CAPTURED_RULESET.read_text(encoding="utf-8") + INPUT_RENDER_22


def test_the_rendered_input_filter_is_what_nft_lists(relay: Relay) -> None:
    """The render uses nft's own spelling (a one-port set bare), so the live listing
    captured from nft 1.0.9 equals it once counters and whitespace are normalised."""
    def norm(text: str) -> list[str]:
        out = re.sub(r"counter packets \d+ bytes \d+", "counter", text)
        return [" ".join(ln.split()) for ln in out.splitlines() if ln.strip()]
    rendered = INPUT_RENDER_22.split(INPUT_HEAD, 1)[1]
    assert norm(INPUT_LIVE_LISTING.read_text(encoding="utf-8")) == norm(rendered)


def test_explicit_defaults_and_explicit_iface_render_the_same_file(relay: Relay) -> None:
    relay.write_env(
        f"NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4={UPSTREAM}\n"
        "RELAY_FORWARD_TCP_PORTS=443\nRELAY_FORWARD_UDP_PORTS=443\nRELAY_WAN_IFACE=eth0\n"
        "RELAY_INPUT_FILTER=on\nRELAY_INPUT_EXTRA_TCP=\nRELAY_INPUT_EXTRA_UDP=  # none\n"
    )
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == CAPTURED_RULESET.read_text(encoding="utf-8") + INPUT_RENDER_22
    assert not any(c.startswith("ip ") for c in relay.calls()), "RELAY_WAN_IFACE wins over detection"


def test_render_is_an_atomic_replace_of_two_tables(relay: Relay) -> None:
    lines = relay.run("show").stdout.splitlines()
    assert lines[:3] == ["table ip vpnrelay", "delete table ip vpnrelay", "table ip vpnrelay {"]
    i = lines.index("table inet vpnrelay_input")
    assert lines[i : i + 3] == [
        "table inet vpnrelay_input", "delete table inet vpnrelay_input", "table inet vpnrelay_input {",
    ]
    assert [ln for ln in lines if ln.startswith(("table", "delete"))] == [
        "table ip vpnrelay", "delete table ip vpnrelay", "table ip vpnrelay {",
        "table inet vpnrelay_input", "delete table inet vpnrelay_input", "table inet vpnrelay_input {",
    ]


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
        "RELAY_INPUT_EXTRA_TCP=8080\nRELAY_INPUT_EXTRA_UDP=51820\n",
        "",
    ],
)
def test_hooks_are_prerouting_postrouting_forward_and_one_input(relay: Relay, env: str) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n{env}")
    out = relay.run("show").stdout
    assert out, "render failed"
    assert re.findall(r"hook\s+(\w+)", out) == ["prerouting", "postrouting", "forward", "input"]
    assert re.findall(r"hook\s+(\w+)", forward_part(out)) == ["prerouting", "postrouting", "forward"]
    assert "type filter hook input priority filter; policy drop;" in out.split(INPUT_HEAD, 1)[1]


# --------------------------------------------------------------------------- #
# The input filter: rules, SSH discovery, extra ports
# --------------------------------------------------------------------------- #
def test_input_filter_rules(relay: Relay) -> None:
    """inet (sshd listens on IPv4 and IPv6), policy drop, then exactly: lo,
    established/related, invalid drop, ICMP, ICMPv6 (NDP), DHCPv6 client, ssh."""
    block = relay.run("show").stdout.split(INPUT_HEAD, 1)[1]
    rules = [ln.strip() for ln in block.splitlines()]
    assert rules == [
        "table inet vpnrelay_input {",
        "chain input {",
        "type filter hook input priority filter; policy drop;",
        'iif "lo" accept',
        "ct state established,related accept",
        "ct state invalid drop",
        "ip protocol icmp accept",
        "meta l4proto ipv6-icmp accept",
        'ip6 saddr fe80::/10 udp dport 546 accept comment "dhcpv6 client"',
        'tcp dport 22 accept comment "ssh"',
        "counter",
        "}",
        "}",
    ]


def _ss(*rows: tuple[str, str, str]) -> str:
    """ss -Hltunp rows: (proto, local address:port, users field)."""
    out = []
    for proto, local, users in rows:
        state = "LISTEN" if proto == "tcp" else "UNCONN"
        out.append(f"{proto}   {state} 0      4096      {local}      0.0.0.0:*    {users}")
    return "\n".join(out) + "\n"


SSHD = '"sshd",pid=1001,fd=3'
PID1 = '"systemd",pid=1,fd=117'


@pytest.mark.parametrize(
    ("rows", "socket_listen", "ssh_rule"),
    [
        # sshd running behind ssh.socket (the live relay): both owners shown
        ([("tcp", "0.0.0.0:22", f"users:(({SSHD}),({PID1}))"), ("tcp", "[::]:22", f"users:(({SSHD}))")],
         SOCKET_LISTEN_22, "tcp dport 22"),
        # socket activation before the first connection: only systemd holds the socket
        ([("tcp", "0.0.0.0:22", f"users:(({PID1}))"), ("tcp", "[::]:22", f"users:(({PID1}))")],
         SOCKET_LISTEN_22, "tcp dport 22"),
        # a plain ssh.service on two ports (one IPv6-only)
        ([("tcp", "0.0.0.0:22", f"users:(({SSHD}))"), ("tcp", "[::]:2222", f"users:(({SSHD}))")],
         "", "tcp dport { 22, 2222 }"),
        # OpenSSH 9.8+ (sshd-session) and an interface-bound listener
        ([("tcp", "10.0.0.5%eth0:54321", 'users:(("sshd-session",pid=7,fd=3))')], "", "tcp dport 54321"),
        # systemd also holds a socket ssh.socket does not declare (rpcbind): not SSH
        ([("tcp", "0.0.0.0:111", f'users:(("rpcbind",pid=77,fd=4),({PID1}))'),
          ("tcp", "0.0.0.0:2222", f"users:(({PID1}))")],
         "Listen=0.0.0.0:2222 (Stream)\n", "tcp dport 2222"),
    ],
)
def test_ssh_ports_are_discovered_from_ss(
    relay: Relay, rows: list[tuple[str, str, str]], socket_listen: str, ssh_rule: str
) -> None:
    relay.ss_text = _ss(*rows)
    relay.socket_listen = socket_listen
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert f'    {ssh_rule} accept comment "ssh"\n' in proc.stdout
    assert [ln for ln in proc.stdout.splitlines() if 'comment "ssh"' in ln] == [
        f'    {ssh_rule} accept comment "ssh"'
    ]
    assert "ss -Hltunp" in relay.calls()


@pytest.mark.parametrize(
    ("ss_text", "socket_listen"),
    [
        ("", SOCKET_LISTEN_22),  # nothing listens
        # sshd on loopback only (a tunnel-only host)
        (_ss(("tcp", "127.0.0.1:22", f"users:(({SSHD}))"), ("tcp", "[::1]:22", f"users:(({SSHD}))")), ""),
        # something else on 22, no sshd
        (_ss(("tcp", "0.0.0.0:22", 'users:(("dropbear",pid=5,fd=3))')), ""),
        # systemd holds 22, but ssh.socket declares nothing (another socket unit)
        (_ss(("tcp", "0.0.0.0:22", f"users:(({PID1}))")), ""),
        # ss could not see the owner (not root)
        (_ss(("tcp", "0.0.0.0:22", "")), SOCKET_LISTEN_22),
    ],
)
def test_no_ssh_port_refuses_everything_without_a_change(relay: Relay, ss_text: str, socket_listen: str) -> None:
    relay.ss_text = ss_text
    relay.socket_listen = socket_listen
    for args in (("apply",), ("show",), ("check", "--dry-run"), ("check",)):
        proc = relay.run(*args)
        assert proc.returncode == 8, (args, proc.stdout, proc.stderr)
        assert "no SSH port found — refusing to install a drop policy" in proc.stderr
    calls = relay.calls()
    assert not [c for c in calls if c.startswith(("nft -f", "nft -c", "systemd-run", "sysctl", "modprobe"))]
    assert not [c for c in calls if c.startswith("systemctl") and " show " not in f" {c} "]
    assert relay.input_live() is not None, "the live input table is untouched"
    assert not relay.sysctl_file.exists()
    assert not relay.pending.exists() and not relay.marker.exists()


def test_a_non_root_dry_run_notes_the_skipped_discovery(relay: Relay) -> None:
    """ss shows the owner of root's sockets only to root: a non-root dry-run says so
    instead of failing (as root the same host is exit 8, above)."""
    relay.uid = "1000"
    relay.ss_text = _ss(("tcp", "0.0.0.0:22", ""))
    proc = relay.run("check", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert "SSH port discovery skipped (not root" in proc.stdout


def test_extra_ports_from_env(relay: Relay) -> None:
    relay.write_env(
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n"
        "RELAY_INPUT_EXTRA_TCP=8443, 80,22\nRELAY_INPUT_EXTRA_UDP=51820\n"
    )
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    block = proc.stdout.split(INPUT_HEAD, 1)[1]
    assert block == INPUT_RULES_HEAD + (
        '    tcp dport 22 accept comment "ssh"\n'
        '    tcp dport { 80, 8443 } accept comment "RELAY_INPUT_EXTRA_TCP"\n'
        '    udp dport 51820 accept comment "RELAY_INPUT_EXTRA_UDP"\n'
    ) + INPUT_TAIL, "22 is an ssh port already: not repeated in the extra rule"
    assert "extra tcp: 22,80,8443; extra udp: 51820" in relay.run("check", "--dry-run").stdout


def test_extra_ports_that_are_all_ssh_ports_add_no_rule(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=22\n")
    assert relay.run("show").stdout.endswith(INPUT_RENDER_22)


@pytest.mark.parametrize(
    "env",
    [
        "RELAY_INPUT_FILTER=yes\n",
        "RELAY_INPUT_FILTER=ON\n",
        "RELAY_INPUT_EXTRA_TCP=0\n",
        "RELAY_INPUT_EXTRA_TCP=8080,\n",
        "RELAY_INPUT_EXTRA_UDP=65536\n",
        "RELAY_INPUT_CLOSED_TCP=http\n",
        "RELAY_INPUT_EXTRA_TCP=8080\nRELAY_INPUT_CLOSED_TCP=8080\n",
        "RELAY_INPUT_EXTRA_UDP=53\nRELAY_INPUT_CLOSED_UDP=53\n",
        "RELAY_INPUT_CLOSED_TCP=22\n",  # an ssh port is always open
    ],
)
def test_invalid_input_values_are_refused_before_anything_applies(relay: Relay, env: str) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n{env}")
    for args in (("show",), ("check", "--dry-run"), ("apply",), ("check",)):
        proc = relay.run(*args)
        assert proc.returncode == 3, (args, proc.stdout, proc.stderr)
    assert not [c for c in relay.calls() if c.startswith(("nft", "systemd-run", "sysctl", "modprobe"))]


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
    assert forward_part(proc.stdout) == CAPTURED_RULESET.read_text(encoding="utf-8")


def test_an_empty_port_value_means_the_default(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_FORWARD_TCP_PORTS=\nRELAY_FORWARD_UDP_PORTS= # none\n")
    assert forward_part(relay.run("show").stdout) == CAPTURED_RULESET.read_text(encoding="utf-8")


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
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=8191\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=1048577\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=065536\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=64k\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=-65536\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=65536.0\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=65 536\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_MAX=99999999999999999999999\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=299\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=432001\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=0\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=1d\n",
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=86400s\n",
    ],
)
def test_invalid_values_are_refused_before_anything_renders(relay: Relay, env: str) -> None:
    relay.write_env(env)
    for args in (("show",), ("check", "--dry-run"), ("apply",)):
        proc = relay.run(*args)
        assert proc.returncode == 3, (args, proc.stdout, proc.stderr)
        assert "table ip" not in proc.stdout
    assert not any(c.startswith("nft") for c in relay.calls()), "nothing may reach nft"
    assert not any(c.startswith(("sysctl", "modprobe", "systemd-run")) for c in relay.calls()), "sysctls untouched"
    assert not relay.sysctl_file.exists()


@pytest.mark.parametrize(
    ("env", "ct_max", "ct_est"),
    [
        ("", "65536", "86400"),  # defaults
        ("RELAY_CONNTRACK_MAX=\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT= # default\n", "65536", "86400"),
        ("RELAY_CONNTRACK_MAX=8192\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=300\n", "8192", "300"),
        ("RELAY_CONNTRACK_MAX=1048576\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=432000\n", "1048576", "432000"),
        ('export RELAY_CONNTRACK_MAX = "262144"  # 4x\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=\'7200\'\n',
         "262144", "7200"),
    ],
)
def test_conntrack_values_in_range_are_accepted(relay: Relay, env: str, ct_max: str, ct_est: str) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n{env}")
    proc = relay.run("check", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert f"conntrack: max {ct_max}; tcp established timeout {ct_est}s" in proc.stdout
    assert forward_part(relay.run("show").stdout) == CAPTURED_RULESET.read_text(encoding="utf-8"), (
        "the conntrack values never change the nft ruleset"
    )


def test_a_missing_env_file_is_refused(relay: Relay) -> None:
    relay.env_file.unlink()
    proc = relay.run("show")
    assert proc.returncode == 3
    assert "relay.env.example" in proc.stderr


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #
def _relay_kernel_defaults(relay: Relay) -> None:
    """The relay before the first apply of this version: kernel conntrack values."""
    relay.sysctls.update({FORWARD: "0", CT_MAX: KERNEL_CT[CT_MAX], CT_EST: KERNEL_CT[CT_EST]})


def test_apply_is_one_nft_transaction_then_the_sysctls(confirmed: Relay) -> None:
    relay = confirmed
    _relay_kernel_defaults(relay)
    proc = relay.run("apply")
    assert proc.returncode == 0, proc.stderr
    calls = relay.calls()
    nft_calls = [c for c in calls if c.startswith("nft")]
    assert len(nft_calls) == 1 and nft_calls[0].startswith("nft -f ")
    assert relay.nft_input.read_text(encoding="utf-8") == CAPTURED_RULESET.read_text(encoding="utf-8") + INPUT_RENDER_22
    writes = [c for c in calls if c.startswith("sysctl -q -w")]
    assert writes == [
        "sysctl -q -w net.netfilter.nf_conntrack_max=65536",
        "sysctl -q -w net.netfilter.nf_conntrack_tcp_timeout_established=86400",
        "sysctl -q -w net.ipv4.ip_forward=1",
    ], "all three at runtime, forwarding last"
    first_sysctl = next(i for i, c in enumerate(calls) if c.startswith("sysctl"))
    assert calls.index(nft_calls[0]) < first_sysctl, (
        "every sysctl comes after the table: the forward chain (policy drop) is in place and "
        "the table has loaded nf_conntrack"
    )
    assert not any(c.startswith("modprobe") for c in calls), "the key is there: no modprobe"
    assert (relay.now(FORWARD), relay.now(CT_MAX), relay.now(CT_EST)) == ("1", "65536", "86400")


def test_apply_renders_the_whole_sysctl_file(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    assert relay.sysctl_file.read_text(encoding="utf-8") == DEFAULT_SYSCTL_FILE
    assert oct(relay.sysctl_file.stat().st_mode & 0o777) == "0o644"


def test_apply_renders_the_sysctl_file_from_env(relay: Relay) -> None:
    relay.write_env(
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n"
        "RELAY_CONNTRACK_MAX=262144\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=7200\n"
    )
    proc = relay.run("apply")
    assert proc.returncode == 0, proc.stderr
    assert relay.sysctl_file.read_text(encoding="utf-8") == (
        "net.ipv4.ip_forward = 1\n"
        "net.netfilter.nf_conntrack_max = 262144\n"
        "net.netfilter.nf_conntrack_tcp_timeout_established = 7200\n"
    )
    assert (relay.now(CT_MAX), relay.now(CT_EST)) == ("262144", "7200")


def test_apply_replaces_the_hand_made_one_line_file_atomically(relay: Relay) -> None:
    """The captured host file (ip_forward only) is rewritten whole, by rename: a new
    inode, no temp file left next to it, no partial content ever visible."""
    relay.sysctl_file.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    inode = relay.sysctl_file.stat().st_ino
    assert relay.run("apply").returncode == 0
    assert relay.sysctl_file.read_text(encoding="utf-8") == DEFAULT_SYSCTL_FILE
    assert relay.sysctl_file.stat().st_ino != inode, "replaced with mv, not rewritten in place"
    assert [p.name for p in relay.tmp.glob("90-vpn-relay.conf*")] == ["90-vpn-relay.conf"]


def test_apply_leaves_an_identical_sysctl_file_alone(relay: Relay) -> None:
    relay.sysctl_file.write_text(DEFAULT_SYSCTL_FILE, encoding="utf-8")
    inode = relay.sysctl_file.stat().st_ino
    assert relay.run("apply").returncode == 0
    assert relay.sysctl_file.stat().st_ino == inode, "an up-to-date file is not rewritten"


def test_apply_loads_nf_conntrack_when_its_keys_are_absent(relay: Relay) -> None:
    for key in (CT_MAX, CT_EST, CT_COUNT):
        relay.sysctls[key] = None
    proc = relay.run("apply")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = relay.calls()
    assert [c for c in calls if c.startswith("modprobe")] == ["modprobe nf_conntrack"]
    assert calls.index("modprobe nf_conntrack") < calls.index("sysctl -q -w net.netfilter.nf_conntrack_max=65536")
    assert calls.count("sysctl -n net.netfilter.nf_conntrack_max") == 3, "probed, retried, read back"
    assert (relay.now(CT_MAX), relay.now(CT_EST), relay.now(FORWARD)) == ("65536", "86400", "1")


def test_apply_exits_7_when_modprobe_does_not_bring_the_keys(relay: Relay) -> None:
    _relay_kernel_defaults(relay)
    for key in (CT_MAX, CT_EST, CT_COUNT):
        relay.sysctls[key] = None
    relay.modprobe_loads = False
    proc = relay.run("apply")
    assert proc.returncode == 7, proc.stdout + proc.stderr
    assert "still absent after modprobe nf_conntrack" in proc.stderr
    assert "Module nf_conntrack not found" in proc.stderr, "modprobe's own reason is shown"
    assert not any(c.startswith("sysctl -q -w") for c in relay.calls())
    assert relay.now(FORWARD) == "0", "forwarding is not switched on by a failed apply"


@pytest.mark.parametrize("key", [CT_MAX, CT_EST, FORWARD])
def test_apply_exits_7_when_a_sysctl_cannot_be_set(relay: Relay, key: str) -> None:
    relay.read_only.add(key)
    proc = relay.run("apply")
    assert proc.returncode == 7, proc.stdout + proc.stderr
    assert f"sysctl -w {key}=" in proc.stderr


def test_apply_reads_every_value_back(relay: Relay) -> None:
    proc = relay.run("apply")
    assert proc.returncode == 0, proc.stderr
    calls = [c for c in relay.calls() if c.startswith("sysctl")]
    for key, value in ((CT_MAX, "65536"), (CT_EST, "86400"), (FORWARD, "1")):
        i = calls.index(f"sysctl -q -w {key}={value}")
        assert calls[i + 1] == f"sysctl -n {key}", f"{key} is read back right after the write"


def test_apply_exits_7_when_sysctl_w_exits_0_without_setting_the_value(relay: Relay) -> None:
    """Seen for real with procps 4.0.4 in a network namespace: `sysctl -w
    net.netfilter.nf_conntrack_max=...` prints "Operation not permitted", leaves the
    value as it was and exits 0."""
    _relay_kernel_defaults(relay)
    relay.silent_eperm.add(CT_MAX)
    proc = relay.run("apply")
    assert proc.returncode == 7, proc.stdout + proc.stderr
    assert f"sysctl -w {CT_MAX}=65536 did not take: {CT_MAX} = 262144" in proc.stderr
    assert relay.now(FORWARD) == "0", "forwarding stays off"


def test_a_rejected_ruleset_leaves_every_sysctl_alone(relay: Relay) -> None:
    _relay_kernel_defaults(relay)
    relay.nft_rc = 1
    proc = relay.run("apply")
    assert proc.returncode == 6, proc.stderr
    assert "unchanged" in proc.stderr
    assert not any(c.startswith(("sysctl", "modprobe")) for c in relay.calls())
    assert not relay.sysctl_file.exists()
    assert (relay.now(FORWARD), relay.now(CT_MAX), relay.now(CT_EST)) == ("0", "262144", "432000")


def test_apply_requires_root(relay: Relay) -> None:
    relay.uid = "1000"
    proc = relay.run("apply")
    assert proc.returncode == 5
    assert relay.calls() == []


# --------------------------------------------------------------------------- #
# apply: the dead-man and the confirmation
# --------------------------------------------------------------------------- #
def _deadman_runs(relay: Relay) -> list[str]:
    return [c for c in relay.calls() if c.startswith("systemd-run")]


def test_the_first_enable_arms_the_dead_man_before_the_drop_policy(relay: Relay) -> None:
    proc = relay.run("apply")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    (run,) = _deadman_runs(relay)
    assert "--on-active=300" in run.split() and f"--unit={DEADMAN}" in run.split()
    assert run.endswith(f"{HELPER} input-off"), "the dead-man runs input-off of this very helper"
    calls = relay.calls()
    assert calls.index(run) < calls.index(next(c for c in calls if c.startswith("nft -f"))), (
        "armed BEFORE the table: an unconfirmed drop policy is never live without it"
    )
    assert relay.deadman_armed()
    pending = relay.kv(relay.pending)
    assert pending["sha256"] == input_hash(22) and pending["tcp"] == "22"
    assert int(pending["reverts_at"]) - int(pending["applied_at"]) == 300
    assert "PENDING CONFIRM" in proc.stdout and "open a NEW ssh session" in proc.stdout
    assert "input-confirm" in proc.stdout
    assert not relay.marker.exists(), "apply never confirms by itself"


def test_the_confirmed_set_needs_no_dead_man(confirmed: Relay) -> None:
    proc = confirmed.run("apply")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _deadman_runs(confirmed) == []
    assert not confirmed.deadman_armed() and not confirmed.pending.exists()
    assert "confirmed earlier" in proc.stdout
    assert confirmed.input_live() is not None and "PENDING" not in proc.stdout


@pytest.mark.parametrize(
    ("env", "ss_rows", "needs_confirm"),
    [
        ("RELAY_INPUT_EXTRA_TCP=8080\n", None, True),          # a new TCP port
        ("", [("tcp", "0.0.0.0:2222", f"users:(({SSHD}))")], True),  # sshd moved to 2222
        ("RELAY_INPUT_EXTRA_UDP=51820\n", None, False),        # UDP never costs ssh
        ("RELAY_INPUT_EXTRA_TCP=22\n", None, False),           # same set, spelled differently
        ("RELAY_INPUT_CLOSED_TCP=8080\n", None, False),        # only a check declaration
    ],
)
def test_any_change_of_the_tcp_set_asks_for_a_confirmation_again(
    confirmed: Relay, env: str, ss_rows: list[tuple[str, str, str]] | None, needs_confirm: bool
) -> None:
    confirmed.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n{env}")
    if ss_rows is not None:
        confirmed.ss_text = _ss(*ss_rows)
    proc = confirmed.run("apply")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert bool(_deadman_runs(confirmed)) is needs_confirm
    assert confirmed.pending.exists() is needs_confirm


def test_the_confirmed_set_again_disarms_a_pending_dead_man(confirmed: Relay) -> None:
    """A pending set (8080 added) is withdrawn before it was confirmed: the next
    apply of the confirmed set stops the timer and drops the pending note."""
    confirmed.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=8080\n")
    assert confirmed.run("apply").returncode == 0
    assert confirmed.deadman_armed()
    confirmed.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n")
    confirmed.clear_calls()
    proc = confirmed.run("apply")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not confirmed.deadman_armed() and not confirmed.pending.exists()
    assert f"systemctl stop {DEADMAN_TIMER}" in confirmed.calls()
    assert _deadman_runs(confirmed) == []


def test_a_dead_man_that_cannot_be_armed_applies_nothing(relay: Relay) -> None:
    relay.systemd_run_rc = 1
    before = relay.input_live()
    proc = relay.run("apply")
    assert proc.returncode == 9, proc.stdout + proc.stderr
    assert "refusing to install an unconfirmed drop policy" in proc.stderr
    assert "already loaded" in proc.stderr, "systemd-run's own reason is shown"
    assert not [c for c in relay.calls() if c.startswith(("nft -f", "sysctl", "modprobe"))]
    assert relay.input_live() == before and not relay.pending.exists()


def test_a_re_arm_failure_removes_a_still_unconfirmed_filter(relay: Relay) -> None:
    """Stopping the old timer and failing to start the new one would leave an
    unconfirmed filter unguarded: it is taken off instead (the safe direction)."""
    assert relay.run("apply").returncode == 0  # pending, armed
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=8080\n")
    relay.systemd_run_rc = 1
    proc = relay.run("apply")
    assert proc.returncode == 9, proc.stdout + proc.stderr
    assert relay.input_live() is None, "the unconfirmed filter is gone"
    assert relay.reverted.exists() and not relay.pending.exists()
    assert relay.applied_files()[-1] == INPUT_HEAD, "removed alone, forwarding untouched"


def test_an_nft_rejection_disarms_the_fresh_dead_man_when_nothing_was_pending(confirmed: Relay) -> None:
    confirmed.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=8080\n")
    confirmed.nft_rc = 1
    proc = confirmed.run("apply")
    assert proc.returncode == 6, proc.stdout + proc.stderr
    assert not confirmed.deadman_armed(), "the live filter is still the confirmed one: nothing to guard"
    assert not confirmed.pending.exists()


def test_an_nft_rejection_keeps_guarding_a_pending_filter(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    first = relay.kv(relay.pending)
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=8080\n")
    relay.nft_rc = 1
    proc = relay.run("apply")
    assert proc.returncode == 6, proc.stdout + proc.stderr
    assert relay.deadman_armed(), "the previous, unconfirmed filter is still live"
    after = relay.kv(relay.pending)
    assert (after["sha256"], after["tcp"], after["applied_at"]) == (first["sha256"], "22", first["applied_at"])
    assert int(after["reverts_at"]) >= int(first["reverts_at"]), "the deadline of the fresh timer"


# --------------------------------------------------------------------------- #
# input-confirm
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("session", ["new", "sudo-new"])
def test_input_confirm_stops_the_timer_and_writes_the_marker(relay: Relay, session: str) -> None:
    assert relay.run("apply").returncode == 0
    relay.session = session
    proc = relay.run("input-confirm")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not relay.deadman_armed()
    assert f"systemctl stop {DEADMAN_TIMER}" in relay.calls()
    marker = relay.kv(relay.marker)
    assert marker["sha256"] == input_hash(22) and marker["tcp"] == "22"
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", marker["confirmed_at"])
    assert oct(relay.marker.stat().st_mode & 0o777) == "0o644"
    assert not relay.pending.exists()
    assert relay.input_live() is not None, "the filter stays"
    # ... and the next apply of the same set is fully automatic
    relay.clear_calls()
    assert relay.run("apply").returncode == 0
    assert _deadman_runs(relay) == []


@pytest.mark.parametrize(
    ("session", "why"),
    [
        ("old", "before the filter was applied"),
        ("tmux", "not run from an ssh session"),
    ],
)
def test_input_confirm_from_a_session_that_did_not_come_in_through_the_filter_is_refused(
    relay: Relay, session: str, why: str
) -> None:
    """The operator's live session rides an established connection, which the filter
    always lets through: it proves nothing about NEW ssh connections."""
    assert relay.run("apply").returncode == 0
    relay.session = session
    proc = relay.run("input-confirm")
    assert proc.returncode == 19, proc.stdout + proc.stderr
    assert why in proc.stderr and "NEW ssh session" in proc.stderr
    assert relay.deadman_armed(), "the dead-man still reverts the filter"
    assert relay.pending.exists() and not relay.marker.exists()


def test_input_confirm_with_nothing_pending(confirmed: Relay) -> None:
    proc = confirmed.run("input-confirm")
    assert proc.returncode == 0, proc.stderr
    assert "nothing to confirm" in proc.stdout
    confirmed.marker.unlink()
    proc = confirmed.run("input-confirm")
    assert proc.returncode == 19
    assert "nothing to confirm" in proc.stderr


def test_input_confirm_after_the_dead_man_fired_is_too_late(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    assert relay.run("input-off").returncode == 0  # what the timer runs
    proc = relay.run("input-confirm")
    assert proc.returncode == 19
    assert "too late: the dead-man removed the input filter" in proc.stderr
    assert not relay.marker.exists()


def test_input_confirm_without_an_armed_timer_is_refused(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    (relay.units / DEADMAN_TIMER).unlink()   # stopped by hand / already elapsed
    proc = relay.run("input-confirm")
    assert proc.returncode == 19
    assert "is not armed" in proc.stderr and not relay.marker.exists()


def test_input_confirm_while_the_dead_man_runs_is_too_late(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    relay.unit_state(f"{DEADMAN}.service", "activating")
    proc = relay.run("input-confirm")
    assert proc.returncode == 19
    assert "too late: the dead-man fired" in proc.stderr and not relay.marker.exists()


def test_input_confirm_reports_a_timer_that_does_not_stop(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    (relay.units / f"{DEADMAN_TIMER}.stuck").touch()
    proc = relay.run("input-confirm")
    assert proc.returncode == 19
    assert "could not stop" in proc.stderr and not relay.marker.exists()


# --------------------------------------------------------------------------- #
# input-off (what the dead-man runs)
# --------------------------------------------------------------------------- #
def test_input_off_removes_only_the_input_table(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    pending = relay.kv(relay.pending)
    relay.clear_calls()
    proc = relay.run("input-off")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert relay.applied_files()[-1] == INPUT_HEAD, "create + delete of the input table, nothing else"
    assert "vpnrelay {" not in relay.applied_files()[-1] and "table ip" not in relay.applied_files()[-1]
    assert relay.input_live() is None
    reverted = relay.kv(relay.reverted)
    assert reverted["tcp"] == "22" and reverted["sha256"] == pending["sha256"]
    assert int(reverted["reverted_at"]) >= int(pending["applied_at"])
    assert not relay.pending.exists()
    (logged,) = [c for c in relay.calls() if c.startswith("logger")]
    assert "table inet vpnrelay_input removed" in logged and "was not confirmed" in logged
    assert "table ip vpnrelay (forwarding) untouched" in logged
    assert not any(c.startswith("sysctl") for c in relay.calls())


def test_input_off_under_systemd_writes_the_journal_through_stdout(relay: Relay) -> None:
    relay.journal_stream = True
    proc = relay.run("input-off")
    assert proc.returncode == 0, proc.stderr
    assert "table inet vpnrelay_input removed — on request" in proc.stdout
    assert not [c for c in relay.calls() if c.startswith("logger")], "stdout is the journal already"


def test_input_off_on_an_absent_table_is_a_no_op(relay: Relay) -> None:
    relay.set_input_live(None)
    proc = relay.run("input-off")
    assert proc.returncode == 0, proc.stderr
    assert "already absent" in proc.stdout


# --------------------------------------------------------------------------- #
# RELAY_INPUT_FILTER=off
# --------------------------------------------------------------------------- #
def test_filter_off_renders_only_the_removal(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_FILTER=off\n")
    relay.ss_text = ""  # no discovery needed: nothing is filtered
    proc = relay.run("show")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == CAPTURED_RULESET.read_text(encoding="utf-8") + INPUT_HEAD
    assert not any(c.startswith("ss ") for c in relay.calls())


def test_filter_off_apply_removes_the_table_and_any_dead_man(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0  # pending, armed
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_FILTER=off\n")
    relay.clear_calls()
    proc = relay.run("apply")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert relay.input_live() is None
    assert not relay.deadman_armed() and not relay.pending.exists()
    assert _deadman_runs(relay) == []
    assert "table inet vpnrelay_input removed" in proc.stdout


def test_filter_off_check_sees_the_table_state(relay: Relay) -> None:
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_FILTER=off\n")
    proc = relay.run("check")
    assert proc.returncode == 16, proc.stdout + proc.stderr
    assert "loaded although RELAY_INPUT_FILTER=off" in proc.stderr
    relay.set_input_live(None)
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok: input filter off (RELAY_INPUT_FILTER=off)" in proc.stdout
    assert "listening but filtered" not in proc.stderr


# --------------------------------------------------------------------------- #
# The forwarding table stays the captured one, whatever the input filter does
# --------------------------------------------------------------------------- #
def test_the_forwarding_table_is_byte_identical_in_every_scenario(relay: Relay) -> None:
    captured = CAPTURED_RULESET.read_text(encoding="utf-8")
    assert relay.run("apply").returncode == 0                      # first enable: dead-man
    relay.session = "new"
    assert relay.run("input-confirm").returncode == 0
    assert relay.run("apply").returncode == 0                      # confirmed set
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=8080\nRELAY_INPUT_EXTRA_UDP=51820\n")
    assert relay.run("apply").returncode == 0                      # changed set: dead-man again
    assert relay.run("input-off").returncode == 0                  # the dead-man fires
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_FILTER=off\n")
    assert relay.run("apply").returncode == 0                      # filter off
    files = relay.applied_files()
    assert len(files) == 5
    with_forward = [f for f in files if "table ip vpnrelay" in f]
    assert len(with_forward) == 4
    for f in with_forward:
        assert forward_part(f) == captured
    assert [f for f in files if "table ip vpnrelay" not in f] == [INPUT_HEAD], "input-off touches nothing else"


# --------------------------------------------------------------------------- #
# input-status (DEPLOY OK prints it)
# --------------------------------------------------------------------------- #
def test_input_status_follows_the_lifecycle(relay: Relay) -> None:
    assert relay.run("input-status").stdout.startswith("UNCONFIRMED (no ")
    assert relay.run("apply").returncode == 0
    status = relay.run("input-status").stdout.strip()
    assert re.fullmatch(r"PENDING CONFIRM \(reverts at \d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+\)", status), status
    assert relay.run("input-confirm").returncode == 0
    assert re.fullmatch(r"OK \(tcp 22; confirmed \S+\)", relay.run("input-status").stdout.strip())
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=8080\n")
    assert relay.run("apply").returncode == 0
    assert relay.run("input-off").returncode == 0
    status = relay.run("input-status").stdout.strip()
    assert status.startswith("ABSENT — the dead-man removed it at ") and "(tcp 22 8080 was not confirmed)" in status
    relay.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_FILTER=off\n")
    assert relay.run("input-status").stdout.strip() == "off (RELAY_INPUT_FILTER=off)"


# --------------------------------------------------------------------------- #
# check --dry-run (deploy.sh Phase 1)
# --------------------------------------------------------------------------- #
def test_dry_run_as_root_syntax_checks_and_applies_nothing(relay: Relay) -> None:
    proc = relay.run("check", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert [c.split()[:2] for c in relay.calls() if c.startswith("nft")] == [["nft", "-c"]]
    assert relay.nft_input.read_text(encoding="utf-8") == CAPTURED_RULESET.read_text(encoding="utf-8") + INPUT_RENDER_22
    assert not any(c.startswith(("sysctl", "probe", "systemd-run")) for c in relay.calls())
    assert not any(c.startswith("systemctl") for c in relay.calls())
    assert "nothing applied" in proc.stdout
    assert "input filter: on (policy drop); ssh tcp: 22" in proc.stdout
    assert "is NOT confirmed" in proc.stdout and "apply arms a 300s dead-man" in proc.stdout


def test_dry_run_reports_a_confirmed_set(confirmed: Relay) -> None:
    proc = confirmed.run("check", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert "tcp 22 is confirmed" in proc.stdout and "no confirmation needed" in proc.stdout


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
    """The live listings (tabs, blank lines, growing counters) equal the render."""
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check OK" in proc.stdout
    assert "ok: table inet vpnrelay_input matches the render (policy drop; ssh tcp 22)" in proc.stdout
    assert "ok: tcp/22 on 0.0.0.0 :: (sshd,systemd) — ssh" in proc.stdout
    assert "ok: udp/546 on fe80::be24:11ff:febf:df1d (systemd-network) — dhcpv6 client" in proc.stdout
    assert "/53 " not in proc.stdout, "loopback listeners are not judged"
    assert "probe tcp 150.251.152.243 443" in relay.calls()
    assert not any(c.startswith("probe tls") for c in relay.calls()), "no SNI -> no handshake"
    assert "RELAY_CHECK_SNI not set" in proc.stdout


def test_check_is_read_only(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0     # with a pending confirmation to look at
    relay.clear_calls()
    relay.run("check")
    assert [c for c in relay.calls() if c.startswith("nft")] == [
        "nft list table ip vpnrelay", "nft list table inet vpnrelay_input",
    ]
    assert [c for c in relay.calls() if c.startswith("sysctl")] == [
        "sysctl -n net.ipv4.ip_forward",
        "sysctl -n net.netfilter.nf_conntrack_max",
        "sysctl -n net.netfilter.nf_conntrack_tcp_timeout_established",
        "sysctl -n net.netfilter.nf_conntrack_count",
    ]
    assert [c for c in relay.calls() if c.startswith("systemctl")] == [f"systemctl is-active {DEADMAN_TIMER}"]
    assert not any(c.startswith(("modprobe", "systemd-run", "logger")) for c in relay.calls())


def test_check_shows_a_pending_confirmation_without_failing(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "input filter: PENDING CONFIRM (reverts at" in proc.stdout


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


def test_check_absent_input_table_is_16(relay: Relay) -> None:
    relay.set_input_live(None)
    proc = relay.run("check")
    assert proc.returncode == 16, proc.stdout + proc.stderr
    assert "table inet vpnrelay_input is absent although RELAY_INPUT_FILTER=on" in proc.stderr


def test_check_names_the_dead_man_when_it_removed_the_filter(relay: Relay) -> None:
    assert relay.run("apply").returncode == 0
    assert relay.run("input-off").returncode == 0
    proc = relay.run("check")
    assert proc.returncode == 16
    assert "the dead-man removed it at" in proc.stderr and "(tcp 22 was not confirmed)" in proc.stderr


@pytest.mark.parametrize(
    ("live", "fragment"),
    [
        # policy accept: the drop policy is the point
        (INPUT_LIVE_LISTING.read_text(encoding="utf-8").replace("policy drop;", "policy accept;"),
         "+type filter hook input priority filter; policy drop;"),
        # a rule added by hand
        (INPUT_LIVE_LISTING.read_text(encoding="utf-8").replace(
            '\t\ttcp dport 22 accept comment "ssh"\n',
            '\t\ttcp dport 22 accept comment "ssh"\n\t\ttcp dport 3306 accept\n'),
         "-tcp dport 3306 accept"),
    ],
)
def test_check_different_input_table_is_17_with_a_diff(relay: Relay, live: str, fragment: str) -> None:
    relay.set_input_live(live)
    proc = relay.run("check")
    assert proc.returncode == 17, proc.stdout + proc.stderr
    assert fragment in proc.stderr


def test_check_sees_an_ssh_port_that_moved(relay: Relay) -> None:
    """sshd now listens on 2222: the live filter (22) would cut new sessions."""
    relay.ss_text = _ss(("tcp", "0.0.0.0:2222", f"users:(({SSHD}))"))
    proc = relay.run("check")
    assert proc.returncode == 17, proc.stdout + proc.stderr
    assert '+tcp dport 2222 accept comment "ssh"' in proc.stderr


def test_check_a_port_that_listens_but_is_filtered_is_18(relay: Relay) -> None:
    """A new service would be silently dead behind the drop policy."""
    relay.ss_text += _ss(
        ("tcp", "0.0.0.0:8080", 'users:(("nginx",pid=900,fd=6))'),
        ("tcp", "[::]:8080", 'users:(("nginx",pid=900,fd=7))'),
        ("udp", "0.0.0.0:51820", ""),
        ("tcp", "127.0.0.1:9000", 'users:(("php-fpm",pid=5,fd=3))'),  # loopback: fine
    )
    proc = relay.run("check")
    assert proc.returncode == 18, proc.stdout + proc.stderr
    assert ("FAIL: tcp/8080 listening but filtered: nginx listens on 0.0.0.0 :: and the input filter drops it"
            " — open it (RELAY_INPUT_EXTRA_TCP=8080) or declare it closed (RELAY_INPUT_CLOSED_TCP=8080)") in proc.stderr
    assert "FAIL: udp/51820 listening but filtered: ? listens on 0.0.0.0" in proc.stderr
    assert "9000" not in proc.stderr


def test_check_an_open_or_declared_port_is_fine(relay: Relay) -> None:
    relay.write_env(
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_EXTRA_TCP=8080\nRELAY_INPUT_CLOSED_UDP=51820\n"
    )
    relay.ss_text += _ss(("tcp", "0.0.0.0:8080", 'users:(("nginx",pid=900,fd=6))'), ("udp", "0.0.0.0:51820", ""))
    relay.set_input_live(relay.run("show").stdout.split(INPUT_HEAD, 1)[1])
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok: tcp/8080 on 0.0.0.0 (nginx) — RELAY_INPUT_EXTRA_TCP" in proc.stdout
    assert "ok: udp/51820 on 0.0.0.0 (?) — closed on purpose (RELAY_INPUT_CLOSED_UDP)" in proc.stdout


def test_check_dhcpv6_is_allowed_on_ipv6_only(relay: Relay) -> None:
    """udp 546 passes the DHCPv6 rule only for IPv6 (it matches ip6 saddr fe80::/10)."""
    relay.ss_text += _ss(("udp", "0.0.0.0:546", ""))
    proc = relay.run("check")
    assert proc.returncode == 18
    assert "FAIL: udp/546 listening but filtered" in proc.stderr


def test_check_forwarding_off_is_12(relay: Relay) -> None:
    relay.forward = "0"
    assert relay.run("check").returncode == 12


@pytest.mark.parametrize(
    ("key", "value", "fragment"),
    [
        (CT_MAX, "262144", "nf_conntrack_max = 262144, expected 65536 (RELAY_CONNTRACK_MAX)"),
        (CT_EST, "432000", "nf_conntrack_tcp_timeout_established = 432000, expected 86400"),
        (CT_MAX, None, "nf_conntrack_max = <unreadable>, expected 65536"),
    ],
)
def test_check_conntrack_sysctl_differs_is_15(relay: Relay, key: str, value: str | None, fragment: str) -> None:
    relay.sysctls[key] = value
    proc = relay.run("check")
    assert proc.returncode == 15, proc.stdout + proc.stderr
    assert f"FAIL: net.netfilter.{fragment}" in proc.stderr
    assert "ok: table ip vpnrelay matches" in proc.stdout, "the table step still reports"


def test_check_compares_conntrack_with_the_env_values(relay: Relay) -> None:
    relay.write_env(
        f"RELAY_UPSTREAM_IPV4={UPSTREAM}\n"
        "RELAY_CONNTRACK_MAX=262144\nRELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT=7200\n"
    )
    assert relay.run("check").returncode == 15, "the live 65536/86400 are not what .env asks for"
    relay.sysctls.update({CT_MAX: "262144", CT_EST: "7200"})
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ok: net.netfilter.nf_conntrack_max = 262144" in proc.stdout
    assert "ok: net.netfilter.nf_conntrack_tcp_timeout_established = 7200" in proc.stdout


def test_check_exit_order_is_input_then_forwarding_then_conntrack_then_the_probes(relay: Relay) -> None:
    relay.sysctls[CT_MAX] = "262144"
    relay.tcp_rc = 1
    proc = relay.run("check")
    assert proc.returncode == 15, "conntrack (local state) comes before the upstream probe"
    assert "FAIL: TCP connect" in proc.stderr, "the probe still runs and reports"
    relay.forward = "0"
    assert relay.run("check").returncode == 12
    relay.ss_text += _ss(("tcp", "0.0.0.0:8080", 'users:(("nginx",pid=900,fd=6))'))
    assert relay.run("check").returncode == 18
    relay.set_input_live(None)
    assert relay.run("check").returncode == 16
    relay.live_listing = None
    assert relay.run("check").returncode == 10


@pytest.mark.parametrize(
    ("count", "warned"),
    [("52429", True), ("52428", False), ("0", False), ("65536", True)],
)
def test_check_warns_over_80_percent_conntrack_without_failing(relay: Relay, count: str, warned: bool) -> None:
    relay.sysctls[CT_COUNT] = count  # 80% of 65536 = 52428.8
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "check OK" in proc.stdout
    assert ("WARNING: conntrack table" in proc.stderr) is warned
    if warned:
        assert f"{count} of 65536 (over 80%)" in proc.stderr and "RELAY_CONNTRACK_MAX" in proc.stderr
    else:
        assert f"conntrack in use: {count} of 65536" in proc.stdout


def test_check_measures_fill_against_the_live_max(relay: Relay) -> None:
    """The kernel drops at ITS limit: with a live max that differs from .env the
    warning still compares against the live value (and the check fails with 15)."""
    relay.sysctls.update({CT_MAX: "10000", CT_COUNT: "9000"})
    proc = relay.run("check")
    assert proc.returncode == 15
    assert "WARNING: conntrack table 9000 of 10000 (over 80%)" in proc.stderr


def test_check_without_a_readable_count_does_not_warn(relay: Relay) -> None:
    relay.sysctls[CT_COUNT] = None
    proc = relay.run("check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING" not in proc.stderr and "conntrack in use" not in proc.stdout


def test_helper_never_reads_proc_net_stat() -> None:
    """/proc/net/stat/nf_conntrack does not exist on the relay's 6.8 kernel: the fill
    level comes from the nf_conntrack_count sysctl. Code only (the header says why)."""
    code = _code()
    assert "net.netfilter.nf_conntrack_count" in code
    assert "/proc/net/stat" not in code


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
    relay.set_input_live(None)
    relay.forward = "0"
    relay.tcp_rc = 1
    proc = relay.run("check")
    assert proc.returncode == 10
    for fragment in ("table ip vpnrelay is absent", "table inet vpnrelay_input is absent", "ip_forward = 0",
                     "TCP connect"):
        assert fragment in proc.stderr


def test_check_requires_root(relay: Relay) -> None:
    relay.uid = "1000"
    assert relay.run("check").returncode == 5


# --------------------------------------------------------------------------- #
# The sandbox itself: nothing of the environment the suite runs in leaks in
# --------------------------------------------------------------------------- #
def test_the_sandbox_pins_every_override_against_the_environment(
    relay: Relay, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """deploy.sh runs this suite as its Phase 1 gate ON the relay (cf. #325): an
    override or JOURNAL_STREAM in that environment must not steer a run. The setenv
    stands for a leak past the conftest scrub."""
    leak = tmp_path / "leak"
    for name in ("RELAY_STATE_DIR", "RELAY_RUN_DIR", "RELAY_ENV", "RELAY_SYSCTL_FILE"):
        monkeypatch.setenv(name, str(leak / name))
    monkeypatch.setenv("JOURNAL_STREAM", "8:1")
    assert relay.run("apply").returncode == 0
    assert relay.run("input-off").returncode == 0
    assert not leak.exists(), "a leaked override was used"
    assert relay.reverted.exists()
    assert [c for c in relay.calls() if c.startswith("logger")], "JOURNAL_STREAM did not leak in"


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
