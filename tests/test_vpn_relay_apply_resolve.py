"""scripts/vpn-relay-apply with a DNS name as the upstream (RELAY_UPSTREAM_HOST).

nftables resolves a name only when a ruleset is loaded, so the helper never puts a
name into the table: it resolves RELAY_UPSTREAM_HOST itself at every render, and
`resolve` (vpn-relay-resolve.timer, every 5 minutes) reloads the table — through the
very `apply` path, one atomic `nft -f` — only when the live DNAT target is no longer
one of the name's addresses. Pinned here, with the sandbox of
tests/test_vpn_relay_apply.py plus a `getent` stub:

* exactly one of RELAY_UPSTREAM_IPV4 / RELAY_UPSTREAM_HOST, a name that is a name;
* the rendered table carries an ADDRESS, the same table as with RELAY_UPSTREAM_IPV4;
* among several A records the live one is kept (round-robin answers do not reload);
* a name that does not resolve falls back to the last-known address of THAT name,
  else exit 20 with nothing applied;
* `resolve`: unchanged address -> no nft -f; changed -> exactly one nft -f with the
  new address; unresolvable -> exit 20, the live table untouched; no name -> no-op;
* the timer and its service are what the docs say.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from test_vpn_relay_apply import UPSTREAM, Relay, _stub, forward_part

ROOT = Path(__file__).resolve().parents[1]
HOST = "vpn.example.com"
NEW = "198.51.100.20"

pytestmark = pytest.mark.timeout(60)


class NamedRelay(Relay):
    """The sandbox with a getent stub: ``self.dns`` maps a name to its A records."""

    def __init__(self, tmp_path: Path) -> None:
        super().__init__(tmp_path)
        self.dns: dict[str, list[str]] = {HOST: [UPSTREAM]}
        self.upstream_state = self.state_dir / "upstream.resolved"

    def _install_stubs(self) -> None:
        super()._install_stubs()
        table = self.tmp / "dns.txt"
        table.write_text(
            "".join(f"{name} {addr}\n" for name, addrs in self.dns.items() for addr in addrs), encoding="utf-8"
        )
        _stub(
            self.bin / "getent",
            f'echo "getent $*" >> "{self.log}"\n'
            f'[[ "$1" == "ahostsv4" ]] || exit 1\n'
            f'found=0\n'
            f'while read -r n a; do\n'
            f'  if [[ "$n" == "$2" ]]; then printf "%s      STREAM %s\\n%s      DGRAM\\n" "$a" "$2" "$a"; found=1; fi\n'
            f'done < "{table}"\n'
            f'(( found )) || exit 2\n',
        )

    def nft_files(self) -> list[str]:
        return [c for c in self.calls() if c.startswith("nft -f")]


@pytest.fixture
def named(tmp_path: Path) -> NamedRelay:
    r = NamedRelay(tmp_path)
    r.write_env(f"NODE_ROLE=relay\nRELAY_UPSTREAM_HOST={HOST}\nRELAY_INPUT_FILTER=off\n")
    return r


def _ip_relay(tmp_path: Path) -> NamedRelay:
    (tmp_path / "ip").mkdir(exist_ok=True)
    r = NamedRelay(tmp_path / "ip")
    r.write_env(f"NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_INPUT_FILTER=off\n")
    return r


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def test_both_upstreams_are_refused(named: NamedRelay) -> None:
    named.write_env(f"RELAY_UPSTREAM_IPV4={UPSTREAM}\nRELAY_UPSTREAM_HOST={HOST}\n")
    result = named.run("show")
    assert result.returncode == 3
    assert "both set" in result.stderr


def test_neither_upstream_is_refused(named: NamedRelay) -> None:
    named.write_env("NODE_ROLE=relay\n")
    result = named.run("show")
    assert result.returncode == 3
    assert "neither RELAY_UPSTREAM_IPV4 nor RELAY_UPSTREAM_HOST" in result.stderr


@pytest.mark.parametrize(
    "value",
    ["203.0.113.5", "localhost", "-bad.example.com", "a..b", "x" * 64 + ".com", "vpn.example.com;id", "vpn example.com"],
)
def test_upstream_host_must_be_a_dns_name(named: NamedRelay, value: str) -> None:
    named.write_env(f"RELAY_UPSTREAM_HOST={value}\n")
    result = named.run("show")
    assert result.returncode == 3, result.stderr
    assert not named.nft_files()


def test_a_name_renders_the_same_table_as_its_address(named: NamedRelay, tmp_path: Path) -> None:
    by_name = named.run("show")
    assert by_name.returncode == 0, by_name.stderr
    by_ip = _ip_relay(tmp_path).run("show")
    assert by_ip.returncode == 0, by_ip.stderr
    assert forward_part(by_name.stdout) == forward_part(by_ip.stdout)
    assert HOST not in by_name.stdout, "nft must never get the name itself"


def test_the_live_address_is_kept_among_several(named: NamedRelay) -> None:
    # The live table (fixture) DNATs to UPSTREAM; a lower address appears too.
    named.dns[HOST] = ["10.9.9.9", "1.2.3.4", UPSTREAM]
    result = named.run("show")
    assert result.returncode == 0, result.stderr
    assert f"dnat to {UPSTREAM}:443" in result.stdout
    assert "10.9.9.9" not in result.stdout


def test_without_a_live_table_the_lowest_address_wins(named: NamedRelay) -> None:
    named.live_listing = None
    named.dns[HOST] = ["203.0.113.9", "198.51.100.30", "198.51.100.4"]
    result = named.run("show")
    assert result.returncode == 0, result.stderr
    assert "dnat to 198.51.100.4:443" in result.stdout


def test_non_unicast_answers_are_ignored(named: NamedRelay) -> None:
    named.live_listing = None
    named.dns[HOST] = ["127.0.0.1", "0.0.0.0", "240.0.0.1", NEW]
    result = named.run("show")
    assert result.returncode == 0, result.stderr
    assert f"dnat to {NEW}:443" in result.stdout


# --------------------------------------------------------------------------- #
# apply and the last-known address
# --------------------------------------------------------------------------- #
def test_apply_remembers_the_address_of_the_name(named: NamedRelay) -> None:
    result = named.run("apply")
    assert result.returncode == 0, result.stderr
    state = named.kv(named.upstream_state)
    assert state["host"] == HOST
    assert state["ipv4"] == UPSTREAM
    assert len(named.nft_files()) == 1


def test_apply_with_an_address_writes_no_upstream_state(tmp_path: Path) -> None:
    relay = _ip_relay(tmp_path)
    assert relay.run("apply").returncode == 0
    assert not relay.upstream_state.exists()


def test_unresolvable_name_falls_back_to_its_last_known_address(named: NamedRelay) -> None:
    named.state_dir.mkdir(parents=True, exist_ok=True)
    named.upstream_state.write_text(f"host={HOST}\nipv4={NEW}\nat=1\n", encoding="utf-8")
    named.dns = {}
    result = named.run("apply")
    assert result.returncode == 0, result.stderr
    assert "does not resolve right now" in result.stderr
    assert f"dnat to {NEW}:443" in named.applied_files()[-1]


def test_last_known_address_of_another_name_is_not_used(named: NamedRelay) -> None:
    named.state_dir.mkdir(parents=True, exist_ok=True)
    named.upstream_state.write_text(f"host=old.example.com\nipv4={NEW}\nat=1\n", encoding="utf-8")
    named.dns = {}
    result = named.run("apply")
    assert result.returncode == 20
    assert not named.nft_files(), "nothing may be applied"
    assert not any(c.startswith("sysctl -q -w") for c in named.calls())


# --------------------------------------------------------------------------- #
# resolve (the timer)
# --------------------------------------------------------------------------- #
def test_resolve_with_an_unchanged_address_applies_nothing(named: NamedRelay) -> None:
    result = named.run("resolve")
    assert result.returncode == 0, result.stderr
    assert "unchanged" in result.stdout
    assert not named.nft_files()


def test_resolve_reloads_the_table_once_on_a_new_address(named: NamedRelay) -> None:
    named.dns[HOST] = [NEW]
    result = named.run("resolve")
    assert result.returncode == 0, result.stderr
    files = named.applied_files()
    assert len(files) == 1, "exactly one atomic nft -f"
    rendered = files[0]
    assert rendered.startswith("table ip vpnrelay\ndelete table ip vpnrelay\n"), "create + delete + table: atomic"
    assert f"dnat to {NEW}:443" in rendered and UPSTREAM not in rendered
    assert rendered.count("dnat to") == 2, "tcp + udp, no duplicate DNAT"
    assert named.kv(named.upstream_state)["ipv4"] == NEW


def test_resolve_failure_leaves_the_live_table_alone(named: NamedRelay) -> None:
    named.dns = {}
    result = named.run("resolve")
    assert result.returncode == 20
    assert "left as it is" in result.stderr
    assert not named.nft_files()


def test_resolve_applies_when_the_table_is_absent(named: NamedRelay) -> None:
    named.live_listing = None
    result = named.run("resolve")
    assert result.returncode == 0, result.stderr
    assert len(named.nft_files()) == 1


def test_resolve_without_a_name_is_a_no_op(tmp_path: Path) -> None:
    relay = _ip_relay(tmp_path)
    result = relay.run("resolve")
    assert result.returncode == 0, result.stderr
    assert "nothing to do" in result.stdout
    assert not any(c.startswith(("nft", "getent")) for c in relay.calls())


def test_resolve_needs_root(named: NamedRelay) -> None:
    named.uid = "1000"
    assert named.run("resolve").returncode == 5


def test_resolve_takes_no_argument(named: NamedRelay) -> None:
    assert named.run("resolve", "now").returncode == 2


def test_check_with_a_name_compares_against_the_resolved_address(named: NamedRelay) -> None:
    named.dns[HOST] = [NEW]
    result = named.run("check")
    assert result.returncode == 11, "the live table still points at the old address"


# --------------------------------------------------------------------------- #
# The units
# --------------------------------------------------------------------------- #
def test_timer_runs_the_resolve_service_every_five_minutes() -> None:
    timer = (ROOT / "deploy" / "relay" / "vpn-relay-resolve.timer").read_text(encoding="utf-8")
    service = (ROOT / "deploy" / "relay" / "vpn-relay-resolve.service").read_text(encoding="utf-8")
    assert "OnUnitActiveSec=5min" in timer
    assert "Unit=vpn-relay-resolve.service" in timer
    assert "WantedBy=timers.target" in timer
    assert "Type=oneshot" in service
    assert "ExecStart=/usr/local/sbin/vpn-relay-apply resolve" in service


def test_env_example_documents_the_name() -> None:
    text = (ROOT / "deploy" / "relay" / "relay.env.example").read_text(encoding="utf-8")
    assert "RELAY_UPSTREAM_HOST=" in text
