"""scripts/vpn-relay-agent — the forced command of the main bot's key on a relay.

Pinned, by running the shipped script (and by loading it as a module for the pure
parts):

* **The whitelist.** Only `hello <token>`, `status`, `apply target=… tcp=… udp=…`,
  `update`, `uninstall` — full-string matches. Everything else (shell syntax, extra
  words, a second line, control or non-ASCII characters, an over-long request, argv)
  is refused with exit 2 BEFORE any host command runs.
* **Arguments.** A target that is not a DNS name, ports outside 1..65535, leading
  zeros, duplicates, more than 8 ports, a TCP port sshd listens on — refused.
* **Pairing.** Before `hello` nothing but `hello` works; the token is compared with
  the stored sha256 (constant time) within the expiry (+ grace); a repeat with the
  same token answers again, any other token is refused.
* **apply** rewrites only the four upstream/port keys of .env, and puts .env back and
  re-applies when the ruleset or its check fails.
* **uninstall** removes what the installer installed and only the agent's own
  authorized_keys line; it refuses a host that is not an installer relay.

External commands are stubs (VPN_RELAY_AGENT_SELFTEST_BIN); every path is re-rooted
under a temporary directory (VPN_RELAY_AGENT_ROOT).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "scripts" / "vpn-relay-agent"
TOKEN = "A" * 20 + "b-_" + "9" * 20
OTHER = "Z" * 43
KEY_LINE = 'restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBB vpn-relay-agent\n'
OPERATOR_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPER operator@laptop\n"

pytestmark = pytest.mark.timeout(60)


def _load() -> ModuleType:
    loader = SourceFileLoader("vpn_relay_agent", str(AGENT))
    spec = spec_from_loader("vpn_relay_agent", loader)
    assert spec is not None
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


agent = _load()


# --------------------------------------------------------------------------- #
# The whitelist (pure)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("raw", "name", "args"),
    [
        ("status", "status", {}),
        ("update", "update", {}),
        ("uninstall", "uninstall", {}),
        (f"hello {TOKEN}", "hello", {"token": TOKEN}),
        ("apply target=vpn.example.com tcp=443 udp=443", "apply", {"target": "vpn.example.com", "tcp": "443", "udp": "443"}),
        ("apply target=a-b.example.org tcp=443,8443 udp=443", "apply", {"target": "a-b.example.org", "tcp": "443,8443", "udp": "443"}),
    ],
)
def test_whitelisted_requests(raw: str, name: str, args: dict[str, str]) -> None:
    assert agent.parse_request(raw) == (name, args)


INJECTIONS = [
    None,
    "",
    " status",
    "status ",
    "STATUS",
    "status; id",
    "status && id",
    "status | sh",
    "status\nuninstall",
    "status\x00",
    "status\tnow",
    "$(id)",
    "`id`",
    "status $(reboot)",
    "update --force",
    "uninstall now",
    "--internal-update",
    "--internal-uninstall",
    "hello",
    f"hello {TOKEN} extra",
    f"hello {TOKEN[:-1]}",
    f"hello {TOKEN}x",
    f"hello {TOKEN[:-1]};",
    "hello ../../etc/shadow",
    "apply target=vpn.example.com tcp=443",
    "apply target=vpn.example.com tcp=443 udp=443 extra=1",
    "apply target=vpn.example.com;id tcp=443 udp=443",
    "apply target=$(id) tcp=443 udp=443",
    "apply target=vpn.example.com tcp=443;id udp=443",
    "apply target=vpn.example.com tcp=443 udp=443\nuninstall",
    "apply tcp=443 udp=443 target=vpn.example.com",
    "apply target=vpn.example.com tcp= udp=443",
    "apply target=vpn.example.com tcp=1,2,3,4,5,6,7,8,9 udp=443",
    "apply target=vpn.exämple.com tcp=443 udp=443",
    "status" + " " * 600,
    "sh -c id",
    "scp -t /root",
    "rsync --server . /",
    "internal-sftp",
]


@pytest.mark.parametrize("raw", INJECTIONS)
def test_everything_else_is_refused(raw: str | None) -> None:
    with pytest.raises(agent.Refused):
        agent.parse_request(raw)


@pytest.mark.parametrize("target", ["vpn.example.com", "a.b", "x-1.example.co.uk", "A.EXAMPLE.COM"])
def test_dns_names_accepted(target: str) -> None:
    assert agent.valid_dns_name(target)


@pytest.mark.parametrize(
    "target",
    ["203.0.113.5", "localhost", "example", "-a.example.com", "a-.example.com", "a..b", "example.com.",
     "x" * 64 + ".com", ".example.com", "example.123"],
)
def test_dns_names_refused(target: str) -> None:
    assert not agent.valid_dns_name(target)


@pytest.mark.parametrize(("raw", "ports"), [("443", [443]), ("8443,443", [443, 8443]), ("1,65535", [1, 65535])])
def test_ports(raw: str, ports: list[int]) -> None:
    assert agent.parse_ports(raw) == ports


@pytest.mark.parametrize("raw", ["0", "65536", "0443", "443,443", "1,2,3,4,5,6,7,8,9", "", "443,", "-1"])
def test_bad_ports(raw: str) -> None:
    with pytest.raises(agent.Refused):
        agent.parse_ports(raw)


def test_env_with_replaces_last_assignment_and_drops_the_rest() -> None:
    text = (
        "# relay\nNODE_ROLE=relay\nRELAY_UPSTREAM_IPV4=203.0.113.10\n"
        "export RELAY_FORWARD_TCP_PORTS = 443  # comment\nRELAY_FORWARD_TCP_PORTS=8443\nSSH_PORT=22\n"
    )
    out = agent.env_with(text, {"RELAY_UPSTREAM_IPV4": None, "RELAY_UPSTREAM_HOST": "vpn.example.com",
                                "RELAY_FORWARD_TCP_PORTS": "443"})
    assert out == "# relay\nNODE_ROLE=relay\nRELAY_FORWARD_TCP_PORTS=443\nSSH_PORT=22\nRELAY_UPSTREAM_HOST=vpn.example.com\n"
    assert agent.env_value(out, "RELAY_FORWARD_TCP_PORTS") == "443"
    assert agent.env_value(text, "RELAY_FORWARD_TCP_PORTS") == "8443"


# --------------------------------------------------------------------------- #
# The sandbox: the real script, stubs on a private bin dir, a fake root
# --------------------------------------------------------------------------- #
STUB_LOG = r"""
echo "$(basename "$0") $*" >> "@LOG@"
"""


class Host:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.log = tmp / "calls.log"
        for d in ("opt/vpn-service", "etc/vpn-relay", "etc/systemd/system", "etc/sysctl.d", "var/lib/vpn-relay",
                  "run", "root/.ssh", "usr/local/sbin"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        self.env_path = self.root / "opt/vpn-service/.env"
        self.env_path.write_text(
            "NODE_ROLE=relay\nSSH_PORT=22\nRELAY_UPSTREAM_HOST=vpn.example.com\n"
            "RELAY_FORWARD_TCP_PORTS=443\nRELAY_FORWARD_UDP_PORTS=443\nRELAY_INPUT_FILTER=off\n",
            encoding="utf-8",
        )
        self.pairing_path = self.root / "etc/vpn-relay/pairing.json"
        self.keys = self.root / "root/.ssh/authorized_keys"
        self.keys.write_text(OPERATOR_LINE + KEY_LINE + "# keep me\n", encoding="utf-8")
        self.apply_rc: list[int] = [0]
        self.check_rc = 0
        # Extra lines `vpn-relay-apply check` prints (FAIL lines decide what apply keeps).
        self.check_output = "vpn-relay-apply: ok: table ip vpnrelay matches"
        # Tables `nft delete` cannot remove (uninstall must then keep the key).
        self.undeletable: set[str] = set()
        self.dns = {"vpn.example.com": "203.0.113.10", "new.example.com": "198.51.100.20"}
        self.sshd_ports = [22]
        self.stubs()

    def pair(self, *, exp: int | None = None, paired: bool = False, token: str = TOKEN) -> None:
        data: dict[str, Any] = {
            "v": 1,
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "exp": int(time.time()) + 1800 if exp is None else exp,
            "paired_at": int(time.time()) if paired else None,
        }
        self.pairing_path.write_text(json.dumps(data), encoding="utf-8")

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        # /bin/bash, not env: the stub dir is first on PATH and holds a `bash` stub.
        path.write_text("#!/bin/bash\n" + STUB_LOG.replace("@LOG@", str(self.log)) + body, encoding="utf-8")
        path.chmod(0o755)

    def stubs(self) -> None:
        rcs = self.tmp / "apply-rcs"
        rcs.write_text("\n".join(map(str, self.apply_rc)) + "\n", encoding="utf-8")
        self.stub(
            "vpn-relay-apply",
            f'if [[ "$1" == apply ]]; then\n'
            f'  n=$(grep -c "^vpn-relay-apply apply" "{self.log}")\n'
            f'  rc=$(sed -n "${{n}}p" "{rcs}"); [[ -n "$rc" ]] || rc=$(tail -n1 "{rcs}")\n'
            f'  cp "{self.env_path}" "{self.tmp}/env-at-apply-$n"\n'
            f'  cache="{self.root}/etc/vpn-relay/upstream.resolved"\n'
            f'  if [[ -f "$cache" ]]; then cp "$cache" "{self.tmp}/cache-at-apply-$n"; fi\n'
            # like the real helper: an apply remembers the address of the name it applied
            f'  h=$(sed -n "s/^RELAY_UPSTREAM_HOST=//p" "{self.env_path}" | tail -n1)\n'
            f'  printf "host=%s\\nipv4=192.0.2.99\\nat=1\\n" "$h" > "$cache"\n'
            f'  echo "applied"; exit "$rc"\nfi\n'
            f'if [[ "$1" == check ]]; then cat "{self.tmp}/check-output"; exit {self.check_rc}; fi\nexit 0\n',
        )
        hosts = "\n".join(f'  {n}) echo "{a}      STREAM {n}";;' for n, a in self.dns.items())
        self.stub("getent", f'case "$2" in\n{hosts}\n  *) exit 2;;\nesac\n')
        (self.tmp / "check-output").write_text(self.check_output + "\n", encoding="utf-8")
        gone = self.tmp / "nft-gone"
        gone.mkdir(exist_ok=True)
        stuck = " ".join(self.undeletable)
        self.stub(
            "nft",
            f'if [[ "$1" == delete ]]; then case " {stuck} " in *" $3-$4 "*) exit 1;; esac; touch "{gone}/$3-$4"; exit 0; fi\n'
            f'if [[ "$1" == list && -e "{gone}/$3-$4" ]]; then echo "Error: No such file or directory" >&2; exit 1; fi\n'
            'echo "table ip vpnrelay { chain pre { iifname \\"eth0\\" tcp dport 443 counter dnat to 203.0.113.10:443 } }"\n',
        )
        ss = "\n".join(f'LISTEN 0 4096 0.0.0.0:{p} 0.0.0.0:* users:(("sshd",pid=1,fd=3))' for p in self.sshd_ports)
        self.stub("ss", f"cat <<'EOF'\n{ss}\nEOF\n")
        self.stub("systemctl", 'case "$1" in is-active) echo active;; esac\nexit 0\n')
        self.stub("sysctl", 'echo 1\n')
        self.stub("ip", 'echo "203.0.113.10 via 192.0.2.1 dev eth0 src 192.0.2.50 uid 0"\n')
        self.stub("git", 'echo 0123456789abcdef0123456789abcdef01234567\n')
        self.stub("logger", "exit 0\n")
        self.stub("systemd-run", "exit 0\n")
        # update/uninstall run the agent again (the internal entry) — the real one.
        (self.bin / "vpn-relay-agent").write_text(
            f'#!/bin/bash\nexec "{sys.executable}" -I "{AGENT}" "$@"\n', encoding="utf-8"
        )
        (self.bin / "vpn-relay-agent").chmod(0o755)

    def run(self, request: str | None, *argv: str, ssh: bool = False) -> tuple[int, dict[str, Any]]:
        self.stubs()
        env = {
            "PATH": os.environ["PATH"],
            "VPN_RELAY_AGENT_SELFTEST": "1",
            "VPN_RELAY_AGENT_ROOT": str(self.root),
            "VPN_RELAY_AGENT_SELFTEST_BIN": str(self.bin),
        }
        if request is not None:
            env["SSH_ORIGINAL_COMMAND"] = request
        if ssh:
            env["SSH_CONNECTION"] = "192.0.2.1 50000 192.0.2.50 22"
        result = subprocess.run(
            [sys.executable, "-I", str(AGENT), *argv], env=env, capture_output=True, text=True, check=False, timeout=50
        )
        try:
            payload = json.loads(result.stdout) if result.stdout.strip() else {}
        except ValueError:
            payload = {"raw": result.stdout, "stderr": result.stderr}
        return result.returncode, payload

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []

    def host_calls(self) -> list[str]:
        """Every call except the journal line."""
        return [c for c in self.calls() if not c.startswith("logger")]


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


@pytest.mark.parametrize("raw", [r for r in INJECTIONS if r is not None and "\x00" not in r])  # env cannot carry NUL
def test_refused_requests_touch_nothing(host: Host, raw: str) -> None:
    host.pair(paired=True)
    rc, payload = host.run(raw)
    assert rc == 2
    assert payload["ok"] is False and payload["error"].startswith("refused")
    assert host.host_calls() == [], "nothing may run for a refused request"


def test_no_request_is_refused(host: Host) -> None:
    rc, payload = host.run(None)
    assert rc == 2 and payload["ok"] is False


def test_argv_is_refused(host: Host) -> None:
    host.pair(paired=True)
    rc, payload = host.run("status", "status")
    assert rc == 2 and "arguments are not accepted" in payload["error"]
    assert host.host_calls() == []


def test_internal_entry_points_refuse_an_ssh_session(host: Host) -> None:
    for entry in ("--internal-update", "--internal-uninstall"):
        rc, _ = host.run(None, entry, ssh=True)
        assert rc == 2
    assert host.calls() == []


def test_the_journal_never_sees_the_token(host: Host) -> None:
    host.pair()
    host.run(f"hello {TOKEN}")
    host.run(f"hello {OTHER}")
    logged = [c for c in host.calls() if c.startswith("logger")]
    assert logged and all(TOKEN not in c and OTHER not in c for c in logged)


# --------------------------------------------------------------------------- #
# Pairing
# --------------------------------------------------------------------------- #
def test_nothing_but_hello_before_pairing(host: Host) -> None:
    host.pair()
    for request in ("status", "update", "uninstall", "apply target=new.example.com tcp=443 udp=443"):
        rc, payload = host.run(request)
        assert rc == 3, request
        assert "not paired" in payload["error"]


def test_hello_pairs_and_reports_the_facts(host: Host) -> None:
    host.pair()
    rc, payload = host.run(f"hello {TOKEN}")
    assert rc == 0, payload
    assert payload["ok"] is True and payload["cmd"] == "hello"
    assert payload["protocol"] == 1
    assert payload["target_host"] == "vpn.example.com"
    assert payload["tcp"] == [443] and payload["udp"] == [443]
    assert payload["live_target"] == "203.0.113.10"
    assert payload["egress"] == {"src": "192.0.2.50", "dev": "eth0"}
    assert payload["ssh_ports"] == [22]
    stored = json.loads(host.pairing_path.read_text(encoding="utf-8"))
    assert stored["paired_at"] == payload["paired_at"]


def test_hello_again_with_the_same_token_answers_and_another_is_refused(host: Host) -> None:
    host.pair()
    assert host.run(f"hello {TOKEN}")[0] == 0
    first = json.loads(host.pairing_path.read_text(encoding="utf-8"))["paired_at"]
    rc, payload = host.run(f"hello {TOKEN}")
    assert rc == 0 and payload["paired_at"] == first
    rc, payload = host.run(f"hello {OTHER}")
    assert rc == 3 and "does not match" in payload["error"]


def test_wrong_token_does_not_pair(host: Host) -> None:
    host.pair()
    rc, _ = host.run(f"hello {OTHER}")
    assert rc == 3
    assert json.loads(host.pairing_path.read_text(encoding="utf-8"))["paired_at"] is None


def test_expired_code_does_not_pair(host: Host) -> None:
    host.pair(exp=int(time.time()) - agent.HELLO_GRACE_SECONDS - 5)
    rc, payload = host.run(f"hello {TOKEN}")
    assert rc == 3 and "expired" in payload["error"]
    assert json.loads(host.pairing_path.read_text(encoding="utf-8"))["paired_at"] is None


def test_within_the_grace_it_still_pairs(host: Host) -> None:
    host.pair(exp=int(time.time()) - 60)
    assert host.run(f"hello {TOKEN}")[0] == 0


def test_without_a_pairing_file(host: Host) -> None:
    rc, payload = host.run(f"hello {TOKEN}")
    assert rc == 3 and "no pairing" in payload["error"]


# --------------------------------------------------------------------------- #
# status / apply
# --------------------------------------------------------------------------- #
def test_status_runs_the_check(host: Host) -> None:
    host.pair(paired=True)
    rc, payload = host.run("status")
    assert rc == 0
    assert payload["check"]["rc"] == 0
    assert "vpn-relay-apply check" in host.calls()


def test_apply_rewrites_only_the_upstream_keys(host: Host) -> None:
    host.pair(paired=True)
    host.env_path.write_text(
        "NODE_ROLE=relay\nSSH_PORT=22\nRELAY_UPSTREAM_IPV4=203.0.113.10\nRELAY_FORWARD_TCP_PORTS=443\n"
        "RELAY_FORWARD_UDP_PORTS=443\nRELAY_INPUT_FILTER=off\n",
        encoding="utf-8",
    )
    rc, payload = host.run("apply target=new.example.com tcp=443,8443 udp=443")
    assert rc == 0, payload
    env = host.env_path.read_text(encoding="utf-8")
    assert env == (
        "NODE_ROLE=relay\nSSH_PORT=22\nRELAY_FORWARD_TCP_PORTS=443,8443\nRELAY_FORWARD_UDP_PORTS=443\n"
        "RELAY_INPUT_FILTER=off\nRELAY_UPSTREAM_HOST=new.example.com\n"
    )
    assert oct(host.env_path.stat().st_mode & 0o777) == "0o600"
    assert payload["applied"] == {"target": "new.example.com", "tcp": [443, 8443], "udp": [443]}


def test_apply_refuses_the_ssh_port(host: Host) -> None:
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    rc, payload = host.run("apply target=new.example.com tcp=443,22 udp=443")
    assert rc == 2 and "sshd listens" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == before
    assert not any(c.startswith("vpn-relay-apply") for c in host.calls())


@pytest.mark.parametrize(
    "request_",
    ["apply target=203.0.113.9 tcp=443 udp=443", "apply target=localhost tcp=443 udp=443",
     "apply target=new.example.com tcp=0 udp=443", "apply target=new.example.com tcp=443,443 udp=443",
     "apply target=new.example.com tcp=443 udp=070000"],
)
def test_apply_refuses_bad_arguments(host: Host, request_: str) -> None:
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    rc, _ = host.run(request_)
    assert rc == 2
    assert host.env_path.read_text(encoding="utf-8") == before
    assert host.host_calls() == []


def test_apply_refuses_a_name_the_relay_cannot_resolve(host: Host) -> None:
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    rc, payload = host.run("apply target=nowhere.example.com tcp=443 udp=443")
    assert rc == 4 and "does not resolve" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == before


def test_apply_failure_puts_env_back_and_reapplies(host: Host) -> None:
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    host.apply_rc = [6, 0]
    rc, payload = host.run("apply target=new.example.com tcp=443 udp=443")
    assert rc == 4 and "rolled back (restored)" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == before
    assert [c for c in host.calls() if c.startswith("vpn-relay-apply apply")] == ["vpn-relay-apply apply"] * 2
    assert "new.example.com" in (host.tmp / "env-at-apply-1").read_text(encoding="utf-8")
    assert (host.tmp / "env-at-apply-2").read_text(encoding="utf-8") == before


@pytest.mark.parametrize("rc", [124, 127, 1])
def test_apply_rolls_back_on_any_check_result_it_does_not_tolerate(host: Host, rc: int) -> None:
    """A check that timed out (124) or could not run never validated the new upstream."""
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    host.check_rc = rc
    rc_, payload = host.run("apply target=new.example.com tcp=443 udp=443")
    assert rc_ == 4 and f"exit {rc}" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("rc", [16, 17, 18])
def test_apply_keeps_the_forward_when_only_the_input_filter_check_fails(host: Host, rc: int) -> None:
    host.pair(paired=True)
    host.check_rc = rc
    host.check_output = (
        "vpn-relay-apply: FAIL: table inet vpnrelay_input differs from the render\n"
        "vpn-relay-apply: FAIL: tcp/9100 listening but filtered: x listens on 0.0.0.0\n"
        "vpn-relay-apply: ok: TCP connect 198.51.100.20:443"
    )
    assert host.run("apply target=new.example.com tcp=443 udp=443")[0] == 0
    assert "RELAY_UPSTREAM_HOST=new.example.com" in host.env_path.read_text(encoding="utf-8")


def test_apply_rollback_puts_back_the_old_upstream_cache(host: Host) -> None:
    """The first apply writes the NEW name's last-known address; the rollback must put
    the old one back before it re-applies, or a DNS-less moment refuses it (exit 20)."""
    host.pair(paired=True)
    cache = host.root / "etc/vpn-relay/upstream.resolved"
    cache.write_text("host=vpn.example.com\nipv4=203.0.113.10\nat=1\n", encoding="utf-8")
    host.check_rc = 13
    assert host.run("apply target=new.example.com tcp=443 udp=443")[0] == 4
    assert (host.tmp / "cache-at-apply-2").read_text(encoding="utf-8").startswith("host=vpn.example.com\nipv4=203.0.113.10")


def test_apply_rollback_removes_a_cache_that_did_not_exist(host: Host) -> None:
    host.pair(paired=True)
    host.check_rc = 13
    assert host.run("apply target=new.example.com tcp=443 udp=443")[0] == 4
    assert not (host.tmp / "cache-at-apply-2").exists(), "no cache of the new name when the old apply ran"


def test_an_input_filter_exit_code_does_not_hide_a_dead_upstream(host: Host) -> None:
    """check exits with its FIRST failure (the input filter's 18) although TCP failed too."""
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    host.check_rc = 18
    host.check_output = (
        "vpn-relay-apply: FAIL: tcp/9100 listening but filtered: node_exporter listens on 0.0.0.0\n"
        "vpn-relay-apply: FAIL: TCP connect 198.51.100.20:443 failed: timed out"
    )
    rc, payload = host.run("apply target=new.example.com tcp=443 udp=443")
    assert rc == 4 and "rolled back" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == before


def test_apply_with_a_dead_upstream_rolls_back(host: Host) -> None:
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    host.check_rc = 13
    rc, payload = host.run("apply target=new.example.com tcp=443 udp=443")
    assert rc == 4 and "exit 13" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == before


# --------------------------------------------------------------------------- #
# uninstall
# --------------------------------------------------------------------------- #
def _installed(host: Host, *, created_app_dir: bool) -> None:
    host.pair(paired=True)
    (host.root / "etc/vpn-relay/install.json").write_text(
        json.dumps({"installer": "vpn-relay", "created_app_dir": created_app_dir, "ip_forward_before": "0",
                    "authorized_keys": "/root/.ssh/authorized_keys", "adoption_backup": None}),
        encoding="utf-8",
    )
    for unit in ("vpn-relay.service", "vpn-relay-resolve.service", "vpn-relay-resolve.timer"):
        (host.root / "etc/systemd/system" / unit).write_text("[Unit]\n", encoding="utf-8")
    (host.root / "etc/sysctl.d/90-vpn-relay.conf").write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    for name in ("vpn-relay-apply", "vpn-relay-agent"):
        (host.root / "usr/local/sbin" / name).write_text("#!/bin/sh\n", encoding="utf-8")


def test_uninstall_removes_what_the_installer_installed(host: Host) -> None:
    _installed(host, created_app_dir=True)
    rc, payload = host.run("uninstall")
    assert rc == 0, payload
    for gone in ("etc/systemd/system/vpn-relay.service", "etc/systemd/system/vpn-relay-resolve.timer",
                 "etc/sysctl.d/90-vpn-relay.conf", "etc/vpn-relay", "usr/local/sbin/vpn-relay-apply",
                 "usr/local/sbin/vpn-relay-agent", "opt/vpn-service", "var/lib/vpn-relay"):
        assert not (host.root / gone).exists(), gone
    assert host.keys.read_text(encoding="utf-8") == OPERATOR_LINE + "# keep me\n", "only the agent's line goes"
    calls = host.calls()
    assert "systemctl disable --now vpn-relay.service" in calls
    assert "sysctl -q -w net.ipv4.ip_forward=0" in calls


def test_uninstall_keeps_the_key_when_a_table_survives(host: Host) -> None:
    """A table nft could not delete keeps forwarding: the key, the pairing and the
    helpers stay, so the bot can run uninstall again."""
    _installed(host, created_app_dir=True)
    host.undeletable = {"ip-vpnrelay"}
    rc, payload = host.run("uninstall")
    assert rc == 4 and "could not be removed" in payload["error"]
    assert KEY_LINE in host.keys.read_text(encoding="utf-8")
    assert host.pairing_path.exists()
    assert (host.root / "usr/local/sbin/vpn-relay-agent").exists()
    assert (host.root / "etc/vpn-relay/install.json").exists()
    host.undeletable = set()
    assert host.run("uninstall")[0] == 0, "the retry finishes the job"
    assert KEY_LINE not in host.keys.read_text(encoding="utf-8")


def test_uninstall_keeps_an_app_dir_it_did_not_create(host: Host) -> None:
    _installed(host, created_app_dir=False)
    assert host.run("uninstall")[0] == 0
    assert (host.root / "opt/vpn-service").is_dir()


def test_uninstall_refuses_a_host_without_the_installers_record(host: Host) -> None:
    _installed(host, created_app_dir=True)
    (host.root / "etc/vpn-relay/install.json").unlink()
    rc, payload = host.run("uninstall")
    assert rc == 4 and "not a relay" in payload["error"]
    assert (host.root / "usr/local/sbin/vpn-relay-apply").exists()
    assert not any(c.startswith(("systemctl", "nft", "sysctl")) for c in host.host_calls() if "is-active" not in c)


def test_nested_agent_keeps_the_seam(host: Host) -> None:
    """update/uninstall start the agent again: it must stay inside the fake root."""
    _installed(host, created_app_dir=True)
    assert host.run("uninstall")[0] == 0
    assert not Path("/run/vpn-relay-uninstall.json").exists()


def test_uninstall_refuses_a_main_server(host: Host) -> None:
    _installed(host, created_app_dir=True)
    host.env_path.write_text("BOT_TOKEN=x\n", encoding="utf-8")
    rc, payload = host.run("uninstall")
    assert rc == 4 and "not a relay" in payload["error"]
    assert (host.root / "opt/vpn-service").is_dir()
    assert KEY_LINE in host.keys.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# update — real git against a local "origin", the installer stubbed
# --------------------------------------------------------------------------- #
def _git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo_host(host: Host) -> tuple[Host, Path]:
    origin = host.tmp / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    for tag in ("v1.0.0", "v1.1.0"):
        (origin / "f").write_text(tag, encoding="utf-8")
        _git(origin, "add", "f")
        _git(origin, "commit", "-q", "-m", tag)
        _git(origin, "tag", tag)
    app = host.root / "opt/vpn-service"
    env_text = host.env_path.read_text(encoding="utf-8")
    shutil.rmtree(app)
    _git(host.tmp, "clone", "-q", str(origin), str(app))
    _git(app, "checkout", "-q", "--detach", "v1.0.0")
    host.env_path.write_text(env_text, encoding="utf-8")
    _installed(host, created_app_dir=True)
    return host, origin


def _run_update(host: Host, installer_rc: int = 0) -> tuple[int, dict[str, Any]]:
    original = host.stubs

    def stubs() -> None:
        original()
        host.stub("git", 'exec /usr/bin/git -c safe.directory="*" "$@"\n')
        host.stub("bash", f"exit {installer_rc}\n")

    host.stubs = stubs  # type: ignore[method-assign]
    return host.run("update")


def test_update_moves_to_the_newest_release(repo_host: tuple[Host, Path]) -> None:
    host, origin = repo_host
    rc, payload = _run_update(host)
    assert rc == 0, payload
    assert payload["update"]["state"] == "succeeded"
    assert payload["update"]["release"] == "v1.1.0"
    app = host.root / "opt/vpn-service"
    assert _git(app, "rev-parse", "HEAD") == _git(origin, "rev-parse", "v1.1.0")
    assert any(c.startswith("bash ") and c.endswith("--relay-update") for c in host.calls())


def test_update_at_the_newest_release_is_a_noop(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    _git(host.root / "opt/vpn-service", "checkout", "-q", "--detach", "v1.1.0")
    rc, payload = _run_update(host)
    assert rc == 0 and payload["update"]["state"] == "noop"
    assert not any(c.startswith("bash ") for c in host.calls())


def test_update_never_goes_backwards(repo_host: tuple[Host, Path]) -> None:
    host, origin = repo_host
    app = host.root / "opt/vpn-service"
    _git(app, "checkout", "-q", "--detach", "v1.1.0")
    (origin / "f").write_text("newer", encoding="utf-8")
    _git(origin, "commit", "-qam", "unreleased")
    _git(app, "fetch", "-q", "origin")
    _git(app, "checkout", "-q", "--detach", "origin/main")
    head = _git(app, "rev-parse", "HEAD")
    rc, payload = _run_update(host)
    assert rc == 0 and payload["update"]["state"] == "noop"
    assert _git(app, "rev-parse", "HEAD") == head


def test_failed_installer_puts_the_checkout_back(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    app = host.root / "opt/vpn-service"
    before = _git(app, "rev-parse", "HEAD")
    rc, payload = _run_update(host, installer_rc=1)
    assert rc == 4 and "rolled back" in payload["error"]
    assert _git(app, "rev-parse", "HEAD") == before
    state = json.loads((host.root / "var/lib/vpn-relay/update.json").read_text(encoding="utf-8"))
    assert state["state"] == "failed"
