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
* **The unit set** is ``relay_unit_names`` of scripts/deploy.sh (one rule with install.sh
  and the host check), read from the checkout: equal on the repo and on a checkout with
  an extra timer/service. uninstall stops, disables and removes every unit of it —
  timers, then the oneshots, vpn-relay.service last — and, without a checkout, the
  vpn-relay*.service|.timer files present; status shows the data plane and every timer.

External commands are stubs (VPN_RELAY_AGENT_SELFTEST_BIN); every path is re-rooted
under a temporary directory (VPN_RELAY_AGENT_ROOT).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
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
# The unit set: relay_unit_names of scripts/deploy.sh, read from the checkout
# --------------------------------------------------------------------------- #
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
DATA_PLANE = "vpn-relay.service"
EXTRA_TIMER = "vpn-relay-extra.timer"
EXTRA_SERVICE = "vpn-relay-extra.service"


def _repo_unit_names() -> list[str]:
    return [p.name for p in sorted((ROOT / "deploy" / "relay").iterdir())
            if p.suffix in (".service", ".timer") and ".example." not in p.name]


def _deploy_relay_unit_names(checkout: Path) -> set[str]:
    """relay_unit_names of scripts/deploy.sh (the body tests/test_deploy_relay_units.py
    pins identical in install.sh and the host check), run on <checkout>."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start = text.index("\nrelay_unit_names() {\n") + 1
    body = text[start : text.index("\n}\n", start) + 3]
    proc = subprocess.run(["bash", "-c", body + 'relay_unit_names "$1"\n', "x", str(checkout)],
                          capture_output=True, text=True, check=True)
    lines = proc.stdout.splitlines()
    assert len(lines) == len(set(lines)), lines
    return set(lines)


def _checkout(app: Path, *, extra: bool) -> None:
    """deploy/relay/ of the repo in <app>; with <extra>, a unit pair the repo does not have
    and everything relay_unit_names must skip."""
    src = app / "deploy" / "relay"
    src.mkdir(parents=True, exist_ok=True)
    for f in (ROOT / "deploy" / "relay").iterdir():
        shutil.copyfile(f, src / f.name)
    if not extra:
        return
    files = {
        EXTRA_TIMER: "[Timer]\nOnUnitActiveSec=1h\nUnit=vpn-relay-extra.service\n[Install]\nWantedBy=timers.target\n",
        EXTRA_SERVICE: "[Service]\nType=oneshot\nExecStart=/bin/true\n",
        "vpn-relay-x.example.service": "[Service]\n",
        ".hidden.timer": "[Timer]\n",
        "notes.txt": "not a unit\n",
    }
    for name, body in files.items():
        (src / name).write_text(body, encoding="utf-8")
    (src / "dir.service").mkdir()


@pytest.mark.parametrize("which", ["repo", "extra"])
def test_the_agents_unit_set_is_deploys_relay_unit_names(tmp_path: Path, which: str) -> None:
    checkout = ROOT
    if which == "extra":
        checkout = tmp_path / "checkout"
        _checkout(checkout, extra=True)
    names = agent.checkout_unit_names(checkout)
    assert len(names) == len(set(names)), names
    assert set(names) == _deploy_relay_unit_names(checkout)
    expected = set(_repo_unit_names()) | ({EXTRA_TIMER, EXTRA_SERVICE} if which == "extra" else set())
    assert set(names) == expected and DATA_PLANE in expected


def test_the_agent_names_no_relay_unit_in_code() -> None:
    """The set is read from the checkout: no unit of deploy/relay/ but the data plane
    (which uninstall stops even without a checkout) is named in the agent."""
    text = AGENT.read_text(encoding="utf-8")
    for name in _repo_unit_names():
        if name != DATA_PLANE:
            assert f'"{name}"' not in text, name


def test_every_repo_unit_is_one_the_fallback_finds() -> None:
    """Without a checkout, uninstall finds the units by name in /etc/systemd/system."""
    for name in _repo_unit_names():
        assert agent.INSTALLED_UNIT_RE.fullmatch(name), name
    for other in ("vpn-relay.service.d", "vpn-relay.service.bak", "vpn-relayx.service", "nginx.service",
                  "vpn-relay-x.socket", "vpn-relay@.service"):
        assert not agent.INSTALLED_UNIT_RE.fullmatch(other), other


def test_stop_order_is_timers_then_services_then_the_data_plane(tmp_path: Path) -> None:
    _checkout(tmp_path, extra=True)
    order = agent.stop_order(agent.checkout_unit_names(tmp_path))
    timers = [n for n in order if n.endswith(".timer")]
    assert order[: len(timers)] == timers and EXTRA_TIMER in timers and "vpn-relay-resolve.timer" in timers
    assert order[-1] == DATA_PLANE
    assert set(order[len(timers) : -1]) == {EXTRA_SERVICE, "vpn-relay-resolve.service"}
    assert agent.stop_order([DATA_PLANE, "b.service", "a.timer", "a.timer"]) == ["a.timer", "b.service", DATA_PLANE]


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
            f'  cp "${{RELAY_ENV:-{self.env_path}}}" "{self.tmp}/env-at-apply-$n"\n'
            f'  cp "{self.env_path}" "{self.tmp}/live-env-at-apply-$n"\n'
            f'  cache="{self.root}/etc/vpn-relay/upstream.resolved"\n'
            f'  if [[ -f "$cache" ]]; then cp "$cache" "{self.tmp}/cache-at-apply-$n"; fi\n'
            # like the real helper: an apply remembers the address of the name it applied
            f'  h=$(sed -n "s/^RELAY_UPSTREAM_HOST=//p" "{self.env_path}" | tail -n1)\n'
            f'  printf "host=%s\\nipv4=192.0.2.99\\nat=1\\n" "$h" > "$cache"\n'
            f'  echo "applied"; exit "$rc"\nfi\n'
            f'if [[ "$1" == check ]]; then cat "{self.tmp}/check-output"; exit {self.check_rc}; fi\n'
            # input-status: what the test put there, and which .env it was asked with.
            f'if [[ "$1" == input-status ]]; then echo "${{RELAY_ENV:-live}}" >> "{self.tmp}/input-status-env"\n'
            f'  if [[ -f "{self.tmp}/input-status" ]]; then cat "{self.tmp}/input-status"; fi; exit 0; fi\nexit 0\n',
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

    def run(self, request: str | None, *argv: str, ssh: bool = False, conn: str | None = None) -> tuple[int, dict[str, Any]]:
        self.stubs()
        env = {
            "PATH": os.environ["PATH"],
            "VPN_RELAY_AGENT_SELFTEST": "1",
            "VPN_RELAY_AGENT_ROOT": str(self.root),
            "VPN_RELAY_AGENT_SELFTEST_BIN": str(self.bin),
        }
        if conn is not None:
            env["VPN_RELAY_AGENT_SELFTEST_CONN"] = conn
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


@pytest.mark.parametrize("extra", [False, True])
def test_status_shows_the_data_plane_and_every_timer_of_the_set(host: Host, extra: bool) -> None:
    host.pair(paired=True)
    _checkout(host.root / "opt/vpn-service", extra=extra)
    rc, payload = host.run("status")
    assert rc == 0, payload
    timers = {n for n in _repo_unit_names() if n.endswith(".timer")} | ({EXTRA_TIMER} if extra else set())
    assert set(payload["units"]) == {DATA_PLANE} | timers
    assert all(state == "active" for state in payload["units"].values())


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
def _installed(host: Host, *, created_app_dir: bool, checkout: bool = True, extra: bool = False) -> list[str]:
    """What install.sh leaves: with <checkout>, deploy/relay/ in the checkout (with
    <extra>, a unit pair the repo does not have) and its whole set installed; without,
    the units installed and no deploy/relay/ to read them from. Returns the units."""
    host.pair(paired=True)
    (host.root / "etc/vpn-relay/install.json").write_text(
        json.dumps({"installer": "vpn-relay", "created_app_dir": created_app_dir, "ip_forward_before": "0",
                    "authorized_keys": "/root/.ssh/authorized_keys", "adoption_backup": None}),
        encoding="utf-8",
    )
    units = _repo_unit_names() + ([EXTRA_TIMER, EXTRA_SERVICE] if extra else [])
    if checkout:
        _checkout(host.root / "opt/vpn-service", extra=extra)
    for unit in units:
        (host.root / "etc/systemd/system" / unit).write_text("[Unit]\n", encoding="utf-8")
    (host.root / "etc/sysctl.d/90-vpn-relay.conf").write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
    for name in ("vpn-relay-apply", "vpn-relay-agent"):
        (host.root / "usr/local/sbin" / name).write_text("#!/bin/sh\n", encoding="utf-8")
    return units


def _disabled(host: Host) -> list[str]:
    """The units uninstall stopped and disabled, in its order."""
    prefix = "systemctl disable --now "
    return [c[len(prefix):] for c in host.calls() if c.startswith(prefix)]


def _assert_stop_order(order: list[str]) -> None:
    timers = [u for u in order if u.endswith(".timer")]
    assert order[: len(timers)] == timers, order
    assert order[-1] == DATA_PLANE and order.count(DATA_PLANE) == 1, order


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


def test_uninstall_stops_disables_and_removes_a_unit_the_checkout_adds(host: Host) -> None:
    """A unit added to deploy/relay/ is installed by deploy/install — and undone here."""
    units = _installed(host, created_app_dir=False, extra=True)
    rc, payload = host.run("uninstall")
    assert rc == 0, payload
    order = _disabled(host)
    assert sorted(order) == sorted(units) and {EXTRA_TIMER, EXTRA_SERVICE} <= set(order)
    _assert_stop_order(order)
    for unit in units:
        assert not (host.root / "etc/systemd/system" / unit).exists(), unit
    assert EXTRA_TIMER in payload["uninstall"]["steps"][0]
    calls = host.calls()
    last_stop = calls.index(f"systemctl disable --now {DATA_PLANE}")
    assert all(i <= last_stop for i, c in enumerate(calls) if c.startswith("systemctl disable --now "))
    assert last_stop < calls.index("nft delete table ip vpnrelay") < calls.index("systemctl daemon-reload")


def test_uninstall_with_a_checkout_leaves_other_unit_files_alone(host: Host) -> None:
    """The checkout's set is what deploy/install installed from it — nothing else goes."""
    _installed(host, created_app_dir=False)
    unit_dir = host.root / "etc/systemd/system"
    for other in ("vpn-relay-operator.service", "nginx.service"):
        (unit_dir / other).write_text("[Unit]\n", encoding="utf-8")
    assert host.run("uninstall")[0] == 0
    assert (unit_dir / "vpn-relay-operator.service").exists() and (unit_dir / "nginx.service").exists()
    assert sorted(_disabled(host)) == sorted(_repo_unit_names())


def test_uninstall_without_a_checkout_removes_the_relay_units_present(host: Host) -> None:
    """No deploy/relay/ to read: the vpn-relay*.service|.timer files present decide, and
    vpn-relay.service is stopped even when its file is gone already."""
    units = _installed(host, created_app_dir=True, checkout=False, extra=True)
    unit_dir = host.root / "etc/systemd/system"
    (unit_dir / DATA_PLANE).unlink()
    (unit_dir / "nginx.service").write_text("[Unit]\n", encoding="utf-8")
    (unit_dir / "vpn-relay.service.d").mkdir()
    rc, payload = host.run("uninstall")
    assert rc == 0, payload
    order = _disabled(host)
    assert sorted(order) == sorted(units)
    _assert_stop_order(order)
    assert not any((unit_dir / u).exists() for u in units)
    assert (unit_dir / "nginx.service").exists() and (unit_dir / "vpn-relay.service.d").is_dir()


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
# update — real git against a local "origin", redeploy.sh stubbed
# --------------------------------------------------------------------------- #
# The agent no longer checks anything out or installs anything: it picks the release
# (latest_release, the rule of deploy.sh's relay_latest_release) and runs
# scripts/redeploy.sh with DEPLOY_REF=<tag> REDEPLOY_ATTACH=pipe. The `bash` stub below
# plays redeploy.sh + deploy.sh: it records the env, and per DEPLOY_MODE moves the
# checkout to the tag and prints DEPLOY OK, rolls back, stops in Phase 1, or no-ops.
def _git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


REDEPLOY_TEXT = "# scripts/redeploy.sh (stand-in): forwards DEPLOY_REF\n"


@pytest.fixture
def repo_host(host: Host) -> tuple[Host, Path]:
    origin = host.tmp / "origin"
    origin.mkdir()
    _git(origin, "init", "-q", "-b", "main")
    (origin / "scripts").mkdir()
    (origin / "scripts" / "redeploy.sh").write_text(REDEPLOY_TEXT, encoding="utf-8")
    for tag in ("v1.0.0", "v1.1.0"):
        (origin / "f").write_text(tag, encoding="utf-8")
        _git(origin, "add", "f", "scripts/redeploy.sh")
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


DEPLOY_STUB = r"""
echo "env DEPLOY_REF=${DEPLOY_REF:-} REDEPLOY_ATTACH=${REDEPLOY_ATTACH:-} FORCE=${FORCE:-}" >> "@LOG@"
echo "redeploy: launching vpn-bot-deploy (log: /root/deploy-20261116T000000Z.log)"
G=(/usr/bin/git -c safe.directory=* -C "@APP@")
case "@MODE@" in
  ok)
    "${G[@]}" -c advice.detachedHead=false checkout -q --detach "${DEPLOY_REF}^{commit}"
    printf '%s
' "[deploy] moving the working tree to latest release ${DEPLOY_REF}" "" "===== DEPLOY OK (relay) =====" "  role : relay"
    exit 0 ;;
  rollback)
    old="$("${G[@]}" rev-parse HEAD)"
    "${G[@]}" -c advice.detachedHead=false checkout -q --detach "${DEPLOY_REF}^{commit}"
    printf '%s
' "[deploy][WARN] vpn-relay-apply check failed after the restart (exit 13: the upstream does not answer)" >&2
    printf '%s
' "[deploy][WARN] ROLLBACK (relay): restoring PREV_SHA=${old} and the backed-up relay state" >&2
    "${G[@]}" -c advice.detachedHead=false checkout -q --detach "$old"
    printf '%s
' "" "===== ROLLBACK REPORT (relay) =====" "  - git checkout -f --detach ${old}: rc=0" >&2
    exit 1 ;;
  phase1)
    printf '%s
' "[deploy][FAIL] insufficient space on /opt/vpn-service FS for the test venv: need >1024MiB, have 300MiB" >&2
    exit 1 ;;
  noop)
    printf '%s
' "[deploy] INFO: the checkout (0123) is ahead of latest release ${DEPLOY_REF} (abc) — a relay never goes backwards: nothing to deploy"
    exit 0 ;;
  venv)
    # A deploy.sh that predates the result markers, stopping on errexit in its venv build.
    printf '%s
' "[deploy] building test venv /var/lib/vpn-bot-deploy/.venv-test (constraints changed or venv absent)" \
      "The virtual environment was not created successfully because ensurepip is not" \
      "available.  On Debian/Ubuntu systems, you need to install the python3-venv" \
      "    apt install python3.12-venv" "Failing command: /var/lib/vpn-bot-deploy/.venv-test/bin/python3" >&2
    exit 1 ;;
  tests)
    printf '%s
' "[deploy:step 3/8 tests]" "FAILED tests/test_x.py::test_y - assert 0 == 1" \
      "=========== 1 failed, 5600 passed in 780.12s (0:13:00) ===========" \
      "[deploy][FAIL] Phase 1 gate: pytest failed on tag v1.1.0 (above) — nothing was changed" \
      "[deploy:result failed step=tests reason=tests]" >&2
    exit 1 ;;
  warn)
    "${G[@]}" -c advice.detachedHead=false checkout -q --detach "${DEPLOY_REF}^{commit}"
    printf '%s
' "===== DEPLOY OK (relay) =====" "[deploy:warn upstream_preexisting] upstream unreachable before and after (pre-existing): TCP connect 203.0.113.5:443" "[deploy:result ok]"
    exit 0 ;;
  progress)
    "${G[@]}" -c advice.detachedHead=false checkout -q --detach "${DEPLOY_REF}^{commit}"
    printf '%s\n' "[deploy:step 1/8 preflight]" "[deploy:step 3/8 tests]" "[deploy:tests total=10]" "....."
    sleep 3
    printf '%s\n' "....." "[deploy:step 8/8 verify]" "===== DEPLOY OK (relay) =====" "[deploy:result ok]"
    exit 0 ;;
  binary)
    # Not UTF-8: the agent must not crash on it (the bot would show a stale line).
    printf 'bad byte \xff\xfe here\n[deploy][FAIL] stopped\n' >&2
    exit 1 ;;
esac
exit 99
"""


def _run_update(host: Host, mode: str = "ok") -> tuple[int, dict[str, Any]]:
    original = host.stubs
    app = host.root / "opt/vpn-service"

    def stubs() -> None:
        original()
        host.stub("git", 'exec /usr/bin/git -c safe.directory="*" "$@"\n')
        host.stub("bash", DEPLOY_STUB.replace("@LOG@", str(host.log)).replace("@APP@", str(app)).replace("@MODE@", mode))

    host.stubs = stubs  # type: ignore[method-assign]
    return host.run("update")


def _update_state(host: Host) -> dict[str, Any]:
    return json.loads((host.root / "var/lib/vpn-relay/update.json").read_text(encoding="utf-8"))


def _deploys(host: Host) -> list[str]:
    return [c for c in host.calls() if c.startswith("bash ")]


def _agent_moved_the_checkout(host: Host) -> bool:
    """Did the AGENT run git checkout/reset (the stub's own git is /usr/bin/git, unlogged)?"""
    return any(c.startswith("git ") and (" checkout" in c or " reset" in c) for c in host.calls())


def test_update_deploys_the_newest_release_through_redeploy(repo_host: tuple[Host, Path]) -> None:
    host, origin = repo_host
    app = host.root / "opt/vpn-service"
    old = _git(app, "rev-parse", "HEAD")
    install_record = (host.root / "etc/vpn-relay/install.json").read_bytes()
    rc, payload = _run_update(host)
    assert rc == 0, payload
    state = payload["update"]
    assert state["state"] == "succeeded" and state["release"] == "v1.1.0"
    assert state["from_commit"] == old and state["to_commit"] == _git(origin, "rev-parse", "v1.1.0")
    assert state["log"] == "/root/deploy-20261116T000000Z.log"
    assert _git(app, "rev-parse", "HEAD") == _git(origin, "rev-parse", "v1.1.0")
    assert _deploys(host) == [f"bash {app}/scripts/redeploy.sh"], "redeploy.sh, nothing else"
    assert "env DEPLOY_REF=v1.1.0 REDEPLOY_ATTACH=pipe FORCE=" in host.calls()
    assert not _agent_moved_the_checkout(host), "deploy.sh moves the tree, never the agent"
    assert not any("--relay-update" in c for c in host.calls()), "install.sh --relay-update is retired"
    assert (host.root / "etc/vpn-relay/install.json").read_bytes() == install_record, "install.json: the install's ref"
    assert _update_state(host) == state


def test_update_at_the_newest_release_is_a_noop(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    _git(host.root / "opt/vpn-service", "checkout", "-q", "--detach", "v1.1.0")
    rc, payload = _run_update(host)
    assert rc == 0 and payload["update"]["state"] == "noop"
    assert "already at or past v1.1.0" in payload["update"]["message"]
    assert _deploys(host) == []


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
    assert _deploys(host) == []


def test_update_never_moves_sideways(repo_host: tuple[Host, Path]) -> None:
    host, origin = repo_host
    app = host.root / "opt/vpn-service"
    _git(app, "checkout", "-q", "--detach", "v1.1.0")
    _git(origin, "checkout", "-q", "-b", "side", "v1.0.0")
    (origin / "f").write_text("side", encoding="utf-8")
    _git(origin, "commit", "-qam", "side")
    _git(origin, "tag", "v2.0.0")
    _git(origin, "checkout", "-q", "main")
    rc, _ = _run_update(host)
    assert rc == 4
    assert _update_state(host)["state"] == "failed" and "not moving sideways" in _update_state(host)["message"]
    assert _update_state(host)["release"] == "v2.0.0"
    assert _deploys(host) == [] and _git(app, "rev-parse", "HEAD") == _git(origin, "rev-parse", "v1.1.0")


def test_update_ignores_tags_that_are_not_releases(repo_host: tuple[Host, Path]) -> None:
    """v.3.1.0 (the typo tag on the real repo), pre-releases and other v* names are not
    releases: the newest RELEASE is still v1.1.0."""
    host, origin = repo_host
    for junk in ("v.3.1.0", "v9.0.0-rc1", "v9", "vX.1.0", "v9.0.0.0.0", "version-9.0"):
        _git(origin, "tag", junk, "v1.1.0")
    rc, payload = _run_update(host)
    assert rc == 0 and payload["update"]["release"] == "v1.1.0"
    assert "env DEPLOY_REF=v1.1.0 REDEPLOY_ATTACH=pipe FORCE=" in host.calls()


def test_failed_deploy_is_rolled_back_by_deploy_sh(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    app = host.root / "opt/vpn-service"
    before = _git(app, "rev-parse", "HEAD")
    rc, payload = _run_update(host, "rollback")
    assert rc == 4 and "failed and rolled back (exit 1)" in payload["error"]
    assert "vpn-relay-apply check failed after the restart" in payload["error"], "deploy.sh's own reason"
    assert _git(app, "rev-parse", "HEAD") == before
    assert not _agent_moved_the_checkout(host), "the rollback is deploy.sh's"
    state = _update_state(host)
    assert state["state"] == "failed" and state["from_commit"] == before and "to_commit" not in state
    assert state["log"] == "/root/deploy-20261116T000000Z.log"


def test_deploy_stopping_in_phase1_changes_nothing(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    app = host.root / "opt/vpn-service"
    before = _git(app, "rev-parse", "HEAD")
    rc, payload = _run_update(host, "phase1")
    assert rc == 4
    assert "stopped before any change (exit 1): insufficient space" in payload["error"]
    assert _git(app, "rev-parse", "HEAD") == before and _update_state(host)["state"] == "failed"


def test_deploy_finding_nothing_to_do_is_a_noop(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    rc, payload = _run_update(host, "noop")
    assert rc == 0 and payload["update"]["state"] == "noop"
    assert "never goes backwards" in payload["update"]["message"]


def test_a_checkout_whose_redeploy_predates_deploy_ref_is_refused(repo_host: tuple[Host, Path]) -> None:
    """An older redeploy.sh would drop DEPLOY_REF and deploy origin/main: never run it."""
    host, _ = repo_host
    (host.root / "opt/vpn-service/scripts/redeploy.sh").write_text("# an old wrapper\n", encoding="utf-8")
    rc, payload = _run_update(host)
    assert rc == 4 and "cannot deploy a release (no DEPLOY_REF)" in payload["error"]
    assert _deploys(host) == []


def test_update_unit_and_bot_wait_long_enough_for_a_deploy() -> None:
    """The deploy runs the pytest gate on the relay: the transient unit, the deploy's own
    wait and the bot's SSH call are sized for it, each inside the next."""
    from services.relays import AGENT_UPDATE_TIMEOUT

    text = AGENT.read_text(encoding="utf-8")
    assert '_transient("vpn-relay-update", "--internal-update", UPDATE_TIMEOUT)' in text
    assert "timeout=UPDATE_TIMEOUT - 120" in text
    assert agent.UPDATE_TIMEOUT >= 2400
    assert AGENT_UPDATE_TIMEOUT == agent.UPDATE_TIMEOUT + 60


# --------------------------------------------------------------------------- #
# update: the cause, for the bot (DEPLOY VERDICT — tests/test_deploy_verdict.py)
# --------------------------------------------------------------------------- #
def test_a_failed_update_carries_its_cause_in_the_answer(repo_host: tuple[Host, Path]) -> None:
    """The bot shows the cause, the step and the lines that tell it — not a bare refusal."""
    host, _ = repo_host
    rc, payload = _run_update(host, "tests")
    assert rc == 4
    update = payload["update"]
    assert update["state"] == "failed" and update["reason"] == "tests" and update["step"] == "tests"
    assert "FAILED tests/test_x.py::test_y - assert 0 == 1" in update["excerpt"]
    assert any("1 failed, 5600 passed" in line for line in update["excerpt"])
    assert update["log"] == "/root/deploy-20261116T000000Z.log"
    assert _update_state(host) == update


def test_a_deploy_without_markers_is_classified_from_its_text(repo_host: tuple[Host, Path]) -> None:
    """A target whose deploy.sh predates the markers (a relay updating to an older
    release): the venv failure still reads as «no venv», with apt's hint."""
    host, _ = repo_host
    rc, payload = _run_update(host, "venv")
    assert rc == 4
    update = payload["update"]
    assert update["reason"] == "no_venv" and update["step"] == ""
    assert any("apt install python3.12-venv" in line for line in update["excerpt"])


def test_a_rollback_on_the_upstream_reads_as_upstream(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    rc, payload = _run_update(host, "rollback")
    assert rc == 4 and payload["update"]["reason"] == "upstream"
    assert any("vpn-relay-apply check failed after the restart" in line for line in payload["update"]["excerpt"])


def test_a_successful_update_carries_the_deploys_warnings(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    rc, payload = _run_update(host, "warn")
    assert rc == 0 and payload["update"]["state"] == "succeeded"
    assert payload["update"]["warnings"] == [{
        "code": "upstream_preexisting",
        "text": "upstream unreachable before and after (pre-existing): TCP connect 203.0.113.5:443",
    }]


def test_output_that_is_not_utf8_does_not_crash_update(repo_host: tuple[Host, Path]) -> None:
    host, _ = repo_host
    rc, payload = _run_update(host, "binary")
    assert rc == 4
    assert payload["update"]["state"] == "failed" and payload["update"]["reason"] == "checks"
    assert "deploying v1.1.0" not in payload["error"], "never the stale running line"



# --------------------------------------------------------------------------- #
# The SSH port (docs/host-state.md#the-ssh-port): phase 2 only from the new port
# --------------------------------------------------------------------------- #
SSH_PORT_STUB = r"""
echo "ssh-port $*" >> "@LOG@"
case "$1" in
  plan) printf '%s\n' ssh_port=54321 current=22,54321 state=phase1 action=wait from=22 to=54321 since=1763460000 hold=0 \
          proof=none "status=ssh port: migrating 22 -> 54321 (waiting for proof)" listen=22,54321 ;;
  confirm-session) [[ -f "@SD@/refuse" ]] && { echo "vpn-bot-ssh-port: stale" >&2; exit 3; }; echo "phase 2: 22 -> 54321" ;;
  begin) [[ -f "@SD@/refuse" ]] && { echo "vpn-bot-ssh-port: this session came in on 54321" >&2; exit 3; }; echo "$1 done" ;;
  hold|unhold) echo "$1 done" ;;
esac
"""


def _ssh_port_host(host: Host) -> Host:
    host.pair(paired=True)
    original = host.stubs
    sd = host.tmp / "sp"
    sd.mkdir(exist_ok=True)

    def stubs() -> None:
        original()
        host.stub("vpn-bot-ssh-port", SSH_PORT_STUB.replace("@LOG@", str(host.log)).replace("@SD@", str(sd)))

    host.stubs = stubs  # type: ignore[method-assign]
    return host


@pytest.mark.parametrize(
    "request_",
    ["ssh-port-finish port=54321 since=1763460000", "ssh-port-keep since=1763460000",
     "ssh-port-resume since=1763460000", "ssh-port-set port=60022"],
)
def test_the_ssh_port_requests_are_on_the_whitelist(request_: str) -> None:
    assert agent.parse_request(request_)[0] == request_.split()[0]


@pytest.mark.parametrize(
    "request_",
    ["ssh-port-finish port=54321", "ssh-port-finish port=54321 since=1 extra", "ssh-port-set port=-1",
     "ssh-port-set port=123456", "ssh-port-keep", "ssh-port-finish port=54321 since=1;id"],
)
def test_malformed_ssh_port_requests_are_refused(request_: str) -> None:
    with pytest.raises(agent.Refused):
        agent.parse_request(request_)


def test_status_carries_the_migration(host: Host) -> None:
    _ssh_port_host(host)
    rc, payload = host.run("status")
    assert rc == 0, payload
    assert payload["ssh_migration"]["state"] == "phase1" and payload["ssh_migration"]["to"] == "54321"
    assert "listen" not in payload["ssh_migration"], "only the keys the bot reads"


def test_finish_runs_phase2_only_from_a_session_on_the_new_port(host: Host) -> None:
    _ssh_port_host(host)
    rc, payload = host.run("ssh-port-finish port=54321 since=1763460000", conn="192.0.2.1 50000 192.0.2.50 22")
    assert rc == 2 and "came in on 22, not on 54321" in payload["error"]
    assert not [c for c in host.calls() if c.startswith("ssh-port confirm-session")], "nothing ran"
    rc, payload = host.run("ssh-port-finish port=54321 since=1763460000", conn="192.0.2.1 50000 192.0.2.50 54321")
    assert rc == 0, payload
    assert ("ssh-port confirm-session --port 54321 --since 1763460000 --local-port 54321 --addr 192.0.2.1"
            in host.calls())
    assert payload["ssh_port"]["lines"] == ["phase 2: 22 -> 54321"]


def test_finish_without_an_ssh_session_is_refused(host: Host) -> None:
    _ssh_port_host(host)
    rc, payload = host.run("ssh-port-finish port=54321 since=1763460000")
    assert rc == 2 and "not an ssh session" in payload["error"]


def test_a_refused_finish_reports_the_helpers_reason(host: Host) -> None:
    _ssh_port_host(host)
    (host.tmp / "sp" / "refuse").touch()
    rc, payload = host.run("ssh-port-finish port=54321 since=1763460000", conn="192.0.2.1 50000 192.0.2.50 54321")
    assert rc == 4 and "stale" in payload["error"] and payload["ssh_port"]["rc"] == 3


@pytest.mark.parametrize(("verb", "arg"), [("keep", "hold"), ("resume", "unhold")])
def test_keep_and_resume_hold_the_migration(host: Host, verb: str, arg: str) -> None:
    _ssh_port_host(host)
    rc, payload = host.run(f"ssh-port-{verb} since=1763460000")
    assert rc == 0, payload
    assert f"ssh-port {arg} --since 1763460000" in host.calls()


def test_set_writes_ssh_port_and_begins(host: Host) -> None:
    _ssh_port_host(host)
    rc, payload = host.run("ssh-port-set port=60022")
    assert rc == 0, payload
    assert "ssh-port begin" in host.calls()
    assert "SSH_PORT=60022" in host.env_path.read_text(encoding="utf-8")


def test_set_keeps_the_port_this_session_came_in_on(host: Host) -> None:
    """A new target must not close the port the bot manages the relay through."""
    _ssh_port_host(host)
    rc, payload = host.run("ssh-port-set port=60022", conn="192.0.2.1 50000 192.0.2.50 54321")
    assert rc == 0, payload
    assert "ssh-port begin --keep 54321" in host.calls()


def test_a_refused_begin_restores_ssh_port(host: Host) -> None:
    _ssh_port_host(host)
    before = host.env_path.read_text(encoding="utf-8")
    (host.tmp / "sp" / "refuse").touch()
    rc, payload = host.run("ssh-port-set port=60022", conn="192.0.2.1 50000 192.0.2.50 54321")
    assert rc == 4 and "SSH_PORT restored" in payload["error"], payload
    assert host.env_path.read_text(encoding="utf-8") == before


def test_set_refuses_a_forwarded_port(host: Host) -> None:
    _ssh_port_host(host)
    before = host.env_path.read_text(encoding="utf-8")
    rc, payload = host.run("ssh-port-set port=443")
    assert rc == 2 and "forwarded" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == before



def test_update_writes_its_progress_while_it_runs_and_update_status_reads_it(repo_host: tuple[Host, Path]) -> None:
    """D: update.json carries the deploy's steps and tests while it runs (written at most
    every 2 s); `update-status` answers it, with no lock, next to the running update."""
    host, _ = repo_host
    rc, payload = _run_update(host, "progress")
    assert rc == 0 and payload["update"]["state"] == "succeeded"
    rc, status = host.run("update-status")
    assert rc == 0 and status["update"]["state"] == "succeeded"
    # The running state seen mid-way is gone now; the progress the bot read then is
    # what deploy_progress made of the output so far:
    assert agent.deploy_progress("[deploy:step 3/8 tests]\n[deploy:tests total=10]\n.....\n")["tests"] == {
        "done": 5, "total": 10}


def test_update_status_needs_the_pairing(host: Host) -> None:
    host.pair()
    rc, payload = host.run("update-status")
    assert rc == 3 and "not paired" in payload["error"]


# --------------------------------------------------------------------------- #
# input-filter on|off (agent 4, docs/relay.md «Входной фильтр relay»)
# --------------------------------------------------------------------------- #
STAGE = "etc/vpn-relay/input-filter.env"


def _filter_status(host: Host, line: str) -> None:
    (host.tmp / "input-status").write_text(line + "\n", encoding="utf-8")


def test_input_filter_on_confirmed_by_mains_probe_commits_at_once(host: Host) -> None:
    host.pair(paired=True)
    _filter_status(host, "CONFIRMED by main probe (tcp 22; 2026-11-18 21:00:00 UTC)")
    rc, payload = host.run("input-filter on")
    assert rc == 0, payload
    assert payload["input_filter"]["committed"] is True and payload["input_status"].startswith("CONFIRMED")
    assert "RELAY_INPUT_FILTER=on" in (host.tmp / "env-at-apply-1").read_text(encoding="utf-8"), "applied from the stage"
    assert "RELAY_INPUT_FILTER=off" in (host.tmp / "live-env-at-apply-1").read_text(encoding="utf-8"), (
        "the live .env did not say on while the filter was unproven"
    )
    env = host.env_path.read_text(encoding="utf-8")
    assert "RELAY_INPUT_FILTER=on" in env and "RELAY_INPUT_FILTER=off" not in env
    assert "SSH_PORT=22" in env, "nothing else of .env changes"
    assert not (host.root / STAGE).exists()
    assert (host.tmp / "input-status-env").read_text(encoding="utf-8").split() == [str(host.root / STAGE)]


def test_input_filter_on_pending_leaves_env_until_the_confirmation(host: Host) -> None:
    host.pair(paired=True)
    _filter_status(host, "PENDING CONFIRM (reverts at 2026-11-18 21:05:00 UTC) — main probe: no result")
    before = host.env_path.read_text(encoding="utf-8")
    rc, payload = host.run("input-filter on")
    assert rc == 0 and payload["input_filter"]["committed"] is False
    assert payload["input_status"].startswith("PENDING CONFIRM")
    assert host.env_path.read_text(encoding="utf-8") == before, "not committed: the dead-man may still revert"
    stage = host.root / STAGE
    assert stage.exists() and stat.S_IMODE(stage.stat().st_mode) == 0o600
    # The bot confirmed from a new session; the second call finds the set confirmed.
    _filter_status(host, "OK (tcp 22; confirmed 2026-11-18T21:01:00Z by ssh-session)")
    rc, payload = host.run("input-filter on")
    assert rc == 0 and payload["input_filter"]["committed"] is True
    assert "RELAY_INPUT_FILTER=on" in host.env_path.read_text(encoding="utf-8") and not stage.exists()


def test_input_filter_on_whose_apply_fails_applies_the_live_env_again(host: Host) -> None:
    host.pair(paired=True)
    before = host.env_path.read_text(encoding="utf-8")
    host.apply_rc = [9, 0]
    rc, payload = host.run("input-filter on")
    assert rc == 4 and "the live .env applied again (restored)" in payload["error"]
    assert payload["input_filter"]["committed"] is False
    assert [c for c in host.calls() if c.startswith("vpn-relay-apply apply")] == ["vpn-relay-apply apply"] * 2
    assert "RELAY_INPUT_FILTER=on" in (host.tmp / "env-at-apply-1").read_text(encoding="utf-8")
    assert (host.tmp / "env-at-apply-2").read_text(encoding="utf-8") == before, "the second apply is the live .env"
    assert host.env_path.read_text(encoding="utf-8") == before and not (host.root / STAGE).exists()


def test_input_filter_off_writes_env_and_applies(host: Host) -> None:
    host.pair(paired=True)
    host.env_path.write_text(host.env_path.read_text(encoding="utf-8").replace("FILTER=off", "FILTER=on"), encoding="utf-8")
    (host.root / STAGE).write_text("RELAY_INPUT_FILTER=on\n", encoding="utf-8")
    _filter_status(host, "off (RELAY_INPUT_FILTER=off)")
    rc, payload = host.run("input-filter off")
    assert rc == 0 and payload["input_filter"] == {"state": "off", "committed": True}
    assert "RELAY_INPUT_FILTER=off" in host.env_path.read_text(encoding="utf-8")
    assert not (host.root / STAGE).exists(), "a stage of an unfinished `on` goes too"
    assert "RELAY_INPUT_FILTER=off" in (host.tmp / "env-at-apply-1").read_text(encoding="utf-8")


def test_input_filter_off_whose_apply_fails_puts_env_back(host: Host) -> None:
    host.pair(paired=True)
    on = host.env_path.read_text(encoding="utf-8").replace("FILTER=off", "FILTER=on")
    host.env_path.write_text(on, encoding="utf-8")
    host.apply_rc = [6, 0]
    rc, payload = host.run("input-filter off")
    assert rc == 4 and ".env put back (restored)" in payload["error"]
    assert host.env_path.read_text(encoding="utf-8") == on


def test_input_filter_needs_a_pairing(host: Host) -> None:
    host.pair(paired=False)
    rc, _ = host.run("input-filter on")
    assert rc == 3 and not [c for c in host.calls() if c.startswith("vpn-relay-apply")]


def test_the_agent_says_version_4() -> None:
    assert agent.AGENT_VERSION == "4" and "input-filter" in agent.COMMANDS
