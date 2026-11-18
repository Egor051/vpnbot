"""Managing RU relays THROUGH the hub (docs/relay.md «Управление RU-relay через hub»).

Pinned:

* **The ssh argv with a jump** (services/relay_ssh.py) — run through a fake ``ssh``
  that does what OpenSSH does with a ``ProxyCommand``: hands it to ``$SHELL -c
  "exec …"`` after %-expansion. Both hops: ``-F /dev/null`` and the SAME pinned
  option set, ``StrictHostKeyChecking=yes`` (the hub's hop even on a pairing's TOFU
  call), each its own alias and known_hosts with its own pinned key; the agent key
  on the relay's hop, the jump key on the hub's — never the other way round; no
  ``-J``. A target the hub's list does not open is refused before any process starts.
* **The hub's line** (scripts/vpn-relay-agent ``jump`` / ``jump-off``) —
  ``restrict,port-forwarding,permitopen="h:p"[,…],command="/bin/false" ssh-ed25519 …``,
  exactly; every other line of authorized_keys byte-identical; values validated; a
  key with another line refused; ``uninstall`` removes it.
* **The whitelist** — ``_REQUEST`` of the bot and the agent's WHITELIST accept and
  refuse the same requests.
* **input-confirm through the agent** — the agent runs ``vpn-relay-apply
  input-confirm`` as a direct child (never systemd-run); the relay service sends it
  from the card, after ``update`` and in the health loop when ``status`` reports
  PENDING CONFIRM.
* **Routing** (services/relays.py) — «через hub» and the fallback mode route every
  relay but a hub through the hub, the hub's jump line opens exactly those relays,
  a pairing in the fallback mode says hello through the hub (the address opened for
  it, the relay's own check instead of the outside probes), and no hub = a clear
  refusal.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import subprocess
import sys
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType
from typing import Any

import aiosqlite
import pytest
from test_relay import ADMIN, _settings
from test_relay_admin import _Audit, _Users

from adapters.clock import ClockProvider
from adapters.shell_runner import ShellRunner
from config import validators
from db.database import CURRENT_SCHEMA_VERSION, Database
from models.dto import RELAY_ROLE_HUB, RelayAgent
from repositories.relays import RelayRepository
from services.errors import InvalidOperation, ServiceError
from services.relay import RelayCatalog
from services.relay_health import AgentCheck
from services.relay_ssh import (
    _REQUEST,
    MAX_REQUEST,
    AgentReply,
    JumpHost,
    RelayAgentClient,
    RelayHostKeyMismatch,
    RelayKeyStore,
    RelaySshError,
    jump_key_store,
    jump_request,
)
from services.relays import RelayService

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "scripts" / "vpn-relay-agent"
SNAPSHOT_DIR = ROOT / "tests" / "schema_snapshots"
HUB_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHubHostKeyHubHostKeyHubHostKeyHubHost00"
RELAY_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRelayHostKeyRelayHostKeyRelayHostKey00"
OTHER_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherKeyAnotherKeyAnotherKeyAnother0"
HUB_IP = "198.51.100.9"
RU_IP = "203.0.113.50"
RU2_IP = "203.0.113.60"
NOW = "2026-11-18T00:00:00+00:00"
BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
JUMP_PUB = f"ssh-ed25519 {BLOB}"

pytestmark = pytest.mark.timeout(60)


def _load_agent() -> ModuleType:
    loader = SourceFileLoader("vpn_relay_agent_jump", str(AGENT))
    spec = spec_from_loader("vpn_relay_agent_jump", loader)
    assert spec is not None
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


agent = _load_agent()


# ── the whitelist: the bot's _REQUEST and the agent's, on the same requests ────

SAME_REQUESTS = [
    ("status", True),
    ("update", True),
    ("uninstall", True),
    ("input-confirm", True),
    ("jump-off", True),
    (f"hello {'A' * 43}", True),
    ("apply target=vpn.example.com tcp=443,2096 udp=443", True),
    (f"jump key={BLOB} open={RU_IP}:22", True),
    (f"jump key={BLOB} open=ru1.example.net:2222,{RU_IP}:22", True),
    (f"jump key={BLOB} open=" + ",".join(f"10.0.0.{i}:22" for i in range(1, 33)), True),
    # The SSH port of a relay (docs/host-state.md#the-ssh-port).
    ("ssh-port-finish port=54321 since=1763460000", True),
    ("ssh-port-keep since=1763460000", True),
    ("ssh-port-resume since=1763460000", True),
    ("ssh-port-set port=60022", True),
    ("update-status", True),
    # The relay's input filter (docs/relay.md «Входной фильтр relay»), agent 4.
    ("input-filter on", True),
    ("input-filter off", True),
    ("input-filter", False),
    ("input-filter maybe", False),
    ("input-filter on;id", False),
    ("input-filter on off", False),
    ("input-filter  on", False),
    ("input-filter ON", False),
    ("update-status now", False),
    ("update-statuses", False),
    ("ssh-port-finish port=54321", False),
    ("ssh-port-finish since=1763460000 port=54321", False),
    ("ssh-port-finish port=543210 since=1", False),
    ("ssh-port-finish port=54321 since=1763460000;id", False),
    ("ssh-port-set port=", False),
    ("ssh-port-set port=22 extra", False),
    ("ssh-port-keep since=1234567890123", False),
    ("ssh-port-keep", False),
    # refused by both
    ("input-confirm now", False),
    ("input-confirm;id", False),
    ("jump-off now", False),
    ("jump", False),
    (f"jump key={BLOB}", False),
    (f"jump key={BLOB} open=", False),
    (f"jump open={RU_IP}:22 key={BLOB}", False),
    (f"jump key={BLOB} open={RU_IP}", False),
    (f"jump key={BLOB} open={RU_IP}:22;id", False),
    (f"jump key={BLOB} open={RU_IP}:22 extra", False),
    (f"jump key={BLOB} open={RU_IP}:22,", False),
    (f"jump key={BLOB} open=\"{RU_IP}:22\"", False),
    (f"jump key={BLOB} open={RU_IP}:22\nuninstall", False),
    (f"jump key={BLOB[:-1]} open={RU_IP}:22", False),
    (f"jump key={BLOB}= open={RU_IP}:22", False),
    (f"jump key={BLOB.replace('AAAAC3', 'AAAAB3', 1)} open={RU_IP}:22", False),
    (f"jump key={BLOB} open=[::1]:22", False),
    (f"jump key={BLOB} open=" + ",".join(f"10.0.0.{i}:22" for i in range(1, 34)), False),
]


@pytest.mark.parametrize(("request_", "accepted"), SAME_REQUESTS)
def test_the_bot_and_the_agent_whitelist_the_same_requests(request_: str, accepted: bool) -> None:
    bot = len(request_) <= MAX_REQUEST and _REQUEST.fullmatch(request_) is not None
    try:
        agent.parse_request(request_)
        on_relay = True
    except agent.Refused:
        on_relay = False
    assert bot is accepted and on_relay is accepted, (bot, on_relay)
    assert MAX_REQUEST == agent.MAX_REQUEST


def test_jump_request_is_sorted_unique_and_off_when_empty() -> None:
    assert jump_request(JUMP_PUB, [("RU1.example.net", 2222), (RU_IP, 22), (RU_IP, 22)]) == (
        f"jump key={BLOB} open={RU_IP}:22,ru1.example.net:2222"
    )
    assert jump_request(JUMP_PUB, []) == "jump-off"
    with pytest.raises(RelaySshError):
        jump_request("ssh-rsa AAAA", [(RU_IP, 22)])
    with pytest.raises(RelaySshError):
        jump_request(JUMP_PUB, [("a b", 22)])
    with pytest.raises(RelaySshError) as exc:
        jump_request(JUMP_PUB, [(f"10.0.{i // 250}.{i % 250 + 1}", 22) for i in range(33)])
    assert exc.value.key == "relay_jump_too_many"


# ── ssh with a jump: a fake ssh that runs ProxyCommand the way OpenSSH does ────

FAKE_SSH = r"""#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
opts, info = {}, {}
i = 0
while i < len(args):
    a = args[i]
    if a == "-o":
        k, _, v = args[i + 1].partition("="); opts[k] = v; i += 2
    elif a in ("-F", "-i", "-p", "-l", "-W"):
        info[a] = args[i + 1]; i += 2
    elif a == "--":
        info["host"] = args[i + 1]; info["request"] = args[i + 2] if len(args) > i + 2 else None; break
    else:
        info.setdefault("other", []).append(a); i += 1
state = json.load(open(os.environ["FAKE_SSH_STATE"]))
hop = "hub" if "-W" in info else "relay"
with open(os.environ["FAKE_SSH_LOG"], "a") as log:
    log.write(json.dumps({"hop": hop, "argv": args, "opts": opts, "info": info,
                          "shell": os.environ.get("SHELL")}) + "\n")
if "ProxyCommand" in opts:
    command = opts["ProxyCommand"].replace("%%", "%")
    proxy = subprocess.run([os.environ.get("SHELL") or "/bin/sh", "-c", "exec " + command],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if proxy.returncode != 0:
        sys.stderr.write(proxy.stderr + "kex_exchange_identification: Connection closed by remote host\n")
        sys.exit(255)
presented = state["hub_key"] if hop == "hub" else state["relay_key"]
known = open(opts["UserKnownHostsFile"]).read()
alias = opts["HostKeyAlias"]
pinned = [f"{l.split()[1]} {l.split()[2]}" for l in known.splitlines() if l.strip() and l.split()[0] == alias]
if pinned and presented not in pinned:
    print("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.", file=sys.stderr)
    sys.exit(255)
if not pinned:
    if opts["StrictHostKeyChecking"] != "accept-new":
        print("Host key verification failed.", file=sys.stderr); sys.exit(255)
    with open(opts["UserKnownHostsFile"], "a") as fh:
        fh.write(f"{alias} {presented}\n")
if hop == "hub":
    if state.get("hub_denies"):
        print(f"root@{info['host']}: Permission denied (publickey).", file=sys.stderr)
        sys.exit(255)
    if info["-W"] not in state["permit"]:
        print("channel 0: open failed: administratively prohibited: open failed\nstdio forwarding failed",
              file=sys.stderr)
        sys.exit(255)
    sys.exit(0)
reply = state["replies"].get(info["request"].split()[0], {"ok": False, "error": "refused"})
print(json.dumps(reply))
sys.exit(0 if reply.get("ok") else 4)
"""


class FakeSsh:
    def __init__(self, tmp: Path) -> None:
        self.binary = tmp / "bin with space" / "ssh"
        self.binary.parent.mkdir()
        self.binary.write_text(FAKE_SSH, encoding="utf-8")
        self.binary.chmod(0o755)
        self.state_path = tmp / "ssh-state.json"
        self.log = tmp / "ssh-log.jsonl"
        self.state: dict[str, Any] = {
            "hub_key": HUB_KEY, "relay_key": RELAY_KEY, "permit": [f"{RU_IP}:22"],
            "replies": {"status": {"ok": True}, "hello": {"ok": True}, "input-confirm": {"ok": True}},
        }
        os.environ["FAKE_SSH_STATE"] = str(self.state_path)
        os.environ["FAKE_SSH_LOG"] = str(self.log)
        self.save()

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")

    def calls(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def fake_ssh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeSsh:
    monkeypatch.setenv("FAKE_SSH_STATE", "")
    monkeypatch.setenv("FAKE_SSH_LOG", "")
    # The bot's own $SHELL may be nologin: the client must not depend on it.
    monkeypatch.setenv("SHELL", "/usr/sbin/nologin")
    return FakeSsh(tmp_path)


def _client(tmp_path: Path, fake: FakeSsh) -> RelayAgentClient:
    keys = RelayKeyStore(tmp_path / "relay_ssh")
    keys.ensure()
    jump = jump_key_store(tmp_path / "relay_ssh")
    jump.ensure()
    work = tmp_path / "work %h"
    work.mkdir(exist_ok=True)
    return RelayAgentClient(ShellRunner(), keys, jump_keys=jump, ssh_binary=str(fake.binary), work_dir=work)


def _via(*opens: tuple[str, int]) -> JumpHost:
    return JumpHost(host=HUB_IP, port=2202, alias="vpn-relay-1", host_key=HUB_KEY,
                    opens=frozenset(opens or [(RU_IP, 22)]))


PINNED = {
    "BatchMode": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none", "PubkeyAuthentication": "yes",
    "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "GlobalKnownHostsFile": "/dev/null",
    "CheckHostIP": "no", "UpdateHostKeys": "no", "HashKnownHosts": "no", "ConnectTimeout": "10",
    "ServerAliveInterval": "10", "ServerAliveCountMax": "3", "ForwardAgent": "no", "ForwardX11": "no",
    "ClearAllForwardings": "yes", "RequestTTY": "no", "ControlMaster": "no", "ControlPath": "none",
}


async def test_a_call_via_the_hub_pins_both_hops_with_their_own_keys(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    client = _client(tmp_path, fake_ssh)
    reply = await client.call(RU_IP, 22, "status", alias="vpn-relay-7", host_key=RELAY_KEY, via=_via())
    assert reply.ok
    calls = fake_ssh.calls()
    assert [c["hop"] for c in calls] == ["relay", "hub"]
    relay, hub = calls
    for hop in (relay, hub):
        assert hop["argv"][:2] == ["-F", "/dev/null"]
        for key, value in PINNED.items():
            assert hop["opts"][key] == value, (hop["hop"], key)
        assert hop["opts"]["StrictHostKeyChecking"] == "yes", hop["hop"]
        assert hop["info"]["-l"] == "root"
        assert "-J" not in hop["argv"] and "ProxyJump" not in hop["opts"]
    # The keys are not mixed up: the agent key on the relay, the jump key on the hub.
    assert relay["info"]["-i"] == str(tmp_path / "relay_ssh" / "id_ed25519")
    assert hub["info"]["-i"] == str(tmp_path / "relay_ssh" / "id_ed25519_jump")
    # Each hop its alias, its port, its known_hosts — and only its own pinned key there.
    assert (relay["opts"]["HostKeyAlias"], relay["info"]["-p"]) == ("vpn-relay-7", "22")
    assert (hub["opts"]["HostKeyAlias"], hub["info"]["-p"]) == ("vpn-relay-1", "2202")
    assert relay["opts"]["UserKnownHostsFile"] != hub["opts"]["UserKnownHostsFile"]
    assert hub["info"]["-W"] == f"{RU_IP}:22" and hub["info"]["host"] == HUB_IP and hub["info"]["request"] is None
    assert relay["info"]["host"] == RU_IP and relay["info"]["request"] == "status"
    assert relay["opts"]["ProxyUseFdpass"] == "no" and "ProxyCommand" not in hub["opts"]
    assert relay["opts"]["LogLevel"] == "ERROR" and hub["opts"]["LogLevel"] == "INFO"
    # The ProxyCommand is exactly the hub's argv, shell-quoted (the paths carry a space
    # and a %), and runs in /bin/sh whatever the bot's $SHELL.
    proxy = shlex.split(relay["opts"]["ProxyCommand"].replace("%%", "%"))
    assert proxy == [str(fake_ssh.binary), *hub["argv"]]
    assert relay["shell"] == "/bin/sh"
    assert not list((tmp_path / "work %h").iterdir()), "both temporary known_hosts are gone"


async def test_a_pairing_via_the_hub_learns_the_relay_key_and_still_pins_the_hub(
    tmp_path: Path, fake_ssh: FakeSsh
) -> None:
    client = _client(tmp_path, fake_ssh)
    reply = await client.call(RU_IP, 22, f"hello {'A' * 43}", alias="vpn-relay-pairing-3", host_key=None, via=_via())
    assert reply.ok and reply.learned_host_key == RELAY_KEY
    relay, hub = fake_ssh.calls()
    assert relay["opts"]["StrictHostKeyChecking"] == "accept-new"
    assert hub["opts"]["StrictHostKeyChecking"] == "yes", "the hub's hop is never trust-on-first-use"


async def test_the_forward_names_the_relay_in_lower_case_like_the_hubs_list(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    """sshd compares a permitopen host with strcmp: ``-W`` must match the line exactly."""
    fake_ssh.state["permit"] = ["ru1.example.net:22"]
    fake_ssh.save()
    client = _client(tmp_path, fake_ssh)
    reply = await client.call("RU1.Example.NET", 22, "status", alias="vpn-relay-7", host_key=RELAY_KEY,
                              via=_via(("ru1.example.net", 22)))
    assert reply.ok
    assert fake_ssh.calls()[1]["info"]["-W"] == "ru1.example.net:22"


async def test_a_hub_with_another_host_key_is_refused(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    fake_ssh.state["hub_key"] = OTHER_KEY
    fake_ssh.save()
    client = _client(tmp_path, fake_ssh)
    with pytest.raises(RelayHostKeyMismatch) as exc:
        await client.call(RU_IP, 22, "status", alias="vpn-relay-7", host_key=RELAY_KEY, via=_via())
    assert exc.value.key == "relay_ssh_host_key_changed_hub"
    assert [c["hop"] for c in fake_ssh.calls()] == ["relay", "hub"], "the relay's hop never got a connection"


async def test_a_relay_with_another_host_key_behind_the_hub_is_refused(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    fake_ssh.state["relay_key"] = OTHER_KEY
    fake_ssh.save()
    client = _client(tmp_path, fake_ssh)
    with pytest.raises(RelayHostKeyMismatch):
        await client.call(RU_IP, 22, "status", alias="vpn-relay-7", host_key=RELAY_KEY, via=_via())


async def test_an_unknown_relay_is_refused_before_anything_runs(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    client = _client(tmp_path, fake_ssh)
    for host, port in ((RU2_IP, 22), (RU_IP, 2222), (HUB_IP, 2202)):
        with pytest.raises(RelaySshError) as exc:
            await client.call(host, port, "status", alias="vpn-relay-8", host_key=RELAY_KEY, via=_via())
        assert exc.value.key == "relay_ssh_not_behind_hub"
    assert fake_ssh.calls() == []


async def test_the_hubs_permitopen_refusal_is_named(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    """The bot believes the hub opens RU2, the hub's line does not: sshd refuses the forward."""
    client = _client(tmp_path, fake_ssh)
    with pytest.raises(RelaySshError) as exc:
        await client.call(RU2_IP, 22, "status", alias="vpn-relay-8", host_key=RELAY_KEY,
                          via=_via((RU_IP, 22), (RU2_IP, 22)))
    assert exc.value.key == "relay_ssh_jump_refused" and exc.value.params["value"] == f"{RU2_IP}:22"


async def test_a_hub_that_lost_the_jump_line_is_named(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    """ssh names the host it was given: the hub's refusal of the jump key is told apart."""
    fake_ssh.state["hub_denies"] = True
    fake_ssh.save()
    client = _client(tmp_path, fake_ssh)
    with pytest.raises(RelaySshError) as exc:
        await client.call(RU_IP, 22, "status", alias="vpn-relay-7", host_key=RELAY_KEY, via=_via())
    assert exc.value.key == "relay_ssh_jump_denied" and exc.value.params == {"hub": HUB_IP}


async def test_a_call_via_the_hub_needs_the_jump_key(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    keys = RelayKeyStore(tmp_path / "k")
    keys.ensure()
    client = RelayAgentClient(ShellRunner(), keys, ssh_binary=str(fake_ssh.binary))
    with pytest.raises(RelaySshError):
        await client.call(RU_IP, 22, "status", alias="vpn-relay-7", host_key=RELAY_KEY, via=_via())
    assert fake_ssh.calls() == []


def test_the_jump_key_is_its_own_key_next_to_the_agent_key(tmp_path: Path) -> None:
    keys = RelayKeyStore(tmp_path)
    jump = jump_key_store(tmp_path)
    assert keys.ensure() != jump.ensure()
    assert jump.key_path == tmp_path / "id_ed25519_jump"
    assert oct(jump.key_path.stat().st_mode & 0o777) == "0o600"
    assert jump.pub_path.read_text(encoding="utf-8").endswith(" vpn-bot-relay-jump\n")
    before = jump.key_path.read_bytes()
    jump.ensure()
    assert jump.key_path.read_bytes() == before, "never replaced"
    jump.key_path.chmod(0o644)
    with pytest.raises(ServiceError) as exc:
        jump.public_key()
    assert exc.value.params["path"] == str(jump.key_path)


# ── the hub's line: the real agent, stubs, a fake root ──────────────────────────

AGENT_LINE = 'restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBB vpn-relay-agent\n'
OPERATOR_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPER operator@laptop\n"


class Hub:
    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.log = tmp / "calls.log"
        for d in ("opt/vpn-service", "etc/vpn-relay", "etc/systemd/system", "run", "root/.ssh", "var/lib/vpn-relay"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        self.bin.mkdir()
        (self.root / "opt/vpn-service/.env").write_text(
            "NODE_ROLE=relay\nRELAY_UPSTREAM_HOST=origin.example.com\nRELAY_FORWARD_TCP_PORTS=443\n", encoding="utf-8"
        )
        (self.root / "etc/vpn-relay/pairing.json").write_text(
            json.dumps({"v": 1, "token_sha256": "0" * 64, "exp": 0, "paired_at": 1}), encoding="utf-8"
        )
        (self.root / "etc/vpn-relay/install.json").write_text(
            json.dumps({"installer": "vpn-relay", "created_app_dir": False, "ip_forward_before": "0",
                        "authorized_keys": "/root/.ssh/authorized_keys", "adoption_backup": None}),
            encoding="utf-8",
        )
        self.keys = self.root / "root/.ssh/authorized_keys"
        self.keys.write_text(OPERATOR_LINE + AGENT_LINE + "# keep me\n", encoding="utf-8")
        self.keys.chmod(0o600)
        self.confirm_rc = 0
        self.input_status = "PENDING CONFIRM (reverts at 2026-11-18 10:05:00 UTC) — main probe did not confirm it: x"
        # What `sshd -T` says about forwarding: local only, as deploy installs it.
        self.sshd_t = "allowtcpforwarding local\nallowstreamlocalforwarding no\ndisableforwarding no\n"
        self.sshd_rc = 0

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(f'#!/bin/bash\necho "$(basename "$0") $*" >> "{self.log}"\n{body}', encoding="utf-8")
        path.chmod(0o755)

    def run(self, request: str) -> tuple[int, dict[str, Any]]:
        status_file = self.root / "status-line"
        status_file.write_text(self.input_status + "\n", encoding="utf-8")
        self.stub(
            "vpn-relay-apply",
            f'case "$1" in\n'
            f'  input-confirm) echo "input filter confirmed by ssh-session"; '
            f'[[ {self.confirm_rc} == 0 ]] && echo "OK (tcp 22; confirmed now by ssh-session)" > "{status_file}"; '
            f'[[ {self.confirm_rc} == 0 ]] || echo "vpn-relay-apply: this ssh session began before the filter" >&2; '
            f'exit {self.confirm_rc};;\n'
            f'  input-status) cat "{status_file}";;\n'
            f'  check) echo "vpn-relay-apply: ok"; exit 0;;\n'
            f"esac\nexit 0\n",
        )
        sshd_t = self.root / "sshd-T"
        sshd_t.write_text("port 22\n" + self.sshd_t + "permitrootlogin without-password\n", encoding="utf-8")
        self.stub("sshd", f'[[ "$1" == -T ]] || exit 2\ncat "{sshd_t}"\nexit {self.sshd_rc}\n')
        for name, body in {"nft": "exit 1\n", "getent": "exit 2\n", "ss": "exit 0\n", "sysctl": "echo 1\n",
                           "ip": "exit 0\n", "git": "exit 0\n", "logger": "exit 0\n", "systemctl": "exit 0\n",
                           "systemd-run": "exit 0\n"}.items():
            self.stub(name, body)
        env = {"PATH": os.environ["PATH"], "VPN_RELAY_AGENT_SELFTEST": "1", "VPN_RELAY_AGENT_ROOT": str(self.root),
               "VPN_RELAY_AGENT_SELFTEST_BIN": str(self.bin), "SSH_ORIGINAL_COMMAND": request}
        proc = subprocess.run([sys.executable, "-I", str(AGENT)], env=env, capture_output=True, text=True,
                              check=False, timeout=50)
        return proc.returncode, json.loads(proc.stdout)

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


@pytest.fixture
def hub(tmp_path: Path) -> Hub:
    return Hub(tmp_path)


def _jump_line(*opens: str) -> str:
    permits = ",".join(f'permitopen="{o}"' for o in opens)
    return f'restrict,port-forwarding,{permits},command="/bin/false" ssh-ed25519 {BLOB} vpn-bot-relay-jump'


def test_the_hub_keeps_exactly_one_jump_line_and_nothing_else_moves(hub: Hub) -> None:
    rc, payload = hub.run(f"jump key={BLOB} open=ru1.example.net:2222,{RU_IP}:22")
    assert rc == 0, payload
    line = _jump_line(f"{RU_IP}:22", "ru1.example.net:2222")
    assert hub.keys.read_text(encoding="utf-8") == OPERATOR_LINE + AGENT_LINE + "# keep me\n" + line + "\n"
    assert payload["jump"] == {"open": [f"{RU_IP}:22", "ru1.example.net:2222"], "changed": True,
                               "key_sha256": agent.key_sha256(BLOB)}
    assert oct(hub.keys.stat().st_mode & 0o777) == "0o600", "the file's mode is kept"
    # The same list again: nothing to write.
    rc, payload = hub.run(f"jump key={BLOB} open={RU_IP}:22,ru1.example.net:2222")
    assert rc == 0 and payload["jump"]["changed"] is False
    # Another list: the line is replaced where it stands, still one.
    hub.keys.write_text(hub.keys.read_text(encoding="utf-8") + "# after\n", encoding="utf-8")
    rc, _ = hub.run(f"jump key={BLOB} open={RU2_IP}:22")
    assert rc == 0
    assert hub.keys.read_text(encoding="utf-8") == (
        OPERATOR_LINE + AGENT_LINE + "# keep me\n" + _jump_line(f"{RU2_IP}:22") + "\n# after\n"
    )
    # status reports it.
    rc, status = hub.run("status")
    assert rc == 0 and status["jump"] == {"open": [f"{RU2_IP}:22"], "key_sha256": agent.key_sha256(BLOB)}
    # jump-off: the line goes, the rest is exactly what it was.
    rc, payload = hub.run("jump-off")
    assert rc == 0 and payload["jump"] == {"open": [], "changed": True}
    assert hub.keys.read_text(encoding="utf-8") == OPERATOR_LINE + AGENT_LINE + "# keep me\n# after\n"
    assert "jump" not in hub.run("status")[1]


@pytest.mark.parametrize(
    ("sshd_t", "why"),
    [
        ("allowtcpforwarding yes\nallowstreamlocalforwarding yes\ndisableforwarding no\n", "more than local TCP"),
        ("allowtcpforwarding remote\nallowstreamlocalforwarding no\ndisableforwarding no\n", "more than local TCP"),
        ("allowtcpforwarding local\nallowstreamlocalforwarding local\ndisableforwarding no\n", "more than local TCP"),
        ("allowtcpforwarding local\nallowstreamlocalforwarding remote\ndisableforwarding no\n", "more than local TCP"),
        ("allowtcpforwarding local\nallowstreamlocalforwarding all\ndisableforwarding no\n", "more than local TCP"),
        ("allowtcpforwarding no\nallowstreamlocalforwarding no\ndisableforwarding no\n", "forwards nothing"),
        ("allowtcpforwarding local\nallowstreamlocalforwarding no\ndisableforwarding yes\n", "forwards nothing"),
        ("", "more than local TCP"),
    ],
)
def test_no_jump_line_where_sshd_allows_remote_forwarding(hub: Hub, sshd_t: str, why: str) -> None:
    """port-forwarding in the key would let it open listeners too (-R: TCP, Unix
    sockets) — no key option forbids that, sshd's own setting must."""
    hub.sshd_t = sshd_t
    before = hub.keys.read_text(encoding="utf-8")
    rc, payload = hub.run(f"jump key={BLOB} open={RU_IP}:22")
    assert rc == 4 and why in payload["error"], payload
    assert hub.keys.read_text(encoding="utf-8") == before
    # jump-off never needs it: removing the line is always allowed.
    assert hub.run("jump-off")[0] == 0


def test_no_jump_line_when_sshd_cannot_tell(hub: Hub) -> None:
    hub.sshd_rc = 255
    before = hub.keys.read_text(encoding="utf-8")
    rc, payload = hub.run(f"jump key={BLOB} open={RU_IP}:22")
    assert rc == 4 and "sshd -T failed" in payload["error"]
    assert hub.keys.read_text(encoding="utf-8") == before


def test_every_relay_gets_local_only_forwarding_from_the_deploy() -> None:
    """deploy.sh installs the setting the agent requires, on every relay (class ssh)."""
    text = (ROOT / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    assert ('"deploy/host/ssh/00-vpnrelay-forwarding.conf|/etc/ssh/sshd_config.d/00-vpnrelay-forwarding.conf'
            '|0644|root:root|ssh|relay"') in text
    lines = [ln for ln in (ROOT / "deploy/host/ssh/00-vpnrelay-forwarding.conf").read_text(encoding="utf-8")
             .splitlines() if ln.strip() and not ln.startswith("#")]
    assert lines == ["AllowTcpForwarding local", "AllowStreamLocalForwarding no"]


def test_the_jump_line_grants_forwarding_and_nothing_else() -> None:
    line = agent.jump_line(BLOB, [(RU_IP, 22), ("ru1.example.net", 2222)])
    options, keytype, blob, comment = line.split(" ")
    assert options.split(",") == [
        "restrict", "port-forwarding", f'permitopen="{RU_IP}:22"', 'permitopen="ru1.example.net:2222"',
        'command="/bin/false"',
    ]
    assert (keytype, blob, comment) == ("ssh-ed25519", BLOB, "vpn-bot-relay-jump")
    for never in ("pty", "agent-forwarding", "x11-forwarding", "user-rc", "permitlisten", "environment"):
        assert never not in options


def test_a_file_without_a_final_newline_keeps_its_lines(hub: Hub) -> None:
    hub.keys.write_text(OPERATOR_LINE + AGENT_LINE.rstrip("\n"), encoding="utf-8")
    assert hub.run(f"jump key={BLOB} open={RU_IP}:22")[0] == 0
    assert hub.keys.read_text(encoding="utf-8") == OPERATOR_LINE + AGENT_LINE + _jump_line(f"{RU_IP}:22") + "\n"
    assert hub.run("jump-off")[0] == 0
    assert hub.keys.read_text(encoding="utf-8") == OPERATOR_LINE + AGENT_LINE


@pytest.mark.parametrize(
    "open_",
    ["127.0.0.1:22", "0.0.0.0:22", "169.254.1.1:22", "224.0.0.1:22", "localhost:22", f"{RU_IP}:0",
     f"{RU_IP}:65536", f"{RU_IP}:022", f"{RU_IP}:22,{RU_IP}:22", "256.1.1.1:22", "-a.example.net:22"],
)
def test_bad_jump_values_are_refused_and_change_nothing(hub: Hub, open_: str) -> None:
    before = hub.keys.read_text(encoding="utf-8")
    rc, payload = hub.run(f"jump key={BLOB} open={open_}")
    assert rc == 2 and payload["error"].startswith("refused"), payload
    assert hub.keys.read_text(encoding="utf-8") == before


def test_a_key_that_is_not_ed25519_is_refused(hub: Hub) -> None:
    wrong = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x21" + bytes(32)).decode()
    assert len(wrong) == len(BLOB) and wrong.startswith("AAAAC3NzaC1lZDI1NTE5AAAAI")
    rc, payload = hub.run(f"jump key={wrong} open={RU_IP}:22")
    assert rc == 2 and "not an ssh-ed25519" in payload["error"]


def test_a_key_with_another_line_is_never_made_a_jump_key(hub: Hub) -> None:
    """The agent's own key (or any key the file already authorizes) cannot get forwarding."""
    hub.keys.write_text(OPERATOR_LINE + f'restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 {BLOB} x\n',
                        encoding="utf-8")
    before = hub.keys.read_text(encoding="utf-8")
    rc, payload = hub.run(f"jump key={BLOB} open={RU_IP}:22")
    assert rc == 2 and "already has another line" in payload["error"]
    assert hub.keys.read_text(encoding="utf-8") == before


def test_jump_needs_a_paired_relay(hub: Hub) -> None:
    (hub.root / "etc/vpn-relay/pairing.json").write_text(
        json.dumps({"v": 1, "token_sha256": "0" * 64, "exp": 0, "paired_at": None}), encoding="utf-8"
    )
    for request in (f"jump key={BLOB} open={RU_IP}:22", "jump-off", "input-confirm"):
        rc, payload = hub.run(request)
        assert rc == 3 and "not paired" in payload["error"], request
    assert "vpn-relay-apply input-confirm" not in hub.calls()


def test_uninstall_removes_the_jump_line_too(hub: Hub) -> None:
    assert hub.run(f"jump key={BLOB} open={RU_IP}:22")[0] == 0
    assert agent.strip_agent_keys(hub.keys) == 2
    assert hub.keys.read_text(encoding="utf-8") == OPERATOR_LINE + "# keep me\n"


# ── input-confirm through the agent ─────────────────────────────────────────────


def test_input_confirm_runs_the_helper_inside_the_session(hub: Hub) -> None:
    rc, payload = hub.run("input-confirm")
    assert rc == 0, payload
    calls = hub.calls()
    assert "vpn-relay-apply input-confirm" in calls
    assert not any(c.startswith("systemd-run") for c in calls), "a direct child: the ssh session is its ancestor"
    assert payload["input_confirm"]["rc"] == 0
    assert payload["input_status"] == "OK (tcp 22; confirmed now by ssh-session)"


def test_a_refused_input_confirm_is_reported(hub: Hub) -> None:
    hub.confirm_rc = 19
    rc, payload = hub.run("input-confirm")
    assert rc == 4 and "input-confirm exit 19" in payload["error"] and "began before the filter" in payload["error"]


def test_status_carries_the_input_filter_line(hub: Hub) -> None:
    rc, payload = hub.run("status")
    assert rc == 0 and payload["input_status"].startswith("PENDING CONFIRM (reverts at")


# ── the relay service: routing, the jump line, input-confirm ───────────────────


class FakeClient:
    """Records every call with its route; answers from ``replies`` (first word)."""

    def __init__(self, tmp: Path) -> None:
        self.jump_keys = jump_key_store(tmp / "relay_ssh")
        self.calls: list[dict[str, Any]] = []
        self.replies: dict[str, list[AgentReply]] = {}
        self.errors: list[ServiceError] = []

    def answer(self, word: str, *replies: AgentReply) -> None:
        self.replies[word] = list(replies)

    async def call(self, host: str, port: int, request: str, *, alias: str, host_key: str | None,
                   timeout: float = 60.0, sensitive: Any = (), via: JumpHost | None = None) -> AgentReply:
        self.calls.append({"host": host, "port": port, "request": request, "alias": alias,
                           "host_key": host_key, "via": via})
        if self.errors:
            raise self.errors.pop(0)
        word = request.split()[0]
        if word in ("jump", "jump-off"):
            return AgentReply(0, {"ok": True, "jump": {"changed": True}})
        queue = self.replies.get(word) or [AgentReply(0, {"ok": True})]
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def requests(self) -> list[tuple[str, str, str | None]]:
        """(host, request, the hub it went through)."""
        return [(c["host"], c["request"], c["via"].host if c["via"] else None) for c in self.calls]


def _agent(ssh_host: str, *, port: int = 22, host_key: str = RELAY_KEY, target: str = "vpn.example.com") -> RelayAgent:
    return RelayAgent(ssh_host=ssh_host, ssh_port=port, host_key=host_key, target_host=target, tcp_ports=(443,),
                      udp_ports=(443,), agent_version="1", paired_at=NOW)


class World:
    async def start(self, tmp: Path) -> World:
        self.db = Database(tmp / "vpn.db")
        await self.db.connect()
        await self.db.bootstrap()
        await self.db.conn.execute(
            "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
            "VALUES (?, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now')", (ADMIN,)
        )
        await self.db.commit()
        self.repo = RelayRepository(self.db)
        self.audit = _Audit()
        self.client = FakeClient(tmp)
        self.outside: list[str] = []

        async def tcp(host: str, port: int, sni: str) -> bool:
            self.outside.append(host)
            return True

        async def udp(host: str, port: int) -> bool | None:
            self.outside.append(host)
            return True

        async def resolve(host: str) -> list[str]:
            return [host] if validators.ipv4_address(host) is not None else []

        root = tmp / "checkout"
        (root / ".git").mkdir(parents=True)
        (root / ".git/HEAD").write_text("0123456789abcdef0123456789abcdef01234567\n", encoding="utf-8")
        (root / "scripts").mkdir()
        (root / "scripts/install.sh").write_text("#!/bin/bash\n", encoding="utf-8")
        self.service = RelayService(
            relays=self.repo, users=_Users(), audit=self.audit,  # type: ignore[arg-type]
            clock=ClockProvider(), catalog=RelayCatalog(), keys=RelayKeyStore(tmp / "relay_ssh"),
            client=self.client,  # type: ignore[arg-type]
            settings=_settings(tmp, hysteria2_enabled=True, xray_public_host="vpn.example.com"),
            source_root=root, tcp_probe=tcp, udp_probe=udp, resolve=resolve,
        )
        self.hub = await self._relay("he1", HUB_IP, host_key=HUB_KEY, port=2202)
        await self.repo.set_role(self.hub.id, RELAY_ROLE_HUB, now=NOW, updated_by=None)
        self.hub = await self.repo.get_by_id(self.hub.id)
        self.ru1 = await self._relay("ru1", RU_IP)
        self.ru2 = await self._relay("ru2", RU2_IP)
        await self.service.refresh_catalog()
        return self

    async def _relay(self, name: str, ip: str, *, host_key: str = RELAY_KEY, port: int = 22) -> Any:
        return await self.repo.create(
            name=name, label=name, host=ip, source_ips=validators.parse_ipv4_networks("s", f"{ip}/32"), now=NOW,
            agent=_agent(ip, port=port, host_key=host_key),
        )

    async def mode(self, on: bool) -> None:
        await self.db.set_meta("failover_mode", "on" if on else "off")

    async def close(self) -> None:
        await self.db.close()


@pytest.fixture
async def world(tmp_path: Path) -> Any:
    w = await World().start(tmp_path)
    yield w
    await w.close()


def _jump_requests(world: World) -> list[str]:
    return [c["request"] for c in world.client.calls if c["request"].split()[0] in ("jump", "jump-off")]


def _open_of(request: str) -> str:
    return request.rsplit(" open=", 1)[1]


async def test_without_the_flag_or_the_mode_every_relay_is_reached_directly(world: World) -> None:
    await world.service.agent_status(ADMIN, world.ru1.id)
    assert world.client.requests() == [(RU_IP, "status", None)]


async def test_via_hub_routes_that_relay_through_the_hub_and_opens_exactly_it(world: World) -> None:
    result = await world.service.set_via_hub(ADMIN, world.ru1.id, True)
    assert result.relay.via_hub and result.sync_error is None
    assert _jump_requests(world) == [jump_request(world.client.jump_keys.public_key(), [(RU_IP, 22)])]
    world.client.calls.clear()
    await world.service.agent_status(ADMIN, world.ru1.id)
    await world.service.agent_status(ADMIN, world.ru2.id)
    await world.service.agent_status(ADMIN, world.hub.id)
    assert world.client.requests() == [(RU_IP, "status", HUB_IP), (RU2_IP, "status", None), (HUB_IP, "status", None)]
    via = world.client.calls[0]["via"]
    assert via == JumpHost(host=HUB_IP, port=2202, alias=f"vpn-relay-{world.hub.id}", host_key=HUB_KEY,
                           opens=frozenset({(RU_IP, 22)}))
    assert world.client.calls[0]["alias"] == f"vpn-relay-{world.ru1.id}"
    assert world.client.calls[0]["host_key"] == RELAY_KEY
    assert "relay_via_hub_changed" in world.audit.actions() and "relay_hub_jump_synced" in world.audit.actions()
    # Off again: the hub's line goes (nothing is behind the hub any more).
    await world.service.set_via_hub(ADMIN, world.ru1.id, False)
    assert _jump_requests(world) == ["jump-off"]


async def test_the_fallback_mode_routes_every_relay_but_the_hub(world: World) -> None:
    await world.mode(True)
    for relay in (world.ru1, world.ru2, world.hub):
        await world.service.agent_status(ADMIN, relay.id)
    assert world.client.requests() == [
        (HUB_IP, f"jump key={BLOB_OF(world)} open={RU_IP}:22,{RU2_IP}:22", None),
        (RU_IP, "status", HUB_IP),
        (RU2_IP, "status", HUB_IP),
        (HUB_IP, "status", None),
    ], "one jump line for both, written once, before the first call through the hub"


def BLOB_OF(world: World) -> str:  # noqa: N802 — reads like a constant in the expectations
    return world.client.jump_keys.public_key().split()[1]


async def test_a_relay_behind_the_hub_without_a_hub_is_refused_clearly(world: World) -> None:
    await world.repo.set_role(world.hub.id, "edge", now=NOW, updated_by=None)
    await world.mode(True)
    with pytest.raises(RelaySshError) as exc:
        await world.service.agent_status(ADMIN, world.ru1.id)
    assert exc.value.key == "relay_hub_route_no_hub"
    assert world.client.calls == []
    with pytest.raises(InvalidOperation) as refused:
        await world.service.set_via_hub(ADMIN, world.ru2.id, True)
    assert refused.value.key == "relay_hub_route_no_hub"


async def test_the_hub_itself_cannot_be_put_behind_the_hub(world: World) -> None:
    with pytest.raises(InvalidOperation) as exc:
        await world.service.set_via_hub(ADMIN, world.hub.id, True)
    assert exc.value.key == "relay_via_hub_is_hub"


async def test_a_refused_forward_rewrites_the_hubs_line_once(world: World) -> None:
    await world.service.set_via_hub(ADMIN, world.ru1.id, True)
    world.client.calls.clear()
    world.client.errors = [RelaySshError("no", key="relay_ssh_jump_refused")]
    reply = await world.service.agent_status(ADMIN, world.ru1.id)
    assert reply.ok
    assert [r for _, r, _ in world.client.requests()] == ["status", f"jump key={BLOB_OF(world)} open={RU_IP}:22", "status"]


async def test_a_hub_that_lost_the_line_gets_it_written_again_once(world: World) -> None:
    """The bot's cache says the line is there; the hub refuses the jump key: rewrite, retry."""
    await world.service.set_via_hub(ADMIN, world.ru1.id, True)
    world.client.calls.clear()
    world.client.errors = [RelaySshError("no", key="relay_ssh_jump_denied")]
    assert (await world.service.agent_status(ADMIN, world.ru1.id)).ok
    assert [r for _, r, _ in world.client.requests()] == ["status", f"jump key={BLOB_OF(world)} open={RU_IP}:22", "status"]


async def test_a_health_poll_during_a_pairing_keeps_its_address_open(world: World) -> None:
    """The hub's line is synced by anyone (a health poll) while a pairing runs through
    the hub: the address opened for the pairing stays in it until the pairing ends."""
    await world.mode(True)
    issued = await world.service.issue_new(ADMIN, name="ru3", host="ru3.example.net", target_host="vpn.example.com")
    new_ip = "203.0.113.70"
    real_call = world.client.call

    async def hello_with_a_poll(host: str, port: int, request: str, **kwargs: Any) -> AgentReply:
        if request.startswith("hello"):
            # A health poll of ru1 lands in the middle of the pairing: its route
            # rewrites the hub's line (forced, as after a refused forward).
            await world.service.sync_hub_jump(force=True)
        return await real_call(host, port, request, **kwargs)

    world.client.call = hello_with_a_poll  # type: ignore[method-assign]
    world.client.answer("hello", AgentReply(0, {
        "ok": True, "protocol": 1, "agent": "1", "target_host": "vpn.example.com", "tcp": [443], "udp": [443],
        "egress": {"src": new_ip, "dev": "eth0"},
    }, learned_host_key=RELAY_KEY))
    world.client.answer("status", AgentReply(0, {"ok": True, "check": {"rc": 0, "lines": []}}))
    await world.service.complete(ADMIN, issued.pairing.id, new_ip)
    jumps = [_open_of(r) for r in _jump_requests(world)]
    assert len(jumps) == 2, "the pairing's write and the poll's"
    assert set(jumps) == {f"{RU_IP}:22,{RU2_IP}:22,{new_ip}:22"}, "never rewritten without the pairing's address"
    check = [c for c in world.client.calls if c["request"] == "status" and c["host"] == new_ip][0]
    assert (new_ip, 22) in check["via"].opens


async def test_the_switch_of_the_fallback_mode_follows_on_the_hubs_line(world: World) -> None:
    await world.mode(True)
    await world.service.sync_hub_jump_quietly()
    await world.mode(False)
    await world.service.sync_hub_jump_quietly()
    assert [_open_of(r) if r != "jump-off" else r for r in _jump_requests(world)] == [
        f"{RU_IP}:22,{RU2_IP}:22", "jump-off",
    ]


async def test_a_pairing_in_the_fallback_mode_says_hello_through_the_hub(world: World) -> None:
    await world.mode(True)
    issued = await world.service.issue_new(ADMIN, name="ru3", host="ru3.example.net", target_host="vpn.example.com")
    new_ip = "203.0.113.70"
    world.client.answer("hello", AgentReply(0, {
        "ok": True, "protocol": 1, "agent": "1", "target_host": "vpn.example.com", "tcp": [443], "udp": [443],
        "egress": {"src": new_ip, "dev": "eth0"},
    }, learned_host_key=RELAY_KEY))
    world.client.answer("status", AgentReply(0, {"ok": True, "check": {"rc": 0, "lines": ["ok: TCP connect"]}}))
    outcome = await world.service.complete(ADMIN, issued.pairing.id, new_ip)
    assert outcome.checks.passed and outcome.checks.via_hub
    assert world.outside == [], "main cannot probe a relay behind the hub — its own check stands in"
    jumps = _jump_requests(world)
    assert _open_of(jumps[0]) == f"{RU_IP}:22,{RU2_IP}:22,{new_ip}:22", "the new address opened for the hello"
    hello = next(c for c in world.client.calls if c["request"].startswith("hello"))
    assert hello["via"] is not None and hello["host_key"] is None and (new_ip, 22) in hello["via"].opens
    check = [c for c in world.client.calls if c["request"] == "status"][0]
    assert check["via"] is not None and check["host_key"] == RELAY_KEY and check["alias"] == hello["alias"]
    # Paired: now one of the relays behind the hub — the same list, nothing rewritten.
    assert len(jumps) == 1


async def test_a_failed_pairing_through_the_hub_closes_the_address_again(world: World) -> None:
    await world.mode(True)
    issued = await world.service.issue_new(ADMIN, name="ru3", host="ru3.example.net", target_host="vpn.example.com")
    world.client.answer("hello", AgentReply(3, {"ok": False, "error": "token does not match"}))
    with pytest.raises(ServiceError):
        await world.service.complete(ADMIN, issued.pairing.id, "203.0.113.70")
    assert [_open_of(r) for r in _jump_requests(world)] == [
        f"{RU_IP}:22,{RU2_IP}:22,203.0.113.70:22", f"{RU_IP}:22,{RU2_IP}:22",
    ]


async def test_confirm_input_goes_through_the_hub_for_a_relay_behind_it(world: World) -> None:
    await world.mode(True)
    world.client.answer("input-confirm", AgentReply(0, {"ok": True, "input_status": "OK (tcp 22)"}))
    reply = await world.service.confirm_input(ADMIN, world.ru1.id)
    assert reply.payload["input_status"] == "OK (tcp 22)"
    assert (RU_IP, "input-confirm", HUB_IP) in world.client.requests()
    rows = [r for r in world.audit.rows if r["action"] == "relay_input_confirmed"]
    assert rows and rows[0]["details"]["ok"] is True and rows[0]["details"]["auto"] is False


PENDING = "PENDING CONFIRM (reverts at 2026-11-18 10:05:00 UTC) — main probe did not confirm it: main unreachable"


async def test_a_pending_filter_after_update_is_confirmed_by_the_bots_session(world: World) -> None:
    world.client.answer("update", AgentReply(0, {"ok": True, "update": {"state": "succeeded"}}))
    world.client.answer("status", AgentReply(0, {"ok": True, "agent": "1", "input_status": PENDING}))
    world.client.answer("input-confirm", AgentReply(0, {"ok": True, "input_status": "OK (tcp 22)"}))
    await world.service.update_agent(ADMIN, world.ru1.id)
    assert [r for _, r, _ in world.client.requests()] == ["update", "status", "input-confirm"]
    stored = await world.repo.get_by_id(world.ru1.id)
    assert stored is not None and stored.agent is not None and stored.agent.last_status is not None
    assert stored.agent.last_status["input_status"] == "OK (tcp 22)"


async def test_the_health_loop_confirms_a_pending_filter_and_leaves_a_confirmed_one(world: World) -> None:
    world.client.answer("status", AgentReply(0, {"ok": True, "agent": "1", "input_status": PENDING,
                                                  "check": {"rc": 0, "lines": []}}))
    world.client.answer("input-confirm", AgentReply(4, {"ok": False, "error": "too late"}))
    check = await world.service.poll_agent(world.ru1)
    assert check == AgentCheck(ok=True, rc=0)
    assert [r for _, r, _ in world.client.requests()] == ["status", "input-confirm"]
    stored = await world.repo.get_by_id(world.ru1.id)
    assert stored is not None and stored.agent is not None and stored.agent.last_status is not None
    assert stored.agent.last_status["input_status"] == PENDING, "a refused confirmation changes nothing"
    world.client.calls.clear()
    world.client.answer("status", AgentReply(0, {"ok": True, "agent": "1", "input_status": "OK (tcp 22)"}))
    await world.service.poll_agent(world.ru1)
    assert [r for _, r, _ in world.client.requests()] == ["status"]


async def test_route_info_says_why_for_the_card(world: World) -> None:
    assert (await world.service.route_info(world.ru1)).via_hub is False
    await world.mode(True)
    info = await world.service.route_info(world.ru1)
    assert info.via_hub and info.reason == "mode" and info.hub is not None and info.hub.name == "he1"
    assert (await world.service.route_info(world.hub)).via_hub is False
    await world.service.set_via_hub(ADMIN, world.ru1.id, True)
    ru1 = await world.repo.get_by_id(world.ru1.id)
    assert ru1 is not None and (await world.service.route_info(ru1)).reason == "flag"


# ── schema v47 ──────────────────────────────────────────────────────────────────


async def test_v46_relays_come_out_managed_directly(tmp_path: Path) -> None:
    path = tmp_path / "v46.db"
    async with aiosqlite.connect(path) as conn:
        await conn.executescript((SNAPSHOT_DIR / "v46.sql").read_text(encoding="utf-8"))
        await conn.execute(
            "INSERT INTO relays (name, label, host, source_ips, created_at, updated_at, role) "
            "VALUES ('ru1', 'ru1', 'ru1.example.net', '203.0.113.50/32', 'now', 'now', 'edge')"
        )
        await conn.execute("INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '46')")
        await conn.commit()
    db = Database(path)
    await db.connect()
    try:
        await db.bootstrap()
        assert await db.get_meta("schema_version") == str(CURRENT_SCHEMA_VERSION)
        relays = await RelayRepository(db).list_all()
        assert [(r.name, r.via_hub) for r in relays] == [("ru1", False)]
        assert await RelayRepository(db).set_via_hub(relays[0].id, True, now=NOW, updated_by=None)
        relay = await RelayRepository(db).get_by_id(relays[0].id)
        assert relay is not None and relay.via_hub is True
    finally:
        await db.close()


# ── the card ────────────────────────────────────────────────────────────────────


async def test_the_card_offers_via_hub_and_confirm_and_says_how_the_agent_is_reached(world: World) -> None:
    from bot.keyboards.admin_relays import relay_card_keyboard
    from bot.relays import relay_card_text
    from i18n import t

    def buttons(relay: Any, *, fallback: bool = True) -> dict[str, str]:
        markup = relay_card_keyboard(relay, fallback=fallback)
        return {b.callback_data or "": b.text for row in markup.inline_keyboard for b in row}

    base = f"admin:relay:{world.ru1.id}"
    assert buttons(world.ru1)[f"{base}:ag:hub"] == t("btn_relay_via_hub_off")
    assert f"{base}:ag:hub" not in buttons(world.ru1, fallback=False)
    assert f"admin:relay:{world.hub.id}:ag:hub" not in buttons(world.hub), "a hub is reached directly"
    assert f"{base}:ag:inconf" not in buttons(world.ru1)

    await world.repo.record_agent_status(world.ru1.id, {"input_status": PENDING}, now=NOW, agent_version="1")
    await world.service.set_via_hub(ADMIN, world.ru1.id, True)
    ru1 = await world.repo.get_by_id(world.ru1.id)
    assert ru1 is not None
    found = buttons(ru1)
    assert found[f"{base}:ag:hub"] == t("btn_relay_via_hub_on")
    assert found[f"{base}:ag:inconf"] == t("btn_relay_input_confirm")
    text = relay_card_text(ru1, active_keys=0, probe=None, route=await world.service.route_info(ru1))
    assert t("relay_route_hub_flag", hub="he1 · he1") in text
    assert "PENDING CONFIRM" in text


async def test_an_agent_from_before_jump_is_named_outdated(world: World) -> None:
    async def old_agent(host: str, port: int, request: str, **kwargs: Any) -> AgentReply:
        world.client.calls.append({"host": host, "port": port, "request": request, "alias": kwargs["alias"],
                                   "host_key": kwargs["host_key"], "via": kwargs.get("via")})
        return AgentReply(2, {"ok": False, "error": "refused: not an agent command"})

    world.client.call = old_agent  # type: ignore[method-assign]
    result = await world.service.set_via_hub(ADMIN, world.ru1.id, True)
    assert result.relay.via_hub and result.sync_error is not None
    assert result.sync_error.key == "relay_agent_outdated" and result.sync_error.params == {"name": "he1"}
