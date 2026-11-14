"""The main server's side of the relay installer (docs/relay.md).

* services/relay_pairing.py — the code (round trip, every field validated, expiry)
  and the one command line for the relay (the bot's commit, the installer's sha256
  pinned, the code on stdin);
* services/relay_ssh.py — the bot's ed25519 key (generated once, 0600, never
  replaced, refused when not private), the ssh argv (every option pinned, only a
  whitelisted request), trust on first use and the pinned key afterwards — with a
  fake `ssh` that behaves like OpenSSH's known_hosts handling;
* services/relay_agents.py — pairing on a real SQLite database: hello, the TCP/UDP
  checks, registration in the relays table with the source IPs the anomaly detector
  excludes, the token cleared; a failed check or a wrong relay registers nothing;
  status / apply / update / remove;
* services/relay_health.py — the QUIC version-negotiation probe against a local UDP
  server that answers like a QUIC server, and one that does not.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from test_relay import ADMIN, _settings
from test_relay_admin import MODERATOR, _Audit, _Users

from adapters.clock import ClockProvider
from adapters.shell_runner import ShellRunner
from db.database import Database
from models.enums import AuditEntityType
from repositories.relay_agents import RelayAgentRepository
from repositories.relays import RelayRepository
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.relay import RelayCatalog, RelaySnapshot
from services.relay_agents import (
    PairingCheckFailed,
    RelayAgentError,
    RelayAgentService,
    installer_source,
    parse_address,
)
from services.relay_health import is_version_negotiation, quic_probe, quic_vn_request
from services.relay_management import RelayService
from services.relay_pairing import (
    PairingCode,
    PairingCodeError,
    Source,
    decode_pairing_code,
    encode_pairing_code,
    new_token,
    parse_ports,
    relay_command,
)
from services.relay_ssh import AgentReply, RelayAgentClient, RelayHostKeyMismatch, RelayKeyStore, RelaySshError

BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
PUBKEY = f"ssh-ed25519 {BLOB}"
SHA = "0123456789abcdef0123456789abcdef01234567"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyOfTheRelayHostKeyOfTheRelay00"
RELAY_IP = "203.0.113.50"
TARGET = "vpn.example.com"

pytestmark = pytest.mark.timeout(60)


# ── the code ──────────────────────────────────────────────────────────────────


def _code(**kw: Any) -> PairingCode:
    values: dict[str, Any] = dict(
        target_host=TARGET, tcp_ports=(443,), udp_ports=(443,), main_pubkey=PUBKEY, token=new_token(),
        exp=int(time.time()) + 1800,
    )
    values.update(kw)
    return PairingCode(**values)


def test_code_round_trip_and_format() -> None:
    code = _code(tcp_ports=(8443, 443))
    raw = encode_pairing_code(code)
    assert "=" not in raw and raw.isascii()
    data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    assert set(data) == {"v", "target_host", "ports", "main_pubkey", "one_time_token", "exp"}
    assert data["ports"] == ["443/tcp", "8443/tcp", "443/udp"]
    assert data["v"] == 1
    assert decode_pairing_code(raw, now=int(time.time())) == PairingCode(
        target_host=TARGET, tcp_ports=(443, 8443), udp_ports=(443,), main_pubkey=PUBKEY, token=code.token, exp=code.exp
    )


def test_code_expiry() -> None:
    raw = encode_pairing_code(_code(exp=1000))
    decode_pairing_code(raw, now=1000 + 300)
    with pytest.raises(PairingCodeError, match="истёк"):
        decode_pairing_code(raw, now=1000 + 301)


@pytest.mark.parametrize(
    "kw",
    [
        {"target_host": "203.0.113.1"},
        {"target_host": "localhost"},
        {"tcp_ports": ()},
        {"udp_ports": (1, 2, 3, 4, 5, 6, 7, 8, 9)},
        {"tcp_ports": (443, 443)},
        {"tcp_ports": (0,)},
        {"main_pubkey": "ssh-rsa AAAA"},
        {"token": "short"},
    ],
)
def test_code_fields_validated(kw: dict[str, Any]) -> None:
    with pytest.raises(PairingCodeError):
        _code(**kw)


def test_tokens_are_fresh_and_43_chars() -> None:
    tokens = {new_token() for _ in range(50)}
    assert len(tokens) == 50 and all(len(t) == 43 for t in tokens)


@pytest.mark.parametrize(("raw", "ok"), [("443", (443,)), ("443, 8443", (443, 8443)), ("0", None), ("0443", None), ("", None)])
def test_parse_ports(raw: str, ok: tuple[int, ...] | None) -> None:
    if ok is None:
        with pytest.raises(PairingCodeError):
            parse_ports(raw)
    else:
        assert parse_ports(raw) == ok


def test_relay_command_pins_commit_and_sha256() -> None:
    raw = encode_pairing_code(_code())
    source = Source(owner="Egor051", repo="vpnbot", commit=SHA, installer_sha256="a" * 64)
    command = relay_command(raw, source)
    assert command.startswith(f"curl -fsSL -o install.sh https://raw.githubusercontent.com/Egor051/vpnbot/{SHA}/scripts/install.sh")
    assert f"echo '{'a' * 64}  install.sh' | sha256sum -c --quiet -" in command
    assert f"printf '%s\\n' '{raw}' | sudo env INSTALL_REF={SHA} bash install.sh --relay" in command
    assert "INSTALL_REPO" not in command
    assert "\n" not in command
    fork = relay_command(raw, Source(owner="me", repo="fork", commit=SHA, installer_sha256="b" * 64))
    assert "INSTALL_REPO=https://github.com/me/fork.git" in fork


def test_installer_source_reads_the_checkout(tmp_path: Path) -> None:
    git = tmp_path / ".git"
    (git / "refs/heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "refs/heads/main").write_text(SHA + "\n", encoding="utf-8")
    (git / "config").write_text('[core]\n\tbare = false\n[remote "origin"]\n\turl = https://github.com/me/fork.git\n', encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts/install.sh").write_bytes(b"#!/bin/bash\n")
    source = installer_source(tmp_path)
    assert source == Source(owner="me", repo="fork", commit=SHA, installer_sha256=hashlib.sha256(b"#!/bin/bash\n").hexdigest())
    (git / "refs/heads/main").unlink()
    (git / "packed-refs").write_text(f"# pack-refs\n{SHA} refs/heads/main\n", encoding="utf-8")
    assert installer_source(tmp_path).commit == SHA


def test_installer_source_of_this_repository() -> None:
    root = Path(__file__).resolve().parents[1]
    if not (root / ".git").exists():
        pytest.skip("not a git checkout")
    source = installer_source(root)
    assert len(source.commit) == 40
    assert source.installer_sha256 == hashlib.sha256((root / "scripts/install.sh").read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("value", "expected"),
    [(RELAY_IP, (RELAY_IP, 22)), (f"{RELAY_IP}:2222", (RELAY_IP, 2222)), ("Relay.Example.com", ("relay.example.com", 22))],
)
def test_parse_address(value: str, expected: tuple[str, int]) -> None:
    assert parse_address(value) == expected


@pytest.mark.parametrize("value", ["", "10.0.0.5", "192.168.1.1:22", "relay:22", "-oProxyCommand=x", "a b", f"{RELAY_IP}:0", f"{RELAY_IP}:99999", "[::1]:22"])
def test_parse_address_refuses(value: str) -> None:
    with pytest.raises(InvalidOperation):
        parse_address(value)


# ── the key ───────────────────────────────────────────────────────────────────


def test_key_is_generated_once_private_and_never_replaced(tmp_path: Path) -> None:
    store = RelayKeyStore(tmp_path / "relay_ssh")
    pub = store.ensure()
    assert pub.startswith("ssh-ed25519 ")
    mode = stat.S_IMODE(store.key_path.stat().st_mode)
    assert mode == 0o600
    assert stat.S_IMODE((tmp_path / "relay_ssh").stat().st_mode) == 0o700
    before = store.key_path.read_bytes()
    assert store.ensure() == pub
    assert store.key_path.read_bytes() == before
    assert store.pub_path.read_text(encoding="utf-8").startswith(pub)


def test_a_key_others_can_read_is_refused(tmp_path: Path) -> None:
    store = RelayKeyStore(tmp_path)
    store.ensure()
    store.key_path.chmod(0o644)
    with pytest.raises(Exception, match="не приватный"):
        store.public_key()


def test_a_symlinked_key_is_refused(tmp_path: Path) -> None:
    real = RelayKeyStore(tmp_path / "real")
    real.ensure()
    (tmp_path / "link").mkdir()
    (tmp_path / "link/id_ed25519").symlink_to(real.key_path)
    with pytest.raises(Exception, match="недоступен|не обычный"):
        RelayKeyStore(tmp_path / "link").public_key()


# ── ssh: argv, TOFU, pinning — a fake ssh that writes known_hosts like OpenSSH ─

FAKE_SSH = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
opts = {}
i = 0
while i < len(args):
    if args[i] == "-o":
        k, _, v = args[i + 1].partition("="); opts[k] = v; i += 2
    elif args[i] in ("-F", "-i", "-p", "-l"):
        i += 2
    elif args[i] == "--":
        host, request = args[i + 1], args[i + 2]; break
    else:
        i += 1
state = json.load(open(os.environ["FAKE_SSH_STATE"]))
with open(os.environ["FAKE_SSH_LOG"], "a") as log:
    log.write(json.dumps({"argv": sys.argv[1:], "opts": opts}) + "\n")
known = open(opts["UserKnownHostsFile"]).read()
alias = opts["HostKeyAlias"]
lines = [l.split() for l in known.splitlines() if l.strip()]
pinned = [f"{l[1]} {l[2]}" for l in lines if l[0] == alias]
if pinned and state["host_key"] not in pinned:
    print("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.", file=sys.stderr); sys.exit(255)
if not pinned:
    if opts["StrictHostKeyChecking"] != "accept-new":
        print("Host key verification failed.", file=sys.stderr); sys.exit(255)
    with open(opts["UserKnownHostsFile"], "a") as fh:
        fh.write(f"{alias} {state['host_key']}\n")
reply = state["replies"].get(request.split()[0], {"ok": False, "error": "refused"})
print(json.dumps(reply))
sys.exit(0 if reply.get("ok") else int(state.get("rc", 4)))
"""


class FakeSsh:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.binary = tmp / "ssh"
        self.binary.write_text(FAKE_SSH, encoding="utf-8")
        self.binary.chmod(0o755)
        self.state_path = tmp / "ssh-state.json"
        self.log = tmp / "ssh-log.jsonl"
        self.state: dict[str, Any] = {"host_key": HOST_KEY, "replies": {}}
        os.environ["FAKE_SSH_STATE"] = str(self.state_path)
        os.environ["FAKE_SSH_LOG"] = str(self.log)
        self.save()

    def save(self) -> None:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")

    def reply(self, command: str, payload: dict[str, Any]) -> None:
        self.state["replies"][command] = payload
        self.save()

    def calls(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def fake_ssh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeSsh:
    monkeypatch.setenv("FAKE_SSH_STATE", "")
    return FakeSsh(tmp_path)


def _client(tmp_path: Path, fake: FakeSsh) -> RelayAgentClient:
    keys = RelayKeyStore(tmp_path / "relay_ssh")
    keys.ensure()
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return RelayAgentClient(ShellRunner(), keys, ssh_binary=str(fake.binary), work_dir=work)


async def test_ssh_argv_pins_every_option(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    fake_ssh.reply("status", {"ok": True})
    client = _client(tmp_path, fake_ssh)
    reply = await client.call(RELAY_IP, 2222, "status", alias="vpn-relay-7", host_key=HOST_KEY)
    assert reply.ok
    call = fake_ssh.calls()[-1]
    argv, opts = call["argv"], call["opts"]
    assert argv[:2] == ["-F", "/dev/null"]
    assert argv[-3:] == ["--", RELAY_IP, "status"]
    assert "-p" in argv and argv[argv.index("-p") + 1] == "2222"
    assert argv[argv.index("-l") + 1] == "root"
    assert opts["StrictHostKeyChecking"] == "yes"
    for key, value in {"BatchMode": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none",
                       "PasswordAuthentication": "no", "ForwardAgent": "no", "ClearAllForwardings": "yes",
                       "RequestTTY": "no", "GlobalKnownHostsFile": "/dev/null", "HostKeyAlias": "vpn-relay-7",
                       "UpdateHostKeys": "no", "ControlMaster": "no"}.items():
        assert opts[key] == value, key
    assert not list((tmp_path / "work").iterdir()), "the temporary known_hosts is gone"


async def test_tofu_learns_the_key_then_a_changed_key_is_refused(tmp_path: Path, fake_ssh: FakeSsh) -> None:
    fake_ssh.reply("hello", {"ok": True})
    fake_ssh.reply("status", {"ok": True})
    client = _client(tmp_path, fake_ssh)
    first = await client.call(RELAY_IP, 22, f"hello {new_token()}", alias="vpn-relay-pairing-1", host_key=None)
    assert first.ok and first.learned_host_key == HOST_KEY
    assert fake_ssh.calls()[-1]["opts"]["StrictHostKeyChecking"] == "accept-new"
    assert (await client.call(RELAY_IP, 22, "status", alias="vpn-relay-1", host_key=first.learned_host_key)).ok
    fake_ssh.state["host_key"] = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherKeyAnotherKeyAnotherKeyAnother0"
    fake_ssh.save()
    with pytest.raises(RelayHostKeyMismatch):
        await client.call(RELAY_IP, 22, "status", alias="vpn-relay-1", host_key=first.learned_host_key)


@pytest.mark.parametrize(
    "request_",
    ["status; id", "id", "hello x", "apply target=a.b tcp=443", "uninstall now", "status\n", "update --force"],
)
async def test_only_whitelisted_requests_leave_the_bot(tmp_path: Path, fake_ssh: FakeSsh, request_: str) -> None:
    client = _client(tmp_path, fake_ssh)
    with pytest.raises(RelaySshError):
        await client.call(RELAY_IP, 22, request_, alias="vpn-relay-1", host_key=HOST_KEY)
    assert fake_ssh.calls() == []


@pytest.mark.parametrize("host", ["-oProxyCommand=sh", "a b", "relay;id", "10.0.0.1/8"])
async def test_hosts_that_ssh_could_misread_are_refused(tmp_path: Path, fake_ssh: FakeSsh, host: str) -> None:
    client = _client(tmp_path, fake_ssh)
    with pytest.raises(RelaySshError):
        await client.call(host, 22, "status", alias="vpn-relay-1", host_key=HOST_KEY)
    assert fake_ssh.calls() == []


async def test_the_token_is_redacted_from_the_runner_log(tmp_path: Path, fake_ssh: FakeSsh, caplog: pytest.LogCaptureFixture) -> None:
    token = new_token()
    fake_ssh.state["rc"] = 3
    fake_ssh.reply("hello", {"ok": False, "error": "no"})
    client = _client(tmp_path, fake_ssh)
    reply = await client.call(RELAY_IP, 22, f"hello {token}", alias="vpn-relay-pairing-1", host_key=None, sensitive=(token,))
    assert not reply.ok
    assert token not in caplog.text


# ── the service on a real database ────────────────────────────────────────────


class FakeClient:
    """Records requests; answers from ``replies`` (first word of the request)."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.replies: dict[str, AgentReply] = {}

    async def call(self, host: str, port: int, request: str, *, alias: str, host_key: str | None,
                   timeout: float = 60.0, sensitive: Any = ()) -> AgentReply:
        self.calls.append({"host": host, "port": port, "request": request, "alias": alias, "host_key": host_key})
        return self.replies.get(request.split()[0], AgentReply(4, {"ok": False, "error": "unexpected"}))


def _hello(**kw: Any) -> AgentReply:
    payload: dict[str, Any] = {"ok": True, "cmd": "hello", "protocol": 1, "agent": "1", "target_host": TARGET,
                               "tcp": [443], "udp": [443], "egress": {"src": "198.51.100.77", "dev": "eth0"},
                               "live_target": "192.0.2.10"}
    payload.update(kw)
    return AgentReply(0, payload, learned_host_key=HOST_KEY)


class World:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path

    async def start(self, **settings: Any) -> World:
        self.db = Database(self.tmp / "vpn.db")
        await self.db.connect()
        await self.db.bootstrap()
        await self.db.conn.execute(
            "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
            "VALUES (?, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now')", (ADMIN,)
        )
        await self.db.commit()
        self.audit = _Audit()
        self.relay_repo = RelayRepository(self.db)
        self.relays = RelayService(relays=self.relay_repo, users=_Users(), audit=self.audit,  # type: ignore[arg-type]
                                   clock=ClockProvider(), catalog=RelayCatalog())
        self.repo = RelayAgentRepository(self.db)
        self.keys = RelayKeyStore(self.tmp / "relay_ssh")
        self.client = FakeClient()
        self.client.replies["hello"] = _hello()
        self.tcp: list[bool] = [True]
        self.udp: list[bool | None] = [True]
        self.now = time.time()
        root = self.tmp / "checkout"
        (root / ".git").mkdir(parents=True)
        (root / ".git/HEAD").write_text(SHA + "\n", encoding="utf-8")
        (root / "scripts").mkdir()
        (root / "scripts/install.sh").write_text("#!/bin/bash\n", encoding="utf-8")

        async def tcp(host: str, port: int, sni: str) -> bool:
            return self.tcp[0]

        async def udp(host: str, port: int) -> bool | None:
            return self.udp[0]

        async def resolve(host: str) -> list[str]:
            return [RELAY_IP] if host in (RELAY_IP, "relay.example.com") else []

        self.service = RelayAgentService(
            repo=self.repo, relays=self.relays, users=_Users(), audit=self.audit,  # type: ignore[arg-type]
            clock=ClockProvider(), keys=self.keys, client=self.client,  # type: ignore[arg-type]
            settings=_settings(self.tmp, hysteria2_enabled=True, xray_public_host=TARGET, **settings),
            source_root=root, tcp_probe=tcp, udp_probe=udp, resolve=resolve, now=lambda: self.now,
        )
        return self

    async def close(self) -> None:
        await self.db.close()


@pytest.fixture
async def world(tmp_path: Path) -> Any:
    w = await World(tmp_path).start()
    yield w
    await w.close()


async def test_issue_renders_code_and_command_and_keeps_only_the_live_token(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    code = decode_pairing_code(issued.code, now=int(time.time()))
    assert code.target_host == TARGET and code.tcp_ports == (443,) and code.udp_ports == (443,)
    assert code.main_pubkey == world.keys.public_key()
    assert code.token == issued.pairing.token
    assert issued.pairing.expires_at == int(world.now) + 1800
    assert issued.code in issued.command and SHA in issued.command
    assert world.keys.key_path.exists()
    rows = [r for r in world.audit.rows if r["action"] == "relay_pairing_issued"]
    assert rows and issued.pairing.token not in json.dumps(rows[0]["details"])


async def test_issue_is_superadmin_only(world: World) -> None:
    with pytest.raises(AccessDenied):
        await world.service.issue(MODERATOR, name="ru2", target_host=TARGET)


@pytest.mark.parametrize("target", ["203.0.113.1", "localhost", "bad name"])
async def test_issue_refuses_a_target_that_is_not_a_name(world: World, target: str) -> None:
    with pytest.raises(InvalidOperation):
        await world.service.issue(ADMIN, name="ru2", target_host=target)


async def test_a_name_can_wait_for_only_one_pairing(world: World) -> None:
    await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    with pytest.raises(InvalidOperation):
        await world.service.issue(ADMIN, name="ru2", target_host=TARGET)


async def test_default_target_is_the_main_dns_name(world: World) -> None:
    assert world.service.default_target() == TARGET


async def test_complete_registers_the_relay(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    outcome = await world.service.complete(ADMIN, issued.pairing.id, f"{RELAY_IP}:2222")
    hello = world.client.calls[0]
    assert hello["request"] == f"hello {issued.pairing.token}"
    assert hello["host_key"] is None and hello["port"] == 2222
    relay = outcome.relay
    assert relay.name == "ru2" and relay.host == RELAY_IP and relay.enabled
    assert {str(n) for n in relay.source_ips} == {f"{RELAY_IP}/32", "198.51.100.77/32"}
    agent = await world.repo.get(relay.id)
    assert agent is not None and agent.host_key == HOST_KEY and agent.ssh_port == 2222
    assert agent.target_host == TARGET
    pairing = await world.repo.get_pairing(issued.pairing.id)
    assert pairing is not None and pairing.state == "completed" and pairing.token == "" and pairing.relay_id == relay.id
    assert outcome.checks.tcp is True and outcome.checks.udp is True
    assert outcome.health_interval == 300
    # The anomaly detector excludes exactly these (it reads the relays table).
    snapshot = RelaySnapshot.of(await world.relay_repo.list_all())
    assert ipaddress.IPv4Address("198.51.100.77") in snapshot.source_networks[0] or any(
        ipaddress.IPv4Address("198.51.100.77") in n for n in snapshot.source_networks
    )
    assert "relay_paired" in world.audit.actions(AuditEntityType.RELAY)


async def test_a_failed_check_registers_nothing_and_a_retry_works(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    world.udp[0] = False
    with pytest.raises(PairingCheckFailed) as exc:
        await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)
    assert exc.value.checks.udp is False
    assert await world.relay_repo.count() == 0
    still = await world.repo.get_pairing(issued.pairing.id)
    assert still is not None and still.state == "pending" and still.token
    world.udp[0] = None  # this host's own QUIC server does not answer: not judged
    outcome = await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)
    assert outcome.checks.udp is None


async def test_tcp_failure_blocks_too(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    world.tcp[0] = False
    with pytest.raises(PairingCheckFailed):
        await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)


async def test_a_relay_set_up_by_another_code_is_refused(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    world.client.replies["hello"] = _hello(target_host="other.example.com")
    with pytest.raises(RelayAgentError):
        await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)
    world.client.replies["hello"] = _hello(protocol=2)
    with pytest.raises(RelayAgentError):
        await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)
    assert await world.relay_repo.count() == 0


async def test_a_refused_hello_is_reported(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    world.client.replies["hello"] = AgentReply(3, {"ok": False, "error": "token does not match"})
    with pytest.raises(RelayAgentError, match="token does not match"):
        await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)


async def test_an_expired_pairing_cannot_complete_and_loses_its_token(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    world.now += 1800 + 900 + 1
    with pytest.raises(NotFound):
        await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)
    pairing = await world.repo.get_pairing(issued.pairing.id)
    assert pairing is not None and pairing.state == "expired" and pairing.token == ""
    assert world.client.calls == []


async def test_within_the_grace_it_completes(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    world.now += 1800 + 600
    await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)


async def test_cancel_clears_the_token(world: World) -> None:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    await world.service.cancel(ADMIN, issued.pairing.id)
    pairing = await world.repo.get_pairing(issued.pairing.id)
    assert pairing is not None and pairing.state == "cancelled" and pairing.token == ""
    with pytest.raises(NotFound):
        await world.service.show(ADMIN, issued.pairing.id)


async def _paired(world: World) -> int:
    issued = await world.service.issue(ADMIN, name="ru2", target_host=TARGET)
    return (await world.service.complete(ADMIN, issued.pairing.id, RELAY_IP)).relay.id


async def test_status_uses_the_pinned_key_and_records_it(world: World) -> None:
    relay_id = await _paired(world)
    world.client.replies["status"] = AgentReply(0, {"ok": True, "agent": "1", "check": {"rc": 0, "lines": []}})
    await world.service.status(ADMIN, relay_id)
    call = world.client.calls[-1]
    assert call["request"] == "status" and call["host_key"] == HOST_KEY and call["alias"] == f"vpn-relay-{relay_id}"
    agent = await world.repo.get(relay_id)
    assert agent is not None and agent.last_status == {"agent": "1", "check": {"rc": 0, "lines": []}}


async def test_change_forward_validates_and_records(world: World) -> None:
    relay_id = await _paired(world)
    world.client.replies["apply"] = AgentReply(0, {"ok": True})
    await world.service.change_forward(ADMIN, relay_id, target_host="New.Example.com", tcp="443, 8443", udp="443")
    assert world.client.calls[-1]["request"] == "apply target=new.example.com tcp=443,8443 udp=443"
    agent = await world.repo.get(relay_id)
    assert agent is not None and agent.target_host == "new.example.com" and agent.tcp_ports == (443, 8443)
    with pytest.raises(InvalidOperation):
        await world.service.change_forward(ADMIN, relay_id, target_host="1.2.3.4", tcp="443", udp="443")
    world.client.replies["apply"] = AgentReply(4, {"ok": False, "error": "rolled back"})
    with pytest.raises(RelayAgentError):
        await world.service.change_forward(ADMIN, relay_id, target_host="x.example.com", tcp="443", udp="443")
    agent = await world.repo.get(relay_id)
    assert agent is not None and agent.target_host == "new.example.com", "a failed apply records nothing"


async def test_remove_uninstalls_then_deletes(world: World) -> None:
    relay_id = await _paired(world)
    world.client.replies["uninstall"] = AgentReply(0, {"ok": True, "uninstall": {"ok": True}})
    report = await world.service.remove(ADMIN, relay_id, with_keys=False)
    assert report.uninstalled and report.deletion.deleted
    assert await world.repo.get(relay_id) is None
    assert await world.relay_repo.get_by_id(relay_id) is None


async def test_remove_stops_when_the_relay_refuses(world: World) -> None:
    relay_id = await _paired(world)
    world.client.replies["uninstall"] = AgentReply(4, {"ok": False, "error": "busy"})
    with pytest.raises(RelayAgentError):
        await world.service.remove(ADMIN, relay_id, with_keys=False)
    assert await world.relay_repo.get_by_id(relay_id) is not None
    report = await world.service.remove(ADMIN, relay_id, with_keys=False, relay_side=False)
    assert not report.uninstalled and report.deletion.deleted


async def test_an_unmanaged_relay_is_not_offered(world: World) -> None:
    relay = await world.relays.create(ADMIN, name="ru1", host="relay.example.com", source_ips=RELAY_IP)
    with pytest.raises(NotFound):
        await world.service.status(ADMIN, relay.id)
    assert await world.service.managed(ADMIN) == []


# ── the QUIC probe against a real local UDP socket ────────────────────────────


def _udp_server(answer: bool) -> tuple[int, threading.Event]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        try:
            while not stop.is_set():
                try:
                    data, addr = sock.recvfrom(2048)
                except OSError:
                    return
                if not answer or len(data) < 1200 or data[1:5] != bytes.fromhex("1a2a3a4a"):
                    continue
                dl = data[5]
                dcid = data[6 : 6 + dl]
                sl = data[6 + dl]
                scid = data[7 + dl : 7 + dl + sl]
                vn = bytes([0x80]) + b"\x00\x00\x00\x00" + bytes([len(scid)]) + scid + bytes([len(dcid)]) + dcid
                sock.sendto(vn + bytes.fromhex("00000001"), addr)
        finally:
            sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return port, stop


async def test_quic_probe_sees_version_negotiation() -> None:
    port, stop = _udp_server(answer=True)
    try:
        assert await quic_probe("127.0.0.1", port, timeout=3) is True
    finally:
        stop.set()


async def test_quic_probe_fails_without_an_answer() -> None:
    port, stop = _udp_server(answer=False)
    try:
        assert await quic_probe("127.0.0.1", port, timeout=0.6) is False
    finally:
        stop.set()


def test_vn_parser_wants_our_connection_ids() -> None:
    dcid, scid = b"A" * 8, b"B" * 8
    assert len(quic_vn_request(dcid, scid)) == 1200
    good = b"\x80\x00\x00\x00\x00" + bytes([8]) + scid + bytes([8]) + dcid + b"\x00\x00\x00\x01"
    assert is_version_negotiation(good, dcid=dcid, scid=scid)
    assert not is_version_negotiation(good, dcid=scid, scid=dcid)
    assert not is_version_negotiation(b"\x80\x00\x00\x00\x01" + good[5:], dcid=dcid, scid=scid)
    assert not is_version_negotiation(good[:-4], dcid=dcid, scid=scid)
    assert not is_version_negotiation(b"\x40" + good[1:], dcid=dcid, scid=scid)


def test_asyncio_is_available() -> None:
    assert asyncio.get_event_loop_policy() is not None


@pytest.mark.parametrize(("tcp", "udp", "ok"), [(True, True, True), (True, None, True), (True, False, False), (False, True, False)])
async def test_health_loop_counts_udp_when_it_is_judged(tcp: bool, udp: bool | None, ok: bool) -> None:
    from conftest import make_relay

    from services.relay_health import RelayHealthSupervisor

    relay = make_relay(1, "ru1", host="relay.example.com")

    async def load() -> list[Any]:
        return [relay]

    async def tcp_probe(host: str, port: int, sni: str) -> bool:
        return tcp

    async def udp_probe(host: str) -> bool | None:
        return udp

    supervisor = RelayHealthSupervisor(
        load_relays=load, port=443, sni="example.com", admin_ids=frozenset({ADMIN}), window=0.0,
        probe=tcp_probe, udp_probe=udp_probe,
    )
    result = await supervisor.probe_now(relay)
    assert result.ok is ok and result.udp is udp


def test_udp_is_probed_only_with_hysteria2(tmp_path: Path) -> None:
    from services.relay_health import build_relay_health_supervisor

    async def load() -> list[Any]:
        return []

    off = build_relay_health_supervisor(_settings(tmp_path, hysteria2_enabled=False), load)
    on = build_relay_health_supervisor(_settings(tmp_path, hysteria2_enabled=True), load)
    assert off._udp_probe is None
    assert on._udp_probe is not None
