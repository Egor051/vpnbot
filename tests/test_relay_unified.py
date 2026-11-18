"""ONE relay model, ONE service, ONE screen (v44, services/relays.py, docs/relay.md).

* migration — the production snapshot (ru1 from the legacy seed, 13 keys, an empty
  relay_agents) and a snapshot with an agent: every relays / vpn_keys value
  byte-identical, the agent folded onto its relay, relay_agents gone;
* the production scenario end to end on that very database — ru1 with its keys →
  connect an agent (no name asked) → still ONE relay, keys / links / subscriptions
  unchanged → disconnect the agent → a hand-made relay again, nothing lost;
* «это другой сервер», and every failure leaving the relay exactly as it was;
* a NEW relay: the public host for links apart from the SSH address;
* the one health verdict: traffic + the agent, ONE alert per change, never two;
* the one screen: list, page, add, attach, detach, delete with uninstall, the
  wizard's «🛰 Relay», buttons of both former sections still in the chat history,
  TOTP in front of every change.
"""

from __future__ import annotations

import ast
import ipaddress
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiosqlite
import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from test_relay import ADMIN, _settings
from test_relay_admin import MODERATOR, _Audit, _Users
from test_relay_agents import HOST_KEY, SHA, TARGET, FakeClient, _hello
from test_schema_upgrade_path import _materialise

from adapters.clock import ClockProvider
from bot.fsm.states import AdminRelayStates, TotpStates
from bot.handlers import admin_relays as ui
from bot.progress import PROGRESS_EDIT_INTERVAL_SECONDS
from bot.relays import outcome_text, pairing_text
from bot.wizard_views import menu_keyboard
from db.database import Database
from i18n import t
from models.dto import Relay
from models.enums import AuditEntityType
from repositories.key_bundles import KeyBundleRepository
from repositories.relays import RelayRepository
from services.errors import AccessDenied, InvalidOperation, NotFound, ServiceError
from services.relay import RelayCatalog, RelaySnapshot
from services.relay_health import (
    LEVEL_DOWN,
    LEVEL_OK,
    LEVEL_WARN,
    AgentCheck,
    RelayHealthSupervisor,
    agent_check_from_status,
)
from services.relay_ssh import AgentReply, RelayKeyStore
from services.relays import PairingCheckFailed, RelayAgentError, RelayService, merge_source_ips
from subscription_server.render import render_links
from subscription_server.store import BundleView

pytestmark = pytest.mark.timeout(60)

RU1_HOST = "relay.example.net"
RU1_IP = "198.51.100.7"
OTHER_IP = "203.0.113.200"
EGRESS = "198.51.100.77"  # what _hello() reports as the relay's source address


# ── the world: a real database, the real service, a fake SSH client ───────────


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.dns: dict[str, list[str]] = {RU1_HOST: [RU1_IP]}

    async def start(self, *, production: bool = False) -> Env:
        db_path = self.tmp / "vpn.db"
        if production:
            await _materialise(db_path, 43)
        self.db = Database(db_path)
        await self.db.connect()
        await self.db.bootstrap()
        await self.db.conn.execute(
            "INSERT OR IGNORE INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
            "VALUES (?, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now')", (ADMIN,)
        )
        await self.db.commit()
        self.audit = _Audit()
        self.repo = RelayRepository(self.db)
        self.client = FakeClient()
        self.client.replies["hello"] = _hello()
        self.tcp: list[bool] = [True]
        self.udp: list[bool | None] = [True]
        self.settings = _settings(self.tmp, hysteria2_enabled=True, xray_public_host=TARGET)
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
            if host in self.dns:
                return list(self.dns[host])
            return [host] if host.replace(".", "").isdigit() else []

        self.catalog = RelayCatalog()
        self.service = RelayService(
            relays=self.repo, users=_Users(), audit=self.audit,  # type: ignore[arg-type]
            clock=ClockProvider(), catalog=self.catalog, settings=self.settings,
            keys=RelayKeyStore(self.tmp / "relay_ssh"), client=self.client,  # type: ignore[arg-type]
            source_root=root, tcp_probe=tcp, udp_probe=udp, resolve=resolve,
        )
        await self.service.refresh_catalog()
        return self

    async def close(self) -> None:
        await self.db.close()

    async def relay(self, relay_id: int = 1) -> Relay:
        relay = await self.repo.get_by_id(relay_id)
        assert relay is not None
        return relay

    async def key_rows(self) -> list[tuple[Any, ...]]:
        rows = await self.db.conn.execute_fetchall("SELECT * FROM vpn_keys ORDER BY id")
        return [tuple(row) for row in rows]

    async def links(self) -> list[list[str]]:
        """Every link of both production subscriptions, as the endpoint renders them."""
        bundles = KeyBundleRepository(self.db)
        snapshot = RelaySnapshot.of(await self.repo.list_all())
        out = []
        for bundle_id in (1, 2):
            bundle = await bundles.get_by_id(bundle_id)
            assert bundle is not None
            keys = tuple(await bundles.list_keys_of_bundle(bundle_id))
            out.append(render_links(BundleView(bundle=bundle, keys=keys, traffic=None, relays=snapshot), self.settings))
        return out


def common(relay: Relay) -> tuple[Any, ...]:
    """What keys and links read of a relay: never touched by its agent."""
    return (relay.id, relay.name, relay.label, relay.host, relay.enabled, relay.in_subscriptions, relay.note)


@pytest.fixture
async def env(tmp_path: Path) -> Any:
    world = await Env(tmp_path).start()
    yield world
    await world.close()


@pytest.fixture
async def prod(tmp_path: Path) -> Any:
    world = await Env(tmp_path).start(production=True)
    yield world
    await world.close()


# ── migration ─────────────────────────────────────────────────────────────────

AGENT_COLUMNS = (
    "ssh_host", "ssh_port", "host_key", "target_host", "tcp_ports", "udp_ports",
    "agent_version", "agent_paired_at", "agent_status_json", "agent_status_at",
)


async def _rows(db_path: Path, table: str) -> dict[int, dict[str, Any]]:
    async with aiosqlite.connect(db_path) as conn:
        conn.row_factory = aiosqlite.Row
        rows = await (await conn.execute(f"SELECT * FROM {table}")).fetchall()  # noqa: S608
    return {int(row["id"]): dict(row) for row in rows}


async def _bootstrap(db_path: Path) -> None:
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
    finally:
        await db.close()


async def test_v44_on_the_production_snapshot_keeps_every_relay_and_key_value(tmp_path: Path) -> None:
    db_path = tmp_path / "vpn.db"
    await _materialise(db_path, 43)
    relays_before, keys_before = await _rows(db_path, "relays"), await _rows(db_path, "vpn_keys")
    assert [r["name"] for r in relays_before.values()] == ["ru1"]
    assert sum(1 for k in keys_before.values() if k["relay"] == "ru1" and k["status"] != "deleted") == 13

    await _bootstrap(db_path)

    relays_after, keys_after = await _rows(db_path, "relays"), await _rows(db_path, "vpn_keys")
    assert keys_after == keys_before, "every key row byte-identical (relay, labels, payloads)"
    assert relays_after.keys() == relays_before.keys()
    for relay_id, before in relays_before.items():
        after = relays_after[relay_id]
        assert {k: after[k] for k in before} == before, "name, label, host, source IPs… unchanged"
        assert all(after[column] is None for column in AGENT_COLUMNS), "no agent"
    async with aiosqlite.connect(db_path) as conn:
        tables = {r[0] for r in await (await conn.execute("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
    assert "relay_agents" not in tables
    db = Database(db_path)
    await db.connect()
    try:
        [ru1] = await RelayRepository(db).list_all()
        assert ru1.agent is None and not ru1.managed
        assert (ru1.name, ru1.label, ru1.host) == ("ru1", "relay", RU1_HOST)
        assert (await RelayRepository(db).usage("ru1")).keys == 13
    finally:
        await db.close()


async def test_v44_folds_an_agent_onto_its_relay(tmp_path: Path) -> None:
    db_path = tmp_path / "vpn.db"
    await _materialise(db_path, 43)
    status = '{"agent": "1.2", "check": {"rc": 0}}'
    async with aiosqlite.connect(db_path) as conn:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute(
            "INSERT INTO relays (id, name, label, host, source_ips, created_at, updated_at) "
            "VALUES (2, 'ru2', 'ru2', '203.0.113.50', '203.0.113.50/32', 't0', 't0')"
        )
        await conn.execute(
            "INSERT INTO relay_agents (relay_id, ssh_host, ssh_port, host_key, target_host, tcp_ports, udp_ports, "
            "agent_version, paired_at, last_status_json, last_status_at) "
            "VALUES (2, '203.0.113.50', 2222, ?, 'vpn.example.com', '443', '443,8443', '1.2', 'p0', ?, 's0')",
            (HOST_KEY, status),
        )
        await conn.execute(
            "INSERT INTO relay_pairings (id, name, token, target_host, tcp_ports, udp_ports, state, expires_at, created_at) "
            "VALUES (7, 'ru3', ?, 'vpn.example.com', '443', '443', 'pending', 1900000000, 't0')",
            ("t" * 43,),
        )
        await conn.commit()
    relays_before, keys_before = await _rows(db_path, "relays"), await _rows(db_path, "vpn_keys")

    await _bootstrap(db_path)

    relays_after = await _rows(db_path, "relays")
    assert await _rows(db_path, "vpn_keys") == keys_before
    for relay_id, before in relays_before.items():
        assert {k: relays_after[relay_id][k] for k in before} == before
    folded = relays_after[2]
    assert {c: folded[c] for c in AGENT_COLUMNS} == {
        "ssh_host": "203.0.113.50", "ssh_port": 2222, "host_key": HOST_KEY, "target_host": "vpn.example.com",
        "tcp_ports": "443", "udp_ports": "443,8443", "agent_version": "1.2", "agent_paired_at": "p0",
        "agent_status_json": status, "agent_status_at": "s0",
    }
    assert all(relays_after[1][c] is None for c in AGENT_COLUMNS)
    db = Database(db_path)
    await db.connect()
    try:
        repo = RelayRepository(db)
        ru2 = await repo.get_by_id(2)
        assert ru2 is not None and ru2.agent is not None
        assert (ru2.agent.ssh_port, ru2.agent.udp_ports, ru2.agent.last_status) == (2222, (443, 8443), {"agent": "1.2", "check": {"rc": 0}})
        pairing = await repo.get_pairing(7)
        assert pairing is not None and (pairing.kind, pairing.relay_host, pairing.state) == ("new", None, "pending")
    finally:
        await db.close()


def test_merge_source_ips_only_adds() -> None:
    current = (ipaddress.IPv4Network("198.51.100.7/32"), ipaddress.IPv4Network("203.0.113.0/28"))
    merged, added = merge_source_ips(current, ["203.0.113.5", EGRESS, RU1_IP])
    assert merged[:2] == current and added == (EGRESS,)
    assert merged[2] == ipaddress.IPv4Network(f"{EGRESS}/32")


# ── the production scenario, end to end ───────────────────────────────────────


async def test_production_scenario_attach_then_detach(prod: Env) -> None:
    """ru1 from the legacy seed with 13 keys → connect an agent → ONE relay, keys,
    links and subscriptions unchanged → disconnect → a hand-made relay again."""
    before = await prod.relay()
    keys_before, links_before = await prod.key_rows(), await prod.links()
    assert before.agent is None and any("relay.example.net" in link for link in links_before[0])
    [overview] = await prod.service.list_overview(ADMIN)
    assert overview.relay.id == before.id and overview.relay.agent is None

    # Pairing the same VPS as a NEW relay is not the way: its name is ru1's.
    with pytest.raises(InvalidOperation):
        await prod.service.issue_new(ADMIN, name="ru1", host=RU1_HOST, target_host=TARGET)

    issued = await prod.service.issue_attach(ADMIN, before.id, target_host=TARGET)
    assert (issued.pairing.kind, issued.pairing.relay_id, issued.pairing.name) == ("attach", before.id, "ru1")
    assert "install.sh --relay" in issued.command
    # Pressing it again shows the same code, it does not issue a second one.
    again = await prod.service.issue_attach(ADMIN, before.id, target_host=TARGET)
    assert again.pairing.id == issued.pairing.id

    outcome = await prod.service.complete(ADMIN, issued.pairing.id, f"{RU1_IP}:22")
    attached = outcome.relay
    assert outcome.attached and attached.agent is not None
    assert await prod.repo.count() == 1, "ONE relay — no second one with a new label"
    assert common(attached) == common(before)
    assert set(before.source_ips) <= set(attached.source_ips), "nothing removed"
    assert outcome.added_source_ips == (EGRESS,)
    assert (attached.agent.ssh_host, attached.agent.ssh_port, attached.agent.host_key) == (RU1_IP, 22, HOST_KEY)
    assert await prod.key_rows() == keys_before
    assert await prod.links() == links_before
    assert prod.catalog.snapshot.get("ru1") == attached
    assert "relay_agent_attached" in prod.audit.actions(AuditEntityType.RELAY)
    pairing = await prod.repo.get_pairing(issued.pairing.id)
    assert pairing is not None and pairing.state == "completed" and pairing.token == ""
    # The probes ran against the links' host, the hello against the SSH address.
    assert prod.client.calls[0]["host"] == RU1_IP and prod.client.calls[0]["alias"] == f"vpn-relay-pairing-{issued.pairing.id}"

    prod.client.replies["status"] = AgentReply(0, {"ok": True, "agent": "1", "check": {"rc": 0}})
    await prod.service.agent_status(ADMIN, attached.id)
    assert prod.client.calls[-1]["alias"] == f"vpn-relay-{attached.id}"

    calls = len(prod.client.calls)
    report = await prod.service.detach_agent(ADMIN, attached.id, uninstall=False)
    assert not report.uninstalled and len(prod.client.calls) == calls, "nothing was asked of the relay"
    detached = await prod.relay()
    assert detached.agent is None and common(detached) == common(before)
    assert detached.source_ips == attached.source_ips
    assert await prod.key_rows() == keys_before
    assert await prod.links() == links_before
    assert "relay_agent_detached" in prod.audit.actions(AuditEntityType.RELAY)
    # …and an agent can be connected again.
    assert (await prod.service.issue_attach(ADMIN, detached.id, target_host=TARGET)).pairing.kind == "attach"


async def test_attach_to_another_server_is_refused_and_changes_nothing(prod: Env) -> None:
    before = await prod.relay()
    issued = await prod.service.issue_attach(ADMIN, before.id, target_host=TARGET)
    with pytest.raises(InvalidOperation) as exc:
        await prod.service.complete(ADMIN, issued.pairing.id, OTHER_IP)
    assert exc.value.key == "relay_attach_other_server"
    assert t(exc.value.key, **exc.value.params).startswith(OTHER_IP)
    assert prod.client.calls == [], "the other server was not even contacted"
    assert await prod.relay() == before
    pairing = await prod.repo.get_pairing(issued.pairing.id)
    assert pairing is not None and pairing.state == "pending", "the operator can still send the right address"
    assert "relay_attach_refused" in prod.audit.actions(AuditEntityType.RELAY)


@pytest.mark.parametrize("address", [RU1_HOST, "203.0.113.5", "relay-ssh.example.net"])
async def test_attach_accepts_the_same_server_by_host_source_ip_or_resolution(prod: Env, address: str) -> None:
    # relay-ssh.example.net: another name for the address the links' host resolves to.
    prod.dns["relay-ssh.example.net"] = [RU1_IP]
    prod.dns[RU1_HOST] = [RU1_IP]
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    outcome = await prod.service.complete(ADMIN, issued.pairing.id, address)
    assert outcome.attached and outcome.relay.agent is not None and outcome.relay.agent.ssh_host == address


async def test_every_failure_of_an_attach_leaves_the_relay_as_it_was(prod: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    before = await prod.relay()
    issued = await prod.service.issue_attach(ADMIN, before.id, target_host=TARGET)
    pid = issued.pairing.id
    # 1. traffic through the relay does not reach this server
    prod.tcp[0] = False
    with pytest.raises(PairingCheckFailed):
        await prod.service.complete(ADMIN, pid, RU1_IP)
    prod.tcp[0] = True
    # 2. the relay refuses hello / answers for another code
    prod.client.replies["hello"] = AgentReply(3, {"ok": False, "error": "token does not match"})
    with pytest.raises(RelayAgentError):
        await prod.service.complete(ADMIN, pid, RU1_IP)
    prod.client.replies["hello"] = _hello(target_host="other.example.com")
    with pytest.raises(RelayAgentError):
        await prod.service.complete(ADMIN, pid, RU1_IP)
    prod.client.replies["hello"] = _hello()
    # 3. the database fails half-way through the write: one transaction, rolled back
    original = prod.repo.update

    async def broken_update(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("disk I/O error")

    monkeypatch.setattr(prod.repo, "update", broken_update)
    with pytest.raises(RuntimeError):
        await prod.service.complete(ADMIN, pid, RU1_IP)
    monkeypatch.setattr(prod.repo, "update", original)
    assert await prod.relay() == before
    pending = await prod.repo.get_pairing(pid)
    assert pending is not None and pending.state == "pending"
    # 4. the code is closed while the relay is being asked
    original_call = prod.client.call

    async def closing_call(*args: Any, **kwargs: Any) -> AgentReply:
        reply = await original_call(*args, **kwargs)
        await prod.repo.finish_pairing(pid, "cancelled", now="now")
        return reply

    prod.client.call = closing_call  # type: ignore[method-assign]
    with pytest.raises(NotFound):
        await prod.service.complete(ADMIN, pid, RU1_IP)
    assert await prod.relay() == before
    assert prod.catalog.snapshot.get("ru1") == before


async def test_attach_guards(prod: Env) -> None:
    with pytest.raises(AccessDenied):
        await prod.service.issue_attach(MODERATOR, 1, target_host=TARGET)
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    with pytest.raises(InvalidOperation) as exc:
        await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    assert exc.value.key == "relay_agent_already"
    with pytest.raises(NotFound):
        await prod.service.issue_attach(ADMIN, 99, target_host=TARGET)


async def test_deleting_a_relay_cancels_its_attach_code(env: Env) -> None:
    relay = await env.service.create(ADMIN, name="ru9", host="203.0.113.9", source_ips="203.0.113.9")
    issued = await env.service.issue_attach(ADMIN, relay.id, target_host=TARGET)
    report = await env.service.delete(ADMIN, relay.id, with_keys=False)
    assert report.deleted and not report.uninstalled
    pairing = await env.repo.get_pairing(issued.pairing.id)
    assert pairing is not None and pairing.state == "cancelled" and pairing.token == ""
    assert env.client.calls == [], "a relay without an agent: nothing is asked of it"


async def test_detach_with_uninstall_and_when_the_relay_does_not_answer(prod: Env) -> None:
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    prod.client.replies["uninstall"] = AgentReply(4, {"ok": False, "error": "connection refused"})
    with pytest.raises(RelayAgentError):
        await prod.service.detach_agent(ADMIN, 1, uninstall=True)
    assert (await prod.relay()).agent is not None, "a failed uninstall disconnects nothing"
    prod.client.replies["uninstall"] = AgentReply(0, {"ok": True})
    report = await prod.service.detach_agent(ADMIN, 1, uninstall=True)
    assert report.uninstalled and report.relay.agent is None
    assert await prod.repo.count() == 1 and (await prod.repo.usage("ru1")).keys == 13


async def test_a_long_agent_call_marks_the_relay_busy(prod: Env) -> None:
    import asyncio

    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    gate, entered = asyncio.Event(), asyncio.Event()
    original = prod.client.call

    async def slow(*args: Any, **kwargs: Any) -> AgentReply:
        if args[2] == "update":
            entered.set()
            await gate.wait()
            return AgentReply(0, {"ok": True, "update": {"state": "ok"}})
        return await original(*args, **kwargs)

    prod.client.call = slow  # type: ignore[method-assign]
    updating = asyncio.create_task(prod.service.update_agent(ADMIN, 1))
    await entered.wait()  # the update runs on the relay (claimed: busy) — no sleep
    with pytest.raises(InvalidOperation) as exc:
        await prod.service.detach_agent(ADMIN, 1, uninstall=False)
    assert exc.value.key == "relay_busy"
    # Everything else goes on meanwhile (the lock is not held by the slow call).
    await prod.service.update(ADMIN, 1, note="during the update")
    assert await prod.service.poll_agent(await prod.relay()) is None, "the health loop does not interfere"
    gate.set()
    await updating
    await prod.service.detach_agent(ADMIN, 1, uninstall=False)


# ── a new relay: the public host apart from the SSH address ───────────────────


async def test_new_relay_public_host_and_a_mismatch_warning(env: Env) -> None:
    env.dns["relay2.example.net"] = ["192.0.2.99"]  # the A record points elsewhere
    issued = await env.service.issue_new(ADMIN, name="ru2", host="relay2.example.net", target_host=TARGET)
    outcome = await env.service.complete(ADMIN, issued.pairing.id, "203.0.113.50:2222")
    relay = outcome.relay
    assert relay.host == "relay2.example.net" and relay.agent is not None and relay.agent.ssh_host == "203.0.113.50"
    assert outcome.host_mismatch == ("192.0.2.99",)
    # A paired relay starts OUT of subscriptions (its card's «Добавить в
    # подписки» switches it in and tops the issued ones up); BASIC shows it.
    assert not relay.in_subscriptions and relay.basic_visible
    assert env.service.snapshot.for_subscriptions == ()
    assert "192.0.2.99" in outcome_text(outcome)


async def test_new_relay_may_take_an_ipv4_host(env: Env) -> None:
    issued = await env.service.issue_new(ADMIN, name="ru2", host="203.0.113.50", target_host=TARGET)
    assert "203.0.113.50" in pairing_text(issued)
    outcome = await env.service.complete(ADMIN, issued.pairing.id, "203.0.113.50")
    assert outcome.relay.host == "203.0.113.50" and outcome.host_mismatch is None


def test_no_bot_handler_creates_a_relay_without_an_agent() -> None:
    """«Добавить relay» is the only way: no handler calls the service's create()."""
    root = Path(__file__).resolve().parents[1] / "bot"
    offenders = []
    for path in root.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "create":
                target = ast.unparse(node.func.value)
                if "relays" in target:
                    offenders.append(f"{path.name}: {target}.create")
    assert offenders == []


# ── one health verdict, one alert per change ──────────────────────────────────


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize(
    ("status", "ok"),
    [({"check": {"rc": 0}}, True), ({"check": {"rc": 13}}, True), ({"check": {"rc": 14}}, True),
     ({"check": {"rc": 11}}, False), ({}, True)],
)
def test_agent_check_codes(status: dict[str, Any], ok: bool) -> None:
    assert agent_check_from_status(status).ok is ok


async def test_one_alert_per_change_never_two(prod: Env) -> None:
    """Traffic AND the agent failing is ONE alert, not one per monitor; traffic
    back with the agent still silent is one 🟡; both fine is one 🟢."""
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    traffic = {"ok": False}
    sent: list[tuple[int, str]] = []

    class _Bot:
        async def send_message(self, chat_id: int, text: str) -> None:
            sent.append((chat_id, text))

    async def probe(host: str, port: int, sni: str) -> bool:
        return traffic["ok"]

    clock = _Clock()
    supervisor = RelayHealthSupervisor(
        load_relays=prod.repo.list_all, port=443, sni="example.com", admin_ids=frozenset({ADMIN, 2}), window=300,
        probe=probe, clock=clock, wall_clock=lambda: "2026-11-15T10:00:00+00:00", bot=_Bot(),  # type: ignore[arg-type]
        agent_probe=prod.service.poll_agent,
    )

    async def passes(n: int = 3) -> None:
        for _ in range(n):
            await supervisor.check_once()
            clock.now += 300

    prod.client.replies["status"] = AgentReply(255, {"ok": False, "error": "connection refused"})
    await passes()
    assert len(sent) == 2 and {chat for chat, _ in sent} == {ADMIN, 2}, "one message per admin"
    assert sent[0][1].startswith("🔴") and t("relay_reason_tcp_down", port=443) in sent[0][1]
    assert supervisor.level(1) == LEVEL_DOWN

    traffic["ok"] = True
    sent.clear()
    await passes()
    assert len(sent) == 2 and sent[0][1].startswith("🟡")
    assert supervisor.level(1) == LEVEL_WARN

    prod.client.replies["status"] = AgentReply(0, {"ok": True, "agent": "1", "check": {"rc": 0}})
    sent.clear()
    await passes()
    assert len(sent) == 2 and sent[0][1].startswith("🟢")
    assert supervisor.level(1) == LEVEL_OK
    probe_result = supervisor.last_probe(1)
    assert probe_result is not None and probe_result.agent == AgentCheck(ok=True, rc=0)
    assert supervisor.reason(probe_result) == t("relay_reason_ok_agent", udp="—")
    # The status the loop got is kept on the relay's row (shown on its page).
    relay = await prod.relay()
    assert relay.agent is not None and relay.agent.last_status == {"agent": "1", "check": {"rc": 0}}

    sent.clear()
    await passes(5)
    assert sent == [], "no repeats while nothing changes"


async def test_a_relay_without_an_agent_is_judged_by_traffic_alone(prod: Env) -> None:
    supervisor = RelayHealthSupervisor(
        load_relays=prod.repo.list_all, port=443, sni="example.com", admin_ids=frozenset(), window=300,
        probe=lambda *_: _true(), agent_probe=prod.service.poll_agent,
    )
    result = await supervisor.probe_now(await prod.relay())
    assert result.level == LEVEL_OK and result.agent is None
    assert prod.client.calls == []


async def _true() -> bool:
    return True


# ── the one screen ────────────────────────────────────────────────────────────


class FakeTotp:
    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled
        self.elevated = False

    async def is_enabled(self, user_id: int) -> bool:
        return self.enabled

    def is_elevated(self, user_id: int) -> bool:
        return self.elevated


class Msg:
    def __init__(self, text: str = "") -> None:
        import asyncio

        self.message_id = 10
        self.text = text
        self.chat = SimpleNamespace(id=ADMIN, type="private")
        self.from_user = SimpleNamespace(id=ADMIN)
        self.edits: list[str] = []
        self.answers: list[Msg] = []
        self.markups: list[Any] = []
        self.body = ""
        self.edited = asyncio.Event()  # set by every edit (the _patch fixture)

    async def until_edit(self, predicate: Any) -> str:
        """The first edit *predicate* accepts — waited for edit by edit, never by time."""
        while True:
            for text in self.edits:
                if predicate(text):
                    return text
            self.edited.clear()
            await self.edited.wait()

    async def answer(self, text: str, reply_markup: Any = None, **_: Any) -> Msg:
        reply = Msg()
        reply.body = text
        reply.markups.append(reply_markup)
        self.answers.append(reply)
        return reply

    @property
    def shown(self) -> str:
        """The latest text: an edit of this message or an answer under it."""
        if self.answers and (not self.edits or self.answers[-1].body):
            last = self.answers[-1]
            return last.edits[-1] if last.edits else last.body
        return self.edits[-1]


class Callback:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=ADMIN)
        self.message = Msg()
        self.alerts: list[tuple[str | None, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **_: Any) -> None:
        self.alerts.append((text, show_alert))


@pytest.fixture(autouse=True)
def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(*_: Any) -> bool:
        return True

    async def edit(message: Any, text: str, reply_markup: Any = None, **_: Any) -> bool:
        message.edits.append(text)
        message.markups.append(reply_markup)
        if hasattr(message, "edited"):
            message.edited.set()
        return True

    monkeypatch.setattr(ui, "ensure_private_callback", ok)
    monkeypatch.setattr(ui, "ensure_private_message", ok)
    monkeypatch.setattr(ui, "safe_edit_message_text", edit)


def fsm() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=ADMIN, user_id=ADMIN))


def _services(world: Env, totp: FakeTotp | None = None) -> Any:
    health = RelayHealthSupervisor(
        load_relays=world.repo.list_all, port=443, sni="example.com", admin_ids=frozenset(), window=300,
        probe=lambda *_: _true(), agent_probe=world.service.poll_agent,
    )
    return SimpleNamespace(users=_Users(), relays=world.service, relay_health=health, totp=totp or FakeTotp(),
                           settings=world.settings)


def _buttons(markup: Any) -> list[str]:
    return [b.callback_data for row in markup.inline_keyboard for b in row]


def test_the_wizard_opens_the_same_screen() -> None:
    buttons = _buttons(menu_keyboard(active=None, daily=False))
    assert "admin:relays" in buttons and not any(b.startswith("wrl:") for b in buttons)


async def test_add_a_relay_from_the_screen(env: Env) -> None:
    services = _services(env)
    state = fsm()
    start = Callback("admin:relay:add")
    await ui.relay_add_start(start, state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.add_name.state
    assert "admin:relay:add:nm" in _buttons(start.message.markups[-1])  # «relay1»
    await ui.relay_add_name(Msg("ru2"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.add_host.state
    await ui.relay_add_host(Msg("relay2.example.net"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.add_target.state
    target = Callback("admin:relay:add:tg")
    await ui.relay_add_default_target(target, state, services)  # type: ignore[arg-type]
    assert await state.get_state() is None
    text = target.message.edits[-1]
    assert "relay2.example.net" in text and "install.sh --relay" in text
    [pairing] = await env.repo.list_pending()
    assert (pairing.kind, pairing.name, pairing.relay_host) == ("new", "ru2", "relay2.example.net")

    state = fsm()
    await ui.relay_connect(Callback(f"admin:rpair:{pairing.id}:go"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.pair_address.state
    env.dns["relay2.example.net"] = ["203.0.113.50"]
    msg = Msg("203.0.113.50:2222")
    await ui.relay_connect_address(msg, state, services)  # type: ignore[arg-type]
    assert "ru2" in msg.shown and t("relay_paired_health_on", interval=300) in msg.shown
    [relay] = await env.repo.list_all()
    assert relay.host == "relay2.example.net" and relay.agent is not None and relay.agent.ssh_port == 2222


async def test_an_ipv4_host_is_warned_about_not_refused(env: Env) -> None:
    services = _services(env)
    state = fsm()
    await ui.relay_add_start(Callback("admin:relay:add"), state, services)  # type: ignore[arg-type]
    await ui.relay_add_name(Msg("ru2"), state, services)  # type: ignore[arg-type]
    msg = Msg("203.0.113.50")
    await ui.relay_add_host(msg, state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.add_host_ipv4.state
    assert "admin:relay:add:ipok" in _buttons(msg.answers[-1].markups[-1])
    assert "IPv4" in msg.answers[-1].body
    await ui.relay_add_keep_ipv4(Callback("admin:relay:add:ipok"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.add_target.state


async def test_attach_from_the_page_and_the_list_shows_one_relay(prod: Env) -> None:
    services = _services(prod)
    listing = Callback("admin:relays")
    await ui.relays_panel(listing, fsm(), services)  # type: ignore[arg-type]
    assert t("relay_managed_none") in listing.message.edits[-1]
    card = Callback("admin:relay:1")
    await ui.relay_card(card, fsm(), services)  # type: ignore[arg-type]
    assert "admin:relay:1:ag:attach" in _buttons(card.message.markups[-1])
    assert t("btn_relay_attach") in [b.text for row in card.message.markups[-1].inline_keyboard for b in row]

    attach = Callback("admin:relay:1:ag:attach")
    await ui.relay_attach(attach, fsm(), services)  # type: ignore[arg-type]
    text = attach.message.edits[-1]
    assert "ru1" in text and "install.sh --relay" in text
    [pairing] = await prod.repo.list_pending()
    assert pairing.kind == "attach" and pairing.relay_id == 1

    # The page now offers the code instead of a second one.
    card = Callback("admin:relay:1")
    await ui.relay_card(card, fsm(), services)  # type: ignore[arg-type]
    assert f"admin:rpair:{pairing.id}" in _buttons(card.message.markups[-1])

    state = fsm()
    await ui.relay_connect(Callback(f"admin:rpair:{pairing.id}:go"), state, services)  # type: ignore[arg-type]
    msg = Msg(RU1_IP)
    await ui.relay_connect_address(msg, state, services)  # type: ignore[arg-type]
    assert t("relay_attached_sources_added", sources=EGRESS) in msg.shown
    listing = Callback("admin:relays")
    await ui.relays_panel(listing, fsm(), services)  # type: ignore[arg-type]
    assert _buttons(listing.message.markups[-1]) == [
        "admin:relay:1", "admin:relays:mainbasic", "admin:relay:add", "admin:grp:infra"
    ]
    assert t("relay_managed_agent", version="1") in listing.message.edits[-1]

    card = Callback("admin:relay:1")
    await ui.relay_card(card, fsm(), services)  # type: ignore[arg-type]
    buttons = _buttons(card.message.markups[-1])
    assert {"admin:relay:1:ag:up", "admin:relay:1:ag:fw", "admin:relay:1:ag:detach"} <= set(buttons)
    assert "admin:relay:1:ag:attach" not in buttons
    assert all(len(b.encode()) <= 64 for b in buttons)


async def test_attach_from_another_server_via_the_screen(prod: Env) -> None:
    services = _services(prod)
    await ui.relay_attach(Callback("admin:relay:1:ag:attach"), fsm(), services)  # type: ignore[arg-type]
    [pairing] = await prod.repo.list_pending()
    state = fsm()
    await ui.relay_connect(Callback(f"admin:rpair:{pairing.id}:go"), state, services)  # type: ignore[arg-type]
    msg = Msg(OTHER_IP)
    await ui.relay_connect_address(msg, state, services)  # type: ignore[arg-type]
    assert OTHER_IP in msg.shown and f"admin:rpair:{pairing.id}:go" in _buttons(msg.answers[-1].markups[-1])
    assert (await prod.relay()).agent is None


async def _attached(prod: Env) -> None:
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)


async def test_detach_from_the_screen(prod: Env) -> None:
    await _attached(prod)
    services = _services(prod)
    prompt = Callback("admin:relay:1:ag:detach")
    await ui.relay_detach_prompt(prompt, services)  # type: ignore[arg-type]
    assert _buttons(prompt.message.markups[-1]) == [
        "admin:relay:1:ag:detach:keep", "admin:relay:1:ag:detach:uninst", "admin:relay:1",
    ]
    keep = Callback("admin:relay:1:ag:detach:keep")
    await ui.relay_detach_execute(keep, fsm(), services)  # type: ignore[arg-type]
    assert t("relay_detached", label="relay") in keep.message.edits[-1]
    assert (await prod.relay()).agent is None


async def test_deleting_a_relay_with_an_agent_uninstalls_first(prod: Env) -> None:
    await _attached(prod)
    services = _services(prod)
    prompt = Callback("admin:relay:1:del")
    await ui.relay_delete_prompt(prompt, services)  # type: ignore[arg-type]
    assert t("relay_delete_uninstall_first") in prompt.message.edits[-1]
    assert _buttons(prompt.message.markups[-1])[0] == "admin:relay:1:del:keys"  # 13 keys

    prod.client.replies["uninstall"] = AgentReply(4, {"ok": False, "error": "connection refused"})
    delete = Callback("admin:relay:1:del:keys")
    await ui.relay_delete_execute(delete, fsm(), services)  # type: ignore[arg-type]
    assert "admin:relay:1:del:rec:1" in _buttons(delete.message.markups[-1])
    assert await prod.repo.count() == 1, "nothing deleted while the relay did not uninstall"
    assert [c["request"] for c in prod.client.calls][-1] == "uninstall"


async def test_typed_steps_recheck_the_elevation(prod: Env) -> None:
    await _attached(prod)
    totp = FakeTotp(enabled=True)
    totp.elevated = True
    services = _services(prod, totp)
    state = fsm()
    await ui.relay_agent_forward(Callback("admin:relay:1:ag:fw"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.forward.state
    totp.elevated = False  # five minutes later
    calls = len(prod.client.calls)
    msg = Msg("new.example.com tcp=443 udp=443")
    await ui.relay_agent_forward_input(msg, state, services)  # type: ignore[arg-type]
    assert msg.answers[-1].body == t("relay_reauth")
    assert len(prod.client.calls) == calls, "nothing reached the relay"

    totp.elevated = True
    state = fsm()
    await ui.relay_edit_start(Callback("admin:relay:1:edit:host"), state, services)  # type: ignore[arg-type]
    totp.elevated = False
    before = await prod.relay()
    await ui.relay_edit_host(Msg("relay9.example.net"), state, services)  # type: ignore[arg-type]
    assert await prod.relay() == before


@pytest.mark.parametrize(
    "data",
    [
        "admin:relay:add",
        "admin:relay:1:subs:add:run",
        "admin:relay:1:subs:rm:run",
        "admin:relay:1:basic",
        "admin:relays:mainbasic",
        "admin:relay:1:toggle:enabled:ok",
        "admin:relay:1:edit:host",
        "admin:relay:1:edit:label",
        "admin:relay:1:del:yes",
        "admin:relay:1:del:keys",
        "admin:relay:1:del:disable",
        "admin:relay:1:del:rec:1",
        "admin:relay:1:ag:attach",
    ],
)
async def test_every_change_of_a_hand_made_relay_asks_the_totp_code(prod: Env, data: str) -> None:
    services = _services(prod, FakeTotp(enabled=True))
    before, keys = await prod.relay(), await prod.key_rows()
    state = fsm()
    cb = Callback(data)
    handler, takes_state = _handler_for(data)
    await (handler(cb, state, services) if takes_state else handler(cb, services))
    assert await state.get_state() == TotpStates.gate_code.state, data
    assert await prod.relay() == before and await prod.key_rows() == keys
    assert await prod.repo.list_pending() == []


@pytest.mark.parametrize(
    "data",
    ["admin:relay:1:ag:up", "admin:relay:1:ag:fw", "admin:relay:1:ag:detach:keep", "admin:relay:1:ag:detach:uninst"],
)
async def test_every_agent_action_asks_the_totp_code(prod: Env, data: str) -> None:
    await _attached(prod)
    services = _services(prod, FakeTotp(enabled=True))
    before, calls = await prod.relay(), len(prod.client.calls)
    state = fsm()
    handler, _ = _handler_for(data)
    await handler(Callback(data), state, services)
    assert await state.get_state() == TotpStates.gate_code.state, data
    assert await prod.relay() == before and len(prod.client.calls) == calls


async def test_connecting_a_code_asks_the_totp_code(prod: Env) -> None:
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    state = fsm()
    await ui.relay_connect(Callback(f"admin:rpair:{issued.pairing.id}:go"), state, _services(prod, FakeTotp(enabled=True)))  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.gate_code.state


def _handler_for(data: str) -> tuple[Any, bool]:
    if data == "admin:relay:add":
        return ui.relay_add_start, True
    if data == "admin:relays:mainbasic":
        return ui.relays_main_basic_toggle, True
    action = data.split(":")[3]
    sub = data.split(":")[4] if len(data.split(":")) > 4 else ""
    return {
        "toggle": (ui.relay_toggle, True),
        "subs": (ui.relay_subs_run, True),
        "basic": (ui.relay_basic_toggle, True),
        "edit": (ui.relay_edit_start, True),
        "del": (ui.relay_delete_execute, True),
        "ag": {
            "attach": (ui.relay_attach, True),
            "up": (ui.relay_agent_update, True),
            "fw": (ui.relay_agent_forward, True),
            "detach": (ui.relay_detach_execute, True),
        }.get(sub, (None, True)),
    }[action]


# ── buttons of both former sections still in the chat history ─────────────────


@pytest.mark.parametrize(
    ("data", "expect"),
    [
        ("wrl:menu", "list"),
        ("wrl:add", "list"),
        ("wrl:nm", "list"),
        ("wrl:tg", "list"),
        ("wrl:r:1", "card"),
        ("wrl:st:1", "card"),
        ("wrl:up:1", "card"),
        ("wrl:fw:1", "card"),
        ("wrl:del:1", "card"),
        ("wrl:dk:1:1", "card"),
        ("wrl:dr:1:0", "card"),
        ("wrl:r:999", "gone"),
    ],
)
async def test_old_wizard_buttons_lead_to_the_new_screen(prod: Env, data: str, expect: str) -> None:
    services = _services(prod)
    before, calls = await prod.relay(), len(prod.client.calls)
    cb = Callback(data)
    await ui.legacy_wizard_relay(cb, fsm(), services)  # type: ignore[arg-type]
    text = cb.message.edits[-1]
    if expect == "card":
        assert t("relay_card_title", label="relay") in text
    else:
        assert t("relays_title") in text
    assert not [alert for alert, _ in cb.alerts if alert == t("internal_error")]
    assert await prod.relay() == before and len(prod.client.calls) == calls, "an old button changes nothing"


async def test_old_wizard_pairing_buttons(prod: Env) -> None:
    services = _services(prod)
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    pid = issued.pairing.id
    view = Callback(f"wrl:p:{pid}")
    await ui.legacy_wizard_relay(view, fsm(), services)  # type: ignore[arg-type]
    assert "install.sh --relay" in view.message.edits[-1]
    state = fsm()
    await ui.legacy_wizard_relay(Callback(f"wrl:pc:{pid}"), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminRelayStates.pair_address.state
    cancel = Callback(f"wrl:px:{pid}")
    await ui.legacy_wizard_relay(cancel, fsm(), services)  # type: ignore[arg-type]
    pairing = await prod.repo.get_pairing(pid)
    assert pairing is not None and pairing.state == "cancelled"
    gone = Callback(f"wrl:p:{pid}")
    await ui.legacy_wizard_relay(gone, fsm(), services)  # type: ignore[arg-type]
    assert (t("relay_pair_not_pending"), True) in gone.alerts


@pytest.mark.parametrize(
    "data",
    ["wrl:menu", "wrl:add", "wrl:nm", "wrl:tg", "wrl:r:1", "wrl:st:1", "wrl:up:1", "wrl:fw:1", "wrl:del:1",
     "wrl:dk:1:1", "wrl:dr:1:0", "wrl:p:1", "wrl:pc:1", "wrl:px:1"],
)
def test_every_old_wizard_button_is_routed_to_the_relay_screen(data: str) -> None:
    from test_admin_panel_structure import _resolve

    assert _resolve(data, None) == "admin_relays.legacy_wizard_relay"


@pytest.mark.parametrize("data", ["admin:relay:add:srcashost", "admin:relay:add:labeldefault", "admin:relay:add:confirm"])
def test_old_panel_add_buttons_resolve_to_the_list(data: str) -> None:
    from test_admin_panel_structure import _resolve

    assert _resolve(data, None) == "admin_relays.stale_relay_callback"


@pytest.mark.parametrize(
    ("text", "expected"),
    [("a.example.com", ("a.example.com", "", "")), ("a.example.com tcp=443,8443", ("a.example.com", "443,8443", "")),
     ("a.example.com udp=443 tcp=443", ("a.example.com", "443", "443"))],
)
def test_parse_forward_input(text: str, expected: tuple[str, str, str]) -> None:
    assert ui.parse_forward_input(text) == expected


@pytest.mark.parametrize("text", ["", "a b c d", "a.example.com sctp=1", "a.example.com tcp=1 tcp=2"])
def test_parse_forward_input_refuses(text: str) -> None:
    with pytest.raises(ServiceError):
        ui.parse_forward_input(text)


async def test_a_late_status_answer_never_erases_the_uninstall_mark(prod: Env) -> None:
    """A health `status` that started before an `uninstall` and answers after it has
    finished: the answer is dropped, the mark stays, and the interrupted delete
    resumes without a second uninstall (which would fail: the bot's key is gone)."""
    import asyncio

    await _attached(prod)
    gate, entered = asyncio.Event(), asyncio.Event()
    original = prod.client.call

    async def racing(*args: Any, **kwargs: Any) -> AgentReply:
        if args[2] == "status":
            entered.set()
            await gate.wait()  # still running on the relay while uninstall goes through
            return AgentReply(0, {"ok": True, "agent": "1", "check": {"rc": 0}})
        return await original(*args, **kwargs)

    prod.client.call = racing  # type: ignore[method-assign]
    prod.client.replies["uninstall"] = AgentReply(0, {"ok": True})
    polling = asyncio.create_task(prod.service.poll_agent(await prod.relay()))
    await entered.wait()  # the status call is on the relay — no sleep

    # No key deleters are wired in this world, so with_keys=True stops at the first
    # key right after the uninstall: an interrupted delete.
    first = await prod.service.delete(ADMIN, 1, with_keys=True)
    assert first.uninstalled and not first.deleted
    gate.set()
    check = await polling
    assert check is not None and check.ok  # the health loop still gets its verdict…
    relay = await prod.relay()
    assert relay.agent is not None and relay.agent.last_status is not None
    assert "uninstalled_at" in relay.agent.last_status, "…but the late answer is not kept"
    uninstalls = sum(1 for c in prod.client.calls if c["request"] == "uninstall")
    second = await prod.service.delete(ADMIN, 1, with_keys=True)
    assert second.uninstalled
    assert sum(1 for c in prod.client.calls if c["request"] == "uninstall") == uninstalls, "no second uninstall"


async def test_the_repository_refuses_to_erase_the_uninstall_mark(env: Env) -> None:
    issued = await env.service.issue_new(ADMIN, name="ru2", host="203.0.113.50", target_host=TARGET)
    relay = (await env.service.complete(ADMIN, issued.pairing.id, "203.0.113.50")).relay
    assert await env.repo.record_agent_status(relay.id, {"agent": "1", "uninstalled_at": "t1"}, now="t1", agent_version="1")
    assert not await env.repo.record_agent_status(relay.id, {"agent": "1", "check": {"rc": 0}}, now="t2", agent_version="1")
    stored = await env.relay(relay.id)
    assert stored.agent is not None and stored.agent.last_status == {"agent": "1", "uninstalled_at": "t1"}


# ── «Обновить агент»: a failed deploy shows its cause, not «relay отказал» (A4) ──


async def test_a_failed_update_shows_the_cause_step_lines_and_log(prod: Env) -> None:
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    prod.client.replies["update"] = AgentReply(4, {
        "ok": False, "error": "the deploy of v9.1.0 stopped before any change (exit 1): …",
        "update": {"state": "failed", "reason": "no_venv", "step": "tests",
                   "excerpt": ["The virtual environment was not created successfully because ensurepip is not",
                               "    apt install python3.12-venv"],
                   "log": "/root/deploy-20261118T120000Z.log"},
    })
    cb = Callback("admin:relay:1:ag:up:ok")
    await ui.relay_agent_update_run(cb, fsm(), _services(prod))  # type: ignore[arg-type]
    text = cb.message.edits[-1]
    assert t("relay_agent_update_failed_cause") in text
    assert "❌ " + t("deploy_step_tests") in text, "the failing step is marked"
    assert t("deploy_reason_no_venv") in text and t("deploy_step_tests") in text
    assert "apt install python3.12-venv" in text and "/root/deploy-20261118T120000Z.log" in text
    assert t("relay_agent_refused", error="").split(":")[0] not in text


async def test_a_successful_update_shows_the_deploys_warning(prod: Env) -> None:
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    prod.client.replies["update"] = AgentReply(0, {"ok": True, "update": {
        "state": "succeeded", "message": "updated to v9.1.0",
        "warnings": [{"code": "upstream_preexisting", "text": "TCP connect 203.0.113.5:443"}],
    }})
    cb = Callback("admin:relay:1:ag:up:ok")
    await ui.relay_agent_update_run(cb, fsm(), _services(prod))  # type: ignore[arg-type]
    text = cb.message.edits[-1]
    assert "updated to v9.1.0" in text and t("deploy_warn_upstream_preexisting") in text
    assert "✅ " + t("deploy_step_verify") in text


class _UpdateOnRelay:
    """The relay's side of a long ``update``: it starts, waits for the test, answers.
    ``update-status`` answers the progress below, or waits on ``poll_gate`` when set."""

    def __init__(self, world: Env, *, final: AgentReply | None = None) -> None:
        import asyncio

        self.started, self.finish = asyncio.Event(), asyncio.Event()
        self.poll_entered = asyncio.Event()
        self.poll_gate: asyncio.Event | None = None
        self.final = final or AgentReply(0, {"ok": True, "update": {"state": "succeeded", "message": "updated to v9.1.0"}})
        self.original = world.client.call
        world.client.call = self.call  # type: ignore[method-assign]

    async def call(self, *args: Any, **kwargs: Any) -> AgentReply:
        if args[2] == "update":
            self.started.set()
            await self.finish.wait()
            return self.final
        if args[2] == "update-status" and self.poll_gate is not None:
            self.poll_entered.set()
            await self.poll_gate.wait()
        return await self.original(*args, **kwargs)


PROGRESS = {"step": "tests", "steps": {"preflight": "ok", "fetch": "ok", "tests": "run"},
            "tests": {"done": 2802, "total": 5604}}


async def _agent_v(prod: Env, version: str, describe: str = "") -> None:
    """Pair ru1 with an agent that says AGENT_VERSION=*version* in its status."""
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    status: dict[str, Any] = {"ok": True, "agent": version, "check": {"rc": 0}}
    if describe:
        status["checkout"] = {"commit": SHA, "describe": describe}
    prod.client.replies["status"] = AgentReply(0, status)
    await prod.service.agent_status(ADMIN, 1)


async def test_update_shows_the_plan_first_then_runs_with_progress(prod: Env, fake_timer: Any) -> None:
    """D: the plan (every step ⚪, «Подтвердить»), then the run; `update-status` next to
    the long call moves the steps and counts the tests. Explicit steps on the fake clock
    (tests/fake_timer.py): the relay's update waits for the test, time moves only when
    the test moves it — the outcome cannot depend on how loaded the host is."""
    import asyncio

    await _agent_v(prod, "3")
    plan = Callback("admin:relay:1:ag:up")
    await ui.relay_agent_update(plan, fsm(), _services(prod))  # type: ignore[arg-type]
    assert plan.message.edits[-1].count("⚪") == 8
    assert "admin:relay:1:ag:up:ok" in _buttons(plan.message.markups[-1])
    assert not [c for c in prod.client.calls if c["request"] == "update"], "nothing ran before the confirmation"

    prod.client.replies["update-status"] = AgentReply(0, {"ok": True, "update": {"state": "running", "progress": PROGRESS}})
    relay = _UpdateOnRelay(prod)
    run = Callback("admin:relay:1:ag:up:ok")
    task = asyncio.create_task(ui.relay_agent_update_run(run, fsm(), _services(prod)))  # type: ignore[arg-type]
    await relay.started.wait()
    await fake_timer.parked(2)  # the animation and the poller wait on the clock
    assert run.message.edits[-1].startswith(t("relay_update_title", name="ru1") + "\n\n🔄 " + t("deploy_step_preflight"))
    assert not [c for c in prod.client.calls if c["request"] == "update-status"], "no poll before its interval"

    # The animation ticks every PROGRESS_EDIT_INTERVAL_SECONDS; the first poll comes at
    # UPDATE_POLL_SECONDS (10 s): move to just before it, then onto it.
    interval = PROGRESS_EDIT_INTERVAL_SECONDS
    await fake_timer.advance(ui.UPDATE_POLL_SECONDS - 1)
    assert not [c for c in prod.client.calls if c["request"] == "update-status"]
    assert await fake_timer.advance(1) == 1, "only the poller wakes at 10 s"
    assert [c["request"] for c in prod.client.calls].count("update-status") == 1
    before = len(run.message.edits)
    await fake_timer.advance(interval)  # the next animation tick shows the polled progress
    assert len(run.message.edits) == before + 1
    frame = run.message.edits[-1]
    assert "✅ " + t("deploy_step_fetch") in frame and "🔄 " + t("deploy_step_tests") + " — 2802/5604" in frame
    assert frame.rstrip().endswith("50%"), "a measurable step: its percentage"

    relay.finish.set()
    await task
    final = run.message.edits[-1]
    assert "updated to v9.1.0" in final and final.count("✅") >= 8 and "🔄" not in final
    assert fake_timer.waiting == 0, "the animation and the poller are gone"


async def test_a_poll_answered_after_the_update_never_reopens_the_steps(prod: Env, fake_timer: Any) -> None:
    """THE flake of deploy.sh's Phase 1 on he2 (1 vCPU): an ``update-status`` still in
    flight when the update finished answered afterwards, and «🔄 тесты — 2802/5604» was
    drawn over the result's ✅. Forced here deterministically: the poll is held on the
    relay until the result is on the screen, then answers «running»."""
    import asyncio

    await _agent_v(prod, "3")
    prod.client.replies["update-status"] = AgentReply(0, {"ok": True, "update": {"state": "running", "progress": PROGRESS}})
    relay = _UpdateOnRelay(prod)
    relay.poll_gate = asyncio.Event()
    run = Callback("admin:relay:1:ag:up:ok")
    task = asyncio.create_task(ui.relay_agent_update_run(run, fsm(), _services(prod)))  # type: ignore[arg-type]
    await relay.started.wait()
    await fake_timer.parked(2)
    await fake_timer.advance(ui.UPDATE_POLL_SECONDS, settle=False)  # the poll starts…
    await relay.poll_entered.wait()  # …and hangs on the relay
    relay.finish.set()  # the update ends first
    await run.message.until_edit(lambda text: "updated to v9.1.0" in text)  # the result is drawn
    relay.poll_gate.set()  # now the late «running» answer arrives
    await task
    final = [text for text in run.message.edits if "updated to v9.1.0" in text]
    assert len(final) == 1 and final[0] == run.message.edits[-1], "nothing was drawn after the result"
    assert "🔄" not in final[0] and final[0].count("✅") >= 8


async def test_an_agent_without_update_status_shows_one_line_not_a_frozen_list(prod: Env, fake_timer: Any) -> None:
    """he2 on agent v3.2.0 (AGENT_VERSION 2): no `update-status`, so no list of ⚪ steps
    that cannot move — one line «агент v3.2.0 — прогресс по шагам появится после этого
    обновления» with the activity line; no poll is sent to it at all."""
    import asyncio

    await _agent_v(prod, "2", describe="v3.2.0")
    line = t("relay_update_legacy", version="v3.2.0")
    plan = Callback("admin:relay:1:ag:up")
    await ui.relay_agent_update(plan, fsm(), _services(prod))  # type: ignore[arg-type]
    assert line in plan.message.edits[-1] and "⚪ " + t("deploy_step_tests") not in plan.message.edits[-1]

    relay = _UpdateOnRelay(prod)
    run = Callback("admin:relay:1:ag:up:ok")
    task = asyncio.create_task(ui.relay_agent_update_run(run, fsm(), _services(prod)))  # type: ignore[arg-type]
    await relay.started.wait()
    await fake_timer.parked(1)  # the animation only: no poller for this agent
    await fake_timer.advance(PROGRESS_EDIT_INTERVAL_SECONDS)
    frame = run.message.edits[-1]
    assert "🔄 " + line in frame and frame.rstrip().endswith("**")
    for step in ("preflight", "fetch", "tests", "checks"):
        assert t(f"deploy_step_{step}") not in frame, "no frozen list of steps"
    await fake_timer.advance(ui.UPDATE_POLL_SECONDS)
    assert not [c for c in prod.client.calls if c["request"] == "update-status"]
    relay.finish.set()
    await task
    assert "updated to v9.1.0" in run.message.edits[-1]


async def test_an_unknown_agent_that_refuses_update_status_turns_into_the_one_line(prod: Env, fake_timer: Any) -> None:
    """The version is not known (no status kept): the first poll's «not an agent
    command» turns the list into the one line, and polling stops."""
    import asyncio

    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    await prod.repo.record_agent_status(1, {}, now="t", agent_version="")
    prod.client.replies["update-status"] = AgentReply(2, {"ok": False, "error": "refused: not an agent command"})
    relay = _UpdateOnRelay(prod)
    run = Callback("admin:relay:1:ag:up:ok")
    task = asyncio.create_task(ui.relay_agent_update_run(run, fsm(), _services(prod)))  # type: ignore[arg-type]
    await relay.started.wait()
    await fake_timer.parked(2)
    assert "🔄 " + t("deploy_step_preflight") in run.message.edits[-1]
    await fake_timer.advance(ui.UPDATE_POLL_SECONDS - 1)  # the animation's tick only
    assert await fake_timer.advance(1, settle=False) == 1  # the poll: refused, the poller ends
    line = t("relay_update_legacy", version="?")
    frame = await run.message.until_edit(lambda text: line in text)
    assert t("deploy_step_preflight") not in frame, "the list is gone, the one line is shown at once"
    await fake_timer.advance(ui.UPDATE_POLL_SECONDS * 3)
    assert [c["request"] for c in prod.client.calls].count("update-status") == 1, "asked once"
    relay.finish.set()
    await task


async def test_an_old_agents_pytest_failure_is_marked_on_the_tests(prod: Env) -> None:
    """he2: the old agent answers only its message — «Phase 1 gate: pytest failed on tag
    v3.2.1» — and the bot put ❌ on «проверки перед деплоем» (fail_running). The step now
    comes from the text: ❌ on «тесты», the ones before ✅, the rest ⚪."""
    await _agent_v(prod, "2", describe="v3.2.0")
    prod.client.replies["update"] = AgentReply(4, {
        "ok": False,
        "error": "the deploy of v3.2.1 stopped before any change (exit 1): Phase 1 gate: pytest failed on tag "
                 "v3.2.1 (above) — nothing was changed",
    })
    cb = Callback("admin:relay:1:ag:up:ok")
    await ui.relay_agent_update_run(cb, fsm(), _services(prod))  # type: ignore[arg-type]
    text = cb.message.edits[-1]
    assert "❌ " + t("deploy_step_tests") in text
    assert "✅ " + t("deploy_step_preflight") in text and "✅ " + t("deploy_step_fetch") in text
    assert "⚪ " + t("deploy_step_checks") in text and "❌ " + t("deploy_step_preflight") not in text
    assert t("deploy_reason_tests") in text and t("deploy_fail_step", step=t("deploy_step_tests")) in text


async def test_a_result_marker_in_the_text_names_the_step(prod: Env) -> None:
    await _agent_v(prod, "2")
    prod.client.replies["update"] = AgentReply(4, {
        "ok": False, "error": "deploy failed\n[deploy:result failed step=checks reason=checks]",
    })
    cb = Callback("admin:relay:1:ag:up:ok")
    await ui.relay_agent_update_run(cb, fsm(), _services(prod))  # type: ignore[arg-type]
    assert "❌ " + t("deploy_step_checks") in cb.message.edits[-1]


async def test_a_failure_nobody_can_place_marks_no_step(prod: Env) -> None:
    """Neither a marker nor a text that tells the step, and no progress was reported:
    no ❌ on the first step, no list — «шаг неизвестен»."""
    await _agent_v(prod, "2")
    prod.client.replies["update"] = AgentReply(4, {"ok": False, "error": "something odd happened"})
    cb = Callback("admin:relay:1:ag:up:ok")
    await ui.relay_agent_update_run(cb, fsm(), _services(prod))  # type: ignore[arg-type]
    text = cb.message.edits[-1]
    assert "❌ " + t("deploy_step_preflight") not in text and t("deploy_step_preflight") not in text
    assert t("deploy_fail_step_unknown") in text


# ── «🔑 SSH-порт relay» and the buttons of a relay's migration (B) ─────────────

PHASE1 = {"ssh_port": "54321", "current": "22,54321", "state": "phase1", "action": "wait", "from": "22",
          "to": "54321", "since": "1763460000", "hold": "0", "proof": "none", "status": "migrating 22 -> 54321"}


@pytest.fixture
def sshp(monkeypatch: pytest.MonkeyPatch) -> Any:
    from bot.handlers import ssh_port as handlers

    async def ok(*_: Any) -> bool:
        return True

    async def edit(message: Any, text: str, reply_markup: Any = None, **_: Any) -> bool:
        message.edits.append(text)
        message.markups.append(reply_markup)
        return True

    monkeypatch.setattr(handlers, "ensure_private_callback", ok)
    monkeypatch.setattr(handlers, "ensure_private_message", ok)
    monkeypatch.setattr(handlers, "safe_edit_message_text", edit)
    return handlers


async def _relay_in_phase1(prod: Env) -> None:
    issued = await prod.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await prod.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    prod.client.replies["status"] = AgentReply(0, {"ok": True, "agent": "3", "check": {"rc": 0},
                                                   "ssh_migration": PHASE1})
    await prod.service.agent_status(ADMIN, 1)


def test_the_wizard_menu_has_the_relay_ssh_port() -> None:
    assert "admin:sshp" in _buttons(menu_keyboard(active=None, daily=False))


async def test_the_screen_lists_the_relay_and_offers_close_and_keep(prod: Env, sshp: Any) -> None:
    await _relay_in_phase1(prod)
    services = _services(prod)
    cb = Callback("admin:sshp")
    await sshp.relay_ssh_port_list(cb, fsm(), services)
    relay = await prod.relay()
    assert t("relay_ssh_port_line_phase1", name=relay.name, old="22", new=54321) in cb.message.edits[-1]
    card = Callback("admin:sshp:1")
    await sshp.relay_ssh_port_card(card, fsm(), services)
    buttons = _buttons(card.message.markups[-1])
    assert buttons[:2] == ["sshport:r:ok:1:54321:1763460000", "sshport:r:keep:1:1763460000"]
    assert "admin:sshp:1:set" in buttons


async def test_confirm_is_totp_gated_then_closes_over_the_new_port(prod: Env, sshp: Any) -> None:
    await _relay_in_phase1(prod)
    prod.client.replies["ssh-port-finish"] = AgentReply(0, {"ok": True})
    totp = FakeTotp(enabled=True)
    state = fsm()
    await sshp.relay_ssh_port_button(Callback("sshport:r:ok:1:54321:1763460000"), state, _services(prod, totp))
    assert await state.get_state() == TotpStates.gate_code.state
    assert not [c for c in prod.client.calls if c["request"].startswith("ssh-port")]
    totp.elevated = True
    cb = Callback("sshport:r:ok:1:54321:1763460000")
    await sshp.relay_ssh_port_button(cb, fsm(), _services(prod, totp))
    finish = [c for c in prod.client.calls if c["request"].startswith("ssh-port-finish")]
    assert [(c["port"], c["request"]) for c in finish] == [(54321, "ssh-port-finish port=54321 since=1763460000")]
    assert t("relay_ssh_port_finished", port=54321) in cb.message.edits[-1]
    assert (await prod.relay()).agent.ssh_port == 54321  # type: ignore[union-attr]


async def test_a_new_port_that_does_not_answer_closes_nothing(prod: Env, sshp: Any) -> None:
    await _relay_in_phase1(prod)
    prod.client.replies["ssh-port-finish"] = AgentReply(255, {})
    cb = Callback("sshport:r:ok:1:54321:1763460000")
    await sshp.relay_ssh_port_button(cb, fsm(), _services(prod))
    assert t("relay_ssh_port_failed", error="").split(":")[0] in cb.message.edits[-1]
    assert (await prod.relay()).agent.ssh_port != 54321  # type: ignore[union-attr]


async def test_keep_holds_it_on_the_relay(prod: Env, sshp: Any) -> None:
    await _relay_in_phase1(prod)
    prod.client.replies["ssh-port-keep"] = AgentReply(0, {"ok": True})
    cb = Callback("sshport:r:keep:1:1763460000")
    await sshp.relay_ssh_port_button(cb, fsm(), _services(prod))
    assert [c["request"] for c in prod.client.calls if c["request"].startswith("ssh-port")] == [
        "ssh-port-keep since=1763460000"
    ]
    assert t("relay_ssh_port_kept") in cb.message.edits[-1]


async def test_change_the_port_asks_it_and_runs_set(prod: Env, sshp: Any) -> None:
    await _relay_in_phase1(prod)
    prod.client.replies["ssh-port-set"] = AgentReply(0, {"ok": True})
    services = _services(prod)
    state = fsm()
    start = Callback("admin:sshp:1:set")
    await sshp.relay_ssh_port_set_start(start, state, services)
    assert await state.get_state() == sshp.RelaySshPortStates.port.state
    bad = Msg("abc")
    await sshp.relay_ssh_port_set_input(bad, state, services)
    assert t("relay_ssh_port_bad", value="abc") in bad.answers[-1].body
    good = Msg("60022")
    await sshp.relay_ssh_port_set_input(good, state, services)
    assert "ssh-port-set port=60022" in [c["request"] for c in prod.client.calls]
    assert t("relay_ssh_port_set_done", port=60022) in good.answers[-1].edits[-1]
    assert await state.get_state() is None


async def test_cancelling_the_port_prompt_forgets_it(prod: Env, sshp: Any) -> None:
    """«Отмена» of the prompt leads back to the card: a number typed afterwards starts nothing."""
    await _relay_in_phase1(prod)
    services = _services(prod)
    state = fsm()
    await sshp.relay_ssh_port_set_start(Callback("admin:sshp:1:set"), state, services)
    assert await state.get_state() == sshp.RelaySshPortStates.port.state
    await sshp.relay_ssh_port_card(Callback("admin:sshp:1"), state, services)
    assert await state.get_state() is None
    assert not [c for c in prod.client.calls if c["request"].startswith("ssh-port-set")]


async def test_a_stale_relay_button_changes_nothing(prod: Env, sshp: Any) -> None:
    await _relay_in_phase1(prod)
    cb = Callback("sshport:r:ok:1:0:5")
    await sshp.relay_ssh_port_button(cb, fsm(), _services(prod))
    assert cb.alerts and cb.alerts[-1][1] is True
    assert not [c for c in prod.client.calls if c["request"].startswith("ssh-port")]
