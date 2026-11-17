"""The fallback mode (hub) — docs/relay.md «Режим фолбэка».

Schema v46 (relays.role, failover_names) and the failover repository. The service,
the DNS adapter and the screens have their own sections below / files.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import aiosqlite
import pytest

from config import validators
from db.database import CURRENT_SCHEMA_VERSION, Database
from repositories.failover import FailoverRepository
from repositories.relays import RelayRepository

SNAPSHOT_DIR = Path(__file__).resolve().parent / "schema_snapshots"
NOW = "2026-11-17T10:00:00+00:00"


async def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    return db


# ── schema v46 ────────────────────────────────────────────────────────────────


async def test_v45_relays_come_out_as_edges_with_every_value_kept(tmp_path: Path) -> None:
    path = tmp_path / "v45.db"
    async with aiosqlite.connect(path) as conn:
        await conn.executescript((SNAPSHOT_DIR / "v45.sql").read_text(encoding="utf-8"))
        await conn.executescript((SNAPSHOT_DIR / "v45.seed.sql").read_text(encoding="utf-8"))
        await conn.execute("INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '45')")
        await conn.commit()
        conn.row_factory = aiosqlite.Row
        before = [dict(row) for row in await conn.execute_fetchall("SELECT * FROM relays ORDER BY id")]
    db = Database(path)
    await db.connect()
    try:
        await db.bootstrap()
        assert await db.get_meta("schema_version") == str(CURRENT_SCHEMA_VERSION)
        after = [dict(row) for row in await db.conn.execute_fetchall("SELECT * FROM relays ORDER BY id")]
        assert [row.pop("role") for row in after] == ["edge", "edge", "edge"]
        assert after == before
        relays = await RelayRepository(db).list_all()
        assert [(r.name, r.role, r.is_hub) for r in relays] == [
            ("ru1", "edge", False), ("he2", "edge", False), ("manual", "edge", False),
        ]
        assert await FailoverRepository(db).list_names() == []
        assert await FailoverRepository(db).mode_on() is False
    finally:
        await db.close()


async def test_role_is_checked_by_the_database(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        relays = RelayRepository(db)
        relay = await relays.create(
            name="he1", label="he1", host="hub.example.net",
            source_ips=validators.parse_ipv4_networks("s", "203.0.113.9/32"), now=NOW,
        )
        assert relay.role == "edge"
        assert await relays.set_role(relay.id, "hub", now=NOW, updated_by=None) is True
        assert [r.name for r in await relays.list_hubs()] == ["he1"]
        assert (await relays.get_by_id(relay.id)).is_hub  # type: ignore[union-attr]
        with pytest.raises(ValueError):
            await relays.set_role(relay.id, "core", now=NOW, updated_by=None)
        with pytest.raises(sqlite3.IntegrityError):
            await db.conn.execute("UPDATE relays SET role = 'core' WHERE id = ?", (relay.id,))
        await db.rollback()
        assert await relays.set_role(999, "hub", now=NOW, updated_by=None) is False
    finally:
        await db.close()


# ── the failover repository ───────────────────────────────────────────────────


async def test_names_are_unique_and_keep_what_the_last_write_did(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        repo = FailoverRepository(db)
        first = await repo.add_name("example.net", now=NOW, created_by=None)
        assert first is not None and first.applied is None
        assert await repo.add_name("example.net", now=NOW, created_by=None) is None
        second = await repo.add_name("relay.example.net", now=NOW, created_by=None)
        assert second is not None
        await repo.record_error(first.id, "boom " * 200)
        stored = await repo.get_name(first.id)
        assert stored is not None and stored.applied is None and len(stored.last_error or "") == 300
        await repo.record_applied(first.id, applied="failover", ipv4="203.0.113.9", now=NOW)
        stored = await repo.get_name(first.id)
        assert stored is not None
        assert (stored.applied, stored.applied_ipv4, stored.applied_at, stored.last_error) == (
            "failover", "203.0.113.9", NOW, None,
        )
        with pytest.raises(ValueError):
            await repo.record_applied(first.id, applied="sideways", ipv4="1.2.3.4", now=NOW)
        assert [n.name for n in await repo.list_names()] == ["example.net", "relay.example.net"]
        removed = await repo.remove_name(second.id)
        assert removed is not None and removed.name == "relay.example.net"
        assert await repo.remove_name(second.id) is None
    finally:
        await db.close()


async def test_runtime_settings_default_off(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        repo = FailoverRepository(db)
        assert (await repo.mode_on(), await repo.sub_fallback_url(), await repo.direct_host()) == (False, False, None)
        await repo.set_mode(True, now=NOW)
        assert await repo.mode_on() is True
        assert await repo.mode_changed_at() == NOW
        await repo.set_setting("failover_sub_fallback_url", "1")
        await repo.set_setting("failover_direct_host", " example.net ")
        assert await repo.sub_fallback_url() is True
        assert await repo.direct_host() == "example.net"
        assert await repo.get_setting("failover_main_ipv4") == ""
        await repo.set_mode(False, now=NOW)
        assert await repo.mode_on() is False
    finally:
        await db.close()


# ══ the service (services/fallback.py) on a real database ═════════════════════
#
# Cloudflare is a stateful fake transport (zones, A/AAAA records, the token's
# status, injected failures); DoH answers from that same state unless a name is
# marked stale; the hub's agent is the FakeClient of the relay tests.

import json  # noqa: E402
from collections.abc import Mapping  # noqa: E402
from typing import Any  # noqa: E402

from test_relay import ADMIN, _settings  # noqa: E402
from test_relay_admin import MODERATOR, _Audit, _Users  # noqa: E402
from test_relay_agents import FakeClient  # noqa: E402

from adapters.clock import ClockProvider  # noqa: E402
from adapters.cloudflare_dns import CloudflareDns, CloudflareTokenFile, DohAnswer, HttpReply  # noqa: E402
from models.dto import Relay, RelayAgent  # noqa: E402
from services.errors import AccessDenied, InvalidOperation  # noqa: E402
from services.fallback import FallbackService, check_reaches, name_settled  # noqa: E402
from services.relay import RelayCatalog, relay_link_host  # noqa: E402
from services.relay_health import LEVEL_HUB, LEVEL_OK, AgentCheck, RelayHealthSupervisor  # noqa: E402
from services.relay_ssh import AgentReply  # noqa: E402
from services.relays import RelayService  # noqa: E402
from utils.redact import forget_secret  # noqa: E402

MAIN = "198.51.100.1"
HUB = "203.0.113.9"
ZONE = "example.net"
ORIGIN = "origin.example.net"
TOKEN = "cfTOKEN_0123456789abcdefghijklmnopqrstuv"


class FakeCloudflare:
    """A Cloudflare API in memory: one zone, its records, the token's status."""

    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        self.token_status = "active"
        self.reject_token = False
        self.fail_writes: set[str] = set()
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self._n = 0

    def add(self, name: str, content: str, *, rtype: str = "A", proxied: bool = False, ttl: int = 300) -> str:
        self._n += 1
        rid = f"r{self._n}"
        self.records[rid] = {"id": rid, "type": rtype, "name": name, "content": content, "proxied": proxied, "ttl": ttl}
        return rid

    def a(self, name: str) -> list[dict[str, Any]]:
        return [r for r in self.records.values() if r["name"] == name and r["type"] == "A"]

    @staticmethod
    def _ok(result: object) -> HttpReply:
        return HttpReply(200, {"success": True, "errors": [], "result": result})

    async def __call__(self, method: str, url: str, *, headers: Mapping[str, str],
                       params: Mapping[str, str] | None = None, json_body: Mapping[str, object] | None = None,
                       timeout: float) -> HttpReply:
        path = url.split("/client/v4", 1)[1]
        self.calls.append((method, path, None if json_body is None else dict(json_body)))
        if self.reject_token:
            return HttpReply(403, {"success": False, "errors": [{"code": 9109, "message": "Invalid access token"}]})
        if path == "/user/tokens/verify":
            return self._ok({"status": self.token_status})
        if path == "/zones":
            return self._ok([{"id": "z1", "name": ZONE}] if (params or {}).get("name") == ZONE else [])
        if path == "/zones/z1/dns_records" and method == "GET":
            assert params is not None
            return self._ok([r for r in self.records.values() if r["type"] == params["type"] and r["name"] == params["name"]])
        body = dict(json_body or {})
        if method == "POST":
            if body["name"] in self.fail_writes:
                return HttpReply(500, {"success": False, "errors": [{"code": 1, "message": "boom"}]})
            rid = self.add(str(body["name"]), str(body["content"]), proxied=bool(body["proxied"]), ttl=int(body["ttl"]))  # type: ignore[call-overload]
            return self._ok(self.records[rid])
        if method == "PATCH":
            rid = path.rsplit("/", 1)[1]
            record = self.records[rid]
            if record["name"] in self.fail_writes:
                return HttpReply(500, {"success": False, "errors": [{"code": 1, "message": "boom"}]})
            record.update(body)
            return self._ok(record)
        raise AssertionError(f"unexpected {method} {path}")


class Fallback:
    """The world: DB, relays, the hub's agent, Cloudflare, DoH, the service."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path

    async def start(self, **settings: Any) -> Fallback:
        self.db = await _db(self.tmp)
        await self.db.conn.execute(
            "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
            "VALUES (?, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now')", (ADMIN,)
        )
        await self.db.commit()
        self.audit = _Audit()
        self.relays_repo = RelayRepository(self.db)
        self.repo = FailoverRepository(self.db)
        self.client = FakeClient()
        self.client.replies["apply"] = AgentReply(0, {"ok": True, "live_target": MAIN, "resolved": [MAIN]})
        self.client.replies["status"] = self.status_reply()
        values: dict[str, Any] = dict(
            xray_public_host=MAIN, hysteria2_host=MAIN, hysteria2_sni=ZONE, hysteria2_enabled=True,
            subscription_public_port=2096,
        )
        values.update(settings)
        self.settings = _settings(self.tmp, **values)
        self.catalog = RelayCatalog()
        self.relay_service = RelayService(
            relays=self.relays_repo, users=_Users(), audit=self.audit,  # type: ignore[arg-type]
            clock=ClockProvider(), catalog=self.catalog, settings=self.settings, client=self.client,  # type: ignore[arg-type]
        )
        self.cf = FakeCloudflare()
        self.stale: dict[str, tuple[str, ...]] = {}
        self.doh_calls: list[str] = []
        self.token_file = CloudflareTokenFile(self.tmp / "dns_failover" / "cloudflare_token")
        self.token_file.save(TOKEN)
        self.sleeps: list[float] = []
        self.clock_value = [0.0]

        async def doh(name: str) -> list[DohAnswer]:
            self.doh_calls.append(name)
            if name in self.stale:
                return [DohAnswer("cloudflare", self.stale[name], 60)]
            return [DohAnswer("cloudflare", tuple(sorted(r["content"] for r in self.cf.a(name))), 60)]

        async def sleep(seconds: float) -> None:
            self.sleeps.append(seconds)
            self.clock_value[0] += seconds

        self.service = FallbackService(
            repo=self.repo, relays_repo=self.relays_repo, relays=self.relay_service, users=_Users(),  # type: ignore[arg-type]
            audit=self.audit, clock=ClockProvider(), settings=self.settings, token_file=self.token_file,  # type: ignore[arg-type]
            dns=CloudflareDns(self.token_file.load, transport=self.cf), doh=doh, sleep=sleep,
            monotonic=lambda: self.clock_value[0], verify_timeout=20.0, verify_interval=5.0,
        )
        return self

    def status_reply(self, *, lines: list[str] | None = None, rc: int = 0, live: str = MAIN) -> AgentReply:
        return AgentReply(0, {
            "ok": True, "agent": "1", "live_target": live, "resolved": [live],
            "check": {"rc": rc, "lines": lines if lines is not None else [
                f"vpn-relay-apply: ok: TCP connect {MAIN}:443", f"vpn-relay-apply: ok: TCP connect {MAIN}:2096",
                "vpn-relay-apply: check OK",
            ]},
        })

    async def relay(self, name: str, *, target: str | None = ZONE, host: str | None = None, ssh: str = HUB,
                    source: str = "203.0.113.9/32", enabled: bool = True) -> Relay:
        agent = None if target is None else RelayAgent(
            ssh_host=ssh, ssh_port=22, host_key="ssh-ed25519 AAAA", target_host=target, tcp_ports=(443,),
            udp_ports=(443,), agent_version="1", paired_at=NOW,
        )
        return await self.relays_repo.create(
            name=name, label=name, host=host or f"{name}.{ZONE}", source_ips=validators.parse_ipv4_networks("s", source),
            now=NOW, enabled=enabled, agent=agent,
        )

    async def hub(self) -> Relay:
        """he1 made THE hub through the service (origin record created on the way)."""
        relay = await self.relay("he1", ssh=HUB)
        outcome = await self.service.assign_hub(ADMIN, relay.id, ORIGIN)
        return outcome.relay

    async def close(self) -> None:
        forget_secret(TOKEN)
        await self.db.close()


@pytest.fixture
async def fb(tmp_path: Path) -> Any:
    world = await Fallback(tmp_path).start()
    yield world
    await world.close()


# ── the hub ───────────────────────────────────────────────────────────────────


async def test_assign_hub_creates_the_origin_then_repoints_the_agent_then_sets_the_role(fb: Fallback) -> None:
    relay = await fb.relay("he1")
    outcome = await fb.service.assign_hub(ADMIN, relay.id, ORIGIN)
    assert outcome.created_record and outcome.main_ipv4 == MAIN
    [origin] = fb.cf.a(ORIGIN)
    assert (origin["content"], origin["proxied"], origin["ttl"]) == (MAIN, False, 60)
    assert [c["request"] for c in fb.client.calls] == [f"apply target={ORIGIN} tcp=443,2096 udp=443"]
    hub = await fb.relays_repo.get_by_id(relay.id)
    assert hub is not None and hub.is_hub and hub.agent is not None and hub.agent.target_host == ORIGIN
    assert hub.agent.tcp_ports == (443, 2096)
    assert fb.catalog.snapshot.hubs == (hub,)
    assert "relay_hub_assigned" in fb.audit.actions()
    # Assigned again: the record exists now (checked, not duplicated).
    await fb.service.clear_hub(ADMIN, relay.id)
    again = await fb.service.assign_hub(ADMIN, relay.id, ORIGIN)
    assert again.created_record is False and len(fb.cf.a(ORIGIN)) == 1


async def test_an_existing_origin_record_is_corrected_not_duplicated(fb: Fallback) -> None:
    fb.cf.add(ORIGIN, "192.0.2.77", proxied=True)
    relay = await fb.relay("he1")
    await fb.service.assign_hub(ADMIN, relay.id, ORIGIN)
    [origin] = fb.cf.a(ORIGIN)
    assert (origin["content"], origin["proxied"], origin["ttl"]) == (MAIN, False, 60)


@pytest.mark.parametrize("case", ["no_agent", "disabled", "origin_in_set", "origin_is_host", "second_hub",
                                  "bad_name", "not_resolving", "loop", "no_main", "mode_on"])
async def test_assign_hub_refusals_leave_the_role_alone(fb: Fallback, case: str) -> None:
    relay = await fb.relay("he1", target=None if case == "no_agent" else ZONE, enabled=case != "disabled")
    origin = ORIGIN
    if case == "origin_in_set":
        await fb.repo.add_name(ORIGIN, now=NOW, created_by=None)
    elif case == "origin_is_host":
        origin = relay.host
    elif case == "second_hub":
        other = await fb.relay("he9", ssh="203.0.113.99", source="203.0.113.99/32")
        await fb.relays_repo.set_role(other.id, "hub", now=NOW, updated_by=None)
    elif case == "bad_name":
        origin = "203.0.113.1"
    elif case == "not_resolving":
        fb.stale[ORIGIN] = ()
    elif case == "loop":
        fb.client.replies["apply"] = AgentReply(0, {"ok": True, "live_target": HUB, "resolved": [HUB]})
    elif case == "no_main":
        await fb.close()
        fb2 = await Fallback(fb.tmp / "x").start(xray_public_host="vpn.example.com", hysteria2_host="vpn.example.com")
        fb.__dict__.update(fb2.__dict__)
        relay = await fb.relay("he1")
    elif case == "mode_on":
        await fb.repo.set_mode(True, now=NOW)
    with pytest.raises(InvalidOperation):
        await fb.service.assign_hub(ADMIN, relay.id, origin)
    assert not (await fb.relays_repo.get_by_id(relay.id)).is_hub  # type: ignore[union-attr]
    if case in ("not_resolving", "origin_in_set", "second_hub"):
        assert fb.client.calls == [], "the agent is never asked when the origin is not right"


async def test_clear_hub_is_refused_while_the_mode_is_on(fb: Fallback) -> None:
    hub = await fb.hub()
    await fb.repo.set_mode(True, now=NOW)
    with pytest.raises(InvalidOperation):
        await fb.service.clear_hub(ADMIN, hub.id)
    await fb.repo.set_mode(False, now=NOW)
    assert not (await fb.service.clear_hub(ADMIN, hub.id)).is_hub
    edge = await fb.relay("ru1", ssh="198.51.100.7", source="198.51.100.7/32")
    assert (await fb.service.clear_hub(ADMIN, edge.id)).role == "edge"


async def test_only_a_superadmin(fb: Fallback) -> None:
    relay = await fb.relay("he1")
    for call in (
        fb.service.overview(MODERATOR), fb.service.assign_hub(MODERATOR, relay.id, ORIGIN),
        fb.service.enable(MODERATOR), fb.service.disable(MODERATOR), fb.service.add_name(MODERATOR, ZONE),
        fb.service.set_token(MODERATOR, TOKEN), fb.service.preflight(MODERATOR),
    ):
        with pytest.raises(AccessDenied):
            await call
    assert fb.cf.calls == [] and fb.client.calls == []


# ── the failover set ──────────────────────────────────────────────────────────


async def test_names_never_include_a_hubs_origin_or_host(fb: Fallback) -> None:
    hub = await fb.hub()
    for value in (ORIGIN, hub.host):
        with pytest.raises(InvalidOperation):
            await fb.service.add_name(ADMIN, value)
    with pytest.raises(InvalidOperation):
        await fb.service.add_name(ADMIN, "198.51.100.1")
    added = await fb.service.add_name(ADMIN, "Example.NET.")
    assert added.name == ZONE
    with pytest.raises(InvalidOperation):
        await fb.service.add_name(ADMIN, ZONE)
    assert [n.name for n in await fb.repo.list_names()] == [ZONE]
    assert "failover_name_added" in fb.audit.actions()


async def test_candidates_are_the_sni_and_the_edges_targets(fb: Fallback) -> None:
    await fb.relay("ru1", target="relay-target.example.net", ssh="198.51.100.7", source="198.51.100.7/32")
    await fb.relay("manual", target=None, ssh="198.51.100.8", source="198.51.100.8/32")
    await fb.hub()
    assert await fb.service.candidates(ADMIN) == [ZONE, "relay-target.example.net"]
    await fb.service.add_name(ADMIN, ZONE)
    assert await fb.service.candidates(ADMIN) == ["relay-target.example.net"]


async def test_a_name_pointing_at_the_hub_cannot_be_removed(fb: Fallback) -> None:
    added = await fb.service.add_name(ADMIN, ZONE)
    await fb.repo.record_applied(added.id, applied="failover", ipv4=HUB, now=NOW)
    with pytest.raises(InvalidOperation):
        await fb.service.remove_name(ADMIN, added.id)
    await fb.repo.record_applied(added.id, applied="normal", ipv4=MAIN, now=NOW)
    assert (await fb.service.remove_name(ADMIN, added.id)).name == ZONE
    with pytest.raises(Exception, match="имени нет"):
        await fb.service.remove_name(ADMIN, added.id)


# ── the switch ────────────────────────────────────────────────────────────────


async def _ready(fb: Fallback) -> Relay:
    """A hub, two names pointing at the main server, an RU relay forwarding to one."""
    hub = await fb.hub()
    fb.cf.add(ZONE, MAIN)
    fb.cf.add("relay.example.net", MAIN, ttl=1)
    await fb.service.add_name(ADMIN, ZONE)
    await fb.service.add_name(ADMIN, "relay.example.net")
    await fb.relay("ru1", target=ZONE, ssh="198.51.100.7", source="198.51.100.7/32")
    fb.client.calls.clear()
    fb.cf.calls.clear()
    return hub


async def test_enable_switches_every_name_to_the_hub_and_disable_switches_back(fb: Fallback) -> None:
    hub = await _ready(fb)
    report = await fb.service.enable(ADMIN)
    assert report.preflight is not None and report.preflight.passed, report.preflight
    assert report.complete and report.started
    assert [(r.name, r.ok, r.propagated) for r in report.results] == [(ZONE, True, True), ("relay.example.net", True, True)]
    for name in (ZONE, "relay.example.net"):
        [record] = fb.cf.a(name)
        assert (record["content"], record["proxied"], record["ttl"]) == (HUB, False, 60)
    assert [c["request"] for c in fb.client.calls] == ["status"], "the preflight asks the hub's agent, once"
    overview = await fb.service.overview(ADMIN)
    assert overview.hub is not None and overview.hub.id == hub.id
    assert (overview.state, overview.hub_ipv4, overview.origin) == ("on", HUB, ORIGIN)
    # Health: the RU relay forwarding to a failover name is behind the hub now; the
    # hub and a relay forwarding elsewhere are not.
    ru1 = await fb.relays_repo.get_by_name("ru1")
    other = await fb.relay("de1", target="elsewhere.example.org", ssh="192.0.2.5", source="192.0.2.5/32")
    assert ru1 is not None and fb.service.behind_hub(ru1)
    assert not fb.service.behind_hub(hub) and not fb.service.behind_hub(other)
    details = json.dumps([row["details"] for row in fb.audit.rows if row["action"] == "failover_enabled"])
    assert HUB in details and TOKEN not in details

    back = await fb.service.disable(ADMIN)
    assert back.preflight is None and back.complete
    assert {r["content"] for name in (ZONE, "relay.example.net") for r in fb.cf.a(name)} == {MAIN}
    assert (await fb.service.overview(ADMIN)).state == "off"
    assert ru1 is not None and not fb.service.behind_hub(ru1)
    assert fb.audit.actions()[-1] == "failover_disabled"


async def test_a_failed_preflight_touches_no_record_and_keeps_the_mode(fb: Fallback) -> None:
    await _ready(fb)
    fb.cf.records[next(iter(r["id"] for r in fb.cf.a(ZONE)))]["proxied"] = True
    fb.client.replies["status"] = fb.status_reply(lines=[f"ok: TCP connect {MAIN}:443", f"FAIL: TCP connect {MAIN}:2096"], rc=13)
    report = await fb.service.enable(ADMIN)
    assert report.preflight is not None and not report.started and not report.complete
    failed = {item.key for item in report.preflight.failures}
    assert {"fb_pf_reach", "fb_pf_record_proxied"} <= failed
    assert not [c for c in fb.cf.calls if c[0] in ("POST", "PATCH")]
    assert await fb.repo.mode_on() is False
    assert "failover_preflight_failed" in fb.audit.actions()


@pytest.mark.parametrize("breakage", ["loop_live", "origin_public", "origin_in_set", "token", "foreign", "count",
                                      "agent", "forward", "no_hub"])
async def test_every_preflight_blocker(fb: Fallback, breakage: str) -> None:
    hub = await _ready(fb)
    expected = {
        "loop_live": "fb_pf_loop", "origin_public": "fb_pf_loop", "origin_in_set": "fb_pf_loop",
        "token": "fb_pf_token", "foreign": "fb_pf_record_foreign", "count": "fb_pf_record_count",
        "agent": "fb_pf_agent_failed", "forward": "fb_pf_forward", "no_hub": "fb_pf_hub",
    }[breakage]
    if breakage == "loop_live":
        fb.client.replies["status"] = fb.status_reply(live=HUB)
    elif breakage == "origin_public":
        fb.stale[ORIGIN] = (HUB,)
    elif breakage == "origin_in_set":
        await fb.db.conn.execute("INSERT INTO failover_names (name, created_at) VALUES (?, ?)", (ORIGIN, NOW))
        await fb.db.commit()
    elif breakage == "token":
        fb.cf.token_status = "disabled"
    elif breakage == "foreign":
        fb.cf.records[fb.cf.a(ZONE)[0]["id"]]["content"] = "192.0.2.200"
    elif breakage == "count":
        fb.cf.add(ZONE, MAIN)
    elif breakage == "agent":
        fb.client.replies["status"] = AgentReply(255, {})
    elif breakage == "forward":
        await fb.relays_repo.update_agent_forward(hub.id, target_host=ORIGIN, tcp_ports=(443,), udp_ports=(443,))
    elif breakage == "no_hub":
        await fb.relays_repo.update(hub.id, {"enabled": False}, now=NOW, updated_by=None)
    preflight = await fb.service.preflight(ADMIN)
    assert not preflight.passed
    assert expected in {item.key for item in preflight.failures}, preflight
    assert not [c for c in fb.cf.calls if c[0] in ("POST", "PATCH")]


async def test_an_aaaa_record_is_a_warning_not_a_blocker(fb: Fallback) -> None:
    await _ready(fb)
    fb.cf.add(ZONE, "2001:db8::1", rtype="AAAA")
    preflight = await fb.service.preflight(ADMIN)
    assert preflight.passed
    assert [item.key for item in preflight.items if item.warning] == ["fb_pf_record_aaaa"]


async def test_a_partial_switch_is_visible_per_name_and_the_repeat_finishes_it(fb: Fallback) -> None:
    await _ready(fb)
    fb.cf.fail_writes.add("relay.example.net")
    report = await fb.service.enable(ADMIN)
    assert report.started and not report.complete and report.failed_names == ("relay.example.net",)
    overview = await fb.service.overview(ADMIN)
    assert overview.state == "partial" and [n.name for n in overview.pending] == ["relay.example.net"]
    failed = [n for n in overview.names if n.name == "relay.example.net"][0]
    assert failed.applied is None and "boom" in (failed.last_error or "")
    fb.cf.fail_writes.clear()
    again = await fb.service.repeat(ADMIN)
    assert again.complete and (await fb.service.overview(ADMIN)).state == "on"
    # The repeat did not rewrite the name that was already right: only the failed
    # record was patched again.
    patched = [c[1].rsplit("/", 1)[1] for c in fb.cf.calls if c[0] == "PATCH"]
    zone_id = fb.cf.a(ZONE)[0]["id"]
    relay_id = fb.cf.a("relay.example.net")[0]["id"]
    assert patched == [zone_id, relay_id, relay_id]


async def test_the_switch_waits_for_resolvers_then_reports_what_they_say(fb: Fallback) -> None:
    await _ready(fb)
    fb.stale["relay.example.net"] = (MAIN,)
    report = await fb.service.enable(ADMIN)
    assert report.complete, "the records are written: a slow resolver is a report, not a failure"
    assert [(r.name, r.propagated) for r in report.results] == [(ZONE, True), ("relay.example.net", False)]
    assert fb.sleeps == [5.0, 5.0, 5.0, 5.0]


async def test_disable_needs_only_the_token(fb: Fallback) -> None:
    await _ready(fb)
    await fb.service.enable(ADMIN)
    hub = (await fb.relays_repo.list_hubs())[0]
    await fb.relays_repo.update(hub.id, {"enabled": False}, now=NOW, updated_by=None)
    fb.client.replies["status"] = AgentReply(255, {})
    assert (await fb.service.disable(ADMIN)).complete
    fb.token_file.delete()
    with pytest.raises(InvalidOperation):
        await fb.service.disable(ADMIN)


async def test_switching_an_empty_set_is_refused(fb: Fallback) -> None:
    with pytest.raises(InvalidOperation):
        await fb.service.enable(ADMIN)


# ── the token ─────────────────────────────────────────────────────────────────


async def test_the_token_is_checked_before_it_is_stored_and_never_audited(fb: Fallback) -> None:
    fb.token_file.delete()
    fb.cf.token_status = "disabled"
    with pytest.raises(InvalidOperation):
        await fb.service.set_token(ADMIN, TOKEN)
    assert not fb.token_file.exists()
    fb.cf.reject_token = True
    with pytest.raises(InvalidOperation):
        await fb.service.set_token(ADMIN, TOKEN)
    with pytest.raises(InvalidOperation):
        await fb.service.set_token(ADMIN, "not a token")
    fb.cf.reject_token = False
    fb.cf.token_status = "active"
    assert await fb.service.set_token(ADMIN, f"  {TOKEN}\n") == "active"
    assert fb.token_file.load() == TOKEN
    overview = await fb.service.overview(ADMIN)
    assert overview.token_set and overview.token_fingerprint and overview.token_fingerprint not in TOKEN
    assert await fb.service.delete_token(ADMIN) is True
    assert await fb.service.delete_token(ADMIN) is False
    assert TOKEN not in json.dumps([row["details"] for row in fb.audit.rows], default=str)
    assert {"failover_token_set", "failover_token_deleted", "failover_token_rejected"} <= set(fb.audit.actions())


# ── settings ──────────────────────────────────────────────────────────────────


async def test_addresses_are_derived_and_can_be_overridden(fb: Fallback) -> None:
    assert await fb.service.main_ipv4() == MAIN
    hub = await fb.relay("he1", host="hub.example.org", ssh="hub-ssh.example.org", source="203.0.113.10/32")
    assert await fb.service.hub_ipv4(hub) == "203.0.113.10"
    await fb.service.set_address(ADMIN, "hub", "8.8.4.4")
    assert await fb.service.hub_ipv4(hub) == "8.8.4.4"
    await fb.service.set_address(ADMIN, "hub", "-")
    assert await fb.service.hub_ipv4(hub) == "203.0.113.10"
    with pytest.raises(InvalidOperation):
        await fb.service.set_address(ADMIN, "main", "10.0.0.1")
    with pytest.raises(InvalidOperation):
        await fb.service.set_address(ADMIN, "main", "nonsense")
    await fb.repo.set_mode(True, now=NOW)
    with pytest.raises(InvalidOperation):
        await fb.service.set_address(ADMIN, "main", "8.8.8.8")
    assert await fb.service.hub_ipv4(None) is None


async def test_the_direct_host_moves_new_direct_links_and_counts_the_old_ones(fb: Fallback) -> None:
    fb.cf.add(ZONE, MAIN)
    fb.stale["elsewhere.example.net"] = ("192.0.2.200",)
    with pytest.raises(InvalidOperation):
        await fb.service.set_direct_host(ADMIN, "elsewhere.example.net")
    with pytest.raises(InvalidOperation):
        await fb.service.set_direct_host(ADMIN, "198.51.100.1")
    assert await fb.service.set_direct_host(ADMIN, ZONE) == ZONE
    assert fb.catalog.snapshot.direct_host == ZONE
    assert relay_link_host(fb.catalog.snapshot, None, direct_host=MAIN) == ZONE
    overview = await fb.service.overview(ADMIN)
    assert overview.direct_host == ZONE and overview.single_direct_keys == 0
    assert await fb.service.set_direct_host(ADMIN, "-") is None
    assert fb.catalog.snapshot.direct_host is None
    assert relay_link_host(fb.catalog.snapshot, None, direct_host=MAIN) == MAIN
    assert "failover_direct_host_changed" in fb.audit.actions()


async def test_the_subscription_header_switch(fb: Fallback) -> None:
    assert (await fb.service.overview(ADMIN)).sub_fallback_url is False
    await fb.service.set_sub_fallback_url(ADMIN, True)
    assert (await fb.service.overview(ADMIN)).sub_fallback_url is True
    assert fb.service.suggest_origin() == ORIGIN
    assert fb.service.hub_ports() == ((443, 2096), (443,))


async def test_single_direct_keys_are_counted_without_bundle_children(fb: Fallback) -> None:
    async def key(kid: int, *, key_type: str = "xray", relay: str | None = None, bundle: int | None = None,
                  status: str = "active", created: str = "2026-01-01T00:00:00+00:00") -> None:
        await fb.db.conn.execute(
            "INSERT INTO vpn_keys (id, owner_user_id, key_type, status, created_by, created_at, updated_at, "
            "payload_json, public_payload_json, relay, bundle_id) VALUES (?, ?, ?, ?, ?, ?, ?, '{}', '{}', ?, ?)",
            (kid, ADMIN, key_type, status, ADMIN, created, created, relay, bundle),
        )

    await fb.db.conn.execute(
        "INSERT INTO key_bundles (id, user_id, label, status, token, created_at, updated_at) "
        "VALUES (1, ?, 'b', 'active', 'tok', 'now', 'now')", (ADMIN,)
    )
    await key(1)
    await key(2, key_type="hysteria2", created="2026-12-01T00:00:00+00:00")
    await key(3, relay="ru1")
    await key(4, bundle=1)
    await key(5, status="revoked")
    await key(6, key_type="awg")
    await fb.db.commit()
    assert await fb.repo.single_direct_keys() == 2
    assert await fb.repo.single_direct_keys(issued_before="2026-06-01T00:00:00+00:00") == 1


# ── pure helpers ──────────────────────────────────────────────────────────────


def test_check_reaches_reads_the_agents_check_lines() -> None:
    good = {"check": {"rc": 17, "lines": [f"ok: TCP connect {MAIN}:443", f"ok: TCP connect {MAIN}:2096"]}}
    assert check_reaches(good, MAIN, (443, 2096)) == (True, [])
    assert check_reaches(good, HUB, (443,)) == (False, [443])
    bad = {"check": {"rc": 13, "lines": [f"ok: TCP connect {MAIN}:443", f"FAIL: TCP connect {MAIN}:2096 failed"]}}
    assert check_reaches(bad, MAIN, (443, 2096)) == (False, [2096])
    assert check_reaches({"check": {"rc": 11, "lines": good["check"]["lines"]}}, MAIN, (443,))[0] is False
    assert check_reaches({}, MAIN, (443,)) == (False, [443])


def test_name_settled() -> None:
    from models.dto import FailoverName

    def name(applied: str | None, error: str | None = None) -> FailoverName:
        return FailoverName(1, ZONE, applied, None, None, error, NOW, None)

    assert name_settled(name(None), mode_on=False) and name_settled(name("normal"), mode_on=False)
    assert not name_settled(name("failover"), mode_on=False)
    assert name_settled(name("failover"), mode_on=True) and not name_settled(name(None), mode_on=True)
    assert not name_settled(name("normal", "boom"), mode_on=False)


# ── health: «за hub», no alert storm ──────────────────────────────────────────


async def test_health_marks_a_relay_behind_the_hub_without_an_alert_or_an_ssh_wait() -> None:
    ru1 = Relay(
        id=1, name="ru1", label="ru1", host="relay.example.net",
        source_ips=validators.parse_ipv4_networks("s", "198.51.100.7/32"), enabled=True, in_subscriptions=True,
        note=None, created_at=NOW, updated_at=NOW, created_by=None, updated_by=None,
        agent=RelayAgent(ssh_host="198.51.100.7", ssh_port=22, host_key="k", target_host=ZONE, tcp_ports=(443,),
                         udp_ports=(443,), agent_version="1", paired_at=NOW),
    )
    traffic = [False]
    agent_calls: list[str] = []
    sent: list[str] = []
    now = [0.0]

    async def probe(host: str, port: int, sni: str) -> bool:
        return traffic[0]

    async def agent_probe(relay: Relay) -> AgentCheck:
        agent_calls.append(relay.name)
        return AgentCheck(ok=True)

    async def load() -> list[Relay]:
        return [ru1]

    class _Bot:
        async def send_message(self, chat_id: int, text: str) -> None:
            sent.append(text)

    supervisor = RelayHealthSupervisor(
        load_relays=load, port=443, sni="example.com", admin_ids=frozenset({1}), window=10.0, probe=probe,
        clock=lambda: now[0], agent_probe=agent_probe, bot=_Bot(),  # type: ignore[arg-type]
    )
    behind = [True]
    supervisor.behind_hub = lambda relay: behind[0]
    for step in range(4):
        now[0] = step * 10.0
        await supervisor.check_once()
    assert supervisor.level(ru1.id) == LEVEL_HUB
    assert supervisor.last_probe(ru1.id).level == LEVEL_HUB  # type: ignore[union-attr]
    assert "hub" in supervisor.reason(supervisor.last_probe(ru1.id)).lower()  # type: ignore[arg-type]
    assert agent_calls == [], "SSH to a relay behind the hub is not even tried"
    assert sent == [], "no alert into or inside the fallback mode"
    # The mode is switched off and the relay is reachable again: back to ok, silently.
    behind[0] = False
    traffic[0] = True
    for step in range(4, 8):
        now[0] = step * 10.0
        await supervisor.check_once()
    assert supervisor.level(ru1.id) == LEVEL_OK and sent == [] and agent_calls
    # Off and unreachable: an ordinary «down», alerted as before.
    traffic[0] = False
    for step in range(8, 12):
        now[0] = step * 10.0
        await supervisor.check_once()
    assert len(sent) == 1 and "🔴" in sent[0]
