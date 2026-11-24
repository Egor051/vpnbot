"""services/dns.py — the bot's ONE Cloudflare token and the A records it owns (docs/certificate.md).

* the token is checked against the API BEFORE it is stored: active, the zone visible, its
  records readable, a TXT probe created AND deleted (the only proof of «DNS · Edit»); a
  token without the right permissions is refused and nothing is stored;
* every A write is proxied=false (TTL 60), whatever the record was;
* ``dns_records`` is the ONE list of the records the bot owns — the fallback hub's origin
  arrives there (written by assign_hub, and backfilled by the v48 migration on the
  production snapshot); a record the bot does not own is never deleted.

Cloudflare is the stateful fake of tests/test_fallback_mode.py — no network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_fallback_mode import ADMIN, HUB, MAIN, ORIGIN, TOKEN, ZONE, Fallback
from test_schema_upgrade_path import _materialise

from adapters.cloudflare_dns import CloudflareDns, HttpReply
from db.database import Database
from repositories.dns_records import DnsRecordsRepository
from services.errors import InvalidOperation, NotFound
from utils.redact import forget_secret

OTHER = "cfOTHER_0123456789abcdefghijklmnopqrstu"


@pytest.fixture
async def world(tmp_path: Path) -> Any:
    w = await Fallback(tmp_path).start()
    yield w
    forget_secret(OTHER)
    await w.close()


def _a_writes(world: Fallback) -> list[dict[str, Any]]:
    return [body for method, path, body in world.cf.calls
            if method in ("POST", "PATCH") and body is not None and body.get("type", "A") == "A"]


# ── the token ─────────────────────────────────────────────────────────────────


async def test_a_good_token_is_checked_with_a_txt_probe_that_is_deleted_then_stored(world: Fallback) -> None:
    world.token_file.delete()
    check = await world.dns_service.set_token(ADMIN, OTHER, ZONE)
    assert (check.status, check.zone.name) == ("active", ZONE)
    assert world.token_file.load() == OTHER
    probes = [(m, body) for m, p, body in world.cf.calls if m == "POST" and body and body.get("type") == "TXT"]
    assert len(probes) == 1 and probes[0][1]["name"] == f"_vpn-bot-token-check.{ZONE}"
    assert [m for m, p, _ in world.cf.calls if m == "DELETE"] == ["DELETE"]
    assert not [r for r in world.cf.records.values() if r["type"] == "TXT"], "the probe is gone"
    rows = json.dumps([row["details"] for row in world.audit.rows], default=str)
    assert OTHER not in rows and check.fingerprint in rows


@pytest.mark.parametrize(
    ("break_it", "key"),
    [
        ("inactive", "dns_err_token_inactive"),
        ("rejected", "dns_err_token_rejected"),
        ("no_edit", "dns_err_token_no_edit"),
        ("other_zone", "dns_err_token_no_zone"),
        ("format", "dns_err_token_format"),
    ],
)
async def test_a_token_without_the_permissions_is_refused_and_nothing_is_stored(
    world: Fallback, break_it: str, key: str
) -> None:
    world.token_file.delete()
    token, name = OTHER, ZONE
    if break_it == "inactive":
        world.cf.token_status = "disabled"
    elif break_it == "rejected":
        world.cf.reject_token = True
    elif break_it == "no_edit":
        world.cf.no_edit = True
    elif break_it == "other_zone":
        name = "example.org"
    else:
        token = "not a token"
    with pytest.raises(InvalidOperation) as caught:
        await world.dns_service.set_token(ADMIN, token, name)
    assert caught.value.key == key
    assert not world.token_file.exists()
    assert not [r for r in world.cf.records.values() if r["type"] == "TXT"]


async def test_a_probe_that_cannot_be_deleted_refuses_the_token(world: Fallback) -> None:
    world.token_file.delete()
    real = world.cf.__call__

    async def no_delete(method: str, url: str, **kw: Any) -> HttpReply:
        if method == "DELETE":
            return HttpReply(403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]})
        return await real(method, url, **kw)

    world.dns_service.dns = CloudflareDns(world.token_file.load, transport=no_delete)
    with pytest.raises(InvalidOperation) as caught:
        await world.dns_service.set_token(ADMIN, OTHER, ZONE)
    assert caught.value.key == "dns_err_token_no_delete"
    assert caught.value.params["name"] == f"_vpn-bot-token-check.{ZONE}"
    assert not world.token_file.exists()


async def test_the_fallback_screens_token_goes_through_the_same_check(world: Fallback) -> None:
    """One token per bot, one check: «🔑 DNS API token» of the fallback mode refuses a
    token that cannot edit the zone too (it used to verify the token only)."""
    world.token_file.delete()
    world.cf.no_edit = True
    with pytest.raises(InvalidOperation):
        await world.service.set_token(ADMIN, OTHER)
    assert not world.token_file.exists()
    assert "failover_token_rejected" in world.audit.actions()
    world.cf.no_edit = False
    assert await world.service.set_token(ADMIN, OTHER) == "active"
    assert world.token_file.load() == OTHER == world.dns_service.token_file.load()


# ── the records: always proxied=false ─────────────────────────────────────────


async def test_every_write_is_proxied_false_with_ttl_60(world: Fallback) -> None:
    world.cf.add("host.example.net", "192.0.2.1", proxied=True, ttl=1)
    created = await world.dns_service.upsert_a(ADMIN, "new.example.net", MAIN, purpose="host")
    updated = await world.dns_service.upsert_a(ADMIN, "host.example.net", MAIN, purpose="host")
    assert (created.change, updated.change) == ("created", "updated")
    writes = _a_writes(world)
    assert writes and all(w["proxied"] is False and w["ttl"] == 60 for w in writes)
    for name in ("new.example.net", "host.example.net"):
        [record] = world.cf.a(name)
        assert (record["content"], record["proxied"], record["ttl"]) == (MAIN, False, 60)
    again = await world.dns_service.upsert_a(ADMIN, "host.example.net", MAIN, purpose="host")
    assert again.change == "unchanged" and len(_a_writes(world)) == len(writes)


async def test_ownership_is_recorded_adopted_or_created(world: Fallback) -> None:
    world.cf.add("old.example.net", "192.0.2.1")
    await world.dns_service.upsert_a(ADMIN, "Old.Example.NET.", MAIN, purpose="host")
    await world.dns_service.upsert_a(ADMIN, "new.example.net", MAIN, purpose="host")
    owned = {r.name: r for r in await world.dns_service.owned()}
    assert set(owned) == {"old.example.net", "new.example.net"}
    assert owned["old.example.net"].adopted and not owned["new.example.net"].adopted
    assert owned["new.example.net"].content == MAIN and owned["new.example.net"].zone_id == "z1"
    assert owned["new.example.net"].record_id in world.cf.records


async def test_a_write_is_refused_on_several_records_a_foreign_one_or_another_purpose(world: Fallback) -> None:
    world.cf.add("two.example.net", "192.0.2.1")
    world.cf.add("two.example.net", "192.0.2.2")
    with pytest.raises(InvalidOperation) as caught:
        await world.dns_service.upsert_a(ADMIN, "two.example.net", MAIN, purpose="host")
    assert caught.value.key == "dns_err_record_count"
    world.cf.add("foreign.example.net", "192.0.2.9")
    with pytest.raises(InvalidOperation) as caught:
        await world.dns_service.upsert_a(ADMIN, "foreign.example.net", MAIN, purpose="host", allowed={MAIN, HUB})
    assert caught.value.key == "dns_err_record_foreign" and world.cf.a("foreign.example.net")[0]["content"] == "192.0.2.9"
    await world.dns_service.upsert_a(ADMIN, "mine.example.net", MAIN, purpose="host")
    with pytest.raises(InvalidOperation) as caught:
        await world.dns_service.upsert_a(ADMIN, "mine.example.net", MAIN, purpose="fallback_origin")
    assert caught.value.key == "dns_err_record_other_purpose"
    with pytest.raises(InvalidOperation):
        await world.dns_service.upsert_a(ADMIN, "mine.example.net", "not-an-ip", purpose="host")


async def test_delete_only_what_the_bot_owns_and_created(world: Fallback) -> None:
    world.cf.add("adopted.example.net", "192.0.2.1")
    await world.dns_service.upsert_a(ADMIN, "adopted.example.net", MAIN, purpose="host")
    await world.dns_service.upsert_a(ADMIN, "created.example.net", MAIN, purpose="host")
    world.cf.add("stranger.example.net", MAIN)
    with pytest.raises(NotFound):
        await world.dns_service.delete_a(ADMIN, "stranger.example.net")
    assert world.cf.a("stranger.example.net")
    assert await world.dns_service.delete_a(ADMIN, "adopted.example.net") is False
    assert world.cf.a("adopted.example.net"), "an adopted record stays at Cloudflare"
    assert await world.dns_service.delete_a(ADMIN, "created.example.net") is True
    assert not world.cf.a("created.example.net")
    assert [r.name for r in await world.dns_service.owned()] == []


# ── one model of ownership: the fallback's origin is in it ───────────────────


async def test_the_hubs_origin_is_a_record_the_bot_owns(world: Fallback) -> None:
    await world.hub()
    owned = {r.name: r for r in await world.dns_service.owned()}
    assert list(owned) == [ORIGIN]
    assert owned[ORIGIN].purpose == "fallback_origin" and owned[ORIGIN].content == MAIN
    assert not owned[ORIGIN].adopted
    # The failover set is not ownership: switching it writes no row.
    await world.service.add_name(ADMIN, ZONE)
    world.cf.add(ZONE, MAIN)
    await world.service.enable(ADMIN)
    assert [r.name for r in await world.dns_service.owned()] == [ORIGIN]
    assert all(w["proxied"] is False for w in _a_writes(world))


async def test_v48_backfills_the_production_origin_and_keeps_the_failover_set(tmp_path: Path) -> None:
    """The production snapshot (v47 + its seed: he1 is the hub on origin.example.net)
    upgraded: the origin is in dns_records — fallback_origin, adopted — and nothing
    else moved."""
    path = tmp_path / "vpn.db"
    await _materialise(path, 47)
    db = Database(path)
    await db.connect()
    try:
        await db.bootstrap()
        rows = await DnsRecordsRepository(db).list_all()
        assert [(r.name, r.type, r.purpose, r.adopted, r.content) for r in rows] == [
            ("origin.example.net", "A", "fallback_origin", True, None),
        ]
        names = await db.conn.execute_fetchall("SELECT name, applied, applied_ipv4 FROM failover_names")
        assert [tuple(r) for r in names] == [("example.net", "normal", "198.51.100.1")]
        await db.bootstrap()  # again: idempotent
        assert len(await DnsRecordsRepository(db).list_all()) == 1
    finally:
        await db.close()


async def test_an_adopted_origin_is_written_through_without_losing_its_ownership(tmp_path: Path) -> None:
    """After the backfill the next write (the hub given again, W4 later) fills the row in."""
    world = await Fallback(tmp_path).start()
    try:
        await world.records_repo.save(ORIGIN, purpose="fallback_origin", content="192.0.2.50", zone_id="", record_id="",
                                      adopted=True, now="now", actor=None)
        world.cf.add(ORIGIN, "192.0.2.50")
        written = await world.dns_service.upsert_a(ADMIN, ORIGIN, MAIN, purpose="fallback_origin",
                                                   allowed={MAIN})
        assert written.change == "updated" and written.record is not None and written.record.adopted
        assert world.cf.a(ORIGIN)[0]["content"] == MAIN
    finally:
        forget_secret(TOKEN)
        await world.close()


async def test_a_token_change_waits_for_a_running_switch(world: Fallback) -> None:
    """The switch writes names with the token loaded per call: a new token — from the
    fallback's screen or the certificate's — lands only once the switch is done."""
    import asyncio

    assert world.service._lock is world.dns_service.lock
    async with world.service._lock:  # a switch in progress
        task = asyncio.create_task(world.dns_service.set_token(ADMIN, OTHER, ZONE))
        for _ in range(50):
            await asyncio.sleep(0)
        assert not task.done() and world.token_file.load() == TOKEN
    await task
    assert world.token_file.load() == OTHER


async def test_delete_removes_only_the_record_the_bot_wrote(world: Fallback) -> None:
    """Another A record of the name — even with the same address — is not the bot's."""
    written = await world.dns_service.upsert_a(ADMIN, "created.example.net", MAIN, purpose="host")
    assert written.record is not None and written.record.record_id
    other = world.cf.add("created.example.net", MAIN)
    assert await world.dns_service.delete_a(ADMIN, "created.example.net") is True
    assert [r["id"] for r in world.cf.a("created.example.net")] == [other]
    # Replaced out of band (the saved id is gone): nothing is deleted at Cloudflare.
    await world.records_repo.save("gone.example.net", purpose="host", content=MAIN, zone_id="z1",
                                  record_id="r-gone", adopted=False, now="now", actor=ADMIN)
    stranger = world.cf.add("gone.example.net", MAIN)
    assert await world.dns_service.delete_a(ADMIN, "gone.example.net") is False
    assert [r["id"] for r in world.cf.a("gone.example.net")] == [stranger]
