"""«в подписках» acts on every issued subscription; «👁 в базовых» filters BASIC ones.

Two features of the relay card (docs/relay.md, docs/subscription.md):

* «Добавить в подписки» / «Убрать из подписок» — a new relay starts OUT of
  subscriptions; adding it creates ITS members (and nothing else) in every active
  bundle, removing it deletes them — :meth:`KeyBundleService.reconcile_relay_members`;
* «👁 в базовых» — per relay (``relays.basic_visible``) and for the main server
  (``schema_meta``) — hides a server's children from BASIC subscriptions at render
  time only, never leaving BASIC subscriptions with nothing to show.

Everything runs against the REAL relay / Xray / Hysteria2 / bundle services over a
real SQLite database (recording Xray adapters), and the subscription is checked
through the real renderer and the real read-only store of the endpoint.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
from conftest import make_relay, relay_snapshot
from test_key_bundle_reconcile import (
    ADMIN,
    DIRECT_HOST,
    EXPIRES_AT,
    OWNER,
    _Adapter,
    _Audit,
    _Ids,
    _Modules,
    _settings,
    _Users,
)

from adapters.clock import ClockProvider
from bot.handlers import admin_bundles
from bot.handlers import admin_relays as panel
from db.database import Database
from i18n import t
from models.dto import KeyBundle, TelegramUserProfile, VpnKey
from models.enums import KeyBundleKind, UserRole, VpnKeyStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from repositories.relays import MAIN_BASIC_VISIBLE_META_KEY, RelayRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.backend_health import BackendHealth
from services.errors import InvalidOperation
from services.hysteria import HysteriaService
from services.key_bundles import (
    KeyBundleService,
    ReconcileOutcome,
    ReconcileSkipReason,
    RelayMembersAction,
    child_audit_name,
)
from services.relay import RelayCatalog, RelaySnapshot, basic_has_visible_server, basic_visible_child
from services.relays import RelayService
from services.xray import XrayService
from subscription_server.render import render_links
from subscription_server.store import BundleView, ReadOnlyBundleStore

HOSTS = {"ru1": "relay1.example.net", "ru2": "relay2.example.net"}
SOURCES = {"ru1": "198.51.100.7", "ru2": "198.51.100.8"}
FINGERPRINT = "firefox"
XHTTP = ("xray_http_base", "xray_http_multi", "xray_http_antisib")


class _Estate:
    """One database, the real services wired the way bot/app.py wires them: ONE
    relay catalog shared by the relay service (its only writer) and every service
    that reads relays."""

    def __init__(self, tmp_path: Path, db: Database) -> None:
        self.tmp_path = tmp_path
        self.db = db
        self.settings = _settings(tmp_path)
        self.tcp = _Adapter()
        self.http = _Adapter()
        self.audit = _Audit()
        self.ids = _Ids()
        self.bundle_repo = KeyBundleRepository(db)
        self.vpn_keys = VpnKeyRepository(db)
        self.relay_repo = RelayRepository(db)
        self.catalog = RelayCatalog()
        clock = ClockProvider()
        health = self.health = BackendHealth()
        self.relays = RelayService(
            relays=self.relay_repo, users=_Users(), audit=self.audit, clock=clock, catalog=self.catalog  # type: ignore[arg-type]
        )
        self.xray = XrayService(
            vpn_keys=self.vpn_keys,
            users=_Users(),  # type: ignore[arg-type]
            adapter=self.tcp,  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=self.ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            backend_health=health,
            xhttp_adapter=self.http,  # type: ignore[arg-type]
            relays=self.catalog,
        )
        self.hysteria = HysteriaService(
            vpn_keys=self.vpn_keys,
            users=_Users(),  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=self.ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            modules=_Modules(),  # type: ignore[arg-type]
            relays=self.catalog,
        )
        self.service = KeyBundleService(
            bundles=self.bundle_repo,
            users=_Users(),  # type: ignore[arg-type]
            xray=self.xray,
            hysteria=self.hysteria,
            modules=_Modules(),  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=self.ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            backend_health=health,
            relays=self.catalog,
        )

    async def add_relay(self, name: str, *, in_subscriptions: bool | None = None) -> Any:
        """A relay as the service creates it — out of subscriptions unless asked."""
        extra = {} if in_subscriptions is None else {"in_subscriptions": in_subscriptions}
        return await self.relays.create(
            ADMIN, name=name, host=HOSTS[name], source_ips=SOURCES[name], label=name, **extra
        )

    async def relay(self, name: str) -> Any:
        relay = await self.relay_repo.get_by_name(name)
        assert relay is not None
        return relay

    async def create(self, kind: KeyBundleKind) -> KeyBundle:
        result = await self.service.create_bundle(
            ADMIN,
            TelegramUserProfile(OWNER, f"user{OWNER}", "User"),
            "семья",
            expires_at=EXPIRES_AT,
            fingerprint=FINGERPRINT,
            kind=kind,
        )
        return result.bundle

    async def bundle(self, bundle_id: int) -> KeyBundle:
        bundle = await self.bundle_repo.get_by_id(bundle_id)
        assert bundle is not None
        return bundle

    async def children(self, bundle_id: int) -> list[VpnKey]:
        return await self.bundle_repo.list_keys_of_bundle(bundle_id)

    async def members(self, bundle_id: int) -> list[str]:
        return sorted(child_audit_name(key) for key in await self.children(bundle_id))

    async def rows(self, bundle_id: int, *, relay: str | None = "*") -> dict[int, tuple[object, ...]]:
        """Every child (optionally of one relay) as (slot, status, expiry, fingerprint)."""
        return {
            key.id: (child_audit_name(key), key.status, key.expires_at, key.payload.get("fingerprint"))
            for key in await self.children(bundle_id)
            if relay == "*" or key.relay == relay
        }

    async def view(self, bundle_id: int) -> BundleView:
        keys = tuple(key for key in await self.children(bundle_id) if key.status is VpnKeyStatus.ACTIVE)
        return BundleView(
            bundle=await self.bundle(bundle_id),
            keys=keys,
            traffic=None,
            relays=RelaySnapshot.of(await self.relay_repo.list_all()),
            main_basic_visible=await self.relay_repo.main_basic_visible(),
        )

    async def hosts(self, bundle_id: int) -> list[str]:
        return [urlsplit(link).hostname or "" for link in render_links(await self.view(bundle_id), self.settings)]

    async def add(self, name: str, **kwargs: Any) -> Any:
        return await self.service.reconcile_relay_members(
            name, RelayMembersAction.ADD, actor_user_id=ADMIN, **kwargs
        )

    async def remove(self, name: str, **kwargs: Any) -> Any:
        return await self.service.reconcile_relay_members(
            name, RelayMembersAction.REMOVE, actor_user_id=ADMIN, **kwargs
        )

    def live_clients(self) -> int:
        return len(self.tcp.clients) + len(self.http.clients)


async def _key_count(estate: _Estate) -> int:
    row = await estate.db.conn.execute_fetchone("SELECT COUNT(*) AS n FROM vpn_keys")
    assert row is not None
    return int(row["n"])


@pytest.fixture
async def estate(tmp_path: Path) -> Any:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users = UserRepository(db)
    for uid in (ADMIN, OWNER):
        await users.upsert_profile(TelegramUserProfile(uid, f"user{uid}", "User"), UserRole.APPROVED_USER, "now")
    try:
        yield _Estate(tmp_path, db)
    finally:
        await db.close()


# ── a new relay starts out of subscriptions ───────────────────────────────────


async def test_a_new_relay_starts_out_of_subscriptions_and_new_bundles_skip_it(estate: _Estate) -> None:
    relay = await estate.add_relay("ru1")

    assert not relay.in_subscriptions and relay.basic_visible
    row = await estate.db.conn.execute_fetchone("SELECT in_subscriptions FROM relays WHERE id = ?", (relay.id,))
    assert row is not None and row["in_subscriptions"] == 0  # written by the code, not the column default
    assert estate.catalog.snapshot.for_subscriptions == ()
    bundle = await estate.create(KeyBundleKind.BASIC)
    assert await estate.members(bundle.id) == ["hysteria2", "xray_tcp"]


async def test_a_paired_relay_is_written_out_of_subscriptions(estate: _Estate) -> None:
    """The pairing completion (RelayService._complete_new) goes through
    RelayRepository.complete_new, which names the column explicitly."""
    pairing = await estate.relay_repo.create_pairing(
        kind="new", name="ru1", token="t" * 43, target_host="vpn.example.com", tcp_ports=(443,),
        udp_ports=(443,), expires_at=2_000_000_000, created_by=ADMIN, now="2026-01-01T00:00:00+00:00",
        relay_host=HOSTS["ru1"],
    )
    from models.dto import RelayAgent

    agent = RelayAgent("203.0.113.5", 22, "ssh-ed25519 AAAA", "vpn.example.com", (443,), (443,), "1", "now")
    relay = await estate.relay_repo.complete_new(
        pairing.id, name="ru1", label="ru1", host=HOSTS["ru1"],
        source_ips=(ipaddress.IPv4Network("198.51.100.7/32"),), note=None, agent=agent,
        created_by=ADMIN, now="2026-01-01T00:00:00+00:00",
    )
    assert relay is not None and not relay.in_subscriptions and relay.basic_visible


# ── «Добавить в подписки»: only this relay's members, every active bundle ──


async def test_add_creates_only_this_relays_members_in_basic_and_extended(estate: _Estate) -> None:
    await estate.add_relay("ru2", in_subscriptions=True)  # already in subscriptions
    basic = await estate.create(KeyBundleKind.BASIC)
    extended = await estate.create(KeyBundleKind.EXTENDED)
    await estate.add_relay("ru1")  # added later, out of subscriptions
    before = {bundle.id: await estate.rows(bundle.id) for bundle in (basic, extended)}
    tokens = {bundle.id: bundle.token for bundle in (basic, extended)}

    await estate.relays.update(ADMIN, (await estate.relay("ru1")).id, in_subscriptions=True)
    summary = await estate.add("ru1")

    assert [result.outcome for result in summary.results] == [ReconcileOutcome.APPLIED] * 2
    assert summary.keys_created == 2 + 5 and summary.keys_deleted == 0
    for bundle, created in ((basic, ["hysteria2_relay_ru1", "xray_tcp_relay_ru1"]),
                            (extended, sorted(["xray_tcp_relay_ru1", "hysteria2_relay_ru1",
                                               *(f"{name}_relay_ru1" for name in XHTTP)]))):
        after = await estate.rows(bundle.id)
        # Nothing else touched: every earlier child — direct, VLESS (HTTP), ru2 — is
        # the same row with the same values.
        assert {key_id: after[key_id] for key_id in before[bundle.id]} == before[bundle.id]
        added = {key_id: row for key_id, row in after.items() if key_id not in before[bundle.id]}
        assert sorted(str(row[0]) for row in added.values()) == created
        # The bundle's shared expiry and VLESS fingerprint, an active status.
        for slot, status, expires_at, fingerprint in added.values():
            assert status is VpnKeyStatus.ACTIVE and expires_at == EXPIRES_AT
            assert fingerprint == (None if str(slot).startswith("hysteria2") else FINGERPRINT)
        current = await estate.bundle(bundle.id)
        assert current.token == tokens[bundle.id] and current.kind is bundle.kind
    # Served: the ru1 group after the direct one and ru2's (relay id order).
    assert await estate.hosts(basic.id) == [DIRECT_HOST] * 2 + [HOSTS["ru2"]] * 2 + [HOSTS["ru1"]] * 2
    records = [item for item in estate.audit.items if item["action"] == "key_bundle_relay_members_added"]
    assert len(records) == 2
    details = records[0]["details"]
    assert isinstance(details, dict) and details["relay"] == "ru1" and details["relay_action"] == "add"

    again = await estate.add("ru1")
    assert {result.outcome for result in again.results} == {ReconcileOutcome.NOOP}


async def test_add_dry_run_plans_and_writes_nothing(estate: _Estate) -> None:
    await estate.create(KeyBundleKind.BASIC)
    await estate.create(KeyBundleKind.EXTENDED)
    await estate.add_relay("ru1")
    keys, clients, audits = await _key_count(estate), estate.live_clients(), len(estate.audit.items)

    plan = await estate.add("ru1", dry_run=True)

    assert [result.outcome for result in plan.results] == [ReconcileOutcome.PLANNED] * 2
    assert plan.keys_to_create == 7 and plan.keys_to_delete == 0
    assert plan.results[0].to_create == ("xray_tcp_relay_ru1", "hysteria2_relay_ru1")
    assert (await _key_count(estate), estate.live_clients(), len(estate.audit.items)) == (keys, clients, audits)
    for result in plan.results:
        assert all(not name.endswith("_relay_ru1") for name in await estate.members(result.bundle_id))


async def test_adding_a_disabled_relay_is_refused_before_anything_is_planned(estate: _Estate) -> None:
    await estate.create(KeyBundleKind.BASIC)
    relay = await estate.add_relay("ru1")
    await estate.relays.update(ADMIN, relay.id, enabled=False)

    with pytest.raises(InvalidOperation) as exc:
        await estate.add("ru1", dry_run=True)

    assert exc.value.key == "err_relay_subs_add_disabled"


async def test_a_failing_create_rolls_the_bundle_back_and_the_rest_go_on(estate: _Estate) -> None:
    first = await estate.create(KeyBundleKind.BASIC)
    second = await estate.create(KeyBundleKind.BASIC)
    await estate.add_relay("ru1", in_subscriptions=True)
    before = {bundle.id: await estate.rows(bundle.id) for bundle in (first, second)}
    clients = estate.live_clients()
    real_issue = estate.hysteria.issue
    calls = [0]

    async def fail_once(*args: Any, **kwargs: Any) -> Any:
        calls[0] += 1
        if calls[0] == 1:  # the first bundle's relay Hysteria2 member
            raise RuntimeError("hy2 exploded")
        return await real_issue(*args, **kwargs)

    estate.hysteria.issue = fail_once  # type: ignore[method-assign]

    summary = await estate.add("ru1")

    failed, applied = summary.results
    assert failed.outcome is ReconcileOutcome.FAILED and isinstance(failed.error, RuntimeError)
    assert len(failed.created_key_ids) == 1 and failed.rollback_failed_key_ids == ()
    assert await estate.vpn_keys.get_by_id(failed.created_key_ids[0]) is None
    assert await estate.rows(first.id) == before[first.id]  # exactly as it was
    assert applied.outcome is ReconcileOutcome.APPLIED and len(applied.created_key_ids) == 2
    assert estate.live_clients() == clients + 1  # only the second bundle's VLESS member
    rolled = [item for item in estate.audit.items if item["action"] == "key_bundle_reconcile_rolled_back"]
    assert len(rolled) == 1
    assert isinstance(rolled[0]["details"], dict) and rolled[0]["details"]["relay"] == "ru1"
    # A re-run finishes the job for the first bundle only.
    retry = await estate.add("ru1")
    assert [result.outcome for result in retry.results] == [ReconcileOutcome.APPLIED, ReconcileOutcome.NOOP]


async def test_an_anomalous_bundle_is_skipped_with_the_reason(estate: _Estate) -> None:
    odd = await estate.create(KeyBundleKind.BASIC)
    fine = await estate.create(KeyBundleKind.BASIC)
    await estate.add_relay("ru1", in_subscriptions=True)
    hy2 = next(key for key in await estate.children(odd.id) if key.key_type.value == "hysteria2")
    await estate.db.conn.execute(
        "UPDATE vpn_keys SET expires_at = ? WHERE id = ?", ("2031-01-01T00:00:00+00:00", hy2.id)
    )
    await estate.db.commit()
    before = await estate.rows(odd.id)

    summary = await estate.add("ru1")

    skipped, applied = summary.results
    assert skipped.outcome is ReconcileOutcome.SKIPPED and skipped.skip_reason is ReconcileSkipReason.MIXED_EXPIRY
    assert await estate.rows(odd.id) == before
    assert applied.bundle_id == fine.id and applied.outcome is ReconcileOutcome.APPLIED


async def _child(estate: _Estate, bundle_id: int, relay: str | None, key_type: VpnKeyType) -> VpnKey:
    return next(key for key in await estate.children(bundle_id) if key.relay == relay and key.key_type is key_type)


async def _set(estate: _Estate, sql: str, *params: object) -> None:
    await estate.db.conn.execute(sql, params)
    await estate.db.commit()


@pytest.mark.parametrize(
    "case",
    ["duplicate", "inactive_member", "expired", "no_active", "degraded"],
)
async def test_add_skips_every_kind_of_anomalous_bundle_untouched(estate: _Estate, case: str) -> None:
    await estate.add_relay("ru1", in_subscriptions=True)
    bundle = await estate.create(KeyBundleKind.BASIC)
    await estate.add_relay("ru2")
    expected = {
        "duplicate": ReconcileSkipReason.DUPLICATE_MEMBER,
        "inactive_member": ReconcileSkipReason.INACTIVE_CHILD,
        "expired": ReconcileSkipReason.EXPIRED,
        "no_active": ReconcileSkipReason.NO_ACTIVE_CHILDREN,
        "degraded": ReconcileSkipReason.BACKEND_DEGRADED,
    }[case]
    target = "ru2"
    if case == "duplicate":  # two active children in the direct Hysteria2 slot
        hy2 = await _child(estate, bundle.id, "ru1", VpnKeyType.HYSTERIA2)
        await _set(estate, "UPDATE vpn_keys SET relay = NULL WHERE id = ?", hy2.id)
    elif case == "inactive_member":  # a revoked child holding a slot the add targets
        target = "ru1"
        await estate.hysteria.revoke(ADMIN, (await _child(estate, bundle.id, "ru1", VpnKeyType.HYSTERIA2)).id)
    elif case == "expired":
        await _set(estate, "UPDATE vpn_keys SET expires_at = ? WHERE bundle_id = ?", "2020-01-01T00:00:00+00:00", bundle.id)
    elif case == "no_active":
        await _set(estate, "UPDATE vpn_keys SET status = 'revoked' WHERE bundle_id = ?", bundle.id)
    else:
        estate.health.mark_degraded(VpnKeyType.XRAY, "test")
    before = await estate.rows(bundle.id)

    [result] = (await estate.add(target)).results

    assert result.outcome is ReconcileOutcome.SKIPPED and result.skip_reason is expected
    assert await estate.rows(bundle.id) == before


async def test_remove_skips_a_bundle_on_a_degraded_backend(estate: _Estate) -> None:
    await estate.add_relay("ru1", in_subscriptions=True)
    bundle = await estate.create(KeyBundleKind.BASIC)
    estate.health.mark_degraded(VpnKeyType.XRAY, "test")
    before = await estate.rows(bundle.id)

    [result] = (await estate.remove("ru1")).results

    assert result.skip_reason is ReconcileSkipReason.BACKEND_DEGRADED
    assert await estate.rows(bundle.id) == before


async def test_add_with_every_member_switched_off_skips_with_no_members(
    estate: _Estate, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = await estate.create(KeyBundleKind.BASIC)
    await estate.add_relay("ru1")

    async def nothing_enabled(_member: object) -> bool:
        return False

    monkeypatch.setattr(estate.service, "_member_enabled", nothing_enabled)
    [result] = (await estate.add("ru1")).results

    assert result.bundle_id == bundle.id and result.skip_reason is ReconcileSkipReason.NO_MEMBERS


async def test_add_finishes_a_removal_of_its_own_relay_and_leaves_other_slots_alone(estate: _Estate) -> None:
    """A child of the relay left ``delete_failed`` by an earlier failure is removed
    and its slot filled afresh; a revoked child of ANOTHER relay is not touched."""
    await estate.add_relay("ru1", in_subscriptions=True)
    await estate.add_relay("ru2", in_subscriptions=True)
    bundle = await estate.create(KeyBundleKind.BASIC)
    children = await estate.children(bundle.id)
    stuck = next(key for key in children if key.relay == "ru1" and key.key_type.value == "xray")
    other = next(key for key in children if key.relay == "ru2" and key.key_type.value == "hysteria2")
    await estate.db.conn.execute("UPDATE vpn_keys SET status = 'delete_failed' WHERE id = ?", (stuck.id,))
    await estate.db.commit()
    other_before = await estate.rows(bundle.id, relay="ru2")

    [result] = (await estate.add("ru1")).results

    assert result.outcome is ReconcileOutcome.APPLIED
    assert result.to_create == ("xray_tcp_relay_ru1",) and result.deleted_key_ids == (stuck.id,)
    assert await estate.rows(bundle.id, relay="ru2") == other_before
    assert other.id in other_before


# ── «Убрать из подписок»: only this relay's members go ──────────────────────


async def test_remove_deletes_only_this_relays_members(estate: _Estate) -> None:
    await estate.add_relay("ru1", in_subscriptions=True)
    await estate.add_relay("ru2", in_subscriptions=True)
    basic = await estate.create(KeyBundleKind.BASIC)
    extended = await estate.create(KeyBundleKind.EXTENDED)
    keep = {bundle.id: {k: v for k, v in (await estate.rows(bundle.id)).items() if not str(v[0]).endswith("_ru1")}
            for bundle in (basic, extended)}
    clients = estate.live_clients()

    plan = await estate.remove("ru1", dry_run=True)
    assert plan.keys_to_delete == 2 + 5 and plan.keys_to_create == 0
    await estate.relays.update(ADMIN, (await estate.relay("ru1")).id, in_subscriptions=False)
    summary = await estate.remove("ru1")

    assert [result.outcome for result in summary.results] == [ReconcileOutcome.APPLIED] * 2
    assert summary.keys_deleted == 7 and summary.keys_created == 0
    for bundle in (basic, extended):
        assert await estate.rows(bundle.id) == keep[bundle.id]
        assert (await estate.bundle(bundle.id)).token == bundle.token
    assert estate.live_clients() == clients - 1 - 4  # basic: 1 VLESS, extended: 4 VLESS
    assert await estate.hosts(basic.id) == [DIRECT_HOST] * 2 + [HOSTS["ru2"]] * 2
    removed = [item for item in estate.audit.items if item["action"] == "key_bundle_relay_members_removed"]
    assert len(removed) == 2
    again = await estate.remove("ru1")
    assert {result.outcome for result in again.results} == {ReconcileOutcome.NOOP}


async def test_remove_skips_a_bundle_it_would_leave_without_an_active_key(estate: _Estate) -> None:
    await estate.add_relay("ru1", in_subscriptions=True)
    bundle = await estate.create(KeyBundleKind.BASIC)
    await estate.db.conn.execute(
        "UPDATE vpn_keys SET status = 'revoked' WHERE bundle_id = ? AND relay IS NULL", (bundle.id,)
    )
    await estate.db.commit()
    before = await estate.rows(bundle.id)

    [result] = (await estate.remove("ru1")).results

    assert result.outcome is ReconcileOutcome.SKIPPED and result.skip_reason is ReconcileSkipReason.WOULD_EMPTY
    assert await estate.rows(bundle.id) == before


async def test_only_a_superadmin_runs_it(estate: _Estate) -> None:
    from services.errors import AccessDenied

    await estate.add_relay("ru1", in_subscriptions=True)
    with pytest.raises(AccessDenied):
        await estate.service.reconcile_relay_members("ru1", RelayMembersAction.ADD, actor_user_id=OWNER)


# ── «👁 в базовых»: render-time only, BASIC only, never empty ──────────────────


async def test_basic_hides_a_hidden_server_extended_does_not(estate: _Estate) -> None:
    ru1 = await estate.add_relay("ru1", in_subscriptions=True)
    basic = await estate.create(KeyBundleKind.BASIC)
    extended = await estate.create(KeyBundleKind.EXTENDED)
    keys_before = {bundle.id: await estate.rows(bundle.id) for bundle in (basic, extended)}
    clients = estate.live_clients()
    extended_hosts = await estate.hosts(extended.id)
    assert await estate.hosts(basic.id) == [DIRECT_HOST] * 2 + [HOSTS["ru1"]] * 2

    assert await estate.relays.set_main_basic_visible(ADMIN, False) is False
    assert await estate.hosts(basic.id) == [HOSTS["ru1"]] * 2
    assert await estate.hosts(extended.id) == extended_hosts

    await estate.relays.set_main_basic_visible(ADMIN, True)
    await estate.relays.update(ADMIN, ru1.id, basic_visible=False)
    assert await estate.hosts(basic.id) == [DIRECT_HOST] * 2
    assert await estate.hosts(extended.id) == extended_hosts

    await estate.relays.update(ADMIN, ru1.id, basic_visible=True)
    assert await estate.hosts(basic.id) == [DIRECT_HOST] * 2 + [HOSTS["ru1"]] * 2
    # Keys and Xray were never touched: the switch is instant and reversible.
    assert {bundle.id: await estate.rows(bundle.id) for bundle in (basic, extended)} == keys_before
    assert estate.live_clients() == clients
    actions = [item["action"] for item in estate.audit.items]
    assert actions.count("relay_main_basic_visibility_changed") == 2


async def test_the_endpoint_store_reads_the_main_servers_flag(estate: _Estate) -> None:
    await estate.add_relay("ru1", in_subscriptions=True)
    bundle = await estate.create(KeyBundleKind.BASIC)
    await estate.relays.set_main_basic_visible(ADMIN, False)
    assert await estate.db.get_meta(MAIN_BASIC_VISIBLE_META_KEY) == "0"

    store = ReadOnlyBundleStore(estate.tmp_path / "vpn.db")
    await store.connect()
    try:
        view = await store.load_active_bundle(bundle.token)
    finally:
        await store.close()

    assert view is not None and view.main_basic_visible is False
    assert [urlsplit(link).hostname for link in render_links(view, estate.settings)] == [HOSTS["ru1"]] * 2


async def test_a_switch_that_would_leave_basic_empty_is_refused(estate: _Estate) -> None:
    # Only the main server: it cannot be hidden.
    with pytest.raises(InvalidOperation) as exc:
        await estate.relays.set_main_basic_visible(ADMIN, False)
    assert exc.value.key == "err_basic_would_be_empty"
    ru1 = await estate.add_relay("ru1")
    # A relay out of subscriptions does not count either.
    with pytest.raises(InvalidOperation):
        await estate.relays.set_main_basic_visible(ADMIN, False)

    await estate.relays.update(ADMIN, ru1.id, in_subscriptions=True)
    await estate.relays.set_main_basic_visible(ADMIN, False)  # ru1 is left: allowed
    for change in ({"basic_visible": False}, {"in_subscriptions": False}):
        with pytest.raises(InvalidOperation) as exc:
            await estate.relays.update(ADMIN, ru1.id, **change)
        assert exc.value.key == "err_basic_would_be_empty"
        with pytest.raises(InvalidOperation):
            await estate.relays.check_basic_keeps_a_server(ADMIN, ru1.id, **change)
    assert (await estate.relay("ru1")).basic_visible and (await estate.relay("ru1")).in_subscriptions
    assert await estate.relays.basic_has_visible_server(ADMIN)

    # Switching the relay off is never refused (an emergency action): BASIC
    # subscriptions are then served unfiltered, and the panel says so.
    await estate.relays.update(ADMIN, ru1.id, enabled=False)
    assert not await estate.relays.basic_has_visible_server(ADMIN)
    # Showing a server is always allowed.
    assert await estate.relays.set_main_basic_visible(ADMIN, True) is True


async def test_render_fails_open_when_every_server_of_a_basic_bundle_is_hidden(
    estate: _Estate, caplog: pytest.LogCaptureFixture
) -> None:
    """The panel refuses hiding the last server, but switching the last visible
    relay off is never refused: the BASIC bundle is then served unfiltered with a
    WARNING — never empty (which would 404). EXTENDED never filters at all."""
    ru1 = await estate.add_relay("ru1", in_subscriptions=True)
    basic = await estate.create(KeyBundleKind.BASIC)
    extended = await estate.create(KeyBundleKind.EXTENDED)
    await estate.relays.set_main_basic_visible(ADMIN, False)
    with caplog.at_level(logging.WARNING, logger="subscription_server.render"):
        assert await estate.hosts(basic.id) == [HOSTS["ru1"]] * 2
    assert "fail-open" not in caplog.text

    await estate.relays.update(ADMIN, ru1.id, enabled=False)
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="subscription_server.render"):
        assert await estate.hosts(basic.id) == [DIRECT_HOST] * 2
    assert "fail-open" in caplog.text

    # Every server hidden while all of them are up (state the panel cannot reach,
    # written by hand): everything is served.
    await estate.relays.update(ADMIN, ru1.id, enabled=True)
    await estate.db.conn.execute("UPDATE relays SET basic_visible = 0 WHERE id = ?", (ru1.id,))
    await estate.db.commit()
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="subscription_server.render"):
        assert await estate.hosts(basic.id) == [DIRECT_HOST] * 2 + [HOSTS["ru1"]] * 2
        assert len(await estate.hosts(extended.id)) == 10
    assert caplog.text.count("fail-open") == 1  # the basic bundle only


def test_visibility_helpers() -> None:
    shown = make_relay(1, "ru1")
    hidden = make_relay(2, "ru2", basic_visible=False)
    out = make_relay(3, "ru3", in_subscriptions=False)
    off = make_relay(4, "ru4", enabled=False)
    snapshot = relay_snapshot(hidden, out, off)
    assert not basic_has_visible_server(snapshot, main_visible=False)
    assert basic_has_visible_server(snapshot, main_visible=True)
    assert basic_has_visible_server(relay_snapshot(shown), main_visible=False)
    assert basic_visible_child(snapshot, None, main_visible=True)
    assert not basic_visible_child(snapshot, None, main_visible=False)
    assert not basic_visible_child(snapshot, "ru2", main_visible=True)
    assert basic_visible_child(snapshot, "ru3", main_visible=False)
    assert basic_visible_child(snapshot, "unknown", main_visible=False)


# ── the relay card and the list ───────────────────────────────────────────────


class _Message:
    def __init__(self) -> None:
        self.message_id = 1
        self.chat = SimpleNamespace(id=ADMIN, type="private")
        self.edits: list[tuple[str, Any]] = []

    async def edit_text(self, text: str, reply_markup: Any = None) -> None:
        self.edits.append((text, reply_markup))


class _Callback:
    def __init__(self, data: str, user_id: int = ADMIN) -> None:
        self.from_user = SimpleNamespace(id=user_id)
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


def _callbacks(markup: Any) -> list[str]:
    return [button.callback_data for row in markup.inline_keyboard for button in row]


@pytest.fixture
def services(estate: _Estate, monkeypatch: pytest.MonkeyPatch) -> Any:
    async def allow(*_args: object, **_kwargs: object) -> bool:
        return True

    monkeypatch.setattr(panel, "ensure_private_callback", allow)
    return SimpleNamespace(
        users=_Users(),
        relays=estate.relays,
        key_bundles=estate.service,
        settings=estate.settings,
        relay_health=SimpleNamespace(last_probe=lambda _relay_id: None),
    )


async def _finish_run() -> None:
    task = admin_bundles.runner.task
    assert task is not None
    await task
    assert not admin_bundles.runner.running


async def test_card_add_then_remove_runs_over_every_subscription(estate: _Estate, services: Any) -> None:
    basic = await estate.create(KeyBundleKind.BASIC)
    extended = await estate.create(KeyBundleKind.EXTENDED)
    relay = await estate.add_relay("ru1")

    card = _Callback(f"admin:relay:{relay.id}")
    await panel.relay_card(card, None, services)  # type: ignore[arg-type]
    buttons = _callbacks(card.message.edits[-1][1])
    assert f"admin:relay:{relay.id}:subs:add" in buttons and f"admin:relay:{relay.id}:basic" in buttons
    assert not any(":toggle:subs" in data for data in buttons)
    assert t("relay_basic_shown") in card.message.edits[-1][0]

    plan = _Callback(f"admin:relay:{relay.id}:subs:add")
    await panel.relay_subs_plan(plan, services)  # type: ignore[arg-type]
    text, markup = plan.message.edits[-1]
    title = t("relay_subs_title_add", label="ru1")
    assert t("relay_subs_plan_header_add", title=title, total=2, planned=2, create=7, delete=0, noop=0,
             skipped=0) in text
    assert _callbacks(markup) == [f"admin:relay:{relay.id}:subs:add:run", f"admin:relay:{relay.id}"]
    assert not (await estate.relay("ru1")).in_subscriptions  # the plan wrote nothing
    assert await estate.members(basic.id) == ["hysteria2", "xray_tcp"]

    run = _Callback(f"admin:relay:{relay.id}:subs:add:run")
    await panel.relay_subs_run(run, None, services)  # type: ignore[arg-type]
    assert run.answers[-1] == (t("aio_started"), None)
    await _finish_run()
    final, final_markup = run.message.edits[-1]
    assert t("aio_report_header", title=title, total=2, applied=2, created=7, deleted=0, noop=0, skipped=0,
             failed=0) in final
    assert _callbacks(final_markup) == [f"admin:relay:{relay.id}", "admin:relays"]  # nothing to retry
    assert run.message.edits[0][0] == t("aio_run_started", title=title)  # progress came first
    assert (await estate.relay("ru1")).in_subscriptions
    assert "xray_tcp_relay_ru1" in await estate.members(basic.id)
    assert len([m for m in await estate.members(extended.id) if m.endswith("_relay_ru1")]) == 5

    # The card now offers to remove it; the plan names subscriptions and keys.
    plan = _Callback(f"admin:relay:{relay.id}:subs:rm")
    await panel.relay_subs_plan(plan, services)  # type: ignore[arg-type]
    title = t("relay_subs_title_rm", label="ru1")
    assert t("relay_subs_plan_header_rm", title=title, total=2, planned=2, create=0, delete=7, noop=0,
             skipped=0) in plan.message.edits[-1][0]
    run = _Callback(f"admin:relay:{relay.id}:subs:rm:run")
    await panel.relay_subs_run(run, None, services)  # type: ignore[arg-type]
    await _finish_run()
    assert t("aio_report_header", title=title, total=2, applied=2, created=0, deleted=7, noop=0, skipped=0,
             failed=0) in run.message.edits[-1][0]
    assert not (await estate.relay("ru1")).in_subscriptions
    assert await estate.members(basic.id) == ["hysteria2", "xray_tcp"]


async def test_a_disabled_relay_cannot_be_added(estate: _Estate, services: Any) -> None:
    await estate.create(KeyBundleKind.BASIC)
    relay = await estate.add_relay("ru1")
    await estate.relays.update(ADMIN, relay.id, enabled=False)

    for handler, data, args in (
        (panel.relay_subs_plan, f"admin:relay:{relay.id}:subs:add", ()),
        (panel.relay_subs_run, f"admin:relay:{relay.id}:subs:add:run", (None,)),
    ):
        callback = _Callback(data)
        await handler(callback, *args, services)
        assert callback.answers[0] == (t("err_relay_subs_add_disabled", relay="ru1"), True)
    assert not (await estate.relay("ru1")).in_subscriptions
    assert admin_bundles.runner.task is None or admin_bundles.runner.task.done()


async def test_a_legacy_toggle_opens_the_plan_and_changes_nothing(estate: _Estate, services: Any) -> None:
    await estate.create(KeyBundleKind.BASIC)
    relay = await estate.add_relay("ru1")
    legacy = _Callback(f"admin:relay:{relay.id}:toggle:subs:ok")
    await panel.relay_subs_legacy_toggle(legacy, services)  # type: ignore[arg-type]
    assert f"admin:relay:{relay.id}:subs:add:run" in _callbacks(legacy.message.edits[-1][1])
    assert await estate.relay("ru1") == relay


async def test_remove_is_refused_when_basic_would_be_left_empty(estate: _Estate, services: Any) -> None:
    relay = await estate.add_relay("ru1", in_subscriptions=True)
    await estate.relays.set_main_basic_visible(ADMIN, False)
    plan = _Callback(f"admin:relay:{relay.id}:subs:rm")
    await panel.relay_subs_plan(plan, services)  # type: ignore[arg-type]
    assert plan.answers[0] == (t("err_basic_would_be_empty"), True)
    assert (await estate.relay("ru1")).in_subscriptions


async def test_basic_switches_on_the_card_and_the_list(estate: _Estate, services: Any) -> None:
    relay = await estate.add_relay("ru1", in_subscriptions=True)

    listing = _Callback("admin:relays")
    await panel.relays_panel(listing, None, services)  # type: ignore[arg-type]
    text, markup = listing.message.edits[-1]
    assert t("relays_main_line", basic=t("relay_basic_shown")) in text
    assert "admin:relays:mainbasic" in _callbacks(markup)

    main = _Callback("admin:relays:mainbasic")
    await panel.relays_main_basic_toggle(main, None, services)  # type: ignore[arg-type]
    assert not await estate.relay_repo.main_basic_visible()
    assert t("relays_main_line", basic=t("relay_basic_hidden")) in main.message.edits[-1][0]

    hide = _Callback(f"admin:relay:{relay.id}:basic")
    await panel.relay_basic_toggle(hide, None, services)  # type: ignore[arg-type]
    assert hide.answers[0] == (t("err_basic_would_be_empty"), True)
    assert (await estate.relay("ru1")).basic_visible

    await panel.relays_main_basic_toggle(_Callback("admin:relays:mainbasic"), None, services)  # type: ignore[arg-type]
    hide = _Callback(f"admin:relay:{relay.id}:basic")
    await panel.relay_basic_toggle(hide, None, services)  # type: ignore[arg-type]
    assert not (await estate.relay("ru1")).basic_visible
    assert t("relay_basic_saved_off", label="ru1") in hide.message.edits[-1][0]

    # Main hidden + the only relay switched off: the list warns about fail-open.
    await estate.relays.update(ADMIN, relay.id, basic_visible=True)
    await estate.relays.set_main_basic_visible(ADMIN, False)
    await estate.relays.update(ADMIN, relay.id, enabled=False)
    listing = _Callback("admin:relays")
    await panel.relays_panel(listing, None, services)  # type: ignore[arg-type]
    assert t("relays_basic_fail_open") in listing.message.edits[-1][0]


async def test_a_second_run_is_refused_while_one_is_running(estate: _Estate, services: Any) -> None:
    import asyncio

    relay = await estate.add_relay("ru1")
    gate = asyncio.Event()

    async def slow(*_args: object, **kwargs: object) -> Any:
        if not kwargs.get("dry_run"):
            await gate.wait()
        from services.key_bundles import ReconcileSummary

        return ReconcileSummary(())

    services.key_bundles = SimpleNamespace(reconcile_relay_members=slow)
    first = _Callback(f"admin:relay:{relay.id}:subs:add:run")
    await panel.relay_subs_run(first, None, services)  # type: ignore[arg-type]
    assert admin_bundles.runner.running
    for handler, data, args in (
        (panel.relay_subs_plan, f"admin:relay:{relay.id}:subs:rm", ()),
        (panel.relay_subs_run, f"admin:relay:{relay.id}:subs:rm:run", (None,)),
    ):
        callback = _Callback(data)
        await handler(callback, *args, services)
        assert callback.answers == [(t("aio_already_running"), True)]
    assert (await estate.relay("ru1")).in_subscriptions  # the second action changed nothing
    gate.set()
    await _finish_run()


async def test_a_failing_plan_and_a_failing_run_are_reported(estate: _Estate, services: Any) -> None:
    relay = await estate.add_relay("ru1")

    async def boom(*_args: object, **_kwargs: object) -> Any:
        raise InvalidOperation("boom", key="err_relay_subs_add_disabled", params={"relay": "ru1"})

    services.key_bundles = SimpleNamespace(reconcile_relay_members=boom)
    plan = _Callback(f"admin:relay:{relay.id}:subs:add")
    await panel.relay_subs_plan(plan, services)  # type: ignore[arg-type]
    title = t("relay_subs_title_add", label="ru1")
    error = t("err_relay_subs_add_disabled", relay="ru1")
    assert plan.message.edits[-1][0] == t("aio_failed", title=title, error=error)

    run = _Callback(f"admin:relay:{relay.id}:subs:add:run")
    await panel.relay_subs_run(run, None, services)  # type: ignore[arg-type]
    await _finish_run()
    final, markup = run.message.edits[-1]
    assert final == t("aio_failed", title=title, error=error)
    assert f"admin:relay:{relay.id}:subs:add" in _callbacks(markup)  # «🔁 Повторить»


async def test_hiding_the_only_server_from_the_list_is_refused(estate: _Estate, services: Any) -> None:
    main = _Callback("admin:relays:mainbasic")
    await panel.relays_main_basic_toggle(main, None, services)  # type: ignore[arg-type]
    assert main.answers[0] == (t("err_basic_would_be_empty"), True)
    assert await estate.relay_repo.main_basic_visible()


async def test_actions_on_a_deleted_relay_lead_to_the_list(estate: _Estate, services: Any) -> None:
    relay = await estate.add_relay("ru1")
    await estate.relays.delete(ADMIN, relay.id, with_keys=False)
    for handler, data, args in (
        (panel.relay_subs_plan, f"admin:relay:{relay.id}:subs:add", ()),
        (panel.relay_subs_legacy_toggle, f"admin:relay:{relay.id}:toggle:subs", ()),
        (panel.relay_subs_run, f"admin:relay:{relay.id}:subs:add:run", (None,)),
        (panel.relay_basic_toggle, f"admin:relay:{relay.id}:basic", (None,)),
    ):
        callback = _Callback(data)
        await handler(callback, *args, services)
        assert callback.answers[0] == (t("err_relay_not_found"), True), data
        assert "admin:relay:add" in _callbacks(callback.message.edits[-1][1])


# ── v45: existing relays keep everything and are shown in basic ───────────────


async def test_v45_upgrade_keeps_in_subscriptions_and_shows_every_relay(tmp_path: Path) -> None:
    from test_schema_upgrade_path import _materialise

    db_path = tmp_path / "vpn.db"
    await _materialise(db_path, 44)
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
        relays = {relay.name: relay for relay in await RelayRepository(db).list_all()}
        assert (relays["ru1"].in_subscriptions, relays["ru2"].in_subscriptions) == (True, False)
        assert relays["ru1"].basic_visible and relays["ru2"].basic_visible
        assert await RelayRepository(db).main_basic_visible()  # no schema_meta key: shown
    finally:
        await db.close()
