"""Admin composition reconcile of all-in-one bundles.

``KeyBundleService.reconcile_composition`` / ``reconcile_all`` run against the
REAL ``XrayService``/``HysteriaService`` and a real SQLite DB with recording Xray
adapters, so each assertion covers the backend side and the database side at
once. The rendered subscription is checked through the real renderer of the
subscription endpoint. The admin «All-in-One» section is driven through its
handlers with stand-in callbacks.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import unquote, urlsplit

import pytest
from conftest import make_relay, relay_snapshot

from adapters.clock import ClockProvider
from bot.handlers import admin_bundles
from bot.keyboards.admin import admin_group_keyboard
from config.settings import Settings
from db.database import Database
from i18n import t
from models.dto import KeyBundle, TelegramUserProfile, User, VpnKey
from models.enums import KeyBundleKind, KeyBundleStatus, UserRole, VpnKeyStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from repositories.relays import RelayRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.backend_health import BackendHealth
from services.errors import AccessDenied
from services.hysteria import HysteriaService
from services.key_bundles import (
    KeyBundleService,
    ReconcileOutcome,
    ReconcileResult,
    ReconcileSkipReason,
    ReconcileSummary,
    child_audit_name,
)
from services.key_naming import key_member_name
from services.relay import EMPTY_RELAYS, RelayCatalog
from services.xray import XrayService
from subscription_server.render import render_links
from subscription_server.store import BundleView

OWNER = 100
OTHER = 101
GUEST = 102
ADMIN = 1
FLAG = "🇫🇮"
DIRECT_HOST = "vpn.example.com"
RELAY_HOST = "relay.anycastedge.net"
EXPIRES_AT = "2030-01-01T00:00:00+00:00"
XHTTP = {"xray_http_base", "xray_http_multi", "xray_http_antisib"}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = dict(
        bot_token="token",
        admin_ids=frozenset({ADMIN}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="vless-in",
        xray_public_host=DIRECT_HOST,
        xray_public_port=443,
        xray_reality_public_key="public",
        xray_sni="example.com",
        xray_flow="xtls-rprx-vision",
        xray_fingerprint="chrome",
        xray_network_type="tcp",
        xray_short_id="abcd",
        xray_manage_short_ids=False,
        xray_allow_restart_on_rollback=False,
        xray_stats_server="",
        awg_config_path=tmp_path / "awg.conf",
        awg_interface="awg0",
        awg_network="10.0.0.0/24",
        awg_server_address="10.0.0.1",
        awg_endpoint_host=DIRECT_HOST,
        awg_endpoint_port=443,
        awg_server_public_key="server-public",
        awg_client_dns="1.1.1.1",
        awg_mtu=None,
        awg_allowed_ips="0.0.0.0/0, ::/0",
        awg_persistent_keepalive=25,
        awg_use_preshared_key=True,
        default_proxy_type="",
        default_proxy_host="",
        default_proxy_port=None,
        default_proxy_login="",
        default_proxy_password="",
        default_proxy_note="",
        audit_retention_days=180,
        config_backup_keep_last=20,
        xray_xhttp_enabled=True,
        xray_xhttp_inbound_tag="vless-xhttp-reality",
        xray_xhttp_port=8443,
        xray_xhttp_path="/v1/messages/stream",
        xray_xhttp_mode="stream-one",
        hysteria2_enabled=True,
        hysteria2_host=DIRECT_HOST,
        hysteria2_port=443,
        hysteria2_sni="anycastedge.duckdns.org",
        hysteria2_insecure=False,
        subscription_enabled=True,
    )
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


# ── harness ───────────────────────────────────────────────────────────────────


class _Users:
    """ADMIN is the superadmin, GUEST a pending user, everyone else approved."""

    def _role(self, user_id: int) -> UserRole:
        if user_id == ADMIN:
            return UserRole.SUPERADMIN
        if user_id == GUEST:
            return UserRole.PENDING_USER
        return UserRole.APPROVED_USER

    async def get_user(self, user_id: int) -> User:
        return User(user_id, f"user{user_id}", "User", self._role(user_id), "now", "now", None)

    async def require_approved_or_admin(self, user_id: int) -> User:
        user = await self.get_user(user_id)
        if user.role is UserRole.PENDING_USER:
            raise AccessDenied("pending", key="err_insufficient_rights")
        return user

    async def require_superadmin(self, user_id: int) -> User:
        user = await self.get_user(user_id)
        if user.role is not UserRole.SUPERADMIN:
            raise AccessDenied("Недостаточно прав", key="err_insufficient_rights")
        return user


class _Audit:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    async def write_best_effort(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    async def write(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    def actions(self) -> list[str]:
        return [str(item.get("action")) for item in self.items]

    def bundle_records(self) -> list[dict[str, object]]:
        return [item for item in self.items if str(item.get("action", "")).startswith("key_bundle_reconcile")
                or item.get("action") == "key_bundle_composition_reconciled"]


class _Modules:
    async def is_enabled(self, name: str) -> bool:
        return True


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def _next(self) -> int:
        self._n += 1
        return self._n

    def uuid4(self) -> str:
        return f"00000000-0000-4000-8000-{self._next():012d}"

    def generated_key_name(self, prefix: str) -> str:
        return f"{prefix}_{self._next():05d}"

    def xray_short_id(self) -> str:
        return "ff69b6f523de0d17"

    def hysteria2_label(self) -> str:
        return f"hy2_{self._next():016x}"


class _Adapter:
    """One Xray inbound: tracks live clients; can fail the Nth add/remove once."""

    def __init__(self) -> None:
        self.clients: list[dict[str, str]] = []
        self.add_calls = 0
        self.remove_calls = 0
        self.fail_add_on: int | None = None
        self.fail_remove_on: int | None = None

    async def add_client(self, **kwargs: object) -> object:
        self.add_calls += 1
        if self.fail_add_on == self.add_calls:
            raise RuntimeError("xray apply exploded")
        self.clients.append({"id": str(kwargs["uuid_value"]), "email": str(kwargs["email_label"])})
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        self.remove_calls += 1
        if self.fail_remove_on == self.remove_calls:
            raise RuntimeError("xray remove exploded")
        self.clients = [c for c in self.clients if c["id"] != kwargs.get("uuid_value")]

    def find_client(self, *, uuid_value: str | None = None, email_label: str | None = None) -> dict[str, str] | None:
        for client in self.clients:
            if (uuid_value and client["id"] == uuid_value) or (email_label and client["email"] == email_label):
                return dict(client)
        return None

    def list_clients(self) -> list[dict[str, str]]:
        return [dict(c) for c in self.clients]

    def list_short_ids(self) -> set[str]:
        return set()


class _World:
    """One DB and one pair of adapters; services are (re)built per settings.

    Rebuilding over the same DB is how a test changes ``.env`` or the relays
    between creating a bundle and reconciling it — e.g. bundles made before the
    relay ``ru1`` was added («в подписках») in the admin panel.
    """

    def __init__(self, tmp_path: Path, db: Database) -> None:
        self.tmp_path = tmp_path
        self.db = db
        self.tcp = _Adapter()
        self.http = _Adapter()
        self.audit = _Audit()
        self.health = BackendHealth()
        self.ids = _Ids()
        self.repo = KeyBundleRepository(db)
        self.vpn_keys = VpnKeyRepository(db)
        self.configure()

    def configure(self, *, relay_enabled: bool = False, **overrides: object) -> None:
        self.settings = _settings(self.tmp_path, **overrides)
        self.catalog = RelayCatalog(
            relay_snapshot(make_relay(1, "ru1", host=RELAY_HOST)) if relay_enabled else EMPTY_RELAYS
        )
        clock = ClockProvider()
        self.xray = XrayService(
            vpn_keys=self.vpn_keys,
            users=_Users(),  # type: ignore[arg-type]
            adapter=self.tcp,  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=self.ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            backend_health=self.health,
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
            bundles=self.repo,
            users=_Users(),  # type: ignore[arg-type]
            xray=self.xray,
            hysteria=self.hysteria,
            modules=_Modules(),  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=self.ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            backend_health=self.health,
            relays=self.catalog,
        )

    async def create(
        self,
        kind: KeyBundleKind = KeyBundleKind.EXTENDED,
        *,
        owner: int = OWNER,
        fingerprint: str | None = None,
        note: str | None = "семья",
    ) -> KeyBundle:
        result = await self.service.create_bundle(
            ADMIN,
            TelegramUserProfile(owner, f"user{owner}", "User"),
            note,
            expires_at=EXPIRES_AT,
            fingerprint=fingerprint,
            kind=kind,
            allow_pending_owner=owner == GUEST,
        )
        return result.bundle

    async def bundle(self, bundle_id: int) -> KeyBundle:
        bundle = await self.repo.get_by_id(bundle_id)
        assert bundle is not None
        return bundle

    async def children(self, bundle_id: int) -> list[VpnKey]:
        return await self.repo.list_keys_of_bundle(bundle_id)

    async def members(self, bundle_id: int) -> list[str]:
        return sorted(child_audit_name(key) for key in await self.children(bundle_id))

    async def reconcile(self, bundle_id: int, **kwargs: Any) -> ReconcileResult:
        return await self.service.reconcile_composition(bundle_id, actor_user_id=ADMIN, **kwargs)

    async def links(self, bundle_id: int) -> tuple[str, ...]:
        keys = tuple(key for key in await self.children(bundle_id) if key.status is VpnKeyStatus.ACTIVE)
        view = BundleView(bundle=await self.bundle(bundle_id), keys=keys, traffic=None, relays=self.catalog.snapshot)
        return render_links(view, self.settings)

    def live_clients(self) -> int:
        return len(self.tcp.clients) + len(self.http.clients)

    async def key_count(self) -> int:
        row = await self.db.conn.execute_fetchone("SELECT COUNT(*) AS cnt FROM vpn_keys")
        assert row is not None
        return int(row["cnt"])


@pytest.fixture
async def world(tmp_path: Path) -> Any:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users = UserRepository(db)
    for uid in (ADMIN, OWNER, OTHER, GUEST):
        await users.upsert_profile(TelegramUserProfile(uid, f"user{uid}", "User"), UserRole.APPROVED_USER, "now")
    # The relay row a relay key must reference; whether new bundles get members
    # through it is the services' catalog, switched by _World.configure.
    await RelayRepository(db).create(
        name="ru1",
        label="relay",
        host=RELAY_HOST,
        source_ips=(ipaddress.IPv4Network("198.51.100.7/32"),),
        now="2026-01-01T00:00:00+00:00",
    )
    try:
        yield _World(tmp_path, db)
    finally:
        await db.close()


def _fragment(link: str) -> str:
    return unquote(urlsplit(link).fragment)


def _basic_tail(link: str) -> str:
    """How a basic-subscription entry's name ends: the flag, plus "(alt.)" for hy2."""
    return f"{FLAG}(alt.)" if link.startswith("hysteria2://") else FLAG


def _host(link: str) -> str:
    return urlsplit(link).hostname or ""


# ── extended → basic ──────────────────────────────────────────────────────────


async def test_extended_to_basic_without_relay_deletes_the_xhttp_children(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.EXTENDED)
    assert len(await world.children(bundle.id)) == 5
    http_ids = {key.id for key in await world.children(bundle.id) if key_member_name(key) in XHTTP}

    result = await world.reconcile(bundle.id, target_kind=KeyBundleKind.BASIC)

    assert result.outcome is ReconcileOutcome.APPLIED
    assert set(result.deleted_key_ids) == http_ids
    assert result.created_key_ids == ()
    assert set(result.to_delete) == XHTTP
    after = await world.bundle(bundle.id)
    assert after.kind is KeyBundleKind.BASIC
    assert after.token == bundle.token
    assert await world.members(bundle.id) == ["hysteria2", "xray_tcp"]
    # Backend side: the three XHTTP clients are gone, the TCP one stays.
    assert world.http.clients == []
    assert len(world.tcp.clients) == 1
    # The subscription now serves two entries named like standalone keys, hy2 marked "(alt.)".
    links = await world.links(bundle.id)
    assert len(links) == 2
    assert all(_fragment(link).endswith(f"_{_basic_tail(link)}") for link in links)
    # One bundle-level audit record with the kinds and the key ids.
    [record] = world.audit.bundle_records()
    assert record["action"] == "key_bundle_composition_reconciled"
    details = record["details"]
    assert isinstance(details, dict)
    assert details["kind_before"] == "extended" and details["kind_after"] == "basic"
    assert set(details["deleted_key_ids"]) == http_ids  # type: ignore[arg-type]


async def test_extended_to_basic_with_relay_creates_relay_members_and_deletes_xhttp(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.EXTENDED)  # made before the relay existed
    world.configure(relay_enabled=True)

    result = await world.reconcile(bundle.id, target_kind=KeyBundleKind.BASIC)

    assert result.outcome is ReconcileOutcome.APPLIED
    assert result.to_create == ("xray_tcp_relay_ru1", "hysteria2_relay_ru1")
    assert len(result.created_key_ids) == 2
    assert len(result.deleted_key_ids) == 3
    after = await world.bundle(bundle.id)
    assert after.kind is KeyBundleKind.BASIC
    assert after.token == bundle.token
    assert await world.members(bundle.id) == ["hysteria2", "hysteria2_relay_ru1", "xray_tcp", "xray_tcp_relay_ru1"]
    # The new children carry the bundle's owner, note and expiry.
    for key in await world.children(bundle.id):
        assert key.owner_user_id == OWNER
        assert key.expires_at == EXPIRES_AT
        assert key.note == "семья"
    links = await world.links(bundle.id)
    assert len(links) == 4
    assert [_host(link) for link in links] == [DIRECT_HOST, DIRECT_HOST, RELAY_HOST, RELAY_HOST]
    assert all(_fragment(link).endswith(f"_{_basic_tail(link)}") for link in links[:2])
    # The relay's label (default "relay") is glued to the flag.
    assert all(_fragment(link).endswith(f"_relay{_basic_tail(link)}") for link in links[2:])


async def test_top_up_of_a_basic_bundle_only_adds_the_relay_members(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.BASIC)
    before = {key.id for key in await world.children(bundle.id)}
    world.configure(relay_enabled=True)

    result = await world.reconcile(bundle.id)

    assert result.outcome is ReconcileOutcome.APPLIED
    assert result.to_create == ("xray_tcp_relay_ru1", "hysteria2_relay_ru1")
    assert result.deleted_key_ids == ()
    assert before <= {key.id for key in await world.children(bundle.id)}
    assert (await world.bundle(bundle.id)).kind is KeyBundleKind.BASIC
    assert len(await world.links(bundle.id)) == 4


async def test_top_up_of_a_guest_bundle_passes_the_pending_owner_allowance(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.BASIC, owner=GUEST)
    world.configure(relay_enabled=True)

    result = await world.reconcile(bundle.id)

    assert result.outcome is ReconcileOutcome.APPLIED
    assert len(result.created_key_ids) == 2


# ── idempotency and dry run ───────────────────────────────────────────────────


async def test_second_call_is_a_noop(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.EXTENDED)
    world.configure(relay_enabled=True)
    await world.reconcile(bundle.id, target_kind=KeyBundleKind.BASIC)
    keys, clients, audits = await world.key_count(), world.live_clients(), len(world.audit.items)

    again = await world.reconcile(bundle.id, target_kind=KeyBundleKind.BASIC)
    top_up = await world.reconcile(bundle.id)

    assert again.outcome is ReconcileOutcome.NOOP
    assert top_up.outcome is ReconcileOutcome.NOOP
    assert (await world.key_count(), world.live_clients(), len(world.audit.items)) == (keys, clients, audits)


async def test_dry_run_returns_the_plan_and_writes_nothing(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.EXTENDED)
    world.configure(relay_enabled=True)
    keys, clients, audits = await world.key_count(), world.live_clients(), len(world.audit.items)
    adds, removes = world.tcp.add_calls + world.http.add_calls, world.tcp.remove_calls + world.http.remove_calls

    plan = await world.reconcile(bundle.id, target_kind=KeyBundleKind.BASIC, dry_run=True)

    assert plan.outcome is ReconcileOutcome.PLANNED
    assert plan.to_create == ("xray_tcp_relay_ru1", "hysteria2_relay_ru1")
    assert sorted(plan.to_delete) == sorted(XHTTP)
    assert plan.kind_before is KeyBundleKind.EXTENDED and plan.kind_after is KeyBundleKind.BASIC
    assert plan.created_key_ids == () and plan.deleted_key_ids == ()
    assert (await world.key_count(), world.live_clients(), len(world.audit.items)) == (keys, clients, audits)
    assert world.tcp.add_calls + world.http.add_calls == adds
    assert world.tcp.remove_calls + world.http.remove_calls == removes
    assert (await world.bundle(bundle.id)).kind is KeyBundleKind.EXTENDED


# ── failures ──────────────────────────────────────────────────────────────────


async def test_create_failing_on_the_second_member_rolls_back_the_first(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.BASIC)
    world.configure(relay_enabled=True)
    before = await world.children(bundle.id)
    world.hysteria.issue = AsyncMock(side_effect=RuntimeError("hy2 exploded"))  # type: ignore[method-assign]

    result = await world.reconcile(bundle.id)

    assert result.outcome is ReconcileOutcome.FAILED
    assert isinstance(result.error, RuntimeError)
    assert len(result.created_key_ids) == 1  # the relay VLESS child, then undone
    assert result.rollback_failed_key_ids == ()
    # The bundle is exactly as it was: same children, same kind, no live extra client.
    assert [key.id for key in await world.children(bundle.id)] == [key.id for key in before]
    assert await world.vpn_keys.get_by_id(result.created_key_ids[0]) is None
    assert len(world.tcp.clients) == 1
    after = await world.bundle(bundle.id)
    assert after.kind is KeyBundleKind.BASIC and after.status is KeyBundleStatus.ACTIVE
    [record] = world.audit.bundle_records()
    assert record["action"] == "key_bundle_reconcile_rolled_back"


async def test_delete_failing_midway_returns_partial_and_a_rerun_finishes(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.EXTENDED)
    world.http.fail_remove_on = world.http.remove_calls + 2  # the second XHTTP delete

    partial = await world.reconcile(bundle.id, target_kind=KeyBundleKind.BASIC)

    assert partial.outcome is ReconcileOutcome.PARTIAL
    assert len(partial.deleted_key_ids) == 1
    assert len(partial.to_delete) == 3
    assert (await world.bundle(bundle.id)).kind is KeyBundleKind.EXTENDED  # kind left alone
    statuses = sorted(key.status.value for key in await world.children(bundle.id) if key_member_name(key) in XHTTP)
    assert statuses == ["active", "delete_failed"]
    assert world.audit.bundle_records()[-1]["action"] == "key_bundle_reconcile_partial"

    again = await world.reconcile(bundle.id, target_kind=KeyBundleKind.BASIC)

    assert again.outcome is ReconcileOutcome.APPLIED
    assert len(again.deleted_key_ids) == 2  # the failed one and the untouched one
    assert (await world.bundle(bundle.id)).kind is KeyBundleKind.BASIC
    assert await world.members(bundle.id) == ["hysteria2", "xray_tcp"]
    assert world.http.clients == []


async def test_a_failed_rollback_does_not_block_the_retry(world: _World) -> None:
    """Create fails, then the rollback's delete fails too: the child is left
    attached in delete_failed. A re-run finishes that removal and fills the slot
    afresh instead of skipping the bundle forever."""
    bundle = await world.create(KeyBundleKind.BASIC)
    world.configure(relay_enabled=True)
    world.hysteria.issue = AsyncMock(side_effect=RuntimeError("hy2 exploded"))  # type: ignore[method-assign]
    world.tcp.fail_remove_on = world.tcp.remove_calls + 1

    failed = await world.reconcile(bundle.id)

    assert failed.outcome is ReconcileOutcome.FAILED
    [stuck_id] = failed.rollback_failed_key_ids
    stuck = await world.vpn_keys.get_by_id(stuck_id)
    assert stuck is not None and stuck.status is VpnKeyStatus.DELETE_FAILED
    assert stuck_id in [key.id for key in await world.children(bundle.id)]  # still attached
    assert world.audit.bundle_records()[-1]["action"] == "key_bundle_reconcile_rollback_failed"

    world.configure(relay_enabled=True)  # both backends healthy again
    plan = await world.reconcile(bundle.id, dry_run=True)
    assert plan.outcome is ReconcileOutcome.PLANNED
    assert plan.to_create == ("xray_tcp_relay_ru1", "hysteria2_relay_ru1")
    assert plan.to_delete == ("xray_tcp_relay_ru1",)

    retry = await world.reconcile(bundle.id)

    assert retry.outcome is ReconcileOutcome.APPLIED
    assert retry.deleted_key_ids == (stuck_id,)
    assert await world.vpn_keys.get_by_id(stuck_id) is None
    assert await world.members(bundle.id) == ["hysteria2", "hysteria2_relay_ru1", "xray_tcp", "xray_tcp_relay_ru1"]
    assert all(key.status is VpnKeyStatus.ACTIVE for key in await world.children(bundle.id))
    assert len(world.tcp.clients) == 2  # direct + the new relay one; the stuck client is gone
    assert (await world.reconcile(bundle.id)).outcome is ReconcileOutcome.NOOP


async def test_reconcile_all_stops_between_bundles_when_asked(world: _World) -> None:
    first = await world.create(KeyBundleKind.EXTENDED)
    second = await world.create(KeyBundleKind.EXTENDED)
    third = await world.create(KeyBundleKind.EXTENDED)
    processed: list[int] = []

    async def on_progress(done: int, total: int) -> None:
        processed.append(done)

    summary = await world.service.reconcile_all(
        actor_user_id=ADMIN,
        target_kind=KeyBundleKind.BASIC,
        on_progress=on_progress,
        should_stop=lambda: len(processed) >= 1,
    )

    assert [result.bundle_id for result in summary.results] == [first.id]
    assert summary.remaining == 2
    assert (await world.bundle(first.id)).kind is KeyBundleKind.BASIC
    for untouched in (second, third):
        assert (await world.bundle(untouched.id)).kind is KeyBundleKind.EXTENDED
        assert len(await world.children(untouched.id)) == 5


# ── skipped bundles ───────────────────────────────────────────────────────────


async def test_mixed_expiry_duplicate_and_degraded_bundles_are_skipped_others_processed(world: _World) -> None:
    mixed = await world.create(KeyBundleKind.EXTENDED)
    duplicate = await world.create(KeyBundleKind.EXTENDED)
    normal = await world.create(KeyBundleKind.EXTENDED)
    hy2_child = next(k for k in await world.children(mixed.id) if k.key_type is VpnKeyType.HYSTERIA2)
    await world.db.conn.execute(
        "UPDATE vpn_keys SET expires_at = ? WHERE id = ?", ("2031-01-01T00:00:00+00:00", hy2_child.id)
    )
    await world.db.commit()
    extra = (await world.xray.create_xray_key(ADMIN, TelegramUserProfile(OWNER, "u", "U"), None)).key
    await world.repo.attach_key_to_bundle(extra.id, duplicate.id, "now")

    summary = await world.service.reconcile_all(actor_user_id=ADMIN, target_kind=KeyBundleKind.BASIC)

    by_id = {result.bundle_id: result for result in summary.results}
    assert by_id[mixed.id].skip_reason is ReconcileSkipReason.MIXED_EXPIRY
    assert by_id[duplicate.id].skip_reason is ReconcileSkipReason.DUPLICATE_MEMBER
    assert "xray_tcp" in by_id[duplicate.id].anomalies[0]
    assert by_id[normal.id].outcome is ReconcileOutcome.APPLIED
    # Skipped bundles are untouched.
    for skipped in (mixed, duplicate):
        assert (await world.bundle(skipped.id)).kind is KeyBundleKind.EXTENDED
    assert len(await world.children(mixed.id)) == 5
    assert len(await world.children(duplicate.id)) == 6


async def test_degraded_xray_skips_bundles_that_touch_it_and_processes_the_rest(world: _World) -> None:
    needs_xray = await world.create(KeyBundleKind.EXTENDED)
    world.configure(xray_xhttp_enabled=False)
    kind_only = await world.create(KeyBundleKind.EXTENDED)  # XHTTP off: tcp + hy2 only
    world.configure()
    world.health.mark_degraded(VpnKeyType.XRAY, "test")

    summary = await world.service.reconcile_all(actor_user_id=ADMIN, target_kind=KeyBundleKind.BASIC)

    by_id = {result.bundle_id: result for result in summary.results}
    assert by_id[needs_xray.id].outcome is ReconcileOutcome.SKIPPED
    assert by_id[needs_xray.id].skip_reason is ReconcileSkipReason.BACKEND_DEGRADED
    assert len(await world.children(needs_xray.id)) == 5
    assert by_id[kind_only.id].outcome is ReconcileOutcome.APPLIED
    assert (await world.bundle(kind_only.id)).kind is KeyBundleKind.BASIC


async def test_inactive_member_child_skips_and_expired_bundle_skips(world: _World) -> None:
    revoked_child = await world.create(KeyBundleKind.BASIC)
    hy2 = next(k for k in await world.children(revoked_child.id) if k.key_type is VpnKeyType.HYSTERIA2)
    await world.hysteria.revoke(ADMIN, hy2.id)
    expired = await world.create(KeyBundleKind.BASIC)
    for key in await world.children(expired.id):
        await world.vpn_keys.set_status(key.id, VpnKeyStatus.REVOKED, "now")

    first = await world.reconcile(revoked_child.id)
    second = await world.reconcile(expired.id)

    assert first.skip_reason is ReconcileSkipReason.INACTIVE_CHILD
    assert second.skip_reason is ReconcileSkipReason.NO_ACTIVE_CHILDREN


async def test_only_active_bundles_and_only_a_superadmin(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.EXTENDED)
    await world.service.revoke_bundle(ADMIN, bundle.id)
    assert (await world.reconcile(bundle.id)).skip_reason is ReconcileSkipReason.NOT_ACTIVE
    with pytest.raises(AccessDenied):
        await world.service.reconcile_composition(bundle.id, actor_user_id=OWNER)
    with pytest.raises(AccessDenied):
        await world.service.reconcile_all(actor_user_id=OWNER)


# ── fingerprint ───────────────────────────────────────────────────────────────


async def test_new_vless_child_inherits_the_existing_fingerprint(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.BASIC, fingerprint="firefox")
    world.configure(relay_enabled=True)

    result = await world.reconcile(bundle.id)

    created = [await world.vpn_keys.get_by_id(key_id) for key_id in result.created_key_ids]
    [vless] = [key for key in created if key is not None and key.key_type is VpnKeyType.XRAY]
    assert vless.payload["fingerprint"] == "firefox"
    assert "fp=firefox" in (await world.links(bundle.id))[2]


async def test_bundle_without_a_fingerprint_keeps_the_default(world: _World) -> None:
    bundle = await world.create(KeyBundleKind.BASIC)
    world.configure(relay_enabled=True)

    result = await world.reconcile(bundle.id)

    created = [await world.vpn_keys.get_by_id(key_id) for key_id in result.created_key_ids]
    [vless] = [key for key in created if key is not None and key.key_type is VpnKeyType.XRAY]
    assert vless.payload["fingerprint"] is None


# ── repository ────────────────────────────────────────────────────────────────


async def test_set_kind_validates_and_list_ids_by_status(world: _World) -> None:
    first = await world.create(KeyBundleKind.EXTENDED)
    second = await world.create(KeyBundleKind.BASIC)
    await world.service.revoke_bundle(ADMIN, second.id)
    assert await world.repo.list_ids_by_status(KeyBundleStatus.ACTIVE) == [first.id]
    await world.repo.set_kind(first.id, KeyBundleKind.BASIC, now="now")
    assert (await world.bundle(first.id)).kind is KeyBundleKind.BASIC
    with pytest.raises(ValueError):
        await world.repo.set_kind(first.id, "mega", now="now")
    with pytest.raises(RuntimeError):
        await world.repo.set_kind(9999, KeyBundleKind.BASIC, now="now")


# ── admin UI ──────────────────────────────────────────────────────────────────


class _Message:
    def __init__(self) -> None:
        self.message_id = 1
        self.chat = SimpleNamespace(id=ADMIN)
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))


class _Callback:
    def __init__(self, data: str, user_id: int = ADMIN) -> None:
        self.from_user = SimpleNamespace(id=user_id)
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


async def _allow_private(*_args: object, **_kwargs: object) -> bool:
    return True


@pytest.fixture(autouse=True)
def _private_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bot.handlers.admin_bundles.ensure_private_callback", _allow_private)


def _services(world: _World) -> Any:
    return SimpleNamespace(settings=world.settings, users=_Users(), key_bundles=world.service)


def _callbacks(markup: object) -> list[str]:
    return [button.callback_data for row in markup.inline_keyboard for button in row]  # type: ignore[attr-defined]


def test_admin_panel_shows_the_section_only_with_subscriptions_on() -> None:
    # «All-in-One» sits in the «Протоколы и маршрутизация» section of the panel.
    assert "admin:aio" in _callbacks(admin_group_keyboard("infra", subscription_enabled=True))
    assert "admin:aio" not in _callbacks(admin_group_keyboard("infra", subscription_enabled=False))
    assert "admin:aio" not in _callbacks(admin_group_keyboard("infra"))


@pytest.mark.parametrize(
    ("handler", "data"),
    [
        (admin_bundles.admin_bundles_panel, "admin:aio"),
        (admin_bundles.admin_bundles_plan, "admin:aio:plan:basic"),
        (admin_bundles.admin_bundles_run, "admin:aio:run:basic"),
        (admin_bundles.admin_bundles_run, "admin:aio:run:top"),
    ],
)
async def test_non_superadmin_is_refused_by_every_handler(world: _World, handler: Any, data: str) -> None:
    bundle = await world.create(KeyBundleKind.EXTENDED)
    callback = _Callback(data, user_id=OWNER)

    await handler(callback, _services(world))

    assert callback.answers and callback.answers[-1][1] is True  # an alert
    assert callback.message.edits == []
    assert admin_bundles.runner.task is None or admin_bundles.runner.task.done()
    assert (await world.bundle(bundle.id)).kind is KeyBundleKind.EXTENDED


async def test_section_refused_while_subscriptions_are_off(world: _World) -> None:
    world.configure(subscription_enabled=False)
    callback = _Callback("admin:aio")
    await admin_bundles.admin_bundles_panel(callback, _services(world))
    assert callback.answers[-1] == (t("err_subscription_disabled"), True)


async def test_plan_then_run_switches_every_bundle_to_basic(world: _World) -> None:
    first = await world.create(KeyBundleKind.EXTENDED)
    second = await world.create(KeyBundleKind.EXTENDED)
    world.configure(relay_enabled=True)
    services = _services(world)

    plan = _Callback("admin:aio:plan:basic")
    await admin_bundles.admin_bundles_plan(plan, services)

    text, markup = plan.message.edits[-1]
    assert plan.answers[0] == (t("aio_planning"), None)  # answered before the work
    assert t("aio_plan_header", title=t("aio_mode_basic"), total=2, planned=2, create=4, delete=6,
             kinds=2, noop=0, skipped=0) in text
    assert "admin:aio:run:basic" in _callbacks(markup)
    assert len(await world.children(first.id)) == 5  # the plan wrote nothing

    run = _Callback("admin:aio:run:basic")
    await admin_bundles.admin_bundles_run(run, services)
    assert run.answers == [(t("aio_started"), None)]
    task = admin_bundles.runner.task
    assert task is not None
    await task

    final, final_markup = run.message.edits[-1]
    assert t("aio_report_header", title=t("aio_mode_basic"), total=2, applied=2, created=4, deleted=6,
             noop=0, skipped=0, failed=0) in final
    assert "admin:aio" in _callbacks(final_markup)
    for bundle in (first, second):
        assert (await world.bundle(bundle.id)).kind is KeyBundleKind.BASIC
        assert await world.members(bundle.id) == ["hysteria2", "hysteria2_relay_ru1", "xray_tcp", "xray_tcp_relay_ru1"]


async def test_plan_with_nothing_to_do_offers_no_run_button(world: _World) -> None:
    await world.create(KeyBundleKind.BASIC)
    plan = _Callback("admin:aio:plan:top")
    await admin_bundles.admin_bundles_plan(plan, _services(world))
    text, markup = plan.message.edits[-1]
    assert t("aio_plan_nothing") in text
    assert not any(data.startswith("admin:aio:run:") for data in _callbacks(markup))


async def test_second_run_is_refused_while_one_is_running(world: _World) -> None:
    await world.create(KeyBundleKind.EXTENDED)
    gate = asyncio.Event()
    services = _services(world)

    async def slow_reconcile_all(**_kwargs: object) -> ReconcileSummary:
        await gate.wait()
        return ReconcileSummary(())

    services.key_bundles = SimpleNamespace(reconcile_all=slow_reconcile_all)
    first = _Callback("admin:aio:run:top")
    await admin_bundles.admin_bundles_run(first, services)
    second = _Callback("admin:aio:run:basic")
    await admin_bundles.admin_bundles_run(second, services)
    plan = _Callback("admin:aio:plan:basic")
    await admin_bundles.admin_bundles_plan(plan, services)

    assert second.answers == [(t("aio_already_running"), True)]
    assert plan.answers == [(t("aio_already_running"), True)]
    gate.set()
    task = admin_bundles.runner.task
    assert task is not None
    await task
    assert not admin_bundles.runner.running


async def test_one_bundle_error_does_not_stop_the_run_and_is_reported(world: _World) -> None:
    good = await world.create(KeyBundleKind.EXTENDED)
    bad = await world.create(KeyBundleKind.EXTENDED)
    original = world.service.reconcile_composition

    async def flaky(bundle_id: int, **kwargs: Any) -> ReconcileResult:
        if bundle_id == bad.id:
            raise RuntimeError("boom")
        return await original(bundle_id, **kwargs)

    world.service.reconcile_composition = flaky  # type: ignore[method-assign]
    run = _Callback("admin:aio:run:basic")
    await admin_bundles.admin_bundles_run(run, _services(world))
    task = admin_bundles.runner.task
    assert task is not None
    await task

    final, _ = run.message.edits[-1]
    assert t("aio_report_header", title=t("aio_mode_basic"), total=2, applied=1, created=0, deleted=3,
             noop=0, skipped=0, failed=1) in final
    assert t("bundle_title", id=bad.display_no) in final
    assert (await world.bundle(good.id)).kind is KeyBundleKind.BASIC


async def test_progress_is_edited_at_most_every_three_seconds() -> None:
    message = _Message()
    now = [100.0]
    reporter = admin_bundles.ProgressReporter(message, "T", clock=lambda: now[0])
    await reporter.start()
    for done in range(1, 10):
        now[0] += 1.0  # one bundle per second
        await reporter(done, 20)
    # start + t=103 + t=106 + t=109
    assert reporter.edits == 4
    assert len(message.edits) == 4
    assert message.edits[-1][0] == t("aio_run_progress", title="T", done=9, total=20)
    await reporter(20, 20)  # the last bundle: the final report replaces it instead
    assert len(message.edits) == 4


def test_report_lists_skip_reasons_and_failures() -> None:
    summary = ReconcileSummary(
        (
            ReconcileResult(1, 11, ReconcileOutcome.APPLIED, KeyBundleKind.EXTENDED, KeyBundleKind.BASIC,
                            created_key_ids=(5,), deleted_key_ids=(6, 7)),
            ReconcileResult(2, 12, ReconcileOutcome.SKIPPED, skip_reason=ReconcileSkipReason.MIXED_EXPIRY,
                            anomalies=("2030", "2031")),
            ReconcileResult(3, 13, ReconcileOutcome.PARTIAL, to_delete=("a", "b", "c"), deleted_key_ids=(9,),
                            error=RuntimeError("x")),
        )
    )
    text = admin_bundles.aio_report_text("basic", summary)
    assert f"{t('bundle_title', id=12)} — {t('aio_reason_mixed_expiry')} (2030, 2031)" in text
    assert t("aio_state_partial", done=1, total=3) in text
    assert t("aio_report_retry_hint") in text


def test_dry_run_summary_counts_only_planned_results() -> None:
    planned = ReconcileResult(1, 1, ReconcileOutcome.PLANNED, KeyBundleKind.EXTENDED, KeyBundleKind.BASIC,
                              to_create=("x",), to_delete=("a", "b"))
    skipped = replace(planned, outcome=ReconcileOutcome.SKIPPED)
    summary = ReconcileSummary((planned, skipped))
    assert (summary.keys_to_create, summary.keys_to_delete, summary.kind_changes) == (1, 2, 1)


async def test_shutdown_lets_the_current_bundle_finish_then_stops(world: _World) -> None:
    first = await world.create(KeyBundleKind.EXTENDED)
    second = await world.create(KeyBundleKind.EXTENDED)
    gate = asyncio.Event()
    entered = asyncio.Event()
    original = world.service.reconcile_composition

    async def gated(bundle_id: int, **kwargs: Any) -> ReconcileResult:
        entered.set()
        await gate.wait()
        return await original(bundle_id, **kwargs)

    world.service.reconcile_composition = gated  # type: ignore[method-assign]
    run = _Callback("admin:aio:run:basic")
    await admin_bundles.admin_bundles_run(run, _services(world))
    await entered.wait()  # the run is inside the first bundle

    shutdown = asyncio.create_task(admin_bundles.runner.shutdown(timeout=5))
    await asyncio.sleep(0)
    assert admin_bundles.runner.stop_requested()
    gate.set()
    await shutdown

    assert not admin_bundles.runner.running
    assert (await world.bundle(first.id)).kind is KeyBundleKind.BASIC  # finished, not cut off
    assert (await world.bundle(second.id)).kind is KeyBundleKind.EXTENDED  # never started
    final, _ = run.message.edits[-1]
    assert t("aio_report_stopped", remaining=1) in final
    assert t("aio_report_retry_hint") in final


async def test_shutdown_cancels_a_run_that_does_not_stop_in_time() -> None:
    never = asyncio.Event()

    async def stuck() -> None:
        await never.wait()

    task = admin_bundles.runner.start(stuck())
    await admin_bundles.runner.shutdown(timeout=0.01)
    assert task.cancelled()
    await admin_bundles.runner.shutdown()  # nothing running: a no-op
