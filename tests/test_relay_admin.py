"""Relays managed from the admin panel instead of .env (relays table, v38).

Covers:

* the v38 migration — fresh database and an upgrade from a populated v37 one;
* the one-time seed from the legacy RELAY_* variables, and the WARNING when they
  are ignored;
* RelayService — validation of every field, the immutable name, a name still
  carried by keys, SUPERADMIN-only access, the audit trail;
* deletion — with no keys, with keys (each through the key's normal delete path:
  a bundle child goes, its bundle stays), a key that fails (the relay stays, a
  retry finishes), «disable instead»;
* edits take effect at once — single links, the subscription, and a second
  process (the read-only subscription store) without a restart;
* several relays — subscription groups in relay order, «в подписках» = off;
* anomaly detection and the health loop reading relays from the database;
* the panel's handlers — list, card, the add wizard, an edit, stale callbacks.
"""

from __future__ import annotations

import base64
import ipaddress
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import unquote

import aiosqlite
import pytest
from conftest import make_relay
from test_relay import (
    ADMIN,
    DIRECT_HOST,
    FLAG,
    OWNER,
    RELAY_HOST,
    _Ids,
    _minimal_env,
    _Modules,
    _owner,
    _settings,
)

from adapters.clock import ClockProvider
from bot.fsm.states import AdminRelayStates
from bot.handlers import admin_relays as panel
from config.settings import Settings, SettingsError, load_settings
from db.database import CURRENT_SCHEMA_VERSION, Database
from i18n import t
from models.dto import TelegramUserProfile, User
from models.enums import AuditEntityType, KeyBundleKind, KeyBundleStatus, UserRole, VpnKeyStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from repositories.relays import RelayRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.anomaly_detection import AnomalyDetectionService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.hysteria import HysteriaService
from services.key_bundles import KeyBundleService, subscription_sort_key
from services.relay import RelayCatalog, RelaySnapshot, RelayUnavailable
from services.relay_health import RelayHealthSupervisor
from services.relay_management import RelayService
from services.xray import XrayService
from subscription_server.render import render_links
from subscription_server.store import BundleView, ReadOnlyBundleStore

MODERATOR = 5
NEW_HOST = "relay2.anycastedge.net"


# ── harness ───────────────────────────────────────────────────────────────────


class _Users:
    """ADMIN is the superadmin; MODERATOR and OWNER are not."""

    def _role(self, user_id: int) -> UserRole:
        if user_id == ADMIN:
            return UserRole.SUPERADMIN
        if user_id == MODERATOR:
            return UserRole.MODERATOR
        return UserRole.APPROVED_USER

    async def get_user(self, user_id: int) -> User:
        return User(user_id, f"user{user_id}", "User", self._role(user_id), "now", "now", None)

    async def require_approved_or_admin(self, user_id: int) -> User:
        return await self.get_user(user_id)

    async def require_superadmin(self, user_id: int) -> User:
        user = await self.get_user(user_id)
        if user.role is not UserRole.SUPERADMIN:
            raise AccessDenied("Недостаточно прав", key="err_insufficient_rights")
        return user


class _Audit:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def write_best_effort(self, **kwargs: Any) -> None:
        self.rows.append(kwargs)

    async def write(self, **kwargs: Any) -> None:
        self.rows.append(kwargs)

    def actions(self, entity_type: AuditEntityType | None = None) -> list[str]:
        return [
            str(row["action"]) for row in self.rows if entity_type is None or row["entity_type"] is entity_type
        ]


class _Adapter:
    """Records clients; ``fail_on`` uuids make ``remove_client`` raise once each."""

    def __init__(self) -> None:
        self.clients: list[str] = []
        self.removed: list[str] = []
        self.fail_on: set[str] = set()

    async def add_client(self, **kwargs: object) -> object:
        self.clients.append(str(kwargs["uuid_value"]))
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        uuid_value = str(kwargs["uuid_value"])
        if uuid_value in self.fail_on:
            self.fail_on.discard(uuid_value)
            raise RuntimeError("xray -test failed")
        self.removed.append(uuid_value)


class _World:
    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.settings: Settings = _settings(tmp_path)

    async def start(self) -> _World:
        self.db = Database(self.tmp_path / "vpn.db")
        await self.db.connect()
        await self.db.bootstrap()
        users_repo = UserRepository(self.db)
        for uid in (ADMIN, OWNER, MODERATOR):
            await users_repo.upsert_profile(
                TelegramUserProfile(uid, f"user{uid}", "User"), UserRole.APPROVED_USER, "now"
            )
        self.audit = _Audit()
        self.catalog = RelayCatalog()
        self.relay_repo = RelayRepository(self.db)
        self.vpn_keys = VpnKeyRepository(self.db)
        self.bundle_repo = KeyBundleRepository(self.db)
        self.adapter = _Adapter()
        clock = ClockProvider()
        ids = _Ids()
        self.xray = XrayService(
            vpn_keys=self.vpn_keys,
            users=_Users(),  # type: ignore[arg-type]
            adapter=self.adapter,  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            xhttp_adapter=_Adapter(),  # type: ignore[arg-type]
            relays=self.catalog,
        )
        self.hysteria = HysteriaService(
            vpn_keys=self.vpn_keys,
            users=_Users(),  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            modules=_Modules(),  # type: ignore[arg-type]
            relays=self.catalog,
        )
        self.bundles = KeyBundleService(
            bundles=self.bundle_repo,
            users=_Users(),  # type: ignore[arg-type]
            xray=self.xray,
            hysteria=self.hysteria,
            modules=_Modules(),  # type: ignore[arg-type]
            settings=self.settings,
            clock=clock,
            ids=ids,  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            relays=self.catalog,
        )
        self.relays = RelayService(
            relays=self.relay_repo,
            users=_Users(),  # type: ignore[arg-type]
            audit=self.audit,  # type: ignore[arg-type]
            clock=clock,
            catalog=self.catalog,
            key_deleters={
                VpnKeyType.XRAY: self.xray.delete_xray_key,
                VpnKeyType.HYSTERIA2: self.hysteria.delete_hysteria2_key,
            },
        )
        return self

    async def close(self) -> None:
        await self.db.close()

    async def add_relay(self, name: str = "ru1", **kwargs: Any) -> Any:
        values: dict[str, Any] = {"host": RELAY_HOST, "source_ips": "198.51.100.7"}
        values.update(kwargs)
        return await self.relays.create(ADMIN, name=name, **values)

    async def view(self, bundle_id: int) -> BundleView:
        bundle = await self.bundle_repo.get_by_id(bundle_id)
        assert bundle is not None
        keys = tuple(await self.bundle_repo.list_keys_of_bundle(bundle_id))
        return BundleView(
            bundle=bundle, keys=keys, traffic=None, relays=RelaySnapshot.of(await self.relay_repo.list_all())
        )


@pytest.fixture
async def world(tmp_path: Path) -> Any:
    w = await _World(tmp_path).start()
    try:
        yield w
    finally:
        await w.close()


def _fragment(link: str) -> str:
    return unquote(link.split("#", 1)[1])


# ── migration v38 ─────────────────────────────────────────────────────────────


async def test_fresh_database_has_an_empty_relays_table(tmp_path: Path) -> None:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    try:
        await db.bootstrap()
        version = await db.conn.execute_fetchone("SELECT value FROM schema_meta WHERE key = 'schema_version'")
        assert version is not None and int(version["value"]) == CURRENT_SCHEMA_VERSION == 38
        assert await RelayRepository(db).count() == 0
        columns = {row["name"] for row in await db.conn.execute_fetchall("PRAGMA table_info(relays)")}
        assert columns == {
            "id", "name", "label", "host", "source_ips", "enabled", "in_subscriptions", "note",
            "created_at", "updated_at", "created_by", "updated_by",
        }
        # vpn_keys.relay is deliberately NOT a foreign key to relays.
        fks = await db.conn.execute_fetchall("PRAGMA foreign_key_list(vpn_keys)")
        assert all(row["table"] != "relays" for row in fks)
    finally:
        await db.close()


async def test_v37_upgrade_keeps_relay_keys_and_the_seed_adopts_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A v37 host that used the .env relay: the migration leaves vpn_keys.relay as it
    was, the relays table starts empty, and the startup seed gives the keys back
    the relay they already name — their links point at RELAY_HOST again."""
    from test_schema_upgrade_path import _materialise

    db_path = tmp_path / "vpn.db"
    await _materialise(db_path, 37)
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
        async with aiosqlite.connect(db_path) as conn:
            rows = await (await conn.execute("SELECT id, relay FROM vpn_keys ORDER BY id")).fetchall()
        assert [(int(r[0]), r[1]) for r in rows] == [(20, None), (21, "ru1"), (22, "ru1"), (24, None), (25, "ru1")]
        relay_repo = RelayRepository(db)
        assert await relay_repo.count() == 0

        _minimal_env(monkeypatch, tmp_path)
        monkeypatch.setenv("RELAY_ENABLED", "true")
        monkeypatch.setenv("RELAY_HOST", RELAY_HOST)
        monkeypatch.setenv("RELAY_SOURCE_IPS", "198.51.100.7")
        catalog = RelayCatalog()
        service = RelayService(
            relays=relay_repo, users=_Users(), audit=_Audit(), clock=ClockProvider(), catalog=catalog,  # type: ignore[arg-type]
        )
        seeded = await service.seed_from_settings(load_settings())
        assert seeded is not None and seeded.name == "ru1"
        bundle_repo = KeyBundleRepository(db)
        bundle = await bundle_repo.get_by_id(1)
        assert bundle is not None
        view = BundleView(
            bundle=bundle,
            keys=tuple(await bundle_repo.list_keys_of_bundle(1)),
            traffic=None,
            relays=catalog.snapshot,
        )
        links = render_links(view, _settings(tmp_path))
        assert len(links) == 2
        assert DIRECT_HOST in links[0] and RELAY_HOST in links[1]
        assert _fragment(links[1]) == f"xray_tcp_Ii999_relay_{FLAG}"
    finally:
        await db.close()


# ── the one-time seed from RELAY_* ────────────────────────────────────────────


def _seed_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **values: str) -> Settings:
    _minimal_env(monkeypatch, tmp_path)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return load_settings()


async def test_seed_creates_one_relay_from_env(
    world: _World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _seed_env(
        monkeypatch, tmp_path,
        RELAY_ENABLED="true", RELAY_NAME="msk-2", RELAY_HOST=RELAY_HOST, RELAY_SOURCE_IPS="198.51.100.7, 203.0.113.0/28",
    )
    with caplog.at_level(logging.INFO, logger="services.relay_management"):
        relay = await world.relays.seed_from_settings(settings)
    assert relay is not None
    rows = await world.relay_repo.list_all()
    assert len(rows) == 1
    seeded = rows[0]
    assert (seeded.name, seeded.label, seeded.host) == ("msk-2", "relay", RELAY_HOST)
    assert seeded.source_ips == (ipaddress.IPv4Network("198.51.100.7/32"), ipaddress.IPv4Network("203.0.113.0/28"))
    assert seeded.enabled and seeded.in_subscriptions
    # The bot's snapshot already has it, the seed is audited, INFO (not WARNING) is logged.
    assert world.catalog.snapshot.get("msk-2") == seeded
    assert world.audit.actions(AuditEntityType.RELAY) == ["relay_seeded_from_env"]
    assert [r.levelno for r in caplog.records if r.name == "services.relay_management"] == [logging.INFO]


async def test_seed_uses_ru1_when_relay_name_is_unset(
    world: _World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _seed_env(monkeypatch, tmp_path, RELAY_ENABLED="true", RELAY_HOST="203.0.113.5", RELAY_SOURCE_IPS="203.0.113.5")
    relay = await world.relays.seed_from_settings(settings)
    assert relay is not None and relay.name == "ru1"


async def test_seed_skips_a_non_empty_table_and_warns(
    world: _World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    await world.add_relay("ru1")
    settings = _seed_env(
        monkeypatch, tmp_path, RELAY_ENABLED="true", RELAY_NAME="other", RELAY_HOST=NEW_HOST, RELAY_SOURCE_IPS="203.0.113.5"
    )
    with caplog.at_level(logging.INFO, logger="services.relay_management"):
        assert await world.relays.seed_from_settings(settings) is None
    assert [r.name for r in await world.relay_repo.list_all()] == ["ru1"]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "RELAY_* в .env игнорируются: relay управляется из админки" in warnings[0].getMessage()
    assert "RELAY_HOST" in warnings[0].getMessage()


async def test_relay_vars_without_enabled_only_warn(
    world: _World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _seed_env(monkeypatch, tmp_path, RELAY_ENABLED="false", RELAY_HOST=RELAY_HOST)
    with caplog.at_level(logging.WARNING, logger="services.relay_management"):
        assert await world.relays.seed_from_settings(settings) is None
    assert await world.relay_repo.count() == 0
    assert any("игнорируются" in r.getMessage() for r in caplog.records)


async def test_no_relay_vars_no_seed_no_warning(
    world: _World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _seed_env(monkeypatch, tmp_path)
    with caplog.at_level(logging.INFO, logger="services.relay_management"):
        assert await world.relays.seed_from_settings(settings) is None
    assert await world.relay_repo.count() == 0
    assert not [r for r in caplog.records if r.name == "services.relay_management"]


@pytest.mark.parametrize(
    "values",
    [
        {"RELAY_ENABLED": "true", "RELAY_HOST": "bad host", "RELAY_SOURCE_IPS": "198.51.100.7"},
        {"RELAY_ENABLED": "true", "RELAY_HOST": RELAY_HOST, "RELAY_SOURCE_IPS": "198.51.100.7,nope"},
        {"RELAY_ENABLED": "true", "RELAY_HOST": RELAY_HOST},
        {"RELAY_ENABLED": "true", "RELAY_SOURCE_IPS": "198.51.100.7"},
        {"RELAY_NAME": "Bad_Name"},
        {"RELAY_SOURCE_IPS": "2001:db8::1"},
    ],
)
def test_garbage_relay_env_still_fails_startup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, values: dict[str, str]
) -> None:
    with pytest.raises(SettingsError, match="RELAY_"):
        _seed_env(monkeypatch, tmp_path, **values)


# ── RelayService: validation, immutability, rights, audit ─────────────────────


async def test_create_normalizes_and_audits(world: _World) -> None:
    relay = await world.relays.create(
        ADMIN, name="ru1", host=" relay.anycastedge.net ", source_ips=" 198.51.100.7 , 203.0.113.0/28,", note=" spb "
    )
    assert relay.host == RELAY_HOST
    assert relay.label == "relay"
    assert relay.note == "spb"
    assert relay.source_ips == (ipaddress.IPv4Network("198.51.100.7/32"), ipaddress.IPv4Network("203.0.113.0/28"))
    raw = await world.db.conn.execute_fetchone("SELECT source_ips, created_by FROM relays WHERE id = ?", (relay.id,))
    assert raw is not None and raw["source_ips"] == "198.51.100.7,203.0.113.0/28" and raw["created_by"] == ADMIN
    created = [row for row in world.audit.rows if row["action"] == "relay_created"]
    assert len(created) == 1 and created[0]["actor_user_id"] == ADMIN
    assert created[0]["details"]["host"] == RELAY_HOST
    assert world.catalog.snapshot.get("ru1") == relay


@pytest.mark.parametrize(
    ("field", "value", "key"),
    [
        ("name", "RU1", "err_relay_name_invalid"),
        ("name", "-ru1", "err_relay_name_invalid"),
        ("name", "r" * 33, "err_relay_name_invalid"),
        ("name", "ru_1", "err_relay_name_invalid"),
        ("host", "", "err_relay_host_required"),
        ("host", "2001:db8::1", "err_relay_host_invalid"),
        ("host", "bad host", "err_relay_host_invalid"),
        ("host", "1.2.3.256", "err_relay_host_invalid"),
        ("host", "relay.example.net\n", "err_relay_host_invalid"),
        ("source_ips", "", "err_relay_source_ips_required"),
        ("source_ips", ",", "err_relay_source_ips_required"),
        ("source_ips", "198.51.100.7,garbage", "err_relay_source_ips_invalid"),
        ("source_ips", "198.51.100.7/24", "err_relay_source_ips_invalid"),
        ("source_ips", "2001:db8::1", "err_relay_source_ips_invalid"),
        ("label", "", "err_relay_label_invalid"),
        ("label", "Relay", "err_relay_label_invalid"),
        ("label", "r" * 17, "err_relay_label_invalid"),
        ("label", "re lay", "err_relay_label_invalid"),
        ("note", "two\nlines", "err_relay_note_invalid"),
        ("note", "x" * 300, "err_relay_note_invalid"),
    ],
)
async def test_every_field_is_validated(world: _World, field: str, value: str, key: str) -> None:
    values: dict[str, Any] = {"name": "ru1", "host": RELAY_HOST, "source_ips": "198.51.100.7"}
    values[field] = value
    with pytest.raises(InvalidOperation) as excinfo:
        await world.relays.create(ADMIN, **values)
    assert excinfo.value.key == key
    assert await world.relay_repo.count() == 0


async def test_source_ip_error_names_the_bad_entry(world: _World) -> None:
    with pytest.raises(InvalidOperation) as excinfo:
        await world.relays.create(ADMIN, name="ru1", host=RELAY_HOST, source_ips="198.51.100.7, 10.0.0.300 ,203.0.113.1")
    assert excinfo.value.params == {"value": "10.0.0.300"}


async def test_edits_are_validated_too(world: _World) -> None:
    relay = await world.add_relay()
    for kwargs, key in (
        ({"host": "::1"}, "err_relay_host_invalid"),
        ({"source_ips": ""}, "err_relay_source_ips_required"),
        ({"label": "BAD"}, "err_relay_label_invalid"),
    ):
        with pytest.raises(InvalidOperation) as excinfo:
            await world.relays.update(ADMIN, relay.id, **kwargs)
        assert excinfo.value.key == key
    assert await world.relay_repo.get_by_id(relay.id) == relay


async def test_names_and_labels_are_unique(world: _World) -> None:
    await world.add_relay("ru1")
    with pytest.raises(InvalidOperation) as excinfo:
        await world.add_relay("ru1", label="other")
    assert excinfo.value.key == "err_relay_name_taken"
    with pytest.raises(InvalidOperation) as excinfo:
        await world.add_relay("ru2")  # default label "relay" is taken
    assert excinfo.value.key == "err_relay_label_taken"
    second = await world.add_relay("ru2", label="msk")
    with pytest.raises(InvalidOperation) as excinfo:
        await world.relays.update(ADMIN, second.id, label="relay")
    assert excinfo.value.key == "err_relay_label_taken"


async def test_the_name_is_immutable(world: _World) -> None:
    relay = await world.add_relay()
    with pytest.raises(TypeError):
        await world.relays.update(ADMIN, relay.id, name="ru9")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="name"):
        await world.relay_repo.update(relay.id, {"name": "ru9"}, now="now", updated_by=ADMIN)
    stored = await world.relay_repo.get_by_id(relay.id)
    assert stored is not None and stored.name == "ru1"


@pytest.mark.parametrize("status", ["active", "revoked", "deleted"])
async def test_a_name_still_carried_by_keys_cannot_be_reused(world: _World, status: str) -> None:
    """Keys — even deleted ones — keep the name forever; a new relay under it would
    silently re-point them."""
    key = await world.vpn_keys.create_pending(
        owner_user_id=OWNER, username="u", key_type=VpnKeyType.XRAY, note=None, payload={}, public_payload={},
        created_by=OWNER, now="now", relay="old1",
    )
    await world.db.conn.execute("UPDATE vpn_keys SET status = ? WHERE id = ?", (status, key.id))
    await world.db.commit()
    with pytest.raises(InvalidOperation) as excinfo:
        await world.add_relay("old1")
    assert excinfo.value.key == "err_relay_name_used_by_keys"
    with pytest.raises(InvalidOperation):
        await world.relays.check_new_name(ADMIN, "old1")
    assert await world.relays.check_new_name(ADMIN, "fresh1") == "fresh1"


@pytest.mark.parametrize("actor", [OWNER, MODERATOR])
async def test_only_a_superadmin_may_touch_relays(world: _World, actor: int) -> None:
    relay = await world.add_relay()
    calls = [
        world.relays.list_overview(actor),
        world.relays.get(actor, relay.id),
        world.relays.usage(actor, relay.id),
        world.relays.check_new_name(actor, "ru2"),
        world.relays.create(actor, name="ru2", host=NEW_HOST, source_ips="203.0.113.5", label="b"),
        world.relays.update(actor, relay.id, host=NEW_HOST),
        world.relays.add_source_ip(actor, relay.id, "203.0.113.5"),
        world.relays.delete(actor, relay.id, with_keys=True),
    ]
    for call in calls:
        with pytest.raises(AccessDenied):
            await call
    assert await world.relay_repo.get_by_id(relay.id) == relay
    assert world.audit.actions(AuditEntityType.RELAY) == ["relay_created"]


async def test_update_audits_before_and_after(world: _World) -> None:
    relay = await world.add_relay()
    result = await world.relays.update(ADMIN, relay.id, label="msk", enabled=False, note="spb")
    assert result.changed == ("enabled", "label", "note")
    row = [r for r in world.audit.rows if r["action"] == "relay_updated"][-1]
    assert row["actor_user_id"] == ADMIN and row["entity_id"] == relay.id
    assert row["details"]["changes"] == {
        "enabled": {"before": True, "after": False},
        "label": {"before": "relay", "after": "msk"},
        "note": {"before": None, "after": "spb"},
    }
    # A no-op edit changes nothing and writes nothing.
    again = await world.relays.update(ADMIN, relay.id, label="msk")
    assert again.changed == ()
    assert world.audit.actions(AuditEntityType.RELAY).count("relay_updated") == 1
    stored = await world.relay_repo.get_by_id(relay.id)
    assert stored is not None and stored.updated_by == ADMIN


async def test_a_missing_relay_is_not_found(world: _World) -> None:
    for call in (
        world.relays.get(ADMIN, 99),
        world.relays.update(ADMIN, 99, host=NEW_HOST),
        world.relays.delete(ADMIN, 99, with_keys=False),
    ):
        with pytest.raises(NotFound) as excinfo:
            await call
        assert excinfo.value.key == "err_relay_not_found"


# ── delete ────────────────────────────────────────────────────────────────────


async def test_delete_a_relay_without_keys(world: _World) -> None:
    relay = await world.add_relay()
    report = await world.relays.delete(ADMIN, relay.id, with_keys=False)
    assert report.deleted and report.deleted_key_ids == ()
    assert await world.relay_repo.count() == 0
    assert world.catalog.snapshot.get("ru1") is None
    assert world.audit.actions(AuditEntityType.RELAY)[-1] == "relay_deleted"


async def _relay_estate(world: _World) -> dict[str, Any]:
    """A relay with a single VLESS key, a single hy2 key and a basic bundle."""
    await world.add_relay()
    single_vless = (await world.xray.create_xray_key(ADMIN, _owner(), None, relay="ru1")).key
    single_hy2 = (await world.hysteria.issue(ADMIN, _owner(), None, relay="ru1")).key
    direct = (await world.xray.create_xray_key(ADMIN, _owner(), None)).key
    bundle = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.BASIC)
    await world.db.conn.execute(
        "INSERT INTO vpn_key_traffic_stats (key_id, downloaded_bytes, uploaded_bytes, last_success_at, available) "
        "VALUES (?, 1000, 200, 'now', 1)",
        (single_vless.id,),
    )
    await world.db.commit()
    return {"vless": single_vless, "hy2": single_hy2, "direct": direct, "bundle": bundle}


async def test_usage_counts_keys_bundles_and_singles(world: _World) -> None:
    estate = await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    _, usage = await world.relays.usage(ADMIN, relay.id)
    assert (usage.keys, usage.bundle_keys, usage.bundles, usage.active_keys, usage.single_active_keys) == (4, 2, 1, 4, 2)
    overview = await world.relays.list_overview(ADMIN)
    assert [(o.relay.name, o.active_keys) for o in overview] == [("ru1", 4)]
    assert estate["direct"].relay is None


async def test_delete_without_keys_flag_refuses_while_keys_remain(world: _World) -> None:
    await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    report = await world.relays.delete(ADMIN, relay.id, with_keys=False)
    assert not report.deleted and report.remaining_keys == 4
    assert await world.relay_repo.count() == 1


async def test_delete_with_keys_goes_through_the_key_delete_path(world: _World) -> None:
    estate = await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    bundle = estate["bundle"].bundle
    relay_children = [k for k in estate["bundle"].keys if k.relay]
    direct_children = [k for k in estate["bundle"].keys if not k.relay]

    report = await world.relays.delete(ADMIN, relay.id, with_keys=True)

    assert report.deleted
    assert sorted(report.deleted_key_ids) == sorted(
        [estate["vless"].id, estate["hy2"].id, *(k.id for k in relay_children)]
    )
    assert await world.relay_repo.count() == 0
    # Every relay key is gone, every other key is untouched.
    for key_id in report.deleted_key_ids:
        assert await world.vpn_keys.get_by_id(key_id) is None
    assert await world.vpn_keys.get_by_id(estate["direct"].id) is not None
    # The VLESS ones were removed from Xray, through the adapter.
    vless_uuids = {k.uuid for k in (estate["vless"], *relay_children) if k.key_type is VpnKeyType.XRAY}
    assert vless_uuids <= set(world.adapter.removed)
    # Traffic was archived, exactly as deleting the key on its own screen does.
    archived = await world.db.conn.execute_fetchone(
        "SELECT downloaded_bytes FROM deleted_key_traffic_archive WHERE key_id = ?", (estate["vless"].id,)
    )
    assert archived is not None and int(archived["downloaded_bytes"]) == 1000
    # Each key's own audit entry was written by its service.
    actions = world.audit.actions()
    assert actions.count("xray_key_hard_deleted") == 2 and actions.count("hysteria2_key_hard_deleted") == 2
    # The bundle survives with its direct members.
    kept = await world.bundle_repo.get_by_id(bundle.id)
    assert kept is not None and kept.status is KeyBundleStatus.ACTIVE
    children = await world.bundle_repo.list_keys_of_bundle(bundle.id)
    assert {k.id for k in children} == {k.id for k in direct_children}
    deleted = [r for r in world.audit.rows if r["action"] == "relay_deleted"][-1]
    assert sorted(deleted["details"]["deleted_key_ids"]) == sorted(report.deleted_key_ids)


async def test_a_failing_key_stops_the_delete_and_a_retry_finishes(world: _World) -> None:
    estate = await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    world.adapter.fail_on.add(str(estate["bundle"].keys[2].uuid))  # the bundle's relay VLESS child

    report = await world.relays.delete(ADMIN, relay.id, with_keys=True)
    assert not report.deleted
    assert report.failed_key_id == estate["bundle"].keys[2].id
    assert isinstance(report.failure, Exception)
    assert report.remaining_keys >= 1
    assert estate["vless"].id in report.deleted_key_ids
    assert await world.relay_repo.get_by_id(relay.id) is not None
    assert "relay_delete_incomplete" in world.audit.actions(AuditEntityType.RELAY)
    # The relay is still in the snapshot (not deleted), so its remaining keys still render.
    assert world.catalog.snapshot.get("ru1") is not None

    retry = await world.relays.delete(ADMIN, relay.id, with_keys=True)
    assert retry.deleted
    assert await world.relay_repo.count() == 0
    assert await world.vpn_keys.get_by_id(estate["bundle"].keys[2].id) is None


async def test_disable_instead_of_delete_keeps_the_keys(world: _World) -> None:
    estate = await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    await world.relays.update(ADMIN, relay.id, enabled=False)
    stored = await world.vpn_keys.get_by_id(estate["vless"].id)
    assert stored is not None and stored.status is VpnKeyStatus.ACTIVE
    with pytest.raises(RelayUnavailable):
        world.xray.connection_link(stored)
    # …and it is no longer offered for new keys.
    with pytest.raises(RelayUnavailable):
        await world.xray.create_xray_key(ADMIN, _owner(), None, relay="ru1")


# ── edits take effect at once, in both processes ──────────────────────────────


async def test_host_change_reaches_links_and_subscriptions_at_once(world: _World) -> None:
    estate = await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    store = ReadOnlyBundleStore(world.db.path)
    await store.connect()
    try:
        before = await store.load_active_bundle(estate["bundle"].bundle.token)
        assert before is not None
        assert any(RELAY_HOST in link for link in render_links(before, world.settings))

        result = await world.relays.update(ADMIN, relay.id, host=NEW_HOST)
        assert result.changed == ("host",)
        assert result.single_keys_to_reimport == 2
        assert result.suggest_source_ip is None  # a DNS name: nothing to suggest

        vless = await world.vpn_keys.get_by_id(estate["vless"].id)
        hy2 = await world.vpn_keys.get_by_id(estate["hy2"].id)
        assert vless is not None and hy2 is not None
        assert f"@{NEW_HOST}:443?" in world.xray.connection_link(vless)
        assert world.hysteria.connection_link(hy2).startswith(f"hysteria2://{hy2.payload['secret']}@{NEW_HOST}:443/")
        # The second process sees the change on its very next read — no restart.
        after = await store.load_active_bundle(estate["bundle"].bundle.token)
        assert after is not None
        links = render_links(after, world.settings)
        assert [link for link in links if NEW_HOST in link] and not [link for link in links if RELAY_HOST in link]
    finally:
        await store.close()


async def test_label_change_renames_relay_keys_at_once(world: _World) -> None:
    estate = await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    await world.relays.update(ADMIN, relay.id, label="spb")
    vless = await world.vpn_keys.get_by_id(estate["vless"].id)
    assert vless is not None
    assert _fragment(world.xray.connection_link(vless)) == f"{vless.email_label}_spb_{FLAG}"
    names = [_fragment(link) for link in render_links(await world.view(estate["bundle"].bundle.id), world.settings)]
    assert sum("_spb_" in name for name in names) == 2


async def test_an_ipv4_host_outside_the_source_ips_is_suggested(world: _World) -> None:
    relay = await world.add_relay(host="203.0.113.5", source_ips="203.0.113.5")
    result = await world.relays.update(ADMIN, relay.id, host="198.51.100.20")
    assert result.suggest_source_ip == "198.51.100.20"
    added = await world.relays.add_source_ip(ADMIN, relay.id, "198.51.100.20")
    assert added.relay.source_ips == (
        ipaddress.IPv4Network("203.0.113.5/32"),
        ipaddress.IPv4Network("198.51.100.20/32"),
    )
    # Covered now: no suggestion on the next edit.
    covered = await world.relays.update(ADMIN, relay.id, host="203.0.113.5")
    assert covered.suggest_source_ip is None


# ── several relays ────────────────────────────────────────────────────────────


async def test_two_relays_subscription_is_grouped_in_relay_order(world: _World) -> None:
    """Direct members, then those of relay #1, then relay #2 — by relays.id, not by name."""
    await world.add_relay("zz-first", label="a", host="a.example.net", source_ips="198.51.100.7")
    await world.add_relay("aa-second", label="b", host="b.example.net", source_ips="198.51.100.8")
    result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.EXTENDED)
    assert len(result.keys) == 15
    links = render_links(await world.view(result.bundle.id), world.settings)
    assert len(links) == 15
    assert all(DIRECT_HOST in link for link in links[:5])
    assert all("a.example.net" in link for link in links[5:10])
    assert all("b.example.net" in link for link in links[10:])
    names = [_fragment(link) for link in links]
    assert all("_a_" in name for name in names[5:10]) and all("_b_" in name for name in names[10:])
    # Each group carries the direct twins' circles in the same order.
    assert [n.rsplit("_", 1)[1] for n in names[5:10]] == [n.rsplit("_", 1)[1] for n in names[:5]]
    # The bot's «Состав» preview sorts the same way.
    snapshot = world.catalog.snapshot
    ordered = sorted(result.keys, key=lambda key: subscription_sort_key(key, snapshot))
    assert [k.relay for k in ordered] == [None] * 5 + ["zz-first"] * 5 + ["aa-second"] * 5


async def test_a_relay_out_of_subscriptions_is_left_out_of_new_bundles(world: _World) -> None:
    await world.add_relay("ru1", host="a.example.net")
    second = await world.add_relay("ru2", label="b", host="b.example.net", source_ips="198.51.100.8")
    await world.relays.update(ADMIN, second.id, in_subscriptions=False)
    result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.BASIC)
    assert sorted({k.relay or "" for k in result.keys}) == ["", "ru1"]
    assert len(result.keys) == 4
    # …while single keys can still be issued through it.
    key = (await world.xray.create_xray_key(ADMIN, _owner(), None, relay="ru2")).key
    assert "@b.example.net:443" in world.xray.connection_link(key)


async def test_an_existing_bundle_skips_a_relay_switched_off_later(world: _World) -> None:
    await world.add_relay("ru1", host="a.example.net")
    second = await world.add_relay("ru2", label="b", host="b.example.net", source_ips="198.51.100.8")
    result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.BASIC)
    assert len(render_links(await world.view(result.bundle.id), world.settings)) == 6
    await world.relays.update(ADMIN, second.id, enabled=False)
    links = render_links(await world.view(result.bundle.id), world.settings)
    assert len(links) == 4 and not any("b.example.net" in link for link in links)


# ── anomaly detection reads the relays every cycle ────────────────────────────


async def test_anomaly_picks_up_source_ip_changes_on_the_next_cycle(world: _World) -> None:
    relay = await world.add_relay(source_ips="198.51.100.7")
    await world.add_relay("ru2", label="b", host="b.example.net", source_ips="198.51.100.9")
    svc = AnomalyDetectionService(
        vpn_keys=world.vpn_keys,
        awg=AsyncMock(),
        xray_service=AsyncMock(),
        awg_service=AsyncMock(),
        admin_ids=frozenset([ADMIN]),
        relays=world.relay_repo,
    )
    await svc.check_all()
    assert svc._is_relay_source("198.51.100.7") and svc._is_relay_source("198.51.100.9")
    # A switched-off relay keeps its addresses excluded.
    second = await world.relay_repo.get_by_name("ru2")
    assert second is not None
    await world.relays.update(ADMIN, second.id, enabled=False)
    await world.relays.update(ADMIN, relay.id, source_ips="203.0.113.0/28")
    assert svc._is_relay_source("198.51.100.7")  # not until the next cycle
    await svc.check_all()
    assert not svc._is_relay_source("198.51.100.7")
    assert svc._is_relay_source("203.0.113.4") and svc._is_relay_source("198.51.100.9")
    # A failed read keeps the previous set instead of counting relay IPs again.
    svc._relays = SimpleNamespace(list_all=AsyncMock(side_effect=RuntimeError("locked")))  # type: ignore[assignment]
    await svc.check_all()
    assert svc._is_relay_source("203.0.113.4")


# ── the health loop over every relay ──────────────────────────────────────────


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


async def test_health_latches_are_independent_and_survive_a_deletion() -> None:
    relays = [make_relay(1, "ru1", host="a.example.net"), make_relay(2, "ru2", label="b", host="b.example.net")]
    up = {"a.example.net": False, "b.example.net": True}
    probes: list[str] = []

    async def load() -> list[Any]:
        return list(relays)

    async def probe(host: str, port: int, sni: str) -> bool:
        probes.append(host)
        if host == "boom.example.net":
            raise RuntimeError("probe exploded")
        return up[host]

    sent: list[str] = []
    bot = SimpleNamespace(send_message=AsyncMock(side_effect=lambda chat_id, text: sent.append(text)))
    clock = _Clock()
    supervisor = RelayHealthSupervisor(
        load_relays=load, port=443, sni="example.com", admin_ids=frozenset({ADMIN}), window=300,
        probe=probe, clock=clock, wall_clock=lambda: "2026-11-03T10:00:00+00:00", bot=bot,  # type: ignore[arg-type]
    )
    for _ in range(3):
        await supervisor.check_once()
        clock.now += 300
    assert sent == [t("relay_alert_down", label="relay", name="ru1", host="a.example.net", port=443)]
    assert supervisor.healthy(1) is False and supervisor.healthy(2) is True
    last = supervisor.last_probe(2)
    assert last is not None and last.ok and last.checked_at == "2026-11-03T10:00:00+00:00"

    # ru1 is deleted mid-run: the loop carries on, its latch and last probe go.
    relays.pop(0)
    await supervisor.check_once()
    assert supervisor.healthy(1) is None and supervisor.last_probe(1) is None
    assert supervisor.healthy(2) is True
    # A new relay starts healthy; a probe that raises does not stop the others.
    relays.append(make_relay(3, "ru3", label="c", host="boom.example.net"))
    probes.clear()
    await supervisor.check_once()
    assert probes == ["b.example.net", "boom.example.net"]
    assert supervisor.healthy(3) is True
    # Switched off: no longer probed, latch dropped, last probe kept for its card.
    relays[0] = make_relay(2, "ru2", label="b", host="b.example.net", enabled=False)
    probes.clear()
    await supervisor.check_once()
    assert "b.example.net" not in probes and supervisor.healthy(2) is None
    assert supervisor.last_probe(2) is not None


async def test_probe_now_records_the_result_for_the_card() -> None:
    async def probe(host: str, port: int, sni: str) -> bool:
        return host == "ok.example.net"

    supervisor = RelayHealthSupervisor(
        load_relays=AsyncMock(return_value=[]), port=443, sni="example.com", admin_ids=frozenset(), window=300,
        probe=probe, wall_clock=lambda: "2026-11-03T11:00:00+00:00",
    )
    result = await supervisor.probe_now(make_relay(7, "ru7", host="ok.example.net"))
    assert result.ok and result.host == "ok.example.net"
    assert supervisor.last_probe(7) == result
    # It never feeds the latch (alerts must not depend on a button).
    assert supervisor.healthy(7) is None


# ── the panel's handlers ──────────────────────────────────────────────────────


class _Message:
    def __init__(self, text: str | None = None, user_id: int = ADMIN) -> None:
        self.message_id = 1
        self.text = text
        self.from_user = SimpleNamespace(id=user_id, username="admin", first_name="Admin")
        self.chat = SimpleNamespace(id=user_id)
        self.sent: list[tuple[str, Any]] = []

    async def edit_text(self, text: str, reply_markup: Any = None, **kwargs: object) -> None:
        self.sent.append((text, reply_markup))

    async def answer(self, text: str, reply_markup: Any = None, **kwargs: object) -> None:
        self.sent.append((text, reply_markup))

    @property
    def last_text(self) -> str:
        return self.sent[-1][0]

    @property
    def last_markup(self) -> Any:
        return self.sent[-1][1]


class _Callback:
    def __init__(self, data: str, user_id: int = ADMIN, message: _Message | None = None) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="admin", first_name="Admin")
        self.message = message or _Message(user_id=user_id)
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))

    @property
    def alerts(self) -> list[str]:
        return [text for text, show_alert in self.answers if show_alert]


class _State:
    def __init__(self) -> None:
        self.data: dict[str, Any] = {}
        self.state: Any = None

    async def get_state(self) -> str | None:
        return None if self.state is None else str(self.state.state)

    async def get_data(self) -> dict[str, Any]:
        return dict(self.data)

    async def set_state(self, state: Any) -> None:
        self.state = state

    async def update_data(self, data: dict[str, Any] | None = None, **kwargs: Any) -> None:
        self.data.update(data or {})
        self.data.update(kwargs)

    async def clear(self) -> None:
        self.data.clear()
        self.state = None


def _callbacks(markup: Any) -> list[str]:
    return [button.callback_data for row in markup.inline_keyboard for button in row]


@pytest.fixture
def panel_services(world: _World, monkeypatch: pytest.MonkeyPatch) -> Any:
    async def allow(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr(panel, "ensure_private_callback", allow)
    monkeypatch.setattr(panel, "ensure_private_message", allow)
    health = RelayHealthSupervisor(
        load_relays=world.relay_repo.list_all, port=443, sni="example.com", admin_ids=frozenset(), window=300,
        probe=AsyncMock(return_value=True), wall_clock=lambda: "2026-11-03T12:00:00+00:00",
    )
    return SimpleNamespace(users=_Users(), relays=world.relays, relay_health=health)


async def test_panel_is_superadmin_only(panel_services: Any) -> None:
    callback = _Callback("admin:relays", user_id=MODERATOR)
    await panel.relays_panel(callback, _State(), panel_services)  # type: ignore[arg-type]
    assert callback.alerts == [t("err_insufficient_rights")]
    assert callback.message.sent == []


async def test_list_and_card(world: _World, panel_services: Any) -> None:
    relay = await world.add_relay(note="spb")
    callback = _Callback("admin:relays")
    await panel.relays_panel(callback, _State(), panel_services)  # type: ignore[arg-type]
    assert "ru1" in callback.message.last_text and RELAY_HOST in callback.message.last_text
    assert _callbacks(callback.message.last_markup) == [f"admin:relay:{relay.id}", "admin:relay:add", "admin:panel"]

    card = _Callback(f"admin:relay:{relay.id}")
    await panel.relay_card(card, _State(), panel_services)  # type: ignore[arg-type]
    assert "198.51.100.7" in card.message.last_text and "spb" in card.message.last_text
    assert f"admin:relay:{relay.id}:check" in _callbacks(card.message.last_markup)

    check = _Callback(f"admin:relay:{relay.id}:check")
    await panel.relay_check_now(check, panel_services)  # type: ignore[arg-type]
    assert check.message.last_text.startswith(t("relay_check_ok", host=f"<code>{RELAY_HOST}:443</code>"))
    assert panel_services.relay_health.last_probe(relay.id) is not None


async def test_stale_callbacks_get_a_short_answer_and_the_list(world: _World, panel_services: Any) -> None:
    relay = await world.add_relay()
    await world.relays.delete(ADMIN, relay.id, with_keys=False)
    for handler, data in (
        (panel.relay_card, f"admin:relay:{relay.id}"),
        (panel.relay_edit_start, f"admin:relay:{relay.id}:edit:host"),
    ):
        callback = _Callback(data)
        await handler(callback, _State(), panel_services)  # type: ignore[operator]
        assert callback.alerts == [t("err_relay_not_found")]
        assert t("relays_empty") in callback.message.last_text
    for handler, data in (
        (panel.relay_toggle, f"admin:relay:{relay.id}:toggle:enabled"),
        (panel.relay_check_now, f"admin:relay:{relay.id}:check"),
        (panel.relay_delete_prompt, f"admin:relay:{relay.id}:del"),
        (panel.relay_delete_execute, f"admin:relay:{relay.id}:del:keys"),
    ):
        callback = _Callback(data)
        await handler(callback, panel_services)  # type: ignore[operator]
        assert callback.alerts == [t("err_relay_not_found")], data


async def test_add_wizard_end_to_end(world: _World, panel_services: Any) -> None:
    state = _State()
    start = _Callback("admin:relay:add")
    await panel.relay_add_start(start, state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.add_name

    bad = _Message("Bad Name")
    await panel.relay_add_name(bad, state, panel_services)  # type: ignore[arg-type]
    assert t("err_relay_name_invalid", value="Bad Name") in bad.last_text
    assert state.state == AdminRelayStates.add_name  # the same step again

    await panel.relay_add_name(_Message("ru1"), state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.add_host
    await panel.relay_add_host(_Message("bad host"), state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.add_host
    host_msg = _Message("203.0.113.5")
    await panel.relay_add_host(host_msg, state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.add_source_ips
    assert "admin:relay:add:srcashost" in _callbacks(host_msg.last_markup)

    as_host = _Callback("admin:relay:add:srcashost")
    await panel.relay_add_source_as_host(as_host, state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.add_label
    assert "admin:relay:add:labeldefault" in _callbacks(as_host.message.last_markup)

    default = _Callback("admin:relay:add:labeldefault")
    await panel.relay_add_label_default(default, state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.add_confirm
    assert "203.0.113.5" in default.message.last_text and "ru1" in default.message.last_text
    assert await world.relay_repo.count() == 0  # nothing written before the confirmation

    confirm = _Callback("admin:relay:add:confirm")
    await panel.relay_add_confirm(confirm, state, panel_services)  # type: ignore[arg-type]
    assert state.state is None
    relays = await world.relay_repo.list_all()
    assert [(r.name, r.host, r.label) for r in relays] == [("ru1", "203.0.113.5", "relay")]
    assert relays[0].source_ips == (ipaddress.IPv4Network("203.0.113.5/32"),)
    assert t("relay_created", label="relay") in confirm.message.last_text


async def test_add_wizard_dns_host_and_typed_label(world: _World, panel_services: Any) -> None:
    await world.add_relay("ru1")  # takes the default "relay" label
    state = _State()
    await panel.relay_add_start(_Callback("admin:relay:add"), state, panel_services)  # type: ignore[arg-type]
    await panel.relay_add_name(_Message("ru2"), state, panel_services)  # type: ignore[arg-type]
    host = _Message(NEW_HOST)
    await panel.relay_add_host(host, state, panel_services)  # type: ignore[arg-type]
    assert "admin:relay:add:srcashost" not in _callbacks(host.last_markup)  # not an IPv4 host
    src = _Message("198.51.100.20, 198.51.100.21")
    await panel.relay_add_source_ips(src, state, panel_services)  # type: ignore[arg-type]
    assert "admin:relay:add:labeldefault" not in _callbacks(src.last_markup)  # "relay" is taken
    taken = _Message("relay")
    await panel.relay_add_label(taken, state, panel_services)  # type: ignore[arg-type]
    assert t("err_relay_label_taken", value="relay") in taken.last_text
    await panel.relay_add_label(_Message("msk"), state, panel_services)  # type: ignore[arg-type]
    await panel.relay_add_confirm(_Callback("admin:relay:add:confirm"), state, panel_services)  # type: ignore[arg-type]
    created = await world.relay_repo.get_by_name("ru2")
    assert created is not None and created.label == "msk"


async def test_edit_host_shows_the_reimport_notice_and_the_source_ip_offer(
    world: _World, panel_services: Any
) -> None:
    relay = await world.add_relay(host="203.0.113.5", source_ips="203.0.113.5")
    await world.xray.create_xray_key(ADMIN, _owner(), None, relay="ru1")
    state = _State()
    start = _Callback(f"admin:relay:{relay.id}:edit:host")
    await panel.relay_edit_start(start, state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.edit_host
    message = _Message("198.51.100.20")
    await panel.relay_edit_host(message, state, panel_services)  # type: ignore[arg-type]
    assert state.state is None
    assert t("relay_host_changed", host="<code>198.51.100.20</code>", count=1) in message.last_text
    assert f"admin:relay:{relay.id}:addsrc" in _callbacks(message.last_markup)

    add = _Callback(f"admin:relay:{relay.id}:addsrc")
    await panel.relay_add_host_to_sources(add, panel_services)  # type: ignore[arg-type]
    stored = await world.relay_repo.get_by_id(relay.id)
    assert stored is not None and ipaddress.IPv4Network("198.51.100.20/32") in stored.source_ips


async def test_edit_with_a_bad_value_asks_again(world: _World, panel_services: Any) -> None:
    relay = await world.add_relay()
    state = _State()
    await panel.relay_edit_start(_Callback(f"admin:relay:{relay.id}:edit:src"), state, panel_services)  # type: ignore[arg-type]
    message = _Message("not-an-ip")
    await panel.relay_edit_source_ips(message, state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.edit_source_ips
    assert t("err_relay_source_ips_invalid", value="not-an-ip") in message.last_text
    assert await world.relay_repo.get_by_id(relay.id) == relay


async def test_delete_flow_from_the_panel(world: _World, panel_services: Any) -> None:
    await _relay_estate(world)
    relay = await world.relay_repo.get_by_name("ru1")
    assert relay is not None
    prompt = _Callback(f"admin:relay:{relay.id}:del")
    await panel.relay_delete_prompt(prompt, panel_services)  # type: ignore[arg-type]
    assert _callbacks(prompt.message.last_markup) == [
        f"admin:relay:{relay.id}:del:keys",
        f"admin:relay:{relay.id}:del:disable",
        f"admin:relay:{relay.id}",
    ]
    assert "4" in prompt.message.last_text

    disable = _Callback(f"admin:relay:{relay.id}:del:disable")
    await panel.relay_delete_execute(disable, panel_services)  # type: ignore[arg-type]
    stored = await world.relay_repo.get_by_id(relay.id)
    assert stored is not None and not stored.enabled
    assert t("relay_disabled_instead", label="relay") in disable.message.last_text

    delete = _Callback(f"admin:relay:{relay.id}:del:keys")
    await panel.relay_delete_execute(delete, panel_services)  # type: ignore[arg-type]
    assert await world.relay_repo.count() == 0
    assert t("relay_deleted", label="relay", count=4) in delete.message.last_text


async def test_delete_a_relay_without_keys_from_the_panel(world: _World, panel_services: Any) -> None:
    relay = await world.add_relay()
    prompt = _Callback(f"admin:relay:{relay.id}:del")
    await panel.relay_delete_prompt(prompt, panel_services)  # type: ignore[arg-type]
    assert _callbacks(prompt.message.last_markup) == [f"admin:relay:{relay.id}:del:yes", f"admin:relay:{relay.id}"]
    yes = _Callback(f"admin:relay:{relay.id}:del:yes")
    await panel.relay_delete_execute(yes, panel_services)  # type: ignore[arg-type]
    assert await world.relay_repo.count() == 0


async def test_toggles_from_the_card(world: _World, panel_services: Any) -> None:
    relay = await world.add_relay()
    await panel.relay_toggle(_Callback(f"admin:relay:{relay.id}:toggle:subs"), panel_services)  # type: ignore[arg-type]
    await panel.relay_toggle(_Callback(f"admin:relay:{relay.id}:toggle:enabled"), panel_services)  # type: ignore[arg-type]
    stored = await world.relay_repo.get_by_id(relay.id)
    assert stored is not None and not stored.in_subscriptions and not stored.enabled
    assert world.catalog.snapshot.enabled == ()


async def test_leaving_to_the_list_abandons_a_relay_wizard(world: _World, panel_services: Any) -> None:
    state = _State()
    await panel.relay_add_start(_Callback("admin:relay:add"), state, panel_services)  # type: ignore[arg-type]
    assert state.state == AdminRelayStates.add_name
    await panel.relays_panel(_Callback("admin:relays"), state, panel_services)  # type: ignore[arg-type]
    assert state.state is None


# ── bot startup ───────────────────────────────────────────────────────────────


async def test_bot_startup_seeds_once_and_then_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """create_app: the first start moves RELAY_* into the table and loads the
    snapshot every link builder reads; the next start leaves the table alone and
    says the variables are ignored."""
    import bot.app as app_module

    _minimal_env(monkeypatch, tmp_path)
    for name, value in {
        "BOT_TOKEN": "123456:test-token",
        "LOG_DIR": str(tmp_path / "logs"),
        "XRAY_CONFIG_PATH": str(tmp_path / "xray.json"),
        "XRAY_APPLY_MODE": "reload",
        "AWG_CONFIG_PATH": str(tmp_path / "awg.conf"),
        "RELAY_ENABLED": "true",
        "RELAY_HOST": RELAY_HOST,
        "RELAY_SOURCE_IPS": "198.51.100.7",
    }.items():
        monkeypatch.setenv(name, value)
    settings = load_settings()
    # The routers are module-level and attach to one Dispatcher per process; this
    # test is about startup state, not routing, so it does not attach them.
    monkeypatch.setattr(app_module.Dispatcher, "include_router", lambda self, router: router)

    async def start() -> Any:
        bot, _dp, db, _health, services = await app_module.create_app(settings)
        snapshot = services.relays.snapshot
        assert services.xray.relays is services.hysteria.relays is services.key_bundles.relays
        await bot.session.close()
        await db.close()
        return snapshot

    with caplog.at_level(logging.INFO, logger="services.relay_management"):
        first = await start()
    assert [relay.name for relay in first.relays] == ["ru1"]
    assert first.get("ru1").host == RELAY_HOST
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="services.relay_management"):
        second = await start()
    assert second.relays == first.relays
    assert any(
        record.levelno == logging.WARNING and "игнорируются" in record.getMessage() for record in caplog.records
    )
