"""Relay mode, display-name rules and the two all-in-one kinds.

Covers, end to end where it matters:

* settings — the legacy RELAY_* (now only a one-time seed) / SERVER_FLAG_EMOJI
  parsing and the cross-field checks;
* link rendering — a DIRECT key keeps every byte but the remark; a RELAY key
  differs from its direct twin ONLY by host and the relay's marker; a relay that
  is switched off, deleted or unknown is an error, never a silent fallback to the
  main host;
* creation through the real services with ``relay="ru1"`` — the label prefix and
  the hy2_auth lookup are exactly those of a direct key;
* subscriptions — basic and extended, with and without the relay, ordering, the
  skip-with-warning of a member whose relay is off, and a pre-v37 bundle rendering
  exactly as before;
* anomaly detection ignores relay egress IPs; the relay health latch alerts once
  per transition.

The relay itself is a row of the ``relays`` table (see services.relay_management
and tests/test_relay_admin.py for the panel side); the world below inserts it
through the repository, exactly as the admin panel would.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time as time_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, quote, unquote, urlsplit

import aiosqlite
import pytest

from adapters.clock import ClockProvider
from bot.bundles import bundle_config_text, bundle_created_text, bundle_detail_text
from conftest import make_relay, relay_snapshot

from bot.formatters import create_type_label, format_hysteria2_link, hysteria2_key_link, key_type_label
from config.settings import RelaySeed, Settings, SettingsError, load_settings, parse_ipv4_networks
from db.database import Database
from hy2_auth.store import ReadOnlyKeyStore
from i18n import t
from models.dto import KeyBundle, TelegramUserProfile, User, VpnKey
from models.enums import KeyBundleKind, KeyBundleStatus, UserRole, VpnKeyStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from repositories.relays import RelayRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.anomaly_detection import AnomalyDetectionService
from services.hysteria import HysteriaService
from services.key_bundles import KeyBundleService, bundle_composition, member_audit_name
from services.key_naming import NameStyle, key_display_name
from services.relay import (
    EMPTY_RELAYS,
    RelayCatalog,
    RelaySnapshot,
    RelayUnavailable,
    relay_link_host,
    require_relay_for_issue,
)
from services.relay_health import RelayHealthMonitor, relay_health_loop, tls_probe
from services.xray import XRAY_MANAGED_LABEL_RE, XrayService
from subscription_server.render import SubscriptionRenderError, render_links, render_subscription
from subscription_server.store import BundleView, ReadOnlyBundleStore

OWNER = 100
ADMIN = 1
FLAG = "🇫🇮"
RELAY_HOST = "relay.anycastedge.net"
DIRECT_HOST = "vpn.example.com"
MARKS = ("🟢", "🟡", "🟠", "🔴")


# ── harness ───────────────────────────────────────────────────────────────────


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = dict(
        bot_token="token",
        admin_ids=frozenset({ADMIN, 2}),
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
        subscription_rate_limit_seconds=0,
    )
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


class _Users:
    async def require_approved_or_admin(self, user_id: int) -> User:
        role = UserRole.SUPERADMIN if user_id == ADMIN else UserRole.APPROVED_USER
        return User(user_id, f"user{user_id}", "User", role, "now", "now", None)

    async def get_user(self, user_id: int) -> User:
        return await self.require_approved_or_admin(user_id)


class _Audit:
    async def write_best_effort(self, **kwargs: object) -> None:
        return None

    async def write(self, **kwargs: object) -> None:
        return None


class _Modules:
    async def is_enabled(self, name: str) -> bool:
        return True


class _Ids:
    """Deterministic ids shaped like the real generator (5-char suffixes)."""

    def __init__(self) -> None:
        self._n = 0

    def _next(self) -> int:
        self._n += 1
        return self._n

    def uuid4(self) -> str:
        return f"00000000-0000-4000-8000-{self._next():012d}"

    def generated_key_name(self, prefix: str) -> str:
        return f"{prefix}_A{self._next():04d}"

    def xray_short_id(self) -> str:
        return "ff69b6f523de0d17"

    def hysteria2_label(self) -> str:
        return f"hy2_B{self._next():04d}"


class _RecordingAdapter:
    def __init__(self) -> None:
        self.clients: list[dict[str, str]] = []

    async def add_client(self, **kwargs: object) -> object:
        self.clients.append({"id": str(kwargs["uuid_value"]), "email": str(kwargs["email_label"])})
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        return None


class _World:
    def __init__(self, db: Database, settings: Settings, xray: XrayService, hysteria: HysteriaService,
                 bundles: KeyBundleService, tcp_adapter: _RecordingAdapter, catalog: RelayCatalog) -> None:
        self.db = db
        self.settings = settings
        self.xray = xray
        self.hysteria = hysteria
        self.bundles = bundles
        self.tcp_adapter = tcp_adapter
        self.catalog = catalog
        self.repo = KeyBundleRepository(db)
        self.vpn_keys = VpnKeyRepository(db)
        self.relays = RelayRepository(db)

    async def refresh(self) -> RelaySnapshot:
        """Re-read the relays table into the services' catalog (what RelayService does)."""
        snapshot = RelaySnapshot.of(await self.relays.list_all())
        self.catalog.replace(snapshot)
        return snapshot

    async def set_relay(self, name: str = "ru1", **changes: object) -> None:
        relay = await self.relays.get_by_name(name)
        assert relay is not None
        await self.relays.update(relay.id, changes, now="2026-01-02T00:00:00+00:00", updated_by=None)
        await self.refresh()


async def _world(tmp_path: Path, *, relay_enabled: bool | None = True, **overrides: object) -> _World:
    """The real services over a real database holding one relay ``ru1``.

    *relay_enabled* True/False inserts ``ru1`` (host RELAY_HOST) enabled/disabled;
    None leaves the relays table empty.
    """
    settings = _settings(tmp_path, **overrides)
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    if relay_enabled is not None:
        await RelayRepository(db).create(
            name="ru1",
            label="relay",
            host=RELAY_HOST,
            source_ips=(ipaddress.IPv4Network("198.51.100.7/32"),),
            enabled=relay_enabled,
            now="2026-01-01T00:00:00+00:00",
        )
    catalog = RelayCatalog(RelaySnapshot.of(await RelayRepository(db).list_all()))
    users = UserRepository(db)
    for uid in (ADMIN, OWNER):
        await users.upsert_profile(TelegramUserProfile(uid, f"user{uid}", "User"), UserRole.APPROVED_USER, "now")
    vpn_keys = VpnKeyRepository(db)
    clock = ClockProvider()
    ids = _Ids()
    tcp_adapter = _RecordingAdapter()
    xray = XrayService(
        vpn_keys=vpn_keys,
        users=_Users(),  # type: ignore[arg-type]
        adapter=tcp_adapter,  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=ids,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        xhttp_adapter=_RecordingAdapter(),  # type: ignore[arg-type]
        relays=catalog,
    )
    hysteria = HysteriaService(
        vpn_keys=vpn_keys,
        users=_Users(),  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=ids,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        modules=_Modules(),  # type: ignore[arg-type]
        relays=catalog,
    )
    bundles = KeyBundleService(
        bundles=KeyBundleRepository(db),
        users=_Users(),  # type: ignore[arg-type]
        xray=xray,
        hysteria=hysteria,
        modules=_Modules(),  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=ids,  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        relays=catalog,
    )
    return _World(db, settings, xray, hysteria, bundles, tcp_adapter, catalog)


def _owner() -> TelegramUserProfile:
    return TelegramUserProfile(OWNER, f"user{OWNER}", "User")


def _key(
    key_type: VpnKeyType = VpnKeyType.XRAY,
    *,
    key_id: int = 1,
    label: str = "xray_tcp_ab12c",
    transport: str = "tcp",
    profile: str = "base",
    relay: str | None = None,
    spider_x: str | None = None,
) -> VpnKey:
    payload: dict[str, object]
    if key_type is VpnKeyType.HYSTERIA2:
        payload = {"secret": "00ff00ff", "email_label": label}
    else:
        payload = {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "email_label": label,
            "short_id": "abcd",
            "transport": transport,
            "xhttp_profile": profile,
        }
    return VpnKey(
        id=key_id,
        owner_user_id=OWNER,
        username="user",
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=str(payload.get("uuid")) if key_type is VpnKeyType.XRAY else None,
        email_label=label,
        public_key=None,
        client_ip=None,
        payload=payload,
        public_payload={"email_label": label, "short_id": "abcd"},
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        created_by=OWNER,
        revoked_by=None,
        deleted_by=None,
        transport=transport,
        xhttp_profile=profile,
        spider_x=spider_x,
        relay=relay,
    )


# The relay the link tests render through: ru1 → RELAY_HOST, marker "relay".
RU1 = relay_snapshot(make_relay(1, "ru1", host=RELAY_HOST))


def _renderer(settings: Settings, relays: RelaySnapshot = RU1) -> XrayService:
    service = XrayService.__new__(XrayService)
    service.settings = settings
    service.unix_clock = time_module.time
    service.relays = RelayCatalog(relays)
    return service


def _fragment(link: str) -> str:
    return unquote(link.split("#", 1)[1])


def _prefix(link: str) -> str:
    return link.split("#", 1)[0]


# ── settings ──────────────────────────────────────────────────────────────────


def _minimal_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))


def test_relay_settings_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """With no RELAY_* at all there is nothing to seed and nothing to warn about."""
    _minimal_env(monkeypatch, tmp_path)
    settings = load_settings()
    assert settings.relay_seed is None
    assert settings.relay_env_vars == ()
    assert settings.relay_health_interval == 300
    assert settings.server_flag_emoji == FLAG
    # The legacy fields are gone from Settings: nothing can read them as truth.
    for legacy in ("relay_enabled", "relay_name", "relay_host", "relay_source_ips"):
        assert not hasattr(settings, legacy)


@pytest.mark.parametrize("missing", ["RELAY_HOST", "RELAY_SOURCE_IPS"])
def test_relay_enabled_requires_host_and_source_ips(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing: str
) -> None:
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAY_ENABLED", "true")
    monkeypatch.setenv("RELAY_HOST", RELAY_HOST)
    monkeypatch.setenv("RELAY_SOURCE_IPS", "198.51.100.7")
    monkeypatch.delenv(missing)
    with pytest.raises(SettingsError, match=missing):
        load_settings()


def test_relay_enabled_with_everything_loads(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """RELAY_ENABLED=true + host + source IPs is parsed into the one-time seed."""
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAY_ENABLED", "true")
    monkeypatch.setenv("RELAY_NAME", "msk-2")
    monkeypatch.setenv("RELAY_HOST", RELAY_HOST)
    monkeypatch.setenv("RELAY_SOURCE_IPS", "198.51.100.7, 203.0.113.0/28")
    monkeypatch.setenv("RELAY_HEALTH_INTERVAL", "0")
    settings = load_settings()
    assert settings.relay_seed == RelaySeed(
        name="msk-2",
        host=RELAY_HOST,
        source_ips=(ipaddress.IPv4Network("198.51.100.7/32"), ipaddress.IPv4Network("203.0.113.0/28")),
    )
    assert settings.relay_env_vars == ("RELAY_ENABLED", "RELAY_NAME", "RELAY_HOST", "RELAY_SOURCE_IPS")
    assert settings.relay_health_interval == 0


def test_relay_disabled_in_env_seeds_nothing_but_is_noticed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAY_ENABLED", "false")
    monkeypatch.setenv("RELAY_HOST", RELAY_HOST)
    settings = load_settings()
    assert settings.relay_seed is None
    assert settings.relay_env_vars == ("RELAY_ENABLED", "RELAY_HOST")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("198.51.100.7", ("198.51.100.7/32",)),
        ("198.51.100.7,203.0.113.0/24", ("198.51.100.7/32", "203.0.113.0/24")),
        ("  198.51.100.7 ,   203.0.113.0/24  ", ("198.51.100.7/32", "203.0.113.0/24")),
        ("198.51.100.7,,203.0.113.0/24,", ("198.51.100.7/32", "203.0.113.0/24")),
        (",", ()),
        ("", ()),
        ("198.51.100.7,198.51.100.7/32", ("198.51.100.7/32",)),
    ],
)
def test_source_ip_parser_accepts(raw: str, expected: tuple[str, ...]) -> None:
    assert tuple(str(net) for net in parse_ipv4_networks("RELAY_SOURCE_IPS", raw)) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "198.51.100.7,garbage",
        "198.51.100.256",
        "198.51.100.7/33",
        "198.51.100.7/24",  # host bits set: strict
        "2001:db8::1",
        "relay.example.net",
        "198.51.100. 7",
        "198.51.100.7;203.0.113.1",
        "198.51.100.7\n",
        "198.51.100.7,\t203.0.113.0/24",
    ],
)
def test_source_ip_parser_rejects_garbage(raw: str) -> None:
    with pytest.raises(SettingsError):
        parse_ipv4_networks("RELAY_SOURCE_IPS", raw)


def test_garbage_source_ips_fail_startup_even_with_relay_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAY_SOURCE_IPS", "198.51.100.7,nope")
    with pytest.raises(SettingsError, match="RELAY_SOURCE_IPS"):
        load_settings()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RELAY_NAME", "RU1"),
        ("RELAY_NAME", "-ru1"),
        ("RELAY_NAME", "ru_1"),
        ("RELAY_NAME", "r" * 33),
        ("RELAY_HOST", "2001:db8::1"),
        ("RELAY_HOST", "bad host"),
        ("RELAY_HOST", "-bad.example.net"),
        ("RELAY_HOST", "1.2.3.256"),
        ("RELAY_HEALTH_INTERVAL", "-1"),
    ],
)
def test_relay_values_are_validated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, value: str
) -> None:
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv(name, value)
    with pytest.raises(SettingsError, match=name):
        load_settings()


@pytest.mark.parametrize("host", ["relay.anycastedge.net", "relay.anycastedge.net.", "203.0.113.5", "r1"])
def test_relay_host_accepts_dns_names_and_ipv4(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: str
) -> None:
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RELAY_ENABLED", "true")
    monkeypatch.setenv("RELAY_HOST", host)
    monkeypatch.setenv("RELAY_SOURCE_IPS", "198.51.100.7")
    seed = load_settings().relay_seed
    assert seed is not None and seed.host == host


def test_server_flag_emoji_custom_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv("SERVER_FLAG_EMOJI", "🇩🇪")
    assert load_settings().server_flag_emoji == "🇩🇪"


@pytest.mark.parametrize("value", ["", "   ", "🇫🇮\x07", "x" * 17])
def test_server_flag_emoji_is_validated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    _minimal_env(monkeypatch, tmp_path)
    monkeypatch.setenv("SERVER_FLAG_EMOJI", value)
    with pytest.raises(SettingsError, match="SERVER_FLAG_EMOJI"):
        load_settings()


# ── relay host resolution ─────────────────────────────────────────────────────


def test_relay_host_resolution() -> None:
    assert relay_link_host(RU1, None, direct_host="main") == "main"
    assert relay_link_host(RU1, "ru1", direct_host="main") == RELAY_HOST
    with pytest.raises(RelayUnavailable):
        relay_link_host(RU1, "ru2", direct_host="main")
    off = relay_snapshot(make_relay(1, "ru1", host=RELAY_HOST, enabled=False))
    assert relay_link_host(off, None, direct_host="main") == "main"
    with pytest.raises(RelayUnavailable) as excinfo:
        relay_link_host(off, "ru1", direct_host="main")
    assert excinfo.value.key == "err_relay_unavailable"
    assert excinfo.value.params == {"relay": "ru1"}
    # Deleted (no row at all): refused the same way, never the main host.
    with pytest.raises(RelayUnavailable):
        relay_link_host(EMPTY_RELAYS, "ru1", direct_host="main")
    # Two relays: each key goes to ITS relay's host.
    two = relay_snapshot(make_relay(1, "ru1", host="a.example.net"), make_relay(2, "ru2", label="b", host="b.example.net"))
    assert relay_link_host(two, "ru1", direct_host="main") == "a.example.net"
    assert relay_link_host(two, "ru2", direct_host="main") == "b.example.net"


def test_require_relay_for_issue() -> None:
    assert require_relay_for_issue(RU1, None) is None
    assert require_relay_for_issue(RU1, "") is None
    assert require_relay_for_issue(RU1, "ru1") == "ru1"
    with pytest.raises(RelayUnavailable):
        require_relay_for_issue(RU1, "ru2")
    with pytest.raises(RelayUnavailable):
        require_relay_for_issue(relay_snapshot(make_relay(1, "ru1", enabled=False)), "ru1")
    with pytest.raises(RelayUnavailable):
        require_relay_for_issue(EMPTY_RELAYS, "ru1")


# ── single-key rendering ──────────────────────────────────────────────────────

# The exact pre-change link of each direct key minus its fragment, spelled out
# literally so "byte-for-byte as before" is pinned rather than recomputed.
_EXPECTED_DIRECT_PREFIX = {
    ("tcp", "base"): (
        "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?type=tcp&security=reality"
        "&encryption=none&pbk=public&fp=chrome&sni=example.com&sid=abcd&flow=xtls-rprx-vision"
    ),
    ("http", "base"): (
        "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?type=xhttp&security=reality"
        "&encryption=none&pbk=public&fp=chrome&sni=example.com&sid=abcd"
        "&path=%2Fv1%2Fmessages%2Fstream&mode=stream-one"
    ),
    ("http", "multi"): (
        "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?type=xhttp&security=reality"
        "&encryption=none&pbk=public&fp=chrome&sni=example.com&sid=abcd"
        "&path=%2Fv1%2Fmessages%2Fstream&mode=packet-up&extra=%7B%22scMaxEachPostBytes%22%3A%22800000-1000000"
        "%22%2C%22scMinPostsIntervalMs%22%3A%2230-50%22%2C%22xmux%22%3A%7B%22maxConnections%22%3A2%2C"
        "%22cMaxReuseTimes%22%3A%2264-128%22%2C%22hMaxReusableSecs%22%3A%22180-300%22%7D%7D"
    ),
    ("http", "antisib"): (
        "vless://11111111-1111-4111-8111-111111111111@vpn.example.com:443?type=xhttp&security=reality"
        "&encryption=none&pbk=public&fp=chrome&sni=example.com&sid=abcd"
        "&path=%2Fv1%2Fmessages%2Fstream&mode=stream-one&extra=%7B%22xmux%22%3A%7B%22maxConnections%22%3A1"
        "%2C%22cMaxReuseTimes%22%3A%2264-128%22%7D%7D"
    ),
}
_VLESS_VARIANTS = [
    ("tcp", "base", "xray_tcp_ab12c"),
    ("http", "base", "xray_http_base_ab12c"),
    ("http", "multi", "xray_http_multi_ab12c"),
    ("http", "antisib", "xray_http_antisib_ab12c"),
]


@pytest.mark.parametrize(("transport", "profile", "label"), _VLESS_VARIANTS)
def test_direct_vless_link_changes_only_the_remark(
    tmp_path: Path, transport: str, profile: str, label: str
) -> None:
    service = _renderer(_settings(tmp_path))
    link = service.connection_link(_key(label=label, transport=transport, profile=profile))
    assert _prefix(link) == _EXPECTED_DIRECT_PREFIX[transport, profile]
    # The remark: <label>_<flag>, encoded exactly as before (urllib quote).
    assert link.split("#", 1)[1] == quote(f"{label}_{FLAG}")
    assert _fragment(link) == f"{label}_{FLAG}"


@pytest.mark.parametrize(("transport", "profile", "label"), _VLESS_VARIANTS)
def test_relay_vless_link_differs_only_by_host_and_marker(
    tmp_path: Path, transport: str, profile: str, label: str
) -> None:
    service = _renderer(_settings(tmp_path))
    direct = service.connection_link(_key(label=label, transport=transport, profile=profile))
    relay = service.connection_link(_key(label=label, transport=transport, profile=profile, relay="ru1"))
    assert _prefix(relay) == _prefix(direct).replace(f"@{DIRECT_HOST}:443", f"@{RELAY_HOST}:443")
    assert f"@{RELAY_HOST}:443?" in relay
    assert _fragment(relay) == f"{label}_relay_{FLAG}"
    # Everything in the query (sni, pbk, sid, fp, flow, path, mode, extra) is identical.
    assert parse_qs(urlsplit(relay).query) == parse_qs(urlsplit(direct).query)


def test_relay_vless_keeps_the_stored_spider_x(tmp_path: Path) -> None:
    service = _renderer(_settings(tmp_path))
    direct = service.connection_link(_key(spider_x="/a"))
    relay = service.connection_link(_key(spider_x="/a", relay="ru1"))
    assert "&spx=%2Fa#" in direct and "&spx=%2Fa#" in relay


def test_hysteria2_direct_and_relay_links(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    direct = hysteria2_key_link(_key(VpnKeyType.HYSTERIA2, label="hy2_x7k2p"), settings, RU1)
    relay = hysteria2_key_link(_key(VpnKeyType.HYSTERIA2, label="hy2_x7k2p", relay="ru1"), settings, RU1)
    # The direct link is the pre-change link, remark aside.
    assert _prefix(direct) == _prefix(
        format_hysteria2_link(
            "hy2_x7k2p", "00ff00ff", host=DIRECT_HOST, port=443, sni="anycastedge.duckdns.org"
        )
    )
    assert direct == "hysteria2://00ff00ff@vpn.example.com:443/?sni=anycastedge.duckdns.org#" + quote(
        f"hy2_x7k2p_{FLAG}", safe=""
    )
    assert relay == "hysteria2://00ff00ff@relay.anycastedge.net:443/?sni=anycastedge.duckdns.org#" + quote(
        f"hy2_x7k2p_relay_{FLAG}", safe=""
    )
    assert "sni=anycastedge.duckdns.org" in relay


@pytest.mark.parametrize(
    "relays",
    [
        relay_snapshot(make_relay(1, "ru1", host=RELAY_HOST, enabled=False)),  # switched off
        relay_snapshot(make_relay(1, "ru2", host=RELAY_HOST)),  # only another relay is known
        EMPTY_RELAYS,  # deleted
    ],
    ids=["disabled", "unknown", "deleted"],
)
def test_unknown_or_disabled_relay_never_falls_back(tmp_path: Path, relays: RelaySnapshot) -> None:
    settings = _settings(tmp_path)
    service = _renderer(settings, relays)
    with pytest.raises(RelayUnavailable):
        service.connection_link(_key(relay="ru1"))
    with pytest.raises(RelayUnavailable):
        hysteria2_key_link(_key(VpnKeyType.HYSTERIA2, label="hy2_x7k2p", relay="ru1"), settings, relays)
    # Direct keys are unaffected.
    assert DIRECT_HOST in service.connection_link(_key())


def test_display_name_rules(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    tcp = _key(label="xray_tcp_ab12c")
    tcp_relay = _key(label="xray_tcp_ab12c", relay="ru1")
    multi_relay = _key(label="xray_http_multi_ab12c", transport="http", profile="multi", relay="ru1")
    hy2 = _key(VpnKeyType.HYSTERIA2, label="hy2_x7k2p", relay="ru1")
    assert key_display_name(tcp, NameStyle.SINGLE, settings, RU1) == f"xray_tcp_ab12c_{FLAG}"
    assert key_display_name(tcp_relay, NameStyle.SINGLE, settings, RU1) == f"xray_tcp_ab12c_relay_{FLAG}"
    # In a basic subscription hy2 ends with "(alt.)" right after the flag — no separator;
    # the same key on its own, and VLESS in a basic subscription, do not.
    hy2_direct = _key(VpnKeyType.HYSTERIA2, label="hy2_x7k2p")
    assert key_display_name(hy2, NameStyle.BASIC, settings, RU1) == f"hy2_x7k2p_relay_{FLAG}(alt.)"
    assert key_display_name(hy2_direct, NameStyle.BASIC, settings, RU1) == f"hy2_x7k2p_{FLAG}(alt.)"
    assert key_display_name(hy2, NameStyle.SINGLE, settings, RU1) == f"hy2_x7k2p_relay_{FLAG}"
    assert key_display_name(tcp, NameStyle.BASIC, settings, RU1) == f"xray_tcp_ab12c_{FLAG}"
    assert key_display_name(tcp_relay, NameStyle.BASIC, settings, RU1) == f"xray_tcp_ab12c_relay_{FLAG}"
    assert "(alt.)" not in key_display_name(hy2, NameStyle.EXTENDED, settings, RU1)
    assert key_display_name(tcp, NameStyle.EXTENDED, settings, RU1) == "xray_tcp_ab12c_🟢"
    assert key_display_name(tcp_relay, NameStyle.EXTENDED, settings, RU1) == "xray_tcp_ab12c_relay_🟢"
    assert key_display_name(multi_relay, NameStyle.EXTENDED, settings, RU1) == "xray_http_multi_ab12c_relay_🟠"
    # A custom flag is used verbatim.
    flagged = _settings(tmp_path, server_flag_emoji="🇩🇪")
    assert key_display_name(tcp, NameStyle.SINGLE, flagged, RU1).endswith("_🇩🇪")


def test_display_name_uses_the_relays_label(tmp_path: Path) -> None:
    """The marker is the relay's label from the panel, not a constant."""
    settings = _settings(tmp_path)
    msk = relay_snapshot(make_relay(1, "ru1", label="msk"))
    tcp_relay = _key(label="xray_tcp_ab12c", relay="ru1")
    assert key_display_name(tcp_relay, NameStyle.SINGLE, settings, msk) == f"xray_tcp_ab12c_msk_{FLAG}"
    assert key_display_name(tcp_relay, NameStyle.EXTENDED, settings, msk) == "xray_tcp_ab12c_msk_🟢"
    # A switched-off relay still has its label (its link is refused by the host lookup).
    off = relay_snapshot(make_relay(1, "ru1", label="msk", enabled=False))
    assert key_display_name(tcp_relay, NameStyle.SINGLE, settings, off) == f"xray_tcp_ab12c_msk_{FLAG}"
    # A deleted relay: refused, like rendering its host would be.
    with pytest.raises(RelayUnavailable):
        key_display_name(tcp_relay, NameStyle.SINGLE, settings, EMPTY_RELAYS)
    # Direct keys never need a relay.
    assert key_display_name(_key(), NameStyle.SINGLE, settings, EMPTY_RELAYS) == f"xray_tcp_ab12c_{FLAG}"


def test_relay_marker_in_bot_labels() -> None:
    assert key_type_label(_key()) == "VLESS (TCP)"
    assert key_type_label(_key(relay="ru1")) == f"VLESS (TCP) · {t('relay_marker')}"
    assert key_type_label(_key(VpnKeyType.HYSTERIA2, label="hy2_x", relay="ru1")) == (
        f"Hysteria2 · {t('relay_marker')}"
    )
    assert create_type_label("xray", "http", "multi") == f"VLESS (HTTP) · {t('xhttp_profile_multi_name')}"
    assert create_type_label("xray", "http", "multi", relay="ru1").endswith(f" · {t('relay_marker')}")
    assert create_type_label("awg", relay="ru1") == "AmneziaWG"


# ── creation through the services ─────────────────────────────────────────────


async def test_create_relay_xray_key_keeps_the_direct_label_scheme(tmp_path: Path) -> None:
    world = await _world(tmp_path)
    try:
        for transport, profile in (("tcp", "base"), ("http", "multi")):
            result = await world.xray.create_xray_key(
                ADMIN, _owner(), None, transport=transport, xhttp_profile=profile, relay="ru1"
            )
            key = result.key
            assert key.relay == "ru1"
            prefix = "xray_tcp_" if transport == "tcp" else "xray_http_multi_"
            assert (key.email_label or "").startswith(prefix)
            assert XRAY_MANAGED_LABEL_RE.fullmatch(key.email_label or "")
            assert key.key_type is VpnKeyType.XRAY
            # The cached link and the config screen both point at the relay.
            assert f"@{RELAY_HOST}:443" in str(key.public_payload["link"])
            assert _fragment(str(key.public_payload["link"])) == f"{key.email_label}_relay_{FLAG}"
            assert world.xray.connection_link(key) == key.public_payload["link"]
            assert t("relay_marker") in result.config_text
        # The client went into the very same inbound, under its email label.
        assert [client["email"] for client in world.tcp_adapter.clients][0].startswith("xray_tcp_")
    finally:
        await world.db.close()


async def test_create_direct_key_cached_link_has_flag_remark(tmp_path: Path) -> None:
    world = await _world(tmp_path)
    try:
        key = (await world.xray.create_xray_key(ADMIN, _owner(), None)).key
        assert key.relay is None
        link = str(key.public_payload["link"])
        assert f"@{DIRECT_HOST}:443" in link
        assert _fragment(link) == f"{key.email_label}_{FLAG}"
    finally:
        await world.db.close()


async def test_hy2_relay_key_is_authenticated_by_hy2_auth_unchanged(tmp_path: Path) -> None:
    world = await _world(tmp_path)
    try:
        result = await world.hysteria.issue(ADMIN, _owner(), None, relay="ru1")
        key = result.key
        assert key.relay == "ru1"
        assert key.key_type is VpnKeyType.HYSTERIA2
        assert re.fullmatch(r"hy2_\w+", key.email_label or "")
        link = world.hysteria.connection_link(key)
        assert link.startswith(f"hysteria2://{key.payload['secret']}@{RELAY_HOST}:443/?sni=anycastedge.duckdns.org#")
        store = ReadOnlyKeyStore(world.db.path)
        await store.connect()
        try:
            assert await store.match(str(key.payload["secret"])) == key.email_label
        finally:
            await store.close()
    finally:
        await world.db.close()


@pytest.mark.parametrize("relay_enabled", [False, None], ids=["disabled", "absent"])
async def test_issuing_through_a_disabled_relay_writes_nothing(tmp_path: Path, relay_enabled: bool | None) -> None:
    world = await _world(tmp_path, relay_enabled=relay_enabled)
    try:
        with pytest.raises(RelayUnavailable):
            await world.xray.create_xray_key(ADMIN, _owner(), None, relay="ru1")
        with pytest.raises(RelayUnavailable):
            await world.hysteria.issue(ADMIN, _owner(), None, relay="ru1")
        assert await world.vpn_keys.count_by_owner(OWNER) == 0
        assert world.tcp_adapter.clients == []
    finally:
        await world.db.close()


async def test_repository_refuses_a_malformed_relay_name(tmp_path: Path) -> None:
    world = await _world(tmp_path)
    try:
        with pytest.raises(ValueError, match="relay"):
            await world.vpn_keys.create_pending(
                owner_user_id=OWNER, username="u", key_type=VpnKeyType.XRAY, note=None, payload={},
                public_payload={}, created_by=OWNER, now="now", relay="Bad Name",
            )
    finally:
        await world.db.close()


# ── bundle composition ────────────────────────────────────────────────────────


def test_composition_sizes() -> None:
    assert len(bundle_composition(KeyBundleKind.BASIC)) == 2
    assert len(bundle_composition(KeyBundleKind.BASIC, relays=("ru1",))) == 4
    assert len(bundle_composition(KeyBundleKind.EXTENDED)) == 5
    assert len(bundle_composition(KeyBundleKind.EXTENDED, relays=("ru1",))) == 10
    # One more group per relay, in the order the relays are given (relays.id).
    assert len(bundle_composition(KeyBundleKind.BASIC, relays=("ru1", "ru2"))) == 6
    assert len(bundle_composition(KeyBundleKind.EXTENDED, relays=("ru1", "ru2"))) == 15
    members = bundle_composition(KeyBundleKind.BASIC, relays=("ru1", "ru2"))
    assert [member_audit_name(m) for m in members] == [
        "xray_tcp", "hysteria2",
        "xray_tcp_relay_ru1", "hysteria2_relay_ru1",
        "xray_tcp_relay_ru2", "hysteria2_relay_ru2",
    ]


# ── subscriptions ─────────────────────────────────────────────────────────────


async def _view(world: _World, bundle_id: int) -> BundleView:
    """What the subscription endpoint builds: the bundle, its children, the relays table."""
    bundle = await world.repo.get_by_id(bundle_id)
    assert bundle is not None
    keys = tuple(await world.repo.list_keys_of_bundle(bundle_id))
    relays = RelaySnapshot.of(await world.relays.list_all())
    return BundleView(bundle=bundle, keys=keys, traffic=None, relays=relays)


def _member_of(name: str) -> str:
    """``xray_http_multi`` out of ``xray_http_multi_A0004[_relay]_🟠``."""
    if "_relay_" in name:
        return name.split("_relay_")[0].rsplit("_", 1)[0]
    return name.rsplit("_", 2)[0]


def _assert_no_circle(names: list[str]) -> None:
    for name in names:
        assert not any(mark in name for mark in MARKS), name


@pytest.mark.parametrize(("relay_on", "expected"), [(True, 4), (False, 2)])
async def test_basic_subscription(tmp_path: Path, relay_on: bool, expected: int) -> None:
    world = await _world(tmp_path, relay_enabled=relay_on)
    try:
        result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.BASIC)
        assert result.bundle.kind is KeyBundleKind.BASIC
        assert len(result.keys) == expected
        links = render_links(await _view(world, result.bundle.id), world.settings)
        assert len(links) == expected
        names = [_fragment(link) for link in links]
        labels = [key.email_label for key in sorted(result.keys, key=lambda k: (k.relay is not None, k.id))]
        expected_names = [
            f"{key.email_label}{'_relay' if key.relay else ''}_{FLAG}"
            f"{'(alt.)' if key.key_type is VpnKeyType.HYSTERIA2 else ''}"
            for key in sorted(result.keys, key=lambda k: (k.relay is not None, k.id))
        ]
        assert names == expected_names, labels
        _assert_no_circle(names)
        # VLESS before hy2 inside each group; direct before relay.
        assert links[0].startswith("vless://") and links[1].startswith("hysteria2://")
        assert all(DIRECT_HOST in link for link in links[:2])
        if relay_on:
            assert links[2].startswith("vless://") and links[3].startswith("hysteria2://")
            assert all(RELAY_HOST in link for link in links[2:])
        # No circles hint on any of the subscription's screens.
        legend = t("bundle_marks_legend")
        assert legend not in bundle_created_text(result, viewer_user_id=OWNER, settings=world.settings)
        assert legend not in bundle_detail_text(result.bundle, list(result.keys), viewer_user_id=OWNER)
        assert legend not in bundle_config_text(result.bundle, world.settings)
    finally:
        await world.db.close()


@pytest.mark.parametrize(("relay_on", "expected"), [(True, 10), (False, 5)])
async def test_extended_subscription(tmp_path: Path, relay_on: bool, expected: int) -> None:
    world = await _world(tmp_path, relay_enabled=relay_on)
    try:
        result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.EXTENDED)
        assert result.bundle.kind is KeyBundleKind.EXTENDED
        links = render_links(await _view(world, result.bundle.id), world.settings)
        assert len(links) == expected
        names = [_fragment(link) for link in links]
        direct, relayed = names[:5], names[5:]
        assert [name.rsplit("_", 1)[1] for name in direct] == ["🟢", "🟢", "🟡", "🟠", "🔴"]
        assert all("_relay_" not in name for name in direct)
        assert all(FLAG not in name for name in names)
        assert all(DIRECT_HOST in link for link in links[:5])
        if relay_on:
            # Each relay member carries its direct twin's circle, in the same order.
            assert [name.rsplit("_", 1)[1] for name in relayed] == ["🟢", "🟢", "🟡", "🟠", "🔴"]
            assert all("_relay_" in name for name in relayed)
            # …and is the same member (transport/profile) as the twin at its index.
            assert [_member_of(name) for name in relayed] == [_member_of(name) for name in direct]
            assert all(RELAY_HOST in link for link in links[5:])
        legend = t("bundle_marks_legend")
        assert legend in bundle_created_text(result, viewer_user_id=OWNER, settings=world.settings)
        assert legend in bundle_detail_text(result.bundle, list(result.keys), viewer_user_id=OWNER)
        assert legend in bundle_config_text(result.bundle, world.settings)
    finally:
        await world.db.close()


async def test_member_with_a_disabled_relay_is_skipped_not_404(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    world = await _world(tmp_path)
    try:
        result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.BASIC)
        assert len(render_links(await _view(world, result.bundle.id), world.settings)) == 4
        # Switched off in the panel (a write to the relays table)…
        await world.set_relay("ru1", enabled=False)
        view = await _view(world, result.bundle.id)
        with caplog.at_level(logging.WARNING, logger="subscription_server.render"):
            rendered = render_subscription(view, world.settings)
        assert len(render_links(view, world.settings)) == 2
        assert rendered.body
        assert any("relay" in record.getMessage() for record in caplog.records)
        # Through the real endpoint, which reads the table itself: still a 200.
        from aiohttp.test_utils import TestClient, TestServer

        from subscription_server.config import load_config
        from subscription_server.server import build_app

        store = ReadOnlyBundleStore(world.db.path)
        await store.connect()
        client = TestClient(TestServer(build_app(store, load_config(world.settings))))
        await client.start_server()
        try:
            resp = await client.get(f"/sub/{result.bundle.token}")
            assert resp.status == 200
            import base64

            links = base64.b64decode(await resp.text()).decode().splitlines()
            assert len(links) == 2 and all(RELAY_HOST not in link for link in links)
        finally:
            await client.close()
            await store.close()
    finally:
        await world.db.close()


async def test_a_bundle_with_only_unrenderable_members_is_still_fail_closed(tmp_path: Path) -> None:
    """Skipping never yields an empty 200: nothing left to serve is the usual 404."""
    world = await _world(tmp_path)
    try:
        result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.BASIC)
        view = await _view(world, result.bundle.id)
        relay_only = BundleView(
            bundle=view.bundle,
            keys=tuple(k for k in view.keys if k.relay),
            traffic=None,
            relays=relay_snapshot(make_relay(1, "ru1", host=RELAY_HOST, enabled=False)),
        )
        with pytest.raises(SubscriptionRenderError):
            render_subscription(relay_only, world.settings)
    finally:
        await world.db.close()


async def test_pre_v37_bundle_renders_exactly_as_before(tmp_path: Path) -> None:
    """A v36 database upgraded to v37: keys are direct, the bundle is extended, and
    its subscription is the pre-change one — ``<label>_<circle>``, main host, no flag."""
    from test_schema_upgrade_path import _materialise

    db_path = tmp_path / "vpn.db"
    await _materialise(db_path, 36)
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
        async with aiosqlite.connect(db_path) as conn:
            relays = [row[0] for row in await (await conn.execute("SELECT relay FROM vpn_keys")).fetchall()]
            kinds = [row[0] for row in await (await conn.execute("SELECT kind FROM key_bundles")).fetchall()]
        assert relays and all(value is None for value in relays)
        assert kinds == ["extended"]
        repo = KeyBundleRepository(db)
        bundle = await repo.get_by_id(1)
        assert bundle is not None and bundle.kind is KeyBundleKind.EXTENDED
        view = BundleView(bundle=bundle, keys=tuple(await repo.list_keys_of_bundle(1)), traffic=None)
        links = render_links(view, _settings(tmp_path))
        assert links == (
            "vless://33333333-3333-4333-8333-333333333333@vpn.example.com:443?type=tcp&security=reality"
            "&encryption=none&pbk=public&fp=chrome&sni=example.com&sid=abcd&flow=xtls-rprx-vision#"
            + quote("xray_tcp_Cc333_🟢"),
            "hysteria2://11ee@vpn.example.com:443/?sni=anycastedge.duckdns.org#" + quote("hy2_Dd444_🟢", safe=""),
        )
    finally:
        await db.close()


def test_bundle_screens_show_the_kind(tmp_path: Path) -> None:
    bundle = KeyBundle(
        id=1, user_id=OWNER, label="bundle_x", note=None, status=KeyBundleStatus.ACTIVE, token="tok",
        created_at="2026-01-01T00:00:00+00:00", updated_at="2026-01-01T00:00:00+00:00",
        revoked_at=None, deleted_at=None, display_no=5, kind=KeyBundleKind.BASIC,
    )
    text = bundle_detail_text(bundle, [], viewer_user_id=OWNER)
    assert f"{t('field_bundle_kind')}: {t('bundle_kind_basic')}" in text


# ── anomaly detection ─────────────────────────────────────────────────────────


class _RelayTable:
    """The relays table as anomaly detection reads it (``list_all``), editable."""

    def __init__(self, *relays: Any) -> None:
        self.rows = list(relays)
        self.fail = False

    async def list_all(self) -> list[Any]:
        if self.fail:
            raise RuntimeError("database is locked")
        return list(self.rows)


def _anomaly(**kwargs: object) -> AnomalyDetectionService:
    defaults: dict[str, object] = dict(
        vpn_keys=AsyncMock(),
        awg=AsyncMock(),
        xray_service=AsyncMock(),
        awg_service=AsyncMock(),
        admin_ids=frozenset([999]),
        window_seconds=3600,
        unique_nets=2,
        auto_revoke=False,
        cooldown_seconds=7200,
        xray_access_log_path="",
        concurrent_window_seconds=0,
        relays=_RelayTable(
            make_relay(1, "ru1", source_ips="198.51.100.0/29"),
            # A switched-off relay's addresses are excluded too: its clients may
            # still be connected.
            make_relay(2, "ru2", label="b", source_ips="203.0.113.9", enabled=False),
        ),
    )
    defaults.update(kwargs)
    return AnomalyDetectionService(**defaults)  # type: ignore[arg-type]


async def test_relay_source_ips_are_not_recorded() -> None:
    svc = _anomaly()
    await svc._refresh_relay_source_ips()
    now = time_module.time()
    for ip in ("198.51.100.1", "198.51.100.7", "203.0.113.9", "[::ffff:203.0.113.9]", "::ffff:198.51.100.2"):
        svc._record_ip(1, now, ip)
    assert svc._unique_ips_in_window(1, now) == frozenset()
    # Everything else is recorded exactly as before, including the neighbours.
    for ip in ("198.51.100.8", "203.0.113.10", "2001:db8::1", "not-an-ip"):
        svc._record_ip(1, now, ip)
    assert svc._unique_ips_in_window(1, now) == frozenset({"198.51.100.8", "203.0.113.10", "2001:db8::1", "not-an-ip"})


async def test_without_relay_ips_nothing_changes() -> None:
    svc = _anomaly(relays=_RelayTable())
    await svc._refresh_relay_source_ips()
    now = time_module.time()
    svc._record_ip(1, now, "198.51.100.1")
    assert svc._unique_ips_in_window(1, now) == frozenset({"198.51.100.1"})


async def test_relay_ip_does_not_push_a_key_over_the_threshold() -> None:
    vpn_keys = AsyncMock()
    key = _key()
    vpn_keys.get_by_id.return_value = key
    svc = _anomaly(vpn_keys=vpn_keys, unique_nets=2)
    await svc._refresh_relay_source_ips()
    svc.bot = AsyncMock()
    now = time_module.time()
    svc._record_ip(1, now, "192.0.2.10")
    svc._record_ip(1, now, "198.51.100.3")  # relay egress: ignored
    await svc._check_thresholds(now)
    svc.bot.send_message.assert_not_called()
    svc._record_ip(1, now, "192.0.3.10")  # a second real network: alert
    await svc._check_thresholds(now)
    svc.bot.send_message.assert_called()


# ── health monitor ────────────────────────────────────────────────────────────


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


async def test_health_alerts_exactly_once_per_transition() -> None:
    outcomes: list[bool] = []
    events: list[str] = []
    clock = _Clock()

    async def probe() -> bool:
        return outcomes.pop(0)

    async def down() -> None:
        events.append("down")

    async def up() -> None:
        events.append("up")

    monitor = RelayHealthMonitor(probe=probe, on_down=down, on_recovered=up, fail_window=300, recover_window=300, clock=clock)
    # A single failure (and a single success in between) never alerts.
    for ok in (True, False, True, False):
        outcomes.append(ok)
        await monitor.check_once()
        clock.now += 300
    assert events == []
    # Sustained failure: exactly one "down", however long it lasts.
    for _ in range(5):
        outcomes.append(False)
        await monitor.check_once()
        clock.now += 300
    assert events == ["down"]
    assert monitor.healthy is False
    # Sustained recovery: exactly one "up".
    for _ in range(5):
        outcomes.append(True)
        await monitor.check_once()
        clock.now += 300
    assert events == ["down", "up"]
    assert monitor.healthy is True


async def test_probe_exception_counts_as_failure_and_never_escapes() -> None:
    events: list[str] = []
    clock = _Clock()

    async def probe() -> bool:
        raise RuntimeError("boom")

    async def down() -> None:
        events.append("down")
        raise RuntimeError("telegram is down too")

    async def up() -> None:
        events.append("up")

    monitor = RelayHealthMonitor(probe=probe, on_down=down, on_recovered=up, fail_window=10, recover_window=10, clock=clock)
    assert await monitor.check_once() is False
    clock.now += 10
    assert await monitor.check_once() is False  # callback raised: swallowed
    assert events == ["down"]


async def test_health_loop_survives_a_failing_iteration(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    class _Monitor:
        async def check_once(self) -> bool:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("unexpected")
            return True

    sleeps = 0

    async def fake_sleep(_: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr("services.relay_health.asyncio.sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await relay_health_loop(_Monitor(), 300)  # type: ignore[arg-type]
    assert calls == 3


async def test_tls_probe_never_raises_on_a_dead_port() -> None:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    assert await tls_probe("127.0.0.1", port, "example.com", timeout=2) is False
    # A plain-TCP listener that is not TLS fails the handshake, not the caller.
    plain = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    try:
        plain_port = plain.sockets[0].getsockname()[1]
        assert await tls_probe("127.0.0.1", plain_port, "example.com", timeout=2) is False
    finally:
        plain.close()
        await plain.wait_closed()


async def test_qr_delivery_of_relay_keys_points_at_the_relay(tmp_path: Path) -> None:
    """The QR (bot.handlers.common.config_delivery) is the same string the config
    screen shows — relay host and relay name included."""
    from bot.handlers.common import config_delivery

    world = await _world(tmp_path)
    try:
        services = SimpleNamespace(xray=world.xray, hysteria=world.hysteria)
        vless = (await world.xray.create_xray_key(ADMIN, _owner(), None, relay="ru1")).key
        hy2 = (await world.hysteria.issue(ADMIN, _owner(), None, relay="ru1")).key
        vless_qr, document = await config_delivery(services, ADMIN, vless)  # type: ignore[arg-type]
        assert document is None
        assert vless_qr == world.xray.connection_link(vless)
        assert f"@{RELAY_HOST}:443" in vless_qr and _fragment(vless_qr).endswith(f"_relay_{FLAG}")
        hy2_qr, _ = await config_delivery(services, ADMIN, hy2)  # type: ignore[arg-type]
        assert hy2_qr == world.hysteria.connection_link(hy2)
        assert f"@{RELAY_HOST}:443/" in hy2_qr
        # The config screens carry the same links.
        assert vless_qr in (await world.xray.get_xray_key_config(ADMIN, vless.id)).replace("&amp;", "&")
        assert hy2_qr in (await world.hysteria.get_config(ADMIN, hy2.id)).replace("&amp;", "&")
    finally:
        await world.db.close()


async def test_fingerprint_change_keeps_relay_host_and_name(tmp_path: Path) -> None:
    world = await _world(tmp_path)
    try:
        key = (await world.xray.create_xray_key(ADMIN, _owner(), None, relay="ru1")).key
        updated = await world.xray.change_fingerprint(OWNER, key.id, "safari")
        link = str(updated.public_payload["link"])
        assert "fp=safari" in link
        assert f"@{RELAY_HOST}:443" in link
        assert _fragment(link) == f"{key.email_label}_relay_{FLAG}"
    finally:
        await world.db.close()


async def test_built_monitor_alerts_every_admin_once_per_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wired monitor probes <relay host>:XRAY_PUBLIC_PORT with SNI=XRAY_SNI and
    tells every ADMIN_IDS chat — naming the relay's label, name and host; one admin
    who cannot be reached does not stop the others."""
    from services import relay_health

    settings = _settings(tmp_path, relay_health_interval=0)
    probes: list[tuple[str, int, str]] = []
    outcome = {"ok": False}

    async def fake_probe(host: str, port: int, sni: str, **_: object) -> bool:
        probes.append((host, port, sni))
        return outcome["ok"]

    monkeypatch.setattr(relay_health, "tls_probe", fake_probe)
    sent: list[tuple[int, str]] = []

    class _Bot:
        async def send_message(self, chat_id: int, text: str) -> None:
            if chat_id == 2:
                raise RuntimeError("blocked the bot")
            sent.append((chat_id, text))

    table = _RelayTable(make_relay(1, "ru1", host=RELAY_HOST))
    monitor = relay_health.build_relay_health_supervisor(settings, table.list_all)
    monitor.bot = _Bot()  # type: ignore[assignment]
    for _ in range(3):
        await monitor.check_once()
    assert probes[0] == (RELAY_HOST, 443, "example.com")
    params = {"label": "relay", "name": "ru1", "host": RELAY_HOST, "port": 443}
    assert sent == [(ADMIN, t("relay_alert_down", **params))]
    outcome["ok"] = True
    for _ in range(3):
        await monitor.check_once()
    assert sent[-1] == (ADMIN, t("relay_alert_recovered", **params))
    assert len(sent) == 2


async def test_bundle_fingerprint_change_completes_while_the_relay_is_off(tmp_path: Path) -> None:
    """The fingerprint is a property of the key, not of its link: switching the
    relay off must not make a bundle's fingerprint change fail half-way on its
    first relay child (and fail the same way on every retry)."""
    world = await _world(tmp_path)
    try:
        result = await world.bundles.create_bundle(ADMIN, _owner(), None, kind=KeyBundleKind.BASIC)
        relay_child = next(k for k in result.keys if k.relay and k.key_type is VpnKeyType.XRAY)
        await world.set_relay("ru1", enabled=False)

        _, changed = await world.bundles.change_fingerprint(OWNER, result.bundle.id, "safari")
        assert changed == 2

        stored = await world.vpn_keys.get_by_id(relay_child.id)
        assert stored is not None
        assert stored.payload["fingerprint"] == "safari"
        # The relay link cannot be rendered now, so no stale one is kept cached…
        assert "link" not in stored.public_payload
        # …and once the relay is back the link carries the new fingerprint.
        await world.set_relay("ru1", enabled=True)
        assert "fp=safari" in world.xray.connection_link(stored)
    finally:
        await world.db.close()
