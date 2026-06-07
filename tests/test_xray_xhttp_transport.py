"""Tests for the second VLESS transport (XHTTP+REALITY).

Covers create/remove routing by transport into the right adapter/inbound, the
VLESS link builder for both transports, the transport DB migration (default
'tcp' + backfill + idempotency) and the new transport selection UI.
"""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import aiosqlite
import pytest

from adapters.clock import ClockProvider
from bot.formatters import key_type_label
from bot.keyboards.admin import admin_key_type_keyboard, admin_vless_transport_keyboard
from bot.keyboards.keys import create_key_keyboard, vless_transport_keyboard
from config.settings import Settings
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.backend_health import BackendHealth
from services.errors import InvalidOperation
from services.user_locks import UserLockManager
from services.xray import XrayService


def _settings(tmp_path: Path, *, xhttp_enabled: bool = True) -> Settings:
    return Settings(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="vless-in",
        xray_public_host="vpn.example.com",
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
        awg_endpoint_host="vpn.example.com",
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
        xray_xhttp_enabled=xhttp_enabled,
        xray_xhttp_inbound_tag="vless-xhttp-reality",
        xray_xhttp_port=8443,
        xray_xhttp_path="/v1/messages/stream",
        xray_xhttp_mode="packet-up",
    )


class _Users:
    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)


class _Audit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    async def write(self, *, action: str, **kwargs: object) -> None:
        self.actions.append(action)


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def uuid4(self) -> str:
        self._n += 1
        return f"00000000-0000-4000-8000-0000000000{self._n:02d}"

    def generated_key_name(self, prefix: str) -> str:
        return f"{prefix}_A{self._n:04d}"

    def xray_short_id(self) -> str:
        return "ff69b6f523de0d17"


class _RecordingAdapter:
    """Records add/remove client calls and pretends the inbound is empty."""

    def __init__(self) -> None:
        self.add_calls: list[dict[str, object]] = []
        self.remove_calls: list[dict[str, object]] = []

    async def add_client(self, **kwargs: object) -> object:
        self.add_calls.append(dict(kwargs))
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        self.remove_calls.append(dict(kwargs))

    def find_client(self, **kwargs: object) -> None:
        return None

    def list_clients(self) -> list[dict[str, object]]:
        return []

    def list_short_ids(self) -> set[str]:
        return set()


async def _make_service(
    tmp_path: Path,
    *,
    xhttp_enabled: bool = True,
) -> tuple[XrayService, VpnKeyRepository, _RecordingAdapter, _RecordingAdapter, Database]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    repo = VpnKeyRepository(db)
    await repo.db.conn.execute(
        "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (100, "user", "User", UserRole.APPROVED_USER.value, "now", "now"),
    )
    await repo.db.commit()
    tcp = _RecordingAdapter()
    http = _RecordingAdapter()
    service = XrayService(
        vpn_keys=repo,
        users=_Users(),  # type: ignore[arg-type]
        adapter=tcp,  # type: ignore[arg-type]
        settings=_settings(tmp_path, xhttp_enabled=xhttp_enabled),
        clock=ClockProvider(),
        ids=_Ids(),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        user_locks=UserLockManager(),
        backend_health=BackendHealth(),
        xhttp_adapter=http if xhttp_enabled else None,
    )
    return service, repo, tcp, http, db


def test_create_tcp_routes_to_tcp_inbound_with_flow(tmp_path: Path) -> None:
    async def run() -> None:
        service, repo, tcp, http, db = await _make_service(tmp_path)
        try:
            result = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="tcp"
            )
            assert len(tcp.add_calls) == 1
            assert tcp.add_calls[0]["flow"] == "xtls-rprx-vision"
            assert http.add_calls == []
            persisted = await repo.get_by_id(result.key.id)
            assert persisted is not None
            assert persisted.transport == "tcp"
            assert persisted.payload.get("transport") == "tcp"
        finally:
            await db.close()

    asyncio.run(run())


def test_create_http_routes_to_xhttp_inbound_without_flow(tmp_path: Path) -> None:
    async def run() -> None:
        service, repo, tcp, http, db = await _make_service(tmp_path)
        try:
            result = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="http"
            )
            assert len(http.add_calls) == 1
            # XHTTP clients must never carry a flow.
            assert http.add_calls[0]["flow"] == ""
            assert tcp.add_calls == []
            persisted = await repo.get_by_id(result.key.id)
            assert persisted is not None
            assert persisted.transport == "http"
            assert persisted.payload.get("flow") == ""
        finally:
            await db.close()

    asyncio.run(run())


def test_create_http_when_disabled_raises_and_persists_nothing(tmp_path: Path) -> None:
    async def run() -> None:
        service, repo, tcp, _http, db = await _make_service(tmp_path, xhttp_enabled=False)
        try:
            with pytest.raises(InvalidOperation):
                await service.create_xray_key(
                    100, TelegramUserProfile(100, "user", "User"), None, transport="http"
                )
            assert tcp.add_calls == []
            cursor = await repo.db.conn.execute("SELECT COUNT(*) AS c FROM vpn_keys")
            row = await cursor.fetchone()
            assert int(row["c"]) == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_delete_routes_removal_by_saved_transport(tmp_path: Path) -> None:
    async def run() -> None:
        service, _repo, tcp, http, db = await _make_service(tmp_path)
        try:
            http_key = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="http"
            )
            tcp_key = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="tcp"
            )
            tcp.remove_calls.clear()
            http.remove_calls.clear()

            await service.delete_xray_key(100, http_key.key.id)
            assert len(http.remove_calls) == 1
            assert tcp.remove_calls == []

            await service.delete_xray_key(100, tcp_key.key.id)
            assert len(tcp.remove_calls) == 1
        finally:
            await db.close()

    asyncio.run(run())


def test_build_vless_link_tcp_is_unchanged(tmp_path: Path) -> None:
    async def run() -> None:
        service, _repo, _tcp, _http, db = await _make_service(tmp_path)
        try:
            link = service._build_vless_link("uuid-1", "abcd", "xray_A0001", transport="tcp")
            parts = urlsplit(link)
            assert parts.scheme == "vless"
            assert parts.port == 443
            params = parse_qs(parts.query)
            assert params["type"] == ["tcp"]
            assert params["security"] == ["reality"]
            assert params["flow"] == ["xtls-rprx-vision"]
            assert "path" not in params
            assert "mode" not in params
        finally:
            await db.close()

    asyncio.run(run())


def test_build_vless_link_http_uses_xhttp_no_flow(tmp_path: Path) -> None:
    async def run() -> None:
        service, _repo, _tcp, _http, db = await _make_service(tmp_path)
        try:
            link = service._build_vless_link("uuid-1", "abcd", "xray_A0001", transport="http")
            parts = urlsplit(link)
            assert parts.port == 8443
            params = parse_qs(parts.query)
            assert params["type"] == ["xhttp"]
            assert params["security"] == ["reality"]
            assert params["encryption"] == ["none"]
            assert params["path"] == ["/v1/messages/stream"]
            assert params["mode"] == ["packet-up"]
            assert params["sid"] == ["abcd"]
            # No flow for XHTTP, and server-side `extra` tuning is not in the link.
            assert "flow" not in params
            assert "xPaddingBytes" not in parts.query
            assert "scMaxEachPostBytes" not in parts.query
        finally:
            await db.close()

    asyncio.run(run())


def test_key_type_label_by_protocol_and_transport() -> None:
    def _vpn_key(key_type: VpnKeyType, transport: str) -> VpnKey:
        return VpnKey(
            id=1,
            owner_user_id=100,
            username="user",
            key_type=key_type,
            status=VpnKeyStatus.ACTIVE,
            note=None,
            uuid="u",
            email_label="label",
            public_key=None,
            client_ip=None,
            payload={},
            public_payload={},
            created_at="now",
            updated_at="now",
            revoked_at=None,
            deleted_at=None,
            created_by=100,
            revoked_by=None,
            deleted_by=None,
            transport=transport,
        )

    assert key_type_label(_vpn_key(VpnKeyType.XRAY, "tcp")) == "VLESS (TCP)"
    assert key_type_label(_vpn_key(VpnKeyType.XRAY, "http")) == "VLESS (HTTP)"
    assert key_type_label(_vpn_key(VpnKeyType.AWG, "tcp")) == "AmneziaWG"
    # Legacy/unknown transport on an Xray key reads as TCP.
    assert key_type_label(_vpn_key(VpnKeyType.XRAY, "")) == "VLESS (TCP)"


def _button_texts(markup: object) -> list[str]:
    return [b.text for row in markup.inline_keyboard for b in row]  # type: ignore[attr-defined]


def _button_callbacks(markup: object) -> list[str]:
    return [b.callback_data for row in markup.inline_keyboard for b in row]  # type: ignore[attr-defined]


def test_create_key_keyboard_offers_vless_protocol() -> None:
    markup = create_key_keyboard(xray_enabled=True, awg_enabled=True)
    assert "VLESS" in _button_texts(markup)
    assert "AmneziaWG 2.0" in _button_texts(markup)
    assert "keys:proto:vless" in _button_callbacks(markup)


def test_vless_transport_keyboard_hides_http_when_disabled() -> None:
    enabled = vless_transport_keyboard(xhttp_enabled=True)
    assert "VLESS (TCP)" in _button_texts(enabled)
    assert "VLESS (HTTP)" in _button_texts(enabled)
    assert "keys:create:xray" in _button_callbacks(enabled)
    assert "keys:create:xhttp" in _button_callbacks(enabled)

    disabled = vless_transport_keyboard(xhttp_enabled=False)
    assert "VLESS (HTTP)" not in _button_texts(disabled)
    assert "keys:create:xhttp" not in _button_callbacks(disabled)


def test_admin_transport_keyboard_routes_by_user() -> None:
    proto = admin_key_type_keyboard(555, xray_enabled=True, awg_enabled=True)
    assert "admin:proto:vless:555" in _button_callbacks(proto)

    enabled = admin_vless_transport_keyboard(555, xhttp_enabled=True)
    assert "admin:ctype:xray:555" in _button_callbacks(enabled)
    assert "admin:ctype:xhttp:555" in _button_callbacks(enabled)

    disabled = admin_vless_transport_keyboard(555, xhttp_enabled=False)
    assert "admin:ctype:xhttp:555" not in _button_callbacks(disabled)


def test_migration_defaults_transport_to_tcp(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        await db.bootstrap()
        try:
            cols = await db._table_columns("vpn_keys")
            assert "transport" in cols
            await db.conn.execute(
                "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (100, "user", "User", UserRole.APPROVED_USER.value, "now", "now"),
            )
            repo = VpnKeyRepository(db)
            # Insert without specifying transport -> column default 'tcp'.
            key = await repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                uuid="u-default",
                email_label="label-default",
            )
            reloaded = await repo.get_by_id(key.id)
            assert reloaded is not None
            assert reloaded.transport == "tcp"

            # Idempotent: re-running the migration is a no-op and never errors.
            await db._migrate_v23()
            await db._migrate_v23()
            assert "transport" in await db._table_columns("vpn_keys")
        finally:
            await db.close()

    asyncio.run(run())


def test_migration_backfills_existing_rows_to_tcp(tmp_path: Path) -> None:
    """ALTER TABLE ADD COLUMN ... NOT NULL DEFAULT 'tcp' backfills legacy rows."""

    async def run() -> None:
        path = tmp_path / "legacy.db"
        conn = await aiosqlite.connect(path)
        try:
            await conn.execute("CREATE TABLE vpn_keys_legacy (id INTEGER PRIMARY KEY, uuid TEXT)")
            await conn.execute("INSERT INTO vpn_keys_legacy (id, uuid) VALUES (1, 'old')")
            await conn.execute("INSERT INTO vpn_keys_legacy (id, uuid) VALUES (2, 'old2')")
            await conn.commit()
            await conn.execute(
                "ALTER TABLE vpn_keys_legacy ADD COLUMN transport TEXT NOT NULL DEFAULT 'tcp'"
            )
            await conn.commit()
            cursor = await conn.execute("SELECT transport FROM vpn_keys_legacy ORDER BY id")
            rows = await cursor.fetchall()
            assert [r[0] for r in rows] == ["tcp", "tcp"]
        finally:
            await conn.close()

    asyncio.run(run())
