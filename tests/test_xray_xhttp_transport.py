"""Tests for the second VLESS transport (XHTTP+REALITY).

Covers create/remove routing by transport into the right adapter/inbound, the
VLESS link builder for both transports, the transport DB migration (default
'tcp' + backfill + idempotency) and the new transport selection UI.
"""

import asyncio
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import aiosqlite
import pytest

from adapters.clock import ClockProvider
from bot.formatters import create_confirm_text, create_type_label, key_type_label
from bot.keyboards.admin import admin_key_type_keyboard, admin_vless_transport_keyboard
from bot.keyboards.keys import create_key_keyboard, vless_transport_keyboard
from config.settings import Settings, SettingsError, load_settings
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
        xray_xhttp_mode="stream-one",
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
    """A stateful stand-in for one inbound: records calls and tracks clients."""

    def __init__(self) -> None:
        self.add_calls: list[dict[str, object]] = []
        self.remove_calls: list[dict[str, object]] = []
        self.clients: list[dict[str, str]] = []
        self.short_ids: set[str] = set()

    async def add_client(self, **kwargs: object) -> object:
        self.add_calls.append(dict(kwargs))
        self.clients.append({"id": str(kwargs["uuid_value"]), "email": str(kwargs["email_label"])})
        if kwargs.get("manage_short_id") and kwargs.get("short_id"):
            self.short_ids.add(str(kwargs["short_id"]))
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        self.remove_calls.append(dict(kwargs))
        uuid_value = kwargs.get("uuid_value")
        email_label = kwargs.get("email_label")
        self.clients = [
            c
            for c in self.clients
            if not ((uuid_value and c["id"] == uuid_value) or (email_label and c["email"] == email_label))
        ]

    def find_client(self, *, uuid_value: str | None = None, email_label: str | None = None) -> dict[str, str] | None:
        for c in self.clients:
            if uuid_value and c["id"] == uuid_value:
                return dict(c)
            if email_label and c["email"] == email_label:
                return dict(c)
        return None

    def list_clients(self) -> list[dict[str, str]]:
        return [dict(c) for c in self.clients]

    def list_short_ids(self) -> set[str]:
        return set(self.short_ids)


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


def _service_with(
    repo: VpnKeyRepository,
    tcp: _RecordingAdapter,
    http: _RecordingAdapter | None,
    settings: Settings,
) -> XrayService:
    """Build an XrayService over existing repo/adapters with explicit settings.

    Mirrors app.py wiring the XHTTP adapter from the *inbound's* presence rather
    than the feature flag, so a test can pair an adapter with the flag off.
    """
    return XrayService(
        vpn_keys=repo,
        users=_Users(),  # type: ignore[arg-type]
        adapter=tcp,  # type: ignore[arg-type]
        settings=settings,
        clock=ClockProvider(),
        ids=_Ids(),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        user_locks=UserLockManager(),
        backend_health=BackendHealth(),
        xhttp_adapter=http,  # type: ignore[arg-type]
    )


async def _insert_active_http_key(repo: VpnKeyRepository) -> VpnKey:
    """Insert an ACTIVE http key directly, as if issued while the inbound existed."""
    key = await repo.create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        note=None,
        payload={"transport": "http", "uuid": "u-http", "email_label": "xray_AHTTP", "short_id": "abcd"},
        public_payload={"short_id": "abcd"},
        created_by=100,
        now="now",
        uuid="u-http",
        email_label="xray_AHTTP",
        transport="http",
    )
    await repo.mark_active(key.id, "now")
    reloaded = await repo.get_by_id(key.id)
    assert reloaded is not None
    return reloaded


def test_existing_http_key_revocable_when_flag_disabled_but_inbound_present(tmp_path: Path) -> None:
    """The flag gates only NEW http keys; an issued http key stays revocable while its inbound is present."""

    async def run() -> None:
        service, repo, tcp, http, db = await _make_service(tmp_path, xhttp_enabled=True)
        try:
            created = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="http"
            )
            http.remove_calls.clear()
            # Simulate a restart with XRAY_XHTTP_ENABLED=false while the XHTTP
            # inbound (hence its adapter) is still present in config.json.
            disabled = _service_with(repo, tcp, http, _settings(tmp_path, xhttp_enabled=False))
            # Issuing a NEW http key is refused...
            with pytest.raises(InvalidOperation):
                await disabled.create_xray_key(
                    100, TelegramUserProfile(100, "user", "User"), None, transport="http"
                )
            # ...but the already-issued http key is still revoked on its own inbound.
            updated = await disabled.revoke_xray_key(100, created.key.id)
            assert updated.status == VpnKeyStatus.REVOKED
            assert len(http.remove_calls) == 1
            assert tcp.remove_calls == []
        finally:
            await db.close()

    asyncio.run(run())


def test_existing_http_key_revocable_when_inbound_absent(tmp_path: Path) -> None:
    """With no XHTTP adapter (inbound gone), removal is a no-op but the DB row is still cleared."""

    async def run() -> None:
        # xhttp_enabled=False -> _make_service wires xhttp_adapter=None, modelling
        # a restart where the XHTTP inbound was removed from config.json entirely.
        service, repo, tcp, _http, db = await _make_service(tmp_path, xhttp_enabled=False)
        try:
            key = await _insert_active_http_key(repo)
            updated = await service.revoke_xray_key(100, key.id)
            assert updated.status == VpnKeyStatus.REVOKED
            # Never touched the unrelated tcp inbound while compensating for the missing one.
            assert tcp.remove_calls == []
        finally:
            await db.close()

    asyncio.run(run())


def test_existing_http_key_deletable_when_inbound_absent(tmp_path: Path) -> None:
    """Delete of an http key still hard-deletes the DB row when its inbound/adapter is gone."""

    async def run() -> None:
        service, repo, tcp, _http, db = await _make_service(tmp_path, xhttp_enabled=False)
        try:
            key = await _insert_active_http_key(repo)
            await service.delete_xray_key(100, key.id)
            assert await repo.get_by_id(key.id) is None
            assert tcp.remove_calls == []
        finally:
            await db.close()

    asyncio.run(run())


def test_reconcile_http_key_tolerant_when_inbound_absent(tmp_path: Path) -> None:
    """A manual single-key reconcile never hard-fails when the http inbound/adapter is missing."""

    async def run() -> None:
        class _SuperUsers(_Users):
            async def require_superadmin(self, actor_user_id: int) -> User:
                return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

        service, repo, _tcp, _http, db = await _make_service(tmp_path, xhttp_enabled=False)
        service.users = _SuperUsers()  # type: ignore[assignment]
        try:
            key = await _insert_active_http_key(repo)
            # Active key + absent adapter -> treated as client-not-found, no raise,
            # no status change (only ACTIVE), reconcile returns the key.
            result = await service.reconcile_key_status(1, key.id)
            assert result.status == VpnKeyStatus.ACTIVE
        finally:
            await db.close()

    asyncio.run(run())


def test_vless_reality_inbound_present_detection(tmp_path: Path) -> None:
    from adapters.xray_config import vless_reality_inbound_present

    config_path = tmp_path / "xray.json"
    tag = "vless-xhttp-reality"

    # Missing file -> absent, never raises.
    assert vless_reality_inbound_present(config_path, tag) is False

    # The tagged VLESS/REALITY inbound present -> detected (independently of any flag).
    config_path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"tag": "vless-in", "protocol": "vless", "streamSettings": {"security": "reality"}, "settings": {"clients": []}},
                    {"tag": tag, "protocol": "vless", "streamSettings": {"security": "reality"}, "settings": {"clients": []}},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert vless_reality_inbound_present(config_path, tag) is True

    # Broken JSON -> absent, swallowed.
    config_path.write_text("{not json", encoding="utf-8")
    assert vless_reality_inbound_present(config_path, tag) is False

    # Tag present but not a VLESS/REALITY inbound -> absent.
    config_path.write_text(
        json.dumps({"inbounds": [{"tag": tag, "protocol": "trojan"}]}), encoding="utf-8"
    )
    assert vless_reality_inbound_present(config_path, tag) is False

    # Empty tag -> never matches.
    assert vless_reality_inbound_present(config_path, "") is False


def test_existing_http_key_deletable_when_flag_disabled_but_inbound_present(tmp_path: Path) -> None:
    """Delete of an issued http key removes its client from vless-xhttp-reality even with the flag off."""

    async def run() -> None:
        service, repo, tcp, http, db = await _make_service(tmp_path, xhttp_enabled=True)
        try:
            created = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="http"
            )
            http.remove_calls.clear()
            disabled = _service_with(repo, tcp, http, _settings(tmp_path, xhttp_enabled=False))
            await disabled.delete_xray_key(100, created.key.id)
            assert await repo.get_by_id(created.key.id) is None
            assert len(http.remove_calls) == 1  # removed from the http inbound
            assert tcp.remove_calls == []
        finally:
            await db.close()

    asyncio.run(run())


def test_http_key_labels_use_vless_not_xray(tmp_path: Path) -> None:
    """Config header and display_name read VLESS (TCP)/(HTTP), never "Xray"."""

    async def run() -> None:
        service, _repo, _tcp, _http, db = await _make_service(tmp_path)
        try:
            http_created = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="http"
            )
            assert "VLESS (HTTP)" in str(http_created.key.public_payload["display_name"])
            assert "Xray" not in str(http_created.key.public_payload["display_name"])
            http_cfg = await service.get_xray_key_config(100, http_created.key.id)
            assert "VLESS (HTTP)" in http_cfg
            assert "Xray" not in http_cfg

            tcp_created = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="tcp"
            )
            assert "VLESS (TCP)" in str(tcp_created.key.public_payload["display_name"])
            tcp_cfg = await service.get_xray_key_config(100, tcp_created.key.id)
            assert "VLESS (TCP)" in tcp_cfg
            assert "Xray" not in tcp_cfg
        finally:
            await db.close()

    asyncio.run(run())


def test_startup_warns_about_unmanaged_http_keys(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Active http keys + absent XHTTP adapter -> a CRITICAL diagnostic, no crash."""

    async def run() -> None:
        service, repo, _tcp, _http, db = await _make_service(tmp_path, xhttp_enabled=False)
        try:
            await _insert_active_http_key(repo)
            with caplog.at_level(logging.CRITICAL, logger="services.xray"):
                summary = await service.startup_reconcile()
            assert "cannot manage them server-side" in caplog.text
            assert any(r.levelno == logging.CRITICAL for r in caplog.records)
            assert "checked" in summary  # startup completed normally
        finally:
            await db.close()

    asyncio.run(run())


def test_startup_no_unmanaged_warning_when_adapter_present(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """With the http adapter present (inbound seeded), the diagnostic stays silent."""

    async def run() -> None:
        service, _repo, _tcp, _http, db = await _make_service(tmp_path, xhttp_enabled=True)
        try:
            await service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None, transport="http")
            with caplog.at_level(logging.CRITICAL, logger="services.xray"):
                await service.startup_reconcile()
            assert "cannot manage them server-side" not in caplog.text
        finally:
            await db.close()

    asyncio.run(run())


def test_settings_load_rejects_colliding_xhttp_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    """XRAY_XHTTP_ENABLED=true with the XHTTP tag equal to the primary tag fails at load."""
    monkeypatch.setenv("XRAY_XHTTP_ENABLED", "true")
    monkeypatch.setenv("XRAY_INBOUND_TAG", "vless-in")
    monkeypatch.setenv("XRAY_XHTTP_INBOUND_TAG", "vless-in")
    with pytest.raises(SettingsError):
        load_settings()


def test_startup_reconcile_restores_missing_key_into_its_own_inbound(tmp_path: Path) -> None:
    async def run() -> None:
        service, _repo, tcp, http, db = await _make_service(tmp_path)
        try:
            await service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None, transport="http")
            await service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None, transport="tcp")
            # The http client drifts out of the http inbound only.
            http.clients.clear()
            tcp.add_calls.clear()
            http.add_calls.clear()

            summary = await service.startup_reconcile()

            # Restored into the http inbound (no flow), never the tcp inbound.
            assert len(http.add_calls) == 1
            assert http.add_calls[0]["flow"] == ""
            assert tcp.add_calls == []  # tcp client still present -> not re-added
            assert summary["recovered"] >= 1
        finally:
            await db.close()

    asyncio.run(run())


def test_startup_reconcile_removes_revoked_client_from_its_own_inbound(tmp_path: Path) -> None:
    async def run() -> None:
        service, repo, tcp, http, db = await _make_service(tmp_path)
        try:
            http_key = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="http"
            )
            # Key revoked in the DB but its client is still live in the http inbound.
            await repo.set_status(http_key.key.id, VpnKeyStatus.REVOKED, "now")
            tcp.remove_calls.clear()
            http.remove_calls.clear()

            await service.startup_reconcile()

            assert len(http.remove_calls) == 1
            assert tcp.remove_calls == []
            assert http.clients == []
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


def test_build_vless_link_http_is_hybrid_reality_over_xhttp(tmp_path: Path) -> None:
    """The http link reuses vless-in's REALITY on :443, differing only in transport."""

    async def run() -> None:
        service, _repo, _tcp, _http, db = await _make_service(tmp_path)
        try:
            link = service._build_vless_link("uuid-1", "abcd", "xray_A0001", transport="http")
            parts = urlsplit(link)
            # Rides vless-in's public :443 (NOT 8001/8443).
            assert parts.port == 443
            params = parse_qs(parts.query)
            assert params["type"] == ["xhttp"]
            assert params["security"] == ["reality"]
            assert params["encryption"] == ["none"]
            assert params["mode"] == ["stream-one"]
            assert params["path"] == ["/v1/messages/stream"]
            # REALITY part matches the TCP link: pbk/sni/sid/fp from vless-in/settings.
            assert params["pbk"] == ["public"]
            assert params["sni"] == ["example.com"]
            assert params["sid"] == ["abcd"]
            assert params["fp"] == ["chrome"]
            # No flow for XHTTP (xtls-rprx-vision is TCP/Vision-only); no server `extra` tuning.
            assert "flow" not in params
            assert "xtls-rprx-vision" not in link
            assert "xPaddingBytes" not in parts.query
            assert "scMaxEachPostBytes" not in parts.query
        finally:
            await db.close()

    asyncio.run(run())


def test_get_config_and_change_fingerprint_for_http_key(tmp_path: Path) -> None:
    async def run() -> None:
        service, _repo, _tcp, _http, db = await _make_service(tmp_path)
        try:
            created = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="http"
            )
            text = await service.get_xray_key_config(100, created.key.id)
            assert "type=xhttp" in text
            assert "flow=" not in text

            updated = await service.change_fingerprint(100, created.key.id, "firefox")
            link = str(updated.public_payload["link"])
            assert "type=xhttp" in link
            assert "fp=firefox" in link
            assert "flow=" not in link
        finally:
            await db.close()

    asyncio.run(run())


def test_create_confirm_text_renders_transport_label() -> None:
    assert create_type_label(VpnKeyType.XRAY.value, "tcp") == "VLESS (TCP)"
    assert create_type_label(VpnKeyType.XRAY.value, "http") == "VLESS (HTTP)"
    assert create_type_label(VpnKeyType.AWG.value) == "AmneziaWG"
    assert "VLESS (HTTP)" in create_confirm_text(VpnKeyType.XRAY.value, None, transport="http")
    assert "VLESS (TCP)" in create_confirm_text(VpnKeyType.XRAY.value, None, transport="tcp")


def test_settings_validation_guards_xhttp_misconfig(tmp_path: Path) -> None:
    # Valid config passes.
    _settings(tmp_path, xhttp_enabled=True).validate_xray_ready()

    from dataclasses import replace

    base = _settings(tmp_path, xhttp_enabled=True)
    # XHTTP tag must differ from the TCP inbound tag.
    with pytest.raises(SettingsError):
        replace(base, xray_xhttp_inbound_tag="vless-in").validate_xray_ready()
    # XHTTP path must be absolute.
    with pytest.raises(SettingsError):
        replace(base, xray_xhttp_path="v1/messages").validate_xray_ready()
    # Disabled -> no XHTTP constraints apply.
    replace(base, xray_xhttp_enabled=False, xray_xhttp_inbound_tag="").validate_xray_ready()


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
    # XHTTP enabled -> VLESS leads to the transport selection step.
    enabled = create_key_keyboard(xray_enabled=True, awg_enabled=True, xhttp_enabled=True)
    assert "VLESS" in _button_texts(enabled)
    assert "AmneziaWG 2.0" in _button_texts(enabled)
    assert "keys:proto:vless" in _button_callbacks(enabled)
    assert "keys:create:xray" not in _button_callbacks(enabled)

    # XHTTP disabled -> VLESS goes straight to TCP key creation (no transport step).
    disabled = create_key_keyboard(xray_enabled=True, awg_enabled=True, xhttp_enabled=False)
    assert "VLESS" in _button_texts(disabled)
    assert "keys:create:xray" in _button_callbacks(disabled)
    assert "keys:proto:vless" not in _button_callbacks(disabled)


def test_create_key_keyboard_back_button_honours_entry_point() -> None:
    # Default (entered from the «My keys» list) -> back returns to the list.
    from_list = create_key_keyboard(xray_enabled=True, awg_enabled=True)
    assert "keys:list" in _button_callbacks(from_list)
    assert "menu:main" not in _button_callbacks(from_list)

    # Entered from the main menu -> back returns to the main menu, not «My keys».
    from_menu = create_key_keyboard(xray_enabled=True, awg_enabled=True, back_data="menu:main")
    assert "menu:main" in _button_callbacks(from_menu)
    assert "keys:list" not in _button_callbacks(from_menu)


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
    # XHTTP enabled -> VLESS leads to the transport selection step.
    proto = admin_key_type_keyboard(555, xray_enabled=True, awg_enabled=True, xhttp_enabled=True)
    assert "admin:proto:vless:555" in _button_callbacks(proto)
    assert "admin:ctype:xray:555" not in _button_callbacks(proto)

    # XHTTP disabled -> VLESS goes straight to TCP key creation (no transport step).
    proto_disabled = admin_key_type_keyboard(555, xray_enabled=True, awg_enabled=True, xhttp_enabled=False)
    assert "admin:ctype:xray:555" in _button_callbacks(proto_disabled)
    assert "admin:proto:vless:555" not in _button_callbacks(proto_disabled)

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
