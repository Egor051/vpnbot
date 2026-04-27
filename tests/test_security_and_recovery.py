from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.shell_runner import ShellRunner
from config.settings import Settings, SettingsError, load_settings
from db.database import CURRENT_SCHEMA_VERSION, Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.access_requests import AccessRequestRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.awg import AwgService
from services.xray import XrayService


def _settings(**overrides: object) -> Settings:
    values = dict(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=Path("/tmp/vpn.db"),
        log_dir=Path("/tmp/logs"),
        bot_lock_path=Path("/tmp/vpn.lock"),
        xray_config_path=Path("/tmp/xray.json"),
        xray_service_name="xray",
        xray_inbound_tag="",
        xray_public_host="2001:db8::1",
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
        awg_config_path=Path("/tmp/awg.conf"),
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
    )
    values.update(overrides)
    return Settings(**values)


def test_xray_vless_ipv6_host_is_bracketed() -> None:
    service = XrayService(
        vpn_keys=object(),  # type: ignore[arg-type]
        users=object(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=_settings(),
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=object(),  # type: ignore[arg-type]
    )

    link = service._build_vless_link("00000000-0000-4000-8000-000000000000", "abcd", "label")

    assert "vless://00000000-0000-4000-8000-000000000000@[2001:db8::1]:443?" in link


def test_settings_reject_invalid_xray_short_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com")
    monkeypatch.setenv("XRAY_REALITY_PUBLIC_KEY", "public")
    monkeypatch.setenv("XRAY_SNI", "example.com")
    monkeypatch.setenv("XRAY_SHORT_ID", "not-hex")

    with pytest.raises(SettingsError):
        load_settings()


def test_audit_sanitizer_masks_nested_secrets() -> None:
    audit = AuditService(audit_logs=object(), clock=ClockProvider())  # type: ignore[arg-type]

    clean = audit._sanitize(
        {
            "errors": [
                {"private_key": "secret", "nested": {"shortId": "abcd", "token": "bot"}},
                {"message": "ok"},
            ],
            "uuid": "00000000-0000-4000-8000-000000000000",
        }
    )

    assert clean["errors"][0]["private_key"] == "***"
    assert clean["errors"][0]["nested"]["shortId"] == "***"
    assert clean["errors"][0]["nested"]["token"] == "***"
    assert clean["uuid"] == "***"


def test_awg_remove_managed_block() -> None:
    adapter = AwgConfigAdapter(
        config_path=Path("/tmp/unused-awg.conf"),
        interface="awg0",
        backup=BackupAdapter(ClockProvider()),
        shell=ShellRunner(),
        persistent_keepalive=25,
    )
    text = """[Interface]
PrivateKey = server

# vpn-bot peer start key_id=10 owner=100 label=test
[Peer]
PublicKey = client
AllowedIPs = 10.0.0.2/32
# vpn-bot peer end key_id=10
"""

    updated = adapter._remove_managed_block(text, 10)

    assert "PublicKey = client" not in updated
    assert "[Interface]" in updated


def test_awg_delete_failed_retry_removes_access_before_deleted() -> None:
    class Repo:
        def __init__(self) -> None:
            self.key = VpnKey(
                id=10,
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                status=VpnKeyStatus.DELETE_FAILED,
                note=None,
                uuid=None,
                email_label="label",
                public_key="public",
                client_ip="10.0.0.2",
                payload={"public_key": "public"},
                public_payload={},
                created_at="now",
                updated_at="now",
                revoked_at=None,
                deleted_at=None,
                created_by=100,
                revoked_by=None,
                deleted_by=None,
            )

        async def get_by_id(self, key_id: int) -> VpnKey | None:
            return self.key if key_id == self.key.id else None

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            self.key = self._replace(status=status)

        async def hard_delete_with_stats(self, key_id: int) -> None:
            self.key = None

        def _replace(self, **changes: object) -> VpnKey:
            if self.key is None:
                raise RuntimeError("key is deleted")
            return replace(self.key, **changes)

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

    class Adapter:
        def __init__(self) -> None:
            self.removed = False

        async def remove_peer(self, *, key_id: int, public_key: str | None) -> None:
            self.removed = True

    class Audit:
        async def write(self, **kwargs: object) -> None:
            return None

    repo = Repo()
    adapter = Adapter()
    service = AwgService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        ip_allocator=object(),  # type: ignore[arg-type]
        settings=_settings(),
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=Audit(),  # type: ignore[arg-type]
    )

    asyncio.run(service.delete_awg_key(100, 10))

    assert adapter.removed is True
    assert repo.key is None


def test_db_v4_prevents_two_pending_requests_and_tolerates_corrupted_json(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            assert CURRENT_SCHEMA_VERSION == 4
            users = UserRepository(db)
            profile = TelegramUserProfile(telegram_user_id=100, username="user", first_name="User")
            await users.upsert_profile(profile, UserRole.PENDING_USER, "now")
            requests = AccessRequestRepository(db)
            first, created_first = await requests.create_pending_idempotent(100, "user", "now")
            second, created_second = await requests.create_pending_idempotent(100, "user", "now")
            assert created_first is True
            assert created_second is False
            assert first.id == second.id

            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, username, key_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (100, "user", "xray", "active", "{bad json", json.dumps({}), "now", "now", 100),
            )
            await db.commit()
            keys = await VpnKeyRepository(db).list_by_owner(100)
            assert len(keys) == 1
            assert keys[0].payload == {"_corrupted": True}
        finally:
            await db.close()

    asyncio.run(run())
