from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from adapters.clock import ClockProvider
from bot.keyboards.keys import key_actions_keyboard, keys_list_keyboard
from config.settings import Settings
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.proxy_entries import ProxyRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied
from services.notes import NotesService
from services.users import UserService
from repositories.audit_log import AuditLogRepository


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "bot.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="restart",
        xray_inbound_tag="",
        xray_public_host="vpn.example.com",
        xray_public_port=443,
        xray_reality_public_key="public",
        xray_sni="example.com",
        xray_flow="xtls-rprx-vision",
        xray_fingerprint="chrome",
        xray_network_type="tcp",
        xray_short_id="abcd",
        xray_manage_short_ids=True,
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
    )


def _key(owner_user_id: int = 100) -> VpnKey:
    return VpnKey(
        id=10,
        owner_user_id=owner_user_id,
        username="owner",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note="private",
        uuid="uuid",
        email_label="xray_A7kQz",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=owner_user_id,
        revoked_by=None,
        deleted_by=None,
    )


class _FailingAudit:
    async def write(self, **kwargs: object) -> None:
        raise RuntimeError("audit down")


def test_note_update_succeeds_when_non_critical_audit_fails(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            vpn_keys = VpnKeyRepository(db)
            users = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=_FailingAudit())  # type: ignore[arg-type]
            await users.bootstrap_admins()
            await users_repo.upsert_profile(TelegramUserProfile(100, "owner", "Owner"), UserRole.APPROVED_USER, "now")
            key = await vpn_keys.create_pending(
                owner_user_id=100,
                username="owner",
                key_type=VpnKeyType.XRAY,
                note="old",
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                uuid="00000000-0000-4000-8000-000000000100",
                email_label="xray_A7kQz",
            )
            notes = NotesService(vpn_keys=vpn_keys, proxies=ProxyRepository(db), users=users, audit=_FailingAudit())  # type: ignore[arg-type]

            await notes.update_key_note(100, key.id, "new")

            refreshed = await vpn_keys.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.note == "new"
        finally:
            await db.close()

    asyncio.run(run())


def test_role_change_rolls_back_when_security_audit_fails(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            await users_repo.upsert_profile(TelegramUserProfile(200, "user", "User"), UserRole.PENDING_USER, "now")
            users.audit = _FailingAudit()  # type: ignore[assignment]

            with pytest.raises(RuntimeError, match="audit down"):
                await users.set_role(1, 200, UserRole.APPROVED_USER)

            refreshed = await users_repo.get_by_id(200)
            assert refreshed is not None
            assert refreshed.role == UserRole.PENDING_USER
        finally:
            await db.close()

    asyncio.run(run())


def test_superadmin_cannot_update_foreign_private_note(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            vpn_keys = VpnKeyRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            await users_repo.upsert_profile(TelegramUserProfile(100, "owner", "Owner"), UserRole.APPROVED_USER, "now")
            key = await vpn_keys.create_pending(
                owner_user_id=100,
                username="owner",
                key_type=VpnKeyType.XRAY,
                note="private",
                payload={},
                public_payload={},
                created_by=100,
                now="now",
                uuid="00000000-0000-4000-8000-000000000101",
                email_label="xray_Z7kQz",
            )
            notes = NotesService(vpn_keys=vpn_keys, proxies=ProxyRepository(db), users=users, audit=audit)

            with pytest.raises(AccessDenied):
                await notes.update_key_note(1, key.id, "admin overwrite")

            refreshed = await vpn_keys.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.note == "private"
        finally:
            await db.close()

    asyncio.run(run())


def test_note_buttons_hidden_for_admin_foreign_key_context() -> None:
    key = _key(owner_user_id=100)
    detail_markup = key_actions_keyboard(key, owner_user_id=100)
    list_markup = keys_list_keyboard([key], owner_user_id=100)

    detail_callbacks = [button.callback_data for row in detail_markup.inline_keyboard for button in row]
    list_callbacks = [button.callback_data for row in list_markup.inline_keyboard for button in row]

    assert f"key:note:{key.id}" not in detail_callbacks
    assert f"key:note:{key.id}" not in list_callbacks
