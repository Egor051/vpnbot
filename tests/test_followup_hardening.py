from __future__ import annotations

import asyncio
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import aiosqlite
import pytest
from aiogram.enums import ChatType
from aiogram.types import CallbackQuery, Chat, Message, User as TgUser

from adapters.awg_config import AwgServerConfig
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.xray_config import XrayConfigAdapter
from bot.app import _startup_reconcile_keys
from bot.private_chat import ADMIN_PRIVATE_ONLY_TEXT, ensure_private_callback, ensure_private_message
from config.settings import Settings
from db.database import Database
from models.dto import ShellResult, TelegramUserProfile, User, VpnKey
from models.enums import AccessRequestStatus, AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.access_requests import AccessRequestRepository
from repositories.audit_log import AuditLogRepository
from repositories.users import UserRepository
from services.access_approval import AccessApprovalService
from services.audit import AuditService
from services.awg import AwgService
from services.errors import InvalidOperation
from services.users import UserService


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_inbound_tag="",
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
    )


async def _create_legacy_v3_db_with_duplicate_pending(path: Path) -> None:
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(
            """
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO schema_meta VALUES ('schema_version','3');
            CREATE TABLE users (
              telegram_user_id INTEGER PRIMARY KEY,
              username TEXT,
              first_name TEXT,
              role TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              blocked_at TEXT
            );
            CREATE TABLE access_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              telegram_user_id INTEGER NOT NULL,
              username TEXT,
              status TEXT NOT NULL,
              requested_at TEXT NOT NULL,
              decided_by INTEGER,
              decided_at TEXT,
              decision_note TEXT
            );
            CREATE TABLE vpn_keys (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner_user_id INTEGER NOT NULL,
              username TEXT,
              key_type TEXT NOT NULL,
              status TEXT NOT NULL,
              note TEXT,
              uuid TEXT,
              email_label TEXT,
              public_key TEXT,
              client_ip TEXT,
              payload_json TEXT NOT NULL,
              public_payload_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              revoked_at TEXT,
              deleted_at TEXT,
              created_by INTEGER NOT NULL,
              revoked_by INTEGER,
              deleted_by INTEGER
            );
            CREATE TABLE proxy_entries (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              proxy_type TEXT NOT NULL,
              host TEXT NOT NULL,
              port INTEGER NOT NULL,
              login TEXT,
              password TEXT,
              note TEXT,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              actor_user_id INTEGER,
              action TEXT NOT NULL,
              entity_type TEXT NOT NULL,
              entity_id TEXT,
              details_json TEXT,
              created_at TEXT NOT NULL
            );
            CREATE TABLE vpn_key_traffic_stats (
              key_id INTEGER PRIMARY KEY,
              downloaded_bytes INTEGER NOT NULL DEFAULT 0,
              uploaded_bytes INTEGER NOT NULL DEFAULT 0,
              last_raw_downloaded_bytes INTEGER,
              last_raw_uploaded_bytes INTEGER,
              last_success_at TEXT,
              last_attempt_at TEXT,
              available INTEGER NOT NULL DEFAULT 0,
              unavailable_reason TEXT,
              source TEXT
            );
            INSERT INTO users VALUES (100,'user','User','pending','now','now',NULL);
            INSERT INTO access_requests (telegram_user_id, username, status, requested_at)
            VALUES (100,'user','pending','2026-01-01T00:00:00+00:00');
            INSERT INTO access_requests (telegram_user_id, username, status, requested_at)
            VALUES (100,'user','pending','2026-01-02T00:00:00+00:00');
            """
        )
        await conn.commit()


def test_legacy_v3_duplicate_pending_migrates_before_unique_index(tmp_path: Path) -> None:
    async def run() -> None:
        db_path = tmp_path / "legacy.db"
        await _create_legacy_v3_db_with_duplicate_pending(db_path)
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            print("BOOTSTRAP_OK")
            cursor = await db.conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            version = await cursor.fetchone()
            assert version["value"] == "4"
            cursor = await db.conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM access_requests GROUP BY status ORDER BY status"
            )
            counts = {row["status"]: row["cnt"] for row in await cursor.fetchall()}
            assert counts == {"pending": 1, "rejected": 1}
            cursor = await db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'idx_access_requests_one_pending'"
            )
            assert await cursor.fetchone() is not None
        finally:
            await db.close()

    asyncio.run(run())


def test_transaction_begin_failure_releases_lock() -> None:
    class FakeConnection:
        def __init__(self) -> None:
            self.fail_begin = True
            self.commits = 0

        async def execute(self, sql: str, parameters: object = None) -> object:
            if sql.startswith("BEGIN") and self.fail_begin:
                self.fail_begin = False
                raise RuntimeError("begin failed")
            return object()

        async def commit(self) -> None:
            self.commits += 1

        async def rollback(self) -> None:
            return None

    async def run() -> None:
        db = Database(Path(":memory:"))
        fake = FakeConnection()
        db._conn = fake  # type: ignore[assignment]
        with pytest.raises(RuntimeError, match="begin failed"):
            async with db.transaction():
                pass
        assert not db._transaction_lock.locked()
        async with db.transaction():
            pass
        assert fake.commits == 1

    asyncio.run(run())


def test_shared_connection_write_waits_for_active_transaction(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            async with db.transaction():
                task = asyncio.create_task(
                    users.upsert_profile(TelegramUserProfile(telegram_user_id=200, username="u", first_name="U"), UserRole.PENDING_USER, "now")
                )
                await asyncio.sleep(0.05)
                assert not task.done()
            await asyncio.wait_for(task, timeout=1)
        finally:
            await db.close()

    asyncio.run(run())


def test_approve_rolls_back_request_if_role_update_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            requests_repo = AccessRequestRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=200, username="user", first_name="User"), UserRole.PENDING_USER, "now")
            request = await requests_repo.create(200, "user", "now")

            original_set_role = users_repo.set_role

            async def fail_target_role(telegram_user_id: int, role: UserRole, now: str, blocked_at: str | None = None) -> None:
                if telegram_user_id == 200:
                    raise RuntimeError("role update failed")
                await original_set_role(telegram_user_id, role, now, blocked_at)

            monkeypatch.setattr(users_repo, "set_role", fail_target_role)
            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            with pytest.raises(RuntimeError, match="role update failed"):
                await service.approve(1, request.id)

            refreshed_request = await requests_repo.get_by_id(request.id)
            refreshed_user = await users_repo.get_by_id(200)
            assert refreshed_request is not None
            assert refreshed_request.status == AccessRequestStatus.PENDING
            assert refreshed_user is not None
            assert refreshed_user.role == UserRole.PENDING_USER
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode preservation is only meaningful on POSIX")
def test_xray_mutation_preserves_main_config_mode_while_backup_is_private(tmp_path: Path) -> None:
    class FakeSystemctl:
        async def xray_test_config(self, path: Path) -> ShellResult:
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray",), 0, "", "")

        async def reload_or_restart(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl",), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl",), 0, "active", "")

    async def run() -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(
            json.dumps(
                {
                    "inbounds": [
                        {
                            "protocol": "vless",
                            "settings": {"clients": []},
                            "streamSettings": {"security": "reality", "realitySettings": {"shortIds": []}},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        config_path.chmod(0o644)
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider()),
            systemctl=FakeSystemctl(),  # type: ignore[arg-type]
        )
        await adapter.add_client(uuid_value="00000000-0000-4000-8000-000000000000", email_label="user", short_id="abcd", flow="", manage_short_id=True)
        backup = next(tmp_path.glob("config.json.*.bak"))
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o644
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600

    asyncio.run(run())


def test_startup_reconcile_service_or_audit_failure_does_not_abort() -> None:
    class FailingXray:
        async def startup_reconcile(self) -> dict[str, int]:
            raise RuntimeError("list failed")

    class Awg:
        async def startup_reconcile(self) -> dict[str, int]:
            return {"checked": 1, "recovered": 0, "failed": 0}

    class FailingAudit:
        async def write(self, **kwargs: object) -> None:
            raise RuntimeError("audit failed")

    services = SimpleNamespace(xray=FailingXray(), awg=Awg(), audit=FailingAudit())
    asyncio.run(_startup_reconcile_keys(services))


def test_admin_private_chat_guard_rejects_group_message_and_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    message_calls: list[str] = []
    callback_calls: list[tuple[str, bool | None]] = []

    class GroupMessage:
        chat = SimpleNamespace(type=ChatType.SUPERGROUP)

        async def answer(self, text: str) -> None:
            message_calls.append(text)

    async def fake_callback_answer(self: CallbackQuery, text: str, show_alert: bool | None = None, **kwargs: object) -> None:
        callback_calls.append((text, show_alert))

    monkeypatch.setattr(CallbackQuery, "answer", fake_callback_answer)
    callback_message = Message(
        message_id=1,
        date=datetime.now(timezone.utc),
        chat=Chat(id=-100, type=ChatType.SUPERGROUP),
    )
    callback = CallbackQuery(
        id="cb",
        from_user=TgUser(id=1, is_bot=False, first_name="Admin"),
        chat_instance="ci",
        message=callback_message,
        data="admin:panel",
    )

    async def run() -> None:
        assert await ensure_private_message(GroupMessage(), ADMIN_PRIVATE_ONLY_TEXT) is False  # type: ignore[arg-type]
        assert await ensure_private_callback(callback, ADMIN_PRIVATE_ONLY_TEXT) is False

    asyncio.run(run())
    assert message_calls == [ADMIN_PRIVATE_ONLY_TEXT]
    assert callback_calls == [(ADMIN_PRIVATE_ONLY_TEXT, True)]


def test_awg_corrupted_payload_does_not_return_empty_private_key() -> None:
    class Repo:
        async def get_by_id(self, key_id: int) -> VpnKey | None:
            return VpnKey(
                id=key_id,
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                status=VpnKeyStatus.ACTIVE,
                note=None,
                uuid=None,
                email_label="label",
                public_key="public",
                client_ip="10.0.0.2",
                payload={"_corrupted": True},
                public_payload={},
                created_at="now",
                updated_at="now",
                revoked_at=None,
                deleted_at=None,
                created_by=100,
                revoked_by=None,
                deleted_by=None,
            )

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

    class Adapter:
        def read_server_config(self) -> AwgServerConfig:
            return AwgServerConfig(listen_port=443, public_key="server-public", interface_options={})

        def client_interface_options(self) -> dict[str, str]:
            return {}

    class Audit:
        def __init__(self) -> None:
            self.actions: list[str] = []

        async def write(self, *, action: str, **kwargs: object) -> None:
            self.actions.append(action)

    async def run() -> None:
        audit = Audit()
        service = AwgService(
            vpn_keys=Repo(),  # type: ignore[arg-type]
            users=Users(),  # type: ignore[arg-type]
            adapter=Adapter(),  # type: ignore[arg-type]
            ip_allocator=object(),  # type: ignore[arg-type]
            settings=_settings(Path("/tmp")),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
        )
        with pytest.raises(InvalidOperation, match="AWG-конфигурация повреждена"):
            await service.get_awg_client_config_plain(100, 10)
        assert audit.actions == ["awg_config_corrupted"]

    asyncio.run(run())
