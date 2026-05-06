from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import aiosqlite
import pytest
from aiogram.enums import ChatType
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import CallbackQuery, Chat, Message, User as TgUser

from adapters.awg_config import AwgServerConfig
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.errors import XrayApplyError
from adapters.xray_config import XrayConfigAdapter
from bot.app import _startup_reconcile_keys
from bot.handlers.common import answer_callback_error
from bot.messages import MAX_TEXT_CONFIG_LEN, safe_callback_answer, safe_edit_message_text, send_awg_config
from bot.middlewares.access import BLOCKED_CALLBACK_TEXT, BLOCKED_MESSAGE_TEXT, BlockedUserMiddleware
from bot.private_chat import ADMIN_PRIVATE_ONLY_TEXT, ensure_private_callback, ensure_private_message
from config.settings import Settings
from db.database import Database
from models.access import is_blocked_user
from models.dto import ShellResult, TelegramUserProfile, User, VpnKey
from models.enums import AccessRequestStatus, AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType, parse_user_role
from repositories.access_requests import AccessRequestRepository
from repositories.audit_log import AuditLogRepository
from repositories.proxy_entries import ProxyRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.access_approval import AccessApprovalService
from services.audit import AuditService
from services.awg import AwgService
from services.errors import AccessDenied, InvalidOperation
from services.notes import NotesService
from services.users import UserService
from services.xray import XrayService


VALID_AWG_PRIVATE_KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def _write_minimal_xray_config(config_path: Path) -> None:
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


def _settings(tmp_path: Path) -> Settings:
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
            assert version["value"] == "9"
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


def test_connection_proxy_gates_execute_insert_and_execute_fetchall_writes(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()

            async def insert_via_execute_insert() -> None:
                await db.conn.execute_insert(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (301, "insert", "Insert", UserRole.PENDING_USER.value, "now", "now"),
                )
                await db.commit()

            async with db.transaction():
                task = asyncio.create_task(insert_via_execute_insert())
                await asyncio.sleep(0.05)
                assert not task.done()
            await asyncio.wait_for(task, timeout=1)

            async def insert_via_execute_fetchall() -> None:
                rows = await db.conn.execute_fetchall(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    RETURNING telegram_user_id
                    """,
                    (302, "fetchall", "Fetchall", UserRole.PENDING_USER.value, "now", "now"),
                )
                assert [row["telegram_user_id"] for row in rows] == [302]
                await db.commit()

            async with db.transaction():
                task = asyncio.create_task(insert_via_execute_fetchall())
                await asyncio.sleep(0.05)
                assert not task.done()
            await asyncio.wait_for(task, timeout=1)

            cursor = await db.conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE telegram_user_id IN (301, 302)")
            row = await cursor.fetchone()
            assert row["cnt"] == 2
        finally:
            await db.close()

    asyncio.run(run())


def test_connection_proxy_raw_commit_and_rollback_do_not_break_foreign_transaction(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()

            async with db.transaction():
                await db.conn.execute(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                    VALUES (401, 'commit', 'Commit', 'pending', 'now', 'now')
                    """
                )
                commit_task = asyncio.create_task(db.conn.commit())
                await asyncio.sleep(0.05)
                assert not commit_task.done()
            await asyncio.wait_for(commit_task, timeout=1)

            async with db.transaction():
                await db.conn.execute(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                    VALUES (402, 'rollback', 'Rollback', 'pending', 'now', 'now')
                    """
                )
                rollback_task = asyncio.create_task(db.conn.rollback())
                await asyncio.sleep(0.05)
                assert not rollback_task.done()
            await asyncio.wait_for(rollback_task, timeout=1)

            cursor = await db.conn.execute("SELECT COUNT(*) AS cnt FROM users WHERE telegram_user_id IN (401, 402)")
            row = await cursor.fetchone()
            assert row["cnt"] == 2
        finally:
            await db.close()

    asyncio.run(run())


def test_connection_proxy_select_during_active_transaction_does_not_wait(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            async with db.transaction():
                cursor = await asyncio.wait_for(db.conn.execute("SELECT 1 AS value"), timeout=1)
                row = await cursor.fetchone()
                assert row["value"] == 1
        finally:
            await db.close()

    asyncio.run(run())


def test_connection_proxy_treats_with_mutation_as_gated_write(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()

            async def insert_with_cte() -> None:
                await db.conn.execute(
                    """
                    WITH src(id, username) AS (SELECT 501, 'cte')
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                    SELECT id, username, 'CTE', 'pending', 'now', 'now' FROM src
                    """
                )
                await db.commit()

            async with db.transaction():
                task = asyncio.create_task(insert_with_cte())
                await asyncio.sleep(0.05)
                assert not task.done()
            await asyncio.wait_for(task, timeout=1)
            cursor = await db.conn.execute("SELECT username FROM users WHERE telegram_user_id = 501")
            row = await cursor.fetchone()
            assert row["username"] == "cte"
        finally:
            await db.close()

    asyncio.run(run())


def test_common_repository_calls_still_work_with_connection_proxy(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            requests = AccessRequestRepository(db)
            user = await users.upsert_profile(
                TelegramUserProfile(telegram_user_id=601, username="repo", first_name="Repo"),
                UserRole.PENDING_USER,
                "now",
            )
            request, created = await requests.create_pending_idempotent(user.telegram_user_id, user.username, "now")
            assert created is True
            assert request.telegram_user_id == 601
            assert await users.get_by_id(601) == user
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


def test_blocked_middleware_blocks_message_and_clears_fsm(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[str] = []

    async def fake_message_answer(self: Message, text: str, **kwargs: object) -> None:
        answers.append(text)

    monkeypatch.setattr(Message, "answer", fake_message_answer)

    class Users:
        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "blocked", "Blocked", UserRole.BLOCKED_USER, "now", "now", "now")

    class State:
        def __init__(self) -> None:
            self.cleared = False

        async def clear(self) -> None:
            self.cleared = True

    async def run() -> None:
        middleware = BlockedUserMiddleware(Users())  # type: ignore[arg-type]
        user = TgUser(id=200, is_bot=False, first_name="Blocked", username="blocked")
        message = Message(
            message_id=1,
            date=datetime.now(timezone.utc),
            chat=Chat(id=200, type=ChatType.PRIVATE),
            from_user=user,
            text="/help",
        )
        state = State()
        handler_called = False

        async def handler(event: object, data: dict[str, object]) -> None:
            nonlocal handler_called
            handler_called = True

        await middleware(handler, message, {"event_from_user": user, "state": state})

        assert handler_called is False
        assert state.cleared is True
        assert answers == [BLOCKED_MESSAGE_TEXT]

    asyncio.run(run())


def test_blocked_middleware_allows_start_command(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[str] = []

    async def fake_message_answer(self: Message, text: str, **kwargs: object) -> None:
        answers.append(text)

    monkeypatch.setattr(Message, "answer", fake_message_answer)

    class Users:
        async def get_user(self, telegram_user_id: int) -> User:
            raise AssertionError("start should bypass blocked lookup")

    class State:
        def __init__(self) -> None:
            self.cleared = False

        async def clear(self) -> None:
            self.cleared = True

    async def run() -> None:
        middleware = BlockedUserMiddleware(Users())  # type: ignore[arg-type]
        user = TgUser(id=200, is_bot=False, first_name="Blocked", username="blocked")
        message = Message(
            message_id=1,
            date=datetime.now(timezone.utc),
            chat=Chat(id=200, type=ChatType.PRIVATE),
            from_user=user,
            text="/start",
        )
        state = State()
        handler_called = False

        async def handler(event: object, data: dict[str, object]) -> None:
            nonlocal handler_called
            handler_called = True

        await middleware(handler, message, {"event_from_user": user, "state": state})

        assert handler_called is True
        assert state.cleared is False
        assert answers == []

    asyncio.run(run())


def test_blocked_middleware_blocks_callback_before_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[tuple[str, bool | None]] = []

    async def fake_callback_answer(self: CallbackQuery, text: str, show_alert: bool | None = None, **kwargs: object) -> None:
        answers.append((text, show_alert))

    monkeypatch.setattr(CallbackQuery, "answer", fake_callback_answer)

    class Users:
        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "blocked", "Blocked", UserRole.BLOCKED_USER, "now", "now", "now")

    class State:
        def __init__(self) -> None:
            self.cleared = False

        async def clear(self) -> None:
            self.cleared = True

    async def run() -> None:
        middleware = BlockedUserMiddleware(Users())  # type: ignore[arg-type]
        user = TgUser(id=200, is_bot=False, first_name="Blocked", username="blocked")
        callback_message = Message(
            message_id=1,
            date=datetime.now(timezone.utc),
            chat=Chat(id=200, type=ChatType.PRIVATE),
        )
        callback = CallbackQuery(
            id="cb",
            from_user=user,
            chat_instance="ci",
            message=callback_message,
            data="keys:create",
        )
        state = State()
        handler_called = False

        async def handler(event: object, data: dict[str, object]) -> None:
            nonlocal handler_called
            handler_called = True

        await middleware(handler, callback, {"event_from_user": user, "state": state})

        assert handler_called is False
        assert state.cleared is True
        assert answers == [(BLOCKED_CALLBACK_TEXT, True)]

    asyncio.run(run())


def test_blocked_middleware_treats_blocked_at_only_user_as_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    message_answers: list[str] = []
    callback_answers: list[tuple[str, bool | None]] = []

    async def fake_message_answer(self: Message, text: str, **kwargs: object) -> None:
        message_answers.append(text)

    async def fake_callback_answer(self: CallbackQuery, text: str, show_alert: bool | None = None, **kwargs: object) -> None:
        callback_answers.append((text, show_alert))

    monkeypatch.setattr(Message, "answer", fake_message_answer)
    monkeypatch.setattr(CallbackQuery, "answer", fake_callback_answer)

    class Users:
        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "approved", "Approved", UserRole.APPROVED_USER, "now", "now", "blocked")

    class State:
        def __init__(self) -> None:
            self.cleared = 0

        async def clear(self) -> None:
            self.cleared += 1

    async def run() -> None:
        middleware = BlockedUserMiddleware(Users())  # type: ignore[arg-type]
        user = TgUser(id=201, is_bot=False, first_name="Approved", username="approved")
        state = State()
        handler_calls = 0

        async def handler(event: object, data: dict[str, object]) -> None:
            nonlocal handler_calls
            handler_calls += 1

        message = Message(
            message_id=1,
            date=datetime.now(timezone.utc),
            chat=Chat(id=201, type=ChatType.PRIVATE),
            from_user=user,
            text="/stats",
        )
        await middleware(handler, message, {"event_from_user": user, "state": state})

        start = Message(
            message_id=2,
            date=datetime.now(timezone.utc),
            chat=Chat(id=201, type=ChatType.PRIVATE),
            from_user=user,
            text="/start",
        )
        await middleware(handler, start, {"event_from_user": user, "state": state})

        callback = CallbackQuery(
            id="cb",
            from_user=user,
            chat_instance="ci",
            message=Message(message_id=3, date=datetime.now(timezone.utc), chat=Chat(id=201, type=ChatType.PRIVATE)),
            data="create:confirm",
        )
        await middleware(handler, callback, {"event_from_user": user, "state": state})

        assert handler_calls == 1
        assert state.cleared == 2
        assert message_answers == [BLOCKED_MESSAGE_TEXT]
        assert callback_answers == [(BLOCKED_CALLBACK_TEXT, True)]

    asyncio.run(run())


def test_require_approved_or_admin_uses_blocked_predicate(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()

            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=200, username="approved", first_name="Approved"), UserRole.APPROVED_USER, "now")
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=201, username="blocked_at", first_name="BlockedAt"), UserRole.APPROVED_USER, "now")
            await db.conn.execute("UPDATE users SET blocked_at = ? WHERE telegram_user_id = ?", ("blocked", 201))
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=202, username="blocked", first_name="Blocked"), UserRole.BLOCKED_USER, "now")
            await users_repo.set_role(202, UserRole.BLOCKED_USER, "now", blocked_at="blocked")
            for telegram_user_id, role in ((203, "banned"), (204, "revoked"), (205, "blocked")):
                await db.conn.execute(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at, blocked_at)
                    VALUES (?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (telegram_user_id, role, role.title(), role, "now", "now"),
                )
            await db.commit()

            assert (await users.require_approved_or_admin(1)).role == UserRole.SUPERADMIN
            assert (await users.require_approved_or_admin(200)).role == UserRole.APPROVED_USER
            for telegram_user_id in (201, 202, 203, 204, 205):
                with pytest.raises(AccessDenied):
                    await users.require_approved_or_admin(telegram_user_id)
        finally:
            await db.close()

    asyncio.run(run())


def test_blocked_user_start_creates_single_repeat_access_request(tmp_path: Path) -> None:
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
            profile = TelegramUserProfile(telegram_user_id=200, username="blocked", first_name="Blocked")
            await users_repo.upsert_profile(profile, UserRole.BLOCKED_USER, "now")
            await users_repo.set_role(profile.telegram_user_id, UserRole.BLOCKED_USER, "now", blocked_at="now")

            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            first = await service.create_or_get_request(profile)
            second = await service.create_or_get_request(profile)

            assert first.user.role == UserRole.BLOCKED_USER
            assert first.request is not None
            assert first.created is True
            assert second.request is not None
            assert second.request.id == first.request.id
            assert second.created is False

            cursor = await db.conn.execute(
                "SELECT COUNT(*) AS cnt FROM access_requests WHERE telegram_user_id = ? AND status = ?",
                (profile.telegram_user_id, AccessRequestStatus.PENDING.value),
            )
            row = await cursor.fetchone()
            assert row["cnt"] == 1

            cursor = await db.conn.execute(
                "SELECT details_json FROM audit_log WHERE action = 'access_requested'"
            )
            audit_row = await cursor.fetchone()
            assert audit_row is not None
            assert json.loads(audit_row["details_json"])["repeat_after_block"] is True
        finally:
            await db.close()

    asyncio.run(run())


def test_blocked_at_only_start_creates_single_repeat_access_request(tmp_path: Path) -> None:
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
            profile = TelegramUserProfile(telegram_user_id=210, username="blocked_at", first_name="BlockedAt")
            await users_repo.upsert_profile(profile, UserRole.APPROVED_USER, "now")
            await db.conn.execute("UPDATE users SET blocked_at = ? WHERE telegram_user_id = ?", ("blocked", profile.telegram_user_id))
            await db.commit()

            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            first = await service.create_or_get_request(profile)
            second = await service.create_or_get_request(profile)

            assert first.user.role == UserRole.APPROVED_USER
            assert first.user.blocked_at == "blocked"
            assert first.request is not None
            assert first.created is True
            assert second.request is not None
            assert second.request.id == first.request.id
            assert second.created is False

            refreshed = await users_repo.get_by_id(profile.telegram_user_id)
            assert refreshed is not None
            assert refreshed.role == UserRole.APPROVED_USER
            assert refreshed.blocked_at == "blocked"
            cursor = await db.conn.execute(
                "SELECT COUNT(*) AS cnt FROM access_requests WHERE telegram_user_id = ? AND status = ?",
                (profile.telegram_user_id, AccessRequestStatus.PENDING.value),
            )
            row = await cursor.fetchone()
            assert row["cnt"] == 1

            approved_profile = TelegramUserProfile(telegram_user_id=211, username="approved", first_name="Approved")
            await users_repo.upsert_profile(approved_profile, UserRole.APPROVED_USER, "now")
            approved_result = await service.create_or_get_request(approved_profile)
            assert approved_result.request is None
            assert approved_result.created is False
        finally:
            await db.close()

    asyncio.run(run())


def test_reject_preserves_all_blocked_user_variants(tmp_path: Path) -> None:
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
            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            blocked_at_profile = TelegramUserProfile(telegram_user_id=220, username="blocked_at", first_name="BlockedAt")
            await users_repo.upsert_profile(blocked_at_profile, UserRole.APPROVED_USER, "now")
            await db.conn.execute("UPDATE users SET blocked_at = ? WHERE telegram_user_id = ?", ("blocked", 220))

            canonical_profile = TelegramUserProfile(telegram_user_id=221, username="canonical", first_name="Canonical")
            await users_repo.upsert_profile(canonical_profile, UserRole.BLOCKED_USER, "now")
            await users_repo.set_role(221, UserRole.BLOCKED_USER, "now", blocked_at="blocked")

            for telegram_user_id, role in ((222, "banned"), (223, "revoked")):
                await db.conn.execute(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at, blocked_at)
                    VALUES (?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (telegram_user_id, role, role.title(), role, "now", "now"),
                )
            await db.commit()

            request_ids: dict[int, int] = {}
            for telegram_user_id, username in ((220, "blocked_at"), (221, "canonical"), (222, "banned"), (223, "revoked")):
                request = await requests_repo.create(telegram_user_id, username, "now")
                request_ids[telegram_user_id] = request.id

            for request_id in request_ids.values():
                await service.reject(1, request_id)

            blocked_at_user = await users_repo.get_by_id(220)
            assert blocked_at_user is not None
            assert blocked_at_user.role == UserRole.APPROVED_USER
            assert blocked_at_user.blocked_at == "blocked"
            assert is_blocked_user(blocked_at_user) is True

            canonical_user = await users_repo.get_by_id(221)
            assert canonical_user is not None
            assert canonical_user.role == UserRole.BLOCKED_USER
            assert canonical_user.blocked_at == "blocked"

            for telegram_user_id in (222, 223):
                user = await users_repo.get_by_id(telegram_user_id)
                assert user is not None
                assert user.role == UserRole.BLOCKED_USER
                assert is_blocked_user(user) is True
                cursor = await db.conn.execute("SELECT role, blocked_at FROM users WHERE telegram_user_id = ?", (telegram_user_id,))
                row = await cursor.fetchone()
                assert row["role"] in {"banned", "revoked"}
                assert row["blocked_at"] is None
        finally:
            await db.close()

    asyncio.run(run())


def test_announcement_recipients_exclude_blocked_predicate_users(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            await users_repo.create_admin_placeholders({1}, "now")
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=230, username="approved", first_name="Approved"), UserRole.APPROVED_USER, "now")
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=231, username="pending", first_name="Pending"), UserRole.PENDING_USER, "now")
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=232, username="canonical", first_name="Canonical"), UserRole.BLOCKED_USER, "now")
            await users_repo.set_role(232, UserRole.BLOCKED_USER, "now", blocked_at="blocked")
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=236, username="blocked_at", first_name="BlockedAt"), UserRole.APPROVED_USER, "now")
            await db.conn.execute("UPDATE users SET blocked_at = ? WHERE telegram_user_id = ?", ("blocked", 236))
            for telegram_user_id, role in ((233, "banned"), (234, "revoked"), (235, "blocked")):
                await db.conn.execute(
                    """
                    INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at, blocked_at)
                    VALUES (?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (telegram_user_id, role, role.title(), role, "now", "now"),
                )
            await db.commit()

            assert await users_repo.count_announcement_recipients() == 2
            recipients = await users_repo.list_announcement_recipients_after(None, limit=20)
            assert [user.telegram_user_id for user in recipients] == [1, 230]
            recipients_after_admin = await users_repo.list_announcement_recipients_after(1, limit=20)
            assert [user.telegram_user_id for user in recipients_after_admin] == [230]
        finally:
            await db.close()

    asyncio.run(run())


def test_blocked_at_only_owner_cannot_update_key_note(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            vpn_keys = VpnKeyRepository(db)
            audit_repo = AuditLogRepository(db)
            audit = AuditService(audit_repo, ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            notes = NotesService(vpn_keys=vpn_keys, proxies=ProxyRepository(db), users=users, audit=audit)

            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=240, username="owner", first_name="Owner"), UserRole.APPROVED_USER, "now")
            key = await vpn_keys.create_pending(
                owner_user_id=240,
                username="owner",
                key_type=VpnKeyType.XRAY,
                note="old",
                payload={},
                public_payload={},
                created_by=240,
                now="now",
                uuid="00000000-0000-4000-8000-000000000240",
                email_label="owner",
            )
            await db.conn.execute("UPDATE users SET blocked_at = ? WHERE telegram_user_id = ?", ("blocked", 240))
            await db.commit()

            with pytest.raises(AccessDenied):
                await notes.update_key_note(240, key.id, "new")

            refreshed = await vpn_keys.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.note == "old"
            assert await _count_audit_actions(db, "note_updated") == 0
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.parametrize("legacy_role", ["banned", "revoked", "blocked", "ban"])
def test_legacy_blocked_owner_cannot_update_key_note(legacy_role: str, tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            vpn_keys = VpnKeyRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            notes = NotesService(vpn_keys=vpn_keys, proxies=ProxyRepository(db), users=users, audit=audit)

            await db.conn.execute(
                """
                INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at, blocked_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL)
                """,
                (241, legacy_role, legacy_role.title(), legacy_role, "now", "now"),
            )
            await db.commit()
            key = await vpn_keys.create_pending(
                owner_user_id=241,
                username=legacy_role,
                key_type=VpnKeyType.XRAY,
                note="old",
                payload={},
                public_payload={},
                created_by=241,
                now="now",
                uuid="00000000-0000-4000-8000-000000000241",
                email_label=legacy_role,
            )

            with pytest.raises(AccessDenied):
                await notes.update_key_note(241, key.id, "new")

            refreshed = await vpn_keys.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.note == "old"
            assert await _count_audit_actions(db, "note_updated") == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_key_note_update_preserves_owner_private_note_rules(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            vpn_keys = VpnKeyRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            users = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            await users.bootstrap_admins()
            notes = NotesService(vpn_keys=vpn_keys, proxies=ProxyRepository(db), users=users, audit=audit)

            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=250, username="owner", first_name="Owner"), UserRole.APPROVED_USER, "now")
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=251, username="other", first_name="Other"), UserRole.APPROVED_USER, "now")
            key = await vpn_keys.create_pending(
                owner_user_id=250,
                username="owner",
                key_type=VpnKeyType.XRAY,
                note="old",
                payload={},
                public_payload={},
                created_by=250,
                now="now",
                uuid="00000000-0000-4000-8000-000000000250",
                email_label="owner",
            )

            await notes.update_key_note(250, key.id, "owner note")
            refreshed = await vpn_keys.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.note == "owner note"
            assert await _count_audit_actions(db, "note_updated") == 1

            with pytest.raises(AccessDenied):
                await notes.update_key_note(251, key.id, "other note")
            refreshed = await vpn_keys.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.note == "owner note"
            assert await _count_audit_actions(db, "note_updated") == 1

            with pytest.raises(AccessDenied):
                await notes.update_key_note(1, key.id, "admin note")
            refreshed = await vpn_keys.get_by_id(key.id)
            assert refreshed is not None
            assert refreshed.note == "owner note"
            assert await _count_audit_actions(db, "note_updated") == 1
        finally:
            await db.close()

    asyncio.run(run())


async def _count_audit_actions(db: Database, action: str) -> int:
    cursor = await db.conn.execute("SELECT COUNT(*) AS cnt FROM audit_log WHERE action = ?", (action,))
    row = await cursor.fetchone()
    return int(row["cnt"]) if row is not None else 0


def test_legacy_blocking_role_aliases_are_treated_as_blocked() -> None:
    assert parse_user_role("blocked") == UserRole.BLOCKED_USER
    assert parse_user_role("banned") == UserRole.BLOCKED_USER
    assert parse_user_role("revoked") == UserRole.BLOCKED_USER
    assert is_blocked_user(User(300, "blocked", "Blocked", "blocked", "now", "now", None)) is True  # type: ignore[arg-type]
    assert is_blocked_user(User(301, "banned", "Banned", "banned", "now", "now", None)) is True  # type: ignore[arg-type]
    assert is_blocked_user(User(302, "revoked", "Revoked", "revoked", "now", "now", None)) is True  # type: ignore[arg-type]


def test_superadmin_is_not_blocked_by_stale_blocked_at() -> None:
    user = User(1, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", "now")
    assert is_blocked_user(user) is False


def test_reject_rolls_back_request_if_role_update_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
            await users_repo.upsert_profile(TelegramUserProfile(telegram_user_id=200, username="user", first_name="User"), UserRole.APPROVED_USER, "now")
            request = await requests_repo.create(200, "user", "now")

            original_set_role = users_repo.set_role

            async def fail_target_role(telegram_user_id: int, role: UserRole, now: str, blocked_at: str | None = None) -> None:
                if telegram_user_id == 200:
                    raise RuntimeError("role update failed")
                await original_set_role(telegram_user_id, role, now, blocked_at)

            monkeypatch.setattr(users_repo, "set_role", fail_target_role)
            service = AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)

            with pytest.raises(RuntimeError, match="role update failed"):
                await service.reject(1, request.id)

            refreshed_request = await requests_repo.get_by_id(request.id)
            refreshed_user = await users_repo.get_by_id(200)
            assert refreshed_request is not None
            assert refreshed_request.status == AccessRequestStatus.PENDING
            assert refreshed_user is not None
            assert refreshed_user.role == UserRole.APPROVED_USER
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode preservation is only meaningful on POSIX")
def test_xray_mutation_preserves_main_config_mode_while_backup_is_private(tmp_path: Path) -> None:
    class FakeSystemctl:
        async def xray_test_config(self, path: Path) -> ShellResult:
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray",), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
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
            apply_mode="reload",
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


def test_xray_reload_mode_uses_reload_without_restart(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"

    class FakeSystemctl:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def xray_test_config(self, path: Path) -> ShellResult:
            self.calls.append("test:candidate" if path != config_path else "test:config")
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            self.calls.append("reload")
            return ShellResult(("systemctl", "reload", service_name), 0, "", "")

        async def restart(self, service_name: str) -> ShellResult:
            self.calls.append("restart")
            return ShellResult(("systemctl", "restart", service_name), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            self.calls.append("is-active")
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    async def run() -> None:
        _write_minimal_xray_config(config_path)
        systemctl = FakeSystemctl()
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="reload",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider()),
            systemctl=systemctl,  # type: ignore[arg-type]
        )

        await adapter.add_client(
            uuid_value="00000000-0000-4000-8000-000000000000",
            email_label="user",
            short_id="abcd",
            flow="",
            manage_short_id=True,
        )

        updated = json.loads(config_path.read_text(encoding="utf-8"))
        assert updated["inbounds"][0]["settings"]["clients"][0]["email"] == "user"
        assert systemctl.calls == ["test:config", "test:candidate", "reload", "is-active"]

    asyncio.run(run())


def test_xray_remove_client_prefers_uuid_over_email_collision(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    bot_uuid = "00000000-0000-4000-8000-000000000001"
    manual_uuid = "00000000-0000-4000-8000-000000000002"
    email_label = "xray_A7kQz"

    class FakeSystemctl:
        async def xray_test_config(self, path: Path) -> ShellResult:
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

        async def restart(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "restart", service_name), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "reload", service_name), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    async def run() -> None:
        config_path.write_text(
            json.dumps(
                {
                    "inbounds": [
                        {
                            "protocol": "vless",
                            "settings": {
                                "clients": [
                                    {"id": manual_uuid, "email": email_label},
                                    {"id": bot_uuid, "email": email_label},
                                ]
                            },
                            "streamSettings": {"security": "reality", "realitySettings": {"shortIds": []}},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="restart",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider()),
            systemctl=FakeSystemctl(),  # type: ignore[arg-type]
        )

        await adapter.remove_client(
            uuid_value=bot_uuid,
            email_label=email_label,
            short_id=None,
            remove_short_id=False,
        )

        clients = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"]
        assert clients == [{"id": manual_uuid, "email": email_label}]

    asyncio.run(run())


def test_xray_reload_failure_restores_backup_without_restart_when_disabled(tmp_path: Path) -> None:
    class FakeSystemctl:
        def __init__(self) -> None:
            self.restart_calls = 0

        async def xray_test_config(self, path: Path) -> ShellResult:
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray",), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "reload", service_name), 1, "", "reload failed")

        async def restart(self, service_name: str) -> ShellResult:
            self.restart_calls += 1
            return ShellResult(("systemctl", "restart", service_name), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

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
        systemctl = FakeSystemctl()
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="reload",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider()),
            systemctl=systemctl,  # type: ignore[arg-type]
        )

        with pytest.raises(XrayApplyError):
            await adapter.add_client(
                uuid_value="00000000-0000-4000-8000-000000000000",
                email_label="user",
                short_id="abcd",
                flow="",
                manage_short_id=True,
            )

        restored = json.loads(config_path.read_text(encoding="utf-8"))
        assert restored["inbounds"][0]["settings"]["clients"] == []
        assert systemctl.restart_calls == 0

    asyncio.run(run())


def test_xray_reload_failure_restarts_restored_config_when_enabled(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"

    class FakeSystemctl:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def xray_test_config(self, path: Path) -> ShellResult:
            if path == config_path:
                self.calls.append("test:config")
            else:
                self.calls.append("test:candidate")
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            self.calls.append("reload")
            return ShellResult(("systemctl", "reload", service_name), 1, "", "reload failed")

        async def restart(self, service_name: str) -> ShellResult:
            self.calls.append("restart")
            return ShellResult(("systemctl", "restart", service_name), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            self.calls.append("is-active")
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    async def run() -> None:
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
        systemctl = FakeSystemctl()
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="reload",
            inbound_tag="",
            allow_restart_on_rollback=True,
            backup=BackupAdapter(ClockProvider()),
            systemctl=systemctl,  # type: ignore[arg-type]
        )

        with pytest.raises(XrayApplyError, match="backup восстановлен"):
            await adapter.add_client(
                uuid_value="00000000-0000-4000-8000-000000000000",
                email_label="user",
                short_id="abcd",
                flow="",
                manage_short_id=True,
            )

        restored = json.loads(config_path.read_text(encoding="utf-8"))
        assert restored["inbounds"][0]["settings"]["clients"] == []
        assert systemctl.calls == ["test:config", "test:candidate", "reload", "test:config", "restart"]

    asyncio.run(run())


def test_xray_reload_failure_with_invalid_restored_config_never_restarts(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"

    class FakeSystemctl:
        def __init__(self) -> None:
            self.config_test_calls = 0
            self.restart_calls = 0

        async def xray_test_config(self, path: Path) -> ShellResult:
            if path == config_path:
                self.config_test_calls += 1
                if self.config_test_calls >= 2:
                    return ShellResult(("xray", "run", "-test", "-config", str(path)), 1, "", "restored config invalid")
            else:
                json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "reload", service_name), 1, "", "reload failed")

        async def restart(self, service_name: str) -> ShellResult:
            self.restart_calls += 1
            return ShellResult(("systemctl", "restart", service_name), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    async def run() -> None:
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
        systemctl = FakeSystemctl()
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="reload",
            inbound_tag="",
            allow_restart_on_rollback=True,
            backup=BackupAdapter(ClockProvider()),
            systemctl=systemctl,  # type: ignore[arg-type]
        )

        with pytest.raises(XrayApplyError, match="восстановленный config не прошёл проверку"):
            await adapter.add_client(
                uuid_value="00000000-0000-4000-8000-000000000000",
                email_label="user",
                short_id="abcd",
                flow="",
                manage_short_id=True,
            )

        restored = json.loads(config_path.read_text(encoding="utf-8"))
        assert restored["inbounds"][0]["settings"]["clients"] == []
        assert systemctl.restart_calls == 0

    asyncio.run(run())


def test_xray_restart_mode_applies_with_restart_without_reload(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"

    class FakeSystemctl:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def xray_test_config(self, path: Path) -> ShellResult:
            self.calls.append("test:candidate" if path != config_path else "test:config")
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            self.calls.append("reload")
            return ShellResult(("systemctl", "reload", service_name), 0, "", "")

        async def restart(self, service_name: str) -> ShellResult:
            self.calls.append("restart")
            return ShellResult(("systemctl", "restart", service_name), 0, "", "")

        async def is_active(self, service_name: str) -> ShellResult:
            self.calls.append("is-active")
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    async def run() -> None:
        _write_minimal_xray_config(config_path)
        systemctl = FakeSystemctl()
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="restart",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider()),
            systemctl=systemctl,  # type: ignore[arg-type]
        )

        await adapter.add_client(
            uuid_value="00000000-0000-4000-8000-000000000000",
            email_label="user",
            short_id="abcd",
            flow="",
            manage_short_id=True,
        )

        updated = json.loads(config_path.read_text(encoding="utf-8"))
        assert updated["inbounds"][0]["settings"]["clients"][0]["email"] == "user"
        assert systemctl.calls == ["test:config", "test:candidate", "restart", "is-active"]

    asyncio.run(run())


def test_xray_restart_mode_restores_and_restarts_backup_on_restart_failure(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"

    class FakeSystemctl:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.restart_results = [
                ShellResult(("systemctl", "restart", "xray"), 1, "", "restart failed"),
                ShellResult(("systemctl", "restart", "xray"), 0, "", ""),
            ]

        async def xray_test_config(self, path: Path) -> ShellResult:
            self.calls.append("test:candidate" if path != config_path else "test:config")
            json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            self.calls.append("reload")
            return ShellResult(("systemctl", "reload", service_name), 0, "", "")

        async def restart(self, service_name: str) -> ShellResult:
            self.calls.append("restart")
            return self.restart_results.pop(0)

        async def is_active(self, service_name: str) -> ShellResult:
            self.calls.append("is-active")
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    async def run() -> None:
        _write_minimal_xray_config(config_path)
        systemctl = FakeSystemctl()
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="restart",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider()),
            systemctl=systemctl,  # type: ignore[arg-type]
        )

        with pytest.raises(XrayApplyError, match="backup восстановлен"):
            await adapter.add_client(
                uuid_value="00000000-0000-4000-8000-000000000000",
                email_label="user",
                short_id="abcd",
                flow="",
                manage_short_id=True,
            )

        restored = json.loads(config_path.read_text(encoding="utf-8"))
        assert restored["inbounds"][0]["settings"]["clients"] == []
        assert systemctl.calls == ["test:config", "test:candidate", "restart", "test:config", "restart", "is-active"]

    asyncio.run(run())


def test_xray_restart_mode_invalid_restored_config_never_restarts_backup(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"

    class FakeSystemctl:
        def __init__(self) -> None:
            self.config_test_calls = 0
            self.restart_calls = 0

        async def xray_test_config(self, path: Path) -> ShellResult:
            if path == config_path:
                self.config_test_calls += 1
                if self.config_test_calls >= 2:
                    return ShellResult(("xray", "run", "-test", "-config", str(path)), 1, "", "restored config invalid")
            else:
                json.loads(path.read_text(encoding="utf-8"))
            return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

        async def reload(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "reload", service_name), 0, "", "")

        async def restart(self, service_name: str) -> ShellResult:
            self.restart_calls += 1
            return ShellResult(("systemctl", "restart", service_name), 1, "", "restart failed")

        async def is_active(self, service_name: str) -> ShellResult:
            return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")

    async def run() -> None:
        _write_minimal_xray_config(config_path)
        systemctl = FakeSystemctl()
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="restart",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter(ClockProvider()),
            systemctl=systemctl,  # type: ignore[arg-type]
        )

        with pytest.raises(XrayApplyError, match="восстановленный config не прошёл проверку"):
            await adapter.add_client(
                uuid_value="00000000-0000-4000-8000-000000000000",
                email_label="user",
                short_id="abcd",
                flow="",
                manage_short_id=True,
            )

        restored = json.loads(config_path.read_text(encoding="utf-8"))
        assert restored["inbounds"][0]["settings"]["clients"] == []
        assert systemctl.restart_calls == 1

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


def test_awg_startup_reconcile_audit_failure_does_not_stop_remaining_keys(tmp_path: Path) -> None:
    keys = [
        VpnKey(
            id=1,
            owner_user_id=100,
            username="user",
            key_type=VpnKeyType.AWG,
            status=VpnKeyStatus.PENDING_DELETE,
            note=None,
            uuid=None,
            email_label="label-1",
            public_key="public-1",
            client_ip="10.0.0.2",
            payload={},
            public_payload={},
            created_at="now",
            updated_at="now",
            revoked_at=None,
            deleted_at=None,
            created_by=100,
            revoked_by=None,
            deleted_by=None,
        ),
        VpnKey(
            id=2,
            owner_user_id=100,
            username="user",
            key_type=VpnKeyType.AWG,
            status=VpnKeyStatus.PENDING_DELETE,
            note=None,
            uuid=None,
            email_label="label-2",
            public_key="public-2",
            client_ip="10.0.0.3",
            payload={},
            public_payload={},
            created_at="now",
            updated_at="now",
            revoked_at=None,
            deleted_at=None,
            created_by=100,
            revoked_by=None,
            deleted_by=None,
        ),
    ]

    class Repo:
        async def list_by_type_statuses(
            self,
            key_type: VpnKeyType,
            statuses: set[VpnKeyStatus],
            limit: int = 500,
            offset: int = 0,
            after_id: int | None = None,
        ) -> list[VpnKey]:
            return [key for key in keys if after_id is None or key.id > after_id][:limit]

    class Audit:
        def __init__(self) -> None:
            self.actions: list[str] = []

        async def write(self, *, action: str, **kwargs: object) -> None:
            self.actions.append(action)
            raise RuntimeError("audit failed")

    async def run() -> None:
        audit = Audit()
        service = AwgService(
            vpn_keys=Repo(),  # type: ignore[arg-type]
            users=object(),  # type: ignore[arg-type]
            adapter=object(),  # type: ignore[arg-type]
            ip_allocator=object(),  # type: ignore[arg-type]
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
        )
        processed: list[int] = []

        async def reconcile_key(key: VpnKey) -> bool:
            processed.append(key.id)
            if key.id == 1:
                raise RuntimeError("service failed")
            return False

        service._startup_reconcile_key = reconcile_key  # type: ignore[method-assign]
        summary = await service.startup_reconcile()
        assert summary == {"checked": 2, "recovered": 0, "failed": 1}
        assert processed == [1, 2]
        assert audit.actions == ["awg_startup_reconcile_failed"]

    asyncio.run(run())


def test_xray_startup_reconcile_audit_failure_does_not_stop_remaining_keys(tmp_path: Path) -> None:
    keys = [
        VpnKey(
            id=1,
            owner_user_id=100,
            username="user",
            key_type=VpnKeyType.XRAY,
            status=VpnKeyStatus.PENDING_DELETE,
            note=None,
            uuid="00000000-0000-4000-8000-000000000001",
            email_label="label-1",
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
        ),
        VpnKey(
            id=2,
            owner_user_id=100,
            username="user",
            key_type=VpnKeyType.XRAY,
            status=VpnKeyStatus.PENDING_DELETE,
            note=None,
            uuid="00000000-0000-4000-8000-000000000002",
            email_label="label-2",
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
        ),
    ]

    class Repo:
        async def list_by_type_statuses(
            self,
            key_type: VpnKeyType,
            statuses: set[VpnKeyStatus],
            limit: int = 500,
            offset: int = 0,
            after_id: int | None = None,
        ) -> list[VpnKey]:
            return [key for key in keys if after_id is None or key.id > after_id][:limit]

    class Audit:
        def __init__(self) -> None:
            self.actions: list[str] = []

        async def write(self, *, action: str, **kwargs: object) -> None:
            self.actions.append(action)
            raise RuntimeError("audit failed")

    async def run() -> None:
        audit = Audit()
        service = XrayService(
            vpn_keys=Repo(),  # type: ignore[arg-type]
            users=object(),  # type: ignore[arg-type]
            adapter=object(),  # type: ignore[arg-type]
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
        )
        processed: list[int] = []

        async def reconcile_key(key: VpnKey) -> bool:
            processed.append(key.id)
            if key.id == 1:
                raise RuntimeError("service failed")
            return False

        service._startup_reconcile_key = reconcile_key  # type: ignore[method-assign]
        summary = await service.startup_reconcile()
        assert summary == {"checked": 2, "recovered": 0, "failed": 1}
        assert processed == [1, 2]
        assert audit.actions == ["xray_startup_reconcile_failed"]

    asyncio.run(run())


@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.AWG])
def test_startup_reconcile_processes_more_than_one_batch(key_type: VpnKeyType, tmp_path: Path) -> None:
    keys = [
        VpnKey(
            id=index,
            owner_user_id=100,
            username="user",
            key_type=key_type,
            status=VpnKeyStatus.PENDING_DELETE,
            note=None,
            uuid=f"00000000-0000-4000-8000-{index:012d}" if key_type == VpnKeyType.XRAY else None,
            email_label=f"label-{index}",
            public_key=f"public-{index}" if key_type == VpnKeyType.AWG else None,
            client_ip=f"10.0.0.{index % 250 + 1}" if key_type == VpnKeyType.AWG else None,
            payload={},
            public_payload={},
            created_at="now",
            updated_at="now",
            revoked_at=None,
            deleted_at=None,
            created_by=100,
            revoked_by=None,
            deleted_by=None,
        )
        for index in range(1, 502)
    ]

    class Repo:
        async def list_by_type_statuses(
            self,
            requested_type: VpnKeyType,
            statuses: set[VpnKeyStatus],
            limit: int = 500,
            offset: int = 0,
            after_id: int | None = None,
        ) -> list[VpnKey]:
            assert requested_type == key_type
            return [key for key in keys if after_id is None or key.id > after_id][:limit]

    class Audit:
        async def write(self, **kwargs: object) -> None:
            return None

    async def run() -> None:
        if key_type == VpnKeyType.XRAY:
            service = XrayService(
                vpn_keys=Repo(),  # type: ignore[arg-type]
                users=object(),  # type: ignore[arg-type]
                adapter=object(),  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=Audit(),  # type: ignore[arg-type]
            )
        else:
            service = AwgService(
                vpn_keys=Repo(),  # type: ignore[arg-type]
                users=object(),  # type: ignore[arg-type]
                adapter=object(),  # type: ignore[arg-type]
                ip_allocator=object(),  # type: ignore[arg-type]
                settings=_settings(tmp_path),
                clock=ClockProvider(),
                ids=object(),  # type: ignore[arg-type]
                audit=Audit(),  # type: ignore[arg-type]
            )
        processed: list[int] = []

        async def reconcile_key(key: VpnKey) -> bool:
            processed.append(key.id)
            return False

        service._startup_reconcile_key = reconcile_key  # type: ignore[method-assign]
        summary = await service.startup_reconcile()

        assert summary == {"checked": 501, "recovered": 0, "failed": 0}
        assert processed == list(range(1, 502))

    asyncio.run(run())


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


@pytest.mark.parametrize(
    "payload",
    [
        {"_corrupted": True, "client_ip": "10.0.0.2"},
        {"client_ip": "10.0.0.2"},
        {"private_key": "", "client_ip": "10.0.0.2"},
        {"private_key": f"{VALID_AWG_PRIVATE_KEY}\n", "client_ip": "10.0.0.2"},
        {"private_key": "...", "client_ip": "10.0.0.2"},
        {"private_key": "not-base64", "client_ip": "10.0.0.2"},
        {"private_key": base64.b64encode(b"short").decode("ascii"), "client_ip": "10.0.0.2"},
    ],
)
def test_awg_invalid_private_key_payload_does_not_return_config(payload: dict[str, object], tmp_path: Path) -> None:
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
                payload=payload,
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
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
        )
        with pytest.raises(InvalidOperation, match="AWG-конфигурация повреждена") as exc_info:
            await service.get_awg_client_config_plain(100, 10)
        assert "PrivateKey" not in str(exc_info.value)
        assert audit.actions == ["awg_config_corrupted"]

    asyncio.run(run())


def test_awg_valid_private_key_payload_returns_config_and_russian_status(tmp_path: Path) -> None:
    payload = {"private_key": VALID_AWG_PRIVATE_KEY, "client_ip": "10.0.0.2"}

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
                payload=payload,
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
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
        )
        config = await service.get_awg_client_config_plain(100, 10)
        assert f"PrivateKey = {VALID_AWG_PRIVATE_KEY}" in config
        assert audit.actions == ["awg_config_file_shown"]

        key = await Repo().get_by_id(10)
        assert key is not None
        text = service._format_config(key)
        assert "Статус: активен" in text
        assert "Статус: active" not in text

    asyncio.run(run())


def test_xray_config_format_uses_russian_status(tmp_path: Path) -> None:
    key = VpnKey(
        id=10,
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="00000000-0000-4000-8000-000000000000",
        email_label="label",
        public_key=None,
        client_ip=None,
        payload={
            "uuid": "00000000-0000-4000-8000-000000000000",
            "short_id": "abcd",
            "email_label": "label",
        },
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )
    service = XrayService(
        vpn_keys=object(),  # type: ignore[arg-type]
        users=object(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=object(),  # type: ignore[arg-type]
    )
    text = service._format_config(key)
    assert "Статус: активен" in text
    assert "Статус: active" not in text


def test_safe_edit_message_text_sends_new_message_when_edit_target_is_unavailable() -> None:
    class MessageStub:
        def __init__(self) -> None:
            self.answers: list[tuple[str, object | None]] = []

        async def edit_text(self, text: str, reply_markup: object = None) -> None:
            raise TelegramBadRequest(method=SimpleNamespace(), message="Bad Request: message to edit not found")

        async def answer(self, text: str, reply_markup: object = None) -> None:
            self.answers.append((text, reply_markup))

    async def run() -> None:
        message = MessageStub()
        assert await safe_edit_message_text(message, "fallback", reply_markup="keyboard") is True  # type: ignore[arg-type]
        assert message.answers == [("fallback", "keyboard")]

    asyncio.run(run())


def test_safe_callback_answer_calls_regular_callback_answer() -> None:
    class CallbackStub:
        def __init__(self) -> None:
            self.answers: list[tuple[str | None, bool | None]] = []

        async def answer(
            self,
            text: str | None = None,
            show_alert: bool | None = None,
            **kwargs: object,
        ) -> None:
            self.answers.append((text, show_alert))

    async def run() -> None:
        callback = CallbackStub()
        assert await safe_callback_answer(callback, "ok", show_alert=True) is True  # type: ignore[arg-type]
        assert callback.answers == [("ok", True)]

    asyncio.run(run())


def test_safe_callback_answer_ignores_stale_callback_query() -> None:
    class CallbackStub:
        async def answer(self, **kwargs: object) -> None:
            raise TelegramBadRequest(
                method=SimpleNamespace(),
                message="Bad Request: query is too old and response timeout expired or query ID is invalid",
            )

    async def run() -> None:
        assert await safe_callback_answer(CallbackStub()) is False  # type: ignore[arg-type]

    asyncio.run(run())


def test_safe_callback_answer_reraises_other_bad_request() -> None:
    class CallbackStub:
        async def answer(self, **kwargs: object) -> None:
            raise TelegramBadRequest(method=SimpleNamespace(), message="Bad Request: button_data_invalid")

    async def run() -> None:
        with pytest.raises(TelegramBadRequest, match="button_data_invalid"):
            await safe_callback_answer(CallbackStub())  # type: ignore[arg-type]

    asyncio.run(run())


def test_answer_callback_error_does_not_fail_again_for_stale_callback_query() -> None:
    class CallbackStub:
        async def answer(self, **kwargs: object) -> None:
            raise TelegramBadRequest(method=SimpleNamespace(), message="Bad Request: query ID is invalid")

    async def run() -> None:
        await answer_callback_error(CallbackStub(), AccessDenied("denied"))  # type: ignore[arg-type]

    asyncio.run(run())


def test_send_awg_config_still_sends_document_when_edit_text_is_not_modified() -> None:
    class MessageStub:
        def __init__(self) -> None:
            self.documents: list[tuple[object, str | None]] = []

        async def edit_text(self, text: str, reply_markup: object = None) -> None:
            raise TelegramBadRequest(method=SimpleNamespace(), message="Bad Request: message is not modified")

        async def answer(self, text: str, reply_markup: object = None) -> None:
            raise AssertionError("long config should be sent as document")

        async def answer_document(
            self,
            document: object,
            caption: str | None = None,
            disable_content_type_detection: bool = False,
            reply_markup: object = None,
        ) -> None:
            self.documents.append((document, caption))

    async def run() -> None:
        message = MessageStub()
        await send_awg_config(
            message,  # type: ignore[arg-type]
            title="AWG",
            config_text="x" * (MAX_TEXT_CONFIG_LEN + 1),
            filename="awg_A7kQz.conf",
            edit_text=True,
        )

        assert len(message.documents) == 1
        assert message.documents[0][1] is not None

    asyncio.run(run())


def test_awg_client_config_skips_empty_interface_options(tmp_path: Path) -> None:
    payload = {"private_key": VALID_AWG_PRIVATE_KEY, "client_ip": "10.0.0.2"}

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
                payload=payload,
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
            return {"I2": "", "I3": "   ", "H1": "abc", "Jc": "4", "DNS": "9.9.9.9"}

    class Audit:
        async def write(self, **kwargs: object) -> None:
            return None

    async def run() -> None:
        service = AwgService(
            vpn_keys=Repo(),  # type: ignore[arg-type]
            users=Users(),  # type: ignore[arg-type]
            adapter=Adapter(),  # type: ignore[arg-type]
            ip_allocator=object(),  # type: ignore[arg-type]
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=object(),  # type: ignore[arg-type]
            audit=Audit(),  # type: ignore[arg-type]
        )
        config = await service.get_awg_client_config_plain(100, 10)
        assert "I2 =" not in config
        assert "I3 =" not in config
        assert "H1 = abc" in config
        assert "Jc = 4" in config
        assert "DNS = 1.1.1.1" in config
        assert "DNS = 9.9.9.9" not in config

    asyncio.run(run())
