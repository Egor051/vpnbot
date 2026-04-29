from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiogram.enums import ChatType

from adapters.clock import ClockProvider
from adapters.errors import AwgIpAllocationError, XrayInboundNotFoundError
from adapters.id_generator import IdGenerator
from adapters.ip_allocator import IpAllocator
from adapters.xray_config import XrayConfigAdapter
from bot.app import _startup_reconcile_keys
from bot.handlers.admin import admin_announcement_send
from bot.messages import awg_config_filename
from config.settings import Settings, SettingsError, load_settings
from db.database import Database
from models.dto import ShellResult, TelegramUserProfile, User, VpnKey
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.awg import AwgService
from services.backend_health import BackendHealth
from services.errors import InvalidOperation
from services.user_locks import UserLockManager
from services.users import UserService
from services.xray import XrayService


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values = dict(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
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
    values.update(overrides)
    return Settings(**values)


def _vpn_key(
    *,
    key_id: int = 1,
    key_type: VpnKeyType = VpnKeyType.XRAY,
    status: VpnKeyStatus = VpnKeyStatus.APPLY_FAILED,
    email_label: str = "xray_Ab3dE",
) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=100,
        username="user",
        key_type=key_type,
        status=status,
        note=None,
        uuid="00000000-0000-4000-8000-000000000000" if key_type == VpnKeyType.XRAY else None,
        email_label=email_label,
        public_key="public" if key_type == VpnKeyType.AWG else None,
        client_ip="10.0.0.2" if key_type == VpnKeyType.AWG else None,
        payload={"email_label": email_label},
        public_payload={"email_label": email_label},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


class _Audit:
    async def write(self, **kwargs: object) -> None:
        return None

    async def write_best_effort(self, **kwargs: object) -> None:
        return None


class _Ids:
    def __init__(self, labels: list[str] | None = None) -> None:
        self.labels = labels or ["xray_Ab3dE", "awg_Ab3dE"]

    def uuid4(self) -> str:
        return "00000000-0000-4000-8000-000000000001"

    def xray_short_id(self) -> str:
        return "abcd"

    def generated_key_name(self, prefix: str) -> str:
        if self.labels:
            return self.labels.pop(0)
        return f"{prefix}_Z9yX8"


class _Users:
    def __init__(self, role: UserRole = UserRole.APPROVED_USER) -> None:
        self.role = role
        self.user_locks = UserLockManager()

    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        if self.role != UserRole.APPROVED_USER:
            raise InvalidOperation("Доступ заблокирован")
        return User(actor_user_id, "user", "User", self.role, "now", "now", None)

    async def require_superadmin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)


def test_generated_key_name_format_uses_required_alphabet() -> None:
    ids = IdGenerator()

    assert re.fullmatch(r"xray_[A-Za-z0-9]{5}", ids.generated_key_name("xray"))
    assert re.fullmatch(r"awg_[A-Za-z0-9]{5}", ids.generated_key_name("awg"))


def test_generated_names_retry_email_label_collision(tmp_path: Path) -> None:
    class Repo:
        async def find_by_uuid(self, uuid_value: str) -> None:
            return None

        async def find_by_email_label(self, email_label: str) -> object | None:
            return object() if email_label.endswith("AAAAA") else None

    service = XrayService(
        vpn_keys=Repo(),  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=_Ids(["xray_AAAAA", "xray_Bbbbb"]),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
    )

    uuid_value, label = asyncio.run(service._unique_identity(100, "old_name"))

    assert uuid_value == "00000000-0000-4000-8000-000000000001"
    assert label == "xray_Bbbbb"


def test_awg_generated_filename_uses_generated_name() -> None:
    key = _vpn_key(key_type=VpnKeyType.AWG, email_label="awg_A7kQz")

    assert awg_config_filename(key) == "awg_A7kQz.conf"


def test_xray_link_fragment_uses_generated_email_label(tmp_path: Path) -> None:
    service = XrayService(
        vpn_keys=object(),  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=IdGenerator(),
        audit=_Audit(),  # type: ignore[arg-type]
    )

    link = service._build_vless_link("00000000-0000-4000-8000-000000000000", "abcd", "xray_m91Bc")

    assert link.endswith("#xray_m91Bc")


def test_degraded_mode_after_failed_reconcile_blocks_only_matching_backend() -> None:
    class FailingXray:
        async def startup_reconcile(self) -> dict[str, int]:
            raise RuntimeError("boom")

    class Awg:
        async def startup_reconcile(self) -> dict[str, int]:
            return {"checked": 0, "recovered": 0, "failed": 0}

    class Audit:
        async def write(self, **kwargs: object) -> None:
            return None

    health = BackendHealth()
    services = SimpleNamespace(xray=FailingXray(), awg=Awg(), audit=Audit(), backend_health=health)

    asyncio.run(_startup_reconcile_keys(services))  # type: ignore[arg-type]

    with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
        health.require_mutation_allowed(VpnKeyType.XRAY)
    health.require_mutation_allowed(VpnKeyType.AWG)


def test_xray_apply_failed_recovered_when_client_present(tmp_path: Path) -> None:
    class Repo:
        def __init__(self) -> None:
            self.key = _vpn_key(status=VpnKeyStatus.APPLY_FAILED)

        async def list_by_type_statuses(self, *args: object, **kwargs: object) -> list[VpnKey]:
            return [self.key] if self.key.status == VpnKeyStatus.APPLY_FAILED else []

        async def mark_active(self, key_id: int, now: str, payload: object = None, public_payload: object = None) -> None:
            self.key = _vpn_key(status=VpnKeyStatus.ACTIVE)

    class Adapter:
        def find_client(self, **kwargs: object) -> dict[str, str]:
            return {"email": "xray_Ab3dE"}

    repo = Repo()
    service = XrayService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=Adapter(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=IdGenerator(),
        audit=_Audit(),  # type: ignore[arg-type]
    )

    summary = asyncio.run(service.startup_reconcile())

    assert summary == {"checked": 1, "recovered": 1, "failed": 0}
    assert repo.key.status == VpnKeyStatus.ACTIVE


def test_xray_apply_failed_remains_failed_when_client_absent(tmp_path: Path) -> None:
    class Repo:
        def __init__(self) -> None:
            self.key = _vpn_key(status=VpnKeyStatus.APPLY_FAILED)
            self.sent = False

        async def list_by_type_statuses(self, *args: object, **kwargs: object) -> list[VpnKey]:
            if self.sent:
                return []
            self.sent = True
            return [self.key]

    class Adapter:
        def find_client(self, **kwargs: object) -> None:
            return None

    service = XrayService(
        vpn_keys=Repo(),  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=Adapter(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=IdGenerator(),
        audit=_Audit(),  # type: ignore[arg-type]
    )

    summary = asyncio.run(service.startup_reconcile())

    assert summary == {"checked": 1, "recovered": 0, "failed": 0}


def test_awg_apply_failed_recovered_when_peer_present(tmp_path: Path) -> None:
    class Repo:
        def __init__(self) -> None:
            self.key = _vpn_key(key_type=VpnKeyType.AWG, status=VpnKeyStatus.APPLY_FAILED, email_label="awg_Ab3dE")

        async def list_by_type_statuses(self, *args: object, **kwargs: object) -> list[VpnKey]:
            return [self.key] if self.key.status == VpnKeyStatus.APPLY_FAILED else []

        async def mark_active(self, key_id: int, now: str, payload: object = None, public_payload: object = None) -> None:
            self.key = _vpn_key(key_type=VpnKeyType.AWG, status=VpnKeyStatus.ACTIVE, email_label="awg_Ab3dE")

    class Adapter:
        def find_peer(self, **kwargs: object) -> dict[str, str]:
            return {"PublicKey": "public"}

    service = AwgService(
        vpn_keys=Repo(),  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=Adapter(),  # type: ignore[arg-type]
        ip_allocator=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=IdGenerator(),
        audit=_Audit(),  # type: ignore[arg-type]
    )

    summary = asyncio.run(service.startup_reconcile())

    assert summary == {"checked": 1, "recovered": 1, "failed": 0}


def test_awg_apply_failed_remains_failed_when_peer_absent(tmp_path: Path) -> None:
    class Repo:
        def __init__(self) -> None:
            self.sent = False

        async def list_by_type_statuses(self, *args: object, **kwargs: object) -> list[VpnKey]:
            if self.sent:
                return []
            self.sent = True
            return [_vpn_key(key_type=VpnKeyType.AWG, status=VpnKeyStatus.APPLY_FAILED, email_label="awg_Ab3dE")]

    class Adapter:
        def find_peer(self, **kwargs: object) -> None:
            return None

    service = AwgService(
        vpn_keys=Repo(),  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=Adapter(),  # type: ignore[arg-type]
        ip_allocator=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=IdGenerator(),
        audit=_Audit(),  # type: ignore[arg-type]
    )

    summary = asyncio.run(service.startup_reconcile())

    assert summary == {"checked": 1, "recovered": 0, "failed": 0}


def test_xray_inbound_selection_requires_tag_when_multiple_reality_inbounds(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"tag": "a", "protocol": "vless", "settings": {"clients": []}, "streamSettings": {"security": "reality"}},
                    {"tag": "b", "protocol": "vless", "settings": {"clients": []}, "streamSettings": {"security": "reality"}},
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
        backup=object(),  # type: ignore[arg-type]
        systemctl=object(),  # type: ignore[arg-type]
    )

    with pytest.raises(XrayInboundNotFoundError, match="несколько VLESS/Reality"):
        adapter.find_client(uuid_value="missing")


def test_xray_inbound_selection_with_single_reality_inbound_allows_empty_tag(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {"tag": "main", "protocol": "vless", "settings": {"clients": [{"id": "u"}]}, "streamSettings": {"security": "reality"}}
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
        backup=object(),  # type: ignore[arg-type]
        systemctl=object(),  # type: ignore[arg-type]
    )

    assert adapter.find_client(uuid_value="u") == {"id": "u"}


def test_awg_server_address_validation_rejects_invalid_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("AWG_NETWORK", "10.0.0.0/24")

    monkeypatch.setenv("AWG_SERVER_ADDRESS", "10.0.1.1")
    with pytest.raises(SettingsError, match="AWG_SERVER_ADDRESS должен входить"):
        load_settings()

    monkeypatch.setenv("AWG_SERVER_ADDRESS", "10.0.0.0")
    with pytest.raises(SettingsError, match="network или broadcast"):
        load_settings()

    monkeypatch.setenv("AWG_SERVER_ADDRESS", "10.0.0.255")
    with pytest.raises(SettingsError, match="network или broadcast"):
        load_settings()


def test_ip_allocator_never_allocates_valid_server_address(tmp_path: Path) -> None:
    class Repo:
        async def get_occupied_awg_ips(self) -> set[str]:
            return set()

    allocator = IpAllocator(Repo(), "10.0.0.0/30", "10.0.0.1")  # type: ignore[arg-type]

    assert asyncio.run(allocator.next_free_ip()) == "10.0.0.2"

    with pytest.raises(AwgIpAllocationError):
        IpAllocator(Repo(), "10.0.0.0/30", "10.0.1.1")  # type: ignore[arg-type]


def test_announcement_double_confirm_sends_once(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private_callback(callback: object, text: str = "") -> bool:
        return True

    async def fake_edit(message: object, text: str, reply_markup: object = None) -> bool:
        message.edits.append(text)
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private_callback)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_edit)

    class State:
        def __init__(self) -> None:
            self.data: dict[str, object] = {"from_chat_id": 1, "message_id": 77}

        async def get_data(self) -> dict[str, object]:
            return dict(self.data)

        async def clear(self) -> None:
            self.data.clear()

    class Callback:
        def __init__(self) -> None:
            self.from_user = SimpleNamespace(id=1)
            self.message = SimpleNamespace(chat=SimpleNamespace(type=ChatType.PRIVATE), edits=[])
            self.answers: list[tuple[str, bool | None]] = []

        async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
            self.answers.append((text or "", show_alert))

    class Announcements:
        def __init__(self) -> None:
            self.calls = 0

        async def send_to_all(self, **kwargs: object) -> SimpleNamespace:
            self.calls += 1
            await asyncio.sleep(0.01)
            return SimpleNamespace(total=1, success=1, failed=0)

    async def run() -> None:
        state = State()
        announcements = Announcements()
        services = SimpleNamespace(users=_Users(), announcements=announcements)
        bot = object()
        first = Callback()
        second = Callback()

        await asyncio.gather(
            admin_announcement_send(first, state, services, bot),  # type: ignore[arg-type]
            admin_announcement_send(second, state, services, bot),  # type: ignore[arg-type]
        )

        assert announcements.calls == 1
        all_answers = first.answers + second.answers
        assert ("Объявление уже отправлено или устарело.", True) in all_answers

    asyncio.run(run())


def test_block_user_revokes_more_than_one_batch(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            keys_repo = VpnKeyRepository(db)
            for index in range(501):
                key = await keys_repo.create_pending(
                    owner_user_id=100,
                    username="user",
                    key_type=VpnKeyType.XRAY,
                    note=None,
                    payload={"uuid": str(index), "email_label": f"xray_{index}"},
                    public_payload={"email_label": f"xray_{index}"},
                    created_by=100,
                    now=f"now-{index}",
                    uuid=f"00000000-0000-4000-8000-{index:012d}",
                    email_label=f"xray_{index}",
                )
                await keys_repo.mark_active(key.id, "now")
            service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=_Audit())  # type: ignore[arg-type]

            async def revoke(actor_user_id: int, key_id: int) -> VpnKey:
                await keys_repo.mark_revoked(key_id, actor_user_id, "now")
                key = await keys_repo.get_by_id(key_id)
                assert key is not None
                return key

            service.attach_key_management(keys_repo, {VpnKeyType.XRAY: revoke})

            result = await service.block_user(1, 100)

            assert len(result.revoked_key_ids) == 501
            assert result.errors == ()
            user = await users_repo.get_by_id(100)
            assert user is not None and user.role == UserRole.BLOCKED_USER
        finally:
            await db.close()

    asyncio.run(run())


def test_concurrent_xray_create_vs_block_finishes_without_active_key(tmp_path: Path) -> None:
    class Adapter:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.removed = False

        async def add_client(self, **kwargs: object) -> None:
            self.started.set()
            await self.release.wait()

        async def remove_client(self, **kwargs: object) -> None:
            self.removed = True

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            keys_repo = VpnKeyRepository(db)
            user_service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=_Audit())  # type: ignore[arg-type]
            adapter = Adapter()
            xray = XrayService(
                vpn_keys=keys_repo,
                users=user_service,
                adapter=adapter,  # type: ignore[arg-type]
                settings=settings,
                clock=ClockProvider(),
                ids=_Ids(["xray_A7kQz"]),  # type: ignore[arg-type]
                audit=_Audit(),  # type: ignore[arg-type]
            )
            user_service.attach_key_management(keys_repo, {VpnKeyType.XRAY: xray.revoke_xray_key})

            create_task = asyncio.create_task(xray.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None))
            await adapter.started.wait()
            block_task = asyncio.create_task(user_service.block_user(1, 100))
            await asyncio.sleep(0)
            adapter.release.set()

            created = await create_task
            blocked = await block_task
            stored = await keys_repo.get_by_id(created.key.id)
            user = await users_repo.get_by_id(100)

            assert blocked.errors == ()
            assert stored is not None and stored.status == VpnKeyStatus.REVOKED
            assert user is not None and user.role == UserRole.BLOCKED_USER
            assert adapter.removed is True
        finally:
            await db.close()

    asyncio.run(run())


def test_concurrent_awg_create_vs_block_finishes_without_active_key(tmp_path: Path) -> None:
    class Adapter:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.removed = False

        def read_server_config(self) -> SimpleNamespace:
            return SimpleNamespace(listen_port=443, public_key="server-public", interface_options={}, address=None)

        def client_interface_options(self) -> dict[str, str]:
            return {}

        async def generate_private_key(self) -> str:
            return "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

        async def generate_public_key(self, private_key: str) -> str:
            return "public"

        async def generate_preshared_key(self) -> str:
            return "psk"

        async def add_peer(self, **kwargs: object) -> None:
            self.started.set()
            await self.release.wait()

        async def remove_peer(self, **kwargs: object) -> None:
            self.removed = True

    class Allocator:
        async def next_free_ip(self) -> str:
            return "10.0.0.2"

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            keys_repo = VpnKeyRepository(db)
            user_service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=_Audit())  # type: ignore[arg-type]
            adapter = Adapter()
            awg = AwgService(
                vpn_keys=keys_repo,
                users=user_service,
                adapter=adapter,  # type: ignore[arg-type]
                ip_allocator=Allocator(),  # type: ignore[arg-type]
                settings=settings,
                clock=ClockProvider(),
                ids=_Ids(["awg_A7kQz"]),  # type: ignore[arg-type]
                audit=_Audit(),  # type: ignore[arg-type]
            )
            user_service.attach_key_management(keys_repo, {VpnKeyType.AWG: awg.revoke_awg_key})

            create_task = asyncio.create_task(awg.create_awg_key(100, TelegramUserProfile(100, "user", "User"), None))
            await adapter.started.wait()
            block_task = asyncio.create_task(user_service.block_user(1, 100))
            await asyncio.sleep(0)
            adapter.release.set()

            created = await create_task
            blocked = await block_task
            stored = await keys_repo.get_by_id(created.key.id)
            user = await users_repo.get_by_id(100)

            assert blocked.errors == ()
            assert stored is not None and stored.status == VpnKeyStatus.REVOKED
            assert user is not None and user.role == UserRole.BLOCKED_USER
            assert adapter.removed is True
        finally:
            await db.close()

    asyncio.run(run())
