"""Generated key naming and backend failure-recovery regressions.

Covers two related areas:
  - generated key names / email labels (required alphabet, collision retry, and how
    the label flows into AWG filenames and Xray link fragments);
  - backend apply-failure handling: compensation when a create half-applies,
    degraded-mode gating per backend, and recovery of apply_failed keys once the
    client/peer is confirmed present or absent.

Large by history; the two areas above are natural split points for a future
cleanup.
"""

import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiogram.enums import ChatType

from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.errors import AwgIpAllocationError, XrayInboundNotFoundError
from adapters.id_generator import IdGenerator
from adapters.ip_allocator import IpAllocator
from adapters.xray_config import XrayClientApplyResult, XrayConfigAdapter
from bot.app import _startup_reconcile_keys
from bot.handlers.admin import admin_announcement_send
from bot.messages import awg_config_filename
from config.settings import Settings, SettingsError, load_settings
from db.database import Database
from models.dto import ShellResult, TelegramUserProfile, User, VpnKey
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.audit_log import AuditLogRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.awg import AwgService
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation
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


def _write_xray_config(config_path: Path, short_ids: list[str] | None = None) -> None:
    config_path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {
                            "security": "reality",
                            "realitySettings": {"shortIds": list(short_ids or [])},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


class _XraySystemctl:
    async def xray_test_config(self, path: Path) -> ShellResult:
        json.loads(path.read_text(encoding="utf-8"))
        return ShellResult(("xray", "run", "-test", "-config", str(path)), 0, "", "")

    async def reload(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "reload", service_name), 0, "", "")

    async def restart(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "restart", service_name), 0, "", "")

    async def is_active(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")


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

    uuid_value, label = asyncio.run(service._unique_identity("xray_tcp"))

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


def test_xray_create_mark_active_failure_removes_applied_client(tmp_path: Path) -> None:
    class Repo:
        def __init__(self) -> None:
            self.statuses: list[VpnKeyStatus] = []

        async def find_by_uuid(self, uuid_value: str) -> None:
            return None

        async def find_by_email_label(self, email_label: str) -> None:
            return None

        async def create_pending(self, **kwargs: object) -> VpnKey:
            return _vpn_key(
                key_id=10,
                status=VpnKeyStatus.PENDING_APPLY,
                email_label=str(kwargs["email_label"]),
            )

        async def mark_active(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("db mark failed")

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            self.statuses.append(status)

    class Adapter:
        def __init__(self) -> None:
            self.added = False
            self.removed: list[dict[str, object]] = []

        async def add_client(self, **kwargs: object) -> XrayClientApplyResult:
            self.added = True
            return XrayClientApplyResult(short_id_inserted=True)

        async def remove_client(self, **kwargs: object) -> None:
            self.removed.append(kwargs)

    repo = Repo()
    adapter = Adapter()
    service = XrayService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        settings=_settings(tmp_path, xray_manage_short_ids=True),
        clock=ClockProvider(),
        ids=_Ids(["xray_A7kQz"]),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="db mark failed"):
        asyncio.run(service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None))

    assert adapter.added is True
    assert adapter.removed == [
        {
            "uuid_value": "00000000-0000-4000-8000-000000000001",
            "email_label": "xray_A7kQz",
            "short_id": "abcd",
            "remove_short_id": True,
        }
    ]
    assert repo.statuses == [VpnKeyStatus.APPLY_FAILED]


def test_xray_create_compensation_failure_degrades_backend(tmp_path: Path) -> None:
    class Repo:
        async def find_by_uuid(self, uuid_value: str) -> None:
            return None

        async def find_by_email_label(self, email_label: str) -> None:
            return None

        async def create_pending(self, **kwargs: object) -> VpnKey:
            return _vpn_key(key_id=10, status=VpnKeyStatus.PENDING_APPLY, email_label=str(kwargs["email_label"]))

        async def mark_active(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("db mark failed")

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            return None

    class Adapter:
        def __init__(self) -> None:
            self.remove_kwargs: dict[str, object] | None = None

        async def add_client(self, **kwargs: object) -> XrayClientApplyResult:
            return XrayClientApplyResult(short_id_inserted=True)

        async def remove_client(self, **kwargs: object) -> None:
            self.remove_kwargs = kwargs
            raise RuntimeError("remove failed")

    health = BackendHealth()
    adapter = Adapter()
    service = XrayService(
        vpn_keys=Repo(),  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        settings=_settings(tmp_path, xray_manage_short_ids=True),
        clock=ClockProvider(),
        ids=_Ids(["xray_A7kQz"]),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        backend_health=health,
    )

    with pytest.raises(RuntimeError, match="db mark failed"):
        asyncio.run(service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None))

    with pytest.raises(InvalidOperation, match="Xray-операции временно заблокированы"):
        health.require_mutation_allowed(VpnKeyType.XRAY)
    assert adapter.remove_kwargs is not None
    assert adapter.remove_kwargs["remove_short_id"] is True


def test_xray_create_compensation_keeps_pre_existing_short_id(tmp_path: Path) -> None:
    async def run() -> None:
        config_path = tmp_path / "xray.json"
        _write_xray_config(config_path, short_ids=["abcd"])
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            base_repo = VpnKeyRepository(db)

            class Repo:
                def __getattr__(self, name: str) -> object:
                    return getattr(base_repo, name)

                async def mark_active(self, *args: object, **kwargs: object) -> None:
                    raise RuntimeError("db mark failed")

            adapter = XrayConfigAdapter(
                config_path=config_path,
                service_name="xray",
                apply_mode="reload",
                inbound_tag="",
                allow_restart_on_rollback=False,
                backup=BackupAdapter(ClockProvider(), keep_last=0),
                systemctl=_XraySystemctl(),  # type: ignore[arg-type]
            )
            service = XrayService(
                vpn_keys=Repo(),  # type: ignore[arg-type]
                users=_Users(),  # type: ignore[arg-type]
                adapter=adapter,
                settings=_settings(tmp_path, xray_manage_short_ids=True, xray_apply_mode="reload"),
                clock=ClockProvider(),
                ids=_Ids(["xray_A7kQz"]),  # type: ignore[arg-type]
                audit=_Audit(),  # type: ignore[arg-type]
            )

            with pytest.raises(RuntimeError, match="db mark failed"):
                await service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None)

            inbound = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"][0]
            assert inbound["settings"]["clients"] == []
            assert inbound["streamSettings"]["realitySettings"]["shortIds"] == ["abcd"]
        finally:
            await db.close()

    asyncio.run(run())


def test_xray_create_compensation_removes_newly_inserted_short_id(tmp_path: Path) -> None:
    async def run() -> None:
        config_path = tmp_path / "xray.json"
        _write_xray_config(config_path, short_ids=[])
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            base_repo = VpnKeyRepository(db)

            class Repo:
                def __getattr__(self, name: str) -> object:
                    return getattr(base_repo, name)

                async def mark_active(self, *args: object, **kwargs: object) -> None:
                    raise RuntimeError("db mark failed")

            adapter = XrayConfigAdapter(
                config_path=config_path,
                service_name="xray",
                apply_mode="reload",
                inbound_tag="",
                allow_restart_on_rollback=False,
                backup=BackupAdapter(ClockProvider(), keep_last=0),
                systemctl=_XraySystemctl(),  # type: ignore[arg-type]
            )
            service = XrayService(
                vpn_keys=Repo(),  # type: ignore[arg-type]
                users=_Users(),  # type: ignore[arg-type]
                adapter=adapter,
                settings=_settings(tmp_path, xray_manage_short_ids=True, xray_apply_mode="reload"),
                clock=ClockProvider(),
                ids=_Ids(["xray_A7kQz"]),  # type: ignore[arg-type]
                audit=_Audit(),  # type: ignore[arg-type]
            )

            with pytest.raises(RuntimeError, match="db mark failed"):
                await service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None)

            inbound = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"][0]
            assert inbound["settings"]["clients"] == []
            assert inbound["streamSettings"]["realitySettings"]["shortIds"] == []
        finally:
            await db.close()

    asyncio.run(run())


def test_xray_create_compensation_keeps_static_short_id_when_management_disabled(tmp_path: Path) -> None:
    async def run() -> None:
        config_path = tmp_path / "xray.json"
        _write_xray_config(config_path, short_ids=["abcd"])
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            base_repo = VpnKeyRepository(db)

            class Repo:
                def __getattr__(self, name: str) -> object:
                    return getattr(base_repo, name)

                async def mark_active(self, *args: object, **kwargs: object) -> None:
                    raise RuntimeError("db mark failed")

            adapter = XrayConfigAdapter(
                config_path=config_path,
                service_name="xray",
                apply_mode="reload",
                inbound_tag="",
                allow_restart_on_rollback=False,
                backup=BackupAdapter(ClockProvider(), keep_last=0),
                systemctl=_XraySystemctl(),  # type: ignore[arg-type]
            )
            service = XrayService(
                vpn_keys=Repo(),  # type: ignore[arg-type]
                users=_Users(),  # type: ignore[arg-type]
                adapter=adapter,
                settings=_settings(tmp_path, xray_manage_short_ids=False, xray_apply_mode="reload"),
                clock=ClockProvider(),
                ids=_Ids(["xray_A7kQz"]),  # type: ignore[arg-type]
                audit=_Audit(),  # type: ignore[arg-type]
            )

            with pytest.raises(RuntimeError, match="db mark failed"):
                await service.create_xray_key(100, TelegramUserProfile(100, "user", "User"), None)

            inbound = json.loads(config_path.read_text(encoding="utf-8"))["inbounds"][0]
            assert inbound["settings"]["clients"] == []
            assert inbound["streamSettings"]["realitySettings"]["shortIds"] == ["abcd"]
        finally:
            await db.close()

    asyncio.run(run())


def test_awg_create_mark_active_failure_removes_applied_peer(tmp_path: Path) -> None:
    class Repo:
        def __init__(self) -> None:
            self.statuses: list[VpnKeyStatus] = []

        async def find_by_public_key(self, public_key: str) -> None:
            return None

        async def find_by_email_label(self, email_label: str) -> None:
            return None

        async def create_pending(self, **kwargs: object) -> VpnKey:
            return _vpn_key(
                key_id=10,
                key_type=VpnKeyType.AWG,
                status=VpnKeyStatus.PENDING_APPLY,
                email_label=str(kwargs["email_label"]),
            )

        async def mark_active(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("db mark failed")

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            self.statuses.append(status)

    class Adapter:
        def __init__(self) -> None:
            self.removed: list[dict[str, object]] = []

        def read_server_config(self) -> SimpleNamespace:
            return SimpleNamespace(listen_port=443, public_key="server-public", address="10.0.0.1/24")

        async def generate_private_key(self) -> str:
            return "private"

        async def generate_public_key(self, private_key: str) -> str:
            return "public"

        async def generate_preshared_key(self) -> str:
            return "psk"

        async def add_peer(self, **kwargs: object) -> None:
            return None

        async def remove_peer(self, **kwargs: object) -> None:
            self.removed.append(kwargs)

    class Allocator:
        async def next_free_ip(self) -> str:
            return "10.0.0.2"

    repo = Repo()
    adapter = Adapter()
    service = AwgService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=_Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        ip_allocator=Allocator(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=ClockProvider(),
        ids=_Ids(["awg_A7kQz"]),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="db mark failed"):
        asyncio.run(service.create_awg_key(100, TelegramUserProfile(100, "user", "User"), None))

    assert adapter.removed == [{"key_id": 10, "public_key": "public"}]
    assert repo.statuses == [VpnKeyStatus.APPLY_FAILED]


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
            # Yield once so the second concurrent send interleaves here and hits the
            # already-sent guard — a deterministic hand-off, not a wall-clock delay.
            await asyncio.sleep(0)
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


def test_block_user_revokes_apply_failed_keys(tmp_path: Path) -> None:
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
            xray_key = await keys_repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={"short_id_managed": False},
                public_payload={},
                created_by=100,
                now="now-1",
                uuid="00000000-0000-4000-8000-000000000101",
                email_label="xray_apply_failed",
            )
            await keys_repo.set_status(xray_key.id, VpnKeyStatus.APPLY_FAILED, "status-1")
            awg_key = await keys_repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                note=None,
                payload={},
                public_payload={},
                created_by=100,
                now="now-2",
                public_key="public-apply-failed",
                client_ip="10.0.0.2",
            )
            await keys_repo.set_status(awg_key.id, VpnKeyStatus.APPLY_FAILED, "status-2")
            service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=_Audit())  # type: ignore[arg-type]
            revoked: list[tuple[VpnKeyType, int]] = []

            async def revoke_xray(actor_user_id: int, key_id: int) -> VpnKey:
                revoked.append((VpnKeyType.XRAY, key_id))
                await keys_repo.mark_revoked(key_id, actor_user_id, "now")
                key = await keys_repo.get_by_id(key_id)
                assert key is not None
                return key

            async def revoke_awg(actor_user_id: int, key_id: int) -> VpnKey:
                revoked.append((VpnKeyType.AWG, key_id))
                await keys_repo.mark_revoked(key_id, actor_user_id, "now")
                key = await keys_repo.get_by_id(key_id)
                assert key is not None
                return key

            service.attach_key_management(keys_repo, {VpnKeyType.XRAY: revoke_xray, VpnKeyType.AWG: revoke_awg})

            result = await service.block_user(1, 100)

            assert result.errors == ()
            assert set(result.revoked_key_ids) == {xray_key.id, awg_key.id}
            assert set(revoked) == {(VpnKeyType.XRAY, xray_key.id), (VpnKeyType.AWG, awg_key.id)}
            stored_xray = await keys_repo.get_by_id(xray_key.id)
            stored_awg = await keys_repo.get_by_id(awg_key.id)
            user = await users_repo.get_by_id(100)
            assert stored_xray is not None and stored_xray.status == VpnKeyStatus.REVOKED
            assert stored_awg is not None and stored_awg.status == VpnKeyStatus.REVOKED
            assert user is not None and user.role == UserRole.BLOCKED_USER
        finally:
            await db.close()

    asyncio.run(run())


def test_block_user_with_revoke_error_still_blocks_bot_access(tmp_path: Path) -> None:
    class Audit:
        def __init__(self) -> None:
            self.actions: list[tuple[str, dict[str, object] | None]] = []

        async def write(self, *, action: str, details: dict[str, object] | None = None, **kwargs: object) -> None:
            self.actions.append((action, details))

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
            key = await keys_repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={"short_id_managed": False},
                public_payload={},
                created_by=100,
                now="now",
                uuid="00000000-0000-4000-8000-000000000777",
                email_label="xray_fail",
            )
            await keys_repo.mark_active(key.id, "now")
            audit = Audit()
            service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)  # type: ignore[arg-type]
            cleared: list[int] = []

            async def revoke(actor_user_id: int, key_id: int) -> VpnKey:
                raise RuntimeError("backend unreachable")

            async def clear_state(user_id: int) -> None:
                cleared.append(user_id)

            service.attach_key_management(keys_repo, {VpnKeyType.XRAY: revoke})
            service.attach_state_clearer(clear_state)

            result = await service.block_user(1, 100)

            assert len(result.errors) == 1
            assert result.revoked_key_ids == ()
            assert result.user.role == UserRole.BLOCKED_USER
            assert result.user.blocked_at is not None
            assert cleared == [100]
            with pytest.raises(AccessDenied, match="Доступ заблокирован"):
                await service.require_approved_or_admin(100)
            action, details = audit.actions[-1]
            assert action == "user_blocked_with_revoke_errors"
            assert details is not None
            assert details["error_count"] == 1
            assert details["bot_access_blocked"] is True
            assert details["vpn_revoke_complete"] is False
        finally:
            await db.close()

    asyncio.run(run())


def test_inspect_unblock_risk_reports_previous_revoke_errors(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.BLOCKED_USER, "now")
            await users_repo.set_role(100, UserRole.BLOCKED_USER, "blocked", blocked_at="blocked")
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            await audit.write(
                actor_user_id=1,
                action="user_blocked_with_revoke_errors",
                entity_type=AuditEntityType.USER,
                entity_id=100,
                details={"error_count": 2, "errors": [{"key_id": 10, "error": "backend unreachable"}]},
            )
            service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)

            warning = await service.inspect_unblock_risk(1, 100)

            assert warning.has_warning is True
            assert warning.previous_revoke_error_count == 2
            assert warning.last_block_error_at is not None
            assert warning.active_or_problem_key_count == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_inspect_unblock_risk_reports_active_or_problem_keys(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            settings = _settings(tmp_path)
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.BLOCKED_USER, "now")
            await users_repo.set_role(100, UserRole.BLOCKED_USER, "blocked", blocked_at="blocked")
            keys_repo = VpnKeyRepository(db)
            key = await keys_repo.create_pending(
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.XRAY,
                note=None,
                payload={"short_id_managed": False},
                public_payload={},
                created_by=100,
                now="now",
                uuid="00000000-0000-4000-8000-000000000888",
                email_label="xray_active",
            )
            await keys_repo.mark_active(key.id, "active")
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
            service.attach_key_management(keys_repo, {})

            warning = await service.inspect_unblock_risk(1, 100)

            assert warning.has_warning is True
            assert warning.active_or_problem_key_count == 1
            assert warning.previous_revoke_error_count == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_concurrent_xray_create_vs_block_finishes_without_active_key(tmp_path: Path) -> None:
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    class TrackingLockMgr(UserLockManager):
        def __init__(self) -> None:
            super().__init__()
            self.contended = asyncio.Event()

        @asynccontextmanager
        async def lock(self, user_id: int) -> AsyncIterator[None]:
            async with self._guard:
                existing = self._locks.get(user_id)
                if existing is not None and existing.locked():
                    self.contended.set()
            async with super().lock(user_id):
                yield

    class Adapter:
        def __init__(self, contended: asyncio.Event) -> None:
            self.started = asyncio.Event()
            self.removed = False
            self._contended = contended

        async def add_client(self, **kwargs: object) -> None:
            self.started.set()
            await self._contended.wait()

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
            lock_mgr = TrackingLockMgr()
            user_service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=_Audit(), user_locks=lock_mgr)  # type: ignore[arg-type]
            adapter = Adapter(lock_mgr.contended)
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
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    class TrackingLockMgr(UserLockManager):
        def __init__(self) -> None:
            super().__init__()
            self.contended = asyncio.Event()

        @asynccontextmanager
        async def lock(self, user_id: int) -> AsyncIterator[None]:
            async with self._guard:
                existing = self._locks.get(user_id)
                if existing is not None and existing.locked():
                    self.contended.set()
            async with super().lock(user_id):
                yield

    class Adapter:
        def __init__(self, contended: asyncio.Event) -> None:
            self.started = asyncio.Event()
            self.removed = False
            self._contended = contended

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
            await self._contended.wait()

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
            lock_mgr = TrackingLockMgr()
            user_service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=_Audit(), user_locks=lock_mgr)  # type: ignore[arg-type]
            adapter = Adapter(lock_mgr.contended)
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
