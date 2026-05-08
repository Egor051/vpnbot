from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.errors import AwgApplyError, AwgConfigError, AwgIpAllocationError
from adapters.ip_allocator import IpAllocator
from adapters.shell_runner import ShellRunner
from config.settings import Settings
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from services.awg import AwgService
from services.errors import InvalidOperation


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


def _adapter(config_path: Path) -> AwgConfigAdapter:
    return AwgConfigAdapter(
        config_path=config_path,
        interface="awg0",
        backup=BackupAdapter.__new__(BackupAdapter),
        shell=ShellRunner(),
        persistent_keepalive=25,
    )


class _Repo:
    def __init__(self, occupied: set[str] | None = None) -> None:
        self.occupied = occupied or set()

    async def get_occupied_awg_ips(self) -> set[str]:
        return set(self.occupied)


class _Source:
    def __init__(self, allowed: set[str]) -> None:
        self.allowed = allowed

    def list_peer_allowed_ips(self) -> set[str]:
        return set(self.allowed)


def test_unmanaged_subnet_reserves_entire_range_inside_awg_network() -> None:
    repo = _Repo({f"10.0.0.{value}" for value in range(2, 8)})
    allocator = IpAllocator(repo, "10.0.0.0/28", "10.0.0.1", awg_config=_Source({"10.0.0.8/29"}))

    with pytest.raises(AwgIpAllocationError, match="не осталось"):
        asyncio.run(allocator.next_free_ip())


def test_unmanaged_32_reserves_single_ip() -> None:
    allocator = IpAllocator(_Repo(), "10.0.0.0/29", "10.0.0.1", awg_config=_Source({"10.0.0.2/32"}))

    assert asyncio.run(allocator.next_free_ip()) == "10.0.0.3"


def test_unmanaged_subnet_outside_awg_network_does_not_break_allocation() -> None:
    allocator = IpAllocator(_Repo(), "10.0.0.0/30", "10.0.0.1", awg_config=_Source({"10.0.1.8/29"}))

    assert asyncio.run(allocator.next_free_ip()) == "10.0.0.2"


def test_awg_parser_rejects_duplicate_peer_public_key(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path / "awg.conf")

    with pytest.raises(AwgConfigError, match="Дублирующий критичный параметр.*PublicKey"):
        adapter._parse_sections(
            """
[Interface]
PrivateKey = server

[Peer]
PublicKey = one
PublicKey = two
AllowedIPs = 10.0.0.2/32
"""
        )


def test_awg_parser_rejects_duplicate_peer_allowed_ips(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path / "awg.conf")

    with pytest.raises(AwgConfigError, match="Дублирующий критичный параметр.*AllowedIPs"):
        adapter._parse_sections(
            """
[Interface]
PrivateKey = server

[Peer]
PublicKey = one
AllowedIPs = 10.0.0.2/32
AllowedIPs = 10.0.0.3/32
"""
        )


def test_awg_parser_rejects_duplicate_interface_address(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path / "awg.conf")

    with pytest.raises(AwgConfigError, match="Дублирующий критичный параметр.*Address"):
        adapter._parse_sections(
            """
[Interface]
PrivateKey = server
Address = 10.0.0.1/24
Address = 10.0.1.1/24
"""
        )


def test_awg_parser_accepts_normal_config(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path / "awg.conf")
    sections = adapter._parse_sections(
        """
[Interface]
PrivateKey = server
Address = 10.0.0.1/24
ListenPort = 443

[Peer]
PublicKey = one
AllowedIPs = 10.0.0.2/32
"""
    )

    assert [section.name for section in sections] == ["Interface", "Peer"]


def test_missing_public_key_is_recovered_from_managed_block_and_removed(tmp_path: Path) -> None:
    key = _key(public_key=None)

    class Repo:
        def __init__(self) -> None:
            self.key: VpnKey | None = key
            self.hard_deleted = False

        async def get_by_id(self, key_id: int) -> VpnKey | None:
            return self.key

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            assert self.key is not None
            self.key = replace(self.key, status=status)

        async def hard_delete_with_stats(self, key_id: int) -> None:
            self.hard_deleted = True
            self.key = None

    class Adapter:
        def __init__(self) -> None:
            self.removed_public_key: str | None = None

        def find_managed_peer_public_key(self, key_id: int) -> str:
            return "recovered-public"

        async def remove_peer(self, *, key_id: int, public_key: str | None) -> None:
            self.removed_public_key = public_key

    async def run() -> None:
        repo = Repo()
        adapter = Adapter()
        service = _service(tmp_path, repo, adapter)

        await service.delete_awg_key(100, key.id)

        assert adapter.removed_public_key == "recovered-public"
        assert repo.hard_deleted is True

    asyncio.run(run())


def test_missing_public_key_without_managed_block_fails_safe(tmp_path: Path) -> None:
    key = _key(public_key=None)

    class Repo:
        def __init__(self) -> None:
            self.key: VpnKey | None = key
            self.hard_deleted = False

        async def get_by_id(self, key_id: int) -> VpnKey | None:
            return self.key

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            assert self.key is not None
            self.key = replace(self.key, status=status)

        async def hard_delete_with_stats(self, key_id: int) -> None:
            self.hard_deleted = True

    class Adapter:
        def find_managed_peer_public_key(self, key_id: int) -> None:
            return None

        async def remove_peer(self, *, key_id: int, public_key: str | None) -> None:
            raise AssertionError("runtime remove must not run without public_key")

    async def run() -> None:
        repo = Repo()
        service = _service(tmp_path, repo, Adapter())

        with pytest.raises(InvalidOperation, match="Нельзя безопасно удалить AWG peer"):
            await service.delete_awg_key(100, key.id)

        assert repo.key is not None and repo.key.status == VpnKeyStatus.DELETE_FAILED
        assert repo.hard_deleted is False

    asyncio.run(run())


def test_apply_failed_runtime_only_peer_is_removed_on_startup(tmp_path: Path) -> None:
    key = replace(_key(), status=VpnKeyStatus.APPLY_FAILED)

    class Repo:
        def __init__(self) -> None:
            self.sent = False
            self.statuses: list[VpnKeyStatus] = []

        async def list_by_type_statuses(
            self,
            key_type: VpnKeyType,
            statuses: set[VpnKeyStatus],
            limit: int = 500,
            offset: int = 0,
            after_id: int | None = None,
        ) -> list[VpnKey]:
            assert VpnKeyStatus.APPLY_FAILED in statuses
            if self.sent:
                return []
            self.sent = True
            return [key]

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            self.statuses.append(status)

        async def mark_active(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("runtime-only peer must not be marked active without config peer")

    class Adapter:
        def __init__(self) -> None:
            self.removed_public_key: str | None = None

        def find_peer(self, **kwargs: object) -> None:
            return None

        async def verify_runtime_peer(self, public_key: str) -> bool:
            return public_key == key.public_key

        async def remove_peer(self, *, key_id: int, public_key: str | None) -> None:
            self.removed_public_key = public_key

    async def run() -> None:
        repo = Repo()
        adapter = Adapter()
        service = _service(tmp_path, repo, adapter)

        summary = await service.startup_reconcile()

        assert summary == {"checked": 1, "recovered": 1, "failed": 0}
        assert adapter.removed_public_key == key.public_key
        assert repo.statuses == []

    asyncio.run(run())


def test_add_peer_restore_failure_still_attempts_runtime_cleanup(tmp_path: Path) -> None:
    config_path = _write_awg_config(tmp_path)

    class Backup:
        def __init__(self) -> None:
            self.restored = False

        def create_backup(self, target: Path) -> Path:
            return target.with_suffix(".bak")

        def atomic_write_text(self, target: Path, content: str, mode_from: Path | None = None) -> None:
            target.write_text(content, encoding="utf-8")

        def restore(self, backup_path: Path, target: Path, mode_from: Path | None = None) -> None:
            self.restored = True
            raise RuntimeError("restore failed")

    class Adapter(AwgConfigAdapter):
        def __init__(self) -> None:
            self.backup_obj = Backup()
            self.cleanup_called = False
            super().__init__(config_path=config_path, interface="awg0", backup=self.backup_obj, shell=ShellRunner(), persistent_keepalive=25)

        async def ensure_interface_active(self) -> None:
            return None

        async def _validate_candidate_config(self, text: str) -> None:
            return None

        async def _add_peer_runtime(self, public_key: str, preshared_key: str | None, client_ip: str) -> bool:
            return False

        async def _remove_peer_runtime(self, public_key: str) -> bool:
            self.cleanup_called = True
            return True

    async def run() -> None:
        adapter = Adapter()

        with pytest.raises(AwgApplyError, match="rollback failed steps: restore config"):
            await adapter.add_peer(key_id=1, owner_user_id=100, public_key="public", preshared_key=None, client_ip="10.0.0.2")

        assert adapter.backup_obj.restored is True
        assert adapter.cleanup_called is True

    asyncio.run(run())


def test_add_peer_runtime_cleanup_failure_still_restores_config(tmp_path: Path) -> None:
    config_path = _write_awg_config(tmp_path)

    class Backup:
        def __init__(self) -> None:
            self.restored = False

        def create_backup(self, target: Path) -> Path:
            return target.with_suffix(".bak")

        def atomic_write_text(self, target: Path, content: str, mode_from: Path | None = None) -> None:
            target.write_text(content, encoding="utf-8")

        def restore(self, backup_path: Path, target: Path, mode_from: Path | None = None) -> None:
            self.restored = True

    class Adapter(AwgConfigAdapter):
        def __init__(self) -> None:
            self.backup_obj = Backup()
            super().__init__(config_path=config_path, interface="awg0", backup=self.backup_obj, shell=ShellRunner(), persistent_keepalive=25)

        async def ensure_interface_active(self) -> None:
            return None

        async def _validate_candidate_config(self, text: str) -> None:
            return None

        async def _add_peer_runtime(self, public_key: str, preshared_key: str | None, client_ip: str) -> bool:
            return False

        async def _remove_peer_runtime(self, public_key: str) -> bool:
            raise RuntimeError("cleanup failed")

    async def run() -> None:
        adapter = Adapter()

        with pytest.raises(AwgApplyError, match="rollback failed steps: runtime cleanup"):
            await adapter.add_peer(key_id=1, owner_user_id=100, public_key="public", preshared_key=None, client_ip="10.0.0.2")

        assert adapter.backup_obj.restored is True

    asyncio.run(run())


def _key(public_key: str | None = "public") -> VpnKey:
    return VpnKey(
        id=10,
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.AWG,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=None,
        email_label="awg_A7kQz",
        public_key=public_key,
        client_ip="10.0.0.2",
        payload={"public_key": public_key, "client_ip": "10.0.0.2"},
        public_payload={"public_key": public_key, "client_ip": "10.0.0.2"},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


def _service(tmp_path: Path, repo: object, adapter: object) -> AwgService:
    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

        async def require_superadmin(self, actor_user_id: int) -> User:
            return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

    class Audit:
        async def write(self, **kwargs: object) -> None:
            return None

        async def write_best_effort(self, **kwargs: object) -> None:
            return None

    return AwgService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        ip_allocator=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path),
        clock=SimpleNamespace(now=lambda: "now"),  # type: ignore[arg-type]
        ids=object(),  # type: ignore[arg-type]
        audit=Audit(),  # type: ignore[arg-type]
    )


def _write_awg_config(tmp_path: Path) -> Path:
    path = tmp_path / "awg.conf"
    path.write_text(
        """
[Interface]
PrivateKey = server
Address = 10.0.0.1/24

""",
        encoding="utf-8",
    )
    return path
