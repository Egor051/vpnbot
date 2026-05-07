from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from adapters.clock import ClockProvider
from adapters.dante_users import DanteUserAdapter
from adapters.errors import DanteUserError
from adapters.mtproxy import MtProxyApplyResult, MtProxyManagedSecret
from config.settings import Settings
from db.database import Database
from models.dto import ShellResult, TelegramUserProfile, User
from models.enums import ProxyAccessStatus, ProxyAccessType, UserRole, VpnKeyType
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.audit_log import AuditLogRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.mtproto import MtProtoService
from services.proxy import ProxyService
from services.socks5 import Socks5Service
from services.user_locks import UserLockManager
from services.users import UserService


def _settings(**overrides: object) -> Settings:
    values = dict(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=Path("/tmp/vpn.db"),
        log_dir=Path("/tmp/logs"),
        bot_lock_path=Path("/tmp/vpn.lock"),
        bot_drop_pending_updates=False,
        xray_config_path=Path("/tmp/xray.json"),
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
        socks5_enabled=True,
        socks5_host="150.251.152.243",
        socks5_port=31337,
        socks5_login_prefix="vpn_socks_",
        mtproto_enabled=True,
        mtproto_host="150.251.152.243",
        mtproto_port=8443,
        mtproto_secret="0123456789abcdef0123456789abcdef",
    )
    values.update(overrides)
    return Settings(**values)


class _Shell:
    def __init__(self, existing: set[str] | None = None) -> None:
        self.existing = existing or set()
        self.calls: list[tuple[tuple[str, ...], str | None, tuple[str, ...]]] = []

    async def run(self, args: list[str], **kwargs: object) -> ShellResult:
        input_text = kwargs.get("input_text")
        sensitive_values = tuple(str(item) for item in kwargs.get("sensitive_values", ()))
        self.calls.append((tuple(args), str(input_text) if input_text is not None else None, sensitive_values))
        if args[:2] == ["getent", "passwd"]:
            return ShellResult(tuple(args), 0 if args[2] in self.existing else 2, "", "")
        if args[0] == "useradd":
            self.existing.add(args[-1])
            return ShellResult(tuple(args), 0, "", "")
        if args[0] == "chpasswd":
            return ShellResult(tuple(args), 0, "", "")
        if args[:2] == ["passwd", "-l"]:
            return ShellResult(tuple(args), 0, "", "")
        if args[0] == "userdel":
            self.existing.discard(args[-1])
            return ShellResult(tuple(args), 0, "", "")
        raise AssertionError(f"unexpected command {args}")


class _Users:
    clock = ClockProvider()

    async def require_approved_or_admin(self, user_id: int) -> User:
        role = UserRole.SUPERADMIN if user_id == 1 else UserRole.APPROVED_USER
        return User(user_id, "user", "User", role, "now", "now", None)

    async def require_superadmin(self, user_id: int) -> User:
        return User(user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)


class _Audit:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    async def write_best_effort(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    async def write(self, **kwargs: object) -> None:
        self.items.append(kwargs)


class _FailingAdapter:
    async def exists(self, login: str) -> bool:
        return False

    async def create_user(self, login: str, password: str) -> None:
        raise RuntimeError("create failed")


class _LockOnlyAdapter:
    def __init__(self) -> None:
        self.locked: list[str] = []

    async def lock_user(self, login: str) -> None:
        self.locked.append(login)

    async def exists(self, login: str) -> bool:
        return False

    async def create_user(self, login: str, password: str) -> None:
        return None

    async def delete_user(self, login: str) -> None:
        return None


class _MtProxyAdapter:
    def __init__(self, *, fail_apply: bool = False, ready: bool = True) -> None:
        self.current: list[MtProxyManagedSecret] = []
        self.applied: list[list[MtProxyManagedSecret]] = []
        self.fail_apply = fail_apply
        self.ready = ready

    def read_current_managed_secrets(self) -> list[MtProxyManagedSecret]:
        return list(self.current)

    def ensure_managed_runtime_ready(self) -> bool:
        if not self.ready:
            raise RuntimeError("MTProto managed runtime is not initialized; run manual setup/preflight first")
        return False

    async def apply_managed_secrets(self, secrets: list[MtProxyManagedSecret]) -> MtProxyApplyResult:
        self.applied.append(list(secrets))
        if self.fail_apply:
            raise RuntimeError("mtproxy apply failed")
        self.current = list(secrets)
        return MtProxyApplyResult(changed=True, generation=len(self.applied))


async def _repo(tmp_path: Path) -> tuple[Database, ProxyAccessRepository]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users = UserRepository(db)
    await users.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
    await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
    return db, ProxyAccessRepository(db)


def test_dante_adapter_uses_argv_and_hides_password() -> None:
    async def run() -> None:
        shell = _Shell()
        adapter = DanteUserAdapter(shell=shell, login_prefix="vpn_socks_", system_user_shell="/usr/sbin/nologin")  # type: ignore[arg-type]
        await adapter.create_user("vpn_socks_100_abcd", "secret-password")

        args = [call[0] for call in shell.calls]
        assert ("useradd", "-r", "-s", "/usr/sbin/nologin", "vpn_socks_100_abcd") in args
        assert ("chpasswd",) in args
        assert all("secret-password" not in part for argv in args for part in argv)
        chpasswd = [call for call in shell.calls if call[0] == ("chpasswd",)][0]
        assert chpasswd[2] == ("secret-password",)

    asyncio.run(run())


@pytest.mark.parametrize("method", ["exists", "create_user", "lock_user", "delete_user"])
def test_dante_adapter_rejects_unmanaged_login(method: str) -> None:
    async def run() -> None:
        adapter = DanteUserAdapter(shell=_Shell(), login_prefix="vpn_socks_", system_user_shell="/usr/sbin/nologin")  # type: ignore[arg-type]
        with pytest.raises(DanteUserError):
            if method == "exists":
                await adapter.exists("admin")
            elif method == "create_user":
                await adapter.create_user("admin", "secret")
            elif method == "lock_user":
                await adapter.lock_user("admin")
            else:
                await adapter.delete_user("admin")

    asyncio.run(run())


def test_socks5_issue_happy_path_is_idempotent_and_keeps_password_private(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            shell = _Shell()
            audit = _Audit()
            service = Socks5Service(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                adapter=DanteUserAdapter(shell=shell, login_prefix="vpn_socks_", system_user_shell="/usr/sbin/nologin"),  # type: ignore[arg-type]
                settings=_settings(),
                clock=ClockProvider(),
                audit=audit,  # type: ignore[arg-type]
            )
            profile = TelegramUserProfile(100, "user", "User")
            first = await service.issue_socks5_proxy(100, profile)
            second = await service.issue_socks5_proxy(100, profile)

            assert first.id == second.id
            assert first.status == ProxyAccessStatus.ACTIVE
            assert first.payload["password"]
            assert "password" not in first.public_payload
            assert str(first.payload["password"]) not in str(first.public_payload)
            assert len([call for call in shell.calls if call[0][0] == "useradd"]) == 1
            assert str(first.payload["password"]) not in str(audit.items)
        finally:
            await db.close()

    asyncio.run(run())


def test_socks5_create_failure_marks_apply_failed(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            service = Socks5Service(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                adapter=_FailingAdapter(),  # type: ignore[arg-type]
                settings=_settings(),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
            )
            with pytest.raises(RuntimeError, match="create failed"):
                await service.issue_socks5_proxy(100, TelegramUserProfile(100, "user", "User"))
            accesses = await repo.list_by_owner(100)
            assert accesses[0].status == ProxyAccessStatus.APPLY_FAILED
        finally:
            await db.close()

    asyncio.run(run())


def test_socks5_revoke_and_delete_are_idempotent(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            shell = _Shell()
            service = Socks5Service(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                adapter=DanteUserAdapter(shell=shell, login_prefix="vpn_socks_", system_user_shell="/usr/sbin/nologin"),  # type: ignore[arg-type]
                settings=_settings(),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
            )
            access = await service.issue_socks5_proxy(100, TelegramUserProfile(100, "user", "User"))
            await service.revoke_socks5_proxy(1, access.id, "hard_block")
            await service.revoke_socks5_proxy(1, access.id, "hard_block")
            await service.delete_socks5_proxy(1, access.id, "cleanup")
            await service.delete_socks5_proxy(1, access.id, "cleanup")

            assert len([call for call in shell.calls if call[0][:2] == ("passwd", "-l")]) == 1
            assert len([call for call in shell.calls if call[0][0] == "userdel"]) == 1
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_issue_outputs_both_links_and_audit_has_no_secret(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            audit = _Audit()
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(),
                clock=ClockProvider(),
                audit=audit,  # type: ignore[arg-type]
            )
            access = await service.issue_mtproto_proxy(100, TelegramUserProfile(100, "user", "User"))

            assert access.payload["link"] == (
                "https://t.me/proxy?server=150.251.152.243&port=8443&secret=0123456789abcdef0123456789abcdef"
            )
            assert access.payload["link_dd"] == (
                "https://t.me/proxy?server=150.251.152.243&port=8443&secret=dd0123456789abcdef0123456789abcdef"
            )
            assert str(access.payload["secret"]) not in str(audit.items)
            assert "secret" not in access.public_payload
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_revoke_is_db_only(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
            )
            access = await service.issue_mtproto_proxy(100, TelegramUserProfile(100, "user", "User"))
            revoked = await service.revoke_mtproto_proxy(1, access.id, "hard_block")

            assert revoked.access_type == ProxyAccessType.MTPROTO
            assert revoked.status == ProxyAccessStatus.INACTIVE
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_managed_issue_is_idempotent_and_secret_is_private(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            audit = _Audit()
            adapter = _MtProxyAdapter()
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(mtproto_mode="managed", mtproto_secret=""),
                clock=ClockProvider(),
                audit=audit,  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
            )
            profile = TelegramUserProfile(100, "user", "User")
            first = await service.issue_mtproto_proxy(100, profile)
            second = await service.issue_mtproto_proxy(100, profile)

            secret = str(first.payload["secret"])
            assert first.id == second.id
            assert first.status == ProxyAccessStatus.ACTIVE
            assert first.payload["mode"] == "managed"
            assert len(secret) == 32
            int(secret, 16)
            assert first.payload["link"] == f"https://t.me/proxy?server=150.251.152.243&port=8443&secret={secret}"
            assert first.payload["link_dd"] == f"https://t.me/proxy?server=150.251.152.243&port=8443&secret=dd{secret}"
            assert "secret" not in first.public_payload
            assert secret not in str(first.public_payload)
            assert len(adapter.applied) == 1
            assert len(adapter.current) == 1
            assert secret not in str(audit.items)
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_managed_apply_failure_marks_apply_failed(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(mtproto_mode="managed", mtproto_secret=""),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
                adapter=_MtProxyAdapter(fail_apply=True),  # type: ignore[arg-type]
            )
            with pytest.raises(RuntimeError, match="mtproxy apply failed"):
                await service.issue_mtproto_proxy(100, TelegramUserProfile(100, "user", "User"))
            accesses = await repo.list_by_owner(100)
            assert accesses[0].status == ProxyAccessStatus.APPLY_FAILED
        finally:
            await db.close()

    asyncio.run(run())


def test_managed_preflight_missing_baseline_blocks_issue(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            adapter = _MtProxyAdapter(ready=False)
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(mtproto_mode="managed", mtproto_secret=""),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
            )

            with pytest.raises(RuntimeError, match="managed runtime is not initialized"):
                await service.issue_mtproto_proxy(100, TelegramUserProfile(100, "user", "User"))

            assert await repo.list_by_owner(100) == []
            assert adapter.applied == []
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_managed_revoke_removes_only_target_secret(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(101, "other", "Other"), UserRole.APPROVED_USER, "now")
            adapter = _MtProxyAdapter()
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(mtproto_mode="managed", mtproto_secret=""),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
            )
            first = await service.issue_mtproto_proxy(100, TelegramUserProfile(100, "user", "User"))
            second = await service.issue_mtproto_proxy(101, TelegramUserProfile(101, "other", "Other"))
            await service.revoke_mtproto_proxy(1, first.id, "hard_block")
            await service.revoke_mtproto_proxy(1, first.id, "hard_block")

            first_after = await repo.get_by_id(first.id)
            second_after = await repo.get_by_id(second.id)
            assert first_after is not None and first_after.status == ProxyAccessStatus.REVOKED
            assert second_after is not None and second_after.status == ProxyAccessStatus.ACTIVE
            assert [item.access_id for item in adapter.current] == [second.id]
            assert len([items for items in adapter.applied if len(items) == 1]) >= 1
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_managed_missing_secret_does_not_fallback_to_static(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(mtproto_mode="managed", mtproto_secret="f" * 32),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
                adapter=_MtProxyAdapter(),  # type: ignore[arg-type]
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload={"type": "mtproto", "mode": "managed"},
                public_payload={"type": "mtproto", "mode": "managed"},
                created_by=100,
                now="now",
            )

            with pytest.raises(Exception) as exc_info:
                await service.get_mtproto_proxy_config(100)

            assert "incomplete" in str(exc_info.value)
            assert "f" * 32 not in str(exc_info.value)
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_static_missing_payload_secret_uses_static_secret(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(mtproto_mode="static", mtproto_secret="e" * 32),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload={"type": "mtproto", "mode": "static"},
                public_payload={"type": "mtproto", "mode": "static"},
                created_by=100,
                now="now",
            )

            access = await service.get_mtproto_proxy_config(100)

            assert access.payload["secret"] == "e" * 32
        finally:
            await db.close()

    asyncio.run(run())


def test_mtproto_managed_revoke_failure_marks_revoke_failed(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            adapter = _MtProxyAdapter()
            service = MtProtoService(
                accesses=repo,
                users=_Users(),  # type: ignore[arg-type]
                settings=_settings(mtproto_mode="managed", mtproto_secret=""),
                clock=ClockProvider(),
                audit=_Audit(),  # type: ignore[arg-type]
                adapter=adapter,  # type: ignore[arg-type]
            )
            access = await service.issue_mtproto_proxy(100, TelegramUserProfile(100, "user", "User"))
            adapter.fail_apply = True
            with pytest.raises(RuntimeError, match="mtproxy apply failed"):
                await service.revoke_mtproto_proxy(1, access.id, "hard_block")
            after = await repo.get_by_id(access.id)
            assert after is not None and after.status == ProxyAccessStatus.REVOKE_FAILED
            assert [item.access_id for item in adapter.current] == [access.id]
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_lifecycle_stats_separate_managed_static_and_failures(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(101, "other", "Other"), UserRole.APPROVED_USER, "now")
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload={"type": "mtproto", "mode": "static"},
                public_payload={"type": "mtproto", "mode": "static"},
                created_by=100,
                now="now",
            )
            await repo.create(
                owner_user_id=101,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload={"type": "mtproto", "mode": "managed"},
                public_payload={"type": "mtproto", "mode": "managed"},
                created_by=100,
                now="now",
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.APPLY_FAILED,
                payload={"type": "mtproto", "mode": "managed"},
                public_payload={"type": "mtproto", "mode": "managed"},
                created_by=100,
                now="now",
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.REVOKE_FAILED,
                payload={"type": "mtproto", "mode": "managed"},
                public_payload={"type": "mtproto", "mode": "managed"},
                created_by=100,
                now="now",
            )

            stats = await repo.lifecycle_stats()

            assert stats.mtproto_issued == 4
            assert stats.mtproto_active == 2
            assert stats.mtproto_legacy_static == 1
            assert stats.mtproto_managed_issued == 3
            assert stats.mtproto_managed_active == 1
            assert stats.mtproto_apply_failed == 1
            assert stats.mtproto_revoke_failed == 1
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_admin_stats_counts_statuses_users_and_timestamps(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.SOCKS5,
                status=ProxyAccessStatus.ACTIVE,
                payload={
                    "type": "socks5",
                    "host": "150.251.152.243",
                    "port": 31337,
                    "login": "vpn_socks_100_abcd",
                    "password": "secret-password",
                },
                public_payload={
                    "type": "socks5",
                    "host": "150.251.152.243",
                    "port": 31337,
                    "login": "vpn_socks_100_abcd",
                },
                created_by=100,
                now="2026-05-06T20:19:00+00:00",
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload={
                    "type": "mtproto",
                    "mode": "managed",
                    "host": "150.251.152.243",
                    "port": 8443,
                    "secret": "0123456789abcdef0123456789abcdef",
                    "link": "https://t.me/proxy?secret=0123456789abcdef0123456789abcdef",
                    "fingerprint": "f3bff43850e88441",
                },
                public_payload={
                    "type": "mtproto",
                    "mode": "managed",
                    "host": "150.251.152.243",
                    "port": 8443,
                },
                created_by=100,
                now="2026-05-06T20:20:00+00:00",
                secret_fingerprint="f3bff43850e88441",
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.SOCKS5,
                status=ProxyAccessStatus.APPLY_FAILED,
                payload={"type": "socks5", "login": "vpn_socks_failed", "password": "failed-password"},
                public_payload={"type": "socks5", "login": "vpn_socks_failed"},
                created_by=100,
                now="2026-05-06T20:21:00+00:00",
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.REVOKED,
                payload={"type": "mtproto", "mode": "static", "secret": "ffffffffffffffffffffffffffffffff"},
                public_payload={"type": "mtproto", "mode": "static"},
                created_by=100,
                now="2026-05-06T20:18:00+00:00",
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.SOCKS5,
                status=ProxyAccessStatus.DELETED,
                payload={"type": "socks5", "login": "vpn_socks_deleted", "password": "deleted-password"},
                public_payload={"type": "socks5", "login": "vpn_socks_deleted"},
                created_by=100,
                now="2026-05-06T20:17:00+00:00",
            )

            stats = await repo.get_admin_proxy_stats(user_limit=10)
            type_status = await repo.count_by_type_status()

            assert stats.total_accesses == 5
            assert stats.active_total == 2
            assert stats.active_socks5 == 1
            assert stats.active_mtproto == 1
            assert stats.apply_failed == 1
            assert stats.revoked == 1
            assert stats.deleted == 1
            assert stats.users_with_active_proxies == 1
            assert stats.last_issued_at == "2026-05-06T20:21:00+00:00"
            assert stats.last_failed_at == "2026-05-06T20:21:00+00:00"
            assert type_status[ProxyAccessType.SOCKS5][ProxyAccessStatus.ACTIVE] == 1
            assert type_status[ProxyAccessType.MTPROTO][ProxyAccessStatus.ACTIVE] == 1
            assert stats.mtproto_mode_counts["managed"] == 1
            assert stats.mtproto_mode_counts["static"] == 1
            assert len(stats.users) == 1
            user = stats.users[0]
            assert user.telegram_user_id == 100
            assert user.active_socks5_count == 1
            assert user.active_mtproto_count == 1
            assert user.failed_count == 1
            assert {ref.access_type for ref in user.active_accesses} == {
                ProxyAccessType.SOCKS5,
                ProxyAccessType.MTPROTO,
            }
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_user_stats_are_sanitized_and_do_not_include_password_or_secret(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.SOCKS5,
                status=ProxyAccessStatus.ACTIVE,
                payload={
                    "type": "socks5",
                    "host": "150.251.152.243",
                    "port": 31337,
                    "login": "vpn_socks_100_abcd",
                    "password": "secret-password",
                    "url": "socks5://vpn_socks_100_abcd:secret-password@150.251.152.243:31337",
                },
                public_payload={
                    "type": "socks5",
                    "host": "150.251.152.243",
                    "port": 31337,
                    "login": "vpn_socks_100_abcd",
                },
                created_by=100,
                now="2026-05-06T20:19:00+00:00",
            )
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload={
                    "type": "mtproto",
                    "mode": "managed",
                    "host": "150.251.152.243",
                    "port": 8443,
                    "secret": "0123456789abcdef0123456789abcdef",
                    "link": "https://t.me/proxy?secret=0123456789abcdef0123456789abcdef",
                    "fingerprint": "f3bff43850e88441",
                },
                public_payload={
                    "type": "mtproto",
                    "mode": "managed",
                    "host": "150.251.152.243",
                    "port": 8443,
                },
                created_by=100,
                now="2026-05-06T20:20:00+00:00",
                secret_fingerprint="f3bff43850e88441",
            )

            stats = await repo.get_user_proxy_stats(100)
            rendered = str(stats)

            assert len(stats.accesses) == 2
            assert "vpn_socks_100_abcd" in rendered
            assert "f3bff43850e88441" in rendered
            assert "secret-password" not in rendered
            assert "0123456789abcdef0123456789abcdef" not in rendered
            assert "t.me/proxy" not in rendered
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_admin_stats_keeps_all_failed_records_in_aggregate_and_user_summary(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            for index, status in enumerate(
                (
                    ProxyAccessStatus.APPLY_FAILED,
                    ProxyAccessStatus.REVOKE_FAILED,
                    ProxyAccessStatus.DELETE_FAILED,
                ),
                start=1,
            ):
                await repo.create(
                    owner_user_id=100,
                    username="user",
                    access_type=ProxyAccessType.SOCKS5 if index != 2 else ProxyAccessType.MTPROTO,
                    status=status,
                    payload={"type": "socks5", "login": f"vpn_socks_failed_{index}", "password": "secret-password"},
                    public_payload={"type": "socks5", "login": f"vpn_socks_failed_{index}"},
                    created_by=100,
                    now=f"2026-05-06T20:0{index}:00+00:00",
                )

            stats = await repo.get_admin_proxy_stats(user_limit=10)
            failed_total = sum(
                value
                for status_counts in stats.type_status_counts.values()
                for status, value in status_counts.items()
                if status
                in {
                    ProxyAccessStatus.APPLY_FAILED,
                    ProxyAccessStatus.REVOKE_FAILED,
                    ProxyAccessStatus.DELETE_FAILED,
                }
            )

            assert stats.apply_failed == 1
            assert failed_total == 3
            assert stats.last_failed_at == "2026-05-06T20:03:00+00:00"
            assert len(stats.users) == 1
            assert stats.users[0].failed_count == 3
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_service_exposes_user_and_admin_stats_with_rbac(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _repo(tmp_path)
        try:
            await repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.SOCKS5,
                status=ProxyAccessStatus.ACTIVE,
                payload={"type": "socks5", "login": "vpn_socks_100_abcd", "password": "secret-password"},
                public_payload={"type": "socks5", "login": "vpn_socks_100_abcd"},
                created_by=100,
                now="2026-05-06T20:19:00+00:00",
            )
            service = ProxyService(accesses=repo, users=_Users(), settings=_settings())  # type: ignore[arg-type]

            user_stats = await service.get_user_proxy_stats(100)
            admin_stats = await service.get_admin_proxy_stats(1)

            assert len(user_stats.accesses) == 1
            assert admin_stats.total_accesses == 1
            assert admin_stats.runtime is not None
            assert admin_stats.runtime.socks5_host == "150.251.152.243"
        finally:
            await db.close()

    asyncio.run(run())


def test_hard_block_revokes_socks5_and_deactivates_mtproto(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            access_repo = ProxyAccessRepository(db)
            socks5 = await access_repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.SOCKS5,
                status=ProxyAccessStatus.ACTIVE,
                payload={"type": "socks5", "login": "vpn_socks_100_abcd"},
                public_payload={"type": "socks5", "login": "vpn_socks_100_abcd"},
                created_by=100,
                now="now",
            )
            mtproto = await access_repo.create(
                owner_user_id=100,
                username="user",
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload={"type": "mtproto"},
                public_payload={"type": "mtproto"},
                created_by=100,
                now="now",
            )
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            user_locks = UserLockManager()
            user_service = UserService(
                users=users_repo,
                settings=_settings(),
                clock=ClockProvider(),
                audit=audit,
                user_locks=user_locks,
            )
            async def revoke_vpn(actor_user_id: int, key_id: int):  # pragma: no cover - no VPN keys in this test
                raise AssertionError("unexpected VPN revoke")

            user_service.attach_key_management(VpnKeyRepository(db), {VpnKeyType.XRAY: revoke_vpn})
            lock_adapter = _LockOnlyAdapter()
            socks5_service = Socks5Service(
                accesses=access_repo,
                users=user_service,
                adapter=lock_adapter,  # type: ignore[arg-type]
                settings=_settings(),
                clock=ClockProvider(),
                audit=audit,
                user_locks=user_locks,
            )
            mtproto_service = MtProtoService(
                accesses=access_repo,
                users=user_service,
                settings=_settings(),
                clock=ClockProvider(),
                audit=audit,
                user_locks=user_locks,
            )
            user_service.attach_proxy_access_management(
                access_repo,
                {
                    ProxyAccessType.SOCKS5: socks5_service.revoke_socks5_proxy,
                    ProxyAccessType.MTPROTO: mtproto_service.revoke_mtproto_proxy,
                },
            )

            result = await user_service.block_user(1, 100)
            socks5_after = await access_repo.get_by_id(socks5.id)
            mtproto_after = await access_repo.get_by_id(mtproto.id)

            assert result.errors == ()
            assert set(result.revoked_proxy_ids) == {socks5.id, mtproto.id}
            assert lock_adapter.locked == ["vpn_socks_100_abcd"]
            assert socks5_after is not None and socks5_after.status == ProxyAccessStatus.REVOKED
            assert mtproto_after is not None and mtproto_after.status == ProxyAccessStatus.INACTIVE
        finally:
            await db.close()

    asyncio.run(run())


def test_hard_block_revokes_managed_mtproto_secret_without_touching_other_users(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users_repo = UserRepository(db)
            await users_repo.upsert_profile(TelegramUserProfile(1, "admin", "Admin"), UserRole.SUPERADMIN, "now")
            await users_repo.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            await users_repo.upsert_profile(TelegramUserProfile(101, "other", "Other"), UserRole.APPROVED_USER, "now")
            access_repo = ProxyAccessRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            user_locks = UserLockManager()
            user_service = UserService(
                users=users_repo,
                settings=_settings(mtproto_mode="managed", mtproto_secret=""),
                clock=ClockProvider(),
                audit=audit,
                user_locks=user_locks,
            )
            adapter = _MtProxyAdapter()
            mtproto_service = MtProtoService(
                accesses=access_repo,
                users=user_service,
                settings=_settings(mtproto_mode="managed", mtproto_secret=""),
                clock=ClockProvider(),
                audit=audit,
                adapter=adapter,  # type: ignore[arg-type]
                user_locks=user_locks,
            )
            async def revoke_vpn(actor_user_id: int, key_id: int):  # pragma: no cover - no VPN keys in this test
                raise AssertionError("unexpected VPN revoke")

            user_service.attach_key_management(VpnKeyRepository(db), {VpnKeyType.XRAY: revoke_vpn})
            first = await mtproto_service.issue_mtproto_proxy(100, TelegramUserProfile(100, "user", "User"))
            second = await mtproto_service.issue_mtproto_proxy(101, TelegramUserProfile(101, "other", "Other"))
            user_service.attach_proxy_access_management(
                access_repo,
                {ProxyAccessType.MTPROTO: mtproto_service.revoke_mtproto_proxy},
            )

            result = await user_service.block_user(1, 100)

            first_after = await access_repo.get_by_id(first.id)
            second_after = await access_repo.get_by_id(second.id)
            assert result.errors == ()
            assert result.revoked_proxy_ids == (first.id,)
            assert first_after is not None and first_after.status == ProxyAccessStatus.REVOKED
            assert second_after is not None and second_after.status == ProxyAccessStatus.ACTIVE
            assert [item.access_id for item in adapter.current] == [second.id]
        finally:
            await db.close()

    asyncio.run(run())
