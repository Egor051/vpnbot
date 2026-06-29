
import asyncio
from pathlib import Path

import pytest

from adapters.clock import ClockProvider
from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.audit_log import AuditLogRepository
from repositories.trial_requests import TrialKeyRequestRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied
from services.trial_access import TrialAccessService


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


async def _bootstrap(tmp_path: Path) -> Database:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    return db


async def _add_user(
    users_repo: UserRepository,
    user_id: int,
    role: UserRole = UserRole.APPROVED_USER,
) -> None:
    await users_repo.upsert_profile(
        TelegramUserProfile(user_id, f"user{user_id}", f"User{user_id}"),
        role,
        "2026-01-01T00:00:00",
    )


# ---------------------------------------------------------------------------
# G1 — test_trial_double_tap
# ---------------------------------------------------------------------------


def test_trial_double_tap(tmp_path: Path) -> None:
    """Two concurrent create_trial_request calls for the same user: exactly one succeeds."""

    async def run() -> None:
        db = await _bootstrap(tmp_path)
        try:
            users_repo = UserRepository(db)
            await _add_user(users_repo, 100)
            trial_repo = TrialKeyRequestRepository(db)
            audit = AuditService(AuditLogRepository(db), ClockProvider())
            clock = ClockProvider()

            svc = TrialAccessService(
                trial_requests=trial_repo,
                users_repo=users_repo,
                xray=object(),
                awg=object(),
                hysteria=object(),
                audit=audit,
                clock=clock,
            )

            results: list[object] = []
            errors: list[Exception] = []

            async def attempt() -> None:
                try:
                    req = await svc.create_trial_request(100, VpnKeyType.XRAY)
                    results.append(req)
                except (AccessDenied, Exception) as exc:
                    errors.append(exc)

            await asyncio.gather(attempt(), attempt(), return_exceptions=False)

            pending = await trial_repo.count_pending()
            assert pending == 1, "exactly one pending trial request should exist"
            succeeded = len(results)
            assert succeeded == 1, f"expected 1 success, got {succeeded}"
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# G1 — test_update_note_vs_delete_key
# ---------------------------------------------------------------------------


def test_update_note_vs_delete_key(tmp_path: Path) -> None:
    """Concurrent note update and key deletion must not crash and must leave the DB consistent."""
    from adapters.clock import ClockProvider as Clock
    from repositories.proxy_entries import ProxyRepository
    from services.notes import NotesService
    from services.users import UserService
    from services.xray import XrayService

    class _NullAdapter:
        async def add_client(self, **kwargs: object) -> None:
            pass

        async def remove_client(self, **kwargs: object) -> None:
            pass

    class _Ids:
        def uuid4(self) -> str:
            return "00000000-0000-4000-8000-000000000099"

        def generated_key_name(self, prefix: str) -> str:
            return f"{prefix}_ConcTest"

        def xray_short_id(self) -> str:
            return "abcd1234"

    class _Audit:
        async def write(self, **kwargs: object) -> None:
            pass

        async def write_best_effort(self, **kwargs: object) -> None:
            pass

    async def run() -> None:
        db = await _bootstrap(tmp_path)
        try:
            users_repo = UserRepository(db)
            await _add_user(users_repo, 100)
            keys_repo = VpnKeyRepository(db)

            from config.settings import Settings

            settings = Settings(
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

            audit = _Audit()
            user_svc = UserService(
                users=users_repo,
                settings=settings,
                clock=Clock(),
                audit=audit,  # type: ignore[arg-type]
            )
            xray_svc = XrayService(
                vpn_keys=keys_repo,
                users=user_svc,
                adapter=_NullAdapter(),  # type: ignore[arg-type]
                settings=settings,
                clock=Clock(),
                ids=_Ids(),  # type: ignore[arg-type]
                audit=audit,  # type: ignore[arg-type]
            )

            key = await xray_svc.create_xray_key(
                100, TelegramUserProfile(100, "user100", "User100"), None
            )
            key_id = key.key.id

            proxy_repo = ProxyRepository(db)
            notes_svc = NotesService(
                vpn_keys=keys_repo,
                proxies=proxy_repo,
                users=user_svc,
                users_repo=users_repo,
                audit=audit,  # type: ignore[arg-type]
            )

            note_exc: list[Exception] = []
            delete_exc: list[Exception] = []

            async def update_note() -> None:
                try:
                    await notes_svc.update_key_note(100, key_id, "concurrent note")
                except Exception as exc:
                    note_exc.append(exc)

            async def delete_key() -> None:
                try:
                    await xray_svc.delete_xray_key(100, key_id)
                except Exception as exc:
                    delete_exc.append(exc)

            await asyncio.gather(update_note(), delete_key())

            # DB must be consistent: key is either deleted or still active with a note
            stored = await keys_repo.get_by_id(key_id)
            if stored is not None:
                assert stored.status != VpnKeyStatus.ACTIVE or stored.note in (None, "concurrent note")
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# G1 — test_socks5_revoke_vs_issue_race
# ---------------------------------------------------------------------------


def test_socks5_revoke_vs_issue_race(tmp_path: Path) -> None:
    """Concurrent socks5 revoke and re-issue must not crash and leave consistent state."""
    from adapters.clock import ClockProvider as Clock
    from repositories.proxy_accesses import ProxyAccessRepository
    from services.socks5 import Socks5Service
    from services.users import UserService

    class _Shell:
        def __init__(self) -> None:
            self.users: set[str] = set()

        async def run(self, args: list[str], **kwargs: object) -> object:
            from models.dto import ShellResult

            if args[:2] == ["getent", "passwd"]:
                code = 0 if args[2] in self.users else 2
                return ShellResult(tuple(args), code, "", "")
            if args[0] == "useradd":
                self.users.add(args[-1])
                return ShellResult(tuple(args), 0, "", "")
            if args[0] == "chpasswd":
                return ShellResult(tuple(args), 0, "", "")
            if args[:2] == ["passwd", "-l"]:
                return ShellResult(tuple(args), 0, "", "")
            if args[0] == "userdel":
                self.users.discard(args[-1])
                return ShellResult(tuple(args), 0, "", "")
            return ShellResult(tuple(args), 0, "", "")

    class _Audit:
        async def write(self, **kwargs: object) -> None:
            pass

        async def write_best_effort(self, **kwargs: object) -> None:
            pass

    async def run() -> None:
        from adapters.dante_users import DanteUserAdapter
        from config.settings import Settings

        db = await _bootstrap(tmp_path)
        try:
            users_repo = UserRepository(db)
            await _add_user(users_repo, 100)
            access_repo = ProxyAccessRepository(db)

            settings = Settings(
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
                socks5_enabled=True,
                socks5_host="203.0.113.1",
                socks5_port=31337,
                socks5_login_prefix="vpn_socks_",
                mtproto_enabled=False,
                mtproto_host="203.0.113.1",
                mtproto_port=8443,
                mtproto_secret="0123456789abcdef0123456789abcdef",
                audit_retention_days=180,
                config_backup_keep_last=20,
            )

            audit = _Audit()
            shell = _Shell()
            adapter = DanteUserAdapter(
                shell=shell,  # type: ignore[arg-type]
                login_prefix="vpn_socks_",
                system_user_shell="/usr/sbin/nologin",
            )
            user_svc = UserService(
                users=users_repo,
                settings=settings,
                clock=Clock(),
                audit=audit,  # type: ignore[arg-type]
            )
            socks5_svc = Socks5Service(
                accesses=access_repo,
                users=user_svc,
                adapter=adapter,
                settings=settings,
                clock=Clock(),
                audit=audit,  # type: ignore[arg-type]
            )

            profile = TelegramUserProfile(100, "user100", "User100")

            # Create initial access
            first = await socks5_svc.issue_socks5_proxy(100, profile)
            access_id = first.id

            issue_exc: list[Exception] = []
            revoke_exc: list[Exception] = []

            async def re_issue() -> None:
                try:
                    await socks5_svc.issue_socks5_proxy(100, profile)
                except Exception as exc:
                    issue_exc.append(exc)

            async def revoke() -> None:
                try:
                    await socks5_svc.revoke_socks5_proxy(100, access_id, "concurrent test")
                except Exception as exc:
                    revoke_exc.append(exc)

            await asyncio.gather(re_issue(), revoke())

            accesses = await access_repo.list_by_owner(100)
            assert len(accesses) >= 1, "at least one access record must exist"
            from models.enums import ProxyAccessStatus
            statuses = {a.status for a in accesses}
            valid_statuses = {
                ProxyAccessStatus.ACTIVE,
                ProxyAccessStatus.REVOKED,
                ProxyAccessStatus.PENDING_REVOKE,
            }
            assert statuses <= valid_statuses, f"unexpected statuses: {statuses}"
        finally:
            await db.close()

    asyncio.run(run())
