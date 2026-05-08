from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.dante_users import DanteUserAdapter
from adapters.id_generator import IdGenerator
from adapters.ip_allocator import IpAllocator
from adapters.mtproxy import MtProxyAdapter
from adapters.shell_runner import ShellRunner
from adapters.systemctl import SystemCtlAdapter
from adapters.xray_config import XrayConfigAdapter
from adapters.xray_stats import XrayStatsAdapter
from bot.handlers import admin, callbacks, common, keys, proxy, start
from bot.middlewares.access import BlockedUserMiddleware
from bot.rate_limit import RateLimiter
from config.settings import Settings
from db.database import Database
from models.enums import AuditEntityType, ProxyAccessType, VpnKeyType
from repositories.access_requests import AccessRequestRepository
from repositories.announcements import AnnouncementRepository
from repositories.audit_log import AuditLogRepository
from repositories.proxy_entries import ProxyRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.traffic_stats import TrafficStatsRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.access_approval import AccessApprovalService
from services.announcements import AnnouncementService
from services.audit import AuditService
from services.awg import AwgService
from services.backend_health import BackendHealth
from services.notes import NotesService
from services.proxy import ProxyService
from services.socks5 import Socks5Service
from services.mtproto import MtProtoService
from services.traffic_stats import TrafficStatsService
from services.user_locks import UserLockManager
from services.users import UserService
from services.vpn_keys import VpnKeyQueryService
from services.xray import XrayService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Services:
    settings: Settings
    db: Database
    users: UserService
    access: AccessApprovalService
    xray: XrayService
    awg: AwgService
    proxy: ProxyService
    socks5: Socks5Service
    mtproto: MtProtoService
    notes: NotesService
    vpn_keys: VpnKeyQueryService
    traffic_stats: TrafficStatsService
    audit: AuditService
    announcements: AnnouncementService
    backend_health: BackendHealth


async def create_app(settings: Settings) -> tuple[Bot, Dispatcher, Database]:
    db = Database(settings.db_path, synchronous=settings.sqlite_synchronous)
    await db.connect()
    await db.bootstrap()

    clock = ClockProvider()
    shell = ShellRunner(max_output_chars=4096)
    backup = BackupAdapter(clock, keep_last=settings.config_backup_keep_last)
    systemctl = SystemCtlAdapter(shell)
    ids = IdGenerator()
    user_locks = UserLockManager()
    backend_health = BackendHealth()

    users_repo = UserRepository(db)
    access_repo = AccessRequestRepository(db)
    announcement_repo = AnnouncementRepository(db)
    vpn_keys_repo = VpnKeyRepository(db)
    proxy_accesses_repo = ProxyAccessRepository(db)
    proxy_repo = ProxyRepository(db)
    audit_repo = AuditLogRepository(db)
    traffic_stats_repo = TrafficStatsRepository(db)

    audit_service = AuditService(audit_repo, clock)
    user_service = UserService(users=users_repo, settings=settings, clock=clock, audit=audit_service, user_locks=user_locks)
    await user_service.bootstrap_admins()

    access_service = AccessApprovalService(
        requests=access_repo,
        users=user_service,
        clock=clock,
        audit=audit_service,
    )

    xray_adapter = XrayConfigAdapter(
        config_path=settings.xray_config_path,
        service_name=settings.xray_service_name,
        apply_mode=settings.xray_apply_mode,
        inbound_tag=settings.xray_inbound_tag,
        allow_restart_on_rollback=settings.xray_allow_restart_on_rollback,
        backup=backup,
        systemctl=systemctl,
    )
    xray_stats_adapter = XrayStatsAdapter(shell=shell, stats_server=settings.xray_stats_server)
    awg_adapter = AwgConfigAdapter(
        config_path=settings.awg_config_path,
        interface=settings.awg_interface,
        backup=backup,
        shell=shell,
        persistent_keepalive=settings.awg_persistent_keepalive,
    )
    ip_allocator = IpAllocator(vpn_keys_repo, settings.awg_network, settings.awg_server_address, awg_config=awg_adapter)
    dante_adapter = DanteUserAdapter(
        shell=shell,
        login_prefix=settings.socks5_login_prefix,
        system_user_shell=settings.socks5_system_user_shell,
    )
    mtproxy_adapter = (
        MtProxyAdapter(
            shell=shell,
            systemctl=systemctl,
            service_name=settings.mtproto_service_name,
            binary_path=settings.mtproto_binary_path,
            run_user=settings.mtproto_run_user,
            run_group=settings.mtproto_run_group,
            proxy_secret_path=settings.mtproto_proxy_secret_path,
            proxy_multi_conf_path=settings.mtproto_proxy_multi_conf_path,
            managed_secrets_path=settings.mtproto_managed_secrets_path,
            managed_env_path=settings.mtproto_managed_env_path,
            managed_wrapper_path=settings.mtproto_managed_wrapper_path,
            backup_dir=settings.mtproto_backup_dir,
            port=settings.mtproto_port,
            internal_stats_port=settings.mtproto_internal_stats_port,
            workers=settings.mtproto_workers,
            apply_timeout_seconds=settings.mtproto_apply_timeout_seconds,
            rollback_on_apply_failure=settings.mtproto_rollback_on_apply_failure,
            keep_last_backups=settings.mtproto_keep_last_backups,
        )
        if settings.mtproto_mode == "managed"
        else None
    )

    xray_service = XrayService(
        vpn_keys=vpn_keys_repo,
        users=user_service,
        adapter=xray_adapter,
        settings=settings,
        clock=clock,
        ids=ids,
        audit=audit_service,
        user_locks=user_locks,
        backend_health=backend_health,
    )
    awg_service = AwgService(
        vpn_keys=vpn_keys_repo,
        users=user_service,
        adapter=awg_adapter,
        ip_allocator=ip_allocator,
        settings=settings,
        clock=clock,
        ids=ids,
        audit=audit_service,
        user_locks=user_locks,
        backend_health=backend_health,
    )
    user_service.attach_key_management(
        vpn_keys_repo,
        {
            VpnKeyType.XRAY: xray_service.revoke_xray_key,
            VpnKeyType.AWG: awg_service.revoke_awg_key,
        },
    )
    proxy_service = ProxyService(accesses=proxy_accesses_repo, users=user_service, settings=settings)
    socks5_service = Socks5Service(
        accesses=proxy_accesses_repo,
        users=user_service,
        adapter=dante_adapter,
        settings=settings,
        clock=clock,
        audit=audit_service,
        user_locks=user_locks,
        backend_health=backend_health,
    )
    mtproto_service = MtProtoService(
        accesses=proxy_accesses_repo,
        users=user_service,
        settings=settings,
        clock=clock,
        audit=audit_service,
        adapter=mtproxy_adapter,
        user_locks=user_locks,
        backend_health=backend_health,
    )
    user_service.attach_proxy_access_management(
        proxy_accesses_repo,
        {
            ProxyAccessType.SOCKS5: socks5_service.revoke_socks5_proxy,
            ProxyAccessType.MTPROTO: mtproto_service.revoke_mtproto_proxy,
        },
    )
    notes_service = NotesService(
        vpn_keys=vpn_keys_repo,
        proxies=proxy_repo,
        users=user_service,
        audit=audit_service,
    )
    vpn_key_service = VpnKeyQueryService(vpn_keys=vpn_keys_repo, users=user_service)
    traffic_stats_service = TrafficStatsService(
        stats=traffic_stats_repo,
        vpn_keys=vpn_keys_repo,
        users_repo=users_repo,
        users=user_service,
        awg=awg_adapter,
        xray=xray_stats_adapter,
    )
    announcement_service = AnnouncementService(
        users=user_service,
        users_repo=users_repo,
        announcements=announcement_repo,
        audit=audit_service,
    )

    await proxy_service.seed_default_from_env()
    await audit_service.prune_old_audit_logs(settings.audit_retention_days)

    services = Services(
        settings=settings,
        db=db,
        users=user_service,
        access=access_service,
        xray=xray_service,
        awg=awg_service,
        proxy=proxy_service,
        socks5=socks5_service,
        mtproto=mtproto_service,
        notes=notes_service,
        vpn_keys=vpn_key_service,
        traffic_stats=traffic_stats_service,
        audit=audit_service,
        announcements=announcement_service,
        backend_health=backend_health,
    )

    await _startup_reconcile_keys(services)

    bot = Bot(settings.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.workflow_data["services"] = services
    dp.workflow_data["rate_limiter"] = RateLimiter()
    user_service.attach_state_clearer(
        lambda user_id: dp.fsm.get_context(bot=bot, chat_id=user_id, user_id=user_id).clear()
    )

    blocked_middleware = BlockedUserMiddleware(user_service)
    dp.message.outer_middleware(blocked_middleware)
    dp.callback_query.outer_middleware(blocked_middleware)

    dp.include_router(start.router)
    dp.include_router(common.router)
    dp.include_router(admin.router)
    dp.include_router(keys.router)
    dp.include_router(proxy.router)
    dp.include_router(callbacks.router)

    return bot, dp, db


async def _startup_reconcile_keys(services: Services) -> None:
    xray_summary = await _safe_startup_reconcile("Xray", services.xray.startup_reconcile)
    awg_summary = await _safe_startup_reconcile("AWG", services.awg.startup_reconcile)
    mtproto_reconcile = getattr(getattr(services, "mtproto", None), "reconcile_mtproto_state", None)
    mtproto_summary = (
        await _safe_startup_reconcile("MTProto", mtproto_reconcile)
        if mtproto_reconcile is not None
        else {"checked": 0, "missing": 0, "orphaned": 0, "pending": 0, "failed": 0}
    )
    backend_health = getattr(services, "backend_health", None)
    if backend_health is not None:
        if xray_summary.get("failed", 0):
            backend_health.mark_degraded(VpnKeyType.XRAY, "startup reconciliation failed")
        if awg_summary.get("failed", 0):
            backend_health.mark_degraded(VpnKeyType.AWG, "startup reconciliation failed")
        if mtproto_summary.get("failed", 0):
            backend_health.mark_degraded(ProxyAccessType.MTPROTO, "startup reconciliation failed")
    logger.info(
        "Startup access reconciliation: xray=%s awg=%s mtproto=%s",
        xray_summary,
        awg_summary,
        mtproto_summary,
    )
    if xray_summary["checked"] or awg_summary["checked"] or mtproto_summary["checked"]:
        try:
            await services.audit.write(
                actor_user_id=None,
                action="startup_reconciliation_completed",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details={"xray": xray_summary, "awg": awg_summary, "mtproto": mtproto_summary},
            )
        except Exception:
            logger.warning("Startup VPN key reconciliation completed, but audit write failed", exc_info=True)


async def _safe_startup_reconcile(name: str, reconcile: Any) -> dict[str, int]:
    try:
        return await reconcile()
    except Exception:
        logger.warning("Startup VPN key reconciliation for %s failed; bot startup continues", name, exc_info=True)
        return {"checked": 0, "recovered": 0, "failed": 1}
