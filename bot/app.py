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
from adapters.id_generator import IdGenerator
from adapters.ip_allocator import IpAllocator
from adapters.shell_runner import ShellRunner
from adapters.systemctl import SystemCtlAdapter
from adapters.xray_config import XrayConfigAdapter
from adapters.xray_stats import XrayStatsAdapter
from bot.handlers import admin, callbacks, common, keys, proxy, start
from bot.middlewares.access import BlockedUserMiddleware
from bot.rate_limit import RateLimiter
from config.settings import Settings
from db.database import Database
from models.enums import AuditEntityType, VpnKeyType
from repositories.access_requests import AccessRequestRepository
from repositories.audit_log import AuditLogRepository
from repositories.proxy_entries import ProxyRepository
from repositories.traffic_stats import TrafficStatsRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.access_approval import AccessApprovalService
from services.audit import AuditService
from services.awg import AwgService
from services.notes import NotesService
from services.proxy import ProxyService
from services.traffic_stats import TrafficStatsService
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
    notes: NotesService
    vpn_keys: VpnKeyQueryService
    traffic_stats: TrafficStatsService
    audit: AuditService


async def create_app(settings: Settings) -> tuple[Bot, Dispatcher, Database]:
    db = Database(settings.db_path)
    await db.connect()
    await db.bootstrap()

    clock = ClockProvider()
    shell = ShellRunner(max_output_chars=4096)
    backup = BackupAdapter(clock, keep_last=settings.config_backup_keep_last)
    systemctl = SystemCtlAdapter(shell)
    ids = IdGenerator()

    users_repo = UserRepository(db)
    access_repo = AccessRequestRepository(db)
    vpn_keys_repo = VpnKeyRepository(db)
    proxy_repo = ProxyRepository(db)
    audit_repo = AuditLogRepository(db)
    traffic_stats_repo = TrafficStatsRepository(db)

    audit_service = AuditService(audit_repo, clock)
    user_service = UserService(users=users_repo, settings=settings, clock=clock, audit=audit_service)
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

    xray_service = XrayService(
        vpn_keys=vpn_keys_repo,
        users=user_service,
        adapter=xray_adapter,
        settings=settings,
        clock=clock,
        ids=ids,
        audit=audit_service,
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
    )
    user_service.attach_key_management(
        vpn_keys_repo,
        {
            VpnKeyType.XRAY: xray_service.revoke_xray_key,
            VpnKeyType.AWG: awg_service.revoke_awg_key,
        },
    )
    proxy_service = ProxyService(
        proxies=proxy_repo,
        users=user_service,
        settings=settings,
        audit=audit_service,
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
        notes=notes_service,
        vpn_keys=vpn_key_service,
        traffic_stats=traffic_stats_service,
        audit=audit_service,
    )

    await _startup_reconcile_keys(services)

    bot = Bot(settings.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.workflow_data["services"] = services
    dp.workflow_data["rate_limiter"] = RateLimiter()

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
    logger.info("Startup VPN key reconciliation: xray=%s awg=%s", xray_summary, awg_summary)
    if xray_summary["checked"] or awg_summary["checked"]:
        try:
            await services.audit.write(
                actor_user_id=None,
                action="startup_reconciliation_completed",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details={"xray": xray_summary, "awg": awg_summary},
            )
        except Exception:
            logger.warning("Startup VPN key reconciliation completed, but audit write failed", exc_info=True)


async def _safe_startup_reconcile(name: str, reconcile: Any) -> dict[str, int]:
    try:
        return await reconcile()
    except Exception:
        logger.warning("Startup VPN key reconciliation for %s failed; bot startup continues", name, exc_info=True)
        return {"checked": 0, "recovered": 0, "failed": 1}
