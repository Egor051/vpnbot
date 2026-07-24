
import asyncio
import logging
from contextlib import suppress
from pathlib import Path
from typing import Any

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from bot.fsm.ttl_storage import TTLMemoryStorage

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.hysteria_auth_health import Hysteria2AuthHealthProbe
from adapters.hysteria_stats import HysteriaStatsAdapter
from adapters.dante_users import DanteUserAdapter
from adapters.id_generator import IdGenerator
from adapters.ip_allocator import IpAllocator
from adapters.mtproxy import MtProxyAdapter
from adapters.privileged_helpers import PrivilegedHelperRunner
from adapters.shell_runner import ShellRunner
from adapters.systemctl import SystemCtlAdapter
from adapters.xray_config import XrayConfigAdapter, vless_inbound_present
from adapters.xray_stats import XrayStatsAdapter
from bot.container import Services
from bot.handlers import admin, admin_dashboard, admin_maintenance, admin_modules, admin_warp, admin_warp_split, admin_warp_split_ui, callbacks, common, keys, proxy, settings as settings_handler, start
from bot.middlewares.access import BlockedUserMiddleware
from bot.middlewares.config_cleanup import ConfigDocumentCleanupMiddleware
from bot.middlewares.locale import LocaleMiddleware
from bot.middlewares.maintenance import MaintenanceModeMiddleware
from bot.rate_limit import RateLimiter
from config.settings import Settings
from db.database import Database
from models.enums import AuditEntityType, ProxyAccessType, VpnKeyType
from repositories.access_requests import AccessRequestRepository
from repositories.announcements import AnnouncementRepository
from repositories.audit_log import AuditLogRepository
from repositories.dashboard import DashboardRepository
from repositories.key_bundles import KeyBundleRepository
from repositories.protocol_modules import ProtocolModulesRepository
from repositories.proxy_entries import ProxyRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.traffic_stats import TrafficStatsRepository
from repositories.trial_requests import TrialKeyRequestRepository
from repositories.users import UserRepository
from repositories.maintenance_settings import MaintenanceSettingsRepository
from repositories.server_status_settings import ServerStatusSettingsRepository
from repositories.vpn_keys import VpnKeyRepository
from services.access_approval import AccessApprovalService
from services.anomaly_detection import AnomalyDetectionService
from services.auto_refresh import LiveRefreshManager
from services.announcements import AnnouncementService
from services.audit import AuditService
from services.awg import AwgService
from services.backend_health import BackendHealth
from services.dashboard import DashboardService
from services.hysteria import HysteriaService
from services.key_bundles import KeyBundleService
from services.key_expiry import KeyExpiryService
from services.maintenance import MaintenanceService
from services.offsite_backup import OffsiteBackupService
from services.notes import NotesService
from services.online_clients import OnlineClientsService
from services.protocol_modules import ProtocolModulesService
from services.proxy import ProxyService
from services.server_status import ServerStatusService
from services.socks5 import Socks5Service
from services.mtproto import MtProtoService
from services.traffic_stats import TrafficStatsService
from services.trial_access import TrialAccessService
from services.user_locks import UserLockManager
from services.users import UserService
from services.vpn_keys import VpnKeyQueryService
from services.xray import XrayService
from warp.manager import WarpManager
from warp.proxy_egress import make_send_through_provider
from warp.split_manager import WarpSplitManager

logger = logging.getLogger(__name__)


class StartupReconcileError(RuntimeError):
    """Raised when a backend's startup reconciliation fails fatally and the bot must
    not continue. Propagates out of create_app so main.py aborts with a clean exit
    instead of running with a silently broken data plane."""


async def _awg_stats_loop(traffic_stats: TrafficStatsService, interval: int) -> None:
    while True:
        try:
            await traffic_stats.refresh_all_awg()
        except Exception:
            logger.warning("AWG background stats collection failed", exc_info=True)
        await asyncio.sleep(interval)


async def _xray_stats_loop(traffic_stats: TrafficStatsService, interval: int) -> None:
    # statsquery is read without -reset (non-destructive), so manual stat views poll
    # it live; this loop only keeps the cache warm between them so the dashboard
    # stays fresh without user interaction (see TrafficStatsService.refresh_all_xray).
    while True:
        try:
            await traffic_stats.refresh_all_xray()
        except Exception:
            logger.warning("Xray background stats collection failed", exc_info=True)
        await asyncio.sleep(interval)


async def _hysteria_stats_loop(traffic_stats: TrafficStatsService, interval: int) -> None:
    # GET /traffic is read without ?clear (non-destructive), so manual per-key views
    # poll it live; this loop only keeps the cache warm between them, mirroring the
    # Xray loop (see TrafficStatsService.refresh_all_hysteria). A no-op when the
    # Traffic Stats API is not configured.
    while True:
        try:
            await traffic_stats.refresh_all_hysteria()
        except Exception:
            logger.warning("Hysteria2 background stats collection failed", exc_info=True)
        await asyncio.sleep(interval)


async def _hysteria_health_loop(
    probe: Hysteria2AuthHealthProbe, backend_health: BackendHealth, interval: int
) -> None:
    # Poll hy2_auth /healthz and reflect it in backend_health so the dashboard and
    # health panel show "Hysteria2: OK/DEGRADED" like Xray/AWG. Hysteria2 has no
    # data-plane apply — its mutations are pure DB writes that never call
    # require_mutation_allowed — so a degraded mark here is purely informational
    # (data-plane liveness) and never blocks issuance/revocation.
    while True:
        try:
            if await probe.healthy():
                backend_health.mark_healthy(VpnKeyType.HYSTERIA2)
            else:
                backend_health.mark_degraded(VpnKeyType.HYSTERIA2, "hy2_auth /healthz недоступен")
        except Exception:
            logger.warning("Hysteria2 health probe failed", exc_info=True)
        await asyncio.sleep(interval)


async def create_app(settings: Settings) -> tuple[Bot, Dispatcher, Database, BackendHealth, Services]:
    db = Database(settings.db_path, synchronous=settings.sqlite_synchronous)
    await db.connect()
    try:
        return await _build_app(settings, db)
    except BaseException:
        # create_app is not atomic: if startup fails after connect() (bootstrap,
        # admin seeding, reconciliation, …) close the DB so the aiosqlite
        # connection/background thread is not leaked when startup aborts.
        with suppress(Exception):
            await db.close()
        raise


async def _build_app(
    settings: Settings, db: Database
) -> tuple[Bot, Dispatcher, Database, BackendHealth, Services]:
    await db.bootstrap()

    clock = ClockProvider()
    shell = ShellRunner(max_output_chars=4096)
    backup = BackupAdapter(clock, keep_last=settings.config_backup_keep_last)
    systemctl = SystemCtlAdapter(shell)
    helper_runner = PrivilegedHelperRunner(shell=shell) if settings.privilege_helpers_enabled else None
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
    trial_requests_repo = TrialKeyRequestRepository(db)

    protocol_modules_repo = ProtocolModulesRepository(db)
    protocol_modules_service = ProtocolModulesService(protocol_modules_repo, db)
    dashboard_repo = DashboardRepository(db)

    audit_service = AuditService(audit_repo, clock, users_repo)
    user_service = UserService(users=users_repo, settings=settings, clock=clock, audit=audit_service, user_locks=user_locks)
    await user_service.bootstrap_admins()

    access_service = AccessApprovalService(
        requests=access_repo,
        users=user_service,
        clock=clock,
        audit=audit_service,
    )

    # When WARP proxy egress is enabled, every Xray config write binds the freedom
    # outbound's egress source to the tunnel IP (sendThrough) so its traffic is
    # diverted into the tunnel by vpn-bot-warp-routes. Both adapters share it because
    # they write the same config.json (and therefore the same outbounds).
    warp_send_through = make_send_through_provider(
        enabled=settings.warp_proxy_egress_enabled,
        config_path=settings.warp_config_path,
    )
    xray_adapter = XrayConfigAdapter(
        config_path=settings.xray_config_path,
        service_name=settings.xray_service_name,
        apply_mode=settings.xray_apply_mode,
        inbound_tag=settings.xray_inbound_tag,
        allow_restart_on_rollback=settings.xray_allow_restart_on_rollback,
        backup=backup,
        systemctl=systemctl,
        shell=shell,
        stats_server=settings.xray_stats_server,
        helper_runner=helper_runner,
        helper_path=settings.xray_apply_helper_path,
        helper_staging_dir=settings.xray_helper_staging_dir,
        warp_send_through=warp_send_through,
    )
    # Second VLESS transport (XHTTP+REALITY) inbound. Shares the same config.json,
    # service, apply_mode and stats_server; only the inbound_tag differs. Both
    # adapters serialise on the same ConfigFileLock (keyed by config_path).
    #
    # The adapter is built from the *actual* presence of the XHTTP inbound in
    # config.json — NOT from XRAY_XHTTP_ENABLED. This keeps already-issued VLESS
    # (HTTP) keys revocable/deletable/reconcilable even after the flag is turned
    # back off (the flag gates only the issuance of NEW http keys: UI buttons +
    # create). When the inbound is absent (or the config is unreadable) the
    # adapter is None and the feature stays fully inert, identical to before.
    #
    # In the fallback topology the XHTTP inbound is the dest of vless-in's REALITY
    # fallback and carries `security: none` itself, so it is detected by VLESS
    # presence (not REALITY) and the adapter runs with require_reality=False: it
    # mutates only that inbound's settings.clients[] and never its (absent) REALITY.
    xray_xhttp_adapter = (
        XrayConfigAdapter(
            config_path=settings.xray_config_path,
            service_name=settings.xray_service_name,
            apply_mode=settings.xray_apply_mode,
            inbound_tag=settings.xray_xhttp_inbound_tag,
            allow_restart_on_rollback=settings.xray_allow_restart_on_rollback,
            backup=backup,
            systemctl=systemctl,
            shell=shell,
            stats_server=settings.xray_stats_server,
            helper_runner=helper_runner,
            helper_path=settings.xray_apply_helper_path,
            helper_staging_dir=settings.xray_helper_staging_dir,
            require_reality=False,
            warp_send_through=warp_send_through,
        )
        if vless_inbound_present(settings.xray_config_path, settings.xray_xhttp_inbound_tag)
        else None
    )
    xray_stats_adapter = XrayStatsAdapter(shell=shell, stats_server=settings.xray_stats_server)
    # Hysteria2 Traffic Stats API client — only when the operator configured it
    # (listen + secret). None keeps hy2 traffic/online/kick fully inert.
    hysteria_stats_adapter = (
        HysteriaStatsAdapter(
            listen=settings.hysteria2_stats_listen,
            secret=settings.hysteria2_stats_secret,
        )
        if settings.is_hysteria2_stats_ready()
        else None
    )
    # Loopback /healthz probe for the hy2_auth endpoint. Present whenever Hysteria2
    # is enabled (independent of the Traffic Stats API): it drives the background
    # health loop that marks the Hysteria2 backend degraded/healthy.
    hysteria_health_probe = (
        Hysteria2AuthHealthProbe(auth_listen=settings.hysteria2_auth_listen)
        if settings.hysteria2_enabled
        else None
    )
    awg_adapter = AwgConfigAdapter(
        config_path=settings.awg_config_path,
        interface=settings.awg_interface,
        backup=backup,
        shell=shell,
        persistent_keepalive=settings.awg_persistent_keepalive,
        helper_runner=helper_runner,
        helper_path=settings.awg_apply_helper_path,
        helper_staging_dir=settings.awg_helper_staging_dir,
    )
    ip_allocator = IpAllocator(vpn_keys_repo, settings.awg_network, settings.awg_server_address, awg_config=awg_adapter)
    dante_adapter = DanteUserAdapter(
        shell=shell,
        login_prefix=settings.socks5_login_prefix,
        system_user_shell=settings.socks5_system_user_shell,
        helper_runner=helper_runner,
        helper_path=settings.socks5_user_helper_path,
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
            helper_runner=helper_runner,
            helper_path=settings.mtproto_apply_helper_path,
            helper_staging_dir=settings.mtproto_helper_staging_dir,
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
        xhttp_adapter=xray_xhttp_adapter,
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
    hysteria_service = HysteriaService(
        vpn_keys=vpn_keys_repo,
        users=user_service,
        settings=settings,
        clock=clock,
        ids=ids,
        audit=audit_service,
        modules=protocol_modules_service,
        user_locks=user_locks,
        stats=hysteria_stats_adapter,
    )
    # block_user is reachable by moderators, who are neither superadmin nor the
    # key owner. Wire the *system* revokers (authorisation is already done by
    # block_user) so a moderator-initiated block actually revokes backend access
    # instead of failing with AccessDenied and leaving keys live.
    user_service.attach_key_management(
        vpn_keys_repo,
        {
            VpnKeyType.XRAY: lambda actor, key_id: xray_service.revoke_xray_key_system(
                key_id, actor_user_id=actor, action="xray_key_revoked"
            ),
            VpnKeyType.AWG: lambda actor, key_id: awg_service.revoke_awg_key_system(
                key_id, actor_user_id=actor, action="awg_key_revoked"
            ),
            VpnKeyType.HYSTERIA2: lambda actor, key_id: hysteria_service.revoke_hysteria2_key_system(
                key_id, actor_user_id=actor, action="hysteria2_key_revoked"
            ),
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
            ProxyAccessType.SOCKS5: socks5_service.revoke_socks5_proxy_system,
            ProxyAccessType.MTPROTO: mtproto_service.revoke_mtproto_proxy_system,
        },
    )
    # Disabling a protocol must revoke each key/access on the backend before the
    # DB row is removed — otherwise live access is orphaned with no DB trace.
    protocol_modules_service.attach_purge_handlers(
        users=user_service,
        audit=audit_service,
        vpn_keys=vpn_keys_repo,
        proxy_accesses=proxy_accesses_repo,
        key_purgers={
            VpnKeyType.XRAY: xray_service.delete_xray_key,
            VpnKeyType.AWG: awg_service.delete_awg_key,
            VpnKeyType.HYSTERIA2: hysteria_service.delete_hysteria2_key,
        },
        proxy_purgers={
            ProxyAccessType.SOCKS5: socks5_service.delete_socks5_proxy,
            ProxyAccessType.MTPROTO: mtproto_service.delete_mtproto_proxy,
        },
    )
    notes_service = NotesService(
        vpn_keys=vpn_keys_repo,
        proxies=proxy_repo,
        users=user_service,
        users_repo=users_repo,
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
        hysteria=hysteria_stats_adapter,
    )
    announcement_service = AnnouncementService(
        users=user_service,
        users_repo=users_repo,
        announcements=announcement_repo,
        audit=audit_service,
    )
    key_expiry_service = KeyExpiryService(
        vpn_keys=vpn_keys_repo,
        users=users_repo,
        xray=xray_service,
        awg=awg_service,
        hysteria=hysteria_service,
        audit=audit_service,
        clock=clock,
        notify_days=settings.key_expiry_notify_days,
    )
    # All-in-one subscription bundles. Built on top of the per-protocol services
    # (it never re-implements their create/revoke/delete paths) and inert until
    # SUBSCRIPTION_ENABLED is turned on; nothing calls it yet.
    key_bundle_service = KeyBundleService(
        bundles=KeyBundleRepository(db),
        users=user_service,
        xray=xray_service,
        hysteria=hysteria_service,
        modules=protocol_modules_service,
        settings=settings,
        clock=clock,
        ids=ids,
        audit=audit_service,
        backend_health=backend_health,
    )
    trial_access_service = TrialAccessService(
        trial_requests=trial_requests_repo,
        users_repo=users_repo,
        xray=xray_service,
        awg=awg_service,
        hysteria=hysteria_service,
        audit=audit_service,
        clock=clock,
    )

    # Files bundled into the recovery archive alongside the DB backup so the
    # service can be rebuilt on a clean server: .env (secrets + AWG/MTProto keys),
    # the Xray config (REALITY private key + shortIds), the AWG config (interface
    # private key), and — when present — the managed MTProto secrets and WARP
    # config. Missing/unreadable entries are skipped best-effort at backup time.
    recovery_sources: list[Path] = []
    if settings.offsite_backup_env_path is not None:
        recovery_sources.append(settings.offsite_backup_env_path)
    recovery_sources.append(settings.xray_config_path)
    recovery_sources.append(settings.awg_config_path)
    if settings.mtproto_enabled and settings.mtproto_mode == "managed":
        recovery_sources.append(settings.mtproto_managed_secrets_path)
        recovery_sources.append(settings.mtproto_managed_env_path)
    recovery_sources.append(settings.warp_config_path)
    # Hysteria2 per-key secrets live in vpn.db (already in the DB snapshot) and the
    # obfs/stats secrets in .env, but the hysteria-server config.yaml itself is not
    # otherwise captured. Bundle it so a rebuilt box can restore the hy2 data plane,
    # mirroring the Xray/AWG config backup. Missing file is skipped best-effort.
    if settings.hysteria2_enabled:
        recovery_sources.append(settings.hysteria2_config_path)

    offsite_backup_service = OffsiteBackupService(
        db=db,
        db_path=settings.db_path,
        encryption_key=settings.offsite_backup_encryption_key,
        clock=clock,
        recovery_sources=recovery_sources,
        include_recovery=settings.offsite_backup_include_configs,
    )

    anomaly_detection_service = AnomalyDetectionService(
        vpn_keys=vpn_keys_repo,
        awg=awg_adapter,
        xray_service=xray_service,
        awg_service=awg_service,
        admin_ids=settings.admin_ids,
        window_seconds=settings.anomaly_window_seconds,
        unique_nets=settings.anomaly_unique_nets,
        auto_revoke=settings.anomaly_auto_revoke,
        cooldown_seconds=settings.anomaly_cooldown_seconds,
        xray_access_log_path=settings.xray_access_log_path,
        concurrent_window_seconds=settings.anomaly_concurrent_window_seconds,
        hysteria_stats=hysteria_stats_adapter,
        hysteria_service=hysteria_service,
        hysteria2_max_conn=settings.anomaly_hysteria2_max_conn,
        backend_health=backend_health,
    )

    await audit_service.prune_old_audit_logs(settings.audit_retention_days)

    warp_manager = WarpManager(db=db, settings=settings, shell=shell)
    warp_split_manager = WarpSplitManager(
        list_path=settings.warp_split_list_path,
        apply_helper_path=settings.warp_split_apply_helper_path,
        awg_network=settings.awg_network,
        shell=shell,
        state_helper_path=settings.warp_split_state_helper_path,
        marker_path=settings.warp_split_disabled_marker_path,
        interface_name=settings.warp_interface,
    )

    server_status_service = ServerStatusService()
    server_status_settings_repo = ServerStatusSettingsRepository(db)
    # Restore the persisted detailed-metrics toggle so the sampler resumes
    # (or stays out of) background history collection across restarts.
    server_status_service.set_detailed(await server_status_settings_repo.get())
    maintenance_settings_repo = MaintenanceSettingsRepository(db)
    maintenance_service = MaintenanceService(maintenance_settings_repo, user_service, audit_service)
    # Restore the persisted maintenance flag so the request gate resumes the same
    # state across restarts (e.g. a crash mid-maintenance must not silently reopen).
    await maintenance_service.load()
    online_clients_service = OnlineClientsService(
        awg_adapter=awg_service.adapter,
        xray_stats=xray_stats_adapter,
        hysteria_stats=hysteria_stats_adapter,
    )
    auto_refresh_manager = LiveRefreshManager()

    dashboard_service = DashboardService(
        repo=dashboard_repo,
        access_requests=access_repo,
        trial_requests=trial_requests_repo,
        proxy_accesses=proxy_accesses_repo,
        audit_log=audit_repo,
        backend_health=backend_health,
        warp=warp_manager,
        offsite_backup=offsite_backup_service,
        modules=protocol_modules_service,
        clock=clock,
        db_path=settings.db_path,
    )

    services = Services(
        settings=settings,
        db=db,
        users=user_service,
        access=access_service,
        xray=xray_service,
        awg=awg_service,
        hysteria=hysteria_service,
        proxy=proxy_service,
        socks5=socks5_service,
        mtproto=mtproto_service,
        notes=notes_service,
        vpn_keys=vpn_key_service,
        traffic_stats=traffic_stats_service,
        audit=audit_service,
        announcements=announcement_service,
        backend_health=backend_health,
        key_expiry=key_expiry_service,
        trial_access=trial_access_service,
        offsite_backup=offsite_backup_service,
        anomaly_detection=anomaly_detection_service,
        warp=warp_manager,
        warp_split=warp_split_manager,
        modules=protocol_modules_service,
        dashboard=dashboard_service,
        server_status=server_status_service,
        server_status_settings=server_status_settings_repo,
        online_clients=online_clients_service,
        auto_refresh=auto_refresh_manager,
        maintenance=maintenance_service,
        key_bundles=key_bundle_service,
        hysteria_health_probe=hysteria_health_probe,
    )

    await _startup_reconcile_keys(services)

    bot = Bot(settings.bot_token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    key_expiry_service.bot = bot
    trial_access_service.bot = bot
    anomaly_detection_service.bot = bot
    warp_manager.bot = bot
    # FSM state is in-memory only — bot restart clears in-progress wizards.
    # TTLMemoryStorage expires sessions idle for >30 min via the fsm_cleanup_loop
    # background task started in main.py.
    dp = Dispatcher(storage=TTLMemoryStorage(ttl_seconds=1800))
    dp.workflow_data["services"] = services
    dp.workflow_data["rate_limiter"] = RateLimiter()
    user_service.attach_state_clearer(
        lambda user_id: dp.fsm.get_context(bot=bot, chat_id=user_id, user_id=user_id).clear()
    )

    # Locale runs as the outermost outer-middleware so the user's stored language
    # is active for everything downstream — including the maintenance and blocked
    # banners, which are localized. It does one get_user (the same lookup the
    # blocked gate already performs), so the net DB cost is unchanged. Maintenance
    # then gates the update (short-circuits non-superadmins with the banner before
    # the blocked gate or any handler sees it), and the blocked gate runs last.
    maintenance_middleware = MaintenanceModeMiddleware(maintenance_service, settings)
    blocked_middleware = BlockedUserMiddleware(user_service)
    locale_middleware = LocaleMiddleware(user_service)
    for observer in (
        dp.message,
        dp.callback_query,
        dp.edited_message,
        dp.inline_query,
        dp.channel_post,
        dp.my_chat_member,
    ):
        observer.outer_middleware(locale_middleware)
        observer.outer_middleware(maintenance_middleware)
        observer.outer_middleware(blocked_middleware)

    # Runs after the blocked-user gate so the cleanup only fires for callbacks
    # that are actually about to be handled.
    dp.callback_query.outer_middleware(ConfigDocumentCleanupMiddleware())

    dp.include_router(start.router)
    dp.include_router(common.router)
    dp.include_router(settings_handler.router)
    dp.include_router(admin.router)
    dp.include_router(admin_dashboard.router)
    dp.include_router(admin_warp.router)
    dp.include_router(admin_warp_split.router)
    dp.include_router(admin_warp_split_ui.router)
    dp.include_router(admin_modules.router)
    dp.include_router(admin_maintenance.router)
    dp.include_router(keys.router)
    dp.include_router(proxy.router)
    dp.include_router(callbacks.router)

    return bot, dp, db, backend_health, services


async def _startup_reconcile_keys(services: Services) -> None:
    xray_summary = await _safe_startup_reconcile("Xray", services.xray.startup_reconcile)
    # Sync the running config's client emails to the DB labels after the v28
    # relabel. Idempotent: a no-op (no restart) once they already match; a
    # failure leaves only label drift (connectivity is unaffected — UUIDs are
    # stable) so it never degrades the backend. Optional (getattr-guarded) so
    # lightweight test doubles for the xray service stay valid.
    xray_label_reconcile = getattr(services.xray, "reconcile_email_labels", None)
    xray_label_summary = (
        await _safe_startup_reconcile("Xray labels", xray_label_reconcile)
        if xray_label_reconcile is not None
        else {"checked": 0, "renamed": 0, "failed": 0}
    )
    awg_summary = await _safe_startup_reconcile("AWG", services.awg.startup_reconcile)
    mtproto_reconcile = getattr(getattr(services, "mtproto", None), "reconcile_mtproto_state", None)
    mtproto_summary = (
        await _safe_startup_reconcile("MTProto", mtproto_reconcile, fatal_on_error=True)
        if mtproto_reconcile is not None
        else {"checked": 0, "missing": 0, "orphaned": 0, "pending": 0, "failed": 0, "fatal": 0}
    )
    socks5_reconcile = getattr(getattr(services, "socks5", None), "reconcile_socks5_state", None)
    socks5_summary = (
        await _safe_startup_reconcile("SOCKS5", socks5_reconcile)
        if socks5_reconcile is not None
        else {"checked": 0, "recovered": 0, "failed": 0}
    )
    backend_health = getattr(services, "backend_health", None)
    if backend_health is not None:
        if xray_summary.get("failed", 0):
            backend_health.mark_degraded(VpnKeyType.XRAY, "startup reconciliation failed")
        if awg_summary.get("failed", 0):
            backend_health.mark_degraded(VpnKeyType.AWG, "startup reconciliation failed")
        if mtproto_summary.get("fatal", 0):
            backend_health.mark_degraded(ProxyAccessType.MTPROTO, "startup reconciliation failed")
        if socks5_summary.get("failed", 0):
            backend_health.mark_degraded(ProxyAccessType.SOCKS5, "startup reconciliation failed")
    logger.info(
        "Startup access reconciliation: xray=%s xray_labels=%s awg=%s mtproto=%s socks5=%s",
        xray_summary,
        xray_label_summary,
        awg_summary,
        mtproto_summary,
        socks5_summary,
    )
    # MTProto manages per-user secrets on a live proxy; a fatal reconcile failure means
    # the runtime and DB have drifted in a way the bot cannot safely paper over, so abort
    # startup instead of running degraded (backend already marked degraded above).
    if mtproto_summary.get("fatal", 0):
        raise StartupReconcileError("MTProto startup reconciliation failed; aborting startup")
    any_checked = (
        xray_summary.get("checked", 0)
        or xray_label_summary.get("checked", 0)
        or awg_summary.get("checked", 0)
        or mtproto_summary.get("checked", 0)
        or socks5_summary.get("checked", 0)
    )
    if any_checked:
        try:
            await services.audit.write(
                actor_user_id=None,
                action="startup_reconciliation_completed",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details={
                    "xray": xray_summary,
                    "xray_labels": xray_label_summary,
                    "awg": awg_summary,
                    "mtproto": mtproto_summary,
                    "socks5": socks5_summary,
                },
            )
        except Exception:
            logger.warning("Startup VPN key reconciliation completed, but audit write failed", exc_info=True)


async def _safe_startup_reconcile(name: str, reconcile: Any, *, fatal_on_error: bool = False) -> dict[str, int]:
    try:
        return await reconcile()  # type: ignore[no-any-return]
    except Exception as exc:
        # Log at error (not warning) with the concrete exception type so a real backend
        # outage is diagnosable rather than blending into routine noise. Non-fatal
        # backends still let startup continue; a fatal one signals the abort via
        # summary["fatal"], which _startup_reconcile_keys turns into a StartupReconcileError.
        logger.error(
            "Startup VPN key reconciliation for %s failed (%s); %s",
            name,
            type(exc).__name__,
            "aborting startup" if fatal_on_error else "bot startup continues",
            exc_info=True,
        )
        summary = {"checked": 0, "recovered": 0, "failed": 1}
        if fatal_on_error:
            summary["fatal"] = 1
        return summary
