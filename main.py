
import asyncio
import ipaddress
import logging
import os

from aiohttp import web

import i18n
from bot.app import StartupReconcileError
from config.settings import SettingsError, load_settings
from utils.logging import setup_logging
from utils.single_instance import SingleInstanceError, SingleInstanceLock

logger = logging.getLogger(__name__)

# Cadence of the background task that expires idle in-memory FSM sessions. Kept next
# to the log line below so the two cannot drift; the per-session TTL lives on the
# TTLMemoryStorage instance (see bot/app.py) and is read back for the log.
FSM_CLEANUP_INTERVAL_SECONDS = 3600


def _is_loopback_host(host: str) -> bool:
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


async def main() -> None:
    settings = load_settings()
    i18n.configure(settings.bot_language)
    setup_logging(settings.log_dir)

    if settings.xray_apply_mode == "api" and os.name == "posix" and os.geteuid() != 0:
        logger.warning(
            "XRAY_APPLY_MODE=api requires root but the bot is running as uid=%d — "
            "Xray key apply operations will fail",
            os.geteuid(),
        )

    from adapters.health_server import create_health_app
    from bot.app import (
        _awg_stats_loop,
        _hysteria_health_loop,
        _hysteria_stats_loop,
        _xray_stats_loop,
        create_app,
    )
    from bot.commands import setup_bot_commands
    from bot.fsm.ttl_storage import TTLMemoryStorage, fsm_cleanup_loop
    from services.anomaly_detection import anomaly_detection_loop
    from services.key_expiry import key_expiry_loop
    from services.offsite_backup import offsite_backup_loop
    from services.scheduled_announcements import scheduled_announcements_loop

    with SingleInstanceLock(settings.bot_lock_path):
        bot, dp, db, backend_health, services = await create_app(settings)
        runner: web.AppRunner | None = None
        awg_stats_task: asyncio.Task[None] | None = None
        xray_stats_task: asyncio.Task[None] | None = None
        hysteria_stats_task: asyncio.Task[None] | None = None
        hysteria_health_task: asyncio.Task[None] | None = None
        expiry_task: asyncio.Task[None] | None = None
        backup_task: asyncio.Task[None] | None = None
        anomaly_task: asyncio.Task[None] | None = None
        scheduled_announcements_task: asyncio.Task[None] | None = None
        fsm_cleanup_task: asyncio.Task[None] | None = None
        server_status_task: asyncio.Task[None] | None = None
        try:
            if isinstance(dp.storage, TTLMemoryStorage):
                fsm_cleanup_task = asyncio.create_task(
                    fsm_cleanup_loop(dp.storage, interval_seconds=FSM_CLEANUP_INTERVAL_SECONDS),
                    name="fsm-cleanup",
                )
                logger.info(
                    "FSM session cleanup started (TTL=%ds, interval=%ds)",
                    getattr(dp.storage, "_ttl", 1800),
                    FSM_CLEANUP_INTERVAL_SECONDS,
                )
            if settings.awg_stats_interval > 0:
                awg_stats_task = asyncio.create_task(
                    _awg_stats_loop(services.traffic_stats, settings.awg_stats_interval),
                    name="awg-stats-collector",
                )
                logger.info("AWG stats collector started (interval=%ds)", settings.awg_stats_interval)
            if settings.xray_stats_interval > 0:
                xray_stats_task = asyncio.create_task(
                    _xray_stats_loop(services.traffic_stats, settings.xray_stats_interval),
                    name="xray-stats-collector",
                )
                logger.info("Xray stats collector started (interval=%ds)", settings.xray_stats_interval)
            if settings.is_hysteria2_stats_ready() and settings.hysteria2_stats_interval > 0:
                hysteria_stats_task = asyncio.create_task(
                    _hysteria_stats_loop(services.traffic_stats, settings.hysteria2_stats_interval),
                    name="hysteria-stats-collector",
                )
                logger.info(
                    "Hysteria2 stats collector started (interval=%ds)", settings.hysteria2_stats_interval
                )
            if services.hysteria_health_probe is not None and settings.hysteria2_health_interval > 0:
                hysteria_health_task = asyncio.create_task(
                    _hysteria_health_loop(
                        services.hysteria_health_probe,
                        backend_health,
                        settings.hysteria2_health_interval,
                    ),
                    name="hysteria-health-probe",
                )
                logger.info(
                    "Hysteria2 health probe started (interval=%ds)", settings.hysteria2_health_interval
                )
            if settings.key_expiry_check_interval > 0:
                expiry_task = asyncio.create_task(
                    key_expiry_loop(services.key_expiry, settings.key_expiry_check_interval),
                    name="key-expiry-checker",
                )
                logger.info("Key expiry checker started (interval=%ds)", settings.key_expiry_check_interval)
            if settings.anomaly_check_interval > 0:
                anomaly_task = asyncio.create_task(
                    anomaly_detection_loop(services.anomaly_detection, settings.anomaly_check_interval),
                    name="anomaly-detector",
                )
                logger.info("Anomaly detector started (interval=%ds)", settings.anomaly_check_interval)
            if settings.offsite_backup_interval > 0 and services.offsite_backup.enabled:
                backup_task = asyncio.create_task(
                    offsite_backup_loop(
                        services.offsite_backup,
                        bot,
                        settings.admin_ids,
                        settings.offsite_backup_interval,
                    ),
                    name="offsite-backup",
                )
                logger.info("Offsite backup scheduler started (interval=%ds)", settings.offsite_backup_interval)
            if settings.scheduled_announcements_interval > 0:
                scheduled_announcements_task = asyncio.create_task(
                    scheduled_announcements_loop(
                        services.announcements, bot, settings.scheduled_announcements_interval
                    ),
                    name="scheduled-announcements",
                )
                logger.info(
                    "Scheduled announcements checker started (interval=%ds)",
                    settings.scheduled_announcements_interval,
                )
            server_status_task = asyncio.create_task(
                services.server_status.run(),
                name="server-status-sampler",
            )
            logger.info("Server status sampler started (continuous /proc sampling)")
            if settings.health_port is not None:
                if not _is_loopback_host(settings.health_host):
                    logger.warning(
                        "Health check endpoint bound to non-loopback host %s — it is unauthenticated; "
                        "expose it off-localhost only behind a trusted proxy/firewall",
                        settings.health_host,
                    )
                health_app = create_health_app(backend_health)
                runner = web.AppRunner(health_app)
                await runner.setup()
                site = web.TCPSite(runner, settings.health_host, settings.health_port)
                await site.start()
                logger.info("Health check endpoint started on port %d", settings.health_port)
            await services.warp.reset_runtime_state()
            if await services.warp.is_enabled():
                try:
                    await services.warp.start()
                    logger.info("WARP routing module autostarted")
                except Exception:
                    logger.warning("WARP routing module autostart failed; continuing", exc_info=True)
            await bot.delete_webhook(drop_pending_updates=settings.bot_drop_pending_updates)
            await setup_bot_commands(bot, settings)
            logger.info("VPN bot started")
            await dp.start_polling(bot)
        finally:
            if fsm_cleanup_task is not None:
                fsm_cleanup_task.cancel()
                await asyncio.gather(fsm_cleanup_task, return_exceptions=True)
            if awg_stats_task is not None:
                awg_stats_task.cancel()
                await asyncio.gather(awg_stats_task, return_exceptions=True)
            if xray_stats_task is not None:
                xray_stats_task.cancel()
                await asyncio.gather(xray_stats_task, return_exceptions=True)
            if hysteria_stats_task is not None:
                hysteria_stats_task.cancel()
                await asyncio.gather(hysteria_stats_task, return_exceptions=True)
            if hysteria_health_task is not None:
                hysteria_health_task.cancel()
                await asyncio.gather(hysteria_health_task, return_exceptions=True)
            if expiry_task is not None:
                expiry_task.cancel()
                await asyncio.gather(expiry_task, return_exceptions=True)
            if backup_task is not None:
                backup_task.cancel()
                await asyncio.gather(backup_task, return_exceptions=True)
            if anomaly_task is not None:
                anomaly_task.cancel()
                await asyncio.gather(anomaly_task, return_exceptions=True)
            if scheduled_announcements_task is not None:
                scheduled_announcements_task.cancel()
                await asyncio.gather(scheduled_announcements_task, return_exceptions=True)
            if server_status_task is not None:
                server_status_task.cancel()
                await asyncio.gather(server_status_task, return_exceptions=True)
            try:
                await services.warp.stop()
            except Exception:
                logger.warning("WARP routing module shutdown failed", exc_info=True)
            if runner is not None:
                try:
                    await runner.cleanup()
                except Exception:
                    logger.warning("Health check endpoint shutdown failed", exc_info=True)
            try:
                await db.close()
            except Exception:
                logger.warning("Database close failed", exc_info=True)
            try:
                await bot.session.close()
            except Exception:
                logger.warning("Bot session close failed", exc_info=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SingleInstanceError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc
    except SettingsError as exc:
        logger.error("Ошибка конфигурации: %s", exc)
        raise SystemExit(1) from exc
    except StartupReconcileError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc
