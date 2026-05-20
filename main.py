
import asyncio
import logging

from aiohttp import web

from adapters.health_server import create_health_app
from bot.app import _awg_stats_loop, create_app
from services.anomaly_detection import anomaly_detection_loop
from services.key_expiry import key_expiry_loop
from services.offsite_backup import offsite_backup_loop
from services.scheduled_announcements import scheduled_announcements_loop
from config.settings import load_settings
from utils.logging import setup_logging
from utils.single_instance import SingleInstanceError, SingleInstanceLock

logger = logging.getLogger(__name__)


async def main() -> None:
    settings = load_settings()
    setup_logging(settings.log_dir)
    with SingleInstanceLock(settings.bot_lock_path):
        bot, dp, db, backend_health, services = await create_app(settings)
        runner: web.AppRunner | None = None
        awg_stats_task: asyncio.Task | None = None
        expiry_task: asyncio.Task | None = None
        backup_task: asyncio.Task | None = None
        anomaly_task: asyncio.Task | None = None
        scheduled_announcements_task: asyncio.Task | None = None
        try:
            if settings.awg_stats_interval > 0:
                awg_stats_task = asyncio.create_task(
                    _awg_stats_loop(services.traffic_stats, settings.awg_stats_interval),
                    name="awg-stats-collector",
                )
                logger.info("AWG stats collector started (interval=%ds)", settings.awg_stats_interval)
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
            if services.announcements.announcements is not None:
                scheduled_announcements_task = asyncio.create_task(
                    scheduled_announcements_loop(services.announcements, bot, 60),
                    name="scheduled-announcements",
                )
                logger.info("Scheduled announcements checker started (interval=60s)")
            if settings.health_port is not None:
                health_app = create_health_app(backend_health)
                runner = web.AppRunner(health_app)
                await runner.setup()
                site = web.TCPSite(runner, settings.health_host, settings.health_port)
                await site.start()
                logger.info("Health check endpoint started on port %d", settings.health_port)
            await bot.delete_webhook(drop_pending_updates=settings.bot_drop_pending_updates)
            logger.info("VPN bot started")
            await dp.start_polling(bot)
        finally:
            if awg_stats_task is not None:
                awg_stats_task.cancel()
                await asyncio.gather(awg_stats_task, return_exceptions=True)
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
            if runner is not None:
                await runner.cleanup()
            await db.close()
            await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SingleInstanceError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc
