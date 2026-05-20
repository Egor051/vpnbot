
import asyncio
import logging

from aiogram import Bot

from services.announcements import AnnouncementService

logger = logging.getLogger(__name__)


async def scheduled_announcements_loop(service: AnnouncementService, bot: Bot, interval: int) -> None:
    while True:
        try:
            results = await service.check_and_send_due(bot)
            for result in results:
                logger.info(
                    "Scheduled announcement sent: id=%s total=%s success=%s failed=%s",
                    result.announcement_id,
                    result.total,
                    result.success,
                    result.failed,
                )
        except Exception:
            logger.warning("Scheduled announcements job failed", exc_info=True)
        await asyncio.sleep(interval)
