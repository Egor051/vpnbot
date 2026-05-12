
import asyncio
import logging

from aiohttp import web

from adapters.health_server import create_health_app
from bot.app import create_app
from config.settings import load_settings
from utils.logging import setup_logging
from utils.single_instance import SingleInstanceError, SingleInstanceLock

logger = logging.getLogger(__name__)


async def main() -> None:
    settings = load_settings()
    setup_logging(settings.log_dir)
    with SingleInstanceLock(settings.bot_lock_path):
        bot, dp, db, backend_health = await create_app(settings)
        runner: web.AppRunner | None = None
        try:
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
