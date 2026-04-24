from __future__ import annotations

import asyncio
import logging

from bot.app import create_app
from config.settings import load_settings
from utils.logging import setup_logging
from utils.single_instance import SingleInstanceError, SingleInstanceLock

logger = logging.getLogger(__name__)


async def main() -> None:
    settings = load_settings()
    setup_logging(settings.log_dir)
    with SingleInstanceLock(settings.bot_lock_path):
        bot, dp, db = await create_app(settings)
        try:
            await bot.delete_webhook(drop_pending_updates=True)
            logger.info("VPN bot started")
            await dp.start_polling(bot)
        finally:
            await db.close()
            await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SingleInstanceError as exc:
        logger.error("%s", exc)
        raise SystemExit(1) from exc
