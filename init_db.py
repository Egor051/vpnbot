
import asyncio

from config.settings import Settings, SettingsError, load_settings
from db.database import Database
from utils.single_instance import SingleInstanceError, SingleInstanceLock


async def _bootstrap(settings: Settings) -> None:
    db = Database(settings.db_path, synchronous=settings.sqlite_synchronous)
    await db.connect()
    try:
        await db.bootstrap()
    finally:
        await db.close()


async def main() -> None:
    settings = load_settings()
    # Hold the same lock the bot uses so manual schema bootstrap cannot run
    # concurrently with a live bot writing to the same SQLite database.
    with SingleInstanceLock(settings.bot_lock_path):
        await _bootstrap(settings)
    print(f"SQLite schema is ready: {settings.db_path}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SingleInstanceError as exc:
        raise SystemExit(f"init_db: {exc}") from exc
    except SettingsError as exc:
        raise SystemExit(f"init_db: ошибка конфигурации: {exc}") from exc
