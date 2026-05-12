
import asyncio

from config.settings import load_settings
from db.database import Database


async def main() -> None:
    settings = load_settings()
    db = Database(settings.db_path, synchronous=settings.sqlite_synchronous)
    await db.connect()
    try:
        await db.bootstrap()
    finally:
        await db.close()
    print(f"SQLite schema is ready: {settings.db_path}")


if __name__ == "__main__":
    asyncio.run(main())
