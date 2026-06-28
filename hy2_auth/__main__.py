
import asyncio
import logging

from aiohttp import web

from hy2_auth.config import load_config
from hy2_auth.server import build_app
from hy2_auth.store import ReadOnlyKeyStore

logger = logging.getLogger("hy2_auth")


async def _run() -> None:
    config = load_config()
    store = ReadOnlyKeyStore(config.db_path)
    await store.connect()
    app = build_app(store)
    runner = web.AppRunner(app)
    await runner.setup()
    # config.host is guaranteed loopback by parse_loopback_listen().
    site = web.TCPSite(runner, config.host, config.port)
    await site.start()
    logger.info("hy2_auth listening on %s:%s (db=%s, read-only)", config.host, config.port, config.db_path)
    try:
        await asyncio.Event().wait()  # run until cancelled / process killed
    finally:
        await runner.cleanup()
        await store.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
