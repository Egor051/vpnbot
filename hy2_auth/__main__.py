
import asyncio
import logging
import signal

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

    # systemd stops the unit with SIGTERM. Without a handler the default action
    # terminates the process abruptly, so the finally-block below would never run
    # on a normal `systemctl stop`. Install handlers that simply unblock the wait
    # so the runner/store get cleaned up gracefully. (The connection is read-only,
    # so an abrupt stop was harmless — but a dead finally is misleading.)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - non-Unix fallback
            signal.signal(sig, lambda *_: stop.set())
    try:
        await stop.wait()  # run until SIGTERM/SIGINT
        logger.info("hy2_auth shutting down")
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
