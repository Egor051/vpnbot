
import asyncio
import logging
import signal

from aiohttp import web

from subscription_server.config import (
    SubscriptionConfig,
    SubscriptionConfigError,
    build_ssl_context,
    load_config,
)
from subscription_server.server import build_app
from subscription_server.store import ReadOnlyBundleStore
from utils.single_instance import SingleInstanceLock

logger = logging.getLogger("subscription_server")


async def _start_sites(runner: web.AppRunner, config: SubscriptionConfig) -> None:
    """Bind the loopback plain-HTTP site and, when configured, the public TLS one.

    The loopback site is unconditional: it is what an operator curls and what a
    future local component would use. The public site exists only when TLS
    material is configured — this process terminates TLS itself (there is no
    reverse proxy in this stack), so "public" and "encrypted" are the same
    switch and a cleartext public port cannot be produced by any configuration.
    """
    site = web.TCPSite(runner, config.bind_host, config.bind_port)
    await site.start()
    logger.info(
        "subscription endpoint listening on %s:%s (db=%s, read-only, enabled=%s)",
        config.bind_host,
        config.bind_port,
        config.db_path,
        config.enabled,
    )
    if not config.enabled:
        # A switched-off feature holds no public socket: while the flag is false
        # every request is a 404 anyway, so a public listener would be pure
        # attack surface with no function. The loopback site above stays up so
        # the unit's state does not flap with the flag.
        logger.info("subscription: public listener not started while SUBSCRIPTION_ENABLED=false")
        return
    ssl_context = build_ssl_context(config)
    if ssl_context is None:
        if config.public_port:  # pragma: no cover - load_config refuses this combination
            logger.error("subscription: public port set without TLS material — public listener NOT started")
        return
    # host=None binds every interface (v4 + v6); the port must be opened in ufw
    # via deploy/ufw-subscription.sh.
    public = web.TCPSite(runner, None, config.public_port, ssl_context=ssl_context)
    await public.start()
    logger.info("subscription endpoint listening on :%s (HTTPS, cert=%s)", config.public_port, config.tls_cert)


async def _run(config: SubscriptionConfig) -> None:
    if not config.enabled:
        # Deliberately still binds: the route answers 404 while the flag is off,
        # so flipping SUBSCRIPTION_ENABLED needs a restart, not an install, and
        # the unit's active state does not flap with the feature flag.
        logger.warning("SUBSCRIPTION_ENABLED=false — every request will be answered with 404")
    store = ReadOnlyBundleStore(config.db_path)
    await store.connect()
    app = build_app(store, config)
    # access_log=None is a security control, not tidiness: aiohttp's access log
    # prints the request line, and the request line contains the subscription
    # token. It must never reach a log file.
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    try:
        await _start_sites(runner, config)

        # systemd stops the unit with SIGTERM; without handlers the default
        # action kills the process outright and the cleanup below never runs.
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop.set)
            except NotImplementedError:  # pragma: no cover - non-Unix fallback
                signal.signal(sig, lambda *_: stop.set())
        await stop.wait()
        logger.info("subscription endpoint shutting down")
    finally:
        await runner.cleanup()
        await store.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        config = load_config()
    except SubscriptionConfigError as exc:
        # A misconfigured endpoint stops HERE, loudly, instead of starting in a
        # weaker posture (e.g. a public port without TLS).
        logger.error("subscription endpoint refuses to start: %s", exc)
        raise SystemExit(1) from exc
    try:
        # One endpoint per host: two instances would race for the same loopback
        # port anyway, and the lock turns that into a clear message instead of an
        # EADDRINUSE traceback (and still catches two differently-bound copies).
        with SingleInstanceLock(config.lock_path):
            asyncio.run(_run(config))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
