
import logging

from aiohttp import web

from hy2_auth.store import KeyStoreUnavailable, ReadOnlyKeyStore

logger = logging.getLogger(__name__)

_STORE_KEY: web.AppKey[ReadOnlyKeyStore] = web.AppKey("hy2_store", ReadOnlyKeyStore)


async def _auth_handler(request: web.Request) -> web.Response:
    """Handle one Hysteria2 (apernet v2) auth POST.

    Request body (v2 schema): ``{"addr": "<ip:port>", "auth": "<token>", "tx": <int>}``.
    We use only ``auth`` (the client's single token = our per-key secret); ``tx``
    is ignored. The endpoint ALWAYS replies HTTP 200 — even on rejection, a
    malformed body or an infra fault — with ``{"ok": <bool>, "id": "<label>"}`` so
    Hysteria never sees a 5xx (which it would treat differently). ``ok`` is false
    on any error. The mismatch-vs-infra distinction lives in the store: a wrong
    token is quiet (debug), a broken DB is loud (error + counter), both fail closed.
    """
    store: ReadOnlyKeyStore = request.app[_STORE_KEY]
    try:
        try:
            data = await request.json()
        except Exception:
            logger.debug("hy2_auth: unparseable auth body — rejecting", exc_info=True)
            return web.json_response({"ok": False})
        incoming = data.get("auth") if isinstance(data, dict) else None
        if not isinstance(incoming, str) or not incoming:
            return web.json_response({"ok": False})
        try:
            label = await store.match(incoming)
        except KeyStoreUnavailable:
            # Infra fault: the store already logged it at error and bumped the
            # failure counter. Fail closed without re-logging or surfacing a 5xx.
            return web.json_response({"ok": False})
        if label is not None:
            return web.json_response({"ok": True, "id": label})
        return web.json_response({"ok": False})
    except Exception:
        # Final safety net: anything unexpected still fails closed as a plain
        # rejection so Hysteria never receives a 500.
        logger.warning("hy2_auth: rejecting handshake after unexpected error", exc_info=True)
        return web.json_response({"ok": False})


async def _healthz_handler(request: web.Request) -> web.Response:
    """Liveness/readiness probe: 200 ``{"ok": true}`` when the DB reads, else 503.

    A 503 means the store cannot read vpn.db (locked/corrupt/missing) — exactly
    the condition under which every handshake is failing closed — so an operator
    or systemd watchdog can detect a broken data plane without parsing auth logs.
    """
    store: ReadOnlyKeyStore = request.app[_STORE_KEY]
    healthy = await store.healthcheck()
    return web.json_response({"ok": healthy}, status=200 if healthy else 503)


def build_app(store: ReadOnlyKeyStore) -> web.Application:
    """Build the aiohttp app with the POST /auth and GET /healthz routes."""
    app = web.Application()
    app[_STORE_KEY] = store
    app.router.add_post("/auth", _auth_handler)
    app.router.add_get("/healthz", _healthz_handler)
    return app
