
import logging

from aiohttp import web

from hy2_auth.store import ReadOnlyKeyStore

logger = logging.getLogger(__name__)

_STORE_KEY: web.AppKey[ReadOnlyKeyStore] = web.AppKey("hy2_store", ReadOnlyKeyStore)


async def _auth_handler(request: web.Request) -> web.Response:
    """Handle one Hysteria2 (apernet v2) auth POST.

    Request body (v2 schema): ``{"addr": "<ip:port>", "auth": "<token>", "tx": <int>}``.
    We use only ``auth`` (the client's single token = our per-key secret); ``tx``
    is ignored. The endpoint ALWAYS replies HTTP 200 — even on rejection or a
    malformed body — with ``{"ok": <bool>, "id": "<label>"}`` so Hysteria never
    sees a 5xx (which it would treat differently). ``ok`` is false on any error.
    """
    store: ReadOnlyKeyStore = request.app[_STORE_KEY]
    try:
        data = await request.json()
        incoming = data.get("auth") if isinstance(data, dict) else None
        if not isinstance(incoming, str) or not incoming:
            return web.json_response({"ok": False})
        label = await store.match(incoming)
        if label is not None:
            return web.json_response({"ok": True, "id": label})
        return web.json_response({"ok": False})
    except Exception:
        # Never surface a 500 to Hysteria: a broken body, DB hiccup or anything
        # else fails closed as a plain rejection.
        logger.warning("hy2_auth: rejecting handshake after error", exc_info=True)
        return web.json_response({"ok": False})


def build_app(store: ReadOnlyKeyStore) -> web.Application:
    """Build the aiohttp app with the single POST /auth route."""
    app = web.Application()
    app[_STORE_KEY] = store
    app.router.add_post("/auth", _auth_handler)
    return app
