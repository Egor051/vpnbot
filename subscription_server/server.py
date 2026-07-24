
import hashlib
import logging
import re

from aiohttp import web

from bot.rate_limit import RateLimitExceeded, RateLimiter
from subscription_server.config import SubscriptionConfig
from subscription_server.render import SubscriptionRenderError, render_subscription
from subscription_server.store import BundleStoreUnavailable, ReadOnlyBundleStore

logger = logging.getLogger(__name__)

_STORE_KEY: web.AppKey[ReadOnlyBundleStore] = web.AppKey("subscription_store", ReadOnlyBundleStore)
_CONFIG_KEY: web.AppKey[SubscriptionConfig] = web.AppKey("subscription_config", SubscriptionConfig)
_LIMITER_KEY: web.AppKey[RateLimiter] = web.AppKey("subscription_limiter", RateLimiter)

# Tokens are ``secrets.token_urlsafe(32)`` — 43 URL-safe characters. Anything
# outside this shape cannot be a token we issued, so it is rejected before the
# database is touched: a public endpoint must not turn junk paths into queries.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

# Nothing about this endpoint reads a request body, so cap it low: a caller
# cannot make us buffer anything.
_MAX_BODY_BYTES = 4 * 1024


def token_fingerprint(token: str) -> str:
    """A short, non-reversible tag for logs.

    The token IS the credential: logging it (or letting aiohttp's access log
    print the request line, which is why the runner disables that log) would put
    working subscription URLs in a file that is rotated, backed up and read over
    someone's shoulder. Twelve hex chars of SHA-256 are enough to correlate two
    log lines and useless to an attacker.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


class _TokenRedactingFilter(logging.Filter):
    """Rewrites ``/sub/<token>`` into ``/sub/<redacted:fingerprint>`` in a record.

    Attached to ``aiohttp.access``, whose format string contains the request line
    — i.e. the token in full, on a logger this package does not control.
    """

    _PATH_RE = re.compile(r"/sub/([A-Za-z0-9_-]{16,128})")

    def _redact(self, value: str) -> str:
        return self._PATH_RE.sub(lambda m: f"/sub/<redacted:{token_fingerprint(m.group(1))}>", value)

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str) and "/sub/" in record.msg:
            record.msg = self._redact(record.msg)
        if record.args and isinstance(record.args, tuple):
            record.args = tuple(
                self._redact(arg) if isinstance(arg, str) and "/sub/" in arg else arg
                for arg in record.args
            )
        return True


def install_log_guards() -> None:
    """Make it impossible for this process to print a subscription token.

    Two loggers outside this package would otherwise do exactly that, and both
    are easy to re-enable by accident (a debug session, a changed runner), so the
    guard lives with the app rather than with one call site:

    * ``aiohttp.access`` logs the request line — the token is in the URL. The
      runner also passes ``access_log=None``; this filter is what holds if that
      ever changes.
    * ``aiosqlite`` logs every statement WITH ITS BOUND PARAMETERS at DEBUG, and
      the token is a bound parameter of the bundle lookup. Pinned to INFO.

    Idempotent: re-running it adds no duplicate filter.
    """
    access = logging.getLogger("aiohttp.access")
    if not any(isinstance(existing, _TokenRedactingFilter) for existing in access.filters):
        access.addFilter(_TokenRedactingFilter())
    logging.getLogger("aiosqlite").setLevel(max(logging.getLogger("aiosqlite").level, logging.INFO))


def _client_key(request: web.Request) -> int:
    """Stable integer bucket for the rate limiter, derived from the peer address."""
    remote = request.remote or "unknown"
    return int.from_bytes(hashlib.sha256(remote.encode("utf-8")).digest()[:8], "big")


def _not_found() -> web.Response:
    """The single negative answer: empty 404, identical in every rejection case.

    Unknown token, revoked bundle, deleted bundle, disabled feature and internal
    fault all land here, so the response can never be used to tell a token that
    exists from one that does not, nor a revoked subscription from a typo.
    """
    return web.Response(status=404, text="", content_type="text/plain")


async def _subscription_handler(request: web.Request) -> web.Response:
    """Serve ``GET /sub/{token}``: the bundle's links, base64, or a bare 404.

    Fail-closed by construction — every failure path returns the same empty 404,
    and the only 200 is one that carries a fully rendered set of links. The
    endpoint never emits a 5xx (a traceback would leak internals to the
    internet), never a partial config, and never the token itself into the log.
    """
    store: ReadOnlyBundleStore = request.app[_STORE_KEY]
    config: SubscriptionConfig = request.app[_CONFIG_KEY]
    limiter: RateLimiter = request.app[_LIMITER_KEY]
    try:
        cooldown = config.settings.subscription_rate_limit_seconds
        if cooldown > 0:
            try:
                limiter.check(_client_key(request), "subscription", cooldown)
            except RateLimitExceeded as exc:
                return web.Response(
                    status=429,
                    text="",
                    content_type="text/plain",
                    headers={"Retry-After": str(exc.retry_after)},
                )

        if not config.enabled:
            # The flag has teeth here too: with SUBSCRIPTION_ENABLED=false the
            # route exists (so the unit does not flap on a toggle) but resolves
            # nothing and never reads the database.
            logger.debug("subscription: request while SUBSCRIPTION_ENABLED=false — 404")
            return _not_found()

        token = request.match_info.get("token", "")
        # fullmatch, not match: `$` alone would also accept a trailing newline.
        if not _TOKEN_RE.fullmatch(token):
            return _not_found()
        fingerprint = token_fingerprint(token)

        try:
            view = await store.load_active_bundle(token)
        except BundleStoreUnavailable:
            # Already error-logged and counted by the store; fail closed quietly.
            return _not_found()
        if view is None:
            logger.debug("subscription: token %s resolves to no active bundle", fingerprint)
            return _not_found()

        try:
            rendered = render_subscription(view, config.settings)
        except SubscriptionRenderError as exc:
            # A malformed/incomplete child: serve nothing rather than a
            # subscription that is quietly missing a protocol.
            logger.error(
                "subscription: bundle_id=%s (token %s) failed to render — serving 404: %s",
                view.bundle.id,
                fingerprint,
                exc,
            )
            return _not_found()

        headers = dict(rendered.headers)
        # The body is a live credential set: never let a proxy or the client
        # store it beyond the request.
        headers["Cache-Control"] = "no-store"
        logger.info(
            "subscription: served bundle_id=%s (token %s) with %d links",
            view.bundle.id,
            fingerprint,
            len(view.keys),
        )
        return web.Response(status=200, text=rendered.body, content_type="text/plain", headers=headers)
    except Exception:
        # Final safety net: an unexpected fault still leaves as a plain 404, so
        # aiohttp never renders a 500 with a traceback to an internet client.
        logger.warning("subscription: unexpected error — answering 404", exc_info=True)
        return _not_found()


def build_app(store: ReadOnlyBundleStore, config: SubscriptionConfig) -> web.Application:
    """Build the aiohttp app with its ONE route, ``GET /sub/{token}``.

    No health route and no listing route on purpose: anything else on this
    process would be reachable from the internet once the public TLS listener is
    on, and the endpoint's whole job is to answer exactly one question.
    """
    install_log_guards()
    app = web.Application(client_max_size=_MAX_BODY_BYTES)
    app[_STORE_KEY] = store
    app[_CONFIG_KEY] = config
    app[_LIMITER_KEY] = RateLimiter()
    app.router.add_get("/sub/{token}", _subscription_handler)
    return app
