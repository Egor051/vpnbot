
import asyncio
import hashlib
import ipaddress
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress

from aiohttp import web

from bot.rate_limit import RateLimitExceeded, RateLimiter
from models.dto import Relay
from subscription_server.config import SubscriptionConfig
from subscription_server.render import SubscriptionRenderError, render_subscription
from subscription_server.store import BundleStoreUnavailable, ReadOnlyBundleStore

logger = logging.getLogger(__name__)

# (host, port, timeout seconds) -> did a TCP connection open. Only ever called with
# the probing relay's own address (see _relay_ssh_probe_handler).
ProbeConnect = Callable[[str, int, float], Awaitable[bool]]

_STORE_KEY: web.AppKey[ReadOnlyBundleStore] = web.AppKey("subscription_store", ReadOnlyBundleStore)
_CONFIG_KEY: web.AppKey[SubscriptionConfig] = web.AppKey("subscription_config", SubscriptionConfig)
_LIMITER_KEY: web.AppKey[RateLimiter] = web.AppKey("subscription_limiter", RateLimiter)
# Wall clock (unix seconds) the renderer reads once per response — only the
# rotating spiderX of bundle children depends on it. Injectable for tests.
_CLOCK_KEY: web.AppKey[Callable[[], float]] = web.AppKey("subscription_clock")
# The TCP connect of POST /relay/ssh-probe. Injectable for tests (every test client
# is 127.0.0.1, which the handler refuses to connect to).
_PROBE_CONNECT_KEY: web.AppKey[ProbeConnect] = web.AppKey("relay_probe_connect")

# POST /relay/ssh-probe — main proves to a relay that a NEW TCP connection from the
# outside reaches its SSH ports through the relay's input filter (docs/relay.md).
RELAY_PROBE_PATH = "/relay/ssh-probe"
RELAY_PROBE_MAX_PORTS = 4
RELAY_PROBE_CONNECT_TIMEOUT = 5.0
# Its own limiter bucket, fixed and always on: every accepted probe makes this host
# open up to RELAY_PROBE_MAX_PORTS connections, so the limit must not depend on the
# subscription's SUBSCRIPTION_RATE_LIMIT_* (which may be 0). A relay's apply asks at
# most twice per run.
RELAY_PROBE_RATE_WINDOW_SECONDS = 60
RELAY_PROBE_RATE_BURST = 6

# Tokens are ``secrets.token_urlsafe(32)`` — 43 URL-safe characters. Anything
# outside this shape cannot be a token we issued, so it is rejected before the
# database is touched: a public endpoint must not turn junk paths into queries.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")

# GET /sub reads no body and POST /relay/ssh-probe reads at most a few ports, so cap
# it low: a caller cannot make us buffer anything.
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


def _bucket_tag(bucket: int) -> str:
    """The limiter bucket as a short, stable tag for logs.

    Hex rather than the raw integer so two lines about the same client are easy
    to grep together; it is a hash of the peer address, so it identifies the
    bucket without printing the address itself.
    """
    return f"{bucket:016x}"


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
            burst = config.settings.subscription_rate_limit_burst
            bucket = _client_key(request)
            try:
                # Deliberately BEFORE the token is looked at: a 429 must not
                # depend on whether the token exists, or the refusal itself would
                # answer the one question this endpoint keeps behind its 404.
                limiter.check(bucket, "subscription", cooldown, burst=burst)
            except RateLimitExceeded as exc:
                # The only visible trace of a throttled client. No token and no
                # fingerprint of one: the limit is keyed by peer, so the bucket
                # is all a diagnosis needs, and a rejected request must not put
                # anything token-shaped in the log.
                logger.warning(
                    "subscription: rate limit hit for client %s — %d requests per %ds exhausted, "
                    "answering 429 (Retry-After: %ds)",
                    _bucket_tag(bucket),
                    burst,
                    cooldown,
                    exc.retry_after,
                )
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
            rendered = render_subscription(view, config.settings, clock=request.app[_CLOCK_KEY])
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


async def tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Open a TCP connection to *host*:*port* and close it; True when it opened.

    A connection that opens is the whole answer: nothing is sent or read, so the
    far end (sshd) sees a client that came and went before its banner.
    """
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return False
    writer.close()
    with suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    return True


class _BadProbeRequest(ValueError):
    """The body of a relay's ssh-probe is not 1 to 4 distinct ports in 1..65535."""


def _probe_ports(raw: bytes) -> tuple[int, ...]:
    """The ports of a probe request: a JSON array of 1 to 4 distinct integers, 1..65535."""
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise _BadProbeRequest("body is not JSON") from exc
    if not isinstance(value, list) or not 1 <= len(value) <= RELAY_PROBE_MAX_PORTS:
        raise _BadProbeRequest(f"body must be a JSON array of 1 to {RELAY_PROBE_MAX_PORTS} ports")
    # `type(...) is int`: a JSON true/false is a Python bool, which isinstance() calls an int.
    if not all(type(port) is int and 1 <= port <= 65535 for port in value):
        raise _BadProbeRequest("every port must be an integer in 1..65535")
    if len(set(value)) != len(value):
        raise _BadProbeRequest("ports must be distinct")
    return tuple(value)


def _probe_caller(remote: str | None) -> ipaddress.IPv4Address | None:
    """The peer of a probe as the IPv4 address main may connect back to, or None.

    Relays are IPv4 (their source IPs are IPv4 networks), so an IPv4-mapped IPv6 peer
    is unwrapped and any other IPv6 peer is nobody. Loopback, unspecified, multicast,
    link-local and reserved addresses are refused whatever a relay's source IPs say:
    the probe connects to the caller, and none of those is a relay out there.
    """
    if not remote:
        return None
    try:
        address = ipaddress.ip_address(remote)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is None:
            return None
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
    ):
        return None
    return address


def _relay_of(relays: tuple[Relay, ...], address: ipaddress.IPv4Address) -> Relay | None:
    """The first ENABLED relay whose source IPs cover *address*."""
    for relay in relays:
        if relay.enabled and any(address in network for network in relay.source_ips):
            return relay
    return None


async def _relay_ssh_probe_handler(request: web.Request) -> web.Response:
    """Serve ``POST /relay/ssh-probe``: TCP-connect back to the caller's SSH ports.

    A relay's apply asks this after it installed an input filter that is not
    confirmed yet (scripts/vpn-relay-apply): every port that answers proves that a
    NEW connection from the outside passes the filter — what ``input-confirm`` from
    a new ssh session proves by hand.

    * Rate limit first, keyed by the peer, so a 429 cannot tell a relay from anyone.
    * The peer must be inside the source IPs of an ENABLED relay of the ``relays``
      table, read live; otherwise — and while ``SUBSCRIPTION_ENABLED=false``, and
      on any internal fault — the same empty 404 as every refusal of this server.
    * Only then the body is judged: a JSON array of 1 to 4 distinct ports in 1..65535,
      anything else is an empty 400.
    * The connections go to the caller's own address and nowhere else — no address
      is taken from the body — concurrently, 5 s each. The answer is
      ``{"<port>": "ok" | "fail"}``.
    """
    config: SubscriptionConfig = request.app[_CONFIG_KEY]
    limiter: RateLimiter = request.app[_LIMITER_KEY]
    store: ReadOnlyBundleStore = request.app[_STORE_KEY]
    try:
        bucket = _client_key(request)
        try:
            limiter.check(
                bucket, "relay-ssh-probe", RELAY_PROBE_RATE_WINDOW_SECONDS, burst=RELAY_PROBE_RATE_BURST
            )
        except RateLimitExceeded as exc:
            logger.warning(
                "relay ssh-probe: rate limit hit for client %s — %d requests per %ds exhausted, "
                "answering 429 (Retry-After: %ds)",
                _bucket_tag(bucket),
                RELAY_PROBE_RATE_BURST,
                RELAY_PROBE_RATE_WINDOW_SECONDS,
                exc.retry_after,
            )
            return web.Response(
                status=429, text="", content_type="text/plain", headers={"Retry-After": str(exc.retry_after)}
            )
        if not config.enabled:
            return _not_found()
        caller = _probe_caller(request.remote)
        if caller is None:
            return _not_found()
        try:
            relays = await store.load_relays()
        except BundleStoreUnavailable:
            return _not_found()
        relay = _relay_of(relays.relays, caller)
        if relay is None:
            # Routine for anyone who finds the route: quiet, and no address in the log.
            logger.debug("relay ssh-probe: client %s is no enabled relay — 404", _bucket_tag(bucket))
            return _not_found()
        try:
            ports = _probe_ports(await request.read())
        except (web.HTTPRequestEntityTooLarge, _BadProbeRequest) as exc:
            reason = str(exc) if isinstance(exc, _BadProbeRequest) else "body too large"
            logger.info("relay ssh-probe: relay %s sent a bad request (%s) — 400", relay.name, reason)
            return web.Response(status=400, text="", content_type="text/plain")

        connect = request.app[_PROBE_CONNECT_KEY]
        target = str(caller)
        opened = await asyncio.gather(*(connect(target, port, RELAY_PROBE_CONNECT_TIMEOUT) for port in ports))
        answer = {str(port): ("ok" if ok else "fail") for port, ok in zip(ports, opened, strict=True)}
        logger.info(
            "relay ssh-probe: relay %s — tcp %s",
            relay.name,
            ", ".join(f"{port} {verdict}" for port, verdict in answer.items()),
        )
        return web.Response(
            status=200,
            text=json.dumps(answer, separators=(",", ":")),
            content_type="application/json",
            headers={"Cache-Control": "no-store"},
        )
    except Exception:
        logger.warning("relay ssh-probe: unexpected error — answering 404", exc_info=True)
        return _not_found()


def build_app(
    store: ReadOnlyBundleStore,
    config: SubscriptionConfig,
    *,
    clock: Callable[[], float] = time.time,
    probe_connect: ProbeConnect = tcp_connect,
) -> web.Application:
    """Build the aiohttp app with its two routes, ``GET /sub/{token}`` and
    ``POST /relay/ssh-probe``.

    No health route and no listing route on purpose: anything else on this
    process would be reachable from the internet once the public TLS listener is
    on. The second route answers only the relays of the ``relays`` table, and
    only about their own SSH ports (see :func:`_relay_ssh_probe_handler`).
    """
    install_log_guards()
    app = web.Application(client_max_size=_MAX_BODY_BYTES)
    app[_STORE_KEY] = store
    app[_CONFIG_KEY] = config
    app[_LIMITER_KEY] = RateLimiter()
    app[_CLOCK_KEY] = clock
    app[_PROBE_CONNECT_KEY] = probe_connect
    app.router.add_get("/sub/{token}", _subscription_handler)
    app.router.add_post(RELAY_PROBE_PATH, _relay_ssh_probe_handler)
    return app
