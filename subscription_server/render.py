
import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from bot.formatters import format_hysteria2_link
from config.settings import Settings
from models.dto import VpnKey
from models.enums import VpnKeyType
from services.xray import XrayService
from subscription_server.store import BundleView

logger = logging.getLogger(__name__)


class SubscriptionRenderError(RuntimeError):
    """A child key could not be rendered into a client link.

    Always fatal for the whole response: a subscription that silently drops the
    protocol whose row was malformed would leave the user with a working-looking
    profile that is missing exactly the transport they needed. The endpoint
    answers 404 instead, so the client keeps the profile it already has.
    """


class _VlessLinkRenderer(XrayService):
    """Reuse of the single source of truth for the ``vless://`` link format.

    ``XrayService._build_vless_link`` is what the per-key path renders, and a
    subscription link that differs from it — by one REALITY parameter, one xhttp
    ``extra`` field, one missing ``spx`` — is a key that connects from the bot's
    message and fails from the sub-URL. So this subclass calls that method rather
    than restating the format.

    It deliberately initialises ONLY ``settings`` (all ``_build_vless_link``
    reads): the mutation-capable half of the service — repositories, config
    adapters, the audit writer — is left unset, so this object physically cannot
    apply anything to a backend. Any future dependency added to the link builder
    surfaces as an AttributeError, which the endpoint turns into a fail-closed
    404, and is pinned by the drift test that compares this output against a
    fully-constructed XrayService.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def vless_link(self, key: VpnKey) -> str:
        """Render one Xray child exactly as the single-key config view does."""
        uuid_value = str(key.payload.get("uuid") or key.uuid or "")
        short_id = str(key.payload.get("short_id") or key.public_payload.get("short_id") or "")
        email_label = str(key.payload.get("email_label") or key.email_label or "")
        if not uuid_value or not email_label:
            raise SubscriptionRenderError(f"Xray key {key.id} has no uuid/email_label")
        fingerprint = str(key.payload.get("fingerprint")) if key.payload.get("fingerprint") else None
        return self._build_vless_link(
            uuid_value,
            short_id,
            email_label,
            fingerprint=fingerprint,
            transport=self._key_transport(key),
            profile=self._key_profile(key),
            spider_x=self._key_spider_x(key),
        )


@dataclass(frozen=True, slots=True)
class RenderedSubscription:
    """The response body (base64) plus the subscription headers that go with it."""

    body: str
    headers: dict[str, str]


def render_links(view: BundleView, settings: Settings) -> tuple[str, ...]:
    """Render every active child of the bundle into its client link.

    Order follows creation order (``list_keys_of_bundle`` is ``ORDER BY id``),
    which is the composition order — VLESS (TCP), the XHTTP profiles, Hysteria2.
    A protocol that cannot ride a v2ray subscription never reaches here (AWG and
    the proxies are excluded from ``bundle_composition``), so anything else is a
    corrupt row and fails the whole render rather than being skipped.
    """
    renderer = _VlessLinkRenderer(settings)
    links: list[str] = []
    for key in view.keys:
        if key.key_type is VpnKeyType.XRAY:
            links.append(renderer.vless_link(key))
        elif key.key_type is VpnKeyType.HYSTERIA2:
            links.append(_hysteria2_link(key, settings))
        else:
            raise SubscriptionRenderError(
                f"key {key.id} of type {key.key_type.value} cannot ride a subscription"
            )
    return tuple(links)


def _hysteria2_link(key: VpnKey, settings: Settings) -> str:
    secret = str(key.payload.get("secret") or "")
    label = key.email_label or ""
    if not secret or not label:
        raise SubscriptionRenderError(f"Hysteria2 key {key.id} has no secret/label")
    return format_hysteria2_link(
        label,
        secret,
        host=settings.hysteria2_host,
        port=settings.hysteria2_port,
        sni=settings.hysteria2_sni,
        insecure=settings.hysteria2_insecure,
    )


def render_subscription(view: BundleView, settings: Settings) -> RenderedSubscription:
    """Build the full base64 subscription body and its headers.

    Raises :class:`SubscriptionRenderError` when the bundle has nothing to serve
    or any child fails to render — the caller must translate that into a 404 with
    an empty body, never a partial config and never a 500.
    """
    links = render_links(view, settings)
    if not links:
        raise SubscriptionRenderError(f"bundle {view.bundle.id} has no active children")
    body = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    return RenderedSubscription(body=body, headers=_headers(view, settings))


def _headers(view: BundleView, settings: Settings) -> dict[str, str]:
    headers = {
        "Profile-Title": _profile_title(view.bundle.label),
        "Profile-Update-Interval": str(settings.subscription_update_interval_hours),
    }
    userinfo = _subscription_userinfo(view)
    if userinfo:
        headers["Subscription-Userinfo"] = userinfo
    return headers


def _profile_title(label: str) -> str:
    """The bundle's own display label, base64-wrapped only if it is not ASCII.

    ``base64:``-prefixed titles are the client-side convention for non-ASCII
    names; bot-generated labels (``bundle_XXXXX``) never need it, but a
    hand-edited label must not break the header encoding.
    """
    if label.isascii() and label.isprintable():
        return label
    return "base64:" + base64.b64encode(label.encode("utf-8")).decode("ascii")


def _subscription_userinfo(view: BundleView) -> str:
    """Build ``Subscription-Userinfo`` from values that actually exist.

    Emitted only when measured: ``upload``/``download`` come from the traffic
    counters the bot collected for the children (omitted entirely when no child
    has ever been measured), ``expire`` from their shared expiry. ``total`` is
    NEVER emitted — this deployment has no traffic quota, so any number there
    would be invented, and clients read a fabricated quota as a hard limit.
    """
    parts: list[str] = []
    if view.traffic:
        parts.append(f"upload={sum(stats.uploaded_bytes for stats in view.traffic)}")
        parts.append(f"download={sum(stats.downloaded_bytes for stats in view.traffic)}")
    expire = _expire_timestamp(view.expires_at)
    if expire is not None:
        parts.append(f"expire={expire}")
    return "; ".join(parts)


def _expire_timestamp(expires_at: str | None) -> int | None:
    """Convert the stored ISO expiry into the unix seconds clients expect.

    Naive timestamps are read as UTC (the clock provider writes UTC). An
    unparseable value yields None — the header simply omits ``expire`` rather
    than advertising a wrong expiry date.
    """
    if not expires_at:
        return None
    try:
        parsed = datetime.fromisoformat(expires_at)
    except ValueError:
        logger.warning("subscription: unparseable expires_at on a bundle child — omitting expire")
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())
