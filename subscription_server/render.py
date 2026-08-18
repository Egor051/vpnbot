
import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from bot.formatters import format_hysteria2_link
from config.settings import Settings
from models.dto import VpnKey
from models.enums import VpnKeyType
from services.key_bundles import subscription_member_order
from services.xray import XrayService
from subscription_server.store import BundleView

logger = logging.getLogger(__name__)

# Preference mark appended to each child's display name inside the subscription,
# so the profile list a client shows is self-explanatory: the colour ranks the
# average speed and latency the member gives, best (green) to worst (red), and
# that is the order the user should try them in. Deliberately confined to the
# subscription — a standalone key is shown one at a time, with nothing to rank it
# against, and its link must stay byte-for-byte what the per-key screen renders.
# Keyed by the composition seam's member names (services.key_bundles.member_name).
_PREFERENCE_MARKS: dict[str, str] = {
    "xray_tcp": "🟢",
    "hysteria2": "🟢",
    "xray_http_base": "🟡",
    "xray_http_multi": "🟠",
    "xray_http_antisib": "🔴",
}


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

    def member_name(self, key: VpnKey) -> str:
        """The composition seam's name for a provisioned Xray child.

        Resolved through the service's own transport/profile lookups (column →
        payload → email label), so a legacy row without the columns still lands on
        the right member instead of silently ranking as ``base``.
        """
        if self._key_transport(key) == "http":
            return f"xray_http_{self._key_profile(key)}"
        return "xray_tcp"

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
            _marked_name(email_label, self.member_name(key)),
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

    Order comes from the composition seam (:func:`subscription_member_order`), NOT
    from the children's ``id`` order: a bundle provisioned before the seam's order
    last changed would otherwise keep serving the old one forever, and the
    preference marks below only read as a ranking when the list is actually sorted
    by it. Anything the seam does not know keeps its relative position at the end.

    A protocol that cannot ride a v2ray subscription never reaches here (AWG and
    the proxies are excluded from ``bundle_composition``), so anything else is a
    corrupt row and fails the whole render rather than being skipped.
    """
    renderer = _VlessLinkRenderer(settings)
    links: list[str] = []
    for key in _ordered_children(view.keys, renderer):
        if key.key_type is VpnKeyType.XRAY:
            links.append(renderer.vless_link(key))
        elif key.key_type is VpnKeyType.HYSTERIA2:
            links.append(_hysteria2_link(key, settings))
        else:
            raise SubscriptionRenderError(
                f"key {key.id} of type {key.key_type.value} cannot ride a subscription"
            )
    return tuple(links)


def _ordered_children(keys: tuple[VpnKey, ...] | list[VpnKey], renderer: _VlessLinkRenderer) -> list[VpnKey]:
    """Sort a bundle's children into the composition order, ties broken by id.

    ``sorted`` is stable and the fallback rank is past the end of the seam, so an
    unknown member (a protocol added to a bundle by a future migration before this
    table learns about it) is appended rather than dropped or crashing the render.
    """
    order = subscription_member_order()
    fallback = len(order)

    def rank(key: VpnKey) -> tuple[int, int]:
        name = _member_name(key, renderer)
        return (order.index(name) if name in order else fallback, key.id)

    return sorted(keys, key=rank)


def _member_name(key: VpnKey, renderer: _VlessLinkRenderer) -> str:
    """Composition-seam name of one provisioned child, whatever its protocol."""
    if key.key_type is VpnKeyType.XRAY:
        return renderer.member_name(key)
    return key.key_type.value


def _marked_name(label: str, member: str) -> str:
    """``<label>_<mark>`` — the display name a subscription client shows.

    Appended to the *name* only (the link's ``#fragment``); the label the backends
    know is untouched, so reconciliation, stats and anomaly detection keep matching
    on it. A member with no mark keeps its bare label.
    """
    mark = _PREFERENCE_MARKS.get(member)
    return f"{label}_{mark}" if mark else label


def _hysteria2_link(key: VpnKey, settings: Settings) -> str:
    secret = str(key.payload.get("secret") or "")
    label = key.email_label or ""
    if not secret or not label:
        raise SubscriptionRenderError(f"Hysteria2 key {key.id} has no secret/label")
    return format_hysteria2_link(
        _marked_name(label, key.key_type.value),
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

    Emitted only when measured: ``upload``/``download`` are the owner's «за всё
    время» totals — the same scope (:data:`~repositories.traffic_scope.ALL_TIME`),
    from the same query, that the personal cabinet and the admin card print on
    their all-time line, so the figure a VPN client shows and the figure the bot
    shows are one number. Deleted keys are included: a counter in a client app is
    read as "what this account has used", and under the «current keys» scope
    deleting a key made that counter go backwards. Omitted entirely when nothing
    has ever been measured for that owner. ``expire`` comes from the children's
    shared expiry. ``total`` is NEVER emitted — this deployment has no traffic
    quota, so any number there would be invented, and clients read a fabricated
    quota as a hard limit.
    """
    parts: list[str] = []
    if view.traffic is not None:
        parts.append(f"upload={view.traffic.uploaded_bytes}")
        parts.append(f"download={view.traffic.downloaded_bytes}")
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
