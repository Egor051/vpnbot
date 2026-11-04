
import base64
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from bot.formatters import hysteria2_key_link
from config.settings import Settings
from models.dto import VpnKey
from models.enums import VpnKeyType
from services.key_bundles import subscription_sort_key
from services.key_naming import NameStyle, bundle_name_style, key_display_name, key_member_name
from services.relay import RelayCatalog, RelaySnapshot, relay_available
from services.xray import XrayService
from subscription_server.store import BundleView

logger = logging.getLogger(__name__)

# The display name of each child is built by services.key_naming.key_display_name
# — the same function the bot's per-key screen uses — with the bundle's naming
# rule: an EXTENDED bundle appends the preference circle (🟢 🟡 🟠 🔴, the order to
# try the profiles in), a BASIC bundle names its members like standalone keys
# (``<label>_[<relay label>]<SERVER_FLAG_EMOJI>``, with ``(alt.)`` glued onto the
# Hysteria2 member's name). The circles are confined to extended subscriptions,
# where there is something to rank against.


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
    reads), the relays snapshot of this request (the host and the marker of a
    relay child) and the wall clock the spiderX rotation of bundle children
    reads: the mutation-capable half of the service — repositories, config
    adapters, the audit writer — is left unset, so this object physically cannot
    apply anything to a backend. Any future dependency added to the link builder
    surfaces as an AttributeError, which the endpoint turns into a fail-closed
    404, and is pinned by the drift test that compares this output against a
    fully-constructed XrayService.
    """

    def __init__(
        self,
        settings: Settings,
        unix_clock: Callable[[], float] = time.time,
        relays: RelaySnapshot | None = None,
    ) -> None:
        self.settings = settings
        self.unix_clock = unix_clock
        self.relays = RelayCatalog(relays) if relays is not None else RelayCatalog()

    def member_name(self, key: VpnKey) -> str:
        """The composition seam's name for a provisioned Xray child.

        Resolved through the shared transport/profile lookups (column → payload →
        email label), so a legacy row without the columns still lands on the right
        member instead of silently ranking as ``base``.
        """
        return key_member_name(key)

    def vless_link(self, key: VpnKey, *, now_unix: int, style: NameStyle = NameStyle.EXTENDED) -> str:
        """Render one Xray child exactly as the single-key config view does.

        This path is where "this key is a bundle member" is KNOWN rather than
        guessed — every key reaching it is a child of the bundle being served — so
        it states that to the spiderX seam explicitly. With rotation off the seam
        returns the stored value and the link is the per-key link, byte for byte,
        apart from the display name, which follows the bundle's naming *style*.
        The host follows the child's relay (its relay's ``host`` for a relay child).
        """
        uuid_value = str(key.payload.get("uuid") or key.uuid or "")
        short_id = str(key.payload.get("short_id") or key.public_payload.get("short_id") or "")
        email_label = str(key.payload.get("email_label") or key.email_label or "")
        if not uuid_value or not email_label:
            raise SubscriptionRenderError(f"Xray key {key.id} has no uuid/email_label")
        fingerprint = str(key.payload.get("fingerprint")) if key.payload.get("fingerprint") else None
        return self._build_vless_link(
            uuid_value,
            short_id,
            key_display_name(key, style, self.settings, self.relays.snapshot),
            fingerprint=fingerprint,
            transport=self._key_transport(key),
            profile=self._key_profile(key),
            spider_x=self.link_spider_x(key, bundle_member=True, now_unix=now_unix),
            relay=key.relay,
        )


@dataclass(frozen=True, slots=True)
class RenderedSubscription:
    """The response body (base64) plus the subscription headers that go with it."""

    body: str
    headers: dict[str, str]


def render_links(
    view: BundleView, settings: Settings, *, clock: Callable[[], float] = time.time
) -> tuple[str, ...]:
    """Render every active child of the bundle into its client link.

    Order comes from the composition seam (:func:`services.key_bundles.subscription_sort_key`),
    NOT from the children's ``id`` order: every direct child first, then the
    children of relay #1, relay #2, … in relay order (``relays.id``), each group
    in the composition order. A bundle provisioned before the seam's order last
    changed would otherwise keep serving the old one, and the preference marks
    only read as a ranking when the list is actually sorted by it. Anything the
    seam does not know keeps its relative position at the end of its group.

    The bundle's kind picks the naming rule (:func:`services.key_naming.bundle_name_style`).
    Hosts and relay markers come from ``view.relays`` — the ``relays`` table as
    read for this very request.

    A child whose relay is switched off, deleted or unknown is SKIPPED with a
    warning — the rest of the subscription is still served. That is the one
    deliberate exception to "a child that cannot render fails the whole
    response": switching a relay off is an operator decision, not a corrupt
    row, and must not take the direct links of every relay-carrying bundle down
    with it. Rendering such a child would need a host the bot refuses to invent.

    A protocol that cannot ride a v2ray subscription never reaches here (AWG and
    the proxies are excluded from ``bundle_composition``), so anything else is a
    corrupt row and fails the whole render rather than being skipped.

    *clock* is read ONCE per response: every child is rendered at the same instant,
    which only matters to the rotating spiderX (XRAY_SPIDER_X_ROTATION_HOURS).
    """
    relays = view.relays
    renderer = _VlessLinkRenderer(settings, clock, relays)
    now_unix = renderer.link_instant()
    style = bundle_name_style(view.bundle.kind)
    links: list[str] = []
    for key in _ordered_children(view.keys, relays):
        if key.relay is not None and not relay_available(relays, key.relay):
            logger.warning(
                "subscription: bundle_id=%s skipping child key_id=%s — relay %r is switched off or deleted",
                view.bundle.id,
                key.id,
                key.relay,
            )
            continue
        if key.key_type is VpnKeyType.XRAY:
            links.append(renderer.vless_link(key, now_unix=now_unix, style=style))
        elif key.key_type is VpnKeyType.HYSTERIA2:
            links.append(_hysteria2_link(key, settings, relays, style))
        else:
            raise SubscriptionRenderError(
                f"key {key.id} of type {key.key_type.value} cannot ride a subscription"
            )
    return tuple(links)


def _ordered_children(keys: tuple[VpnKey, ...] | list[VpnKey], relays: RelaySnapshot) -> list[VpnKey]:
    """Sort a bundle's children into the serving order (``sorted`` is stable)."""
    return sorted(keys, key=lambda key: subscription_sort_key(key, relays))


def _hysteria2_link(key: VpnKey, settings: Settings, relays: RelaySnapshot, style: NameStyle) -> str:
    secret = str(key.payload.get("secret") or "")
    label = key.email_label or ""
    if not secret or not label:
        raise SubscriptionRenderError(f"Hysteria2 key {key.id} has no secret/label")
    return hysteria2_key_link(key, settings, relays, style=style)


def render_subscription(
    view: BundleView, settings: Settings, *, clock: Callable[[], float] = time.time
) -> RenderedSubscription:
    """Build the full base64 subscription body and its headers.

    Raises :class:`SubscriptionRenderError` when the bundle has nothing to serve
    or any child fails to render — the caller must translate that into a 404 with
    an empty body, never a partial config and never a 500.
    """
    links = render_links(view, settings, clock=clock)
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
