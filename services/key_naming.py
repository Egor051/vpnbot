"""Display names of VPN keys — the ``#fragment`` a client shows for a link.

There is exactly ONE function that assembles a display name,
:func:`key_display_name`, and every path that puts a key's name into a link goes
through it: the bot's config screen and QR (single key), the create wizard, the
cached ``public_payload.link``, and the subscription renderer (both bundle
kinds). Nothing assembles a name in place, so the rules below cannot drift
between the per-key screen and the subscription.

The name is display-only. ``email_label`` — Xray's client email, the hy2 auth
id, the key the traffic stats and anomaly detection match on — is never
changed; the name is derived from it at render time.

Rules (``[_<relay label>]`` is present only for a relay key, and is the
``label`` of its relay as the admin panel set it — ``relay`` by default):

* standalone key (link / QR / delivery outside a subscription):
  ``<label>[_<relay label>]_<SERVER_FLAG_EMOJI>`` — e.g. ``xray_tcp_ab12c_🇫🇮``
  or ``xray_tcp_ab12c_relay_🇫🇮``;
* member of a **basic** subscription: the same as a standalone key, except that a
  Hysteria2 member also ends with :data:`BASIC_ALT_SUFFIX` glued on with no
  separator — e.g. ``hy2_x7k2p_🇫🇮(alt.)`` — marking it as the alternative
  to VLESS (TCP);
* member of an **extended** subscription: ``<label>[_<relay label>]_<mark>``,
  where the mark is the preference circle of the member (no flag). A relay member
  gets the circle of its direct twin, because the circle is keyed by
  transport/profile.

This module deliberately imports nothing from ``bot`` or the per-protocol
services, so all of them — and the standalone subscription process — can use it
without an import cycle. The transport/profile resolution that the member name
needs lives here for the same reason; :class:`services.xray.XrayService`
delegates to it.
"""

from __future__ import annotations

from enum import StrEnum

from config.settings import Settings
from models.dto import VpnKey
from models.enums import KeyBundleKind, VpnKeyType
from services.relay import RelaySnapshot, relay_marker

# XHTTP client transport profiles (see services.xray for what each one tunes).
# Defined here, re-exported by services.xray, so the naming code and the link
# builder share one list.
XHTTP_PROFILES: tuple[str, ...] = ("base", "multi", "antisib")
XHTTP_DEFAULT_PROFILE = "base"

# Preference circle per composition member, used only by the EXTENDED style: the
# colour ranks the average speed and latency the member gives, best (green) to
# worst (red), which is the order the subscription lists them in and the order
# the user should try them in. Keyed by the composition seam's member names
# (services.key_bundles.member_name / :func:`key_member_name`).
PREFERENCE_MARKS: dict[str, str] = {
    "xray_tcp": "🟢",
    "hysteria2": "🟢",
    "xray_http_base": "🟡",
    "xray_http_multi": "🟠",
    "xray_http_antisib": "🔴",
}

# Tail of a Hysteria2 member's name in a BASIC subscription. Both members of a
# basic subscription carry the same flag, so without it nothing in the client
# says which one to try first; hy2 is the alternative to VLESS (TCP). Appended
# as is — no underscore, no space.
BASIC_ALT_SUFFIX = "(alt.)"


class NameStyle(StrEnum):
    """Which naming rule a rendered link follows."""

    # A key shown on its own: config screen, QR, create wizard, cached link.
    SINGLE = "single"
    # A member of a basic all-in-one subscription.
    BASIC = "basic"
    # A member of an extended all-in-one subscription.
    EXTENDED = "extended"


def bundle_name_style(kind: KeyBundleKind) -> NameStyle:
    """The naming rule the children of a bundle of *kind* are served with."""
    return NameStyle.BASIC if kind is KeyBundleKind.BASIC else NameStyle.EXTENDED


def normalize_transport(value: object) -> str:
    """Map any stored/requested transport to the canonical 'tcp' or 'http'."""
    return "http" if str(value or "").strip().lower() == "http" else "tcp"


def normalize_profile(value: object) -> str:
    """Map any stored/requested XHTTP profile to a known one (default base)."""
    profile = str(value or "").strip().lower()
    return profile if profile in XHTTP_PROFILES else XHTTP_DEFAULT_PROFILE


def key_transport(key: VpnKey) -> str:
    """A key's VLESS transport: the DB column, falling back to the payload."""
    return normalize_transport(getattr(key, "transport", None) or key.payload.get("transport"))


def key_profile(key: VpnKey) -> str:
    """A key's XHTTP profile: the column, then the payload, then the email prefix.

    The label fallback keeps a legacy row without the column on its real profile
    instead of silently reading as ``base``.
    """
    raw = getattr(key, "xhttp_profile", None) or key.payload.get("xhttp_profile")
    if raw:
        return normalize_profile(raw)
    label = str(getattr(key, "email_label", None) or key.payload.get("email_label") or "")
    for profile in XHTTP_PROFILES:
        if label.startswith(f"xray_http_{profile}_"):
            return profile
    return XHTTP_DEFAULT_PROFILE


def key_member_name(key: VpnKey) -> str:
    """The composition seam's member name of a provisioned key.

    ``xray_tcp`` / ``xray_http_<profile>`` / ``hysteria2``. A relay key has the
    same member name as its direct twin — relay is an attribute, not a member
    type — which is what gives the twin's circle to a relay member.
    """
    if key.key_type is VpnKeyType.XRAY:
        if key_transport(key) == "http":
            return f"xray_http_{key_profile(key)}"
        return "xray_tcp"
    return key.key_type.value


def key_label(key: VpnKey) -> str:
    """The stored label the display name starts from (never modified)."""
    if key.key_type is VpnKeyType.XRAY:
        return str(key.payload.get("email_label") or key.email_label or "")
    return str(key.email_label or key.payload.get("email_label") or "")


def key_display_name(key: VpnKey, style: NameStyle, settings: Settings, relays: RelaySnapshot) -> str:
    """THE display name of *key* in a link rendered with *style*.

    The relay marker is the ``label`` of the key's relay in *relays*; a key whose
    relay is deleted or unknown raises :class:`services.relay.RelayUnavailable`,
    exactly as rendering its host would a moment later.

    Returns ``""`` for a key with no label at all, so each link builder keeps
    its own historical fallback for that corrupt case.
    """
    label = key_label(key)
    if not label:
        return ""
    base = f"{label}_{relay_marker(relays, key.relay)}" if key.relay else label
    if style is NameStyle.EXTENDED:
        mark = PREFERENCE_MARKS.get(key_member_name(key))
        return f"{base}_{mark}" if mark else base
    name = f"{base}_{settings.server_flag_emoji}"
    if style is NameStyle.BASIC and key.key_type is VpnKeyType.HYSTERIA2:
        return f"{name}{BASIC_ALT_SUFFIX}"
    return name
