"""UI layer for all-in-one subscription bundles: the flag gate, the sub-URL and
every piece of text the bundle screens render.

Why not ``bot/formatters.py``: that module is the *single-key* view and the
subscription endpoint renders links with it, so it is deliberately frozen by this
PR. Bundle text lives here instead and reuses the formatter helpers read-only
(``key_type_label``, ``create_type_label``, …) so a bundle card and a key card
cannot drift apart.

Everything below is inert while ``SUBSCRIPTION_ENABLED`` is false: the create menu
does not offer the option, the key list does not render the group, and
:func:`require_subscription_ui` refuses a hand-crafted ``bundle:*`` callback
before any service is touched.
"""

from __future__ import annotations

from urllib.parse import quote

from bot.container import Services
from bot.formatters import create_type_label, short_note
from config.settings import Settings
from i18n import t
from models.dto import KeyBundle, KeyTrafficStatsView, VpnKey
from models.enums import KeyBundleStatus, VpnKeyType
from services.errors import InvalidOperation
from services.key_bundles import BundleMember, KeyBundleCreateResult
from utils.formatting import code, format_bytes, format_expiry_date, format_msk_datetime, h

# The pseudo key-type the create wizard carries in its FSM data for an all-in-one
# bundle. Deliberately NOT a VpnKeyType member: a bundle is a parent row, not a
# protocol, and no key of this type is ever written.
BUNDLE_KEY_TYPE = "bundle"

# HTTPS default port — omitted from the sub-URL so a standard deployment yields
# the short, copy-pasteable form.
_DEFAULT_HTTPS_PORT = 443


# ── flag gate ─────────────────────────────────────────────────────────────────


def subscription_ui_enabled(services: Services) -> bool:
    """Whether the all-in-one UI may be shown at all."""
    return bool(services.settings.subscription_enabled)


def require_subscription_ui(services: Services) -> None:
    """Refuse a bundle interaction while ``SUBSCRIPTION_ENABLED`` is false.

    Hiding the buttons is not enough: callback data is client-supplied, so a
    replayed or hand-typed ``bundle:*`` payload would otherwise reach the service
    layer. Raising here keeps the flag's promise that with it off the bot behaves
    exactly as it did before this feature existed.
    """
    if not services.settings.subscription_enabled:
        raise InvalidOperation("All-in-one подписка сейчас отключена", key="err_subscription_disabled")


# ── subscription URL ──────────────────────────────────────────────────────────


def subscription_host(settings: Settings) -> str:
    """The public hostname the subscription endpoint is reachable at.

    Not a setting of its own and not a constant: the endpoint terminates TLS with
    a copy of the very certificate Hysteria2 already uses (see
    ``docs/subscription.md``), so the host clients must address is that
    certificate's domain — ``HYSTERIA2_SNI``, falling back to ``HYSTERIA2_HOST``
    when only the latter is set. Deriving it keeps the URL, the certificate and
    the hy2 links on one domain by construction instead of by an operator
    remembering to keep two values in sync.
    """
    return (settings.hysteria2_sni or settings.hysteria2_host).strip()


def subscription_url(settings: Settings, token: str) -> str | None:
    """Build ``https://<host>[:<port>]/sub/<token>``, or None when unreachable.

    Returns None — never a half-built URL — when the endpoint has no public
    listener (``SUBSCRIPTION_PUBLIC_PORT=0``, i.e. loopback-only) or no host is
    configured, so the config screen can say so plainly instead of handing the
    user a link that cannot resolve.
    """
    host = subscription_host(settings)
    port = settings.subscription_public_port
    if not host or port <= 0:
        return None
    # A bare IPv6 literal has to be bracketed before a port can be appended.
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port != _DEFAULT_HTTPS_PORT:
        netloc = f"{netloc}:{port}"
    return f"https://{netloc}/sub/{quote(token, safe='')}"


# ── labels ────────────────────────────────────────────────────────────────────


def bundle_status_text(status: KeyBundleStatus) -> str:
    """Localized bundle status.

    ``KeyBundleStatus`` shares its vocabulary with ``VpnKeyStatus`` on purpose, so
    the existing ``key_status_*`` strings are reused rather than duplicated — a
    bundle and its children always read the same word for the same state.
    """
    return {
        KeyBundleStatus.ACTIVE: t("key_status_active"),
        KeyBundleStatus.PENDING_REVOKE: t("key_status_pending_revoke"),
        KeyBundleStatus.REVOKED: t("key_status_revoked"),
        KeyBundleStatus.PENDING_DELETE: t("key_status_pending_delete"),
        KeyBundleStatus.DELETE_FAILED: t("key_status_delete_failed"),
        KeyBundleStatus.DELETED: t("key_status_deleted"),
    }.get(status, status.value)


def bundle_title(bundle: KeyBundle) -> str:
    """``All-in-One #12`` — the bundle's heading on every screen."""
    return t("bundle_title", id=bundle.id)


def bundle_member_label(member: BundleMember) -> str:
    """Human label for one member of the composition seam."""
    return create_type_label(member.key_type.value, member.transport, member.xhttp_profile)


def bundle_key_label(key: VpnKey) -> str:
    """Human label for one provisioned child key."""
    return create_type_label(key.key_type.value, key.transport, key.xhttp_profile)


def _bundle_note_for_viewer(bundle: KeyBundle, viewer_user_id: int) -> str | None:
    """A bundle note belongs to its owner and is never shown to anyone else."""
    if not bundle.note:
        return None
    return bundle.note if bundle.user_id == viewer_user_id else None


# ── cards ─────────────────────────────────────────────────────────────────────


def bundle_card_text(bundle: KeyBundle, *, viewer_user_id: int) -> str:
    """The compact bundle card — the same four fields a key card shows.

    The AmneziaWG explanation is appended by the caller (once per screen rather
    than once per card), so a user with several bundles does not read the same
    paragraph five times.
    """
    note = _bundle_note_for_viewer(bundle, viewer_user_id)
    return "\n".join(
        [
            f"<b>{h(bundle_title(bundle))}</b>",
            f"{t('field_status')}: {h(bundle_status_text(bundle.status))}",
            f"{t('field_label')}: {code(bundle.label)}",
            f"{t('field_created')}: {h(format_msk_datetime(bundle.created_at))}",
            f"{t('field_note')}: {h(short_note(note))}",
        ]
    )


def bundle_detail_text(bundle: KeyBundle, keys: list[VpnKey], *, viewer_user_id: int) -> str:
    """The full bundle screen: card, what is inside it, and when it expires."""
    note = _bundle_note_for_viewer(bundle, viewer_user_id)
    lines = [
        f"<b>{h(bundle_title(bundle))}</b>",
        f"{t('field_status')}: {h(bundle_status_text(bundle.status))}",
        f"{t('field_label')}: {code(bundle.label)}",
        f"{t('field_created')}: {h(format_msk_datetime(bundle.created_at))}",
        f"{t('field_updated')}: {h(format_msk_datetime(bundle.updated_at))}",
    ]
    expires_at = next((key.expires_at for key in keys if key.expires_at), None)
    if expires_at:
        lines.append(f"{t('field_expires')}: {h(format_expiry_date(expires_at))}")
    lines.append(f"{t('field_note')}: {h(note or t('none'))}")
    lines.append("")
    lines.append(_composition_block(keys))
    lines.append("")
    lines.append(t("bundle_awg_separate"))
    return "\n".join(lines)


def _composition_block(keys: list[VpnKey]) -> str:
    if not keys:
        return f"{t('bundle_composition')}: {h(t('none'))}"
    entries = "\n".join(f"• {h(bundle_key_label(key))} #{key.id}" for key in keys)
    return f"{t('bundle_composition')}:\n{entries}"


def bundles_section_text(bundles: list[KeyBundle], *, viewer_user_id: int, total: int | None = None) -> str:
    """The «All-in-One» group of the «My keys» page, rendered next to the protocol groups."""
    if not bundles:
        return ""
    cards = "\n\n".join(bundle_card_text(bundle, viewer_user_id=viewer_user_id) for bundle in bundles)
    parts = [f"{t('bundles_group_title')}\n{cards}", t("bundle_awg_separate")]
    if total is not None and total > len(bundles):
        parts.append(t("bundles_more_hint", shown=len(bundles), total=total))
    return "\n\n".join(parts)


# ── create ────────────────────────────────────────────────────────────────────


def bundle_create_confirm_text(note: str | None, *, expires_at: str | None) -> str:
    """Confirmation screen of the create wizard for an all-in-one bundle."""
    return "\n".join(
        [
            t("bundle_create_confirm_title"),
            f"{t('field_type')}: {h(t('bundle_type_label'))}",
            f"{t('field_note')}: {h(note or t('none'))}",
            f"{t('field_expires_at')}: {h(format_expiry_date(expires_at))}",
            "",
            t("bundle_awg_separate"),
        ]
    )


def bundle_created_text(result: KeyBundleCreateResult, *, viewer_user_id: int) -> str:
    """What the user gets after a successful create — including a partial one.

    A bundle may legitimately come out smaller than the full composition when a
    backend is switched off, so the actual contents are always spelled out and the
    omissions named. Staying silent here is how a user ends up believing they have
    a Hysteria2 link they never received.
    """
    lines = [
        t("bundle_created_title"),
        "",
        bundle_card_text(result.bundle, viewer_user_id=viewer_user_id),
        "",
        _composition_block(list(result.keys)),
    ]
    if result.skipped:
        skipped = ", ".join(bundle_member_label(member) for member in result.skipped)
        lines.append("")
        lines.append(t("bundle_created_skipped", skipped=h(skipped)))
    lines.append("")
    lines.append(t("bundle_awg_separate"))
    return "\n".join(lines)


# ── config ────────────────────────────────────────────────────────────────────


def bundle_config_text(bundle: KeyBundle, settings: Settings) -> str:
    """The sub-URL screen.

    No QR image: the dependency tree has no QR library (see the PR description),
    and pulling one in to draw a picture of a string the user can already copy is
    not a trade this feature needs. The URL is emitted as a ``<code>`` block, which
    Telegram makes tap-to-copy.
    """
    url = subscription_url(settings, bundle.token)
    if url is None:
        return f"<b>{h(bundle_title(bundle))}</b>\n\n{t('bundle_config_unavailable')}"
    return "\n".join(
        [
            f"<b>{h(bundle_title(bundle))}</b>",
            "",
            code(url),
            "",
            t("bundle_config_hint"),
            t("bundle_config_secret_warning"),
            t("bundle_awg_separate"),
        ]
    )


# ── stats ─────────────────────────────────────────────────────────────────────

# Protocol buckets for the breakdown. The four Xray children (TCP + three XHTTP
# profiles) collapse into one VLESS row: the user cares which protocol burned the
# traffic, and their per-key numbers are still one tap away on each child key.
_STATS_BUCKETS: tuple[tuple[VpnKeyType, str], ...] = (
    (VpnKeyType.XRAY, "VLESS"),
    (VpnKeyType.HYSTERIA2, "Hysteria2"),
)


def bundle_stats_text(bundle: KeyBundle, views: list[KeyTrafficStatsView]) -> str:
    """Bundle totals WITH a per-protocol split.

    The split is not decoration: the two numbers come from different sources
    (Xray's stats API vs. the Hysteria2 trafficStats endpoint) and one of them can
    be unavailable while the other is fine. A single summed figure would hide both
    that gap and which protocol a traffic spike came from.
    """
    lines = [t("bundle_stats_title", title=bundle_title(bundle))]
    if not views:
        lines.append("")
        lines.append(t("bundle_stats_empty"))
        return "\n".join(lines)

    total_down = 0
    total_up = 0
    breakdown: list[str] = []
    for key_type, label in _STATS_BUCKETS:
        bucket = [view for view in views if view.key.key_type == key_type]
        if not bucket:
            continue
        measured = [view.stats for view in bucket if view.stats is not None and view.stats.available]
        if not measured:
            breakdown.append(f"• {h(label)}: {h(t('bundle_stats_unavailable'))}")
            continue
        down = sum(stats.downloaded_bytes for stats in measured)
        up = sum(stats.uploaded_bytes for stats in measured)
        total_down += down
        total_up += up
        breakdown.append(
            f"• {h(label)}: ↓ {h(format_bytes(down))} · ↑ {h(format_bytes(up))}"
        )

    lines.extend(
        [
            "",
            t("bundle_stats_total"),
            f"{t('field_downloaded')}: {h(format_bytes(total_down))}",
            f"{t('field_uploaded')}: {h(format_bytes(total_up))}",
            "",
            t("bundle_stats_by_protocol"),
            *breakdown,
        ]
    )
    return "\n".join(lines)


# ── note ──────────────────────────────────────────────────────────────────────


def bundle_note_confirm_text(bundle: KeyBundle, note: str | None) -> str:
    """Confirmation of a note change, mirroring ``note_confirm_text`` for keys."""
    return (
        f"{t('note_confirm_title')}\n"
        f"{t('note_confirm_key')}: {h(bundle_title(bundle))}\n"
        f"{t('note_confirm_new_note')}: {h(note or t('none'))}"
    )
