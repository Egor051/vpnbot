"""UI layer for all-in-one subscription bundles: the flag gate, the sub-URL and the
text of the screens a bundle has to itself — its detail view, config, stats and the
create wizard's confirmation.

What is NOT here: the bundle's list card, title and status word. Those live in
``bot/formatters.py`` next to their key equivalents, because «My keys» renders keys
and bundles interleaved in one list — they are the same card for two entities, and
keeping them in separate modules is how they drift apart. This module imports them
back for the screens above.

Everything below is inert while ``SUBSCRIPTION_ENABLED`` is false: the create menu
does not offer the option, the key list contains no bundles, and
:func:`require_subscription_ui` refuses a hand-crafted ``bundle:*`` callback
before any service is touched.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import quote

from bot.availability import Availability
from bot.container import Services
from bot.formatters import (
    bundle_card_text,
    bundle_note_for_viewer,
    bundle_status_text,
    bundle_title,
    create_type_label,
    sum_traffic_figures,
    traffic_figures_inline,
    traffic_stale_mark,
)
from bot.protocol_texts import bundle_awg_notice, bundle_kind_description, bundle_kinds
from config.settings import Settings
from i18n import t
from models.dto import KeyBundle, KeyTrafficStatsView, VpnKey
from models.enums import KeyBundleKind, VpnKeyType
from services.errors import InvalidOperation
from services.key_bundles import BundleMember, KeyBundleCreateResult, member_protocol, subscription_sort_key
from services.relay import EMPTY_RELAYS, RelaySnapshot
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


def bundle_member_label(member: BundleMember) -> str:
    """Human label for one member of the composition seam."""
    return create_type_label(
        member.key_type.value, member.transport, member.xhttp_profile, relay=member.relay
    )


def bundle_key_label(key: VpnKey) -> str:
    """Human label for one provisioned child key."""
    return create_type_label(key.key_type.value, key.transport, key.xhttp_profile, relay=key.relay)


def bundle_kind_label(kind: KeyBundleKind) -> str:
    """«Базовая» / «Расширенная» — the name of a bundle kind."""
    return t(f"bundle_kind_{kind.value}")


def bundle_kind_prompt(available: Availability, *, relay_labels: Sequence[str] = ()) -> str:
    """The kind-choice screen of the create wizard: every offered kind, explained.

    Each description is built from the composition filtered by *available*
    (:func:`bot.protocol_texts.bundle_kind_description`), so a switched-off
    protocol is never promised; the kinds themselves come from
    :func:`bot.protocol_texts.bundle_kinds` and match :func:`bundle_kind_keyboard`'s
    buttons.

    *relay_labels* are the relays new bundles get members through (enabled and
    «в подписках», in relay order); each kind then also carries a copy of its
    members through each of them, which is said once below the descriptions.
    """
    blocks = "\n\n".join(
        f"<b>{t(f'bundle_kind_{kind.value}')}</b>\n{bundle_kind_description(kind, available)}"
        for kind in bundle_kinds(available)
    )
    text = f"{t('bundle_kind_prompt')}\n\n{blocks}"
    if relay_labels:
        text += f"\n\n{t('bundle_kind_relay_note', relays=h(', '.join(relay_labels)))}"
    return text


def bundle_has_vless(keys: list[VpnKey]) -> bool:
    """Whether a fingerprint can be applied to this bundle at all.

    The fingerprint is a VLESS/REALITY client setting; Hysteria2 has no such knob.
    A bundle provisioned while the Xray module was off therefore has nothing to
    apply one to, and its screen must not offer the row.
    """
    return any(key.key_type is VpnKeyType.XRAY for key in keys)


# ── cards ─────────────────────────────────────────────────────────────────────


def bundle_notices(available: Availability, *, with_marks_legend: bool = True) -> list[str]:
    """The notices every subscription screen ends with, in reading order.

    The preference-mark legend comes FIRST and is the louder of the two: it is what
    a user needs before touching the profiles the client just imported, whereas the
    AmneziaWG note explains an absence. ``with_marks_legend`` drops it on screens
    shown before the subscription exists, where there are no marked keys yet to
    rank, and for a basic subscription, whose names carry no circles at all (see
    :func:`marks_legend_for`).

    The AmneziaWG note exists only while AmneziaWG is offered at all — explaining
    the absence of a protocol the user cannot get anyway would be news about it.
    May therefore be empty; append it with :func:`_with_notices`.
    """
    notices: list[str] = []
    awg_notice = bundle_awg_notice(available)
    if awg_notice is not None:
        notices.append(awg_notice)
    if with_marks_legend:
        return [t("bundle_marks_legend"), *([""] if notices else []), *notices]
    return notices


def _with_notices(lines: list[str], notices: list[str]) -> list[str]:
    """Append *notices* after a blank line — or nothing at all when there are none."""
    if notices:
        lines.extend(["", *notices])
    return lines


def marks_legend_for(bundle: KeyBundle) -> bool:
    """Whether this bundle's screens explain the preference circles.

    Only an EXTENDED subscription names its members with circles; a basic one
    names them like standalone keys (with the server flag), so the legend would
    explain something the user never sees.
    """
    return bundle.kind is KeyBundleKind.EXTENDED


def bundle_detail_text(
    bundle: KeyBundle,
    keys: list[VpnKey],
    *,
    viewer_user_id: int,
    available: Availability,
    views: list[KeyTrafficStatsView] | None = None,
    relays: RelaySnapshot = EMPTY_RELAYS,
) -> str:
    """The full bundle screen: card, what is inside it, its traffic, its notices.

    *relays* only orders the «Состав» preview the way the subscription serves it
    (relay children grouped by relay, in relay order).

    ``views`` carries the children's traffic, rendered here rather than behind a
    «Статистика» button — the same move the per-key screen makes. ``None`` means the
    figures could not be sampled at all, and the block says so instead of showing
    zeroes.
    """
    note = bundle_note_for_viewer(bundle, viewer_user_id)
    lines = [
        f"<b>{h(bundle_title(bundle))}</b>",
        f"{t('field_status')}: {h(bundle_status_text(bundle.status))}",
        f"{t('field_bundle_kind')}: {h(bundle_kind_label(bundle.kind))}",
        f"{t('field_label')}: {code(bundle.label)}",
        f"{t('field_created')}: {h(format_msk_datetime(bundle.created_at))}",
        f"{t('field_updated')}: {h(format_msk_datetime(bundle.updated_at))}",
    ]
    expires_at = next((key.expires_at for key in keys if key.expires_at), None)
    if expires_at:
        lines.append(f"{t('field_expires')}: {h(format_expiry_date(expires_at))}")
    lines.append(f"{t('field_note')}: {h(note or t('none'))}")
    lines.append("")
    lines.append(_composition_block(keys, relays))
    lines.append("")
    lines.extend(bundle_stats_block(views))
    _with_notices(lines, bundle_notices(available, with_marks_legend=marks_legend_for(bundle)))
    return "\n".join(lines)


def _composition_block(keys: list[VpnKey], relays: RelaySnapshot) -> str:
    if not keys:
        return f"{t('bundle_composition')}: {h(t('none'))}"
    entries = "\n".join(
        f"• {h(bundle_key_label(key))} #{key.id}" for key in _in_subscription_order(keys, relays)
    )
    return f"{t('bundle_composition')}:\n{entries}"


def _in_subscription_order(keys: list[VpnKey], relays: RelaySnapshot) -> list[VpnKey]:
    """Order the children the way the subscription serves them.

    «Состав» is a preview of the profile list the client is about to import, so it
    has to agree with it: the same order — direct children first, then the
    children of each relay in relay order, each group from the member giving the
    best connection to the worst.
    Sorted with the renderer's own sort key rather than left in row order, which
    for a bundle provisioned before the seam's order last changed would show
    something the client never displays. Unknown members keep their relative
    position at the end of their group instead of disappearing.
    """
    return sorted(keys, key=lambda key: subscription_sort_key(key, relays))


# ── create ────────────────────────────────────────────────────────────────────


def bundle_create_confirm_text(
    note: str | None,
    *,
    expires_at: str | None,
    available: Availability,
    fingerprint: str | None = None,
    kind: KeyBundleKind = KeyBundleKind.EXTENDED,
) -> str:
    """Confirmation screen of the create wizard for an all-in-one bundle.

    ``fingerprint`` is absent only when the bundle will carry no VLESS child at all
    (the Xray module is off), so the line is omitted rather than showing a value
    that nothing would apply.
    """
    lines = [
        t("bundle_create_confirm_title"),
        f"{t('field_type')}: {h(t('bundle_type_label'))}",
        f"{t('field_bundle_kind')}: {h(bundle_kind_label(kind))}",
        f"{t('field_note')}: {h(note or t('none'))}",
    ]
    if fingerprint:
        lines.append(f"Fingerprint: {h(fingerprint)}")
    lines.append(f"{t('field_expires_at')}: {h(format_expiry_date(expires_at))}")
    # No mark legend here: nothing has been provisioned yet, so there are no
    # marked keys on screen for it to explain.
    _with_notices(lines, bundle_notices(available, with_marks_legend=False))
    return "\n".join(lines)


def bundle_created_text(
    result: KeyBundleCreateResult,
    *,
    viewer_user_id: int,
    settings: Settings,
    available: Availability,
    relays: RelaySnapshot = EMPTY_RELAYS,
) -> str:
    """What the user gets after a successful create — including a partial one.

    A bundle may legitimately come out smaller than the full composition, so the
    actual contents are always spelled out and the omissions named — but only
    omissions of a protocol the user can still see (a member left out because its
    relay is down). A member skipped because its protocol is switched off is not
    named: the kind description never promised it, and naming it would tell the
    user about a protocol they cannot get.

    Ends with the subscription URL itself, exactly as the single-key flow ends with
    the key's ``vless://``/``hy2://`` link: the deliverable of the wizard belongs on
    screen when the wizard finishes, not one tap away behind «Конфиг». The token
    reaches the chat message and nothing else — no log line and no audit field
    formats it, the same contract the config screen keeps.
    """
    lines = [
        t("bundle_created_title"),
        "",
        bundle_card_text(result.bundle, viewer_user_id=viewer_user_id),
        "",
        _composition_block(list(result.keys), relays),
    ]
    visible_skipped = [member for member in result.skipped if member_protocol(member) in available]
    if visible_skipped:
        skipped = ", ".join(bundle_member_label(member) for member in visible_skipped)
        lines.append("")
        lines.append(t("bundle_created_skipped", skipped=h(skipped)))
    lines.append("")
    lines.extend(_subscription_block(result.bundle, settings))
    _with_notices(lines, bundle_notices(available, with_marks_legend=marks_legend_for(result.bundle)))
    return "\n".join(lines)


# ── config ────────────────────────────────────────────────────────────────────


def _subscription_block(bundle: KeyBundle, settings: Settings) -> list[str]:
    """The sub-URL with its two footnotes, or the "not published yet" notice.

    Shared by the config screen and the just-created screen so the credential is
    presented identically on both — including the warning that the link *is* the
    credential. The URL is emitted as a ``<code>`` block, which Telegram makes
    tap-to-copy. No QR image: the dependency tree has no QR library, and pulling
    one in to draw a picture of a string the user can already copy is not a trade
    this feature needs.
    """
    url = subscription_url(settings, bundle.token)
    if url is None:
        return [t("bundle_config_unavailable")]
    return [code(url), "", t("bundle_config_hint"), t("bundle_config_secret_warning")]


def bundle_config_text(bundle: KeyBundle, settings: Settings, available: Availability) -> str:
    """The sub-URL screen."""
    lines = [f"<b>{h(bundle_title(bundle))}</b>", "", *_subscription_block(bundle, settings)]
    _with_notices(lines, bundle_notices(available, with_marks_legend=marks_legend_for(bundle)))
    return "\n".join(lines)


# ── stats ─────────────────────────────────────────────────────────────────────

# Protocol buckets for the breakdown. The four Xray children (TCP + three XHTTP
# profiles) collapse into one VLESS row: the user cares which protocol burned the
# traffic, and their per-key numbers are still one tap away on each child key.
_STATS_BUCKETS: tuple[tuple[VpnKeyType, str], ...] = (
    (VpnKeyType.XRAY, "VLESS"),
    (VpnKeyType.HYSTERIA2, "Hysteria2"),
)


def bundle_stats_block(views: list[KeyTrafficStatsView] | None) -> list[str]:
    """Bundle totals WITH a per-protocol split, as lines of the bundle screen.

    The split is not decoration: the two numbers come from different sources
    (Xray's stats API vs. the Hysteria2 trafficStats endpoint) and one of them can
    be unavailable while the other is fine. A single summed figure would hide both
    that gap and which protocol a traffic spike came from.

    Every figure — the per-protocol rows and the total alike — goes through
    :func:`bot.formatters.sum_traffic_figures`, the one place that decides what a
    traffic number means. This screen used to decide for itself: it dropped any
    key whose latest poll had not confirmed its counters and summed a 0 into the
    total, so a subscription showed «недоступно» and 0 B while the very keys
    listed under it showed their real figures.
    """
    lines = [t("stats_block_title")]
    if not views:
        lines.append(t("bundle_stats_empty") if views is not None else t("stats_not_available_yet"))
        return lines

    breakdown: list[str] = []
    for key_type, label in _STATS_BUCKETS:
        bucket = [view for view in views if view.key.key_type == key_type]
        if not bucket:
            continue
        figures = sum_traffic_figures(view.stats for view in bucket)
        if not figures.known:
            breakdown.append(f"• {h(label)}: {h(t('bundle_stats_unavailable'))}")
            continue
        breakdown.append(f"• {h(label)}: {h(traffic_figures_inline(figures))}")

    total = sum_traffic_figures(view.stats for view in views)
    lines.extend(
        [
            t("bundle_stats_total"),
            f"{t('field_downloaded')}: {h(format_bytes(total.downloaded_bytes))}",
            f"{t('field_uploaded')}: {h(format_bytes(total.uploaded_bytes))}",
            *([h(traffic_stale_mark(total))] if total.stale else []),
            "",
            t("bundle_stats_by_protocol"),
            *breakdown,
        ]
    )
    return lines


# ── note ──────────────────────────────────────────────────────────────────────


def bundle_note_confirm_text(bundle: KeyBundle, note: str | None) -> str:
    """Confirmation of a note change, mirroring ``note_confirm_text`` for keys."""
    return (
        f"{t('note_confirm_title')}\n"
        f"{t('note_confirm_key')}: {h(bundle_title(bundle))}\n"
        f"{t('note_confirm_new_note')}: {h(note or t('none'))}"
    )
