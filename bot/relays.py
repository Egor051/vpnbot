"""Text of the relay panel's screens (admin panel → «🛰 Управлять relay»).

Kept apart from the handlers so the screens can be rendered and tested without
aiogram, the way ``bot/bundles.py`` does it for subscriptions.
"""

from __future__ import annotations

from collections.abc import Sequence

from config.validators import format_ipv4_networks
from i18n import t
from models.dto import Relay
from repositories.relays import RelayUsage
from services.relay_health import ProbeResult
from services.relay_management import RelayOverview
from utils.formatting import code, format_msk_datetime, h


def relay_health_text(probe: ProbeResult | None) -> str:
    """The latest probe of a relay as one short phrase."""
    if probe is None:
        return t("relay_health_none")
    key = "relay_health_ok" if probe.ok else "relay_health_fail"
    return t(key, time=h(format_msk_datetime(probe.checked_at)))


def relay_state_text(relay: Relay) -> str:
    return t("relay_state_on") if relay.enabled else t("relay_state_off")


def relay_subs_text(relay: Relay) -> str:
    return t("relay_subs_on") if relay.in_subscriptions else t("relay_subs_off")


def relays_list_text(overviews: Sequence[RelayOverview], probes: dict[int, ProbeResult | None]) -> str:
    """The relay list: one entry per relay, in relay (``id``) order."""
    lines = [t("relays_title"), "", t("relays_intro")]
    if not overviews:
        lines.extend(["", t("relays_empty")])
        return "\n".join(lines)
    for overview in overviews:
        relay = overview.relay
        lines.append("")
        lines.append(
            t(
                "relays_list_line",
                icon="🟢" if relay.enabled else "⏸",
                label=h(relay.label),
                name=code(relay.name),
                host=code(relay.host),
                state=relay_state_text(relay),
                subs=relay_subs_text(relay),
                keys=overview.active_keys,
                health=relay_health_text(probes.get(relay.id)),
            )
        )
    return "\n".join(lines)


def relay_card_text(relay: Relay, *, active_keys: int | None, probe: ProbeResult | None) -> str:
    """The relay card: every field, the key count and the latest probe."""
    lines = [
        t("relay_card_title", label=h(relay.label)),
        f"{t('relay_field_name')}: {code(relay.name)} {t('relay_name_immutable')}",
        f"{t('relay_field_label')}: {code(relay.label)}",
        f"{t('relay_field_host')}: {code(relay.host)}",
        f"{t('relay_field_source_ips')}: {code(format_ipv4_networks(relay.source_ips))}",
        f"{t('relay_field_state')}: {relay_state_text(relay)}",
        f"{t('relay_field_subs')}: {relay_subs_text(relay)}",
    ]
    if active_keys is not None:
        lines.append(f"{t('relay_field_keys')}: {active_keys}")
    lines.append(f"{t('relay_field_health')}: {relay_health_text(probe)}")
    lines.append(f"{t('relay_field_note')}: {h(relay.note or t('none'))}")
    return "\n".join(lines)


def relay_draft_text(*, name: str, host: str, source_ips: str, label: str) -> str:
    """The «Добавить relay» confirmation card, before anything is written."""
    return "\n".join(
        [
            t("relay_add_confirm_title"),
            "",
            f"{t('relay_field_name')}: {code(name)} {t('relay_name_immutable')}",
            f"{t('relay_field_label')}: {code(label)}",
            f"{t('relay_field_host')}: {code(host)}",
            f"{t('relay_field_source_ips')}: {code(source_ips)}",
            f"{t('relay_field_state')}: {t('relay_state_on')}",
            f"{t('relay_field_subs')}: {t('relay_subs_on')}",
            "",
            t("relay_add_confirm_question"),
        ]
    )


def relay_delete_impact_text(relay: Relay, usage: RelayUsage) -> str:
    """The screen shown when the relay to delete still has keys."""
    return t(
        "relay_delete_impact",
        label=h(relay.label),
        name=code(relay.name),
        keys=usage.keys,
        bundle_keys=usage.bundle_keys,
        bundles=usage.bundles,
    )
