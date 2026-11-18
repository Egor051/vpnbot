"""Text of the ONE relay screen (admin panel → «🛰 Relay»; the wizard opens it too).

Kept apart from the handlers so the screens can be rendered and tested without
aiogram, the way ``bot/bundles.py`` does it for subscriptions.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any

from config.validators import format_ipv4_networks
from i18n import t
from models.dto import Relay, RelayAgent, RelayPairing
from repositories.relays import RelayUsage
from services.relay_health import LEVEL_ICONS, ProbeResult
from services.relay_pairing import format_port_specs
from services.relays import IssuedPairing, PairingOutcome, RelayOverview, RouteInfo, agent_uninstalled, host_is_ipv4
from utils.formatting import code, format_msk_datetime, h

# Renders a probe's one-line reason (the supervisor's ``reason``).
ReasonFn = Callable[[ProbeResult], str]


def until_text(epoch: int) -> str:
    return time.strftime("%H:%M UTC", time.gmtime(epoch))


def relay_health_text(probe: ProbeResult | None, reason: ReasonFn | None = None) -> str:
    """The relay's ONE health verdict: icon, reason, time."""
    if probe is None:
        return t("relay_health_none")
    why = reason(probe) if reason is not None else ""
    return t(
        "relay_health_line",
        icon=LEVEL_ICONS.get(probe.level, "⚪️"),
        reason=why,
        time=h(format_msk_datetime(probe.checked_at)),
    )


def relay_icon(relay: Relay, probe: ProbeResult | None) -> str:
    """⏸ for a relay switched off, else its health icon (⚪️ before the first probe)."""
    if not relay.enabled:
        return "⏸"
    return "⚪️" if probe is None else LEVEL_ICONS.get(probe.level, "⚪️")


def relay_state_text(relay: Relay) -> str:
    return t("relay_state_on") if relay.enabled else t("relay_state_off")


def relay_subs_text(relay: Relay) -> str:
    return t("relay_subs_on") if relay.in_subscriptions else t("relay_subs_off")


def basic_visibility_text(visible: bool) -> str:
    """«👁 в базовых» / «🙈 скрыт в базовых» — a server's visibility in BASIC subscriptions."""
    return t("relay_basic_shown") if visible else t("relay_basic_hidden")


def relay_management_text(relay: Relay) -> str:
    """How the relay is managed: «агент vX» or «⚠️ без агента»."""
    agent = relay.agent
    if agent is None:
        return t("relay_managed_none")
    if agent_uninstalled(agent):
        return t("relay_managed_uninstalled")
    return t("relay_managed_agent", version=h(agent.agent_version or "?"))


def pairing_line(pairing: RelayPairing) -> str:
    key = "relay_pending_line_attach" if pairing.kind == "attach" else "relay_pending_line_new"
    return t(key, name=h(pairing.name), until=until_text(pairing.expires_at))


def relays_list_text(
    overviews: Sequence[RelayOverview],
    probes: dict[int, ProbeResult | None],
    *,
    pending: Sequence[RelayPairing] = (),
    reason: ReasonFn | None = None,
    main_basic_visible: bool | None = None,
    basic_has_server: bool = True,
    fallback_line: str | None = None,
) -> str:
    """The relay list: the main server's line (its visibility in BASIC subscriptions,
    when known), one entry per relay (``id`` order), then the codes still waiting.

    *basic_has_server* False adds the warning that BASIC subscriptions currently
    show nothing and are therefore served unfiltered (fail-open).
    """
    lines = [t("relays_title"), "", t("relays_intro")]
    if main_basic_visible is not None:
        lines.extend(["", t("relays_main_line", basic=basic_visibility_text(main_basic_visible))])
    if not basic_has_server:
        lines.extend(["", t("relays_basic_fail_open")])
    if fallback_line:
        lines.extend(["", fallback_line])
    if not overviews and not pending:
        lines.extend(["", t("relays_empty")])
        return "\n".join(lines)
    for overview in overviews:
        relay = overview.relay
        probe = probes.get(relay.id)
        lines.append("")
        lines.append(
            t(
                "relays_list_line",
                icon=relay_icon(relay, probe),
                label=h(relay.label),
                name=code(relay.name),
                host=code(relay.host),
                state=relay_state_text(relay),
                subs=relay_subs_text(relay),
                basic=basic_visibility_text(relay.basic_visible),
                keys=overview.active_keys,
                health=relay_health_text(probe, reason),
                managed=relay_management_text(relay),
            )
        )
    if pending:
        lines.extend(["", t("relays_pending_title")])
        lines.extend(pairing_line(pairing) for pairing in pending)
    return "\n".join(lines)


def _agent_status_lines(agent: RelayAgent) -> list[str]:
    status: dict[str, Any] = dict(agent.last_status or {})
    if not status:
        return [t("relay_agent_status_none")]
    lines = [t("relay_agent_status_at", at=h((agent.last_status_at or "?")[:16].replace("T", " ")))]
    live = status.get("live_target")
    if live:
        lines.append(t("relay_agent_status_live", target=h(str(live))))
    units = status.get("units")
    if isinstance(units, dict):
        lines.append(t("relay_agent_status_units", units=h(", ".join(f"{k} {v}" for k, v in sorted(units.items())))))
    check = status.get("check")
    if isinstance(check, dict):
        lines.append(t("relay_agent_status_check", rc=h(str(check.get("rc")))))
    checkout = status.get("checkout")
    if isinstance(checkout, dict) and checkout.get("describe"):
        lines.append(t("relay_agent_status_version", version=h(str(checkout["describe"]))))
    update = status.get("update")
    if isinstance(update, dict) and update.get("state"):
        lines.append(
            t("relay_agent_status_update", state=h(str(update["state"])), message=h(str(update.get("message", ""))))
        )
    input_status = status.get("input_status")
    if isinstance(input_status, str) and input_status:
        lines.append(t("relay_agent_status_input", status=h(input_status)))
    jump = status.get("jump")
    if isinstance(jump, dict) and isinstance(jump.get("open"), list):
        lines.append(t("relay_agent_status_jump", open=h(", ".join(map(str, jump["open"])) or "—")))
    return lines


def relay_card_text(
    relay: Relay,
    *,
    active_keys: int | None,
    probe: ProbeResult | None,
    reason: ReasonFn | None = None,
    pending_attach: RelayPairing | None = None,
    route: RouteInfo | None = None,
) -> str:
    """The relay page: the common fields, then how it is managed (its agent) and
    how the bot reaches it (*route*: directly, or through the hub)."""
    lines = [
        t("relay_card_title", label=h(relay.label)),
        f"{t('relay_field_name')}: {code(relay.name)} {t('relay_name_immutable')}",
        f"{t('relay_field_label')}: {code(relay.label)}",
        f"{t('relay_field_host')}: {code(relay.host)}",
        f"{t('relay_field_source_ips')}: {code(format_ipv4_networks(relay.source_ips))}",
        f"{t('relay_field_state')}: {relay_state_text(relay)} · {relay_subs_text(relay)}",
        f"{t('relay_field_basic')}: {basic_visibility_text(relay.basic_visible)}",
    ]
    if active_keys is not None:
        lines.append(f"{t('relay_field_keys')}: {active_keys}")
    lines.append(f"{t('relay_field_health')}: {relay_health_text(probe, reason)}")
    lines.append(f"{t('relay_field_note')}: {h(relay.note or t('none'))}")
    if relay.is_hub:
        origin = relay.agent.target_host if relay.agent is not None else "—"
        lines.append(t("relay_role_hub", origin=code(origin)))
    if host_is_ipv4(relay.host):
        lines.append(t("relay_host_ipv4_hint"))
    lines.append("")
    lines.append(f"<b>{t('relay_field_managed')}:</b> {relay_management_text(relay)}")
    agent = relay.agent
    if agent is None:
        lines.append(t("relay_no_agent_hint"))
        if pending_attach is not None:
            lines.append(t("relay_attach_pending", until=until_text(pending_attach.expires_at)))
        return "\n".join(lines)
    lines.append(
        t(
            "relay_agent_block",
            ssh=code(f"{agent.ssh_host}:{agent.ssh_port}"),
            target=code(agent.target_host),
            ports=h(format_port_specs(agent.tcp_ports, agent.udp_ports)),
        )
    )
    if route is not None and route.via_hub and not agent_uninstalled(agent):
        if route.hub is None:
            lines.append(t("relay_route_no_hub"))
        else:
            key = "relay_route_hub_flag" if route.reason == "flag" else "relay_route_hub_mode"
            lines.append(t(key, hub=h(f"{route.hub.label} · {route.hub.name}")))
    if agent_uninstalled(agent):
        lines.append(t("relay_agent_uninstalled"))
    else:
        lines.extend(_agent_status_lines(agent))
    return "\n".join(lines)


def relay_delete_text(relay: Relay, usage: RelayUsage) -> str:
    """The delete screen: what goes, and the uninstall first for a relay with an agent."""
    if usage.keys:
        text = t(
            "relay_delete_impact",
            label=h(relay.label),
            name=code(relay.name),
            keys=usage.keys,
            bundle_keys=usage.bundle_keys,
            bundles=usage.bundles,
        )
    else:
        text = t("relay_delete_confirm", label=h(relay.label), name=code(relay.name))
    if relay.agent is not None and not agent_uninstalled(relay.agent):
        text = f"{text}\n\n{t('relay_delete_uninstall_first')}"
    elif relay.agent is None:
        text = f"{text}\n\n{t('relay_delete_no_agent_note')}"
    return text


def pairing_text(issued: IssuedPairing, relay: Relay | None = None) -> str:
    """The code and the ONE command for the relay."""
    p = issued.pairing
    params = {
        "name": h(p.name),
        "target": h(p.target_host),
        "ports": h(format_port_specs(p.tcp_ports, p.udp_ports)),
        "until": until_text(p.expires_at),
        "command": code(issued.command),
    }
    if p.kind == "attach":
        return t("relay_pairing_attach", label=h(relay.label if relay is not None else p.name), **params)
    return t("relay_pairing_new", host=h(p.relay_host or "—"), **params)


def outcome_text(outcome: PairingOutcome) -> str:
    relay = outcome.relay
    agent = relay.agent
    health = (
        t("relay_paired_health_on", interval=outcome.health_interval)
        if outcome.health_interval > 0
        else t("relay_paired_health_off")
    )
    ssh = f"{agent.ssh_host}:{agent.ssh_port}" if agent is not None else "—"
    if outcome.attached:
        sources = (
            t("relay_attached_sources_added", sources=h(", ".join(outcome.added_source_ips)))
            if outcome.added_source_ips
            else t("relay_attached_sources_same")
        )
        return t(
            "relay_attached",
            label=h(relay.label),
            name=h(relay.name),
            host=h(relay.host),
            ssh=h(ssh),
            checks=h(outcome.checks.describe()),
            sources=sources,
            health=health,
        )
    text = t(
        "relay_paired",
        label=h(relay.label),
        name=h(relay.name),
        host=h(relay.host),
        ssh=h(ssh),
        checks=h(outcome.checks.describe()),
        sources=h(", ".join(str(n) for n in relay.source_ips)),
        health=health,
    )
    if outcome.host_mismatch is not None:
        resolved = ", ".join(outcome.host_mismatch) or t("relay_host_unresolved")
        text = f"{text}\n\n{t('relay_paired_host_mismatch', host=h(relay.host), resolved=h(resolved))}"
    return text
