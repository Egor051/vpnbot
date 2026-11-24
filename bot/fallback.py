"""Text of the «🛟 Режим фолбэка» screens (admin panel → «🛰 Relay»).

Kept apart from the handlers (bot/handlers/admin_fallback.py) so the screens can be
rendered and tested without aiogram, the way bot/relays.py does it for relays.
docs/relay.md «Режим фолбэка (hub)».
"""

from __future__ import annotations

from collections.abc import Sequence

from adapters.cloudflare_dns import DohAnswer
from i18n import t
from models.dto import FailoverName
from services.fallback import (
    FAILOVER,
    PROXY_TITLES,
    SWITCH_STEPS,
    Candidate,
    FallbackOverview,
    NameResult,
    Preflight,
    PreflightItem,
    ProxyAlert,
    ProxyReconcile,
    ProxyRoute,
    SwitchReport,
)
from services.proxy_endpoint import ProxyEndpoint, ProxyEndpoints
from utils.formatting import code, format_msk_datetime, h


def fallback_state_line(overview: FallbackOverview) -> str:
    """The one line of the relay list: off / ON (hub) / not finished."""
    if overview.state == "partial":
        return t("fb_line_partial", count=len(overview.pending))
    if overview.state == "on":
        return t("fb_line_on", hub=h(overview.hub.name if overview.hub is not None else "—"))
    return t("fb_line_off")


def _name_line(name: FailoverName, mode_on: bool) -> str:
    from services.fallback import name_settled

    icon = "✅" if name_settled(name, mode_on) else "⚠️"
    if name.applied is None:
        where = t("fb_name_untouched")
    else:
        where = t(
            "fb_name_applied",
            state=t("fb_name_state_failover") if name.applied == FAILOVER else t("fb_name_state_normal"),
            ip=code(name.applied_ipv4 or "?"),
            at=h(format_msk_datetime(name.applied_at) if name.applied_at else "?"),
        )
    line = f"{icon} {code(name.name)} — {where}"
    if name.last_error:
        line += "\n   " + t("fb_name_error", error=h(name.last_error[:200]))
    return line


def fallback_text(overview: FallbackOverview, notice: str | None = None) -> str:
    lines: list[str] = []
    if notice:
        lines.extend([notice, ""])
    lines.extend([t("fb_title"), "", t("fb_intro"), ""])
    state_key = {"on": "fb_state_on", "off": "fb_state_off", "partial": "fb_state_partial"}[overview.state]
    lines.append(t(state_key, count=len(overview.pending)))
    if overview.mode_at:
        lines.append(t("fb_state_since", at=h(format_msk_datetime(overview.mode_at))))
    lines.append("")
    if overview.hub is not None:
        lines.append(t(
            "fb_hub_line", name=h(overview.hub.name), host=code(overview.hub.host),
            origin=code(overview.origin or "—"),
        ))
    elif len([hub for hub in overview.hubs if hub.enabled]) > 1:
        lines.append(t("fb_hub_many", names=h(", ".join(hub.name for hub in overview.hubs))))
    else:
        lines.append(t("fb_hub_none"))
    lines.append(t(
        "fb_addresses", main=code(overview.main_ipv4 or "—"), hub=code(overview.hub_ipv4 or "—"),
    ))
    lines.append(
        t("fb_token_set", fp=code(overview.token_fingerprint or "?")) if overview.token_set else t("fb_token_none")
    )
    lines.append("")
    lines.append(t("fb_names_title", count=len(overview.names)))
    if overview.names:
        lines.extend(_name_line(name, overview.mode_on) for name in overview.names)
    else:
        lines.append(t("fb_names_empty"))
    lines.append("")
    if overview.direct_host:
        lines.append(t("fb_direct_name", host=code(overview.direct_host), count=overview.single_direct_keys))
    else:
        lines.append(t("fb_direct_ipv4", count=overview.single_direct_keys))
    lines.append(t("fb_sub_header_on") if overview.sub_fallback_url else t("fb_sub_header_off"))
    if overview.proxies:
        lines.append("")
        lines.extend(proxy_line(kind, endpoint) for kind, endpoint in overview.proxies)
    if overview.proxy_notice:
        lines.append(t("fb_proxy_notice_pending", proxies=h(", ".join(PROXY_TITLES[k] for k in overview.proxy_notice))))
    return "\n".join(lines)


def proxy_notice_text(kinds: Sequence[str], endpoints: ProxyEndpoints) -> str:
    """What the users of the moved proxies get: the new address of each (the same for
    everyone — logins and passwords do not change) and where the ready link is."""
    lines = [t("fb_proxy_notice_user_title"), ""]
    lines += [t("fb_proxy_notice_user_line", proxy=h(PROXY_TITLES.get(kind, kind)),
                address=code(endpoints.endpoint(kind).address)) for kind in kinds]
    lines += ["", t("fb_proxy_notice_user_tail")]
    return "\n".join(lines)


def proxy_line(kind: str, endpoint: ProxyEndpoint) -> str:
    """Where users reach a proxy now: through the hub (the mode) or main."""
    key = "fb_proxy_via_hub" if endpoint.via_hub else "fb_proxy_direct"
    return t(key, proxy=h(PROXY_TITLES.get(kind, kind)), address=code(endpoint.address))


def _route_line(route: ProxyRoute, target: str) -> str:
    params = {"proxy": h(PROXY_TITLES.get(route.kind, route.kind)), "port": route.port}
    if route.error == "ssh":
        return t("fb_route_ssh", **params)
    if not route.ok:
        return t("fb_route_failed", error=h((route.error or "")[:200]), **params)
    return t("fb_route_on" if target == FAILOVER else "fb_route_off", **params)


def proxy_reconcile_text(result: ProxyReconcile, *, hub: bool = True) -> str:
    """What «🔁 Довести прокси до hub» did: each port sent and its outcome, each port still
    waiting — or that there was nothing to do."""
    target = FAILOVER if result.mode_on else "normal"
    side = "on" if result.mode_on else "off"
    lines: list[str] = []
    for route in (*result.routes, *result.blocked):
        params = {"proxy": h(PROXY_TITLES.get(route.kind, route.kind)), "port": route.port}
        if route.ok or route.error == "ssh":
            lines.append(_route_line(route, target))
        else:
            lines.append(t(f"fb_reconcile_failed_{side}", error=h((route.error or "")[:200]), **params))
    for route in result.deferred:
        lines.append(t("fb_reconcile_deferred", proxy=h(PROXY_TITLES.get(route.kind, route.kind)), port=route.port,
                       error=h((route.error or "")[:200])))
    if lines:
        return "\n".join(lines)
    if not hub:
        return t("fb_proxy_reconcile_no_hub")
    return t("fb_proxy_reconcile_nothing") if result.mode_on else t("fb_proxy_reconcile_off")


def proxy_alert_text(alert: ProxyAlert) -> str:
    """The superadmins' message about a proxy port the reconcile could not move (one per
    (port, error)): what users get now, the agent's own error, when the bot tries again."""
    route = alert.route
    return t(
        "fb_proxy_alert_on" if alert.mode_on else "fb_proxy_alert_off",
        hub=h(alert.hub), proxy=h(PROXY_TITLES.get(route.kind, route.kind)), port=route.port,
        main=h(alert.main or "—"), error=h((route.error or "—")[:300]), minutes=alert.retry_minutes,
    )


def preflight_item_text(item: PreflightItem) -> str:
    icon = "ℹ️" if item.info else ("✅" if item.ok else ("⚠️" if item.warning else "❌"))
    params = {key: h(str(value)) for key, value in item.params.items()}
    return f"{icon} {t(item.key, **params)}"


def preflight_text(preflight: Preflight) -> str:
    lines = [t("fb_pf_title_ok") if preflight.passed else t("fb_pf_title_fail"), ""]
    lines.extend(preflight_item_text(item) for item in preflight.items)
    return "\n".join(lines)


def _doh_text(answers: Sequence[DohAnswer]) -> str:
    return "; ".join(
        f"{h(answer.resolver)}: {h(answer.error or ', '.join(answer.addresses) or '—')}" for answer in answers
    ) or "—"


def _result_line(result: NameResult) -> str:
    if not result.ok:
        return t("fb_result_failed", name=code(result.name), error=h((result.error or "")[:200]))
    key = "fb_result_propagated" if result.propagated else "fb_result_not_yet"
    return t(key, name=code(result.name), ip=code(result.ipv4), doh=_doh_text(result.doh))


def report_text(report: SwitchReport) -> str:
    """What «Включить» / «Выключить» / «Повторить» did."""
    if report.preflight is not None and not report.preflight.passed:
        return f"{t('fb_report_blocked')}\n\n{preflight_text(report.preflight)}"
    key = "fb_report_on" if report.target == FAILOVER else "fb_report_off"
    lines = [t(key)]
    if not report.complete:
        lines.append(t("fb_report_partial", names=h(", ".join(report.failed_names))))
    lines.append("")
    lines.extend(_result_line(result) for result in report.results)
    if any(result.ok and not result.propagated for result in report.results):
        lines.extend(["", t("fb_report_not_yet_hint")])
    if report.proxies:
        lines.append("")
        lines.extend(_route_line(route, report.target) for route in report.proxies)
    return "\n".join(lines)


def names_text(overview: FallbackOverview, candidates: Sequence[str]) -> str:
    lines = [t("fb_names_screen_title"), "", t("fb_names_intro"), ""]
    if overview.names:
        lines.extend(_name_line(name, overview.mode_on) for name in overview.names)
    else:
        lines.append(t("fb_names_empty"))
    if candidates:
        lines.extend(["", t("fb_names_candidates", names=", ".join(code(name) for name in candidates))])
    return "\n".join(lines)


# ── the setup, the candidates, the switch's steps (C1, C4, D) ─────────────────


def not_configured_text(overview: FallbackOverview, notice: str | None = None) -> str:
    """The screen while the mode is not set up: what it is, what is missing."""
    lines: list[str] = []
    if notice:
        lines.extend([notice, ""])
    lines.extend([t("fb_title"), "", t("fb_intro"), "", t("fb_setup_needed")])
    lines.append(("✅ " if overview.token_set else "⚪ ") + t("fb_setup_item_token"))
    lines.append(("✅ " if overview.hub is not None else "⚪ ") + t("fb_setup_item_hub"))
    lines.append(("✅ " if overview.names else "⚪ ") + t("fb_setup_item_names", count=len(overview.names)))
    return "\n".join(lines)


def candidates_text(title: str, candidates: Sequence[Candidate], unchecked: Sequence[str]) -> str:
    """Every candidate with WHY it belongs in the set; ☑️ checked, ⬜ unchecked."""
    from bot.keyboards.admin_fallback import name_tag

    lines = [title, "", t("fb_cand_intro"), ""]
    if not candidates:
        lines.append(t("fb_cand_none"))
    for candidate in candidates:
        mark = "⬜" if name_tag(candidate.name) in unchecked else "☑️"
        why = "; ".join(
            t(reason, relays=h(", ".join(candidate.relays))) if reason == "fb_cand_why_relay" else t(reason)
            for reason in candidate.reasons
        )
        lines.append(f"{mark} {code(candidate.name)} — {why}")
    return "\n".join(lines)


def setup_step_title(step: int) -> str:
    return t("fb_setup_step", step=step, total=5)


def switch_step_titles(*, proxies: bool = False) -> list[tuple[str, str]]:
    """The switch's steps for bot/progress.py (services.fallback.SWITCH_STEPS); the
    proxies' step only when a proxying module is on."""
    return [(key, t(f"fb_step_{key}")) for key in SWITCH_STEPS if proxies or key != "proxy"]


def failure_keys(report: SwitchReport) -> list[str]:
    """The i18n keys of what blocked a switch (the fix buttons are keyed by them)."""
    if report.preflight is None:
        return []
    return [item.key for item in report.preflight.failures]
