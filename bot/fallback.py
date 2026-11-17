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
from services.fallback import FAILOVER, FallbackOverview, NameResult, Preflight, PreflightItem, SwitchReport
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
    return "\n".join(lines)


def preflight_item_text(item: PreflightItem) -> str:
    icon = "✅" if item.ok else ("⚠️" if item.warning else "❌")
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
