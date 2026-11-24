"""Texts and keyboards of «🔐 Сертификат и DNS» (bot/handlers/admin_cert.py, docs/certificate.md)."""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import OwnedDnsRecord
from services.cert import CertStatus
from utils.formatting import code, h

LEVEL_ICONS = {"green": "🟢", "yellow": "🟡", "red": "🔴"}
_MAX_PROBLEMS = 12
# Candidates to adopt offered one button each (cert:adopt:<index into status.candidates>).
MAX_PICK = 8


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def _reloadcmd_line(dom: dict[str, object]) -> str:
    kind = str(dom.get("reloadcmd_kind") or "")
    if kind == "ours":
        return t("cert_reload_ours")
    if kind == "legacy":
        return t("cert_reload_legacy", cmd=code(dom.get("reloadcmd") or "—"))
    return t("cert_reload_other", cmd=code(dom.get("reloadcmd") or "—"))


def _consumer_line(c: dict[str, object]) -> str:
    name = h(c.get("name"))
    if not c.get("installed"):
        return t("cert_consumer_inactive", name=name, why=h(c.get("why") or ""))
    action = t(f"cert_action_{str(c.get('action') or '').replace('-', '_')}", unit=code(c.get("unit") or ""))
    if c.get("in_sync") is True and c.get("took_current") is not False:
        return t("cert_consumer_ok", name=name, action=action)
    if c.get("in_sync") is True:
        return t("cert_consumer_not_taken", name=name, action=action)
    if c.get("in_sync") is False:
        return t("cert_consumer_differs", name=name, action=action)
    return t("cert_consumer_unknown", name=name, action=action)


def _records_block(records: list[OwnedDnsRecord]) -> list[str]:
    if not records:
        return [t("cert_records_none")]
    lines = []
    for r in records:
        extra = t("cert_record_adopted") if r.adopted else ""
        error = f" — ⚠️ {h(r.last_error[:120])}" if r.last_error else ""
        lines.append(t("cert_record_line", name=code(r.name), content=code(r.content or "?"),
                       purpose=t(f"cert_purpose_{r.purpose}"), extra=extra) + error)
    return lines


def screen_text(status: CertStatus | None, records: list[OwnedDnsRecord], *, token_fp: str | None,
                error: str | None = None, notice: str | None = None) -> str:
    lines = [t("cert_title")]
    if notice:
        lines += ["", notice]
    if status is None:
        lines += ["", error or t("cert_status_unavailable")]
    else:
        dom = status.domain
        acme = status.acme
        lines.append("")
        if dom is None and len(status.candidates) > 1:
            lines.append(t("cert_ambiguous", names=h(", ".join(status.candidates))))
        elif dom is None:
            lines.append(t("cert_none"))
        else:
            lines.append(t("cert_domain_line", name=code(dom.get("name")), keylen=h(dom.get("keylength") or "?"),
                           until=h(str(dom.get("not_after") or "?")[:10]), days=h(f"{dom.get('days_left') or 0:.0f}")))
            lines.append(t("cert_san_line", san=h(", ".join(dom.get("san") or []) or "—")))
            lines.append(_reloadcmd_line(dom))
            if not status.adopted:
                lines.append(t("cert_not_adopted"))
        if acme.get("installed"):
            lines.append(t("cert_acme_line", version=h(acme.get("version") or "?"),
                           cron=t("cert_cron_ok") if acme.get("cron") else t("cert_cron_missing")))
        else:
            lines.append(t("cert_acme_missing"))
        lines += ["", t("cert_consumers_title")]
        lines += [_consumer_line(c) for c in status.consumers]
    lines += ["", t("cert_token_set", fp=code(token_fp)) if token_fp else t("cert_token_none")]
    lines += ["", t("cert_records_title")]
    lines += _records_block(records)
    if status is not None and status.problems:
        lines += ["", t("cert_problems_title")]
        order = {"red": 0, "yellow": 1}
        for p in sorted(status.problems, key=lambda p: order.get(str(p.get("level")), 2))[:_MAX_PROBLEMS]:
            lines.append(f"{LEVEL_ICONS.get(str(p.get('level')), '•')} {h(p.get('text') or '')}")
    return "\n".join(lines)


def screen_keyboard(status: CertStatus | None) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if status is not None:
        if not status.adopted and status.candidate:
            rows.append(_row(t("btn_cert_adopt"), "cert:go:adopt"))
        elif not status.adopted:
            # Several domains could be the bot's: the superadmin picks the one to adopt.
            for i, name in enumerate(status.candidates[:MAX_PICK]):
                rows.append(_row(t("btn_cert_adopt_domain", name=name), f"cert:adopt:{i}"))
        rows.append(_row(t("btn_cert_issue"), "cert:issue"))
        if status.adopted:
            rows.append(_row(t("btn_cert_renew"), "cert:go:renew"))
            if status.out_of_sync:
                rows.append(_row(t("btn_cert_deploy"), "cert:go:deploy"))
    rows.append(_row(t("btn_cert_token"), "cert:token"))
    rows.append(_row(t("btn_cert_refresh"), "cert:menu"))
    rows.append(_row(t("btn_wizard_back"), "wiz:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def issue_text(names: list[str], status: CertStatus | None) -> str:
    current = status.domain_name if status is not None else None
    lines = [t("cert_issue_title"), "", t("cert_issue_names", names=h(", ".join(names) or "—"))]
    if current and current not in names:
        lines.append(t("cert_issue_name_change", current=code(current)))
    lines += ["", t("cert_issue_hint")]
    return "\n".join(lines)


def issue_keyboard(has_names: bool) -> InlineKeyboardMarkup:
    rows = []
    if has_names:
        rows.append(_row(t("btn_cert_issue_go"), "cert:go:issue"))
    rows.append(_row(t("btn_cert_names"), "cert:names"))
    rows.append(_row(t("btn_cert_back"), "cert:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def token_text(token_fp: str | None, status: CertStatus | None, path: str, notice: str | None = None) -> str:
    lines = [t("cert_token_title"), "", t("cert_token_about", path=code(path))]
    lines += ["", t("cert_token_set", fp=code(token_fp)) if token_fp else t("cert_token_none")]
    dom = status.domain if status is not None else None
    acme_token = dom.get("token") if isinstance(dom, dict) else None
    if isinstance(acme_token, dict):
        acme_fp = acme_token.get("fp")
        if acme_fp and token_fp and acme_fp == token_fp:
            lines.append(t("cert_token_acme_same"))
        elif acme_fp:
            lines.append(t("cert_token_acme_other", fp=code(acme_fp)))
        else:
            lines.append(t("cert_token_acme_none", source=h(acme_token.get("source") or "none")))
    if notice:
        lines += ["", notice]
    return "\n".join(lines)


def token_keyboard(token_set: bool) -> InlineKeyboardMarkup:
    rows = [_row(t("btn_cert_token_set"), "cert:tok:set")]
    if token_set:
        rows.append(_row(t("btn_cert_token_delete"), "cert:tok:del"))
    rows.append(_row(t("btn_cert_back"), "cert:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def cancel_keyboard(back: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cert_cancel"), back)])
