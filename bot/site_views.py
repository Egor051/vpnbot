"""Texts and keyboards of «🌐 Сайт» (bot/handlers/admin_site.py, docs/site.md)."""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from services.site import MAX_ARCHIVE_BYTES, SiteStatus
from utils.formatting import code, h
from utils.redact import redact_value

PAGES_PER_SCREEN = 40
_MAX_PROBLEMS = 8


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def _shown(value: object) -> str:
    """Host text for Telegram: utils/redact once more, then escaped by the caller."""
    return redact_value(str(value or "")) or "—"


def size_text(n: object) -> str:
    value = float(n) if isinstance(n, (int, float)) and not isinstance(n, bool) else 0.0
    if value < 1024:
        return t("site_size_b", n=int(value))
    if value < 1 << 20:
        return t("site_size_kib", n=f"{value / 1024:.1f}")
    return t("site_size_mib", n=f"{value / (1 << 20):.1f}")


def _when(value: object) -> str:
    text = str(value or "")
    return text[:16].replace("T", " ") + " UTC" if len(text) >= 16 else text or "—"


def _version_lines(status: SiteStatus) -> list[str]:
    cur = status.current
    tree = str(cur.get("tree") or "")[:12] or "?"
    if cur.get("deployed_at"):
        origin = t("site_version_deployed", when=_when(cur.get("deployed_at")), run=cur.get("run") or "?")
    else:
        origin = t("site_version_by_hand", when=_when(cur.get("newest_mtime")))
    lines = [
        t("site_version_line", sha=code(tree), origin=origin),
        t("site_pages_line", pages=cur.get("pages", 0), files=cur.get("files", 0), size=size_text(cur.get("bytes"))),
    ]
    if cur.get("modified"):
        lines.append(t("site_modified_line"))
    return lines


def _spx_line(status: SiteStatus) -> str:
    spx = status.spx
    if not spx.get("enabled"):
        return t("site_spx_off")
    missing = [str(p) for p in spx.get("missing") or []]
    if missing:
        return t("site_spx_missing", n=len(status.pool), paths=h(", ".join(missing[:8]) + (" …" if len(missing) > 8 else "")))
    if spx.get("in_sync"):
        return t("site_spx_ok", n=len(status.pool))
    return t("site_spx_partial", n=len(status.pool))


def _hy2_line(status: SiteStatus) -> str | None:
    layout = status.hy2.get("layout")
    if layout == "proxy":
        return t("site_hy2_proxy")
    if layout == "file":
        return t("site_hy2_file", dir=code(_shown(status.hy2.get("detail"))))
    if layout == "other":
        return t("site_hy2_other", target=code(_shown(status.hy2.get("detail"))))
    return None


def screen_text(status: SiteStatus | None, *, error: str | None = None, notice: str | None = None) -> str:
    lines = [t("site_title")]
    if notice:
        lines += ["", notice]
    if status is None:
        lines += ["", t("site_status_unavailable")]
        if error:
            lines.append(error)
        return "\n".join(lines)
    lines.append("")
    if status.docroot:
        lines.append(t("site_where_line", docroot=code(_shown(status.docroot)), domain=code(_shown(status.domain))))
    if status.current:
        lines += _version_lines(status)
    keep = status.limits.get("keep", 5)
    releases = status.releases
    if status.revert_to:
        lines.append(t("site_kept_line", n=len(releases), keep=keep, target=code(_shown(status.revert_to))))
    else:
        lines.append(t("site_kept_none", n=len(releases), keep=keep))
    lines.append(_spx_line(status))
    hy2 = _hy2_line(status)
    if hy2:
        lines.append(hy2)
    if status.unfinished:
        lines.append(t("site_unfinished_line"))
    problems = status.problems
    if problems:
        lines += ["", t("site_problems_title")]
        lines += [f"⛔ {h(_shown(p))}" for p in problems[:_MAX_PROBLEMS]]
    return "\n".join(lines)


def screen_keyboard(status: SiteStatus | None) -> InlineKeyboardMarkup:
    rows = []
    if status is not None and status.ok:
        rows.append(_row(t("btn_site_upload"), "site:upload"))
        if status.revert_to:
            rows.append(_row(t("btn_site_revert"), "site:revert"))
    if status is not None and status.pages:
        rows.append(_row(t("btn_site_pages"), "site:pages:0"))
    rows.append(_row(t("btn_cert_refresh"), "site:menu"))
    rows.append(_row(t("btn_cert_back"), "wiz:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def upload_text(status: SiteStatus | None) -> str:
    limits = status.limits if status is not None else {}
    ext = " ".join(str(e) for e in limits.get("ext") or [])
    return t(
        "site_upload_prompt",
        max_mb=int(limits.get("archive") or MAX_ARCHIVE_BYTES) // (1 << 20),
        files=limits.get("files", 1000),
        total_mb=int(limits.get("bytes") or (64 << 20)) // (1 << 20),
        depth=limits.get("depth", 12),
        ext=code(ext or "html css js …"),
    )


def upload_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_cert_cancel"), "site:menu")])


def pages_text(status: SiteStatus, page: int) -> str:
    pages = status.pages
    chunk = pages[page * PAGES_PER_SCREEN:(page + 1) * PAGES_PER_SCREEN]
    lines = [t("site_pages_title", total=status.pages_total, domain=code(_shown(status.domain)))]
    lines += [f"• {code(p)}" for p in chunk]
    if status.pages_total > len(pages) and (page + 1) * PAGES_PER_SCREEN >= len(pages):
        lines.append(t("site_pages_more", n=status.pages_total - len(pages)))
    return "\n".join(lines)


def pages_keyboard(status: SiteStatus, page: int) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=f"site:pages:{page - 1}"))
    if (page + 1) * PAGES_PER_SCREEN < len(status.pages):
        nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=f"site:pages:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append(_row(t("btn_cert_back"), "site:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)
