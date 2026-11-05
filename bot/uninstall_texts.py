"""Telegram rendering of a protocol-uninstall plan and of its report.

Admin-only screens. The helper's own strings (paths, unit names, reasons) are
technical and stay in English; every heading and sentence around them is
localized. Long lists are cut so the message stays inside Telegram's 4096
characters — the plan JSON on the server is the complete record.
"""

from __future__ import annotations

from collections.abc import Sequence

from i18n import t
from repositories.protocol_modules import PROTOCOL_DISPLAY
from services.protocol_uninstall import UninstallPlan, UninstallReport
from utils.formatting import format_bytes, h

# Telegram caps a message at 4096 characters; keep a margin for the keyboard text.
MAX_MESSAGE = 3800
MAX_ITEMS = 12


def _label(name: str) -> str:
    return PROTOCOL_DISPLAY.get(name, name)


def _cut(lines: list[str], limit: int = MAX_ITEMS) -> list[str]:
    if len(lines) <= limit:
        return lines
    return [*lines[:limit], "• " + t("module_uninstall_more", count=len(lines) - limit)]


def _int(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _fit(lines: Sequence[str]) -> str:
    text = "\n".join(lines)
    if len(text) <= MAX_MESSAGE:
        return text
    # Cut at a line boundary, then say so: a truncated plan must not look complete.
    out: list[str] = []
    size = 0
    tail = t("module_uninstall_truncated")
    for line in lines:
        if size + len(line) + 1 > MAX_MESSAGE - len(tail) - 2:
            break
        out.append(line)
        size += len(line) + 1
    out.append(tail)
    return "\n".join(out)


def uninstall_plan_text(plan: UninstallPlan) -> str:
    lines = [
        t("module_uninstall_plan_title", label=h(_label(plan.protocol))),
        t(
            "module_uninstall_plan_header",
            state=h(t(f"module_uninstall_state_{plan.state}") if plan.state in
                    ("installed", "partial", "uninstalled") else plan.state),
            sha=h(plan.sha_prefix),
        ),
    ]
    if plan.nothing_to_do:
        lines += ["", t("module_uninstall_nothing_to_do")]
        return _fit(lines)

    absent: list[str] = []
    kept: list[str] = []

    units: list[str] = []
    for unit in plan.units:
        name = str(unit.get("unit", ""))
        actions = str(unit.get("actions", ""))
        load = str(unit.get("load", ""))
        if load == "template":
            units.append("• " + t("module_uninstall_unit_template", unit=h(name)))
        elif actions:
            state = f"{unit.get('load', '')}, {unit.get('active', '')}, {unit.get('file_state', '') or '-'}"
            units.append(f"• {h(name)}: {h(actions.replace(' ', ', '))} <i>({h(state)})</i>")
        else:
            absent.append(f"• {h(name)} <i>({h(load)})</i>")

    files: list[str] = []
    awg_names: list[str] = []
    awg_size = 0
    awg_dir = ""
    for f in plan.files:
        path = str(f.get("path", ""))
        state = str(f.get("state", ""))
        if state == "absent":
            absent.append(f"• {h(path)}")
            continue
        if state in ("skip", "refuse"):
            if state == "skip":
                kept.append(f"• {h(path)} — {h(str(f.get('reason', '')))}")
            continue
        size = format_bytes(_int(f.get("size")))
        if f.get("group") == "awg":
            awg_names.append(path.rsplit("/", 1)[-1])
            awg_size += _int(f.get("size"))
            awg_dir = path.rsplit("/", 1)[0]
            continue
        if f.get("kind") == "dir":
            files.append("• " + t("module_uninstall_dir_line", path=h(path), entries=_int(f.get("entries")),
                                  size=h(size)))
        else:
            files.append(f"• {h(path)} ({h(size)})")
    if awg_names:
        shown = ", ".join(awg_names[:4]) + (", …" if len(awg_names) > 4 else "")
        files.append("• " + t("module_uninstall_awg_group", count=len(awg_names), dir=h(awg_dir),
                              size=h(format_bytes(awg_size)), names=h(shown)))

    ufw: list[str] = []
    for rule in plan.ufw:
        state = str(rule.get("state", ""))
        spec = str(rule.get("rule", ""))
        if state == "delete":
            ufw.append(f"• {h(spec)} <i>({h(str(rule.get('line', '')))})</i>")
        elif state == "absent":
            absent.append(f"• ufw {h(spec)}")
        else:
            kept.append(f"• ufw {h(spec)} — {h(str(rule.get('reason', '')))}")

    packages: list[str] = []
    for pkg in plan.packages:
        state = str(pkg.get("state", ""))
        name = str(pkg.get("name", ""))
        if state == "purge":
            packages.append(f"• {h(name)} {h(str(pkg.get('version', '')))}")
        elif state == "absent":
            absent.append(f"• {h(name)}")
        elif state == "skip":
            kept.append(f"• {h(name)} — {h(str(pkg.get('reason', '')))}")

    users: list[str] = []
    for user in plan.users:
        state = str(user.get("state", ""))
        name = str(user.get("name", ""))
        uid = str(user.get("uid", ""))
        if state == "delete":
            users.append(f"• {h(name)} (uid {h(uid)})")
        elif state == "absent":
            absent.append(f"• {h(name)}")
        elif state == "keep":
            kept.append(f"• {h(name)} — {h(str(user.get('reason', '')))}")

    def section(title_key: str, items: list[str]) -> None:
        if items:
            lines.append("")
            lines.append(t(title_key))
            lines.extend(_cut(items))

    section("module_uninstall_section_units", units)
    section("module_uninstall_section_files", files)
    section("module_uninstall_section_ufw", ufw)
    section("module_uninstall_section_packages", packages)
    section("module_uninstall_section_users", users)
    if plan.env_state in ("set_false", "append", "already_false"):
        lines += ["", t("module_uninstall_section_env"),
                  "• " + t(f"module_uninstall_env_{plan.env_state}", var=h(plan.env_key))]
    section("module_uninstall_section_absent", absent)
    shared = [f"• {h(str(s.get('what', '')))} — {h(str(s.get('reason', '')))}" for s in plan.skipped_shared]
    section("module_uninstall_section_shared", shared)
    section("module_uninstall_section_kept", kept)

    warnings = [f"• {h(w)}" for w in plan.warnings]
    for w in plan.bot_warnings:
        if w.startswith("relays:"):
            warnings.append("• " + t("module_uninstall_relays_warning", relays=h(w.split(":", 1)[1])))
        else:
            warnings.append(f"• {h(w)}")
    section("module_uninstall_section_warnings", warnings)
    if plan.blocking:
        section("module_uninstall_section_blocking", [f"• {h(b)}" for b in plan.blocking])
        lines += ["", t("module_uninstall_blocked_note")]
        return _fit(lines)

    lines += [
        "",
        t("module_uninstall_marker_line", path=h(plan.marker_path)),
        t("module_uninstall_backup_line", dir=h(plan.backup_dir), size=h(format_bytes(plan.backup_estimate_bytes))),
        "",
        t("module_uninstall_purge_note"),
    ]
    return _fit(lines)


def _item_line(item: dict[str, object]) -> str:
    detail = str(item.get("detail", "") or "")
    text = f"• {h(str(item.get('kind', '')))} {h(str(item.get('item', '')))}"
    return text + (f" — {h(detail)}" if detail else "")


def _step(step: str) -> str:
    known = ("backup", "units", "files", "ufw", "packages", "users", "env", "marker", "signal")
    return t(f"module_uninstall_step_{step}") if step in known else step


def uninstall_report_text(report: UninstallReport) -> str:
    label = h(_label(report.protocol))
    if report.nothing_to_do:
        return t("module_uninstall_nothing_done", label=label)
    if report.ok:
        lines = [t("module_uninstall_ok", label=label, purged=report.purged)]
    elif report.rolled_back and not report.rollback_errors:
        lines = [t("module_uninstall_failed_rolled_back", label=label, step=h(_step(report.failed_step)))]
    elif report.rolled_back:
        lines = [t("module_uninstall_failed_rollback_incomplete", label=label, step=h(_step(report.failed_step)))]
    else:
        lines = [t("module_uninstall_failed_nothing_changed", label=label,
                   step=h(_step(report.failed_step or "backup")))]

    def section(key: str, items: Sequence[dict[str, object]]) -> None:
        if items:
            lines.extend(["", t(key, count=len(items)), *_cut([_item_line(i) for i in items])])

    section("module_uninstall_section_removed", report.removed)
    section("module_uninstall_section_absent_count", report.already_absent)
    section("module_uninstall_section_skipped_count", report.skipped)
    if report.errors:
        lines += ["", t("module_uninstall_section_errors"), *_cut([f"• {h(e)}" for e in report.errors], 5)]
    if report.rollback_errors:
        lines += ["", t("module_uninstall_section_rollback_errors"),
                  *_cut([f"• {h(e)}" for e in report.rollback_errors], 5)]
    if report.backup:
        lines += ["", t("module_uninstall_report_backup", path=h(report.backup))]
    if report.rollback_command and (report.ok or report.rollback_errors):
        lines.append(t("module_uninstall_report_rollback", command=h(report.rollback_command)))
    return _fit(lines)
