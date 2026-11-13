"""Texts and keyboards of the setup wizard (docs/wizard.md).

Shared by the handlers (bot/handlers/admin_wizard.py) and the background notifier
(bot/wizard_notifier.py), so a progress message looks the same whichever of the two
last edited it — including after a restart of the bot.
"""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import WizardRun
from services.wizard import Item, StatusSnapshot
from services.wizard_modes import MODES
from utils.formatting import h

STATE_ICONS = {
    "planned": "📝",
    "running": "⏳",
    "verifying": "🔎",
    "succeeded": "✅",
    "rolled_back": "↩️",
    "failed": "❌",
    "cancelled": "🚫",
}
LEVEL_ICONS = {"green": "🟢", "yellow": "🟡", "red": "🔴"}
STEP_ORDER = ("plan", "apply", "verify", "rollback")
_MAX_PRE = 2500


def mode_title(key: str) -> str:
    return t(f"wizard_mode_{key}") if key in MODES else key


def state_label(state: str) -> str:
    return f"{STATE_ICONS.get(state, '•')} {t(f'wizard_state_{state}')}"


def _pre(text: str) -> str:
    body = text if len(text) <= _MAX_PRE else text[:_MAX_PRE] + "\n…"
    return f"<pre>{h(body)}</pre>"


def header(run: WizardRun) -> str:
    who = t("wizard_origin_scheduled") if run.origin == "scheduled" else ""
    return t("wizard_run_header", mode=h(mode_title(run.mode)), id=run.id, state=state_label(run.state)) + (
        f"\n{who}" if who else ""
    )


def _steps_line(snap: StatusSnapshot) -> str:
    marks = {"start": "⏳", "ok": "✅", "fail": "❌"}
    parts = [f"{marks.get(snap.step_states[s], '•')} {s}" for s in STEP_ORDER if s in snap.step_states]
    return " · ".join(parts)


def progress_text(run: WizardRun, snap: StatusSnapshot) -> str:
    lines = [header(run)]
    steps = _steps_line(snap)
    if steps:
        lines.append(steps)
    if snap.progress:
        lines.append("")
        lines.extend(f"• {h(p)}" for p in snap.progress[-6:])
    if run.mode == "update" and run.phase == "execute":
        lines += ["", t("wizard_update_restart_note")]
    return "\n".join(lines)


def plan_text(run: WizardRun, snap: StatusSnapshot | None = None) -> str:
    body = (snap.plan_text if snap is not None and snap.plan_text else run.summary) or "—"
    return "\n".join([header(run), "", t("wizard_plan_title"), _pre(body), t("wizard_plan_confirm_hint")])


def _items_block(items: list[Item]) -> str:
    order = {"red": 0, "yellow": 1, "green": 2}
    return "\n".join(
        f"{LEVEL_ICONS[i.level]} <b>{h(i.key)}</b>: {h(i.text)}" for i in sorted(items, key=lambda i: order[i.level])
    )


def final_text(run: WizardRun, snap: StatusSnapshot) -> str:
    lines = [header(run)]
    if run.mode == "selfcheck" and snap.items:
        counts = snap.counts or {
            level: sum(1 for i in snap.items if i.level == level) for level in ("green", "yellow", "red")
        }
        lines.append(t("wizard_selfcheck_counts", green=counts["green"], yellow=counts["yellow"], red=counts["red"]))
        lines += ["", _items_block(snap.items)]
    elif run.mode == "dump" and run.state == "succeeded":
        lines.append(t("wizard_dump_ready"))
    elif snap.result_text:
        lines += ["", _pre(snap.result_text)]
    elif run.summary:
        lines += ["", _pre(run.summary)]
    if run.state in ("failed", "rolled_back"):
        lines += ["", t("wizard_failed_hint")]
    return "\n".join(lines)


def scheduled_alert_text(run: WizardRun, snap: StatusSnapshot) -> str:
    if run.state != "succeeded":
        return t("wizard_scheduled_failed", id=run.id, state=state_label(run.state))
    return "\n".join([t("wizard_scheduled_alert", id=run.id), "", _items_block(snap.deviations)])


# --------------------------------------------------------------------------- #
# Keyboards
# --------------------------------------------------------------------------- #
def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def menu_keyboard(*, active: WizardRun | None, daily: bool) -> InlineKeyboardMarkup:
    rows = [_row(f"{mode_title(key)}", f"wiz:start:{key}") for key in MODES]
    if active is not None:
        rows.insert(0, _row(t("btn_wizard_active", id=active.id, mode=mode_title(active.mode)), f"wiz:run:{active.id}"))
    rows.append(_row(t("btn_wizard_history"), "wiz:hist:0"))
    rows.append(_row(t("btn_wizard_daily_on") if daily else t("btn_wizard_daily_off"), "wiz:sched"))
    rows.append(_row(t("btn_admin_panel"), "admin:panel"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def progress_keyboard(run: WizardRun) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text=t("btn_refresh"), callback_data=f"wiz:run:{run.id}"),
                InlineKeyboardButton(text=t("btn_wizard_log"), callback_data=f"wiz:log:{run.id}"),
            ]
        ]
    )


def plan_keyboard(run: WizardRun) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_wizard_apply"), f"wiz:ok:{run.id}"),
            _row(t("btn_wizard_cancel"), f"wiz:no:{run.id}"),
            _row(t("btn_wizard_log"), f"wiz:log:{run.id}"),
        ]
    )


def final_keyboard(run: WizardRun, *, artifact: bool = False) -> InlineKeyboardMarkup:
    rows = [_row(t("btn_wizard_log"), f"wiz:log:{run.id}")]
    if artifact:
        rows.append(_row(t("btn_wizard_artifact"), f"wiz:art:{run.id}"))
    rows.append(_row(t("btn_wizard_menu"), "wiz:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def history_text(runs: list[WizardRun], page: int, total: int) -> str:
    if not runs:
        return t("wizard_history_empty")
    lines = [t("wizard_history_title", total=total)]
    for run in runs:
        when = run.created_at[:16].replace("T", " ")
        lines.append(f"{STATE_ICONS.get(run.state, '•')} #{run.id} · {h(mode_title(run.mode))} · {h(when)}")
    return "\n".join(lines)


def history_keyboard(runs: list[WizardRun], page: int, has_next: bool) -> InlineKeyboardMarkup:
    rows = [
        _row(f"{STATE_ICONS.get(r.state, '•')} #{r.id} {mode_title(r.mode)}", f"wiz:run:{r.id}") for r in runs
    ]
    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=f"wiz:hist:{page - 1}"))
    if has_next:
        nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=f"wiz:hist:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append(_row(t("btn_wizard_menu"), "wiz:menu"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def run_view(run: WizardRun, snap: StatusSnapshot) -> tuple[str, InlineKeyboardMarkup]:
    """The screen of one run, whatever state it is in."""
    if run.active and run.state == "planned" and run.plan_ready:
        return plan_text(run, snap), plan_keyboard(run)
    if run.active:
        return progress_text(run, snap), progress_keyboard(run)
    return final_text(run, snap), final_keyboard(run, artifact=snap.artifact is not None)
