"""Texts and keyboards of the setup wizard (docs/wizard.md).

Shared by the handlers (bot/handlers/admin_wizard.py) and the background notifier
(bot/wizard_notifier.py), so a progress message looks the same whichever of the two
last edited it — including after a restart of the bot.
"""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from bot.deploy_views import deploy_failure_text, deploy_warnings_text
from bot.progress import STATES, Step, render_steps, steps_of
from i18n import t
from models.dto import WizardRun
from services.deploy_result import DEPLOY_STEPS
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
    # "setup": the first setup's own row in the history (no helper mode of its own).
    return t(f"wizard_mode_{key}") if key in MODES or key == "setup" else key


def state_label(state: str) -> str:
    return f"{STATE_ICONS.get(state, '•')} {t(f'wizard_state_{state}')}"


def _pre(text: str) -> str:
    body = text if len(text) <= _MAX_PRE else text[:_MAX_PRE] + "\n…"
    return f"<pre>{h(body)}</pre>"


def _current_step(snap: StatusSnapshot | None) -> str:
    """The step a run is in, as the reader names it: the deploy's step («тесты»), else
    the helper's (plan / apply / verify / rollback); "" before the first marker."""
    if snap is None:
        return ""
    progress = snap.deploy_progress
    step = progress.get("step") if isinstance(progress, dict) else None
    if isinstance(step, str) and step in DEPLOY_STEPS:
        return t(f"deploy_step_{step}")
    return t(f"wizard_step_{snap.step}") if snap.step in STEP_ORDER else ""


def run_state_label(run: WizardRun, snap: StatusSnapshot | None) -> str:
    """«Состояние:» as it IS: a plan waiting for its confirmation, running (and in which
    step), or how it ended — never «план» once the run has started moving."""
    if not run.active:
        return state_label(run.state)
    if run.state == "planned" and run.plan_ready:
        return state_label("planned")
    step = _current_step(snap)
    label = f"{STATE_ICONS['running']} {t('wizard_state_running')}"
    return f"{label} ({t('wizard_state_step', step=h(step))})" if step else label


def header(run: WizardRun, snap: StatusSnapshot | None = None) -> str:
    who = t("wizard_origin_scheduled") if run.origin == "scheduled" else ""
    return t("wizard_run_header", mode=h(mode_title(run.mode)), id=run.id, state=run_state_label(run, snap)) + (
        f"\n{who}" if who else ""
    )


def update_plan_text(*, needs_code: bool = False) -> str:
    """«⬆️ Обновить бота» before the run exists: the deploy's steps, all ⚪, and the one
    confirmation (or, with TOTP, the code that is it)."""
    head = t("wizard_run_header_new", mode=h(mode_title("update")), state=state_label("planned"))
    steps = render_steps(t("wizard_update_steps_title"), deploy_steps_view(None)).strip()
    hint = t("wizard_update_confirm_code") if needs_code else t("wizard_update_confirm_hint")
    return "\n".join([head, "", steps, "", t("wizard_update_plan_note"), "", hint])


def update_confirm_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_relay_update_confirm"), callback_data="wiz:go:update")],
        [InlineKeyboardButton(text=t("btn_wizard_cancel"), callback_data="wiz:menu")],
    ])


def _steps_line(snap: StatusSnapshot) -> str:
    marks = {"start": "⏳", "ok": "✅", "fail": "❌"}
    parts = [f"{marks.get(snap.step_states[s], '•')} {s}" for s in STEP_ORDER if s in snap.step_states]
    return " · ".join(parts)


def deploy_steps_view(snap: StatusSnapshot | None, *, phase1_only: bool = False) -> list[Step]:
    """«Обновить бота»: the deploy's steps (bot/progress.py) from the helper's last
    ``deploy`` event — all ⚪ before it ran. *phase1_only*: the first four (a plan that
    waits for «Применить»). The execute phase keeps what the plan's CHECK already got
    through: a step it passed stays ✅ until the deploy reaches it again — never back to ⚪."""
    names = DEPLOY_STEPS[:4] if phase1_only else DEPLOY_STEPS
    steps = steps_of([(name, t(f"deploy_step_{name}")) for name in names])
    earlier = snap.earlier_deploy_progress if snap is not None else None
    earlier_states = earlier.get("steps") if isinstance(earlier, dict) else None
    if isinstance(earlier_states, dict):
        for step in steps:
            if earlier_states.get(step.key) == "ok":
                step.state = "ok"
    progress = snap.deploy_progress if snap is not None else None
    if isinstance(progress, dict):
        states = progress.get("steps")
        if isinstance(states, dict):
            for step in steps:
                state = states.get(step.key)
                if state not in STATES or (step.state == "ok" and state in ("wait", "skip")):
                    continue
                step.state = str(state)
        tests = progress.get("tests")
        if isinstance(tests, dict):
            for step in steps:
                if step.key == "tests":
                    done, total = tests.get("done"), tests.get("total")
                    step.done = done if isinstance(done, int) else None
                    step.total = total if isinstance(total, int) and total > 0 else None
    return steps


def helper_steps_view(snap: StatusSnapshot | None, *, closed: str | None = None) -> list[Step]:
    """A mode helper's own steps (``steps`` events: «📦 Установить протокол»), labelled
    ``install_step_<key>``. *closed* (the run's final state): a step still ⚪/🔄 of a run
    that succeeded is ✅ — it had nothing to do — and 🔄 of one that failed goes back to ⚪."""
    if snap is None or not snap.helper_steps:
        return []
    steps = [Step(key=k, title=t(f"install_step_{k}"), state=v) for k, v in snap.helper_steps.items()]
    if closed is not None:
        for step in steps:
            if step.state == "run":
                step.state = "ok" if closed == "succeeded" else "wait"
    return steps


def progress_text(run: WizardRun, snap: StatusSnapshot) -> str:
    if snap.helper_steps and run.phase == "execute":
        # The helper's steps, the activity line moving with every new event.
        return render_steps(header(run, snap), helper_steps_view(snap), tick=snap.events)
    if run.mode == "update":
        # The deploy's own steps (all of them: the plan's CHECK is the run's first
        # half), the activity line moving with every new event.
        body = render_steps(header(run, snap), deploy_steps_view(snap), tick=snap.events)
        return body + "\n\n" + t("wizard_update_restart_note")
    lines = [header(run, snap)]
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
    lines = [header(run, snap), "", t("wizard_plan_title"), _pre(body)]
    if run.mode == "update":
        # What «Применить» runs: the deploy's steps, all ⚪ (bot/progress.py).
        lines.append(render_steps(t("wizard_update_steps_title"), deploy_steps_view(None)).strip())
    steps = helper_steps_view(snap)
    if steps:
        # What «Применить» runs: the helper's steps, all ⚪.
        for step in steps:
            step.state = "wait"
        lines.append(render_steps(t("wizard_install_steps_title"), steps).strip())
    lines.append(t("wizard_plan_confirm_hint"))
    return "\n".join(lines)


def item_text(item: Item) -> str:
    """The item in the reader's language (``wizard_item_<msg>``), else the helper's text.

    A message this bot does not know, or arguments that do not fill it, fall back to
    the English ``text`` the helper wrote — a helper newer than the bot must not break
    the report. Plain text: the caller escapes it."""
    if item.msg:
        key = f"wizard_item_{item.msg}"
        template = t(key)  # t() returns the key itself for a message it does not know
        if template != key:
            try:
                # Always formatted (t() skips it without kwargs): a placeholder the
                # arguments do not fill is a fallback, never a raw "{iface}" in chat.
                return template.format_map(dict(item.args))
            except (KeyError, IndexError, ValueError):
                pass
    return item.text


def _items_block(items: list[Item]) -> str:
    order = {"red": 0, "yellow": 1, "green": 2}
    return "\n".join(
        f"{LEVEL_ICONS[i.level]} <b>{h(i.key)}</b>: {h(item_text(i))}" for i in sorted(items, key=lambda i: order[i.level])
    )


def final_text(run: WizardRun, snap: StatusSnapshot) -> str:
    lines = [header(run, snap)]
    if run.mode == "selfcheck" and snap.items:
        counts = snap.counts or {
            level: sum(1 for i in snap.items if i.level == level) for level in ("green", "yellow", "red")
        }
        lines.append(t("wizard_selfcheck_counts", green=counts["green"], yellow=counts["yellow"], red=counts["red"]))
        lines += ["", _items_block(snap.items)]
    elif run.mode == "dump" and run.state == "succeeded":
        lines.append(t("wizard_dump_ready"))
    elif run.mode in ("protocol", "site") and snap.helper_steps:
        lines += ["", render_steps(t("wizard_install_steps_title"), helper_steps_view(snap, closed=run.state)).strip()]
        if snap.items:
            lines += ["", _items_block(snap.items)]
        if snap.result_text:
            lines += ["", _pre(snap.result_text)]
    elif snap.result_text:
        lines += ["", _pre(snap.result_text)]
    elif run.summary:
        lines += ["", _pre(run.summary)]
    if run.mode == "update" and (snap.deploy_progress is not None or snap.earlier_deploy_progress is not None):
        # The steps as the deploy left them — closed with ✅ / ❌.
        steps = deploy_steps_view(snap)
        if run.state in ("failed", "rolled_back") and snap.deploy_failure is not None:
            failed = snap.deploy_failure.step
            if failed in DEPLOY_STEPS and not any(step.state == "fail" for step in steps):
                for step in steps:
                    if step.key == failed:
                        step.state = "fail"
                    elif step.state == "run":
                        step.state = "wait"
        if run.state == "succeeded":
            for step in steps:
                if step.state in ("wait", "run"):
                    step.state = "ok"
        lines += ["", render_steps(t("wizard_update_steps_title"), steps).strip()]
    if run.mode == "update" and snap.deploy_warnings:
        lines += ["", deploy_warnings_text(snap.deploy_warnings)]
    if run.mode == "update" and run.state in ("failed", "rolled_back") and snap.deploy_failure is not None:
        lines += ["", deploy_failure_text(snap.deploy_failure)]
    if snap.notes:
        lines += [""] + [h(note) for note in snap.notes]
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
    rows = [_row(f"{mode_title(key)}", f"wiz:start:{key}") for key, mode in MODES.items() if mode.menu]
    if active is not None:
        rows.insert(0, _row(t("btn_wizard_active", id=active.id, mode=mode_title(active.mode)), f"wiz:run:{active.id}"))
    # «🧭 Первичная настройка»: start or resume (services/first_setup.py).
    rows.append(_row(t("btn_wizard_first_setup"), "setup:start"))
    # The certificate's own screen: its runs need the names and the zone it works out.
    rows.append(_row(t("btn_wizard_cert"), "cert:menu"))
    # The decoy site's own screen: its runs need the archive the screen receives.
    rows.append(_row(t("btn_wizard_site"), "site:menu"))
    # «🛰 Relay» opens THE relay screen of the admin panel (no list of its own).
    rows.append(_row(t("btn_wizard_relay"), "admin:relays"))
    # The relays' SSH port: back to a held migration, or another port (bot/handlers/ssh_port.py).
    rows.append(_row(t("btn_wizard_relay_ssh_port"), "admin:sshp"))
    rows.append(_row(t("btn_wizard_relay_input_filter"), "admin:rfilt"))
    rows.append(_row(t("btn_wizard_history"), "wiz:hist:0"))
    rows.append(_row(t("btn_wizard_daily_on") if daily else t("btn_wizard_daily_off"), "wiz:sched"))
    rows.append(_row(t("btn_admin_panel"), "admin:panel"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def progress_keyboard(run: WizardRun) -> InlineKeyboardMarkup:
    """While a run moves: only «📄 Лог» — the message updates itself, a second «Обновить»
    or «Применить» would only start nothing or the same run again."""
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_wizard_log"), f"wiz:log:{run.id}")])


def plan_keyboard(run: WizardRun) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            _row(t("btn_wizard_apply"), f"wiz:ok:{run.id}"),
            _row(t("btn_wizard_cancel"), f"wiz:no:{run.id}"),
            _row(t("btn_wizard_log"), f"wiz:log:{run.id}"),
        ]
    )


def final_keyboard(run: WizardRun, *, artifact: bool = False) -> InlineKeyboardMarkup:
    """The result: its log (and the dump's file), and «⬅️ Назад» to the wizard."""
    rows = [_row(t("btn_wizard_log"), f"wiz:log:{run.id}")]
    if artifact:
        rows.append(_row(t("btn_wizard_artifact"), f"wiz:art:{run.id}"))
    rows.append(_row(t("btn_wizard_back"), "wiz:menu"))
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
