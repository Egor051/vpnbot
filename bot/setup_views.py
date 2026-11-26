"""Texts and keyboards of «🧭 Первичная настройка» (services/first_setup.py).

One message: the steps with bot/progress.py's icons, what each found or did, and what the
setup waits for now — an answer typed into the chat, a choice, a run of the wizard (whose
own report arrives as its own message), or «🔁 Повторить» after a failure.
"""

from __future__ import annotations

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from bot.progress import Step, render_steps
from i18n import t
from repositories.protocol_modules import PROTOCOL_DISPLAY
from services.first_setup import PROTOCOL_CHOICES, STEPS, SetupView
from utils.formatting import h


def _row(text: str, data: str) -> list[InlineKeyboardButton]:
    return [InlineKeyboardButton(text=text, callback_data=data)]


def steps_of(view: SetupView) -> list[Step]:
    out = []
    for key in STEPS:
        state = view.states.get(key, "wait")
        out.append(Step(key=key, title=t(f"setup_step_{key}"), state=state if state in ("wait", "run", "ok", "fail", "skip")
                        else "wait", note=view.notes.get(key, "") if state in ("ok", "skip", "fail") else ""))
    return out


def setup_text(view: SetupView) -> str:
    head = t("setup_title", id=view.run_id)
    body = render_steps(head, steps_of(view), tick=None).strip()
    lines = [body, ""]
    if view.finished == "succeeded":
        lines.append(t("setup_done"))
    elif view.finished == "cancelled":
        lines.append(t("setup_cancelled"))
    elif view.waiting == "retry":
        lines.append(t("setup_failed", step=t(f"setup_step_{view.step}"), why=h(view.note[:400])))
    elif view.waiting == "run":
        lines.append(t("setup_waiting_run", step=t(f"setup_step_{view.step}"), note=h(view.note or "")))
    elif view.input_needed:
        prompt = t(f"setup_ask_{view.step}", domain=h(view.domain))
        if view.step == "protocols":
            chosen = ", ".join(PROTOCOL_DISPLAY.get(p, p) for p in view.protocols) or "—"
            prompt += "\n" + t("setup_protocols_chosen", chosen=h(chosen))
        lines.append(prompt)
    return "\n".join(lines)


def setup_keyboard(view: SetupView) -> InlineKeyboardMarkup:
    rid = view.run_id
    rows: list[list[InlineKeyboardButton]] = []
    if view.finished:
        rows.append(_row(t("btn_admin_panel"), "admin:panel"))
        return InlineKeyboardMarkup(inline_keyboard=rows)
    if view.waiting == "retry":
        rows.append(_row(t("btn_setup_retry"), f"setup:retry:{rid}"))
    elif view.input_needed == "domain":
        rows.append(_row(t("btn_setup_enter_domain"), f"setup:ask:domain:{rid}"))
    elif view.input_needed == "token":
        rows.append(_row(t("btn_setup_enter_token"), f"setup:ask:token:{rid}"))
    elif view.input_needed == "protocols":
        for proto in PROTOCOL_CHOICES:
            mark = "☑️" if proto in view.protocols else "⬜"
            rows.append(_row(f"{mark} {PROTOCOL_DISPLAY.get(proto, proto)}", f"setup:proto:{proto}:{rid}"))
        rows.append(_row(t("btn_setup_confirm"), f"setup:go:{rid}"))
    elif view.input_needed == "totp":
        rows.append(_row(t("btn_totp_enable"), "sec:totp:on"))
        rows.append(_row(t("btn_setup_totp_done"), f"setup:totp:done:{rid}"))
        rows.append(_row(t("btn_setup_totp_skip"), f"setup:totp:skip:{rid}"))
    else:
        rows.append(_row(t("btn_setup_refresh"), f"setup:show:{rid}"))
    rows.append(_row(t("btn_setup_cancel"), f"setup:cancel:{rid}"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def offer_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[_row(t("btn_setup_start"), "setup:start"),
                                                 _row(t("btn_setup_later"), "setup:later")])
