"""The wizard's messages (bot/wizard_views.py, bot/wizard_notifier.py).

* Whatever a helper wrote into the status file is HTML-escaped before it reaches
  Telegram (parse_mode=HTML): a `<` in a log line must not break the message.
* A progress message that can no longer be edited is replaced by a new one, which
  becomes the run's message (so the report after a restart lands somewhere).
* The dump's file follows the report; the scheduled alert goes to every superadmin.
* An item that names a message (``msg``/``args``) is shown in the reader's language;
  a message this bot does not know, or arguments that do not fill it, fall back to the
  helper's English text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from aiogram.exceptions import TelegramBadRequest
from aiogram.methods import EditMessageText

from bot.wizard_notifier import TelegramWizardNotifier
from bot.wizard_views import final_text, item_text, plan_text, progress_text, run_view, scheduled_alert_text
from i18n import use_locale
from models.dto import WizardRun
from services.wizard import Item, StatusSnapshot, parse_status

pytestmark = pytest.mark.timeout(30)


def run(**over: Any) -> WizardRun:
    base: dict[str, Any] = dict(
        id=3, mode="selfcheck", state="running", phase="execute", current_step="apply", params={}, started_by=9,
        origin="manual", chat_id=9, message_id=50, log_path="", summary="", plan_ready=False, active=True,
        created_at="2026-11-13T10:00:00+00:00", updated_at="2026-11-13T10:00:00+00:00", finished_at=None,
        reported_at=None,
    )
    base.update(over)
    return WizardRun(**base)


def test_helper_text_is_escaped_everywhere() -> None:
    snap = StatusSnapshot(progress=["<b>bold</b> & co"], plan_text="a <script>", result_text="x < y")
    snap.items = [Item("red", "perms", "<.env> is 0644")]
    assert "&lt;b&gt;bold&lt;/b&gt; &amp; co" in progress_text(run(), snap)
    assert "a &lt;script&gt;" in plan_text(run(mode="update", state="planned", plan_ready=True), snap)
    assert "&lt;.env&gt;" in final_text(run(state="succeeded", active=False), snap)
    assert "x &lt; y" in final_text(run(mode="update", state="succeeded", active=False), snap)
    assert "&lt;.env&gt;" in scheduled_alert_text(run(origin="scheduled", state="succeeded"), snap)


def test_an_item_is_shown_in_the_readers_language() -> None:
    args = (("addr", "172.16.0.2"), ("protos", "VLESS/SOCKS5"), ("wan", "eth0"))
    item = Item("red", "warp:egress", "English fallback", "warp_egress_no_snat", args)
    with use_locale("ru"):
        ru = item_text(item)
    with use_locale("en"):
        en = item_text(item)
    assert ru == "VLESS/SOCKS5 уходят в eth0 с адресом 172.16.0.2 без SNAT — трафик не выходит; hy2 при этом может работать"
    assert en.startswith("VLESS/SOCKS5 leave into eth0 with source 172.16.0.2 and no SNAT")
    with use_locale("ru"):
        text = final_text(run(state="succeeded", active=False), StatusSnapshot(items=[item]))
    assert "🔴 <b>warp:egress</b>: VLESS/SOCKS5 уходят в eth0" in text


def test_an_unknown_message_or_missing_arguments_fall_back_to_the_helpers_text() -> None:
    assert item_text(Item("yellow", "x", "plain <text>", "no_such_message", ())) == "plain <text>"
    assert item_text(Item("red", "warp", "fallback", "warp_down", ())) == "fallback"  # {iface} unfilled
    assert item_text(Item("green", "disk", "no msg at all")) == "no msg at all"
    snap = StatusSnapshot(items=[Item("red", "warp", "x", "warp_down", (("iface", "<b>"),))])
    assert "&lt;b&gt;" in final_text(run(state="succeeded", active=False), snap)  # arguments are escaped too


def test_run_view_picks_the_screen_by_state() -> None:
    snap = parse_status("")
    _, plan_kb = run_view(run(mode="update", state="planned", plan_ready=True), snap)
    assert [b.callback_data for r in plan_kb.inline_keyboard for b in r][:2] == ["wiz:ok:3", "wiz:no:3"]
    _, progress_kb = run_view(run(), snap)
    # While a run moves: only «📄 Лог» — no «Обновить», no second confirmation.
    assert [b.callback_data for r in progress_kb.inline_keyboard for b in r] == ["wiz:log:3"]
    snap.artifact = "dump.txt"
    _, final_kb = run_view(run(mode="dump", state="succeeded", active=False), snap)
    assert "wiz:art:3" in [b.callback_data for r in final_kb.inline_keyboard for b in r]


class FakeService:
    def __init__(self) -> None:
        self.attached: list[tuple[int, int, int]] = []

    async def attach_message(self, run_id: int, chat_id: int, message_id: int) -> None:
        self.attached.append((run_id, chat_id, message_id))

    async def artifact_document(self, run: WizardRun, name: str) -> tuple[str, bytes] | None:
        return (f"wizard-{run.id}-{name}", b"dump")


@dataclass
class Sent:
    message_id: int


class FakeBot:
    def __init__(self, *, editable: bool = True) -> None:
        self.editable = editable
        self.sent: list[tuple[int, str]] = []
        self.documents: list[tuple[int, str]] = []
        self.edits = 0

    async def edit_message_text(self, text: str, **_: Any) -> None:
        self.edits += 1
        if not self.editable:
            raise TelegramBadRequest(method=EditMessageText(text=text), message="Bad Request: message to edit not found")

    async def send_message(self, chat_id: int, text: str, **_: Any) -> Sent:
        self.sent.append((chat_id, text))
        return Sent(700 + len(self.sent))

    async def send_document(self, chat_id: int, document: Any, **_: Any) -> None:
        self.documents.append((chat_id, document.filename))


async def test_an_uneditable_message_is_replaced_and_remembered() -> None:
    bot, service = FakeBot(editable=False), FakeService()
    notifier = TelegramWizardNotifier(bot=bot, service=service, admin_ids={9})  # type: ignore[arg-type]
    ok = await notifier.finished(run(state="succeeded", active=False), parse_status(""))
    assert ok and bot.edits == 1 and len(bot.sent) == 1
    assert service.attached == [(3, 9, 701)]


async def test_progress_waits_for_the_handler_to_attach_a_message() -> None:
    bot = FakeBot()
    notifier = TelegramWizardNotifier(bot=bot, service=FakeService(), admin_ids={9})  # type: ignore[arg-type]
    await notifier.progress(run(message_id=None), parse_status(""))
    assert bot.edits == 0 and bot.sent == []


async def test_the_dump_file_follows_the_report() -> None:
    bot = FakeBot()
    notifier = TelegramWizardNotifier(bot=bot, service=FakeService(), admin_ids={9})  # type: ignore[arg-type]
    snap = parse_status('{"event": "artifact", "name": "dump.txt"}\n{"event": "finished", "outcome": "succeeded"}')
    assert await notifier.finished(run(mode="dump", state="succeeded", active=False), snap)
    assert bot.documents == [(9, "wizard-3-dump.txt")]


async def test_the_scheduled_alert_reaches_every_superadmin() -> None:
    bot = FakeBot()
    notifier = TelegramWizardNotifier(bot=bot, service=FakeService(), admin_ids={9, 10})  # type: ignore[arg-type]
    snap = StatusSnapshot(items=[Item("yellow", "reboot", "a reboot is required")])
    assert await notifier.scheduled_alert(run(origin="scheduled", state="succeeded", active=False), snap)
    assert sorted(chat for chat, _ in bot.sent) == [9, 10]


def test_a_failed_update_shows_the_deploys_cause() -> None:
    """«Обновить бота» (the main server): the cause deploy.sh reported, not just «failed»."""
    status = "\n".join([
        '{"event": "launched", "phase": "execute"}',
        '{"event": "result", "text": "no ROLLBACK REPORT", "verdict": "no_report", "reason": "tests", '
        '"fail_step": "tests", "excerpt": ["FAILED tests/test_a.py::test_b - <boom>"], '
        '"deploy_log": "/root/deploy-20261118T120000Z.log"}',
        '{"event": "finished", "outcome": "failed"}',
    ])
    snap = parse_status(status)
    with use_locale("ru"):
        from i18n import t

        text = final_text(run(mode="update", state="failed", active=False), snap)
        assert t("deploy_reason_tests") in text and t("deploy_step_tests") in text
    assert "FAILED tests/test_a.py::test_b - &lt;boom&gt;" in text
    assert "/root/deploy-20261118T120000Z.log" in text


def test_a_successful_update_shows_the_deploys_warning() -> None:
    status = "\n".join([
        '{"event": "launched", "phase": "execute"}',
        '{"event": "result", "text": "===== DEPLOY OK =====", "verdict": "deploy_ok", '
        '"warnings": [{"code": "upstream_preexisting", "text": "x"}]}',
        '{"event": "finished", "outcome": "succeeded"}',
    ])
    text = final_text(run(mode="update", state="succeeded", active=False), parse_status(status))
    assert "⚠️" in text



def test_the_update_plan_lists_the_deploys_steps_waiting() -> None:
    text = plan_text(run(mode="update", state="planned", plan_ready=True), StatusSnapshot(plan_text="x"))
    assert text.count("⚪") == 8


def test_a_running_update_shows_its_steps_and_tests_and_survives_the_restart() -> None:
    """The steps come from the status file (the helper's ``deploy`` events): the bot that
    the deploy restarted reads the same file and edits the same message (message_id
    in wizard_runs) — and closes it with the result."""
    progress = {"step": "tests", "steps": {"preflight": "ok", "fetch": "ok", "tests": "run"},
                "tests": {"done": 2802, "total": 5604}}
    status = "\n".join([
        '{"event": "launched", "phase": "execute"}',
        '{"event": "deploy", "progress": ' + __import__("json").dumps(progress) + "}",
    ])
    snap = parse_status(status)
    text = progress_text(run(mode="update", phase="execute"), snap)
    assert "✅" in text and "🔄" in text and "2802/5604" in text and text.count("⚪") == 5
    assert "50%" in text
    done = parse_status(status + '\n{"event": "result", "text": "===== DEPLOY OK =====", "verdict": "deploy_ok"}'
                        '\n{"event": "finished", "outcome": "succeeded"}')
    final = final_text(run(mode="update", state="succeeded", active=False), done)
    assert final.count("✅") >= 8 and "⚪" not in final


# ── «Состояние:» as it is (one message, one confirmation — «⬆️ Обновить бота») ──
def _status_lines(*records: dict[str, Any]) -> str:
    import json

    return "\n".join(json.dumps(r) for r in records)


def _state_line(text: str) -> str:
    from i18n import t

    prefix = t("wizard_run_header", mode="M", id=1, state="S").split("S")[0].split("\n")[-1]
    return next(line for line in text.splitlines() if line.startswith(prefix))


def test_after_the_first_step_marker_the_state_is_not_plan() -> None:
    """Run #6 on he2's main: «Состояние: 📝 план» while the steps were already ✅✅🔄."""
    from i18n import t

    planning = run(mode="update", state="planned", phase="plan", current_step="plan")
    launched = parse_status(_status_lines({"event": "launched", "phase": "plan"}))
    moving = parse_status(_status_lines(
        {"event": "launched", "phase": "plan"},
        {"event": "deploy", "progress": {"step": "tests", "steps": {"preflight": "ok", "fetch": "ok", "tests": "run"}}},
    ))
    first = _state_line(progress_text(planning, launched))
    assert t("wizard_state_planned") not in first, "a confirmed run is running from its start"
    line = _state_line(progress_text(planning, moving))
    assert t("wizard_state_planned") not in line and t("wizard_state_running") in line
    assert t("wizard_state_step", step=t("deploy_step_tests")) in line
    # The execute phase: the plan's steps stay ✅, the deploy's own steps move on.
    execute = parse_status(_status_lines(
        {"event": "launched", "phase": "plan"},
        {"event": "deploy", "progress": {"step": "checks", "steps": {
            "preflight": "ok", "fetch": "ok", "tests": "ok", "checks": "ok"}}},
        {"event": "launched", "phase": "execute"},
        {"event": "deploy", "progress": {"step": "fetch", "steps": {"preflight": "ok", "fetch": "run", "tests": "wait"}}},
    ))
    text = progress_text(run(mode="update", state="running", phase="execute"), execute)
    assert "✅ " + t("deploy_step_tests") in text and "✅ " + t("deploy_step_checks") in text
    assert "🔄 " + t("deploy_step_fetch") in text and "⚪ " + t("deploy_step_install") in text
    # A legacy plan that waits for «Применить» is the only «план»; the end says how it ended.
    assert t("wizard_state_planned") in _state_line(plan_text(run(mode="update", state="planned", plan_ready=True)))
    done = final_text(run(mode="update", state="succeeded", active=False), execute)
    assert t("wizard_state_succeeded") in _state_line(done)
    failed = final_text(run(mode="update", state="failed", active=False), execute)
    assert t("wizard_state_failed") in _state_line(failed)


def test_the_update_plan_before_the_run_is_one_screen_with_one_confirmation() -> None:
    from bot.wizard_views import update_confirm_keyboard, update_plan_text
    from i18n import t

    text = update_plan_text()
    assert text.count("⚪") == 8 and t("wizard_update_confirm_hint") in text
    assert t("wizard_update_confirm_code") in update_plan_text(needs_code=True)
    assert [b.callback_data for r in update_confirm_keyboard().inline_keyboard for b in r] == ["wiz:go:update", "wiz:menu"]


def test_the_result_has_its_log_and_back() -> None:
    _, final_kb = run_view(run(mode="update", state="failed", active=False), StatusSnapshot())
    assert [b.callback_data for r in final_kb.inline_keyboard for b in r] == ["wiz:log:3", "wiz:menu"]
