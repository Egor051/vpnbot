"""bot/progress.py — the progress of a long operation in one Telegram message (D).

The step icons (⚪ 🔄 ✅ ❌ ⏭), the activity line (stars 1 → 6, then 1; a percentage
for a measurable step), at most one edit per PROGRESS_EDIT_INTERVAL_SECONDS, no edit
for an unchanged text, a 429 waited out, a failing edit never failing the operation,
the plan first (all ⚪) and the result always sent.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from aiogram.exceptions import TelegramRetryAfter
from aiogram.methods import EditMessageText

from bot.handlers.admin_bundles import PROGRESS_EDIT_INTERVAL_SECONDS
from bot.progress import PROGRESS_EDIT_INTERVAL_SECONDS as INTERVAL
from bot.progress import ProgressMessage, Step, render_steps, stars, steps_of

pytestmark = pytest.mark.timeout(30)


class _Message:
    def __init__(self, *, flood: int = 0) -> None:
        self.edits: list[tuple[str, Any]] = []
        self.flood = flood

    async def edit_text(self, text: str, reply_markup: Any = None, **_: Any) -> None:
        if self.flood:
            self.flood -= 1
            raise TelegramRetryAfter(method=EditMessageText(text=text), message="flood", retry_after=2)
        self.edits.append((text, reply_markup))


def test_one_interval_everywhere() -> None:
    assert INTERVAL is PROGRESS_EDIT_INTERVAL_SECONDS
    assert PROGRESS_EDIT_INTERVAL_SECONDS == pytest.approx(3.0)


def test_stars_grow_to_six_and_start_over() -> None:
    assert [stars(i) for i in range(8)] == ["*", "**", "***", "****", "*****", "******", "*", "**"]


def test_render_icons_counts_and_activity() -> None:
    steps = [Step("a", "Alpha", "ok"), Step("b", "<B>", "run", done=42, total=100), Step("c", "C", "wait"),
             Step("d", "D", "skip"), Step("e", "E", "fail", note="boom")]
    text = render_steps("<b>T</b>", steps, tick=3)
    assert text.splitlines()[:7] == ["<b>T</b>", "", "✅ Alpha", "🔄 &lt;B&gt; — 42/100", "⚪ C", "⏭ D", "❌ E — boom"]
    assert text.endswith("42%"), "a measurable step: its percentage instead of the stars"
    steps[1].total = None
    assert render_steps("T", steps, tick=3).endswith("****")
    assert "*" not in render_steps("T", steps, tick=None), "the plan and the result have no activity line"


async def test_edits_at_most_every_three_seconds_and_never_the_same_text() -> None:
    now = [0.0]
    message = _Message()
    view = ProgressMessage(message, "T", steps_of([("a", "A"), ("b", "B")]), clock=lambda: now[0])  # type: ignore[arg-type]
    view.start("a")
    assert await view.push(force=True)
    for _ in range(5):
        now[0] += 1.0
        await view.push()
    assert len(message.edits) == 2, "t=0 and t=3"
    view.edit = None
    view.complete()
    await view.finish("done")
    assert message.edits[-1][0].startswith("T\n\n✅ A\n✅ B") and message.edits[-1][0].endswith("done")


async def test_a_flood_is_waited_out_not_fatal() -> None:
    message = _Message(flood=1)
    slept: list[float] = []

    async def edit(msg: Any, text: str, *, reply_markup: Any = None) -> bool:
        from bot.messages import safe_edit_message_text

        async def sleep(seconds: float) -> None:
            slept.append(seconds)

        return await safe_edit_message_text(msg, text, reply_markup=reply_markup, sleep=sleep)

    view = ProgressMessage(message, "T", steps_of([("a", "A")]), edit=edit)  # type: ignore[arg-type]
    assert await view.push(force=True)
    assert slept == [2] and len(message.edits) == 1


async def test_an_edit_that_fails_never_fails_the_operation() -> None:
    async def broken(*_: Any, **__: Any) -> bool:
        raise RuntimeError("telegram is down")

    view = ProgressMessage(None, "T", steps_of([("a", "A")]), edit=broken)
    assert not await view.push(force=True)
    assert await view.run(asyncio.sleep(0, result=7)) == 7


async def test_the_plan_waits_then_run_animates_until_the_work_is_done() -> None:
    message = _Message()
    view = ProgressMessage(message, "T", steps_of([("a", "A"), ("b", "B")]), interval=0.01)  # type: ignore[arg-type]
    await view.show_plan("MARKUP")  # type: ignore[arg-type]
    assert message.edits[-1] == ("T\n\n⚪ A\n⚪ B", "MARKUP")
    view.start("a")

    async def work() -> str:
        await asyncio.sleep(0.08)
        view.start("b")
        await asyncio.sleep(0.05)
        return "ok"

    assert await view.run(work()) == "ok"
    texts = [text for text, _ in message.edits[1:]]
    assert any("🔄 A" in text for text in texts) and any("✅ A\n🔄 B" in text for text in texts)
    assert len({text.rsplit("\n", 1)[-1] for text in texts}) > 1, "the activity line moves"


def test_fail_running_marks_the_running_step_and_keeps_the_rest() -> None:
    view = ProgressMessage(None, "T", steps_of([("a", "A"), ("b", "B"), ("c", "C")]))
    view.start("b")
    view.fail_running("x")
    assert [s.state for s in view.steps] == ["ok", "fail", "wait"] and view.step("b").note == "x"
    with pytest.raises(ValueError):
        view.set("a", "bogus")
