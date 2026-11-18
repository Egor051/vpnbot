"""bot/progress.py — the progress of a long operation in one Telegram message (D).

The step icons (⚪ 🔄 ✅ ❌ ⏭), the activity line (stars 1 → 6, then 1; a percentage
for a measurable step), at most one edit per PROGRESS_EDIT_INTERVAL_SECONDS, no edit
for an unchanged text, a 429 waited out, a failing edit never failing the operation,
the plan first (all ⚪) and the result always sent.

Time is the fake one of tests/fake_timer.py (the autouse ``fake_timer`` fixture): the
throttle and the animation move only when a test advances it — nothing here sleeps.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from aiogram.exceptions import TelegramRetryAfter
from aiogram.methods import EditMessageText

from bot.handlers.admin_bundles import PROGRESS_EDIT_INTERVAL_SECONDS
from bot.progress import PROGRESS_EDIT_INTERVAL_SECONDS as INTERVAL
from bot.progress import ProgressMessage, Step, Timer, render_steps, stars, steps_of
from fake_timer import FakeTimer

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


async def test_edits_at_most_every_three_seconds_and_never_the_same_text(fake_timer: FakeTimer) -> None:
    message = _Message()
    view = ProgressMessage(message, "T", steps_of([("a", "A"), ("b", "B")]))  # type: ignore[arg-type]
    assert view.timer is fake_timer, "a view built without a timer takes bot.progress.TIMER"
    view.start("a")
    assert await view.push(force=True)
    for _ in range(5):
        await fake_timer.advance(1.0)
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


async def test_the_plan_waits_then_run_animates_until_the_work_is_done(fake_timer: FakeTimer) -> None:
    """Explicit steps, no sleeps: the work waits on events the test sets, the animation
    ticks when the test moves the fake clock by one interval."""
    message = _Message()
    view = ProgressMessage(message, "T", steps_of([("a", "A"), ("b", "B")]))  # type: ignore[arg-type]
    await view.show_plan("MARKUP")  # type: ignore[arg-type]
    assert message.edits[-1] == ("T\n\n⚪ A\n⚪ B", "MARKUP")
    view.start("a")
    to_b, at_b, done = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def work() -> str:
        await to_b.wait()
        view.start("b")
        at_b.set()
        await done.wait()
        return "ok"

    running = asyncio.create_task(view.run(work()))
    await fake_timer.parked(1)  # the animation's tick waits
    assert message.edits[-1][0] == "T\n\n⚪ A\n⚪ B", "the plan went out just now: no frame inside the interval"
    assert await fake_timer.advance(view.interval) == 1
    assert message.edits[-1][0] == "T\n\n🔄 A\n⚪ B\n\n*"
    assert await fake_timer.advance(view.interval - 0.5) == 0, "no tick before the interval"
    assert await fake_timer.advance(0.5) == 1
    assert message.edits[-1][0] == "T\n\n🔄 A\n⚪ B\n\n**", "the activity line moves"
    to_b.set()
    await at_b.wait()  # the work moved to B (no clock involved)
    await fake_timer.advance(view.interval)
    assert message.edits[-1][0] == "T\n\n✅ A\n🔄 B\n\n***"
    edits = len(message.edits)
    done.set()
    assert await running == "ok"
    assert len(message.edits) == edits, "the animation stopped with the work: no frame after it"
    assert fake_timer.waiting == 0


async def test_a_step_change_waits_for_the_next_tick(fake_timer: FakeTimer) -> None:
    """The throttle on the fake clock: a change inside the interval is not sent, the
    next push after it is."""
    message = _Message()
    view = ProgressMessage(message, "T", steps_of([("a", "A"), ("b", "B")]))  # type: ignore[arg-type]
    view.start("a")
    assert await view.push()
    view.start("b")
    await fake_timer.advance(view.interval - 0.001)
    assert not await view.push(), "inside the interval: no edit"
    await fake_timer.advance(0.001)
    assert await view.push()
    assert message.edits[-1][0].startswith("T\n\n✅ A\n🔄 B")


async def test_the_real_timer_waits_for_the_event_or_the_timeout() -> None:
    timer = Timer()
    event = asyncio.Event()
    event.set()
    assert await timer.wait(event, 60.0) is True, "a set event answers at once"
    assert await timer.wait(asyncio.Event(), 0.0) is False, "a timeout says so"
    assert timer.now() <= timer.now()


def test_fail_at_closes_the_steps_before_and_reopens_the_ones_after() -> None:
    view = ProgressMessage(None, "T", steps_of([("a", "A"), ("b", "B"), ("c", "C"), ("d", "D")], b="skip"))
    view.set("d", "run")
    view.fail_at("c", "boom")
    assert [s.state for s in view.steps] == ["ok", "skip", "fail", "wait"] and view.step("c").note == "boom"
    with pytest.raises(KeyError):
        view.fail_at("zzz")


def test_fail_running_marks_the_running_step_and_keeps_the_rest() -> None:
    view = ProgressMessage(None, "T", steps_of([("a", "A"), ("b", "B"), ("c", "C")]))
    view.start("b")
    view.fail_running("x")
    assert [s.state for s in view.steps] == ["ok", "fail", "wait"] and view.step("b").note == "x"
    with pytest.raises(ValueError):
        view.set("a", "bogus")
