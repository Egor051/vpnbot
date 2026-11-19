"""The progress of a long operation in ONE Telegram message (D).

The message is a list of the operation's steps, each with its state:

    ⚪ waits · 🔄 runs · ✅ done · ❌ failed · ⏭ skipped

and, under the list while a step runs, an activity line: stars growing 1 → 6 and back
to 1 («*», «**», … «******», «*»), or — when the running step has a measurable
progress (pytest: passed of collected; a reconcile: N of M) — «42%». The order is
always: the plan with every step ⚪ and «Подтвердить» (:meth:`ProgressMessage.show_plan`),
then, after the confirmation, the run (:meth:`ProgressMessage.run`), then the result
(:meth:`ProgressMessage.finish`).

Edits: at most one per :data:`PROGRESS_EDIT_INTERVAL_SECONDS` per message (Telegram
throttles edits of one message), an edit with an unchanged text is not sent, «message
is not modified» is no error, and a 429 (TelegramRetryAfter) is waited out by
:func:`bot.messages.safe_edit_message_text` — it never fails the operation. An edit
that still fails is logged and the operation goes on; the final edit is always sent.

Time: every wait of a progress message — the throttle, the animation's tick, and the
pollers that run next to an operation (the relay's ``update-status``) — goes through
its :class:`Timer` (``now`` + ``wait``). Production uses real time (:data:`TIMER`);
a test hands a fake one that moves only when the test says so (tests/fake_timer.py),
so no progress test depends on how fast the host is.

Used by: the All-in-One reconcile and the relay card's scoped twin
(bot/handlers/admin_bundles.py, admin_relays.py), the fallback switch
(admin_fallback.py), the relay's SSH port move (ssh_port.py) and the relay's
«Обновить агент» (admin_relays.py, with the agent's ``update-status``). The main
server's «Обновить бота» renders the same list from the wizard's status file
(bot/wizard_views.py) — its message survives the bot's own restart there.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from aiogram.types import InaccessibleMessage, InlineKeyboardMarkup, Message

from bot import messages
from utils.formatting import h

logger = logging.getLogger(__name__)

# The progress message is edited no more often than this (Telegram throttles edits
# of one message, and a step can take well under a second).
PROGRESS_EDIT_INTERVAL_SECONDS = 3.0
ICONS = {"wait": "⚪", "run": "🔄", "ok": "✅", "fail": "❌", "skip": "⏭"}
STATES = frozenset(ICONS)
MAX_STARS = 6

T = TypeVar("T")
Edit = Callable[..., Awaitable[bool]]


class Timer:
    """Real time: what a progress message (and a poller next to it) reads and waits with.

    :meth:`now` is a monotonic clock in seconds; :meth:`wait` waits for *event* at
    most *timeout* seconds and says whether it is set. A test swaps in a fake one
    (``bot.progress.TIMER``, or the ``timer`` of a :class:`ProgressMessage`)."""

    def now(self) -> float:
        return time.monotonic()

    async def wait(self, event: asyncio.Event, timeout: float) -> bool:
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except TimeoutError:
            return event.is_set()
        return True


# The timer a ProgressMessage gets when it is given none (read when it is built).
TIMER = Timer()


def current_timer() -> Timer:
    return TIMER


@dataclass
class Step:
    key: str
    title: str
    state: str = "wait"
    done: int | None = None
    total: int | None = None
    note: str = ""

    @property
    def percent(self) -> int | None:
        if self.done is None or not self.total:
            return None
        return max(0, min(100, self.done * 100 // self.total))


def stars(tick: int) -> str:
    """The activity line: 1 → 6 stars, then 1 again."""
    return "*" * (tick % MAX_STARS + 1)


def render_steps(title: str, steps: Sequence[Step], *, tick: int | None = None, footer: str = "") -> str:
    """The message: *title*, one line per step, the activity line while one runs
    (*tick* None: no activity line — the plan and the result), then *footer*.
    *title* and *footer* are HTML already; a step's title and note are escaped."""
    lines = [title, ""]
    for step in steps:
        line = f"{ICONS.get(step.state, '•')} {h(step.title)}"
        if step.total:
            line += f" — {step.done or 0}/{step.total}"
        if step.note:
            line += f" — {h(step.note)}"
        lines.append(line)
    running = [step for step in steps if step.state == "run"]
    if tick is not None and running:
        percent = running[-1].percent
        lines += ["", f"{percent}%" if percent is not None else stars(tick)]
    if footer:
        lines += ["", footer]
    return "\n".join(lines)


@dataclass
class ProgressMessage:
    """Edits one message with :func:`render_steps`, at most once per *interval*."""

    message: Message | InaccessibleMessage | None
    title: str
    steps: list[Step]
    interval: float = PROGRESS_EDIT_INTERVAL_SECONDS
    timer: Timer = field(default_factory=current_timer)
    edit: Edit | None = None
    footer: str = ""
    # The keyboard every progress edit carries while the operation runs (only «📄 Лог»
    # — never a button that does nothing or that starts the run again); None: none.
    markup: InlineKeyboardMarkup | None = None
    tick: int = 0
    edits: int = 0
    _last_at: float | None = field(default=None, repr=False)
    _last_text: str | None = field(default=None, repr=False)

    # ── the state ─────────────────────────────────────────────────────────────

    def step(self, key: str) -> Step:
        for step in self.steps:
            if step.key == key:
                return step
        raise KeyError(key)

    def set(self, key: str, state: str, *, done: int | None = None, total: int | None = None,
            note: str | None = None) -> None:
        """A step's state (and its measurable progress / note). Shown by the next push."""
        if state not in STATES:
            raise ValueError(state)
        step = self.step(key)
        step.state = state
        if done is not None:
            step.done = done
        if total is not None:
            step.total = total
        if note is not None:
            step.note = note

    def start(self, key: str, *, note: str | None = None) -> None:
        """*key* runs; every step before it that still waits is done."""
        for step in self.steps:
            if step.key == key:
                break
            if step.state in ("wait", "run"):
                step.state = "ok"
        self.set(key, "run", note=note)

    def fail_at(self, key: str, note: str | None = None) -> None:
        """*key* failed: every step before it that still waits or runs is done (the
        operation got past it), *key* is ❌, a step after it that runs waits again."""
        failed = False
        for step in self.steps:
            if step.key == key:
                failed = True
                step.state = "fail"
                if note is not None:
                    step.note = note
            elif not failed and step.state in ("wait", "run"):
                step.state = "ok"
            elif failed and step.state == "run":
                step.state = "wait"
        if not failed:
            raise KeyError(key)

    def fail_running(self, note: str | None = None) -> None:
        """The running step (else the first waiting one) failed; the rest stays ⚪."""
        running = [s for s in self.steps if s.state == "run"] or [s for s in self.steps if s.state == "wait"][:1]
        for step in running[-1:]:
            step.state = "fail"
            if note is not None:
                step.note = note

    def complete(self) -> None:
        """Every step that still waits or runs is done."""
        for step in self.steps:
            if step.state in ("wait", "run"):
                step.state = "ok"

    # ── the message ───────────────────────────────────────────────────────────

    def text(self, *, activity: bool = True) -> str:
        return render_steps(self.title, self.steps, tick=self.tick if activity else None, footer=self.footer)

    async def _send(self, text: str, markup: InlineKeyboardMarkup | None) -> bool:
        edit = self.edit or messages.safe_edit_message_text
        try:
            await edit(self.message, text, reply_markup=markup)
        except Exception as exc:
            # A progress edit never fails the operation it reports on.
            logger.warning("Progress message edit failed: %s: %s", type(exc).__name__, exc)
            return False
        self._last_text = text
        self._last_at = self.timer.now()
        self.edits += 1
        return True

    async def show_plan(self, markup: InlineKeyboardMarkup | None) -> bool:
        """The plan: every step ⚪, no activity line, *markup* (with «Подтвердить»)."""
        return await self._send(self.text(activity=False), markup)

    async def push(self, *, force: bool = False, markup: InlineKeyboardMarkup | None = None) -> bool:
        """Edit when *interval* has passed since the last edit (or *force*) and the
        text changed. True when an edit went out."""
        now = self.timer.now()
        if not force and self._last_at is not None and now - self._last_at < self.interval:
            return False
        text = self.text()
        self.tick += 1
        if text == self._last_text and not force:
            return False
        return await self._send(text, markup if markup is not None else self.markup)

    async def animate(self, stop: asyncio.Event) -> None:
        """Until *stop*: one edit per *interval* (the activity line moves between the
        step changes; a step change waits for the next tick)."""
        while not stop.is_set():
            await self.push()
            await self.timer.wait(stop, self.interval)

    async def run(self, work: Awaitable[T]) -> T:
        """Await *work* while the message animates; the animation stops with it."""
        stop = asyncio.Event()
        animation = asyncio.create_task(self.animate(stop))
        try:
            return await work
        finally:
            stop.set()
            await asyncio.gather(animation, return_exceptions=True)

    async def finish(self, footer: str = "", markup: InlineKeyboardMarkup | None = None) -> bool:
        """The result: the steps as they ended, *footer*, *markup* — always sent."""
        self.footer = footer
        return await self._send(self.text(activity=False), markup)


def steps_of(pairs: Sequence[tuple[str, str]], **states: Any) -> list[Step]:
    """Steps from (key, title) pairs; ``key=state`` sets an initial state."""
    return [Step(key=key, title=title, state=str(states.get(key, "wait"))) for key, title in pairs]
