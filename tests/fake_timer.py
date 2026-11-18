"""A bot.progress.Timer that moves only when the test says so.

Every wait of a progress message — its edit throttle, its animation tick — and of the
pollers next to an operation (a relay's ``update-status``) goes through a Timer. With
this one no such test waits on the real clock: a test parks the waiters, moves time
with :meth:`FakeTimer.advance`, and :meth:`FakeTimer.advance` returns once every
waiter it woke has done its work and parked again. Nothing here sleeps, so the result
does not depend on how fast or loaded the host is (deploy.sh runs the suite on a relay
with one vCPU).
"""

from __future__ import annotations

import asyncio

from bot.progress import Timer


class FakeTimer(Timer):
    def __init__(self, start: float = 1000.0) -> None:
        self.t = start
        self._waiters: list[tuple[float, asyncio.Future[None]]] = []
        # How many waits have parked so far (a waiter that wakes and waits again
        # counts again): what advance() and parked() synchronise on.
        self.parks = 0
        self._changed = asyncio.Event()

    def now(self) -> float:
        return self.t

    async def wait(self, event: asyncio.Event, timeout: float) -> bool:
        if event.is_set():
            return True
        due: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        entry = (self.t + timeout, due)
        self._waiters.append(entry)
        self.parks += 1
        self._changed.set()
        watcher = asyncio.ensure_future(event.wait())
        try:
            await asyncio.wait({watcher, due}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            watcher.cancel()
            self._waiters.remove(entry)
        return event.is_set()

    @property
    def waiting(self) -> int:
        """How many waits are parked right now."""
        return len(self._waiters)

    async def parked(self, count: int) -> None:
        """Until *count* waits have parked in total (event-driven, no polling)."""
        while self.parks < count:
            self._changed.clear()
            await self._changed.wait()

    async def advance(self, seconds: float, *, settle: bool = True) -> int:
        """Move time by *seconds*; every waiter whose deadline has come wakes. With
        *settle*, return once each of them has parked again (it did its step's work).
        Returns how many woke."""
        self.t += seconds
        due = [future for deadline, future in self._waiters if deadline <= self.t and not future.done()]
        target = self.parks + len(due)
        for future in due:
            future.set_result(None)
        if settle:
            await self.parked(target)
        return len(due)
