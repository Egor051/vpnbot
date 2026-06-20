
from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections.abc import Awaitable, Callable, Hashable

logger = logging.getLogger(__name__)

# Defaults for the server-status panel: re-render every few seconds, but cap the
# total lifetime so an abandoned panel stops hammering Telegram and ``/proc``.
DEFAULT_INTERVAL_SECONDS = 3.0
DEFAULT_DURATION_SECONDS = 3600.0  # one hour


class LiveRefreshManager:
    """Runs a periodic refresh loop per on-screen panel, with a lifetime cap.

    Each open panel is tracked by an arbitrary hashable ``key`` (the bot layer
    uses ``(chat_id, message_id)``). Starting a loop for a key that already has
    one cancels the old loop first, so a panel never has two loops fighting over
    the same message. A loop ends when:

    * the ``refresh`` callback reports the target is gone (returns ``False``),
    * the lifetime cap elapses — then ``on_expire`` runs once, and
    * :meth:`cancel` is called (e.g. the user navigated away).

    All timing goes through an injectable monotonic ``clock`` so tests can drive
    the loop deterministically without real sleeps.
    """

    def __init__(
        self,
        *,
        interval: float = DEFAULT_INTERVAL_SECONDS,
        duration: float = DEFAULT_DURATION_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._interval = interval
        self._duration = duration
        self._clock = clock
        self._sleep = sleep
        self._tasks: dict[Hashable, asyncio.Task[None]] = {}

    def start(
        self,
        key: Hashable,
        *,
        refresh: Callable[[], Awaitable[bool]],
        on_expire: Callable[[], Awaitable[None]],
    ) -> None:
        """Begin (or restart) the refresh loop for ``key``."""
        self.cancel(key)
        task = asyncio.create_task(self._run(key, refresh, on_expire))
        self._tasks[key] = task
        task.add_done_callback(functools.partial(self._forget, key))

    def cancel(self, key: Hashable) -> None:
        """Stop the refresh loop for ``key`` if one is running."""
        task = self._tasks.pop(key, None)
        if task is not None and not task.done():
            task.cancel()

    def active(self, key: Hashable) -> bool:
        """Return whether a refresh loop is currently running for ``key``."""
        task = self._tasks.get(key)
        return task is not None and not task.done()

    def _forget(self, key: Hashable, task: asyncio.Task[None]) -> None:
        # Only drop the entry if it still points at the task that just finished;
        # a concurrent ``start`` may have already replaced it.
        if self._tasks.get(key) is task:
            del self._tasks[key]

    async def _run(
        self,
        key: Hashable,
        refresh: Callable[[], Awaitable[bool]],
        on_expire: Callable[[], Awaitable[None]],
    ) -> None:
        deadline = self._clock() + self._duration
        next_tick = self._clock() + self._interval
        try:
            while self._clock() < deadline:
                delay = next_tick - self._clock()
                if delay > 0:
                    await self._sleep(delay)
                if self._clock() >= deadline:
                    break
                # Advance the schedule by a fixed step so a slow refresh (the
                # snapshot itself samples for ~1s) does not let drift accumulate.
                next_tick += self._interval
                try:
                    alive = await refresh()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.debug("live refresh tick failed for %r", key, exc_info=True)
                    continue
                if not alive:
                    return
            try:
                await on_expire()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("live refresh expiry handler failed for %r", key, exc_info=True)
        except asyncio.CancelledError:
            raise
