
import time
from collections import OrderedDict


class RateLimitExceeded(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__(f"Слишком часто. Повторите через {retry_after} сек.")


class RateLimiter:
    """Fixed-window counter, keyed by ``(caller, action)``.

    A window opens on the first accepted call and lasts ``cooldown_seconds``;
    up to ``burst`` calls are accepted inside it and everything beyond that is
    refused until the window ends. With the default ``burst=1`` this is exactly
    the plain cooldown the bot handlers have always used — one call, then wait —
    so those call sites keep their behaviour unchanged.
    """

    def __init__(self, max_entries: int = 2048) -> None:
        self.max_entries = max_entries
        # key -> (window start, calls accepted in that window)
        self._windows: OrderedDict[tuple[int, str], tuple[float, int]] = OrderedDict()

    def check(self, user_id: int, action: str, cooldown_seconds: float, burst: int = 1) -> None:
        now = time.monotonic()
        key = (user_id, action)
        allowance = max(1, int(burst))
        window = self._windows.get(key)
        if window is not None:
            # Keep the entry "hot" (most-recently-used) even while throttling so
            # that an actively spamming key cannot be evicted by _trim() — that
            # would drop its window and reset the cooldown, defeating the limit.
            self._windows.move_to_end(key)
            started, used = window
            retry_after = cooldown_seconds - (now - started)
            if retry_after > 0:
                if used >= allowance:
                    # A refusal never extends the window: a client hammering the
                    # endpoint waits out the window it opened, no longer.
                    raise RateLimitExceeded(max(1, int(retry_after)))
                self._windows[key] = (started, used + 1)
                return
        self._windows[key] = (now, 1)
        self._trim()

    def _trim(self) -> None:
        while len(self._windows) > self.max_entries:
            self._windows.popitem(last=False)
