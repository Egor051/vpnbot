
import time
from collections import OrderedDict


class RateLimitExceeded(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__(f"Слишком часто. Повторите через {retry_after} сек.")


class RateLimiter:
    def __init__(self, max_entries: int = 2048) -> None:
        self.max_entries = max_entries
        self._last_seen: OrderedDict[tuple[int, str], float] = OrderedDict()

    def check(self, user_id: int, action: str, cooldown_seconds: float) -> None:
        now = time.monotonic()
        key = (user_id, action)
        last = self._last_seen.get(key)
        if last is not None:
            retry_after = cooldown_seconds - (now - last)
            if retry_after > 0:
                raise RateLimitExceeded(max(1, int(retry_after)))
            self._last_seen.move_to_end(key)
        self._last_seen[key] = now
        self._trim()

    def _trim(self) -> None:
        while len(self._last_seen) > self.max_entries:
            self._last_seen.popitem(last=False)
