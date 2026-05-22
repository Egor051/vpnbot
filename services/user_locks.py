
import asyncio
import weakref
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator


class UserLockManager:
    def __init__(self) -> None:
        self._guard = asyncio.Lock()
        self._locks: weakref.WeakValueDictionary[int, asyncio.Lock] = weakref.WeakValueDictionary()

    @asynccontextmanager
    async def lock(self, user_id: int) -> AsyncIterator[None]:
        async with self._guard:
            lock = self._locks.get(user_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[user_id] = lock
        # `lock` is a strong reference held for the entire lifetime of this
        # context manager (the coroutine is suspended at `yield`, not exited).
        # WeakValueDictionary cannot GC the Lock while any caller is waiting to
        # enter or is inside the `async with` block — so two coroutines for the
        # same user_id always contend on the exact same Lock object.
        await lock.acquire()
        try:
            yield
        finally:
            lock.release()
