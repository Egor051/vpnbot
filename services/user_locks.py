
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
        await lock.acquire()
        try:
            yield
        finally:
            lock.release()
