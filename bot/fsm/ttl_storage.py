
import asyncio
import logging
import time
from collections.abc import Mapping
from typing import Any

from aiogram.fsm.storage.base import StateType, StorageKey
from aiogram.fsm.storage.memory import MemoryStorage

logger = logging.getLogger(__name__)


class TTLMemoryStorage(MemoryStorage):
    """MemoryStorage that expires FSM sessions idle for longer than *ttl_seconds*."""

    def __init__(self, ttl_seconds: int = 1800) -> None:
        super().__init__()
        self._ttl = ttl_seconds
        self._touched: dict[StorageKey, float] = {}

    async def set_state(self, key: StorageKey, state: StateType = None) -> None:
        if state is None:
            self._touched.pop(key, None)
        else:
            self._touched[key] = time.monotonic()
        await super().set_state(key, state)

    async def set_data(self, key: StorageKey, data: Mapping[str, Any]) -> None:
        # Only track sessions that actually hold data. Empty data means there is
        # nothing to expire — notably ``state.clear()`` issues ``set_state(None)``
        # (which drops the entry) followed by ``set_data({})``; re-adding the key
        # here would resurrect a cleared session, keep it alive for a full TTL and
        # inflate the expire_stale counter. Leaving an already-tracked entry alone
        # on an empty write lets TTL retire it normally.
        if data:
            self._touched[key] = time.monotonic()
        await super().set_data(key, data)

    async def expire_stale(self) -> int:
        now = time.monotonic()
        candidates = [k for k, ts in list(self._touched.items()) if now - ts > self._ttl]
        expired = 0
        for key in candidates:
            # Re-validate each key right before wiping it: a concurrent
            # set_state/set_data may have refreshed it after the snapshot was
            # taken (user resumed a wizard at the TTL boundary). Skip those so
            # we never clear a freshly-touched session.
            ts = self._touched.get(key)
            if ts is None or time.monotonic() - ts <= self._ttl:
                continue
            await super().set_state(key, state=None)
            await super().set_data(key, data={})
            self._touched.pop(key, None)
            expired += 1
        if expired:
            logger.info("FSM TTL cleanup: expired %d stale sessions", expired)
        return expired


async def fsm_cleanup_loop(storage: TTLMemoryStorage, interval_seconds: int = 3600) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await storage.expire_stale()
        except Exception:
            logger.warning("FSM cleanup loop failed", exc_info=True)
