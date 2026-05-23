
import asyncio
import logging
import time
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

    async def set_data(self, key: StorageKey, data: dict[str, Any]) -> None:
        self._touched[key] = time.monotonic()
        await super().set_data(key, data)

    async def expire_stale(self) -> int:
        now = time.monotonic()
        expired = [k for k, ts in list(self._touched.items()) if now - ts > self._ttl]
        for key in expired:
            await super().set_state(key, state=None)
            await super().set_data(key, data={})
            self._touched.pop(key, None)
        if expired:
            logger.info("FSM TTL cleanup: expired %d stale sessions", len(expired))
        return len(expired)


async def fsm_cleanup_loop(storage: TTLMemoryStorage, interval_seconds: int = 3600) -> None:
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await storage.expire_stale()
        except Exception:
            logger.warning("FSM cleanup loop failed", exc_info=True)
