"""Best-effort counter of currently-online VPN clients (WireGuard + Xray + Hysteria2).

"Online" is inferred from traffic movement: a client counts as online when its
cumulative transfer counters grew since the previous poll. Both backends expose
non-destructive cumulative counters that are cheap to read:

* WireGuard via the AWG adapter's ``list_transfer`` (``wg/awg show transfer``).
  Persistent-keepalive nudges a connected peer's counters every ~25 s, so a poll
  window of ~30 s reliably registers idle-but-connected peers as online while a
  disconnected peer's counters stay flat.
* Xray via ``xray api statsquery`` per-user uplink/downlink totals — these only
  move with real traffic, so Xray "online" means "transferred data recently".

Because the panel re-renders every second but online counts change slowly, the
result is cached for ``ttl`` seconds; renders within the window are served from
cache and never touch a subprocess. The previous poll's totals are held in
memory, so the first poll has no baseline and reports "collecting".
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)

# Poll window. Kept ≥ the WireGuard persistent-keepalive interval (25 s) so a
# connected-but-idle peer's keepalive-driven counter movement is captured.
DEFAULT_TTL_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class OnlineClients:
    """Snapshot of online VPN client counts.

    A ``None`` per-backend count means that backend could not be read (not
    configured or a transient error); ``available`` is ``False`` only while no
    baseline exists yet (the very first poll), rendered as "collecting".
    """

    wg: int | None
    xray: int | None
    total: int | None
    available: bool
    hysteria2: int | None = None


class _AwgTransferSource(Protocol):
    async def list_transfer(self) -> dict[str, tuple[int, int]]: ...


class _XrayStatsSource(Protocol):
    async def query_all(self) -> dict[str, int]: ...


class _HysteriaOnlineSource(Protocol):
    async def query_online(self) -> dict[str, int]: ...


class OnlineClientsService:
    def __init__(
        self,
        *,
        awg_adapter: _AwgTransferSource,
        xray_stats: _XrayStatsSource,
        hysteria_stats: _HysteriaOnlineSource | None = None,
        ttl: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._awg_adapter = awg_adapter
        self._xray_stats = xray_stats
        # None when the Hysteria2 Traffic Stats API is not configured.
        self._hysteria_stats = hysteria_stats
        self._ttl = ttl
        self._clock = clock
        self._lock = asyncio.Lock()
        self._cached: OnlineClients | None = None
        self._cached_at: float | None = None
        self._prev_wg: dict[str, int] | None = None
        self._prev_xray: dict[str, int] | None = None

    async def get(self) -> OnlineClients:
        """Return the cached online counts, recomputing once per ``ttl`` window."""
        if self._fresh():
            assert self._cached is not None
            return self._cached
        async with self._lock:
            # Another coroutine may have refreshed the cache while we waited.
            if self._fresh():
                assert self._cached is not None
                return self._cached
            result = await self._compute()
            self._cached = result
            self._cached_at = self._clock()
            return result

    def _fresh(self) -> bool:
        return (
            self._cached is not None
            and self._cached_at is not None
            and self._clock() - self._cached_at < self._ttl
        )

    async def _compute(self) -> OnlineClients:
        wg = await self._count_wg()
        xray = await self._count_xray()
        hysteria2 = await self._count_hysteria()
        if wg is None and xray is None and hysteria2 is None:
            return OnlineClients(wg=None, xray=None, hysteria2=None, total=None, available=False)
        total = (wg or 0) + (xray or 0) + (hysteria2 or 0)
        return OnlineClients(wg=wg, xray=xray, hysteria2=hysteria2, total=total, available=True)

    async def _count_wg(self) -> int | None:
        try:
            transfer = await self._awg_adapter.list_transfer()
        except Exception:
            logger.debug("online WG transfer read failed", exc_info=True)
            return None
        cur = {pubkey: rx + tx for pubkey, (rx, tx) in transfer.items()}
        prev = self._prev_wg
        self._prev_wg = cur
        return self._count_increased(cur, prev)

    async def _count_xray(self) -> int | None:
        try:
            stats = await self._xray_stats.query_all()
        except Exception:
            logger.debug("online Xray stats read failed", exc_info=True)
            return None
        cur = self._group_xray_by_email(stats)
        prev = self._prev_xray
        self._prev_xray = cur
        return self._count_increased(cur, prev)

    async def _count_hysteria(self) -> int | None:
        # Unlike wg/xray, Hysteria2's /online is an instantaneous connection count,
        # so "online" is a direct read (labels with >=1 live connection) with no
        # baseline needed. Returns None when the API is unconfigured/unreachable.
        if self._hysteria_stats is None:
            return None
        try:
            online = await self._hysteria_stats.query_online()
        except Exception:
            logger.debug("online Hysteria2 stats read failed", exc_info=True)
            return None
        return sum(1 for count in online.values() if count > 0)

    @staticmethod
    def _count_increased(cur: dict[str, int], prev: dict[str, int] | None) -> int | None:
        # No baseline yet: report "unknown" rather than a misleading zero.
        if prev is None:
            return None
        count = 0
        for identity, total in cur.items():
            prev_total = prev.get(identity)
            if prev_total is not None and total > prev_total:
                count += 1
        return count

    @staticmethod
    def _group_xray_by_email(stats: dict[str, int]) -> dict[str, int]:
        """Sum per-user uplink+downlink from ``user>>>EMAIL>>>traffic>>>{up,down}link``."""
        grouped: dict[str, int] = {}
        for name, value in stats.items():
            parts = name.split(">>>")
            if (
                len(parts) == 4
                and parts[0] == "user"
                and parts[2] == "traffic"
                and parts[3] in ("uplink", "downlink")
            ):
                grouped[parts[1]] = grouped.get(parts[1], 0) + value
        return grouped
