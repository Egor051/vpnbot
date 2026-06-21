
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_GB = 1024**3


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ServerStatus:
    """Point-in-time snapshot of host resource usage.

    All values are best-effort: a metric that cannot be read (e.g. ``/proc`` is
    unavailable on a non-Linux host) is reported as ``0.0`` and rendered as
    "no data" by the formatter rather than raising.
    """

    cpu_percent: float
    cpu_available: bool
    ram_used_gb: float
    ram_total_gb: float
    disk_free_gb: float
    disk_total_gb: float
    net_in_mbps: float
    net_out_mbps: float
    net_available: bool
    sampled_at: datetime | None = None

    @property
    def disk_used_gb(self) -> float:
        """Occupied disk space, derived from total minus free."""
        return max(self.disk_total_gb - self.disk_free_gb, 0.0)


def _read_cpu_times() -> tuple[int, int] | None:
    """Return (total_jiffies, idle_jiffies) from the aggregate line of /proc/stat."""
    try:
        with open("/proc/stat", encoding="ascii") as fh:
            line = fh.readline()
    except OSError:
        return None
    if not line.startswith("cpu "):
        return None
    try:
        values = [int(part) for part in line.split()[1:]]
    except ValueError:
        return None
    if len(values) < 5:
        return None
    # Fields: user nice system idle iowait irq softirq steal guest guest_nice.
    # "Busy" idle is idle + iowait; everything counts toward the total.
    idle = values[3] + values[4]
    total = sum(values)
    return total, idle


def _read_net_bytes() -> tuple[int, int] | None:
    """Return total (rx_bytes, tx_bytes) across real interfaces from /proc/net/dev."""
    try:
        with open("/proc/net/dev", encoding="ascii") as fh:
            lines = fh.readlines()
    except OSError:
        return None
    rx_total = 0
    tx_total = 0
    for line in lines[2:]:  # first two lines are headers
        iface, sep, data = line.partition(":")
        if not sep:
            continue
        if iface.strip() == "lo":  # loopback is not real network activity
            continue
        fields = data.split()
        if len(fields) < 16:
            continue
        try:
            rx_total += int(fields[0])
            tx_total += int(fields[8])
        except ValueError:
            continue
    return rx_total, tx_total


def _read_mem_gb() -> tuple[float, float] | None:
    """Return (used_gb, total_gb) of RAM from /proc/meminfo."""
    info: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if parts:
                    try:
                        info[key] = int(parts[0])  # value is in kB
                    except ValueError:
                        continue
    except OSError:
        return None
    total_kb = info.get("MemTotal")
    if total_kb is None:
        return None
    available_kb = info.get("MemAvailable")
    if available_kb is None:
        # Older kernels lack MemAvailable — approximate it.
        available_kb = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)
    used_kb = max(total_kb - available_kb, 0)
    return used_kb * 1024 / _GB, total_kb * 1024 / _GB


def _cpu_percent(before: tuple[int, int], after: tuple[int, int]) -> float:
    total_delta = after[0] - before[0]
    idle_delta = after[1] - before[1]
    if total_delta <= 0:
        return 0.0
    busy = total_delta - idle_delta
    return max(0.0, min(100.0, busy / total_delta * 100.0))


def _net_mbps(before: int, after: int, interval: float) -> float:
    if interval <= 0:
        return 0.0
    delta = max(after - before, 0)
    return delta * 8 / interval / 1_000_000


class ServerStatusService:
    """Collects real-time host metrics (CPU, RAM, disk, network) from /proc.

    A background sampler (:meth:`run`) takes one reading per ``interval`` and
    derives CPU/network rates against the *previous* reading. Because each
    reading is reused as the "before" of the next window, consecutive
    measurement windows abut edge-to-edge — there is never an unobserved
    second. :meth:`snapshot` returns the most recently computed status
    instantly, with no blocking sample on the render path.

    All timing goes through an injectable monotonic ``clock`` and ``sleep`` so
    tests can drive the loop deterministically without real sleeps.
    """

    def __init__(
        self,
        *,
        disk_path: Path | str = "/",
        interval: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        wall_clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._disk_path = str(disk_path)
        self._interval = interval
        self._clock = clock
        self._sleep = sleep
        self._wall_clock = wall_clock
        self._prev_cpu: tuple[int, int] | None = None
        self._prev_net: tuple[int, int] | None = None
        self._prev_time: float | None = None
        self._latest: ServerStatus | None = None

    async def run(self) -> None:
        """Continuously sample host metrics until cancelled.

        Each iteration reads fresh counters and derives CPU/network rates from
        the previous iteration's reading over the actually-elapsed Δt, so the
        windows tile time end-to-end with no blind gap. The result is cached in
        ``self._latest`` for :meth:`snapshot` to return instantly. A failed read
        is logged and skipped; the loop keeps running.
        """
        while True:
            try:
                self._latest = self._sample_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("server status sampler tick failed", exc_info=True)
            await self._sleep(self._interval)

    async def snapshot(self) -> ServerStatus:
        """Return the most recently sampled status without blocking.

        Before the sampler has produced its first reading the cache is empty; we
        then return a cold status (CPU/network reported as unavailable) while
        still reading RAM and disk, which are point-in-time and need no prior
        sample.
        """
        latest = self._latest
        if latest is not None:
            return latest
        return self._cold_status()

    def _sample_once(self) -> ServerStatus:
        """Take one reading and derive rates against the previous reading."""
        now = self._clock()
        cpu_now = _read_cpu_times()
        net_now = _read_net_bytes()

        if self._prev_cpu is not None and cpu_now is not None:
            cpu_percent = _cpu_percent(self._prev_cpu, cpu_now)
            cpu_available = True
        else:
            cpu_percent = 0.0
            cpu_available = False

        if self._prev_net is not None and self._prev_time is not None and net_now is not None:
            # Divide by the measured Δt, not the configured interval, so a long
            # or short tick still reports the true rate.
            interval = now - self._prev_time
            net_in = _net_mbps(self._prev_net[0], net_now[0], interval)
            net_out = _net_mbps(self._prev_net[1], net_now[1], interval)
            net_available = True
        else:
            net_in = 0.0
            net_out = 0.0
            net_available = False

        ram_used_gb, ram_total_gb = self._read_ram()
        disk_free_gb, disk_total_gb = self._read_disk()

        # This reading becomes the "before" of the next window, so consecutive
        # windows share an edge and no interval goes unmeasured.
        if cpu_now is not None:
            self._prev_cpu = cpu_now
        if net_now is not None:
            self._prev_net = net_now
            self._prev_time = now

        return ServerStatus(
            cpu_percent=cpu_percent,
            cpu_available=cpu_available,
            ram_used_gb=ram_used_gb,
            ram_total_gb=ram_total_gb,
            disk_free_gb=disk_free_gb,
            disk_total_gb=disk_total_gb,
            net_in_mbps=net_in,
            net_out_mbps=net_out,
            net_available=net_available,
            sampled_at=self._wall_clock(),
        )

    def _cold_status(self) -> ServerStatus:
        """Status for a cold cache: RAM/disk read live, CPU/network unavailable."""
        ram_used_gb, ram_total_gb = self._read_ram()
        disk_free_gb, disk_total_gb = self._read_disk()
        return ServerStatus(
            cpu_percent=0.0,
            cpu_available=False,
            ram_used_gb=ram_used_gb,
            ram_total_gb=ram_total_gb,
            disk_free_gb=disk_free_gb,
            disk_total_gb=disk_total_gb,
            net_in_mbps=0.0,
            net_out_mbps=0.0,
            net_available=False,
            sampled_at=self._wall_clock(),
        )

    @staticmethod
    def _read_ram() -> tuple[float, float]:
        mem = _read_mem_gb()
        return mem if mem is not None else (0.0, 0.0)

    def _read_disk(self) -> tuple[float, float]:
        try:
            usage = shutil.disk_usage(self._disk_path)
        except OSError:
            return 0.0, 0.0
        return usage.free / _GB, usage.total / _GB
