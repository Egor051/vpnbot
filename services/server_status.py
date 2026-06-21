
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_GB = 1024**3

# Number of one-second samples kept for the detailed network history (≈ last
# minute). Only populated while the detailed-metrics toggle is on.
_HISTORY_LEN = 60
# Points in the downsampled sparkline handed to the formatter.
_SPARKLINE_POINTS = 12


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
    # Swap usage is always read (cheap, point-in-time from /proc/meminfo). A host
    # with no swap configured reports total 0.0, rendered as "off" by the formatter.
    swap_used_gb: float = 0.0
    swap_total_gb: float = 0.0
    # Detailed metrics — populated only while the panel's detailed-metrics toggle
    # is on; otherwise left at their "no data" defaults (None). ``detailed_enabled``
    # tells the formatter which mode the snapshot was taken in.
    detailed_enabled: bool = False
    load1: float | None = None
    load5: float | None = None
    load15: float | None = None
    cpu_count: int | None = None
    uptime_seconds: float | None = None
    net_in_avg: float | None = None
    net_out_avg: float | None = None
    net_in_peak: float | None = None
    net_out_peak: float | None = None
    net_in_trend: str | None = None
    net_out_trend: str | None = None
    net_sparkline: tuple[float, ...] | None = None

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


def _read_swap_gb() -> tuple[float, float]:
    """Return (used_gb, total_gb) of swap from /proc/meminfo, (0, 0) on failure."""
    total_kb: int | None = None
    free_kb: int | None = None
    try:
        with open("/proc/meminfo", encoding="ascii") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                parts = rest.split()
                if not parts:
                    continue
                if key == "SwapTotal":
                    try:
                        total_kb = int(parts[0])
                    except ValueError:
                        return 0.0, 0.0
                elif key == "SwapFree":
                    try:
                        free_kb = int(parts[0])
                    except ValueError:
                        return 0.0, 0.0
    except OSError:
        return 0.0, 0.0
    if total_kb is None or free_kb is None:
        return 0.0, 0.0
    used_kb = max(total_kb - free_kb, 0)
    return used_kb * 1024 / _GB, total_kb * 1024 / _GB


def _read_loadavg() -> tuple[float, float, float] | None:
    """Return the 1/5/15-minute load averages from /proc/loadavg."""
    try:
        with open("/proc/loadavg", encoding="ascii") as fh:
            parts = fh.readline().split()
    except OSError:
        return None
    if len(parts) < 3:
        return None
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except ValueError:
        return None


def _read_uptime() -> float | None:
    """Return the host uptime in seconds from /proc/uptime."""
    try:
        with open("/proc/uptime", encoding="ascii") as fh:
            first = fh.readline().split()
    except OSError:
        return None
    if not first:
        return None
    try:
        return float(first[0])
    except ValueError:
        return None


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _trend(values: list[float]) -> str:
    """Classify the recent direction of a chronological series as up/down/flat.

    Compares the mean of the latest third of the window against the preceding
    third, with a relative dead-band so small jitter reads as ``flat``.
    """
    n = len(values)
    if n < 6:
        return "flat"
    third = n // 3
    older = _mean(values[-2 * third : -third])
    recent = _mean(values[-third:])
    # Dead-band: ignore changes under ~15% of the older value (and tiny absolutes).
    margin = max(older * 0.15, 0.05)
    if recent > older + margin:
        return "up"
    if recent < older - margin:
        return "down"
    return "flat"


def _downsample(values: list[float], points: int) -> tuple[float, ...]:
    """Reduce a series to at most ``points`` representative values (bucket means)."""
    n = len(values)
    if n == 0:
        return ()
    if n <= points:
        return tuple(values)
    bucket = n / points
    out: list[float] = []
    for i in range(points):
        start = int(i * bucket)
        end = int((i + 1) * bucket) if i < points - 1 else n
        out.append(_mean(values[start:end]))
    return tuple(out)


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
        # Detailed-metrics mode (load average, uptime, network history). Off by
        # default so the sampler does no extra work until an admin enables it.
        self._detailed = False
        self._history: deque[tuple[float, float]] = deque(maxlen=_HISTORY_LEN)

    @property
    def detailed(self) -> bool:
        """Whether detailed-metrics collection is currently enabled."""
        return self._detailed

    def set_detailed(self, enabled: bool) -> None:
        """Enable or disable detailed-metrics collection.

        Turning the mode off clears the accumulated network history so a later
        re-enable starts from a clean window rather than stale samples.
        """
        if enabled == self._detailed:
            return
        self._detailed = enabled
        if not enabled:
            self._history.clear()

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
        swap_used_gb, swap_total_gb = _read_swap_gb()

        # This reading becomes the "before" of the next window, so consecutive
        # windows share an edge and no interval goes unmeasured.
        if cpu_now is not None:
            self._prev_cpu = cpu_now
        if net_now is not None:
            self._prev_net = net_now
            self._prev_time = now

        detailed = self._detailed_fields(net_in, net_out, net_available)

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
            swap_used_gb=swap_used_gb,
            swap_total_gb=swap_total_gb,
            detailed_enabled=self._detailed,
            **detailed,
        )

    def _detailed_fields(self, net_in: float, net_out: float, net_available: bool) -> dict[str, Any]:
        """Read load/uptime and update the network history, returning the derived
        detailed fields. Returns empty (all-default) when detailed mode is off so
        the sampler does no extra ``/proc`` reads or history work in the base view.
        """
        if not self._detailed:
            return {}
        if net_available:
            self._history.append((net_in, net_out))
        loadavg = _read_loadavg()
        ins = [sample[0] for sample in self._history]
        outs = [sample[1] for sample in self._history]
        fields: dict[str, Any] = {
            "load1": loadavg[0] if loadavg else None,
            "load5": loadavg[1] if loadavg else None,
            "load15": loadavg[2] if loadavg else None,
            "cpu_count": os.cpu_count(),
            "uptime_seconds": _read_uptime(),
        }
        if ins:
            totals = [i + o for i, o in zip(ins, outs, strict=True)]
            fields.update(
                net_in_avg=_mean(ins),
                net_out_avg=_mean(outs),
                net_in_peak=max(ins),
                net_out_peak=max(outs),
                net_in_trend=_trend(ins),
                net_out_trend=_trend(outs),
                net_sparkline=_downsample(totals, _SPARKLINE_POINTS),
            )
        return fields

    def _cold_status(self) -> ServerStatus:
        """Status for a cold cache: RAM/disk read live, CPU/network unavailable."""
        ram_used_gb, ram_total_gb = self._read_ram()
        disk_free_gb, disk_total_gb = self._read_disk()
        swap_used_gb, swap_total_gb = _read_swap_gb()
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
            swap_used_gb=swap_used_gb,
            swap_total_gb=swap_total_gb,
            detailed_enabled=self._detailed,
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
