
from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from pathlib import Path

_GB = 1024**3


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
    """Collects real-time host metrics (CPU, RAM, disk, network) from /proc."""

    def __init__(self, *, disk_path: Path | str = "/", sample_interval: float = 1.0) -> None:
        self._disk_path = str(disk_path)
        self._sample_interval = sample_interval

    async def snapshot(self) -> ServerStatus:
        """Sample host metrics, taking two readings to derive CPU and network rates."""
        cpu_before = _read_cpu_times()
        net_before = _read_net_bytes()
        await asyncio.sleep(self._sample_interval)
        cpu_after = _read_cpu_times()
        net_after = _read_net_bytes()

        if cpu_before is not None and cpu_after is not None:
            cpu_percent = _cpu_percent(cpu_before, cpu_after)
            cpu_available = True
        else:
            cpu_percent = 0.0
            cpu_available = False

        if net_before is not None and net_after is not None:
            net_in = _net_mbps(net_before[0], net_after[0], self._sample_interval)
            net_out = _net_mbps(net_before[1], net_after[1], self._sample_interval)
            net_available = True
        else:
            net_in = 0.0
            net_out = 0.0
            net_available = False

        mem = _read_mem_gb()
        ram_used_gb, ram_total_gb = mem if mem is not None else (0.0, 0.0)

        try:
            usage = shutil.disk_usage(self._disk_path)
            disk_free_gb = usage.free / _GB
            disk_total_gb = usage.total / _GB
        except OSError:
            disk_free_gb = 0.0
            disk_total_gb = 0.0

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
        )
