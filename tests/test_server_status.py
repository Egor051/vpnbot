import asyncio
from itertools import pairwise

import pytest
from pytest import approx

from bot.formatters import server_status_text
from services import server_status as ss
from services.server_status import ServerStatus, ServerStatusService


def test_cpu_percent_computes_busy_fraction() -> None:
    # total grows by 1000, idle grows by 750 -> 25% busy
    assert ss._cpu_percent((1000, 500), (2000, 1250)) == approx(25.0)


def test_cpu_percent_clamps_and_handles_no_delta() -> None:
    assert ss._cpu_percent((1000, 500), (1000, 500)) == approx(0.0)
    # idle shrinking would over-report; result is clamped to 100
    assert ss._cpu_percent((0, 0), (100, -50)) == approx(100.0)


def test_net_mbps_converts_bytes_to_megabits() -> None:
    # 1_000_000 bytes over 1s = 8 Mbps
    assert ss._net_mbps(0, 1_000_000, 1.0) == approx(8.0)
    assert ss._net_mbps(0, 1_000_000, 0.0) == approx(0.0)
    # counter reset / decrease never goes negative
    assert ss._net_mbps(100, 0, 1.0) == approx(0.0)


def test_snapshot_returns_live_metrics() -> None:
    # snapshot() now returns the cached reading; prime the sampler with two
    # ticks so the cache holds a live (warm) status before reading it.
    service = ServerStatusService(interval=0.01)
    service._sample_once()  # first reading: becomes the "before"
    service._sample_once()  # second reading: produces a live CPU/net status
    status = asyncio.run(service.snapshot())
    assert isinstance(status, ServerStatus)
    # On the Linux CI host /proc is present, so disk total is always positive.
    assert status.disk_total_gb > 0
    assert 0.0 <= status.cpu_percent <= 100.0


def test_measurement_windows_are_contiguous(monkeypatch: pytest.MonkeyPatch) -> None:
    """The "before" of window N+1 equals the "after" of window N — no blind gap."""
    cpu_seq = iter([(0, 0), (1000, 750), (2000, 1500), (3000, 2250)])
    net_seq = iter([(0, 0), (1_000, 2_000), (3_000, 5_000), (6_000, 9_000)])
    clock_seq = iter([0.0, 1.0, 2.0, 3.0])
    monkeypatch.setattr(ss, "_read_cpu_times", lambda: next(cpu_seq))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: next(net_seq))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    cpu_windows: list[tuple[tuple[int, int], tuple[int, int]]] = []
    net_windows: list[tuple[int, int]] = []
    real_cpu = ss._cpu_percent
    real_net = ss._net_mbps

    def spy_cpu(before: tuple[int, int], after: tuple[int, int]) -> float:
        cpu_windows.append((before, after))
        return real_cpu(before, after)

    def spy_net(before: int, after: int, interval: float) -> float:
        net_windows.append((before, after))
        return real_net(before, after, interval)

    monkeypatch.setattr(ss, "_cpu_percent", spy_cpu)
    monkeypatch.setattr(ss, "_net_mbps", spy_net)

    service = ServerStatusService(clock=lambda: next(clock_seq))
    for _ in range(4):
        service._sample_once()

    # First tick has no "before", so 4 readings yield 3 measured windows.
    assert len(cpu_windows) == 3
    # Each window's "after" is reused verbatim as the next window's "before".
    for cur, nxt in pairwise(cpu_windows):
        assert cur[1] == nxt[0]
    # _net_mbps records rx (in) then tx (out) per tick: pair up same-direction.
    in_windows = net_windows[0::2]
    for cur, nxt in pairwise(in_windows):
        assert cur[1] == nxt[0]


def test_net_rate_uses_measured_delta(monkeypatch: pytest.MonkeyPatch) -> None:
    """Network speed divides by the real Δt, not the configured interval."""
    cpu_seq = iter([(0, 0), (1000, 750), (2000, 1500)])
    # rx grows by 1e6 over the first window, 2e6 over the second.
    net_seq = iter([(0, 0), (1_000_000, 0), (3_000_000, 0)])
    clock_seq = iter([0.0, 1.0, 5.0])  # Δt = 1s then 4s
    monkeypatch.setattr(ss, "_read_cpu_times", lambda: next(cpu_seq))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: next(net_seq))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService(clock=lambda: next(clock_seq))
    service._sample_once()  # prime
    s1 = service._sample_once()  # 1e6 bytes over 1s -> 8 Mbps
    s2 = service._sample_once()  # 2e6 bytes over 4s -> 4 Mbps
    assert s1.net_in_mbps == approx(8.0)
    assert s2.net_in_mbps == approx(4.0)


def test_cold_start_marks_cpu_and_net_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Until a second reading lands, CPU/network are unavailable; RAM/disk are not."""
    monkeypatch.setattr(ss, "_read_cpu_times", lambda: (1000, 500))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: (10, 20))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService()
    first = service._sample_once()
    assert first.cpu_available is False
    assert first.net_available is False
    # RAM/disk are point-in-time and available from the very first reading.
    assert first.ram_total_gb == approx(2.0)
    assert first.disk_total_gb == approx(10.0)

    second = service._sample_once()
    assert second.cpu_available is True
    assert second.net_available is True


def test_snapshot_on_cold_cache_returns_ram_disk_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """A snapshot taken before the sampler runs still surfaces RAM/disk."""
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService()
    status = asyncio.run(service.snapshot())
    assert status.cpu_available is False
    assert status.net_available is False
    assert status.ram_total_gb == approx(2.0)
    assert status.disk_total_gb == approx(10.0)


def test_sampler_survives_read_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exception in one tick is logged and skipped; the loop keeps sampling."""
    calls = {"cpu": 0}

    def fake_cpu() -> tuple[int, int]:
        calls["cpu"] += 1
        if calls["cpu"] == 2:
            raise RuntimeError("transient /proc read failure")
        return calls["cpu"] * 1000, calls["cpu"] * 500

    monkeypatch.setattr(ss, "_read_cpu_times", fake_cpu)
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: (0, 0))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    class _StopSampler(Exception):
        pass

    sleeps = {"n": 0}

    async def sleep(_delay: float) -> None:
        sleeps["n"] += 1
        if sleeps["n"] >= 3:
            raise _StopSampler

    clock_seq = iter([0.0, 1.0, 2.0, 3.0])
    service = ServerStatusService(sleep=sleep, clock=lambda: next(clock_seq))
    with pytest.raises(_StopSampler):
        asyncio.run(service.run())

    # Three iterations ran: tick 2 raised inside _sample_once but the loop kept
    # going, and a later successful tick refreshed the cache.
    assert calls["cpu"] == 3
    assert service._latest is not None
    assert service._latest.cpu_available is True


def test_run_starts_task_and_cancels_cleanly() -> None:
    """run() drives a task that primes the cache and cancels without leaking."""

    async def scenario() -> tuple[bool, bool, bool]:
        ticked = asyncio.Event()
        parked = asyncio.Event()

        async def sleep(_delay: float) -> None:
            ticked.set()
            await parked.wait()  # park after the first reading

        service = ServerStatusService(interval=0.0, sleep=sleep)
        task = asyncio.create_task(service.run(), name="server-status-sampler")
        await asyncio.wait_for(ticked.wait(), timeout=1.0)
        running = not task.done()
        primed = service._latest is not None
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return running, primed, task.cancelled()

    running, primed, cancelled = asyncio.run(scenario())
    assert running is True
    assert primed is True
    assert cancelled is True


def test_server_status_text_matches_layout() -> None:
    status = ServerStatus(
        cpu_percent=8.3,
        cpu_available=True,
        ram_used_gb=0.54,
        ram_total_gb=0.93,
        disk_free_gb=6.43,
        disk_total_gb=9.71,
        net_in_mbps=0.42,
        net_out_mbps=0.02,
        net_available=True,
    )
    text = server_status_text(status)
    assert "CPU: 8.3%" in text
    assert "RAM: 0.54 GB / 0.93 GB" in text
    # Disk shows used space (total - free = 9.71 - 6.43 = 3.28), not free space.
    assert "3.28 GB" in text and "9.71 GB" in text
    assert "занято" in text and "6.43 GB" not in text
    assert "📥" in text and "0.42 Mbps" in text
    assert "📤" in text and "0.02 Mbps" in text


def test_disk_used_gb_is_total_minus_free() -> None:
    status = ServerStatus(
        cpu_percent=0.0,
        cpu_available=False,
        ram_used_gb=0.0,
        ram_total_gb=0.0,
        disk_free_gb=6.43,
        disk_total_gb=9.71,
        net_in_mbps=0.0,
        net_out_mbps=0.0,
        net_available=False,
    )
    assert status.disk_used_gb == approx(3.28)
    # Never negative even if free somehow exceeds total (clock skew, races).
    assert ServerStatus(0, False, 0, 0, 100.0, 10.0, 0, 0, False).disk_used_gb == approx(0.0)


def test_server_status_text_reports_no_data_when_unavailable() -> None:
    status = ServerStatus(
        cpu_percent=0.0,
        cpu_available=False,
        ram_used_gb=0.0,
        ram_total_gb=0.0,
        disk_free_gb=0.0,
        disk_total_gb=0.0,
        net_in_mbps=0.0,
        net_out_mbps=0.0,
        net_available=False,
    )
    text = server_status_text(status)
    # CPU/RAM/disk/network all degrade gracefully rather than showing zeros.
    assert "8.3%" not in text
    assert text.count("нет данных") == 5
