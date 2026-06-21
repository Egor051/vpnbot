import asyncio
from datetime import datetime, timezone
from itertools import pairwise

import pytest
from pytest import approx

from bot.formatters import server_status_text
from services import server_status as ss
from services.online_clients import OnlineClients
from services.server_status import ServerStatus, ServerStatusService

# Online counts are rendered separately; most formatter tests don't exercise them,
# so they pass a "no baseline yet" value that renders as "collecting".
_ONLINE_COLLECTING = OnlineClients(wg=None, xray=None, total=None, available=False)


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


def test_sampler_stamps_sampled_at_from_wall_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both the warm and cold sampling paths stamp the injected wall clock."""
    monkeypatch.setattr(ss, "_read_cpu_times", lambda: (1000, 500))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: (10, 20))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    fixed = datetime(2026, 6, 21, 12, 34, 56, tzinfo=timezone.utc)
    service = ServerStatusService(wall_clock=lambda: fixed)

    service._sample_once()  # prime so the next reading is a warm status
    warm = service._sample_once()
    assert warm.sampled_at == fixed

    assert service._cold_status().sampled_at == fixed


def test_server_status_text_shows_updated_at() -> None:
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
        sampled_at=datetime(2026, 6, 21, 12, 34, 56, tzinfo=timezone.utc),
    )
    text = server_status_text(status, _ONLINE_COLLECTING)
    assert "12:34:56" in text
    assert "обновлено" in text


def test_server_status_text_omits_updated_at_without_timestamp() -> None:
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
        sampled_at=None,
    )
    text = server_status_text(status, _ONLINE_COLLECTING)
    assert "обновлено" not in text


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
    text = server_status_text(status, _ONLINE_COLLECTING)
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
    text = server_status_text(status, _ONLINE_COLLECTING)
    # CPU/RAM/disk/network all degrade gracefully rather than showing zeros.
    assert "8.3%" not in text
    assert text.count("нет данных") == 5


def _base_status(**overrides: object) -> ServerStatus:
    defaults: dict[str, object] = dict(
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
    defaults.update(overrides)
    return ServerStatus(**defaults)  # type: ignore[arg-type]


def test_usage_bar_empty_full_and_red() -> None:
    from bot.formatters import _usage_bar

    assert _usage_bar(0.0) == "⬛" * 10
    assert _usage_bar(47.0) == "⬜" * 5 + "⬛" * 5  # round(4.7) = 5
    # At/above 90% the filled glyph turns red.
    assert _usage_bar(90.0) == "🟥" * 9 + "⬛"
    assert _usage_bar(100.0) == "🟥" * 10


def test_server_status_text_base_view_shows_swap_and_online() -> None:
    status = _base_status(swap_used_gb=0.25, swap_total_gb=2.0)
    online = OnlineClients(wg=28, xray=9, total=37, available=True)
    text = server_status_text(status, online)
    assert "Подкачка" in text and "0.25 GB / 2.00 GB" in text
    assert "Онлайн-клиентов" in text and "37" in text
    assert "WG: 28" in text and "Xray: 9" in text
    # Detailed-only blocks stay hidden in the base view.
    assert "Средняя нагрузка" not in text
    assert "Аптайм" not in text


def test_server_status_text_swap_off_when_no_swap() -> None:
    text = server_status_text(_base_status(swap_total_gb=0.0), _ONLINE_COLLECTING)
    assert "выкл" in text


def test_server_status_text_detailed_view_shows_loadavg_and_uptime() -> None:
    status = _base_status(
        detailed_enabled=True,
        load1=0.5,
        load5=1.0,
        load15=1.5,
        cpu_count=2,
        uptime_seconds=90061.0,  # 1d 1h 1m
        net_in_avg=0.30,
        net_out_avg=0.10,
        net_in_peak=0.90,
        net_out_peak=0.40,
        net_in_trend="up",
        net_out_trend="flat",
        net_sparkline=(0.1, 0.5, 0.9),
    )
    text = server_status_text(status, _ONLINE_COLLECTING)
    # Each load average is shown as a % of total CPU capacity (load / cpu_count):
    # 0.5/2, 1.0/2, 1.5/2 -> 25% / 50% / 75%. No raw figures, no "(.. / N CPU)".
    assert "Средняя нагрузка" in text and "25% / 50% / 75%" in text
    assert "CPU)" not in text
    assert "Аптайм" in text and "1д 1ч 1м" in text
    assert "↑" in text and "→" in text  # trend arrows


def test_loadavg_falls_back_to_raw_figures_without_cpu_count() -> None:
    """Without a CPU count to normalise against, the load line keeps raw figures."""
    status = _base_status(
        detailed_enabled=True,
        load1=0.5,
        load5=1.0,
        load15=1.5,
        cpu_count=None,
    )
    text = server_status_text(status, _ONLINE_COLLECTING)
    load_line = next(line for line in text.splitlines() if "Средняя нагрузка" in line)
    assert "0.50 / 1.00 / 1.50" in load_line
    assert "%" not in load_line


def test_detailed_mode_collects_history_loadavg_and_uptime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ss, "_read_cpu_times", lambda: (1000, 500))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: (0, 0))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ss, "_read_swap_gb", lambda: (0.5, 4.0))
    monkeypatch.setattr(ss, "_read_loadavg", lambda: (0.1, 0.2, 0.3))
    monkeypatch.setattr(ss, "_read_uptime", lambda: 12345.0)
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService()
    service.set_detailed(True)
    # Prime, then take several samples so the history window fills.
    for _ in range(8):
        status = service._sample_once()

    assert status.detailed_enabled is True
    assert status.swap_total_gb == approx(4.0)  # swap is always read
    assert status.load1 == approx(0.1) and status.load15 == approx(0.3)
    assert status.uptime_seconds == approx(12345.0)
    assert status.cpu_count is not None
    assert status.net_in_avg is not None and status.net_in_peak is not None
    assert len(service._history) > 0
    # The sparkline is no longer attached by _sample_once; it is built per render
    # by snapshot_averaged, which flushes the accumulated bucket samples.
    assert status.net_sparkline is None
    assert len(service._bucket_samples) > 0
    avg = asyncio.run(service.snapshot_averaged())
    assert avg.net_sparkline is not None
    assert service._bucket_samples == []  # flushed into a column


def test_detailed_disabled_skips_history_and_loadavg(monkeypatch: pytest.MonkeyPatch) -> None:
    # Tripwires: if the sampler reads these while detailed is off, the test fails.
    def _boom_loadavg() -> tuple[float, float, float]:
        raise AssertionError("loadavg must not be read in base mode")

    def _boom_uptime() -> float:
        raise AssertionError("uptime must not be read in base mode")

    monkeypatch.setattr(ss, "_read_cpu_times", lambda: (1000, 500))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: (0, 0))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ss, "_read_swap_gb", lambda: (0.5, 4.0))
    monkeypatch.setattr(ss, "_read_loadavg", _boom_loadavg)
    monkeypatch.setattr(ss, "_read_uptime", _boom_uptime)
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService()  # detailed defaults off
    for _ in range(3):
        status = service._sample_once()

    assert status.detailed_enabled is False
    assert status.load1 is None and status.uptime_seconds is None
    assert status.net_sparkline is None
    assert len(service._history) == 0
    # Swap is part of the base view and must still be present.
    assert status.swap_total_gb == approx(4.0)


def test_set_detailed_off_clears_history(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ss, "_read_cpu_times", lambda: (1000, 500))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: (0, 0))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ss, "_read_swap_gb", lambda: (0.0, 0.0))
    monkeypatch.setattr(ss, "_read_loadavg", lambda: (0.1, 0.2, 0.3))
    monkeypatch.setattr(ss, "_read_uptime", lambda: 1.0)
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService()
    service.set_detailed(True)
    for _ in range(4):
        service._sample_once()
    assert len(service._history) > 0
    assert len(service._bucket_samples) > 0
    service.set_detailed(False)
    assert len(service._history) == 0
    # Sparkline buckets and the in-progress accumulator reset too, so a later
    # re-enable starts from a clean window.
    assert len(service._bucket_samples) == 0
    assert len(service._sparkline_buckets) == 0


# --- snapshot_averaged: smoothed head-line rate metrics ----------------------


def test_averaging_and_interval_constants() -> None:
    """The averaging window is 3 samples and the panel re-renders every 3s."""
    from services.auto_refresh import DEFAULT_INTERVAL_SECONDS

    assert ss._AVERAGING_SAMPLES == 3
    assert ss._SPARKLINE_POINTS == 20
    assert DEFAULT_INTERVAL_SECONDS == approx(3.0)


def test_snapshot_averaged_means_cpu_and_net_over_last_three() -> None:
    """CPU% and net in/out are the mean of the last exactly-3 samples."""
    service = ServerStatusService()
    # Feed five samples; the bounded window must keep only the last three, so
    # the first two values (10/20 cpu, 1-4 net) do not contribute to the mean.
    service._recent.append(_base_status(cpu_percent=10.0, net_in_mbps=1.0, net_out_mbps=2.0))
    service._recent.append(_base_status(cpu_percent=20.0, net_in_mbps=3.0, net_out_mbps=4.0))
    service._recent.append(_base_status(cpu_percent=30.0, net_in_mbps=5.0, net_out_mbps=6.0))
    service._recent.append(_base_status(cpu_percent=40.0, net_in_mbps=7.0, net_out_mbps=8.0))
    service._recent.append(_base_status(cpu_percent=60.0, net_in_mbps=9.0, net_out_mbps=12.0))

    avg = asyncio.run(service.snapshot_averaged())

    assert avg.cpu_percent == approx((30.0 + 40.0 + 60.0) / 3)
    assert avg.net_in_mbps == approx((5.0 + 7.0 + 9.0) / 3)
    assert avg.net_out_mbps == approx((6.0 + 8.0 + 12.0) / 3)
    assert avg.cpu_available is True
    assert avg.net_available is True


def test_snapshot_averaged_takes_point_in_time_fields_from_latest() -> None:
    """RAM/disk/swap, loadavg, uptime and sampled_at come from the latest sample."""
    service = ServerStatusService()
    t_old = datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc)
    t_new = datetime(2026, 6, 21, 12, 0, 2, tzinfo=timezone.utc)
    service._recent.append(
        _base_status(
            cpu_percent=10.0,
            ram_used_gb=1.0,
            disk_free_gb=8.0,
            swap_used_gb=0.1,
            load1=0.5,
            load5=0.6,
            load15=0.7,
            uptime_seconds=100.0,
            sampled_at=t_old,
            detailed_enabled=True,
        )
    )
    service._recent.append(
        _base_status(
            cpu_percent=20.0,
            ram_used_gb=2.0,
            disk_free_gb=4.0,
            swap_used_gb=0.9,
            load1=5.0,
            load5=6.0,
            load15=7.0,
            uptime_seconds=300.0,
            sampled_at=t_new,
            detailed_enabled=True,
        )
    )

    avg = asyncio.run(service.snapshot_averaged())

    # Rate metric is averaged...
    assert avg.cpu_percent == approx(15.0)
    # ...but every point-in-time field is taken verbatim from the latest sample,
    # never averaged (loadavg in particular is already a kernel-side average).
    assert avg.ram_used_gb == approx(2.0)
    assert avg.disk_free_gb == approx(4.0)
    assert avg.swap_used_gb == approx(0.9)
    assert avg.load1 == approx(5.0)
    assert avg.load5 == approx(6.0)
    assert avg.load15 == approx(7.0)
    assert avg.uptime_seconds == approx(300.0)
    assert avg.sampled_at == t_new


def test_snapshot_averaged_partial_window_averages_what_is_present() -> None:
    """With 1 then 2 samples, the mean is taken over only those samples."""
    service = ServerStatusService()
    service._recent.append(_base_status(cpu_percent=12.0, net_in_mbps=3.0, net_out_mbps=1.0))
    one = asyncio.run(service.snapshot_averaged())
    assert one.cpu_percent == approx(12.0)
    assert one.net_in_mbps == approx(3.0)
    assert one.net_out_mbps == approx(1.0)

    service._recent.append(_base_status(cpu_percent=18.0, net_in_mbps=5.0, net_out_mbps=3.0))
    two = asyncio.run(service.snapshot_averaged())
    assert two.cpu_percent == approx(15.0)
    assert two.net_in_mbps == approx(4.0)
    assert two.net_out_mbps == approx(2.0)


def test_snapshot_averaged_empty_buffer_returns_cold_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty window mirrors snapshot(): a cold status with RAM/disk only."""
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService()
    cold = asyncio.run(service.snapshot_averaged())

    assert cold.cpu_available is False
    assert cold.net_available is False
    assert cold.ram_total_gb == approx(2.0)
    assert cold.disk_total_gb == approx(10.0)


def test_snapshot_averaged_cpu_mean_over_available_samples_only() -> None:
    """CPU is averaged over only the samples where it was available; flag set."""
    service = ServerStatusService()
    service._recent.append(_base_status(cpu_percent=0.0, cpu_available=False))
    service._recent.append(_base_status(cpu_percent=20.0, cpu_available=True))
    service._recent.append(_base_status(cpu_percent=40.0, cpu_available=True))

    avg = asyncio.run(service.snapshot_averaged())

    # Only the two available readings (20, 40) count -> 30, not (0+20+40)/3.
    assert avg.cpu_percent == approx(30.0)
    assert avg.cpu_available is True


def test_snapshot_averaged_net_mean_over_available_samples_only() -> None:
    """Network is averaged over only the available samples; the rest are skipped."""
    service = ServerStatusService()
    service._recent.append(_base_status(net_available=False, net_in_mbps=0.0, net_out_mbps=0.0))
    service._recent.append(_base_status(net_available=True, net_in_mbps=8.0, net_out_mbps=4.0))
    service._recent.append(_base_status(net_available=True, net_in_mbps=12.0, net_out_mbps=6.0))

    avg = asyncio.run(service.snapshot_averaged())

    assert avg.net_in_mbps == approx(10.0)  # (8 + 12) / 2; the unavailable sample excluded
    assert avg.net_out_mbps == approx(5.0)
    assert avg.net_available is True


def test_snapshot_averaged_all_unavailable_falls_back_to_zero() -> None:
    """When no sample in the window has a metric, it reads 0.0 with flag cleared."""
    service = ServerStatusService()
    for _ in range(3):
        service._recent.append(
            _base_status(
                cpu_percent=0.0,
                cpu_available=False,
                net_available=False,
                net_in_mbps=0.0,
                net_out_mbps=0.0,
            )
        )

    avg = asyncio.run(service.snapshot_averaged())

    assert avg.cpu_available is False
    assert avg.cpu_percent == approx(0.0)
    assert avg.net_available is False
    assert avg.net_in_mbps == approx(0.0)
    assert avg.net_out_mbps == approx(0.0)


def test_sample_once_fills_recent_buffer_in_base_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """The averaging window is filled every tick even with detailed mode off,
    and is bounded to exactly the averaging length."""
    monkeypatch.setattr(ss, "_read_cpu_times", lambda: (1000, 500))
    monkeypatch.setattr(ss, "_read_net_bytes", lambda: (0, 0))
    monkeypatch.setattr(ss, "_read_mem_gb", lambda: (1.0, 2.0))
    monkeypatch.setattr(ServerStatusService, "_read_disk", lambda self: (5.0, 10.0))

    service = ServerStatusService()  # detailed defaults off
    for _ in range(5):
        service._sample_once()

    assert service.detailed is False
    assert len(service._recent) == ss._AVERAGING_SAMPLES
    # The 60s detailed history stays empty in base mode (unchanged behaviour).
    assert len(service._history) == 0


def test_snapshot_returns_latest_not_averaged() -> None:
    """Regression: snapshot() still returns the most recent sample verbatim,
    while snapshot_averaged() smooths across the window."""
    service = ServerStatusService()
    s1 = _base_status(cpu_percent=10.0, net_in_mbps=2.0)
    s2 = _base_status(cpu_percent=50.0, net_in_mbps=10.0)
    service._recent.append(s1)
    service._recent.append(s2)
    service._latest = s2

    latest = asyncio.run(service.snapshot())
    assert latest is s2
    assert latest.cpu_percent == approx(50.0)

    avg = asyncio.run(service.snapshot_averaged())
    assert avg.cpu_percent == approx(30.0)  # (10 + 50) / 2


# --- sparkline buckets: one column per render -------------------------------


def test_snapshot_averaged_flushes_one_sparkline_bucket_per_render() -> None:
    """In detailed mode each render averages the samples gathered since the
    previous render into a single sparkline column, then resets the accumulator —
    so a sampled second feeds exactly one column and never re-buckets."""
    service = ServerStatusService()
    service.set_detailed(True)
    service._recent.append(_base_status(detailed_enabled=True))

    # Three ticks accumulate before the first render.
    service._bucket_samples.extend([1.0, 2.0, 3.0])
    first = asyncio.run(service.snapshot_averaged())
    assert first.net_sparkline is not None and len(first.net_sparkline) == 1
    assert first.net_sparkline[0] == approx(2.0)  # mean(1, 2, 3)
    assert service._bucket_samples == []  # accumulator reset by the flush

    # A second render with a fresh batch appends a second column; the first
    # column is untouched (already-consumed seconds are never re-bucketed).
    service._bucket_samples.extend([4.0, 8.0])
    second = asyncio.run(service.snapshot_averaged())
    assert second.net_sparkline is not None and len(second.net_sparkline) == 2
    assert second.net_sparkline[0] == approx(2.0)
    assert second.net_sparkline[1] == approx(6.0)  # mean(4, 8)

    # An empty accumulator (no tick since the last render) emits no new column.
    third = asyncio.run(service.snapshot_averaged())
    assert third.net_sparkline is not None and len(third.net_sparkline) == 2


def test_sparkline_buckets_cap_at_sparkline_width() -> None:
    """The bucket window holds at most _SPARKLINE_POINTS columns (oldest drop)."""
    service = ServerStatusService()
    service.set_detailed(True)
    service._recent.append(_base_status(detailed_enabled=True))
    avg = None
    for i in range(ss._SPARKLINE_POINTS + 5):
        service._bucket_samples.append(float(i))
        avg = asyncio.run(service.snapshot_averaged())
    assert avg is not None and avg.net_sparkline is not None
    assert len(avg.net_sparkline) == ss._SPARKLINE_POINTS
