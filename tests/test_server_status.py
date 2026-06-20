import asyncio

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
    service = ServerStatusService(sample_interval=0.01)
    status = asyncio.run(service.snapshot())
    assert isinstance(status, ServerStatus)
    # On the Linux CI host /proc is present, so disk total is always positive.
    assert status.disk_total_gb > 0
    assert 0.0 <= status.cpu_percent <= 100.0


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
