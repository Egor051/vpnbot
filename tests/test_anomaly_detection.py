
import asyncio
import collections
import time as time_module
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adapters import ip_asn
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType
from services.anomaly_detection import (
    AnomalyDetectionService,
    _parse_xray_log_timestamp,
)


# ------------------------------------------------------------------ fixtures


def _awg_key(key_id: int = 1, public_key: str = "pubkey1") -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=100,
        username="alice",
        key_type=VpnKeyType.AWG,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=None,
        email_label=None,
        public_key=public_key,
        client_ip="10.0.0.2",
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


def _xray_key(key_id: int = 2, email_label: str = "xray_label1") -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=101,
        username="bob",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="uuid-1",
        email_label=email_label,
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=101,
        revoked_by=None,
        deleted_by=None,
    )


def _make_service(**kwargs) -> AnomalyDetectionService:
    defaults = dict(
        vpn_keys=AsyncMock(),
        awg=AsyncMock(),
        xray_service=AsyncMock(),
        awg_service=AsyncMock(),
        admin_ids=frozenset([999]),
        window_seconds=3600,
        unique_nets=3,
        auto_revoke=False,
        cooldown_seconds=7200,
        xray_access_log_path="",
        concurrent_window_seconds=0,
    )
    # No IP2ASN_DB_PATH is set for these tests, so normalize_ip degrades to /24
    # grouping; the IPs below are chosen to live in distinct /24s where a test
    # expects an alert. See test_ip_asn.py for the ASN-database path.
    defaults.update(kwargs)
    svc = AnomalyDetectionService(**defaults)
    svc.bot = AsyncMock()
    return svc


# ------------------------------------------------------------------ rolling window


def test_record_and_unique_ips():
    svc = _make_service(window_seconds=60)
    now = time_module.time()
    svc._record_ip(1, now, "1.2.3.4")
    svc._record_ip(1, now, "5.6.7.8")
    svc._record_ip(1, now, "1.2.3.4")  # duplicate
    assert svc._unique_ips_in_window(1, now) == frozenset({"1.2.3.4", "5.6.7.8"})


def test_window_prunes_old_entries():
    svc = _make_service(window_seconds=60)
    now = time_module.time()
    svc._record_ip(1, now - 120, "old.ip.0.1")  # outside window
    svc._record_ip(1, now - 30, "new.ip.0.2")  # inside window
    unique = svc._unique_ips_in_window(1, now)
    assert unique == frozenset({"new.ip.0.2"})


def test_empty_window_returns_empty():
    svc = _make_service()
    assert svc._unique_ips_in_window(99, time_module.time()) == frozenset()


# ------------------------------------------------------------------ AWG endpoint parsing


def test_awg_endpoint_ipv4_stripped():
    from adapters.awg_config import AwgConfigAdapter
    output = (
        "interface: awg0\n"
        "  public key: serverkey\n\n"
        "peer: pubkey1\n"
        "  endpoint: 1.2.3.4:51820\n"
        "  allowed ips: 10.0.0.2/32\n"
        "  latest handshake: 5 seconds ago\n"
        "  transfer: 1 MiB received, 2 MiB sent\n"
    )
    peers = AwgConfigAdapter._parse_runtime_peers(None, output)
    assert peers == [{"PublicKey": "pubkey1", "AllowedIPs": "10.0.0.2/32", "Endpoint": "1.2.3.4:51820"}]


def test_awg_endpoint_ipv6_stripped():
    from adapters.awg_config import AwgConfigAdapter
    output = (
        "peer: pubkey2\n"
        "  endpoint: [2001:db8::1]:51820\n"
        "  allowed ips: 10.0.0.3/32\n"
    )
    peers = AwgConfigAdapter._parse_runtime_peers(None, output)
    assert peers[0]["Endpoint"] == "[2001:db8::1]:51820"


def test_awg_peer_no_endpoint():
    from adapters.awg_config import AwgConfigAdapter
    output = "peer: pubkey3\n  allowed ips: 10.0.0.4/32\n"
    peers = AwgConfigAdapter._parse_runtime_peers(None, output)
    assert "Endpoint" not in peers[0]


# ------------------------------------------------------------------ list_peer_endpoints helper


def test_list_peer_endpoints_extracts_ips():
    from adapters.awg_config import AwgConfigAdapter

    svc = MagicMock(spec=AwgConfigAdapter)
    svc.list_runtime_peers = AsyncMock(
        return_value=[
            {"PublicKey": "pk1", "Endpoint": "1.2.3.4:51820", "AllowedIPs": "10.0.0.2/32"},
            {"PublicKey": "pk2", "Endpoint": "[::1]:51820"},
            {"PublicKey": "pk3"},  # no endpoint
        ]
    )

    async def run():
        return await AwgConfigAdapter.list_peer_endpoints(svc)

    result = asyncio.run(run())
    assert result == {"pk1": "1.2.3.4", "pk2": "::1"}


# ------------------------------------------------------------------ Xray log parsing


def test_parse_xray_log_timestamp_valid():
    line = "2024/06/15 14:30:00 from 1.2.3.4:5678 accepted tcp:example.com:443 email: user_abc [vless]"
    ts = _parse_xray_log_timestamp(line)
    assert ts is not None
    assert isinstance(ts, float)


def test_parse_xray_log_timestamp_invalid():
    assert _parse_xray_log_timestamp("no timestamp here") is None
    assert _parse_xray_log_timestamp("") is None


def test_parse_xray_log_tail_extracts_ips(tmp_path):
    svc = _make_service(xray_access_log_path=str(tmp_path / "access.log"))
    now = time_module.time()
    import datetime as dt
    ts_str = dt.datetime.fromtimestamp(now - 60).strftime("%Y/%m/%d %H:%M:%S")
    log = (
        f"{ts_str} from 1.2.3.4:5678 accepted tcp:example.com:443 email: xray_label1 [vless]\n"
        f"{ts_str} from 5.6.7.8:9999 accepted tcp:example.com:443 email: xray_label1 [vless]\n"
        f"{ts_str} from 9.9.9.9:1234 accepted tcp:example.com:443 email: xray_label2 [vless]\n"
    )
    (tmp_path / "access.log").write_text(log)
    label_to_key = {"xray_label1": 10, "xray_label2": 20}
    entries = svc._parse_xray_log_tail(now - 3600, label_to_key)
    key_ips: dict[int, set[str]] = {}
    for key_id, ip, ts in entries:
        assert isinstance(ts, float)
        key_ips.setdefault(key_id, set()).add(ip)
    assert key_ips.get(10) == {"1.2.3.4", "5.6.7.8"}
    assert key_ips.get(20) == {"9.9.9.9"}


def test_parse_xray_log_tail_skips_old_entries(tmp_path):
    svc = _make_service(xray_access_log_path=str(tmp_path / "access.log"))
    now = time_module.time()
    import datetime as dt
    old_ts = dt.datetime.fromtimestamp(now - 7200).strftime("%Y/%m/%d %H:%M:%S")
    log = f"{old_ts} from 1.2.3.4:5678 accepted tcp:x.com:443 email: xray_label1 [vless]\n"
    (tmp_path / "access.log").write_text(log)
    entries = svc._parse_xray_log_tail(now - 3600, {"xray_label1": 10})
    assert entries == []


def test_parse_xray_log_tail_missing_file(tmp_path):
    svc = _make_service(xray_access_log_path=str(tmp_path / "nonexistent.log"))
    entries = svc._parse_xray_log_tail(0.0, {"label": 1})
    assert entries == []


# ------------------------------------------------------------------ check_all / thresholds


def test_alert_fires_when_threshold_exceeded():
    key = _awg_key(key_id=5, public_key="pkX")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.list_by_type_statuses.return_value = [key]
    vpn_keys_mock.get_by_id.return_value = key

    awg_mock = AsyncMock()
    awg_mock.list_peer_endpoints.return_value = {"pkX": "1.1.1.1"}

    svc = _make_service(
        vpn_keys=vpn_keys_mock,
        awg=awg_mock,
        unique_nets=3,
        window_seconds=3600,
        cooldown_seconds=0,
    )
    svc.bot = AsyncMock()

    now = time_module.time()
    # Three IPs in three distinct /24s => 3 unique networks (real sharing).
    svc._record_ip(5, now - 100, "10.0.0.1")
    svc._record_ip(5, now - 80, "10.1.0.2")
    svc._record_ip(5, now - 60, "10.2.0.3")

    asyncio.run(svc._check_thresholds(now))

    svc.bot.send_message.assert_called_once()
    call_args, call_kwargs = svc.bot.send_message.call_args
    assert call_args[0] == 999
    assert call_kwargs.get("reply_markup") is not None


def test_alert_respects_cooldown():
    key = _awg_key(key_id=6, public_key="pkY")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(
        vpn_keys=vpn_keys_mock,
        unique_nets=1,
        cooldown_seconds=3600,
    )
    svc.bot = AsyncMock()

    now = time_module.time()
    svc._record_ip(6, now - 10, "1.2.3.4")
    svc._last_alerted[6] = now - 100  # alerted 100s ago, cooldown=3600

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_not_called()


def test_no_alert_below_threshold():
    key = _awg_key(key_id=7)
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(vpn_keys=vpn_keys_mock, unique_nets=5, cooldown_seconds=0)
    svc.bot = AsyncMock()

    now = time_module.time()
    svc._record_ip(7, now, "1.1.1.1")
    svc._record_ip(7, now, "2.2.2.2")

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_not_called()


# ------------------------------------------------------------------ concurrent window


def test_no_alert_mobile_roaming():
    """Mobile user: 4 unique IPs over 60 min but only 1 IP in the last 10 min."""
    key = _awg_key(key_id=10, public_key="pkMobile")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(
        vpn_keys=vpn_keys_mock,
        unique_nets=3,
        cooldown_seconds=0,
        window_seconds=3600,
        concurrent_window_seconds=600,
    )
    svc.bot = AsyncMock()

    now = time_module.time()
    # Four sequential IPs from different carrier NAT sessions — all older than 10 min
    svc._record_ip(10, now - 3000, "31.135.76.185")
    svc._record_ip(10, now - 2400, "31.173.84.186")
    svc._record_ip(10, now - 1800, "31.173.84.228")
    svc._record_ip(10, now - 700, "31.173.85.7")
    # Only the current IP is within the 10-min concurrent window
    svc._record_ip(10, now - 60, "31.173.85.7")

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_not_called()


def test_alert_fires_concurrent_sharing():
    """Key sharing: 3 different IPs active within the last 10 min."""
    key = _awg_key(key_id=11, public_key="pkShared")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(
        vpn_keys=vpn_keys_mock,
        unique_nets=3,
        cooldown_seconds=0,
        window_seconds=3600,
        concurrent_window_seconds=600,
    )
    svc.bot = AsyncMock()

    now = time_module.time()
    # Three concurrent IPs in three distinct /24s => 3 unique networks.
    svc._record_ip(11, now - 120, "10.0.0.1")
    svc._record_ip(11, now - 90, "10.1.0.2")
    svc._record_ip(11, now - 60, "10.2.0.3")

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_called_once()


def test_concurrent_window_disabled_falls_back_to_full_window():
    """concurrent_window_seconds=0 restores original full-window behavior."""
    key = _awg_key(key_id=12, public_key="pkLegacy")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(
        vpn_keys=vpn_keys_mock,
        unique_nets=3,
        cooldown_seconds=0,
        window_seconds=3600,
        concurrent_window_seconds=0,
    )
    svc.bot = AsyncMock()

    now = time_module.time()
    # Three IPs spread over the last hour (no concurrent overlap) — still triggers
    svc._record_ip(12, now - 3000, "1.1.1.1")
    svc._record_ip(12, now - 2000, "2.2.2.2")
    svc._record_ip(12, now - 1000, "3.3.3.3")

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_called_once()


def test_unique_ips_in_concurrent_window():
    svc = _make_service(window_seconds=3600, concurrent_window_seconds=600)
    now = time_module.time()
    svc._record_ip(1, now - 700, "old.ip")    # outside concurrent window
    svc._record_ip(1, now - 300, "new.ip.1")  # inside
    svc._record_ip(1, now - 100, "new.ip.2")  # inside
    # Prune main window first
    svc._unique_ips_in_window(1, now)
    assert svc._unique_ips_in_concurrent_window(1, now) == frozenset({"new.ip.1", "new.ip.2"})


# ------------------------------------------------------------------ P5-007: Xray ts + high-water


def test_sample_xray_log_records_real_ts_and_dedupes_on_rescan(tmp_path):
    """A historical Xray log line is recorded at its own timestamp and only once.

    The 2 MB tail is re-parsed every scan; without the high-water gate and with
    recording at `now`, the same past event would be re-stamped to "now" each
    scan — inflating the window and wrongly counting as "concurrent". Here the
    event is 50 min old (inside the 60-min window, outside the 10-min concurrent
    window) and must never register as concurrent, even after a re-scan.
    """
    import datetime as dt

    key = _xray_key(key_id=30, email_label="xray_label1")

    def _list(key_type, statuses, limit, after_id):
        return [key] if after_id == 0 else []

    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.list_by_type_statuses = AsyncMock(side_effect=_list)

    svc = _make_service(
        vpn_keys=vpn_keys_mock,
        xray_access_log_path=str(tmp_path / "access.log"),
        window_seconds=3600,
        concurrent_window_seconds=600,
    )

    now = time_module.time()
    event_ts = now - 3000  # 50 min ago
    ts_str = dt.datetime.fromtimestamp(event_ts).strftime("%Y/%m/%d %H:%M:%S")
    (tmp_path / "access.log").write_text(
        f"{ts_str} from 1.2.3.4:5678 accepted tcp:x.com:443 email: xray_label1 [vless]\n"
    )

    asyncio.run(svc._sample_xray_log(now))

    obs = svc._observations.get(30)
    assert obs is not None and len(obs) == 1
    recorded_ts, recorded_ip = obs[0]
    assert recorded_ip == "1.2.3.4"
    # Recorded at the event's OWN timestamp (not `now`).
    assert abs(recorded_ts - event_ts) < 1.0
    # 50-min-old event is NOT within the 10-min concurrent window.
    assert svc._unique_ips_in_concurrent_window(30, now) == frozenset()

    # Re-scanning the identical tail must not re-record the line.
    asyncio.run(svc._sample_xray_log(now + 1))
    assert len(svc._observations[30]) == 1
    assert svc._unique_ips_in_concurrent_window(30, now + 1) == frozenset()


def test_evict_stale_last_alerted_drops_expired_entries():
    """Cooldown timestamps past the cooldown horizon are forgotten (P5-010)."""
    svc = _make_service(cooldown_seconds=7200)
    now = time_module.time()
    svc._last_alerted[1] = now - 100      # fresh — keep
    svc._last_alerted[2] = now - 10_000   # older than cooldown — evict
    svc._evict_stale_last_alerted(now)
    assert 1 in svc._last_alerted
    assert 2 not in svc._last_alerted


# ------------------------------------------------------------------ ASN/network normalization


# The false-positive report: one home-ISP IP (AS25513) plus six rotating LTE
# addresses inside 91.79.3.0/24 (AS8359). Under network counting these collapse
# to two groups, below the default threshold of three.
_REPORT_ASN_TSV = (
    "91.79.3.0\t91.79.3.255\t8359\tRU\tMTS\n"
    "109.252.72.0\t109.252.79.255\t25513\tRU\tMGTS\n"
)
_REPORT_IPS = [
    "109.252.72.195",
    "91.79.3.141",
    "91.79.3.145",
    "91.79.3.151",
    "91.79.3.189",
    "91.79.3.222",
    "91.79.3.227",
]


@pytest.fixture
def report_asn_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db = tmp_path / "ip2asn-v4.tsv"
    db.write_text(_REPORT_ASN_TSV, encoding="utf-8")
    monkeypatch.setenv("IP2ASN_DB_PATH", str(db))
    ip_asn.reset_cache()
    yield db
    ip_asn.reset_cache()


def test_report_seven_ips_do_not_alert_at_threshold_3(report_asn_db):
    """The 7 report IPs collapse to 2 ASN groups -> no alert at unique_nets=3."""
    key = _awg_key(key_id=20, public_key="pkReport")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(vpn_keys=vpn_keys_mock, unique_nets=3, cooldown_seconds=0)
    svc.bot = AsyncMock()

    now = time_module.time()
    for offset, ip in enumerate(_REPORT_IPS):
        svc._record_ip(20, now - offset, ip)

    # Sanity: the raw IPs (7) would have tripped the old count; the networks (2) do not.
    assert len(svc._unique_ips_in_window(20, now)) == len(_REPORT_IPS)
    nets = {ip_asn.normalize_ip(ip) for ip in _REPORT_IPS}
    assert nets == {"AS8359", "AS25513"}

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_not_called()
    assert 20 not in svc._last_alerted


def test_report_alert_shows_grouped_breakdown(report_asn_db):
    """Lowering the threshold to 2 fires an alert grouped by network."""
    key = _awg_key(key_id=21, public_key="pkReport2")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(vpn_keys=vpn_keys_mock, unique_nets=2, cooldown_seconds=0)
    svc.bot = AsyncMock()

    now = time_module.time()
    for offset, ip in enumerate(_REPORT_IPS):
        svc._record_ip(21, now - offset, ip)

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_called_once()
    text = svc.bot.send_message.call_args.args[1]
    assert "AS8359: 6 IP" in text
    assert "AS25513: 1 IP" in text
    assert "2 уник. сетей" in text


def test_garbage_ip_does_not_crash_detector():
    """A non-IP string from a malformed log line must not break the check."""
    key = _awg_key(key_id=22, public_key="pkGarbage")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(vpn_keys=vpn_keys_mock, unique_nets=3, cooldown_seconds=0)
    svc.bot = AsyncMock()

    now = time_module.time()
    # One garbage token plus two IPs in distinct /24s => 3 networks, alert fires,
    # exercising both the threshold count and the grouped alert text with junk.
    svc._record_ip(22, now - 30, "garbage-not-an-ip")
    svc._record_ip(22, now - 20, "203.0.113.10")
    svc._record_ip(22, now - 10, "198.51.100.10")

    asyncio.run(svc._check_thresholds(now))  # must not raise

    svc.bot.send_message.assert_called_once()
    text = svc.bot.send_message.call_args.args[1]
    assert "garbage-not-an-ip: 1 IP" in text
