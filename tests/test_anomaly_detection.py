
import asyncio
import collections
import time as time_module
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

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
        min_unique_ips=3,
        auto_revoke=False,
        cooldown_seconds=7200,
        xray_access_log_path="",
        concurrent_window_seconds=0,
    )
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
    for key_id, ip in entries:
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
        min_unique_ips=3,
        window_seconds=3600,
        cooldown_seconds=0,
    )
    svc.bot = AsyncMock()

    now = time_module.time()
    svc._record_ip(5, now - 100, "10.0.0.1")
    svc._record_ip(5, now - 80, "10.0.0.2")
    svc._record_ip(5, now - 60, "10.0.0.3")

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
        min_unique_ips=1,
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

    svc = _make_service(vpn_keys=vpn_keys_mock, min_unique_ips=5, cooldown_seconds=0)
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
        min_unique_ips=3,
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
        min_unique_ips=3,
        cooldown_seconds=0,
        window_seconds=3600,
        concurrent_window_seconds=600,
    )
    svc.bot = AsyncMock()

    now = time_module.time()
    svc._record_ip(11, now - 120, "10.0.0.1")
    svc._record_ip(11, now - 90, "10.0.0.2")
    svc._record_ip(11, now - 60, "10.0.0.3")

    asyncio.run(svc._check_thresholds(now))
    svc.bot.send_message.assert_called_once()


def test_concurrent_window_disabled_falls_back_to_full_window():
    """concurrent_window_seconds=0 restores original full-window behavior."""
    key = _awg_key(key_id=12, public_key="pkLegacy")
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    svc = _make_service(
        vpn_keys=vpn_keys_mock,
        min_unique_ips=3,
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
