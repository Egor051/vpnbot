"""Hysteria2 Traffic Stats API: adapter, online-clients, traffic-stats, anomaly."""
import asyncio
from itertools import count
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from adapters.hysteria_stats import HysteriaStatsAdapter, HysteriaStatsUnavailable
from models.dto import TrafficStats, VpnKey
from models.enums import VpnKeyStatus, VpnKeyType
from services.anomaly_detection import AnomalyDetectionService
from services.online_clients import OnlineClients, OnlineClientsService
from services.traffic_stats import TrafficStatsService

SECRET = "s3cret-token"


# ── adapter (HTTP level) ─────────────────────────────────────────────────────


async def _serve(handlers: dict[tuple[str, str], object]) -> TestServer:
    app = web.Application()
    for (method, path), handler in handlers.items():
        app.router.add_route(method, path, handler)  # type: ignore[arg-type]
    server = TestServer(app)
    await server.start_server()
    return server


def _adapter_for(server: TestServer) -> HysteriaStatsAdapter:
    return HysteriaStatsAdapter(listen=f"127.0.0.1:{server.port}", secret=SECRET)


async def test_query_all_maps_tx_rx_to_uploaded_downloaded() -> None:
    async def traffic(request: web.Request) -> web.Response:
        assert request.headers.get("Authorization") == SECRET
        return web.json_response({"hy2_a": {"tx": 10, "rx": 20}, "hy2_b": {"tx": 3, "rx": 4}})

    server = await _serve({("GET", "/traffic"): traffic})
    try:
        result = await _adapter_for(server).query_all()
        # (uploaded=tx, downloaded=rx)
        assert result == {"hy2_a": (10, 20), "hy2_b": (3, 4)}
    finally:
        await server.close()


async def test_query_all_ignores_malformed_entries() -> None:
    async def traffic(request: web.Request) -> web.Response:
        return web.json_response(
            {"hy2_a": {"tx": 5, "rx": 6}, "hy2_bad": "nope", 42: {"tx": 1}, "hy2_partial": {"tx": 7}}
        )

    server = await _serve({("GET", "/traffic"): traffic})
    try:
        result = await _adapter_for(server).query_all()
        assert result["hy2_a"] == (5, 6)
        assert result["hy2_partial"] == (7, 0)  # missing rx coerced to 0
        assert "hy2_bad" not in result
    finally:
        await server.close()


async def test_query_online_counts_connections() -> None:
    async def online(request: web.Request) -> web.Response:
        return web.json_response({"hy2_a": 2, "hy2_b": 0, "hy2_c": 1})

    server = await _serve({("GET", "/online"): online})
    try:
        result = await _adapter_for(server).query_online()
        assert result == {"hy2_a": 2, "hy2_b": 0, "hy2_c": 1}
    finally:
        await server.close()


async def test_kick_posts_labels_with_auth() -> None:
    seen: dict[str, object] = {}

    async def kick(request: web.Request) -> web.Response:
        seen["auth"] = request.headers.get("Authorization")
        seen["body"] = await request.json()
        return web.json_response({"ok": True})

    server = await _serve({("POST", "/kick"): kick})
    try:
        await _adapter_for(server).kick(["hy2_a", "hy2_b"])
        assert seen["auth"] == SECRET
        assert seen["body"] == ["hy2_a", "hy2_b"]
    finally:
        await server.close()


async def test_kick_empty_list_is_noop() -> None:
    called = {"n": 0}

    async def kick(request: web.Request) -> web.Response:
        called["n"] += 1
        return web.json_response({"ok": True})

    server = await _serve({("POST", "/kick"): kick})
    try:
        await _adapter_for(server).kick([])
        assert called["n"] == 0  # no request issued
    finally:
        await server.close()


async def test_non_200_raises_unavailable() -> None:
    async def traffic(request: web.Request) -> web.Response:
        return web.json_response({"error": "unauthorized"}, status=401)

    server = await _serve({("GET", "/traffic"): traffic})
    try:
        with pytest.raises(HysteriaStatsUnavailable):
            await _adapter_for(server).query_all()
    finally:
        await server.close()


async def test_bad_json_raises_unavailable() -> None:
    async def traffic(request: web.Request) -> web.Response:
        return web.Response(body=b"not json", content_type="application/json")

    server = await _serve({("GET", "/traffic"): traffic})
    try:
        with pytest.raises(HysteriaStatsUnavailable):
            await _adapter_for(server).query_all()
    finally:
        await server.close()


async def test_connection_refused_raises_unavailable() -> None:
    # Nothing listening on this loopback port → transport error → Unavailable.
    adapter = HysteriaStatsAdapter(listen="127.0.0.1:1", secret=SECRET)
    with pytest.raises(HysteriaStatsUnavailable):
        await adapter.query_online()


def test_build_base_url_brackets_ipv6() -> None:
    adapter = HysteriaStatsAdapter(listen="[::1]:9999", secret=SECRET)
    assert adapter._base_url == "http://[::1]:9999"  # noqa: SLF001


# ── online clients ───────────────────────────────────────────────────────────


class _FakeOnline:
    def __init__(self, snapshots: list[dict[str, int]]) -> None:
        self._snapshots = snapshots
        self.calls = 0

    async def query_online(self) -> dict[str, int]:
        snap = self._snapshots[min(self.calls, len(self._snapshots) - 1)]
        self.calls += 1
        return snap


class _EmptyAwg:
    async def list_transfer(self) -> dict[str, tuple[int, int]]:
        return {}


class _EmptyXray:
    async def query_all(self) -> dict[str, int]:
        return {}


def test_online_counts_hysteria_labels_with_live_connections() -> None:
    # hy2 online is instantaneous: labels with >0 connections count immediately,
    # no baseline needed (unlike wg/xray).
    hy = _FakeOnline([{"hy2_a": 2, "hy2_b": 0, "hy2_c": 1}])
    svc = OnlineClientsService(
        awg_adapter=_EmptyAwg(), xray_stats=_EmptyXray(), hysteria_stats=hy, clock=lambda: 0.0
    )
    result = asyncio.run(svc.get())
    assert result.hysteria2 == 2  # a and c are live, b idle
    assert result.total == 2
    assert result.available is True


def test_online_hysteria_none_when_adapter_absent() -> None:
    svc = OnlineClientsService(awg_adapter=_EmptyAwg(), xray_stats=_EmptyXray(), clock=lambda: 0.0)
    result = asyncio.run(svc.get())
    assert result.hysteria2 is None
    assert result == OnlineClients(wg=None, xray=None, hysteria2=None, total=None, available=False)


def test_online_hysteria_none_on_backend_error() -> None:
    class _BrokenHy:
        async def query_online(self) -> dict[str, int]:
            raise RuntimeError("stats down")

    clock = count(0, 100)
    svc = OnlineClientsService(
        awg_adapter=_EmptyAwg(), xray_stats=_EmptyXray(), hysteria_stats=_BrokenHy(), clock=lambda: next(clock)
    )
    result = asyncio.run(svc.get())
    assert result.hysteria2 is None


# ── traffic stats ────────────────────────────────────────────────────────────


def _hy2_key() -> VpnKey:
    return VpnKey(
        id=42,
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.HYSTERIA2,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=None,
        email_label="hy2_deadbeefdeadbeef",
        public_key=None,
        client_ip=None,
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


class _StatsRepo:
    def __init__(self) -> None:
        self.last: TrafficStats | None = None

    async def upsert_success(self, *, key_id, downloaded_bytes, uploaded_bytes, raw_downloaded_bytes,
                             raw_uploaded_bytes, now, source):  # type: ignore[no-untyped-def]
        self.last = TrafficStats(
            key_id=key_id, downloaded_bytes=downloaded_bytes, uploaded_bytes=uploaded_bytes,
            last_raw_downloaded_bytes=raw_downloaded_bytes, last_raw_uploaded_bytes=raw_uploaded_bytes,
            last_success_at=now, last_attempt_at=now, available=True, unavailable_reason=None, source=source,
        )
        return self.last

    async def upsert_unavailable(self, *, key_id, reason, now, source):  # type: ignore[no-untyped-def]
        self.last = TrafficStats(
            key_id=key_id, downloaded_bytes=0, uploaded_bytes=0, last_raw_downloaded_bytes=None,
            last_raw_uploaded_bytes=None, last_success_at=None, last_attempt_at=now, available=False,
            unavailable_reason=reason, source=source,
        )
        return self.last


def _traffic_service(repo: _StatsRepo, hysteria: object | None) -> TrafficStatsService:
    return TrafficStatsService(
        stats=repo,  # type: ignore[arg-type]
        vpn_keys=SimpleNamespace(),
        users_repo=SimpleNamespace(),
        users=SimpleNamespace(clock=SimpleNamespace(now=lambda: "now")),
        awg=SimpleNamespace(),
        xray=SimpleNamespace(),
        hysteria=hysteria,  # type: ignore[arg-type]
    )


def test_refresh_hysteria_key_accumulates_tx_rx() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _traffic_service(repo, hysteria=SimpleNamespace())
        result = await service._refresh_hysteria_key(  # noqa: SLF001
            _hy2_key(), None, {"hy2_deadbeefdeadbeef": (100, 250)}, None
        )
        assert result.uploaded_bytes == 100  # tx -> uploaded
        assert result.downloaded_bytes == 250  # rx -> downloaded
        assert result.available is True
        assert result.source == "hysteria2 trafficStats"

    asyncio.run(run())


def test_refresh_hysteria_key_missing_label_is_unavailable() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _traffic_service(repo, hysteria=SimpleNamespace())
        result = await service._refresh_hysteria_key(_hy2_key(), None, {}, None)  # noqa: SLF001
        assert result.available is False

    asyncio.run(run())


def test_refresh_hysteria_key_load_error_is_unavailable() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _traffic_service(repo, hysteria=SimpleNamespace())
        result = await service._refresh_hysteria_key(  # noqa: SLF001
            _hy2_key(), None, {}, "backend down"
        )
        assert result.available is False
        assert result.unavailable_reason == "backend down"

    asyncio.run(run())


def test_load_hysteria_stats_returns_error_when_adapter_absent() -> None:
    async def run() -> None:
        repo = _StatsRepo()
        service = _traffic_service(repo, hysteria=None)
        stats, error = await service._load_hysteria_stats([_hy2_key()])  # noqa: SLF001
        assert stats == {}
        assert error is not None  # surfaced as "unavailable" to the key

    asyncio.run(run())


# ── anomaly detection (connection-count signal) ──────────────────────────────


class _FakeVpnKeys:
    def __init__(self, keys: list[VpnKey]) -> None:
        self._keys = keys

    async def list_by_type_statuses(self, key_type, statuses, limit, after_id=0):  # type: ignore[no-untyped-def]
        if after_id:
            return []
        return [k for k in self._keys if k.key_type == key_type]

    async def get_by_id(self, key_id):  # type: ignore[no-untyped-def]
        return next((k for k in self._keys if k.id == key_id), None)


class _FakeHyStats:
    def __init__(self, online: dict[str, int]) -> None:
        self._online = online

    async def query_online(self) -> dict[str, int]:
        return self._online


class _RecordingHysteriaService:
    def __init__(self) -> None:
        self.revoked: list[int] = []

    async def revoke_hysteria2_key_system(self, key_id: int) -> None:
        self.revoked.append(key_id)


def _anomaly(vpn_keys, hy_stats, hy_service, *, max_conn=3, auto_revoke=False):  # type: ignore[no-untyped-def]
    return AnomalyDetectionService(
        vpn_keys=vpn_keys,
        awg=SimpleNamespace(),
        xray_service=SimpleNamespace(),
        awg_service=SimpleNamespace(),
        admin_ids=frozenset(),
        hysteria_stats=hy_stats,
        hysteria_service=hy_service,
        hysteria2_max_conn=max_conn,
        auto_revoke=auto_revoke,
    )


def test_anomaly_flags_hysteria_key_over_threshold() -> None:
    async def run() -> None:
        key = _hy2_key()
        vpn_keys = _FakeVpnKeys([key])
        svc = _anomaly(vpn_keys, _FakeHyStats({key.email_label: 5}), _RecordingHysteriaService(), max_conn=3)
        await svc._check_hysteria_online(100000.0)  # noqa: SLF001
        # Flagged (cooldown recorded); no bot wired so no send, no auto-revoke.
        assert key.id in svc._last_alerted  # noqa: SLF001

    asyncio.run(run())


def test_anomaly_below_threshold_not_flagged() -> None:
    async def run() -> None:
        key = _hy2_key()
        svc = _anomaly(_FakeVpnKeys([key]), _FakeHyStats({key.email_label: 2}), _RecordingHysteriaService(), max_conn=3)
        await svc._check_hysteria_online(100000.0)  # noqa: SLF001
        assert key.id not in svc._last_alerted  # noqa: SLF001

    asyncio.run(run())


def test_anomaly_auto_revokes_hysteria_key() -> None:
    async def run() -> None:
        key = _hy2_key()
        hy_service = _RecordingHysteriaService()
        # auto_revoke on: hy2 uses the raw flag (concurrent by nature, no IP window needed).
        svc = _anomaly(_FakeVpnKeys([key]), _FakeHyStats({key.email_label: 9}), hy_service, max_conn=3, auto_revoke=True)
        await svc._check_hysteria_online(100000.0)  # noqa: SLF001
        assert hy_service.revoked == [key.id]

    asyncio.run(run())


def test_anomaly_disabled_when_threshold_zero() -> None:
    async def run() -> None:
        key = _hy2_key()
        svc = _anomaly(_FakeVpnKeys([key]), _FakeHyStats({key.email_label: 99}), _RecordingHysteriaService(), max_conn=0)
        await svc._check_hysteria_online(100000.0)  # noqa: SLF001
        assert key.id not in svc._last_alerted  # noqa: SLF001

    asyncio.run(run())


def test_anomaly_noop_when_stats_adapter_absent() -> None:
    async def run() -> None:
        key = _hy2_key()
        svc = _anomaly(_FakeVpnKeys([key]), None, _RecordingHysteriaService(), max_conn=3)
        await svc._check_hysteria_online(100000.0)  # noqa: SLF001
        assert key.id not in svc._last_alerted  # noqa: SLF001

    asyncio.run(run())
