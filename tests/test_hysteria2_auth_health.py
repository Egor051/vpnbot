"""Hysteria2 backend-health parity: the hy2_auth /healthz probe and its loop."""
import asyncio

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from adapters.hysteria_auth_health import Hysteria2AuthHealthProbe
from bot.app import _hysteria_health_loop
from models.enums import VpnKeyType
from services.backend_health import BackendHealth


async def _serve(status: int) -> TestServer:
    async def healthz(request: web.Request) -> web.Response:
        return web.json_response({"ok": status == 200}, status=status)

    app = web.Application()
    app.router.add_get("/healthz", healthz)
    server = TestServer(app)
    await server.start_server()
    return server


# ── probe (HTTP level) ───────────────────────────────────────────────────────


async def test_probe_healthy_on_200() -> None:
    server = await _serve(200)
    try:
        probe = Hysteria2AuthHealthProbe(auth_listen=f"127.0.0.1:{server.port}")
        assert await probe.healthy() is True
    finally:
        await server.close()


async def test_probe_unhealthy_on_503() -> None:
    server = await _serve(503)
    try:
        probe = Hysteria2AuthHealthProbe(auth_listen=f"127.0.0.1:{server.port}")
        assert await probe.healthy() is False
    finally:
        await server.close()


async def test_probe_unhealthy_when_unreachable() -> None:
    # Nothing is listening on this loopback port -> connection refused -> False,
    # never raises (the loop treats it as a degraded data plane).
    probe = Hysteria2AuthHealthProbe(auth_listen="127.0.0.1:1")
    assert await probe.healthy() is False


def test_probe_rejects_malformed_listen() -> None:
    with pytest.raises(ValueError):
        Hysteria2AuthHealthProbe(auth_listen="not-a-host-port")


def test_probe_builds_ipv6_authority() -> None:
    probe = Hysteria2AuthHealthProbe(auth_listen="[::1]:8444")
    assert probe._url == "http://[::1]:8444/healthz"


# ── health loop (backend_health integration) ─────────────────────────────────


class _FakeProbe:
    """Returns queued healthy() values, then raises CancelledError to end the loop.

    CancelledError (a BaseException, not Exception) escapes the loop's
    ``except Exception`` guard, so it deterministically stops after the queued
    iterations without relying on timing.
    """

    def __init__(self, values: list[bool]) -> None:
        self._values = values
        self.calls = 0

    async def healthy(self) -> bool:
        if self.calls >= len(self._values):
            raise asyncio.CancelledError
        value = self._values[self.calls]
        self.calls += 1
        return value


def _hy2_status(health: BackendHealth) -> object:
    return {s.backend_type: s for s in health.snapshot()}[VpnKeyType.HYSTERIA2]


async def test_loop_marks_healthy() -> None:
    health = BackendHealth()
    health.mark_degraded(VpnKeyType.HYSTERIA2, "stale")  # pre-existing degraded
    probe = _FakeProbe([True])
    with pytest.raises(asyncio.CancelledError):
        await _hysteria_health_loop(probe, health, interval=0)
    status = _hy2_status(health)
    assert status.degraded is False


async def test_loop_marks_degraded() -> None:
    health = BackendHealth()
    probe = _FakeProbe([False])
    with pytest.raises(asyncio.CancelledError):
        await _hysteria_health_loop(probe, health, interval=0)
    status = _hy2_status(health)
    assert status.degraded is True
    assert status.reason and "healthz" in status.reason
