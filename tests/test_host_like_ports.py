"""tests/host_like_ports.py — the CI job's stand-in for the deploy host's listeners.

Only ephemeral loopback ports here: the suite itself runs on the deploy host,
where the real ports are taken (and 443 is privileged).
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
from host_like_ports import TCP_PORTS, UDP_PORTS, _QuicLike, _tcp_handler, version_negotiation

from services.relay_health import is_version_negotiation, quic_probe, quic_vn_request

ROOT = Path(__file__).resolve().parents[1]
DCID, SCID = b"\x01" * 8, b"\x02" * 8


def test_it_answers_the_relay_probe_like_quic_go() -> None:
    reply = version_negotiation(quic_vn_request(DCID, SCID))
    assert reply is not None and is_version_negotiation(reply, dcid=DCID, scid=SCID)


@pytest.mark.parametrize(
    "datagram",
    [
        quic_vn_request(DCID, SCID)[:1199],  # quic-go ignores a datagram under 1200 bytes
        b"\x40" + quic_vn_request(DCID, SCID)[1:],  # short header
        b"\x80\x00\x00\x00\x00" + bytes(1195),  # a version negotiation itself
        b"\xc0\x1a\x2a\x3a\x4a\x40" + bytes(1194),  # a connection ID longer than QUIC allows
    ],
)
def test_it_does_not_negotiate_what_quic_go_would_not(datagram: bytes) -> None:
    assert version_negotiation(datagram) is None


async def test_the_udp_listener_passes_the_production_probe() -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _QuicLike(0), local_addr=("127.0.0.1", 0))
    try:
        port = transport.get_extra_info("sockname")[1]
        assert await quic_probe("127.0.0.1", port, timeout=3) is True
    finally:
        transport.close()


async def test_the_tcp_listener_answers_http_with_503_and_closes_the_rest() -> None:
    server = await asyncio.start_server(_tcp_handler(0), "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        assert (await asyncio.wait_for(reader.read(), timeout=3)).startswith(b"HTTP/1.1 503 ")
        writer.close()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x16\x03\x01\x00\x05hello")  # not HTTP: read, then closed
        await writer.drain()
        assert await asyncio.wait_for(reader.read(), timeout=3) == b""
        writer.close()
    finally:
        server.close()
        await server.wait_closed()


def test_every_port_env_example_defaults_to_is_occupied() -> None:
    """.env.example is what a deploy host is set up from: each service port it names
    (``*_PORT=<n>``, ``*_LISTEN=127.0.0.1:<n>``) is held in the host-like job."""
    named: dict[str, int] = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+_(?:PORT|LISTEN))=(?:127\.0\.0\.1:)?(\d+)", line.strip())
        if match and int(match.group(2)) > 0:
            named[match.group(1)] = int(match.group(2))
    assert named, "no ports found in .env.example"
    assert named.pop("HYSTERIA2_PORT") in UDP_PORTS
    missing = {name: port for name, port in named.items() if port not in TCP_PORTS}
    assert not missing, f"add these to tests/host_like_ports.py TCP_PORTS: {missing}"
