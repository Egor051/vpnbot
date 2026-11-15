#!/usr/bin/env python3
"""Occupy, on loopback, the ports the production host has in use.

The CI half of the host-leak guard (the ``tests-host-like`` job). deploy.sh Phase 1
runs the suite on the box, where hysteria-server answers QUIC on 443/udp and xray,
hy2_auth, the subscription endpoint, the stats APIs and sshd hold their TCP ports.
On a CI runner every one of them is free — so a test that passes only because
"nobody answers on 127.0.0.1:<port>" is green in CI and red on the box. That is
how ``test_built_monitor_alerts_every_admin_once_per_transition`` broke a deploy:
the real UDP relay probe's control step (QUIC to 127.0.0.1:HYSTERIA2_PORT) got no
answer in CI and the live hysteria-server's answer on the box.

Run as root (443 is privileged) before pytest; it never exits on its own:

* UDP 443 — answers a QUIC long-header datagram of >= 1200 bytes with a Version
  Negotiation packet exactly as quic-go does (RFC 9000 §6, §17.2.1), so
  services.relay_health.quic_probe("127.0.0.1", 443) succeeds here as on the box;
  echoes any other datagram;
* every TCP port below — accepts, answers an HTTP request with ``503``, closes
  anything else after reading it (or after 5 s of silence).

Bound on 127.0.0.1 and, where the runner has it, ::1. Each connection and
datagram is logged (port, peer, size), so a failing test can be matched to what it
reached. With ``--ready-file`` the bound sockets are written there once ALL of
them are up; any bind failure exits non-zero.

The port list follows .env.example and the deploy/ units (tests/test_network_guard.py
checks .env.example's defaults are all here).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import os
import socket
import sys
import time
from collections.abc import Awaitable, Callable
from pathlib import Path

# port -> who holds it on the production host
UDP_PORTS: dict[int, str] = {
    443: "hysteria-server (HYSTERIA2_PORT)",
}
TCP_PORTS: dict[int, str] = {
    443: "xray VLESS+REALITY (XRAY_PUBLIC_PORT)",
    2096: "subscription endpoint, public HTTPS (SUBSCRIPTION_PUBLIC_PORT)",
    8443: "xray XHTTP (XRAY_XHTTP_PORT) / MTProxy (MTPROTO_PORT)",
    8444: "hy2_auth (HYSTERIA2_AUTH_LISTEN)",
    8445: "subscription endpoint, loopback (SUBSCRIPTION_BIND_PORT)",
    8888: "MTProxy internal stats (MTPROTO_INTERNAL_STATS_PORT)",
    9999: "hysteria Traffic Stats API (HYSTERIA2_STATS_LISTEN)",
    10085: "xray gRPC stats/API (XRAY_STATS_SERVER)",
    31337: "danted SOCKS5 (SOCKS5_PORT)",
    54321: "sshd (SSH_PORT)",
}
HOSTS: tuple[str, ...] = ("127.0.0.1", "::1")

QUIC_MIN_DATAGRAM = 1200
HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH")
HTTP_503 = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def version_negotiation(data: bytes) -> bytes | None:
    """quic-go's answer to a long-header packet of an unknown version: version 0,
    the client's connection IDs swapped, then one supported version. None when
    *data* is not such a packet (short header, a VN itself, truncated, < 1200 B)."""
    if len(data) < QUIC_MIN_DATAGRAM or not data[0] & 0x80 or data[1:5] == b"\x00\x00\x00\x00":
        return None
    dcid_len = data[5]
    dcid = data[6 : 6 + dcid_len]
    pos = 6 + dcid_len
    if dcid_len > 20 or pos >= len(data) or data[pos] > 20:
        return None
    scid = data[pos + 1 : pos + 1 + data[pos]]
    first = 0x80 | (os.urandom(1)[0] & 0x7F)
    return bytes([first]) + b"\x00\x00\x00\x00" + bytes([len(scid)]) + scid + bytes([len(dcid)]) + dcid + b"\x00\x00\x00\x01"


def _log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", flush=True)


class _QuicLike(asyncio.DatagramProtocol):
    def __init__(self, port: int) -> None:
        self._port = port
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str | object, int]) -> None:
        reply = version_negotiation(data)
        _log(f"udp:{self._port} <- {addr} {len(data)}B -> {'QUIC version negotiation' if reply else 'echo'}")
        if self._transport is not None:
            self._transport.sendto(reply if reply is not None else data, addr)


def _tcp_handler(port: int) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=5)
            is_http = data.split(b" ", 1)[0] in HTTP_METHODS
            _log(f"tcp:{port} <- {peer} {len(data)}B{' HTTP -> 503' if is_http else ''}")
            if is_http:
                writer.write(HTTP_503)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError) as exc:
            _log(f"tcp:{port} <- {peer} {type(exc).__name__}")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    return handle


def _ipv6_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


async def serve(ready_file: Path | None) -> None:
    loop = asyncio.get_running_loop()
    hosts = HOSTS if _ipv6_available() else HOSTS[:1]
    bound: list[str] = []
    servers: list[asyncio.Server] = []
    for host in hosts:
        for port in UDP_PORTS:
            await loop.create_datagram_endpoint(functools.partial(_QuicLike, port), local_addr=(host, port))
            bound.append(f"udp {host} {port} {UDP_PORTS[port]}")
        for port in TCP_PORTS:
            servers.append(await asyncio.start_server(_tcp_handler(port), host, port))
            bound.append(f"tcp {host} {port} {TCP_PORTS[port]}")
    for line in bound:
        _log(f"listening: {line}")
    if ready_file is not None:
        ready_file.write_text("\n".join(bound) + "\n", encoding="utf-8")
    await asyncio.Event().wait()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--ready-file", type=Path, help="written with the bound sockets once all are up")
    args = parser.parse_args(argv)
    try:
        asyncio.run(serve(args.ready_file))
    except OSError as exc:
        print(f"host_like_ports: cannot bind: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
