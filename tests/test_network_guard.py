"""The suite-wide network guard (tests/conftest.py::_forbid_network).

deploy.sh Phase 1 runs the suite on the production host, so a test that reaches
a real address talks to the live services (the relay health test sent QUIC to the
production relay). The guard records and refuses every such access and fails the
test on teardown. What is pinned here:

* it is active in every test;
* connect / connect_ex / sendto / sendmsg to a non-loopback address and any DNS
  lookup but ``localhost`` are recorded and refused — before a packet leaves;
* a probe that SWALLOWS the refusal (quic_probe, tls_probe never raise) is still
  caught: the record, not the exception, is what fails the test;
* loopback, the unspecified address and AF_UNIX are left alone;
* end to end, a test that swallows the error fails at teardown, naming the
  address, the port and the test in the stack.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import socket
import subprocess
import sys
import textwrap
from collections.abc import Generator
from pathlib import Path

import pytest
from conftest import NetworkGuard

from services.relay_health import quic_probe, tls_probe

CONFTEST = Path(__file__).with_name("conftest.py")


@pytest.fixture
def guard() -> Generator[NetworkGuard, None, None]:
    """A guard inside the suite's own: it refuses first, so the outer one (and the
    test) never sees the deliberate violations below."""
    inner = NetworkGuard()
    inner.install()
    try:
        yield inner
    finally:
        inner.uninstall()


def _targets(guard: NetworkGuard) -> list[tuple[str, str, object]]:
    return [(v.call, v.target, v.port) for v in guard.violations]


def test_the_guard_is_active_in_every_test() -> None:
    for wrapped in (
        socket.getaddrinfo,
        socket.socket.connect,
        socket.socket.sendto,
        asyncio.base_events.BaseEventLoop.getaddrinfo,
    ):
        assert "NetworkGuard.install" in wrapped.__qualname__, wrapped


def test_tcp_connect_outside_loopback_is_recorded_and_refused(guard: NetworkGuard) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError) as raised:
            sock.connect(("192.0.2.1", 9))
        assert raised.value.errno == errno.ENETUNREACH
        assert sock.connect_ex(("198.51.100.1", 443)) == errno.ENETUNREACH
    assert _targets(guard) == [("connect", "192.0.2.1", 9), ("connect_ex", "198.51.100.1", 443)]
    assert "test_tcp_connect_outside_loopback_is_recorded_and_refused" in guard.violations[0].stack


def test_a_name_in_connect_is_a_lookup_too(guard: NetworkGuard) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, pytest.raises(OSError):
        sock.connect(("relay.example.net", 443))
    assert _targets(guard) == [("connect", "relay.example.net", 443)]


def test_datagrams_outside_loopback_are_recorded_and_refused(guard: NetworkGuard) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        with pytest.raises(OSError):
            sock.sendto(b"x", ("203.0.113.9", 443))
        with pytest.raises(OSError):
            sock.sendto(b"x", 0, ("203.0.113.9", 444))
        with pytest.raises(OSError):
            sock.sendmsg([b"x"], [], 0, ("203.0.113.9", 445))
    assert _targets(guard) == [
        ("sendto", "203.0.113.9", 443),
        ("sendto", "203.0.113.9", 444),
        ("sendmsg", "203.0.113.9", 445),
    ]


def test_ipv6_outside_loopback_is_recorded_and_loopback_is_not(guard: NetworkGuard) -> None:
    try:
        sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError as exc:  # a host with IPv6 disabled
        pytest.skip(f"no IPv6 here: {exc}")
    with sock6:
        with pytest.raises(OSError):
            sock6.sendto(b"x", ("2001:db8::1", 443))
        with pytest.raises(OSError):
            sock6.sendto(b"x", ("::ffff:192.0.2.1", 443))
        with contextlib.suppress(OSError):  # ::1 may be unbound; it is not a violation
            sock6.sendto(b"x", ("::1", 9))
    assert _targets(guard) == [("sendto", "2001:db8::1", 443), ("sendto", "::ffff:192.0.2.1", 443)]


def test_dns_lookups_are_recorded_and_refused(guard: NetworkGuard) -> None:
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo("relay.example.net", 443)
    with pytest.raises(socket.gaierror):
        socket.getaddrinfo(b"hy2.example.net", None)
    with pytest.raises(socket.gaierror):
        socket.gethostbyname("vpn.example.net")
    with pytest.raises(socket.gaierror):
        socket.gethostbyname_ex("vpn.example.net")
    assert _targets(guard) == [
        ("getaddrinfo", "relay.example.net", 443),
        ("getaddrinfo", "hy2.example.net", None),
        ("gethostbyname", "vpn.example.net", None),
        ("gethostbyname_ex", "vpn.example.net", None),
    ]


async def test_a_probe_that_swallows_the_refusal_is_still_caught(guard: NetworkGuard) -> None:
    """The incident's shape: the probes never raise, so a refused access only shows
    up as a different verdict — the record is what makes the test fail."""
    assert await quic_probe("198.51.100.1", 443, timeout=0.3) is False
    assert await tls_probe("relay.example.net", 443, "example.com", timeout=1) is False
    assert _targets(guard) == [("connect", "198.51.100.1", 443), ("getaddrinfo", "relay.example.net", 443)]
    # asyncio resolves in a worker thread; the lookup is refused in the task, so
    # the report names the probe and the test, not the executor's frames.
    lookup = guard.violations[1]
    assert lookup.thread == "MainThread"
    assert "in tls_probe" in lookup.stack and "in test_a_probe_that_swallows_the_refusal_is_still_caught" in lookup.stack


async def test_loopback_unspecified_and_unix_are_left_alone(guard: NetworkGuard) -> None:
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
        with socket.create_connection(("localhost", port), timeout=2):
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.sendto(b"x", ("127.0.0.1", 9))
        udp.sendto(b"x", ("0.0.0.0", 9))  # noqa: S104 — Linux delivers it locally
    assert socket.getaddrinfo(None, 0, flags=socket.AI_PASSIVE)
    assert socket.getaddrinfo("192.0.2.1", 443)  # an IP literal: no DNS query
    left, right = socket.socketpair()
    left.close()
    right.close()
    assert guard.violations == []


def test_a_test_that_swallows_the_error_fails_on_teardown(tmp_path: Path) -> None:
    """End to end, in a child pytest wearing the suite's guard."""
    (tmp_path / "conftest.py").write_text(
        textwrap.dedent(
            f"""
            import importlib.util
            import sys

            _spec = importlib.util.spec_from_file_location("vpnbot_suite_conftest", {str(CONFTEST)!r})
            _suite = importlib.util.module_from_spec(_spec)
            sys.modules[_spec.name] = _suite
            _spec.loader.exec_module(_suite)
            _forbid_network = _suite._forbid_network
            """
        ),
        encoding="utf-8",
    )
    (tmp_path / "test_inner.py").write_text(
        textwrap.dedent(
            """
            import socket

            def test_swallows_the_error():
                try:
                    socket.create_connection(("192.0.2.1", 9), timeout=1)
                except OSError:
                    pass  # what quic_probe / tls_probe do

            def test_stays_on_loopback():
                with socket.create_server(("127.0.0.1", 0)) as server:
                    socket.create_connection(server.getsockname(), timeout=1).close()
            """
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(  # noqa: S603 — this interpreter, fixed arguments
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "2 passed, 1 error" in out, out
    assert "ERROR at teardown of test_swallows_the_error" in out, out
    assert "reached the network outside loopback" in out, out
    assert "connect('192.0.2.1', port=9)" in out, out
    assert "in test_swallows_the_error" in out, out
