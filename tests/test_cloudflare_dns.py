"""adapters/cloudflare_dns.py — the DNS API, DoH and the token file of the fallback mode.

Nothing here leaves the process: every Cloudflare / DoH call goes through a fake
transport, and the real aiohttp transport is driven against a local server.
"""

from __future__ import annotations

import logging
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from adapters.cloudflare_dns import (
    FAILOVER_TTL,
    CloudflareDns,
    CloudflareTokenFile,
    DnsApiError,
    DnsTokenMissing,
    HttpReply,
    aiohttp_transport,
    doh_resolve_a,
    fingerprint,
    valid_token,
    zone_candidates,
)
from services.audit import AuditService
from utils.redact import forget_secret, redact, redact_text

TOKEN = "cfTOKEN_0123456789abcdefghijklmnopqrstuv"  # 40 chars, the API token shape


class FakeTransport:
    """Records every request; answers from a script keyed by (method, path)."""

    def __init__(self, answers: Mapping[tuple[str, str], object] | None = None) -> None:
        self.answers: dict[tuple[str, str], object] = dict(answers or {})
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, object] | None = None,
        timeout: float,
    ) -> HttpReply:
        path = url.split("/client/v4", 1)[-1]
        self.calls.append({"method": method, "path": path, "headers": dict(headers), "params": dict(params or {}),
                           "json": None if json_body is None else dict(json_body), "url": url})
        answer = self.answers.get((method, path))
        if callable(answer):
            answer = answer(params or {})
        if isinstance(answer, HttpReply):
            return answer
        if isinstance(answer, Exception):
            raise answer
        return HttpReply(200, {"success": True, "errors": [], "result": answer})


def _record(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "id": "rec1", "type": "A", "name": "example.net", "content": "150.251.152.243", "proxied": False, "ttl": 300,
    }
    data.update(overrides)
    return data


# ── the API ───────────────────────────────────────────────────────────────────


async def test_every_call_carries_the_token_only_in_the_authorization_header() -> None:
    transport = FakeTransport({("GET", "/user/tokens/verify"): {"id": "x", "status": "active"}})
    api = CloudflareDns(lambda: TOKEN, transport=transport)
    assert await api.verify_token() == "active"
    call = transport.calls[0]
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert TOKEN not in call["url"] and not call["params"] and call["json"] is None


def test_zone_candidates_walk_up_to_two_labels() -> None:
    assert zone_candidates("a.b.Example.net.") == ["a.b.example.net", "b.example.net", "example.net"]
    assert zone_candidates("example.net") == ["example.net"]


async def test_find_zone_walks_up_the_labels() -> None:
    def zones(params: Mapping[str, str]) -> list[dict[str, str]]:
        return [{"id": "z1", "name": "example.net"}] if params["name"] == "example.net" else []

    transport = FakeTransport({("GET", "/zones"): zones})
    zone = await CloudflareDns(lambda: TOKEN, transport=transport).find_zone("relay.example.net")
    assert (zone.id, zone.name) == ("z1", "example.net")
    assert [c["params"]["name"] for c in transport.calls] == ["relay.example.net", "example.net"]


async def test_find_zone_says_when_the_token_sees_none() -> None:
    transport = FakeTransport({("GET", "/zones"): []})
    with pytest.raises(DnsApiError, match="no zone"):
        await CloudflareDns(lambda: TOKEN, transport=transport).find_zone("example.org")


async def test_records_keep_only_the_exact_name_and_type() -> None:
    transport = FakeTransport({
        ("GET", "/zones/z1/dns_records"): [
            _record(), _record(id="rec2", name="other.example.net"), _record(id="rec3", type="AAAA", content="::1"),
        ],
    })
    records = await CloudflareDns(lambda: TOKEN, transport=transport).records("z1", "Example.NET")
    assert [r.id for r in records] == ["rec1"]
    assert transport.calls[0]["params"] == {"type": "A", "name": "example.net", "per_page": "100"}


async def test_writes_are_never_proxied_and_have_ttl_60() -> None:
    transport = FakeTransport({
        ("POST", "/zones/z1/dns_records"): _record(id="new", content="203.0.113.9", ttl=60),
        ("PATCH", "/zones/z1/dns_records/rec1"): _record(content="203.0.113.9", ttl=60),
    })
    api = CloudflareDns(lambda: TOKEN, transport=transport)
    created = await api.create_a("z1", "origin.example.net", "203.0.113.9")
    updated = await api.update_a("z1", "rec1", "203.0.113.9")
    assert created.id == "new" and updated.content == "203.0.113.9"
    assert transport.calls[0]["json"] == {
        "type": "A", "name": "origin.example.net", "content": "203.0.113.9", "ttl": FAILOVER_TTL, "proxied": False,
    }
    assert transport.calls[1]["json"] == {"content": "203.0.113.9", "ttl": FAILOVER_TTL, "proxied": False}
    with pytest.raises(DnsApiError, match="not an IPv4"):
        await api.update_a("z1", "rec1", "example.net")
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    "reply",
    [
        HttpReply(403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}),
        HttpReply(200, {"success": False, "errors": []}),
        HttpReply(502, None),
    ],
)
async def test_an_api_refusal_is_one_error_with_the_reason(reply: HttpReply) -> None:
    transport = FakeTransport({("GET", "/user/tokens/verify"): reply})
    with pytest.raises(DnsApiError) as info:
        await CloudflareDns(lambda: TOKEN, transport=transport).verify_token()
    assert f"HTTP {reply.status}" in str(info.value)
    assert TOKEN not in str(info.value)
    if reply.status == 403:
        assert "10000: Authentication error" in str(info.value)


async def test_a_malformed_record_is_an_api_error() -> None:
    transport = FakeTransport({("GET", "/zones/z1/dns_records"): [{"id": "x"}]})
    with pytest.raises(DnsApiError, match="malformed"):
        await CloudflareDns(lambda: TOKEN, transport=transport).records("z1", "example.net")
    transport = FakeTransport({("GET", "/zones/z1/dns_records"): {"not": "a list"}})
    with pytest.raises(DnsApiError, match="not a list"):
        await CloudflareDns(lambda: TOKEN, transport=transport).records("z1", "example.net")


async def test_with_token_checks_another_token_on_the_same_transport() -> None:
    transport = FakeTransport({("GET", "/user/tokens/verify"): {"status": "active"}})
    api = CloudflareDns(lambda: "unused-token-000000000000", transport=transport)
    assert await api.with_token(TOKEN).verify_token() == "active"
    assert transport.calls[0]["headers"]["Authorization"] == f"Bearer {TOKEN}"


# ── DoH ───────────────────────────────────────────────────────────────────────


async def test_doh_asks_every_resolver_and_reads_only_a_records() -> None:
    calls: list[tuple[str, dict[str, str], dict[str, str]]] = []

    async def transport(method: str, url: str, *, headers: Mapping[str, str], params: Mapping[str, str] | None = None,
                        json_body: Mapping[str, object] | None = None, timeout: float) -> HttpReply:
        calls.append((url, dict(headers), dict(params or {})))
        if "cloudflare" in url:
            return HttpReply(200, {"Status": 0, "Answer": [
                {"name": "example.net", "type": 5, "TTL": 60, "data": "alias.example.net."},
                {"name": "example.net", "type": 1, "TTL": 60, "data": "203.0.113.9"},
                {"name": "example.net", "type": 1, "TTL": 30, "data": "203.0.113.9"},
            ]})
        return HttpReply(200, {"Status": 3})

    answers = await doh_resolve_a("example.net", transport=transport)
    assert [(a.resolver, a.addresses, a.ttl, a.error) for a in answers] == [
        ("cloudflare", ("203.0.113.9",), 60, None),
        ("google", (), None, "NXDOMAIN"),
    ]
    assert all(h["Accept"] == "application/dns-json" and p == {"name": "example.net", "type": "A"} for _, h, p in calls)
    assert {url for url, _, _ in calls} == {"https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"}


async def test_doh_reports_a_resolver_it_could_not_ask() -> None:
    async def transport(method: str, url: str, **_: object) -> HttpReply:
        if "google" in url:
            raise DnsApiError("GET https://dns.google/resolve: ClientConnectorError")
        return HttpReply(500, None)

    answers = await doh_resolve_a("example.net", transport=transport)  # type: ignore[arg-type]
    assert [(a.resolver, a.error) for a in answers] == [
        ("cloudflare", "HTTP 500"), ("google", "GET https://dns.google/resolve: ClientConnectorError"),
    ]
    rcode = await doh_resolve_a(
        "example.net", transport=lambda *a, **k: _reply(HttpReply(200, {"Status": 2})),  # type: ignore[arg-type]
        resolvers=(("x", "https://x.example/dns"),),
    )
    assert rcode[0].error == "rcode 2"


async def _reply(reply: HttpReply) -> HttpReply:
    return reply


# ── the real transport, against a local server ────────────────────────────────


async def test_aiohttp_transport_sends_json_and_parses_the_answer() -> None:
    seen: dict[str, Any] = {}

    async def handler(request: web.Request) -> web.Response:
        seen["auth"] = request.headers.get("Authorization")
        seen["query"] = dict(request.query)
        seen["json"] = await request.json() if request.can_read_body else None
        return web.json_response({"success": True, "result": {"ok": 1}})

    async def not_json(request: web.Request) -> web.Response:
        return web.Response(text="<html>")

    async def redirect(request: web.Request) -> web.Response:
        raise web.HTTPFound("http://192.0.2.1/elsewhere")

    async def huge(request: web.Request) -> web.Response:
        return web.Response(body=b"x" * (1024 * 1024 + 10))

    app = web.Application()
    app.router.add_route("*", "/api", handler)
    app.router.add_get("/html", not_json)
    app.router.add_get("/redirect", redirect)
    app.router.add_get("/huge", huge)
    server = TestServer(app, host="127.0.0.1")
    await server.start_server()
    port = server.port
    try:
        base = f"http://127.0.0.1:{server.port}"
        reply = await aiohttp_transport(
            "PATCH", f"{base}/api", headers={"Authorization": "Bearer x"}, params={"a": "1"},
            json_body={"content": "203.0.113.9"}, timeout=5,
        )
        assert (reply.status, reply.body) == (200, {"success": True, "result": {"ok": 1}})
        assert seen == {"auth": "Bearer x", "query": {"a": "1"}, "json": {"content": "203.0.113.9"}}
        assert (await aiohttp_transport("GET", f"{base}/html", headers={}, timeout=5)).body is None
        # Redirects are not followed: the answer is the 302 itself.
        assert (await aiohttp_transport("GET", f"{base}/redirect", headers={}, timeout=5)).status == 302
        with pytest.raises(DnsApiError, match="too large"):
            await aiohttp_transport("GET", f"{base}/huge", headers={}, timeout=5)
    finally:
        await server.close()
    with pytest.raises(DnsApiError, match="ClientConnectorError|ClientOSError|OSError"):
        await aiohttp_transport("GET", f"http://127.0.0.1:{port}/api", headers={}, timeout=2)


# ── the token file ────────────────────────────────────────────────────────────


def test_token_shape() -> None:
    assert valid_token(TOKEN)
    assert not valid_token("short")
    assert not valid_token("has space in it 0123456789")
    assert not valid_token("x" * 201)


def test_token_file_is_private_atomic_and_redacted(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    store = CloudflareTokenFile(tmp_path / "dns_failover" / "cloudflare_token")
    assert not store.exists()
    with pytest.raises(DnsTokenMissing):
        store.load()
    store.save(TOKEN)
    try:
        st = os.stat(store.path)
        assert stat.S_IMODE(st.st_mode) == 0o600
        assert stat.S_IMODE(os.stat(store.path.parent).st_mode) == 0o700
        assert store.load() == TOKEN
        assert not list(store.path.parent.glob(".*.tmp"))
        # Registered: every redaction masks it by value from now on.
        assert TOKEN not in redact(f"token is {TOKEN} ok")
        assert TOKEN not in redact_text(f"Authorization: X {TOKEN}")
        with caplog.at_level(logging.INFO):
            logging.getLogger("vpnbot.test").info("leaked %s", TOKEN)
        assert TOKEN not in AuditService._sanitize(AuditService.__new__(AuditService), {"note": f"x {TOKEN}"})["note"]
        store.save("another_TOKEN_0123456789abcdefghijklmnop")
        assert store.load() == "another_TOKEN_0123456789abcdefghijklmnop"
        assert store.delete() is True
        assert store.delete() is False
        assert not store.exists()
    finally:
        forget_secret(TOKEN)
        forget_secret("another_TOKEN_0123456789abcdefghijklmnop")
    with pytest.raises(ValueError):
        store.save("not a token")


def test_token_file_refuses_a_symlink_a_shared_file_and_garbage(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text(TOKEN + "\n")
    os.chmod(real, 0o600)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(DnsTokenMissing):
        CloudflareTokenFile(link).load()
    os.chmod(real, 0o644)
    with pytest.raises(DnsTokenMissing, match="not private"):
        CloudflareTokenFile(real).load()
    os.chmod(real, 0o600)
    real.write_text("not a token at all\n")
    with pytest.raises(DnsTokenMissing, match="damaged"):
        CloudflareTokenFile(real).load()
    directory = tmp_path / "dir"
    directory.mkdir()
    with pytest.raises(DnsTokenMissing):
        CloudflareTokenFile(directory).load()


def test_token_file_that_cannot_be_written_says_so(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(DnsTokenMissing, match="cannot be written"):
        CloudflareTokenFile(blocker / "sub" / "cloudflare_token").save(TOKEN)
    forget_secret(TOKEN)


def test_fingerprint_is_short_and_not_the_token() -> None:
    assert len(fingerprint(TOKEN)) == 8 and fingerprint(TOKEN) not in TOKEN
