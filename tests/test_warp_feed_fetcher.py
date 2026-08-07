"""HTTP behaviour of the WARP split-list feed fetcher.

Two properties are under test and they pull in opposite directions:

* **Cheap when nothing changed.** The feeds are refreshed on a timer, so a
  conditional GET must actually be conditional — validators sent, 304 accepted,
  cached body returned without a re-download.
* **Loud when anything is wrong.** Every failure mode — transport, non-200,
  oversized, undecodable, empty — must raise rather than return a short body,
  because the caller turns a returned body into the routed list. "Zero prefixes"
  and "the download broke" are indistinguishable downstream, so they are made
  distinguishable here.

The server is a loopback aiohttp app on an ephemeral port (the same pattern as
tests/test_hysteria2_stats.py); no test reaches the real internet.
"""
from __future__ import annotations

import stat
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from adapters.warp_feed_fetcher import FeedFetchError, WarpFeedFetcher

BODY = "91.108.4.0/22\n149.154.160.0/20\n"
ETAG = '"abc123"'
LAST_MODIFIED = "Wed, 06 Aug 2026 10:00:00 GMT"


class Recorder:
    """Captures the request headers each handler saw."""

    def __init__(self) -> None:
        self.headers: list[dict[str, str]] = []

    def note(self, request: web.Request) -> None:
        self.headers.append(dict(request.headers))

    @property
    def last(self) -> dict[str, str]:
        return self.headers[-1]


async def _serve(handler) -> TestServer:  # type: ignore[no-untyped-def]
    app = web.Application()
    app.router.add_route("GET", "/feed", handler)
    server = TestServer(app)
    await server.start_server()
    return server


def _fetcher(tmp_path: Path, **kwargs) -> WarpFeedFetcher:  # type: ignore[no-untyped-def]
    return WarpFeedFetcher(cache_dir=tmp_path / "feeds", timeout=5.0, **kwargs)


def _url(server: TestServer) -> str:
    return f"http://127.0.0.1:{server.port}/feed"


# ── conditional GET ───────────────────────────────────────────────────────────


async def test_first_fetch_sends_no_validators_and_caches_the_body(tmp_path: Path) -> None:
    recorder = Recorder()

    async def handler(request: web.Request) -> web.Response:
        recorder.note(request)
        return web.Response(text=BODY, headers={"ETag": ETAG, "Last-Modified": LAST_MODIFIED})

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        payload = await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()

    assert payload.status == "ok"
    assert payload.text == BODY
    assert payload.etag == ETAG
    assert payload.last_modified == LAST_MODIFIED
    # Nothing cached yet, so a 304 would have been unusable — ask for the full body.
    assert "If-None-Match" not in recorder.last
    assert "If-Modified-Since" not in recorder.last
    assert fetcher.read_cache("telegram") == BODY


async def test_validators_are_sent_once_a_cached_body_exists(tmp_path: Path) -> None:
    recorder = Recorder()

    async def handler(request: web.Request) -> web.Response:
        recorder.note(request)
        return web.Response(text=BODY, headers={"ETag": ETAG})

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        await fetcher.fetch(slug="telegram", url=_url(server))
        await fetcher.fetch(
            slug="telegram", url=_url(server), etag=ETAG, last_modified=LAST_MODIFIED
        )
    finally:
        await server.close()

    assert recorder.headers[1]["If-None-Match"] == ETAG
    assert recorder.headers[1]["If-Modified-Since"] == LAST_MODIFIED


async def test_validators_are_withheld_when_the_cache_file_is_gone(tmp_path: Path) -> None:
    """A stored ETag without a cached body must not be sent.

    The cache file can vanish (operator cleanup, a fresh box restored from a DB
    backup) while the source row still carries its validators. Sending them then
    invites a 304 we have nothing to answer with — so the fetcher asks for the
    whole document instead.
    """
    recorder = Recorder()

    async def handler(request: web.Request) -> web.Response:
        recorder.note(request)
        return web.Response(text=BODY)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        await fetcher.fetch(slug="telegram", url=_url(server))
        fetcher.cache_path("telegram").unlink()
        await fetcher.fetch(
            slug="telegram", url=_url(server), etag=ETAG, last_modified=LAST_MODIFIED
        )
    finally:
        await server.close()

    assert "If-None-Match" not in recorder.headers[1]
    assert "If-Modified-Since" not in recorder.headers[1]


async def test_304_returns_the_cached_body_and_keeps_the_validators(tmp_path: Path) -> None:
    state = {"first": True}

    async def handler(request: web.Request) -> web.Response:
        if state["first"]:
            state["first"] = False
            return web.Response(text=BODY, headers={"ETag": ETAG})
        return web.Response(status=304)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        await fetcher.fetch(slug="telegram", url=_url(server))
        payload = await fetcher.fetch(
            slug="telegram", url=_url(server), etag=ETAG, last_modified=LAST_MODIFIED
        )
    finally:
        await server.close()

    assert payload.status == "not-modified"
    assert payload.text == BODY
    # The validators survive the round trip, or the next request would be unconditional.
    assert payload.etag == ETAG
    assert payload.last_modified == LAST_MODIFIED


async def test_304_without_a_cached_body_is_an_error(tmp_path: Path) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=304)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        with pytest.raises(FeedFetchError, match="304"):
            await fetcher.fetch(slug="telegram", url=_url(server), etag=ETAG)
    finally:
        await server.close()


# ── failure modes ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("status", [404, 500, 503])
async def test_non_200_is_an_error(tmp_path: Path, status: int) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=status, text="upstream is having a day")

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        with pytest.raises(FeedFetchError, match=str(status)):
            await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()


@pytest.mark.parametrize("body", ["", "   \n\n  "])
async def test_empty_body_is_an_error_not_zero_prefixes(tmp_path: Path, body: str) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=body)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        with pytest.raises(FeedFetchError, match="empty"):
            await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()


async def test_oversized_body_is_rejected_from_content_length(tmp_path: Path) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"x" * 5000)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path, max_bytes=1000)
    try:
        with pytest.raises(FeedFetchError, match="declares"):
            await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()


async def test_oversized_chunked_body_is_rejected_while_streaming(tmp_path: Path) -> None:
    """No Content-Length to trust, so the cap has to hold on the stream itself."""

    async def handler(request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse()
        await response.prepare(request)  # chunked: no Content-Length
        for _ in range(5):
            await response.write(b"y" * 1000)
        await response.write_eof()
        return response

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path, max_bytes=1000)
    try:
        with pytest.raises(FeedFetchError, match="exceeded"):
            await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()


async def test_undecodable_body_is_an_error(tmp_path: Path) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(body=b"\xff\xfe\x00garbage", content_type="text/plain")

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        with pytest.raises(FeedFetchError, match="UTF-8"):
            await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()


async def test_transport_failure_is_an_error(tmp_path: Path) -> None:
    """Nothing is listening on port 1 — the closest offline stand-in for a dead feed."""
    fetcher = _fetcher(tmp_path)
    with pytest.raises(FeedFetchError, match="transport error"):
        await fetcher.fetch(slug="telegram", url="http://127.0.0.1:1/feed")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.org/x", "/etc/passwd"])
async def test_non_http_scheme_is_refused(tmp_path: Path, url: str) -> None:
    fetcher = _fetcher(tmp_path)
    with pytest.raises(FeedFetchError, match="scheme"):
        await fetcher.fetch(slug="telegram", url=url)


# ── cache ─────────────────────────────────────────────────────────────────────


async def test_a_failed_fetch_leaves_the_last_good_cache_intact(tmp_path: Path) -> None:
    """The whole point of the cache: yesterday's body outlives today's outage."""
    state = {"first": True}

    async def handler(request: web.Request) -> web.Response:
        if state["first"]:
            state["first"] = False
            return web.Response(text=BODY)
        return web.Response(status=500)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        await fetcher.fetch(slug="telegram", url=_url(server))
        with pytest.raises(FeedFetchError):
            await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()

    assert fetcher.read_cache("telegram") == BODY


async def test_cache_file_is_private_and_the_directory_too(tmp_path: Path) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=BODY)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()

    cache_file = fetcher.cache_path("telegram")
    assert stat.S_IMODE(cache_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(cache_file.parent.stat().st_mode) == 0o700


async def test_cache_write_is_atomic_leaving_no_temp_files(tmp_path: Path) -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text=BODY)

    server = await _serve(handler)
    fetcher = _fetcher(tmp_path)
    try:
        await fetcher.fetch(slug="telegram", url=_url(server))
        await fetcher.fetch(slug="telegram", url=_url(server))
    finally:
        await server.close()

    assert sorted(p.name for p in (tmp_path / "feeds").iterdir()) == ["telegram.raw"]


def test_read_cache_returns_none_when_absent(tmp_path: Path) -> None:
    assert _fetcher(tmp_path).read_cache("telegram") is None


@pytest.mark.parametrize("slug", ["../../etc/passwd", "a/b", "a\\b", "", ".", ".."])
def test_cache_path_refuses_to_escape_the_cache_directory(tmp_path: Path, slug: str) -> None:
    """Second lock on the door validate_slug already guards — this value becomes a path."""
    with pytest.raises(FeedFetchError, match="cache file name"):
        _fetcher(tmp_path).cache_path(slug)


def test_read_cache_swallows_a_bad_slug_instead_of_raising(tmp_path: Path) -> None:
    """read_cache is called on the failure path; it must never raise there."""
    assert _fetcher(tmp_path).read_cache("../escape") is None
