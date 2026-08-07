"""HTTP fetcher for WARP selective-split prefix feeds.

Conditional GET plus a disk cache, because the two together are what make a feed
failure harmless: if the upstream is down, malformed, truncated or simply empty,
this adapter hands back the last body that parsed, and the caller recomputes the
exact same list it already had. Nothing about a bad fetch is allowed to shorten
the routed list.

Both validator styles are implemented because the real feeds disagree (measured
2026-08-06): ``core.telegram.org/resources/cidr.txt`` serves an ``ETag`` *and* a
``Last-Modified``, while ``gstatic.com/ipranges/*.json`` serves ``Last-Modified``
only. Sending whichever we hold, and accepting a 304 from either, is what keeps
the Google feeds from re-downloading 112 KB every six hours.
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import aiohttp

logger = logging.getLogger(__name__)

# Only these schemes may be fetched. An admin types the URL for a custom source,
# so the check is here rather than only in the UI.
_ALLOWED_SCHEMES = ("http://", "https://")

# A redirect chain longer than this is a misconfigured or hostile endpoint.
_MAX_REDIRECTS = 5


class FeedFetchError(RuntimeError):
    """The feed could not be retrieved. The caller falls back to the cache."""


@dataclass(frozen=True, slots=True)
class FeedPayload:
    """A feed body plus the validators to send next time.

    ``status`` is the short token stored on the source row and rendered in the
    panel:

      ``ok``            — a fresh body was downloaded and cached;
      ``not-modified``  — the server answered 304; the cached body is returned;
      ``cached``        — the fetch failed and the caller fell back (set by the
                          service, never by this adapter).
    """

    text: str
    etag: str | None
    last_modified: str | None
    status: str


class WarpFeedFetcher:
    """Downloads feed documents into ``cache_dir`` and reads them back."""

    def __init__(self, *, cache_dir: Path, timeout: float = 20.0, max_bytes: int = 2_000_000) -> None:
        self._cache_dir = cache_dir
        self._timeout = timeout
        self._max_bytes = max_bytes

    # ── cache ─────────────────────────────────────────────────────────────────

    def cache_path(self, slug: str) -> Path:
        """Path of *slug*'s cached body.

        *slug* is validated at source-creation time (``validate_slug``); the
        assertion here is a second lock on the same door, because this value is
        being joined onto a filesystem path.
        """
        if "/" in slug or "\\" in slug or slug in {"", ".", ".."}:
            raise FeedFetchError(f"refusing to use {slug!r} as a cache file name")
        return self._cache_dir / f"{slug}.raw"

    def read_cache(self, slug: str) -> str | None:
        """Return the last cached body for *slug*, or None if there is none."""
        try:
            return self.cache_path(slug).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, FeedFetchError):
            return None

    def _write_cache(self, slug: str, text: str) -> None:
        """Atomically replace the cached body, 0600, creating the dir at 0700.

        Best-effort: a cache write failure is logged but never fails the refresh,
        because the freshly downloaded body in memory is already good enough for
        this run. The next run just has one less fallback.
        """
        target = self.cache_path(slug)
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, tmp_name = tempfile.mkstemp(dir=str(self._cache_dir), prefix=f".{slug}.", suffix=".tmp")
            try:
                # mkstemp already creates the file 0600; fdopen takes ownership of
                # the descriptor, so the only cleanup left is the path itself.
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(text)
                os.replace(tmp_name, target)
            except BaseException:
                Path(tmp_name).unlink(missing_ok=True)
                raise
        except OSError:
            logger.warning("warp-split feed %s: cache write failed", slug, exc_info=True)

    # ── fetch ─────────────────────────────────────────────────────────────────

    async def fetch(
        self,
        *,
        slug: str,
        url: str,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FeedPayload:
        """GET *url*, conditionally when we already hold a cached body.

        Raises :class:`FeedFetchError` for every failure mode — transport,
        timeout, non-200/304 status, oversized body, undecodable bytes, or an
        empty body. An empty response is a failure on purpose: "zero prefixes"
        and "the download broke" look identical from here, and only one of them
        is safe to act on.
        """
        if not url.startswith(_ALLOWED_SCHEMES):
            raise FeedFetchError(f"unsupported URL scheme in {url!r} (http/https only)")

        cached = self.read_cache(slug)
        headers: dict[str, str] = {}
        # Validators are only worth sending when a 304 would leave us something to
        # return. Without a cached body a 304 is unusable, so ask for the full one.
        if cached is not None:
            if etag:
                headers["If-None-Match"] = etag
            if last_modified:
                headers["If-Modified-Since"] = last_modified

        timeout = aiohttp.ClientTimeout(total=self._timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url, headers=headers, allow_redirects=True, max_redirects=_MAX_REDIRECTS
                ) as response:
                    if response.status == 304:
                        if cached is None:
                            raise FeedFetchError("server answered 304 but no cached body exists")
                        return FeedPayload(
                            text=cached,
                            etag=etag,
                            last_modified=last_modified,
                            status="not-modified",
                        )
                    if response.status != 200:
                        raise FeedFetchError(f"HTTP {response.status}")
                    raw = await self._read_capped(response)
                    new_etag = response.headers.get("ETag")
                    new_last_modified = response.headers.get("Last-Modified")
        except FeedFetchError:
            raise
        except asyncio.TimeoutError as exc:
            raise FeedFetchError(f"timed out after {self._timeout:g}s") from exc
        except aiohttp.ClientError as exc:
            raise FeedFetchError(f"transport error: {exc}") from exc

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FeedFetchError(f"body is not valid UTF-8: {exc}") from exc
        if not text.strip():
            raise FeedFetchError("empty response body")

        self._write_cache(slug, text)
        return FeedPayload(
            text=text, etag=new_etag, last_modified=new_last_modified, status="ok"
        )

    async def _read_capped(self, response: aiohttp.ClientResponse) -> bytes:
        """Stream the body, aborting past ``max_bytes``.

        Streamed rather than ``await response.read()`` so a hostile or broken
        endpoint cannot make the bot buffer an unbounded body before the check
        happens. Content-Length is honoured first when present, so the usual case
        costs nothing.
        """
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                if int(declared) > self._max_bytes:
                    raise FeedFetchError(
                        f"response declares {declared} bytes, over the {self._max_bytes} limit"
                    )
            except ValueError:
                pass  # unparseable header — fall through to the streaming cap
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.content.iter_chunked(64 * 1024):
            total += len(chunk)
            if total > self._max_bytes:
                raise FeedFetchError(f"response exceeded the {self._max_bytes} byte limit")
            chunks.append(chunk)
        return b"".join(chunks)
