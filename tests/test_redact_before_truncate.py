"""Redact first, cut second — for every free-text error that is later shortened.

A secret cut in half no longer matches any redaction pattern (a 32-hex MTProto
secret becomes 19 hex digits, a 44-char WireGuard key 30 characters, a
``user:pass@`` URL loses its ``@``), so wherever a message is truncated the whole
message has to be redacted BEFORE the cut. ShellRunner has its own suite
(tests/test_shell_runner.py); this module covers the other two places that cut
untrusted error text: feed-fetch errors and the anomaly auto-revoke failure.

Every case puts the secret straddling the actual cut point used in production
and asserts that not a single fragment of it survives the cut.
"""

from __future__ import annotations

import asyncio
import time as time_module
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest
from test_anomaly_bundle_rollup import _FakeBundleRepo, _key, _sent, _service

import adapters.warp_feed_fetcher as fetcher_module
from adapters.warp_feed_fetcher import FeedFetchError, WarpFeedFetcher
from models.enums import VpnKeyType

HEX_SECRET = "0123456789abcdef0123456789abcdef"
WG_KEY = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
URL_PASSWORD = "Pa55w0rdQQ"


def _fragments(secret: str, *, minimum: int = 4) -> list[str]:
    return [secret[i:j] for i in range(len(secret)) for j in range(i + minimum, len(secret) + 1)]


def _straddling(prefix_len: int, cut: int, secret: str, inside: int) -> str:
    """Text whose `secret` starts `inside` characters before `cut`."""
    return "e" * (cut - inside - prefix_len) + " " + secret + " trailing context"


# ── feed fetch errors ────────────────────────────────────────────────────────


# Invariant: a FeedFetchError never carries a credential, so none of the
# downstream cuts (512 on the row, 200 in the journal/alert, 160 in the panel)
# can leave a fragment of one — whatever the offset of the credential.
@pytest.mark.parametrize("cut", [160, 200, 512])
@pytest.mark.parametrize(
    "secret",
    [f"https://admin:{URL_PASSWORD}@feeds.example/list.txt", f"token={URL_PASSWORD}", HEX_SECRET, WG_KEY],
)
def test_feed_error_is_redacted_before_any_cut(cut: int, secret: str) -> None:
    # Arrange
    sensitive = URL_PASSWORD if URL_PASSWORD in secret else secret
    messages = [_straddling(0, cut, secret, inside) for inside in (1, len(secret) // 2, len(secret) - 1)]

    # Act
    cut_texts = [str(FeedFetchError(message))[:cut] for message in messages]

    # Assert
    for text in cut_texts:
        assert not [f for f in _fragments(sensitive) if f in text], text


# Invariant: the transport-error path of a real fetch (the one that quotes the
# URL) produces a redacted message end to end.
async def test_fetch_transport_error_does_not_quote_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Arrange
    url = f"https://admin:{URL_PASSWORD}@feeds.example/list.txt"

    class _ExplodingSession:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> _ExplodingSession:
            raise aiohttp.InvalidURL(url)

        async def __aexit__(self, *args: Any) -> None:
            return None

    monkeypatch.setattr(fetcher_module.aiohttp, "ClientSession", _ExplodingSession)
    fetcher = WarpFeedFetcher(cache_dir=tmp_path)

    # Act
    with pytest.raises(FeedFetchError) as excinfo:
        await fetcher.fetch(slug="custom", url=url)

    # Assert
    message = str(excinfo.value)
    assert message.startswith("transport error:")
    assert not [f for f in _fragments(URL_PASSWORD) if f in message], message


# Invariant: a URL with credentials and a non-http scheme is refused without
# echoing the credentials.
async def test_unsupported_scheme_error_does_not_quote_credentials(tmp_path: Path) -> None:
    # Arrange
    fetcher = WarpFeedFetcher(cache_dir=tmp_path)

    # Act
    with pytest.raises(FeedFetchError) as excinfo:
        await fetcher.fetch(slug="custom", url=f"ftp://admin:{URL_PASSWORD}@feeds.example/list")

    # Assert
    assert "unsupported URL scheme" in str(excinfo.value)
    assert URL_PASSWORD not in str(excinfo.value)


# Invariant: a message with nothing secret in it is kept as-is (redaction is
# not a blanket rewrite of the error).
def test_feed_error_without_secrets_is_unchanged() -> None:
    # Arrange
    message = "HTTP 503"

    # Act
    text = str(FeedFetchError(message))

    # Assert
    assert text == message


# ── anomaly auto-revoke failure ──────────────────────────────────────────────


# Invariant: the auto-revoke failure that an anomaly alert quotes (cut to 120
# characters) never carries a fragment of a secret from the backend's
# exception, wherever the secret sits relative to the cut.
@pytest.mark.parametrize("secret", [HEX_SECRET, WG_KEY])
@pytest.mark.parametrize("inside", [1, 8, 16, 31])
def test_auto_revoke_error_in_alert_is_redacted_before_cut(secret: str, inside: int) -> None:
    # Arrange
    child = _key(13, key_type=VpnKeyType.HYSTERIA2, email_label="hy2_solo")
    vpn_keys = AsyncMock()
    vpn_keys.list_by_type_statuses.side_effect = [[child], []]
    stats = AsyncMock()
    stats.query_online.return_value = {"hy2_solo": 9}
    hysteria_service = AsyncMock()
    hysteria_service.revoke_hysteria2_key_system.side_effect = RuntimeError(
        _straddling(0, 120, secret, min(inside, len(secret) - 1))
    )
    svc = _service(
        [child],
        _FakeBundleRepo(by_key={}, children={}),
        vpn_keys=vpn_keys,
        hysteria_stats=stats,
        hysteria_service=hysteria_service,
        hysteria2_max_conn=5,
        cooldown_seconds=0,
        auto_revoke=True,
    )

    # Act
    asyncio.run(svc._check_hysteria_online(time_module.time()))

    # Assert
    (text,) = _sent(svc)
    assert "Авто-отзыв не удался" in text
    assert not [f for f in _fragments(secret) if f in text], text
