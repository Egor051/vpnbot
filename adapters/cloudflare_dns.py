"""DNS of the fallback mode: the Cloudflare API, DNS-over-HTTPS and the API token's file.

docs/relay.md «Режим фолбэка (hub)». Three small pieces, all behind one injectable
HTTP transport so the tests never leave the process:

* :class:`CloudflareDns` — the few Cloudflare API v4 calls the mode needs: verify
  the token, find the zone of a name (``GET /zones?name=`` walking up its labels —
  this works with a token that has nothing but «Zone · DNS · Edit» on that zone),
  read the A/AAAA records of a name, create / patch an A record. Every write sets
  ``proxied=false`` and ``ttl=60``: a proxied (orange) record would send the VPN to
  Cloudflare's HTTP proxy, and a long TTL would keep clients on the old address.
* :func:`doh_resolve_a` — what public resolvers answer for a name RIGHT NOW, asked
  over DNS-over-HTTPS (JSON API of cloudflare-dns.com and dns.google). Never the
  system resolver: the host's own cache (and its TTL) says nothing about clients.
* :class:`CloudflareTokenFile` — the token, one line in a 0600 file owned by the
  bot (the checks of the relay SSH key and the TOTP key: a regular file, no
  symlink, private to the bot's uid). It is entered in the admin panel only — no
  ``.env``, no CLI — and registered with :func:`utils.redact.register_secret`
  whenever it is read or written, so no log line or audit record can carry it.

The token never leaves this module except in the ``Authorization`` header.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import stat
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote

import aiohttp

from config import validators
from utils.redact import forget_secret, redact_value, register_secret

logger = logging.getLogger(__name__)

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
# The TTL of every record the bot writes: a switch reaches clients within a minute.
FAILOVER_TTL = 60
TOKEN_DIR = Path("/etc/vpn-bot/dns_failover")
TOKEN_FILE = TOKEN_DIR / "cloudflare_token"
# Cloudflare API tokens are 40 URL-safe characters today; leave room for a longer
# format, refuse anything that could not be one (a pasted sentence, a key file).
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]{20,200}")
_MAX_TOKEN_FILE_BYTES = 1024
_MAX_BODY_BYTES = 1024 * 1024
# The public resolvers asked over DoH (JSON API, RFC 8484's JSON flavour).
DOH_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
)
_DNS_TYPE_A = 1


class DnsApiError(RuntimeError):
    """The DNS API refused or failed a request. The message is redacted at
    construction (it may be cut further down the line, and a cut secret no longer
    matches any pattern)."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(redact_value(message))
        self.status = status


class DnsTokenMissing(DnsApiError):
    """No API token is stored (or it cannot be read)."""


# ── transport ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class HttpReply:
    status: int
    # The parsed JSON body; None when the body is not JSON.
    body: object


class HttpTransport(Protocol):
    async def __call__(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, object] | None = None,
        timeout: float,
    ) -> HttpReply: ...


async def aiohttp_transport(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str],
    params: Mapping[str, str] | None = None,
    json_body: Mapping[str, object] | None = None,
    timeout: float,
) -> HttpReply:
    """One HTTPS request with aiohttp (certificate verified, no redirects, bounded body)."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.request(
                method,
                url,
                headers=dict(headers),
                params=dict(params) if params else None,
                json=dict(json_body) if json_body is not None else None,
                allow_redirects=False,
            ) as response:
                status = response.status
                raw = b""
                while len(raw) <= _MAX_BODY_BYTES:
                    chunk = await response.content.read(64 * 1024)
                    if not chunk:
                        break
                    raw += chunk
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        raise DnsApiError(f"{method} {url.split('?', 1)[0]}: {type(exc).__name__}: {exc}") from None
    if len(raw) > _MAX_BODY_BYTES:
        raise DnsApiError(f"{method} {url.split('?', 1)[0]}: answer too large", status=status)
    try:
        body: object = json.loads(raw.decode("utf-8")) if raw else None
    except (UnicodeDecodeError, ValueError):
        body = None
    return HttpReply(status=status, body=body)


# ── Cloudflare API ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DnsZone:
    id: str
    name: str


@dataclass(frozen=True, slots=True)
class DnsRecord:
    id: str
    type: str
    name: str
    content: str
    proxied: bool
    ttl: int


def _record(data: object) -> DnsRecord:
    if not isinstance(data, dict):
        raise DnsApiError("DNS API: a record is not an object")
    try:
        return DnsRecord(
            id=str(data["id"]),
            type=str(data["type"]),
            name=str(data["name"]).lower(),
            content=str(data["content"]),
            proxied=bool(data.get("proxied", False)),
            ttl=int(data.get("ttl", 0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise DnsApiError(f"DNS API: a malformed record ({type(exc).__name__})") from None


def zone_candidates(name: str) -> list[str]:
    """``a.b.example.net`` → ``a.b.example.net``, ``b.example.net``, ``example.net``."""
    labels = name.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


class CloudflareDns:
    """The Cloudflare API v4 calls of the fallback mode. *token* is asked for on
    every call (the admin may replace it at any time)."""

    def __init__(
        self,
        token: Callable[[], str],
        *,
        transport: HttpTransport | None = None,
        base_url: str = CLOUDFLARE_API,
        timeout: float = 15.0,
    ) -> None:
        self._token = token
        self._transport: HttpTransport = transport or aiohttp_transport
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def with_token(self, token: str) -> CloudflareDns:
        """The same API with another token (to check a new one before storing it)."""
        return CloudflareDns(lambda: token, transport=self._transport, base_url=self._base, timeout=self._timeout)

    async def _call(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, str] | None = None,
        json_body: Mapping[str, object] | None = None,
    ) -> Any:
        token = self._token()
        reply = await self._transport(
            method,
            f"{self._base}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            params=params,
            json_body=json_body,
            timeout=self._timeout,
        )
        body = reply.body if isinstance(reply.body, dict) else {}
        if reply.status >= 400 or not body.get("success", False):
            raw_errors = body.get("errors")
            errors: list[Any] = raw_errors if isinstance(raw_errors, list) else []
            detail = "; ".join(
                f"{e.get('code', '?')}: {e.get('message', '')}" for e in errors if isinstance(e, dict)
            )
            raise DnsApiError(
                f"DNS API {method} {path.split('?', 1)[0]}: HTTP {reply.status}"
                + (f" — {detail[:300]}" if detail else ""),
                status=reply.status,
            )
        return body.get("result")

    async def verify_token(self) -> str:
        """``GET /user/tokens/verify``: the token's status ("active" when usable)."""
        result = await self._call("GET", "/user/tokens/verify")
        return str(result.get("status", "")) if isinstance(result, dict) else ""

    async def find_zone(self, name: str) -> DnsZone:
        """The zone *name* belongs to — the longest suffix the token can see."""
        for candidate in zone_candidates(name):
            result = await self._call("GET", "/zones", params={"name": candidate})
            if isinstance(result, list):
                for zone in result:
                    if isinstance(zone, dict) and str(zone.get("name", "")).lower() == candidate:
                        return DnsZone(id=str(zone["id"]), name=candidate)
        raise DnsApiError(f"DNS API: no zone of {name} is visible to the token")

    async def records(self, zone_id: str, name: str, rtype: str = "A") -> list[DnsRecord]:
        result = await self._call(
            "GET", f"/zones/{quote(zone_id, safe='')}/dns_records",
            params={"type": rtype, "name": name.lower(), "per_page": "100"},
        )
        if not isinstance(result, list):
            raise DnsApiError("DNS API: the record list is not a list")
        return [record for record in map(_record, result) if record.name == name.lower() and record.type == rtype]

    async def create_a(self, zone_id: str, name: str, ipv4: str) -> DnsRecord:
        _require_ipv4(ipv4)
        return _record(
            await self._call(
                "POST", f"/zones/{quote(zone_id, safe='')}/dns_records",
                json_body={"type": "A", "name": name.lower(), "content": ipv4, "ttl": FAILOVER_TTL, "proxied": False},
            )
        )

    async def update_a(self, zone_id: str, record_id: str, ipv4: str) -> DnsRecord:
        _require_ipv4(ipv4)
        return _record(
            await self._call(
                "PATCH", f"/zones/{quote(zone_id, safe='')}/dns_records/{quote(record_id, safe='')}",
                json_body={"content": ipv4, "ttl": FAILOVER_TTL, "proxied": False},
            )
        )


def _require_ipv4(value: str) -> None:
    if validators.ipv4_address(value) is None:
        raise DnsApiError(f"not an IPv4 address: {value!r}")


# ── DNS over HTTPS ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DohAnswer:
    """What one public resolver answers for a name's A record."""

    resolver: str
    addresses: tuple[str, ...]
    # The smallest TTL of the answer; None when there is none.
    ttl: int | None = None
    # Set when the resolver could not be asked or answered with an error rcode.
    error: str | None = None


async def doh_resolve_a(
    name: str,
    *,
    transport: HttpTransport | None = None,
    resolvers: Sequence[tuple[str, str]] = DOH_RESOLVERS,
    timeout: float = 10.0,
) -> list[DohAnswer]:
    """Ask every resolver of *resolvers* for the A record of *name* over DoH."""
    send = transport or aiohttp_transport
    answers: list[DohAnswer] = []
    for label, url in resolvers:
        try:
            reply = await send(
                "GET", url, headers={"Accept": "application/dns-json"},
                params={"name": name, "type": "A"}, timeout=timeout,
            )
        except DnsApiError as exc:
            answers.append(DohAnswer(resolver=label, addresses=(), error=str(exc)))
            continue
        answers.append(_doh_answer(label, reply))
    return answers


def _doh_answer(label: str, reply: HttpReply) -> DohAnswer:
    body = reply.body
    if reply.status != 200 or not isinstance(body, dict):
        return DohAnswer(resolver=label, addresses=(), error=f"HTTP {reply.status}")
    rcode = body.get("Status")
    if rcode != 0:
        return DohAnswer(resolver=label, addresses=(), error="NXDOMAIN" if rcode == 3 else f"rcode {rcode}")
    addresses: list[str] = []
    ttls: list[int] = []
    for item in body.get("Answer") or []:
        if not isinstance(item, dict) or item.get("type") != _DNS_TYPE_A:
            continue
        data = str(item.get("data", ""))
        if validators.ipv4_address(data) is not None and data not in addresses:
            addresses.append(data)
            ttl = item.get("TTL")
            if isinstance(ttl, int):
                ttls.append(ttl)
    return DohAnswer(resolver=label, addresses=tuple(sorted(addresses)), ttl=min(ttls) if ttls else None)


# ── the token's file ──────────────────────────────────────────────────────────


def valid_token(value: str) -> bool:
    return bool(_TOKEN_RE.fullmatch(value))


class CloudflareTokenFile:
    """The API token in ``path`` (0600, the bot's own), registered for redaction."""

    def __init__(self, path: Path = TOKEN_FILE) -> None:
        self.path = path

    def exists(self) -> bool:
        return os.path.lexists(self.path)

    def load(self) -> str:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise DnsTokenMissing("no DNS API token is stored") from None
        except OSError as exc:
            raise DnsTokenMissing(f"the DNS API token file cannot be opened: {type(exc).__name__}") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_TOKEN_FILE_BYTES:
                raise DnsTokenMissing("the DNS API token file is not a regular file")
            if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
                logger.warning(
                    "DNS API token %s: owner %s mode %o is not private to uid %s",
                    self.path, st.st_uid, st.st_mode & 0o777, os.geteuid(),
                )
                raise DnsTokenMissing("the DNS API token file is not private")
            raw = os.read(fd, _MAX_TOKEN_FILE_BYTES + 1)
        finally:
            os.close(fd)
        token = raw.decode("ascii", errors="replace").strip()
        if not valid_token(token):
            raise DnsTokenMissing("the DNS API token file is damaged")
        register_secret(token)
        return token

    def save(self, token: str) -> None:
        """Replace the token atomically (a temporary 0600 file renamed over it)."""
        if not valid_token(token):
            raise ValueError("not a DNS API token")
        register_secret(token)
        directory = self.path.parent
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            tmp = directory / f".{self.path.name}.tmp"
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.write(fd, token.encode("ascii") + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self.path)
        except OSError as exc:
            logger.warning("DNS API token %s cannot be written: %s", self.path, type(exc).__name__)
            raise DnsTokenMissing(f"the DNS API token cannot be written: {type(exc).__name__}") from None

    def delete(self) -> bool:
        """Remove the token; False when there was none."""
        try:
            old = self.load()
        except DnsTokenMissing:
            old = None
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            return False
        if old is not None:
            forget_secret(old)
        return True


def fingerprint(token: str) -> str:
    """A short, non-reversible tag of the token for the audit and the screen."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:8]


Resolve = Callable[[str], Awaitable[list[DohAnswer]]]
