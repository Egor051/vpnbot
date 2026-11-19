"""THE public address of each proxy right now (docs/proxy.md «Через hub в режиме фолбэка»).

ONE source for every place that shows a proxy to a user — the «Прокси» section, the
issued access, the links (``socks5://``, ``https://t.me/socks``, ``https://t.me/proxy``)
and the plain «host:port»: :meth:`ProxyEndpoints.endpoint`. Templates never read
``SOCKS5_HOST`` / ``MTPROTO_HOST`` themselves.

Normally that is SOCKS5_HOST:SOCKS5_PORT (MTPROTO_HOST:MTPROTO_PORT) — the main server.
In the FALLBACK MODE the TSPU drops the main server's address, and a proxy pointing at it
is dead for users in Russia while the hub still reaches main. Then, for every proxying
module the hub forwards (services/fallback.py adds its port to the hub's TCP set when the
mode is switched on, removes it when it is switched off or the module is), the address is
the hub's IPv4 — the same address the failover names get — and the port stays. Logins,
passwords and MTProto secrets do not change: the hub is an L4 forward, main's danted /
mtproxy still authenticate.

WHY the hub's IPv4 and not its host name: the name may be a failover name itself or be
re-pointed with the mode; a name needs a DNS lookup on the client, which is exactly what
is unreliable where the proxy is needed; and the IPv4 is what the switch writes into the
failover records, so the proxy and the VPN names move together.

Only TCP CONNECT goes through the hub: danted answers UDP ASSOCIATE with its own address,
which the client cannot reach in the mode (Telegram needs TCP only).

:class:`FallbackService` keeps this object current (``refresh_state`` — after every
write and at startup), so a read is synchronous.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import quote, urlencode

from config.settings import Settings
from models.dto import ProxyAccess
from models.enums import ProxyAccessType

SOCKS5 = "socks5"
MTPROTO = "mtproto"
# The proxying modules: kind → its access type.
PROXY_KINDS: dict[str, ProxyAccessType] = {SOCKS5: ProxyAccessType.SOCKS5, MTPROTO: ProxyAccessType.MTPROTO}


@dataclass(frozen=True, slots=True)
class ProxyEndpoint:
    """Where a proxy is reached now: host and port, and whether that is the hub."""

    host: str
    port: int | None
    via_hub: bool = False

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}" if self.port is not None else self.host


def socks5_url(endpoint: ProxyEndpoint, login: str, password: str) -> str:
    return f"socks5://{quote(login, safe='')}:{quote(password, safe='')}@{endpoint.host}:{endpoint.port}"


def socks5_tg_link(endpoint: ProxyEndpoint, login: str, password: str) -> str:
    """Telegram's «add this SOCKS5 proxy» link."""
    query = urlencode({"server": endpoint.host, "port": endpoint.port, "user": login, "pass": password})
    return f"https://t.me/socks?{query}"


def mtproto_links(endpoint: ProxyEndpoint, secret: str) -> tuple[str, str]:
    """The two t.me/proxy links of an MTProto secret (plain and «dd»)."""
    base = f"https://t.me/proxy?server={endpoint.host}&port={endpoint.port}"
    return f"{base}&secret={secret}", f"{base}&secret=dd{secret}"


class ProxyEndpoints:
    """The public address of each proxying module now (module docstring)."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._via_hub: dict[str, str] = {}

    def configured(self, kind: str) -> ProxyEndpoint:
        """The address .env gives (the main server)."""
        if kind == SOCKS5:
            return ProxyEndpoint(self.settings.socks5_host, self.settings.socks5_port)
        if kind == MTPROTO:
            return ProxyEndpoint(self.settings.mtproto_host, self.settings.mtproto_port)
        raise ValueError(kind)

    def endpoint(self, kind: str) -> ProxyEndpoint:
        """THE address of *kind* now: the hub's IPv4 while the mode routes it there."""
        base = self.configured(kind)
        hub = self._via_hub.get(kind)
        return ProxyEndpoint(hub, base.port, via_hub=True) if hub else base

    def socks5(self) -> ProxyEndpoint:
        return self.endpoint(SOCKS5)

    def mtproto(self) -> ProxyEndpoint:
        return self.endpoint(MTPROTO)

    def set_via_hub(self, routes: Mapping[str, str]) -> None:
        """{kind: the hub's IPv4} for the modules the hub forwards in the mode ({}: none)."""
        self._via_hub = {kind: host for kind, host in routes.items() if kind in PROXY_KINDS and host}

    def via_hub(self) -> dict[str, str]:
        return dict(self._via_hub)

    def current(self, access: ProxyAccess) -> ProxyAccess:
        """*access* with its address — host, port and every link — as it is now. The
        stored payload keeps the address of the moment it was issued; what a user is
        shown is always this. Credentials are untouched."""
        if access.access_type == ProxyAccessType.SOCKS5:
            return replace(access, payload=self._socks5_payload(access.payload),
                           public_payload=self._address_only(access.public_payload, SOCKS5))
        if access.access_type == ProxyAccessType.MTPROTO:
            return replace(access, payload=self._mtproto_payload(access.payload),
                           public_payload=self._address_only(access.public_payload, MTPROTO))
        return access

    def _address_only(self, payload: Mapping[str, Any], kind: str) -> dict[str, Any]:
        out = dict(payload)
        if "host" in out or "port" in out:
            endpoint = self.endpoint(kind)
            out["host"], out["port"] = endpoint.host, endpoint.port
        return out

    def _socks5_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        out = dict(payload)
        endpoint = self.socks5()
        out["host"], out["port"] = endpoint.host, endpoint.port
        login, password = str(out.get("login") or ""), str(out.get("password") or "")
        if login and password:
            out["url"] = socks5_url(endpoint, login, password)
            out["tg_link"] = socks5_tg_link(endpoint, login, password)
        return out

    def _mtproto_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        out = dict(payload)
        endpoint = self.mtproto()
        out["host"], out["port"] = endpoint.host, endpoint.port
        secret = str(out.get("secret") or "")
        if secret:
            out["link"], out["link_dd"] = mtproto_links(endpoint, secret)
        return out
