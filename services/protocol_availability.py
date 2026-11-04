"""Which protocols the bot may offer — and talk about — right now.

THE single source of truth for user-facing protocol availability. It combines the
two existing switches and invents no third one:

* the ``.env`` flags — ``HYSTERIA2_ENABLED`` (plus the HOST/SNI readiness check),
  ``XRAY_XHTTP_ENABLED``, ``SOCKS5_ENABLED``, ``MTPROTO_ENABLED``. Xray and AWG
  have no flag of their own;
* the runtime module toggle (``protocol_modules`` table), which a superadmin flips
  from the bot without a restart.

A protocol is available only when both say so — the exact rule every create gate
already applied one protocol at a time. XHTTP is a transport of Xray, not a module
of its own, so it is available only together with Xray.

Call :func:`available_protocols` AT RENDER TIME, never at import: the toggle
changes under a running process, and a value captured once would keep describing
a protocol the admin has since switched off.
"""

from __future__ import annotations

import typing
from enum import StrEnum

from config.settings import Settings


class Protocol(StrEnum):
    """A protocol (or, for XHTTP, a transport) a user can be offered."""

    XRAY = "xray"
    XHTTP = "xhttp"
    AWG = "awg"
    HYSTERIA2 = "hysteria2"
    SOCKS5 = "socks5"
    MTPROTO = "mtproto"


ALL_PROTOCOLS: frozenset[Protocol] = frozenset(Protocol)

# The VPN-key protocols in the order the help texts rank them («Xray > Hysteria2 >
# AWG»). XHTTP is a transport of Xray and SOCKS5/MTProto are proxies, not keys.
VPN_PROTOCOLS: tuple[Protocol, ...] = (Protocol.XRAY, Protocol.HYSTERIA2, Protocol.AWG)


class ModuleToggles(typing.Protocol):
    """The read side of :class:`services.protocol_modules.ProtocolModulesService`."""

    async def is_enabled(self, name: str) -> bool: ...


async def available_protocols(settings: Settings, modules: ModuleToggles) -> frozenset[Protocol]:
    """Return the protocols that are switched on in ``.env`` AND in the module toggle.

    Reads the toggle afresh on every call (one small SQLite query per module), so
    the very next render after an admin flips a module already reflects it.
    """
    available: set[Protocol] = set()
    if await modules.is_enabled("xray"):
        available.add(Protocol.XRAY)
        if settings.xray_xhttp_enabled:
            available.add(Protocol.XHTTP)
    if await modules.is_enabled("awg"):
        available.add(Protocol.AWG)
    if (
        settings.hysteria2_enabled
        and settings.is_hysteria2_ready()
        and await modules.is_enabled("hysteria2")
    ):
        available.add(Protocol.HYSTERIA2)
    if settings.socks5_enabled and await modules.is_enabled("socks5"):
        available.add(Protocol.SOCKS5)
    if settings.mtproto_enabled and await modules.is_enabled("mtproto"):
        available.add(Protocol.MTPROTO)
    return frozenset(available)
