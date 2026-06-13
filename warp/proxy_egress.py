"""Helpers for routing local proxy egress (Dante/Xray/MTProto) through WARP.

The tunnel IP that the proxies must source their egress from is the WARP config's
``[Interface] Address`` — it is never hardcoded. The shell helper
``vpnbot-warp-routes`` reads the same value for its ``ip rule``/SNAT setup; this
module is the Python counterpart used by the Xray config writer to emit
``sendThrough`` on the freedom outbound.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

_ADDRESS_RE = re.compile(r"^[ \t]*Address[ \t]*=[ \t]*(.+?)[ \t]*$", re.IGNORECASE | re.MULTILINE)


def read_tunnel_address(config_path: Path | str) -> str | None:
    """Return the IPv4 tunnel address from a WARP config's ``[Interface] Address``.

    Takes the first comma-separated token of the first ``Address =`` line (the
    [Peer] section has no ``Address``), strips the CIDR mask and validates it as an
    IPv4 address. Returns ``None`` when the file is unreadable, has no ``Address``
    line or carries only an IPv6 address — callers treat that as "no WARP egress".
    """
    try:
        content = Path(config_path).read_text(encoding="utf-8")
    except OSError:
        return None
    match = _ADDRESS_RE.search(content)
    if match is None:
        return None
    token = match.group(1).split(",")[0].strip()
    candidate = token.split("/")[0].strip()
    try:
        return str(ipaddress.IPv4Address(candidate))
    except ValueError:
        return None


def make_send_through_provider(
    *, enabled: bool, config_path: Path | str
) -> Callable[[], str | None]:
    """Build the ``sendThrough`` provider for the Xray config writer.

    The returned callable yields the tunnel IP when WARP proxy egress is enabled and
    the address resolves, otherwise ``None`` (so the writer strips any stale
    ``sendThrough`` and a non-WARP deploy stays clean). It is read live on every
    write so a re-uploaded config / toggled flag is picked up without a restart.
    """

    def _provider() -> str | None:
        if not enabled:
            return None
        tunnel_ip = read_tunnel_address(config_path)
        if tunnel_ip is None:
            logger.warning(
                "WARP proxy egress is enabled but no IPv4 [Interface] Address was found in %s; "
                "Xray sendThrough not emitted",
                config_path,
            )
        return tunnel_ip

    return _provider
