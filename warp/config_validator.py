"""Parsing and validation of AmneziaWG (``awg-quick``) client configs.

The validator is intentionally strict: it rejects plain WireGuard configs (which
lack the AmneziaWG obfuscation fields) and configs missing the keys required to
establish the tunnel. ``AllowedIPs`` is extracted verbatim and never rewritten —
the user decides which traffic flows through the tunnel.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


class WarpConfigError(ValueError):
    """Raised when an uploaded config is not a valid AmneziaWG client config."""


@dataclass(frozen=True, slots=True)
class WarpConfig:
    """Result of a successful validation.

    ``allowed_ips`` preserves the exact CIDR tokens from the ``AllowedIPs`` line
    (order and content unchanged).
    """

    allowed_ips: tuple[str, ...]


# Fields that distinguish AmneziaWG from plain WireGuard. If none of the
# obfuscation fields are present the config is a regular WireGuard config and is
# rejected. ``Jc``, ``S1`` and ``S2`` are the canonical markers checked here.
_AMNEZIA_MARKERS = ("Jc", "S1", "S2")


def _has_section(text: str, name: str) -> bool:
    return re.search(rf"^[ \t]*\[{re.escape(name)}\][ \t]*$", text, re.MULTILINE) is not None


def _field_value(text: str, key: str) -> str | None:
    """Return the raw value of ``key = value`` (first occurrence) or ``None``.

    Horizontal-only whitespace classes (``[ \\t]``) are used around ``=`` so an
    empty value never lets the match spill onto the following line.
    """
    match = re.search(rf"^[ \t]*{re.escape(key)}[ \t]*=[ \t]*(.*)$", text, re.MULTILINE)
    if match is None:
        return None
    return match.group(1).strip()


def _has_field(text: str, key: str) -> bool:
    return re.search(rf"^[ \t]*{re.escape(key)}[ \t]*=", text, re.MULTILINE) is not None


def extract_allowed_ips(text: str) -> tuple[str, ...]:
    """Extract the ``AllowedIPs`` CIDR list verbatim, without modifying it."""
    value = _field_value(text, "AllowedIPs")
    if not value:
        return ()
    return tuple(token.strip() for token in value.split(",") if token.strip())


def validate_amnezia_config(text: str) -> WarpConfig:
    """Validate an AmneziaWG client config, returning the parsed result.

    Raises ``WarpConfigError`` with a user-facing message on the first problem.
    """
    if not _has_section(text, "Interface"):
        raise WarpConfigError("В конфиге отсутствует секция [Interface]")
    if not _has_section(text, "Peer"):
        raise WarpConfigError("В конфиге отсутствует секция [Peer]")

    for key in ("PrivateKey", "PublicKey", "Endpoint"):
        if not _has_field(text, key):
            raise WarpConfigError(f"В конфиге отсутствует обязательное поле {key}")

    missing_markers = [marker for marker in _AMNEZIA_MARKERS if not _has_field(text, marker)]
    if missing_markers:
        raise WarpConfigError(
            "Это обычный WireGuard-конфиг, а не AmneziaWG "
            f"(нет полей: {', '.join(missing_markers)}). "
            "Загрузите конфиг в расширенном формате AmneziaWG."
        )

    allowed_ips = extract_allowed_ips(text)
    if not allowed_ips:
        raise WarpConfigError("В конфиге отсутствует непустой AllowedIPs")

    invalid = []
    for token in allowed_ips:
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            invalid.append(token)
    if invalid:
        raise WarpConfigError(
            f"AllowedIPs содержит некорректные CIDR: {', '.join(invalid)}"
        )

    return WarpConfig(allowed_ips=allowed_ips)
