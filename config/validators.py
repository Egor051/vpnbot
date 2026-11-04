"""Format validators shared by the ``.env`` loader and the admin panel.

The relay fields (name, label, host, source IPs) used to be read only from
``.env``; they are now edited in the bot's admin panel too, and both paths must
accept and refuse exactly the same values. So the checks live here, once, and
raise :class:`InvalidValue` — a plain ``ValueError`` that says what is wrong.
Each caller translates it into its own error type: ``config.settings`` into a
``SettingsError`` that names the variable, the relay service into a localized
``InvalidOperation`` for the admin.

Nothing here imports from ``config.settings`` (which imports this module) or
from any service, so every layer can use it.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Iterable

# Name of an L4 relay — the value stored in ``vpn_keys.relay`` and in
# ``relays.name``. The single source of the format: the settings loader, the key
# repository (on write), the relay repository and the admin panel all match
# against THIS pattern.
RELAY_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")

# The relay's marker in a key's display name (``<label>_<relay label><flag>``).
# Free text: emoji, arrows, letters of any script, digits, punctuation — e.g.
# ``🇷🇺➜`` or ``ru_``. It is glued to the flag with no separator, so whoever wants
# one writes it into the label. Length is counted in code points (a flag emoji
# is two).
RELAY_LABEL_MAX_CHARS = 16

# Unicode categories a relay marker may not contain: control characters (Cc),
# lone surrogates (Cs, unencodable) and line/paragraph separators (Zl, Zp). Format
# characters (Cf) stay allowed: the zero-width joiner and the tag characters
# are parts of emoji sequences.
_RELAY_LABEL_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cs", "Zl", "Zp"})

# The marker a relay gets when nobody chose one (and the one the .env seed uses).
DEFAULT_RELAY_LABEL = "relay"

# RFC 1123 hostname: dot-separated labels of 1-63 [A-Za-z0-9-], no leading or
# trailing hyphen, 253 characters in total. A trailing root dot is tolerated.
_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class InvalidValue(ValueError):
    """A value failed one of the format checks below.

    ``str(exc)`` is a complete, human-readable sentence that already names the
    field (the *name* argument every check takes), so a caller can pass it on
    unchanged.
    """


def no_control_chars(name: str, value: str) -> str:
    """Reject control characters in values that flow into generated configs/links."""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise InvalidValue(f"{name} содержит недопустимые управляющие символы")
    return value


def relay_name(name: str, value: str) -> str:
    """A relay name matching :data:`RELAY_NAME_PATTERN`, returned unchanged."""
    if RELAY_NAME_PATTERN.fullmatch(value) is None:
        raise InvalidValue(
            f"{name} должен соответствовать ^[a-z0-9][a-z0-9-]{{0,31}}$ (строчные латинские буквы, цифры, дефис)"
        )
    return value


def relay_label(name: str, value: str) -> str:
    """A relay marker, returned unchanged.

    1..:data:`RELAY_LABEL_MAX_CHARS` characters on one line, no surrounding
    whitespace and none of :data:`_RELAY_LABEL_FORBIDDEN_CATEGORIES`. Anything
    else — emoji included — is accepted: the marker only ever reaches a link's
    ``#fragment`` (percent-encoded there) and chat text (HTML-escaped there).
    """
    if not value or len(value) > RELAY_LABEL_MAX_CHARS:
        raise InvalidValue(f"{name} должен быть длиной от 1 до {RELAY_LABEL_MAX_CHARS} символов")
    if value != value.strip():
        raise InvalidValue(f"{name} не должен начинаться или заканчиваться пробелом")
    if any(unicodedata.category(ch) in _RELAY_LABEL_FORBIDDEN_CATEGORIES for ch in value):
        raise InvalidValue(f"{name} должен быть одной строкой без управляющих символов")
    return value


def dns_name_or_ipv4(name: str, value: str) -> str:
    """Accept an IPv4 address or an RFC 1123 DNS name; reject everything else.

    Surrounding whitespace is stripped and an empty value is returned as ``""``
    (whether empty is allowed is the caller's decision). IPv6 literals are
    refused on purpose: the relay forwards IPv4 only, and a bracket-less IPv6
    host would also need special casing in every link.
    """
    value = no_control_chars(name, value).strip()
    if not value:
        return value
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise InvalidValue(f"{name} должен быть DNS-именем или IPv4-адресом (IPv6 не поддерживается)")
        return value
    if value.replace(".", "").isdigit():
        # Looks numeric but is not a valid IPv4 address (e.g. 1.2.3.256): a
        # DNS name cannot be all digits, so this is a typo, not a hostname.
        raise InvalidValue(f"{name}: {value!r} не является корректным IPv4-адресом")
    hostname = value[:-1] if value.endswith(".") else value
    if len(hostname) > 253 or not all(_HOSTNAME_LABEL.match(label) for label in hostname.split(".")):
        raise InvalidValue(f"{name} должен быть DNS-именем или IPv4-адресом, получено {value!r}")
    return value


def ipv4_address(value: str) -> ipaddress.IPv4Address | None:
    """*value* as an IPv4 address, or None when it is anything else (a DNS name)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address if isinstance(address, ipaddress.IPv4Address) else None


def parse_ipv4_networks(name: str, raw: str) -> tuple[ipaddress.IPv4Network, ...]:
    """Strictly parse a comma-separated list of IPv4 addresses / CIDR networks.

    Whitespace around an item is ignored and empty items (a trailing comma, two
    commas in a row) are skipped. Anything else that is not an IPv4 address or a
    strict IPv4 network (host bits set in a CIDR, an IPv6 value, a hostname,
    stray characters) is refused: a silently dropped entry here would quietly
    re-enable IP accounting for a relay the operator believes is excluded.
    Duplicates are collapsed, order is kept.
    """
    networks: list[ipaddress.IPv4Network] = []
    for item in no_control_chars(name, raw).split(","):
        item = item.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise InvalidValue(f"{name}: {item!r} не является IPv4-адресом или CIDR-сетью") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise InvalidValue(f"{name}: {item!r} — поддерживается только IPv4")
        if network not in networks:
            networks.append(network)
    return tuple(networks)


def format_ipv4_networks(networks: Iterable[ipaddress.IPv4Network]) -> str:
    """The normalized text form of a source-IP list: ``a.b.c.d,e.f.g.0/28``.

    A single host is written as a bare address, a wider network in CIDR form, in
    the given order, comma-separated without spaces. ``parse_ipv4_networks`` reads
    it back to the same tuple, so this is what ``relays.source_ips`` stores.
    """
    parts = [
        str(network.network_address) if network.prefixlen == 32 else str(network)
        for network in networks
    ]
    return ",".join(parts)
