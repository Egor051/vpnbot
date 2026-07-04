
import ipaddress


def _has_control_or_space(value: str) -> bool:
    return any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def reject_option_like(value: str, field: str, *, error: type[Exception] = ValueError) -> str:
    """Reject a value bound for a subprocess argv slot that is empty, whitespace, or option-like.

    A leading ``-`` would be parsed as a flag by the invoked tool (systemctl / awg /
    xray); embedded whitespace could word-split or smuggle a second token. Returns the
    value unchanged when safe so callers can assign inline.
    """
    if not value or value.startswith("-") or any(ch.isspace() for ch in value):
        raise error(f"{field} содержит недопустимое значение для аргумента команды: {value!r}")
    return value


def validate_wireguard_key(value: str, field: str, *, error: type[Exception] = ValueError) -> str:
    """Reject a WireGuard/AmneziaWG key that could break out of its config line or argv slot.

    Keys are server-generated base64, so this is defence-in-depth: it rejects an empty
    value, a leading ``-`` (read as a flag by ``awg set``), and any whitespace or control
    character (which could inject an extra line into an ``awg0.conf`` ``[Peer]`` block).
    It deliberately does NOT pin an exact base64 length/charset, so a legitimately-formatted
    key is never rejected (mirrors the strict label check in awg_config).
    """
    if not value or value.startswith("-") or _has_control_or_space(value):
        raise error(f"{field} содержит недопустимые символы")
    return value


def validate_ip(value: str, field: str, *, error: type[Exception] = ValueError) -> str:
    """Reject a value that is not a bare IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise error(f"{field} не является корректным IP-адресом: {value!r}") from exc
    return value
