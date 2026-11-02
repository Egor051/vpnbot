"""Relay keys: which host a key's link points at, and when that is refused.

A relay key is an ordinary key — same inbound, same ``email_label`` prefix, same
uuid/secret mechanics — whose ``vpn_keys.relay`` column names the L4 relay its
link must point at. The relay forwards TCP+UDP/443 1:1, so the ONLY thing that
differs in the link is the host; the port stays the protocol's public port.

:func:`relay_link_host` is the single place that maps a key's relay to a host,
for every link builder (VLESS and Hysteria2, bot and subscription). It never
falls back to the main host: a relay key whose relay is not configured raises
:class:`RelayUnavailable`, because a link that silently points at the main
server is a key that "works" while bypassing the relay the user chose — the
exact failure this feature exists to avoid.
"""

from __future__ import annotations

from config.settings import Settings
from services.errors import InvalidOperation


class RelayUnavailable(InvalidOperation):
    """A key names a relay that is not configured right now.

    Raised when ``RELAY_ENABLED`` is off or the key's relay is not
    ``RELAY_NAME``. Keyed, so the bot shows a localized alert; the subscription
    renderer catches it and skips that one member.
    """

    def __init__(self, relay: str) -> None:
        super().__init__(
            f"Relay «{relay}» недоступен: RELAY_ENABLED выключен или RELAY_NAME не совпадает",
            key="err_relay_unavailable",
            params={"relay": relay},
        )
        self.relay = relay


def relay_available(settings: Settings, relay: str) -> bool:
    """Whether links for keys of *relay* can be rendered right now."""
    return bool(settings.relay_enabled and settings.relay_host and relay == settings.relay_name)


def relay_link_host(settings: Settings, relay: str | None, *, direct_host: str) -> str:
    """The host a key's link points at.

    ``relay is None`` → *direct_host*, exactly as before relays existed.
    The configured relay (``RELAY_ENABLED`` and ``relay == RELAY_NAME``) →
    ``RELAY_HOST``. Anything else → :class:`RelayUnavailable`, never a fallback.
    """
    if relay is None:
        return direct_host
    if relay_available(settings, relay):
        return settings.relay_host
    raise RelayUnavailable(relay)


def require_relay_for_issue(settings: Settings, relay: str | None) -> str | None:
    """Check the relay a NEW key is about to be issued through.

    Called before anything is written, so a stale wizard (relay switched off
    while the user was on the confirm screen) fails cleanly instead of leaving a
    key whose link can never be rendered. ``None``/``""`` means a direct key.
    """
    if not relay:
        return None
    if not relay_available(settings, relay):
        raise RelayUnavailable(relay)
    return relay
