"""Relay keys: which host a key's link points at, and when that is refused.

A relay key is an ordinary key — same inbound, same ``email_label`` prefix, same
uuid/secret mechanics — whose ``vpn_keys.relay`` column names the L4 relay its
link must point at. The relay forwards TCP+UDP/443 1:1, so the ONLY thing that
differs in the link is the host (plus the relay's marker in the display name);
the port stays the protocol's public port.

Relays live in the ``relays`` table and are managed from the admin panel
(:mod:`services.relay_management`). Everything that renders a link reads them
through a :class:`RelaySnapshot` — an immutable copy of that table:

* the bot keeps one in a :class:`RelayCatalog`, refreshed by every write the
  relay service makes (one process, one writer, so the cache cannot go stale);
* the subscription endpoint reads a fresh snapshot from the database on every
  request, so an admin's change is served without restarting anything.

:func:`relay_link_host` is the single place that maps a key's relay to a host,
for every link builder (VLESS and Hysteria2, bot and subscription). It never
falls back to the main host: a relay key whose relay is switched off, deleted or
unknown raises :class:`RelayUnavailable`, because a link that silently points at
the main server is a key that "works" while bypassing the relay the user chose —
the exact failure this feature exists to avoid.

Nothing here touches the database or imports a service, so the link builders and
the standalone subscription process can use it freely.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from models.dto import Relay
from services.errors import InvalidOperation


class RelayUnavailable(InvalidOperation):
    """A key names a relay that cannot serve links right now.

    Raised when the relay is switched off, deleted or was never known. Keyed, so
    the bot shows a localized alert; the subscription renderer catches it and
    skips that one member.
    """

    def __init__(self, relay: str) -> None:
        super().__init__(
            f"Relay «{relay}» недоступен: он выключен или удалён в админке",
            key="err_relay_unavailable",
            params={"relay": relay},
        )
        self.relay = relay


@dataclass(frozen=True, slots=True)
class RelaySnapshot:
    """An immutable copy of the ``relays`` table, ordered by ``id``.

    ``id`` order is THE relay order: subscriptions list the members of relay #1
    before those of relay #2, and the create wizard offers them in that order.
    """

    relays: tuple[Relay, ...] = ()

    @classmethod
    def of(cls, relays: Iterable[Relay]) -> RelaySnapshot:
        return cls(tuple(sorted(relays, key=lambda relay: relay.id)))

    def get(self, name: str) -> Relay | None:
        """The relay named *name*, enabled or not; None when there is none."""
        for relay in self.relays:
            if relay.name == name:
                return relay
        return None

    def by_id(self, relay_id: int) -> Relay | None:
        for relay in self.relays:
            if relay.id == relay_id:
                return relay
        return None

    @property
    def enabled(self) -> tuple[Relay, ...]:
        """Relays a key can be issued through (and rendered for) right now."""
        return tuple(relay for relay in self.relays if relay.enabled)

    @property
    def for_subscriptions(self) -> tuple[Relay, ...]:
        """Relays new all-in-one bundles get members through: enabled AND in subscriptions."""
        return tuple(relay for relay in self.relays if relay.enabled and relay.in_subscriptions)

    def group_of(self, relay: str | None) -> int:
        """Where a key's relay sorts among the subscription's groups.

        0 for a direct key; 1, 2, … for the relays in ``id`` order (switched-off
        ones keep their slot — their members are skipped when rendering, not
        reordered); after all of them for a relay this snapshot does not know.
        """
        if relay is None:
            return 0
        for index, known in enumerate(self.relays, start=1):
            if known.name == relay:
                return index
        return len(self.relays) + 1

    @property
    def source_networks(self) -> tuple[ipaddress.IPv4Network, ...]:
        """The egress networks of EVERY relay, switched-off ones included.

        A relay that was just switched off can still carry traffic from clients
        that have not reconnected yet, so its addresses stay excluded from
        anomaly detection until the relay is deleted.
        """
        networks: list[ipaddress.IPv4Network] = []
        for relay in self.relays:
            for network in relay.source_ips:
                if network not in networks:
                    networks.append(network)
        return tuple(networks)


EMPTY_RELAYS = RelaySnapshot()


class RelayCatalog:
    """The bot process's current :class:`RelaySnapshot`.

    A plain holder: :class:`services.relay_management.RelayService` replaces the
    snapshot after every write it makes (it is the only writer of the table), and
    the link builders read :attr:`snapshot` synchronously. Starts empty, which is
    exactly "no relays": every relay key is refused until the snapshot is loaded.
    """

    def __init__(self, snapshot: RelaySnapshot = EMPTY_RELAYS) -> None:
        self._snapshot = snapshot

    @property
    def snapshot(self) -> RelaySnapshot:
        return self._snapshot

    def replace(self, snapshot: RelaySnapshot) -> None:
        self._snapshot = snapshot


def relay_available(relays: RelaySnapshot, relay: str) -> bool:
    """Whether links for keys of *relay* can be rendered right now."""
    known = relays.get(relay)
    return bool(known is not None and known.enabled and known.host)


def relay_link_host(relays: RelaySnapshot, relay: str | None, *, direct_host: str) -> str:
    """The host a key's link points at.

    ``relay is None`` → *direct_host*, exactly as before relays existed. An
    enabled relay → its ``host``. Anything else (switched off, deleted, unknown)
    → :class:`RelayUnavailable`, never a fallback.
    """
    if relay is None:
        return direct_host
    known = relays.get(relay)
    if known is not None and known.enabled and known.host:
        return known.host
    raise RelayUnavailable(relay)


def relay_marker(relays: RelaySnapshot, relay: str) -> str:
    """The relay's marker in a key's display name — its ``label``.

    A relay that is switched off still has a label (its keys merely cannot be
    rendered, which :func:`relay_link_host` reports); a deleted or unknown one
    has none, and that key cannot be rendered either, so it is refused here too.
    """
    known = relays.get(relay)
    if known is None:
        raise RelayUnavailable(relay)
    return known.label


def require_relay_for_issue(relays: RelaySnapshot, relay: str | None) -> str | None:
    """Check the relay a NEW key is about to be issued through.

    Called before anything is written, so a stale wizard (relay switched off or
    deleted while the user was on the confirm screen) fails cleanly instead of
    leaving a key whose link can never be rendered. ``None``/``""`` means a
    direct key.
    """
    if not relay:
        return None
    if not relay_available(relays, relay):
        raise RelayUnavailable(relay)
    return relay
