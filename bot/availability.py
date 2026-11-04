"""What a screen may offer and mention right now — the render-time snapshot.

Wraps :func:`services.protocol_availability.available_protocols` together with the
one non-protocol switch the texts also depend on, ``SUBSCRIPTION_ENABLED`` (the
All-in-One bundle). Every user-facing screen that names a protocol takes one of
these, built by :func:`current_availability` in the handler right before it
renders — never cached, never computed at import.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from models.enums import KeyBundleKind
from services.key_bundles import BundleMember, available_composition, member_protocol
from services.protocol_availability import (
    ALL_PROTOCOLS,
    VPN_PROTOCOLS,
    Protocol,
    available_protocols,
)

if TYPE_CHECKING:
    from bot.container import Services


@dataclass(frozen=True, slots=True)
class Availability:
    """The protocols that are on, plus whether All-in-One subscriptions are."""

    protocols: frozenset[Protocol]
    subscription_enabled: bool = False

    def __contains__(self, protocol: object) -> bool:
        return protocol in self.protocols

    @property
    def vpn(self) -> tuple[Protocol, ...]:
        """Available VPN-key protocols in rank order (Xray > Hysteria2 > AWG)."""
        return tuple(protocol for protocol in VPN_PROTOCOLS if protocol in self.protocols)

    def bundle_members(self, kind: KeyBundleKind) -> tuple[BundleMember, ...]:
        """The *kind* composition as it would be provisioned now; empty when off."""
        if not self.subscription_enabled:
            return ()
        return available_composition(kind, self.protocols)

    @property
    def bundle_protocols(self) -> frozenset[Protocol]:
        """Protocols an All-in-One subscription would carry now (empty when off)."""
        return frozenset(member_protocol(member) for member in self.bundle_members(KeyBundleKind.EXTENDED))

    @property
    def bundle_offered(self) -> bool:
        """Whether «All-in-One» may be offered: the flag is on AND it would hold a key."""
        return bool(self.bundle_members(KeyBundleKind.EXTENDED))


# Everything on — what the texts read like on a full deployment. For tests and
# for the golden comparison; handlers always use current_availability().
FULL_AVAILABILITY = Availability(ALL_PROTOCOLS, subscription_enabled=True)


async def current_availability(services: Services) -> Availability:
    """Read the ``.env`` flags and the module toggle as they are at this instant."""
    return Availability(
        protocols=await available_protocols(services.settings, services.modules),
        subscription_enabled=bool(services.settings.subscription_enabled),
    )
