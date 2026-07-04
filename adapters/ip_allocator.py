
import asyncio
import ipaddress
from typing import Protocol

from adapters.errors import AwgIpAllocationError
from repositories.vpn_keys import VpnKeyRepository


class AwgPeerIpSource(Protocol):
    def list_peer_allowed_ips(self) -> set[str]:
        """Return the set of AllowedIPs across all configured peers."""
        ...


class IpAllocator:
    def __init__(
        self,
        vpn_keys: VpnKeyRepository,
        network: str,
        server_address: str,
        awg_config: AwgPeerIpSource | None = None,
    ) -> None:
        self.vpn_keys = vpn_keys
        try:
            self.network = ipaddress.ip_network(network, strict=False)
            self.server_address = ipaddress.ip_address(server_address.split("/", 1)[0])
        except ValueError as exc:
            raise AwgIpAllocationError("AWG_NETWORK и AWG_SERVER_ADDRESS должны быть корректными IPv4-значениями") from exc
        if self.network.version != 4 or self.server_address.version != 4:
            raise AwgIpAllocationError("AWG allocator сейчас поддерживает только IPv4")
        if self.server_address not in self.network:
            raise AwgIpAllocationError("AWG_SERVER_ADDRESS должен входить в AWG_NETWORK")
        if self.server_address == self.network.network_address or self.server_address == self.network.broadcast_address:
            raise AwgIpAllocationError("AWG_SERVER_ADDRESS не должен быть network или broadcast address")
        self.awg_config = awg_config

    # NOT reservation-safe on its own: it reads occupancy but does not atomically claim
    # the returned IP. Callers must serialize allocate->persist under the AWG service lock
    # (see services/awg.py `self._lock`), otherwise two concurrent calls can hand out the
    # same address.
    async def next_free_ip(self) -> str:
        """Allocate and return the next free IP address in the AWG pool."""
        occupied: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for value in await self.vpn_keys.get_occupied_awg_ips():
            # Tolerate values stored either bare ("10.0.0.5") or with a prefix ("10.0.0.5/32").
            text = str(value).split("/", 1)[0].strip()
            if not text:
                continue
            try:
                occupied.add(ipaddress.ip_address(text))
            except ValueError as exc:
                raise AwgIpAllocationError(f"Занятый AWG IP некорректен: {value!r}") from exc
        occupied_networks: list[ipaddress.IPv4Network] = []
        if self.awg_config is not None:
            try:
                # Offload the (blocking) config file read off the event loop.
                peer_allowed_ips = await asyncio.to_thread(self.awg_config.list_peer_allowed_ips)
                for value in peer_allowed_ips:
                    if not value:
                        continue
                    network = ipaddress.ip_network(value, strict=False)
                    if network.version != 4:
                        continue
                    if network.overlaps(self.network):
                        occupied_networks.append(network)
            except ValueError as exc:
                raise AwgIpAllocationError("AWG config содержит некорректный IPv4 AllowedIPs") from exc
            except Exception as exc:
                raise AwgIpAllocationError(f"Не удалось прочитать занятые IP из AWG config: {exc}") from exc
        # Revoked/deleted/failed keys are intentionally excluded by the repository query,
        # so their IPs can be reused from DB. Existing peers in AWG config are always reserved,
        # including unmanaged peers that are not represented in SQLite.
        # Linear scan from the pool start with O(1) set membership and an early return;
        # fine for the expected pool sizes (a /24 has 254 hosts).
        for candidate in self.network.hosts():
            if candidate == self.server_address:
                continue
            if candidate in occupied:
                continue
            if any(candidate in network for network in occupied_networks):
                continue
            return str(candidate)
        raise AwgIpAllocationError("В AWG-пуле не осталось свободных IP")
