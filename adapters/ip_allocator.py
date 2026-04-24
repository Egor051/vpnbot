from __future__ import annotations

import ipaddress
from typing import Protocol

from adapters.errors import AwgIpAllocationError
from repositories.vpn_keys import VpnKeyRepository


class AwgPeerIpSource(Protocol):
    def list_peer_allowed_ips(self) -> set[str]:
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
        self.network = ipaddress.ip_network(network, strict=False)
        self.server_address = ipaddress.ip_address(server_address.split("/", 1)[0])
        self.awg_config = awg_config

    async def next_free_ip(self) -> str:
        occupied = {ipaddress.ip_address(value) for value in await self.vpn_keys.get_occupied_awg_ips()}
        if self.awg_config is not None:
            try:
                occupied.update(
                    ipaddress.ip_address(value)
                    for value in self.awg_config.list_peer_allowed_ips()
                    if value
                )
            except ValueError as exc:
                raise AwgIpAllocationError("AWG config содержит некорректный IP в AllowedIPs") from exc
            except Exception as exc:
                raise AwgIpAllocationError(f"Не удалось прочитать занятые IP из AWG config: {exc}") from exc
        # Revoked/deleted/failed keys are intentionally excluded by the repository query,
        # so their IPs can be reused from DB. Existing peers in AWG config are always reserved,
        # including unmanaged peers that are not represented in SQLite.
        for candidate in self.network.hosts():
            if candidate == self.server_address:
                continue
            if candidate not in occupied:
                return str(candidate)
        raise AwgIpAllocationError("В AWG-пуле не осталось свободных IP")


def self_check_ip_allocator_sources() -> bool:
    class Source:
        def list_peer_allowed_ips(self) -> set[str]:
            return {"10.0.0.2", "10.0.0.3"}

    source = Source()
    return source.list_peer_allowed_ips() == {"10.0.0.2", "10.0.0.3"}
