
from dataclasses import replace

from config.settings import Settings
from models.dto import ProxyAccess, ProxyAdminStats, ProxyLifecycleStats, ProxyRuntimeStats, ProxyServiceStatus, ProxyUserStats
from models.enums import ProxyAccessStatus, ProxyAccessType
from repositories.proxy_accesses import ProxyAccessRepository
from services.proxy_endpoint import ProxyEndpoints
from services.users import UserService


class ProxyService:
    def __init__(
        self,
        *,
        accesses: ProxyAccessRepository,
        users: UserService,
        settings: Settings,
        endpoints: ProxyEndpoints | None = None,
    ) -> None:
        self.accesses = accesses
        self.users = users
        self.settings = settings
        # THE public address of each proxy now (services/proxy_endpoint.py): what the
        # «Прокси» section shows, whatever address an access was issued with.
        self.endpoints = endpoints or ProxyEndpoints(settings)

    async def list_user_accesses(self, actor_user_id: int) -> list[ProxyAccess]:
        """Return the user's active proxy accesses, with the address they are reached at now."""
        await self.users.require_approved_or_admin(actor_user_id)
        accesses = await self.accesses.list_by_owner(actor_user_id)
        return [self.endpoints.current(access) for access in accesses if access.status == ProxyAccessStatus.ACTIVE]

    async def list_all_user_accesses_for_admin(self, actor_user_id: int, owner_user_id: int) -> list[ProxyAccess]:
        """Return all of a user's proxy accesses; requires superadmin."""
        await self.users.require_superadmin(actor_user_id)
        return [self.endpoints.current(access) for access in await self.accesses.list_by_owner(owner_user_id)]

    async def lifecycle_stats(self, actor_user_id: int) -> ProxyLifecycleStats:
        """Return proxy access lifecycle statistics; requires superadmin."""
        await self.users.require_superadmin(actor_user_id)
        return await self.accesses.lifecycle_stats()

    async def get_user_proxy_stats(self, actor_user_id: int) -> ProxyUserStats:
        """Return the requesting user's proxy usage statistics (an active access with the
        address it is reached at now)."""
        await self.users.require_approved_or_admin(actor_user_id)
        stats = await self.accesses.get_user_proxy_stats(actor_user_id)
        kinds = {ProxyAccessType.SOCKS5: "socks5", ProxyAccessType.MTPROTO: "mtproto"}
        items = []
        for item in stats.accesses:
            kind = kinds.get(item.access_type)
            if kind is not None and item.status == ProxyAccessStatus.ACTIVE and item.host:
                endpoint = self.endpoints.endpoint(kind)
                item = replace(item, host=endpoint.host, port=endpoint.port)
            items.append(item)
        return replace(stats, accesses=tuple(items))

    async def get_admin_proxy_stats(
        self,
        actor_user_id: int,
        *,
        user_limit: int = 12,
        user_offset: int = 0,
        runtime: ProxyRuntimeStats | None = None,
    ) -> ProxyAdminStats:
        """Return aggregated proxy statistics for admins, including runtime info."""
        await self.users.require_superadmin(actor_user_id)
        stats = await self.accesses.get_admin_proxy_stats(user_limit=user_limit, user_offset=user_offset)
        return replace(stats, runtime=runtime or self.runtime_stats())

    def runtime_stats(self) -> ProxyRuntimeStats:
        """Return current proxy runtime configuration from settings."""
        return ProxyRuntimeStats(
            socks5_enabled=self.settings.socks5_enabled,
            socks5_host=self.settings.socks5_host,
            socks5_port=self.settings.socks5_port,
            socks5_service_name=self.settings.socks5_service_name,
            mtproto_enabled=self.settings.mtproto_enabled,
            mtproto_host=self.settings.mtproto_host,
            mtproto_port=self.settings.mtproto_port,
            mtproto_mode=self.settings.mtproto_mode,
            mtproto_service_name=self.settings.mtproto_service_name,
        )

    def service_status(self) -> ProxyServiceStatus:
        """Return the configured status of the SOCKS5 and MTProto proxy services."""
        return ProxyServiceStatus(
            socks5_enabled=self.settings.socks5_enabled,
            socks5_host=self.settings.socks5_host,
            socks5_port=self.settings.socks5_port,
            socks5_public_name=self.settings.socks5_public_name,
            socks5_service_name=self.settings.socks5_service_name,
            mtproto_enabled=self.settings.mtproto_enabled,
            mtproto_host=self.settings.mtproto_host,
            mtproto_port=self.settings.mtproto_port,
            mtproto_public_name=self.settings.mtproto_public_name,
            mtproto_stats_url_configured=bool(self.settings.mtproto_stats_url),
            mtproto_mode=self.settings.mtproto_mode,
            mtproto_service_name=self.settings.mtproto_service_name,
        )
