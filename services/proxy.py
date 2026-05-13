
from dataclasses import replace

from config.settings import Settings
from models.dto import ProxyAccess, ProxyAdminStats, ProxyLifecycleStats, ProxyRuntimeStats, ProxyServiceStatus, ProxyUserStats
from models.enums import ProxyAccessStatus
from repositories.proxy_accesses import ProxyAccessRepository
from services.users import UserService


class ProxyService:
    def __init__(
        self,
        *,
        accesses: ProxyAccessRepository,
        users: UserService,
        settings: Settings,
    ) -> None:
        self.accesses = accesses
        self.users = users
        self.settings = settings

    async def list_user_accesses(self, actor_user_id: int) -> list[ProxyAccess]:
        await self.users.require_approved_or_admin(actor_user_id)
        accesses = await self.accesses.list_by_owner(actor_user_id)
        return [access for access in accesses if access.status == ProxyAccessStatus.ACTIVE]

    async def list_all_user_accesses_for_admin(self, actor_user_id: int, owner_user_id: int) -> list[ProxyAccess]:
        await self.users.require_superadmin(actor_user_id)
        return await self.accesses.list_by_owner(owner_user_id)

    async def lifecycle_stats(self, actor_user_id: int) -> ProxyLifecycleStats:
        await self.users.require_superadmin(actor_user_id)
        return await self.accesses.lifecycle_stats()

    async def get_user_proxy_stats(self, actor_user_id: int) -> ProxyUserStats:
        await self.users.require_approved_or_admin(actor_user_id)
        return await self.accesses.get_user_proxy_stats(actor_user_id)

    async def get_admin_proxy_stats(
        self,
        actor_user_id: int,
        *,
        user_limit: int = 12,
        user_offset: int = 0,
        runtime: ProxyRuntimeStats | None = None,
    ) -> ProxyAdminStats:
        await self.users.require_superadmin(actor_user_id)
        stats = await self.accesses.get_admin_proxy_stats(user_limit=user_limit, user_offset=user_offset)
        return replace(stats, runtime=runtime or self.runtime_stats())

    def runtime_stats(self) -> ProxyRuntimeStats:
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
