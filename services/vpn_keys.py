
from models.dto import VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.errors import AccessDenied, NotFound
from services.users import UserService


class VpnKeyQueryService:
    def __init__(self, *, vpn_keys: VpnKeyRepository, users: UserService) -> None:
        self.vpn_keys = vpn_keys
        self.users = users

    async def list_for_actor(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        """Return the VPN keys an actor is allowed to view for a given owner."""
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи", key="err_foreign_keys_view")
        return await self.vpn_keys.list_by_owner(target, limit=limit, offset=offset)

    async def count_for_actor(self, actor_user_id: int, owner_user_id: int | None = None) -> int:
        """Return the number of VPN keys an actor may view for a given owner."""
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи", key="err_foreign_keys_view")
        return await self.vpn_keys.count_by_owner(target)

    async def personal_summary_for_actor(self, actor_user_id: int) -> tuple[int, int, int, int, int]:
        """Return (active_xray, active_awg, active_hysteria2, downloaded, uploaded) for own keys."""
        await self.users.require_approved_or_admin(actor_user_id)
        active = await self.vpn_keys.list_by_owner_statuses(actor_user_id, {VpnKeyStatus.ACTIVE}, limit=500)
        active_xray = sum(1 for key in active if key.key_type == VpnKeyType.XRAY)
        active_awg = sum(1 for key in active if key.key_type == VpnKeyType.AWG)
        active_hysteria2 = sum(1 for key in active if key.key_type == VpnKeyType.HYSTERIA2)
        downloaded, uploaded = await self.vpn_keys.sum_traffic_for_owner(actor_user_id)
        return active_xray, active_awg, active_hysteria2, downloaded, uploaded

    async def list_active_trial_by_owner(self, owner_user_id: int) -> list[VpnKey]:
        """Return the owner's active trial VPN keys."""
        return await self.vpn_keys.list_active_trial_by_owner(owner_user_id)

    async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
        """Return a single VPN key if the actor is allowed to view it."""
        key = await self.vpn_keys.get_by_id(key_id)
        if key is None or key.status == VpnKeyStatus.DELETED:
            raise NotFound("Ключ не найден", key="err_key_not_found")
        if key.owner_user_id == actor_user_id:
            return key
        actor = await self.users.require_approved_or_admin(actor_user_id)
        if actor.role != UserRole.SUPERADMIN:
            raise AccessDenied("Нельзя смотреть чужой ключ", key="err_foreign_key_view")
        return key
