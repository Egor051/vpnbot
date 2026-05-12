
from models.dto import VpnKey
from models.enums import UserRole, VpnKeyStatus
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
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи")
        return await self.vpn_keys.list_by_owner(target, limit=limit, offset=offset)

    async def count_for_actor(self, actor_user_id: int, owner_user_id: int | None = None) -> int:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи")
        return await self.vpn_keys.count_by_owner(target)

    async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        key = await self.vpn_keys.get_by_id(key_id)
        if key is None or key.status == VpnKeyStatus.DELETED:
            raise NotFound("Ключ не найден")
        if actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужой ключ")
        return key
