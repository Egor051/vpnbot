
from models.dto import OwnerTrafficSummary, TrafficScopeTotals, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.traffic_scope import ALL_TIME, CURRENT_KEYS
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
        *,
        exclude_bundled: bool = False,
    ) -> list[VpnKey]:
        """Return the VPN keys an actor is allowed to view for a given owner.

        ``exclude_bundled`` hides the children of all-in-one bundles, which are
        managed through their parent and would otherwise crowd out the list. Off
        by default so the admin view of a user's keys still shows every key —
        there is no bundle screen on the admin side to see them on instead.
        """
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи", key="err_foreign_keys_view")
        return await self.vpn_keys.list_by_owner(
            target, limit=limit, offset=offset, exclude_bundled=exclude_bundled
        )

    async def count_for_actor(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        *,
        exclude_bundled: bool = False,
    ) -> int:
        """Return the number of VPN keys an actor may view for a given owner.

        ``exclude_bundled`` must mirror the value passed to :meth:`list_for_actor`,
        otherwise the page count and the page contents disagree.
        """
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи", key="err_foreign_keys_view")
        return await self.vpn_keys.count_by_owner(target, exclude_bundled=exclude_bundled)

    async def personal_summary_for_actor(
        self, actor_user_id: int
    ) -> tuple[int, int, int, OwnerTrafficSummary]:
        """Return (active_xray, active_awg, active_hysteria2, traffic) for own keys."""
        await self.users.require_approved_or_admin(actor_user_id)
        active = await self.vpn_keys.list_by_owner_statuses(actor_user_id, {VpnKeyStatus.ACTIVE}, limit=500)
        active_xray = sum(1 for key in active if key.key_type == VpnKeyType.XRAY)
        active_awg = sum(1 for key in active if key.key_type == VpnKeyType.AWG)
        active_hysteria2 = sum(1 for key in active if key.key_type == VpnKeyType.HYSTERIA2)
        traffic = await self._owner_traffic_summary(actor_user_id)
        return active_xray, active_awg, active_hysteria2, traffic

    async def traffic_summary_for_actor(
        self, actor_user_id: int, owner_user_id: int | None = None
    ) -> OwnerTrafficSummary:
        """Return both traffic scopes for an owner the actor is allowed to view.

        Counts EVERY key the owner has. The admin user card used to aggregate the
        same ``list_for_actor(..., limit=10)`` page it renders below, so a user
        with an eleventh key silently reported less traffic than they had moved —
        the limit belongs to the displayed list, not to the total above it.
        """
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи", key="err_foreign_keys_view")
        return await self._owner_traffic_summary(target)

    async def _owner_traffic_summary(self, owner_user_id: int) -> OwnerTrafficSummary:
        """Both scopes for one owner, from the one scoped query — no access check."""
        current_down, current_up = await self.vpn_keys.sum_traffic_for_owner(owner_user_id, CURRENT_KEYS)
        all_down, all_up = await self.vpn_keys.sum_traffic_for_owner(owner_user_id, ALL_TIME)
        return OwnerTrafficSummary(
            current_keys=TrafficScopeTotals(downloaded_bytes=current_down, uploaded_bytes=current_up),
            all_time=TrafficScopeTotals(downloaded_bytes=all_down, uploaded_bytes=all_up),
        )

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
