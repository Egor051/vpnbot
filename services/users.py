from __future__ import annotations

from collections.abc import Awaitable, Callable

from adapters.clock import ClockProvider
from config.settings import Settings
from models.dto import BlockUserResult, KeyOperationError, TelegramUserProfile, User, VpnKey
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound

KeyRevoker = Callable[[int, int], Awaitable[VpnKey]]


class UserService:
    def __init__(
        self,
        *,
        users: UserRepository,
        settings: Settings,
        clock: ClockProvider,
        audit: AuditService,
    ) -> None:
        self.users = users
        self.settings = settings
        self.clock = clock
        self.audit = audit
        self._vpn_keys: VpnKeyRepository | None = None
        self._key_revokers: dict[VpnKeyType, KeyRevoker] = {}

    def attach_key_management(self, vpn_keys: VpnKeyRepository, revokers: dict[VpnKeyType, KeyRevoker]) -> None:
        self._vpn_keys = vpn_keys
        self._key_revokers = dict(revokers)

    async def bootstrap_admins(self) -> None:
        await self.users.create_admin_placeholders(self.settings.admin_ids, self.clock.now())

    async def ensure_user(self, profile: TelegramUserProfile) -> User:
        existing = await self.users.get_by_id(profile.telegram_user_id)
        if profile.telegram_user_id in self.settings.admin_ids:
            role = UserRole.SUPERADMIN
        elif existing is None:
            role = UserRole.PENDING_USER
        else:
            role = existing.role
        user = await self.users.upsert_profile(profile, role, self.clock.now())
        if profile.telegram_user_id in self.settings.admin_ids and user.role != UserRole.SUPERADMIN:
            await self.users.set_role(profile.telegram_user_id, UserRole.SUPERADMIN, self.clock.now(), blocked_at=None)
            user = await self.get_user(profile.telegram_user_id)
        return user

    async def get_user(self, telegram_user_id: int) -> User:
        user = await self.users.get_by_id(telegram_user_id)
        if user is None:
            raise NotFound("Пользователь не найден")
        return user

    async def require_superadmin(self, actor_user_id: int) -> User:
        user = await self.get_user(actor_user_id)
        if user.role != UserRole.SUPERADMIN:
            raise AccessDenied("Недостаточно прав")
        return user

    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        user = await self.get_user(actor_user_id)
        if user.role not in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
            raise AccessDenied("Доступ не одобрен")
        return user

    async def can_manage_owner(self, actor_user_id: int, owner_user_id: int) -> bool:
        user = await self.get_user(actor_user_id)
        return user.role == UserRole.SUPERADMIN or actor_user_id == owner_user_id

    async def set_role(self, actor_user_id: int, target_user_id: int, role: UserRole) -> None:
        await self.require_superadmin(actor_user_id)
        if target_user_id in self.settings.admin_ids and role != UserRole.SUPERADMIN:
            raise InvalidOperation("Нельзя изменить роль superadmin из ADMIN_IDS")
        blocked_at = self.clock.now() if role == UserRole.BLOCKED_USER else None
        await self.users.set_role(target_user_id, role, self.clock.now(), blocked_at=blocked_at)
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="user_role_changed",
            entity_type=AuditEntityType.USER,
            entity_id=target_user_id,
            details={"role": role.value},
        )

    async def block_user(
        self,
        actor_user_id: int,
        target_user_id: int,
        revoke_active_keys: bool = True,
    ) -> BlockUserResult:
        await self.require_superadmin(actor_user_id)
        if target_user_id in self.settings.admin_ids:
            raise InvalidOperation("Нельзя заблокировать superadmin из ADMIN_IDS")

        revoked_key_ids: list[int] = []
        errors: list[KeyOperationError] = []
        if revoke_active_keys:
            if self._vpn_keys is None or not self._key_revokers:
                errors.append(KeyOperationError(0, VpnKeyType.XRAY, "Сервисы отзыва ключей не подключены"))
            else:
                keys = await self._vpn_keys.list_by_owner_statuses(
                    target_user_id,
                    {VpnKeyStatus.ACTIVE, VpnKeyStatus.PENDING_APPLY},
                    limit=500,
                )
                for key in keys:
                    revoker = self._key_revokers.get(key.key_type)
                    if revoker is None:
                        errors.append(KeyOperationError(key.id, key.key_type, "Нет сервиса для отзыва ключа"))
                        continue
                    try:
                        await revoker(actor_user_id, key.id)
                        revoked_key_ids.append(key.id)
                    except Exception as exc:
                        errors.append(KeyOperationError(key.id, key.key_type, str(exc)))

        now = self.clock.now()
        await self.users.set_role(target_user_id, UserRole.BLOCKED_USER, now, blocked_at=now)
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="user_blocked",
            entity_type=AuditEntityType.USER,
            entity_id=target_user_id,
            details={
                "revoke_active_keys": revoke_active_keys,
                "revoked_key_ids": revoked_key_ids,
                "error_count": len(errors),
                "errors": [{"key_id": item.key_id, "key_type": item.key_type.value, "error": item.error} for item in errors],
            },
        )
        user = await self.get_user(target_user_id)
        return BlockUserResult(user=user, revoked_key_ids=tuple(revoked_key_ids), errors=tuple(errors))

    async def list_users(self, actor_user_id: int, limit: int = 20, offset: int = 0) -> list[User]:
        await self.require_superadmin(actor_user_id)
        return await self.users.list_users(limit=limit, offset=offset)

    async def count_keys_for_users(self, actor_user_id: int, user_ids: list[int]) -> dict[int, int]:
        await self.require_superadmin(actor_user_id)
        if self._vpn_keys is None:
            return {}
        return await self._vpn_keys.count_by_owners(user_ids)
