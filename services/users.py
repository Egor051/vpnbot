
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime

from adapters.clock import ClockProvider
from config.settings import Settings
from models.access import is_blocked_user
from models.dto import BlockUserResult, KeyOperationError, ProxyAccess, TelegramUserProfile, UnblockUserWarning, User, VpnKey
from models.enums import AuditEntityType, ProxyAccessStatus, ProxyAccessType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.user_locks import UserLockManager

KeyRevoker = Callable[[int, int], Awaitable[VpnKey]]
ProxyRevoker = Callable[[int, int, str | None], Awaitable[ProxyAccess]]
StateClearer = Callable[[int], Awaitable[None]]
logger = logging.getLogger(__name__)

UNBLOCK_ACCESS_MAY_EXIST_STATUSES = {
    VpnKeyStatus.ACTIVE,
    VpnKeyStatus.PENDING_APPLY,
    VpnKeyStatus.APPLY_FAILED,
    VpnKeyStatus.PENDING_REVOKE,
    VpnKeyStatus.PENDING_DELETE,
    VpnKeyStatus.DELETE_FAILED,
}
BLOCK_REVOKE_ERROR_ACTIONS = {"user_blocked_with_revoke_errors", "user_block_failed"}
BLOCK_REVOKE_LOOKUP_ACTIONS = BLOCK_REVOKE_ERROR_ACTIONS | {"user_blocked"}


class UserService:
    def __init__(
        self,
        *,
        users: UserRepository,
        settings: Settings,
        clock: ClockProvider,
        audit: AuditService,
        user_locks: UserLockManager | None = None,
    ) -> None:
        self.users = users
        self.settings = settings
        self.clock = clock
        self.audit = audit
        self.user_locks = user_locks or UserLockManager()
        self._vpn_keys: VpnKeyRepository | None = None
        self._key_revokers: dict[VpnKeyType, KeyRevoker] = {}
        self._proxy_accesses: ProxyAccessRepository | None = None
        self._proxy_revokers: dict[ProxyAccessType, ProxyRevoker] = {}
        self._state_clearer: StateClearer | None = None

    def attach_key_management(self, vpn_keys: VpnKeyRepository, revokers: dict[VpnKeyType, KeyRevoker]) -> None:
        self._vpn_keys = vpn_keys
        self._key_revokers = dict(revokers)

    def attach_proxy_access_management(
        self,
        proxy_accesses: ProxyAccessRepository,
        revokers: dict[ProxyAccessType, ProxyRevoker],
    ) -> None:
        self._proxy_accesses = proxy_accesses
        self._proxy_revokers = dict(revokers)

    def attach_state_clearer(self, clearer: StateClearer) -> None:
        self._state_clearer = clearer

    async def bootstrap_admins(self) -> None:
        await self.users.create_admin_placeholders(self.settings.admin_ids, self.clock.now())

    async def clear_user_state(self, telegram_user_id: int) -> None:
        if self._state_clearer is None:
            return
        try:
            await self._state_clearer(telegram_user_id)
        except Exception:
            logger.warning("Не удалось очистить FSM-состояние пользователя %s", telegram_user_id, exc_info=True)

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

    async def require_moderator_or_admin(self, actor_user_id: int) -> User:
        user = await self.get_user(actor_user_id)
        if user.role in {UserRole.SUPERADMIN, UserRole.MODERATOR}:
            return user
        raise AccessDenied("Недостаточно прав")

    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        user = await self.get_user(actor_user_id)
        if user.role in {UserRole.SUPERADMIN, UserRole.MODERATOR}:
            return user
        if is_blocked_user(user):
            raise AccessDenied("Доступ заблокирован")
        if user.role != UserRole.APPROVED_USER:
            raise AccessDenied("Доступ не одобрен")
        return user

    async def can_manage_owner(self, actor_user_id: int, owner_user_id: int) -> bool:
        user = await self.get_user(actor_user_id)
        return user.role == UserRole.SUPERADMIN or actor_user_id == owner_user_id

    async def set_role(self, actor_user_id: int, target_user_id: int, role: UserRole) -> None:
        await self.require_superadmin(actor_user_id)
        if target_user_id in self.settings.admin_ids and role != UserRole.SUPERADMIN:
            raise InvalidOperation("Нельзя изменить роль superadmin из ADMIN_IDS")
        current = await self.get_user(target_user_id)
        if current.role == UserRole.SUPERADMIN and role != UserRole.SUPERADMIN:
            raise InvalidOperation("Нельзя изменить роль superadmin")
        blocked_at = self.clock.now() if role == UserRole.BLOCKED_USER else None
        action = "user_unblocked" if role == UserRole.APPROVED_USER and is_blocked_user(current) else "user_role_changed"
        async with self.users.db.transaction():
            await self.users.set_role(target_user_id, role, self.clock.now(), blocked_at=blocked_at)
            await self.audit.write(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=AuditEntityType.USER,
                entity_id=target_user_id,
                details={"role": role.value},
            )
        if role in {UserRole.BLOCKED_USER, UserRole.APPROVED_USER, UserRole.PENDING_USER}:
            await self.clear_user_state(target_user_id)

    async def approve_access_request_user(
        self,
        actor_user_id: int,
        target_user_id: int,
        *,
        requested_at: str,
    ) -> tuple[User, bool, bool]:
        await self.require_moderator_or_admin(actor_user_id)
        current = await self.get_user(target_user_id)
        if target_user_id in self.settings.admin_ids or current.role == UserRole.SUPERADMIN:
            return current, False, False
        repeat_after_block = is_blocked_user(current)
        if repeat_after_block and not self._request_is_after_block(current.blocked_at, requested_at):
            raise InvalidOperation("Пользователь заблокирован. Сначала разблокируйте пользователя.")
        if current.role == UserRole.APPROVED_USER and not repeat_after_block:
            return current, False, False
        if current.role not in {UserRole.PENDING_USER, UserRole.APPROVED_USER, UserRole.BLOCKED_USER}:
            raise InvalidOperation("Нельзя одобрить пользователя в текущей роли")
        await self.users.set_role(target_user_id, UserRole.APPROVED_USER, self.clock.now(), blocked_at=None)
        await self.clear_user_state(target_user_id)
        return await self.get_user(target_user_id), True, repeat_after_block

    async def reject_access_request_user(self, actor_user_id: int, target_user_id: int) -> tuple[User | None, bool]:
        await self.require_moderator_or_admin(actor_user_id)
        user = await self.users.get_by_id(target_user_id)
        if user is None:
            return None, False
        if user.role == UserRole.SUPERADMIN or is_blocked_user(user) or user.role == UserRole.APPROVED_USER:
            return user, False
        if user.role != UserRole.PENDING_USER:
            raise InvalidOperation("Нельзя отклонить пользователя в текущей роли")
        return user, False

    async def block_user(
        self,
        actor_user_id: int,
        target_user_id: int,
        revoke_active_keys: bool = True,
    ) -> BlockUserResult:
        actor = await self.require_moderator_or_admin(actor_user_id)
        async with self.user_locks.lock(target_user_id):
            if target_user_id in self.settings.admin_ids:
                raise InvalidOperation("Нельзя заблокировать superadmin из ADMIN_IDS")
            target = await self.get_user(target_user_id)
            if target.role == UserRole.SUPERADMIN:
                raise InvalidOperation("Нельзя заблокировать superadmin")
            if actor.role == UserRole.MODERATOR and target.role == UserRole.MODERATOR:
                raise AccessDenied("Модератор не может заблокировать другого модератора")

            revoked_key_ids: list[int] = []
            revoked_proxy_ids: list[int] = []
            errors: list[KeyOperationError] = []
            now = self.clock.now()
            await self.users.set_role(target_user_id, UserRole.BLOCKED_USER, now, blocked_at=now)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="user_blocked",
                entity_type=AuditEntityType.USER,
                entity_id=target_user_id,
                details={
                    "revoke_active_keys": revoke_active_keys,
                    "bot_access_blocked": True,
                    "revoke_pending": revoke_active_keys,
                },
            )
            await self.clear_user_state(target_user_id)
            if revoke_active_keys:
                if self._vpn_keys is None or not self._key_revokers:
                    errors.append(KeyOperationError(0, VpnKeyType.XRAY, "Сервисы отзыва ключей не подключены"))
                else:
                    await self._revoke_all_access_keys(actor_user_id, target_user_id, revoked_key_ids, errors)
                if self._proxy_accesses is not None and self._proxy_revokers:
                    await self._revoke_all_proxy_accesses(actor_user_id, target_user_id, revoked_proxy_ids, errors)

            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="user_blocked_with_revoke_errors" if errors else "user_blocked",
                entity_type=AuditEntityType.USER,
                entity_id=target_user_id,
                details={
                    "revoke_active_keys": revoke_active_keys,
                    "revoked_key_ids": revoked_key_ids,
                    "revoked_proxy_ids": revoked_proxy_ids,
                    "error_count": len(errors),
                    "errors": [{"key_id": item.key_id, "key_type": item.key_type.value, "error": item.error} for item in errors],
                    "bot_access_blocked": True,
                    "vpn_revoke_complete": not errors,
                    "proxy_revoke_complete": not any(getattr(item.key_type, "value", "") in {"socks5", "mtproto"} for item in errors),
                },
            )
            user = await self.get_user(target_user_id)
            return BlockUserResult(
                user=user,
                revoked_key_ids=tuple(revoked_key_ids),
                errors=tuple(errors),
                revoked_proxy_ids=tuple(revoked_proxy_ids),
            )

    async def _revoke_all_access_keys(
        self,
        actor_user_id: int,
        target_user_id: int,
        revoked_key_ids: list[int],
        errors: list[KeyOperationError],
    ) -> None:
        if self._vpn_keys is None:
            errors.append(KeyOperationError(0, VpnKeyType.XRAY, "Сервисы отзыва ключей не подключены"))
            return
        statuses = {
            VpnKeyStatus.ACTIVE,
            VpnKeyStatus.PENDING_APPLY,
            VpnKeyStatus.APPLY_FAILED,
            VpnKeyStatus.PENDING_REVOKE,
            VpnKeyStatus.PENDING_DELETE,
            VpnKeyStatus.DELETE_FAILED,
        }
        processed_success_ids: set[int] = set()
        while True:
            keys = await self._vpn_keys.list_by_owner_statuses(target_user_id, statuses, limit=500)
            if not keys:
                return
            for key in keys:
                if key.id in processed_success_ids:
                    errors.append(KeyOperationError(key.id, key.key_type, "Ключ застрял в активном статусе после отзыва (stuck in re-list)"))
                    continue
                revoker = self._key_revokers.get(key.key_type)
                if revoker is None:
                    errors.append(KeyOperationError(key.id, key.key_type, "Нет сервиса для отзыва ключа"))
                    continue
                try:
                    await revoker(actor_user_id, key.id)
                    revoked_key_ids.append(key.id)
                    processed_success_ids.add(key.id)
                except Exception as exc:
                    errors.append(KeyOperationError(key.id, key.key_type, str(exc)))
            if errors:
                return

    async def _revoke_all_proxy_accesses(
        self,
        actor_user_id: int,
        target_user_id: int,
        revoked_proxy_ids: list[int],
        errors: list[KeyOperationError],
    ) -> None:
        if self._proxy_accesses is None:
            return
        statuses = {
            ProxyAccessStatus.ACTIVE,
            ProxyAccessStatus.PENDING_APPLY,
            ProxyAccessStatus.APPLY_FAILED,
            ProxyAccessStatus.PENDING_REVOKE,
            ProxyAccessStatus.REVOKE_FAILED,
            ProxyAccessStatus.PENDING_DELETE,
            ProxyAccessStatus.DELETE_FAILED,
        }
        processed_success_ids: set[int] = set()
        while True:
            accesses = await self._proxy_accesses.list_by_owner_statuses(target_user_id, statuses, limit=500)
            if not accesses:
                return
            for access in accesses:
                if access.id in processed_success_ids:
                    errors.append(KeyOperationError(access.id, access.access_type, "Прокси-доступ застрял в активном статусе после отзыва (stuck in re-list)"))
                    continue
                revoker = self._proxy_revokers.get(access.access_type)
                if revoker is None:
                    errors.append(KeyOperationError(access.id, access.access_type, "Нет сервиса для отзыва прокси-доступа"))
                    continue
                try:
                    await revoker(actor_user_id, access.id, "hard_block")
                    revoked_proxy_ids.append(access.id)
                    processed_success_ids.add(access.id)
                except Exception as exc:
                    errors.append(KeyOperationError(access.id, access.access_type, str(exc)))
            if errors:
                return

    async def unblock_user(self, actor_user_id: int, target_user_id: int) -> User:
        await self.require_moderator_or_admin(actor_user_id)
        if target_user_id in self.settings.admin_ids:
            raise InvalidOperation("Нельзя изменить роль superadmin из ADMIN_IDS")
        target = await self.get_user(target_user_id)
        if target.role == UserRole.SUPERADMIN:
            raise InvalidOperation("Нельзя изменить роль superadmin")
        async with self.users.db.transaction():
            await self.users.set_role(target_user_id, UserRole.APPROVED_USER, self.clock.now(), blocked_at=None)
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="user_unblocked",
                entity_type=AuditEntityType.USER,
                entity_id=target_user_id,
                details={"role": UserRole.APPROVED_USER.value},
            )
        await self.clear_user_state(target_user_id)
        return await self.get_user(target_user_id)

    async def inspect_unblock_risk(self, actor_user_id: int, target_user_id: int) -> UnblockUserWarning:
        await self.require_moderator_or_admin(actor_user_id)
        if target_user_id in self.settings.admin_ids:
            raise InvalidOperation("Нельзя изменить роль superadmin из ADMIN_IDS")
        target = await self.get_user(target_user_id)
        if target.role == UserRole.SUPERADMIN:
            raise InvalidOperation("Нельзя изменить роль superadmin")

        active_or_problem_key_count = 0
        if self._vpn_keys is not None:
            active_or_problem_key_count = await self._vpn_keys.count_by_owner_statuses(
                target_user_id,
                UNBLOCK_ACCESS_MAY_EXIST_STATUSES,
            )
        if self._proxy_accesses is not None:
            proxy_accesses = await self._proxy_accesses.list_by_owner_statuses(
                target_user_id,
                {
                    ProxyAccessStatus.ACTIVE,
                    ProxyAccessStatus.PENDING_APPLY,
                    ProxyAccessStatus.APPLY_FAILED,
                    ProxyAccessStatus.PENDING_REVOKE,
                    ProxyAccessStatus.REVOKE_FAILED,
                    ProxyAccessStatus.PENDING_DELETE,
                    ProxyAccessStatus.DELETE_FAILED,
                },
                limit=500,
            )
            active_or_problem_key_count += len(proxy_accesses)
        previous_revoke_error_count, last_block_error_at = await self._last_block_revoke_error(target_user_id)

        reasons: list[str] = []
        if previous_revoke_error_count:
            reasons.append(f"предыдущая блокировка завершилась с ошибками отзыва: {previous_revoke_error_count}")
        if active_or_problem_key_count:
            reasons.append(f"ключей в статусах, где VPN-доступ мог сохраниться: {active_or_problem_key_count}")
        return UnblockUserWarning(
            user=target,
            has_warning=bool(reasons),
            active_or_problem_key_count=active_or_problem_key_count,
            previous_revoke_error_count=previous_revoke_error_count,
            last_block_error_at=last_block_error_at,
            reasons=tuple(reasons),
        )

    async def count_users(self, actor_user_id: int) -> int:
        await self.require_moderator_or_admin(actor_user_id)
        return await self.users.count_users()

    async def list_users(self, actor_user_id: int, limit: int = 20, offset: int = 0) -> list[User]:
        await self.require_moderator_or_admin(actor_user_id)
        return await self.users.list_users(limit=limit, offset=offset)

    async def count_keys_for_users(self, actor_user_id: int, user_ids: list[int]) -> dict[int, int]:
        await self.require_moderator_or_admin(actor_user_id)
        if self._vpn_keys is None:
            return {}
        return await self._vpn_keys.count_by_owners(user_ids)

    async def _last_block_revoke_error(self, target_user_id: int) -> tuple[int, str | None]:
        reader = getattr(self.audit, "recent_for_entity", None)
        if reader is None:
            return 0, None
        items = await reader(
            entity_type=AuditEntityType.USER,
            entity_id=target_user_id,
            actions=BLOCK_REVOKE_LOOKUP_ACTIONS,
            limit=5,
        )
        for item in items:
            action = str(item.get("action") or "")
            details = item.get("details")
            details_dict = details if isinstance(details, dict) else {}
            error_count = self._positive_int(details_dict.get("error_count"))
            if action in BLOCK_REVOKE_ERROR_ACTIONS or error_count > 0:
                return max(error_count, 1), str(item.get("created_at") or "") or None
        return 0, None

    def _positive_int(self, value: object) -> int:
        try:
            result = int(value) if value is not None else 0  # type: ignore[call-overload]
        except (TypeError, ValueError):
            return 0
        return max(result, 0)

    def _request_is_after_block(self, blocked_at: str | None, requested_at: str) -> bool:
        if not blocked_at:
            return False
        try:
            blocked = datetime.fromisoformat(blocked_at)
            requested = datetime.fromisoformat(requested_at)
        except ValueError:
            return False
        return requested > blocked

    async def _write_audit_best_effort(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_type: AuditEntityType,
        entity_id: str | int | None,
        details: dict[str, object] | None = None,
    ) -> None:
        writer = getattr(self.audit, "write_best_effort", None)
        if writer is not None:
            await writer(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
            )
            return
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
            )
        except Exception:
            logger.warning("Audit write failed after user operation: action=%s entity_id=%s", action, entity_id, exc_info=True)
