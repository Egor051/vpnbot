from __future__ import annotations

from adapters.clock import ClockProvider
from models.access import is_blocked_user
from models.dto import AccessRequest, AccessRequestResult, TelegramUserProfile
from models.enums import AccessRequestStatus, AuditEntityType, UserRole
from repositories.access_requests import AccessRequestRepository
from services.audit import AuditService
from services.errors import InvalidOperation, NotFound
from services.users import UserService


class AccessApprovalService:
    def __init__(
        self,
        *,
        requests: AccessRequestRepository,
        users: UserService,
        clock: ClockProvider,
        audit: AuditService,
    ) -> None:
        self.requests = requests
        self.users = users
        self.clock = clock
        self.audit = audit

    async def create_or_get_request(self, profile: TelegramUserProfile) -> AccessRequestResult:
        async with self.requests.db.transaction():
            user = await self.users.ensure_user(profile)
            blocked = is_blocked_user(user)
            if user.role == UserRole.SUPERADMIN:
                return AccessRequestResult(user=user, request=None, created=False)
            if user.role == UserRole.APPROVED_USER and not blocked:
                return AccessRequestResult(user=user, request=None, created=False)

            pending = await self.requests.get_pending_for_user(profile.telegram_user_id)
            if pending is not None:
                return AccessRequestResult(user=user, request=pending, created=False)

            request, created = await self.requests.create_pending_idempotent(
                profile.telegram_user_id,
                profile.username,
                self.clock.now(),
            )
            if created:
                await self.audit.write(
                    actor_user_id=profile.telegram_user_id,
                    action="access_requested",
                    entity_type=AuditEntityType.ACCESS_REQUEST,
                    entity_id=request.id,
                    details={
                        "telegram_user_id": profile.telegram_user_id,
                        "username": profile.username,
                        "repeat_after_block": is_blocked_user(user),
                    },
                )
            return AccessRequestResult(user=user, request=request, created=created)

    async def approve(self, actor_user_id: int, request_id: int) -> tuple[AccessRequest, bool]:
        await self.users.require_superadmin(actor_user_id)
        async with self.requests.db.transaction():
            request = await self.requests.get_by_id(request_id)
            if request is None:
                raise NotFound("Заявка не найдена")
            changed = await self.requests.set_status_if_pending(
                request_id,
                AccessRequestStatus.APPROVED,
                actor_user_id,
                self.clock.now(),
            )
            if changed:
                await self.users.users.set_role(request.telegram_user_id, UserRole.APPROVED_USER, self.clock.now(), blocked_at=None)
                await self.users.clear_user_state(request.telegram_user_id)
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="access_approved",
                    entity_type=AuditEntityType.ACCESS_REQUEST,
                    entity_id=request_id,
                    details={"telegram_user_id": request.telegram_user_id},
                )
            refreshed = await self.requests.get_by_id(request_id)
            if refreshed is None:
                raise NotFound("Заявка не найдена")
            return refreshed, changed

    async def reject(self, actor_user_id: int, request_id: int) -> tuple[AccessRequest, bool]:
        await self.users.require_superadmin(actor_user_id)
        async with self.requests.db.transaction():
            request = await self.requests.get_by_id(request_id)
            if request is None:
                raise NotFound("Заявка не найдена")
            changed = await self.requests.set_status_if_pending(
                request_id,
                AccessRequestStatus.REJECTED,
                actor_user_id,
                self.clock.now(),
            )
            if changed:
                user = await self.users.users.get_by_id(request.telegram_user_id)
                if user is not None and not is_blocked_user(user):
                    await self.users.users.set_role(request.telegram_user_id, UserRole.PENDING_USER, self.clock.now(), blocked_at=None)
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="access_rejected",
                    entity_type=AuditEntityType.ACCESS_REQUEST,
                    entity_id=request_id,
                    details={"telegram_user_id": request.telegram_user_id},
                )
            refreshed = await self.requests.get_by_id(request_id)
            if refreshed is None:
                raise NotFound("Заявка не найдена")
            return refreshed, changed

    async def list_pending(self, actor_user_id: int, limit: int = 20, offset: int = 0) -> list[AccessRequest]:
        await self.users.require_superadmin(actor_user_id)
        return await self.requests.list_by_status(AccessRequestStatus.PENDING, limit=limit, offset=offset)

    async def get_request(self, actor_user_id: int, request_id: int) -> AccessRequest:
        await self.users.require_superadmin(actor_user_id)
        request = await self.requests.get_by_id(request_id)
        if request is None:
            raise NotFound("Заявка не найдена")
        return request

    async def check_access(self, actor_user_id: int) -> UserRole:
        user = await self.users.get_user(actor_user_id)
        if is_blocked_user(user):
            raise InvalidOperation("Пользователь заблокирован")
        return user.role
