
import asyncio
import logging
from datetime import datetime, timedelta

from aiogram import Bot

from adapters.clock import ClockProvider
from models.access import is_blocked_user
from models.dto import TelegramUserProfile, TrialKeyRequest, VpnKeyCreateResult
from models.enums import AuditEntityType, UserRole, VpnKeyType
from repositories.trial_requests import TrialKeyRequestRepository
from repositories.users import UserRepository
from services.audit import AuditService
from services.errors import AccessDenied, NotFound

logger = logging.getLogger(__name__)

TRIAL_DAYS = 7


def _trial_expires_at(now: str) -> str:
    dt = datetime.fromisoformat(now)
    return (dt + timedelta(days=TRIAL_DAYS)).replace(microsecond=0).isoformat()


class TrialAccessService:
    def __init__(
        self,
        *,
        trial_requests: TrialKeyRequestRepository,
        users_repo: UserRepository,
        xray: object,
        awg: object,
        hysteria: object,
        audit: AuditService,
        clock: ClockProvider,
        bot: Bot | None = None,
    ) -> None:
        self.trial_requests = trial_requests
        self.users_repo = users_repo
        self.xray = xray
        self.awg = awg
        self.hysteria = hysteria
        self.audit = audit
        self.clock = clock
        self.bot = bot
        # Serialises approve/reject of trial requests so that two concurrent
        # admin decisions on the same request cannot both provision a key.
        self._decision_lock = asyncio.Lock()

    async def _require_superadmin(self, actor_user_id: int) -> None:
        """Service-level RBAC: only a superadmin may decide trial requests."""
        actor = await self.users_repo.get_by_id(actor_user_id)
        if actor is None or actor.role != UserRole.SUPERADMIN:
            raise AccessDenied("Недостаточно прав")

    async def can_request_trial(self, telegram_user_id: int) -> bool:
        """Return whether the user still has an unused trial quota."""
        reset_at = await self.users_repo.get_trial_quota_reset_at(telegram_user_id)
        used = await self.trial_requests.count_used_since_reset(telegram_user_id, reset_at)
        return used == 0

    async def create_trial_request(
        self, telegram_user_id: int, key_type: VpnKeyType
    ) -> TrialKeyRequest:
        """Create a pending trial key request after verifying the user's quota."""
        # Defense-in-depth: a blocked user must not be able to create requests
        # even if a handler forgets to gate the call.
        requester = await self.users_repo.get_by_id(telegram_user_id)
        if requester is None:
            raise NotFound("Пользователь не найден")
        if is_blocked_user(requester):
            raise AccessDenied("Доступ заблокирован")
        # BEGIN IMMEDIATE serialises the quota check (SELECT) and the INSERT so
        # that two concurrent double-taps cannot both pass can_request_trial and
        # then both succeed at create.  The idx_trial_requests_one_pending
        # partial unique index provides an additional DB-level guard.
        async with self.trial_requests.db.transaction():
            if not await self.can_request_trial(telegram_user_id):
                raise AccessDenied("Вы уже использовали свой пробный доступ")
            now = self.clock.now()
            req = await self.trial_requests.create(
                telegram_user_id=telegram_user_id,
                key_type=key_type,
                requested_at=now,
            )
        # Audit write is outside the transaction — best-effort, no need to hold
        # the write lock while talking to the audit backend.
        await self.audit.write(
            actor_user_id=telegram_user_id,
            action="trial_key_requested",
            entity_type=AuditEntityType.USER,
            entity_id=telegram_user_id,
            details={"key_type": key_type.value, "request_id": req.id},
        )
        return req

    async def get_request(self, request_id: int) -> TrialKeyRequest:
        """Return a trial key request by id."""
        req = await self.trial_requests.get_by_id(request_id)
        if req is None:
            raise NotFound("Заявка на пробный доступ не найдена")
        return req

    async def count_pending_requests(self, actor_user_id: int) -> int:
        """Return the number of pending trial key requests; requires superadmin."""
        await self._require_superadmin(actor_user_id)
        return await self.trial_requests.count_pending()

    async def list_pending_requests(self, actor_user_id: int, limit: int = 20, offset: int = 0) -> list[TrialKeyRequest]:
        """Return a paginated list of pending trial key requests; requires superadmin."""
        await self._require_superadmin(actor_user_id)
        return await self.trial_requests.list_pending(limit=limit, offset=offset)

    async def approve_trial_request(
        self,
        actor_user_id: int,
        request_id: int,
    ) -> VpnKeyCreateResult:
        """Approve a trial request, provision the key, and deliver it to the user."""
        await self._require_superadmin(actor_user_id)
        # The decision lock + a fresh status re-check inside it guarantee the key
        # is provisioned exactly once even if two admins (or a double-tap) approve
        # the same pending request concurrently. Without it, both would create a
        # key before the DB-level `approve()` guard rejected the loser, leaving an
        # orphaned extra key live on the backend.
        async with self._decision_lock:
            req = await self.get_request(request_id)
            if req.status != "pending":
                raise AccessDenied("Заявка уже обработана")
            owner = await self.users_repo.get_by_id(req.telegram_user_id)
            if owner is None:
                raise NotFound("Пользователь-владелец не найден")
            now = self.clock.now()
            expires_at = _trial_expires_at(now)
            profile = TelegramUserProfile(
                telegram_user_id=owner.telegram_user_id,
                username=owner.username,
                first_name=owner.first_name,
            )
            if req.key_type == VpnKeyType.XRAY:
                result: VpnKeyCreateResult = await self.xray.create_xray_key(  # type: ignore[attr-defined]
                    actor_user_id,
                    profile,
                    None,
                    expires_at=expires_at,
                    allow_pending_owner=True,
                )
            elif req.key_type == VpnKeyType.HYSTERIA2:
                result = await self.hysteria.issue(  # type: ignore[attr-defined]
                    actor_user_id,
                    profile,
                    None,
                    expires_at=expires_at,
                    allow_pending_owner=True,
                )
            else:
                result = await self.awg.create_awg_key(  # type: ignore[attr-defined]
                    actor_user_id,
                    profile,
                    None,
                    expires_at=expires_at,
                    allow_pending_owner=True,
                )
            try:
                await self.trial_requests.approve(
                    request_id=request_id,
                    key_id=result.key.id,
                    decided_by=actor_user_id,
                    decided_at=now,
                )
            except Exception:
                # The key was already provisioned on the backend. If we cannot mark
                # the request approved, it stays pending and a retry would provision
                # a *second* key. Best-effort revoke the orphan so no live key
                # survives a still-pending request, then re-raise the original error.
                await self._rollback_provisioned_trial_key(req.key_type, result.key.id, actor_user_id)
                raise
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="trial_key_approved",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=result.key.id,
            details={
                "owner_user_id": owner.telegram_user_id,
                "key_type": req.key_type.value,
                "expires_at": expires_at,
                "request_id": request_id,
            },
        )
        await self._deliver_key_to_user(result, owner.telegram_user_id)
        return result

    async def reject_trial_request(self, actor_user_id: int, request_id: int) -> None:
        """Reject a pending trial request and notify the requester."""
        await self._require_superadmin(actor_user_id)
        # Same lock as approve: prevents reject from racing a concurrent approve
        # of the same request (which could otherwise orphan a provisioned key).
        async with self._decision_lock:
            req = await self.get_request(request_id)
            if req.status != "pending":
                raise AccessDenied("Заявка уже обработана")
            now = self.clock.now()
            await self.trial_requests.reject(
                request_id=request_id,
                decided_by=actor_user_id,
                decided_at=now,
            )
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="trial_key_rejected",
            entity_type=AuditEntityType.USER,
            entity_id=req.telegram_user_id,
            details={"request_id": request_id},
        )
        await self._notify_user_rejected(req.telegram_user_id)

    async def admin_reset_trial_quota(self, actor_user_id: int, target_user_id: int) -> None:
        """Reset a user's trial quota so they can request another trial."""
        await self._require_superadmin(actor_user_id)
        now = self.clock.now()
        await self.users_repo.reset_trial_quota(target_user_id, now)
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="trial_quota_reset",
            entity_type=AuditEntityType.USER,
            entity_id=target_user_id,
            details={"reset_at": now},
        )

    async def _rollback_provisioned_trial_key(
        self, key_type: VpnKeyType, key_id: int, actor_user_id: int
    ) -> None:
        """Best-effort revoke a trial key whose request could not be marked approved.

        Never raises: the caller re-raises the original approve() failure, and a
        rollback failure must not mask it. A failed rollback is logged so an admin
        can clean up the orphaned live key manually.
        """
        try:
            if key_type == VpnKeyType.XRAY:
                await self.xray.revoke_xray_key_system(key_id, actor_user_id=actor_user_id)  # type: ignore[attr-defined]
            elif key_type == VpnKeyType.HYSTERIA2:
                await self.hysteria.revoke_hysteria2_key_system(key_id, actor_user_id=actor_user_id)  # type: ignore[attr-defined]
            else:
                await self.awg.revoke_awg_key_system(key_id, actor_user_id=actor_user_id)  # type: ignore[attr-defined]
        except Exception:
            logger.warning(
                "Не удалось откатить пробный ключ key_id=%s после сбоя approve(); требуется ручная очистка",
                key_id,
                exc_info=True,
            )
            return
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="trial_key_approve_rolled_back",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"key_type": key_type.value},
            )
        except Exception:
            logger.warning("Audit write failed after trial key rollback key_id=%s", key_id, exc_info=True)

    async def _deliver_key_to_user(self, result: VpnKeyCreateResult, user_id: int) -> None:
        if self.bot is None:
            return
        try:
            if result.key.key_type == VpnKeyType.AWG:
                from bot.messages import awg_config_filename
                # Send AWG config as document
                from aiogram.types import BufferedInputFile
                config_bytes = result.config_text.encode("utf-8")
                filename = awg_config_filename(result.key)
                await self.bot.send_document(
                    user_id,
                    document=BufferedInputFile(config_bytes, filename=filename),
                    caption=f"Ваш пробный AWG-ключ #{result.key.id} (7 дней). Используйте этот файл для подключения.",
                )
            else:
                label = "Hysteria2" if result.key.key_type == VpnKeyType.HYSTERIA2 else "Xray"
                await self.bot.send_message(
                    user_id,
                    f"Ваш пробный {label}-ключ #{result.key.id} (7 дней) одобрен!\n\n{result.config_text}",
                )
        except Exception:
            logger.warning("Не удалось доставить пробный ключ пользователю %s", user_id, exc_info=True)

    async def _notify_user_rejected(self, user_id: int) -> None:
        if self.bot is None:
            return
        try:
            await self.bot.send_message(
                user_id,
                "К сожалению, ваша заявка на пробный доступ была отклонена.",
            )
        except Exception:  # noqa: S110
            pass
