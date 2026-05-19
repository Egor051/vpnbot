
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Bot

from adapters.clock import ClockProvider
from models.dto import TelegramUserProfile, TrialKeyRequest, VpnKey, VpnKeyCreateResult
from models.enums import AuditEntityType, VpnKeyType
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
        audit: AuditService,
        clock: ClockProvider,
        bot: Bot | None = None,
    ) -> None:
        self.trial_requests = trial_requests
        self.users_repo = users_repo
        self.xray = xray
        self.awg = awg
        self.audit = audit
        self.clock = clock
        self.bot = bot

    async def can_request_trial(self, telegram_user_id: int) -> bool:
        reset_at = await self.users_repo.get_trial_quota_reset_at(telegram_user_id)
        used = await self.trial_requests.count_used_since_reset(telegram_user_id, reset_at)
        return used == 0

    async def create_trial_request(
        self, telegram_user_id: int, key_type: VpnKeyType
    ) -> TrialKeyRequest:
        if not await self.can_request_trial(telegram_user_id):
            raise AccessDenied("Вы уже использовали свой пробный доступ")
        now = self.clock.now()
        req = await self.trial_requests.create(
            telegram_user_id=telegram_user_id,
            key_type=key_type,
            requested_at=now,
        )
        await self.audit.write(
            actor_user_id=telegram_user_id,
            action="trial_key_requested",
            entity_type=AuditEntityType.USER,
            entity_id=telegram_user_id,
            details={"key_type": key_type.value, "request_id": req.id},
        )
        return req

    async def get_request(self, request_id: int) -> TrialKeyRequest:
        req = await self.trial_requests.get_by_id(request_id)
        if req is None:
            raise NotFound("Заявка на пробный доступ не найдена")
        return req

    async def list_pending_requests(self, limit: int = 20, offset: int = 0) -> list[TrialKeyRequest]:
        return await self.trial_requests.list_pending(limit=limit, offset=offset)

    async def approve_trial_request(
        self,
        actor_user_id: int,
        request_id: int,
    ) -> VpnKeyCreateResult:
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
        else:
            result = await self.awg.create_awg_key(  # type: ignore[attr-defined]
                actor_user_id,
                profile,
                None,
                expires_at=expires_at,
                allow_pending_owner=True,
            )
        await self.trial_requests.approve(
            request_id=request_id,
            key_id=result.key.id,
            decided_by=actor_user_id,
            decided_at=now,
        )
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
        now = self.clock.now()
        await self.users_repo.reset_trial_quota(target_user_id, now)
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="trial_quota_reset",
            entity_type=AuditEntityType.USER,
            entity_id=target_user_id,
            details={"reset_at": now},
        )

    async def _deliver_key_to_user(self, result: VpnKeyCreateResult, user_id: int) -> None:
        if self.bot is None:
            return
        try:
            if result.key.key_type == VpnKeyType.AWG:
                from bot.messages import send_awg_config
                from bot.messages import awg_config_filename
                # Send AWG config as document
                import io
                from aiogram.types import BufferedInputFile
                config_bytes = result.config_text.encode("utf-8")
                filename = awg_config_filename(result.key)
                await self.bot.send_document(
                    user_id,
                    document=BufferedInputFile(config_bytes, filename=filename),
                    caption=f"Ваш пробный AWG-ключ #{result.key.id} (7 дней). Используйте этот файл для подключения.",
                )
            else:
                await self.bot.send_message(
                    user_id,
                    f"Ваш пробный Xray-ключ #{result.key.id} (7 дней) одобрен!\n\n{result.config_text}",
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
        except Exception:
            pass
