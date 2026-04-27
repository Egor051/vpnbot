from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from aiogram import Bot
from aiogram.exceptions import TelegramRetryAfter

from models.enums import AuditEntityType
from repositories.users import UserRepository
from services.audit import AuditService
from services.users import UserService

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AnnouncementResult:
    total: int
    success: int
    failed: int


class AnnouncementService:
    def __init__(
        self,
        *,
        users: UserService,
        users_repo: UserRepository,
        audit: AuditService,
        delay_seconds: float = 0.07,
        batch_size: int = 100,
    ) -> None:
        self.users = users
        self.users_repo = users_repo
        self.audit = audit
        self.delay_seconds = delay_seconds
        self.batch_size = max(batch_size, 1)

    async def count_recipients(self, actor_user_id: int) -> int:
        await self.users.require_superadmin(actor_user_id)
        return await self.users_repo.count_announcement_recipients()

    async def send_to_all(
        self,
        *,
        actor_user_id: int,
        bot: Bot,
        from_chat_id: int,
        message_id: int,
    ) -> AnnouncementResult:
        await self.users.require_superadmin(actor_user_id)
        total = 0
        success = 0
        failed = 0
        offset = 0
        while True:
            recipients = await self.users_repo.list_announcement_recipients(limit=self.batch_size, offset=offset)
            if not recipients:
                break
            total += len(recipients)
            for recipient in recipients:
                target_id = recipient.telegram_user_id
                if target_id <= 0:
                    failed += 1
                    logger.warning("Skipping announcement recipient with non-private chat id=%s", target_id)
                    continue
                if await self._copy_message(bot, target_id, from_chat_id, message_id):
                    success += 1
                else:
                    failed += 1
                if self.delay_seconds > 0:
                    await asyncio.sleep(self.delay_seconds)
            offset += len(recipients)

        result = AnnouncementResult(total=total, success=success, failed=failed)
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="admin_announcement_sent",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details={"total": result.total, "success": result.success, "failed": result.failed},
            )
        except Exception:
            logger.warning("Announcement was sent, but audit write failed", exc_info=True)
        return result

    async def _copy_message(self, bot: Bot, target_id: int, from_chat_id: int, message_id: int) -> bool:
        try:
            await bot.copy_message(chat_id=target_id, from_chat_id=from_chat_id, message_id=message_id)
            return True
        except TelegramRetryAfter as exc:
            await asyncio.sleep(max(exc.retry_after, 0))
            try:
                await bot.copy_message(chat_id=target_id, from_chat_id=from_chat_id, message_id=message_id)
                return True
            except Exception:
                logger.warning("Announcement copy retry failed for user_id=%s", target_id, exc_info=True)
                return False
        except Exception:
            logger.warning("Announcement copy failed for user_id=%s", target_id, exc_info=True)
            return False
