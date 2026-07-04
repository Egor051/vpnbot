
import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from aiogram import Bot
from aiogram.exceptions import TelegramRetryAfter

from models.dto import RecipientFilter, User
from models.enums import AuditEntityType
from repositories.announcements import AnnouncementBatch, AnnouncementRepository
from repositories.users import UserRepository
from services.audit import AuditService
from services.errors import InvalidOperation, InvalidTransition, NotFound
from services.users import UserService

logger = logging.getLogger(__name__)

# Max attempts when Telegram flood-control (TelegramRetryAfter) throttles a send.
# Each attempt honours the server's retry_after before the next try; after the
# cap the delivery is marked failed and can be retried by resuming the batch.
_MAX_SEND_ATTEMPTS = 3


@dataclass(frozen=True, slots=True)
class AnnouncementResult:
    announcement_id: int | None
    total: int
    success: int
    failed: int
    last_seen_id: int | None = None
    delivered_user_ids: tuple[int, ...] = ()
    failed_user_ids: tuple[int, ...] = ()
    skipped_user_ids: tuple[int, ...] = ()
    cancelled: bool = False


@dataclass(frozen=True, slots=True)
class AnnouncementCancelResult:
    batch: AnnouncementBatch
    changed: bool


class AnnouncementService:
    def __init__(
        self,
        *,
        users: UserService,
        users_repo: UserRepository,
        announcements: AnnouncementRepository | None = None,
        audit: AuditService,
        delay_seconds: float = 0.07,
        batch_size: int = 100,
    ) -> None:
        self.users = users
        self.users_repo = users_repo
        self.announcements = announcements
        self.audit = audit
        self.delay_seconds = delay_seconds
        self.batch_size = max(batch_size, 1)
        # One lock per announcement batch id. The bot is a single process / single
        # event loop, so this serialises every send path for a given batch — the
        # scheduled-due loop and a manual resume can otherwise interleave and
        # deliver the same message twice (both copy_message before either marks the
        # delivery). Entries are tiny and few (one per batch ever sent), so the map
        # is left to grow rather than risk a cleanup racing a waiting sender.
        self._batch_locks: dict[int, asyncio.Lock] = {}

    async def count_recipients(self, actor_user_id: int, *, recipient_filter: RecipientFilter | None = None) -> int:
        """Return the number of users eligible to receive an announcement.

        When ``recipient_filter`` is given the count reflects the segmented
        audience (which may span roles beyond the default approved-users set);
        otherwise it counts the legacy approved-users + superadmins audience.
        """
        await self.users.require_superadmin(actor_user_id)
        if recipient_filter is not None:
            return await self.users_repo.count_segment_recipients(recipient_filter)
        return await self.users_repo.count_announcement_recipients()

    async def list_incomplete_batches(self, actor_user_id: int, *, limit: int = 10) -> list[AnnouncementBatch]:
        """Return announcement batches that have not yet completed, with refreshed counts."""
        await self.users.require_superadmin(actor_user_id)
        if self.announcements is None:
            return []
        batches = await self.announcements.list_incomplete_batches(limit=limit)
        for batch in batches:
            await self.announcements.refresh_batch_counts(batch.id, self._now())
        return await self.announcements.list_incomplete_batches(limit=limit)

    async def send_to_all(
        self,
        *,
        actor_user_id: int,
        bot: Bot,
        from_chat_id: int,
        message_id: int,
        recipient_filter: RecipientFilter | None = None,
    ) -> AnnouncementResult:
        """Broadcast a message to the (optionally segmented) recipients and return the result."""
        await self.users.require_superadmin(actor_user_id)
        if self.announcements is None:
            return await self._send_without_ledger(
                actor_user_id=actor_user_id,
                bot=bot,
                from_chat_id=from_chat_id,
                message_id=message_id,
                recipient_filter=recipient_filter,
            )
        recipients = await self._load_recipient_ids(recipient_filter)
        batch = await self.announcements.create_batch(
            actor_user_id=actor_user_id,
            from_chat_id=from_chat_id,
            message_id=message_id,
            recipient_ids=recipients,
            now=self._now(),
            recipient_filter=recipient_filter,
        )
        return await self.resume_batch(actor_user_id=actor_user_id, bot=bot, announcement_id=batch.id, retry_failed=False)

    async def send_text_to_all(
        self,
        *,
        actor_user_id: int,
        bot: Bot,
        text: str,
    ) -> AnnouncementResult:
        """Broadcast a generated text message to all eligible recipients.

        Unlike :meth:`send_to_all` (which copies an existing message) this sends a
        freshly generated ``text`` — used for system notifications such as the
        maintenance-mode on/off banners. It reuses the same keyset pagination,
        rate-limiting and ``TelegramRetryAfter`` handling, but is best-effort
        (no announcement ledger / resume support).
        """
        await self.users.require_superadmin(actor_user_id)
        total = 0
        success = 0
        failed = 0
        last_seen_id: int | None = None
        delivered_user_ids: list[int] = []
        failed_user_ids: list[int] = []
        skipped_user_ids: list[int] = []
        while True:
            recipients = await self.users_repo.list_announcement_recipients_after(last_seen_id=last_seen_id, limit=self.batch_size)
            if not recipients:
                break
            for recipient in recipients:
                last_seen_id = recipient.telegram_user_id
                total += 1
                target_id = recipient.telegram_user_id
                if target_id <= 0:
                    failed += 1
                    skipped_user_ids.append(target_id)
                    logger.warning("Skipping broadcast recipient with non-private chat id=%s", target_id)
                    continue
                sent, _error = await self._send_text(bot, target_id, text)
                if sent:
                    success += 1
                    delivered_user_ids.append(target_id)
                else:
                    failed += 1
                    failed_user_ids.append(target_id)
                if self.delay_seconds > 0:
                    await asyncio.sleep(self.delay_seconds)

        result = AnnouncementResult(
            announcement_id=None,
            total=total,
            success=success,
            failed=failed,
            last_seen_id=last_seen_id,
            delivered_user_ids=tuple(delivered_user_ids),
            failed_user_ids=tuple(failed_user_ids),
            skipped_user_ids=tuple(skipped_user_ids),
        )
        logger.info(
            "Text broadcast completed: total=%s success=%s failed=%s",
            result.total,
            result.success,
            result.failed,
        )
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="text_broadcast_sent",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details={"total": result.total, "success": result.success, "failed": result.failed},
            )
        except Exception:
            logger.warning("Text broadcast was sent, but audit write failed", exc_info=True)
        return result

    async def resume_batch(
        self,
        *,
        actor_user_id: int,
        bot: Bot,
        announcement_id: int,
        retry_failed: bool = True,
    ) -> AnnouncementResult:
        """Resume sending an unfinished announcement batch and return the delivery result."""
        await self.users.require_superadmin(actor_user_id)
        if self.announcements is None:
            raise RuntimeError("Announcement ledger is not configured")
        batch = await self.announcements.get_batch(announcement_id)
        if batch is None:
            raise NotFound("Объявление не найдено")
        if batch.status == "cancelled":
            raise InvalidOperation("Объявление отменено")
        if batch.status == "completed" or batch.completed_at is not None:
            raise InvalidOperation("Объявление уже завершено")
        if batch.status not in {"pending", "sending", "failed", "scheduled"}:
            raise InvalidOperation("Объявление нельзя возобновить в текущем статусе")
        return await self._send_batch(bot=bot, batch=batch, retry_failed=retry_failed)

    async def schedule_to_all(
        self,
        *,
        actor_user_id: int,
        from_chat_id: int,
        message_id: int,
        scheduled_at: str,
        recipient_filter: RecipientFilter | None = None,
    ) -> AnnouncementBatch:
        """Create an announcement batch scheduled for later delivery to the recipients."""
        await self.users.require_superadmin(actor_user_id)
        if self.announcements is None:
            raise RuntimeError("Announcement ledger is not configured")
        recipients = await self._load_recipient_ids(recipient_filter)
        return await self.announcements.create_batch(
            actor_user_id=actor_user_id,
            from_chat_id=from_chat_id,
            message_id=message_id,
            recipient_ids=recipients,
            now=self._now(),
            scheduled_at=scheduled_at,
            recipient_filter=recipient_filter,
        )

    async def check_and_send_due(self, bot: Bot) -> list[AnnouncementResult]:
        """Send all scheduled announcement batches whose time has arrived."""
        if self.announcements is None:
            return []
        due = await self.announcements.list_due_scheduled_batches(self._now())
        results = []
        for batch in due:
            try:
                result = await self._send_batch(bot=bot, batch=batch, retry_failed=False)
                results.append(result)
            except Exception:
                logger.warning("Failed to send scheduled announcement batch id=%s", batch.id, exc_info=True)
        return results

    async def cancel_batch(self, *, actor_user_id: int, announcement_id: int) -> AnnouncementCancelResult:
        """Cancel an in-progress or scheduled announcement batch."""
        await self.users.require_superadmin(actor_user_id)
        if self.announcements is None:
            raise RuntimeError("Announcement ledger is not configured")
        batch = await self.announcements.get_batch(announcement_id)
        if batch is None:
            raise NotFound("Объявление не найдено")
        if batch.status == "cancelled":
            return AnnouncementCancelResult(batch=batch, changed=False)
        if batch.status == "completed" or batch.completed_at is not None:
            raise InvalidOperation("Объявление уже завершено")
        if batch.status not in {"pending", "sending", "failed", "scheduled"}:
            raise InvalidOperation("Нельзя отменить объявление в текущем статусе")
        await self.announcements.mark_cancelled(batch.id, self._now())
        cancelled = await self.announcements.get_batch(batch.id)
        if cancelled is None:
            raise NotFound("Объявление не найдено")
        return AnnouncementCancelResult(batch=cancelled, changed=True)

    async def _send_without_ledger(
        self,
        *,
        actor_user_id: int,
        bot: Bot,
        from_chat_id: int,
        message_id: int,
        recipient_filter: RecipientFilter | None = None,
    ) -> AnnouncementResult:
        total = 0
        success = 0
        failed = 0
        last_seen_id: int | None = None
        delivered_user_ids: list[int] = []
        failed_user_ids: list[int] = []
        skipped_user_ids: list[int] = []
        while True:
            recipients = await self._fetch_recipient_page(recipient_filter, last_seen_id)
            if not recipients:
                break
            for recipient in recipients:
                last_seen_id = recipient.telegram_user_id
                total += 1
                target_id = recipient.telegram_user_id
                if target_id <= 0:
                    failed += 1
                    skipped_user_ids.append(target_id)
                    logger.warning("Skipping announcement recipient with non-private chat id=%s", target_id)
                    continue
                sent, _error = await self._copy_message(bot, target_id, from_chat_id, message_id)
                if sent:
                    success += 1
                    delivered_user_ids.append(target_id)
                else:
                    failed += 1
                    failed_user_ids.append(target_id)
                if self.delay_seconds > 0:
                    await asyncio.sleep(self.delay_seconds)

        result = AnnouncementResult(
            announcement_id=None,
            total=total,
            success=success,
            failed=failed,
            last_seen_id=last_seen_id,
            delivered_user_ids=tuple(delivered_user_ids),
            failed_user_ids=tuple(failed_user_ids),
            skipped_user_ids=tuple(skipped_user_ids),
        )
        logger.info(
            "Announcement completed: total=%s success=%s failed=%s last_seen_id=%s failed_user_ids=%s skipped_user_ids=%s",
            result.total,
            result.success,
            result.failed,
            result.last_seen_id,
            result.failed_user_ids,
            result.skipped_user_ids,
        )
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="admin_announcement_sent",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details={
                    "total": result.total,
                    "success": result.success,
                    "failed": result.failed,
                    "last_seen_id": result.last_seen_id,
                    "delivered_user_ids": list(result.delivered_user_ids),
                    "failed_user_ids": list(result.failed_user_ids),
                    "skipped_user_ids": list(result.skipped_user_ids),
                },
            )
        except Exception:
            logger.warning("Announcement was sent, but audit write failed", exc_info=True)
        return result

    def _batch_lock(self, announcement_id: int) -> asyncio.Lock:
        lock = self._batch_locks.get(announcement_id)
        if lock is None:
            lock = asyncio.Lock()
            self._batch_locks[announcement_id] = lock
        return lock

    async def _send_batch(self, *, bot: Bot, batch: AnnouncementBatch, retry_failed: bool) -> AnnouncementResult:
        # Serialise all sends for this batch so a scheduled-due run and a manual
        # resume (or two resumes) can never both be inside the send loop at once
        # and double-deliver.
        async with self._batch_lock(batch.id):
            return await self._send_batch_locked(bot=bot, batch=batch, retry_failed=retry_failed)

    async def _send_batch_locked(self, *, bot: Bot, batch: AnnouncementBatch, retry_failed: bool) -> AnnouncementResult:
        if self.announcements is None:
            raise RuntimeError("Announcement ledger is not configured")
        now = self._now()
        await self.announcements.set_batch_status(batch.id, "sending", now)
        if await self._batch_cancelled(batch.id):
            return await self._cancelled_ledger_result(batch.id, last_seen_id=None)
        last_seen_id = 0
        try:
            while True:
                if await self._batch_cancelled(batch.id):
                    return await self._cancelled_ledger_result(batch.id, last_seen_id=last_seen_id or None)
                deliveries = await self.announcements.list_pending_deliveries(
                    batch.id,
                    self.batch_size,
                    after_user_id=last_seen_id,
                    retry_failed=retry_failed,
                )
                if not deliveries:
                    break
                for delivery in deliveries:
                    if await self._batch_cancelled(batch.id):
                        return await self._cancelled_ledger_result(batch.id, last_seen_id=last_seen_id or None)
                    last_seen_id = delivery.user_id
                    now = self._now()
                    if delivery.user_id <= 0:
                        logger.warning("Skipping announcement recipient with non-private chat id=%s", delivery.user_id)
                        await self._mark_delivery_safe(batch.id, delivery.user_id, "skipped", now, "non-private chat id")
                        continue
                    # Recipients are snapshotted when the batch is created; for
                    # scheduled/resumed batches a user may have been blocked or
                    # demoted in the meantime, so re-check eligibility at send time.
                    # Segmented batches re-validate against their stored filter so
                    # the targeted roles/protocols (which can fall outside the
                    # default approved-users audience) are honoured.
                    if batch.recipient_filter is not None:
                        still_eligible = await self.users_repo.is_segment_recipient(delivery.user_id, batch.recipient_filter)
                    else:
                        still_eligible = await self.users_repo.is_announcement_recipient(delivery.user_id)
                    if not still_eligible:
                        logger.info("Skipping announcement recipient no longer eligible id=%s", delivery.user_id)
                        await self._mark_delivery_safe(batch.id, delivery.user_id, "skipped", now, "recipient no longer eligible")
                        continue
                    sent, error = await self._copy_message(bot, delivery.user_id, batch.from_chat_id, batch.message_id)
                    if sent:
                        await self._mark_delivery_safe(batch.id, delivery.user_id, "sent", now)
                    else:
                        await self._mark_delivery_safe(batch.id, delivery.user_id, "failed", now, error or "send failed")
                    if self.delay_seconds > 0:
                        await asyncio.sleep(self.delay_seconds)
        except Exception:
            await self.announcements.set_batch_status(batch.id, "failed", self._now())
            raise

        result = await self._ledger_result(batch.id, last_seen_id=last_seen_id)
        completed = result.failed == 0
        await self.announcements.set_batch_status(batch.id, "completed" if completed else "failed", self._now(), completed=completed)
        await self.announcements.refresh_batch_counts(batch.id, self._now())
        logger.info(
            "Announcement completed: id=%s total=%s success=%s failed=%s last_seen_id=%s failed_user_ids=%s skipped_user_ids=%s",
            result.announcement_id,
            result.total,
            result.success,
            result.failed,
            result.last_seen_id,
            result.failed_user_ids,
            result.skipped_user_ids,
        )
        try:
            await self.audit.write(
                actor_user_id=batch.actor_user_id,
                action="admin_announcement_sent",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=batch.id,
                details={
                    "announcement_id": batch.id,
                    "total": result.total,
                    "success": result.success,
                    "failed": result.failed,
                    "last_seen_id": result.last_seen_id,
                    "delivered_user_ids": list(result.delivered_user_ids),
                    "failed_user_ids": list(result.failed_user_ids),
                    "skipped_user_ids": list(result.skipped_user_ids),
                },
            )
        except Exception:
            logger.warning("Announcement was sent, but audit write failed", exc_info=True)
        return result

    async def _batch_cancelled(self, announcement_id: int) -> bool:
        if self.announcements is None:
            raise RuntimeError("Announcement ledger is not configured")
        batch = await self.announcements.get_batch(announcement_id)
        return batch is not None and batch.status == "cancelled"

    async def _cancelled_ledger_result(self, announcement_id: int, *, last_seen_id: int | None) -> AnnouncementResult:
        result = await self._ledger_result(announcement_id, last_seen_id=last_seen_id)
        logger.info(
            "Announcement cancelled: id=%s total=%s success=%s failed=%s last_seen_id=%s",
            result.announcement_id,
            result.total,
            result.success,
            result.failed,
            result.last_seen_id,
        )
        return AnnouncementResult(
            announcement_id=result.announcement_id,
            total=result.total,
            success=result.success,
            failed=result.failed,
            last_seen_id=result.last_seen_id,
            delivered_user_ids=result.delivered_user_ids,
            failed_user_ids=result.failed_user_ids,
            skipped_user_ids=result.skipped_user_ids,
            cancelled=True,
        )

    async def _ledger_result(self, announcement_id: int, *, last_seen_id: int | None) -> AnnouncementResult:
        if self.announcements is None:
            raise RuntimeError("Announcement ledger is not configured")
        await self.announcements.refresh_batch_counts(announcement_id, self._now())
        batch = await self.announcements.get_batch(announcement_id)
        if batch is None:
            raise NotFound("Объявление не найдено")
        grouped = await self.announcements.delivery_user_ids_grouped(announcement_id)
        delivered = grouped.get("sent", ())
        failed = grouped.get("failed", ())
        skipped = grouped.get("skipped", ())
        return AnnouncementResult(
            announcement_id=announcement_id,
            total=batch.total_count,
            success=len(delivered),
            failed=len(failed) + len(skipped),
            last_seen_id=last_seen_id,
            delivered_user_ids=delivered,
            failed_user_ids=failed,
            skipped_user_ids=skipped,
        )

    async def _fetch_recipient_page(self, recipient_filter: RecipientFilter | None, last_seen_id: int | None) -> list[User]:
        """Fetch one keyset page of recipients, segmented when a filter is given."""
        if recipient_filter is not None:
            return await self.users_repo.list_segment_recipients_after(
                recipient_filter, last_seen_id=last_seen_id, limit=self.batch_size
            )
        return await self.users_repo.list_announcement_recipients_after(last_seen_id=last_seen_id, limit=self.batch_size)

    async def _load_recipient_ids(self, recipient_filter: RecipientFilter | None = None) -> list[int]:
        recipients: list[int] = []
        last_seen_id: int | None = None
        while True:
            batch = await self._fetch_recipient_page(recipient_filter, last_seen_id)
            if not batch:
                break
            recipients.extend(user.telegram_user_id for user in batch)
            last_seen_id = batch[-1].telegram_user_id
        return recipients

    async def _mark_delivery_safe(
        self, announcement_id: int, user_id: int, status: str, now: str, error_text: str | None = None
    ) -> None:
        """Mark a delivery, tolerating a lost race instead of failing the batch.

        The per-batch lock already serialises sends, but if a delivery has somehow
        already advanced out of pending/failed (a duplicate row, or a resume that
        raced past the lock in a future multi-worker deployment) ``mark_delivery``
        raises :class:`InvalidTransition`. Treat that as "already handled" and skip
        the recipient rather than aborting the whole batch into ``failed``.
        """
        if self.announcements is None:
            raise RuntimeError("Announcement ledger is not configured")
        try:
            await self.announcements.mark_delivery(announcement_id, user_id, status, now, error_text)
        except InvalidTransition:
            logger.info(
                "Announcement delivery already finalized, skipping mark: id=%s user_id=%s",
                announcement_id,
                user_id,
            )

    async def _send_with_retry(
        self, send: Callable[[], Awaitable[None]], target_id: int, *, what: str
    ) -> tuple[bool, str | None]:
        """Run ``send`` with bounded retries that honour Telegram flood-control.

        A ``TelegramRetryAfter`` is retried (after sleeping the requested back-off)
        up to :data:`_MAX_SEND_ATTEMPTS` times; any other error fails immediately.
        """
        for attempt in range(1, _MAX_SEND_ATTEMPTS + 1):
            try:
                await send()
                return True, None
            except TelegramRetryAfter as exc:
                if attempt < _MAX_SEND_ATTEMPTS:
                    await asyncio.sleep(max(exc.retry_after, 0))
                    continue
                logger.warning(
                    "%s still throttled after %d attempts for user_id=%s", what, attempt, target_id, exc_info=True
                )
                return False, _public_error_text(exc)
            except Exception as error:
                logger.warning("%s failed for user_id=%s", what, target_id, exc_info=True)
                return False, _public_error_text(error)
        return False, None  # unreachable; keeps the type checker satisfied

    async def _copy_message(self, bot: Bot, target_id: int, from_chat_id: int, message_id: int) -> tuple[bool, str | None]:
        async def _do() -> None:
            await bot.copy_message(chat_id=target_id, from_chat_id=from_chat_id, message_id=message_id)

        return await self._send_with_retry(_do, target_id, what="Announcement copy")

    async def _send_text(self, bot: Bot, target_id: int, text: str) -> tuple[bool, str | None]:
        async def _do() -> None:
            await bot.send_message(chat_id=target_id, text=text)

        return await self._send_with_retry(_do, target_id, what="Text broadcast")

    def _now(self) -> str:
        return self.audit.clock.now()


def _public_error_text(error: Exception) -> str:
    return type(error).__name__
