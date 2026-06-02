
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Bot

from adapters.clock import ClockProvider
from models.dto import VpnKey
from models.enums import VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService

logger = logging.getLogger(__name__)


def _add_days(iso_str: str, days: int) -> str:
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt + timedelta(days=days)).isoformat()


class KeyExpiryService:
    def __init__(
        self,
        *,
        vpn_keys: VpnKeyRepository,
        xray: object,
        awg: object,
        audit: AuditService,
        clock: ClockProvider,
        bot: Bot | None = None,
        notify_days: tuple[int, ...] = (),
        backend_health: object | None = None,
    ) -> None:
        self.vpn_keys = vpn_keys
        self.xray = xray
        self.awg = awg
        self.audit = audit
        self.clock = clock
        self.bot = bot
        self.notify_days = notify_days
        self._backend_health = backend_health

    async def revoke_expired_keys(self) -> int:
        """Revoke all active keys whose expiry has passed and notify their owners."""
        now = self.clock.now()
        expired = await self.vpn_keys.list_expired_active(now)
        count = 0
        for key in expired:
            try:
                if key.key_type == VpnKeyType.XRAY:
                    await self.xray.revoke_xray_key_system(key.id)  # type: ignore[attr-defined]
                else:
                    await self.awg.revoke_awg_key_system(key.id)  # type: ignore[attr-defined]
                count += 1
                await self._notify_owner_expired(key)
            except Exception as exc:
                logger.warning(
                    "Не удалось отозвать истёкший ключ key_id=%s owner_user_id=%s key_type=%s reason=%s",
                    key.id,
                    key.owner_user_id,
                    key.key_type.value,
                    exc,
                    exc_info=True,
                )
                if self._backend_health is not None:
                    record = getattr(self._backend_health, "record_skipped_revocation", None)
                    if record is not None:
                        record()
        return count

    async def notify_expiring_keys(self) -> int:
        """Send reminders to owners of keys expiring within the configured lead times."""
        if not self.notify_days or self.bot is None:
            return 0
        now = self.clock.now()
        count = 0
        notified_this_run: set[int] = set()
        # Ascending so a key gets a single reminder at the *smallest* threshold it
        # currently crosses, and the message states its real remaining time — never
        # a contradictory "expires in 7 days" for a key that actually expires
        # tomorrow, and never two reminders for the same key in one run.
        for days in sorted(self.notify_days):
            deadline = _add_days(now, days)
            keys = await self.vpn_keys.list_not_notified_expiring(now, deadline, days)
            for key in keys:
                if key.id in notified_this_run:
                    # Already reminded at a smaller threshold this run; record this
                    # larger threshold as handled so it never re-fires later.
                    await self.vpn_keys.mark_expiry_notified(key.id, days)
                    continue
                remaining = self._remaining_days(now, key.expires_at)
                try:
                    await self._notify_owner_expiring_soon(key, remaining)
                    # mark_expiry_notified is called only if send succeeded
                    await self.vpn_keys.mark_expiry_notified(key.id, days)
                    notified_this_run.add(key.id)
                    count += 1
                except Exception:
                    logger.warning(
                        "Не удалось отправить уведомление об истечении key_id=%s owner_user_id=%s days=%s",
                        key.id,
                        key.owner_user_id,
                        days,
                        exc_info=True,
                    )
        return count

    @staticmethod
    def _remaining_days(now: str, expires_at: str | None) -> int:
        """Return the whole number of days left until expiry (>= 1)."""
        if not expires_at:
            return 1
        try:
            now_dt = datetime.fromisoformat(now)
            exp_dt = datetime.fromisoformat(expires_at)
        except ValueError:
            return 1
        if now_dt.tzinfo is None:
            now_dt = now_dt.replace(tzinfo=timezone.utc)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return max(1, round((exp_dt - now_dt).total_seconds() / 86400))

    async def _notify_owner_expiring_soon(self, key: VpnKey, days: int) -> None:
        if self.bot is None:
            return
        type_label = key.key_type.value.upper()
        noun = _days_noun(days)
        # Let send errors propagate so mark_expiry_notified is not called on failure.
        await self.bot.send_message(
            key.owner_user_id,
            f"Срок действия {type_label}-ключа #{key.id} истекает через {days} {noun}.",
        )

    async def _notify_owner_expired(self, key: VpnKey) -> None:
        if self.bot is None:
            return
        type_label = key.key_type.value.upper()
        try:
            await self.bot.send_message(
                key.owner_user_id,
                f"Срок действия {type_label}-ключа #{key.id} истёк — доступ автоматически отозван.",
            )
        except Exception:  # noqa: S110
            pass


def _days_noun(days: int) -> str:
    if days % 100 in range(11, 20):
        return "дней"
    rem = days % 10
    if rem == 1:
        return "день"
    if rem in (2, 3, 4):
        return "дня"
    return "дней"


async def key_expiry_loop(service: KeyExpiryService, interval: int) -> None:
    """Run expiry notifications and revocations repeatedly at the given interval."""
    while True:
        try:
            notify_count = await service.notify_expiring_keys()
            if notify_count:
                logger.info("Key expiry job: отправлено %d уведомлений об истечении", notify_count)
            count = await service.revoke_expired_keys()
            if count:
                logger.info("Key expiry job: отозвано %d истёкших ключей", count)
        except Exception:
            logger.warning("Key expiry job упал с ошибкой", exc_info=True)
        await asyncio.sleep(interval)
