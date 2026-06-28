
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from aiogram import Bot

import i18n
from adapters.clock import ClockProvider
from models.dto import User, VpnKey
from models.enums import VpnKeyType
from repositories.users import UserRepository
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
        users: UserRepository,
        xray: object,
        awg: object,
        audit: AuditService,
        clock: ClockProvider,
        hysteria: object | None = None,
        bot: Bot | None = None,
        notify_days: tuple[int, ...] = (),
        backend_health: object | None = None,
    ) -> None:
        self.vpn_keys = vpn_keys
        self.users = users
        self.xray = xray
        self.awg = awg
        self.hysteria = hysteria
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
                elif key.key_type == VpnKeyType.HYSTERIA2:
                    if self.hysteria is None:
                        raise RuntimeError("Hysteria2 service not wired for expiry revocation")
                    await self.hysteria.revoke_hysteria2_key_system(key.id)  # type: ignore[attr-defined]
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
        owners: dict[int, User | None] = {}
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
                owner = await self._owner(owners, key.owner_user_id)
                if owner is not None and not owner.expiry_notifications_enabled:
                    # Opted out of expiry reminders. Skip WITHOUT marking notified so
                    # the reminder can still fire if they re-enable before expiry.
                    continue
                remaining = self._remaining_days(now, key.expires_at)
                try:
                    await self._notify_owner_expiring_soon(key, remaining, owner)
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

    async def _owner(self, cache: dict[int, User | None], owner_user_id: int) -> User | None:
        """Return the key owner, caching lookups within a single run."""
        if owner_user_id not in cache:
            cache[owner_user_id] = await self.users.get_by_id(owner_user_id)
        return cache[owner_user_id]

    async def _notify_owner_expiring_soon(self, key: VpnKey, days: int, owner: User | None) -> None:
        if self.bot is None:
            return
        type_label = key.key_type.value.upper()
        locale = owner.language if owner is not None else None
        with i18n.use_locale(locale):
            noun = _days_noun_for(i18n.resolve_locale(), days)
            message = i18n.t("key_expiry_reminder", type=type_label, id=key.id, days=days, noun=noun)
        # Let send errors propagate so mark_expiry_notified is not called on failure.
        await self.bot.send_message(key.owner_user_id, message)

    async def _notify_owner_expired(self, key: VpnKey) -> None:
        if self.bot is None:
            return
        type_label = key.key_type.value.upper()
        try:
            owner = await self.users.get_by_id(key.owner_user_id)
            locale = owner.language if owner is not None else None
            with i18n.use_locale(locale):
                message = i18n.t("key_expired_revoked", type=type_label, id=key.id)
            await self.bot.send_message(key.owner_user_id, message)
        except Exception:  # noqa: S110
            pass


def _days_noun_for(locale: str, days: int) -> str:
    """Return the day-noun matching the given locale and count."""
    if locale == "en":
        return "day" if days == 1 else "days"
    return _days_noun(days)


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
