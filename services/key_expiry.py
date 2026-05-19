
import asyncio
import logging

from aiogram import Bot

from adapters.clock import ClockProvider
from models.dto import VpnKey
from models.enums import VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService

logger = logging.getLogger(__name__)


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
    ) -> None:
        self.vpn_keys = vpn_keys
        self.xray = xray
        self.awg = awg
        self.audit = audit
        self.clock = clock
        self.bot = bot

    async def revoke_expired_keys(self) -> int:
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
            except Exception:
                logger.warning(
                    "Не удалось отозвать истёкший ключ key_id=%s owner=%s",
                    key.id,
                    key.owner_user_id,
                    exc_info=True,
                )
        return count

    async def _notify_owner_expired(self, key: VpnKey) -> None:
        if self.bot is None:
            return
        type_label = key.key_type.value.upper()
        try:
            await self.bot.send_message(
                key.owner_user_id,
                f"Срок действия {type_label}-ключа #{key.id} истёк — доступ автоматически отозван.",
            )
        except Exception:
            pass


async def key_expiry_loop(service: KeyExpiryService, interval: int) -> None:
    while True:
        try:
            count = await service.revoke_expired_keys()
            if count:
                logger.info("Key expiry job: отозвано %d истёкших ключей", count)
        except Exception:
            logger.warning("Key expiry job упал с ошибкой", exc_info=True)
        await asyncio.sleep(interval)
