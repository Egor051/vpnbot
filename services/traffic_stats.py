
import asyncio
import logging

from adapters.awg_config import AwgConfigAdapter
from adapters.xray_stats import XrayStatsAdapter
from models.dto import KeyTrafficStatsView, TrafficStats, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.traffic_stats import TrafficStatsRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.errors import AccessDenied, NotFound
from services.users import UserService

logger = logging.getLogger(__name__)
PUBLIC_BACKEND_STATS_ERROR = "Не удалось получить данные от backend"


class TrafficStatsService:
    def __init__(
        self,
        *,
        stats: TrafficStatsRepository,
        vpn_keys: VpnKeyRepository,
        users_repo: UserRepository,
        users: UserService,
        awg: AwgConfigAdapter,
        xray: XrayStatsAdapter,
    ) -> None:
        self.stats = stats
        self.vpn_keys = vpn_keys
        self.users_repo = users_repo
        self.users = users
        self.awg = awg
        self.xray = xray

    async def refresh_for_actor(self, actor_user_id: int, key_id: int) -> KeyTrafficStatsView:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        key = await self.vpn_keys.get_by_id(key_id)
        if key is None or key.status == VpnKeyStatus.DELETED:
            raise NotFound("Ключ не найден")
        if actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
            raise AccessDenied("Нельзя смотреть статистику чужого ключа")
        views = await self.refresh_views([key])
        if not views:
            raise NotFound("Ключ не найден")
        return views[0]

    async def list_for_superadmin(self, actor_user_id: int, limit: int = 20, offset: int = 0) -> list[KeyTrafficStatsView]:
        await self.users.require_superadmin(actor_user_id)
        keys = await self.vpn_keys.list_traffic_supported(limit=limit, offset=offset)
        return await self.refresh_views(keys)

    async def refresh_views(self, keys: list[VpnKey]) -> list[KeyTrafficStatsView]:
        owner_ids: set[int] = set()
        key_ids: list[int] = []
        for key in keys:
            owner_ids.add(key.owner_user_id)
            key_ids.append(key.id)
        owners, current_stats, (awg_transfers, awg_error), (xray_stats, xray_error) = await asyncio.gather(
            self.users_repo.list_by_ids(sorted(owner_ids)),
            self.stats.list_by_key_ids(key_ids),
            self._load_awg_transfers(keys),
            self._load_xray_stats(keys),
        )

        views: list[KeyTrafficStatsView] = []
        for key in keys:
            stats: TrafficStats | None
            if key.key_type == VpnKeyType.AWG:
                stats = await self._refresh_awg_key(key, current_stats.get(key.id), awg_transfers, awg_error)
            elif key.key_type == VpnKeyType.XRAY:
                stats = await self._refresh_xray_key(key, current_stats.get(key.id), xray_stats, xray_error)
            else:
                stats = None
            views.append(KeyTrafficStatsView(key=key, owner=owners.get(key.owner_user_id), stats=stats))
        return views

    async def cached_for_keys(self, keys: list[VpnKey]) -> dict[int, TrafficStats]:
        return await self.stats.list_by_key_ids([key.id for key in keys])

    async def _load_awg_transfers(self, keys: list[VpnKey]) -> tuple[dict[str, tuple[int, int]], str | None]:
        if not any(key.key_type == VpnKeyType.AWG for key in keys):
            return {}, None
        try:
            return await self.awg.list_transfer(), None
        except Exception as exc:
            logger.warning("AWG transfer недоступен: %s", exc, exc_info=True)
            return {}, PUBLIC_BACKEND_STATS_ERROR

    async def _load_xray_stats(self, keys: list[VpnKey]) -> tuple[dict[str, int], str | None]:
        if not any(key.key_type == VpnKeyType.XRAY for key in keys):
            return {}, None
        try:
            return await self.xray.query_all(), None
        except Exception as exc:
            logger.warning("Xray stats API недоступен: %s", exc, exc_info=True)
            return {}, PUBLIC_BACKEND_STATS_ERROR

    async def _refresh_awg_key(
        self,
        key: VpnKey,
        previous: TrafficStats | None,
        transfers: dict[str, tuple[int, int]],
        load_error: str | None,
    ) -> TrafficStats:
        now = self.users.clock.now()
        if load_error:
            return await self.stats.upsert_unavailable(key_id=key.id, reason=load_error, now=now, source="awg/wg transfer")
        if not key.public_key:
            return await self.stats.upsert_unavailable(
                key_id=key.id,
                reason="У AWG-ключа нет public key для сопоставления статистики",
                now=now,
                source="awg/wg transfer",
            )
        raw = transfers.get(key.public_key)
        if raw is None:
            return await self.stats.upsert_unavailable(
                key_id=key.id,
                reason="AWG peer не найден в выводе transfer",
                now=now,
                source="awg/wg transfer",
            )
        received_bytes, sent_bytes = raw
        return await self._store_success(
            key=key,
            previous=previous,
            raw_downloaded_bytes=sent_bytes,
            raw_uploaded_bytes=received_bytes,
            source="awg/wg transfer",
            now=now,
        )

    async def _refresh_xray_key(
        self,
        key: VpnKey,
        previous: TrafficStats | None,
        raw_stats: dict[str, int],
        load_error: str | None,
    ) -> TrafficStats:
        now = self.users.clock.now()
        if load_error:
            return await self.stats.upsert_unavailable(key_id=key.id, reason=load_error, now=now, source="xray statsquery")
        if not key.email_label:
            return await self.stats.upsert_unavailable(
                key_id=key.id,
                reason="У Xray-ключа нет email/label для сопоставления статистики",
                now=now,
                source="xray statsquery",
            )
        raw_downloaded = raw_stats.get(f"user>>>{key.email_label}>>>traffic>>>downlink")
        raw_uploaded = raw_stats.get(f"user>>>{key.email_label}>>>traffic>>>uplink")
        if raw_downloaded is None and raw_uploaded is None:
            return await self.stats.upsert_unavailable(
                key_id=key.id,
                reason="Xray stats API не вернул счётчики для label ключа",
                now=now,
                source="xray statsquery",
            )
        return await self._store_success(
            key=key,
            previous=previous,
            raw_downloaded_bytes=raw_downloaded,
            raw_uploaded_bytes=raw_uploaded,
            source="xray statsquery",
            now=now,
        )

    async def _store_success(
        self,
        *,
        key: VpnKey,
        previous: TrafficStats | None,
        raw_downloaded_bytes: int | None,
        raw_uploaded_bytes: int | None,
        source: str,
        now: str,
    ) -> TrafficStats:
        downloaded, stored_raw_downloaded = self._next_total_for_direction(
            previous.downloaded_bytes if previous else 0,
            previous.last_raw_downloaded_bytes if previous else None,
            raw_downloaded_bytes,
        )
        uploaded, stored_raw_uploaded = self._next_total_for_direction(
            previous.uploaded_bytes if previous else 0,
            previous.last_raw_uploaded_bytes if previous else None,
            raw_uploaded_bytes,
        )
        return await self.stats.upsert_success(
            key_id=key.id,
            downloaded_bytes=downloaded,
            uploaded_bytes=uploaded,
            raw_downloaded_bytes=stored_raw_downloaded,
            raw_uploaded_bytes=stored_raw_uploaded,
            now=now,
            source=source,
        )

    def _next_total_for_direction(
        self,
        previous_total: int,
        previous_raw: int | None,
        current_raw: int | None,
    ) -> tuple[int, int | None]:
        if current_raw is None:
            return previous_total, previous_raw
        return self._next_total(previous_total, previous_raw, current_raw), max(current_raw, 0)

    def _next_total(self, previous_total: int, previous_raw: int | None, current_raw: int) -> int:
        current_raw = max(current_raw, 0)
        if previous_raw is None:
            return max(previous_total, current_raw)
        if current_raw < previous_raw:
            return previous_total + current_raw
        return previous_total + (current_raw - previous_raw)
