
import asyncio
import collections
import logging
import re
import time as time_module
from pathlib import Path

from aiogram import Bot

from adapters.awg_config import AwgConfigAdapter
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository

logger = logging.getLogger(__name__)

_XRAY_LOG_TAIL_BYTES = 2 * 1024 * 1024  # 2 MB tail read
_XRAY_LOG_RE = re.compile(
    r"from ([\d.]+|\[[\da-fA-F:]+\]):\d+.*?email: (\S+)"
)
_XRAY_TS_RE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")


def _parse_xray_log_timestamp(line: str) -> float | None:
    m = _XRAY_TS_RE.match(line)
    if not m:
        return None
    try:
        t = time_module.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
        return time_module.mktime(t)
    except ValueError:
        return None


class AnomalyDetectionService:
    def __init__(
        self,
        *,
        vpn_keys: VpnKeyRepository,
        awg: AwgConfigAdapter,
        xray_service: object,
        awg_service: object,
        admin_ids: frozenset[int],
        window_seconds: int = 3600,
        min_unique_ips: int = 3,
        auto_revoke: bool = False,
        cooldown_seconds: int = 7200,
        xray_access_log_path: str = "",
        bot: Bot | None = None,
    ) -> None:
        self._vpn_keys = vpn_keys
        self._awg = awg
        self._xray_service = xray_service
        self._awg_service = awg_service
        self._admin_ids = admin_ids
        self._window_seconds = window_seconds
        self._min_unique_ips = min_unique_ips
        self._auto_revoke = auto_revoke
        self._cooldown_seconds = cooldown_seconds
        self._xray_access_log_path = xray_access_log_path
        self.bot = bot
        # {key_id: deque of (wall_clock_float, source_ip)}
        self._observations: dict[int, collections.deque[tuple[float, str]]] = {}
        # {key_id: last_alerted_wall_clock_float}
        self._last_alerted: dict[int, float] = {}

    async def check_all(self) -> None:
        now = time_module.time()
        await self._sample_awg_endpoints(now)
        await self._sample_xray_log(now)
        await self._check_thresholds(now)

    # ------------------------------------------------------------------ AWG

    async def _sample_awg_endpoints(self, now: float) -> None:
        active_keys = await self._list_active_keys(VpnKeyType.AWG)
        pub_to_key: dict[str, int] = {
            k.public_key: k.id for k in active_keys if k.public_key
        }
        if not pub_to_key:
            return
        try:
            endpoints = await self._awg.list_peer_endpoints()
        except Exception:
            logger.warning("Failed to fetch AWG peer endpoints for anomaly detection", exc_info=True)
            return
        for pub_key, ip in endpoints.items():
            key_id = pub_to_key.get(pub_key)
            if key_id is not None and ip:
                self._record_ip(key_id, now, ip)

    # ------------------------------------------------------------------ Xray

    async def _sample_xray_log(self, now: float) -> None:
        if not self._xray_access_log_path:
            return
        active_keys = await self._list_active_keys(VpnKeyType.XRAY)
        label_to_key: dict[str, int] = {
            k.email_label: k.id for k in active_keys if k.email_label
        }
        if not label_to_key:
            return
        cutoff = now - self._window_seconds
        try:
            entries = await asyncio.to_thread(
                self._parse_xray_log_tail, cutoff, label_to_key
            )
        except Exception:
            logger.warning(
                "Failed to parse Xray access log at %s", self._xray_access_log_path, exc_info=True
            )
            return
        for key_id, ip in entries:
            self._record_ip(key_id, now, ip)

    def _parse_xray_log_tail(
        self, cutoff: float, label_to_key: dict[str, int]
    ) -> list[tuple[int, str]]:
        path = Path(self._xray_access_log_path)
        if not path.exists():
            return []
        size = path.stat().st_size
        read_from = max(0, size - _XRAY_LOG_TAIL_BYTES)
        with path.open("rb") as f:
            if read_from > 0:
                f.seek(read_from)
                f.readline()  # skip possible partial line at seek boundary
            text = f.read().decode("utf-8", errors="replace")
        entries: list[tuple[int, str]] = []
        for line in text.splitlines():
            ts = _parse_xray_log_timestamp(line)
            if ts is None or ts < cutoff:
                continue
            m = _XRAY_LOG_RE.search(line)
            if not m:
                continue
            ip_raw, label = m.group(1), m.group(2)
            key_id = label_to_key.get(label)
            if key_id is None:
                continue
            ip = ip_raw.strip("[]")
            entries.append((key_id, ip))
        return entries

    # ------------------------------------------------------------ Threshold check

    async def _check_thresholds(self, now: float) -> None:
        for key_id in list(self._observations):
            unique_ips = self._unique_ips_in_window(key_id, now)
            if not self._observations[key_id]:
                # All samples aged out of the window; drop the key so the
                # observation maps don't accumulate an entry per key seen.
                del self._observations[key_id]
                self._last_alerted.pop(key_id, None)
            if len(unique_ips) < self._min_unique_ips:
                continue
            last = self._last_alerted.get(key_id, 0.0)
            if now - last < self._cooldown_seconds:
                continue
            key = await self._vpn_keys.get_by_id(key_id)
            if key is None or key.status not in {VpnKeyStatus.ACTIVE}:
                continue
            self._last_alerted[key_id] = now
            await self._fire_alert(key, unique_ips)

    # ------------------------------------------------------------------ Alert

    async def _fire_alert(self, key: VpnKey, unique_ips: frozenset[str]) -> None:
        logger.warning(
            "Anomaly: key #%d (%s) owner=%d unique_ips=%d ips=%s",
            key.id,
            key.key_type.value.upper(),
            key.owner_user_id,
            len(unique_ips),
            sorted(unique_ips),
        )
        auto_revoked = False
        revoke_error: str | None = None
        if self._auto_revoke:
            try:
                await self._revoke_key(key)
                auto_revoked = True
            except Exception as exc:
                revoke_error = str(exc)
                logger.warning("Anomaly auto-revoke failed for key #%d: %s", key.id, exc, exc_info=True)

        if self.bot is None:
            return

        if self._window_seconds % 60 == 0:
            window_str = f"{self._window_seconds // 60} мин"
        else:
            window_str = f"{self._window_seconds} сек"

        ips_sorted = sorted(unique_ips)
        ips_preview = ", ".join(ips_sorted[:10])
        if len(unique_ips) > 10:
            ips_preview += f" + ещё {len(unique_ips) - 10}"

        owner_str = f"@{key.username}" if key.username else f"user_id={key.owner_user_id}"
        lines = [
            f"⚠️ <b>Аномалия: ключ #{key.id} ({key.key_type.value.upper()})</b>",
            f"За последние {window_str}: <b>{len(unique_ips)} уник. IP</b>",
            f"Владелец: {owner_str}",
            f"IP: <code>{ips_preview}</code>",
        ]
        if auto_revoked:
            lines.append("🔒 <b>Ключ автоматически отозван</b>")
        elif revoke_error:
            lines.append(f"⚠️ Авто-отзыв не удался: {revoke_error[:120]}")
        text = "\n".join(lines)

        for admin_id in self._admin_ids:
            try:
                await self.bot.send_message(admin_id, text)
            except Exception:
                logger.warning("Failed to send anomaly alert to admin %d", admin_id, exc_info=True)

    async def _revoke_key(self, key: VpnKey) -> None:
        if key.key_type == VpnKeyType.XRAY:
            await self._xray_service.revoke_xray_key_system(key.id)  # type: ignore[attr-defined]
        else:
            await self._awg_service.revoke_awg_key_system(key.id)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ Helpers

    def _record_ip(self, key_id: int, now: float, ip: str) -> None:
        if key_id not in self._observations:
            self._observations[key_id] = collections.deque()
        self._observations[key_id].append((now, ip))

    def _unique_ips_in_window(self, key_id: int, now: float) -> frozenset[str]:
        obs = self._observations.get(key_id)
        if not obs:
            return frozenset()
        cutoff = now - self._window_seconds
        while obs and obs[0][0] < cutoff:
            obs.popleft()
        return frozenset(ip for _, ip in obs)

    async def _list_active_keys(self, key_type: VpnKeyType) -> list[VpnKey]:
        keys: list[VpnKey] = []
        after_id = 0
        while True:
            batch = await self._vpn_keys.list_by_type_statuses(
                key_type, {VpnKeyStatus.ACTIVE}, limit=500, after_id=after_id
            )
            if not batch:
                break
            keys.extend(batch)
            after_id = batch[-1].id
        return keys


async def anomaly_detection_loop(service: AnomalyDetectionService, interval: int) -> None:
    while True:
        try:
            await service.check_all()
        except Exception:
            logger.warning("Anomaly detection job failed", exc_info=True)
        await asyncio.sleep(interval)
