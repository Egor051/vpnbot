
import asyncio
import collections
import logging
import re
import time as time_module
from pathlib import Path

from aiogram import Bot
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from adapters import ip_asn
from adapters.awg_config import AwgConfigAdapter
from i18n import t
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository

logger = logging.getLogger(__name__)

_XRAY_LOG_TAIL_BYTES = 2 * 1024 * 1024  # 2 MB tail read
# Xray access-log timestamps carry no timezone, so they are interpreted in the
# host's local time (time.mktime below), which matches how Xray writes them by
# default and therefore lines up with time.time(). If Xray is (mis)configured to
# log in a different zone, entries land in the future/past and are dropped by the
# cutoff / this skew guard, degrading to "no Xray anomaly signal" rather than a
# wrong one. A small tolerance absorbs benign clock jitter between write and read.
_XRAY_LOG_FUTURE_SKEW_SECONDS = 120.0
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


def _mask_ip_for_log(ip: str) -> str:
    """Reduce an IP to a subnet-ish form for server logs (drop host identity).

    Admins still receive full IPs in the Telegram alert where they are needed to
    act; the server log only needs enough to spot a pattern, so the host portion
    is masked to limit PII sitting in log files.
    """
    if ":" in ip:  # IPv6 — keep the first three hextets, mask the rest
        parts = ip.split(":")
        return ":".join(parts[:3]) + ":*" if len(parts) > 3 else ip
    octets = ip.split(".")
    if len(octets) == 4:
        return ".".join([*octets[:3], "*"])  # /24, host octet masked
    return "*"


def _mask_ips_for_log(ips: frozenset[str], limit: int = 5) -> str:
    """Render a bounded, host-masked sample of IPs for a log line."""
    sample = sorted(ips)
    masked = [_mask_ip_for_log(ip) for ip in sample[:limit]]
    if len(sample) > limit:
        masked.append(f"+{len(sample) - limit}")
    return ", ".join(masked)


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
        unique_nets: int = 3,
        auto_revoke: bool = False,
        cooldown_seconds: int = 7200,
        xray_access_log_path: str = "",
        concurrent_window_seconds: int = 0,
        hysteria_stats: object | None = None,
        hysteria_service: object | None = None,
        hysteria2_max_conn: int = 0,
        bot: Bot | None = None,
        backend_health: object | None = None,
    ) -> None:
        self._vpn_keys = vpn_keys
        self._awg = awg
        self._xray_service = xray_service
        self._awg_service = awg_service
        self._admin_ids = admin_ids
        self._window_seconds = window_seconds
        # Alert threshold, expressed in *distinct networks* (ASN or /24) rather
        # than raw IPs — see adapters.ip_asn.normalize_ip. Counting networks
        # collapses carrier IP rotation and mobile/Wi-Fi switching that would
        # otherwise trip the raw-IP count for a single legitimate user.
        self._min_unique_nets = unique_nets
        self._auto_revoke = auto_revoke
        self._cooldown_seconds = cooldown_seconds
        self._xray_access_log_path = xray_access_log_path
        # Hysteria2 uses a different signal: the Traffic Stats API /online gives an
        # instantaneous per-key concurrent-connection count (there is no usable
        # per-IP feed). When both the adapter and a positive threshold are set, a
        # key with >= hysteria2_max_conn live connections is flagged as sharing.
        self._hysteria_stats = hysteria_stats
        self._hysteria_service = hysteria_service
        self._hysteria2_max_conn = hysteria2_max_conn
        # When > 0, threshold is checked against this shorter window instead of the full window.
        # Prevents false positives from mobile users whose IPs rotate over time.
        # NOTE: the constructor default is 0 (full-window/legacy behaviour); the
        # running bot passes the configured value, whose default is 600 (see
        # config.settings.anomaly_concurrent_window_seconds and docs/configuration.md).
        self._concurrent_window_seconds = concurrent_window_seconds
        # Destructive auto-revoke is only safe when there is a *concurrency*
        # signal: over the full (default 1h) window a single roaming/mobile user
        # legitimately accumulates many IPs and would be wrongly revoked. Require
        # a concurrent window before auto-revoking; otherwise only alert.
        self._auto_revoke_effective = auto_revoke and concurrent_window_seconds > 0
        if auto_revoke and not self._auto_revoke_effective:
            logger.warning(
                "Anomaly auto-revoke is enabled but ANOMALY_CONCURRENT_WINDOW_SECONDS is not set; "
                "auto-revoke is disabled (alert-only) to avoid revoking legitimate roaming users. "
                "Set a concurrent window to enable auto-revoke."
            )
        self.bot = bot
        self._backend_health = backend_health
        # {key_id: deque of (wall_clock_float, source_ip)}
        self._observations: dict[int, collections.deque[tuple[float, str]]] = {}
        # {key_id: last_alerted_wall_clock_float}
        self._last_alerted: dict[int, float] = {}
        # Highest Xray access-log timestamp already ingested. The 2 MB log tail is
        # re-parsed on every scan, so this high-water mark stops a historical line
        # from being re-recorded each scan (which would re-stamp it to "now",
        # doubling the effective window and defeating the concurrent-window check).
        self._xray_log_high_water: float = 0.0

    async def check_all(self) -> None:
        """Sample all backends for connection IPs and fire alerts when thresholds are exceeded."""
        now = time_module.time()
        self._evict_stale_last_alerted(now)
        await self._sample_awg_endpoints(now)
        await self._sample_xray_log(now)
        await self._check_thresholds(now)
        await self._check_hysteria_online(now)

    def _evict_stale_last_alerted(self, now: float) -> None:
        """Drop cooldown timestamps once their cooldown has fully elapsed.

        Past the cooldown the entry no longer suppresses anything, so it can be
        forgotten. Without this, Hysteria2 keys — which never get an observation
        deque and so are never dropped by :meth:`_check_thresholds` — would
        accumulate in ``_last_alerted`` for the process's lifetime.
        """
        if not self._last_alerted:
            return
        horizon = now - self._cooldown_seconds
        for key_id in [kid for kid, ts in self._last_alerted.items() if ts < horizon]:
            del self._last_alerted[key_id]

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
        # Record each connection at its OWN log timestamp (not `now`) and ingest
        # only lines newer than the previous scan's high-water mark. The tail is
        # re-parsed every scan, so recording at `now` and without a high-water gate
        # would re-stamp the same historical line on every scan — persisting an IP
        # for ~2x the window and letting a single past event count as "concurrent"
        # across many scans. The future-skew guard drops timestamps ahead of our
        # clock (e.g. a log written in a different timezone) instead of trusting them.
        future_bound = now + _XRAY_LOG_FUTURE_SKEW_SECONDS
        previous_high_water = self._xray_log_high_water
        max_ts = previous_high_water
        for key_id, ip, ts in entries:
            if ts <= previous_high_water or ts > future_bound:
                continue
            self._record_ip(key_id, ts, ip)
            if ts > max_ts:
                max_ts = ts
        self._xray_log_high_water = max_ts

    def _parse_xray_log_tail(
        self, cutoff: float, label_to_key: dict[str, int]
    ) -> list[tuple[int, str, float]]:
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
        entries: list[tuple[int, str, float]] = []
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
            entries.append((key_id, ip, ts))
        return entries

    # ------------------------------------------------------------ Threshold check

    async def _check_thresholds(self, now: float) -> None:
        for key_id in list(self._observations):
            all_ips = self._unique_ips_in_window(key_id, now)
            if not self._observations[key_id]:
                # All samples aged out of the window; drop the key so the
                # observation maps don't accumulate an entry per key seen.
                del self._observations[key_id]
                self._last_alerted.pop(key_id, None)
            if self._concurrent_window_seconds > 0:
                trigger_ips = self._unique_ips_in_concurrent_window(key_id, now)
            else:
                trigger_ips = all_ips
            # Count distinct networks, not raw IPs: normalize each IP to its ASN
            # (or /24). This is a local bisect lookup — no network/blocking I/O.
            trigger_nets = {ip_asn.normalize_ip(ip) for ip in trigger_ips}
            if len(trigger_nets) < self._min_unique_nets:
                continue
            last = self._last_alerted.get(key_id, 0.0)
            if now - last < self._cooldown_seconds:
                continue
            key = await self._vpn_keys.get_by_id(key_id)
            if key is None or key.status not in {VpnKeyStatus.ACTIVE}:
                continue
            self._last_alerted[key_id] = now
            await self._fire_alert(key, trigger_ips, all_ips)

    # ------------------------------------------------------------------ Alert

    async def _fire_alert(
        self,
        key: VpnKey,
        trigger_ips: frozenset[str],
        all_ips: frozenset[str],
    ) -> None:
        # Log host-masked IPs only: the full IPs go to admins in the Telegram alert
        # below (where they are needed to act), so the server log keeps just enough
        # to spot a pattern without accumulating PII in log files.
        logger.warning(
            "Anomaly: key #%d (%s) owner=%d trigger_ips=%d all_ips=%d ips=%s",
            key.id,
            key.key_type.value.upper(),
            key.owner_user_id,
            len(trigger_ips),
            len(all_ips),
            _mask_ips_for_log(trigger_ips),
        )
        auto_revoked, revoke_error = await self._try_auto_revoke(key, enabled=self._auto_revoke_effective)

        if self.bot is None:
            return

        def _window_str(seconds: int) -> str:
            return f"{seconds // 60} мин" if seconds % 60 == 0 else f"{seconds} сек"

        using_concurrent = self._concurrent_window_seconds > 0 and trigger_ips != all_ips
        ips_for_display = trigger_ips if using_concurrent else all_ips
        # Group the unique raw IPs by their normalized network so the alert reads
        # e.g. "AS8359: 6 IP, AS25513: 1 IP" instead of a flat, noisy IP list.
        # Each network's count is its number of distinct raw IPs.
        net_counts = collections.Counter(
            ip_asn.normalize_ip(ip) for ip in ips_for_display
        )
        groups_str = ", ".join(
            f"{net}: {count} IP" for net, count in net_counts.most_common()
        )

        if using_concurrent:
            all_net_total = len({ip_asn.normalize_ip(ip) for ip in all_ips})
            count_line = (
                f"За последние {_window_str(self._concurrent_window_seconds)}: "
                f"<b>{len(net_counts)} уник. сетей</b> ({len(ips_for_display)} IP) "
                f"(всего за {_window_str(self._window_seconds)}: "
                f"{all_net_total} сетей / {len(all_ips)} IP)"
            )
        else:
            count_line = (
                f"За последние {_window_str(self._window_seconds)}: "
                f"<b>{len(net_counts)} уник. сетей</b> ({len(ips_for_display)} IP)"
            )

        owner_str = f"@{key.username}" if key.username else f"user_id={key.owner_user_id}"
        net_label = (
            f"Сети ({_window_str(self._concurrent_window_seconds)})"
            if using_concurrent
            else "Сети"
        )
        lines = [
            f"⚠️ <b>Аномалия: ключ #{key.id} ({key.key_type.value.upper()})</b>",
            count_line,
            f"Владелец: {owner_str}",
            f"{net_label}: <code>{groups_str}</code>",
        ]
        if auto_revoked:
            lines.append("🔒 <b>Ключ автоматически отозван</b>")
        elif revoke_error:
            lines.append(f"⚠️ Авто-отзыв не удался: {revoke_error[:120]}")
        await self._send_alert_to_admins("\n".join(lines))

    # ------------------------------------------------------ Hysteria2 (conn count)

    async def _check_hysteria_online(self, now: float) -> None:
        """Flag Hysteria2 keys with too many concurrent connections (key sharing).

        Uses the Traffic Stats API /online instantaneous count instead of unique
        IPs. Because the count is inherently a concurrency signal (not a long
        window of rotating mobile IPs), auto-revoke here is gated on the raw
        ``auto_revoke`` flag rather than requiring a concurrent IP window.
        """
        if self._hysteria_stats is None or self._hysteria2_max_conn <= 0:
            return
        try:
            online = await self._hysteria_stats.query_online()  # type: ignore[attr-defined]
        except Exception:
            logger.warning("Failed to fetch Hysteria2 online counts for anomaly detection", exc_info=True)
            return
        if not online:
            return
        active_keys = await self._list_active_keys(VpnKeyType.HYSTERIA2)
        label_to_key: dict[str, VpnKey] = {k.email_label: k for k in active_keys if k.email_label}
        for label, count in online.items():
            if count < self._hysteria2_max_conn:
                continue
            key = label_to_key.get(label)
            if key is None:
                continue
            last = self._last_alerted.get(key.id, 0.0)
            if now - last < self._cooldown_seconds:
                continue
            self._last_alerted[key.id] = now
            await self._fire_hysteria_alert(key, count)

    async def _fire_hysteria_alert(self, key: VpnKey, conn_count: int) -> None:
        logger.warning(
            "Anomaly: key #%d (HYSTERIA2) owner=%d concurrent_conns=%d",
            key.id,
            key.owner_user_id,
            conn_count,
        )
        auto_revoked, revoke_error = await self._try_auto_revoke(key, enabled=self._auto_revoke)
        if self.bot is None:
            return
        owner_str = f"@{key.username}" if key.username else f"user_id={key.owner_user_id}"
        lines = [
            f"⚠️ <b>Аномалия: ключ #{key.id} (HYSTERIA2)</b>",
            f"Одновременных соединений: <b>{conn_count}</b> (порог: {self._hysteria2_max_conn})",
            f"Владелец: {owner_str}",
        ]
        if auto_revoked:
            lines.append("🔒 <b>Ключ автоматически отозван</b>")
        elif revoke_error:
            lines.append(f"⚠️ Авто-отзыв не удался: {revoke_error[:120]}")
        await self._send_alert_to_admins("\n".join(lines))

    # ------------------------------------------------------------------ Alert I/O

    async def _try_auto_revoke(self, key: VpnKey, *, enabled: bool) -> tuple[bool, str | None]:
        """Revoke the key on the backend when auto-revoke is enabled.

        Returns ``(auto_revoked, revoke_error)``; records a skipped revocation on
        the backend-health counter when the revoke raises.
        """
        if not enabled:
            return False, None
        try:
            await self._revoke_key(key)
            return True, None
        except Exception as exc:
            logger.warning(
                "Anomaly auto-revoke failed key_id=%s owner_user_id=%s key_type=%s reason=%s",
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
            return False, str(exc)

    async def _send_alert_to_admins(self, text: str) -> None:
        if self.bot is None:
            return
        keyboard = InlineKeyboardMarkup(
            inline_keyboard=[[InlineKeyboardButton(text=t("btn_anomaly_dismiss"), callback_data="admin:anomaly:dismiss")]]
        )
        for admin_id in self._admin_ids:
            try:
                await self.bot.send_message(admin_id, text, reply_markup=keyboard)
            except Exception:
                logger.warning("Failed to send anomaly alert to admin %d", admin_id, exc_info=True)

    async def _revoke_key(self, key: VpnKey) -> None:
        if key.key_type == VpnKeyType.XRAY:
            await self._xray_service.revoke_xray_key_system(key.id)  # type: ignore[attr-defined]
        elif key.key_type == VpnKeyType.HYSTERIA2:
            await self._hysteria_service.revoke_hysteria2_key_system(key.id)  # type: ignore[union-attr]
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

    def _unique_ips_in_concurrent_window(self, key_id: int, now: float) -> frozenset[str]:
        obs = self._observations.get(key_id)
        if not obs:
            return frozenset()
        cutoff = now - self._concurrent_window_seconds
        return frozenset(ip for ts, ip in obs if ts >= cutoff)

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
    """Run the anomaly detection check repeatedly at the given interval."""
    while True:
        try:
            await service.check_all()
        except Exception:
            logger.warning("Anomaly detection job failed", exc_info=True)
        await asyncio.sleep(interval)
