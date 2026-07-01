
import json
import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 15
# Defensive cap so a misconfigured/hostile endpoint cannot exhaust memory.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class HysteriaStatsUnavailable(RuntimeError):
    """The Hysteria2 Traffic Stats API could not be reached or returned junk.

    Mirrors :class:`adapters.xray_stats.XrayStatsUnavailable`: the caller treats
    it as "backend stats unavailable" and fails soft (preserves stored totals),
    never as an application error.
    """


class HysteriaStatsAdapter:
    """Client for the Hysteria2 (apernet v2) Traffic Stats API.

    A separate authenticated HTTP server exposed by ``hysteria-server`` itself
    (config.yaml ``trafficStats: {listen, secret}``), reachable over loopback:

    * ``GET /traffic``  -> ``{"<id>": {"tx": <bytes>, "rx": <bytes>}}``
    * ``GET /online``   -> ``{"<id>": <conn_count>}``
    * ``POST /kick``    -> body ``["<id>", ...]``

    ``<id>`` is the auth id returned by ``hy2_auth`` — i.e. our key
    ``email_label`` (``hy2_<hex>``). Reads are non-destructive (no ``?clear=1``),
    so per-key views and the background loop can both sample live without
    zeroing counters, exactly like ``xray api statsquery`` without ``-reset``.

    The adapter is only constructed when the operator has configured the API
    (see ``Settings.is_hysteria2_stats_ready``); otherwise the whole hy2
    stats/online/kick surface stays inert.
    """

    def __init__(self, *, listen: str, secret: str, timeout: int = _TIMEOUT_SECONDS) -> None:
        self._base_url = self._build_base_url(listen)
        self._secret = secret
        self._timeout = timeout

    @staticmethod
    def _build_base_url(listen: str) -> str:
        host, sep, port = listen.strip().rpartition(":")
        if not sep or not host:
            raise HysteriaStatsUnavailable(f"Некорректный HYSTERIA2_STATS_LISTEN: {listen!r}")
        host = host.strip("[]")
        # Bracket IPv6 literals for the URL authority ([::1]:9999).
        authority = f"[{host}]" if ":" in host else host
        return f"http://{authority}:{port}"

    @property
    def _headers(self) -> dict[str, str]:
        # The Traffic Stats API authenticates via the Authorization header,
        # which must equal the `trafficStats.secret` from config.yaml.
        return {"Authorization": self._secret}

    async def _get_json(self, path: str) -> Any:
        url = f"{self._base_url}{path}"
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        try:
            # trust_env stays False (default): this is a loopback call and must
            # never be routed through an outbound HTTP(S) proxy from the env.
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=self._headers) as resp:
                    if resp.status != 200:
                        raise HysteriaStatsUnavailable(f"Hysteria2 stats API {path} вернул HTTP {resp.status}")
                    raw = await resp.read()
        except aiohttp.ClientError as exc:
            raise HysteriaStatsUnavailable(f"Hysteria2 stats API недоступен: {exc}") from exc
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise HysteriaStatsUnavailable("Hysteria2 stats API вернул слишком большой ответ")
        try:
            return json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise HysteriaStatsUnavailable("Hysteria2 stats API вернул невалидный JSON") from exc

    async def query_all(self) -> dict[str, tuple[int, int]]:
        """Return ``{label: (uploaded_bytes, downloaded_bytes)}`` from ``GET /traffic``.

        Maps the API's per-user ``tx``/``rx`` to (uploaded, downloaded): ``tx`` is
        traffic uploaded by the client (client->server), ``rx`` is downloaded by
        the client (server->client). Raises :class:`HysteriaStatsUnavailable` on
        any transport/parse fault so the caller can preserve stored totals.
        """
        data = await self._get_json("/traffic")
        if not isinstance(data, dict):
            return {}
        result: dict[str, tuple[int, int]] = {}
        for label, entry in data.items():
            if not isinstance(label, str) or not isinstance(entry, dict):
                continue
            result[label] = (_coerce_int(entry.get("tx")), _coerce_int(entry.get("rx")))
        return result

    async def query_online(self) -> dict[str, int]:
        """Return ``{label: concurrent_connection_count}`` from ``GET /online``.

        Unlike Xray/AWG (where "online" is inferred from counter growth between
        polls) this is a direct instantaneous count, so no baseline is needed.
        """
        data = await self._get_json("/online")
        if not isinstance(data, dict):
            return {}
        return {label: _coerce_int(count) for label, count in data.items() if isinstance(label, str)}

    async def kick(self, labels: list[str]) -> None:
        """Terminate live sessions for the given labels via ``POST /kick``.

        Best-effort by contract of the caller (revoke/delete/expiry): the DB flip
        already blocks new handshakes, so a kick failure must not fail the whole
        operation. Raises :class:`HysteriaStatsUnavailable` for the caller to log.
        """
        clean = [label for label in labels if isinstance(label, str) and label]
        if not clean:
            return
        url = f"{self._base_url}/kick"
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, headers=self._headers, json=clean) as resp:
                    if resp.status != 200:
                        raise HysteriaStatsUnavailable(f"Hysteria2 stats API /kick вернул HTTP {resp.status}")
        except aiohttp.ClientError as exc:
            raise HysteriaStatsUnavailable(f"Hysteria2 stats API /kick недоступен: {exc}") from exc


def _coerce_int(value: object) -> int:
    # JSON numbers decode to int/float; tolerate numeric strings too. bool is an
    # int subclass but is never a meaningful byte count, so treat it as 0.
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, (float, str)):
        try:
            return max(int(value), 0)
        except (TypeError, ValueError):
            return 0
    return 0
