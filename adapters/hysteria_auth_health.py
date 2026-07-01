
import logging

import aiohttp

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5


class Hysteria2AuthHealthProbe:
    """Liveness probe for the standalone ``hy2_auth`` data-plane endpoint.

    ``python -m hy2_auth`` exposes ``GET /healthz`` on its loopback bind
    (``HYSTERIA2_AUTH_LISTEN``): 200 ``{"ok": true}`` when it can read ``vpn.db``,
    503 otherwise. That is exactly the condition under which every Hysteria2
    handshake would fail closed, so the bot polls it to drive the
    ``backend_health`` "Hysteria2" entry at parity with the Xray/AWG reconcile
    signal (which also reflects data-plane, not bot, health).

    The probe is read-only, hits loopback only, and never raises: a failure is
    reported as "not healthy" so the caller can mark the backend degraded.
    """

    def __init__(self, *, auth_listen: str, timeout: int = _TIMEOUT_SECONDS) -> None:
        self._url = f"{self._build_base_url(auth_listen)}/healthz"
        self._timeout = timeout

    @staticmethod
    def _build_base_url(listen: str) -> str:
        host, sep, port = listen.strip().rpartition(":")
        if not sep or not host:
            raise ValueError(f"Некорректный HYSTERIA2_AUTH_LISTEN: {listen!r}")
        host = host.strip("[]")
        # Bracket IPv6 literals for the URL authority ([::1]:8444).
        authority = f"[{host}]" if ":" in host else host
        return f"http://{authority}:{port}"

    async def healthy(self) -> bool:
        """Return whether hy2_auth answered ``GET /healthz`` with HTTP 200.

        Never raises: any transport error or non-200 status maps to ``False`` so
        the health loop treats it as a degraded data plane, not an app error.
        trust_env stays False (default): this is a loopback call and must never be
        routed through an outbound HTTP(S) proxy from the environment.
        """
        timeout = aiohttp.ClientTimeout(total=self._timeout)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(self._url) as resp:
                    return resp.status == 200
        except aiohttp.ClientError:
            return False
        except Exception:
            logger.debug("hy2_auth health probe raised unexpectedly", exc_info=True)
            return False
