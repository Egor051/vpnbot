"""Background health monitor for the L4 relay.

Modelled on the WARP tunnel monitor (``warp/health.py``): a probe runs every
``RELAY_HEALTH_INTERVAL`` seconds and feeds a time-based latch. After
``fail_window`` seconds of continuous failure the relay is declared *down*, after
``recover_window`` seconds of continuous success it is declared *back up*; a
single opposite probe resets the running window, so one dropped probe never
alerts. Each latch crossing fires its callback exactly once — the admins hear
about a state change, never about every failed probe.

The probe is a TCP connect to ``RELAY_HOST:XRAY_PUBLIC_PORT`` plus a full TLS
handshake with ``server_hostname=XRAY_SNI`` and certificate verification. The bot
runs on the main server, so the probe goes out to the relay and comes straight
back in through its DNAT (a hairpin); REALITY does not recognise the probe as one
of its clients and hands it to the decoy, whose certificate is valid for the SNI.
That makes a passing probe mean "TCP/443 through the relay reaches the main
inbound end to end". Each probe leaves one
``REALITY: processed invalid connection from <relay IP>`` line in Xray's error
log — expected, documented in docs/relay.md.

Deliberately NOT done here:

* UDP (Hysteria2) is not probed — there is no cheap unauthenticated QUIC check
  that proves the forward works; documented.
* ``BackendHealth`` / the Xray degraded flag are not touched: a dead relay does
  not block issuing keys (direct keys are unaffected, and relay keys keep
  working the moment the relay comes back).
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress

from aiogram import Bot

from config.settings import Settings
from i18n import t
from utils.formatting import h

logger = logging.getLogger(__name__)

# Hard ceiling of one probe (connect + handshake), in seconds.
PROBE_TIMEOUT_SECONDS = 10.0


async def tls_probe(host: str, port: int, sni: str, *, timeout: float = PROBE_TIMEOUT_SECONDS) -> bool:
    """TCP connect + verified TLS handshake to ``host:port`` with SNI ``sni``.

    Returns True on a completed handshake whose certificate verifies for *sni*,
    False on anything else (refused, timeout, TLS alert, bad certificate, DNS
    failure). Never raises — only task cancellation propagates.
    """
    context = ssl.create_default_context()
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=context, server_hostname=sni, ssl_handshake_timeout=timeout
            ),
            timeout=timeout,
        )
        return True
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(
            "Relay probe %s:%d (SNI %s) failed: %s: %s", host, port, sni, type(exc).__name__, exc
        )
        return False
    finally:
        if writer is not None:
            writer.close()
            with suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=timeout)


class RelayHealthMonitor:
    """Time-based up/down latch over a probe, with one callback per transition."""

    def __init__(
        self,
        *,
        probe: Callable[[], Awaitable[bool]],
        on_down: Callable[[], Awaitable[None]],
        on_recovered: Callable[[], Awaitable[None]],
        fail_window: float,
        recover_window: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._probe = probe
        self._on_down = on_down
        self._on_recovered = on_recovered
        self._fail_window = fail_window
        self._recover_window = recover_window
        self._clock = clock
        # Assumed up at start: a relay that is down at boot is reported after one
        # fail window, exactly like one that goes down later.
        self._healthy = True
        # Start of the current uninterrupted failure / success run (None while
        # the opposite outcome was seen last).
        self._fail_since: float | None = None
        self._success_since: float | None = None

    @property
    def healthy(self) -> bool:
        return self._healthy

    async def check_once(self) -> bool:
        """Run one probe, advance the latch, fire a callback on a crossing.

        A probe that raises (it should not — :func:`tls_probe` never does) counts
        as a failure; a callback that raises is logged and swallowed. Neither can
        break the loop that calls this.
        """
        try:
            ok = bool(await self._probe())
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Relay probe raised; counting it as a failure", exc_info=True)
            ok = False
        now = self._clock()
        if ok:
            self._fail_since = None
            if self._success_since is None:
                self._success_since = now
            if not self._healthy and now - self._success_since >= self._recover_window:
                self._healthy = True
                await self._notify(self._on_recovered, "recovered")
        else:
            self._success_since = None
            if self._fail_since is None:
                self._fail_since = now
            if self._healthy and now - self._fail_since >= self._fail_window:
                self._healthy = False
                await self._notify(self._on_down, "down")
        return ok

    async def _notify(self, callback: Callable[[], Awaitable[None]], kind: str) -> None:
        logger.warning("Relay health: %s", kind)
        try:
            await callback()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Relay health %s notification failed", kind, exc_info=True)


async def broadcast_to_admins(bot: Bot, admin_ids: frozenset[int], text: str) -> None:
    """Send *text* to every admin; one admin failing never stops the rest."""
    for admin_id in admin_ids:
        try:
            await bot.send_message(admin_id, text)
        except Exception:
            logger.warning("Failed to send relay alert to admin %d", admin_id, exc_info=True)


def build_relay_health_monitor(settings: Settings, bot: Bot) -> RelayHealthMonitor:
    """Wire the monitor to the configured relay and the admins' chats.

    Both windows equal the probe interval, so the relay is reported down after
    two consecutive failed probes (one interval of continuous failure) and back
    up after two consecutive successful ones.
    """
    host = settings.relay_host
    port = settings.xray_public_port
    sni = settings.xray_sni
    params = {"relay": h(settings.relay_name), "host": h(host), "port": port}

    async def probe() -> bool:
        return await tls_probe(host, port, sni)

    async def on_down() -> None:
        await broadcast_to_admins(bot, settings.admin_ids, t("relay_alert_down", **params))

    async def on_recovered() -> None:
        await broadcast_to_admins(bot, settings.admin_ids, t("relay_alert_recovered", **params))

    window = float(settings.relay_health_interval)
    return RelayHealthMonitor(
        probe=probe,
        on_down=on_down,
        on_recovered=on_recovered,
        fail_window=window,
        recover_window=window,
    )


async def relay_health_loop(monitor: RelayHealthMonitor, interval: int) -> None:
    """Probe forever at *interval* seconds; an iteration that fails is logged."""
    while True:
        try:
            await monitor.check_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Relay health check failed", exc_info=True)
        await asyncio.sleep(interval)
