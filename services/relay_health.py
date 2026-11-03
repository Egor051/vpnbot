"""Background health monitor for the L4 relays.

Modelled on the WARP tunnel monitor (``warp/health.py``): a probe runs every
``RELAY_HEALTH_INTERVAL`` seconds and feeds a time-based latch. After
``fail_window`` seconds of continuous failure a relay is declared *down*, after
``recover_window`` seconds of continuous success it is declared *back up*; a
single opposite probe resets the running window, so one dropped probe never
alerts. Each latch crossing fires its callback exactly once — the admins hear
about a state change, never about every failed probe.

There is ONE loop for every relay (:class:`RelayHealthSupervisor`). Each pass
reads the relays from the database, so a relay added, re-pointed or switched off
in the admin panel is probed accordingly on the next pass with no restart: each
enabled relay has its own latch, keyed by ``relays.id`` — a new relay starts as
healthy, a relay that is switched off or deleted loses its latch, and one
relay's state never affects another's. The latest probe of each relay is kept in
memory for its card in the panel («Проверить сейчас» records there too).

The probe is a TCP connect to ``<relay host>:XRAY_PUBLIC_PORT`` plus a full TLS
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
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from aiogram import Bot

from config.settings import Settings
from i18n import t
from models.dto import Relay
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


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The outcome of one probe of one relay, for its card in the panel."""

    ok: bool
    # UTC ISO-8601 instant the probe finished at.
    checked_at: str
    # The host that was probed (the relay's host may have changed since).
    host: str


class _Checkable(Protocol):
    async def check_once(self) -> object: ...


class RelayHealthSupervisor:
    """One health loop for every relay; one latch per ``relays.id``.

    *load_relays* returns the relays as the database holds them right now (all of
    them — only the enabled ones are probed). Alerts go to every admin in
    ``ADMIN_IDS`` once :attr:`bot` is attached (bot.app does that), naming the
    relay's label, name and host.
    """

    def __init__(
        self,
        *,
        load_relays: Callable[[], Awaitable[Sequence[Relay]]],
        port: int,
        sni: str,
        admin_ids: frozenset[int],
        window: float,
        probe: Callable[..., Awaitable[bool]] | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], str] = _utc_now,
        bot: Bot | None = None,
    ) -> None:
        self._load_relays = load_relays
        self._port = port
        self._sni = sni
        self._admin_ids = admin_ids
        self._window = window
        self._probe = probe
        self._clock = clock
        self._wall_clock = wall_clock
        self.bot = bot
        # Latest Relay row per id (the probe and the alert text read it at call
        # time, so a host or label edited in the panel is used on the next probe).
        self._current: dict[int, Relay] = {}
        self._monitors: dict[int, RelayHealthMonitor] = {}
        self._last: dict[int, ProbeResult] = {}

    @property
    def port(self) -> int:
        return self._port

    def last_probe(self, relay_id: int) -> ProbeResult | None:
        """The latest probe of this relay (by the loop or «Проверить сейчас»), if any."""
        return self._last.get(relay_id)

    def healthy(self, relay_id: int) -> bool | None:
        """The latch of an enabled relay: True/False, None if the loop has not seen it."""
        monitor = self._monitors.get(relay_id)
        return None if monitor is None else monitor.healthy

    async def _run_probe(self, relay: Relay) -> bool:
        probe = self._probe
        if probe is None:
            # Looked up at call time so tests can monkeypatch the module's probe.
            ok = await tls_probe(relay.host, self._port, self._sni)
        else:
            ok = await probe(relay.host, self._port, self._sni)
        self._last[relay.id] = ProbeResult(ok=bool(ok), checked_at=self._wall_clock(), host=relay.host)
        return bool(ok)

    async def probe_now(self, relay: Relay) -> ProbeResult:
        """«Проверить сейчас»: one probe outside the loop, recorded for the card.

        It does not feed the latch — the latch decides alerts, and an alert must
        not depend on an admin pressing a button.
        """
        await self._run_probe(relay)
        return self._last[relay.id]

    def _monitor_for(self, relay_id: int) -> RelayHealthMonitor:
        monitor = self._monitors.get(relay_id)
        if monitor is not None:
            return monitor

        async def probe() -> bool:
            return await self._run_probe(self._current[relay_id])

        async def on_down() -> None:
            await self._broadcast("relay_alert_down", self._current[relay_id])

        async def on_recovered() -> None:
            await self._broadcast("relay_alert_recovered", self._current[relay_id])

        monitor = RelayHealthMonitor(
            probe=probe,
            on_down=on_down,
            on_recovered=on_recovered,
            fail_window=self._window,
            recover_window=self._window,
            clock=self._clock,
        )
        self._monitors[relay_id] = monitor
        return monitor

    async def _broadcast(self, key: str, relay: Relay) -> None:
        if self.bot is None:
            return
        text = t(key, label=h(relay.label), name=h(relay.name), host=h(relay.host), port=self._port)
        await broadcast_to_admins(self.bot, self._admin_ids, text)

    async def check_once(self) -> None:
        """One pass: refresh the relay list, then probe every enabled relay once.

        A relay that disappeared or was switched off since the last pass drops
        its latch (and, if deleted, its last probe); a new one starts healthy.
        One relay failing — even its probe raising — never stops the others.
        """
        relays = list(await self._load_relays())
        known = {relay.id for relay in relays}
        enabled = [relay for relay in relays if relay.enabled]
        enabled_ids = {relay.id for relay in enabled}
        for relay_id in [rid for rid in self._monitors if rid not in enabled_ids]:
            del self._monitors[relay_id]
        for relay_id in [rid for rid in self._last if rid not in known]:
            del self._last[relay_id]
        self._current = {relay.id: relay for relay in relays}
        for relay in enabled:
            try:
                await self._monitor_for(relay.id).check_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Relay health check of %s failed", relay.name, exc_info=True)


def build_relay_health_supervisor(
    settings: Settings, load_relays: Callable[[], Awaitable[Sequence[Relay]]]
) -> RelayHealthSupervisor:
    """Wire the supervisor to the database and the admins' chats.

    Both windows equal the probe interval, so a relay is reported down after
    two consecutive failed probes (one interval of continuous failure) and back
    up after two consecutive successful ones.
    """
    return RelayHealthSupervisor(
        load_relays=load_relays,
        port=settings.xray_public_port,
        sni=settings.xray_sni,
        admin_ids=settings.admin_ids,
        window=float(settings.relay_health_interval),
    )


async def relay_health_loop(monitor: _Checkable, interval: int) -> None:
    """Probe forever at *interval* seconds; an iteration that fails is logged."""
    while True:
        try:
            await monitor.check_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Relay health check failed", exc_info=True)
        await asyncio.sleep(interval)
