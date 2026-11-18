"""Background health monitor for the L4 relays — ONE verdict per relay.

Modelled on the WARP tunnel monitor (``warp/health.py``): a probe runs every
``RELAY_HEALTH_INTERVAL`` seconds and feeds a time-based latch. A relay's health
has three levels:

* ``ok``   — traffic through the relay reaches this server (TCP, and UDP when it
  is judged) and, for a relay with an agent, the agent answers and its own
  ``vpn-relay-apply check`` passes;
* ``warn`` — traffic passes, but the agent does not answer over SSH or reports a
  problem: keys work, management does not;
* ``down`` — traffic through the relay does not reach this server: its keys do
  not work.

The latch moves to a new level after ``window`` seconds of probes continuously at
that level; a single opposite probe resets the running window, so one dropped
probe never alerts. Each move fires ONE alert naming the level and its one-line
reason — the admins hear about a state change, never about every failed probe,
and never twice (the traffic probe and the agent are one verdict, not two
monitors).

There is ONE loop for every relay (:class:`RelayHealthSupervisor`). Each pass
reads the relays from the database, so a relay added, re-pointed or switched off
in the admin panel is probed accordingly on the next pass with no restart: each
enabled relay has its own latch, keyed by ``relays.id`` — a new relay starts as
healthy, a relay that is switched off or deleted loses its latch, and one
relay's state never affects another's. The latest probe of each relay is kept in
memory for its card in the panel («Проверить сейчас» records there too).

For a relay with an agent the pass also asks the agent ``status`` over SSH (the
relay service's ``poll_agent``): an SSH failure, or a ``check`` exit code other
than 0 / 13 / 14 (13/14 — the relay cannot reach this server by itself — are
judged by the hairpin probe instead), makes an otherwise passing relay ``warn``.

The probe is a TCP connect to ``<relay host>:XRAY_PUBLIC_PORT`` plus a full TLS
handshake with ``server_hostname=XRAY_SNI`` and certificate verification. The bot
runs on the main server, so the probe goes out to the relay and comes straight
back in through its DNAT (a hairpin); REALITY does not recognise the probe as one
of its clients and hands it to the decoy, whose certificate is valid for the SNI.
That makes a passing probe mean "TCP/443 through the relay reaches the main
inbound end to end". Each probe leaves one
``REALITY: processed invalid connection from <relay IP>`` line in Xray's error
log — expected, documented in docs/relay.md.

UDP (Hysteria2), when it is enabled: a QUIC packet with a reserved ("greasing")
version, padded to 1200 bytes, to ``<relay host>:HYSTERIA2_PORT``. Every QUIC server
must answer an unknown version with a Version Negotiation packet (RFC 9000 §6) that
echoes both connection IDs — no handshake, no credentials, and through the relay's
UDP DNAT it is again a hairpin to this host's hysteria-server. The same packet to
127.0.0.1 first is the control: when this host's own server does not answer it
either, UDP is "not judged" (None) — never "down".

Deliberately NOT done here:

* ``BackendHealth`` / the Xray degraded flag are not touched: a dead relay does
  not block issuing keys (direct keys are unaffected, and relay keys keep
  working the moment the relay comes back).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from aiogram import Bot
from aiogram.types import InlineKeyboardMarkup

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


# QUIC version negotiation (RFC 9000 §6, §17.2.1). 0x?a?a?a?a versions are reserved
# for greasing: no server supports one, so every server answers with a VN packet —
# quic-go (hysteria-server) only when the datagram is at least 1200 bytes.
QUIC_GREASE_VERSION = bytes.fromhex("1a2a3a4a")
QUIC_MIN_DATAGRAM = 1200
UDP_PROBE_TIMEOUT_SECONDS = 4.5


def quic_vn_request(dcid: bytes, scid: bytes) -> bytes:
    header = bytes([0xC0]) + QUIC_GREASE_VERSION + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return header + bytes(QUIC_MIN_DATAGRAM - len(header))


def is_version_negotiation(data: bytes, *, dcid: bytes, scid: bytes) -> bool:
    """A VN packet answering OUR request: long header, version 0, the IDs swapped."""
    if len(data) < 7 or not data[0] & 0x80 or data[1:5] != b"\x00\x00\x00\x00":
        return False
    pos = 5
    got_dcid = data[pos + 1 : pos + 1 + data[pos]]
    pos += 1 + data[pos]
    if pos >= len(data):
        return False
    got_scid = data[pos + 1 : pos + 1 + data[pos]]
    pos += 1 + data[pos]
    versions = data[pos:]
    return got_dcid == scid and got_scid == dcid and len(versions) >= 4 and len(versions) % 4 == 0


async def quic_probe(host: str, port: int, *, timeout: float = UDP_PROBE_TIMEOUT_SECONDS) -> bool:
    """True when ``host:port`` answers a QUIC version-negotiation request. Never raises
    (only cancellation propagates); sends the request up to three times (UDP)."""
    loop = asyncio.get_running_loop()
    dcid, scid = os.urandom(8), os.urandom(8)
    answered: asyncio.Future[bool] = loop.create_future()

    class _Protocol(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: tuple[str | object, int]) -> None:
            if not answered.done() and is_version_negotiation(data, dcid=dcid, scid=scid):
                answered.set_result(True)

        def error_received(self, exc: Exception) -> None:  # ICMP port unreachable
            if not answered.done():
                answered.set_result(False)

    transport: asyncio.DatagramTransport | None = None
    try:
        endpoint, _ = await asyncio.wait_for(
            loop.create_datagram_endpoint(_Protocol, remote_addr=(host, port), family=socket.AF_INET),
            timeout=timeout,
        )
        transport = endpoint
        packet = quic_vn_request(dcid, scid)
        for _ in range(3):
            endpoint.sendto(packet)
            try:
                return await asyncio.wait_for(asyncio.shield(answered), timeout=timeout / 3)
            except asyncio.TimeoutError:
                continue
        return False
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("Relay UDP probe %s:%d failed: %s: %s", host, port, type(exc).__name__, exc)
        return False
    finally:
        if transport is not None:
            transport.close()


async def udp_relay_probe(host: str, port: int) -> bool | None:
    """UDP through the relay: True/False, or None when this host's own QUIC server
    does not answer the control probe either (nothing to judge the relay by)."""
    if not await quic_probe("127.0.0.1", port):
        return None
    return await quic_probe(host, port)


LEVEL_OK = "ok"
LEVEL_WARN = "warn"
LEVEL_DOWN = "down"
# The fallback mode (services/fallback.py): a relay the main server cannot reach
# directly any more — its traffic runs client → relay → hub → main — whose hairpin
# probe from here fails. Not "down": it is expected. Moving into or out of this
# level alerts nobody (an alert per RU relay every time the mode is switched would
# be exactly the storm the mode does not need).
LEVEL_HUB = "hub"
LEVELS = (LEVEL_OK, LEVEL_WARN, LEVEL_DOWN, LEVEL_HUB)
LEVEL_ICONS = {LEVEL_OK: "🟢", LEVEL_WARN: "🟡", LEVEL_DOWN: "🔴", LEVEL_HUB: "🛟"}
# `vpn-relay-apply check` exit codes that do not count against the agent: 13/14 =
# the relay cannot reach the upstream by itself (this host may not answer it
# directly) — the hairpin probe from here is what judges the path.
AGENT_CHECK_OK_CODES = frozenset({0, 13, 14})


@dataclass(frozen=True, slots=True)
class AgentCheck:
    """What a relay's agent said in one health pass (the relay service's ``poll_agent``).

    ``ok`` False with ``error_key`` — it did not answer (SSH, refused); with ``rc``
    — it answered and its ``vpn-relay-apply check`` failed with that exit code.
    """

    ok: bool
    rc: int | None = None
    error_key: str | None = None
    error_params: dict[str, object] = field(default_factory=dict, hash=False, compare=False)


def agent_check_from_status(status: dict[str, object]) -> AgentCheck:
    """Judge a ``status`` answer: its ``check.rc`` (no check at all → ok)."""
    check = status.get("check")
    rc = check.get("rc") if isinstance(check, dict) else None
    if not isinstance(rc, int):
        return AgentCheck(ok=True)
    return AgentCheck(ok=rc in AGENT_CHECK_OK_CODES, rc=rc)


class RelayHealthMonitor:
    """Time-based latch over a relay's level, with one callback per level change.

    *probe* returns a level (``ok``/``warn``/``down``) or a bool (True = ok,
    False = down). The latch starts at ``ok`` and moves to another level once the
    probes have been continuously at it for *window* seconds.
    """

    def __init__(
        self,
        *,
        probe: Callable[[], Awaitable[object]],
        on_change: Callable[[str, str], Awaitable[None]],
        window: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._probe = probe
        self._on_change = on_change
        self._window = window
        self._clock = clock
        # Assumed ok at start: a relay that is down at boot is reported after one
        # window, exactly like one that goes down later.
        self._level = LEVEL_OK
        # The level seen since ``_since`` without interruption, while it differs
        # from the latched one (None: the last probe agreed with the latch).
        self._candidate: str | None = None
        self._since: float | None = None

    @property
    def level(self) -> str:
        return self._level

    @property
    def healthy(self) -> bool:
        return self._level == LEVEL_OK

    async def check_once(self) -> str:
        """Run one probe, advance the latch, fire the callback on a change.

        A probe that raises counts as ``down``; a callback that raises is logged
        and swallowed. Neither can break the loop that calls this.
        """
        try:
            raw = await self._probe()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Relay probe raised; counting it as down", exc_info=True)
            raw = LEVEL_DOWN
        observed = raw if raw in LEVELS else (LEVEL_OK if raw is True else LEVEL_DOWN)
        assert isinstance(observed, str)
        now = self._clock()
        if observed == self._level:
            self._candidate = self._since = None
            return observed
        if observed != self._candidate or self._since is None:
            self._candidate, self._since = observed, now
        if now - self._since >= self._window:
            before, self._level = self._level, observed
            self._candidate = self._since = None
            logger.warning("Relay health: %s -> %s", before, observed)
            try:
                await self._on_change(before, observed)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Relay health %s notification failed", observed, exc_info=True)
        return observed


async def broadcast_to_admins(
    bot: Bot, admin_ids: AbstractSet[int], text: str, reply_markup: InlineKeyboardMarkup | None = None
) -> None:
    """Send *text* to every admin; one admin failing never stops the rest."""
    for admin_id in admin_ids:
        try:
            if reply_markup is None:
                await bot.send_message(admin_id, text)
            else:
                await bot.send_message(admin_id, text, reply_markup=reply_markup)
        except Exception:
            logger.warning("Failed to send relay alert to admin %d", admin_id, exc_info=True)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """The outcome of one health pass of one relay, for its card in the panel."""

    # The relay's level is ``ok`` (traffic passes and the agent, if any, is fine).
    ok: bool
    # UTC ISO-8601 instant the probe finished at.
    checked_at: str
    # The host that was probed (the relay's host may have changed since).
    host: str
    # The UDP (Hysteria2) part: None = not probed or not judged (see udp_relay_probe).
    udp: bool | None = None
    # The TCP (TLS through the relay) part.
    tcp: bool = True
    # ok / warn / down — see the module doc.
    level: str = LEVEL_OK
    # The agent's part: None for a relay without one (or not asked).
    agent: AgentCheck | None = None

    @property
    def traffic_ok(self) -> bool:
        return self.tcp and self.udp is not False


def judge(*, tcp: bool, udp: bool | None, agent: AgentCheck | None) -> str:
    """The one verdict: traffic first, then the agent."""
    if not tcp or udp is False:
        return LEVEL_DOWN
    if agent is not None and not agent.ok:
        return LEVEL_WARN
    return LEVEL_OK


def health_reason(probe: ProbeResult, *, port: int, udp_port: int | None = None) -> str:
    """The one line saying why a relay is at its level (in the active locale)."""
    if probe.level == LEVEL_HUB:
        return t("relay_reason_behind_hub")
    if not probe.tcp and probe.udp is False:
        return t("relay_reason_tcp_udp_down", port=port, udp_port=udp_port or port)
    if not probe.tcp:
        return t("relay_reason_tcp_down", port=port)
    if probe.udp is False:
        return t("relay_reason_udp_down", port=udp_port or port)
    agent = probe.agent
    if agent is not None and not agent.ok:
        if agent.error_key:
            return t("relay_reason_agent_unreachable", error=h(t(agent.error_key, **agent.error_params)))
        return t("relay_reason_agent_check", rc=agent.rc)
    udp = "✓" if probe.udp else "—"
    if agent is not None:
        return t("relay_reason_ok_agent", udp=udp)
    return t("relay_reason_ok", udp=udp)


class _Checkable(Protocol):
    async def check_once(self) -> object: ...


class RelayHealthSupervisor:
    """One health loop for every relay; one latch per ``relays.id``.

    *load_relays* returns the relays as the database holds them right now (all of
    them — only the enabled ones are probed). *agent_probe* (the relay service's
    ``poll_agent``) asks a relay's agent for its status; None = traffic only.
    Alerts go to every admin in ``ADMIN_IDS`` once :attr:`bot` is attached
    (bot.app does that): ONE message per level change, naming the relay's label,
    name and host and the one-line reason.
    """

    def __init__(
        self,
        *,
        load_relays: Callable[[], Awaitable[Sequence[Relay]]],
        port: int,
        sni: str,
        admin_ids: AbstractSet[int],
        window: float,
        probe: Callable[..., Awaitable[bool]] | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], str] = _utc_now,
        bot: Bot | None = None,
        udp_probe: Callable[[str], Awaitable[bool | None]] | None = None,
        udp_port: int | None = None,
        agent_probe: Callable[[Relay], Awaitable[AgentCheck | None]] | None = None,
    ) -> None:
        self._load_relays = load_relays
        self._udp_port = udp_port
        self.agent_probe = agent_probe
        self._port = port
        self._sni = sni
        self._admin_ids = admin_ids
        self._window = window
        self._probe = probe
        # Hysteria2 through the relay; None = TCP only (Hysteria2 is off).
        self._udp_probe = udp_probe
        self._clock = clock
        self._wall_clock = wall_clock
        self.bot = bot
        # Latest Relay row per id (the probe and the alert text read it at call
        # time, so a host or label edited in the panel is used on the next probe).
        self._current: dict[int, Relay] = {}
        self._monitors: dict[int, RelayHealthMonitor] = {}
        self._last: dict[int, ProbeResult] = {}
        # The fallback mode's question (FallbackService.behind_hub, attached by
        # bot.app): is this relay one the main server cannot reach directly right
        # now? None — no fallback mode in this process.
        self.behind_hub: Callable[[Relay], bool] | None = None
        # Called after every pass with (relays, the last probe of each) — the fallback
        # mode's automatic switch (services/fallback_auto.py), attached by bot.app.
        self.pass_listeners: list[Callable[[Sequence[Relay], Mapping[int, ProbeResult]], Awaitable[None]]] = []

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

    def level(self, relay_id: int) -> str | None:
        """The latched level of an enabled relay, None if the loop has not seen it."""
        monitor = self._monitors.get(relay_id)
        return None if monitor is None else monitor.level

    def reason(self, probe: ProbeResult) -> str:
        """The one-line reason of a probe (in the active locale)."""
        return health_reason(probe, port=self._port, udp_port=self._udp_port)

    async def _run_probe(self, relay: Relay) -> str:
        probe = self._probe
        if probe is None:
            # Looked up at call time so tests can monkeypatch the module's probe.
            ok = await tls_probe(relay.host, self._port, self._sni)
        else:
            ok = await probe(relay.host, self._port, self._sni)
        udp: bool | None = None
        if self._udp_probe is not None:
            try:
                udp = await self._udp_probe(relay.host)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Relay UDP probe of %s raised", relay.name, exc_info=True)
                udp = False
        agent: AgentCheck | None = None
        # Behind the hub too: the relay service asks the agent THROUGH the hub (its
        # status is kept and a pending input filter confirmed, as for any relay).
        if relay.agent is not None and self.agent_probe is not None:
            try:
                agent = await self.agent_probe(relay)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Relay agent probe of %s raised", relay.name, exc_info=True)
                agent = AgentCheck(ok=False, error_key="internal_error")
        behind = self.behind_hub is not None and self.behind_hub(relay)
        if behind and not (ok and udp is not False):
            # The hairpin from here cannot pass: expected, not "down".
            level = LEVEL_HUB
        else:
            # Up when TCP passes and UDP did not FAIL (None: not judged); then the agent.
            level = judge(tcp=bool(ok), udp=udp, agent=agent)
        self._last[relay.id] = ProbeResult(
            ok=level == LEVEL_OK,
            checked_at=self._wall_clock(),
            host=relay.host,
            udp=udp,
            tcp=bool(ok),
            level=level,
            agent=agent,
        )
        return level

    async def probe_now(self, relay: Relay) -> ProbeResult:
        """«Проверить сейчас»: one pass outside the loop (traffic + agent), recorded for the card.

        It does not feed the latch — the latch decides alerts, and an alert must
        not depend on an admin pressing a button.
        """
        await self._run_probe(relay)
        return self._last[relay.id]

    def _monitor_for(self, relay_id: int) -> RelayHealthMonitor:
        monitor = self._monitors.get(relay_id)
        if monitor is not None:
            return monitor

        async def probe() -> str:
            return await self._run_probe(self._current[relay_id])

        async def on_change(before: str, after: str) -> None:
            # Silent: into «за hub», and back to ok from it (nothing was alerted).
            # Out of it into down / warn alerts as usual: the fallback mode is off
            # and the relay did not come back.
            if after == LEVEL_HUB or (before == LEVEL_HUB and after == LEVEL_OK):
                logger.info("Relay %s: %s -> %s (fallback mode, no alert)", self._current[relay_id].name, before, after)
                return
            await self._broadcast(after, self._current[relay_id])

        monitor = RelayHealthMonitor(probe=probe, on_change=on_change, window=self._window, clock=self._clock)
        self._monitors[relay_id] = monitor
        return monitor

    def alert_text(self, level: str, relay: Relay) -> str:
        """The ONE message of a level change (the reason from the latest probe)."""
        key = {LEVEL_OK: "relay_alert_recovered", LEVEL_WARN: "relay_alert_warn"}.get(level, "relay_alert_down")
        probe = self._last.get(relay.id)
        reason = self.reason(probe) if probe is not None else ""
        return t(key, label=h(relay.label), name=h(relay.name), host=h(relay.host), port=self._port, reason=reason)

    async def _broadcast(self, level: str, relay: Relay) -> None:
        if self.bot is None:
            return
        await broadcast_to_admins(self.bot, self._admin_ids, self.alert_text(level, relay))

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
        for listener in self.pass_listeners:
            try:
                await listener(enabled, dict(self._last))
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("A relay health pass listener failed", exc_info=True)


def build_relay_health_supervisor(
    settings: Settings,
    load_relays: Callable[[], Awaitable[Sequence[Relay]]],
    agent_probe: Callable[[Relay], Awaitable[AgentCheck | None]] | None = None,
) -> RelayHealthSupervisor:
    """Wire the supervisor to the database, the relays' agents and the admins' chats.

    Both windows equal the probe interval, so a relay is reported down after
    two consecutive failed probes (one interval of continuous failure) and back
    up after two consecutive successful ones.
    """
    udp: Callable[[str], Awaitable[bool | None]] | None = None
    if settings.hysteria2_enabled:
        port = settings.hysteria2_port

        async def udp(host: str) -> bool | None:
            # Looked up at call time so tests can monkeypatch the module's probe.
            return await udp_relay_probe(host, port)

    return RelayHealthSupervisor(
        load_relays=load_relays,
        port=settings.xray_public_port,
        sni=settings.xray_sni,
        admin_ids=settings.admin_ids,
        window=float(settings.relay_health_interval),
        udp_probe=udp,
        udp_port=settings.hysteria2_port if settings.hysteria2_enabled else None,
        agent_probe=agent_probe,
    )


async def relay_health_loop(monitor: _Checkable, interval: int, uninstalled: object | None = None) -> None:
    """Probe forever at *interval* seconds; an iteration that fails is logged.

    A relay forwards to THIS host's Xray, so once Xray is removed from the host
    (protocol uninstall marker, *uninstalled*) every probe would fail and alert:
    the passes are skipped instead, re-checked each time.
    """
    while True:
        check = getattr(uninstalled, "is_uninstalled", None)
        if check is None or not check("xray"):
            try:
                await monitor.check_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.warning("Relay health check failed", exc_info=True)
        await asyncio.sleep(interval)
