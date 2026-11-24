"""The fallback mode (hub) — docs/relay.md «Режим фолбэка (hub)».

WHY. The TSPU drops the main server's address at the Russian border in both
directions: clients in Russia, the RU relays and the main server cannot reach each
other, and the main server's egress address cannot change. A relay OUTSIDE Russia
with a clean address — the **hub** — still reaches the main server. In the
fallback mode the hub is the ONLY thing that talks to the main server; every name
of the DNS failover set points at the hub instead:

    client ──► RU relay ──► hub ──► main          (RU relays: RELAY_UPSTREAM_HOST
    client ───────────────► hub ──► main           follows the A record by itself,
                                                    vpn-relay-resolve.timer, 5 min)

Switching the RU relays needs NO connection from the main server to them: they
forward to a DNS name and re-resolve it.

THE HUB. A relay with an agent and the role 'hub' (``relays.role``). It forwards
TCP XRAY_PUBLIC_PORT + SUBSCRIPTION_PUBLIC_PORT and UDP HYSTERIA2_PORT to the
**origin name** — a name that always points at the main server's IPv4 and is
NEVER in the failover set. Without it the hub would forward to a failover name,
and once that name points at the hub, the hub DNATs to ITSELF: a loop, and every
client loses everything. The loop is checked when the role is given and again
before every switch.

THE SWITCH. ``enable``: preflight (one enabled hub whose agent answers, the hub
reaches the main server on both TCP ports by its own check, no loop, every name
has exactly one A record that is not proxied and points at the main server or
the hub) → every name's A record to the hub's IPv4 (``proxied=false``, TTL 60) →
what public resolvers answer, over DoH → the report. ``disable`` writes the main
server's IPv4 back. The mode the admin asked for is kept in schema_meta, what each
write did per name in ``failover_names``: a partial switch is visible name by
name and the same button finishes it. Everything is audited; the DNS API token is
never in a log, the audit or the chat (adapters.cloudflare_dns).

MANAGING the RU relays meanwhile: the main server cannot reach them over SSH either,
so while the mode is on the relay service routes every agent call but the hub's
THROUGH the hub (services/relays.py, «через hub»); the switch rewrites the hub's
jump line to open exactly those relays.

SEAMS left on purpose: :func:`services.relay.select_hub` is where a balancer would
choose among several hubs; :meth:`FallbackService._switch` is the switch without the
superadmin check — the automatic switch on health (services/fallback_auto.py) calls it
with ``actor_user_id=None`` (its preflight asks the hub's agent as the bot itself).

THE PROXIES (docs/proxy.md «Через hub в режиме фолбэка»). SOCKS5 (and MTProto, when on)
are handed out as SOCKS5_HOST:SOCKS5_PORT — main's address, dead for users in Russia in
the mode. The switch adds the port of every proxying module that is on to the hub's TCP
set — the same agent ``apply`` as 443/2096, whose own check proves the hub reaches
main:<port> or rolls the forward back — and the «Прокси» section then shows the hub's
IPv4 with the same port (services/proxy_endpoint.py, ONE source). Switching the mode off
(or the module off) takes the port off the hub again. Chosen at the switch, not with the
hub's role: outside the mode nobody needs main's danted through the hub, and a port the
hub forwards is probed by the hub's own check (its health, its deploy's verify, the
agent's apply) — a danted outage on main must not look like a dead hub, or roll its
update back, while no proxy user needs it. A proxy port that cannot be forwarded never
blocks the switch: the VPN goes first, the report says what the proxies did. Logins and
passwords do not change; only TCP CONNECT works through the hub (danted answers UDP
ASSOCIATE with its own address). Links users already saved still carry main's address:
after a switch that moved a proxy the screen offers «📣 Разослать новую ссылку» — never
sent by itself.

RECONCILED, not only switched (:meth:`FallbackService.reconcile_proxies`). The switch is an
event; a mode turned on BEFORE the bot could forward proxies (an update installed later)
never saw it, and the hub would never get the port. So the hub's proxy ports are brought to
what the mode wants whenever the bot looks: at startup, on every pass of the health loop,
when the screen opens, and with «🔁 Довести прокси до hub». Only the proxy ports are ever
added or taken off — every other port of the hub's set (443/2096 among them), its UDP set
and its upstream go back to the agent exactly as they are. A port whose ``apply`` failed is
not sent again for :data:`RECONCILE_BACKOFF_SECONDS` (the button does not wait), so the
hub is not re-applied every pass and a dead danted never holds the VPN's forward; the
superadmins hear about it ONCE per (port, error), with the agent's own error.

SETTING IT UP (bot/handlers/admin_fallback.py, «⚙️ Настроить фолбэк»): the token
(checked against the zone right away, :meth:`FallbackService.check_zone`), the hub
among the relays with an agent outside Russia (:meth:`hub_candidates`, by the
IP-to-ASN database's country), the origin (``origin.<zone>`` suggested), the
failover set from :meth:`explained_candidates` — every name with WHY it belongs
there, all checked, one confirmation (:meth:`add_names`) — and the preflight.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from adapters.clock import ClockProvider
from adapters.cloudflare_dns import (
    CloudflareDns,
    CloudflareTokenFile,
    DnsApiError,
    DnsRecord,
    DnsTokenMissing,
    DnsZone,
    DohAnswer,
    fingerprint,
    valid_token,
)
from adapters.ip_asn import lookup_country
from config import validators
from config.settings import Settings
from models.dto import RELAY_ROLE_EDGE, RELAY_ROLE_HUB, FailoverName, Relay
from models.enums import AuditEntityType
from repositories.failover import (
    META_DIRECT_HOST,
    META_DIRECT_HOST_AT,
    META_HUB_IPV4,
    META_MAIN_IPV4,
    META_SUB_FALLBACK_URL,
    FailoverRepository,
)
from repositories.relays import RelayRepository
from services.audit import AuditService
from services.errors import InvalidOperation, NotFound, ServiceError
from services.proxy_endpoint import MTPROTO, PROXY_KINDS, SOCKS5, ProxyEndpoint, ProxyEndpoints
from services.relay import select_hub
from services.relay_pairing import format_ports, valid_dns_name
from services.relays import CHECK_OK_CODES, RelayService, agent_uninstalled, only_input_filter_failures
from services.users import UserService

logger = logging.getLogger(__name__)

NORMAL = "normal"
FAILOVER = "failover"
# `vpn-relay-apply check` exit codes a hub may report and still be fit: 0, or only
# the input filter's own complaints (16-18) — not the forward, not the upstream.
_HUB_CHECK_OK = CHECK_OK_CODES
# `vpn-relay-apply check`: TCP connect to the upstream failed (on a forwarded TCP port).
_E_TCP = 13
# How long the switch waits for public resolvers to agree, and how often it asks.
VERIFY_TIMEOUT_SECONDS = 30.0
VERIFY_INTERVAL_SECONDS = 5.0
# schema_meta (failover settings): «Автопереключение» — "1" on, anything else off.
META_AUTO_SWITCH = "fallback_auto_switch"
# The switch's steps, for the progress message (bot/progress.py): on_progress(step,
# state, done, total).
SWITCH_STEPS = ("preflight", "dns", "verify", "jump", "proxy")
# schema_meta: the proxies a switch moved, whose users may want the new address
# («📣 Разослать новую ссылку»): {"kinds": [...], "at": ...}; "" when none.
META_PROXY_NOTICE = "fallback_proxy_notice"
# A proxy port whose forward the agent refused is not sent again by the reconcile for
# this long (module docstring, «RECONCILED»); «🔁 Довести прокси до hub» does not wait.
RECONCILE_BACKOFF_SECONDS = 3600.0
# Refusals that say nothing about the port: the next pass simply tries again.
_TRANSIENT_KEYS = frozenset({"relay_busy"})
# The port a failed `vpn-relay-apply check` names: "FAIL: TCP connect 198.51.100.1:31337 …".
_TCP_CONNECT_PORT = re.compile(r"TCP connect \S+?:(\d+)\b")

Doh = Callable[[str], Awaitable[list[DohAnswer]]]
Progress = Callable[[str, str, int | None, int | None], Awaitable[None]]


async def _noop_progress(step: str, state: str, done: int | None, total: int | None) -> None:
    return None


@dataclass(frozen=True, slots=True)
class Candidate:
    """A name the failover set likely wants, and why: i18n keys (``fb_cand_why_*``)
    and, for a relay's upstream, the relays that forward to it."""

    name: str
    reasons: tuple[str, ...]
    relays: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class HubCandidate:
    relay: Relay
    address: str | None
    country: str | None


# ── results ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PreflightItem:
    """One line of the preflight: an i18n key with its params, and the verdict."""

    key: str
    ok: bool
    params: dict[str, object] = field(default_factory=dict, hash=False, compare=False)
    # True: shown, but does not block the switch.
    warning: bool = False
    # True: neither good nor bad — what will happen (an info icon); never blocks.
    info: bool = False


@dataclass(frozen=True, slots=True)
class Preflight:
    items: tuple[PreflightItem, ...]

    @property
    def passed(self) -> bool:
        return all(item.ok or item.warning for item in self.items)

    @property
    def failures(self) -> tuple[PreflightItem, ...]:
        return tuple(item for item in self.items if not item.ok and not item.warning)


@dataclass(frozen=True, slots=True)
class NameResult:
    """What a switch did to one name."""

    name: str
    # The A record now holds the wanted address (written now or already there).
    ok: bool
    ipv4: str
    error: str | None = None
    # What public resolvers answered after the write (empty: not asked).
    doh: tuple[DohAnswer, ...] = ()

    @property
    def propagated(self) -> bool:
        answered = [a for a in self.doh if a.error is None]
        return bool(answered) and all(a.addresses == (self.ipv4,) for a in answered)


@dataclass(frozen=True, slots=True)
class ProxyRoute:
    """What a switch did to one proxying module's forward on the hub."""

    kind: str
    port: int
    # The hub forwards it now (the mode on) / it is off the hub (the mode off).
    ok: bool
    via_hub: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ProxyReconcile:
    """What one :meth:`FallbackService.reconcile_proxies` did."""

    # The mode it reconciled for: on — the proxy ports go to the hub; off — off it.
    mode_on: bool
    # The ports an ``apply`` was sent for, and what it did (empty: nothing was sent).
    routes: tuple[ProxyRoute, ...] = ()
    # Ports still to do, not sent: their last ``apply`` failed less than the backoff ago
    # (with that error).
    deferred: tuple[ProxyRoute, ...] = ()
    # Ports that can never be forwarded: the hub's own SSH port.
    blocked: tuple[ProxyRoute, ...] = ()
    # Why nothing was looked at: "" (it was), "no_hub" (no hub with an agent), "vpn_gap"
    # (the hub's TCP set lacks a VPN port — never sent without them), "busy" (a switch
    # held the lock and the caller did not wait). *detail*: the gap's params.
    skipped: str = ""
    detail: tuple[tuple[str, str], ...] = ()

    @property
    def applied(self) -> bool:
        return bool(self.routes)

    @property
    def settled(self) -> bool:
        """The hub's proxy ports are what the mode wants (or were made so now)."""
        return (not self.skipped and all(route.ok for route in self.routes)
                and not self.deferred and not self.blocked)


@dataclass(frozen=True, slots=True)
class ProxyAlert:
    """A proxy port the reconcile could not bring to the hub (the mode on) or take off it
    (the mode off) — told to the superadmins once per (port, error)."""

    route: ProxyRoute
    mode_on: bool
    hub: str
    main: str | None
    # When the next automatic try comes, at the earliest.
    retry_minutes: int


@dataclass(frozen=True, slots=True)
class SwitchReport:
    target: str
    preflight: Preflight | None
    results: tuple[NameResult, ...] = ()
    proxies: tuple[ProxyRoute, ...] = ()

    @property
    def started(self) -> bool:
        """The DNS was touched (the preflight passed, or there was none)."""
        return self.preflight is None or self.preflight.passed

    @property
    def complete(self) -> bool:
        return self.started and all(result.ok for result in self.results)

    @property
    def failed_names(self) -> tuple[str, ...]:
        return tuple(result.name for result in self.results if not result.ok)


@dataclass(frozen=True, slots=True)
class HubOutcome:
    relay: Relay
    origin: str
    main_ipv4: str
    created_record: bool


@dataclass(frozen=True, slots=True)
class FallbackOverview:
    """Everything the «🛟 Режим фолбэка» screen and the relay list show."""

    mode_on: bool
    mode_at: str | None
    hubs: tuple[Relay, ...]
    hub: Relay | None
    main_ipv4: str | None
    hub_ipv4: str | None
    names: tuple[FailoverName, ...]
    token_set: bool
    token_fingerprint: str | None
    sub_fallback_url: bool
    direct_host: str | None
    single_direct_keys: int
    # Where each proxying module that is on is reached now (services/proxy_endpoint.py).
    proxies: tuple[tuple[str, ProxyEndpoint], ...] = ()
    # The proxies a switch moved whose users have not been told yet.
    proxy_notice: tuple[str, ...] = ()

    @property
    def proxies_direct(self) -> tuple[str, ...]:
        """The mode is on, yet these proxies are still handed out with main's address:
        the hub does not forward their port («🔁 Довести прокси до hub»). A port equal to
        the hub's SSH port is not one: it can never be forwarded."""
        if not self.mode_on:
            return ()
        ssh = self.hub.agent.ssh_port if self.hub is not None and self.hub.agent is not None else None
        return tuple(kind for kind, endpoint in self.proxies if not endpoint.via_hub and endpoint.port != ssh)

    @property
    def target(self) -> str:
        return FAILOVER if self.mode_on else NORMAL

    @property
    def pending(self) -> tuple[FailoverName, ...]:
        """Names not where the asked mode wants them (a partial switch)."""
        return tuple(name for name in self.names if not name_settled(name, self.mode_on))

    @property
    def state(self) -> str:
        """'off' | 'on' | 'partial' (a switch did not reach every name)."""
        if self.pending:
            return "partial"
        return "on" if self.mode_on else "off"

    @property
    def origin(self) -> str | None:
        return self.hub.agent.target_host if self.hub is not None and self.hub.agent is not None else None


def name_settled(name: FailoverName, mode_on: bool) -> bool:
    """The name is where the mode wants it: on — the bot wrote the hub there; off —
    the bot wrote the main server back, or never touched it."""
    if name.last_error:
        return False
    if mode_on:
        return name.applied == FAILOVER
    return name.applied in (None, NORMAL)


def _ipv4(value: str | None) -> str | None:
    address = validators.ipv4_address((value or "").strip())
    return None if address is None else str(address)


PROXY_TITLES = {SOCKS5: "SOCKS5", MTPROTO: "MTProto"}


def port_reached(status: Mapping[str, Any], address: str, port: int) -> bool:
    """The agent's own check connected to *address*:*port* (and did not fail on it)."""
    check = status.get("check")
    lines = check.get("lines") if isinstance(check, dict) else None
    text = [str(line) for line in lines] if isinstance(lines, list) else []
    return (any(f"ok: TCP connect {address}:{port}" in line for line in text)
            and not any(f"FAIL: TCP connect {address}:{port}" in line for line in text))


def check_reaches(
    status: Mapping[str, Any], address: str, ports: Iterable[int], *, tolerated: Iterable[int] = (),
) -> tuple[bool, list[int]]:
    """Whether the agent's own ``vpn-relay-apply check`` connected to *address* on
    every port of *ports* — and failed on nothing but the input filter, or a TCP connect
    on a *tolerated* port (a proxy port the hub forwards: a danted outage on main is not
    a VPN that cannot switch). Returns (passed, the ports that did not connect)."""
    check = status.get("check")
    lines = check.get("lines") if isinstance(check, dict) else None
    rc = check.get("rc") if isinstance(check, dict) else None
    text = [str(line) for line in lines] if isinstance(lines, list) else []
    missing = [
        port for port in ports
        if not any(f"ok: TCP connect {address}:{port}" in line for line in text)
        or any(f"FAIL: TCP connect {address}:{port}" in line for line in text)
    ]
    skip = tuple(f"TCP connect {address}:{port} " for port in tolerated)
    judged = [line for line in text if not (skip and any(mark in line for mark in skip))]
    # The exit code is the FIRST failure's: a tolerated port's TCP failure (13) may be
    # it — the FAIL lines that are left decide.
    rest_ok = only_input_filter_failures(judged)
    healthy = isinstance(rc, int) and (
        rc == 0 or (rc in _HUB_CHECK_OK and rest_ok) or (bool(skip) and rc == _E_TCP and rest_ok)
    )
    return (healthy and not missing), missing


# ── the service ───────────────────────────────────────────────────────────────


class FallbackService:
    """The hub's role, the failover set, the DNS API token, the switch. SUPERADMIN only."""

    def __init__(
        self,
        *,
        repo: FailoverRepository,
        relays_repo: RelayRepository,
        relays: RelayService,
        users: UserService,
        audit: AuditService,
        clock: ClockProvider,
        settings: Settings,
        token_file: CloudflareTokenFile,
        dns: CloudflareDns,
        doh: Doh,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        verify_timeout: float = VERIFY_TIMEOUT_SECONDS,
        verify_interval: float = VERIFY_INTERVAL_SECONDS,
        endpoints: ProxyEndpoints | None = None,
        modules: Any | None = None,
    ) -> None:
        self.repo = repo
        self.relays_repo = relays_repo
        self.relays = relays
        self.users = users
        self.audit = audit
        self.clock = clock
        self.settings = settings
        self.token_file = token_file
        self.dns = dns
        self._doh = doh
        self._sleep = sleep
        self._monotonic = monotonic
        self._verify_timeout = verify_timeout
        self._verify_interval = verify_interval
        self._lock = asyncio.Lock()
        self._zones: dict[str, DnsZone] = {}
        # What the health loop asks synchronously (refresh_state keeps it current).
        self._mode_on = False
        self._names: frozenset[str] = frozenset()
        # THE public address of each proxy (services/proxy_endpoint.py): refresh_state
        # routes a module through the hub while the mode is on and the hub forwards it.
        self.endpoints = endpoints or ProxyEndpoints(settings)
        # services.protocol_modules (is_enabled): a proxying module switched off is not
        # forwarded. None: .env alone decides (tests).
        self.modules = modules
        # The reconcile's memory (module docstring, «RECONCILED»): port → (the agent's
        # error, monotonic time of that try); the (port, error) pairs already told; and
        # the alerts not delivered yet (no one to tell at startup, before the bot is up).
        self._proxy_failed: dict[int, tuple[str, float]] = {}
        self._proxy_told: set[tuple[int, str]] = set()
        self._proxy_unsent: dict[tuple[int, str], ProxyAlert] = {}
        # Tells the superadmins about a proxy port that could not be reconciled (bot.app).
        self.proxy_alert: Callable[[ProxyAlert], Awaitable[None]] | None = None
        self._reconcile_task: asyncio.Task[ProxyReconcile] | None = None
        self._vpn_gap_logged: tuple[int, ...] | None = None

    # ── state for the health loop ─────────────────────────────────────────────

    async def refresh_state(self) -> None:
        """Re-read the mode and the names (after every write, and at startup) — and where
        each proxy is reached: through the hub while the mode is on and the hub forwards
        its port (the hub's stored forward, written by the agent's apply)."""
        self._mode_on = await self.repo.mode_on()
        self._names = frozenset(name.name for name in await self.repo.list_names())
        via: dict[str, str] = {}
        if self._mode_on:
            hub = select_hub(await self.relays_repo.list_hubs())
            address = await self.hub_ipv4(hub)
            if hub is not None and hub.agent is not None and address:
                for kind, port in (await self.proxy_ports()).items():
                    if port in hub.agent.tcp_ports:
                        via[kind] = address
        self.endpoints.set_via_hub(via)

    # ── the proxies through the hub (module docstring, «THE PROXIES») ─────────

    async def proxy_ports(self) -> dict[str, int]:
        """{kind: port} of the proxying modules that are on (.env and the module switch),
        without a port the hub forwards for the VPN anyway."""
        vpn_tcp, _ = self.hub_ports()
        found: dict[str, int] = {}
        for kind in PROXY_KINDS:
            enabled = self.settings.socks5_enabled if kind == SOCKS5 else self.settings.mtproto_enabled
            port = self.endpoints.configured(kind).port
            if not enabled or port is None or not 0 < port < 65536 or port in vpn_tcp:
                continue
            if self.modules is not None and not await self.modules.is_enabled(kind):
                continue
            found[kind] = port
        return found

    def _proxy_snapshot(self) -> dict[str, str]:
        return {kind: self.endpoints.endpoint(kind).address for kind in PROXY_KINDS}

    async def _sync_proxy_forward(self, actor_user_id: int | None, *, on: bool) -> tuple[ProxyRoute, ...]:
        """The hub's TCP set = the VPN ports (+ the proxy ports while *on*), through the
        agent's ``apply`` (its check proves main:<port> answers, or it rolls back). Never
        raises: what happened is in the routes."""
        wanted = await self.proxy_ports() if on else {}
        hub = select_hub(await self.relays_repo.list_hubs())
        if hub is None or hub.agent is None or agent_uninstalled(hub.agent):
            return tuple(ProxyRoute(kind, port, ok=not on, via_hub=False, error="no hub with an agent")
                         for kind, port in wanted.items())
        agent = hub.agent
        clash = {kind: port for kind, port in wanted.items() if port == agent.ssh_port}
        ports = {kind: port for kind, port in wanted.items() if kind not in clash}
        vpn_tcp, vpn_udp = self.hub_ports()
        tcp = tuple(sorted(set(vpn_tcp) | set(ports.values())))
        udp = tuple(agent.udp_ports) or vpn_udp
        error: str | None = None
        if set(agent.tcp_ports) != set(tcp):
            try:
                await self.relays.change_forward(
                    actor_user_id, hub.id, target_host=agent.target_host, tcp=format_ports(tcp), udp=format_ports(udp),
                    allow_hub=True,
                )
            except ServiceError as exc:
                error = str(exc.params.get("error") or exc)[:300]
                logger.warning("Fallback: the hub's proxy ports %s not applied: %s", format_ports(tcp), error)
        routes = [ProxyRoute(kind, port, ok=False, via_hub=False, error="ssh") for kind, port in clash.items()]
        routes += [ProxyRoute(kind, port, ok=error is None, via_hub=on and error is None, error=error)
                   for kind, port in ports.items()]
        if not on:
            # Off: every proxy port that was there goes (a failure leaves it forwarded).
            gone = {port for port in agent.tcp_ports if port not in vpn_tcp}
            routes = [ProxyRoute(kind, port, ok=error is None, via_hub=error is not None, error=error)
                      for kind, port in (await self.proxy_ports()).items() if port in gone]
        await self._audit(actor_user_id, "fallback_proxy_forward",
                          {"on": on, "tcp": list(tcp), "routes": {r.kind: r.ok for r in routes},
                           **({"error": error} if error else {})}, relay_id=hub.id)
        return tuple(routes)

    async def sync_proxies(self, actor_user_id: int | None) -> tuple[ProxyRoute, ...]:
        """A proxying module was switched on or off: while the mode is on the hub follows
        (its port added or taken off). Nothing while the mode is off."""
        async with self._lock:
            if not await self.repo.mode_on():
                return ()
            before = self._proxy_snapshot()
            routes = await self._sync_proxy_forward(actor_user_id, on=True)
            await self.refresh_state()
            await self._note_proxy_change(before)
            return routes

    # ── the reconcile (module docstring, «RECONCILED») ────────────────────────

    async def reconcile_proxies(
        self, actor_user_id: int | None = None, *, force: bool = False, wait: bool = True,
    ) -> ProxyReconcile:
        """Bring the hub's proxy ports to what the mode wants — whenever asked, not only
        at the switch: the mode on and a proxying module on whose port the hub does not
        forward → the port is added (the agent's ``apply``, whose own check proves the hub
        reaches main:<port>, or it rolls back); a proxy port the hub forwards that the mode
        does not want (the mode off, the module off) → taken off. Nothing else of the hub's
        forward changes: its other TCP ports (443/2096 among them), its UDP ports and its
        upstream go back exactly as they are.

        A port whose ``apply`` failed waits :data:`RECONCILE_BACKOFF_SECONDS` before it is
        sent again — *force* («🔁 Довести прокси до hub») does not wait — and the
        superadmins hear about it once per (port, error) (:attr:`proxy_alert`). *wait*
        False: while a switch (or another reconcile) holds the lock, nothing this time —
        the health loop does not stand behind a switch. *actor_user_id* None: the bot
        itself (startup, the health loop, the screen). An agent's refusal never raises."""
        if actor_user_id is not None:
            await self.users.require_superadmin(actor_user_id)
        if not wait and self._lock.locked():
            return ProxyReconcile(mode_on=self._mode_on, skipped="busy")
        async with self._lock:
            result = await self._reconcile_proxies(actor_user_id, force=force)
        await self._flush_proxy_alerts()
        return result

    def reconcile_in_background(self) -> asyncio.Task[ProxyReconcile]:
        """:meth:`reconcile_proxies` without holding the caller — the bot's startup, the
        health loop (its pass decides the automatic switch and must not wait for an
        agent's ``apply``, up to its 300 s timeout), the screen. One at a time: a call
        while one runs gets that one. :meth:`shutdown` cancels it."""
        task = self._reconcile_task
        if task is None or task.done():
            task = asyncio.create_task(self.reconcile_proxies(), name="fallback-proxy-reconcile")
            task.add_done_callback(_log_reconcile_failure)
            self._reconcile_task = task
        return task

    async def shutdown(self) -> None:
        task, self._reconcile_task = self._reconcile_task, None
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def _proxy_universe(self) -> dict[int, str]:
        """port → kind of every proxying module's configured port, on or off — minus the
        hub's VPN ports: the only ports the reconcile ever adds or takes off."""
        vpn_tcp, _ = self.hub_ports()
        found: dict[int, str] = {}
        for kind in PROXY_KINDS:
            port = self.endpoints.configured(kind).port
            if port is not None and 0 < port < 65536 and port not in vpn_tcp:
                found.setdefault(port, kind)
        return found

    async def _reconcile_proxies(self, actor_user_id: int | None, *, force: bool) -> ProxyReconcile:
        mode_on = await self.repo.mode_on()
        hub = select_hub(await self.relays_repo.list_hubs())
        if hub is None or hub.agent is None or agent_uninstalled(hub.agent):
            return ProxyReconcile(mode_on=mode_on, skipped="no_hub")
        agent = hub.agent
        vpn_tcp, vpn_udp = self.hub_ports()
        if not set(vpn_tcp) <= set(agent.tcp_ports):
            # The hub's VPN forward is not what the mode expects: the preflight and the
            # switch deal with that — the reconcile never sends a set without 443/2096.
            if self._vpn_gap_logged != agent.tcp_ports:
                self._vpn_gap_logged = agent.tcp_ports
                logger.warning("Fallback: the hub's TCP set %s lacks the VPN ports %s — proxies not reconciled",
                               format_ports(agent.tcp_ports), format_ports(vpn_tcp))
            missing = sorted(set(vpn_tcp) - set(agent.tcp_ports))
            return ProxyReconcile(mode_on=mode_on, skipped="vpn_gap", detail=(
                ("name", hub.name), ("have", format_ports(agent.tcp_ports) or "—"), ("missing", format_ports(missing)),
            ))
        self._vpn_gap_logged = None
        universe = self._proxy_universe()
        wanted = {port: kind for kind, port in (await self.proxy_ports()).items()} if mode_on else {}
        blocked = tuple(ProxyRoute(kind, port, ok=False, via_hub=False, error="ssh")
                        for port, kind in wanted.items() if port == agent.ssh_port)
        wanted = {port: kind for port, kind in wanted.items() if port != agent.ssh_port}
        have = {port for port in agent.tcp_ports if port in universe}
        to_add = {port: kind for port, kind in wanted.items() if port not in have}
        to_drop = {port: universe[port] for port in sorted(have) if port not in wanted}
        for port in list(self._proxy_failed):
            if port not in to_add and port not in to_drop:
                self._forget_proxy_failure(port)  # nothing to do any more: a new failure is news
        now = self._monotonic()
        due: dict[int, str] = {}
        deferred: list[ProxyRoute] = []
        for port, kind in {**to_add, **to_drop}.items():
            failed = self._proxy_failed.get(port)
            if failed is not None and not force and now - failed[1] < RECONCILE_BACKOFF_SECONDS:
                deferred.append(ProxyRoute(kind, port, ok=False, via_hub=port in have, error=failed[0]))
            else:
                due[port] = kind
        if not due:
            return ProxyReconcile(mode_on=mode_on, deferred=tuple(deferred), blocked=blocked)
        # The hub's set as it is (443/2096, the proxy ports that stay, a removal still
        # waiting for its backoff) — minus the due removals, plus the due additions.
        dropping = {port for port in due if port in to_drop}
        adding = {port for port in due if port in to_add}
        tcp = tuple(sorted({port for port in agent.tcp_ports if port not in dropping} | adding))
        udp = tuple(agent.udp_ports) or vpn_udp
        before = self._proxy_snapshot()
        error: str | None = None
        transient = False
        try:
            # The set above is built from the bot's copy of the hub's forward: the hub is
            # asked first, and a live forward that is neither that copy nor already the
            # wanted set (changed on the relay by hand) is not overwritten.
            error = await self._live_forward_differs(hub, tcp)
            if error is None:
                await self.relays.change_forward(
                    actor_user_id, hub.id, target_host=agent.target_host, tcp=format_ports(tcp),
                    udp=format_ports(udp), allow_hub=True,
                )
        except ServiceError as exc:
            error = str(exc.params.get("error") or exc)[:300]
            transient = exc.key in _TRANSIENT_KEYS
        if error is not None:
            logger.warning("Fallback: the hub's proxy ports not reconciled (tcp %s): %s", format_ports(tcp), error)
        routes = tuple(
            ProxyRoute(kind, port, ok=error is None, via_hub=(port in to_add) == (error is None), error=error)
            for port, kind in due.items()
        )
        if error is None:
            for port in due:
                self._forget_proxy_failure(port)
            await self.refresh_state()
            await self._note_proxy_change(before)
        elif not transient:
            # The agent's check names the port it could not reach: only that one waits
            # (another proxy goes on the next pass without it). Named none — all of them.
            named = {int(port) for port in _TCP_CONNECT_PORT.findall(error)} & set(due)
            main = await self.main_ipv4()
            for route in routes:
                if named and route.port not in named:
                    continue
                self._proxy_failed[route.port] = (error, now)
                if (route.port, error) not in self._proxy_told:
                    self._proxy_told.add((route.port, error))
                    self._proxy_unsent[route.port, error] = ProxyAlert(
                        route=route, mode_on=mode_on, hub=hub.name, main=main,
                        retry_minutes=int(RECONCILE_BACKOFF_SECONDS // 60),
                    )
        await self._audit(
            actor_user_id, "fallback_proxy_reconcile",
            {"mode_on": mode_on, "tcp": list(tcp), "routes": {f"{r.kind}:{r.port}": r.ok for r in routes},
             **({"error": error} if error else {})},
            relay_id=hub.id,
        )
        return ProxyReconcile(mode_on=mode_on, routes=routes, deferred=tuple(deferred), blocked=blocked)

    async def _live_forward_differs(self, hub: Relay, tcp: tuple[int, ...]) -> str | None:
        """None: the hub's live forward (its fresh ``status``) is the bot's copy — or
        already *tcp* with the same UDP set and upstream; an agent whose status does not
        carry the forward is trusted. Else why it is not overwritten. Raises the status
        call's ServiceError (the hub does not answer: the apply would not either)."""
        assert hub.agent is not None
        agent = hub.agent
        payload = (await self.relays.system_status(hub.id)).payload
        live_tcp, live_udp = _ports_of(payload.get("tcp")), _ports_of(payload.get("udp"))
        live_target = str(payload.get("target_host") or "").lower().rstrip(".")
        same_udp = live_udp is None or set(live_udp) == set(agent.udp_ports)
        same_target = not live_target or live_target == agent.target_host.lower().rstrip(".")
        if live_tcp is None or (same_udp and same_target and set(live_tcp) in (set(agent.tcp_ports), set(tcp))):
            return None
        return (f"the hub's live forward (tcp={format_ports(live_tcp)} udp={format_ports(live_udp or ())} "
                f"-> {live_target or '?'}) is not the bot's copy (tcp={format_ports(agent.tcp_ports)} "
                f"udp={format_ports(agent.udp_ports)} -> {agent.target_host}): not overwritten — "
                f"see «🔍 Проверить»")

    def _forget_proxy_failure(self, port: int) -> None:
        self._proxy_failed.pop(port, None)
        self._proxy_told = {told for told in self._proxy_told if told[0] != port}
        self._proxy_unsent = {key: alert for key, alert in self._proxy_unsent.items() if key[0] != port}

    def proxy_failure(self, port: int) -> str | None:
        """The agent's error of the last failed reconcile of *port* (None: none pending)."""
        failed = self._proxy_failed.get(port)
        return failed[0] if failed is not None else None

    async def _flush_proxy_alerts(self) -> None:
        """Deliver the alerts not told yet; one that fails to go stays for the next time."""
        if self.proxy_alert is None:
            return
        for key, alert in list(self._proxy_unsent.items()):
            try:
                await self.proxy_alert(alert)
            except Exception as exc:
                logger.warning("Fallback: the proxy alert failed: %s: %s", type(exc).__name__, exc)
                continue
            self._proxy_unsent.pop(key, None)

    async def _note_proxy_change(self, before: Mapping[str, str]) -> None:
        """Remember the proxies whose address moved (their users may want the new one)."""
        moved = [kind for kind, address in self._proxy_snapshot().items() if before.get(kind) != address]
        if moved:
            pending = set(await self.proxy_notice())
            await self.repo.set_setting(META_PROXY_NOTICE, ",".join(sorted(pending | set(moved))))

    async def proxy_notice(self) -> tuple[str, ...]:
        """The proxies a switch moved whose users have not been told («📣 Разослать») —
        only those still on: nothing about a proxy that is off (MTPROTO_ENABLED=false)
        is ever offered or sent."""
        raw = await self.repo.get_setting(META_PROXY_NOTICE) or ""
        on = await self.proxy_ports()
        return tuple(kind for kind in raw.split(",") if kind in PROXY_KINDS and kind in on)

    async def clear_proxy_notice(self, actor_user_id: int) -> None:
        await self.users.require_superadmin(actor_user_id)
        await self.repo.set_setting(META_PROXY_NOTICE, "")

    @property
    def mode_on(self) -> bool:
        return self._mode_on

    def behind_hub(self, relay: Relay) -> bool:
        """In the fallback mode, a relay the main server cannot reach directly: not a
        hub, and forwarding to a failover name (or set up by hand — then unknown,
        so assumed). The health loop marks it «за hub» instead of alerting."""
        if not self._mode_on or relay.is_hub:
            return False
        return relay.agent is None or relay.agent.target_host in self._names

    # ── reads ─────────────────────────────────────────────────────────────────

    async def overview(self, actor_user_id: int) -> FallbackOverview:
        await self.users.require_superadmin(actor_user_id)
        return await self._overview()

    async def _overview(self) -> FallbackOverview:
        hubs = tuple(await self.relays_repo.list_hubs())
        hub = select_hub(hubs)
        token_fp: str | None = None
        token_set = self.token_file.exists()
        if token_set:
            try:
                token_fp = fingerprint(self.token_file.load())
            except DnsTokenMissing:
                token_fp = None
        direct_host = await self.repo.direct_host()
        issued_before = await self.repo.get_setting(META_DIRECT_HOST_AT) if direct_host else None
        return FallbackOverview(
            mode_on=await self.repo.mode_on(),
            mode_at=await self.repo.mode_changed_at(),
            hubs=hubs,
            hub=hub,
            main_ipv4=await self.main_ipv4(),
            hub_ipv4=await self.hub_ipv4(hub),
            names=tuple(await self.repo.list_names()),
            token_set=token_set,
            token_fingerprint=token_fp,
            sub_fallback_url=await self.repo.sub_fallback_url(),
            direct_host=direct_host,
            single_direct_keys=await self.repo.single_direct_keys(issued_before=issued_before or None),
            proxies=tuple((kind, self.endpoints.endpoint(kind)) for kind in await self.proxy_ports()),
            proxy_notice=await self.proxy_notice(),
        )

    async def main_ipv4(self) -> str | None:
        """The main server's IPv4: the screen's override, else XRAY_PUBLIC_HOST, else
        HYSTERIA2_HOST — whichever is an IPv4 address."""
        override = _ipv4(await self.repo.get_setting(META_MAIN_IPV4))
        if override:
            return override
        return _ipv4(self.settings.xray_public_host) or _ipv4(self.settings.hysteria2_host)

    async def hub_ipv4(self, hub: Relay | None) -> str | None:
        """The hub's public IPv4 the failover names get: the override, else its host
        or SSH address when an IPv4, else its one /32 source address."""
        override = _ipv4(await self.repo.get_setting(META_HUB_IPV4))
        if override:
            return override
        if hub is None:
            return None
        for value in (hub.host, hub.agent.ssh_host if hub.agent is not None else None):
            address = _ipv4(value)
            if address:
                return address
        singles = [n for n in hub.source_ips if n.prefixlen == 32]
        return str(singles[0].network_address) if len(singles) == 1 else None

    async def candidates(self, actor_user_id: int) -> list[str]:
        """Names the admin will likely want in the set (:meth:`explained_candidates`)."""
        return [c.name for c in await self.explained_candidates(actor_user_id)]

    async def explained_candidates(self, actor_user_id: int) -> list[Candidate]:
        """Names the failover set likely wants, each with WHY: HYSTERIA2_SNI (the hy2
        certificate's name), the subscription's name (HYSTERIA2_SNI, else
        HYSTERIA2_HOST — bot/bundles.py subscription_host), the names the RU (edge)
        relays forward to, a DNS-named XRAY_PUBLIC_HOST (the direct links) — minus
        what is in the set and what can never be there (a hub's origin or host)."""
        await self.users.require_superadmin(actor_user_id)
        taken = {name.name for name in await self.repo.list_names()}
        forbidden = await self._forbidden_names()
        reasons: dict[str, list[str]] = {}
        relays: dict[str, list[str]] = {}

        def add(value: str | None, reason: str, relay: str | None = None) -> None:
            name = (value or "").strip().lower().rstrip(".")
            if not valid_dns_name(name) or name in taken or name in forbidden:
                return
            bucket = reasons.setdefault(name, [])
            if reason not in bucket:
                bucket.append(reason)
            if relay is not None:
                relays.setdefault(name, []).append(relay)

        add(self.settings.hysteria2_sni, "fb_cand_why_sni")
        add((self.settings.hysteria2_sni or self.settings.hysteria2_host), "fb_cand_why_subscription")
        for relay in await self.relays_repo.list_all():
            if not relay.is_hub and relay.agent is not None:
                add(relay.agent.target_host, "fb_cand_why_relay", relay.name)
        add(self.settings.xray_public_host, "fb_cand_why_direct")
        return [Candidate(name, tuple(why), tuple(relays.get(name, ()))) for name, why in reasons.items()]

    async def add_names(self, actor_user_id: int, names: Iterable[str]) -> list[FailoverName]:
        """Add several names (the setup's and «Включить»'s one confirmation); a name
        already in the set is skipped, a refused one stops with its reason."""
        added: list[FailoverName] = []
        present = {n.name for n in await self.repo.list_names()}
        for value in names:
            if value.strip().lower().rstrip(".") in present:
                continue
            added.append(await self.add_name(actor_user_id, value))
        return added

    async def configured(self) -> bool:
        """The fallback mode is set up: a DNS API token and a hub."""
        return self.token_file.exists() and select_hub(await self.relays_repo.list_hubs()) is not None

    async def check_zone(self, actor_user_id: int, name: str | None = None) -> str:
        """The stored token can manage the zone of *name* (default: HYSTERIA2_SNI's) —
        asked right after the token is set. Returns the zone's name."""
        await self.users.require_superadmin(actor_user_id)
        target = (name or self.settings.hysteria2_sni or "").strip().lower()
        if not valid_dns_name(target):
            raise InvalidOperation("нет имени для проверки зоны", key="fb_err_bad_name", params={"value": target})
        self._token()
        try:
            zone = await self.dns.find_zone(target)
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="fb_err_token_zone", params={"name": target, "error": str(exc)}) from None
        self._zones[target] = zone
        return zone.name

    async def hub_candidates(self, actor_user_id: int) -> list[HubCandidate]:
        """Relays that can be THE hub: an agent that answers, enabled, not a hub yet —
        and outside Russia by the IP-to-ASN database's country of their IPv4 (a relay
        whose country is unknown is offered, marked as such)."""
        await self.users.require_superadmin(actor_user_id)
        found: list[HubCandidate] = []
        for relay in await self.relays_repo.list_all():
            if relay.is_hub or not relay.enabled or relay.agent is None or agent_uninstalled(relay.agent):
                continue
            address = next(
                (a for a in (_ipv4(relay.host), _ipv4(relay.agent.ssh_host)) if a),
                next((str(n.network_address) for n in relay.source_ips if n.prefixlen == 32), None),
            )
            country = lookup_country(address) if address else None
            if country == "RU":
                continue
            found.append(HubCandidate(relay=relay, address=address, country=country))
        return found

    async def auto_switch(self) -> bool:
        return (await self.repo.get_setting(META_AUTO_SWITCH)) == "1"

    async def set_auto_switch(self, actor_user_id: int, on: bool) -> bool:
        await self.users.require_superadmin(actor_user_id)
        await self.repo.set_setting(META_AUTO_SWITCH, "1" if on else "0")
        await self._audit(actor_user_id, "failover_setting_changed", {"setting": META_AUTO_SWITCH, "after": on})
        return on

    async def _forbidden_names(self) -> dict[str, str]:
        """Names that may never join the set → why (origin of a hub, host of a hub)."""
        forbidden: dict[str, str] = {}
        for hub in await self.relays_repo.list_hubs():
            forbidden[hub.host.lower()] = "fb_err_name_is_hub_host"
            if hub.agent is not None:
                forbidden[hub.agent.target_host.lower()] = "fb_err_name_is_origin"
        return forbidden

    # ── the failover set ──────────────────────────────────────────────────────

    async def add_name(self, actor_user_id: int, value: str) -> FailoverName:
        await self.users.require_superadmin(actor_user_id)
        name = (value or "").strip().lower().rstrip(".")
        if not valid_dns_name(name):
            raise InvalidOperation("не DNS-имя", key="fb_err_bad_name", params={"value": name})
        async with self._lock:
            why = (await self._forbidden_names()).get(name)
            if why is not None:
                raise InvalidOperation("имя нельзя добавить", key=why, params={"value": name})
            added = await self.repo.add_name(name, now=self.clock.now(), created_by=actor_user_id)
            if added is None:
                raise InvalidOperation("имя уже в наборе", key="fb_err_name_exists", params={"value": name})
            await self._audit(actor_user_id, "failover_name_added", {"name": name})
            await self.refresh_state()
            return added

    async def remove_name(self, actor_user_id: int, name_id: int) -> FailoverName:
        """Take a name out of the set. Refused while the mode is on and the bot
        already wrote the hub there — the record would be left at the hub."""
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            current = await self.repo.get_name(name_id)
            if current is None:
                raise NotFound("имени нет", key="fb_err_name_not_found")
            if current.applied == FAILOVER:
                raise InvalidOperation(
                    "имя указывает на hub", key="fb_err_name_points_at_hub", params={"value": current.name}
                )
            await self.repo.remove_name(name_id)
            await self._audit(actor_user_id, "failover_name_removed", {"name": current.name})
            await self.refresh_state()
            return current

    # ── the DNS API token ─────────────────────────────────────────────────────

    async def set_token(self, actor_user_id: int, token: str) -> str:
        """Check the token with the API, then store it (0600). Returns its status."""
        await self.users.require_superadmin(actor_user_id)
        value = (token or "").strip()
        if not valid_token(value):
            raise InvalidOperation("не похоже на токен", key="fb_err_token_format")
        probe = self.dns.with_token(value)
        try:
            status = await probe.verify_token()
        except DnsApiError as exc:
            await self._audit(actor_user_id, "failover_token_rejected", {"token_fp": fingerprint(value)})
            raise InvalidOperation(str(exc), key="fb_err_token_rejected", params={"error": str(exc)}) from None
        if status != "active":
            raise InvalidOperation("токен не активен", key="fb_err_token_inactive", params={"status": status})
        async with self._lock:
            try:
                self.token_file.save(value)
            except DnsTokenMissing as exc:
                raise ServiceError(str(exc), key="fb_err_token_unwritable", params={"path": str(self.token_file.path)}) from None
            self._zones.clear()
        await self._audit(actor_user_id, "failover_token_set", {"token_fp": fingerprint(value), "status": status})
        return status

    async def delete_token(self, actor_user_id: int) -> bool:
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            removed = self.token_file.delete()
            self._zones.clear()
        if removed:
            await self._audit(actor_user_id, "failover_token_deleted", {})
        return removed

    # ── settings ──────────────────────────────────────────────────────────────

    async def set_address(self, actor_user_id: int, which: str, value: str | None) -> None:
        """Override the main server's or the hub's IPv4 (None / "" → derived again)."""
        await self.users.require_superadmin(actor_user_id)
        key = {"main": META_MAIN_IPV4, "hub": META_HUB_IPV4}.get(which)
        if key is None:
            raise ValueError(which)
        address = ""
        if value and value.strip() and value.strip() != "-":
            parsed = _ipv4(value)
            if parsed is None or not ipaddress.IPv4Address(parsed).is_global:
                raise InvalidOperation("не публичный IPv4", key="fb_err_bad_ipv4", params={"value": value.strip()})
            address = parsed
        async with self._lock:
            if await self.repo.mode_on():
                raise InvalidOperation("режим включён", key="fb_err_mode_on")
            before = await self.repo.get_setting(key)
            await self.repo.set_setting(key, address)
        await self._audit(actor_user_id, "failover_setting_changed", {"setting": key, "before": before, "after": address})

    async def set_sub_fallback_url(self, actor_user_id: int, on: bool) -> bool:
        await self.users.require_superadmin(actor_user_id)
        await self.repo.set_setting(META_SUB_FALLBACK_URL, "1" if on else "0")
        await self._audit(actor_user_id, "failover_setting_changed", {"setting": META_SUB_FALLBACK_URL, "after": on})
        return on

    async def set_direct_host(self, actor_user_id: int, value: str | None) -> str | None:
        """«Host прямых ссылок»: a DNS name instead of XRAY_PUBLIC_HOST / HYSTERIA2_HOST
        (None / "" / "-" → back to .env). The name must resolve, for public resolvers,
        to the main server (or, in the fallback mode, to the hub) — otherwise new
        direct links would point at nothing. Keys already imported keep their IPv4
        and keep working: the main server's address does not change."""
        await self.users.require_superadmin(actor_user_id)
        name = (value or "").strip().lower().rstrip(".")
        if name in ("", "-"):
            name = ""
        elif not valid_dns_name(name):
            raise InvalidOperation("не DNS-имя", key="fb_err_bad_name", params={"value": name})
        async with self._lock:
            if name:
                main = await self.main_ipv4()
                hub_ip = await self.hub_ipv4(select_hub(await self.relays_repo.list_hubs()))
                expected = {address for address in (main, hub_ip) if address}
                answers = await self._doh(name)
                seen = {address for answer in answers if answer.error is None for address in answer.addresses}
                if not seen or not seen <= expected:
                    raise InvalidOperation(
                        "имя указывает не на main", key="fb_err_direct_host_resolves",
                        params={"value": name, "seen": ", ".join(sorted(seen)) or "—", "main": main or "—"},
                    )
            before = await self.repo.direct_host()
            await self.repo.set_setting(META_DIRECT_HOST, name)
            await self.repo.set_setting(META_DIRECT_HOST_AT, self.clock.now() if name else "")
            await self.relays.refresh_catalog()
        await self._audit(actor_user_id, "failover_direct_host_changed", {"before": before, "after": name or None})
        return name or None

    # ── the hub ───────────────────────────────────────────────────────────────

    def hub_ports(self) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """What a hub forwards: TCP XRAY_PUBLIC_PORT (+ SUBSCRIPTION_PUBLIC_PORT when
        the subscription has a public port), UDP HYSTERIA2_PORT."""
        tcp = [self.settings.xray_public_port]
        if self.settings.subscription_public_port > 0 and self.settings.subscription_public_port not in tcp:
            tcp.append(self.settings.subscription_public_port)
        return tuple(sorted(tcp)), (self.settings.hysteria2_port,)

    def suggest_origin(self) -> str | None:
        """``origin.<the zone of HYSTERIA2_SNI>`` — a suggestion, not a rule."""
        base = (self.settings.hysteria2_sni or "").strip().lower()
        labels = base.split(".")
        if not valid_dns_name(base):
            return None
        return "origin." + ".".join(labels[-2:])

    async def assign_hub(self, actor_user_id: int, relay_id: int, origin: str) -> HubOutcome:
        """Make a relay THE hub: the origin record (→ the main server's IPv4, created
        or checked through the DNS API), then the agent re-points the relay to the
        origin on the hub ports — its own check proves the hub reaches the main
        server on each TCP port, or the agent rolls back — then the loop check, then
        the role. Any failure leaves the role as it was."""
        await self.users.require_superadmin(actor_user_id)
        name = (origin or "").strip().lower().rstrip(".")
        if not valid_dns_name(name):
            raise InvalidOperation("не DNS-имя", key="fb_err_bad_name", params={"value": name})
        async with self._lock:
            relay = await self._require_relay(relay_id)
            agent = relay.agent
            if agent is None or agent_uninstalled(agent):
                raise InvalidOperation("у relay нет агента", key="fb_err_hub_needs_agent", params={"name": relay.name})
            if not relay.enabled:
                raise InvalidOperation("relay выключен", key="fb_err_hub_disabled", params={"name": relay.name})
            if await self.repo.mode_on():
                raise InvalidOperation("режим включён", key="fb_err_mode_on")
            others = [hub for hub in await self.relays_repo.list_hubs() if hub.id != relay.id]
            if others:
                raise InvalidOperation(
                    "hub уже есть", key="fb_err_hub_exists", params={"name": others[0].name}
                )
            if name in {n.name for n in await self.repo.list_names()}:
                raise InvalidOperation("origin в наборе", key="fb_err_origin_in_set", params={"value": name})
            if name == relay.host.lower():
                raise InvalidOperation("origin = host hub", key="fb_err_origin_is_hub_host", params={"value": name})
            main = await self.main_ipv4()
            if main is None:
                raise InvalidOperation("нет IPv4 main", key="fb_err_no_main_ipv4")
            created = await self._ensure_record(name, main)
            answers = await self._wait_resolves(name, main)
            if not NameResult(name=name, ok=True, ipv4=main, doh=tuple(answers)).propagated:
                raise InvalidOperation(
                    "origin ещё не резолвится", key="fb_err_origin_not_resolving",
                    params={"value": name, "main": main, "seen": _seen(answers)},
                )
            tcp, udp = self.hub_ports()
            reply = await self.relays.change_forward(
                actor_user_id, relay.id, target_host=name, tcp=format_ports(tcp), udp=format_ports(udp),
                allow_hub=True,
            )
            live = reply.payload.get("live_target")
            resolved = reply.payload.get("resolved")
            if live != main or (isinstance(resolved, list) and resolved and set(map(str, resolved)) != {main}):
                raise InvalidOperation(
                    "hub смотрит не на main", key="fb_err_hub_loop",
                    params={"name": relay.name, "value": f"{live} / {resolved}", "main": main},
                )
            await self.relays_repo.set_role(relay.id, RELAY_ROLE_HUB, now=self.clock.now(), updated_by=actor_user_id)
            await self.relays.refresh_catalog()
            after = await self._require_relay(relay.id)
            # The relays «через hub» are reached through this one from now on.
            await self.relays.sync_hub_jump_quietly()
        await self._audit(
            actor_user_id, "relay_hub_assigned",
            {"name": after.name, "origin": name, "main_ipv4": main, "origin_record_created": created,
             "tcp": list(tcp), "udp": list(udp)},
            relay_id=after.id,
        )
        await self.refresh_state()
        return HubOutcome(relay=after, origin=name, main_ipv4=main, created_record=created)

    async def hub_in_use(self) -> bool:
        """Failover names point — or may point — at the hub: the mode is on, or a
        name's last successful write put the hub there (a switch-off that did not
        finish). While this holds the hub must stay a hub and stay installed."""
        if await self.repo.mode_on():
            return True
        return any(name.applied == FAILOVER for name in await self.repo.list_names())

    async def clear_hub(self, actor_user_id: int, relay_id: int) -> Relay:
        """Back to an ordinary relay (its forward stays as it is). Refused while any
        failover name may still point at it (:meth:`hub_in_use`)."""
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            relay = await self._require_relay(relay_id)
            if not relay.is_hub:
                return relay
            if await self.hub_in_use():
                raise InvalidOperation("имена указывают на hub", key="fb_err_hub_in_use", params={"name": relay.name})
            # Its jump line goes with the role (best effort: an unreachable relay
            # keeps a line that opens only the relays' sshd, behind their own keys).
            await self.relays.drop_hub_jump(actor_user_id, relay)
            await self.relays_repo.set_role(relay.id, RELAY_ROLE_EDGE, now=self.clock.now(), updated_by=actor_user_id)
            await self.relays.refresh_catalog()
            after = await self._require_relay(relay.id)
        await self._audit(actor_user_id, "relay_hub_cleared", {"name": after.name}, relay_id=after.id)
        await self.refresh_state()
        return after

    # ── preflight and the switch ──────────────────────────────────────────────

    async def preflight(self, actor_user_id: int) -> Preflight:
        """Every check of «Включить», without touching the DNS."""
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            return await self._preflight(actor_user_id)

    async def enable(self, actor_user_id: int, *, on_progress: Progress | None = None) -> SwitchReport:
        await self.users.require_superadmin(actor_user_id)
        return await self._switch(FAILOVER, actor_user_id, on_progress=on_progress)

    async def disable(self, actor_user_id: int, *, on_progress: Progress | None = None) -> SwitchReport:
        await self.users.require_superadmin(actor_user_id)
        return await self._switch(NORMAL, actor_user_id, on_progress=on_progress)

    async def repeat(self, actor_user_id: int, *, on_progress: Progress | None = None) -> SwitchReport:
        """«Повторить»: the switch the mode asks for, again — finishes a partial one."""
        await self.users.require_superadmin(actor_user_id)
        return await self._switch(FAILOVER if await self.repo.mode_on() else NORMAL, actor_user_id,
                                  on_progress=on_progress)

    async def _switch(self, target: str, actor_user_id: int | None, *, on_progress: Progress | None = None) -> SwitchReport:
        """THE switch (no authorization here: the public methods check it — the
        automatic switch on health calls this with ``actor_user_id=None``).
        *on_progress* hears the steps (:data:`SWITCH_STEPS`)."""
        progress = on_progress or _noop_progress
        async with self._lock:
            names = await self.repo.list_names()
            if not names:
                raise InvalidOperation("набор пуст", key="fb_err_no_names")
            await progress("preflight", "run", None, None)
            if target == FAILOVER:
                preflight = await self._preflight(actor_user_id)
                if not preflight.passed:
                    await progress("preflight", "fail", None, None)
                    await self._audit(
                        actor_user_id, "failover_preflight_failed",
                        {"failed": [item.key for item in preflight.failures]},
                    )
                    return SwitchReport(target=target, preflight=preflight)
                address = await self.hub_ipv4(select_hub(await self.relays_repo.list_hubs()))
            else:
                preflight = None
                self._token()
                address = await self.main_ipv4()
            if address is None:
                raise InvalidOperation("нет адреса", key="fb_err_no_main_ipv4")
            await progress("preflight", "ok", None, None)
            before = self._proxy_snapshot()
            proxies: tuple[ProxyRoute, ...] = ()
            if target == FAILOVER:
                # The proxies first: their port on the hub before the names move (the
                # agent's apply proves the hub reaches main:<port>); never blocking.
                await progress("proxy", "run", None, None)
                proxies = await self._sync_proxy_forward(actor_user_id, on=True)
                await progress("proxy", "ok" if all(r.ok for r in proxies) else "fail", None, None)
            await self.repo.set_mode(target == FAILOVER, now=self.clock.now())
            await self.refresh_state()
            # Every relay but the hub is managed through the hub while the mode is
            # on: its jump line follows the mode (a failure is logged, the next call
            # through the hub writes it again — the switch does not wait for it).
            await progress("jump", "run", None, None)
            await self.relays.sync_hub_jump_quietly()
            await progress("jump", "ok", None, None)
            written: list[NameResult] = []
            await progress("dns", "run", 0, len(names))
            for name in names:
                written.append(await self._write_name(name, target, address))
                await progress("dns", "run", len(written), len(names))
            await progress("dns", "ok" if all(r.ok for r in written) else "fail", len(written), len(names))
            await progress("verify", "run", None, None)
            results = await self._verify(written)
            await progress("verify", "ok", None, None)
            if target == NORMAL:
                # The names point at main again: the hub stops forwarding the proxies.
                await progress("proxy", "run", None, None)
                proxies = await self._sync_proxy_forward(actor_user_id, on=False)
                await progress("proxy", "ok" if all(r.ok for r in proxies) else "fail", None, None)
                await self.refresh_state()
            await self._note_proxy_change(before)
        await self._audit(
            actor_user_id,
            "failover_enabled" if target == FAILOVER else "failover_disabled",
            {
                "address": address,
                "names": {r.name: ("ok" if r.ok else f"FAIL: {r.error}") for r in results},
                "propagated": {r.name: r.propagated for r in results if r.ok},
            },
        )
        await self.refresh_state()
        return SwitchReport(target=target, preflight=preflight, results=tuple(results), proxies=proxies)

    async def _write_name(self, name: FailoverName, target: str, address: str) -> NameResult:
        # What the record may hold now and still be overwritten: the main server,
        # the hub — and whatever the bot itself last wrote there (a hub switched
        # off or re-addressed since must not block the way back).
        allowed = await self._allowed_contents()
        if name.applied_ipv4:
            allowed.add(name.applied_ipv4)
        try:
            await self._ensure_record(name.name, address, allowed=allowed)
        except (DnsApiError, InvalidOperation) as exc:
            error = str(exc)
            await self.repo.record_error(name.id, error)
            logger.warning("Fallback: %s -> %s not written: %s", name.name, address, error)
            return NameResult(name=name.name, ok=False, ipv4=address, error=error)
        await self.repo.record_applied(name.id, applied=target, ipv4=address, now=self.clock.now())
        return NameResult(name=name.name, ok=True, ipv4=address)

    async def _allowed_contents(self) -> set[str]:
        hub = select_hub(await self.relays_repo.list_hubs())
        return {address for address in (await self.main_ipv4(), await self.hub_ipv4(hub)) if address}

    async def _verify(self, written: list[NameResult]) -> list[NameResult]:
        """Ask public resolvers (DoH) until every written name answers with its new
        address, or the time is up — then report what they answer. Not reaching it
        is a «not yet» in the report, not a failure: resolvers may keep the old
        record up to its previous TTL."""
        deadline = self._monotonic() + self._verify_timeout
        results = list(written)
        while True:
            results = [
                result if not result.ok else NameResult(
                    name=result.name, ok=True, ipv4=result.ipv4, doh=tuple(await self._doh(result.name))
                )
                for result in results
            ]
            if all(r.propagated for r in results if r.ok) or self._monotonic() >= deadline:
                return results
            await self._sleep(self._verify_interval)

    async def _wait_resolves(self, name: str, address: str) -> list[DohAnswer]:
        deadline = self._monotonic() + self._verify_timeout
        while True:
            answers = await self._doh(name)
            if NameResult(name=name, ok=True, ipv4=address, doh=tuple(answers)).propagated:
                return answers
            if self._monotonic() >= deadline:
                return answers
            await self._sleep(self._verify_interval)

    async def _preflight(self, actor_user_id: int | None) -> Preflight:
        items: list[PreflightItem] = []
        names = await self.repo.list_names()
        names_set = {n.name for n in names}
        items.append(PreflightItem("fb_pf_names", bool(names), {"count": len(names)}))
        token_ok = False
        try:
            status = await self.dns.verify_token()
            token_ok = status == "active"
            items.append(PreflightItem("fb_pf_token", token_ok, {"status": status}))
        except DnsApiError as exc:
            items.append(PreflightItem("fb_pf_token", False, {"status": str(exc)}))
        hubs = await self.relays_repo.list_hubs()
        hub = select_hub(hubs)
        items.append(PreflightItem(
            "fb_pf_hub", hub is not None and hub.agent is not None and not agent_uninstalled(hub.agent),
            {"name": hub.name if hub is not None else "—", "count": len([h for h in hubs if h.enabled])},
        ))
        main = await self.main_ipv4()
        hub_ip = await self.hub_ipv4(hub)
        items.append(PreflightItem(
            "fb_pf_addresses", bool(main and hub_ip and main != hub_ip),
            {"main": main or "—", "hub": hub_ip or "—"},
        ))
        if hub is not None and hub.agent is not None and not agent_uninstalled(hub.agent) and main:
            items.extend(await self._preflight_hub(actor_user_id, hub, main, names_set))
        elif hub is not None:
            items.append(PreflightItem("fb_pf_agent_failed", False, {"name": hub.name, "error": "—"}))
        if token_ok and main and hub_ip:
            for name in names:
                items.extend(await self._preflight_name(name.name, {main, hub_ip}))
        return Preflight(tuple(items))

    async def _preflight_hub(
        self, actor_user_id: int | None, hub: Relay, main: str, names: set[str]
    ) -> list[PreflightItem]:
        assert hub.agent is not None
        items: list[PreflightItem] = []
        origin = hub.agent.target_host
        tcp, udp = self.hub_ports()
        try:
            if actor_user_id is None:
                reply = await self.relays.system_status(hub.id)
            else:
                reply = await self.relays.agent_status(actor_user_id, hub.id)
            payload: Mapping[str, Any] = reply.payload
            items.append(PreflightItem("fb_pf_agent", True, {"name": hub.name}))
        except ServiceError as exc:
            items.append(PreflightItem("fb_pf_agent_failed", False, {"name": hub.name, "error": str(exc)[:200]}))
            payload = {}
        # The ports the hub forwards NOW (its fresh status), not the bot's stored
        # copy: a forward changed on the relay by hand still passes its own check,
        # which compares the ruleset with its own .env and probes TCP only.
        live_tcp = _ports_of(payload.get("tcp")) if payload else None
        live_udp = _ports_of(payload.get("udp")) if payload else None
        have_tcp = live_tcp if live_tcp is not None else tuple(hub.agent.tcp_ports)
        have_udp = live_udp if live_udp is not None else tuple(hub.agent.udp_ports)
        forwards = set(tcp) <= set(have_tcp) and set(udp) <= set(have_udp)
        if live_tcp is not None and live_udp is not None:
            forwards = forwards and set(tcp) <= set(hub.agent.tcp_ports) and set(udp) <= set(hub.agent.udp_ports)
        items.append(PreflightItem(
            "fb_pf_forward", forwards,
            {"name": hub.name, "want": f"tcp={format_ports(tcp)} udp={format_ports(udp)}",
             "have": f"tcp={format_ports(have_tcp)} udp={format_ports(have_udp)}"},
        ))
        proxy = await self.proxy_ports()
        forwarded = {kind: port for kind, port in proxy.items() if port in have_tcp}
        if payload:
            reached, missing = check_reaches(payload, main, tcp, tolerated=forwarded.values())
            items.append(PreflightItem(
                "fb_pf_reach", reached,
                {"name": hub.name, "main": main, "ports": format_ports(tcp),
                 "missing": format_ports(missing) if missing else "—"},
            ))
        # The proxies, one row each: through the hub while the mode forwards them; the mode
        # on and handed out «напрямую» — the hub does not forward the port (the reconcile's
        # button fixes it); else what the switch will do (never blocking — the VPN first).
        mode_on = await self.repo.mode_on()
        for kind, port in proxy.items():
            params: dict[str, object] = {"proxy": PROXY_TITLES[kind], "port": port, "main": main, "name": hub.name}
            if port == hub.agent.ssh_port:
                items.append(PreflightItem("fb_pf_proxy_ssh", False, params, warning=True))
            elif mode_on and (kind not in forwarded or not self.endpoints.endpoint(kind).via_hub):
                error = self.proxy_failure(port)
                if error:
                    items.append(PreflightItem("fb_pf_proxy_not_forwarded_failed", False,
                                               {**params, "error": error[:200]}, warning=True))
                else:
                    items.append(PreflightItem("fb_pf_proxy_not_forwarded", False, params, warning=True))
            elif kind in forwarded:
                items.append(PreflightItem("fb_pf_proxy_reach", port_reached(payload, main, port), params, warning=True))
            else:
                items.append(PreflightItem("fb_pf_proxy_later", True, params, info=True))
        # The loop: the hub's upstream is outside the set and IS the main server —
        # by the DNS API's record, by public resolvers and by the hub's own view.
        # The upstream NAME is the one the hub reports now, not the bot's stored
        # copy: a hub re-pointed by hand to a failover name resolves to main today
        # (so every address check agrees) and would DNAT into itself after the switch.
        live = payload.get("live_target") if payload else None
        resolved = payload.get("resolved") if payload else None
        reported = str(payload.get("target_host") or "").lower() if payload else ""
        hub_view = live == main and (not isinstance(resolved, list) or set(map(str, resolved)) <= {main})
        answers = await self._doh(origin)
        public = NameResult(name=origin, ok=True, ipv4=main, doh=tuple(answers)).propagated
        same_upstream = reported == origin.lower()
        items.append(PreflightItem(
            "fb_pf_loop",
            origin not in names and reported not in names and same_upstream and hub_view and public,
            {"origin": origin, "main": main, "hub_view": f"{reported or '—'} → {live or '—'}", "seen": _seen(answers)},
        ))
        return items

    async def _preflight_name(self, name: str, allowed: set[str]) -> list[PreflightItem]:
        try:
            zone = await self._zone(name)
            records = await self.dns.records(zone.id, name, "A")
            aaaa = await self.dns.records(zone.id, name, "AAAA")
        except DnsApiError as exc:
            return [PreflightItem("fb_pf_record_error", False, {"name": name, "error": str(exc)})]
        items: list[PreflightItem] = []
        if len(records) != 1:
            items.append(PreflightItem("fb_pf_record_count", False, {"name": name, "count": len(records)}))
        else:
            record = records[0]
            if record.proxied:
                items.append(PreflightItem("fb_pf_record_proxied", False, {"name": name}))
            elif record.content not in allowed:
                items.append(PreflightItem(
                    "fb_pf_record_foreign", False, {"name": name, "value": record.content},
                ))
            else:
                items.append(PreflightItem("fb_pf_record_ok", True, {"name": name, "value": record.content}))
        if aaaa:
            items.append(PreflightItem("fb_pf_record_aaaa", False, {"name": name, "count": len(aaaa)}, warning=True))
        return items

    # ── DNS helpers ───────────────────────────────────────────────────────────

    def _token(self) -> str:
        try:
            return self.token_file.load()
        except DnsTokenMissing as exc:
            raise InvalidOperation(str(exc), key="fb_err_no_token") from None

    async def _zone(self, name: str) -> DnsZone:
        cached = self._zones.get(name)
        if cached is not None:
            return cached
        zone = await self.dns.find_zone(name)
        self._zones[name] = zone
        return zone

    async def _ensure_record(self, name: str, address: str, *, allowed: set[str] | None = None) -> bool:
        """The A record of *name* holds *address* (``proxied=false``, TTL 60).
        True when it had to be created. Refused — nothing written — for a name with
        several A records, a proxied one, or (with *allowed*) one that points at an
        address that is neither the main server nor the hub."""
        self._token()
        try:
            zone = await self._zone(name)
            records = await self.dns.records(zone.id, name, "A")
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="fb_err_dns", params={"error": str(exc)}) from None
        if len(records) > 1:
            raise InvalidOperation(
                f"{name}: {len(records)} A-записи — оставьте одну", key="fb_err_record_count",
                params={"name": name, "count": len(records)},
            )
        if not records:
            await self._dns_write(lambda: self.dns.create_a(zone.id, name, address))
            return True
        record = records[0]
        if allowed is not None and record.content not in allowed:
            raise InvalidOperation(
                f"{name}: A-запись указывает на {record.content} — не main и не hub, не перезаписываю",
                key="fb_err_record_foreign", params={"name": name, "value": record.content},
            )
        if record.content != address or record.proxied or record.ttl != 60:
            await self._dns_write(lambda: self.dns.update_a(zone.id, record.id, address))
        return False

    @staticmethod
    async def _dns_write(write: Callable[[], Awaitable[DnsRecord]]) -> DnsRecord:
        try:
            return await write()
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="fb_err_dns", params={"error": str(exc)}) from None

    # ── misc ──────────────────────────────────────────────────────────────────

    async def _require_relay(self, relay_id: int) -> Relay:
        relay = await self.relays_repo.get_by_id(relay_id)
        if relay is None:
            raise NotFound("Relay не найден", key="err_relay_not_found")
        return relay

    async def _audit(
        self, actor_user_id: int | None, action: str, details: dict[str, object], *, relay_id: int | None = None
    ) -> None:
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=AuditEntityType.RELAY,
            entity_id=relay_id,
            details=details,
        )


def _log_reconcile_failure(task: asyncio.Task[ProxyReconcile]) -> None:
    if not task.cancelled() and task.exception() is not None:
        logger.warning("Fallback: the proxy reconcile failed", exc_info=task.exception())


def _ports_of(value: object) -> tuple[int, ...] | None:
    """The port list of an agent's status (``[443, 2096]``), or None when absent/malformed."""
    if not isinstance(value, list) or not all(type(port) is int for port in value):
        return None
    return tuple(sorted(value))


def _seen(answers: Iterable[DohAnswer]) -> str:
    parts = []
    for answer in answers:
        parts.append(f"{answer.resolver}: {answer.error or ', '.join(answer.addresses) or '—'}")
    return "; ".join(parts) or "—"
