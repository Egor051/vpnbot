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

SEAMS left on purpose (not built here): :func:`services.relay.select_hub` is where
a balancer would choose among several hubs; :meth:`FallbackService._switch` is the
switch without the superadmin check, for a future automatic switch on health.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
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
from services.relay import select_hub
from services.relay_pairing import format_ports, valid_dns_name
from services.relays import RelayService, agent_uninstalled
from services.users import UserService

logger = logging.getLogger(__name__)

NORMAL = "normal"
FAILOVER = "failover"
# `vpn-relay-apply check` exit codes a hub may report and still be fit: 0, or only
# the input filter's own complaints (16-18) — not the forward, not the upstream.
_HUB_CHECK_OK = frozenset({0, 16, 17, 18})
# How long the switch waits for public resolvers to agree, and how often it asks.
VERIFY_TIMEOUT_SECONDS = 30.0
VERIFY_INTERVAL_SECONDS = 5.0

Doh = Callable[[str], Awaitable[list[DohAnswer]]]


# ── results ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class PreflightItem:
    """One line of the preflight: an i18n key with its params, and the verdict."""

    key: str
    ok: bool
    params: dict[str, object] = field(default_factory=dict, hash=False, compare=False)
    # True: shown, but does not block the switch.
    warning: bool = False


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
class SwitchReport:
    target: str
    preflight: Preflight | None
    results: tuple[NameResult, ...] = ()

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


def only_input_filter_failures(lines: Iterable[str]) -> bool:
    """Every ``FAIL:`` line of a ``vpn-relay-apply check`` is about the input filter.

    The check exits with the code of its FIRST failure and runs the input filter's
    steps before ip_forward, conntrack, TCP and TLS, so an exit 16-18 alone does
    not say the forward is fine — the FAIL lines do. The agent's apply uses the
    same rule (scripts/vpn-relay-agent: only_input_filter_failures).
    """
    fails = [line for line in lines if "FAIL: " in line]
    return all("vpnrelay_input" in line or "listening but filtered" in line for line in fails)


def check_reaches(status: Mapping[str, Any], address: str, ports: Iterable[int]) -> tuple[bool, list[int]]:
    """Whether the agent's own ``vpn-relay-apply check`` connected to *address* on
    every port of *ports* — and failed on nothing but the input filter. Returns
    (passed, the ports that did not connect)."""
    check = status.get("check")
    lines = check.get("lines") if isinstance(check, dict) else None
    rc = check.get("rc") if isinstance(check, dict) else None
    text = [str(line) for line in lines] if isinstance(lines, list) else []
    missing = [
        port for port in ports
        if not any(f"ok: TCP connect {address}:{port}" in line for line in text)
        or any(f"FAIL: TCP connect {address}:{port}" in line for line in text)
    ]
    healthy = isinstance(rc, int) and (rc == 0 or (rc in _HUB_CHECK_OK and only_input_filter_failures(text)))
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

    # ── state for the health loop ─────────────────────────────────────────────

    async def refresh_state(self) -> None:
        """Re-read the mode and the names (after every write, and at startup)."""
        self._mode_on = await self.repo.mode_on()
        self._names = frozenset(name.name for name in await self.repo.list_names())

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
        """Names the admin will likely want in the set: HYSTERIA2_SNI (the
        subscription's and the hy2 certificate's name), the names the edge relays
        forward to, a DNS-named XRAY_PUBLIC_HOST — minus what is in the set and
        what can never be there (a hub's origin or host)."""
        await self.users.require_superadmin(actor_user_id)
        taken = {name.name for name in await self.repo.list_names()}
        forbidden = await self._forbidden_names()
        found: list[str] = []
        values: list[str] = [self.settings.hysteria2_sni, self.settings.xray_public_host]
        for relay in await self.relays_repo.list_all():
            if not relay.is_hub and relay.agent is not None:
                values.append(relay.agent.target_host)
        for value in values:
            name = (value or "").strip().lower()
            if valid_dns_name(name) and name not in taken and name not in forbidden and name not in found:
                found.append(name)
        return found

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

    async def enable(self, actor_user_id: int) -> SwitchReport:
        await self.users.require_superadmin(actor_user_id)
        return await self._switch(FAILOVER, actor_user_id)

    async def disable(self, actor_user_id: int) -> SwitchReport:
        await self.users.require_superadmin(actor_user_id)
        return await self._switch(NORMAL, actor_user_id)

    async def repeat(self, actor_user_id: int) -> SwitchReport:
        """«Повторить»: the switch the mode asks for, again — finishes a partial one."""
        await self.users.require_superadmin(actor_user_id)
        return await self._switch(FAILOVER if await self.repo.mode_on() else NORMAL, actor_user_id)

    async def _switch(self, target: str, actor_user_id: int | None) -> SwitchReport:
        """THE switch (no authorization here: the public methods check it — a future
        automatic switch on health calls this with ``actor_user_id=None``)."""
        async with self._lock:
            names = await self.repo.list_names()
            if not names:
                raise InvalidOperation("набор пуст", key="fb_err_no_names")
            if target == FAILOVER:
                preflight = await self._preflight(actor_user_id)
                if not preflight.passed:
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
            await self.repo.set_mode(target == FAILOVER, now=self.clock.now())
            await self.refresh_state()
            written: list[NameResult] = []
            for name in names:
                written.append(await self._write_name(name, target, address))
            results = await self._verify(written)
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
        return SwitchReport(target=target, preflight=preflight, results=tuple(results))

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
        if hub is not None and hub.agent is not None and not agent_uninstalled(hub.agent) and main and actor_user_id:
            items.extend(await self._preflight_hub(actor_user_id, hub, main, names_set))
        elif hub is not None:
            items.append(PreflightItem("fb_pf_agent_failed", False, {"name": hub.name, "error": "—"}))
        if token_ok and main and hub_ip:
            for name in names:
                items.extend(await self._preflight_name(name.name, {main, hub_ip}))
        return Preflight(tuple(items))

    async def _preflight_hub(
        self, actor_user_id: int, hub: Relay, main: str, names: set[str]
    ) -> list[PreflightItem]:
        assert hub.agent is not None
        items: list[PreflightItem] = []
        origin = hub.agent.target_host
        tcp, udp = self.hub_ports()
        forwards = set(tcp) <= set(hub.agent.tcp_ports) and set(udp) <= set(hub.agent.udp_ports)
        items.append(PreflightItem(
            "fb_pf_forward", forwards,
            {"name": hub.name, "want": f"tcp={format_ports(tcp)} udp={format_ports(udp)}",
             "have": f"tcp={format_ports(hub.agent.tcp_ports)} udp={format_ports(hub.agent.udp_ports)}"},
        ))
        try:
            reply = await self.relays.agent_status(actor_user_id, hub.id)
            payload: Mapping[str, Any] = reply.payload
            items.append(PreflightItem("fb_pf_agent", True, {"name": hub.name}))
        except ServiceError as exc:
            items.append(PreflightItem("fb_pf_agent_failed", False, {"name": hub.name, "error": str(exc)[:200]}))
            payload = {}
        if payload:
            reached, missing = check_reaches(payload, main, tcp)
            items.append(PreflightItem(
                "fb_pf_reach", reached,
                {"name": hub.name, "main": main, "ports": format_ports(tcp),
                 "missing": format_ports(missing) if missing else "—"},
            ))
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


def _seen(answers: Iterable[DohAnswer]) -> str:
    parts = []
    for answer in answers:
        parts.append(f"{answer.resolver}: {answer.error or ', '.join(answer.addresses) or '—'}")
    return "; ".join(parts) or "—"
