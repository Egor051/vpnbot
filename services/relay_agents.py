"""Relays the bot installs and manages itself: «Мастер настройки → Relay» (docs/relay.md).

The flow, SUPERADMIN only, every step audited (entity ``relay``):

1. **Issue** (dangerous → TOTP in the UI): the bot's relay key is generated once
   (:class:`services.relay_ssh.RelayKeyStore`); a pairing row holds a fresh one-time
   token and the expiry (30 minutes); the code (services/relay_pairing.py) and ONE
   command line for the relay are rendered: the installer of the bot's own commit,
   its sha256 pinned, the code on stdin.
2. The operator runs it on the relay: ``scripts/install.sh --relay`` installs the data
   plane and the agent and authorizes the bot's key for the agent only.
3. **Complete**: the operator sends the relay's address. The bot connects (trust on
   first use: the host key is pinned now), runs ``hello <token>``, checks the relay
   from outside — TCP through it to this host's REALITY inbound (the health probe)
   and UDP to Hysteria2 (QUIC version negotiation) — and only when neither FAILS
   registers it: a row in ``relays`` (the existing relay model: links, bundles,
   the health loop with its alerts) whose source IPs — the address it is reached at
   and the source address it reports for the upstream — are what the anomaly
   detector excludes, plus the ``relay_agents`` row. The token is cleared.
4. **Manage**: ``status``, ``update``, ``apply`` (target/ports), and delete =
   ``uninstall`` on the relay + the relay row (with its keys when asked).

The relay never talks to Telegram; the bot talks to the relay over SSH only.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import logging
import re
import socket
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from adapters.clock import ClockProvider
from config import validators
from config.settings import Settings
from models.dto import Relay, RelayAgent, RelayPairing
from models.enums import AuditEntityType
from repositories.relay_agents import RelayAgentRepository
from services.audit import AuditService
from services.errors import InvalidOperation, NotFound, ServiceError
from services.relay_health import tls_probe, udp_relay_probe
from services.relay_management import RelayDeletionReport, RelayService
from services.relay_pairing import (
    COMPLETION_GRACE_SECONDS,
    DEFAULT_OWNER,
    DEFAULT_REPO,
    PAIRING_TTL_SECONDS,
    PairingCode,
    PairingCodeError,
    Source,
    encode_pairing_code,
    format_ports,
    github_remote,
    new_token,
    parse_ports,
    parse_target_host,
    relay_command,
    valid_dns_name,
)
from services.relay_ssh import AgentReply, RelayAgentClient, RelayKeyStore, RelaySshError
from services.users import UserService

logger = logging.getLogger(__name__)

PROTOCOL = 1
DEFAULT_SSH_PORT = 22
_ADDRESS = re.compile(r"(?P<host>[A-Za-z0-9.-]{1,253})(?::(?P<port>[0-9]{1,5}))?")
_SHA = re.compile(r"[0-9a-f]{40}")


class RelayAgentError(ServiceError):
    """The agent on the relay refused or failed a request (its reason in params)."""


class PairingCheckFailed(InvalidOperation):
    """The relay answered hello, but traffic through it does not reach this server."""

    def __init__(self, checks: CheckResult) -> None:
        super().__init__(
            "проверка через relay не прошла", key="relay_pair_check_failed", params={"checks": checks.describe()}
        )
        self.checks = checks


# ── where the relay gets the installer: this checkout's own commit ────────────


def _read_head(git_dir: Path) -> str | None:
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if _SHA.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    if not re.fullmatch(r"refs/[A-Za-z0-9._/-]+", ref) or ".." in ref:
        return None
    try:
        value = (git_dir / ref).read_text(encoding="utf-8").strip()
        return value if _SHA.fullmatch(value) else None
    except OSError:
        pass
    try:
        for line in (git_dir / "packed-refs").read_text(encoding="utf-8").splitlines():
            sha, _, name = line.partition(" ")
            if name.strip() == ref and _SHA.fullmatch(sha):
                return sha
    except OSError:
        return None
    return None


def _origin_url(git_dir: Path) -> str:
    try:
        text = (git_dir / "config").read_text(encoding="utf-8")
    except OSError:
        return ""
    section = re.search(r'\[remote "origin"\](.*?)(?:\n\[|\Z)', text, re.S)
    if section is None:
        return ""
    url = re.search(r"^\s*url\s*=\s*(\S+)\s*$", section.group(1), re.M)
    return url.group(1) if url else ""


def installer_source(repo_root: Path) -> Source:
    """The installer the relay runs: this checkout's commit (its file's sha256)."""
    git_dir = repo_root / ".git"
    commit = _read_head(git_dir)
    if commit is None:
        raise InvalidOperation("не удалось определить коммит бота (.git)", key="relay_pair_no_commit")
    try:
        digest = hashlib.sha256((repo_root / "scripts" / "install.sh").read_bytes()).hexdigest()
    except OSError as exc:
        raise InvalidOperation("нет scripts/install.sh в checkout бота", key="relay_pair_no_installer") from exc
    owner, repo = github_remote(_origin_url(git_dir)) or (DEFAULT_OWNER, DEFAULT_REPO)
    return Source(owner=owner, repo=repo, commit=commit, installer_sha256=digest)


# ── results ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class IssuedPairing:
    pairing: RelayPairing
    code: str
    command: str


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The outside checks of a relay: True / False / None (not checked: protocol off)."""

    tcp: bool | None
    udp: bool | None

    @property
    def passed(self) -> bool:
        return self.tcp is not False and self.udp is not False

    def describe(self) -> str:
        def mark(value: bool | None) -> str:
            return "—" if value is None else ("ok" if value else "FAIL")

        return f"TCP {mark(self.tcp)}, UDP {mark(self.udp)}"


@dataclass(frozen=True, slots=True)
class PairingOutcome:
    relay: Relay
    agent: RelayAgent
    checks: CheckResult
    health_interval: int


@dataclass(frozen=True, slots=True)
class RemovalReport:
    relay: Relay
    uninstalled: bool
    deletion: RelayDeletionReport


_NOT_REACHABLE = tuple(
    ipaddress.IPv4Network(n)
    for n in ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
              "192.168.0.0/16", "224.0.0.0/3")
)


def routable(address: str) -> bool:
    """An address the main server can reach and see traffic from: not RFC 1918, CGNAT,
    loopback, link-local, multicast or reserved (documentation ranges pass: tests)."""
    ip = ipaddress.IPv4Address(address)
    return not any(ip in network for network in _NOT_REACHABLE)


def parse_address(value: str) -> tuple[str, int]:
    """``host[:port]`` — a DNS name or IPv4, ssh port 22 by default."""
    text = (value or "").strip()
    match = _ADDRESS.fullmatch(text)
    if match is None:
        raise InvalidOperation("адрес relay: host или host:port", key="relay_pair_bad_address", params={"value": text})
    host, port = match["host"].lower(), int(match["port"] or DEFAULT_SSH_PORT)
    is_ip = validators.ipv4_address(host) is not None
    if not (is_ip or valid_dns_name(host)) or not 1 <= port <= 65535:
        raise InvalidOperation("адрес relay: host или host:port", key="relay_pair_bad_address", params={"value": text})
    if is_ip and not routable(host):
        raise InvalidOperation(
            "это не публичный адрес", key="relay_pair_private_address", params={"value": host}
        )
    return host, port


async def resolve_ipv4(host: str) -> list[str]:
    if validators.ipv4_address(host) is not None:
        return [host]
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({str(info[4][0]) for info in infos})


class RelayAgentService:
    """Pairing and management of the relays that run ``vpn-relay-agent``."""

    def __init__(
        self,
        *,
        repo: RelayAgentRepository,
        relays: RelayService,
        users: UserService,
        audit: AuditService,
        clock: ClockProvider,
        keys: RelayKeyStore,
        client: RelayAgentClient,
        settings: Settings,
        source_root: Path,
        tcp_probe: Callable[[str, int, str], Awaitable[bool]] | None = None,
        udp_probe: Callable[[str, int], Awaitable[bool | None]] | None = None,
        resolve: Callable[[str], Awaitable[list[str]]] = resolve_ipv4,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.repo = repo
        self.relays = relays
        self.users = users
        self.audit = audit
        self.clock = clock
        self.keys = keys
        self.client = client
        self.settings = settings
        self.source_root = source_root
        self._tcp_probe = tcp_probe
        self._udp_probe = udp_probe
        self._resolve = resolve
        self._now = now
        self._lock = asyncio.Lock()

    # ── defaults the UI offers ────────────────────────────────────────────────

    def default_target(self) -> str | None:
        """The main server's DNS name: the host of direct links, else Hysteria2's."""
        for value in (self.settings.xray_public_host, self.settings.hysteria2_host, self.settings.hysteria2_sni):
            host = (value or "").strip().lower()
            if valid_dns_name(host):
                return host
        return None

    def default_ports(self) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """1:1 with this server: XRAY_PUBLIC_PORT/tcp and HYSTERIA2_PORT/udp (443 both by default)."""
        return (self.settings.xray_public_port,), (self.settings.hysteria2_port,)

    # ── pairing ───────────────────────────────────────────────────────────────

    async def _expire(self) -> None:
        await self.repo.expire_pairings(before=int(self._now()) - COMPLETION_GRACE_SECONDS, now=self.clock.now())

    async def pending(self, actor_user_id: int) -> list[RelayPairing]:
        await self.users.require_superadmin(actor_user_id)
        await self._expire()
        return await self.repo.list_pending()

    async def check_name(self, actor_user_id: int, value: str) -> str:
        name = await self.relays.check_new_name(actor_user_id, value)
        if await self.repo.pending_name_taken(name):
            raise InvalidOperation(f"имя {name!r} уже ждёт подключения", key="relay_pair_name_pending", params={"value": name})
        return name

    async def issue(self, actor_user_id: int, *, name: str, target_host: str) -> IssuedPairing:
        await self.users.require_superadmin(actor_user_id)
        try:
            target = parse_target_host(target_host)
        except PairingCodeError as exc:
            raise InvalidOperation(str(exc), key="relay_pair_bad_target", params={"value": target_host}) from exc
        tcp, udp = self.default_ports()
        async with self._lock:
            await self._expire()
            clean_name = await self.check_name(actor_user_id, name)
            self.keys.ensure()
            pairing = await self.repo.create_pairing(
                name=clean_name,
                token=new_token(),
                target_host=target,
                tcp_ports=tcp,
                udp_ports=udp,
                expires_at=int(self._now()) + PAIRING_TTL_SECONDS,
                created_by=actor_user_id,
                now=self.clock.now(),
            )
        await self._audit(
            actor_user_id,
            "relay_pairing_issued",
            None,
            {"pairing_id": pairing.id, "name": clean_name, "target_host": target, "tcp": list(tcp), "udp": list(udp)},
        )
        return self._render(pairing)

    def _render(self, pairing: RelayPairing) -> IssuedPairing:
        code = encode_pairing_code(
            PairingCode(
                target_host=pairing.target_host,
                tcp_ports=pairing.tcp_ports,
                udp_ports=pairing.udp_ports,
                main_pubkey=self.keys.public_key(),
                token=pairing.token,
                exp=pairing.expires_at,
            )
        )
        return IssuedPairing(pairing=pairing, code=code, command=relay_command(code, installer_source(self.source_root)))

    async def _pending(self, pairing_id: int) -> RelayPairing:
        await self._expire()
        pairing = await self.repo.get_pairing(pairing_id)
        if pairing is None or pairing.state != "pending" or not pairing.token:
            raise NotFound("pairing не найден или закрыт", key="relay_pair_not_pending")
        return pairing

    async def show(self, actor_user_id: int, pairing_id: int) -> IssuedPairing:
        await self.users.require_superadmin(actor_user_id)
        return self._render(await self._pending(pairing_id))

    async def cancel(self, actor_user_id: int, pairing_id: int) -> None:
        """Cancel a pending pairing. Under the completion lock: a cancel never lands in
        the middle of a completion (it waits for it, then finds nothing pending)."""
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            cancelled = await self.repo.finish_pairing(pairing_id, "cancelled", now=self.clock.now())
        if cancelled:
            await self._audit(actor_user_id, "relay_pairing_cancelled", None, {"pairing_id": pairing_id})

    async def checks(self, host: str) -> CheckResult:
        tcp: bool | None = None
        if self.settings.xray_sni:
            probe = self._tcp_probe or tls_probe
            tcp = bool(await probe(host, self.settings.xray_public_port, self.settings.xray_sni))
        udp: bool | None = None
        if self.settings.hysteria2_enabled:
            uprobe = self._udp_probe or udp_relay_probe
            udp = await uprobe(host, self.settings.hysteria2_port)
        return CheckResult(tcp=tcp, udp=udp)

    async def complete(self, actor_user_id: int, pairing_id: int, address: str) -> PairingOutcome:
        """hello -> the outside checks -> the relay registered (see the module doc)."""
        await self.users.require_superadmin(actor_user_id)
        host, port = parse_address(address)
        async with self._lock:
            pairing = await self._pending(pairing_id)
            reply = await self.client.call(
                host,
                port,
                f"hello {pairing.token}",
                alias=f"vpn-relay-pairing-{pairing.id}",
                host_key=None,
                sensitive=(pairing.token,),
            )
            if not reply.ok:
                raise RelayAgentError(
                    f"relay отказал: {reply.error}", key="relay_agent_refused", params={"error": reply.error[:300]}
                )
            self._expect_pairing(reply.payload, pairing)
            if reply.learned_host_key is None:
                raise RelaySshError("ключ хоста relay не получен", key="relay_ssh_bad_host_key")
            checks = await self.checks(host)
            if not checks.passed:
                await self._audit(
                    actor_user_id, "relay_pairing_check_failed", None,
                    {"pairing_id": pairing.id, "host": host, "checks": checks.describe()},
                )
                raise PairingCheckFailed(checks)
            sources = await self._source_ips(host, reply.payload)
            relay = await self.relays.create(
                actor_user_id,
                name=pairing.name,
                host=host,
                source_ips=",".join(sources),
                label=await self._free_label(actor_user_id, pairing.name),
                note="paired by the bot (vpn-relay-agent)",
            )
            try:
                agent = await self.repo.create(
                    relay_id=relay.id,
                    ssh_host=host,
                    ssh_port=port,
                    host_key=reply.learned_host_key,
                    target_host=pairing.target_host,
                    tcp_ports=pairing.tcp_ports,
                    udp_ports=pairing.udp_ports,
                    agent_version=str(reply.payload.get("agent", "")),
                    now=self.clock.now(),
                    status=_slim(reply.payload),
                )
            except Exception:
                # No half-registered relay: without its agent row it would look hand-made.
                await self.relays.delete(actor_user_id, relay.id, with_keys=False)
                raise
            if not await self.repo.finish_pairing(pairing.id, "completed", now=self.clock.now(), relay_id=relay.id):
                # Expired or cancelled meanwhile: no relay is registered for a pairing that
                # is not completed (the agent row goes with the relay row).
                await self.relays.delete(actor_user_id, relay.id, with_keys=False)
                raise NotFound("pairing не найден или закрыт", key="relay_pair_not_pending")
        await self._audit(
            actor_user_id,
            "relay_paired",
            relay.id,
            {"name": relay.name, "host": host, "ssh_port": port, "source_ips": sources,
             "target_host": pairing.target_host, "checks": checks.describe()},
        )
        return PairingOutcome(
            relay=relay, agent=agent, checks=checks, health_interval=self.settings.relay_health_interval
        )

    @staticmethod
    def _expect_pairing(payload: dict[str, Any], pairing: RelayPairing) -> None:
        if payload.get("protocol") != PROTOCOL:
            raise RelayAgentError(
                "несовместимая версия агента", key="relay_agent_protocol", params={"value": payload.get("protocol")}
            )
        got = (payload.get("target_host"), tuple(payload.get("tcp") or ()), tuple(payload.get("udp") or ()))
        want = (pairing.target_host, pairing.tcp_ports, pairing.udp_ports)
        if got != want:
            raise RelayAgentError(
                "relay настроен не по этому коду", key="relay_agent_mismatch",
                params={"got": f"{got[0]} {format_ports(got[1])}/{format_ports(got[2])}"},
            )

    async def _source_ips(self, host: str, payload: dict[str, Any]) -> list[str]:
        """What this server sees relayed traffic come from: the relay's address(es)
        and the source address it reports for the upstream, when that is public."""
        found = set(await self._resolve(host))
        egress = payload.get("egress")
        src = egress.get("src") if isinstance(egress, dict) else None
        if isinstance(src, str) and validators.ipv4_address(src) is not None and routable(src):
            found.add(src)
        if not found:
            raise InvalidOperation("не удалось определить адрес relay", key="relay_pair_no_source", params={"value": host})
        return sorted(found, key=lambda a: tuple(int(x) for x in a.split(".")))

    async def _free_label(self, actor_user_id: int, name: str) -> str:
        for candidate in (validators.DEFAULT_RELAY_LABEL, name[:16], f"{name[:15]}_"):
            if await self.relays.label_free(actor_user_id, candidate):
                return candidate
        return f"r{int(self._now()) % 100000}"

    # ── management ────────────────────────────────────────────────────────────

    async def managed(self, actor_user_id: int) -> list[tuple[Relay, RelayAgent]]:
        await self.users.require_superadmin(actor_user_id)
        relays = {relay.id: relay for relay in await self.relays.relays.list_all()}
        return [(relays[a.relay_id], a) for a in await self.repo.list_all() if a.relay_id in relays]

    async def get(self, actor_user_id: int, relay_id: int) -> tuple[Relay, RelayAgent]:
        relay = await self.relays.get(actor_user_id, relay_id)
        agent = await self.repo.get(relay_id)
        if agent is None:
            raise NotFound("relay не управляется ботом", key="relay_agent_not_managed")
        return relay, agent

    async def _call(self, agent: RelayAgent, request: str, *, timeout: float = 120.0) -> AgentReply:
        if agent_uninstalled(agent) and request != "uninstall":
            raise RelayAgentError("relay уже снят с хоста", key="relay_agent_uninstalled")
        return await self.client.call(
            agent.ssh_host, agent.ssh_port, request, alias=f"vpn-relay-{agent.relay_id}",
            host_key=agent.host_key, timeout=timeout,
        )

    def _require_ok(self, reply: AgentReply) -> AgentReply:
        if not reply.ok:
            raise RelayAgentError(
                f"relay: {reply.error}", key="relay_agent_refused", params={"error": reply.error[:300]}
            )
        return reply

    async def status(self, actor_user_id: int, relay_id: int) -> AgentReply:
        _, agent = await self.get(actor_user_id, relay_id)
        reply = self._require_ok(await self._call(agent, "status"))
        await self.repo.record_status(
            relay_id, _slim(reply.payload), now=self.clock.now(), agent_version=str(reply.payload.get("agent", ""))
        )
        return reply

    async def update(self, actor_user_id: int, relay_id: int) -> AgentReply:
        relay, agent = await self.get(actor_user_id, relay_id)
        async with self._lock:
            reply = await self._call(agent, "update", timeout=960.0)
        await self._audit(actor_user_id, "relay_agent_update", relay.id,
                          {"name": relay.name, "ok": reply.ok, "result": reply.payload.get("update") or reply.error})
        self._require_ok(reply)
        with contextlib.suppress(ServiceError):
            await self.status(actor_user_id, relay_id)
        return reply

    async def change_forward(
        self, actor_user_id: int, relay_id: int, *, target_host: str, tcp: str, udp: str
    ) -> AgentReply:
        relay, agent = await self.get(actor_user_id, relay_id)
        try:
            target = parse_target_host(target_host)
            tcp_ports, udp_ports = parse_ports(tcp), parse_ports(udp)
        except PairingCodeError as exc:
            raise InvalidOperation(str(exc), key="relay_agent_bad_forward", params={"error": str(exc)}) from exc
        request = f"apply target={target} tcp={format_ports(tcp_ports)} udp={format_ports(udp_ports)}"
        async with self._lock:
            reply = await self._call(agent, request, timeout=300.0)
            if reply.ok:
                await self.repo.update_forward(relay_id, target_host=target, tcp_ports=tcp_ports, udp_ports=udp_ports)
        await self._audit(
            actor_user_id, "relay_agent_apply", relay.id,
            {"name": relay.name, "ok": reply.ok,
             "before": {"target_host": agent.target_host, "tcp": list(agent.tcp_ports), "udp": list(agent.udp_ports)},
             "after": {"target_host": target, "tcp": list(tcp_ports), "udp": list(udp_ports)},
             **({} if reply.ok else {"error": reply.error[:300]})},
        )
        return self._require_ok(reply)

    async def remove(
        self, actor_user_id: int, relay_id: int, *, with_keys: bool, relay_side: bool = True
    ) -> RemovalReport:
        """``uninstall`` on the relay, then the relay row (with its keys when asked).

        ``relay_side=False`` (the relay is gone or does not answer) deletes only the
        row; the relay keeps forwarding until it is uninstalled by hand.
        """
        relay, agent = await self.get(actor_user_id, relay_id)
        uninstalled = agent_uninstalled(agent)
        async with self._lock:
            if relay_side and not uninstalled:
                reply = await self._call(agent, "uninstall", timeout=360.0)
                await self._audit(actor_user_id, "relay_agent_uninstall", relay.id,
                                  {"name": relay.name, "ok": reply.ok, **({} if reply.ok else {"error": reply.error[:300]})})
                self._require_ok(reply)
                # The key is no longer authorized there. The agent row stays (marked) until
                # the relay row is really gone, so an interrupted delete can be resumed from
                # the wizard; it goes with the relay row (ON DELETE CASCADE).
                await self.repo.record_status(
                    relay_id, {**(agent.last_status or {}), UNINSTALLED_KEY: self.clock.now()},
                    now=self.clock.now(), agent_version=agent.agent_version,
                )
                uninstalled = True
        deletion = await self.relays.delete(actor_user_id, relay_id, with_keys=with_keys)
        if deletion.deleted:
            await self.repo.delete(relay_id)  # already gone by the cascade; explicit for clarity
        return RemovalReport(relay=relay, uninstalled=uninstalled, deletion=deletion)

    async def _audit(self, actor_user_id: int | None, action: str, relay_id: int | None, details: dict[str, object]) -> None:
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=AuditEntityType.RELAY,
            entity_id=relay_id,
            details=details,
        )


UNINSTALLED_KEY = "uninstalled_at"


def agent_uninstalled(agent: RelayAgent) -> bool:
    """``uninstall`` already ran on this relay (a delete that did not finish)."""
    return bool((agent.last_status or {}).get(UNINSTALLED_KEY))


def _slim(payload: dict[str, Any]) -> dict[str, object]:
    """What is kept of a status answer (no unbounded fields)."""
    keep = ("agent", "protocol", "target_host", "tcp", "udp", "live_target", "resolved", "ip_forward",
            "units", "ssh_ports", "egress", "checkout", "update", "check", "paired_at")
    return {k: payload[k] for k in keep if k in payload}
