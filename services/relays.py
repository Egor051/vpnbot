"""Relays — ONE model, ONE service (docs/relay.md).

A relay is one row of ``relays``. How it is managed is a property of that row,
not a separate entity:

* **with an agent** (``relay.agent`` set — ``relays.ssh_host IS NOT NULL``): the
  bot reaches ``vpn-relay-agent`` on the relay over SSH with its one key and runs
  ``status`` / ``update`` / ``apply`` / ``uninstall`` there;
* **without** (``relay.agent is None``): a relay set up by hand — the legacy one
  from ``.env`` among them. It keeps working exactly as before; the panel offers
  to connect an agent to it, which changes nothing about the relay or its keys.

:class:`RelayService` is the only writer of the table and of ``relay_pairings``.
Everything goes through it, SUPERADMIN only (:class:`services.errors.AccessDenied`
otherwise), audited (entity ``relay``), under ONE asyncio lock. An agent call that
can take minutes (``update``, ``apply``, ``uninstall``) does not hold the lock
while the relay works: the relay is marked busy under the lock, the call runs, the
result is written under the lock again — anything else that wants to change that
relay meanwhile is refused («relay занят»), everything else goes on.

Ways a relay comes into existence or gets its agent — both through a pairing code
(services/relay_pairing.py) and ``scripts/install.sh --relay`` on the relay:

* **new relay** (:meth:`RelayService.issue_new`): name + the PUBLIC host its links
  will point at (a DNS name; an IPv4 works but a burned address then has to be
  changed at every client) + the main server's DNS name. Completing the code
  creates the relay with its agent in one transaction. The SSH address the
  operator sends is stored as the agent's ``ssh_host`` and never becomes
  ``relay.host``. The panel offers no other way to create a relay.
* **agent for an existing relay** (:meth:`RelayService.issue_attach`): completing
  the code writes ONLY the agent columns — name, label, host and keys stay as they
  are; ``source_ips`` may only grow (by the addresses the agent reports). The SSH
  address must be this relay (equal to its host, inside its source IPs, or the
  same address its host resolves to) — otherwise «это другой сервер». Any failure
  leaves the relay exactly as it was.

Every write replaces the bot's :class:`services.relay.RelayCatalog` snapshot right
away (the bot is the single writer; the subscription endpoint reads the table on
every request anyway). A relay's ``name`` is the value its keys carry in
``vpn_keys.relay`` and never changes; a name that any key row still carries can
never be given to a new relay.

Deleting a relay with an agent runs ``uninstall`` on the relay FIRST (so no DNAT
to this server is left behind), then removes the row. A relay that still has keys
loses each through the SAME path the key screen uses (backend removal, traffic
archive, audit), stopping at the first failure; running it again finishes the job.

THROUGH THE HUB (docs/relay.md «Управление RU-relay через hub»). The TSPU cuts SSH
from the main server to the RU relays. Every agent call to a relay that is
**behind the hub** — «через hub» on its card (``relays.via_hub``), or ANY relay but
a hub while the fallback mode is on — goes through the hub (:meth:`_route`): ssh to
the hub with the bot's JUMP key, ``-W`` on to the relay, both hops pinned
(services/relay_ssh.py). The hub's agent keeps ONE authorized_keys line for the
jump key whose ``permitopen`` lists exactly those relays' ``ssh_host:ssh_port``;
:meth:`sync_hub_jump` writes it (``jump key=… open=…`` / ``jump-off``) whenever the
set changes — the flag, the mode, a pairing, a detach, a delete, a new hub — and
before the first call through the hub. A pairing completed while the relay is
behind the hub says ``hello`` through it too; the outside checks from here cannot
pass then, so the relay's own ``vpn-relay-apply check`` (``status``, through the
hub) stands in for them.

BRINGING A RELAY TO THE DEFAULTS («Довести», :meth:`RelayService.harden`).
scripts/install.sh writes a NEW relay ``SSH_PORT=<the port sshd listens on>`` and
``RELAY_INPUT_FILTER=off`` — on purpose, so its first deploy cannot cut the bot off —
and nothing moved them on afterwards (he2, the hub all traffic goes through, ran SSH on
22 with no input filter). :func:`hardening_of` reads what is left from the agent's last
status; ``harden`` does it in two atomic steps, each rolled back when it fails:

1. the input filter: ``input-filter on`` (the agent applies it from a staged .env, the
   helper's dead-man armed), confirmed by ``input-confirm`` from a NEW ssh session of
   the bot (through the hub for a relay behind it), then ``input-filter on`` again
   commits .env. Not confirmed → ``input-filter off`` (or, when the relay cannot be
   reached at all, the dead-man within 5 minutes; .env never said on).
2. SSH off 22: ``ssh-port-set port=54321`` (phase 1: both ports), then
   :meth:`finish_ssh_port` — the bot's call ON 54321 is the proof, phase 2 closes 22.
   The new port not answering → ``ssh-port-set port=22`` cancels phase 1.

The filter goes FIRST: it is the bigger protection (every listener but sshd closed on
the host that carries the traffic) and the step that heals itself (the dead-man), so a
port move that cannot finish — a provider's firewall dropping 54321 — leaves the relay
filtered, on 22. The move then runs the path every default relay takes (filter on; the
filter follows the listeners; main's probe or the bot's new session confirms each TCP
set, and main's probe of {22, 54321} is a proof for phase 2 too). The price: two more
dead-man rounds, each confirmed by the bot itself.

THE INPUT FILTER. A ``status`` that reports ``PENDING CONFIRM`` (a deploy applied a
TCP set main's probe could not confirm — in the fallback mode main cannot reach the
relay at all) is answered with ``input-confirm``: the agent runs ``vpn-relay-apply
input-confirm`` inside the bot's ssh session, a NEW one, which is exactly the proof
that check wants. After ``update``, in the health loop, and from the card.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import re
import socket
import sqlite3
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from adapters.clock import ClockProvider
from config import validators
from config.settings import Settings
from models.dto import Relay, RelayAgent, RelayPairing
from models.enums import AuditEntityType, VpnKeyType
from repositories.relays import AGENT_UNINSTALLED_KEY, RelayRepository, RelayUsage
from services.audit import AuditService
from services.deploy_result import (
    REPO_SSHD_DROPINS,
    SSHD_AUTH_KEYS,
    SSHD_DROPIN,
    DeployFailure,
    deploy_failure_from,
)
from services.errors import InvalidOperation, NotFound, ServiceError
from services.notes import MAX_NOTE_LENGTH, normalize_note
from services.relay import RelayCatalog, RelaySnapshot, basic_has_visible_server, select_hub
from services.relay_health import AgentCheck, agent_check_from_status, tls_probe, udp_relay_probe
from services.relay_pairing import (
    COMPLETION_GRACE_SECONDS,
    PAIRING_TTL_SECONDS,
    PairingCode,
    PairingCodeError,
    encode_pairing_code,
    format_ports,
    installer_source,
    new_token,
    parse_ports,
    parse_target_host,
    relay_command,
    valid_dns_name,
)
from services.relay_ssh import (
    AgentReply,
    JumpHost,
    RelayAgentClient,
    RelayKeyStore,
    RelaySshError,
    jump_request,
)
from services.users import UserService

logger = logging.getLogger(__name__)

# Removes one key through its protocol's normal delete path: (actor, key_id).
KeyDeleter = Callable[[int, int], Awaitable[None]]

PROTOCOL = 1
DEFAULT_SSH_PORT = 22
# `update` runs a whole relay deploy, its pytest gate included, in the agent's transient
# unit (UPDATE_TIMEOUT = 2700 s in scripts/vpn-relay-agent); the answer may take that
# long, plus a minute for SSH and the agent itself.
AGENT_UPDATE_TIMEOUT = 2760.0
UNINSTALLED_KEY = AGENT_UNINSTALLED_KEY
# The agent's AGENT_VERSION from which it knows a request (scripts/vpn-relay-agent:
# 3 — update-status and the progress of an update; 4 — input-filter on|off).
AGENT_SSH_PORT = 3
AGENT_UPDATE_STATUS = 3
AGENT_INPUT_FILTER = 4
# 5 — sshd-check, sshd-override-off, update-log; sshd_drift / sshd_overrides in status.
AGENT_SSHD_OVERRIDE = 5
# «Довести relay до нормы» (docs/relay.md#bringing-a-relay-to-the-defaults): the defaults a
# relay is brought to — SSH_PORT's default (DEFAULT_PORT of scripts/vpn-bot-ssh-port,
# deploy/relay/relay.env.example) away from 22, and RELAY_INPUT_FILTER=on.
HARDEN_SSH_PORT = 54321
HARDEN_FROM_PORT = 22
# How `vpn-relay-apply input-status` starts while a TCP set waits for input-confirm.
INPUT_PENDING = "PENDING CONFIRM"
# `vpn-relay-apply check` exit codes a relay may report and still forward: 0, or only
# the input filter's own complaints (16-18) — judged by the FAIL lines.
CHECK_OK_CODES = frozenset({0, 16, 17, 18})
# Why an ssh through the hub may just need the hub's jump line written again.
_JUMP_RESYNC_KEYS = frozenset({"relay_ssh_jump_refused", "relay_ssh_jump_denied"})
_ADDRESS = re.compile(r"(?P<host>[A-Za-z0-9.-]{1,253})(?::(?P<port>[0-9]{1,5}))?")


# ── input validation (shared by the service and the panel's steps) ────────────


def parse_relay_name(value: str) -> str:
    """A new relay's name, or a localized error saying what the format is."""
    name = (value or "").strip()
    try:
        return validators.relay_name("name", name)
    except validators.InvalidValue as exc:
        raise InvalidOperation(str(exc), key="err_relay_name_invalid", params={"value": name}) from exc


def parse_relay_label(value: str) -> str:
    """A relay's marker, or a localized error saying what the format is."""
    label = (value or "").strip()
    try:
        return validators.relay_label("label", label)
    except validators.InvalidValue as exc:
        raise InvalidOperation(str(exc), key="err_relay_label_invalid", params={"value": label}) from exc


def parse_relay_host(value: str) -> str:
    """A relay's public host: a DNS name or an IPv4 address, never empty."""
    try:
        host = validators.dns_name_or_ipv4("host", value or "")
    except validators.InvalidValue as exc:
        raise InvalidOperation(
            str(exc), key="err_relay_host_invalid", params={"value": (value or "").strip()}
        ) from exc
    if not host:
        raise InvalidOperation("host не задан", key="err_relay_host_required")
    return host


def host_is_ipv4(host: str) -> bool:
    """The host is an IPv4 address (allowed, but a burned IP means re-importing every key)."""
    return validators.ipv4_address(host) is not None


def parse_relay_source_ips(value: str) -> tuple[ipaddress.IPv4Network, ...]:
    """A relay's egress list: IPv4 addresses / CIDR networks, comma-separated, never empty.

    Parsed with :func:`config.validators.parse_ipv4_networks`. On a bad entry the
    error names that entry, found by running the same parser over the items one
    by one.
    """
    raw = value or ""
    try:
        networks = validators.parse_ipv4_networks("source_ips", raw)
    except validators.InvalidValue as exc:
        bad = raw.strip()
        for item in raw.split(","):
            try:
                validators.parse_ipv4_networks("source_ips", item)
            except validators.InvalidValue:
                bad = item.strip()
                break
        raise InvalidOperation(str(exc), key="err_relay_source_ips_invalid", params={"value": bad}) from exc
    if not networks:
        raise InvalidOperation("source_ips пуст", key="err_relay_source_ips_required")
    return networks


def parse_relay_note(value: str | None) -> str | None:
    """A relay's note: the key-note rules (one line, bounded length; ``-`` clears it)."""
    try:
        return normalize_note(value)
    except ValueError as exc:
        raise InvalidOperation(str(exc), key="err_relay_note_invalid", params={"max": MAX_NOTE_LENGTH}) from exc


_NOT_REACHABLE = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.168.0.0/16", "224.0.0.0/3",
    )
)


def routable(address: str) -> bool:
    """An address the main server can reach and see traffic from: not RFC 1918, CGNAT,
    loopback, link-local, multicast or reserved (documentation ranges pass: tests)."""
    ip = ipaddress.IPv4Address(address)
    return not any(ip in network for network in _NOT_REACHABLE)


def parse_address(value: str) -> tuple[str, int]:
    """The relay's SSH address: ``host[:port]`` — a DNS name or IPv4, port 22 by default."""
    text = (value or "").strip()
    match = _ADDRESS.fullmatch(text)
    if match is None:
        raise InvalidOperation("адрес relay: host или host:port", key="relay_pair_bad_address", params={"value": text})
    host, port = match["host"].lower(), int(match["port"] or DEFAULT_SSH_PORT)
    is_ip = validators.ipv4_address(host) is not None
    if not (is_ip or valid_dns_name(host)) or not 1 <= port <= 65535:
        raise InvalidOperation("адрес relay: host или host:port", key="relay_pair_bad_address", params={"value": text})
    if is_ip and not routable(host):
        raise InvalidOperation("это не публичный адрес", key="relay_pair_private_address", params={"value": host})
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


def _sort_ips(addresses: Iterable[str]) -> list[str]:
    return sorted(set(addresses), key=lambda a: tuple(int(x) for x in a.split(".")))


def _covers(networks: tuple[ipaddress.IPv4Network, ...], host: str) -> bool:
    address = validators.ipv4_address(host)
    return address is not None and any(address in network for network in networks)


def merge_source_ips(
    current: tuple[ipaddress.IPv4Network, ...], found: Iterable[str]
) -> tuple[tuple[ipaddress.IPv4Network, ...], tuple[str, ...]]:
    """*current* plus every address of *found* it does not cover yet — nothing is removed.

    Returns the merged list and the addresses that were added.
    """
    merged = list(current)
    added: list[str] = []
    for address in _sort_ips(found):
        if not _covers(tuple(merged), address):
            merged.append(ipaddress.IPv4Network(f"{address}/32"))
            added.append(address)
    return tuple(merged), tuple(added)


def _audit_view(relay: Relay) -> dict[str, object]:
    """The audited fields of a relay (no secrets — a relay has none; the host key is public)."""
    view: dict[str, object] = {
        "name": relay.name,
        "label": relay.label,
        "host": relay.host,
        "source_ips": validators.format_ipv4_networks(relay.source_ips),
        "enabled": relay.enabled,
        "in_subscriptions": relay.in_subscriptions,
        "basic_visible": relay.basic_visible,
        "note": relay.note,
        "role": relay.role,
    }
    if relay.agent is not None:
        view["agent"] = {
            "ssh": f"{relay.agent.ssh_host}:{relay.agent.ssh_port}",
            "target_host": relay.agent.target_host,
            "tcp": list(relay.agent.tcp_ports),
            "udp": list(relay.agent.udp_ports),
        }
    return view


def agent_version_number(agent: RelayAgent | None) -> int | None:
    """The agent's AGENT_VERSION (scripts/vpn-relay-agent) as its last answer said it,
    None when it is not known (no answer kept yet, not a number)."""
    raw = agent.agent_version.strip() if agent is not None else ""
    return int(raw) if raw.isdigit() and len(raw) <= 6 else None


def agent_older_than(agent: RelayAgent | None, version: int) -> bool:
    """The agent is KNOWN to be older than *version* (an unknown version is not)."""
    number = agent_version_number(agent)
    return number is not None and number < version


def agent_release(agent: RelayAgent | None) -> str:
    """How the agent is named to a superadmin: the release its checkout is on
    (``git describe`` of the last status, «v3.2.0»), else its AGENT_VERSION («#2»)."""
    status = (agent.last_status or {}) if agent is not None else {}
    checkout = status.get("checkout")
    describe = str(checkout.get("describe") or "") if isinstance(checkout, dict) else ""
    if re.fullmatch(r"v[0-9][A-Za-z0-9.+-]{0,60}", describe):
        return describe
    number = agent_version_number(agent)
    return f"#{number}" if number is not None else "?"


@dataclass(frozen=True, slots=True)
class SshdOverride:
    """A FOREIGN SSHD OVERRIDE (scripts/vpn-relay-agent, docs/relay.md «Чужой
    sshd-override»): a file in sshd_config.d the repo does not install that beats a repo
    auth key — the keys it beats, the check's texts, the file's mtime (a file that comes
    back is a new one)."""

    path: str
    keys: tuple[str, ...]
    texts: tuple[str, ...] = ()
    mtime: int | None = None

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


def sshd_overrides_of(raw: object) -> tuple[SshdOverride, ...]:
    """An agent's ``sshd_overrides`` (``status`` / ``sshd-check``), validated: only a file
    directly in sshd_config.d that the repo does not install, beating a known auth key."""
    if not isinstance(raw, list):
        return ()
    found: list[SshdOverride] = []
    for item in raw[:16]:
        if not isinstance(item, Mapping):
            continue
        path, keys, texts, mtime = item.get("path"), item.get("keys"), item.get("texts"), item.get("mtime")
        if not isinstance(path, str) or SSHD_DROPIN.fullmatch(path) is None or path.rsplit("/", 1)[-1] in REPO_SSHD_DROPINS:
            continue
        clean = tuple(k for k in (keys if isinstance(keys, list) else []) if isinstance(k, str) and k in SSHD_AUTH_KEYS)
        if not clean or any(o.path == path for o in found):
            continue
        found.append(SshdOverride(
            path=path, keys=clean,
            texts=tuple(str(x)[:300] for x in (texts if isinstance(texts, list) else [])[:8]),
            mtime=mtime if type(mtime) is int and 0 <= mtime < 10**11 else None,
        ))
    return tuple(found)


def sshd_drift_of(raw: object) -> dict[str, tuple[str, str]]:
    """An agent's ``sshd_drift``: {auth key: (effective, the repo's)}."""
    if not isinstance(raw, Mapping):
        return {}
    out: dict[str, tuple[str, str]] = {}
    for key, value in raw.items():
        if key in SSHD_AUTH_KEYS and isinstance(value, Mapping):
            out[str(key)] = (str(value.get("have") or "")[:80], str(value.get("want") or "")[:80])
    return out


@dataclass(frozen=True, slots=True)
class SshdCheck:
    """``sshd-check``: the foreign overrides a fresh host check names, the drift of the
    auth keys, when the check ran."""

    overrides: tuple[SshdOverride, ...]
    drift: dict[str, tuple[str, str]]
    checked_at: str = ""


@dataclass(frozen=True, slots=True)
class RelayHardening:
    """What is left to bring a relay to the defaults (see the module docstring)."""

    ssh_on_22: bool    # SSH_PORT is 22 and no migration is under way
    filter_off: bool   # RELAY_INPUT_FILTER=off (input-status «off …»)
    # Foreign sshd overrides the relay's last status names (step 0 checks afresh anyway).
    overrides: tuple[str, ...] = ()

    @property
    def needed(self) -> bool:
        return bool(self.overrides) or self.ssh_on_22 or self.filter_off

    @property
    def agent_version(self) -> int:
        """The agent «Довести» needs: ``sshd-override-off`` (5) for an override,
        ``input-filter`` (4), else ``ssh-port-set`` (3)."""
        if self.overrides:
            return AGENT_SSHD_OVERRIDE
        return AGENT_INPUT_FILTER if self.filter_off else AGENT_SSH_PORT


def hardening_of_status(status: Mapping[str, Any], ssh_port: int) -> RelayHardening | None:
    """What a ``status`` (or a pairing's ``hello``) answer says is left; None when it
    tells nothing about either (no answer kept, an agent too old to say)."""
    filt = status.get("input_status")
    plan = status.get("ssh_migration")
    ports = status.get("ssh_ports")
    if not (isinstance(filt, str) and filt) and not (isinstance(plan, dict) and plan) and not isinstance(ports, list):
        return None
    filter_off = isinstance(filt, str) and filt.startswith("off")
    if isinstance(plan, dict) and plan.get("ssh_port"):
        ssh_on_22 = str(plan.get("ssh_port")) == str(HARDEN_FROM_PORT) and str(plan.get("state") or "") != "phase1"
    else:
        listening = [str(p) for p in ports] if isinstance(ports, list) else []
        ssh_on_22 = ssh_port == HARDEN_FROM_PORT and listening in ([], [str(HARDEN_FROM_PORT)])
    overrides = tuple(o.path for o in sshd_overrides_of(status.get("sshd_overrides")))
    return RelayHardening(ssh_on_22=ssh_on_22, filter_off=filter_off, overrides=overrides)


def hardening_of(relay: Relay) -> RelayHardening | None:
    """:func:`hardening_of_status` of the relay's last kept status (None: no agent, an
    uninstalled one, nothing kept)."""
    agent = relay.agent
    if agent is None or agent_uninstalled(agent) or not agent.last_status:
        return None
    return hardening_of_status(agent.last_status, agent.ssh_port)


def _phase1_since(relay: Relay, port: int) -> int | None:
    """The start of the relay's migration to *port* (phase 1, from its kept status)."""
    plan = (relay.agent.last_status or {}).get("ssh_migration") if relay.agent is not None else None
    if not isinstance(plan, dict) or str(plan.get("state") or "") != "phase1" or str(plan.get("to") or "") != str(port):
        return None
    since = str(plan.get("since") or "")
    return int(since) if since.isdigit() and 0 < int(since) < 10**12 else None


def _ssh_failed(rollback: str, error: str) -> RelayAgentError:
    """Step 2 of «Довести» failed; *rollback* — «restored» or why not."""
    if rollback == "restored":
        return RelayAgentError("переезд SSH не удался, откачен", key="relay_harden_ssh_failed",
                               params={"port": HARDEN_SSH_PORT, "error": error[:300]})
    return RelayAgentError("переезд SSH не удался, откат тоже", key="relay_harden_ssh_failed_stuck",
                           params={"port": HARDEN_SSH_PORT, "error": error[:300], "rollback": rollback[:300]})


def _filter_committed(reply: AgentReply) -> bool:
    state = reply.payload.get("input_filter")
    return reply.ok and isinstance(state, dict) and state.get("committed") is True


def unknown_request(reply: AgentReply) -> bool:
    """The agent refused the request as one it does not know (an agent from before it)."""
    return not reply.ok and reply.returncode == 2 and "not an agent command" in reply.error


def agent_uninstalled(agent: RelayAgent) -> bool:
    """``uninstall`` already ran on this relay (a delete or a detach that did not finish)."""
    return bool((agent.last_status or {}).get(UNINSTALLED_KEY))


def _slim(payload: Mapping[str, Any]) -> dict[str, object]:
    """What is kept of a status answer (no unbounded fields)."""
    keep = ("agent", "protocol", "target_host", "tcp", "udp", "live_target", "resolved", "ip_forward",
            "units", "ssh_ports", "egress", "checkout", "update", "check", "paired_at", "input_status", "jump",
            "ssh_migration", "sshd_drift", "sshd_overrides", "host_check_at")
    return {k: payload[k] for k in keep if k in payload}


def only_input_filter_failures(lines: Iterable[str]) -> bool:
    """Every ``FAIL:`` line of a ``vpn-relay-apply check`` is about the input filter.

    The check exits with the code of its FIRST failure and runs the input filter's
    steps before ip_forward, conntrack, TCP and TLS, so an exit 16-18 alone does
    not say the forward is fine — the FAIL lines do. The agent's apply uses the
    same rule (scripts/vpn-relay-agent: only_input_filter_failures).
    """
    fails = [line for line in lines if "FAIL: " in line]
    return all("vpnrelay_input" in line or "listening but filtered" in line for line in fails)


def own_check_healthy(status: Mapping[str, Any]) -> bool:
    """The relay's own ``vpn-relay-apply check`` (in a ``status`` answer) passed, or
    failed on nothing but the input filter: its forward reaches its upstream."""
    check = status.get("check")
    lines = check.get("lines") if isinstance(check, dict) else None
    rc = check.get("rc") if isinstance(check, dict) else None
    text = [str(line) for line in lines] if isinstance(lines, list) else []
    return isinstance(rc, int) and (rc == 0 or (rc in CHECK_OK_CODES and only_input_filter_failures(text)))


def input_pending(status: Mapping[str, Any]) -> bool:
    """The relay's input filter waits for ``input-confirm`` (its dead-man is armed)."""
    value = status.get("input_status")
    return isinstance(value, str) and value.startswith(INPUT_PENDING)


async def _agent_call(
    client: RelayAgentClient,
    host: str,
    port: int,
    request: str,
    *,
    alias: str,
    host_key: str | None,
    timeout: float = 60.0,
    sensitive: tuple[str, ...] = (),
    via: JumpHost | None = None,
) -> AgentReply:
    """One agent call; ``via=`` only for a call through the hub (a direct call is
    exactly the call it always was)."""
    if via is None:
        return await client.call(host, port, request, alias=alias, host_key=host_key, timeout=timeout,
                                 sensitive=sensitive)
    return await client.call(host, port, request, alias=alias, host_key=host_key, timeout=timeout,
                             sensitive=sensitive, via=via)


def warn_legacy_relay_env(settings: Settings) -> bool:
    """At startup: ONE warning when the obsolete RELAY_* variables are still in .env.

    They are not read (relays live in the ``relays`` table); the wizard's
    self-check shows the same thing as a yellow item. True when it warned.
    """
    if not settings.relay_env_vars:
        return False
    logger.warning(
        "RELAY_* в .env устарели и не читаются (relay управляются из админки) — удалите их: %s",
        ", ".join(settings.relay_env_vars),
    )
    return True


# ── errors and results ────────────────────────────────────────────────────────


class RelayAgentError(ServiceError):
    """The agent on the relay refused or failed a request (its reason in params)."""


class RelayUpdateFailed(RelayAgentError):
    """``update`` failed on the relay: :attr:`failure` says why (the cause deploy.sh
    reported, the step, the lines that tell it, the deploy log on the relay)."""

    def __init__(self, failure: DeployFailure) -> None:
        super().__init__(
            f"relay update: {failure.reason}: {failure.message}", key="relay_agent_refused",
            params={"error": failure.message[:300] or failure.reason},
        )
        self.failure = failure


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The outside checks of a relay: True / False / None (not checked: protocol off)."""

    tcp: bool | None
    udp: bool | None
    # True: not probed from here (the relay is behind the hub) — ``tcp`` is the
    # relay's own `vpn-relay-apply check`, asked through the hub.
    via_hub: bool = False

    @property
    def passed(self) -> bool:
        return self.tcp is not False and self.udp is not False

    def describe(self) -> str:
        def mark(value: bool | None) -> str:
            return "—" if value is None else ("ok" if value else "FAIL")

        text = f"TCP {mark(self.tcp)}, UDP {mark(self.udp)}"
        return f"{text} (relay's own check, via hub)" if self.via_hub else text


class PairingCheckFailed(InvalidOperation):
    """The relay answered hello, but traffic through it does not reach this server."""

    def __init__(self, checks: CheckResult) -> None:
        super().__init__(
            "проверка через relay не прошла", key="relay_pair_check_failed", params={"checks": checks.describe()}
        )
        self.checks = checks


@dataclass(frozen=True, slots=True)
class RelayOverview:
    """One row of the relay list."""

    relay: Relay
    # ACTIVE keys through this relay right now.
    active_keys: int


@dataclass(frozen=True, slots=True)
class RelayUpdateResult:
    """What an edit changed, plus what the admin should be told about it."""

    before: Relay
    relay: Relay
    changed: tuple[str, ...]
    # Set when the host changed: ACTIVE single (non-bundle) keys through this relay,
    # which hold the old host in a link the user imported and must re-import.
    # Subscriptions follow the new host on their next refresh.
    single_keys_to_reimport: int | None = None
    # Set when the (new) host is an IPv4 address the relay's source IPs do not
    # cover: the panel offers to add it, since a DNAT relay usually egresses from
    # the address it is reached at.
    suggest_source_ip: str | None = None


@dataclass(frozen=True, slots=True)
class RelayDeletionReport:
    """How far a delete got.

    ``deleted`` — the relay row is gone (every key through it was removed first).
    Otherwise ``failed_key_id``/``failure`` name the key that stopped it (None when
    keys simply remain — e.g. one was issued while this ran), ``remaining_keys``
    says how many keys still name the relay, and running the delete again
    continues from there. ``uninstalled`` — ``uninstall`` ran on the relay (now or
    by an earlier, interrupted delete); False for a relay with an agent means the
    relay itself was left as it is (record only).
    """

    relay: Relay
    deleted: bool
    deleted_key_ids: tuple[int, ...] = ()
    failed_key_id: int | None = None
    failure: Exception | None = None
    remaining_keys: int = 0
    uninstalled: bool = False


@dataclass(frozen=True, slots=True)
class IssuedPairing:
    pairing: RelayPairing
    code: str
    command: str


@dataclass(frozen=True, slots=True)
class PairingOutcome:
    relay: Relay
    # True: an agent was connected to an existing relay; False: a new relay.
    attached: bool
    checks: CheckResult
    health_interval: int
    # The source IPs the agent's answer added (an attach never removes any).
    added_source_ips: tuple[str, ...] = ()
    # A NEW relay whose public host does not resolve to the relay: what it
    # resolves to (empty: it does not resolve). None when it is fine.
    host_mismatch: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class JumpSync:
    """What :meth:`RelayService.sync_hub_jump` left on the hub: the relays its jump
    line opens (``hub`` None: there is no usable hub, nothing was done)."""

    hub: Relay | None
    opens: tuple[tuple[str, int], ...]
    changed: bool = False


@dataclass(frozen=True, slots=True)
class RouteInfo:
    """How the bot reaches a relay's agent, for its card: through the hub (because of
    the «через hub» flag, or the fallback mode) or directly."""

    via_hub: bool
    # "flag" | "mode" | "" (directly).
    reason: str = ""
    # The hub the calls go through; None with via_hub — there is none (calls fail).
    hub: Relay | None = None


@dataclass(frozen=True, slots=True)
class ViaHubResult:
    relay: Relay
    # The hub's jump line could not be written (the flag is saved all the same; the
    # next call through the hub tries again).
    sync_error: ServiceError | None = None


@dataclass(frozen=True, slots=True)
class DetachReport:
    relay: Relay
    uninstalled: bool


_UNSET = object()


class RelayService:
    """Every relay: list, edit, delete, pairing codes, the agent. SUPERADMIN only."""

    def __init__(
        self,
        *,
        relays: RelayRepository,
        users: UserService,
        audit: AuditService,
        clock: ClockProvider,
        catalog: RelayCatalog,
        settings: Settings | None = None,
        keys: RelayKeyStore | None = None,
        client: RelayAgentClient | None = None,
        source_root: Path | None = None,
        key_deleters: Mapping[VpnKeyType, KeyDeleter] | None = None,
        tcp_probe: Callable[[str, int, str], Awaitable[bool]] | None = None,
        udp_probe: Callable[[str, int], Awaitable[bool | None]] | None = None,
        resolve: Callable[[str], Awaitable[list[str]]] = resolve_ipv4,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.relays = relays
        self.users = users
        self.audit = audit
        self.clock = clock
        self.catalog = catalog
        self.settings = settings
        self.keys = keys
        self.client = client
        self.source_root = source_root
        # Protocol -> its normal per-key delete path; wired by bot.app. A key whose
        # protocol has no entry cannot be removed here and stops the delete.
        self._key_deleters: dict[VpnKeyType, KeyDeleter] = dict(key_deleters or {})
        self._tcp_probe = tcp_probe
        self._udp_probe = udp_probe
        self._resolve = resolve
        self._now = now
        # THE lock. Taken before any per-protocol lock (the delete path calls into
        # the key services) and by nothing those services call, so no cycle.
        self._lock = asyncio.Lock()
        # Relays an agent call is running on right now (taken/released under _lock).
        self._busy: set[int] = set()
        # The hub's jump line as the bot last wrote it: hub id -> (jump key, opens).
        self._jump_written: dict[int, tuple[str, tuple[tuple[str, int], ...]]] = {}
        # Addresses opened on the hub for a pairing that is running (complete()).
        self._jump_pairing: set[tuple[str, int]] = set()
        self._jump_lock = asyncio.Lock()
        # Called with (relay, status payload) after a status answer is kept (the SSH
        # port monitor, services/ssh_port.py). Set by the bot's wiring.
        self.status_listeners: list[Callable[[Relay, Mapping[str, Any]], Awaitable[None]]] = []

    def attach_key_deleters(self, key_deleters: Mapping[VpnKeyType, KeyDeleter]) -> None:
        self._key_deleters = dict(key_deleters)

    @property
    def snapshot(self) -> RelaySnapshot:
        return self.catalog.snapshot

    @property
    def agents_available(self) -> bool:
        """The bot can install and manage relays (its SSH client and key store are wired)."""
        return self.client is not None and self.keys is not None and self.settings is not None

    async def refresh_catalog(self) -> RelaySnapshot:
        """Re-read the table into the bot's snapshot (after every write, and at startup)."""
        snapshot = RelaySnapshot.of(await self.relays.list_all(), direct_host=await self.relays.direct_host())
        self.catalog.replace(snapshot)
        return snapshot

    # ── reads ─────────────────────────────────────────────────────────────────

    async def list_overview(self, actor_user_id: int) -> list[RelayOverview]:
        await self.users.require_superadmin(actor_user_id)
        relays = await self.relays.list_all()
        counts = await self.relays.active_key_counts()
        return [RelayOverview(relay=relay, active_keys=counts.get(relay.name, 0)) for relay in relays]

    async def get(self, actor_user_id: int, relay_id: int) -> Relay:
        await self.users.require_superadmin(actor_user_id)
        return await self._require(relay_id)

    async def usage(self, actor_user_id: int, relay_id: int) -> tuple[Relay, RelayUsage]:
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require(relay_id)
        return relay, await self.relays.usage(relay.name)

    async def check_new_name(self, actor_user_id: int, value: str) -> str:
        """Validate a name for a NEW relay: format, not taken, not carried by any key,
        not waiting for a pairing."""
        await self.users.require_superadmin(actor_user_id)
        name = parse_relay_name(value)
        await self._ensure_name_free(name)
        if await self.relays.pending_name_taken(name):
            raise InvalidOperation(
                f"имя {name!r} уже ждёт подключения", key="relay_pair_name_pending", params={"value": name}
            )
        return name

    async def suggest_name(self, actor_user_id: int) -> str | None:
        """The first free ``relayN``."""
        for n in range(1, 50):
            try:
                return await self.check_new_name(actor_user_id, f"relay{n}")
            except InvalidOperation:
                continue
        return None

    async def label_free(self, actor_user_id: int, label: str, *, exclude_relay_id: int | None = None) -> bool:
        await self.users.require_superadmin(actor_user_id)
        existing = await self.relays.get_by_label(label)
        return existing is None or existing.id == exclude_relay_id

    async def check_label(self, actor_user_id: int, value: str, *, exclude_relay_id: int | None = None) -> str:
        """Validate a relay marker: format and not used by another relay."""
        label = parse_relay_label(value)
        if not await self.label_free(actor_user_id, label, exclude_relay_id=exclude_relay_id):
            raise InvalidOperation(
                f"label {label!r} уже занят", key="err_relay_label_taken", params={"value": label}
            )
        return label

    async def pending(self, actor_user_id: int) -> list[RelayPairing]:
        """Pairing codes still waiting to be completed (expired ones are closed first)."""
        await self.users.require_superadmin(actor_user_id)
        await self._expire()
        return await self.relays.list_pending()

    def default_target(self) -> str | None:
        """The main server's DNS name: the host of direct links, else Hysteria2's."""
        settings = self.settings
        if settings is None:
            return None
        for value in (settings.xray_public_host, settings.hysteria2_host, settings.hysteria2_sni):
            host = (value or "").strip().lower()
            if valid_dns_name(host):
                return host
        return None

    def default_ports(self) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """1:1 with this server: XRAY_PUBLIC_PORT/tcp and HYSTERIA2_PORT/udp (443 both by default)."""
        settings = self._require_settings()
        return (settings.xray_public_port,), (settings.hysteria2_port,)

    @property
    def health_interval(self) -> int:
        return self.settings.relay_health_interval if self.settings is not None else 0

    # ── create (the pairing completion is its only caller in the bot) ─────────

    async def create(
        self,
        actor_user_id: int,
        *,
        name: str,
        host: str,
        source_ips: str,
        label: str = validators.DEFAULT_RELAY_LABEL,
        note: str | None = None,
        enabled: bool = True,
        in_subscriptions: bool = False,
    ) -> Relay:
        """Insert a relay WITHOUT an agent.

        Not offered in the panel — a new relay is added through a pairing code, so
        it always comes with its agent. Kept as the primitive the tests seed rows
        with; tests/test_relay_unified.py checks no bot handler calls it.

        Like a paired relay it starts OUT of subscriptions: joining them is the
        card's «Добавить в подписки», which tops every issued one up as well.
        """
        await self.users.require_superadmin(actor_user_id)
        clean_name = parse_relay_name(name)
        clean_host = parse_relay_host(host)
        clean_sources = parse_relay_source_ips(source_ips)
        clean_label = parse_relay_label(label)
        clean_note = parse_relay_note(note)
        async with self._lock:
            await self._ensure_name_free(clean_name)
            if await self.relays.get_by_label(clean_label) is not None:
                raise InvalidOperation(
                    f"label {clean_label!r} уже занят", key="err_relay_label_taken", params={"value": clean_label}
                )
            try:
                relay = await self.relays.create(
                    name=clean_name,
                    label=clean_label,
                    host=clean_host,
                    source_ips=clean_sources,
                    enabled=enabled,
                    in_subscriptions=in_subscriptions,
                    note=clean_note,
                    created_by=actor_user_id,
                    now=self.clock.now(),
                )
            except sqlite3.IntegrityError as exc:
                # The UNIQUE constraints caught a race the checks above lost.
                raise InvalidOperation(
                    "relay с таким name или label уже есть", key="err_relay_name_taken", params={"value": clean_name}
                ) from exc
            await self._audit(actor_user_id, "relay_created", relay.id, _audit_view(relay))
            await self.refresh_catalog()
            return relay

    # ── update ────────────────────────────────────────────────────────────────

    async def update(
        self,
        actor_user_id: int,
        relay_id: int,
        *,
        host: str | None = None,
        source_ips: str | None = None,
        label: str | None = None,
        note: object = _UNSET,
        enabled: bool | None = None,
        in_subscriptions: bool | None = None,
        basic_visible: bool | None = None,
    ) -> RelayUpdateResult:
        """Change any editable field; ``name`` is not one of them.

        Takes effect on the very next rendered link: the bot's snapshot is replaced
        before this returns, the subscription endpoint reads the table per request.
        *note* is left alone unless passed (``None`` clears it).

        Hiding the relay from BASIC subscriptions or taking it out of subscriptions
        is refused (``err_basic_would_be_empty``) when no server would be left in
        BASIC subscriptions afterwards. Switching it off is never refused — that is
        an emergency action; the renderer fails open instead.
        """
        await self.users.require_superadmin(actor_user_id)
        changes: dict[str, object] = {}
        if host is not None:
            changes["host"] = parse_relay_host(host)
        if source_ips is not None:
            changes["source_ips"] = parse_relay_source_ips(source_ips)
        if label is not None:
            changes["label"] = parse_relay_label(label)
        if note is not _UNSET:
            changes["note"] = parse_relay_note(note if isinstance(note, str) or note is None else str(note))
        if enabled is not None:
            changes["enabled"] = bool(enabled)
        if in_subscriptions is not None:
            changes["in_subscriptions"] = bool(in_subscriptions)
        if basic_visible is not None:
            changes["basic_visible"] = bool(basic_visible)
        async with self._lock:
            before = await self._require(relay_id)
            changes = {field: value for field, value in changes.items() if getattr(before, field) != value}
            await self._ensure_basic_keeps_a_server(before, changes)
            if "label" in changes:
                taken = await self.relays.get_by_label(str(changes["label"]))
                if taken is not None and taken.id != relay_id:
                    raise InvalidOperation(
                        "label уже занят", key="err_relay_label_taken", params={"value": changes["label"]}
                    )
            if not changes:
                return RelayUpdateResult(before=before, relay=before, changed=())
            try:
                after = await self.relays.update(relay_id, changes, now=self.clock.now(), updated_by=actor_user_id)
            except sqlite3.IntegrityError as exc:
                raise InvalidOperation(
                    "label уже занят", key="err_relay_label_taken", params={"value": changes.get("label", "")}
                ) from exc
            if after is None:
                raise NotFound("Relay не найден", key="err_relay_not_found")
            before_view, after_view = _audit_view(before), _audit_view(after)
            await self._audit(
                actor_user_id,
                "relay_updated",
                relay_id,
                {
                    "name": after.name,
                    "changes": {
                        field: {"before": before_view[field], "after": after_view[field]} for field in sorted(changes)
                    },
                },
            )
            await self.refresh_catalog()
            reimport: int | None = None
            if "host" in changes:
                reimport = (await self.relays.usage(after.name)).single_active_keys
            suggest = None
            if "host" in changes and host_is_ipv4(after.host) and not _covers(after.source_ips, after.host):
                suggest = after.host
            return RelayUpdateResult(
                before=before,
                relay=after,
                changed=tuple(sorted(changes)),
                single_keys_to_reimport=reimport,
                suggest_source_ip=suggest,
            )

    # ── visibility in BASIC subscriptions ────────────────────────────────────

    async def main_basic_visible(self, actor_user_id: int) -> bool:
        """Whether BASIC subscriptions show the main server (its direct children)."""
        await self.users.require_superadmin(actor_user_id)
        return await self.relays.main_basic_visible()

    async def basic_has_visible_server(self, actor_user_id: int) -> bool:
        """Whether BASIC subscriptions show any server right now (False: they fail open)."""
        await self.users.require_superadmin(actor_user_id)
        return basic_has_visible_server(
            RelaySnapshot.of(await self.relays.list_all()), main_visible=await self.relays.main_basic_visible()
        )

    async def set_main_basic_visible(self, actor_user_id: int, visible: bool) -> bool:
        """Show / hide the main server in BASIC subscriptions; returns the new value.

        A render-time switch (nothing about keys or Xray changes), so it is instant
        and reversible. Hiding it is refused when no relay would be left to show.
        """
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            before = await self.relays.main_basic_visible()
            if before == visible:
                return before
            if not visible and not basic_has_visible_server(
                RelaySnapshot.of(await self.relays.list_all()), main_visible=False
            ):
                raise InvalidOperation(
                    "в базовых подписках не останется ни одного сервера", key="err_basic_would_be_empty"
                )
            await self.relays.set_main_basic_visible(visible)
            await self._audit(
                actor_user_id,
                "relay_main_basic_visibility_changed",
                None,
                {"basic_visible": {"before": before, "after": visible}},
            )
            return visible

    async def check_basic_keeps_a_server(
        self,
        actor_user_id: int,
        relay_id: int,
        *,
        in_subscriptions: bool | None = None,
        basic_visible: bool | None = None,
    ) -> None:
        """Raise ``err_basic_would_be_empty`` if the change would empty BASIC subscriptions.

        The same check :meth:`update` makes, asked up front — e.g. before the
        «Убрать из подписок» plan is shown, so the admin does not confirm a plan
        that is then refused.
        """
        await self.users.require_superadmin(actor_user_id)
        changes: dict[str, object] = {}
        if in_subscriptions is not None:
            changes["in_subscriptions"] = in_subscriptions
        if basic_visible is not None:
            changes["basic_visible"] = basic_visible
        await self._ensure_basic_keeps_a_server(await self._require(relay_id), changes)

    async def _ensure_basic_keeps_a_server(self, before: Relay, changes: Mapping[str, object]) -> None:
        """Refuse hiding *before* / taking it out of subscriptions if BASIC would show nothing."""
        if changes.get("in_subscriptions") is not False and changes.get("basic_visible") is not False:
            return
        after = replace(
            before,
            in_subscriptions=bool(changes.get("in_subscriptions", before.in_subscriptions)),
            basic_visible=bool(changes.get("basic_visible", before.basic_visible)),
        )
        relays = [after if relay.id == before.id else relay for relay in await self.relays.list_all()]
        if not basic_has_visible_server(
            RelaySnapshot.of(relays), main_visible=await self.relays.main_basic_visible()
        ):
            raise InvalidOperation(
                "в базовых подписках не останется ни одного сервера", key="err_basic_would_be_empty"
            )

    async def add_source_ip(self, actor_user_id: int, relay_id: int, address: str) -> RelayUpdateResult:
        """Append one address to the relay's source IPs (the post-host-change offer)."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require(relay_id)
        extra = parse_relay_source_ips(address)
        merged = validators.format_ipv4_networks((*relay.source_ips, *extra))
        return await self.update(actor_user_id, relay_id, source_ips=merged)

    # ── delete ────────────────────────────────────────────────────────────────

    async def delete(
        self, actor_user_id: int, relay_id: int, *, with_keys: bool, relay_side: bool = True
    ) -> RelayDeletionReport:
        """Delete a relay; with *with_keys*, first every key through it.

        A relay with an agent: ``uninstall`` runs on the relay FIRST, so no DNAT to
        this server is left behind; a refusal or an unreachable relay raises and
        nothing is deleted. ``relay_side=False`` (the relay is gone) deletes only
        the record — the relay keeps forwarding until it is cleaned up by hand.
        After an ``uninstall`` the relay is marked, so an interrupted delete
        resumes without a second one.

        Without *with_keys* the relay goes only if no key (outside status
        'deleted') names it — otherwise nothing changes and the report says how
        many keys are in the way. With it, each key is removed through its
        protocol's normal delete path, oldest first; the first failure stops
        everything (the relay stays) and is reported, and a repeated call carries
        on with the keys that are left.
        """
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require(relay_id)
        self._refuse_hub(relay)
        uninstalled = relay.agent is not None and agent_uninstalled(relay.agent)
        if relay.agent is not None and relay_side and not uninstalled:
            if not with_keys:
                usage = await self.relays.usage(relay.name)
                if usage.keys:
                    return RelayDeletionReport(relay=relay, deleted=False, remaining_keys=usage.keys)
            await self._uninstall(actor_user_id, relay)
            uninstalled = True
        async with self._lock:
            relay = await self._require(relay_id)
            self._ensure_idle(relay)
            self._refuse_hub(relay)
            deleted_ids: list[int] = []
            if with_keys:
                for ref in await self.relays.list_keys(relay.name):
                    deleter = self._key_deleters.get(ref.key_type)
                    try:
                        if deleter is None:
                            raise InvalidOperation(
                                f"Ключ {ref.key_type.value} нельзя удалить вместе с relay",
                                key="err_relay_key_type_undeletable",
                            )
                        await deleter(actor_user_id, ref.id)
                    except NotFound:
                        # Already gone (deleted concurrently): nothing left to do.
                        continue
                    except Exception as exc:
                        logger.warning(
                            "Relay %s: удаление ключа key_id=%s не удалось — relay не удалён",
                            relay.name,
                            ref.id,
                            exc_info=True,
                        )
                        remaining = (await self.relays.usage(relay.name)).keys
                        await self._audit(
                            actor_user_id,
                            "relay_delete_incomplete",
                            relay_id,
                            {
                                "name": relay.name,
                                "deleted_key_ids": deleted_ids,
                                "failed_key_id": ref.id,
                                "error_type": type(exc).__name__,
                                "remaining_keys": remaining,
                            },
                        )
                        return RelayDeletionReport(
                            relay=relay,
                            deleted=False,
                            deleted_key_ids=tuple(deleted_ids),
                            failed_key_id=ref.id,
                            failure=exc,
                            remaining_keys=remaining,
                            uninstalled=uninstalled,
                        )
                    deleted_ids.append(ref.id)
            if not await self.relays.delete_if_unused(relay_id, now=self.clock.now()):
                remaining = (await self.relays.usage(relay.name)).keys
                if deleted_ids:
                    await self._audit(
                        actor_user_id,
                        "relay_delete_incomplete",
                        relay_id,
                        {"name": relay.name, "deleted_key_ids": deleted_ids, "remaining_keys": remaining},
                    )
                return RelayDeletionReport(
                    relay=relay,
                    deleted=False,
                    deleted_key_ids=tuple(deleted_ids),
                    remaining_keys=remaining,
                    uninstalled=uninstalled,
                )
            await self._audit(
                actor_user_id,
                "relay_deleted",
                relay_id,
                {**_audit_view(relay), "deleted_key_ids": deleted_ids, "uninstalled": uninstalled},
            )
            await self.refresh_catalog()
            done = RelayDeletionReport(
                relay=relay, deleted=True, deleted_key_ids=tuple(deleted_ids), uninstalled=uninstalled
            )
        await self.sync_hub_jump_quietly()
        return done

    # ── pairing codes ─────────────────────────────────────────────────────────

    async def issue_new(self, actor_user_id: int, *, name: str, host: str, target_host: str) -> IssuedPairing:
        """A code for a NEW relay: its name, the public host its links point at, the
        main server's DNS name it forwards to."""
        await self.users.require_superadmin(actor_user_id)
        target = self._parse_target(target_host)
        clean_host = parse_relay_host(host)
        tcp, udp = self.default_ports()
        keys = self._require_keys()
        async with self._lock:
            await self._expire()
            clean_name = await self.check_new_name(actor_user_id, name)
            keys.ensure()
            pairing = await self.relays.create_pairing(
                kind="new",
                name=clean_name,
                token=new_token(),
                target_host=target,
                tcp_ports=tcp,
                udp_ports=udp,
                expires_at=int(self._now()) + PAIRING_TTL_SECONDS,
                created_by=actor_user_id,
                now=self.clock.now(),
                relay_host=clean_host,
            )
        await self._audit(
            actor_user_id,
            "relay_pairing_issued",
            None,
            {"pairing_id": pairing.id, "kind": "new", "name": clean_name, "host": clean_host,
             "target_host": target, "tcp": list(tcp), "udp": list(udp)},
        )
        return self._render(pairing)

    async def issue_attach(self, actor_user_id: int, relay_id: int, *, target_host: str) -> IssuedPairing:
        """A code that connects an agent to the EXISTING relay — no name asked, the
        relay and its keys do not change. A code already waiting is shown again."""
        await self.users.require_superadmin(actor_user_id)
        target = self._parse_target(target_host)
        tcp, udp = self.default_ports()
        keys = self._require_keys()
        async with self._lock:
            await self._expire()
            relay = await self._require(relay_id)
            if relay.agent is not None:
                raise InvalidOperation("у relay уже есть агент", key="relay_agent_already", params={"name": relay.name})
            existing = await self.relays.pending_attach(relay_id)
            if existing is not None:
                return self._render(existing)
            keys.ensure()
            pairing = await self.relays.create_pairing(
                kind="attach",
                name=relay.name,
                token=new_token(),
                target_host=target,
                tcp_ports=tcp,
                udp_ports=udp,
                expires_at=int(self._now()) + PAIRING_TTL_SECONDS,
                created_by=actor_user_id,
                now=self.clock.now(),
                relay_id=relay.id,
            )
        await self._audit(
            actor_user_id,
            "relay_pairing_issued",
            relay.id,
            {"pairing_id": pairing.id, "kind": "attach", "name": relay.name, "target_host": target,
             "tcp": list(tcp), "udp": list(udp)},
        )
        return self._render(pairing)

    async def show(self, actor_user_id: int, pairing_id: int) -> IssuedPairing:
        await self.users.require_superadmin(actor_user_id)
        return self._render(await self._pending(pairing_id))

    async def cancel(self, actor_user_id: int, pairing_id: int) -> None:
        """Cancel a pending pairing. Under the lock: a cancel never lands in the middle
        of a completion (it waits for it, then finds nothing pending)."""
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            pairing = await self.relays.get_pairing(pairing_id)
            cancelled = await self.relays.finish_pairing(pairing_id, "cancelled", now=self.clock.now())
        if cancelled:
            relay_id = pairing.relay_id if pairing is not None else None
            await self._audit(actor_user_id, "relay_pairing_cancelled", relay_id, {"pairing_id": pairing_id})

    async def checks(self, host: str) -> CheckResult:
        """Traffic through the relay at *host* reaches this server: TCP (TLS with
        XRAY_SNI) and, when Hysteria2 is on, UDP (QUIC version negotiation)."""
        settings = self._require_settings()
        tcp: bool | None = None
        if settings.xray_sni:
            probe = self._tcp_probe or tls_probe
            tcp = bool(await probe(host, settings.xray_public_port, settings.xray_sni))
        udp: bool | None = None
        if settings.hysteria2_enabled:
            uprobe = self._udp_probe or udp_relay_probe
            udp = await uprobe(host, settings.hysteria2_port)
        return CheckResult(tcp=tcp, udp=udp)

    async def complete(self, actor_user_id: int, pairing_id: int, address: str) -> PairingOutcome:
        """The operator sent the relay's SSH address: hello → the outside checks →
        a new relay with its agent, or the agent written onto the existing relay."""
        await self.users.require_superadmin(actor_user_id)
        client = self._require_client()
        ssh_host, ssh_port = parse_address(address)
        async with self._lock:
            pairing = await self._pending(pairing_id)
            target: Relay | None = None
            if pairing.kind == "attach":
                target = await self._attach_target(pairing)
                if not await self._same_server(target, ssh_host):
                    await self._audit(
                        actor_user_id, "relay_attach_refused", target.id,
                        {"pairing_id": pairing.id, "name": target.name, "host": target.host, "ssh_host": ssh_host},
                    )
                    raise InvalidOperation(
                        "это другой сервер",
                        key="relay_attach_other_server",
                        params={"value": ssh_host, "name": target.name, "host": target.host},
                    )
            else:
                await self._ensure_name_free(pairing.name)
            # Behind the hub (the fallback mode, or an attach to a relay «через hub»):
            # the hub's jump line opens this address too, for as long as the pairing
            # runs — kept in the set every sync builds, so a health poll syncing the
            # line meanwhile does not close it under the hello or the check.
            via: JumpHost | None = None
            opened: tuple[str, int] | None = None
            if await self.relays.fallback_mode_on() or (target is not None and target.via_hub):
                opened = (ssh_host.lower(), ssh_port)
                self._jump_pairing.add(opened)
            try:
                if opened is not None:
                    via = await self._jump_to(None)
                alias = f"vpn-relay-pairing-{pairing.id}"
                reply = await _agent_call(
                    client,
                    ssh_host,
                    ssh_port,
                    f"hello {pairing.token}",
                    alias=alias,
                    host_key=None,
                    sensitive=(pairing.token,),
                    via=via,
                )
                if not reply.ok:
                    raise RelayAgentError(
                        f"relay отказал: {reply.error}", key="relay_agent_refused", params={"error": reply.error[:300]}
                    )
                self._expect_pairing(reply.payload, pairing)
                if reply.learned_host_key is None:
                    raise RelaySshError("ключ хоста relay не получен", key="relay_ssh_bad_host_key")
                if via is None:
                    checks = await self.checks(target.host if target is not None else ssh_host)
                else:
                    checks = await self._checks_through(ssh_host, ssh_port, alias, reply.learned_host_key, via)
                if not checks.passed:
                    await self._audit(
                        actor_user_id, "relay_pairing_check_failed", target.id if target else None,
                        {"pairing_id": pairing.id, "host": ssh_host, "checks": checks.describe()},
                    )
                    raise PairingCheckFailed(checks)
                found = await self._source_ips(ssh_host, reply.payload)
                now = self.clock.now()
                agent = RelayAgent(
                    ssh_host=ssh_host,
                    ssh_port=ssh_port,
                    host_key=reply.learned_host_key,
                    target_host=pairing.target_host,
                    tcp_ports=pairing.tcp_ports,
                    udp_ports=pairing.udp_ports,
                    agent_version=str(reply.payload.get("agent", "")),
                    paired_at=now,
                    last_status=_slim(reply.payload),
                    last_status_at=now,
                )
                if target is None:
                    relay, added, mismatch = await self._complete_new(actor_user_id, pairing, agent, found, now)
                else:
                    relay, added = await self._complete_attach(actor_user_id, pairing, target, agent, found, now)
                    mismatch = None
                await self.refresh_catalog()
            finally:
                if opened is not None:
                    # Paired: the relay itself is behind the hub now (the same set, nothing
                    # to write). Not paired: the address is closed again.
                    self._jump_pairing.discard(opened)
                    await self.sync_hub_jump_quietly()
        if target is None:
            await self._audit(
                actor_user_id,
                "relay_paired",
                relay.id,
                {**_audit_view(relay), "checks": checks.describe(), "pairing_id": pairing.id,
                 **({"via_hub": True} if via is not None else {})},
            )
        else:
            await self._audit(
                actor_user_id,
                "relay_agent_attached",
                relay.id,
                {"name": relay.name, "ssh": f"{ssh_host}:{ssh_port}", "target_host": pairing.target_host,
                 "added_source_ips": list(added), "checks": checks.describe(), "pairing_id": pairing.id,
                 **({"via_hub": True} if via is not None else {})},
            )
        # The pairing's hello is the relay's first status: the listeners hear it too
        # (a relay the installer left on SSH 22 without the input filter is told now).
        await self._tell_listeners(relay, reply.payload)
        return PairingOutcome(
            relay=relay,
            attached=target is not None,
            checks=checks,
            health_interval=self.health_interval,
            added_source_ips=added,
            host_mismatch=mismatch,
        )

    async def _complete_new(
        self, actor_user_id: int, pairing: RelayPairing, agent: RelayAgent, found: list[str], now: str
    ) -> tuple[Relay, tuple[str, ...], tuple[str, ...] | None]:
        # A pre-v44 code has no public host: the SSH address, as it used to be.
        public_host = pairing.relay_host or agent.ssh_host
        sources = tuple(ipaddress.IPv4Network(f"{a}/32") for a in _sort_ips(found))
        try:
            relay = await self.relays.complete_new(
                pairing.id,
                name=pairing.name,
                label=await self._free_label(pairing.name),
                host=public_host,
                source_ips=sources,
                note="paired by the bot (vpn-relay-agent)",
                agent=agent,
                created_by=actor_user_id,
                now=now,
            )
        except sqlite3.IntegrityError as exc:
            raise InvalidOperation(
                "relay с таким name или label уже есть", key="err_relay_name_taken", params={"value": pairing.name}
            ) from exc
        if relay is None:
            # Expired or cancelled meanwhile: nothing was written.
            raise NotFound("pairing не найден или закрыт", key="relay_pair_not_pending")
        mismatch: tuple[str, ...] | None = None
        if public_host != agent.ssh_host:
            resolved = await self._resolve(public_host)
            if not set(resolved) & set(found) and not any(_covers(sources, ip) for ip in resolved):
                mismatch = tuple(resolved)
        return relay, tuple(_sort_ips(found)), mismatch

    async def _complete_attach(
        self,
        actor_user_id: int,
        pairing: RelayPairing,
        target: Relay,
        agent: RelayAgent,
        found: list[str],
        now: str,
    ) -> tuple[Relay, tuple[str, ...]]:
        merged, added = merge_source_ips(target.source_ips, found)
        relay = await self.relays.complete_attach(
            pairing.id,
            target.id,
            agent=agent,
            source_ips=merged if added else None,
            updated_by=actor_user_id,
            now=now,
        )
        if relay is None:
            # Nothing was written; say why.
            current = await self.relays.get_by_id(target.id)
            if current is None:
                raise NotFound("Relay не найден", key="err_relay_not_found")
            if current.agent is not None:
                raise InvalidOperation("у relay уже есть агент", key="relay_agent_already", params={"name": current.name})
            raise NotFound("pairing не найден или закрыт", key="relay_pair_not_pending")
        return relay, added

    # ── the agent ─────────────────────────────────────────────────────────────

    async def agent_status(self, actor_user_id: int, relay_id: int) -> AgentReply:
        """``status`` on the relay; the answer is kept on the relay's row."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        reply = self._require_ok(await self._call(relay, "status"))
        await self._record_status(relay, reply)
        return reply

    async def system_status(self, relay_id: int) -> AgentReply:
        """``status`` asked by the bot itself (no actor: the fallback mode's automatic
        switch, services/fallback_auto.py) — kept like any status answer."""
        relay = await self._require_managed(relay_id)
        reply = self._require_ok(await self._call(relay, "status"))
        await self._record_status(relay, reply)
        return reply

    async def poll_agent(self, relay: Relay) -> AgentCheck | None:
        """The health loop's question to a relay's agent (no actor: the bot itself).

        None for a relay without an agent, one already uninstalled, or while an
        agent call runs on it. Never raises a service error — a failure is the answer.
        """
        if relay.agent is None or agent_uninstalled(relay.agent) or relay.id in self._busy or self.client is None:
            return None
        try:
            reply = await self._call(relay, "status")
        except ServiceError as exc:
            return AgentCheck(ok=False, error_key=exc.key or "relay_ssh_failed", error_params=dict(exc.params))
        if not reply.ok:
            return AgentCheck(ok=False, error_key="relay_agent_refused", error_params={"error": reply.error[:300]})
        reply = await self._confirm_if_pending(None, relay, reply)
        await self._record_status(relay, reply)
        return agent_check_from_status(reply.payload)

    async def update_agent(self, actor_user_id: int, relay_id: int) -> AgentReply:
        """``update`` on the relay: deploy.sh of the newest release tag (minutes — its
        pytest gate runs on the relay)."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._claim(relay_id)
        try:
            reply = await self._call(relay, "update", timeout=AGENT_UPDATE_TIMEOUT)
        finally:
            self._busy.discard(relay.id)
        await self._audit(actor_user_id, "relay_agent_update", relay.id,
                          {"name": relay.name, "ok": reply.ok, "result": reply.payload.get("update") or reply.error})
        if not reply.ok:
            update = reply.payload.get("update")
            if reply.returncode == 4 or isinstance(update, Mapping):
                # The deploy itself failed: the cause it reported, not "the relay refused".
                # An agent older than the cause fields says only its message.
                raise RelayUpdateFailed(
                    deploy_failure_from(update if isinstance(update, Mapping) else None, message=reply.error)
                )
        self._require_ok(reply)
        try:
            status = await self._call(relay, "status")
            if status.ok:
                # The deploy may have applied a TCP set main's probe could not
                # confirm: this ssh session is the proof (input-confirm).
                status = await self._confirm_if_pending(actor_user_id, relay, status)
                await self._record_status(relay, status)
        except ServiceError:
            logger.info("Relay %s: status after update not received", relay.name)
        return reply

    async def update_progress(self, actor_user_id: int, relay_id: int) -> dict[str, Any] | None:
        """``update-status``: the relay's update.json as it is now — the progress of
        a running ``update`` (its deploy's steps and tests). A light call, made next to
        the long one. None from an agent that does not know the request (older than
        :data:`AGENT_UPDATE_STATUS`: it refuses it as «not an agent command»), {} when
        the answer carries nothing usable."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        reply = await self._call(relay, "update-status", timeout=30.0)
        if unknown_request(reply):
            return None
        update = reply.payload.get("update") if reply.ok else None
        return dict(update) if isinstance(update, Mapping) else {}

    async def change_forward(
        self, actor_user_id: int | None, relay_id: int, *, target_host: str, tcp: str, udp: str,
        allow_hub: bool = False,
    ) -> AgentReply:
        """``apply`` on the relay: forward to another main-server name / other ports.

        A hub's forward (its origin and the hub ports) belongs to the fallback mode
        (services/fallback.py) and is refused here unless *allow_hub* — only the
        fallback service passes it, after its own origin and loop checks. *actor_user_id*
        None: the bot itself — only with *allow_hub* (the automatic switch's proxy ports).
        """
        if actor_user_id is not None:
            await self.users.require_superadmin(actor_user_id)
        elif not allow_hub:
            raise InvalidOperation("нет инициатора", key="err_insufficient_rights")
        if not allow_hub:
            self._refuse_hub(await self._require(relay_id))
        try:
            target = parse_target_host(target_host)
            tcp_ports, udp_ports = parse_ports(tcp), parse_ports(udp)
        except PairingCodeError as exc:
            raise InvalidOperation(str(exc), key="relay_agent_bad_forward", params={"error": str(exc)}) from exc
        relay = await self._claim(relay_id)
        agent = relay.agent
        assert agent is not None
        request = f"apply target={target} tcp={format_ports(tcp_ports)} udp={format_ports(udp_ports)}"
        try:
            reply = await self._call(relay, request, timeout=300.0)
            if reply.ok:
                async with self._lock:
                    await self.relays.update_agent_forward(
                        relay_id, target_host=target, tcp_ports=tcp_ports, udp_ports=udp_ports
                    )
                    await self.refresh_catalog()
        finally:
            self._busy.discard(relay.id)
        await self._audit(
            actor_user_id, "relay_agent_apply", relay.id,
            {"name": relay.name, "ok": reply.ok,
             "before": {"target_host": agent.target_host, "tcp": list(agent.tcp_ports), "udp": list(agent.udp_ports)},
             "after": {"target_host": target, "tcp": list(tcp_ports), "udp": list(udp_ports)},
             **({} if reply.ok else {"error": reply.error[:300]})},
        )
        return self._require_ok(reply)

    async def detach_agent(self, actor_user_id: int, relay_id: int, *, uninstall: bool) -> DetachReport:
        """Forget the relay's agent: the agent columns are cleared, the relay and its
        keys stay (back to a relay managed by hand). With *uninstall*, ``uninstall``
        runs on the relay first — that also removes its forwarding, so its keys stop
        working until the relay is set up again."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        self._refuse_hub(relay)
        assert relay.agent is not None
        uninstalled = agent_uninstalled(relay.agent)
        if uninstall and not uninstalled:
            await self._uninstall(actor_user_id, relay)
            uninstalled = True
        async with self._lock:
            current = await self._require(relay_id)
            self._ensure_idle(current)
            if current.agent is None:
                return DetachReport(relay=current, uninstalled=uninstalled)
            await self.relays.clear_agent(relay_id, now=self.clock.now(), updated_by=actor_user_id)
            after = await self._require(relay_id)
            await self._audit(
                actor_user_id,
                "relay_agent_detached",
                relay_id,
                {"name": after.name, "ssh": f"{current.agent.ssh_host}:{current.agent.ssh_port}",
                 "uninstalled": uninstalled},
            )
            await self.refresh_catalog()
        await self.sync_hub_jump_quietly()
        return DetachReport(relay=after, uninstalled=uninstalled)

    # ── «Довести»: the input filter on, then SSH off 22 (module docstring) ────

    async def harden(
        self, actor_user_id: int, relay_id: int,
        on_progress: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> tuple[str, ...]:
        """«Довести»: what :func:`hardening_of` says is left, step by step (keys
        ``filter_on``, ``filter_confirm``, ``ssh_set``, ``ssh_finish`` to *on_progress*).
        Returns what was done ("filter", "ssh"). A failed step was rolled back and raises
        (its error says how); a step before it stays done."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        hardening = hardening_of(relay)
        if hardening is None or not hardening.needed:
            raise InvalidOperation("relay уже в норме", key="relay_harden_nothing", params={"name": relay.name})
        if agent_older_than(relay.agent, hardening.agent_version):
            raise InvalidOperation(
                "агент relay устарел для этого", key="relay_harden_agent_old",
                params={"name": relay.name, "version": agent_release(relay.agent)},
            )

        async def step(name: str, state: str) -> None:
            if on_progress is not None:
                await on_progress(name, state)

        done: list[str] = []
        # Step 0, always: a foreign sshd override (a fresh host check on the relay); one
        # found is moved away — the relay takes passwords until it is.
        if await self._harden_sshd(actor_user_id, relay, step):
            done.append("sshd")
        if hardening.filter_off:
            await self._harden_filter(actor_user_id, relay, step)
            done.append("filter")
        if hardening.ssh_on_22:
            await self._harden_ssh(actor_user_id, relay_id, step)
            done.append("ssh")
        return tuple(done)

    async def _harden_filter(
        self, actor_user_id: int, relay: Relay, step: Callable[[str, str], Awaitable[None]]
    ) -> None:
        """Step 1: ``input-filter on`` → ``input-confirm`` (a NEW ssh session) →
        ``input-filter on`` (commits). Rolled back with ``input-filter off``."""
        await step("filter_on", "run")
        claimed = await self._claim(relay.id)
        rollback = ""
        try:
            try:
                reply = await self._call(claimed, "input-filter on", timeout=300.0)
            except ServiceError:
                await step("filter_on", "fail")
                raise
            if not reply.ok:
                await step("filter_on", "fail")
                self._require_ok(reply, claimed)  # the agent put .env back itself
            committed = _filter_committed(reply)
            await step("filter_on", "ok")
            await step("filter_confirm", "run")
            error = ""
            if not committed:
                try:
                    confirm = await self._input_confirm(actor_user_id, claimed, auto=False)
                    if confirm.ok:
                        reply = await self._call(claimed, "input-filter on", timeout=300.0)
                        committed = _filter_committed(reply)
                        error = "" if committed else (reply.error or str(reply.payload.get("input_status") or ""))
                    else:
                        error = confirm.error
                except ServiceError as exc:
                    error = str(exc)
            if not committed:
                rollback = await self._filter_off(claimed)
                await step("filter_confirm", "fail")
                await self._audit(actor_user_id, "relay_input_filter_on", relay.id,
                                  {"name": relay.name, "ok": False, "error": error[:300], "rollback": rollback})
                raise RelayAgentError(
                    "входной фильтр не подтверждён",
                    key="relay_harden_filter_failed" if rollback == "restored" else "relay_harden_filter_failed_deadman",
                    params={"name": relay.name, "error": error[:300] or "—"},
                )
            await step("filter_confirm", "ok")
        finally:
            self._busy.discard(relay.id)
        await self._audit(actor_user_id, "relay_input_filter_on", relay.id, {"name": relay.name, "ok": True})
        await self._status_after(actor_user_id, relay.id)

    async def _harden_sshd(
        self, actor_user_id: int, relay: Relay, step: Callable[[str, str], Awaitable[None]]
    ) -> bool:
        """Step 0 of «Довести»: ``sshd-check``, then ``sshd-override-off`` for each file
        it names. True when a file was moved. An agent older than the request skips the
        step (⏭: its status cannot name an override either)."""
        await step("sshd_check", "run")
        if agent_older_than(relay.agent, AGENT_SSHD_OVERRIDE):
            await step("sshd_check", "skip")
            return False
        try:
            check = await self.sshd_check(actor_user_id, relay.id)
        except RelayAgentError as exc:
            if exc.key == "relay_agent_outdated":
                await step("sshd_check", "skip")
                return False
            await step("sshd_check", "fail")
            raise
        except ServiceError:
            await step("sshd_check", "fail")
            raise
        for override in check.overrides:
            try:
                await self.remove_sshd_override(actor_user_id, relay.id, override.path)
            except ServiceError:
                await step("sshd_check", "fail")
                raise
        await step("sshd_check", "ok")
        return bool(check.overrides)

    # ── a foreign sshd override (docs/relay.md «Чужой sshd-override») ─────────

    async def sshd_check(self, actor_user_id: int | None, relay_id: int) -> SshdCheck:
        """``sshd-check``: a fresh host check on the relay — the foreign sshd overrides it
        names. *actor_user_id* None: the bot itself (the override monitor)."""
        if actor_user_id is not None:
            await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        reply = self._require_ok(await self._call(relay, "sshd-check", timeout=300.0), relay)
        return SshdCheck(
            overrides=sshd_overrides_of(reply.payload.get("sshd_overrides")),
            drift=sshd_drift_of(reply.payload.get("sshd_drift")),
            checked_at=str(reply.payload.get("host_check_at") or "")[:40],
        )

    async def remove_sshd_override(self, actor_user_id: int, relay_id: int, path: str) -> dict[str, Any]:
        """``sshd-override-off path=<path>``: the agent moves the file to /root/attic —
        only one a fresh host check names, only while root keeps an own key — checks
        and reloads sshd, and puts it back on any failure. The answer's ``sshd_override``."""
        await self.users.require_superadmin(actor_user_id)
        if SSHD_DROPIN.fullmatch(path) is None or path.rsplit("/", 1)[-1] in REPO_SSHD_DROPINS:
            raise InvalidOperation("не чужой файл sshd_config.d", key="relay_sshd_override_bad_path",
                                   params={"path": path[:120]})
        relay = await self._require_managed(relay_id)
        if agent_older_than(relay.agent, AGENT_SSHD_OVERRIDE):
            raise RelayAgentError("агент relay устарел", key="relay_sshd_override_agent_old",
                                  params={"name": relay.name, "version": agent_release(relay.agent), "path": path})
        claimed = await self._claim(relay_id)
        try:
            reply = await self._call(claimed, f"sshd-override-off path={path}", timeout=600.0)
        finally:
            self._busy.discard(claimed.id)
        raw = reply.payload.get("sshd_override")
        result: dict[str, Any] = dict(raw) if isinstance(raw, Mapping) else {}
        await self._audit(actor_user_id, "relay_sshd_override_off", relay.id,
                          {"name": relay.name, "path": path, "ok": reply.ok,
                           **({"moved_to": result.get("moved_to")} if reply.ok else {"error": reply.error[:300]})})
        if not reply.ok:
            if result.get("refused") == "no_personal_key":
                raise RelayAgentError("нет личного ключа", key="relay_sshd_override_no_key", params={"name": relay.name})
            if unknown_request(reply):
                raise RelayAgentError("агент relay устарел", key="relay_sshd_override_agent_old",
                                      params={"name": relay.name, "version": agent_release(relay.agent), "path": path})
            raise RelayAgentError(f"relay: {reply.error}", key="relay_sshd_override_error",
                                  params={"path": path, "error": reply.error[:300]})
        await self._status_after(actor_user_id, relay.id)
        return result

    async def update_log(self, actor_user_id: int, relay_id: int) -> tuple[str, str] | None:
        """``update-log``: (the deploy log's path on the relay, its end) — None from an
        agent older than the request."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        reply = await self._call(relay, "update-log", timeout=60.0)
        if unknown_request(reply):
            return None
        raw = reply.payload.get("update_log")
        data: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
        if not reply.ok:
            raise RelayAgentError(f"relay: {reply.error}", key="relay_update_log_missing",
                                  params={"error": reply.error[:300]})
        return str(data.get("log") or "")[:200], str(data.get("text") or "")

    async def _filter_off(self, relay: Relay) -> str:
        """The rollback of step 1: «restored», or why the dead-man does it."""
        try:
            reply = await self._call(relay, "input-filter off", timeout=300.0)
        except ServiceError as exc:
            logger.warning("Relay %s: input-filter off failed: %s", relay.name, exc)
            return "deadman"
        return "restored" if reply.ok else "deadman"

    async def _harden_ssh(self, actor_user_id: int, relay_id: int, step: Callable[[str, str], Awaitable[None]]) -> None:
        """Step 2: ``ssh-port-set port=54321`` (phase 1), then :meth:`finish_ssh_port` on
        54321. Rolled back with ``ssh-port-set port=22`` (phase 1 cancelled)."""
        await step("ssh_set", "run")
        try:
            await self.set_ssh_port(actor_user_id, relay_id, port=HARDEN_SSH_PORT)
        except ServiceError:
            await step("ssh_set", "fail")
            raise
        since = _phase1_since(await self._require(relay_id), HARDEN_SSH_PORT)
        if since is None:
            # The status after the set was not kept (a health call ran next to it): ask.
            with contextlib.suppress(ServiceError):
                await self.agent_status(actor_user_id, relay_id)
            since = _phase1_since(await self._require(relay_id), HARDEN_SSH_PORT)
        if since is None:
            rollback = await self._ssh_port_back(actor_user_id, relay_id)
            await step("ssh_set", "fail")
            raise _ssh_failed(rollback, "no phase 1 of the migration in the relay's status")
        await step("ssh_set", "ok")
        await step("ssh_finish", "run")
        try:
            await self.finish_ssh_port(actor_user_id, relay_id, port=HARDEN_SSH_PORT, since=since)
        except ServiceError as exc:
            rollback = await self._ssh_port_back(actor_user_id, relay_id)
            await step("ssh_finish", "fail")
            raise _ssh_failed(rollback, str(exc)) from exc
        await step("ssh_finish", "ok")

    async def _ssh_port_back(self, actor_user_id: int, relay_id: int) -> str:
        """The rollback of step 2: SSH_PORT=22 again, phase 1 cancelled (22 alone)."""
        relay = await self._require(relay_id)
        try:
            claimed = await self._claim(relay_id)
        except ServiceError as exc:
            return f"FAILED: {exc}"[:300]
        try:
            reply = await self._call(claimed, f"ssh-port-set port={HARDEN_FROM_PORT}", timeout=300.0)
        except ServiceError as exc:
            reply = AgentReply(255, {"ok": False, "error": str(exc)})
        finally:
            self._busy.discard(relay_id)
        await self._audit(actor_user_id, "relay_ssh_port_set", relay.id,
                          {"name": relay.name, "to": HARDEN_FROM_PORT, "rollback": True, "ok": reply.ok,
                           **({} if reply.ok else {"error": reply.error[:300]})})
        await self._status_after(actor_user_id, relay_id)
        return "restored" if reply.ok else f"FAILED: {reply.error}"[:300]

    # ── the SSH port of a relay (docs/host-state.md#the-ssh-port) ──────────────

    async def finish_ssh_port(
        self, actor_user_id: int, relay_id: int, *, port: int, since: int,
        on_progress: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> AgentReply:
        """«Подтвердить»: phase 2 of the relay's SSH port migration, proven by THIS call.

        The bot reaches the agent on the NEW port — directly, or through the hub with
        the new port opened in the jump line next to the old one — and the agent runs
        phase 2 only when its session came in on that port. A new port that does not
        answer from here fails the call before anything is closed. Afterwards the
        relay's row says the new port, the jump line opens it alone, and a TCP set
        the input filter now waits a confirmation for is confirmed by the same kind of
        NEW session (input-confirm)."""
        await self.users.require_superadmin(actor_user_id)
        if not 1 <= port <= 65535 or since <= 0:
            raise InvalidOperation("плохой порт", key="relay_ssh_port_bad", params={"value": str(port)})

        async def step(name: str, state: str) -> None:
            if on_progress is not None:
                await on_progress(name, state)

        relay = await self._claim(relay_id)
        agent = relay.agent
        assert agent is not None
        request = f"ssh-port-finish port={port} since={since}"
        await step("probe", "run")
        try:
            client = self._require_client()
            via = None
            if not relay.is_hub and (relay.via_hub or await self.relays.fallback_mode_on()):
                via = await self._jump_to((agent.ssh_host.lower(), port))
            reply = await _agent_call(
                client, agent.ssh_host, port, request, alias=f"vpn-relay-{relay.id}", host_key=agent.host_key,
                timeout=300.0, via=via,
            )
            if reply.ok:
                async with self._lock:
                    await self.relays.update_agent_ssh_port(relay.id, port, now=self.clock.now(), updated_by=actor_user_id)
        finally:
            self._busy.discard(relay.id)
        await self._audit(
            actor_user_id, "relay_ssh_port_finished", relay.id,
            {"name": relay.name, "from": agent.ssh_port, "to": port, "since": since, "ok": reply.ok,
             **({} if reply.ok else {"error": reply.error[:300]})},
        )
        if not reply.ok:
            await step("probe" if reply.returncode in (2, 255) else "phase2", "fail")
        self._require_ok(reply, relay)
        await step("probe", "ok")
        await step("phase2", "ok")
        await step("jump", "run")
        await self.sync_hub_jump_quietly()
        await step("jump", "ok")
        await step("filter", "run")
        await self._status_after(actor_user_id, relay.id)
        await step("filter", "ok")
        return reply

    async def keep_ssh_port(self, actor_user_id: int, relay_id: int, *, since: int, keep: bool = True) -> AgentReply:
        """«Оставить»: the relay holds phase 1 (both ports, no phase 2 on any proof);
        ``keep=False`` — «Вернуться к переезду»: it waits for proof again."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        request = f"ssh-port-{'keep' if keep else 'resume'} since={since}"
        reply = await self._call(relay, request, timeout=120.0)
        await self._audit(actor_user_id, "relay_ssh_port_kept" if keep else "relay_ssh_port_resumed", relay.id,
                          {"name": relay.name, "since": since, "ok": reply.ok,
                           **({} if reply.ok else {"error": reply.error[:300]})})
        self._require_ok(reply, relay)
        await self._status_after(actor_user_id, relay.id)
        return reply

    async def set_ssh_port(self, actor_user_id: int, relay_id: int, *, port: int) -> AgentReply:
        """«Сменить порт»: SSH_PORT=<port> on the relay and phase 1 right away (both
        ports listen) — no deploy. The old port closes later, on «Подтвердить»."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        agent = relay.agent
        assert agent is not None
        if not 1 <= port <= 65535 or port == agent.ssh_port or port in agent.tcp_ports:
            raise InvalidOperation("плохой порт", key="relay_ssh_port_bad", params={"value": str(port)})
        claimed = await self._claim(relay_id)
        try:
            reply = await self._call(claimed, f"ssh-port-set port={port}", timeout=300.0)
        finally:
            self._busy.discard(relay_id)
        await self._audit(actor_user_id, "relay_ssh_port_set", relay.id,
                          {"name": relay.name, "from": agent.ssh_port, "to": port, "ok": reply.ok,
                           **({} if reply.ok else {"error": reply.error[:300]})})
        self._require_ok(reply, relay)
        await self._status_after(actor_user_id, relay.id)
        return reply

    async def _status_after(self, actor_user_id: int | None, relay_id: int) -> None:
        """A fresh status (a NEW session: it confirms a pending input filter), kept."""
        relay = await self._require(relay_id)
        try:
            status = await self._call(relay, "status")
            if status.ok:
                status = await self._confirm_if_pending(actor_user_id, relay, status)
                await self._record_status(relay, status)
        except ServiceError:
            logger.info("Relay %s: status after the SSH port change not received", relay.name)

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _require(self, relay_id: int) -> Relay:
        relay = await self.relays.get_by_id(relay_id)
        if relay is None:
            raise NotFound("Relay не найден", key="err_relay_not_found")
        return relay

    async def _require_managed(self, relay_id: int) -> Relay:
        relay = await self._require(relay_id)
        if relay.agent is None:
            raise NotFound("у relay нет агента", key="relay_agent_not_managed")
        return relay

    def _require_settings(self) -> Settings:
        if self.settings is None:
            raise ServiceError("relay-агенты не подключены", key="relay_agent_unavailable")
        return self.settings

    def _require_keys(self) -> RelayKeyStore:
        self._require_settings()
        if self.keys is None:
            raise ServiceError("relay-агенты не подключены", key="relay_agent_unavailable")
        return self.keys

    def _require_client(self) -> RelayAgentClient:
        self._require_settings()
        if self.client is None:
            raise ServiceError("relay-агенты не подключены", key="relay_agent_unavailable")
        return self.client

    def _require_jump_keys(self) -> RelayKeyStore:
        jump_keys: RelayKeyStore | None = getattr(self._require_client(), "jump_keys", None)
        if jump_keys is None:
            raise ServiceError("jump-ключ не подключён", key="relay_agent_unavailable")
        return jump_keys

    @staticmethod
    def _refuse_hub(relay: Relay) -> None:
        """A hub is not deleted, uninstalled, detached or re-pointed from its card:
        in the fallback mode every client reaches the main server through it, and
        its own key usage counts none of them. Its role is removed first
        («🛟 Снять роль hub»), which the fallback service refuses while any failover
        name may still point at it."""
        if relay.is_hub:
            raise InvalidOperation("relay — hub", key="relay_is_hub", params={"name": relay.name})

    def _ensure_idle(self, relay: Relay) -> None:
        if relay.id in self._busy:
            raise InvalidOperation("relay занят", key="relay_busy", params={"name": relay.name})

    async def _claim(self, relay_id: int) -> Relay:
        """Mark a relay with an agent busy for one long agent call (released by the caller)."""
        async with self._lock:
            relay = await self._require_managed(relay_id)
            self._ensure_idle(relay)
            self._busy.add(relay.id)
            return relay

    async def _uninstall(self, actor_user_id: int, relay: Relay) -> None:
        """``uninstall`` on the relay, then mark it (an interrupted delete/detach resumes)."""
        claimed = await self._claim(relay.id)
        agent = claimed.agent
        assert agent is not None
        try:
            reply = await self._call(claimed, "uninstall", timeout=360.0)
            if reply.ok:
                # The bot's key is no longer authorized there; the row stays marked
                # until the delete/detach that asked for this has finished. Written
                # while still busy, so the health loop cannot overwrite the mark.
                async with self._lock:
                    await self.relays.record_agent_status(
                        claimed.id, {**(agent.last_status or {}), UNINSTALLED_KEY: self.clock.now()},
                        now=self.clock.now(), agent_version=agent.agent_version,
                    )
                    await self.refresh_catalog()
        finally:
            self._busy.discard(claimed.id)
        await self._audit(actor_user_id, "relay_agent_uninstall", claimed.id,
                          {"name": claimed.name, "ok": reply.ok, **({} if reply.ok else {"error": reply.error[:300]})})
        self._require_ok(reply)

    async def _call(self, relay: Relay, request: str, *, timeout: float = 120.0) -> AgentReply:
        agent = relay.agent
        if agent is None:
            raise NotFound("у relay нет агента", key="relay_agent_not_managed")
        if agent_uninstalled(agent) and request != "uninstall":
            raise RelayAgentError("relay уже снят с хоста", key="relay_agent_uninstalled")
        client = self._require_client()
        via = await self._route(relay)
        try:
            return await _agent_call(
                client, agent.ssh_host, agent.ssh_port, request, alias=f"vpn-relay-{relay.id}",
                host_key=agent.host_key, timeout=timeout, via=via,
            )
        except RelaySshError as exc:
            if via is None or exc.key not in _JUMP_RESYNC_KEYS:
                raise
            # The hub refused the forward: its jump line is not what the bot last
            # wrote (the hub re-installed, edited by hand). Write it again, once.
            logger.info("Relay %s: the hub refused the forward — rewriting its jump line", relay.name)
            via = await self._jump_to(None, force=True)
            return await client.call(
                agent.ssh_host, agent.ssh_port, request, alias=f"vpn-relay-{relay.id}",
                host_key=agent.host_key, timeout=timeout, via=via,
            )

    # ── through the hub ───────────────────────────────────────────────────────

    def behind_hub(self, relay: Relay, *, mode_on: bool) -> bool:
        """The bot reaches this relay's agent through the hub: not a hub, an agent
        that is still installed, and «через hub» or the fallback mode."""
        return (
            not relay.is_hub
            and relay.agent is not None
            and not agent_uninstalled(relay.agent)
            and (relay.via_hub or mode_on)
        )

    async def route_info(self, relay: Relay) -> RouteInfo:
        """How calls to *relay*'s agent go right now (its card says so)."""
        if relay.is_hub or relay.agent is None:
            return RouteInfo(via_hub=False)
        if relay.via_hub:
            return RouteInfo(via_hub=True, reason="flag", hub=await self._hub())
        if await self.relays.fallback_mode_on():
            return RouteInfo(via_hub=True, reason="mode", hub=await self._hub())
        return RouteInfo(via_hub=False)

    async def _hub(self) -> Relay | None:
        """THE hub (services.relay.select_hub) when it can carry the jump: an agent
        that is still installed."""
        hub = select_hub(await self.relays.list_hubs())
        if hub is None or hub.agent is None or agent_uninstalled(hub.agent):
            return None
        return hub

    async def _route(self, relay: Relay) -> JumpHost | None:
        """How a call to *relay* goes: None — directly; a :class:`JumpHost` — through
        the hub (refused when the relay is behind the hub and there is none)."""
        if relay.is_hub or relay.agent is None:
            return None
        if not relay.via_hub and not await self.relays.fallback_mode_on():
            return None
        return await self._jump_to(None)

    async def _jump_to(self, extra: tuple[str, int] | None, *, force: bool = False) -> JumpHost:
        sync = await self.sync_hub_jump(extra=extra, force=force)
        hub = sync.hub
        if hub is None or hub.agent is None:
            raise RelaySshError("нет hub для пути через hub", key="relay_hub_route_no_hub")
        return JumpHost(
            host=hub.agent.ssh_host,
            port=hub.agent.ssh_port,
            alias=f"vpn-relay-{hub.id}",
            host_key=hub.agent.host_key,
            opens=frozenset(sync.opens),
        )

    async def jump_opens(self, extra: tuple[str, int] | None = None) -> tuple[tuple[str, int], ...]:
        """``ssh_host:ssh_port`` of every relay behind the hub (+ *extra*), sorted."""
        mode_on = await self.relays.fallback_mode_on()
        opens = {
            (relay.agent.ssh_host.lower(), relay.agent.ssh_port)
            for relay in await self.relays.list_all()
            if relay.agent is not None and self.behind_hub(relay, mode_on=mode_on)
        }
        opens |= self._jump_pairing
        if extra is not None:
            opens.add(extra)
        return tuple(sorted(opens))

    async def sync_hub_jump(
        self, actor_user_id: int | None = None, *, extra: tuple[str, int] | None = None, force: bool = False
    ) -> JumpSync:
        """Make the hub's jump line open exactly the relays behind it (+ *extra*, a
        relay being paired). One agent call on the hub (reached directly) — none
        when the line is already what the bot last wrote, unless *force*."""
        async with self._jump_lock:
            hub = await self._hub()
            if hub is None:
                return JumpSync(hub=None, opens=())
            opens = await self.jump_opens(extra)
            public = self._require_jump_keys().ensure()
            if not force and self._jump_written.get(hub.id) == (public, opens):
                return JumpSync(hub=hub, opens=opens)
            reply = self._require_ok(await self._call(hub, jump_request(public, opens), timeout=60.0), hub)
            self._jump_written = {hub.id: (public, opens)}
        result = reply.payload.get("jump")
        changed = bool(result.get("changed")) if isinstance(result, dict) else False
        if changed or actor_user_id is not None:
            await self._audit(
                actor_user_id, "relay_hub_jump_synced", hub.id,
                {"hub": hub.name, "open": [f"{host}:{port}" for host, port in opens], "changed": changed},
            )
        return JumpSync(hub=hub, opens=opens, changed=changed)

    async def drop_hub_jump(self, actor_user_id: int | None, relay: Relay) -> bool:
        """``jump-off`` on a relay that stops being the hub: its jump line goes. True
        when the agent answered."""
        if relay.agent is None or agent_uninstalled(relay.agent) or self.client is None:
            return False
        try:
            reply = self._require_ok(await self._call(relay, "jump-off", timeout=60.0), relay)
        except ServiceError as exc:
            logger.warning("Relay %s: jump-off failed: %s", relay.name, exc)
            return False
        self._jump_written.pop(relay.id, None)
        await self._audit(actor_user_id, "relay_hub_jump_removed", relay.id,
                          {"hub": relay.name, "changed": bool((reply.payload.get("jump") or {}).get("changed"))})
        return True

    async def sync_hub_jump_quietly(self) -> None:
        """:meth:`sync_hub_jump` where a failure must not undo what was done (logged;
        the next call through the hub writes the line again)."""
        if getattr(self.client, "jump_keys", None) is None:
            return
        try:
            await self.sync_hub_jump()
        except ServiceError as exc:
            logger.warning("The hub's jump line was not written: %s", exc)

    async def set_via_hub(self, actor_user_id: int, relay_id: int, on: bool) -> ViaHubResult:
        """«Через hub»: the bot reaches this relay's agent through the hub, always."""
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            relay = await self._require_managed(relay_id)
            if relay.is_hub:
                raise InvalidOperation("relay — hub", key="relay_via_hub_is_hub", params={"name": relay.name})
            if on and await self._hub() is None:
                raise InvalidOperation("нет hub", key="relay_hub_route_no_hub", params={"name": relay.name})
            if relay.via_hub == on:
                return ViaHubResult(relay=relay)
            await self.relays.set_via_hub(relay.id, on, now=self.clock.now(), updated_by=actor_user_id)
            await self.refresh_catalog()
            after = await self._require(relay.id)
        await self._audit(actor_user_id, "relay_via_hub_changed", relay.id, {"name": relay.name, "via_hub": on})
        try:
            await self.sync_hub_jump(actor_user_id)
        except ServiceError as exc:
            return ViaHubResult(relay=after, sync_error=exc)
        return ViaHubResult(relay=after)

    async def _checks_through(
        self, ssh_host: str, ssh_port: int, alias: str, host_key: str, via: JumpHost
    ) -> CheckResult:
        """A pairing behind the hub: this server cannot probe the relay, so the relay's
        own ``vpn-relay-apply check`` (TCP to its upstream on every forwarded port,
        TLS) — asked through the hub with the key the hello just learned."""
        client = self._require_client()
        reply = await client.call(ssh_host, ssh_port, "status", alias=alias, host_key=host_key, timeout=150.0, via=via)
        return CheckResult(tcp=reply.ok and own_check_healthy(reply.payload), udp=None, via_hub=True)

    # ── the input filter ──────────────────────────────────────────────────────

    async def confirm_input(self, actor_user_id: int, relay_id: int) -> AgentReply:
        """«Подтвердить входной фильтр»: ``input-confirm`` from a NEW ssh session of
        the bot's (through the hub when the relay is behind it)."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require_managed(relay_id)
        reply = await self._input_confirm(actor_user_id, relay, auto=False)
        self._require_ok(reply, relay)
        try:
            status = await self._call(relay, "status")
            if status.ok:
                await self._record_status(relay, status)
        except ServiceError:
            logger.info("Relay %s: status after input-confirm not received", relay.name)
        return reply

    async def _input_confirm(self, actor_user_id: int | None, relay: Relay, *, auto: bool) -> AgentReply:
        reply = await self._call(relay, "input-confirm", timeout=90.0)
        await self._audit(
            actor_user_id, "relay_input_confirmed", relay.id,
            {"name": relay.name, "ok": reply.ok, "auto": auto,
             **({"input_status": reply.payload.get("input_status")} if reply.ok else {"error": reply.error[:300]})},
        )
        return reply

    async def _confirm_if_pending(self, actor_user_id: int | None, relay: Relay, status: AgentReply) -> AgentReply:
        """*status* — or, when its input filter waits for a confirmation, the same
        answer after ``input-confirm`` (its ``input_status`` the new one). A failed
        confirmation is logged and audited; the status stays as it was."""
        if not input_pending(status.payload):
            return status
        try:
            confirmed = await self._input_confirm(actor_user_id, relay, auto=True)
        except ServiceError as exc:
            logger.warning("Relay %s: input-confirm failed: %s", relay.name, exc)
            return status
        if not confirmed.ok:
            logger.warning("Relay %s: input-confirm refused: %s", relay.name, confirmed.error)
            return status
        payload = {**status.payload, "input_status": confirmed.payload.get("input_status") or status.payload.get("input_status")}
        return replace(status, payload=payload)

    async def _record_status(self, relay: Relay, reply: AgentReply) -> bool:
        """:meth:`_record_answer`, then every :attr:`status_listeners` with the answer
        (the SSH port monitor asks a superadmin when the relay is in phase 1 of a
        migration). A listener that fails is logged; the answer is kept anyway."""
        recorded = await self._record_answer(relay, reply)
        if recorded:
            await self._tell_listeners(relay, reply.payload)
        return recorded

    async def _tell_listeners(self, relay: Relay, payload: Mapping[str, Any]) -> None:
        for listener in self.status_listeners:
            try:
                await listener(relay, payload)
            except Exception as exc:  # a listener never breaks the health loop
                logger.warning("Relay %s: a status listener failed: %s: %s", relay.name, type(exc).__name__, exc)

    async def _record_answer(self, relay: Relay, reply: AgentReply) -> bool:
        """Keep a ``status`` answer on the relay's row — only if it still describes it.

        The request may have started before an agent call that changes the row: under
        the lock, the answer is dropped while an agent call runs on the relay, or
        when the relay meanwhile lost its agent, got another one or was uninstalled
        (the repository refuses to erase that mark too).
        """
        async with self._lock:
            current = await self.relays.get_by_id(relay.id)
            if (
                relay.id in self._busy
                or current is None
                or current.agent is None
                or relay.agent is None
                or agent_uninstalled(current.agent)
                or current.agent.host_key != relay.agent.host_key
            ):
                return False
            return await self.relays.record_agent_status(
                relay.id, _slim(reply.payload), now=self.clock.now(), agent_version=str(reply.payload.get("agent", ""))
            )

    @staticmethod
    def _require_ok(reply: AgentReply, relay: Relay | None = None) -> AgentReply:
        if not reply.ok:
            if relay is not None and unknown_request(reply):
                # An agent from before the request existed (input-confirm, jump): update it.
                raise RelayAgentError(
                    "агент relay устарел", key="relay_agent_outdated", params={"name": relay.name}
                )
            raise RelayAgentError(
                f"relay: {reply.error}", key="relay_agent_refused", params={"error": reply.error[:300]}
            )
        return reply

    @staticmethod
    def _parse_target(value: str) -> str:
        try:
            return parse_target_host(value)
        except PairingCodeError as exc:
            raise InvalidOperation(str(exc), key="relay_pair_bad_target", params={"value": value}) from exc

    async def _expire(self) -> None:
        await self.relays.expire_pairings(before=int(self._now()) - COMPLETION_GRACE_SECONDS, now=self.clock.now())

    async def _pending(self, pairing_id: int) -> RelayPairing:
        await self._expire()
        pairing = await self.relays.get_pairing(pairing_id)
        if pairing is None or pairing.state != "pending" or not pairing.token:
            raise NotFound("pairing не найден или закрыт", key="relay_pair_not_pending")
        return pairing

    async def _attach_target(self, pairing: RelayPairing) -> Relay:
        if pairing.relay_id is None:
            raise NotFound("Relay не найден", key="err_relay_not_found")
        relay = await self._require(pairing.relay_id)
        if relay.agent is not None:
            raise InvalidOperation("у relay уже есть агент", key="relay_agent_already", params={"name": relay.name})
        return relay

    async def _same_server(self, relay: Relay, ssh_host: str) -> bool:
        """The SSH address is this relay: its host, inside its source IPs, or the
        address its host resolves to."""
        if ssh_host == relay.host.lower():
            return True
        ssh_ips = await self._resolve(ssh_host)
        if any(_covers(relay.source_ips, ip) for ip in ssh_ips):
            return True
        return bool(set(ssh_ips) & set(await self._resolve(relay.host)))

    def _render(self, pairing: RelayPairing) -> IssuedPairing:
        keys = self._require_keys()
        if self.source_root is None:
            raise ServiceError("relay-агенты не подключены", key="relay_agent_unavailable")
        code = encode_pairing_code(
            PairingCode(
                target_host=pairing.target_host,
                tcp_ports=pairing.tcp_ports,
                udp_ports=pairing.udp_ports,
                main_pubkey=keys.public_key(),
                token=pairing.token,
                exp=pairing.expires_at,
            )
        )
        return IssuedPairing(pairing=pairing, code=code, command=relay_command(code, installer_source(self.source_root)))

    @staticmethod
    def _expect_pairing(payload: Mapping[str, Any], pairing: RelayPairing) -> None:
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

    async def _source_ips(self, host: str, payload: Mapping[str, Any]) -> list[str]:
        """What this server sees relayed traffic come from: the relay's address(es)
        and the source address it reports for the upstream, when that is public."""
        found = set(await self._resolve(host))
        egress = payload.get("egress")
        src = egress.get("src") if isinstance(egress, dict) else None
        if isinstance(src, str) and validators.ipv4_address(src) is not None and routable(src):
            found.add(src)
        if not found:
            raise InvalidOperation("не удалось определить адрес relay", key="relay_pair_no_source", params={"value": host})
        return _sort_ips(found)

    async def _free_label(self, name: str) -> str:
        for candidate in (validators.DEFAULT_RELAY_LABEL, name[:16], f"{name[:15]}_"):
            if await self.relays.get_by_label(candidate) is None:
                return candidate
        return f"r{int(self._now()) % 100000}"

    async def _ensure_name_free(self, name: str) -> None:
        if await self.relays.get_by_name(name) is not None:
            raise InvalidOperation(f"relay {name!r} уже есть", key="err_relay_name_taken", params={"value": name})
        if await self.relays.name_used_by_keys(name):
            raise InvalidOperation(
                f"имя {name!r} уже носят ключи", key="err_relay_name_used_by_keys", params={"value": name}
            )

    async def _audit(
        self, actor_user_id: int | None, action: str, relay_id: int | None, details: dict[str, object]
    ) -> None:
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=AuditEntityType.RELAY,
            entity_id=relay_id,
            details=details,
        )
