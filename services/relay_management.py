"""Relays in the admin panel: add, edit, switch off and delete L4 relays.

Relays used to be four ``RELAY_*`` variables in ``.env``; they are rows of the
``relays`` table now, and :class:`RelayService` is the only thing that writes
them. Every write:

* is SUPERADMIN-only (:class:`services.errors.AccessDenied` otherwise);
* validates its input with the very functions the ``.env`` loader used
  (:mod:`config.validators`), so a value accepted in one place is accepted in the
  other;
* is audited with the values before and after;
* replaces the bot's :class:`services.relay.RelayCatalog` snapshot right away —
  the bot is the single writer, so its cached snapshot cannot go stale, and the
  subscription endpoint reads the table on every request anyway.

A relay's ``name`` is the value its keys carry in ``vpn_keys.relay`` and never
changes. A name that any key row still carries (in any status) can never be
given to a new relay: those keys would silently start pointing at somebody else's
host. The one exception is the one-time seed from the legacy ``RELAY_*``
variables (:meth:`RelayService.seed_from_settings`), whose whole point is to give
the relay its keys already name back to them.

Deleting a relay that still has keys removes each key through the SAME path the
key screen uses (backend removal, traffic archive, audit — a bundle child goes
and its bundle keeps the other members), stops at the first key that fails and
reports how far it got; running it again finishes the job.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from adapters.clock import ClockProvider
from config import validators
from config.settings import Settings
from models.dto import Relay
from models.enums import AuditEntityType, VpnKeyType
from repositories.relays import RelayRepository, RelayUsage
from services.audit import AuditService
from services.errors import InvalidOperation, NotFound
from services.notes import MAX_NOTE_LENGTH, normalize_note
from services.relay import RelayCatalog, RelaySnapshot
from services.users import UserService

logger = logging.getLogger(__name__)

# Removes one key through its protocol's normal delete path: (actor, key_id).
KeyDeleter = Callable[[int, int], Awaitable[None]]


# ── input validation (shared by the service and the panel's wizard steps) ─────


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
    """A relay's host: a DNS name or an IPv4 address, never empty."""
    try:
        host = validators.dns_name_or_ipv4("host", value or "")
    except validators.InvalidValue as exc:
        raise InvalidOperation(
            str(exc), key="err_relay_host_invalid", params={"value": (value or "").strip()}
        ) from exc
    if not host:
        raise InvalidOperation("host не задан", key="err_relay_host_required")
    return host


def parse_relay_source_ips(value: str) -> tuple[ipaddress.IPv4Network, ...]:
    """A relay's egress list: IPv4 addresses / CIDR networks, comma-separated, never empty.

    Parsed with :func:`config.validators.parse_ipv4_networks` — the RELAY_SOURCE_IPS
    parser. On a bad entry the error names that entry, found by running the same
    parser over the items one by one.
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


def _covers(networks: tuple[ipaddress.IPv4Network, ...], host: str) -> bool:
    address = validators.ipv4_address(host)
    return address is not None and any(address in network for network in networks)


def _audit_view(relay: Relay) -> dict[str, object]:
    """The audited fields of a relay (no secrets — a relay has none)."""
    return {
        "name": relay.name,
        "label": relay.label,
        "host": relay.host,
        "source_ips": validators.format_ipv4_networks(relay.source_ips),
        "enabled": relay.enabled,
        "in_subscriptions": relay.in_subscriptions,
        "note": relay.note,
    }


# ── results ───────────────────────────────────────────────────────────────────


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
    continues from there.
    """

    relay: Relay
    deleted: bool
    deleted_key_ids: tuple[int, ...] = ()
    failed_key_id: int | None = None
    failure: Exception | None = None
    remaining_keys: int = 0


_UNSET = object()


class RelayService:
    """Create / edit / delete relays (SUPERADMIN only) and keep the bot's snapshot current."""

    def __init__(
        self,
        *,
        relays: RelayRepository,
        users: UserService,
        audit: AuditService,
        clock: ClockProvider,
        catalog: RelayCatalog,
        key_deleters: Mapping[VpnKeyType, KeyDeleter] | None = None,
    ) -> None:
        self.relays = relays
        self.users = users
        self.audit = audit
        self.clock = clock
        self.catalog = catalog
        # Protocol -> its normal per-key delete path; wired by bot.app. A key whose
        # protocol has no entry cannot be removed here and stops the delete.
        self._key_deleters: dict[VpnKeyType, KeyDeleter] = dict(key_deleters or {})
        # Serialises every write. Taken before any per-protocol lock (the delete
        # path calls into the key services) and by nothing those services call,
        # so no cycle is possible.
        self._lock = asyncio.Lock()

    def attach_key_deleters(self, key_deleters: Mapping[VpnKeyType, KeyDeleter]) -> None:
        self._key_deleters = dict(key_deleters)

    @property
    def snapshot(self) -> RelaySnapshot:
        return self.catalog.snapshot

    async def refresh_catalog(self) -> RelaySnapshot:
        """Re-read the table into the bot's snapshot (after every write, and at startup)."""
        snapshot = RelaySnapshot.of(await self.relays.list_all())
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
        """Validate a name for a NEW relay: format, not taken, not carried by any key."""
        await self.users.require_superadmin(actor_user_id)
        name = parse_relay_name(value)
        await self._ensure_name_free(name)
        return name

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

    # ── create ────────────────────────────────────────────────────────────────

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
        in_subscriptions: bool = True,
    ) -> Relay:
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
    ) -> RelayUpdateResult:
        """Change any editable field; ``name`` is not one of them.

        Takes effect on the very next rendered link: the bot's snapshot is replaced
        before this returns, the subscription endpoint reads the table per request.
        *note* is left alone unless passed (``None`` clears it).
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
        async with self._lock:
            before = await self._require(relay_id)
            changes = {field: value for field, value in changes.items() if getattr(before, field) != value}
            if "label" in changes:
                taken = await self.relays.get_by_label(str(changes["label"]))
                if taken is not None and taken.id != relay_id:
                    raise InvalidOperation(
                        "label уже занят", key="err_relay_label_taken", params={"value": changes["label"]}
                    )
            if not changes:
                return RelayUpdateResult(before=before, relay=before, changed=())
            try:
                after = await self.relays.update(
                    relay_id, changes, now=self.clock.now(), updated_by=actor_user_id
                )
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
            if "host" in changes and validators.ipv4_address(after.host) and not _covers(after.source_ips, after.host):
                suggest = after.host
            return RelayUpdateResult(
                before=before,
                relay=after,
                changed=tuple(sorted(changes)),
                single_keys_to_reimport=reimport,
                suggest_source_ip=suggest,
            )

    async def add_source_ip(self, actor_user_id: int, relay_id: int, address: str) -> RelayUpdateResult:
        """Append one address to the relay's source IPs (the post-host-change offer)."""
        await self.users.require_superadmin(actor_user_id)
        relay = await self._require(relay_id)
        extra = parse_relay_source_ips(address)
        merged = validators.format_ipv4_networks((*relay.source_ips, *extra))
        return await self.update(actor_user_id, relay_id, source_ips=merged)

    # ── delete ────────────────────────────────────────────────────────────────

    async def delete(self, actor_user_id: int, relay_id: int, *, with_keys: bool) -> RelayDeletionReport:
        """Delete a relay; with *with_keys*, first every key through it.

        Without *with_keys* the relay goes only if no key (outside status
        'deleted') names it — otherwise nothing changes and the report says how
        many keys are in the way. With it, each key is removed through its
        protocol's normal delete path, oldest first; the first failure stops
        everything (the relay stays) and is reported, and a repeated call carries
        on with the keys that are left.
        """
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            relay = await self._require(relay_id)
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
                        )
                    deleted_ids.append(ref.id)
            if not await self.relays.delete_if_unused(relay_id):
                remaining = (await self.relays.usage(relay.name)).keys
                if deleted_ids:
                    await self._audit(
                        actor_user_id,
                        "relay_delete_incomplete",
                        relay_id,
                        {"name": relay.name, "deleted_key_ids": deleted_ids, "remaining_keys": remaining},
                    )
                return RelayDeletionReport(
                    relay=relay, deleted=False, deleted_key_ids=tuple(deleted_ids), remaining_keys=remaining
                )
            await self._audit(
                actor_user_id,
                "relay_deleted",
                relay_id,
                {**_audit_view(relay), "deleted_key_ids": deleted_ids},
            )
            await self.refresh_catalog()
            return RelayDeletionReport(relay=relay, deleted=True, deleted_key_ids=tuple(deleted_ids))

    # ── the one-time seed from the legacy RELAY_* variables ───────────────────

    async def seed_from_settings(self, settings: Settings) -> Relay | None:
        """At bot startup: turn the legacy ``RELAY_*`` relay into the first row, once.

        Seeds only when the table is empty AND ``RELAY_ENABLED=true`` (which
        config.settings already validated together with RELAY_HOST /
        RELAY_SOURCE_IPS). The name is RELAY_NAME (default ``ru1``) — exactly what
        the existing relay keys carry, which is why the "name already used by
        keys" rule does not apply here. In every other case where any RELAY_*
        variable is set, a WARNING says they are ignored from now on.
        """
        seed = settings.relay_seed
        async with self._lock:
            if seed is not None and await self.relays.count() == 0:
                relay = await self.relays.create(
                    name=seed.name,
                    label=validators.DEFAULT_RELAY_LABEL,
                    host=seed.host,
                    source_ips=seed.source_ips,
                    now=self.clock.now(),
                )
                await self._audit(None, "relay_seeded_from_env", relay.id, _audit_view(relay))
                logger.info(
                    "Relay %r (host=%s) перенесён из RELAY_* в .env в таблицу relays; "
                    "дальше он управляется из админки, RELAY_* можно удалить из .env",
                    relay.name,
                    relay.host,
                )
                await self.refresh_catalog()
                return relay
        if settings.relay_env_vars:
            logger.warning(
                "RELAY_* в .env игнорируются: relay управляется из админки (заданы: %s)",
                ", ".join(settings.relay_env_vars),
            )
        return None

    # ── helpers ───────────────────────────────────────────────────────────────

    async def _require(self, relay_id: int) -> Relay:
        relay = await self.relays.get_by_id(relay_id)
        if relay is None:
            raise NotFound("Relay не найден", key="err_relay_not_found")
        return relay

    async def _ensure_name_free(self, name: str) -> None:
        if await self.relays.get_by_name(name) is not None:
            raise InvalidOperation(f"relay {name!r} уже есть", key="err_relay_name_taken", params={"value": name})
        if await self.relays.name_used_by_keys(name):
            raise InvalidOperation(
                f"имя {name!r} уже носят ключи", key="err_relay_name_used_by_keys", params={"value": name}
            )

    async def _audit(
        self, actor_user_id: int | None, action: str, relay_id: int, details: dict[str, object]
    ) -> None:
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=AuditEntityType.RELAY,
            entity_id=relay_id,
            details=details,
        )
