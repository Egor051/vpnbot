"""The bot's DNS: its ONE Cloudflare token and the A records it owns (docs/certificate.md).

THE TOKEN. One per bot, one file: ``/etc/vpn-bot/dns_failover/cloudflare_token``
(adapters.cloudflare_dns.CloudflareTokenFile) — the fallback mode switches its names
with it, this service writes the bot's records with it, and the root helper
vpn-bot-cert hands it to acme.sh for the certificate's DNS-01. It is typed into the
chat only (the message is deleted the moment it is read) and checked against the API
BEFORE it is stored (:meth:`DnsService.check_token`):

  1. ``GET /user/tokens/verify`` — the token is active;
  2. the zone of the name is visible to it (``GET /zones?name=`` walking up);
  3. its A records can be read (DNS · Read);
  4. a TXT record ``_vpn-bot-token-check.<zone>`` is created and deleted at once —
     the only proof of «Zone · DNS · Edit» Cloudflare offers a token without the
     right to read its own permissions (DNS-01 itself creates and deletes TXT records).

A token that fails a step is refused with the step's reason, and nothing is stored.
The audit carries only its fingerprint (8 hex of sha256), never the value.

THE RECORDS. ``dns_records`` (repositories/dns_records.py) is the ONE list of the A
records the bot owns — the fallback hub's origin among them. :meth:`upsert_a` writes
through Cloudflare with ``proxied=false`` and TTL 60, always (a proxied record would
send the VPN into Cloudflare's HTTP proxy), and records the ownership;
:meth:`delete_a` deletes only an owned record, and only one the bot created itself
(an adopted one loses its ownership and stays at Cloudflare). The failover set of the
fallback mode is not ownership (services/fallback.py writes those names through
:meth:`write_a`, the same proxied=false path, without a row here).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from adapters.clock import ClockProvider
from adapters.cloudflare_dns import (
    CloudflareDns,
    CloudflareTokenFile,
    DnsApiError,
    DnsRecord,
    DnsTokenMissing,
    DnsZone,
    fingerprint,
    valid_token,
)
from config import validators
from models.dto import OwnedDnsRecord
from models.enums import AuditEntityType
from repositories.dns_records import PURPOSES, DnsRecordsRepository
from services.audit import AuditService
from services.errors import InvalidOperation, NotFound, ServiceError
from services.relay_pairing import valid_dns_name
from services.users import UserService

logger = logging.getLogger(__name__)

PROBE_LABEL = "_vpn-bot-token-check"
RECORD_TTL = 60


@dataclass(frozen=True, slots=True)
class TokenCheck:
    """A token that passed every step: its status, the zone it manages, its fingerprint."""

    status: str
    zone: DnsZone
    fingerprint: str


@dataclass(frozen=True, slots=True)
class RecordWrite:
    """What :meth:`DnsService.upsert_a` did: created / updated / unchanged."""

    name: str
    content: str
    change: str
    record: OwnedDnsRecord | None = None


class DnsService:
    def __init__(
        self,
        *,
        repo: DnsRecordsRepository,
        users: UserService,
        audit: AuditService,
        clock: ClockProvider,
        token_file: CloudflareTokenFile,
        dns: CloudflareDns,
    ) -> None:
        self.repo = repo
        self.users = users
        self.audit = audit
        self.clock = clock
        self.token_file = token_file
        self.dns = dns
        self._zones: dict[str, DnsZone] = {}
        # Held while the token file changes. The fallback mode uses THIS lock as its own
        # (services/fallback.py): a switch writes names with the token loaded per call, so
        # a new token (or none) must not land in the middle of it — whichever screen it
        # comes from. Never held across an API call of set_token's check.
        self.lock = asyncio.Lock()

    # ── the token ─────────────────────────────────────────────────────────────

    def token_set(self) -> bool:
        return self.token_file.exists()

    def token_fingerprint(self) -> str | None:
        try:
            return fingerprint(self.token_file.load())
        except DnsTokenMissing:
            return None

    async def check_token(self, token: str, name: str) -> TokenCheck:
        """Every step of the module docstring with *token* (not stored): the zone of
        *name* must be visible, readable and writable. Raises InvalidOperation with
        the step that failed."""
        value = (token or "").strip()
        if not valid_token(value):
            raise InvalidOperation("не похоже на токен", key="dns_err_token_format")
        target = (name or "").strip().lower().rstrip(".")
        if not valid_dns_name(target):
            raise InvalidOperation("нет имени для проверки зоны", key="dns_err_bad_name", params={"value": target})
        probe = self.dns.with_token(value)
        try:
            status = await probe.verify_token()
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="dns_err_token_rejected", params={"error": str(exc)}) from None
        if status != "active":
            raise InvalidOperation("токен не активен", key="dns_err_token_inactive", params={"status": status})
        try:
            zone = await probe.find_zone(target)
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="dns_err_token_no_zone", params={"name": target, "error": str(exc)}) from None
        try:
            await probe.records(zone.id, target, "A")
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="dns_err_token_no_read", params={"zone": zone.name, "error": str(exc)}) from None
        probe_name = f"{PROBE_LABEL}.{zone.name}"
        try:
            record = await probe.create_txt(zone.id, probe_name, f"vpn-bot token check {secrets.token_hex(4)}")
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="dns_err_token_no_edit", params={"zone": zone.name, "error": str(exc)}) from None
        try:
            await probe.delete_record(zone.id, record.id)
        except DnsApiError as exc:
            raise InvalidOperation(
                str(exc), key="dns_err_token_no_delete", params={"zone": zone.name, "name": probe_name, "error": str(exc)}
            ) from None
        return TokenCheck(status=status, zone=zone, fingerprint=fingerprint(value))

    async def set_token(
        self,
        actor_user_id: int,
        token: str,
        name: str,
        *,
        audit_action: str = "dns_token_set",
        audit_rejected: str = "dns_token_rejected",
    ) -> TokenCheck:
        """Check *token* against the zone of *name*, then store it (0600). SUPERADMIN only."""
        await self.users.require_superadmin(actor_user_id)
        value = (token or "").strip()
        try:
            check = await self.check_token(value, name)
        except InvalidOperation as exc:
            if valid_token(value):
                await self._audit(actor_user_id, audit_rejected, {"token_fp": fingerprint(value), "reason": exc.key})
            raise
        async with self.lock:
            try:
                self.token_file.save(value)
            except DnsTokenMissing as exc:
                raise ServiceError(str(exc), key="dns_err_token_unwritable", params={"path": str(self.token_file.path)}) from None
            self._zones.clear()
        await self._audit(actor_user_id, audit_action, {"token_fp": check.fingerprint, "zone": check.zone.name})
        return check

    async def delete_token(self, actor_user_id: int, *, audit_action: str = "dns_token_deleted") -> bool:
        await self.users.require_superadmin(actor_user_id)
        async with self.lock:
            removed = self.token_file.delete()
            self._zones.clear()
        if removed:
            await self._audit(actor_user_id, audit_action, {})
        return removed

    async def zone(self, name: str) -> DnsZone:
        """The zone of *name* as the stored token sees it (cached until the token changes)."""
        self._token()
        cached = self._zones.get(name)
        if cached is not None:
            return cached
        try:
            zone = await self.dns.find_zone(name)
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="dns_err_api", params={"error": str(exc)}) from None
        self._zones[name] = zone
        return zone

    def forget_zones(self) -> None:
        self._zones.clear()

    # ── the records ───────────────────────────────────────────────────────────

    async def owned(self) -> list[OwnedDnsRecord]:
        return await self.repo.list_all()

    async def write_a(self, name: str, ipv4: str, *, allowed: set[str] | None = None) -> tuple[DnsRecord, str]:
        """THE write path of every A record the bot touches: the one record of *name*
        holds *ipv4*, proxied=false, TTL 60. Returns (the record, created | updated |
        unchanged). Refused — nothing written — for several A records, or (with
        *allowed*) one that points at an address that is not allowed."""
        target = _name(name)
        address = _ipv4(ipv4)
        zone = await self.zone(target)
        try:
            records = await self.dns.records(zone.id, target, "A")
        except DnsApiError as exc:
            raise InvalidOperation(str(exc), key="dns_err_api", params={"error": str(exc)}) from None
        if len(records) > 1:
            raise InvalidOperation(
                f"{target}: {len(records)} A-записи — оставьте одну", key="dns_err_record_count",
                params={"name": target, "count": len(records)},
            )
        if not records:
            return await _write(lambda: self.dns.create_a(zone.id, target, address)), "created"
        record = records[0]
        if allowed is not None and record.content not in allowed:
            raise InvalidOperation(
                f"{target}: A-запись указывает на {record.content} — не перезаписываю", key="dns_err_record_foreign",
                params={"name": target, "value": record.content},
            )
        if record.content == address and not record.proxied and record.ttl == RECORD_TTL:
            return record, "unchanged"
        return await _write(lambda: self.dns.update_a(zone.id, record.id, address)), "updated"

    async def upsert_a(
        self,
        actor_user_id: int | None,
        name: str,
        ipv4: str,
        *,
        purpose: str,
        allowed: set[str] | None = None,
    ) -> RecordWrite:
        """An A record the bot OWNS: written through :meth:`write_a`, then recorded. A
        record that was there before the bot first wrote it is ``adopted``. A name the
        bot already owns for another purpose is refused (ownership never moves)."""
        if purpose not in PURPOSES:
            raise ValueError(f"unknown purpose {purpose!r}")
        target = _name(name)
        owned = await self.repo.get(target)
        if owned is not None and owned.purpose != purpose:
            raise InvalidOperation(
                "запись принадлежит другому", key="dns_err_record_other_purpose",
                params={"name": target, "purpose": owned.purpose},
            )
        if owned is not None and owned.content and allowed is not None:
            allowed = {*allowed, owned.content}
        try:
            record, change = await self.write_a(target, ipv4, allowed=allowed)
        except InvalidOperation as exc:
            if owned is not None:
                await self.repo.record_error(target, str(exc), now=self.clock.now())
            raise
        zone = await self.zone(target)
        adopted = owned.adopted if owned is not None else change != "created"
        saved = await self.repo.save(
            target, purpose=purpose, content=record.content, zone_id=zone.id, record_id=record.id,
            adopted=adopted, now=self.clock.now(), actor=actor_user_id,
        )
        if change != "unchanged" or owned is None:
            await self._audit(
                actor_user_id, f"dns_record_{change}" if change != "unchanged" else "dns_record_owned",
                {"name": target, "content": record.content, "purpose": purpose, "adopted": adopted, "proxied": False},
            )
        return RecordWrite(name=target, content=record.content, change=change, record=saved)

    async def delete_a(self, actor_user_id: int, name: str) -> bool:
        """Delete an owned record at Cloudflare — only one the bot created; an adopted one
        only loses its ownership. A name the bot does not own is refused. True when
        Cloudflare's record was deleted."""
        await self.users.require_superadmin(actor_user_id)
        target = _name(name)
        owned = await self.repo.get(target)
        if owned is None:
            raise NotFound("запись не принадлежит боту", key="dns_err_record_not_owned", params={"name": target})
        deleted = False
        if not owned.adopted:
            zone = await self.zone(target)
            try:
                records = await self.dns.records(zone.id, target, "A")
                for record in records:
                    if owned.content is None or record.content == owned.content:
                        await self.dns.delete_record(zone.id, record.id)
                        deleted = True
            except DnsApiError as exc:
                await self.repo.record_error(target, str(exc), now=self.clock.now())
                raise InvalidOperation(str(exc), key="dns_err_api", params={"error": str(exc)}) from None
        await self.repo.delete(target)
        await self._audit(actor_user_id, "dns_record_deleted",
                          {"name": target, "purpose": owned.purpose, "at_cloudflare": deleted})
        return deleted

    # ── misc ──────────────────────────────────────────────────────────────────

    def _token(self) -> str:
        try:
            return self.token_file.load()
        except DnsTokenMissing as exc:
            raise InvalidOperation(str(exc), key="dns_err_no_token") from None

    async def _audit(self, actor_user_id: int | None, action: str, details: dict[str, object]) -> None:
        await self.audit.write_best_effort(
            actor_user_id=actor_user_id, action=action, entity_type=AuditEntityType.DNS, entity_id=None, details=details,
        )


def _name(value: str) -> str:
    name = (value or "").strip().lower().rstrip(".")
    if not valid_dns_name(name):
        raise InvalidOperation("не DNS-имя", key="dns_err_bad_name", params={"value": name})
    return name


def _ipv4(value: str) -> str:
    parsed = validators.ipv4_address(value)
    if parsed is None:
        raise InvalidOperation("не IPv4", key="dns_err_bad_ipv4", params={"value": value})
    return str(parsed)


async def _write(call: Callable[[], Awaitable[DnsRecord]]) -> DnsRecord:
    try:
        return await call()
    except DnsApiError as exc:
        raise InvalidOperation(str(exc), key="dns_err_api", params={"error": str(exc)}) from None
