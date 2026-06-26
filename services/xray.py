
import asyncio
import hashlib
import json
import logging
import re
from urllib.parse import quote, urlencode

from adapters.clock import ClockProvider
from adapters.id_generator import IdGenerator
from adapters.xray_config import XrayConfigAdapter
from bot.formatters import create_type_label, key_note_for_viewer, key_type_label, status_text
from config.settings import Settings
from models.dto import TelegramUserProfile, VpnKey, VpnKeyCreateResult
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.notes import normalize_note
from services.user_locks import UserLockManager
from services.users import UserService
from utils.formatting import code, h

logger = logging.getLogger(__name__)

XRAY_ACCESS_MAY_EXIST_STATUSES = {
    VpnKeyStatus.ACTIVE,
    VpnKeyStatus.PENDING_APPLY,
    VpnKeyStatus.APPLY_FAILED,
    VpnKeyStatus.PENDING_REVOKE,
    VpnKeyStatus.PENDING_DELETE,
    VpnKeyStatus.DELETE_FAILED,
}

XRAY_STARTUP_RECONCILE_STATUSES = {
    VpnKeyStatus.PENDING_APPLY,
    VpnKeyStatus.APPLY_FAILED,
    VpnKeyStatus.PENDING_REVOKE,
    VpnKeyStatus.PENDING_DELETE,
    VpnKeyStatus.DELETE_FAILED,
}

XRAY_ACTIVE_STATUSES: set[VpnKeyStatus] = {VpnKeyStatus.ACTIVE}
XRAY_ALL_STATUSES: set[VpnKeyStatus] = set(VpnKeyStatus)
# Recognises bot-managed email labels — both the legacy scheme (``xray_<rnd>``)
# and the transport/profile scheme (``xray_tcp_<rnd>`` /
# ``xray_http_{base,antisib,multi}_<rnd>``). Used by startup orphan cleanup to
# tell "a client we issued" from an ambiguous hand-added one, so it must keep
# matching every scheme the bot has ever written.
XRAY_MANAGED_LABEL_RE = re.compile(
    r"^xray_(?:tcp_|http_(?:base|antisib|multi)_)?[A-Za-z0-9]{5}$"
)

# XHTTP client transport profiles. All three are clients on the SAME server
# inbound (:8001, mode auto); they differ ONLY in the client-side xhttpSettings
# (mode + optional ``extra`` tuning) carried in the VLESS (HTTP) link. ``extra``
# is emitted as a single percent-encoded JSON value (``extra=``), which
# v2rayN/v2rayNG/Nekobox/Happ decode back into xhttpSettings. Ranges are
# preferred (anti-cadence); single ints (e.g. cMaxLifetimeMs: 45000,
# cMaxReuseTimes: 96) are the documented fallback if a client/Xray version
# rejects a range. No profile may carry ``maxConcurrency`` — it is mutually
# exclusive with maxConnections and makes Xray refuse to start.
XHTTP_PROFILES: tuple[str, ...] = ("base", "antisib", "multi")
XHTTP_DEFAULT_PROFILE = "base"
# Per-profile client ``mode``. None => use settings.xray_xhttp_mode, keeping the
# ``base`` link byte-for-byte identical to the pre-profile output.
_XHTTP_PROFILE_MODE: dict[str, str | None] = {
    "base": None,
    "antisib": "stream-one",
    "multi": "packet-up",
}
# Per-profile ``extra`` block. None => no ``extra=`` in the link.
_XHTTP_PROFILE_EXTRA: dict[str, dict[str, object] | None] = {
    "base": None,
    "antisib": {
        "xmux": {"maxConnections": 1, "cMaxReuseTimes": "64-128", "cMaxLifetimeMs": 0},
    },
    "multi": {
        "scMaxEachPostBytes": "800000-1200000",
        "scMinPostsIntervalMs": "30-50",
        "xmux": {"maxConnections": 2, "cMaxReuseTimes": "8-16", "cMaxLifetimeMs": "30000-60000"},
    },
}


class XrayService:
    def __init__(
        self,
        *,
        vpn_keys: VpnKeyRepository,
        users: UserService,
        adapter: XrayConfigAdapter,
        settings: Settings,
        clock: ClockProvider,
        ids: IdGenerator,
        audit: AuditService,
        user_locks: UserLockManager | None = None,
        backend_health: BackendHealth | None = None,
        xhttp_adapter: XrayConfigAdapter | None = None,
    ) -> None:
        self.vpn_keys = vpn_keys
        self.users = users
        # `adapter` is the primary VLESS (TCP) inbound (vless-in). The optional
        # xhttp_adapter targets the separate VLESS (HTTP) inbound. Both wrap the
        # same config.json and share one ConfigFileLock (keyed by config_path), so
        # they mutate only their own inbound by tag and reload only their own tag.
        self.adapter = adapter
        self.xhttp_adapter = xhttp_adapter
        self._adapters: dict[str, XrayConfigAdapter] = {"tcp": adapter}
        if xhttp_adapter is not None:
            self._adapters["http"] = xhttp_adapter
        self.settings = settings
        self.clock = clock
        self.ids = ids
        self.audit = audit
        self.user_locks: UserLockManager = user_locks if user_locks is not None else getattr(users, "user_locks", UserLockManager())
        self.backend_health = backend_health or BackendHealth()
        self._lock = asyncio.Lock()

    @staticmethod
    def _normalize_transport(value: object) -> str:
        """Map any stored/requested transport to the canonical 'tcp' or 'http'."""
        return "http" if str(value or "").strip().lower() == "http" else "tcp"

    def _key_transport(self, key: VpnKey) -> str:
        """Resolve a key's transport from the DB column, falling back to payload."""
        return self._normalize_transport(getattr(key, "transport", None) or key.payload.get("transport"))

    @staticmethod
    def _normalize_profile(value: object) -> str:
        """Map any stored/requested XHTTP profile to a known one (default base)."""
        profile = str(value or "").strip().lower()
        return profile if profile in XHTTP_PROFILES else XHTTP_DEFAULT_PROFILE

    def _email_prefix(self, transport: str, profile: str) -> str:
        """Email prefix encoding transport+profile: the naming scheme's source of truth."""
        if self._normalize_transport(transport) == "http":
            return f"xray_http_{self._normalize_profile(profile)}"
        return "xray_tcp"

    def _key_profile(self, key: VpnKey) -> str:
        """Resolve a key's XHTTP profile from the column, payload, then email prefix."""
        raw = getattr(key, "xhttp_profile", None) or key.payload.get("xhttp_profile")
        if raw:
            return self._normalize_profile(raw)
        label = str(getattr(key, "email_label", None) or key.payload.get("email_label") or "")
        for profile in XHTTP_PROFILES:
            if label.startswith(f"xray_http_{profile}_"):
                return profile
        return XHTTP_DEFAULT_PROFILE

    def _flow_for_transport(self, transport: str) -> str:
        """XHTTP clients must never carry a flow; TCP keeps xtls-rprx-vision."""
        return "" if self._normalize_transport(transport) == "http" else self.settings.xray_flow

    def _adapter_optional(self, transport: str) -> XrayConfigAdapter | None:
        return self._adapters.get(self._normalize_transport(transport))

    def _adapter_for(self, transport: str) -> XrayConfigAdapter:
        """Return the adapter for *transport* or raise a clear, user-facing error."""
        adapter = self._adapter_optional(transport)
        if adapter is None:
            raise InvalidOperation("Транспорт VLESS (HTTP) недоступен: XHTTP-inbound не настроен")
        return adapter

    def _iter_adapters(self) -> list[tuple[str, XrayConfigAdapter]]:
        return list(self._adapters.items())

    async def create_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        """Create a new Xray key for the owner."""
        return await self.create_xray_key(actor_user_id, owner, note)

    async def create_xray_key(
        self,
        actor_user_id: int,
        owner: TelegramUserProfile,
        note: str | None,
        expires_at: str | None = None,
        allow_pending_owner: bool = False,
        fingerprint: str | None = None,
        transport: str = "tcp",
        xhttp_profile: str = XHTTP_DEFAULT_PROFILE,
    ) -> VpnKeyCreateResult:
        """Provision a new Xray client, persist the key, and return its config."""
        self.backend_health.require_mutation_allowed(VpnKeyType.XRAY)
        self.settings.validate_xray_ready()
        transport = self._normalize_transport(transport)
        # Profile is meaningful only for http; tcp keys are always "base". The
        # profile is immutable for a key (changing it means creating a new key),
        # and is encoded into both the email label and the xhttp_profile column.
        profile = self._normalize_profile(xhttp_profile) if transport == "http" else XHTTP_DEFAULT_PROFILE
        # Gate the issuance of NEW http keys on the feature flag, before any DB
        # write or partial apply. Management of already-issued http keys
        # (revoke/delete/reconcile) is intentionally NOT gated by the flag — it
        # depends only on the inbound's adapter being present (see app.py).
        if transport == "http" and not self.settings.xray_xhttp_enabled:
            raise InvalidOperation("VLESS (HTTP) сейчас отключён")
        # Fail closed with a clear message if VLESS (HTTP) was requested but the
        # XHTTP inbound is not configured — no DB row, no partial apply. Create
        # stays strict.
        adapter = self._adapter_for(transport)
        flow = self._flow_for_transport(transport)
        clean_note = normalize_note(note)

        async with self.user_locks.lock(owner.telegram_user_id):
            await self._ensure_can_create(actor_user_id, owner.telegram_user_id, allow_pending_owner=allow_pending_owner)
            async with self._lock:
                await self._ensure_can_create(actor_user_id, owner.telegram_user_id, allow_pending_owner=allow_pending_owner)
                uuid_value, email_label = await self._unique_identity(self._email_prefix(transport, profile))
                # http keys ride vless-in's REALITY via the XHTTP fallback dest,
                # which has no realitySettings of its own: never manage shortIds on
                # it. The link's sid is vless-in's configured shortId (the same one
                # the TCP link uses), read from settings.
                short_id_managed = self.settings.xray_manage_short_ids and transport != "http"
                short_id = self.ids.xray_short_id() if short_id_managed else self.settings.xray_short_id
                link = self._build_vless_link(
                    uuid_value, short_id, email_label, fingerprint=fingerprint, transport=transport, profile=profile
                )
                payload = {
                    "uuid": uuid_value,
                    "email_label": email_label,
                    "short_id": short_id,
                    "short_id_managed": short_id_managed,
                    "flow": flow,
                    "fingerprint": fingerprint,
                    "transport": transport,
                    "xhttp_profile": profile,
                }
                public_payload = {
                    "email_label": email_label,
                    "short_id": short_id,
                    "display_name": f"{create_type_label(VpnKeyType.XRAY.value, transport, profile)} #{email_label}",
                    "link": link,
                }
                key = await self.vpn_keys.create_pending(
                    owner_user_id=owner.telegram_user_id,
                    username=owner.username,
                    key_type=VpnKeyType.XRAY,
                    note=clean_note,
                    payload=payload,
                    public_payload=public_payload,
                    created_by=actor_user_id,
                    now=self.clock.now(),
                    uuid=uuid_value,
                    email_label=email_label,
                    expires_at=expires_at,
                    transport=transport,
                    xhttp_profile=profile,
                )
                xray_apply_result = None
                try:
                    await self._ensure_can_create(actor_user_id, owner.telegram_user_id, allow_pending_owner=allow_pending_owner)
                    xray_apply_result = await adapter.add_client(
                        uuid_value=uuid_value,
                        email_label=email_label,
                        short_id=short_id,
                        flow=flow,
                        manage_short_id=short_id_managed,
                    )
                except Exception as exc:
                    await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
                    await self._write_audit_best_effort(
                        actor_user_id=actor_user_id,
                        action="xray_create_failed",
                        entity_type=AuditEntityType.VPN_KEY,
                        entity_id=key.id,
                        details={"owner_user_id": owner.telegram_user_id, "error": str(exc)},
                    )
                    raise

                try:
                    await self.vpn_keys.mark_active(key.id, self.clock.now(), payload=payload, public_payload=public_payload)
                except Exception as exc:
                    await self._compensate_failed_create_after_apply(
                        actor_user_id=actor_user_id,
                        key_id=key.id,
                        owner_user_id=owner.telegram_user_id,
                        uuid_value=uuid_value,
                        email_label=email_label,
                        short_id=short_id,
                        short_id_managed=short_id_managed,
                        short_id_inserted=self._short_id_inserted_from_apply_result(xray_apply_result),
                        original_error=exc,
                        transport=transport,
                    )
                    raise
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="xray_key_created",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={
                        "owner_user_id": owner.telegram_user_id,
                        "owner_username": owner.username,
                        "label": email_label,
                        "expires_at": expires_at,
                    },
                )
                active_key = await self._get_key(key.id)
                return VpnKeyCreateResult(key=active_key, config_text=self._format_config(active_key, viewer_user_id=actor_user_id))

    async def revoke_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        """Revoke an Xray key."""
        return await self.revoke_xray_key(actor_user_id, key_id)

    async def revoke_xray_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        """Revoke an Xray key and remove its client from the running config."""
        self.backend_health.require_mutation_allowed(VpnKeyType.XRAY)
        async with self._lock:
            key = await self._get_xray_key_for_manage(actor_user_id, key_id)
            if key.status == VpnKeyStatus.REVOKED:
                return key
            if key.status == VpnKeyStatus.DELETED:
                return key
            if key.status not in XRAY_ACCESS_MAY_EXIST_STATUSES:
                raise InvalidOperation("Отозвать можно только активный Xray-ключ")
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_REVOKE, self.clock.now())
            try:
                await self._remove_xray_access(key)
            except Exception:
                await self.vpn_keys.set_status(key_id, previous_status, self.clock.now())
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="xray_revoke_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={},
                )
                raise
            await self.vpn_keys.mark_revoked(key_id, actor_user_id, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="xray_key_revoked",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={},
            )
            return await self._get_key(key_id)

    async def revoke_xray_key_system(
        self,
        key_id: int,
        *,
        actor_user_id: int | None = None,
        action: str = "xray_key_expired",
    ) -> VpnKey:
        """Revoke without an interactive role check — for trusted callers.

        Used by the expiry job, anomaly auto-revoke and the block-user flow, all
        of which authorise the operation themselves. When *actor_user_id* is given
        it is recorded as the revoker and used for audit attribution; otherwise
        the key's creator is recorded (system-initiated expiry).
        """
        self.backend_health.require_mutation_allowed(VpnKeyType.XRAY)
        async with self._lock:
            key = await self._get_key(key_id)
            if key.key_type != VpnKeyType.XRAY:
                raise InvalidOperation("Это не Xray-ключ")
            if key.status in {VpnKeyStatus.REVOKED, VpnKeyStatus.DELETED}:
                return key
            if key.status not in XRAY_ACCESS_MAY_EXIST_STATUSES:
                raise InvalidOperation("Отозвать можно только активный Xray-ключ")
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_REVOKE, self.clock.now())
            try:
                await self._remove_xray_access(key)
            except Exception:
                await self.vpn_keys.set_status(key_id, previous_status, self.clock.now())
                raise
            revoked_by = actor_user_id if actor_user_id is not None else key.created_by
            await self.vpn_keys.mark_revoked(key_id, revoked_by, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"owner_user_id": key.owner_user_id, "expires_at": key.expires_at},
            )
            return await self._get_key(key_id)

    async def delete_key(self, actor_user_id: int, key_id: int) -> None:
        """Delete an Xray key."""
        await self.delete_xray_key(actor_user_id, key_id)

    async def delete_xray_key(self, actor_user_id: int, key_id: int) -> None:
        """Remove the Xray client and hard-delete the key record."""
        self.backend_health.require_mutation_allowed(VpnKeyType.XRAY)
        async with self._lock:
            key = await self._get_xray_key_for_manage(actor_user_id, key_id)
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_DELETE, self.clock.now())
            try:
                if previous_status in XRAY_ACCESS_MAY_EXIST_STATUSES:
                    await self._remove_xray_access(key)
            except Exception as exc:
                await self.vpn_keys.set_status(key_id, VpnKeyStatus.DELETE_FAILED, self.clock.now())
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="xray_delete_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={"previous_status": previous_status.value, "error": str(exc)},
                )
                raise
            await self.vpn_keys.hard_delete_with_stats(key_id, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="xray_key_hard_deleted",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"owner_user_id": key.owner_user_id, "previous_status": previous_status.value},
            )

    async def startup_reconcile(self) -> dict[str, int]:
        """Reconcile pending/failed Xray keys against the live config on startup."""
        summary = {"checked": 0, "recovered": 0, "failed": 0}
        async with self._lock:
            last_id = 0
            while True:
                keys = await self.vpn_keys.list_by_type_statuses(
                    VpnKeyType.XRAY,
                    XRAY_STARTUP_RECONCILE_STATUSES,
                    limit=500,
                    after_id=last_id,
                )
                if not keys:
                    break
                for key in keys:
                    last_id = key.id
                    summary["checked"] += 1
                    try:
                        changed = await self._startup_reconcile_key(key)
                        if changed:
                            summary["recovered"] += 1
                    except Exception as exc:
                        summary["failed"] += 1
                        logger.warning("Не удалось восстановить Xray-ключ key_id=%s: %s", key.id, exc, exc_info=True)
                        await self._write_startup_reconcile_failure_audit(key, exc)

            if summary["failed"] == 0:
                drift_summary = await self._startup_reconcile_drift()
                for drift_key, drift_val in drift_summary.items():
                    summary[drift_key] += drift_val
        # Read-only diagnostic, run after reconcile so it observes the settled
        # state (and never the lock).
        await self._warn_if_unmanaged_http_keys()
        return summary

    async def reconcile_email_labels(self) -> dict[str, int]:
        """Sync live Xray client emails to the DB labels (post-v28 rename, by UUID).

        After the v28 relabel the DB carries the new transport/profile email
        labels, but the running config still holds the old client ``email``
        values. This renames each live client — matched by its immutable UUID —
        to the DB's current email_label, one inbound at a time, through the
        standard apply path (backup + ``xray -test`` + helper/restart). It is
        idempotent: once every client already matches it writes nothing and
        restarts nothing, so it is safe to run on every startup. Renaming resets
        Xray's per-email stats (accepted trade-off).
        """
        summary = {"checked": 0, "renamed": 0, "failed": 0}
        async with self._lock:
            # uuid -> desired email, partitioned by transport (one key = one inbound).
            renames: dict[str, dict[str, str]] = {transport: {} for transport, _ in self._iter_adapters()}
            last_id = 0
            while True:
                keys = await self.vpn_keys.list_by_type_statuses(
                    VpnKeyType.XRAY,
                    XRAY_ACCESS_MAY_EXIST_STATUSES,
                    limit=500,
                    after_id=last_id,
                )
                if not keys:
                    break
                for key in keys:
                    last_id = key.id
                    uuid_value = str(key.uuid or key.payload.get("uuid") or "").strip()
                    email_label = str(key.email_label or key.payload.get("email_label") or "").strip()
                    transport = self._key_transport(key)
                    if uuid_value and email_label and transport in renames:
                        renames[transport][uuid_value] = email_label
            for transport, adapter in self._iter_adapters():
                mapping = renames.get(transport) or {}
                summary["checked"] += len(mapping)
                if not mapping:
                    continue
                try:
                    summary["renamed"] += await adapter.rename_clients(mapping)
                except Exception as exc:
                    summary["failed"] += 1
                    logger.warning(
                        "Не удалось синхронизировать email-лейблы Xray (%s): %s", transport, exc, exc_info=True
                    )
        return summary

    async def get_config(self, actor_user_id: int, key_id: int) -> str:
        """Return the connection config text for an Xray key."""
        return await self.get_xray_key_config(actor_user_id, key_id)

    async def get_xray_key_config(self, actor_user_id: int, key_id: int) -> str:
        """Return the connection config for an active Xray key the actor manages."""
        async with self._lock:  # Prevents returning config for a key being concurrently deleted
            key = await self._get_xray_key_for_manage(actor_user_id, key_id, allow_read=True)
            if key.status != VpnKeyStatus.ACTIVE:
                raise InvalidOperation("Конфигурация доступна только для активного ключа")
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="xray_config_shown",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={},
            )
            return self._format_config(key, viewer_user_id=actor_user_id)

    async def get_xray_key_config_for_owner(self, owner_user_id: int, key_id: int) -> str:
        """Return the connection config for an active Xray key owned by the user."""
        async with self._lock:  # Prevents returning config for a key being concurrently deleted
            key = await self._get_key(key_id)
            if key.key_type != VpnKeyType.XRAY:
                raise InvalidOperation("Это не Xray-ключ")
            if key.owner_user_id != owner_user_id:
                raise AccessDenied("Нельзя смотреть чужой ключ")
            if key.status != VpnKeyStatus.ACTIVE:
                raise InvalidOperation("Конфигурация доступна только для активного ключа")
            return self._format_config(key, viewer_user_id=owner_user_id)

    async def change_fingerprint(self, actor_user_id: int, key_id: int, fingerprint: str) -> VpnKey:
        """Update the per-key fingerprint and rebuild the stored VLESS link."""
        from bot.keyboards.keys import VALID_FINGERPRINTS
        if fingerprint not in VALID_FINGERPRINTS:
            raise InvalidOperation("Неподдерживаемый fingerprint")
        # Serialise against concurrent revoke/delete so the status check and the
        # payload write cannot straddle a state change for the same key.
        async with self._lock:
            key = await self._get_xray_key_for_manage(actor_user_id, key_id)
            if key.status != VpnKeyStatus.ACTIVE:
                raise InvalidOperation("Fingerprint можно изменить только у активного ключа")
            new_payload = {**key.payload, "fingerprint": fingerprint}
            uuid_value = str(new_payload.get("uuid") or key.uuid or "")
            short_id = str(new_payload.get("short_id") or key.public_payload.get("short_id") or "")
            email_label = str(new_payload.get("email_label") or key.email_label or "")
            link = self._build_vless_link(
                uuid_value, short_id, email_label,
                fingerprint=fingerprint, transport=self._key_transport(key), profile=self._key_profile(key),
            )
            new_public_payload = {**key.public_payload, "link": link}
            await self.vpn_keys.update_payload(key_id, new_payload, new_public_payload, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="xray_fingerprint_changed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"fingerprint": fingerprint},
            )
            return await self._get_key(key_id)

    async def list_user_keys(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        """Return the Xray keys an actor may view for a given owner."""
        return await self.list_user_xray_keys(actor_user_id, owner_user_id, limit=limit, offset=offset)

    async def list_user_xray_keys(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        """Return the Xray keys an actor is allowed to view for a given owner."""
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи")
        return await self.vpn_keys.list_by_owner_and_type(target, VpnKeyType.XRAY, limit=limit, offset=offset)

    async def update_xray_note(self, actor_user_id: int, key_id: int, note: str | None) -> VpnKey:
        """Update the note on an Xray key owned by the actor."""
        async with self._lock:  # Prevents note update racing with concurrent key deletion
            key = await self._get_xray_key_for_manage(actor_user_id, key_id, allow_read=True)
            if key.owner_user_id != actor_user_id:
                raise AccessDenied("Можно менять заметку только своих ключей")
            clean_note = normalize_note(note)
            await self.vpn_keys.update_note(key.id, clean_note, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="xray_note_updated",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={},
            )
            return await self._get_key(key_id)

    async def reconcile_key_status(self, actor_user_id: int, key_id: int) -> VpnKey:
        """Reconcile a single Xray key's status against the live config."""
        await self.users.require_superadmin(actor_user_id)
        self.backend_health.require_mutation_allowed(VpnKeyType.XRAY)
        # Serialise against concurrent create/revoke/delete for this backend.
        async with self._lock:
            key = await self._get_key(key_id)
            if key.key_type != VpnKeyType.XRAY:
                raise InvalidOperation("Это не Xray-ключ")
            # Tolerant of a missing adapter (optional XHTTP inbound not configured):
            # treat an absent inbound as "client not found" instead of raising, so a
            # manual reconcile never hard-fails on a transport whose inbound is gone.
            transport = self._key_transport(key)
            adapter = self._adapter_optional(transport)
            if adapter is None:
                logger.warning(
                    "Xray reconcile skipped server-side for key_id=%s: transport %s inbound not configured",
                    key.id,
                    transport,
                )
            client = adapter.find_client(uuid_value=key.uuid, email_label=key.email_label) if adapter is not None else None
            if client is not None and key.status in {VpnKeyStatus.PENDING_APPLY, VpnKeyStatus.APPLY_FAILED}:
                await self.vpn_keys.mark_active(key.id, self.clock.now())
            elif client is None and key.status == VpnKeyStatus.PENDING_APPLY:
                await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="xray_key_reconciled",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"client_present": client is not None},
            )
            return await self._get_key(key_id)

    async def _ensure_can_create(
        self, actor_user_id: int, owner_user_id: int, *, allow_pending_owner: bool = False
    ) -> None:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        if actor.role != UserRole.SUPERADMIN and actor_user_id != owner_user_id:
            raise AccessDenied("Нельзя создавать ключи для другого пользователя")
        if allow_pending_owner:
            if actor.role != UserRole.SUPERADMIN:
                raise AccessDenied("Только администратор может выдавать ключи гостям")
            owner = await self.users.get_user(owner_user_id)
            from models.access import is_blocked_user
            if is_blocked_user(owner):
                raise AccessDenied("Нельзя выдать ключ заблокированному пользователю")
        else:
            owner = await self.users.require_approved_or_admin(owner_user_id)
            if owner.role not in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
                raise AccessDenied("Владелец ключа не имеет доступа")

    async def _get_xray_key_for_manage(self, actor_user_id: int, key_id: int, allow_read: bool = False) -> VpnKey:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.XRAY:
            raise InvalidOperation("Это не Xray-ключ")
        if actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
            raise AccessDenied("Нельзя управлять чужим ключом")
        return key

    async def _get_key(self, key_id: int) -> VpnKey:
        key = await self.vpn_keys.get_by_id(key_id)
        if key is None:
            raise NotFound("Ключ не найден")
        return key

    async def _can_remove_short_id(self, key: VpnKey) -> bool:
        short_id = str(key.payload.get("short_id") or "")
        if not short_id or key.payload.get("short_id_managed") is not True:
            return False
        in_use = await self.vpn_keys.count_active_managed_short_id(short_id, exclude_key_id=key.id)
        return in_use == 0

    async def _remove_xray_access(self, key: VpnKey) -> None:
        transport = self._key_transport(key)
        adapter = self._adapter_optional(transport)
        if adapter is None:
            # The key's transport has no managed inbound (e.g. the optional XHTTP
            # inbound was removed from config.json): there is no live client to
            # remove, so removal is a no-op and revoke/delete can still clear the
            # DB row. Never block revocation on a missing optional inbound.
            logger.warning(
                "Xray client removal skipped for key_id=%s: transport %s inbound not configured; "
                "completing the operation on the DB side only",
                key.id,
                transport,
            )
            return
        await adapter.remove_client(
            uuid_value=key.uuid,
            email_label=key.email_label,
            short_id=str(key.payload.get("short_id") or ""),
            remove_short_id=await self._can_remove_short_id(key),
        )

    async def _compensate_failed_create_after_apply(
        self,
        *,
        actor_user_id: int,
        key_id: int,
        owner_user_id: int,
        uuid_value: str,
        email_label: str,
        short_id: str,
        short_id_managed: bool,
        short_id_inserted: bool,
        original_error: Exception,
        transport: str = "tcp",
    ) -> None:
        logger.critical(
            "Xray client applied, but DB mark_active failed for key_id=%s; attempting compensation",
            key_id,
            exc_info=True,
        )
        adapter = self._adapter_optional(transport)
        if adapter is None:
            logger.warning(
                "Xray create compensation skipped server-side for key_id=%s: transport %s inbound not configured",
                key_id,
                transport,
            )
        try:
            # The adapter is resolved optionally so compensation never hard-fails
            # with a fail-closed "inbound not configured" error. In practice the
            # adapter is always present here (create obtained it before add_client
            # succeeded); a None adapter means its inbound vanished, leaving
            # nothing to compensate, so we fall through to mark the key apply_failed.
            if adapter is not None:
                await adapter.remove_client(
                    uuid_value=uuid_value,
                    email_label=email_label,
                    short_id=short_id,
                    remove_short_id=short_id_managed and short_id_inserted,
                )
        except Exception as compensation_error:
            self.backend_health.mark_degraded(VpnKeyType.XRAY, "post-apply mark_active failed and compensation failed")
            logger.critical(
                "Xray create compensation failed after DB mark_active failure for key_id=%s",
                key_id,
                exc_info=True,
            )
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="xray_create_compensation_failed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={
                    "owner_user_id": owner_user_id,
                    "original_error_type": type(original_error).__name__,
                    "compensation_error_type": type(compensation_error).__name__,
                    "backend_degraded": True,
                },
            )
            return

        try:
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
        except Exception:
            logger.warning("Xray create compensation succeeded, but failed to mark key apply_failed key_id=%s", key_id, exc_info=True)
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="xray_create_compensated_after_db_failure",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"owner_user_id": owner_user_id, "original_error_type": type(original_error).__name__},
        )

    def _short_id_inserted_from_apply_result(self, result: object) -> bool:
        if isinstance(result, dict):
            return bool(result.get("short_id_inserted"))
        return bool(getattr(result, "short_id_inserted", False))

    async def _startup_reconcile_drift(self) -> dict[str, int]:
        summary = {"checked": 0, "recovered": 0, "failed": 0}
        if not self._xray_drift_reconcile_supported():
            return summary
        try:
            active_keys = await self._list_xray_keys_by_statuses(XRAY_ACTIVE_STATUSES)
            all_keys = await self._list_xray_keys_by_statuses(XRAY_ALL_STATUSES)
            summary["checked"] = len(active_keys)
            summary["recovered"] += await self._remove_non_live_xray_clients(all_keys)

            # Scan each managed inbound independently: an orphan in vless-in must be
            # removed from vless-in, and one in vless-xhttp-reality from that inbound.
            for _transport, adapter in self._iter_adapters():
                clients = adapter.list_clients()
                summary["checked"] += len(clients)
                orphan_result = await self._remove_or_degrade_xray_orphans(clients, active_keys, adapter)
                summary["recovered"] += orphan_result["recovered"]
                summary["failed"] += orphan_result["failed"]
                if orphan_result["failed"]:
                    return summary

            summary["recovered"] += await self._restore_missing_active_xray_clients(active_keys)
        except Exception as exc:
            summary["failed"] += 1
            await self._mark_xray_degraded(
                "startup drift reconciliation failed",
                details={"error_type": type(exc).__name__},
            )
        return summary

    def _xray_drift_reconcile_supported(self) -> bool:
        required_adapter = ("list_clients", "find_client", "add_client", "remove_client")
        required_repo = ("list_by_type_statuses", "find_by_uuid", "find_by_email_label")
        return all(hasattr(self.adapter, name) for name in required_adapter) and all(
            hasattr(self.vpn_keys, name) for name in required_repo
        )

    async def _list_xray_keys_by_statuses(self, statuses: set[VpnKeyStatus]) -> list[VpnKey]:
        keys: list[VpnKey] = []
        last_id = 0
        while True:
            batch = await self.vpn_keys.list_by_type_statuses(
                VpnKeyType.XRAY,
                statuses,
                limit=500,
                after_id=last_id,
            )
            if not batch:
                break
            keys.extend(batch)
            last_id = batch[-1].id
        return keys

    async def _warn_if_unmanaged_http_keys(self) -> None:
        """Flag at startup any VLESS (HTTP) keys the bot can no longer manage.

        If http keys exist in the DB while the XHTTP inbound (and thus its
        adapter) is absent, the bot cannot revoke/delete them server-side. Log
        loudly so the operator restores the inbound; never abort startup. With no
        such keys this is a silent no-op, preserving pre-feature behaviour.
        """
        if self._adapter_optional("http") is not None:
            return
        unmanaged = 0
        last_id = 0
        while True:
            batch = await self.vpn_keys.list_by_type_statuses(
                VpnKeyType.XRAY,
                XRAY_ACCESS_MAY_EXIST_STATUSES,
                limit=500,
                after_id=last_id,
            )
            if not batch:
                break
            unmanaged += sum(1 for key in batch if self._key_transport(key) == "http")
            new_last = batch[-1].id
            if new_last <= last_id:  # repo not advancing on after_id -> stop, never spin
                break
            last_id = new_last
        if unmanaged:
            logger.critical(
                "%d VLESS (HTTP) key(s) exist in the DB but the XHTTP inbound (tag=%r) is not "
                "configured; the bot cannot manage them server-side (revoke/delete) until the "
                "inbound is restored in config.json",
                unmanaged,
                self.settings.xray_xhttp_inbound_tag,
            )

    async def _restore_missing_active_xray_clients(self, active_keys: list[VpnKey]) -> int:
        recovered = 0
        short_ids_by_transport: dict[str, set[str]] = {}

        def _short_ids(transport: str, adapter: XrayConfigAdapter) -> set[str]:
            reader = getattr(adapter, "list_short_ids", None)
            if reader is None:
                return set()
            value: set[str] = reader()
            short_ids_by_transport[transport] = value
            return value

        for key in active_keys:
            uuid_value, email_label, short_id, flow, short_id_managed, transport = self._xray_restore_values(key)
            adapter = self._adapter_optional(transport)
            if adapter is None:
                logger.warning(
                    "Xray startup restore skipped for key_id=%s: transport %s adapter unavailable",
                    key.id,
                    transport,
                )
                continue
            short_ids = short_ids_by_transport.get(transport)
            if short_ids is None:
                short_ids = _short_ids(transport, adapter)
            client = adapter.find_client(uuid_value=uuid_value, email_label=email_label)
            if client is None:
                await adapter.add_client(
                    uuid_value=uuid_value,
                    email_label=email_label,
                    short_id=short_id,
                    flow=flow,
                    manage_short_id=short_id_managed,
                )
                recovered += 1
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="xray_startup_active_restored",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={"client_present": False, "short_id_managed": short_id_managed},
                )
                _short_ids(transport, adapter)
                continue

            if short_id_managed and short_id and short_id not in short_ids:
                ensured = await adapter.ensure_short_id(short_id)
                if ensured:
                    recovered += 1
                    _short_ids(transport, adapter)
                    await self._write_audit_best_effort(
                        actor_user_id=None,
                        action="xray_startup_short_id_restored",
                        entity_type=AuditEntityType.VPN_KEY,
                        entity_id=key.id,
                        details={"client_present": True, "short_id_managed": True},
                    )
        return recovered

    async def _remove_non_live_xray_clients(self, keys: list[VpnKey]) -> int:
        recovered = 0
        for key in keys:
            if key.status == VpnKeyStatus.ACTIVE:
                continue
            adapter = self._adapter_optional(self._key_transport(key))
            if adapter is None:
                continue
            client = adapter.find_client(uuid_value=key.uuid, email_label=key.email_label)
            if client is None:
                continue
            await self._remove_xray_access(key)
            recovered += 1
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="xray_startup_non_live_removed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"previous_status": key.status.value},
            )
        return recovered

    async def _remove_or_degrade_xray_orphans(
        self,
        clients: list[dict[str, object]],
        active_keys: list[VpnKey],
        adapter: XrayConfigAdapter,
    ) -> dict[str, int]:
        recovered = 0
        active_identities = self._xray_active_identities(active_keys)
        for client in clients:
            uuid_value = str(client.get("id") or "").strip()
            email_label = str(client.get("email") or "").strip()
            if self._xray_client_owned_by_active_key(uuid_value, email_label, active_identities):
                continue

            historical = await self._find_xray_historical_owner(uuid_value, email_label)
            if historical is not None:
                if historical.status == VpnKeyStatus.ACTIVE:
                    continue
                # Routes by the historical key's saved transport (one key = one
                # inbound), preserving managed short-id removal semantics.
                await self._remove_xray_access(historical)
                recovered += 1
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="xray_startup_orphan_removed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=historical.id,
                    details={"historical_status": historical.status.value},
                )
                continue

            if XRAY_MANAGED_LABEL_RE.fullmatch(email_label):
                await adapter.remove_client(
                    uuid_value=uuid_value or None,
                    email_label=email_label or None,
                    short_id=None,
                    remove_short_id=False,
                )
                recovered += 1
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="xray_startup_orphan_removed",
                    entity_type=AuditEntityType.SYSTEM,
                    entity_id=None,
                    details={"managed_label": True, "uuid_fingerprint": self._fingerprint(uuid_value)},
                )
                continue

            await self._mark_xray_degraded(
                "ambiguous orphan client in Xray config",
                details={
                    "managed_label": False,
                    "uuid_fingerprint": self._fingerprint(uuid_value),
                    "email_present": bool(email_label),
                },
            )
            return {"recovered": recovered, "failed": 1}
        return {"recovered": recovered, "failed": 0}

    def _xray_restore_values(self, key: VpnKey) -> tuple[str, str, str, str, bool, str]:
        uuid_value = str(key.payload.get("uuid") or key.uuid or "").strip()
        email_label = str(key.payload.get("email_label") or key.email_label or "").strip()
        short_id_managed = key.payload.get("short_id_managed") is True
        short_id = str(key.payload.get("short_id") or key.public_payload.get("short_id") or "").strip()
        if not short_id and not short_id_managed:
            short_id = self.settings.xray_short_id
        transport = self._key_transport(key)
        # XHTTP clients never carry a flow; TCP keeps the configured flow.
        flow = "" if transport == "http" else str(key.payload.get("flow") or self.settings.xray_flow or "")
        if not uuid_value or not email_label:
            raise InvalidOperation("Xray active key cannot be restored: missing UUID or email label in DB")
        if not short_id:
            raise InvalidOperation("Xray active key cannot be restored: missing short_id in DB/settings")
        return uuid_value, email_label, short_id, flow, short_id_managed, transport

    def _xray_active_identities(self, active_keys: list[VpnKey]) -> tuple[set[str], set[str]]:
        uuids = {str(key.payload.get("uuid") or key.uuid or "").strip() for key in active_keys}
        emails = {str(key.payload.get("email_label") or key.email_label or "").strip() for key in active_keys}
        return {value for value in uuids if value}, {value for value in emails if value}

    def _xray_client_owned_by_active_key(
        self,
        uuid_value: str,
        email_label: str,
        active_identities: tuple[set[str], set[str]],
    ) -> bool:
        active_uuids, active_emails = active_identities
        return bool((uuid_value and uuid_value in active_uuids) or (email_label and email_label in active_emails))

    async def _find_xray_historical_owner(self, uuid_value: str, email_label: str) -> VpnKey | None:
        key = await self.vpn_keys.find_by_uuid(uuid_value) if uuid_value else None
        if key is None and email_label:
            key = await self.vpn_keys.find_by_email_label(email_label)
        if key is None or key.key_type != VpnKeyType.XRAY:
            return None
        return key

    async def _mark_xray_degraded(self, reason: str, *, details: dict[str, object]) -> None:
        self.backend_health.mark_degraded(VpnKeyType.XRAY, reason)
        logger.critical("Xray backend degraded during reconciliation: %s", reason)
        await self._write_audit_best_effort(
            actor_user_id=None,
            action="xray_startup_drift_degraded",
            entity_type=AuditEntityType.SYSTEM,
            entity_id=None,
            details={**details, "reason": reason, "backend_degraded": True},
        )

    def _fingerprint(self, value: str) -> str | None:
        if not value:
            return None
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

    async def _startup_reconcile_key(self, key: VpnKey) -> bool:
        transport = self._key_transport(key)
        adapter = self._adapter_optional(transport)
        if adapter is None:
            logger.warning(
                "Xray startup reconcile skipped for key_id=%s: transport %s adapter unavailable",
                key.id,
                transport,
            )
            return False
        if key.status in {VpnKeyStatus.PENDING_APPLY, VpnKeyStatus.APPLY_FAILED}:
            client = adapter.find_client(uuid_value=key.uuid, email_label=key.email_label)
            if client is None:
                if key.status == VpnKeyStatus.PENDING_APPLY:
                    await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
                    await self._write_audit_best_effort(
                        actor_user_id=None,
                        action="xray_startup_pending_apply_failed",
                        entity_type=AuditEntityType.VPN_KEY,
                        entity_id=key.id,
                        details={"client_present": False},
                    )
                    return True
                return False
            await self.vpn_keys.mark_active(key.id, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="xray_startup_apply_recovered",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"client_present": True, "previous_status": key.status.value},
            )
            return True

        if key.status == VpnKeyStatus.PENDING_REVOKE:
            await self._remove_xray_access(key)
            await self.vpn_keys.mark_revoked(key.id, key.revoked_by or key.deleted_by or key.created_by, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="xray_startup_revoke_completed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={},
            )
            return True

        if key.status in {VpnKeyStatus.PENDING_DELETE, VpnKeyStatus.DELETE_FAILED}:
            try:
                await self._remove_xray_access(key)
            except Exception:
                await self.vpn_keys.set_status(key.id, VpnKeyStatus.DELETE_FAILED, self.clock.now())
                raise
            await self.vpn_keys.hard_delete_with_stats(key.id, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="xray_startup_delete_completed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"owner_user_id": key.owner_user_id, "previous_status": key.status.value, "hard_delete": True},
            )
            return True

        return False

    async def _write_startup_reconcile_failure_audit(self, key: VpnKey, error: Exception) -> None:
        await self._write_audit_best_effort(
            actor_user_id=None,
            action="xray_startup_reconcile_failed",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key.id,
            details={"status": key.status.value, "error": str(error)},
        )

    async def _write_audit_best_effort(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_type: AuditEntityType,
        entity_id: str | int | None,
        details: dict[str, object] | None = None,
    ) -> None:
        writer = getattr(self.audit, "write_best_effort", None)
        if writer is not None:
            await writer(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
            )
            return
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
            )
        except Exception:
            logger.warning("Audit write failed after Xray operation: action=%s entity_id=%s", action, entity_id, exc_info=True)

    async def _unique_identity(self, prefix: str) -> tuple[str, str]:
        """Generate a (uuid, email_label) pair unique across keys, label prefixed.

        *prefix* encodes transport+profile (e.g. ``xray_tcp`` / ``xray_http_multi``)
        so the email itself carries the key's transport and profile.
        """
        for _ in range(5):
            uuid_value = self.ids.uuid4()
            email_label = self.ids.generated_key_name(prefix)
            by_uuid, by_label = await asyncio.gather(
                self.vpn_keys.find_by_uuid(uuid_value),
                self.vpn_keys.find_by_email_label(email_label),
            )
            if by_uuid is None and by_label is None:
                return uuid_value, email_label
        raise InvalidOperation("Не удалось сгенерировать уникальные Xray-идентификаторы")

    def _build_vless_link(
        self,
        uuid_value: str,
        short_id: str,
        email_label: str,
        fingerprint: str | None = None,
        transport: str = "tcp",
        profile: str = XHTTP_DEFAULT_PROFILE,
    ) -> str:
        host = self._format_host(self.settings.xray_public_host)
        fragment = quote(email_label or "xray")
        if self._normalize_transport(transport) == "http":
            # VLESS (HTTP) is a *hybrid* of the TCP link: it shares vless-in's
            # REALITY (pbk/sni/sid/fp) and rides the same public :443, differing
            # only in transport. In the fallback topology vless-in (:443) accepts
            # REALITY/TLS and forwards by path to the internal vless-xhttp-reality
            # inbound, which carries no REALITY of its own — so every REALITY
            # parameter comes from vless-in / settings, never from that inbound.
            # No flow (XHTTP clients must never carry xtls-rprx-vision).
            #
            # The transport profile (base/antisib/multi) sets the client `mode`
            # and the optional `extra` block. `extra` is carried as a single
            # percent-encoded JSON value via `extra=`; urlencode() encodes the
            # whole JSON string for us, and the compact JSON (no spaces) avoids
            # any `+`/space ambiguity. base emits no `extra` (regression-identical
            # to the pre-profile link).
            norm_profile = self._normalize_profile(profile)
            mode = _XHTTP_PROFILE_MODE.get(norm_profile) or self.settings.xray_xhttp_mode
            params = {
                "type": "xhttp",
                "security": "reality",
                "encryption": "none",
                "pbk": self.settings.xray_reality_public_key,
                "fp": fingerprint or self.settings.xray_fingerprint,
                "sni": self.settings.xray_sni,
                "sid": short_id,
                "path": self.settings.xray_xhttp_path,
                "mode": mode,
            }
            extra = _XHTTP_PROFILE_EXTRA.get(norm_profile)
            if extra is not None:
                params["extra"] = json.dumps(extra, separators=(",", ":"), ensure_ascii=False)
            query = urlencode(params)
            return f"vless://{uuid_value}@{host}:{self.settings.xray_public_port}?{query}#{fragment}"
        params = {
            # Always advertise type=tcp (not raw) for the widest client
            # compatibility; the server accepts both (raw is a synonym of tcp).
            "type": "tcp",
            "security": "reality",
            "encryption": "none",
            "pbk": self.settings.xray_reality_public_key,
            "fp": fingerprint or self.settings.xray_fingerprint,
            "sni": self.settings.xray_sni,
            "sid": short_id,
        }
        if self.settings.xray_flow:
            params["flow"] = self.settings.xray_flow
        query = urlencode(params)
        return f"vless://{uuid_value}@{host}:{self.settings.xray_public_port}?{query}#{fragment}"

    def _format_host(self, host: str) -> str:
        if host.startswith("[") and host.endswith("]"):
            return host
        try:
            import ipaddress

            parsed = ipaddress.ip_address(host)
        except ValueError:
            return host
        if parsed.version == 6:
            return f"[{host}]"
        return host

    def _format_config(self, key: VpnKey, *, viewer_user_id: int | None = None) -> str:
        uuid_value = str(key.payload.get("uuid") or key.uuid or "")
        short_id = str(key.payload.get("short_id") or key.public_payload.get("short_id") or "")
        email_label = str(key.payload.get("email_label") or key.email_label or "")
        fingerprint = str(key.payload.get("fingerprint")) if key.payload.get("fingerprint") else None
        link = self._build_vless_link(
            uuid_value, short_id, email_label,
            fingerprint=fingerprint, transport=self._key_transport(key), profile=self._key_profile(key),
        )
        visible_note = key_note_for_viewer(key, viewer_user_id) if viewer_user_id is not None else None
        note = f"\nЗаметка: {h(visible_note)}" if visible_note else ""
        label = f"\nМетка: {h(email_label)}" if email_label else ""
        return (
            f"<b>{key_type_label(key)} #{key.id}</b>\n"
            f"Статус: {status_text(key.status)}{label}{note}\n\n"
            f"{code(link)}"
        )
