
import asyncio
import hashlib
import logging
import secrets
import sqlite3
from dataclasses import replace

from adapters.clock import ClockProvider
from adapters.mtproxy import MtProxyAdapter, MtProxyManagedSecret, MtProxyRuntimeStatus
from config.settings import Settings
from models.dto import ProxyAccess, TelegramUserProfile
from models.enums import AuditEntityType, ProxyAccessStatus, ProxyAccessType, UserRole
from repositories.proxy_accesses import ProxyAccessRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from utils.redact import redact_value
from services.user_locks import UserLockManager
from services.users import UserService

logger = logging.getLogger(__name__)

MTPROTO_ACCESS_MAY_EXIST_STATUSES = {
    ProxyAccessStatus.ACTIVE,
    ProxyAccessStatus.PENDING_APPLY,
    ProxyAccessStatus.APPLY_FAILED,
    ProxyAccessStatus.PENDING_REVOKE,
    ProxyAccessStatus.REVOKE_FAILED,
    ProxyAccessStatus.PENDING_DELETE,
    ProxyAccessStatus.DELETE_FAILED,
}

MTPROTO_STARTUP_RECONCILE_STATUSES = {
    ProxyAccessStatus.PENDING_APPLY,
    ProxyAccessStatus.APPLY_FAILED,
    ProxyAccessStatus.PENDING_REVOKE,
    ProxyAccessStatus.REVOKE_FAILED,
    ProxyAccessStatus.PENDING_DELETE,
    ProxyAccessStatus.DELETE_FAILED,
}


def mtproto_secret_fingerprint(secret: str) -> str:
    """Return a short stable fingerprint for an MTProto secret."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


class MtProtoService:
    def __init__(
        self,
        *,
        accesses: ProxyAccessRepository,
        users: UserService,
        settings: Settings,
        clock: ClockProvider,
        audit: AuditService,
        adapter: MtProxyAdapter | None = None,
        user_locks: UserLockManager | None = None,
        backend_health: BackendHealth | None = None,
    ) -> None:
        self.accesses = accesses
        self.users = users
        self.settings = settings
        self.clock = clock
        self.audit = audit
        self.adapter = adapter
        self.user_locks: UserLockManager = user_locks if user_locks is not None else getattr(users, "user_locks", UserLockManager())
        self.backend_health = backend_health or BackendHealth()
        self._apply_lock = asyncio.Lock()

    async def issue_mtproto_proxy(self, actor_user_id: int, profile: TelegramUserProfile) -> ProxyAccess:
        """Issue or return an MTProto proxy access for the user in the configured mode."""
        self._ensure_enabled()
        self.backend_health.require_mutation_allowed(ProxyAccessType.MTPROTO)
        if self.settings.mtproto_mode == "managed":
            return await self._issue_managed(actor_user_id, profile)
        return await self._issue_static(actor_user_id, profile)

    async def get_mtproto_proxy_config(self, actor_user_id: int) -> ProxyAccess:
        """Return the user's active MTProto proxy access with current connection details."""
        await self.users.require_approved_or_admin(actor_user_id)
        access = await self._active_access(actor_user_id)
        if access is None:
            raise NotFound("MTProto-доступ не найден")
        active = self._with_current_payload(access)
        await self._mark_shown(active, actor_user_id)
        return self._with_current_payload(await self._get_access(access.id))

    async def revoke_mtproto_proxy(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        """Revoke an MTProto proxy access, removing its managed secret when applicable; requires superadmin."""
        await self.users.require_superadmin(actor_user_id)
        return await self._revoke_mtproto_proxy(actor_user_id, access_id, reason)

    async def revoke_mtproto_proxy_system(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        """Revoke without a role check — for trusted callers (e.g. block_user).

        The caller is responsible for authorising the operation. *actor_user_id*
        is recorded as the revoker for audit/attribution purposes.
        """
        return await self._revoke_mtproto_proxy(actor_user_id, access_id, reason)

    async def _revoke_mtproto_proxy(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        access = await self._get_access(access_id)
        if access.access_type != ProxyAccessType.MTPROTO:
            raise InvalidOperation("Это не MTProto-доступ")
        if access.status in {ProxyAccessStatus.REVOKED, ProxyAccessStatus.INACTIVE, ProxyAccessStatus.DELETED}:
            return self._with_current_payload(access)
        self.backend_health.require_mutation_allowed(ProxyAccessType.MTPROTO)
        if self._access_mode(access) != "managed":
            return await self._deactivate_static(access, actor_user_id, reason)
        return await self._revoke_managed(access, actor_user_id, reason)

    async def delete_mtproto_proxy(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        """Revoke and then hard-delete an MTProto proxy access."""
        await self.users.require_superadmin(actor_user_id)
        access = await self.revoke_mtproto_proxy(actor_user_id, access_id, reason=reason)
        if access.status == ProxyAccessStatus.DELETED:
            return access
        self.backend_health.require_mutation_allowed(ProxyAccessType.MTPROTO)
        # Acquire _apply_lock so reconcile cannot observe a REVOKED/INACTIVE row
        # in the gap between revoke_mtproto_proxy returning and mark_deleted.
        async with self._apply_lock:
            await self.accesses.mark_deleted(access.id, actor_user_id, self.clock.now(), reason=reason)
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="mtproto_proxy_deleted",
            entity_id=access.id,
            details={"owner_user_id": access.owner_user_id, "mode": self._access_mode(access), "reason": reason},
        )
        return await self._get_access(access.id)

    async def list_user_mtproto_accesses(self, actor_user_id: int) -> list[ProxyAccess]:
        """Return the user's MTProto proxy accesses."""
        await self.users.require_approved_or_admin(actor_user_id)
        accesses = await self.accesses.list_by_owner(actor_user_id)
        return [access for access in accesses if access.access_type == ProxyAccessType.MTPROTO]

    async def runtime_status(self) -> MtProxyRuntimeStatus | None:
        """Return the managed MTProxy runtime status, or None when not in managed mode."""
        if self.settings.mtproto_mode != "managed" or self.adapter is None:
            return None
        return await self.adapter.runtime_status()

    async def runtime_secret_count(self) -> int | None:
        """Return the number of managed secrets in the runtime, or None when unavailable."""
        if self.settings.mtproto_mode != "managed" or self.adapter is None:
            return None
        try:
            return len(self.adapter.read_current_managed_secrets())
        except Exception:
            return None

    async def reconcile_mtproto_state(self) -> dict[str, int]:
        """Reconcile pending and drifted managed MTProto secrets against the runtime on startup."""
        if not self.settings.mtproto_enabled or self.settings.mtproto_mode != "managed" or self.adapter is None:
            return {"checked": 0, "missing": 0, "orphaned": 0, "pending": 0, "recovered": 0, "failed": 0, "fatal": 0}
        summary = {"checked": 0, "missing": 0, "orphaned": 0, "pending": 0, "recovered": 0, "failed": 0, "fatal": 0}
        async with self._apply_lock:
            try:
                self._managed_adapter().ensure_managed_runtime_ready()
                store = self._read_all_runtime_managed_secrets()
                pending = await self._managed_accesses_by_statuses(MTPROTO_STARTUP_RECONCILE_STATUSES)
                pending = [access for access in pending if self._access_mode(access) == "managed"]
                summary["pending"] = len(pending)
                summary["failed"] = len(
                    [
                        access
                        for access in pending
                        if access.status
                        in {
                            ProxyAccessStatus.APPLY_FAILED,
                            ProxyAccessStatus.REVOKE_FAILED,
                            ProxyAccessStatus.DELETE_FAILED,
                        }
                    ]
                )

                for access in pending:
                    changed = await self._startup_reconcile_managed_access(access, store)
                    if changed:
                        summary["recovered"] += 1
                        store = self._read_all_runtime_managed_secrets()

                active = await self._active_managed_accesses()
                desired = self._managed_secrets_from_accesses(active)
                desired_fingerprints = {item.fingerprint for item in desired}
                store_fingerprints = {item.fingerprint for item in store}
                missing = desired_fingerprints - store_fingerprints
                orphaned = store_fingerprints - desired_fingerprints
                summary["checked"] = len(active)
                summary["missing"] = len(missing)
                summary["orphaned"] = len(orphaned)

                if missing or orphaned:
                    result = await self._managed_adapter().apply_managed_secrets(desired)
                    summary["recovered"] += 1
                    await self._write_audit_best_effort(
                        actor_user_id=None,
                        action="mtproto_startup_drift_repaired",
                        entity_id=None,
                        details={
                            "missing": len(missing),
                            "orphaned": len(orphaned),
                            "desired_count": len(desired),
                            "generation": result.generation,
                            "missing_fingerprints": sorted(missing),
                            "orphaned_fingerprints": sorted(orphaned),
                        },
                    )
            except Exception as exc:
                summary["failed"] += 1
                summary["fatal"] += 1
                self.backend_health.mark_degraded(ProxyAccessType.MTPROTO, "startup reconciliation failed")
                logger.critical(
                    "MTProto startup reconciliation failed; backend degraded error_type=%s",
                    type(exc).__name__,
                )
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="mtproto_startup_reconcile_failed",
                    entity_id=None,
                    details={"error_type": type(exc).__name__, "backend_degraded": True},
                )

        if any(summary.values()):
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="mtproto_startup_reconcile_checked",
                entity_id=None,
                details=dict(summary),
            )
        return summary

    async def _issue_static(self, actor_user_id: int, profile: TelegramUserProfile) -> ProxyAccess:
        async with self.user_locks.lock(profile.telegram_user_id):
            await self._ensure_can_issue(actor_user_id, profile.telegram_user_id)
            existing = await self._active_access(profile.telegram_user_id)
            if existing is not None:
                active = self._with_current_payload(existing)
                await self._mark_shown(active, actor_user_id)
                return self._with_current_payload(await self._get_access(existing.id))

            payload = self._payload(secret=self.settings.mtproto_secret, mode="static")
            public_payload = self._public_payload(mode="static")
            access = await self.accesses.create(
                owner_user_id=profile.telegram_user_id,
                username=profile.username,
                access_type=ProxyAccessType.MTPROTO,
                status=ProxyAccessStatus.ACTIVE,
                payload=payload,
                public_payload=public_payload,
                created_by=actor_user_id,
                now=self.clock.now(),
                secret_fingerprint=mtproto_secret_fingerprint(self.settings.mtproto_secret),
            )
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="mtproto_proxy_created",
                entity_id=access.id,
                details={"owner_user_id": profile.telegram_user_id, "host": self.settings.mtproto_host, "mode": "static"},
            )
            active = self._with_current_payload(await self._get_access(access.id))
            await self._mark_shown(active, actor_user_id)
            return self._with_current_payload(await self._get_access(access.id))

    async def _issue_managed(self, actor_user_id: int, profile: TelegramUserProfile) -> ProxyAccess:
        self._managed_adapter()
        async with self.user_locks.lock(profile.telegram_user_id):
            await self._ensure_can_issue(actor_user_id, profile.telegram_user_id)
            existing = await self._active_access(profile.telegram_user_id)
            if existing is not None:
                active = self._with_current_payload(existing)
                await self._mark_shown(active, actor_user_id)
                return self._with_current_payload(await self._get_access(existing.id))
            async with self._apply_lock:
                # Re-check under the apply lock: the backend may have been marked
                # degraded while we waited, after the pre-lock check in
                # issue_mtproto_proxy passed.
                self.backend_health.require_mutation_allowed(ProxyAccessType.MTPROTO)
                existing = await self._active_access(profile.telegram_user_id)
                if existing is not None:
                    active = self._with_current_payload(existing)
                    await self._mark_shown(active, actor_user_id)
                    return self._with_current_payload(await self._get_access(existing.id))

                self._managed_adapter().ensure_managed_runtime_ready()
                secret = await self._unique_managed_secret()
                fingerprint = mtproto_secret_fingerprint(secret)
                payload = self._payload(secret=secret, mode="managed")
                public_payload = self._public_payload(mode="managed")
                try:
                    access = await self.accesses.create(
                        owner_user_id=profile.telegram_user_id,
                        username=profile.username,
                        access_type=ProxyAccessType.MTPROTO,
                        status=ProxyAccessStatus.PENDING_APPLY,
                        payload=payload,
                        public_payload=public_payload,
                        created_by=actor_user_id,
                        now=self.clock.now(),
                        secret_fingerprint=fingerprint,
                    )
                except sqlite3.IntegrityError as exc:
                    existing_live = await self._live_access(profile.telegram_user_id)
                    if existing_live is not None and existing_live.status == ProxyAccessStatus.ACTIVE:
                        active = self._with_current_payload(existing_live)
                        await self._mark_shown(active, actor_user_id)
                        return self._with_current_payload(await self._get_access(existing_live.id))
                    raise InvalidOperation("MTProto-доступ уже создаётся или отзывается") from exc
                try:
                    desired = await self._desired_managed_secrets(extra=access)
                    result = await self._managed_adapter().apply_managed_secrets(desired)
                except Exception as exc:
                    error = self._redact_secrets(str(exc), secret)
                    await self.accesses.set_status(
                        access.id,
                        ProxyAccessStatus.APPLY_FAILED,
                        self.clock.now(),
                        error=error,
                    )
                    await self._write_audit_best_effort(
                        actor_user_id=actor_user_id,
                        action="mtproto_proxy_apply_failed",
                        entity_id=access.id,
                        details={
                            "owner_user_id": profile.telegram_user_id,
                            "fingerprint": fingerprint,
                            "error": error,
                        },
                    )
                    if error != str(exc):
                        raise InvalidOperation("MTProto apply failed; raw secret was redacted. Contact admin.") from None
                    raise

                try:
                    await self.accesses.mark_active(
                        access.id,
                        self.clock.now(),
                        payload=payload,
                        public_payload=public_payload,
                        apply_generation=result.generation,
                    )
                except Exception as exc:
                    await self._compensate_failed_managed_create_after_apply(
                        actor_user_id=actor_user_id,
                        access_id=access.id,
                        owner_user_id=profile.telegram_user_id,
                        fingerprint=fingerprint,
                        original_error=exc,
                    )
                    raise

                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="mtproto_proxy_created",
                    entity_id=access.id,
                    details={
                        "owner_user_id": profile.telegram_user_id,
                        "host": self.settings.mtproto_host,
                        "mode": "managed",
                        "fingerprint": fingerprint,
                        "generation": result.generation,
                    },
                )
                active = self._with_current_payload(await self._get_access(access.id))
                await self._mark_shown(active, actor_user_id)
                return self._with_current_payload(await self._get_access(access.id))

    async def _revoke_managed(self, access: ProxyAccess, actor_user_id: int, reason: str | None) -> ProxyAccess:
        async with self._apply_lock:
            # Re-check under the apply lock (degraded may have been set while we waited).
            self.backend_health.require_mutation_allowed(ProxyAccessType.MTPROTO)
            access = await self._get_access(access.id)
            if access.status in {ProxyAccessStatus.REVOKED, ProxyAccessStatus.INACTIVE, ProxyAccessStatus.DELETED}:
                return self._with_current_payload(access)
            self._managed_adapter().ensure_managed_runtime_ready()
            await self.accesses.set_status(access.id, ProxyAccessStatus.PENDING_REVOKE, self.clock.now(), reason=reason)
            fingerprint = self._access_fingerprint(access)
            try:
                desired = await self._desired_managed_secrets(exclude_access_id=access.id)
                result = await self._managed_adapter().apply_managed_secrets(desired)
            except Exception as exc:
                error = self._redact_secrets(str(exc), self._access_secret_optional(access))
                await self.accesses.set_status(
                    access.id,
                    ProxyAccessStatus.REVOKE_FAILED,
                    self.clock.now(),
                    error=error,
                    reason=reason,
                )
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="mtproto_proxy_revoke_failed",
                    entity_id=access.id,
                    details={
                        "owner_user_id": access.owner_user_id,
                        "fingerprint": fingerprint,
                        "reason": reason,
                        "error": error,
                    },
                )
                if error != str(exc):
                    raise InvalidOperation("MTProto revoke failed; raw secret was redacted. Contact admin.") from None
                raise
            await self.accesses.mark_revoked(access.id, actor_user_id, self.clock.now(), reason=reason)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="mtproto_proxy_revoked",
                entity_id=access.id,
                details={
                    "owner_user_id": access.owner_user_id,
                    "mode": "managed",
                    "fingerprint": fingerprint,
                    "reason": reason,
                    "generation": result.generation,
                    "server_side_revoke": True,
                },
            )
            return self._with_current_payload(await self._get_access(access.id))

    async def _deactivate_static(self, access: ProxyAccess, actor_user_id: int, reason: str | None) -> ProxyAccess:
        # static mode: shared secret cannot be selectively revoked —
        # deactivating marks the DB row INACTIVE but the shared MTPROTO_SECRET
        # continues to work for all users until it is rotated.
        logger.warning(
            "user %s blocked but shared MTProto secret still active — "
            "rotate MTPROTO_SECRET to invalidate "
            "user_id=%s access_id=%s",
            access.owner_user_id,
            access.owner_user_id,
            access.id,
        )
        await self.accesses.mark_inactive(access.id, actor_user_id, self.clock.now(), reason=reason)
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="mtproto_proxy_deactivated",
            entity_id=access.id,
            details={
                "owner_user_id": access.owner_user_id,
                "reason": reason,
                "mode": "static",
                "server_side_revoke": False,
                "shared_secret_still_active": True,
            },
        )
        return self._with_current_payload(await self._get_access(access.id))

    async def _ensure_can_issue(self, actor_user_id: int, owner_user_id: int) -> None:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        owner = await self.users.require_approved_or_admin(owner_user_id)
        if actor.role != UserRole.SUPERADMIN and actor_user_id != owner_user_id:
            raise AccessDenied("Нельзя создавать прокси для другого пользователя")
        if owner.role not in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
            raise AccessDenied("Владелец прокси не имеет доступа")

    async def _active_access(self, owner_user_id: int) -> ProxyAccess | None:
        return await self.accesses.find_user_access_by_type_statuses(
            owner_user_id,
            ProxyAccessType.MTPROTO,
            {ProxyAccessStatus.ACTIVE},
        )

    async def _live_access(self, owner_user_id: int) -> ProxyAccess | None:
        return await self.accesses.find_user_access_by_type_statuses(
            owner_user_id,
            ProxyAccessType.MTPROTO,
            {ProxyAccessStatus.ACTIVE, ProxyAccessStatus.PENDING_APPLY, ProxyAccessStatus.PENDING_REVOKE},
        )

    async def _active_managed_accesses(self) -> list[ProxyAccess]:
        active = await self._managed_accesses_by_statuses(
            {ProxyAccessStatus.ACTIVE},
        )
        return [access for access in active if self._access_mode(access) == "managed"]

    async def _managed_accesses_by_statuses(self, statuses: set[ProxyAccessStatus]) -> list[ProxyAccess]:
        result: list[ProxyAccess] = []
        last_id = 0
        while True:
            batch = await self.accesses.list_by_type_statuses(
                ProxyAccessType.MTPROTO,
                statuses,
                limit=500,
                after_id=last_id,
            )
            if not batch:
                break
            result.extend(batch)
            last_id = batch[-1].id
        return result

    def _read_all_runtime_managed_secrets(self) -> list[MtProxyManagedSecret]:
        adapter = self._managed_adapter()
        config_items = adapter.read_current_managed_secrets()
        runtime_reader = getattr(adapter, "read_runtime_managed_secrets", None)
        runtime_items = runtime_reader() if runtime_reader is not None else config_items
        by_fingerprint: dict[str, MtProxyManagedSecret] = {}
        for item in [*config_items, *runtime_items]:
            if item.fingerprint == "empty-placeholder":
                continue
            by_fingerprint.setdefault(item.fingerprint, item)
        return list(by_fingerprint.values())

    def _managed_secrets_from_accesses(self, accesses: list[ProxyAccess]) -> list[MtProxyManagedSecret]:
        result: list[MtProxyManagedSecret] = []
        for access in accesses:
            if self._access_mode(access) != "managed":
                continue
            secret = self._access_secret(access)
            fingerprint = self._access_fingerprint(access)
            expected_fingerprint = mtproto_secret_fingerprint(secret)
            if fingerprint != expected_fingerprint:
                raise InvalidOperation("MTProto access fingerprint mismatch; contact admin")
            result.append(
                MtProxyManagedSecret(
                    secret=secret,
                    fingerprint=fingerprint,
                    owner_user_id=access.owner_user_id,
                    access_id=access.id,
                )
            )
        return result

    async def _startup_reconcile_managed_access(
        self,
        access: ProxyAccess,
        store: list[MtProxyManagedSecret],
    ) -> bool:
        if access.status == ProxyAccessStatus.PENDING_APPLY:
            return await self._startup_reconcile_pending_apply(access, store)
        if access.status in {ProxyAccessStatus.PENDING_REVOKE, ProxyAccessStatus.REVOKE_FAILED}:
            return await self._startup_complete_managed_removal(access, delete=False)
        if access.status in {ProxyAccessStatus.PENDING_DELETE, ProxyAccessStatus.DELETE_FAILED}:
            return await self._startup_complete_managed_removal(access, delete=True)
        return False

    async def _startup_reconcile_pending_apply(
        self,
        access: ProxyAccess,
        store: list[MtProxyManagedSecret],
    ) -> bool:
        fingerprint = self._access_fingerprint(access)
        store_by_fingerprint = {item.fingerprint: item for item in store}
        store_item = store_by_fingerprint.get(fingerprint)
        if store_item is None:
            await self.accesses.set_status(
                access.id,
                ProxyAccessStatus.APPLY_FAILED,
                self.clock.now(),
                error="startup reconciliation did not find applied MTProto secret",
            )
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="mtproto_startup_pending_apply_failed",
                entity_id=access.id,
                details={"fingerprint": fingerprint, "secret_present": False},
            )
            return True

        if mtproto_secret_fingerprint(store_item.secret) != fingerprint:
            raise InvalidOperation("MTProto runtime secret fingerprint mismatch; contact admin")
        secret = store_item.secret
        payload = self._payload(secret=secret, mode="managed")
        public_payload = self._public_payload(mode="managed", fingerprint=fingerprint)
        try:
            await self.accesses.mark_active(
                access.id,
                self.clock.now(),
                payload=payload,
                public_payload=public_payload,
            )
        except Exception as exc:
            await self._compensate_failed_startup_pending_apply(
                access=access,
                fingerprint=fingerprint,
                original_error=exc,
            )
            return True
        await self._write_audit_best_effort(
            actor_user_id=None,
            action="mtproto_startup_apply_recovered",
            entity_id=access.id,
            details={"fingerprint": fingerprint, "secret_present": True},
        )
        return True

    async def _startup_complete_managed_removal(self, access: ProxyAccess, *, delete: bool) -> bool:
        desired = self._managed_secrets_from_accesses(await self._active_managed_accesses())
        result = await self._managed_adapter().apply_managed_secrets(desired)
        actor_user_id = access.deleted_by or access.revoked_by or access.created_by
        if delete:
            await self.accesses.mark_deleted(access.id, actor_user_id, self.clock.now(), reason=access.reason)
            action = "mtproto_startup_delete_completed"
        else:
            await self.accesses.mark_revoked(access.id, actor_user_id, self.clock.now(), reason=access.reason)
            action = "mtproto_startup_revoke_completed"
        await self._write_audit_best_effort(
            actor_user_id=None,
            action=action,
            entity_id=access.id,
            details={
                "owner_user_id": access.owner_user_id,
                "fingerprint": self._access_fingerprint(access),
                "previous_status": access.status.value,
                "generation": result.generation,
            },
        )
        return True

    async def _compensate_failed_startup_pending_apply(
        self,
        *,
        access: ProxyAccess,
        fingerprint: str,
        original_error: Exception,
    ) -> None:
        try:
            desired = await self._desired_managed_secrets(exclude_access_id=access.id)
            result = await self._managed_adapter().apply_managed_secrets(desired)
        except Exception as rollback_error:
            self.backend_health.mark_degraded(
                ProxyAccessType.MTPROTO,
                "startup pending_apply mark_active failed and rollback failed",
            )
            logger.critical(
                "MTProto startup pending_apply compensation failed for access_id=%s fingerprint=%s error_type=%s rollback_error_type=%s",
                access.id,
                fingerprint,
                type(original_error).__name__,
                type(rollback_error).__name__,
            )
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="mtproto_startup_pending_apply_compensation_failed",
                entity_id=access.id,
                details={
                    "owner_user_id": access.owner_user_id,
                    "fingerprint": fingerprint,
                    "original_error_type": type(original_error).__name__,
                    "rollback_error_type": type(rollback_error).__name__,
                    "backend_degraded": True,
                },
            )
            return

        try:
            await self.accesses.set_status(
                access.id,
                ProxyAccessStatus.APPLY_FAILED,
                self.clock.now(),
                error="startup mark_active failed; applied MTProto secret was removed",
            )
        except Exception:
            self.backend_health.mark_degraded(
                ProxyAccessType.MTPROTO,
                "startup pending_apply rollback succeeded but DB status update failed",
            )
            logger.warning(
                "MTProto startup pending_apply rollback succeeded, but DB status update failed access_id=%s",
                access.id,
            )
        await self._write_audit_best_effort(
            actor_user_id=None,
            action="mtproto_startup_pending_apply_compensated",
            entity_id=access.id,
            details={
                "owner_user_id": access.owner_user_id,
                "fingerprint": fingerprint,
                "generation": result.generation,
                "original_error_type": type(original_error).__name__,
            },
        )

    async def _compensate_failed_managed_create_after_apply(
        self,
        *,
        actor_user_id: int,
        access_id: int,
        owner_user_id: int,
        fingerprint: str,
        original_error: Exception,
    ) -> None:
        logger.critical(
            "MTProto secret applied, but DB mark_active failed for access_id=%s fingerprint=%s; attempting rollback",
            access_id,
            fingerprint,
        )
        try:
            desired = await self._desired_managed_secrets(exclude_access_id=access_id)
            result = await self._managed_adapter().apply_managed_secrets(desired)
        except Exception as rollback_error:
            self.backend_health.mark_degraded(
                ProxyAccessType.MTPROTO,
                "post-apply mark_active failed and rollback failed",
            )
            logger.critical(
                "MTProto create rollback failed after DB mark_active failure for access_id=%s fingerprint=%s error_type=%s rollback_error_type=%s",
                access_id,
                fingerprint,
                type(original_error).__name__,
                type(rollback_error).__name__,
            )
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="mtproto_create_rollback_failed",
                entity_id=access_id,
                details={
                    "owner_user_id": owner_user_id,
                    "fingerprint": fingerprint,
                    "original_error_type": type(original_error).__name__,
                    "rollback_error_type": type(rollback_error).__name__,
                    "backend_degraded": True,
                },
            )
            return

        try:
            await self.accesses.set_status(
                access_id,
                ProxyAccessStatus.APPLY_FAILED,
                self.clock.now(),
                error="db mark_active failed after server-side apply; MTProto secret was removed",
            )
        except Exception:
            logger.warning(
                "MTProto create rollback succeeded, but failed to mark access apply_failed access_id=%s",
                access_id,
            )
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="mtproto_create_rolled_back_after_db_failure",
            entity_id=access_id,
            details={
                "owner_user_id": owner_user_id,
                "fingerprint": fingerprint,
                "generation": result.generation,
                "original_error_type": type(original_error).__name__,
            },
        )

    async def _desired_managed_secrets(
        self,
        *,
        extra: ProxyAccess | None = None,
        exclude_access_id: int | None = None,
    ) -> list[MtProxyManagedSecret]:
        accesses = await self._active_managed_accesses()
        if extra is not None:
            accesses.append(extra)
        if exclude_access_id is not None:
            accesses = [access for access in accesses if access.id != exclude_access_id]
        return self._managed_secrets_from_accesses(accesses)

    async def _unique_managed_secret(self) -> str:
        store_fingerprints = {
            item.fingerprint for item in self._read_all_runtime_managed_secrets()
        }
        for _ in range(20):
            secret = secrets.token_hex(16)
            fingerprint = mtproto_secret_fingerprint(secret)
            if fingerprint in store_fingerprints:
                continue
            if await self.accesses.find_by_secret_fingerprint(fingerprint) is None:
                return secret
        raise InvalidOperation("Не удалось сгенерировать уникальный MTProto secret")

    def _payload(self, *, secret: str, mode: str) -> dict[str, object]:
        link, link_dd = self._links(secret)
        return {
            "type": ProxyAccessType.MTPROTO.value,
            "mode": mode,
            "protocol": "mtproto",
            "host": self.settings.mtproto_host,
            "port": self.settings.mtproto_port,
            "secret": secret,
            "secret_dd": f"dd{secret}",
            "fingerprint": mtproto_secret_fingerprint(secret),
            "link": link,
            "link_dd": link_dd,
            "public_name": self.settings.mtproto_public_name,
            "note": self.settings.mtproto_note,
        }

    def _public_payload(self, *, mode: str, fingerprint: str | None = None) -> dict[str, object]:
        payload: dict[str, object] = {
            "type": ProxyAccessType.MTPROTO.value,
            "mode": mode,
            "protocol": "mtproto",
            "host": self.settings.mtproto_host,
            "port": self.settings.mtproto_port,
            "public_name": self.settings.mtproto_public_name,
            "note": self.settings.mtproto_note,
        }
        if fingerprint:
            payload["fingerprint"] = fingerprint
        return payload

    def _links(self, secret: str) -> tuple[str, str]:
        base = f"https://t.me/proxy?server={self.settings.mtproto_host}&port={self.settings.mtproto_port}"
        return (
            f"{base}&secret={secret}",
            f"{base}&secret=dd{secret}",
        )

    def _with_current_payload(self, access: ProxyAccess) -> ProxyAccess:
        secret = self._access_secret(access)
        mode = self._access_mode(access)
        if not secret:
            return access
        payload = self._payload(secret=secret, mode=mode)
        public_payload = self._public_payload(mode=mode, fingerprint=mtproto_secret_fingerprint(secret))
        return replace(access, payload=payload, public_payload=public_payload)

    def _ensure_enabled(self) -> None:
        if not self.settings.mtproto_enabled:
            raise InvalidOperation("MTProto Proxy сейчас недоступен")
        if not self.settings.mtproto_host:
            raise InvalidOperation("MTProto Proxy не настроен")
        if self.settings.mtproto_mode == "static" and not self.settings.mtproto_secret:
            raise InvalidOperation("MTProto Proxy не настроен")
        if self.settings.mtproto_mode == "managed" and self.adapter is None:
            raise InvalidOperation("MTProto managed mode не подключён")

    async def _get_access(self, access_id: int) -> ProxyAccess:
        access = await self.accesses.get_by_id(access_id)
        if access is None:
            raise NotFound("Прокси-доступ не найден")
        return access

    async def _mark_shown(self, access: ProxyAccess, actor_user_id: int) -> None:
        await self.accesses.mark_shown(access.id, self.clock.now())
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="mtproto_proxy_shown",
            entity_id=access.id,
            details={"owner_user_id": access.owner_user_id, "mode": self._access_mode(access)},
        )

    def _managed_adapter(self) -> MtProxyAdapter:
        if self.adapter is None:
            raise InvalidOperation("MTProto managed adapter не подключён")
        return self.adapter

    def _access_mode(self, access: ProxyAccess) -> str:
        mode = str(access.payload.get("mode") or access.public_payload.get("mode") or "static").lower()
        return "managed" if mode == "managed" else "static"

    def _access_secret(self, access: ProxyAccess) -> str:
        secret = str(access.payload.get("secret") or "")
        if secret:
            return secret
        if self._access_mode(access) == "static":
            return str(self.settings.mtproto_secret or "")
        raise InvalidOperation("MTProto access data is incomplete; contact admin")

    def _access_secret_optional(self, access: ProxyAccess) -> str:
        try:
            return self._access_secret(access)
        except InvalidOperation:
            return ""

    def _access_fingerprint(self, access: ProxyAccess) -> str:
        if access.secret_fingerprint:
            return access.secret_fingerprint
        value = str(access.payload.get("fingerprint") or access.public_payload.get("fingerprint") or "")
        if value:
            return value
        secret = self._access_secret(access)
        return mtproto_secret_fingerprint(secret) if secret else ""

    def _redact_secrets(self, text: str, *values: str) -> str:
        redacted = text
        for value in values:
            if value:
                redacted = redacted.replace(value, "***")
                redacted = redacted.replace(f"dd{value}", "dd***")
        return redact_value(redacted)

    async def _write_audit_best_effort(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_id: str | int | None,
        details: dict[str, object] | None = None,
    ) -> None:
        writer = getattr(self.audit, "write_best_effort", None)
        if writer is not None:
            await writer(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=AuditEntityType.PROXY,
                entity_id=entity_id,
                details=details,
            )
            return
        await self.audit.write(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=AuditEntityType.PROXY,
            entity_id=entity_id,
            details=details,
        )
