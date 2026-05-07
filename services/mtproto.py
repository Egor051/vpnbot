from __future__ import annotations

import asyncio
import hashlib
import secrets
import sqlite3
from dataclasses import replace

from adapters.clock import ClockProvider
from adapters.mtproxy import MtProxyAdapter, MtProxyManagedSecret
from config.settings import Settings
from models.dto import ProxyAccess, TelegramUserProfile
from models.enums import AuditEntityType, ProxyAccessStatus, ProxyAccessType, UserRole
from repositories.proxy_accesses import ProxyAccessRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.user_locks import UserLockManager
from services.users import UserService

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
}


def mtproto_secret_fingerprint(secret: str) -> str:
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
    ) -> None:
        self.accesses = accesses
        self.users = users
        self.settings = settings
        self.clock = clock
        self.audit = audit
        self.adapter = adapter
        self.user_locks = user_locks or getattr(users, "user_locks", UserLockManager())
        self._apply_lock = asyncio.Lock()

    async def issue_mtproto_proxy(self, actor_user_id: int, profile: TelegramUserProfile) -> ProxyAccess:
        self._ensure_enabled()
        if self.settings.mtproto_mode == "managed":
            return await self._issue_managed(actor_user_id, profile)
        return await self._issue_static(actor_user_id, profile)

    async def get_mtproto_proxy_config(self, actor_user_id: int) -> ProxyAccess:
        await self.users.require_approved_or_admin(actor_user_id)
        access = await self._active_access(actor_user_id)
        if access is None:
            raise NotFound("MTProto-доступ не найден")
        active = self._with_current_payload(access)
        await self._mark_shown(active, actor_user_id)
        return self._with_current_payload(await self._get_access(access.id))

    async def revoke_mtproto_proxy(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        await self.users.require_superadmin(actor_user_id)
        access = await self._get_access(access_id)
        if access.access_type != ProxyAccessType.MTPROTO:
            raise InvalidOperation("Это не MTProto-доступ")
        if access.status in {ProxyAccessStatus.REVOKED, ProxyAccessStatus.INACTIVE, ProxyAccessStatus.DELETED}:
            return self._with_current_payload(access)
        if self._access_mode(access) != "managed":
            return await self._deactivate_static(access, actor_user_id, reason)
        return await self._revoke_managed(access, actor_user_id, reason)

    async def delete_mtproto_proxy(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        await self.users.require_superadmin(actor_user_id)
        access = await self.revoke_mtproto_proxy(actor_user_id, access_id, reason=reason)
        if access.status == ProxyAccessStatus.DELETED:
            return access
        await self.accesses.mark_deleted(access.id, actor_user_id, self.clock.now(), reason=reason)
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="mtproto_proxy_deleted",
            entity_id=access.id,
            details={"owner_user_id": access.owner_user_id, "mode": self._access_mode(access), "reason": reason},
        )
        return await self._get_access(access.id)

    async def list_user_mtproto_accesses(self, actor_user_id: int) -> list[ProxyAccess]:
        await self.users.require_approved_or_admin(actor_user_id)
        accesses = await self.accesses.list_by_owner(actor_user_id)
        return [access for access in accesses if access.access_type == ProxyAccessType.MTPROTO]

    async def runtime_status(self):
        if self.settings.mtproto_mode != "managed" or self.adapter is None:
            return None
        return await self.adapter.runtime_status()

    async def runtime_secret_count(self) -> int | None:
        if self.settings.mtproto_mode != "managed" or self.adapter is None:
            return None
        try:
            return len(self.adapter.read_current_managed_secrets())
        except Exception:
            return None

    async def reconcile_mtproto_state(self) -> dict[str, int]:
        if not self.settings.mtproto_enabled or self.settings.mtproto_mode != "managed" or self.adapter is None:
            return {"checked": 0, "missing": 0, "orphaned": 0, "pending": 0, "failed": 0}
        active = await self._active_managed_accesses()
        store = self.adapter.read_current_managed_secrets()
        db_fingerprints = {self._access_fingerprint(access) for access in active if self._access_fingerprint(access)}
        store_fingerprints = {item.fingerprint for item in store}
        pending = await self.accesses.list_by_type_statuses(
            ProxyAccessType.MTPROTO,
            MTPROTO_STARTUP_RECONCILE_STATUSES,
        )
        summary = {
            "checked": len(active),
            "missing": len(db_fingerprints - store_fingerprints),
            "orphaned": len(store_fingerprints - db_fingerprints),
            "pending": len([access for access in pending if self._access_mode(access) == "managed"]),
            "failed": len(
                [
                    access
                    for access in pending
                    if access.status in {ProxyAccessStatus.APPLY_FAILED, ProxyAccessStatus.REVOKE_FAILED}
                    and self._access_mode(access) == "managed"
                ]
            ),
        }
        if any(summary.values()):
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="mtproto_startup_reconcile_checked",
                entity_id=None,
                details=summary,
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
                    await self.accesses.set_status(
                        access.id,
                        ProxyAccessStatus.APPLY_FAILED,
                        self.clock.now(),
                        error=str(exc),
                    )
                    await self._write_audit_best_effort(
                        actor_user_id=actor_user_id,
                        action="mtproto_proxy_apply_failed",
                        entity_id=access.id,
                        details={
                            "owner_user_id": profile.telegram_user_id,
                            "fingerprint": fingerprint,
                            "error": str(exc),
                        },
                    )
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
                    await self._write_audit_best_effort(
                        actor_user_id=actor_user_id,
                        action="mtproto_proxy_apply_failed",
                        entity_id=access.id,
                        details={
                            "owner_user_id": profile.telegram_user_id,
                            "fingerprint": fingerprint,
                            "mtproxy_applied": True,
                            "db_mark_active_failed": True,
                            "error": str(exc),
                        },
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
                await self.accesses.set_status(
                    access.id,
                    ProxyAccessStatus.REVOKE_FAILED,
                    self.clock.now(),
                    error=str(exc),
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
                        "error": str(exc),
                    },
                )
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
        active = await self.accesses.list_by_type_statuses(
            ProxyAccessType.MTPROTO,
            {ProxyAccessStatus.ACTIVE},
        )
        return [access for access in active if self._access_mode(access) == "managed"]

    async def _desired_managed_secrets(
        self,
        *,
        extra: ProxyAccess | None = None,
        exclude_access_id: int | None = None,
    ) -> list[MtProxyManagedSecret]:
        accesses = await self._active_managed_accesses()
        if extra is not None:
            accesses.append(extra)
        result: list[MtProxyManagedSecret] = []
        for access in accesses:
            if exclude_access_id is not None and access.id == exclude_access_id:
                continue
            secret = self._access_secret(access)
            fingerprint = self._access_fingerprint(access)
            if not secret or not fingerprint:
                continue
            result.append(
                MtProxyManagedSecret(
                    secret=secret,
                    fingerprint=fingerprint,
                    owner_user_id=access.owner_user_id,
                    access_id=access.id,
                )
            )
        return result

    async def _unique_managed_secret(self) -> str:
        store_fingerprints = {
            item.fingerprint for item in self._managed_adapter().read_current_managed_secrets()
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

    def _access_fingerprint(self, access: ProxyAccess) -> str:
        if access.secret_fingerprint:
            return access.secret_fingerprint
        value = str(access.payload.get("fingerprint") or access.public_payload.get("fingerprint") or "")
        if value:
            return value
        secret = self._access_secret(access)
        return mtproto_secret_fingerprint(secret) if secret else ""

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
