
import logging
import secrets
from urllib.parse import quote

from adapters.clock import ClockProvider
from adapters.dante_users import DanteUserAdapter
from adapters.errors import DanteUserNotFoundError
from config.settings import Settings
from models.dto import ProxyAccess, TelegramUserProfile
from models.enums import AuditEntityType, ProxyAccessStatus, ProxyAccessType, UserRole
from repositories.proxy_accesses import ProxyAccessRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.user_locks import UserLockManager
from services.users import UserService

logger = logging.getLogger(__name__)

SOCKS5_ACCESS_MAY_EXIST_STATUSES = {
    ProxyAccessStatus.ACTIVE,
    ProxyAccessStatus.PENDING_APPLY,
    ProxyAccessStatus.APPLY_FAILED,
    ProxyAccessStatus.PENDING_REVOKE,
    ProxyAccessStatus.PENDING_DELETE,
    ProxyAccessStatus.DELETE_FAILED,
}


class Socks5Service:
    def __init__(
        self,
        *,
        accesses: ProxyAccessRepository,
        users: UserService,
        adapter: DanteUserAdapter,
        settings: Settings,
        clock: ClockProvider,
        audit: AuditService,
        user_locks: UserLockManager | None = None,
        backend_health: BackendHealth | None = None,
    ) -> None:
        self.accesses = accesses
        self.users = users
        self.adapter = adapter
        self.settings = settings
        self.clock = clock
        self.audit = audit
        self.user_locks: UserLockManager = user_locks if user_locks is not None else getattr(users, "user_locks", UserLockManager())
        self.backend_health = backend_health or BackendHealth()

    async def issue_socks5_proxy(self, actor_user_id: int, profile: TelegramUserProfile) -> ProxyAccess:
        self._ensure_enabled()
        self.backend_health.require_mutation_allowed(ProxyAccessType.SOCKS5)
        async with self.user_locks.lock(profile.telegram_user_id):
            await self._ensure_can_issue(actor_user_id, profile.telegram_user_id)
            existing = await self._active_access(profile.telegram_user_id)
            if existing is not None:
                await self._mark_shown(existing, actor_user_id)
                return await self._get_access(existing.id)

            login = await self._unique_login(profile.telegram_user_id)
            password = self._generate_password()
            payload = self._payload(login, password)
            public_payload = self._public_payload(login)
            access = await self.accesses.create(
                owner_user_id=profile.telegram_user_id,
                username=profile.username,
                access_type=ProxyAccessType.SOCKS5,
                status=ProxyAccessStatus.PENDING_APPLY,
                payload=payload,
                public_payload=public_payload,
                created_by=actor_user_id,
                now=self.clock.now(),
            )
            try:
                await self._ensure_can_issue(actor_user_id, profile.telegram_user_id)
                await self.adapter.create_user(login, password)
            except Exception as exc:
                error = self._redact_value(str(exc), password)
                await self.accesses.set_status(
                    access.id,
                    ProxyAccessStatus.APPLY_FAILED,
                    self.clock.now(),
                    error=error,
                )
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="socks5_proxy_apply_failed",
                    entity_id=access.id,
                    details={"owner_user_id": profile.telegram_user_id, "login": login, "error": error},
                )
                if error != str(exc):
                    raise InvalidOperation("SOCKS5 apply failed; raw password was redacted. Contact admin.") from None
                raise
            try:
                await self.accesses.mark_active(access.id, self.clock.now(), payload=payload, public_payload=public_payload)
            except Exception as exc:
                await self._compensate_failed_create_after_apply(
                    actor_user_id=actor_user_id,
                    access_id=access.id,
                    owner_user_id=profile.telegram_user_id,
                    login=login,
                    original_error=exc,
                )
                raise

            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="socks5_proxy_created",
                entity_id=access.id,
                details={"owner_user_id": profile.telegram_user_id, "login": login, "host": self.settings.socks5_host},
            )
            active = await self._get_access(access.id)
            await self._mark_shown(active, actor_user_id)
            return await self._get_access(access.id)

    async def get_socks5_proxy_config(self, actor_user_id: int) -> ProxyAccess:
        await self.users.require_approved_or_admin(actor_user_id)
        access = await self._active_access(actor_user_id)
        if access is None:
            raise NotFound("SOCKS5-доступ не найден")
        await self._mark_shown(access, actor_user_id)
        return await self._get_access(access.id)

    async def list_user_proxy_accesses(self, actor_user_id: int) -> list[ProxyAccess]:
        await self.users.require_approved_or_admin(actor_user_id)
        return await self.accesses.list_by_owner(actor_user_id)

    async def revoke_socks5_proxy(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        await self.users.require_superadmin(actor_user_id)
        # Fetch before lock to get owner_user_id; access_type never changes.
        pre_access = await self._get_access(access_id)
        if pre_access.access_type != ProxyAccessType.SOCKS5:
            raise InvalidOperation("Это не SOCKS5-доступ")
        # Serialises revoke/issue for the same owner: prevents races between
        # Dante-adapter calls and DB status writes.
        async with self.user_locks.lock(pre_access.owner_user_id):
            access = await self._get_access(access_id)  # re-fetch under lock
            if access.status in {ProxyAccessStatus.REVOKED, ProxyAccessStatus.INACTIVE, ProxyAccessStatus.DELETED}:
                return access
            self.backend_health.require_mutation_allowed(ProxyAccessType.SOCKS5)
            previous_status = access.status
            await self.accesses.set_status(access.id, ProxyAccessStatus.PENDING_REVOKE, self.clock.now(), reason=reason)
            login = str(access.payload.get("login") or "")
            try:
                if login:
                    await self.adapter.lock_user(login)
            except DanteUserNotFoundError:
                pass
            except Exception as exc:
                await self.accesses.set_status(access.id, previous_status, self.clock.now(), error=str(exc), reason=reason)
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="socks5_proxy_revoke_failed",
                    entity_id=access.id,
                    details={"owner_user_id": access.owner_user_id, "login": login, "error": str(exc)},
                )
                raise
            await self.accesses.mark_revoked(access.id, actor_user_id, self.clock.now(), reason=reason)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="socks5_proxy_revoked",
                entity_id=access.id,
                details={"owner_user_id": access.owner_user_id, "login": login, "reason": reason},
            )
            return await self._get_access(access.id)

    async def delete_socks5_proxy(self, actor_user_id: int, access_id: int, reason: str | None = None) -> ProxyAccess:
        await self.users.require_superadmin(actor_user_id)
        # Fetch before lock to get owner_user_id; access_type never changes.
        pre_access = await self._get_access(access_id)
        if pre_access.access_type != ProxyAccessType.SOCKS5:
            raise InvalidOperation("Это не SOCKS5-доступ")
        # Serialises delete/issue for the same owner: prevents races between
        # Dante-adapter calls and DB status writes.
        async with self.user_locks.lock(pre_access.owner_user_id):
            access = await self._get_access(access_id)  # re-fetch under lock
            if access.status == ProxyAccessStatus.DELETED:
                return access
            self.backend_health.require_mutation_allowed(ProxyAccessType.SOCKS5)
            await self.accesses.set_status(access.id, ProxyAccessStatus.PENDING_DELETE, self.clock.now(), reason=reason)
            login = str(access.payload.get("login") or "")
            try:
                if login:
                    await self.adapter.delete_user(login)
            except Exception as exc:
                await self.accesses.set_status(access.id, ProxyAccessStatus.DELETE_FAILED, self.clock.now(), error=str(exc), reason=reason)
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="socks5_proxy_delete_failed",
                    entity_id=access.id,
                    details={"owner_user_id": access.owner_user_id, "login": login, "error": str(exc)},
                )
                raise
            await self.accesses.mark_deleted(access.id, actor_user_id, self.clock.now(), reason=reason)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="socks5_proxy_deleted",
                entity_id=access.id,
                details={"owner_user_id": access.owner_user_id, "login": login, "reason": reason},
            )
            return await self._get_access(access.id)

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
            ProxyAccessType.SOCKS5,
            {ProxyAccessStatus.ACTIVE},
        )

    async def _unique_login(self, owner_user_id: int) -> str:
        prefix = self.settings.socks5_login_prefix
        max_suffix_len = 32 - len(prefix) - len(str(owner_user_id)) - 1
        if max_suffix_len < 4:
            raise InvalidOperation("SOCKS5_LOGIN_PREFIX слишком длинный для Linux login")
        for _ in range(10):
            suffix = secrets.token_hex(min(4, max_suffix_len // 2))
            login = f"{prefix}{owner_user_id}_{suffix}"
            if await self.accesses.find_by_socks5_login(login) is None and not await self.adapter.exists(login):
                return login
        raise InvalidOperation("Не удалось сгенерировать уникальный SOCKS5 login")

    def _payload(self, login: str, password: str) -> dict[str, object]:
        host = self.settings.socks5_host
        port = self._port()
        url = f"socks5://{quote(login, safe='')}:{quote(password, safe='')}@{host}:{port}"
        return {
            "type": ProxyAccessType.SOCKS5.value,
            "host": host,
            "port": port,
            "login": login,
            "password": password,
            "url": url,
            "public_name": self.settings.socks5_public_name,
            "note": self.settings.socks5_note,
        }

    def _public_payload(self, login: str) -> dict[str, object]:
        return {
            "type": ProxyAccessType.SOCKS5.value,
            "host": self.settings.socks5_host,
            "port": self._port(),
            "login": login,
            "public_name": self.settings.socks5_public_name,
            "note": self.settings.socks5_note,
        }

    def _generate_password(self) -> str:
        return secrets.token_urlsafe(24)

    def _port(self) -> int:
        if self.settings.socks5_port is None:
            raise InvalidOperation("SOCKS5_PORT не настроен")
        return self.settings.socks5_port

    def _ensure_enabled(self) -> None:
        if not self.settings.socks5_enabled:
            raise InvalidOperation("SOCKS5 сейчас недоступен")
        if not self.settings.socks5_host or self.settings.socks5_port is None:
            raise InvalidOperation("SOCKS5 не настроен")

    async def _get_access(self, access_id: int) -> ProxyAccess:
        access = await self.accesses.get_by_id(access_id)
        if access is None:
            raise NotFound("Прокси-доступ не найден")
        return access

    async def _mark_shown(self, access: ProxyAccess, actor_user_id: int) -> None:
        await self.accesses.mark_shown(access.id, self.clock.now())
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="socks5_proxy_shown",
            entity_id=access.id,
            details={"owner_user_id": access.owner_user_id, "login": access.payload.get("login")},
        )

    async def _compensate_failed_create_after_apply(
        self,
        *,
        actor_user_id: int,
        access_id: int,
        owner_user_id: int,
        login: str,
        original_error: Exception,
    ) -> None:
        logger.critical(
            "SOCKS5 Linux user created, but DB mark_active failed for access_id=%s login=%s; attempting compensation",
            access_id,
            login,
            exc_info=True,
        )
        compensation_method = ""
        try:
            await self.adapter.delete_user(login)
            compensation_method = "delete_user"
        except Exception as delete_error:
            try:
                await self.adapter.lock_user(login)
                compensation_method = "lock_user"
            except Exception as lock_error:
                self.backend_health.mark_degraded(
                    ProxyAccessType.SOCKS5,
                    "post-apply mark_active failed and compensation failed",
                )
                logger.critical(
                    "SOCKS5 create compensation failed after DB mark_active failure for access_id=%s login=%s",
                    access_id,
                    login,
                    exc_info=True,
                )
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="socks5_create_compensation_failed",
                    entity_id=access_id,
                    details={
                        "owner_user_id": owner_user_id,
                        "login": login,
                        "original_error_type": type(original_error).__name__,
                        "delete_error_type": type(delete_error).__name__,
                        "lock_error_type": type(lock_error).__name__,
                        "backend_degraded": True,
                    },
                )
                return

        try:
            await self.accesses.set_status(
                access_id,
                ProxyAccessStatus.APPLY_FAILED,
                self.clock.now(),
                error="db mark_active failed after server-side apply; server-side SOCKS5 user was disabled",
            )
        except Exception:
            logger.warning(
                "SOCKS5 create compensation succeeded, but failed to mark access apply_failed access_id=%s",
                access_id,
                exc_info=True,
            )

        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="socks5_create_compensated_after_db_failure",
            entity_id=access_id,
            details={
                "owner_user_id": owner_user_id,
                "login": login,
                "compensation_method": compensation_method,
                "original_error_type": type(original_error).__name__,
            },
        )

    def _redact_value(self, text: str, value: str) -> str:
        return text.replace(value, "***") if value else text

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
