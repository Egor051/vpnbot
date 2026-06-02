
import logging
from typing import Any, ClassVar
from datetime import timedelta

from adapters.clock import ClockProvider
from models.enums import AuditEntityType, UserRole
from repositories.audit_log import AuditLogRepository
from repositories.users import UserRepository
from services.errors import AccessDenied
from utils.redact import redact_value

logger = logging.getLogger(__name__)


class AuditService:
    """Writes audit records with automatic redaction of secrets from details."""
    _SECRET_KEYS: ClassVar[set[str]] = {
        "private_key",
        "privatekey",
        "preshared_key",
        "presharedkey",
        "public_key",
        "publickey",
        "password",
        "secret",
        "secret_dd",
        "mtproto_secret",
        "token",
        "bot_token",
        "payload_json",
        "config",
        "link",
        "link_dd",
        "url",
        "uuid",
        "short_id",
        "shortid",
        "privateKey",
        "publicKey",
        "shortId",
    }

    def __init__(self, audit_logs: AuditLogRepository, clock: ClockProvider, users: UserRepository | None = None) -> None:
        self.audit_logs = audit_logs
        self.clock = clock
        self.users = users

    async def write(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_type: AuditEntityType,
        entity_id: str | int | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit record; raises on DB failure."""
        await self.audit_logs.create(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id is not None else None,
            details=self._sanitize(details or {}),
            now=self.clock.now(),
        )

    async def write_best_effort(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_type: AuditEntityType,
        entity_id: str | int | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Write an audit record; silently logs and swallows DB failures so they never interrupt business operations."""
        try:
            await self.write(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
            )
        except Exception:
            logger.exception(
                "Audit write failed after business operation: action=%s entity_type=%s entity_id=%s",
                action,
                entity_type.value,
                entity_id,
            )

    async def count_all(self, actor_user_id: int) -> int:
        """Return the total number of audit records; requires superadmin."""
        if self.users is None:
            raise RuntimeError("AuditService.count_all requires a UserRepository; pass users= to AuditService()")
        user = await self.users.get_by_id(actor_user_id)
        if user is None or user.role != UserRole.SUPERADMIN:
            raise AccessDenied("Недостаточно прав")
        return await self.audit_logs.count_all()

    async def recent(self, actor_user_id: int, limit: int = 20, offset: int = 0) -> list[dict[str, object]]:
        """Return recent audit log entries; raises AccessDenied if actor is not a superadmin."""
        if self.users is None:
            raise RuntimeError("AuditService.recent requires a UserRepository; pass users= to AuditService()")
        user = await self.users.get_by_id(actor_user_id)
        if user is None or user.role != UserRole.SUPERADMIN:
            raise AccessDenied("Недостаточно прав")
        return await self.audit_logs.list_recent(limit=limit, offset=offset)

    async def recent_for_entity(
        self,
        actor_user_id: int,
        *,
        entity_type: AuditEntityType,
        entity_id: str | int,
        actions: set[str] | None = None,
        limit: int = 10,
    ) -> list[dict[str, object]]:
        """Return recent audit log entries for a specific entity; requires superadmin."""
        if self.users is None:
            raise RuntimeError("AuditService.recent_for_entity requires a UserRepository; pass users= to AuditService()")
        user = await self.users.get_by_id(actor_user_id)
        if user is None or user.role != UserRole.SUPERADMIN:
            raise AccessDenied("Недостаточно прав")
        return await self.recent_for_entity_internal(
            entity_type=entity_type,
            entity_id=entity_id,
            actions=actions,
            limit=limit,
        )

    async def recent_for_entity_internal(
        self,
        *,
        entity_type: AuditEntityType,
        entity_id: str | int,
        actions: set[str] | None = None,
        limit: int = 10,
    ) -> list[dict[str, object]]:
        """Trusted server-side reader (no actor check). For internal service use only."""
        return await self.audit_logs.list_recent_for_entity(
            entity_type=entity_type,
            entity_id=entity_id,
            actions=actions,
            limit=limit,
        )

    async def prune_old_audit_logs(self, retention_days: int) -> int:
        """Delete audit records older than retention_days; no-op if retention_days <= 0."""
        if retention_days <= 0:
            return 0
        from datetime import datetime, timezone

        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).replace(microsecond=0).isoformat()
        removed = await self.audit_logs.prune_older_than(cutoff)
        if removed:
            await self.write(
                actor_user_id=None,
                action="audit_pruned",
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details={"removed": removed, "retention_days": retention_days},
            )
        return removed

    def _sanitize(self, details: dict[str, Any]) -> dict[str, Any]:
        value = self._sanitize_value(details)
        return value if isinstance(value, dict) else {}

    def _sanitize_value(self, value: Any, key: str | None = None) -> Any:
        if key is not None and self._is_secret_key(key):
            return "***"
        if isinstance(value, dict):
            return {str(item_key): self._sanitize_value(item_value, str(item_key)) for item_key, item_value in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._sanitize_value(item) for item in value]
        if isinstance(value, str):
            if len(value) > 256:
                value = value[:256] + "...[truncated]"
            value = redact_value(value)
        return value

    def _is_secret_key(self, key: str) -> bool:
        normalized = key.strip().lower().replace("-", "_")
        return normalized in {item.lower().replace("-", "_") for item in self._SECRET_KEYS}
