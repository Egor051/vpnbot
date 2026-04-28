from __future__ import annotations

import logging
from typing import Any
from datetime import timedelta

from adapters.clock import ClockProvider
from models.enums import AuditEntityType
from repositories.audit_log import AuditLogRepository

logger = logging.getLogger(__name__)


class AuditService:
    _SECRET_KEYS = {
        "private_key",
        "privatekey",
        "preshared_key",
        "presharedkey",
        "public_key",
        "publickey",
        "password",
        "token",
        "bot_token",
        "payload_json",
        "config",
        "link",
        "uuid",
        "short_id",
        "shortid",
        "privateKey",
        "publicKey",
        "shortId",
    }

    def __init__(self, audit_logs: AuditLogRepository, clock: ClockProvider) -> None:
        self.audit_logs = audit_logs
        self.clock = clock

    async def write(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_type: AuditEntityType,
        entity_id: str | int | None,
        details: dict[str, Any] | None = None,
    ) -> None:
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

    async def recent(self, limit: int = 20, offset: int = 0) -> list[dict[str, object]]:
        return await self.audit_logs.list_recent(limit=limit, offset=offset)

    async def prune_old_audit_logs(self, retention_days: int) -> int:
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
        if isinstance(value, str) and len(value) > 256:
            return value[:256] + "...[truncated]"
        return value

    def _is_secret_key(self, key: str) -> bool:
        normalized = key.strip().lower().replace("-", "_")
        return normalized in {item.lower().replace("-", "_") for item in self._SECRET_KEYS}
