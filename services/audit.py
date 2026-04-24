from __future__ import annotations

from typing import Any
from datetime import timedelta

from adapters.clock import ClockProvider
from models.enums import AuditEntityType
from repositories.audit_log import AuditLogRepository


class AuditService:
    _SECRET_KEYS = {
        "private_key",
        "preshared_key",
        "password",
        "token",
        "payload_json",
        "config",
        "link",
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
        clean: dict[str, Any] = {}
        for key, value in details.items():
            if key in self._SECRET_KEYS:
                clean[key] = "***"
            elif isinstance(value, str) and len(value) > 256:
                clean[key] = value[:256] + "...[truncated]"
            else:
                clean[key] = value
        return clean
