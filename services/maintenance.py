"""Global maintenance-mode service.

Combines two established patterns:

* an in-memory snapshot (like ``ServerStatusService``) so the request gate
  (``MaintenanceModeMiddleware``) can check the flag on every update without
  touching the database;
* a thin RBAC + audit wrapper (like ``ProtocolModulesService``) so enabling /
  disabling maintenance requires superadmin and is recorded in the audit log.

The persisted row is the source of truth across restarts; ``load()`` restores
the in-memory snapshot at startup.
"""

from __future__ import annotations

import logging

from i18n import t
from models.enums import AuditEntityType
from repositories.maintenance_settings import MaintenanceSettingsRepository, MaintenanceState
from services.audit import AuditService
from services.users import UserService
from utils.formatting import h

logger = logging.getLogger(__name__)


class MaintenanceService:
    def __init__(
        self,
        repo: MaintenanceSettingsRepository,
        users: UserService,
        audit: AuditService,
    ) -> None:
        self._repo = repo
        self._users = users
        self._audit = audit
        self._state = MaintenanceState(enabled=False, message=None, started_at=0, started_by=None)

    async def load(self) -> None:
        """Restore the in-memory snapshot from the database (call at startup)."""
        self._state = await self._repo.get()

    def is_enabled(self) -> bool:
        """Cheap, synchronous check used by the request gate on every update."""
        return self._state.enabled

    def snapshot(self) -> MaintenanceState:
        return self._state

    def banner_text(self) -> str:
        """Banner shown to non-admin users: the custom message or the default.

        The whole bot sends with ``ParseMode.HTML``, so the admin-typed custom
        message is HTML-escaped here (the single choke point through which the
        banner reaches every HTML-rendered surface: the request gate, the on/off
        broadcasts and the admin panel). Otherwise a ``<`` or ``&`` in the text
        would make Telegram reject the message and silently fail delivery.
        """
        message = self._state.message
        if message:
            return h(message)
        return t("maintenance_default_banner")

    async def enable(self, actor_id: int, message: str | None) -> None:
        await self._users.require_superadmin(actor_id)
        clean = message.strip() if message else None
        await self._repo.set_state(enabled=True, message=clean or None, started_by=actor_id)
        self._state = await self._repo.get()
        await self._audit.write_best_effort(
            actor_user_id=actor_id,
            action="maintenance_enabled",
            entity_type=AuditEntityType.SYSTEM,
            entity_id=None,
            details={"has_custom_message": clean is not None},
        )
        logger.info("Maintenance mode enabled by user %d", actor_id)

    async def disable(self, actor_id: int) -> None:
        await self._users.require_superadmin(actor_id)
        await self._repo.set_state(enabled=False, message=None, started_by=actor_id)
        self._state = await self._repo.get()
        await self._audit.write_best_effort(
            actor_user_id=actor_id,
            action="maintenance_disabled",
            entity_type=AuditEntityType.SYSTEM,
            entity_id=None,
            details={},
        )
        logger.info("Maintenance mode disabled by user %d", actor_id)
