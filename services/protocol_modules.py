
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from db.database import Database
from models.enums import (
    AuditEntityType,
    ProxyAccessStatus,
    ProxyAccessType,
    VpnKeyStatus,
    VpnKeyType,
)
from repositories.protocol_modules import ProtocolModule, ProtocolModulesRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.vpn_keys import VpnKeyRepository
from services.errors import InvalidOperation

logger = logging.getLogger(__name__)

_VPN_KEY_TYPES = {"xray", "awg", "hysteria2"}
_PROXY_TYPES = {"socks5", "mtproto"}

# Purger contracts: each removes the backend artefact (Xray client / AWG peer /
# Dante user / MTProto secret) AND hard-deletes the DB row. On backend failure
# they raise and leave the row in a *_FAILED state, so disabling never silently
# orphans live access.
KeyPurger = Callable[[int, int], Awaitable[object]]
ProxyPurger = Callable[[int, int, str | None], Awaitable[object]]


class ProtocolModulesService:
    def __init__(self, repo: ProtocolModulesRepository, db: Database) -> None:
        self._repo = repo
        self._db = db
        self._users: object | None = None
        self._audit: object | None = None
        self._vpn_keys_repo: VpnKeyRepository | None = None
        self._proxy_accesses_repo: ProxyAccessRepository | None = None
        self._key_purgers: dict[VpnKeyType, KeyPurger] = {}
        self._proxy_purgers: dict[ProxyAccessType, ProxyPurger] = {}

    def attach_purge_handlers(
        self,
        *,
        users: object,
        audit: object,
        vpn_keys: VpnKeyRepository,
        proxy_accesses: ProxyAccessRepository,
        key_purgers: dict[VpnKeyType, KeyPurger],
        proxy_purgers: dict[ProxyAccessType, ProxyPurger],
    ) -> None:
        """Wire in RBAC, audit, repositories and per-protocol purgers.

        Called after the protocol services exist (they are constructed later than
        this service), mirroring UserService.attach_key_management.
        """
        self._users = users
        self._audit = audit
        self._vpn_keys_repo = vpn_keys
        self._proxy_accesses_repo = proxy_accesses
        self._key_purgers = dict(key_purgers)
        self._proxy_purgers = dict(proxy_purgers)

    async def get_all(self) -> list[ProtocolModule]:
        return await self._repo.get_all()

    async def is_enabled(self, name: str) -> bool:
        return await self._repo.is_enabled(name)

    async def disable_protocol(self, name: str, actor_id: int) -> int:
        """Disable a protocol: revoke all backend access, hard-delete the DB rows,
        then mark the module disabled.

        Returns the number of records fully purged. Records whose backend removal
        failed are left in a *_FAILED state (not orphaned) and reported via audit.
        """
        await self._require_superadmin(actor_id)
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        deleted = 0
        failed = 0
        if name in _VPN_KEY_TYPES:
            deleted, failed = await self._purge_vpn_keys(name, actor_id)
        elif name in _PROXY_TYPES:
            deleted, failed = await self._purge_proxy_accesses(name, actor_id)
        await self._repo.set_enabled(name, enabled=False, disabled_by=actor_id, disabled_at=now)
        await self._write_audit(
            actor_id,
            "protocol_disabled",
            {"protocol": name, "deleted": deleted, "failed": failed},
        )
        logger.info(
            "Protocol %s disabled by user %d; %d records purged, %d failed",
            name, actor_id, deleted, failed,
        )
        return deleted

    async def enable_protocol(self, name: str, actor_id: int) -> None:
        await self._require_superadmin(actor_id)
        await self._repo.set_enabled(name, enabled=True)
        await self._write_audit(actor_id, "protocol_enabled", {"protocol": name})
        logger.info("Protocol %s enabled by user %d", name, actor_id)

    async def _require_superadmin(self, actor_id: int) -> None:
        users = self._users
        if users is None:
            # Fail closed: without the RBAC dependency wired we cannot verify the
            # actor, so refuse rather than silently authorising enable/disable.
            raise InvalidOperation("Protocol RBAC не подключён")
        require = getattr(users, "require_superadmin", None)
        if require is not None:
            await require(actor_id)

    async def _purge_vpn_keys(self, name: str, actor_id: int) -> tuple[int, int]:
        key_type = VpnKeyType(name)
        purger = self._key_purgers.get(key_type)
        repo = self._vpn_keys_repo
        if repo is None or purger is None:
            raise InvalidOperation(
                "Очистка протокола не подключена: невозможно безопасно отозвать доступ на бэкенде."
            )
        statuses: set[VpnKeyStatus] = set(VpnKeyStatus)
        statuses.discard(VpnKeyStatus.DELETED)
        # Collect ids up-front so deletions don't disturb keyset pagination.
        ids: list[int] = []
        after_id = 0
        while True:
            batch = await repo.list_by_type_statuses(key_type, statuses, limit=500, after_id=after_id)
            if not batch:
                break
            ids.extend(key.id for key in batch)
            after_id = batch[-1].id
        deleted = 0
        failed = 0
        for key_id in ids:
            try:
                await purger(actor_id, key_id)
                deleted += 1
            except Exception:
                failed += 1
                logger.warning(
                    "Protocol disable: failed to purge %s key id=%s (left for retry)",
                    name, key_id, exc_info=True,
                )
        return deleted, failed

    async def _purge_proxy_accesses(self, name: str, actor_id: int) -> tuple[int, int]:
        access_type = ProxyAccessType(name)
        purger = self._proxy_purgers.get(access_type)
        repo = self._proxy_accesses_repo
        if repo is None or purger is None:
            raise InvalidOperation(
                "Очистка протокола не подключена: невозможно безопасно отозвать доступ на бэкенде."
            )
        statuses: set[ProxyAccessStatus] = set(ProxyAccessStatus)
        statuses.discard(ProxyAccessStatus.DELETED)
        ids: list[int] = []
        after_id = 0
        while True:
            batch = await repo.list_by_type_statuses(access_type, statuses, limit=500, after_id=after_id)
            if not batch:
                break
            ids.extend(access.id for access in batch)
            after_id = batch[-1].id
        deleted = 0
        failed = 0
        for access_id in ids:
            try:
                await purger(actor_id, access_id, "protocol_disabled")
                deleted += 1
            except Exception:
                failed += 1
                logger.warning(
                    "Protocol disable: failed to purge %s access id=%s (left for retry)",
                    name, access_id, exc_info=True,
                )
        return deleted, failed

    async def _write_audit(self, actor_id: int, action: str, details: dict[str, object]) -> None:
        audit = self._audit
        if audit is None:
            return
        writer = getattr(audit, "write_best_effort", None) or getattr(audit, "write", None)
        if writer is None:
            return
        try:
            await writer(
                actor_user_id=actor_id,
                action=action,
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details=details,
            )
        except Exception:
            logger.warning("Audit write failed for protocol action=%s", action, exc_info=True)
