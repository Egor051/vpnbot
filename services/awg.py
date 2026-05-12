
import asyncio
import base64
import binascii
import hashlib
import ipaddress
import logging
import re

from adapters.awg_config import AwgConfigAdapter
from adapters.clock import ClockProvider
from adapters.id_generator import IdGenerator
from adapters.ip_allocator import IpAllocator
from config.settings import Settings
from models.dto import TelegramUserProfile, VpnKey, VpnKeyCreateResult
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from bot.formatters import key_note_for_viewer, status_text
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.notes import normalize_note
from services.user_locks import UserLockManager
from services.users import UserService
from utils.formatting import h, pre

logger = logging.getLogger(__name__)

AWG_ACCESS_MAY_EXIST_STATUSES = {
    VpnKeyStatus.ACTIVE,
    VpnKeyStatus.PENDING_APPLY,
    VpnKeyStatus.APPLY_FAILED,
    VpnKeyStatus.PENDING_REVOKE,
    VpnKeyStatus.PENDING_DELETE,
    VpnKeyStatus.DELETE_FAILED,
}

AWG_STARTUP_RECONCILE_STATUSES = {
    VpnKeyStatus.PENDING_APPLY,
    VpnKeyStatus.APPLY_FAILED,
    VpnKeyStatus.PENDING_REVOKE,
    VpnKeyStatus.PENDING_DELETE,
    VpnKeyStatus.DELETE_FAILED,
}

AWG_ACTIVE_STATUSES: set[VpnKeyStatus] = {VpnKeyStatus.ACTIVE}
AWG_ALL_STATUSES: set[VpnKeyStatus] = set(VpnKeyStatus)
AWG_MANAGED_LABEL_RE = re.compile(r"^awg_[A-Za-z0-9]{5}$")


class AwgService:
    def __init__(
        self,
        *,
        vpn_keys: VpnKeyRepository,
        users: UserService,
        adapter: AwgConfigAdapter,
        ip_allocator: IpAllocator,
        settings: Settings,
        clock: ClockProvider,
        ids: IdGenerator,
        audit: AuditService,
        user_locks: UserLockManager | None = None,
        backend_health: BackendHealth | None = None,
    ) -> None:
        self.vpn_keys = vpn_keys
        self.users = users
        self.adapter = adapter
        self.ip_allocator = ip_allocator
        self.settings = settings
        self.clock = clock
        self.ids = ids
        self.audit = audit
        self.user_locks: UserLockManager = user_locks if user_locks is not None else getattr(users, "user_locks", UserLockManager())
        self.backend_health = backend_health or BackendHealth()
        self._lock = asyncio.Lock()

    async def create_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        return await self.create_awg_key(actor_user_id, owner, note)

    async def create_awg_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        self.backend_health.require_mutation_allowed(VpnKeyType.AWG)
        self.settings.validate_awg_ready()
        self._ensure_ipv4_network()
        clean_note = normalize_note(note)

        async with self.user_locks.lock(owner.telegram_user_id):
            await self._ensure_can_create(actor_user_id, owner.telegram_user_id)
            async with self._lock:
                await self._ensure_can_create(actor_user_id, owner.telegram_user_id)
                server_config = self.adapter.read_server_config()
                self._ensure_server_address_matches_config(server_config)
                self._server_public_key(server_config.public_key)
                self._endpoint_port(server_config.listen_port)
                client_ip = await self.ip_allocator.next_free_ip()
                private_key, public_key = await self._generate_unique_keypair()
                email_label = await self._generate_unique_label(owner.telegram_user_id, owner.username)
                preshared_key = await self.adapter.generate_preshared_key() if self.settings.awg_use_preshared_key else None
                payload = {
                    "private_key": private_key,
                    "public_key": public_key,
                    "preshared_key": preshared_key,
                    "client_ip": client_ip,
                    "email_label": email_label,
                }
                public_payload = {
                    "public_key": public_key,
                    "client_ip": client_ip,
                    "endpoint": f"{self.settings.awg_endpoint_host}:{self._endpoint_port(server_config.listen_port)}",
                    "email_label": email_label,
                }
                key = await self.vpn_keys.create_pending(
                    owner_user_id=owner.telegram_user_id,
                    username=owner.username,
                    key_type=VpnKeyType.AWG,
                    note=clean_note,
                    payload=payload,
                    public_payload=public_payload,
                    created_by=actor_user_id,
                    now=self.clock.now(),
                    email_label=email_label,
                    public_key=public_key,
                    client_ip=client_ip,
                )
                try:
                    await self._ensure_can_create(actor_user_id, owner.telegram_user_id)
                    await self.adapter.add_peer(
                        key_id=key.id,
                        owner_user_id=owner.telegram_user_id,
                        public_key=public_key,
                        preshared_key=preshared_key,
                        client_ip=client_ip,
                        label=email_label,
                    )
                except Exception as exc:
                    await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
                    await self._write_audit_best_effort(
                        actor_user_id=actor_user_id,
                        action="awg_create_failed",
                        entity_type=AuditEntityType.VPN_KEY,
                        entity_id=key.id,
                        details={"owner_user_id": owner.telegram_user_id, "client_ip": client_ip, "error": str(exc)},
                    )
                    raise

                try:
                    await self.vpn_keys.mark_active(key.id, self.clock.now(), payload=payload, public_payload=public_payload)
                except Exception as exc:
                    await self._compensate_failed_create_after_apply(
                        actor_user_id=actor_user_id,
                        key_id=key.id,
                        owner_user_id=owner.telegram_user_id,
                        public_key=public_key,
                        client_ip=client_ip,
                        original_error=exc,
                    )
                    raise
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="awg_key_created",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={
                        "owner_user_id": owner.telegram_user_id,
                        "owner_username": owner.username,
                        "client_ip": client_ip,
                        "label": email_label,
                    },
                )
                active_key = await self._get_key(key.id)
                return VpnKeyCreateResult(key=active_key, config_text=self._format_config(active_key, viewer_user_id=actor_user_id))

    async def revoke_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        return await self.revoke_awg_key(actor_user_id, key_id)

    async def revoke_awg_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        self.backend_health.require_mutation_allowed(VpnKeyType.AWG)
        async with self._lock:
            key = await self._get_awg_key_for_manage(actor_user_id, key_id)
            if key.status == VpnKeyStatus.REVOKED:
                return key
            if key.status == VpnKeyStatus.DELETED:
                return key
            if key.status not in AWG_ACCESS_MAY_EXIST_STATUSES:
                raise InvalidOperation("Отозвать можно только активный AWG-ключ")
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_REVOKE, self.clock.now())
            try:
                await self._remove_awg_access(key)
            except Exception:
                await self.vpn_keys.set_status(key_id, previous_status, self.clock.now())
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="awg_revoke_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={"client_ip": key.client_ip},
                )
                raise
            await self.vpn_keys.mark_revoked(key_id, actor_user_id, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="awg_key_revoked",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"client_ip": key.client_ip},
            )
            return await self._get_key(key_id)

    async def delete_key(self, actor_user_id: int, key_id: int) -> None:
        await self.delete_awg_key(actor_user_id, key_id)

    async def delete_awg_key(self, actor_user_id: int, key_id: int) -> None:
        self.backend_health.require_mutation_allowed(VpnKeyType.AWG)
        async with self._lock:
            key = await self._get_awg_key_for_manage(actor_user_id, key_id)
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_DELETE, self.clock.now())
            try:
                if previous_status in AWG_ACCESS_MAY_EXIST_STATUSES:
                    await self._remove_awg_access(key)
            except Exception as exc:
                await self.vpn_keys.set_status(key_id, VpnKeyStatus.DELETE_FAILED, self.clock.now())
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="awg_delete_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={"previous_status": previous_status.value, "client_ip": key.client_ip, "error": str(exc)},
                )
                raise
            await self.vpn_keys.hard_delete_with_stats(key_id)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="awg_key_hard_deleted",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"owner_user_id": key.owner_user_id, "previous_status": previous_status.value, "client_ip": key.client_ip},
            )

    async def startup_reconcile(self) -> dict[str, int]:
        summary = {"checked": 0, "recovered": 0, "failed": 0}
        async with self._lock:
            last_id = 0
            while True:
                keys = await self.vpn_keys.list_by_type_statuses(
                    VpnKeyType.AWG,
                    AWG_STARTUP_RECONCILE_STATUSES,
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
                        logger.warning("Не удалось восстановить AWG-ключ key_id=%s: %s", key.id, exc, exc_info=True)
                        await self._write_startup_reconcile_failure_audit(key, exc)

            if summary["failed"] == 0:
                drift_summary = await self._startup_reconcile_drift()
                for drift_key, drift_val in drift_summary.items():
                    summary[drift_key] += drift_val
        return summary

    async def get_config(self, actor_user_id: int, key_id: int) -> str:
        return await self.get_awg_client_config(actor_user_id, key_id)

    async def get_awg_client_config(self, actor_user_id: int, key_id: int) -> str:
        key = await self._get_awg_key_for_manage(actor_user_id, key_id, allow_read=True)
        if key.status != VpnKeyStatus.ACTIVE:
            raise InvalidOperation("Конфигурация доступна только для активного ключа")
        await self._ensure_client_payload_valid(actor_user_id, key)
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="awg_config_shown",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"client_ip": key.client_ip},
        )
        return self._format_config(key, viewer_user_id=actor_user_id)

    async def get_awg_client_config_plain(self, actor_user_id: int, key_id: int, audit: bool = True) -> str:
        key = await self._get_awg_key_for_manage(actor_user_id, key_id, allow_read=True)
        if key.status != VpnKeyStatus.ACTIVE:
            raise InvalidOperation("Конфигурация доступна только для активного ключа")
        await self._ensure_client_payload_valid(actor_user_id, key)
        if audit:
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="awg_config_file_shown",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"client_ip": key.client_ip},
            )
        return self._client_config(key)

    async def list_user_keys(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        return await self.list_user_awg_keys(actor_user_id, owner_user_id, limit=limit, offset=offset)

    async def list_user_awg_keys(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи")
        return await self.vpn_keys.list_by_owner_and_type(target, VpnKeyType.AWG, limit=limit, offset=offset)

    async def update_awg_note(self, actor_user_id: int, key_id: int, note: str | None) -> VpnKey:
        key = await self._get_awg_key_for_manage(actor_user_id, key_id, allow_read=True)
        if key.owner_user_id != actor_user_id:
            raise AccessDenied("Можно менять заметку только своих ключей")
        clean_note = normalize_note(note)
        await self.vpn_keys.update_note(key.id, clean_note, self.clock.now())
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="awg_note_updated",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"client_ip": key.client_ip},
        )
        return await self._get_key(key_id)

    async def reconcile_key_status(self, actor_user_id: int, key_id: int) -> VpnKey:
        await self.users.require_superadmin(actor_user_id)
        self.backend_health.require_mutation_allowed(VpnKeyType.AWG)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.AWG:
            raise InvalidOperation("Это не AWG-ключ")
        public_key = self._stored_awg_public_key(key)
        peer = self.adapter.find_peer(public_key=public_key, client_ip=None) if public_key else None
        if peer is not None and key.status in {VpnKeyStatus.PENDING_APPLY, VpnKeyStatus.APPLY_FAILED}:
            await self.vpn_keys.mark_active(key.id, self.clock.now())
        elif peer is None and key.status == VpnKeyStatus.PENDING_APPLY:
            await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="awg_key_reconciled",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"peer_present": peer is not None, "client_ip": key.client_ip},
        )
        return await self._get_key(key_id)

    async def _ensure_can_create(self, actor_user_id: int, owner_user_id: int) -> None:
        owner = await self.users.require_approved_or_admin(owner_user_id)
        actor = await self.users.require_approved_or_admin(actor_user_id)
        if actor.role != UserRole.SUPERADMIN and actor_user_id != owner_user_id:
            raise AccessDenied("Нельзя создавать ключи для другого пользователя")
        if owner.role not in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
            raise AccessDenied("Владелец ключа не имеет доступа")

    async def _get_awg_key_for_manage(self, actor_user_id: int, key_id: int, allow_read: bool = False) -> VpnKey:
        actor = None if not allow_read else await self.users.require_approved_or_admin(actor_user_id)
        if not allow_read:
            await self.users.require_superadmin(actor_user_id)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.AWG:
            raise InvalidOperation("Это не AWG-ключ")
        if actor is not None and actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
            raise AccessDenied("Нельзя управлять чужим ключом")
        return key

    async def _get_key(self, key_id: int) -> VpnKey:
        key = await self.vpn_keys.get_by_id(key_id)
        if key is None:
            raise NotFound("Ключ не найден")
        return key

    async def _generate_unique_keypair(self) -> tuple[str, str]:
        for _ in range(3):
            private_key = await self.adapter.generate_private_key()
            public_key = await self.adapter.generate_public_key(private_key)
            if await self.vpn_keys.find_by_public_key(public_key) is None:
                return private_key, public_key
        raise InvalidOperation("Не удалось сгенерировать уникальный AWG public key")

    async def _generate_unique_label(self, telegram_user_id: int, username: str | None) -> str:
        for _ in range(5):
            label = self.ids.generated_key_name("awg")
            if await self.vpn_keys.find_by_email_label(label) is None:
                return label
        raise InvalidOperation("Не удалось сгенерировать уникальный label для AWG-ключа")

    async def _remove_awg_access(self, key: VpnKey) -> None:
        public_key = self._stored_awg_public_key(key)
        if not public_key:
            public_key = self._managed_awg_public_key(key)
        if not public_key:
            raise InvalidOperation(
                "Нельзя безопасно удалить AWG peer: в БД нет public key, "
                "и восстановить его из managed block не удалось."
            )
        await self.adapter.remove_peer(key_id=key.id, public_key=public_key)

    async def _compensate_failed_create_after_apply(
        self,
        *,
        actor_user_id: int,
        key_id: int,
        owner_user_id: int,
        public_key: str,
        client_ip: str,
        original_error: Exception,
    ) -> None:
        logger.critical(
            "AWG peer applied, but DB mark_active failed for key_id=%s; attempting compensation",
            key_id,
            exc_info=True,
        )
        try:
            await self.adapter.remove_peer(key_id=key_id, public_key=public_key)
        except Exception as compensation_error:
            self.backend_health.mark_degraded(VpnKeyType.AWG, "post-apply mark_active failed and compensation failed")
            logger.critical(
                "AWG create compensation failed after DB mark_active failure for key_id=%s",
                key_id,
                exc_info=True,
            )
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="awg_create_compensation_failed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={
                    "owner_user_id": owner_user_id,
                    "client_ip": client_ip,
                    "original_error_type": type(original_error).__name__,
                    "compensation_error_type": type(compensation_error).__name__,
                    "backend_degraded": True,
                },
            )
            return

        try:
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
        except Exception:
            logger.warning("AWG create compensation succeeded, but failed to mark key apply_failed key_id=%s", key_id, exc_info=True)
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="awg_create_compensated_after_db_failure",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={
                "owner_user_id": owner_user_id,
                "client_ip": client_ip,
                "original_error_type": type(original_error).__name__,
            },
        )

    async def _startup_reconcile_drift(self) -> dict[str, int]:
        summary = {"checked": 0, "recovered": 0, "failed": 0}
        if not self._awg_drift_reconcile_supported():
            return summary
        try:
            active_keys = await self._list_awg_keys_by_statuses(AWG_ACTIVE_STATUSES)
            all_keys = await self._list_awg_keys_by_statuses(AWG_ALL_STATUSES)
            config_peers = self.adapter.list_config_peers()
            runtime_peers = await self._list_runtime_peers()
            summary["checked"] = len(active_keys) + len(config_peers) + len(runtime_peers)

            summary["recovered"] += await self._remove_non_live_awg_peers(all_keys, runtime_peers)
            config_peers = self.adapter.list_config_peers()
            orphan_result = await self._remove_or_degrade_awg_config_orphans(config_peers, active_keys)
            summary["recovered"] += orphan_result["recovered"]
            summary["failed"] += orphan_result["failed"]
            if orphan_result["failed"]:
                return summary

            runtime_peers = await self._list_runtime_peers()
            summary["recovered"] += await self._restore_or_sync_active_awg_peers(active_keys, runtime_peers)
            runtime_peers = await self._list_runtime_peers()
            runtime_result = await self._remove_or_degrade_awg_runtime_orphans(runtime_peers, active_keys)
            summary["recovered"] += runtime_result["recovered"]
            summary["failed"] += runtime_result["failed"]
        except Exception as exc:
            summary["failed"] += 1
            await self._mark_awg_degraded(
                "startup drift reconciliation failed",
                details={"error_type": type(exc).__name__},
            )
        return summary

    def _awg_drift_reconcile_supported(self) -> bool:
        required_adapter = ("list_config_peers", "find_peer", "add_peer", "remove_peer", "list_runtime_peers")
        required_repo = ("list_by_type_statuses", "find_by_public_key", "find_by_client_ip")
        return all(hasattr(self.adapter, name) for name in required_adapter) and all(
            hasattr(self.vpn_keys, name) for name in required_repo
        )

    async def _list_awg_keys_by_statuses(self, statuses: set[VpnKeyStatus]) -> list[VpnKey]:
        keys: list[VpnKey] = []
        last_id = 0
        while True:
            batch = await self.vpn_keys.list_by_type_statuses(
                VpnKeyType.AWG,
                statuses,
                limit=500,
                after_id=last_id,
            )
            if not batch:
                break
            keys.extend(batch)
            last_id = batch[-1].id
        return keys

    async def _list_runtime_peers(self) -> list[dict[str, str]]:
        return await self.adapter.list_runtime_peers()

    async def _remove_non_live_awg_peers(self, keys: list[VpnKey], runtime_peers: list[dict[str, str]]) -> int:
        recovered = 0
        runtime_public_keys = self._runtime_public_keys(runtime_peers)
        for key in keys:
            if key.status == VpnKeyStatus.ACTIVE:
                continue
            public_key, client_ip, _ = self._awg_restore_values(key, require_private=False)
            safe_public_key = public_key or self._managed_awg_public_key(key)
            if not safe_public_key:
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="awg_startup_non_live_skipped_missing_public_key",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={"previous_status": key.status.value, "client_ip": client_ip},
                )
                continue
            config_peer = self.adapter.find_peer(public_key=safe_public_key, client_ip=None)
            runtime_peer = self._runtime_peer_for_identity(runtime_peers, public_key=safe_public_key, client_ip="")
            runtime_present = runtime_peer is not None or safe_public_key in runtime_public_keys
            if config_peer is None and not runtime_present:
                continue
            await self._remove_awg_access_for_reconcile(key, fallback_public_key=safe_public_key)
            recovered += 1
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="awg_startup_non_live_removed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"previous_status": key.status.value, "client_ip": client_ip},
            )
        return recovered

    def _stored_awg_public_key(self, key: VpnKey) -> str:
        return str(key.payload.get("public_key") or key.public_key or "").strip()

    def _managed_awg_public_key(self, key: VpnKey) -> str:
        finder = getattr(self.adapter, "find_managed_peer_public_key", None)
        if finder is None:
            return ""
        return str(finder(key.id) or "").strip()

    async def _restore_or_sync_active_awg_peers(self, active_keys: list[VpnKey], runtime_peers: list[dict[str, str]]) -> int:
        recovered = 0
        runtime_public_keys = self._runtime_public_keys(runtime_peers)
        for key in active_keys:
            public_key, client_ip, preshared_key = self._awg_restore_values(key, require_private=False)
            if not public_key or not client_ip:
                raise InvalidOperation("AWG active key cannot be restored: missing public key or client IP in DB")
            config_peer = self.adapter.find_peer(public_key=public_key, client_ip=client_ip)
            runtime_present = public_key in runtime_public_keys
            if config_peer is None:
                await self.adapter.add_peer(
                    key_id=key.id,
                    owner_user_id=key.owner_user_id,
                    public_key=public_key,
                    preshared_key=preshared_key,
                    client_ip=client_ip,
                    label=key.email_label,
                )
                recovered += 1
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="awg_startup_active_restored",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={"config_peer_present": False, "runtime_peer_present": runtime_present, "client_ip": client_ip},
                )
                runtime_public_keys.add(public_key)
                continue

            if not runtime_present:
                await self.adapter.sync_runtime_from_config()
                if not await self.adapter.verify_runtime_peer(public_key):
                    raise InvalidOperation("AWG runtime sync completed but active peer is still missing")
                recovered += 1
                runtime_public_keys.add(public_key)
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="awg_startup_runtime_synced",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={"config_peer_present": True, "runtime_peer_present": False, "client_ip": client_ip},
                )
        return recovered

    async def _remove_or_degrade_awg_config_orphans(
        self,
        config_peers: list[dict[str, str]],
        active_keys: list[VpnKey],
    ) -> dict[str, int]:
        recovered = 0
        active_identities = self._awg_active_identities(active_keys)
        for peer in config_peers:
            public_key = str(peer.get("PublicKey") or "").strip()
            client_ip = self._client_ip_from_peer(peer)
            if self._awg_peer_owned_by_active_key(public_key, client_ip, active_identities):
                continue

            historical = await self._find_awg_historical_owner(public_key, client_ip)
            if historical is not None:
                if historical.status == VpnKeyStatus.ACTIVE:
                    continue
                await self._remove_awg_access_for_reconcile(historical, fallback_public_key=public_key)
                recovered += 1
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="awg_startup_orphan_removed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=historical.id,
                    details={"historical_status": historical.status.value, "client_ip": client_ip},
                )
                continue

            managed_key_id = self._managed_key_id_from_peer(peer)
            managed_label = str(peer.get("_managed_label") or "").strip()
            if managed_key_id is not None or AWG_MANAGED_LABEL_RE.fullmatch(managed_label):
                if not public_key:
                    await self._mark_awg_degraded(
                        "bot-managed orphan AWG config peer has no public key",
                        details={"client_ip": client_ip},
                    )
                    return {"recovered": recovered, "failed": 1}
                await self.adapter.remove_peer(key_id=managed_key_id or 0, public_key=public_key)
                recovered += 1
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="awg_startup_orphan_removed",
                    entity_type=AuditEntityType.SYSTEM,
                    entity_id=None,
                    details={
                        "managed_block": managed_key_id is not None,
                        "managed_label": bool(AWG_MANAGED_LABEL_RE.fullmatch(managed_label)),
                        "public_key_fingerprint": self._fingerprint(public_key),
                        "client_ip": client_ip,
                    },
                )
                continue

            await self._mark_awg_degraded(
                "ambiguous orphan AWG config peer",
                details={
                    "public_key_fingerprint": self._fingerprint(public_key),
                    "client_ip": client_ip,
                    "managed_block": False,
                },
            )
            return {"recovered": recovered, "failed": 1}
        return {"recovered": recovered, "failed": 0}

    async def _remove_or_degrade_awg_runtime_orphans(
        self,
        runtime_peers: list[dict[str, str]],
        active_keys: list[VpnKey],
    ) -> dict[str, int]:
        recovered = 0
        active_public_keys, _ = self._awg_active_identities(active_keys)
        config_public_keys = {str(peer.get("PublicKey") or "").strip() for peer in self.adapter.list_config_peers()}
        for peer in runtime_peers:
            public_key = str(peer.get("PublicKey") or "").strip()
            if not public_key or public_key in active_public_keys:
                continue
            if public_key in config_public_keys:
                continue

            historical = await self._find_awg_historical_owner(public_key, "")
            if historical is not None and historical.status != VpnKeyStatus.ACTIVE:
                await self._remove_awg_access_for_reconcile(historical, fallback_public_key=public_key)
                recovered += 1
                await self._write_audit_best_effort(
                    actor_user_id=None,
                    action="awg_startup_runtime_orphan_removed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=historical.id,
                    details={
                        "historical_status": historical.status.value,
                        "public_key_fingerprint": self._fingerprint(public_key),
                    },
                )
                continue

            await self._mark_awg_degraded(
                "ambiguous orphan AWG runtime peer",
                details={"public_key_fingerprint": self._fingerprint(public_key)},
            )
            return {"recovered": recovered, "failed": 1}
        return {"recovered": recovered, "failed": 0}

    def _awg_restore_values(
        self,
        key: VpnKey,
        *,
        require_private: bool = True,
    ) -> tuple[str, str, str | None]:
        public_key = str(key.payload.get("public_key") or key.public_key or "").strip()
        client_ip = str(key.payload.get("client_ip") or key.client_ip or "").strip()
        preshared_key_raw = key.payload.get("preshared_key")
        preshared_key = str(preshared_key_raw).strip() if preshared_key_raw else None
        if require_private:
            self._required_private_key(key)
            if not public_key or not client_ip:
                raise InvalidOperation("AWG key cannot be restored: missing public key or client IP in DB")
            self._required_client_ip(key)
        elif client_ip:
            self._required_client_ip(key)
        elif not public_key:
            raise InvalidOperation("AWG key cannot be reconciled: missing public key and client IP in DB")
        return public_key, client_ip, preshared_key

    def _runtime_public_keys(self, runtime_peers: list[dict[str, str]]) -> set[str]:
        return {str(peer.get("PublicKey") or "").strip() for peer in runtime_peers if peer.get("PublicKey")}

    def _runtime_peer_for_identity(
        self,
        runtime_peers: list[dict[str, str]],
        *,
        public_key: str,
        client_ip: str,
    ) -> dict[str, str] | None:
        for peer in runtime_peers:
            peer_public_key = str(peer.get("PublicKey") or "").strip()
            if public_key and peer_public_key == public_key:
                return peer
            if client_ip and self._client_ip_from_peer(peer) == client_ip:
                return peer
        return None

    def _awg_active_identities(self, active_keys: list[VpnKey]) -> tuple[set[str], set[str]]:
        public_keys = {str(key.payload.get("public_key") or key.public_key or "").strip() for key in active_keys}
        client_ips = {str(key.payload.get("client_ip") or key.client_ip or "").strip() for key in active_keys}
        return {value for value in public_keys if value}, {value for value in client_ips if value}

    def _awg_peer_owned_by_active_key(
        self,
        public_key: str,
        client_ip: str,
        active_identities: tuple[set[str], set[str]],
    ) -> bool:
        active_public_keys, active_client_ips = active_identities
        return bool((public_key and public_key in active_public_keys) or (client_ip and client_ip in active_client_ips))

    async def _find_awg_historical_owner(self, public_key: str, client_ip: str) -> VpnKey | None:
        key = await self.vpn_keys.find_by_public_key(public_key) if public_key else None
        if key is None and client_ip:
            key = await self.vpn_keys.find_by_client_ip(client_ip)
        if key is None or key.key_type != VpnKeyType.AWG:
            return None
        return key

    async def _remove_awg_access_for_reconcile(self, key: VpnKey, *, fallback_public_key: str) -> None:
        key_public_key = self._stored_awg_public_key(key)
        if key_public_key or not fallback_public_key:
            await self._remove_awg_access(key)
            return
        owner = await self.vpn_keys.find_by_public_key(fallback_public_key)
        if owner is not None and owner.id != key.id:
            raise InvalidOperation("Unsafe AWG reconcile fallback public key belongs to another DB row")
        await self.adapter.remove_peer(key_id=key.id, public_key=fallback_public_key)

    def _managed_key_id_from_peer(self, peer: dict[str, str]) -> int | None:
        raw_value = str(peer.get("_managed_key_id") or "").strip()
        if not raw_value:
            return None
        try:
            return int(raw_value)
        except ValueError:
            return None

    def _client_ip_from_peer(self, peer: dict[str, str]) -> str:
        allowed_ips = str(peer.get("AllowedIPs") or "")
        for part in allowed_ips.split(","):
            value = part.strip()
            if not value:
                continue
            try:
                interface = ipaddress.ip_interface(value)
            except ValueError:
                continue
            if interface.version == 4 and interface.network.prefixlen == 32:
                return str(interface.ip)
        return ""

    async def _mark_awg_degraded(self, reason: str, *, details: dict[str, object]) -> None:
        self.backend_health.mark_degraded(VpnKeyType.AWG, reason)
        logger.critical("AWG backend degraded during reconciliation: %s", reason)
        await self._write_audit_best_effort(
            actor_user_id=None,
            action="awg_startup_drift_degraded",
            entity_type=AuditEntityType.SYSTEM,
            entity_id=None,
            details={**details, "reason": reason, "backend_degraded": True},
        )

    def _fingerprint(self, value: str) -> str | None:
        if not value:
            return None
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]

    async def _startup_reconcile_key(self, key: VpnKey) -> bool:
        if key.status in {VpnKeyStatus.PENDING_APPLY, VpnKeyStatus.APPLY_FAILED}:
            peer = self.adapter.find_peer(public_key=key.public_key, client_ip=key.client_ip)
            if peer is None:
                runtime_peer_present = await self._runtime_peer_present(key)
                if runtime_peer_present:
                    await self._remove_awg_access(key)
                    if key.status == VpnKeyStatus.PENDING_APPLY:
                        await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
                    await self._write_audit_best_effort(
                        actor_user_id=None,
                        action="awg_startup_runtime_orphan_removed",
                        entity_type=AuditEntityType.VPN_KEY,
                        entity_id=key.id,
                        details={"runtime_peer_present": True, "client_ip": key.client_ip, "previous_status": key.status.value},
                    )
                    return True
                if key.status == VpnKeyStatus.PENDING_APPLY:
                    await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
                    await self._write_audit_best_effort(
                        actor_user_id=None,
                        action="awg_startup_pending_apply_failed",
                        entity_type=AuditEntityType.VPN_KEY,
                        entity_id=key.id,
                        details={"peer_present": False, "client_ip": key.client_ip},
                    )
                    return True
                return False
            await self.vpn_keys.mark_active(key.id, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="awg_startup_apply_recovered",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"peer_present": True, "client_ip": key.client_ip, "previous_status": key.status.value},
            )
            return True

        if key.status == VpnKeyStatus.PENDING_REVOKE:
            await self._remove_awg_access(key)
            await self.vpn_keys.mark_revoked(key.id, key.revoked_by or key.deleted_by or key.created_by, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="awg_startup_revoke_completed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"client_ip": key.client_ip},
            )
            return True

        if key.status in {VpnKeyStatus.PENDING_DELETE, VpnKeyStatus.DELETE_FAILED}:
            try:
                await self._remove_awg_access(key)
            except Exception:
                await self.vpn_keys.set_status(key.id, VpnKeyStatus.DELETE_FAILED, self.clock.now())
                raise
            await self.vpn_keys.hard_delete_with_stats(key.id)
            await self._write_audit_best_effort(
                actor_user_id=None,
                action="awg_startup_delete_completed",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={
                    "owner_user_id": key.owner_user_id,
                    "previous_status": key.status.value,
                    "client_ip": key.client_ip,
                    "hard_delete": True,
                },
            )
            return True

        return False

    async def _runtime_peer_present(self, key: VpnKey) -> bool:
        if not key.public_key:
            return False
        verifier = getattr(self.adapter, "verify_runtime_peer", None)
        if verifier is None:
            return False
        return bool(await verifier(key.public_key))

    async def _write_startup_reconcile_failure_audit(self, key: VpnKey, error: Exception) -> None:
        await self._write_audit_best_effort(
            actor_user_id=None,
            action="awg_startup_reconcile_failed",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key.id,
            details={"status": key.status.value, "client_ip": key.client_ip, "error": str(error)},
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
            logger.warning("Audit write failed after AWG operation: action=%s entity_id=%s", action, entity_id, exc_info=True)

    def _ensure_ipv4_network(self) -> None:
        try:
            network = ipaddress.ip_network(self.settings.awg_network, strict=False)
            server_address = ipaddress.ip_address(self.settings.awg_server_address.split("/", 1)[0])
        except ValueError as exc:
            raise InvalidOperation("AWG_NETWORK и AWG_SERVER_ADDRESS должны быть корректными IPv4-значениями") from exc
        if network.version != 4 or server_address.version != 4:
            raise InvalidOperation("AWG_NETWORK сейчас поддерживает только IPv4")
        if server_address not in network:
            raise InvalidOperation("AWG_SERVER_ADDRESS должен входить в AWG_NETWORK")
        if server_address == network.network_address or server_address == network.broadcast_address:
            raise InvalidOperation("AWG_SERVER_ADDRESS не должен быть network или broadcast address")

    def _ensure_server_address_matches_config(self, server_config: object) -> None:
        raw_address = getattr(server_config, "address", None)
        if not raw_address:
            return
        expected = ipaddress.ip_address(self.settings.awg_server_address.split("/", 1)[0])
        config_addresses: list[ipaddress.IPv4Address] = []
        for part in str(raw_address).split(","):
            value = part.strip()
            if not value:
                continue
            try:
                interface = ipaddress.ip_interface(value)
            except ValueError as exc:
                raise InvalidOperation("Address в AWG config должен содержать корректные IP-интерфейсы") from exc
            if interface.version == 4:
                config_addresses.append(interface.ip)
        if not config_addresses:
            raise InvalidOperation("В Address AWG config не найден IPv4-адрес сервера")
        if expected not in config_addresses:
            raise InvalidOperation("AWG_SERVER_ADDRESS не совпадает с IPv4 Address в AWG config")

    def _format_config(self, key: VpnKey, *, viewer_user_id: int | None = None) -> str:
        config = self._client_config(key)
        visible_note = key_note_for_viewer(key, viewer_user_id) if viewer_user_id is not None else None
        note = f"\nЗаметка: {h(visible_note)}" if visible_note else ""
        label = f"\nМетка: {h(key.email_label)}" if key.email_label else ""
        return (
            f"<b>AWG-ключ #{key.id}</b>\n"
            f"Статус: {status_text(key.status)}{label}{note}\n\n"
            f"{pre(config)}"
        )

    def _client_config(self, key: VpnKey) -> str:
        server_config = self.adapter.read_server_config()
        self._ensure_server_address_matches_config(server_config)
        server_public_key = self._server_public_key(server_config.public_key)
        endpoint_port = self._endpoint_port(server_config.listen_port)
        private_key = self._required_private_key(key)
        preshared_key = key.payload.get("preshared_key")
        client_ip = self._required_client_ip(key)
        lines = [
            "[Interface]",
            f"PrivateKey = {private_key}",
            f"Address = {client_ip}/32",
            f"DNS = {self.settings.awg_client_dns}",
        ]
        interface_options = self.adapter.client_interface_options()
        if self.settings.awg_mtu is not None:
            interface_options["MTU"] = str(self.settings.awg_mtu)
        for option, value in interface_options.items():
            if option == "DNS":
                continue
            if value is None or str(value).strip() == "":
                continue
            lines.append(f"{option} = {value}")
        lines.extend(
            [
                "",
                "[Peer]",
                f"PublicKey = {server_public_key}",
            ]
        )
        if preshared_key:
            lines.append(f"PresharedKey = {preshared_key}")
        lines.extend(
            [
                f"AllowedIPs = {self.settings.awg_allowed_ips}",
                f"Endpoint = {self.settings.awg_endpoint_host}:{endpoint_port}",
                f"PersistentKeepalive = {self.settings.awg_persistent_keepalive}",
            ]
        )
        return "\n".join(lines)

    async def _ensure_client_payload_valid(self, actor_user_id: int, key: VpnKey) -> None:
        try:
            self._required_private_key(key)
            self._required_client_ip(key)
        except InvalidOperation as exc:
            logger.warning("AWG client payload is corrupted for key_id=%s: %s", key.id, exc)
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="awg_config_corrupted",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"client_ip": key.client_ip, "reason": str(exc)},
            )
            raise

    def _required_private_key(self, key: VpnKey) -> str:
        private_key = str(key.payload.get("private_key") or "")
        if not private_key:
            raise InvalidOperation("AWG-конфигурация повреждена: отсутствует private key клиента")
        if "\n" in private_key or "\r" in private_key:
            raise InvalidOperation("AWG-конфигурация повреждена: некорректный private key клиента")
        if any(character.isspace() for character in private_key):
            raise InvalidOperation("AWG-конфигурация повреждена: некорректный private key клиента")
        if private_key.upper() in {"...", "<KEY>", "<PRIVATE_KEY>", "PRIVATE_KEY", "CHANGE_ME"}:
            raise InvalidOperation("AWG-конфигурация повреждена: некорректный private key клиента")
        try:
            decoded = base64.b64decode(private_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidOperation("AWG-конфигурация повреждена: некорректный private key клиента") from exc
        if len(decoded) != 32:
            raise InvalidOperation("AWG-конфигурация повреждена: некорректный private key клиента")
        return private_key

    def _required_client_ip(self, key: VpnKey) -> str:
        client_ip = str(key.payload.get("client_ip") or key.client_ip or "").strip()
        try:
            parsed = ipaddress.ip_address(client_ip)
        except ValueError as exc:
            raise InvalidOperation("AWG-конфигурация повреждена: некорректный IP клиента") from exc
        if parsed.version != 4:
            raise InvalidOperation("AWG-конфигурация повреждена: IP клиента должен быть IPv4")
        return client_ip

    def _server_public_key(self, config_public_key: str | None) -> str:
        public_key = self.settings.awg_server_public_key or config_public_key
        if not public_key:
            raise InvalidOperation("Для AWG не задан AWG_SERVER_PUBLIC_KEY и PublicKey отсутствует в server config")
        return public_key

    def _endpoint_port(self, config_listen_port: int | None) -> int:
        port = self.settings.awg_endpoint_port or config_listen_port
        if not port:
            raise InvalidOperation("Для AWG не задан AWG_ENDPOINT_PORT и ListenPort отсутствует в server config")
        return port
