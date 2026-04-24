from __future__ import annotations

import asyncio
import logging

from adapters.awg_config import AwgConfigAdapter
from adapters.clock import ClockProvider
from adapters.id_generator import IdGenerator
from adapters.ip_allocator import IpAllocator
from config.settings import Settings
from models.dto import TelegramUserProfile, VpnKey, VpnKeyCreateResult
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.notes import normalize_note
from services.users import UserService
from utils.formatting import h, pre

logger = logging.getLogger(__name__)


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
    ) -> None:
        self.vpn_keys = vpn_keys
        self.users = users
        self.adapter = adapter
        self.ip_allocator = ip_allocator
        self.settings = settings
        self.clock = clock
        self.ids = ids
        self.audit = audit
        self._lock = asyncio.Lock()

    async def create_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        return await self.create_awg_key(actor_user_id, owner, note)

    async def create_awg_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        self.settings.validate_awg_ready()
        await self._ensure_can_create(actor_user_id, owner.telegram_user_id)
        clean_note = normalize_note(note)

        async with self._lock:
            server_config = self.adapter.read_server_config()
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
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="awg_create_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={"owner_user_id": owner.telegram_user_id, "client_ip": client_ip, "error": str(exc)},
                )
                raise

            try:
                await self.vpn_keys.mark_active(key.id, self.clock.now(), payload=payload, public_payload=public_payload)
            except Exception:
                logger.critical("AWG peer applied, but DB mark_active failed for key_id=%s", key.id, exc_info=True)
                raise
            await self.audit.write(
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
            return VpnKeyCreateResult(key=active_key, config_text=self._format_config(active_key))

    async def revoke_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        return await self.revoke_awg_key(actor_user_id, key_id)

    async def revoke_awg_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        async with self._lock:
            key = await self._get_awg_key_for_manage(actor_user_id, key_id)
            if key.status == VpnKeyStatus.REVOKED:
                return key
            if key.status == VpnKeyStatus.DELETED:
                return key
            if key.status not in {VpnKeyStatus.ACTIVE, VpnKeyStatus.PENDING_APPLY}:
                raise InvalidOperation("Отозвать можно только активный AWG-ключ")
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_REVOKE, self.clock.now())
            try:
                await self.adapter.remove_peer(key_id=key_id, public_key=key.public_key)
            except Exception:
                await self.vpn_keys.set_status(key_id, previous_status, self.clock.now())
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="awg_revoke_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={"client_ip": key.client_ip},
                )
                raise
            await self.vpn_keys.mark_revoked(key_id, actor_user_id, self.clock.now())
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="awg_key_revoked",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"client_ip": key.client_ip},
            )
            return await self._get_key(key_id)

    async def delete_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        return await self.delete_awg_key(actor_user_id, key_id)

    async def delete_awg_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        async with self._lock:
            key = await self._get_awg_key_for_manage(actor_user_id, key_id)
            if key.status == VpnKeyStatus.DELETED:
                return key
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_DELETE, self.clock.now())
            try:
                if previous_status in {VpnKeyStatus.ACTIVE, VpnKeyStatus.PENDING_APPLY}:
                    await self.adapter.remove_peer(key_id=key_id, public_key=key.public_key)
            except Exception as exc:
                await self.vpn_keys.set_status(key_id, VpnKeyStatus.DELETE_FAILED, self.clock.now())
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="awg_delete_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={"previous_status": previous_status.value, "client_ip": key.client_ip, "error": str(exc)},
                )
                raise
            await self.vpn_keys.mark_deleted(key_id, actor_user_id, self.clock.now())
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="awg_key_deleted",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"previous_status": previous_status.value, "client_ip": key.client_ip},
            )
            return await self._get_key(key_id)

    async def get_config(self, actor_user_id: int, key_id: int) -> str:
        return await self.get_awg_client_config(actor_user_id, key_id)

    async def get_awg_client_config(self, actor_user_id: int, key_id: int) -> str:
        key = await self._get_awg_key_for_manage(actor_user_id, key_id, allow_read=True)
        if key.status != VpnKeyStatus.ACTIVE:
            raise InvalidOperation("Конфигурация доступна только для активного ключа")
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="awg_config_shown",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"client_ip": key.client_ip},
        )
        return self._format_config(key)

    async def get_awg_client_config_plain(self, actor_user_id: int, key_id: int, audit: bool = True) -> str:
        key = await self._get_awg_key_for_manage(actor_user_id, key_id, allow_read=True)
        if key.status != VpnKeyStatus.ACTIVE:
            raise InvalidOperation("Конфигурация доступна только для активного ключа")
        if audit:
            await self.audit.write(
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
        clean_note = normalize_note(note)
        await self.vpn_keys.update_note(key.id, clean_note, self.clock.now())
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="awg_note_updated",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"client_ip": key.client_ip},
        )
        return await self._get_key(key_id)

    async def reconcile_key_status(self, actor_user_id: int, key_id: int) -> VpnKey:
        await self.users.require_superadmin(actor_user_id)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.AWG:
            raise InvalidOperation("Это не AWG-ключ")
        peer = self.adapter.find_peer(public_key=key.public_key, client_ip=key.client_ip)
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
        actor = await self.users.require_approved_or_admin(actor_user_id)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.AWG:
            raise InvalidOperation("Это не AWG-ключ")
        if actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
            raise AccessDenied("Нельзя управлять чужим ключом")
        if not allow_read and actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
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
            label = self.ids.key_label(telegram_user_id, username)
            if await self.vpn_keys.find_by_email_label(label) is None:
                return label
        raise InvalidOperation("Не удалось сгенерировать уникальный label для AWG-ключа")

    def _format_config(self, key: VpnKey) -> str:
        config = self._client_config(key)
        note = f"\nЗаметка: {h(key.note)}" if key.note else ""
        label = f"\nLabel: {h(key.email_label)}" if key.email_label else ""
        return (
            f"<b>AWG-ключ #{key.id}</b>\n"
            f"Статус: {key.status.value}{label}{note}\n\n"
            f"{pre(config)}"
        )

    def _client_config(self, key: VpnKey) -> str:
        server_config = self.adapter.read_server_config()
        server_public_key = self._server_public_key(server_config.public_key)
        endpoint_port = self._endpoint_port(server_config.listen_port)
        private_key = str(key.payload.get("private_key") or "")
        preshared_key = key.payload.get("preshared_key")
        client_ip = str(key.payload.get("client_ip") or key.client_ip or "")
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
