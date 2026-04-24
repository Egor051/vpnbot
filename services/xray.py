from __future__ import annotations

import asyncio
import logging
from urllib.parse import quote, urlencode

from adapters.clock import ClockProvider
from adapters.id_generator import IdGenerator
from adapters.xray_config import XrayConfigAdapter
from config.settings import Settings
from models.dto import TelegramUserProfile, VpnKey, VpnKeyCreateResult
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.notes import normalize_note
from services.users import UserService
from utils.formatting import code, h

logger = logging.getLogger(__name__)


class XrayService:
    def __init__(
        self,
        *,
        vpn_keys: VpnKeyRepository,
        users: UserService,
        adapter: XrayConfigAdapter,
        settings: Settings,
        clock: ClockProvider,
        ids: IdGenerator,
        audit: AuditService,
    ) -> None:
        self.vpn_keys = vpn_keys
        self.users = users
        self.adapter = adapter
        self.settings = settings
        self.clock = clock
        self.ids = ids
        self.audit = audit
        self._lock = asyncio.Lock()

    async def create_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        return await self.create_xray_key(actor_user_id, owner, note)

    async def create_xray_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        self.settings.validate_xray_ready()
        await self._ensure_can_create(actor_user_id, owner.telegram_user_id)
        clean_note = normalize_note(note)

        async with self._lock:
            uuid_value, email_label = await self._unique_identity(owner.telegram_user_id)
            short_id_managed = self.settings.xray_manage_short_ids
            short_id = self.ids.xray_short_id() if short_id_managed else self.settings.xray_short_id
            link = self._build_vless_link(uuid_value, short_id, email_label)
            payload = {
                "uuid": uuid_value,
                "email_label": email_label,
                "short_id": short_id,
                "short_id_managed": short_id_managed,
                "flow": self.settings.xray_flow,
            }
            public_payload = {
                "email_label": email_label,
                "short_id": short_id,
                "display_name": f"Xray #{email_label}",
                "link": link,
            }
            key = await self.vpn_keys.create_pending(
                owner_user_id=owner.telegram_user_id,
                username=owner.username,
                key_type=VpnKeyType.XRAY,
                note=clean_note,
                payload=payload,
                public_payload=public_payload,
                created_by=actor_user_id,
                now=self.clock.now(),
                uuid=uuid_value,
                email_label=email_label,
            )
            try:
                await self.adapter.add_client(
                    uuid_value=uuid_value,
                    email_label=email_label,
                    short_id=short_id,
                    flow=self.settings.xray_flow,
                    manage_short_id=short_id_managed,
                )
            except Exception as exc:
                await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="xray_create_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key.id,
                    details={"owner_user_id": owner.telegram_user_id, "error": str(exc)},
                )
                raise

            try:
                await self.vpn_keys.mark_active(key.id, self.clock.now(), payload=payload, public_payload=public_payload)
            except Exception:
                logger.critical("Xray client applied, but DB mark_active failed for key_id=%s", key.id, exc_info=True)
                raise
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="xray_key_created",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key.id,
                details={"owner_user_id": owner.telegram_user_id},
            )
            active_key = await self._get_key(key.id)
            return VpnKeyCreateResult(key=active_key, config_text=self._format_config(active_key))

    async def revoke_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        return await self.revoke_xray_key(actor_user_id, key_id)

    async def revoke_xray_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        async with self._lock:
            key = await self._get_xray_key_for_manage(actor_user_id, key_id)
            if key.status == VpnKeyStatus.REVOKED:
                return key
            if key.status == VpnKeyStatus.DELETED:
                return key
            if key.status not in {VpnKeyStatus.ACTIVE, VpnKeyStatus.PENDING_APPLY}:
                raise InvalidOperation("Отозвать можно только активный Xray-ключ")
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_REVOKE, self.clock.now())
            try:
                await self.adapter.remove_client(
                    uuid_value=key.uuid,
                    email_label=key.email_label,
                    short_id=str(key.payload.get("short_id") or ""),
                    remove_short_id=await self._can_remove_short_id(key),
                )
            except Exception:
                await self.vpn_keys.set_status(key_id, previous_status, self.clock.now())
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="xray_revoke_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={},
                )
                raise
            await self.vpn_keys.mark_revoked(key_id, actor_user_id, self.clock.now())
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="xray_key_revoked",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={},
            )
            return await self._get_key(key_id)

    async def delete_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        return await self.delete_xray_key(actor_user_id, key_id)

    async def delete_xray_key(self, actor_user_id: int, key_id: int) -> VpnKey:
        async with self._lock:
            key = await self._get_xray_key_for_manage(actor_user_id, key_id)
            if key.status == VpnKeyStatus.DELETED:
                return key
            previous_status = key.status
            await self.vpn_keys.set_status(key_id, VpnKeyStatus.PENDING_DELETE, self.clock.now())
            try:
                if previous_status in {VpnKeyStatus.ACTIVE, VpnKeyStatus.PENDING_APPLY}:
                    await self.adapter.remove_client(
                        uuid_value=key.uuid,
                        email_label=key.email_label,
                        short_id=str(key.payload.get("short_id") or ""),
                        remove_short_id=await self._can_remove_short_id(key),
                    )
            except Exception as exc:
                await self.vpn_keys.set_status(key_id, VpnKeyStatus.DELETE_FAILED, self.clock.now())
                await self.audit.write(
                    actor_user_id=actor_user_id,
                    action="xray_delete_failed",
                    entity_type=AuditEntityType.VPN_KEY,
                    entity_id=key_id,
                    details={"previous_status": previous_status.value, "error": str(exc)},
                )
                raise
            await self.vpn_keys.mark_deleted(key_id, actor_user_id, self.clock.now())
            await self.audit.write(
                actor_user_id=actor_user_id,
                action="xray_key_deleted",
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=key_id,
                details={"previous_status": previous_status.value},
            )
            return await self._get_key(key_id)

    async def get_config(self, actor_user_id: int, key_id: int) -> str:
        return await self.get_xray_key_config(actor_user_id, key_id)

    async def get_xray_key_config(self, actor_user_id: int, key_id: int) -> str:
        key = await self._get_xray_key_for_manage(actor_user_id, key_id, allow_read=True)
        if key.status != VpnKeyStatus.ACTIVE:
            raise InvalidOperation("Конфигурация доступна только для активного ключа")
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="xray_config_shown",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={},
        )
        return self._format_config(key)

    async def list_user_keys(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        return await self.list_user_xray_keys(actor_user_id, owner_user_id, limit=limit, offset=offset)

    async def list_user_xray_keys(
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
        return await self.vpn_keys.list_by_owner_and_type(target, VpnKeyType.XRAY, limit=limit, offset=offset)

    async def update_xray_note(self, actor_user_id: int, key_id: int, note: str | None) -> VpnKey:
        key = await self._get_xray_key_for_manage(actor_user_id, key_id, allow_read=True)
        clean_note = normalize_note(note)
        await self.vpn_keys.update_note(key.id, clean_note, self.clock.now())
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="xray_note_updated",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={},
        )
        return await self._get_key(key_id)

    async def reconcile_key_status(self, actor_user_id: int, key_id: int) -> VpnKey:
        await self.users.require_superadmin(actor_user_id)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.XRAY:
            raise InvalidOperation("Это не Xray-ключ")
        client = self.adapter.find_client(uuid_value=key.uuid, email_label=key.email_label)
        if client is not None and key.status in {VpnKeyStatus.PENDING_APPLY, VpnKeyStatus.APPLY_FAILED}:
            await self.vpn_keys.mark_active(key.id, self.clock.now())
        elif client is None and key.status == VpnKeyStatus.PENDING_APPLY:
            await self.vpn_keys.set_status(key.id, VpnKeyStatus.APPLY_FAILED, self.clock.now())
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="xray_key_reconciled",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"client_present": client is not None},
        )
        return await self._get_key(key_id)

    async def _ensure_can_create(self, actor_user_id: int, owner_user_id: int) -> None:
        owner = await self.users.require_approved_or_admin(owner_user_id)
        actor = await self.users.require_approved_or_admin(actor_user_id)
        if actor.role != UserRole.SUPERADMIN and actor_user_id != owner_user_id:
            raise AccessDenied("Нельзя создавать ключи для другого пользователя")
        if owner.role not in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
            raise AccessDenied("Владелец ключа не имеет доступа")

    async def _get_xray_key_for_manage(self, actor_user_id: int, key_id: int, allow_read: bool = False) -> VpnKey:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.XRAY:
            raise InvalidOperation("Это не Xray-ключ")
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

    async def _can_remove_short_id(self, key: VpnKey) -> bool:
        short_id = str(key.payload.get("short_id") or "")
        if not short_id or key.payload.get("short_id_managed") is not True:
            return False
        in_use = await self.vpn_keys.count_active_managed_short_id(short_id, exclude_key_id=key.id)
        return in_use == 0

    async def _unique_identity(self, telegram_user_id: int) -> tuple[str, str]:
        for _ in range(5):
            uuid_value = self.ids.uuid4()
            email_label = self.ids.email_label(telegram_user_id)
            if await self.vpn_keys.find_by_uuid(uuid_value) is None and await self.vpn_keys.find_by_email_label(email_label) is None:
                return uuid_value, email_label
        raise InvalidOperation("Не удалось сгенерировать уникальные Xray-идентификаторы")

    def _build_vless_link(self, uuid_value: str, short_id: str, email_label: str) -> str:
        params = {
            "type": self.settings.xray_network_type,
            "security": "reality",
            "encryption": "none",
            "pbk": self.settings.xray_reality_public_key,
            "fp": self.settings.xray_fingerprint,
            "sni": self.settings.xray_sni,
            "sid": short_id,
        }
        if self.settings.xray_flow:
            params["flow"] = self.settings.xray_flow
        query = urlencode(params)
        fragment = quote("xray")
        return f"vless://{uuid_value}@{self.settings.xray_public_host}:{self.settings.xray_public_port}?{query}#{fragment}"

    def _format_config(self, key: VpnKey) -> str:
        uuid_value = str(key.payload.get("uuid") or key.uuid or "")
        short_id = str(key.payload.get("short_id") or key.public_payload.get("short_id") or "")
        email_label = str(key.payload.get("email_label") or key.email_label or "")
        link = self._build_vless_link(uuid_value, short_id, email_label)
        note = f"\nЗаметка: {h(key.note)}" if key.note else ""
        return (
            f"<b>Xray-ключ #{key.id}</b>\n"
            f"Статус: {key.status.value}{note}\n\n"
            f"{code(link)}"
        )
