from __future__ import annotations

from models.enums import AuditEntityType, UserRole
from repositories.proxy_entries import ProxyRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, NotFound
from services.users import UserService


MAX_NOTE_LENGTH = 256


def normalize_note(note: str | None) -> str | None:
    if note is None:
        return None
    value = note.strip()
    if value in {"", "-"}:
        return None
    if len(value) > MAX_NOTE_LENGTH:
        raise ValueError(f"Заметка не должна быть длиннее {MAX_NOTE_LENGTH} символов")
    return value


class NotesService:
    def __init__(
        self,
        *,
        vpn_keys: VpnKeyRepository,
        proxies: ProxyRepository,
        users: UserService,
        audit: AuditService,
    ) -> None:
        self.vpn_keys = vpn_keys
        self.proxies = proxies
        self.users = users
        self.audit = audit

    async def update_key_note(self, actor_user_id: int, key_id: int, note: str | None) -> None:
        key = await self.vpn_keys.get_by_id(key_id)
        if key is None:
            raise NotFound("Ключ не найден")
        actor = await self.users.require_approved_or_admin(actor_user_id)
        if actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
            raise AccessDenied("Можно менять заметку только своих ключей")
        clean_note = normalize_note(note)
        await self.vpn_keys.update_note(key_id, clean_note, self.users.clock.now())
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="note_updated",
            entity_type=AuditEntityType.VPN_KEY,
            entity_id=key_id,
            details={"key_type": key.key_type.value},
        )

    async def update_proxy_note(self, actor_user_id: int, proxy_id: int, note: str | None) -> None:
        await self.users.require_superadmin(actor_user_id)
        proxy = await self.proxies.get_by_id(proxy_id)
        if proxy is None:
            raise NotFound("Прокси не найден")
        clean_note = normalize_note(note)
        await self.proxies.update_note(proxy_id, clean_note, self.users.clock.now())
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="proxy_note_updated",
            entity_type=AuditEntityType.PROXY,
            entity_id=proxy_id,
            details={},
        )
