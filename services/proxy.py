from __future__ import annotations

from config.settings import Settings
from models.dto import ProxyEntry
from models.enums import AuditEntityType
from repositories.proxy_entries import ProxyRepository
from services.audit import AuditService
from services.errors import NotFound
from services.users import UserService
from utils.formatting import code, h


class ProxyService:
    def __init__(
        self,
        *,
        proxies: ProxyRepository,
        users: UserService,
        settings: Settings,
        audit: AuditService,
    ) -> None:
        self.proxies = proxies
        self.users = users
        self.settings = settings
        self.audit = audit

    async def seed_default_from_env(self) -> None:
        if await self.proxies.count() > 0:
            return
        if not (self.settings.default_proxy_type and self.settings.default_proxy_host and self.settings.default_proxy_port):
            return
        await self.proxies.create(
            self.settings.default_proxy_type,
            self.settings.default_proxy_host,
            self.settings.default_proxy_port,
            self.settings.default_proxy_login or None,
            self.settings.default_proxy_password or None,
            self.settings.default_proxy_note or None,
            self.users.clock.now(),
        )
        await self.audit.write(
            actor_user_id=None,
            action="proxy_seeded",
            entity_type=AuditEntityType.PROXY,
            entity_id=None,
            details={"host": self.settings.default_proxy_host, "type": self.settings.default_proxy_type},
        )

    async def list_available(self, actor_user_id: int, limit: int = 20, offset: int = 0) -> list[ProxyEntry]:
        await self.users.require_approved_or_admin(actor_user_id)
        return await self.proxies.list_active(limit=limit, offset=offset)

    async def format_for_user(self, actor_user_id: int) -> str:
        entries = await self.list_available(actor_user_id)
        if not entries:
            raise NotFound("Доступные прокси не настроены")
        parts = ["<b>Прокси</b>"]
        for entry in entries:
            lines = [
                f"<b>{h(entry.proxy_type)}</b>",
                f"Host: {code(entry.host)}",
                f"Port: {code(entry.port)}",
            ]
            if entry.login:
                lines.append(f"Login: {code(entry.login)}")
            if entry.password:
                lines.append(f"Password: {code(entry.password)}")
            if entry.note:
                lines.append(f"Описание: {h(entry.note)}")
            lines.append(f"Статус: {entry.status.value}")
            parts.append("\n".join(lines))
        await self.audit.write(
            actor_user_id=actor_user_id,
            action="proxy_shown",
            entity_type=AuditEntityType.PROXY,
            entity_id=None,
            details={"count": len(entries)},
        )
        return "\n\n".join(parts)
