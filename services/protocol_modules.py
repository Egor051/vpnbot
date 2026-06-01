
import logging
from datetime import datetime, timezone

from db.database import Database
from repositories.protocol_modules import ProtocolModule, ProtocolModulesRepository

logger = logging.getLogger(__name__)

_VPN_KEY_TYPES = {"xray", "awg"}
_PROXY_TYPES = {"socks5", "mtproto"}


class ProtocolModulesService:
    def __init__(self, repo: ProtocolModulesRepository, db: Database) -> None:
        self._repo = repo
        self._db = db

    async def get_all(self) -> list[ProtocolModule]:
        return await self._repo.get_all()

    async def is_enabled(self, name: str) -> bool:
        return await self._repo.is_enabled(name)

    async def disable_protocol(self, name: str, actor_id: int) -> int:
        """Disable a protocol: mark disabled and hard-delete all related DB data.

        Returns the number of records deleted.
        """
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        deleted = 0
        if name in _VPN_KEY_TYPES:
            cursor = await self._db.conn.execute(
                "DELETE FROM vpn_keys WHERE key_type = ?", (name,)
            )
            deleted = cursor.rowcount or 0
        elif name in _PROXY_TYPES:
            cursor = await self._db.conn.execute(
                "DELETE FROM proxy_accesses WHERE access_type = ?", (name,)
            )
            deleted = cursor.rowcount or 0
        await self._repo.set_enabled(name, enabled=False, disabled_by=actor_id, disabled_at=now)
        logger.info(
            "Protocol %s disabled by user %d; %d records deleted",
            name, actor_id, deleted,
        )
        return deleted

    async def enable_protocol(self, name: str, actor_id: int) -> None:
        await self._repo.set_enabled(name, enabled=True)
        logger.info("Protocol %s enabled by user %d", name, actor_id)
