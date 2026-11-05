
from dataclasses import dataclass

from db.database import Database

PROTOCOL_NAMES: tuple[str, ...] = ("xray", "awg", "socks5", "mtproto", "hysteria2")

PROTOCOL_DISPLAY: dict[str, str] = {
    "xray": "Xray (VLESS+Reality)",
    "awg": "AmneziaWG 2.0",
    "socks5": "SOCKS5",
    "mtproto": "MTProto",
    "hysteria2": "Hysteria2",
}


@dataclass
class ProtocolModule:
    name: str
    enabled: bool
    disabled_at: str | None = None
    disabled_by: int | None = None
    # Removed from the HOST, not just switched off (v39). A mirror of the marker
    # /etc/vpn-bot/uninstalled/<name> for the panel and the audit trail; the marker
    # is the truth (services.protocol_uninstall.UninstallRegistry).
    uninstalled_at: str | None = None
    uninstalled_by: int | None = None
    uninstall_backup: str | None = None


class ProtocolModulesRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get_all(self) -> list[ProtocolModule]:
        cursor = await self.db.conn.execute(
            "SELECT name, enabled, disabled_at, disabled_by, uninstalled_at, uninstalled_by, uninstall_backup "
            "FROM protocol_modules ORDER BY name"
        )
        rows = await cursor.fetchall()
        return [
            ProtocolModule(
                name=row["name"],
                enabled=bool(row["enabled"]),
                disabled_at=row["disabled_at"],
                disabled_by=row["disabled_by"],
                uninstalled_at=row["uninstalled_at"],
                uninstalled_by=row["uninstalled_by"],
                uninstall_backup=row["uninstall_backup"],
            )
            for row in rows
        ]

    async def is_enabled(self, name: str) -> bool:
        cursor = await self.db.conn.execute(
            "SELECT enabled FROM protocol_modules WHERE name = ?", (name,)
        )
        row = await cursor.fetchone()
        if row is None:
            return True
        return bool(row["enabled"])

    async def set_enabled(
        self,
        name: str,
        *,
        enabled: bool,
        disabled_by: int | None = None,
        disabled_at: str | None = None,
    ) -> None:
        if enabled:
            await self.db.conn.execute(
                "UPDATE protocol_modules SET enabled = 1, disabled_at = NULL, disabled_by = NULL WHERE name = ?",
                (name,),
            )
        else:
            await self.db.conn.execute(
                "UPDATE protocol_modules SET enabled = 0, disabled_at = ?, disabled_by = ? WHERE name = ?",
                (disabled_at, disabled_by, name),
            )
        await self.db.commit()

    async def set_uninstalled(
        self,
        name: str,
        *,
        uninstalled_at: str,
        uninstalled_by: int | None,
        backup: str | None,
    ) -> None:
        """Record that *name* was removed from the host. Also switched off: an
        uninstalled module is never enabled (disabled_at is kept if already set)."""
        await self.db.conn.execute(
            "UPDATE protocol_modules SET enabled = 0, "
            "disabled_at = COALESCE(disabled_at, ?), "
            "uninstalled_at = ?, uninstalled_by = ?, uninstall_backup = ? WHERE name = ?",
            (uninstalled_at, uninstalled_at, uninstalled_by, backup, name),
        )
        await self.db.commit()

    async def clear_uninstalled(self, name: str) -> None:
        """Forget a removal (the marker is gone: reinstalled by hand). The module
        stays switched off until an admin enables it."""
        await self.db.conn.execute(
            "UPDATE protocol_modules SET uninstalled_at = NULL, uninstalled_by = NULL, "
            "uninstall_backup = NULL WHERE name = ?",
            (name,),
        )
        await self.db.commit()
