
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


class ProtocolModulesRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def get_all(self) -> list[ProtocolModule]:
        cursor = await self.db.conn.execute(
            "SELECT name, enabled, disabled_at, disabled_by FROM protocol_modules ORDER BY name"
        )
        rows = await cursor.fetchall()
        return [
            ProtocolModule(
                name=row["name"],
                enabled=bool(row["enabled"]),
                disabled_at=row["disabled_at"],
                disabled_by=row["disabled_by"],
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
