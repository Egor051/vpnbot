
from aiosqlite import Row

from db.database import Database
from models.dto import ProxyEntry
from models.enums import ProxyStatus


def _row_to_proxy(row: Row | None) -> ProxyEntry | None:
    if row is None:
        return None
    try:
        status = ProxyStatus(row["status"])
    except ValueError as exc:
        raise RuntimeError(
            f"Некорректное значение proxy_entries.status в SQLite: {row['status']!r}. "
            "Сделайте backup DB и исправьте повреждённую запись вручную."
        ) from exc
    return ProxyEntry(
        id=int(row["id"]),
        proxy_type=row["proxy_type"],
        host=row["host"],
        port=int(row["port"]),
        login=row["login"],
        password=row["password"],
        note=row["note"],
        status=status,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class ProxyRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def list_active(self, limit: int = 10, offset: int = 0) -> list[ProxyEntry]:
        cursor = await self.db.conn.execute(
            """
            SELECT * FROM proxy_entries
            WHERE status = ?
            ORDER BY id ASC
            LIMIT ? OFFSET ?
            """,
            (ProxyStatus.ACTIVE.value, limit, offset),
        )
        rows = await cursor.fetchall()
        return [entry for row in rows if (entry := _row_to_proxy(row)) is not None]

    async def get_by_id(self, proxy_id: int) -> ProxyEntry | None:
        cursor = await self.db.conn.execute("SELECT * FROM proxy_entries WHERE id = ?", (proxy_id,))
        row = await cursor.fetchone()
        return _row_to_proxy(row)

    async def create(
        self,
        proxy_type: str,
        host: str,
        port: int,
        login: str | None,
        password: str | None,
        note: str | None,
        now: str,
    ) -> ProxyEntry:
        cursor = await self.db.conn.execute(
            """
            INSERT INTO proxy_entries (proxy_type, host, port, login, password, note, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (proxy_type, host, port, login, password, note, ProxyStatus.ACTIVE.value, now, now),
        )
        await self.db.commit()
        assert cursor.lastrowid is not None
        entry = await self.get_by_id(int(cursor.lastrowid))
        if entry is None:
            raise RuntimeError("Proxy insert failed")
        return entry

    async def count(self) -> int:
        cursor = await self.db.conn.execute("SELECT COUNT(*) AS cnt FROM proxy_entries")
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def update_note(self, proxy_id: int, note: str | None, now: str) -> None:
        await self.db.conn.execute(
            "UPDATE proxy_entries SET note = ?, updated_at = ? WHERE id = ?",
            (note, now, proxy_id),
        )
        await self.db.commit()
