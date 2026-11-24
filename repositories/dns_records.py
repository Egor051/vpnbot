"""The DNS records the bot owns (``dns_records``; services/dns.py, docs/certificate.md).

One row per (name, type): the record the bot keeps pointing at an address, why
(``purpose``), what it last wrote and Cloudflare's ids of it. Written only by the DNS
service; a name that is not here is never deleted by the bot.
"""

from __future__ import annotations

from aiosqlite import Row

from db.database import Database
from models.dto import OwnedDnsRecord

PURPOSES = frozenset({"fallback_origin", "host"})
_COLUMNS = (
    "id, name, type, purpose, content, zone_id, record_id, adopted, last_error, created_at, updated_at, created_by"
)


def _row(row: Row) -> OwnedDnsRecord:
    return OwnedDnsRecord(
        id=int(row["id"]),
        name=str(row["name"]),
        type=str(row["type"]),
        purpose=str(row["purpose"]),
        content=None if row["content"] is None else str(row["content"]),
        zone_id=None if row["zone_id"] is None else str(row["zone_id"]),
        record_id=None if row["record_id"] is None else str(row["record_id"]),
        adopted=bool(row["adopted"]),
        last_error=None if row["last_error"] is None else str(row["last_error"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        created_by=None if row["created_by"] is None else int(row["created_by"]),
    )


class DnsRecordsRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def list_all(self) -> list[OwnedDnsRecord]:
        rows = await self.db.conn.execute_fetchall(f"SELECT {_COLUMNS} FROM dns_records ORDER BY purpose, name")
        return [_row(row) for row in rows]

    async def get(self, name: str, rtype: str = "A") -> OwnedDnsRecord | None:
        row = await self.db.conn.execute_fetchone(
            f"SELECT {_COLUMNS} FROM dns_records WHERE name = ? AND type = ?", (name.lower(), rtype)
        )
        return None if row is None else _row(row)

    async def save(
        self,
        name: str,
        *,
        purpose: str,
        content: str,
        zone_id: str,
        record_id: str,
        adopted: bool,
        now: str,
        actor: int | None,
        rtype: str = "A",
    ) -> OwnedDnsRecord:
        """Insert or update the row of a successful write (its last error cleared). The
        purpose and ``adopted`` of an existing row are kept: ownership does not move."""
        if purpose not in PURPOSES:
            raise ValueError(f"dns_records: bad purpose {purpose!r}")
        await self.db.conn.execute(
            "INSERT INTO dns_records (name, type, purpose, content, zone_id, record_id, adopted, last_error, "
            "created_at, updated_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?) "
            "ON CONFLICT(name, type) DO UPDATE SET content = excluded.content, zone_id = excluded.zone_id, "
            "record_id = excluded.record_id, last_error = NULL, updated_at = excluded.updated_at",
            (name.lower(), rtype, purpose, content, zone_id, record_id, int(adopted), now, now, actor),
        )
        await self.db.commit()
        saved = await self.get(name, rtype)
        assert saved is not None
        return saved

    async def record_error(self, name: str, error: str, *, now: str, rtype: str = "A") -> None:
        await self.db.conn.execute(
            "UPDATE dns_records SET last_error = ?, updated_at = ? WHERE name = ? AND type = ?",
            (error[:300], now, name.lower(), rtype),
        )
        await self.db.commit()

    async def delete(self, name: str, rtype: str = "A") -> OwnedDnsRecord | None:
        current = await self.get(name, rtype)
        if current is None:
            return None
        await self.db.conn.execute("DELETE FROM dns_records WHERE id = ?", (current.id,))
        await self.db.commit()
        return current
