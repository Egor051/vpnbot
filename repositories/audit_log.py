from __future__ import annotations

import json
from typing import Any

from db.database import Database
from models.enums import AuditEntityType


class AuditLogRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def create(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_type: AuditEntityType,
        entity_id: str | None,
        details: dict[str, Any] | None,
        now: str,
    ) -> None:
        await self.db.conn.execute(
            """
            INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                actor_user_id,
                action,
                entity_type.value,
                entity_id,
                json.dumps(details or {}, ensure_ascii=False, separators=(",", ":")),
                now,
            ),
        )
        await self.db.conn.commit()

    async def list_recent(self, limit: int = 20, offset: int = 0) -> list[dict[str, object]]:
        cursor = await self.db.conn.execute(
            """
            SELECT id, actor_user_id, action, entity_type, entity_id, details_json, created_at
            FROM audit_log
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [
            {
                "id": int(row["id"]),
                "actor_user_id": row["actor_user_id"],
                "action": row["action"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "details": json.loads(row["details_json"] or "{}"),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    async def prune_older_than(self, cutoff: str) -> int:
        cursor = await self.db.conn.execute(
            "DELETE FROM audit_log WHERE created_at < ?",
            (cutoff,),
        )
        await self.db.conn.commit()
        return int(cursor.rowcount or 0)
