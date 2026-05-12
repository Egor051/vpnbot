
import json
import logging
from typing import Any

from db.database import Database
from models.enums import AuditEntityType

logger = logging.getLogger(__name__)


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
        await self.db.commit()

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
                "details": self._safe_details(row["details_json"], int(row["id"])),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    async def list_recent_for_entity(
        self,
        *,
        entity_type: AuditEntityType,
        entity_id: str | int,
        actions: set[str] | None = None,
        limit: int = 10,
    ) -> list[dict[str, object]]:
        safe_limit = max(1, min(limit, 50))
        params: list[object] = [entity_type.value, str(entity_id)]
        action_sql = ""
        if actions:
            action_values = sorted(actions)
            placeholders = ",".join("?" for _ in action_values)
            action_sql = f"AND action IN ({placeholders})"
            params.extend(action_values)
        params.append(safe_limit)
        cursor = await self.db.conn.execute(
            f"""
            SELECT id, actor_user_id, action, entity_type, entity_id, details_json, created_at
            FROM audit_log
            WHERE entity_type = ? AND entity_id = ?
              {action_sql}
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            tuple(params),
        )
        rows = await cursor.fetchall()
        return [
            {
                "id": int(row["id"]),
                "actor_user_id": row["actor_user_id"],
                "action": row["action"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "details": self._safe_details(row["details_json"], int(row["id"])),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    async def prune_older_than(self, cutoff: str) -> int:
        cursor = await self.db.conn.execute(
            "DELETE FROM audit_log WHERE created_at < ?",
            (cutoff,),
        )
        await self.db.commit()
        return int(cursor.rowcount or 0)

    def _safe_details(self, value: str | None, row_id: int) -> dict[str, object]:
        if not value:
            return {}
        try:
            data = json.loads(value)
        except json.JSONDecodeError:
            logger.warning("Некорректный JSON в audit_log.details_json id=%s", row_id)
            return {"_corrupted": True}
        return data if isinstance(data, dict) else {"_invalid": True}
