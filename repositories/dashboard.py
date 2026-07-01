
from __future__ import annotations

from dataclasses import dataclass

from db.database import Database
from repositories._helpers import _clamp_limit


@dataclass(frozen=True, slots=True)
class KeysSummary:
    total: int
    active: int
    xray_active: int
    awg_active: int
    hysteria2_active: int
    expiring_7d: int
    expiring_30d: int
    stuck: int
    avg_per_user: float


@dataclass(frozen=True, slots=True)
class TrafficTotals:
    total_bytes: int
    xray_bytes: int
    awg_bytes: int
    hysteria2_bytes: int
    avg_per_key_bytes: int


@dataclass(frozen=True, slots=True)
class TopUserTraffic:
    user_id: int
    username: str | None
    total_bytes: int


class DashboardRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def count_users_by_role(self) -> dict[str, int]:
        """Return user count grouped by role."""
        cursor = await self.db.conn.execute(
            "SELECT role, COUNT(*) AS cnt FROM users GROUP BY role"
        )
        rows = await cursor.fetchall()
        return {str(row["role"]): int(row["cnt"]) for row in rows}

    async def count_new_users_since(self, cutoff: str) -> int:
        """Return number of users created at or after cutoff."""
        cursor = await self.db.conn.execute(
            "SELECT COUNT(*) AS cnt FROM users WHERE created_at >= ?",
            (cutoff,),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def count_users_with_active_keys(self) -> int:
        """Return number of distinct users who have at least one active VPN key."""
        cursor = await self.db.conn.execute(
            "SELECT COUNT(DISTINCT owner_user_id) AS cnt FROM vpn_keys WHERE status = 'active'"
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def keys_summary(self, now: str, cutoff_7d: str, cutoff_30d: str) -> KeysSummary:
        """Return aggregated VPN key counts in a single query."""
        row = await self.db.conn.execute_fetchone(
            """
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
              SUM(CASE WHEN status = 'active' AND key_type = 'xray' THEN 1 ELSE 0 END) AS xray_active,
              SUM(CASE WHEN status = 'active' AND key_type = 'awg'  THEN 1 ELSE 0 END) AS awg_active,
              SUM(CASE WHEN status = 'active' AND key_type = 'hysteria2' THEN 1 ELSE 0 END) AS hysteria2_active,
              SUM(CASE WHEN status = 'active' AND expires_at IS NOT NULL
                            AND expires_at > ? AND expires_at <= ?   THEN 1 ELSE 0 END) AS expiring_7d,
              SUM(CASE WHEN status = 'active' AND expires_at IS NOT NULL
                            AND expires_at > ? AND expires_at <= ?   THEN 1 ELSE 0 END) AS expiring_30d,
              SUM(CASE WHEN status IN ('pending_apply','apply_failed','pending_revoke','pending_delete','delete_failed','failed')
                       THEN 1 ELSE 0 END) AS stuck
            FROM vpn_keys
            WHERE status != 'deleted'
            """,
            (now, cutoff_7d, now, cutoff_30d),
        )
        if row is None:
            return KeysSummary(
                total=0, active=0, xray_active=0, awg_active=0, hysteria2_active=0,
                expiring_7d=0, expiring_30d=0, stuck=0, avg_per_user=0.0,
            )
        avg_row = await self.db.conn.execute_fetchone(
            """
            SELECT AVG(cnt) AS avg_keys
            FROM (
              SELECT COUNT(*) AS cnt
              FROM vpn_keys
              WHERE status = 'active'
              GROUP BY owner_user_id
            )
            """
        )
        avg = float(avg_row["avg_keys"]) if avg_row and avg_row["avg_keys"] is not None else 0.0
        return KeysSummary(
            total=int(row["total"] or 0),
            active=int(row["active"] or 0),
            xray_active=int(row["xray_active"] or 0),
            awg_active=int(row["awg_active"] or 0),
            hysteria2_active=int(row["hysteria2_active"] or 0),
            expiring_7d=int(row["expiring_7d"] or 0),
            expiring_30d=int(row["expiring_30d"] or 0),
            stuck=int(row["stuck"] or 0),
            avg_per_user=avg,
        )

    async def traffic_totals(self) -> TrafficTotals:
        """Return aggregate traffic bytes grouped by VPN key protocol.

        Both the per-protocol totals and the per-key average are computed over
        the SAME dataset — live traffic stats UNION the deleted-key archive — so
        ``avg_per_key_bytes`` stays consistent with ``total_bytes`` (i.e.
        avg * key_count == total) instead of drifting because deleted keys count
        toward the total but not the average.
        """
        row = await self.db.conn.execute_fetchone(
            """
            SELECT
              COALESCE(SUM(CASE WHEN key_type = 'xray' THEN total_bytes END), 0) AS xray_bytes,
              COALESCE(SUM(CASE WHEN key_type = 'awg' THEN total_bytes END), 0) AS awg_bytes,
              COALESCE(SUM(CASE WHEN key_type = 'hysteria2' THEN total_bytes END), 0) AS hysteria2_bytes,
              AVG(total_bytes) AS avg_bytes
            FROM (
                SELECT k.key_type AS key_type,
                       (t.downloaded_bytes + t.uploaded_bytes) AS total_bytes
                FROM vpn_key_traffic_stats t
                JOIN vpn_keys k ON k.id = t.key_id
                UNION ALL
                SELECT key_type,
                       (downloaded_bytes + uploaded_bytes) AS total_bytes
                FROM deleted_key_traffic_archive
            )
            """
        )
        xray_bytes = int(row["xray_bytes"] or 0) if row else 0
        awg_bytes = int(row["awg_bytes"] or 0) if row else 0
        hysteria2_bytes = int(row["hysteria2_bytes"] or 0) if row else 0
        avg = int(row["avg_bytes"]) if row and row["avg_bytes"] is not None else 0
        return TrafficTotals(
            total_bytes=xray_bytes + awg_bytes + hysteria2_bytes,
            xray_bytes=xray_bytes,
            awg_bytes=awg_bytes,
            hysteria2_bytes=hysteria2_bytes,
            avg_per_key_bytes=avg,
        )

    async def top_users_by_traffic(self, limit: int = 5) -> list[TopUserTraffic]:
        """Return top N users sorted by total traffic bytes descending."""
        cursor = await self.db.conn.execute(
            """
            SELECT owner_user_id, MAX(username) AS username, SUM(total_bytes) AS total_bytes
            FROM (
                SELECT k.owner_user_id AS owner_user_id,
                       COALESCE(u.username, k.username) AS username,
                       (t.downloaded_bytes + t.uploaded_bytes) AS total_bytes
                FROM vpn_key_traffic_stats t
                JOIN vpn_keys k ON k.id = t.key_id
                LEFT JOIN users u ON u.telegram_user_id = k.owner_user_id
                UNION ALL
                SELECT a.owner_user_id,
                       COALESCE(u.username, CAST(a.owner_user_id AS TEXT)) AS username,
                       (a.downloaded_bytes + a.uploaded_bytes) AS total_bytes
                FROM deleted_key_traffic_archive a
                LEFT JOIN users u ON u.telegram_user_id = a.owner_user_id
            )
            GROUP BY owner_user_id
            ORDER BY total_bytes DESC
            LIMIT ?
            """,
            (_clamp_limit(limit),),
        )
        rows = await cursor.fetchall()
        return [
            TopUserTraffic(
                user_id=int(row["owner_user_id"]),
                username=row["username"],
                total_bytes=int(row["total_bytes"] or 0),
            )
            for row in rows
        ]

    async def count_audit_since(self, cutoff: str) -> int:
        """Return audit log entry count since cutoff timestamp.

        created_at and the cutoff are both produced as UTC ISO-8601 strings with
        a '+00:00' offset (see adapters/clock.py and services/dashboard.py), so a
        plain lexicographic comparison is correct and lets idx_audit_log_created_at
        be used (a REPLACE() on the column would force a full scan).
        """
        cursor = await self.db.conn.execute(
            "SELECT COUNT(*) AS cnt FROM audit_log WHERE created_at >= ?",
            (cutoff,),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0

    async def count_announcements_since(self, cutoff: str) -> int:
        """Return non-cancelled announcement batch count since cutoff."""
        cursor = await self.db.conn.execute(
            """
            SELECT COUNT(*) AS cnt FROM announcement_batches
            WHERE created_at >= ? AND status != 'cancelled'
            """,
            (cutoff,),
        )
        row = await cursor.fetchone()
        return int(row["cnt"]) if row is not None else 0
