"""Persistence of the fallback mode (docs/relay.md «Режим фолбэка», services/fallback.py).

* ``failover_names`` — the DNS failover set: the names whose A record the bot
  switches between the main server's IPv4 and the hub's, with what the last write
  did to each (a partial switch is visible per name and a repeat finishes it).
* runtime settings in ``schema_meta`` (no DDL, read by both processes): the mode
  the admin asked for, the addresses the bot writes (overrides of what it derives),
  the subscription's ``fallback-url`` switch and the direct links' host.

Writes happen only in the bot, through the fallback service. The subscription
endpoint reads the two settings it needs (``fallback-url`` and the direct host)
through its read-only connection, on every request.
"""

from __future__ import annotations

from collections.abc import Sequence

from aiosqlite import Row

from db.database import Database
from models.dto import FailoverName
from models.enums import VpnKeyStatus
from repositories.relays import DIRECT_HOST_META_KEY

_COLUMNS = "id, name, applied, applied_ipv4, applied_at, last_error, created_at, created_by"
APPLIED_STATES = frozenset({"normal", "failover"})

# schema_meta keys. MODE: "on" — the admin switched the fallback mode on (every
# name should point at the hub); anything else, the key absent included — off.
META_MODE = "failover_mode"
# When and by whom the mode was last asked to change (shown on the screen).
META_MODE_AT = "failover_mode_at"
# The addresses the bot writes; absent — derived (services.fallback).
META_MAIN_IPV4 = "failover_main_ipv4"
META_HUB_IPV4 = "failover_hub_ipv4"
# "1": the subscription endpoint sends `fallback-url` (Happ, Provider ID only).
META_SUB_FALLBACK_URL = "failover_sub_fallback_url"
# The DNS name direct links point at instead of XRAY_PUBLIC_HOST / HYSTERIA2_HOST
# (absent or empty: .env, exactly as before), and when it was set.
META_DIRECT_HOST = DIRECT_HOST_META_KEY
META_DIRECT_HOST_AT = "failover_direct_host_at"

_ACTIVE = VpnKeyStatus.ACTIVE.value
# Protocols whose direct link carries XRAY_PUBLIC_HOST / HYSTERIA2_HOST.
_DIRECT_LINK_TYPES = ("xray", "hysteria2")


def _row(row: Row) -> FailoverName:
    return FailoverName(
        id=int(row["id"]),
        name=str(row["name"]),
        applied=None if row["applied"] is None else str(row["applied"]),
        applied_ipv4=None if row["applied_ipv4"] is None else str(row["applied_ipv4"]),
        applied_at=None if row["applied_at"] is None else str(row["applied_at"]),
        last_error=None if row["last_error"] is None else str(row["last_error"]),
        created_at=str(row["created_at"]),
        created_by=None if row["created_by"] is None else int(row["created_by"]),
    )


class FailoverRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ── the failover set ──────────────────────────────────────────────────────

    async def list_names(self) -> list[FailoverName]:
        rows = await self.db.conn.execute_fetchall(f"SELECT {_COLUMNS} FROM failover_names ORDER BY id")
        return [_row(row) for row in rows]

    async def get_name(self, name_id: int) -> FailoverName | None:
        row = await self.db.conn.execute_fetchone(f"SELECT {_COLUMNS} FROM failover_names WHERE id = ?", (name_id,))
        return None if row is None else _row(row)

    async def add_name(self, name: str, *, now: str, created_by: int | None) -> FailoverName | None:
        """Insert *name*; None when it is already in the set (nothing changed)."""
        cursor = await self.db.conn.execute(
            "INSERT INTO failover_names (name, created_at, created_by) VALUES (?, ?, ?) ON CONFLICT(name) DO NOTHING",
            (name, now, created_by),
        )
        await self.db.commit()
        if cursor.rowcount != 1 or cursor.lastrowid is None:
            return None
        return await self.get_name(int(cursor.lastrowid))

    async def remove_name(self, name_id: int) -> FailoverName | None:
        """Delete one name; the row as it was, or None when it was not there."""
        current = await self.get_name(name_id)
        if current is None:
            return None
        await self.db.conn.execute("DELETE FROM failover_names WHERE id = ?", (name_id,))
        await self.db.commit()
        return current

    async def record_applied(self, name_id: int, *, applied: str, ipv4: str, now: str) -> None:
        """A successful write: what it put in the record; the last error is cleared."""
        if applied not in APPLIED_STATES:
            raise ValueError(f"failover_names: bad state {applied!r}")
        await self.db.conn.execute(
            "UPDATE failover_names SET applied = ?, applied_ipv4 = ?, applied_at = ?, last_error = NULL WHERE id = ?",
            (applied, ipv4, now, name_id),
        )
        await self.db.commit()

    async def record_error(self, name_id: int, error: str) -> None:
        """A failed write: the record was left as it was (``applied`` is not touched)."""
        await self.db.conn.execute(
            "UPDATE failover_names SET last_error = ? WHERE id = ?", (error[:300], name_id)
        )
        await self.db.commit()

    # ── runtime settings (schema_meta) ────────────────────────────────────────

    async def mode_on(self) -> bool:
        return await self.db.get_meta(META_MODE) == "on"

    async def set_mode(self, on: bool, *, now: str) -> None:
        await self.db.set_meta(META_MODE, "on" if on else "off")
        await self.db.set_meta(META_MODE_AT, now)

    async def mode_changed_at(self) -> str | None:
        return await self.db.get_meta(META_MODE_AT)

    async def get_setting(self, key: str) -> str:
        """A schema_meta value of this feature; "" when unset."""
        return (await self.db.get_meta(key)) or ""

    async def set_setting(self, key: str, value: str) -> None:
        await self.db.set_meta(key, value)

    async def sub_fallback_url(self) -> bool:
        """Whether subscriptions carry the ``fallback-url`` header (off unless switched on)."""
        return await self.db.get_meta(META_SUB_FALLBACK_URL) == "1"

    async def direct_host(self) -> str | None:
        """The DNS name direct links point at, or None: XRAY_PUBLIC_HOST / HYSTERIA2_HOST."""
        value = ((await self.db.get_meta(META_DIRECT_HOST)) or "").strip()
        return value or None

    # ── keys whose link carries the main server's address ─────────────────────

    async def single_direct_keys(self, *, issued_before: str | None = None) -> int:
        """ACTIVE direct keys (no relay) of VLESS/Hysteria2 that are not subscription
        children: the user imported their link once, with the host it had then.

        *issued_before* counts only the ones issued before that instant (the moment
        the direct host became a name): those were imported with the IPv4 and do not
        follow a DNS switch. An upper bound — a user may have re-imported since.
        """
        placeholders = ", ".join("?" for _ in _DIRECT_LINK_TYPES)
        params: list[object] = [_ACTIVE, *_DIRECT_LINK_TYPES]
        # "Single" = active minus attached children (a set bundle_id is the
        # unambiguous direction — see RelayRepository.usage).
        query = (
            "SELECT COUNT(*) AS n, "
            "COALESCE(SUM(CASE WHEN bundle_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS children "
            f"FROM vpn_keys WHERE status = ? AND relay IS NULL AND key_type IN ({placeholders})"
        )
        if issued_before:
            query += " AND created_at < ?"
            params.append(issued_before)
        row = await self.db.conn.execute_fetchone(query, tuple(params))
        return int(row["n"]) - int(row["children"]) if row is not None else 0


def names_of(rows: Sequence[FailoverName]) -> frozenset[str]:
    return frozenset(row.name for row in rows)
