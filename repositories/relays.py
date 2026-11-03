"""Persistence for the ``relays`` table — the L4 relays managed from the admin panel.

Reads are shared by both processes that need relays: the bot (through
:class:`services.relay_management.RelayService`, which caches a snapshot) and the
subscription endpoint, which reads the table on every request through its
read-only connection. Writes happen only in the bot, only through the relay
service.

``vpn_keys.relay`` is deliberately not a foreign key to ``relays.name`` (see
db/schema.sql), so the questions "how many keys use this relay" and "is this name
still referenced" are answered here, with plain queries over ``vpn_keys``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass

from aiosqlite import Row

from config.validators import format_ipv4_networks, parse_ipv4_networks
from db.database import Database
from models.dto import Relay
from models.enums import VpnKeyStatus, VpnKeyType

_COLUMNS = (
    "id, name, label, host, source_ips, enabled, in_subscriptions, note, "
    "created_at, updated_at, created_by, updated_by"
)

# Columns an update may change. ``name`` is absent on purpose: it is the value
# keys carry in vpn_keys.relay and must never change once the row exists.
UPDATABLE_COLUMNS: frozenset[str] = frozenset(
    {"label", "host", "source_ips", "enabled", "in_subscriptions", "note"}
)

_DELETED = VpnKeyStatus.DELETED.value
_ACTIVE = VpnKeyStatus.ACTIVE.value


def _row_to_relay(row: Row) -> Relay:
    """Map a row to a :class:`Relay`.

    ``source_ips`` is re-parsed with the same strict parser the admin panel and the
    ``.env`` loader use; a row someone edited by hand into garbage raises
    ``ValueError`` here rather than silently excluding fewer addresses than the
    operator believes.
    """
    return Relay(
        id=int(row["id"]),
        name=str(row["name"]),
        label=str(row["label"]),
        host=str(row["host"]),
        source_ips=parse_ipv4_networks("relays.source_ips", str(row["source_ips"])),
        enabled=bool(row["enabled"]),
        in_subscriptions=bool(row["in_subscriptions"]),
        note=None if row["note"] is None else str(row["note"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        created_by=None if row["created_by"] is None else int(row["created_by"]),
        updated_by=None if row["updated_by"] is None else int(row["updated_by"]),
    )


def _column_value(column: str, value: object) -> object:
    """Convert one updatable field to what the column stores."""
    if column in {"enabled", "in_subscriptions"}:
        return 1 if value else 0
    if column == "source_ips":
        assert isinstance(value, tuple)
        return format_ipv4_networks(value)
    return value


@dataclass(frozen=True, slots=True)
class RelayUsage:
    """How the keys of one relay are spread, for the panel and the delete flow.

    Every count excludes rows with status ``deleted``: those are history, they
    never render a link again and they do not stop a relay from being deleted.
    """

    # Keys through this relay in any status except 'deleted'.
    keys: int
    # Of those, the children of all-in-one bundles…
    bundle_keys: int
    # …spread over this many distinct bundles.
    bundles: int
    # ACTIVE keys through this relay.
    active_keys: int
    # ACTIVE keys through this relay that are NOT bundle children — the ones a user
    # imported as a single link and must re-import after the relay's host changes.
    single_active_keys: int


@dataclass(frozen=True, slots=True)
class RelayKeyRef:
    """A key to remove when a relay is deleted together with its keys."""

    id: int
    key_type: VpnKeyType
    bundle_id: int | None


class RelayRepository:
    """CRUD over ``relays`` plus the ``vpn_keys`` queries the relay panel needs."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ── reads ─────────────────────────────────────────────────────────────────

    async def list_all(self) -> list[Relay]:
        """Every relay, enabled or not, in ``id`` order (the order subscriptions use)."""
        rows = await self.db.conn.execute_fetchall(f"SELECT {_COLUMNS} FROM relays ORDER BY id")
        return [_row_to_relay(row) for row in rows]

    async def list_enabled(self) -> list[Relay]:
        """The relays switched on, in ``id`` order."""
        rows = await self.db.conn.execute_fetchall(
            f"SELECT {_COLUMNS} FROM relays WHERE enabled = 1 ORDER BY id"
        )
        return [_row_to_relay(row) for row in rows]

    async def get_by_id(self, relay_id: int) -> Relay | None:
        row = await self.db.conn.execute_fetchone(f"SELECT {_COLUMNS} FROM relays WHERE id = ?", (relay_id,))
        return None if row is None else _row_to_relay(row)

    async def get_by_name(self, name: str) -> Relay | None:
        row = await self.db.conn.execute_fetchone(f"SELECT {_COLUMNS} FROM relays WHERE name = ?", (name,))
        return None if row is None else _row_to_relay(row)

    async def get_by_label(self, label: str) -> Relay | None:
        row = await self.db.conn.execute_fetchone(f"SELECT {_COLUMNS} FROM relays WHERE label = ?", (label,))
        return None if row is None else _row_to_relay(row)

    async def count(self) -> int:
        row = await self.db.conn.execute_fetchone("SELECT COUNT(*) AS n FROM relays")
        return int(row["n"]) if row is not None else 0

    # ── writes ────────────────────────────────────────────────────────────────

    async def create(
        self,
        *,
        name: str,
        label: str,
        host: str,
        source_ips: tuple[ipaddress.IPv4Network, ...],
        now: str,
        enabled: bool = True,
        in_subscriptions: bool = True,
        note: str | None = None,
        created_by: int | None = None,
    ) -> Relay:
        """Insert a relay. Values are validated by the caller (the relay service);
        the UNIQUE constraints on ``name``/``label`` are the backstop for a race."""
        cursor = await self.db.conn.execute(
            """
            INSERT INTO relays
              (name, label, host, source_ips, enabled, in_subscriptions, note,
               created_at, updated_at, created_by, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                label,
                host,
                format_ipv4_networks(source_ips),
                1 if enabled else 0,
                1 if in_subscriptions else 0,
                note,
                now,
                now,
                created_by,
                created_by,
            ),
        )
        await self.db.commit()
        assert cursor.lastrowid is not None
        relay = await self.get_by_id(int(cursor.lastrowid))
        if relay is None:
            raise RuntimeError("Relay insert failed")
        return relay

    async def update(
        self, relay_id: int, changes: Mapping[str, object], *, now: str, updated_by: int | None
    ) -> Relay | None:
        """Apply *changes* (a subset of :data:`UPDATABLE_COLUMNS`) to one relay.

        Returns the updated row, or None when the relay no longer exists.
        """
        unknown = set(changes) - UPDATABLE_COLUMNS
        if unknown:
            raise ValueError(f"relays: columns cannot be updated: {sorted(unknown)}")
        if changes:
            columns = sorted(changes)
            assignments = ", ".join(f"{column} = ?" for column in columns)
            await self.db.conn.execute(
                f"UPDATE relays SET {assignments}, updated_at = ?, updated_by = ? WHERE id = ?",
                (*(_column_value(column, changes[column]) for column in columns), now, updated_by, relay_id),
            )
            await self.db.commit()
        return await self.get_by_id(relay_id)

    async def delete_if_unused(self, relay_id: int) -> bool:
        """Delete the relay only if no key outside status 'deleted' still names it.

        One statement, so the check and the delete cannot straddle a key being
        issued through the relay at that very moment. False when keys remain (or
        the relay is already gone).
        """
        cursor = await self.db.conn.execute(
            """
            DELETE FROM relays
            WHERE id = ?
              AND NOT EXISTS (
                SELECT 1 FROM vpn_keys WHERE vpn_keys.relay = relays.name AND vpn_keys.status != ?
              )
            """,
            (relay_id, _DELETED),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    # ── keys through a relay ──────────────────────────────────────────────────

    async def name_used_by_keys(self, name: str) -> bool:
        """Whether any key row — in ANY status, 'deleted' included — names *name*.

        Such a name can never be given to a new relay: those keys (or their
        history) would silently start pointing at somebody else's host.
        """
        row = await self.db.conn.execute_fetchone("SELECT 1 FROM vpn_keys WHERE relay = ? LIMIT 1", (name,))
        return row is not None

    async def usage(self, name: str) -> RelayUsage:
        row = await self.db.conn.execute_fetchone(
            """
            SELECT
              COUNT(*) AS keys,
              COALESCE(SUM(CASE WHEN bundle_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS bundle_keys,
              COUNT(DISTINCT bundle_id) AS bundles,
              COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS active_keys,
              COALESCE(SUM(CASE WHEN status = ? AND bundle_id IS NOT NULL THEN 1 ELSE 0 END), 0)
                AS active_bundle_keys
            FROM vpn_keys
            WHERE relay = ? AND status != ?
            """,
            (_ACTIVE, _ACTIVE, name, _DELETED),
        )
        if row is None:
            return RelayUsage(0, 0, 0, 0, 0)
        active = int(row["active_keys"])
        # "Single" = active and NOT attached to a bundle, counted as active minus
        # attached children (a set bundle_id is the unambiguous direction — see
        # tests/test_key_bundles.py::test_no_production_query_selects_keys_by_bundle_id_is_null).
        return RelayUsage(
            keys=int(row["keys"]),
            bundle_keys=int(row["bundle_keys"]),
            bundles=int(row["bundles"]),
            active_keys=active,
            single_active_keys=active - int(row["active_bundle_keys"]),
        )

    async def active_key_counts(self) -> dict[str, int]:
        """ACTIVE keys per relay name, for the relay list."""
        rows = await self.db.conn.execute_fetchall(
            "SELECT relay, COUNT(*) AS n FROM vpn_keys WHERE relay IS NOT NULL AND status = ? GROUP BY relay",
            (_ACTIVE,),
        )
        return {str(row["relay"]): int(row["n"]) for row in rows}

    async def list_keys(self, name: str) -> list[RelayKeyRef]:
        """The keys through *name* outside status 'deleted', oldest first."""
        rows = await self.db.conn.execute_fetchall(
            "SELECT id, key_type, bundle_id FROM vpn_keys WHERE relay = ? AND status != ? ORDER BY id",
            (name, _DELETED),
        )
        return [
            RelayKeyRef(
                id=int(row["id"]),
                key_type=VpnKeyType(str(row["key_type"])),
                bundle_id=None if row["bundle_id"] is None else int(row["bundle_id"]),
            )
            for row in rows
        ]
