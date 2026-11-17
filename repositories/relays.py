"""Persistence for the ``relays`` table — every L4 relay — and its pairing codes.

ONE model: a relay is one ``relays`` row, and how it is managed (its agent) is a
property of that row — the agent columns, all set when the bot manages it over SSH
and all NULL for a relay set up by hand (:class:`models.dto.RelayAgent`).
``relay_pairings`` holds the codes issued to add a relay or to connect an agent to
an existing one (temporary rows).

Reads are shared by both processes that need relays: the bot (through
:class:`services.relays.RelayService`, which caches a snapshot) and the
subscription endpoint, which reads the table on every request through its
read-only connection. Writes happen only in the bot, only through the relay
service.

``vpn_keys.relay`` is deliberately not a foreign key to ``relays.name`` (see
db/schema.sql), so the questions "how many keys use this relay" and "is this name
still referenced" are answered here, with plain queries over ``vpn_keys``.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from aiosqlite import Row

from config.validators import format_ipv4_networks, parse_ipv4_networks
from db.database import Database
from models.dto import Relay, RelayAgent, RelayPairing
from models.enums import VpnKeyStatus, VpnKeyType

_COLUMNS = (
    "id, name, label, host, source_ips, enabled, in_subscriptions, note, "
    "created_at, updated_at, created_by, updated_by, "
    "ssh_host, ssh_port, host_key, target_host, tcp_ports, udp_ports, "
    "agent_version, agent_paired_at, agent_status_json, agent_status_at, basic_visible"
)
# The agent columns, written all together and cleared all together.
AGENT_COLUMNS: tuple[str, ...] = (
    "ssh_host", "ssh_port", "host_key", "target_host", "tcp_ports", "udp_ports",
    "agent_version", "agent_paired_at", "agent_status_json", "agent_status_at",
)
_PAIRING_COLUMNS = (
    "id, name, token, target_host, tcp_ports, udp_ports, state, expires_at, created_by, created_at, "
    "relay_id, completed_at, kind, relay_host"
)
PAIRING_STATES = frozenset({"pending", "completed", "cancelled", "expired"})
# Set in the agent's status once `uninstall` ran on the relay (services.relays): the
# bot's key is gone there, and an interrupted delete/detach resumes without a second
# uninstall. A status written later never drops it (record_agent_status).
AGENT_UNINSTALLED_KEY = "uninstalled_at"
PAIRING_KINDS = frozenset({"new", "attach"})

# Columns an update may change. ``name`` is absent on purpose: it is the value
# keys carry in vpn_keys.relay and must never change once the row exists.
UPDATABLE_COLUMNS: frozenset[str] = frozenset(
    {"label", "host", "source_ips", "enabled", "in_subscriptions", "basic_visible", "note"}
)
# schema_meta key holding whether BASIC subscriptions serve the MAIN server's
# (direct) children: "0" hides them, anything else — the key absent included —
# shows them. The relays' twin is the relays.basic_visible column; the main server
# has no row of its own, so its flag lives in the database's runtime key-value
# store (db.database.Database.get_meta / set_meta) rather than in .env.
MAIN_BASIC_VISIBLE_META_KEY = "basic_visible_main"

_DELETED = VpnKeyStatus.DELETED.value
_ACTIVE = VpnKeyStatus.ACTIVE.value


def _ports(value: str) -> tuple[int, ...]:
    return tuple(sorted(int(p) for p in value.split(",") if p.strip()))


def format_ports(ports: Sequence[int]) -> str:
    return ",".join(str(p) for p in sorted(ports))


def _status(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        data = json.loads(str(value))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def status_json(status: Mapping[str, object] | None) -> str | None:
    return None if status is None else json.dumps(dict(status), sort_keys=True)


def _row_to_agent(row: Row) -> RelayAgent | None:
    """The relay's agent, or None when it has none (``ssh_host IS NULL``)."""
    if row["ssh_host"] is None:
        return None
    return RelayAgent(
        ssh_host=str(row["ssh_host"]),
        ssh_port=int(row["ssh_port"]),
        host_key=str(row["host_key"]),
        target_host=str(row["target_host"]),
        tcp_ports=_ports(str(row["tcp_ports"] or "")),
        udp_ports=_ports(str(row["udp_ports"] or "")),
        agent_version=str(row["agent_version"] or ""),
        paired_at=str(row["agent_paired_at"] or ""),
        last_status=_status(row["agent_status_json"]),
        last_status_at=None if row["agent_status_at"] is None else str(row["agent_status_at"]),
    )


def _row_to_relay(row: Row) -> Relay:
    """Map a row to a :class:`Relay`, with its agent when it has one.

    ``source_ips`` is re-parsed with the same strict parser the admin panel uses; a
    row someone edited by hand into garbage raises ``ValueError`` here rather than
    silently excluding fewer addresses than the operator believes.
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
        agent=_row_to_agent(row),
        basic_visible=bool(row["basic_visible"]),
    )


def _row_to_pairing(row: Row) -> RelayPairing:
    return RelayPairing(
        id=int(row["id"]),
        name=str(row["name"]),
        token=str(row["token"]),
        target_host=str(row["target_host"]),
        tcp_ports=_ports(str(row["tcp_ports"])),
        udp_ports=_ports(str(row["udp_ports"])),
        state=str(row["state"]),
        expires_at=int(row["expires_at"]),
        created_by=None if row["created_by"] is None else int(row["created_by"]),
        created_at=str(row["created_at"]),
        relay_id=None if row["relay_id"] is None else int(row["relay_id"]),
        completed_at=None if row["completed_at"] is None else str(row["completed_at"]),
        kind=str(row["kind"]),
        relay_host=None if row["relay_host"] is None else str(row["relay_host"]),
    )


def _agent_values(agent: RelayAgent) -> tuple[object, ...]:
    """The agent columns' values, in :data:`AGENT_COLUMNS` order."""
    return (
        agent.ssh_host,
        agent.ssh_port,
        agent.host_key,
        agent.target_host,
        format_ports(agent.tcp_ports),
        format_ports(agent.udp_ports),
        agent.agent_version,
        agent.paired_at,
        status_json(agent.last_status),
        agent.last_status_at,
    )


def _column_value(column: str, value: object) -> object:
    """Convert one updatable field to what the column stores."""
    if column in {"enabled", "in_subscriptions", "basic_visible"}:
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
    """CRUD over ``relays`` (agent columns included), ``relay_pairings`` and the
    ``vpn_keys`` queries the relay panel needs."""

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

    # ── the main server's visibility in BASIC subscriptions (schema_meta) ─────

    async def main_basic_visible(self) -> bool:
        """Whether BASIC subscriptions serve the main server's (direct) children.

        True unless the flag was explicitly switched off — a database that never
        had it (every one before this setting existed) keeps serving them. Read by
        both processes: the bot's relay screen and, per request, the subscription
        endpoint through its read-only connection.
        """
        return await self.db.get_meta(MAIN_BASIC_VISIBLE_META_KEY) != "0"

    async def set_main_basic_visible(self, visible: bool) -> None:
        await self.db.set_meta(MAIN_BASIC_VISIBLE_META_KEY, "1" if visible else "0")

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
        in_subscriptions: bool = False,
        basic_visible: bool = True,
        note: str | None = None,
        created_by: int | None = None,
        agent: RelayAgent | None = None,
    ) -> Relay:
        """Insert a relay — with its agent in the same row when given. Values are
        validated by the caller (the relay service); the UNIQUE constraints on
        ``name``/``label`` are the backstop for a race.

        ``in_subscriptions`` defaults to False and is ALWAYS written explicitly:
        the column's DEFAULT 1 (kept because changing it needs a table rebuild —
        see ``_migrate_v45``) never applies to a row created here. A relay joins
        subscriptions from its card, which also tops up the issued ones."""
        agent_values = _agent_values(agent) if agent is not None else (None,) * len(AGENT_COLUMNS)
        cursor = await self.db.conn.execute(
            f"""
            INSERT INTO relays
              (name, label, host, source_ips, enabled, in_subscriptions, basic_visible, note,
               created_at, updated_at, created_by, updated_by, {", ".join(AGENT_COLUMNS)})
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, {", ".join("?" for _ in AGENT_COLUMNS)})
            """,
            (
                name,
                label,
                host,
                format_ipv4_networks(source_ips),
                1 if enabled else 0,
                1 if in_subscriptions else 0,
                1 if basic_visible else 0,
                note,
                now,
                now,
                created_by,
                created_by,
                *agent_values,
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

    async def delete_if_unused(self, relay_id: int, *, now: str = "") -> bool:
        """Delete the relay only if no key outside status 'deleted' still names it.

        One DELETE statement, so the check and the delete cannot straddle a key
        being issued through the relay at that very moment. In the same
        transaction, BEFORE it (the foreign key nulls ``relay_pairings.relay_id``
        on delete), every pending 'attach' code of the relay is cancelled — a code
        for a relay that is gone must not linger. False (and nothing changed) when
        keys remain or the relay is already gone.
        """

        class _Kept(Exception):
            pass

        try:
            async with self.db.transaction():
                await self.db.conn.execute(
                    """
                    UPDATE relay_pairings SET state = 'cancelled', token = '', completed_at = ?
                    WHERE state = 'pending' AND kind = 'attach' AND relay_id = ?
                    """,
                    (now, relay_id),
                )
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
                if cursor.rowcount != 1:
                    raise _Kept
        except _Kept:
            return False
        return True

    # ── the agent (columns of the relay's own row) ────────────────────────────

    async def set_agent(self, relay_id: int, agent: RelayAgent, *, now: str, updated_by: int | None) -> bool:
        """Write every agent column of a relay that has NO agent yet. False when the
        relay is gone or already has one (nothing is changed then)."""
        assignments = ", ".join(f"{column} = ?" for column in AGENT_COLUMNS)
        cursor = await self.db.conn.execute(
            f"UPDATE relays SET {assignments}, updated_at = ?, updated_by = ? WHERE id = ? AND ssh_host IS NULL",
            (*_agent_values(agent), now, updated_by, relay_id),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def clear_agent(self, relay_id: int, *, now: str, updated_by: int | None) -> bool:
        """Clear every agent column; the relay itself (name, host, keys…) stays. False
        when the relay is gone or has no agent."""
        assignments = ", ".join(f"{column} = NULL" for column in AGENT_COLUMNS)
        cursor = await self.db.conn.execute(
            f"UPDATE relays SET {assignments}, updated_at = ?, updated_by = ? WHERE id = ? AND ssh_host IS NOT NULL",
            (now, updated_by, relay_id),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def record_agent_status(
        self, relay_id: int, status: Mapping[str, object], *, now: str, agent_version: str
    ) -> bool:
        """The last ``status`` answer of a relay's agent. False (nothing written) when
        the relay has no agent, or when ``uninstall`` already ran there and *status*
        does not carry that mark itself: a late answer of a status request that
        started before the uninstall must not erase it."""
        cursor = await self.db.conn.execute(
            "UPDATE relays SET agent_status_json = ?, agent_status_at = ?, agent_version = ? "
            "WHERE id = ? AND ssh_host IS NOT NULL AND (? OR agent_status_json IS NULL "
            "OR NOT json_valid(agent_status_json) OR json_extract(agent_status_json, ?) IS NULL)",
            (
                status_json(status), now, agent_version, relay_id,
                1 if status.get(AGENT_UNINSTALLED_KEY) else 0, f"$.{AGENT_UNINSTALLED_KEY}",
            ),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def update_agent_forward(
        self, relay_id: int, *, target_host: str, tcp_ports: Sequence[int], udp_ports: Sequence[int]
    ) -> None:
        await self.db.conn.execute(
            "UPDATE relays SET target_host = ?, tcp_ports = ?, udp_ports = ? WHERE id = ? AND ssh_host IS NOT NULL",
            (target_host, format_ports(tcp_ports), format_ports(udp_ports), relay_id),
        )
        await self.db.commit()

    # ── pairing codes (relay_pairings) ────────────────────────────────────────

    async def create_pairing(
        self,
        *,
        kind: str,
        name: str,
        token: str,
        target_host: str,
        tcp_ports: Sequence[int],
        udp_ports: Sequence[int],
        expires_at: int,
        created_by: int | None,
        now: str,
        relay_id: int | None = None,
        relay_host: str | None = None,
    ) -> RelayPairing:
        if kind not in PAIRING_KINDS:
            raise ValueError(f"relay_pairings: bad kind {kind!r}")
        if (kind == "attach") != (relay_id is not None):
            raise ValueError("relay_pairings: an 'attach' pairing names its relay, a 'new' one does not")
        cursor = await self.db.conn.execute(
            """
            INSERT INTO relay_pairings
              (name, token, target_host, tcp_ports, udp_ports, state, expires_at, created_by, created_at,
               relay_id, kind, relay_host)
            VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
            """,
            (
                name, token, target_host, format_ports(tcp_ports), format_ports(udp_ports), expires_at,
                created_by, now, relay_id, kind, relay_host,
            ),
        )
        await self.db.commit()
        assert cursor.lastrowid is not None
        pairing = await self.get_pairing(int(cursor.lastrowid))
        if pairing is None:
            raise RuntimeError("relay_pairings insert failed")
        return pairing

    async def get_pairing(self, pairing_id: int) -> RelayPairing | None:
        row = await self.db.conn.execute_fetchone(
            f"SELECT {_PAIRING_COLUMNS} FROM relay_pairings WHERE id = ?", (pairing_id,)
        )
        return None if row is None else _row_to_pairing(row)

    async def list_pending(self) -> list[RelayPairing]:
        rows = await self.db.conn.execute_fetchall(
            f"SELECT {_PAIRING_COLUMNS} FROM relay_pairings WHERE state = 'pending' ORDER BY id"
        )
        return [_row_to_pairing(row) for row in rows]

    async def pending_name_taken(self, name: str) -> bool:
        """A pending 'new' pairing already reserves this name."""
        row = await self.db.conn.execute_fetchone(
            "SELECT 1 FROM relay_pairings WHERE state = 'pending' AND kind = 'new' AND name = ? LIMIT 1", (name,)
        )
        return row is not None

    async def pending_attach(self, relay_id: int) -> RelayPairing | None:
        """The pending 'attach' pairing of this relay, if one was issued."""
        row = await self.db.conn.execute_fetchone(
            f"SELECT {_PAIRING_COLUMNS} FROM relay_pairings "
            "WHERE state = 'pending' AND kind = 'attach' AND relay_id = ? ORDER BY id LIMIT 1",
            (relay_id,),
        )
        return None if row is None else _row_to_pairing(row)

    async def finish_pairing(
        self, pairing_id: int, state: str, *, now: str, relay_id: int | None = None
    ) -> bool:
        """pending -> *state*, the token cleared. False when it was not pending any more."""
        if state not in PAIRING_STATES - {"pending"}:
            raise ValueError(f"relay_pairings: bad final state {state!r}")
        cursor = await self.db.conn.execute(
            """
            UPDATE relay_pairings
            SET state = ?, token = '', completed_at = ?, relay_id = COALESCE(?, relay_id)
            WHERE id = ? AND state = 'pending'
            """,
            (state, now, relay_id, pairing_id),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def expire_pairings(self, *, before: int, now: str) -> int:
        """Every pending pairing whose window closed before *before*: expired, token cleared."""
        cursor = await self.db.conn.execute(
            """
            UPDATE relay_pairings SET state = 'expired', token = '', completed_at = ?
            WHERE state = 'pending' AND expires_at < ?
            """,
            (now, before),
        )
        await self.db.commit()
        return int(cursor.rowcount or 0)

    # ── a pairing completed: the relay (or its agent) and the code in ONE transaction

    async def complete_new(
        self,
        pairing_id: int,
        *,
        name: str,
        label: str,
        host: str,
        source_ips: tuple[ipaddress.IPv4Network, ...],
        note: str | None,
        agent: RelayAgent,
        created_by: int | None,
        now: str,
    ) -> Relay | None:
        """Create the relay with its agent AND close the code, atomically.

        None (and nothing written) when the code is no longer pending.
        """
        async with self.db.transaction():
            row = await self.db.conn.execute_fetchone(
                "SELECT 1 FROM relay_pairings WHERE id = ? AND state = 'pending'", (pairing_id,)
            )
            if row is None:
                return None
            relay = await self.create(
                name=name,
                label=label,
                host=host,
                source_ips=source_ips,
                now=now,
                # A paired relay starts OUT of subscriptions: «Добавить в
                # подписки» on its card switches it in and tops every issued
                # subscription up in the same step.
                in_subscriptions=False,
                note=note,
                created_by=created_by,
                agent=agent,
            )
            if not await self.finish_pairing(pairing_id, "completed", now=now, relay_id=relay.id):
                raise RuntimeError("relay pairing closed inside its own transaction")
        return await self.get_by_id(relay.id)

    async def complete_attach(
        self,
        pairing_id: int,
        relay_id: int,
        *,
        agent: RelayAgent,
        source_ips: tuple[ipaddress.IPv4Network, ...] | None,
        updated_by: int | None,
        now: str,
    ) -> Relay | None:
        """Connect the agent to an existing relay AND close the code, atomically.

        Writes only the agent columns (and *source_ips* when given — the caller
        passes a superset of the current list); name, label, host and the keys are
        not touched. None — and nothing written — when the code is no longer
        pending, the relay is gone or it already has an agent.
        """
        async with self.db.transaction():
            row = await self.db.conn.execute_fetchone(
                "SELECT 1 FROM relay_pairings WHERE id = ? AND state = 'pending'", (pairing_id,)
            )
            if row is None or not await self.set_agent(relay_id, agent, now=now, updated_by=updated_by):
                return None
            if source_ips is not None:
                await self.update(relay_id, {"source_ips": source_ips}, now=now, updated_by=updated_by)
            if not await self.finish_pairing(pairing_id, "completed", now=now):
                raise RuntimeError("relay pairing closed inside its own transaction")
        return await self.get_by_id(relay_id)

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
