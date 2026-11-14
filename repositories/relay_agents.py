"""Persistence for the relays the bot manages over SSH (docs/relay.md).

``relay_agents`` — one row per paired relay (cascades with its ``relays`` row);
``relay_pairings`` — the codes issued in «Мастер настройки → Relay → Добавить».
Written only by :class:`services.relay_agents.RelayAgentService`.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from aiosqlite import Row

from db.database import Database
from models.dto import RelayAgent, RelayPairing

_AGENT_COLUMNS = (
    "relay_id, ssh_host, ssh_port, host_key, target_host, tcp_ports, udp_ports, agent_version, "
    "paired_at, last_status_json, last_status_at"
)
_PAIRING_COLUMNS = (
    "id, name, token, target_host, tcp_ports, udp_ports, state, expires_at, created_by, created_at, "
    "relay_id, completed_at"
)
PAIRING_STATES = frozenset({"pending", "completed", "cancelled", "expired"})


def _ports(value: str) -> tuple[int, ...]:
    return tuple(sorted(int(p) for p in value.split(",") if p.strip()))


def _format_ports(ports: Sequence[int]) -> str:
    return ",".join(str(p) for p in sorted(ports))


def _status(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        data = json.loads(str(value))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _row_to_agent(row: Row) -> RelayAgent:
    return RelayAgent(
        relay_id=int(row["relay_id"]),
        ssh_host=str(row["ssh_host"]),
        ssh_port=int(row["ssh_port"]),
        host_key=str(row["host_key"]),
        target_host=str(row["target_host"]),
        tcp_ports=_ports(str(row["tcp_ports"])),
        udp_ports=_ports(str(row["udp_ports"])),
        agent_version=str(row["agent_version"]),
        paired_at=str(row["paired_at"]),
        last_status=_status(row["last_status_json"]),
        last_status_at=None if row["last_status_at"] is None else str(row["last_status_at"]),
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
    )


class RelayAgentRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    # ── relay_agents ──────────────────────────────────────────────────────────

    async def get(self, relay_id: int) -> RelayAgent | None:
        row = await self.db.conn.execute_fetchone(
            f"SELECT {_AGENT_COLUMNS} FROM relay_agents WHERE relay_id = ?", (relay_id,)
        )
        return None if row is None else _row_to_agent(row)

    async def list_all(self) -> list[RelayAgent]:
        rows = await self.db.conn.execute_fetchall(f"SELECT {_AGENT_COLUMNS} FROM relay_agents ORDER BY relay_id")
        return [_row_to_agent(row) for row in rows]

    async def create(
        self,
        *,
        relay_id: int,
        ssh_host: str,
        ssh_port: int,
        host_key: str,
        target_host: str,
        tcp_ports: Sequence[int],
        udp_ports: Sequence[int],
        agent_version: str,
        now: str,
        status: dict[str, object] | None = None,
    ) -> RelayAgent:
        await self.db.conn.execute(
            f"""
            INSERT INTO relay_agents ({_AGENT_COLUMNS})
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                relay_id,
                ssh_host,
                ssh_port,
                host_key,
                target_host,
                _format_ports(tcp_ports),
                _format_ports(udp_ports),
                agent_version,
                now,
                None if status is None else json.dumps(status, sort_keys=True),
                None if status is None else now,
            ),
        )
        await self.db.commit()
        agent = await self.get(relay_id)
        if agent is None:
            raise RuntimeError("relay_agents insert failed")
        return agent

    async def record_status(self, relay_id: int, status: dict[str, object], *, now: str, agent_version: str) -> None:
        await self.db.conn.execute(
            "UPDATE relay_agents SET last_status_json = ?, last_status_at = ?, agent_version = ? WHERE relay_id = ?",
            (json.dumps(status, sort_keys=True), now, agent_version, relay_id),
        )
        await self.db.commit()

    async def update_forward(
        self, relay_id: int, *, target_host: str, tcp_ports: Sequence[int], udp_ports: Sequence[int]
    ) -> None:
        await self.db.conn.execute(
            "UPDATE relay_agents SET target_host = ?, tcp_ports = ?, udp_ports = ? WHERE relay_id = ?",
            (target_host, _format_ports(tcp_ports), _format_ports(udp_ports), relay_id),
        )
        await self.db.commit()

    async def delete(self, relay_id: int) -> None:
        await self.db.conn.execute("DELETE FROM relay_agents WHERE relay_id = ?", (relay_id,))
        await self.db.commit()

    # ── relay_pairings ────────────────────────────────────────────────────────

    async def create_pairing(
        self,
        *,
        name: str,
        token: str,
        target_host: str,
        tcp_ports: Sequence[int],
        udp_ports: Sequence[int],
        expires_at: int,
        created_by: int | None,
        now: str,
    ) -> RelayPairing:
        cursor = await self.db.conn.execute(
            """
            INSERT INTO relay_pairings
              (name, token, target_host, tcp_ports, udp_ports, state, expires_at, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
            """,
            (name, token, target_host, _format_ports(tcp_ports), _format_ports(udp_ports), expires_at, created_by, now),
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

    async def pending_name_taken(self, name: str, *, exclude_id: int | None = None) -> bool:
        row = await self.db.conn.execute_fetchone(
            "SELECT 1 FROM relay_pairings WHERE state = 'pending' AND name = ? AND id != ? LIMIT 1",
            (name, -1 if exclude_id is None else exclude_id),
        )
        return row is not None

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
