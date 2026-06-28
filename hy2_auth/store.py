
import asyncio
import hmac
import json
import logging
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

# Hardcoded so this process stays fully decoupled from the bot package. These
# mirror models.enums.VpnKeyType.HYSTERIA2 and VpnKeyStatus.ACTIVE — kept in sync
# by hand (a value rename there must be reflected here).
_KEY_TYPE_HYSTERIA2 = "hysteria2"
_STATUS_ACTIVE = "active"

# Constant query (no interpolation of any value) against a read-only connection.
_ACTIVE_SECRETS_SQL = (
    "SELECT email_label, payload_json FROM vpn_keys "
    "WHERE key_type = ? AND status = ?"
)


class ReadOnlyKeyStore:
    """Live, read-only view of active Hysteria2 secrets in vpn.db.

    Opens the database with ``mode=ro`` (writes raise) and re-queries on every
    handshake — there is NO cache, so a revoke (status flip away from 'active')
    or delete takes effect on the very next authentication.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    @property
    def uri(self) -> str:
        return f"file:{self._db_path}?mode=ro"

    async def connect(self) -> None:
        """Open the read-only connection. Raises if the DB file is missing."""
        conn = await aiosqlite.connect(self.uri, uri=True)
        await conn.execute("PRAGMA busy_timeout = 5000")
        self._conn = conn

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def fetch_active_secrets(self) -> list[tuple[str, str]]:
        """Return ``(label, secret)`` for every active Hysteria2 key, read live."""
        if self._conn is None:
            raise RuntimeError("ReadOnlyKeyStore is not connected")
        async with self._lock:
            cursor = await self._conn.execute(_ACTIVE_SECRETS_SQL, (_KEY_TYPE_HYSTERIA2, _STATUS_ACTIVE))
            rows = await cursor.fetchall()
        result: list[tuple[str, str]] = []
        for label, payload_json in rows:
            try:
                data = json.loads(payload_json)
            except (TypeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            secret = data.get("secret")
            if isinstance(label, str) and label and isinstance(secret, str) and secret:
                result.append((label, secret))
        return result

    async def match(self, incoming_auth: str) -> str | None:
        """Return the stats label of the active key whose secret matches, else None.

        Uses ``hmac.compare_digest`` for a constant-time comparison so the
        endpoint does not leak secret bytes through response timing.
        """
        if not isinstance(incoming_auth, str) or not incoming_auth:
            return None
        for label, secret in await self.fetch_active_secrets():
            if hmac.compare_digest(secret, incoming_auth):
                return label
        return None
