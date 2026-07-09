
import asyncio
import hmac
import json
import logging
import os
from contextlib import suppress
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


class KeyStoreUnavailable(RuntimeError):
    """The backing DB could not be read (locked, corrupt, missing, disconnected).

    Distinct from a routine auth mismatch: the caller still fails closed, but this
    is an infrastructure fault worth logging loudly and counting, not a quiet
    'wrong token'. Mixing the two would either hide a broken data plane behind a
    flood of benign rejections or spam error logs on every bad guess.
    """


class ReadOnlyKeyStore:
    """Live, read-only view of active Hysteria2 secrets in vpn.db.

    Opens the database with ``mode=ro`` (writes raise) and re-queries on every
    handshake — there is NO cache, so a revoke (status flip away from 'active')
    or delete takes effect on the very next authentication. The per-handshake
    full scan of active keys is deliberate: caching secrets would delay revokes,
    which is the exact property this module exists to guarantee, so it is kept
    O(active-keys) per handshake on purpose.

    The connection pins an inode. To keep the revoke guarantee across an operator
    restoring vpn.db by swapping the file (atomic rename), each read checks whether
    the on-disk inode changed and reopens before querying — otherwise it would keep
    reading the stale, deleted inode and authenticate revoked keys.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._infra_failures = 0
        # (st_dev, st_ino) of the file backing the open connection, so a file swap
        # (restore/atomic rename) can be detected and the connection reopened.
        self._file_id: tuple[int, int] | None = None

    @property
    def uri(self) -> str:
        return f"file:{self._db_path}?mode=ro"

    @property
    def infra_failures(self) -> int:
        """Number of live reads that failed with an infrastructure error.

        Exposed as a lightweight metric: a steadily climbing value means the data
        plane is failing closed (DB locked/corrupt), not that clients are sending
        bad tokens.
        """
        return self._infra_failures

    async def connect(self) -> None:
        """Open the read-only connection. Raises if the DB file is missing."""
        await self._open()

    async def _open(self) -> None:
        conn = await aiosqlite.connect(self.uri, uri=True)
        # busy_timeout matters here: the bot is the live writer, so a read that
        # lands during a checkpoint/commit must wait briefly instead of failing.
        await conn.execute("PRAGMA busy_timeout = 5000")
        self._conn = conn
        self._file_id = self._current_file_id()

    def _current_file_id(self) -> tuple[int, int] | None:
        """Return ``(st_dev, st_ino)`` of the DB file, or ``None`` if unstatable."""
        try:
            st = os.stat(self._db_path)
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    async def _reopen_if_replaced(self) -> None:
        """Reopen the connection if vpn.db was swapped on disk (restore/rename).

        A missing/unstatable file leaves the existing connection in place; the
        query below then fails and surfaces as :class:`KeyStoreUnavailable`
        (fail-closed), rather than us reopening against a half-written file.
        """
        current = self._current_file_id()
        if current is None or current == self._file_id:
            return
        logger.warning(
            "hy2_auth: vpn.db was replaced on disk (inode changed) — reopening read-only connection"
        )
        if self._conn is not None:
            with suppress(Exception):
                await self._conn.close()
            self._conn = None
        try:
            await self._open()
        except (aiosqlite.Error, OSError) as exc:
            # A swap to a missing/broken DB must stay fail-closed, matching a live
            # read fault: count it and surface KeyStoreUnavailable so healthcheck
            # returns 503 and auth returns ok:false rather than a raw 5xx.
            self._infra_failures += 1
            logger.error(
                "hy2_auth: reopening vpn.db after a file swap failed (infra failure #%d): %s",
                self._infra_failures,
                exc,
            )
            raise KeyStoreUnavailable(str(exc)) from exc

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def _read_active_rows(self) -> list[aiosqlite.Row]:
        """Run the live SELECT, mapping any DB fault to KeyStoreUnavailable."""
        async with self._lock:
            await self._reopen_if_replaced()
            if self._conn is None:
                raise KeyStoreUnavailable("ReadOnlyKeyStore is not connected")
            try:
                cursor = await self._conn.execute(
                    _ACTIVE_SECRETS_SQL, (_KEY_TYPE_HYSTERIA2, _STATUS_ACTIVE)
                )
                return list(await cursor.fetchall())
            except aiosqlite.Error as exc:
                self._infra_failures += 1
                # Loud, distinguishable from a token mismatch: this is the data
                # plane breaking (DB locked beyond busy_timeout, corrupt, gone).
                logger.error(
                    "hy2_auth: live DB read failed (infra failure #%d) — failing closed: %s",
                    self._infra_failures,
                    exc,
                )
                raise KeyStoreUnavailable(str(exc)) from exc

    async def fetch_active_secrets(self) -> list[tuple[str, str]]:
        """Return ``(label, secret)`` for every active Hysteria2 key, read live.

        Raises :class:`KeyStoreUnavailable` if the underlying DB read fails.
        """
        rows = await self._read_active_rows()
        result: list[tuple[str, str]] = []
        for label, payload_json in rows:
            # A skipped row is a silent per-user auth outage otherwise; log it at
            # debug (by label — never the secret) so "my key stopped working" is
            # diagnosable and distinguishable from "no active key".
            try:
                data = json.loads(payload_json)
            except (TypeError, ValueError):
                logger.debug("hy2_auth: skipping active key %r — unparseable payload_json", label)
                continue
            if not isinstance(data, dict):
                logger.debug("hy2_auth: skipping active key %r — payload_json is not an object", label)
                continue
            secret = data.get("secret")
            if isinstance(label, str) and label and isinstance(secret, str) and secret:
                result.append((label, secret))
            else:
                logger.debug("hy2_auth: skipping active key %r — missing/invalid label or secret", label)
        return result

    async def match(self, incoming_auth: str) -> str | None:
        """Return the stats label of the active key whose secret matches, else None.

        Uses ``hmac.compare_digest`` for a constant-time comparison so the
        endpoint does not leak secret bytes through response timing. A plain
        non-match returns ``None`` and is logged only at debug — that is the
        routine 'wrong token' path and must stay quiet. An infrastructure fault
        propagates as :class:`KeyStoreUnavailable` (already error-logged + counted).
        """
        if not isinstance(incoming_auth, str) or not incoming_auth:
            return None
        # Compare on bytes, not str: hmac.compare_digest rejects a non-ASCII str
        # operand with TypeError, so a weird/non-ASCII client token would blow up
        # mid-loop. Encoding both sides to UTF-8 first turns that into a clean,
        # constant-time non-match instead of relying on a broad except upstream.
        incoming_bytes = incoming_auth.encode("utf-8")
        for label, secret in await self.fetch_active_secrets():
            if hmac.compare_digest(secret.encode("utf-8"), incoming_bytes):
                return label
        logger.debug("hy2_auth: presented token matched no active key")
        return None

    async def healthcheck(self) -> bool:
        """Probe the DB with the live read; ``True`` if healthy, ``False`` if not.

        Backs ``GET /healthz``. A failure here is the same infrastructure fault
        that makes auth fail closed, so it is counted/logged identically.
        """
        try:
            await self._read_active_rows()
            return True
        except KeyStoreUnavailable:
            return False
