
import asyncio
import logging
import os
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import aiosqlite

from db.database import Database
from models.dto import KeyBundle, TrafficStats, VpnKey
from models.enums import KeyBundleStatus, VpnKeyStatus
from repositories.key_bundles import KeyBundleRepository
from repositories.traffic_stats import TrafficStatsRepository

logger = logging.getLogger(__name__)


class BundleStoreUnavailable(RuntimeError):
    """The backing DB could not be read (locked, corrupt, missing, replaced).

    Distinct from "no such token": the caller answers 404 either way, but this is
    an infrastructure fault worth logging loudly and counting, whereas an unknown
    token is the routine path and must stay quiet (an endpoint reachable from the
    internet would otherwise let anyone flood the log with guesses).
    """


class ReadOnlyDatabase(Database):
    """A :class:`~db.database.Database` that can only ever read.

    The point of subclassing instead of hand-writing SQL (which is what
    ``hy2_auth`` does) is that the ordinary repositories run unchanged on top of
    it: the endpoint sees exactly the rows, column mapping and enum decoding the
    rest of the codebase sees, while the connection itself makes a write
    impossible rather than merely unlikely — SQLite raises ``readonly`` on any
    attempt, even a future repository method that forgets it is on this path.

    Opening with ``mode=ro`` never creates the file, so a missing ``vpn.db``
    surfaces as a startup/read error instead of an empty database that would
    answer 404 to every legitimate subscription.
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._file_id: tuple[int, int] | None = None

    @property
    def uri(self) -> str:
        return f"file:{self.path}?mode=ro"

    async def connect(self) -> None:
        await self._open_readonly()

    async def _open_readonly(self) -> None:
        conn = await aiosqlite.connect(self.uri, uri=True)
        conn.row_factory = aiosqlite.Row
        # The bot is the live writer and keeps the DB in WAL mode: a read that
        # lands during a commit/checkpoint must wait briefly rather than fail.
        await conn.execute("PRAGMA busy_timeout = 5000")
        self._conn = conn
        self._file_id = self._current_file_id()

    def _current_file_id(self) -> tuple[int, int] | None:
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return (st.st_dev, st.st_ino)

    async def ensure_fresh(self) -> None:
        """Reopen the connection if ``vpn.db`` was swapped on disk (restore/rename).

        The open connection pins an inode, so without this an operator restoring
        the database by atomic rename would leave the endpoint serving from the
        old, deleted inode — handing out links for bundles that were revoked in
        the restored file. Same guarantee ``hy2_auth`` makes for handshakes.
        """
        current = self._current_file_id()
        if current is None or current == self._file_id:
            return
        logger.warning("subscription: vpn.db was replaced on disk (inode changed) — reopening read-only")
        if self._conn is not None:
            with suppress(Exception):
                await self._conn.close()
            self._conn = None
        await self._open_readonly()


@dataclass(frozen=True, slots=True)
class BundleView:
    """One active bundle plus everything the response is built from.

    ``keys`` holds only ACTIVE children, in creation order, so a child revoked on
    its own simply disappears from the subscription on the next fetch.
    """

    bundle: KeyBundle
    keys: tuple[VpnKey, ...]
    traffic: tuple[TrafficStats, ...]

    @property
    def expires_at(self) -> str | None:
        """The earliest expiry among the active children, or None if unlimited.

        Children of a bundle are created with one shared ``expires_at``; taking
        the earliest is the truthful answer if that ever stops holding, because
        that is when the subscription starts losing protocols.
        """
        stamps = sorted(key.expires_at for key in self.keys if key.expires_at)
        return stamps[0] if stamps else None


class ReadOnlyBundleStore:
    """Live, read-only view of subscription bundles, read through the repositories.

    There is NO cache: every request re-reads the bundle row and its children, so
    a revoke, a token rotation or a delete takes effect on the very next fetch
    without restarting anything — the property the whole "endpoint reads the live
    DB" design exists to guarantee.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db = ReadOnlyDatabase(Path(db_path))
        self._bundles = KeyBundleRepository(self._db)
        self._traffic = TrafficStatsRepository(self._db)
        self._lock = asyncio.Lock()
        self._infra_failures = 0

    @property
    def uri(self) -> str:
        return self._db.uri

    @property
    def infra_failures(self) -> int:
        """Live reads that failed with an infrastructure error (a lightweight metric)."""
        return self._infra_failures

    async def connect(self) -> None:
        await self._db.connect()

    async def close(self) -> None:
        await self._db.close()

    async def load_active_bundle(self, token: str) -> BundleView | None:
        """Return the ACTIVE bundle addressed by *token*, or None.

        None covers every "you get a 404" case without distinguishing them —
        unknown token, revoked bundle, deleted bundle, a bundle mid-transition —
        so the response cannot be used to confirm that a token ever existed.

        Raises :class:`BundleStoreUnavailable` if the database read itself fails.
        """
        async with self._lock:
            try:
                await self._db.ensure_fresh()
                bundle = await self._bundles.get_by_token(token)
                if bundle is None or bundle.status is not KeyBundleStatus.ACTIVE:
                    return None
                children = await self._bundles.list_keys_of_bundle(bundle.id)
                active = tuple(key for key in children if key.status is VpnKeyStatus.ACTIVE)
                stats = await self._traffic.list_by_key_ids([key.id for key in active])
            except (aiosqlite.Error, OSError, ValueError) as exc:
                self._infra_failures += 1
                logger.error(
                    "subscription: live DB read failed (infra failure #%d) — failing closed: %s",
                    self._infra_failures,
                    exc,
                )
                raise BundleStoreUnavailable(str(exc)) from exc
        # Only counters we actually measured: a key with no stats row contributes
        # nothing rather than a fabricated zero.
        measured = tuple(
            stats[key.id] for key in active if key.id in stats and stats[key.id].last_success_at
        )
        return BundleView(bundle=bundle, keys=active, traffic=measured)

    async def healthcheck(self) -> bool:
        """Probe the DB with a trivial live read; False when it cannot be read."""
        async with self._lock:
            try:
                await self._db.ensure_fresh()
                await self._db.conn.execute("SELECT 1 FROM key_bundles LIMIT 1")
            except (aiosqlite.Error, OSError) as exc:
                self._infra_failures += 1
                logger.error(
                    "subscription: healthcheck read failed (infra failure #%d): %s",
                    self._infra_failures,
                    exc,
                )
                return False
        return True
