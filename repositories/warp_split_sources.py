"""Persistence for the WARP selective-split feed tables.

Three tables, one repository, because they are always read together and never
independently useful: ``warp_split_sources`` (where prefixes come from),
``warp_split_prefixes`` (what each origin currently contributes) and
``warp_split_exclusions`` (what the operator vetoed).

None of this is the routed list. That lives in ``/etc/vpn-bot/warp-split.list``
and is written only by the privileged helper — see
:class:`warp.split_manager.WarpSplitManager`.
"""
from __future__ import annotations

import time
from collections.abc import Iterable, Sequence

from aiosqlite import Row

from db.database import Database
from warp.feed_state import SplitSource
from warp.split_merge import MANUAL_ORIGIN

_SOURCE_COLUMNS = (
    "id, slug, title, url, kind, mode, scope_slug, enabled, include_in_list, "
    "refresh_interval_sec, last_attempt_ts, last_success_ts, last_etag, "
    "last_modified, last_status, prefix_count, last_error"
)


def _row_to_source(row: Row) -> SplitSource:
    return SplitSource(
        id=int(row["id"]),
        slug=str(row["slug"]),
        title=str(row["title"]),
        url=str(row["url"]),
        kind=str(row["kind"]),
        mode=str(row["mode"]),
        scope_slug=None if row["scope_slug"] is None else str(row["scope_slug"]),
        enabled=bool(row["enabled"]),
        include_in_list=bool(row["include_in_list"]),
        refresh_interval_sec=int(row["refresh_interval_sec"]),
        last_attempt_ts=int(row["last_attempt_ts"]),
        last_success_ts=int(row["last_success_ts"]),
        last_etag=None if row["last_etag"] is None else str(row["last_etag"]),
        last_modified=None if row["last_modified"] is None else str(row["last_modified"]),
        last_status=None if row["last_status"] is None else str(row["last_status"]),
        prefix_count=int(row["prefix_count"]),
        last_error=None if row["last_error"] is None else str(row["last_error"]),
    )


class WarpSplitSourceRepository:
    """CRUD over the split-feed tables."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ── sources ───────────────────────────────────────────────────────────────

    async def list_sources(self) -> list[SplitSource]:
        rows = await self.db.conn.execute_fetchall(
            f"SELECT {_SOURCE_COLUMNS} FROM warp_split_sources ORDER BY id"
        )
        return [_row_to_source(row) for row in rows]

    async def get_source(self, slug: str) -> SplitSource | None:
        row = await self.db.conn.execute_fetchone(
            f"SELECT {_SOURCE_COLUMNS} FROM warp_split_sources WHERE slug = ?", (slug,)
        )
        return None if row is None else _row_to_source(row)

    async def add_source(
        self,
        *,
        slug: str,
        title: str,
        url: str,
        kind: str,
        mode: str = "add",
        scope_slug: str | None = None,
        enabled: bool = False,
        include_in_list: bool = True,
        refresh_interval_sec: int = 21600,
    ) -> None:
        """Insert a new source. Caller validates the relations first (see
        :func:`warp.split_merge.validate_source_relations`) so the admin gets a
        readable message instead of a CHECK-constraint traceback."""
        await self.db.conn.execute(
            """
            INSERT INTO warp_split_sources
              (slug, title, url, kind, mode, scope_slug, enabled, include_in_list,
               refresh_interval_sec)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                slug,
                title,
                url,
                kind,
                mode,
                scope_slug,
                1 if enabled else 0,
                1 if include_in_list else 0,
                refresh_interval_sec,
            ),
        )
        await self.db.conn.commit()

    async def delete_source(self, slug: str) -> None:
        """Remove a source, everything it contributed, and any operand that
        existed only to be subtracted from it.

        A subtract source scoped onto the deleted slug is DISABLED and its scope
        cleared — not silently promoted to a global subtraction. Promotion would
        widen the operand from "carve GCP out of goog.json" to "carve GCP out of
        everything, including the operator's hand-typed prefixes", which is a
        much bigger act than the delete that triggered it. Leaving the dangling
        scope in place is not an option either: the merge treats an unknown scope
        as inert, and inert-but-still-listed is how a subtraction stops happening
        without anyone noticing. Disabled with a stated reason is the only
        outcome the operator can actually see.
        """
        dependents = await self.db.conn.execute_fetchall(
            "SELECT slug FROM warp_split_sources WHERE scope_slug = ?", (slug,)
        )
        await self.db.conn.execute("DELETE FROM warp_split_sources WHERE slug = ?", (slug,))
        await self.db.conn.execute("DELETE FROM warp_split_prefixes WHERE origin = ?", (slug,))
        for row in dependents:
            await self.db.conn.execute(
                """
                UPDATE warp_split_sources
                   SET scope_slug = NULL, enabled = 0, last_status = 'disabled',
                       last_error = ?
                 WHERE slug = ?
                """,
                (f"scope source '{slug}' was deleted — re-enable deliberately", str(row["slug"])),
            )
        await self.db.conn.commit()

    async def set_enabled(self, slug: str, enabled: bool) -> None:
        await self.db.conn.execute(
            "UPDATE warp_split_sources SET enabled = ? WHERE slug = ?",
            (1 if enabled else 0, slug),
        )
        await self.db.conn.commit()

    async def record_attempt(self, slug: str, *, now: int | None = None) -> None:
        await self.db.conn.execute(
            "UPDATE warp_split_sources SET last_attempt_ts = ? WHERE slug = ?",
            (int(time.time()) if now is None else now, slug),
        )
        await self.db.conn.commit()

    async def record_success(
        self,
        slug: str,
        *,
        status: str,
        prefix_count: int,
        etag: str | None,
        last_modified: str | None,
        now: int | None = None,
    ) -> None:
        """Stamp a successful refresh and clear the previous error.

        ``status`` is a short machine-ish token shown in the panel ("ok",
        "not-modified", "cached") so the operator can tell a real download from a
        304 from a fall back onto the cache.
        """
        stamp = int(time.time()) if now is None else now
        await self.db.conn.execute(
            """
            UPDATE warp_split_sources
               SET last_attempt_ts = ?, last_success_ts = ?, last_status = ?,
                   prefix_count = ?, last_etag = ?, last_modified = ?, last_error = NULL
             WHERE slug = ?
            """,
            (stamp, stamp, status, prefix_count, etag, last_modified, slug),
        )
        await self.db.conn.commit()

    async def record_failure(
        self, slug: str, *, status: str, error: str, now: int | None = None
    ) -> None:
        """Stamp a failed refresh. ``last_success_ts`` and the cached validators
        are deliberately left alone — they describe the last good state, which is
        what the merge falls back onto."""
        await self.db.conn.execute(
            """
            UPDATE warp_split_sources
               SET last_attempt_ts = ?, last_status = ?, last_error = ?
             WHERE slug = ?
            """,
            (int(time.time()) if now is None else now, status, error[:512], slug),
        )
        await self.db.conn.commit()

    # ── prefixes ──────────────────────────────────────────────────────────────

    async def prefixes_for(self, origin: str) -> list[str]:
        rows = await self.db.conn.execute_fetchall(
            "SELECT prefix FROM warp_split_prefixes WHERE origin = ? ORDER BY prefix",
            (origin,),
        )
        return [str(row["prefix"]) for row in rows]

    async def all_prefixes(self) -> dict[str, list[str]]:
        """Return ``{origin: [prefix, …]}`` for every origin that has rows."""
        rows = await self.db.conn.execute_fetchall(
            "SELECT origin, prefix FROM warp_split_prefixes ORDER BY origin, prefix"
        )
        grouped: dict[str, list[str]] = {}
        for row in rows:
            grouped.setdefault(str(row["origin"]), []).append(str(row["prefix"]))
        return grouped

    async def replace_prefixes(self, origin: str, prefixes: Sequence[str]) -> None:
        """Make *origin*'s stored contribution exactly *prefixes*.

        Delete-then-insert rather than a diff: a feed's contribution is replaced
        wholesale on every successful refresh, and the row count is in the
        hundreds, so the simple form is both correct and fast enough.
        """
        now = int(time.time())
        await self.db.conn.execute("DELETE FROM warp_split_prefixes WHERE origin = ?", (origin,))
        if prefixes:
            await self.db.conn.executemany(
                "INSERT OR IGNORE INTO warp_split_prefixes (origin, prefix, added_at) VALUES (?, ?, ?)",
                [(origin, prefix, now) for prefix in prefixes],
            )
        await self.db.conn.commit()

    async def manual_prefixes(self) -> list[str]:
        return await self.prefixes_for(MANUAL_ORIGIN)

    async def set_manual_prefixes(self, prefixes: Sequence[str]) -> None:
        await self.replace_prefixes(MANUAL_ORIGIN, prefixes)

    async def add_manual_prefixes(self, prefixes: Iterable[str]) -> None:
        values = [(MANUAL_ORIGIN, prefix, int(time.time())) for prefix in prefixes]
        if not values:
            return
        await self.db.conn.executemany(
            "INSERT OR IGNORE INTO warp_split_prefixes (origin, prefix, added_at) VALUES (?, ?, ?)",
            values,
        )
        await self.db.conn.commit()

    async def remove_manual_prefixes(self, prefixes: Iterable[str]) -> None:
        values = [(MANUAL_ORIGIN, prefix) for prefix in prefixes]
        if not values:
            return
        await self.db.conn.executemany(
            "DELETE FROM warp_split_prefixes WHERE origin = ? AND prefix = ?", values
        )
        await self.db.conn.commit()

    # ── exclusions ────────────────────────────────────────────────────────────

    async def exclusions(self) -> list[str]:
        rows = await self.db.conn.execute_fetchall(
            "SELECT prefix FROM warp_split_exclusions ORDER BY prefix"
        )
        return [str(row["prefix"]) for row in rows]

    async def add_exclusion(self, prefix: str) -> None:
        await self.db.conn.execute(
            "INSERT OR IGNORE INTO warp_split_exclusions (prefix, created_at) VALUES (?, ?)",
            (prefix, int(time.time())),
        )
        await self.db.conn.commit()

    async def remove_exclusion(self, prefix: str) -> None:
        await self.db.conn.execute(
            "DELETE FROM warp_split_exclusions WHERE prefix = ?", (prefix,)
        )
        await self.db.conn.commit()
