"""Persistence for the WARP selective-split feed tables.

Six tables, one repository, because they are always read together and never
independently useful: ``warp_split_sources`` (where prefixes come from),
``warp_split_prefixes`` (what each origin currently contributes),
``warp_split_exclusions`` (what the operator vetoed), ``warp_split_baseline``
(the coverage of the last state actually applied), ``warp_split_pending`` (the
one candidate awaiting an admin's decision) and ``warp_split_runs`` (the journal
of unattended runs).

None of this is the routed list. That lives in ``/etc/vpn-bot/warp-split.list``
and is written only by the privileged helper — see
:class:`warp.split_manager.WarpSplitManager`.
"""
from __future__ import annotations

import json
import time
from collections.abc import Iterable, Mapping, Sequence

from aiosqlite import Row

from db.database import Database
from warp.feed_state import PendingCandidate, SplitRun, SplitSource
from warp.split_analysis import Coverage
from warp.split_merge import LIST_SCOPE, MANUAL_ORIGIN

_SOURCE_COLUMNS = (
    "id, slug, title, url, kind, mode, scope_slug, enabled, include_in_list, "
    "refresh_interval_sec, last_attempt_ts, last_success_ts, last_etag, "
    "last_modified, last_status, prefix_count, last_error, fail_streak"
)

# How many run rows to keep. Two weeks of six-hourly runs is 56 rows, so 200
# covers the review period the feature exists to support with room to spare,
# while staying small enough that the table never needs its own maintenance.
RUNS_KEPT = 200


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
        fail_streak=int(row["fail_streak"]),
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
                   prefix_count = ?, last_etag = ?, last_modified = ?, last_error = NULL,
                   fail_streak = 0
             WHERE slug = ?
            """,
            (stamp, stamp, status, prefix_count, etag, last_modified, slug),
        )
        await self.db.conn.commit()

    async def record_failure(
        self, slug: str, *, status: str, error: str, now: int | None = None
    ) -> None:
        """Stamp a failed refresh and advance the consecutive-failure counter.

        ``last_success_ts`` and the cached validators are deliberately left alone
        — they describe the last good state, which is what the merge falls back
        onto, and which is also what the staleness check measures against.
        """
        await self.db.conn.execute(
            """
            UPDATE warp_split_sources
               SET last_attempt_ts = ?, last_status = ?, last_error = ?,
                   fail_streak = fail_streak + 1
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

    # ── baseline (last APPLIED coverage) ──────────────────────────────────────

    async def baselines(self) -> dict[str, Coverage]:
        """Return ``{scope: Coverage}`` for every recorded baseline."""
        rows = await self.db.conn.execute_fetchall(
            "SELECT scope, addresses, prefixes FROM warp_split_baseline"
        )
        return {
            str(row["scope"]): Coverage(
                prefixes=int(row["prefixes"]), addresses=int(row["addresses"])
            )
            for row in rows
        }

    async def baseline_list_hash(self) -> str | None:
        row = await self.db.conn.execute_fetchone(
            "SELECT list_hash FROM warp_split_baseline WHERE scope = ?", (LIST_SCOPE,)
        )
        if row is None or row["list_hash"] is None:
            return None
        return str(row["list_hash"])

    async def set_baselines(
        self,
        coverages: Mapping[str, Coverage],
        *,
        list_hash: str | None = None,
        now: int | None = None,
    ) -> None:
        """Replace the baseline wholesale with the state that was just applied.

        Wholesale rather than per-scope: the baseline describes one moment, and a
        half-updated one (new list, old per-source numbers) would compare a
        candidate against a state that never existed. A source that has gone away
        loses its row here for the same reason.
        """
        stamp = int(time.time()) if now is None else now
        await self.db.conn.execute("DELETE FROM warp_split_baseline")
        await self.db.conn.executemany(
            """
            INSERT INTO warp_split_baseline (scope, addresses, prefixes, list_hash, applied_ts)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    scope,
                    coverage.addresses,
                    coverage.prefixes,
                    list_hash if scope == LIST_SCOPE else None,
                    stamp,
                )
                for scope, coverage in coverages.items()
            ],
        )
        await self.db.conn.commit()

    # ── pending candidate ─────────────────────────────────────────────────────

    async def pending(self) -> PendingCandidate | None:
        row = await self.db.conn.execute_fetchone(
            "SELECT ts, list_hash, list_text, reason, deltas_json FROM warp_split_pending WHERE id = 1"
        )
        if row is None:
            return None
        return PendingCandidate(
            ts=int(row["ts"]),
            list_hash=str(row["list_hash"]),
            prefixes=tuple(str(row["list_text"]).split()),
            reason=str(row["reason"]),
            deltas=json.loads(str(row["deltas_json"]) or "{}"),
        )

    async def set_pending(
        self,
        *,
        list_hash: str,
        prefixes: Sequence[str],
        reason: str,
        deltas: Mapping[str, object],
        now: int | None = None,
    ) -> None:
        """Store the candidate awaiting approval, replacing any earlier one."""
        await self.db.conn.execute(
            """
            INSERT INTO warp_split_pending (id, ts, list_hash, list_text, reason, deltas_json)
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              ts = excluded.ts, list_hash = excluded.list_hash,
              list_text = excluded.list_text, reason = excluded.reason,
              deltas_json = excluded.deltas_json
            """,
            (
                int(time.time()) if now is None else now,
                list_hash,
                "\n".join(prefixes),
                reason,
                json.dumps(deltas, ensure_ascii=False),
            ),
        )
        await self.db.conn.commit()

    async def clear_pending(self) -> None:
        await self.db.conn.execute("DELETE FROM warp_split_pending WHERE id = 1")
        await self.db.conn.commit()

    # ── run journal ───────────────────────────────────────────────────────────

    async def record_run(
        self,
        *,
        mode: str,
        decision: str,
        reason: str = "",
        list_hash: str = "",
        sources: Sequence[Mapping[str, object]] = (),
        metrics: Mapping[str, object] | None = None,
        now: int | None = None,
    ) -> None:
        """Append one run row and trim the table to :data:`RUNS_KEPT`.

        Trimming happens here rather than in a separate maintenance job so that
        the table cannot grow unbounded on a host whose operator never opens the
        panel — the write and the cleanup are the same act.
        """
        await self.db.conn.execute(
            """
            INSERT INTO warp_split_runs (ts, mode, decision, reason, list_hash, sources_json, metrics_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(time.time()) if now is None else now,
                mode,
                decision,
                reason,
                list_hash,
                json.dumps(list(sources), ensure_ascii=False),
                json.dumps(dict(metrics or {}), ensure_ascii=False),
            ),
        )
        await self.db.conn.execute(
            """
            DELETE FROM warp_split_runs
             WHERE id NOT IN (SELECT id FROM warp_split_runs ORDER BY id DESC LIMIT ?)
            """,
            (RUNS_KEPT,),
        )
        await self.db.conn.commit()

    async def recent_runs(self, limit: int = 10) -> list[SplitRun]:
        rows = await self.db.conn.execute_fetchall(
            """
            SELECT ts, mode, decision, reason, list_hash, sources_json, metrics_json
              FROM warp_split_runs ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        )
        return [
            SplitRun(
                ts=int(row["ts"]),
                mode=str(row["mode"]),
                decision=str(row["decision"]),
                reason=str(row["reason"]),
                list_hash=str(row["list_hash"]),
                sources=json.loads(str(row["sources_json"]) or "[]"),
                metrics=json.loads(str(row["metrics_json"]) or "{}"),
            )
            for row in rows
        ]

    async def count_runs(self) -> int:
        row = await self.db.conn.execute_fetchone("SELECT COUNT(*) AS n FROM warp_split_runs")
        return 0 if row is None else int(row["n"])
