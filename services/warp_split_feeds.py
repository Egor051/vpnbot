"""Prefix feeds for the WARP selective-split list.

Orchestrates four things that each live somewhere else: the HTTP fetch
(:mod:`adapters.warp_feed_fetcher`), the stored source/prefix/exclusion state
(:mod:`repositories.warp_split_sources`), the pure set arithmetic
(:mod:`warp.split_merge`) and the privileged write
(:class:`warp.split_manager.WarpSplitManager`).

The rule the whole module is arranged around: **a feed failure must never
shorten the routed list.** Every operand resolves to its stored contribution
when the network is down, a source that has never succeeded aborts the merge
outright rather than contributing nothing, and the apply is skipped entirely
when the rendered list matches the file already on disk. The failure mode being
designed against is not "the update did not happen" — that is fine and
recoverable — it is "the update happened with a silently empty operand", which
on the Google pair means every GCP customer range quietly enters the tunnel.

That rule covers a *broken* feed. :meth:`WarpSplitFeedService.run_cycle` covers
the harder case — a feed that works perfectly and publishes something wrong —
by never letting the unattended path apply a change nobody has looked at unless
it survives three separate filters:

* the **ratchet** (:mod:`warp.split_analysis`), measured in addresses against
  the last state actually applied, with the subtract direction checked
  separately because a shrinking subtrahend *grows* the routed list;
* the **confirmation streak**, so a single bad publication that is corrected an
  hour later never reaches the routing table at all;
* the **admin card**, which everything else lands in — including, in ``review``
  mode, a change that passed every threshold.

Anything the guards in :class:`warp.split_manager.WarpSplitManager` reject is a
different category: it is not "suspicious", it is invalid, and it is never
queued for approval, because a button that offers to apply a list the manager
will refuse anyway is a button that teaches admins to distrust the buttons.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from adapters.warp_feed_fetcher import FeedFetchError, WarpFeedFetcher
from db.database import Database
from i18n import t
from repositories.warp_split_sources import WarpSplitSourceRepository
from warp.feed_state import PendingCandidate, SplitRun, SplitSource
from warp.split_analysis import (
    HOLD_EMPTY_SOURCE,
    HOLD_GROWTH,
    HOLD_REVIEW_MODE,
    HOLD_SHRINK_ADD,
    HOLD_SHRINK_SUBTRACT,
    HOLD_STALE_SOURCE,
    HOLD_STREAK,
    ChangeAnalysis,
    Coverage,
    Hold,
    SourceState,
    Thresholds,
    analyse_change,
    coverage_of,
    list_hash,
    with_hold,
)
from warp.split_manager import (
    ApplyOutcome,
    CidrResult,
    WarpSplitCapExceeded,
    WarpSplitError,
    WarpSplitManager,
)
from warp.split_merge import (
    LIST_SCOPE,
    MANUAL_ORIGIN,
    EmptyFeedError,
    FeedParseError,
    MergeReport,
    SourceContribution,
    merge_split_list,
    parse_feed,
    validate_slug,
    validate_source_relations,
)

logger = logging.getLogger(__name__)

# Meta key recording that the pre-feed list file has been adopted as the manual
# set. Without it an operator who legitimately deletes every manual prefix would
# have the file re-adopted on the next restart.
_ADOPTED_META_KEY = "warp_split_manual_adopted"

# The scheduler never fires at startup: a restart loop must not be able to
# rewrite the routing policy before anyone can look at the panel.
FIRST_RUN_DELAY_SECONDS = 300

# Jitter band around the configured interval, so several hosts sharing a feed do
# not synchronise onto the same second.
_JITTER_FRACTION = 0.1

# Meta keys holding the confirm-by-repetition streak. Two scalars, so they live
# in the existing meta table rather than in a table of their own.
_STREAK_HASH_KEY = "warp_split_streak_hash"
_STREAK_COUNT_KEY = "warp_split_streak_count"

# What ``WARP_SPLIT_FEEDS_MODE`` accepts.
MODE_OFF = "off"
MODE_REVIEW = "review"
MODE_AUTO = "auto"
FEED_MODES = frozenset({MODE_OFF, MODE_REVIEW, MODE_AUTO})

# The five outcomes a run can have, recorded in warp_split_runs.decision.
# ``nochange`` means the host was not touched — either the candidate matched what
# is already applied, or auto mode is still waiting for the streak.
DECISION_APPLIED = "applied"
DECISION_QUEUED = "queued"
DECISION_NOCHANGE = "nochange"
DECISION_REJECTED = "rejected"
DECISION_FAILED = "failed"

# How many changed prefixes the approval card spells out, and how many it keeps
# in the stored payload for "show in full". The card must survive Telegram's
# message cap even when a subtraction adds 163 entries at once.
_CARD_SAMPLE = 10
_CARD_STORE_SAMPLE = 50


class WarpFeedError(WarpSplitError):
    """A feed-level failure that is safe to show to the admin verbatim."""


class WarpFeedStaleCandidate(WarpFeedError):
    """The approved card no longer describes what the merge computes.

    Its own type because the caller must not treat it as a guard rejection: the
    candidate may be perfectly valid, it is simply not the one the admin looked
    at — the honest response is to recompute and ask again, not to apply either
    list.
    """


@dataclass(frozen=True, slots=True)
class SourceRefresh:
    """What happened to one source during a refresh."""

    slug: str
    status: str                 # "ok" | "not-modified" | "cached" | "error" | "empty"
    prefix_count: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status not in ("error", "empty")

    @property
    def empty_parse(self) -> bool:
        """The feed answered, and what it published contained no IPv4 prefix."""
        return self.status == "empty"


@dataclass(frozen=True, slots=True)
class MergePlan:
    """A computed candidate list, before anything is written."""

    prefixes: tuple[str, ...]
    report: MergeReport
    current: tuple[str, ...]
    subtract_pairs: tuple[tuple[str, str], ...] = ()

    @property
    def added(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.prefixes) - set(self.current)))

    @property
    def removed(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.current) - set(self.prefixes)))

    @property
    def identical(self) -> bool:
        return tuple(self.prefixes) == tuple(self.current)

    @property
    def delta_pct(self) -> float:
        """Size of the change relative to the list being replaced."""
        base = len(self.current)
        if base == 0:
            return 100.0 if self.prefixes else 0.0
        return 100.0 * (len(self.added) + len(self.removed)) / base


@dataclass(frozen=True, slots=True)
class RefreshResult:
    """Outcome of a full refresh cycle."""

    sources: tuple[SourceRefresh, ...] = ()
    plan: MergePlan | None = None
    outcome: ApplyOutcome | None = None
    blocked_reason: str | None = None
    alerts: tuple[str, ...] = ()

    @property
    def applied(self) -> bool:
        return self.outcome is not None and self.outcome.changed


@dataclass(frozen=True, slots=True)
class CycleResult:
    """Outcome of one unattended run, as recorded in ``warp_split_runs``.

    ``analysis`` is None only when the run never got as far as computing a
    candidate (a failed merge), so ``decision`` and it are read together.
    """

    mode: str
    decision: str
    reason: str = ""
    sources: tuple[SourceRefresh, ...] = ()
    analysis: ChangeAnalysis | None = None
    outcome: ApplyOutcome | None = None
    detail: str = ""
    streak: int = 0

    @property
    def queued(self) -> bool:
        return self.decision == DECISION_QUEUED

    @property
    def applied(self) -> bool:
        return self.decision == DECISION_APPLIED


class WarpSplitFeedService:
    """Fetches, merges and applies the split-list prefix feeds."""

    def __init__(
        self,
        *,
        db: Database,
        repo: WarpSplitSourceRepository,
        fetcher: WarpFeedFetcher,
        manager: WarpSplitManager,
        mode: str = MODE_REVIEW,
        thresholds: Thresholds | None = None,
        confirm_streak: int = 2,
        alert_cooldown_sec: int = 3600,
        fail_streak_alert: int = 3,
        notify: Callable[[str], Awaitable[None]] | None = None,
        notify_card: Callable[[str], Awaitable[None]] | None = None,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._db = db
        self._repo = repo
        self._fetcher = fetcher
        self._manager = manager
        self._mode = mode if mode in FEED_MODES else MODE_REVIEW
        self._thresholds = thresholds or Thresholds()
        self._confirm_streak = max(1, confirm_streak)
        self._alert_cooldown_sec = max(0, alert_cooldown_sec)
        self._fail_streak_alert = max(1, fail_streak_alert)
        self._notify = notify
        self._notify_card = notify_card
        self._clock = clock or (lambda: int(time.time()))
        # Alert de-duplication, in memory. A restart clears it, so the first run
        # after one may repeat a message the operator already has — the cost of
        # one duplicate is far below that of persisting a cooldown ledger and
        # having to reason about its staleness. Documented in docs/warp.md.
        self._alerted_at: dict[str, int] = {}

    @property
    def mode(self) -> str:
        return self._mode

    # ── one-time adoption of the pre-feed list ────────────────────────────────

    async def ensure_manual_adopted(self) -> None:
        """Record the pre-existing list file as the manual prefix set, once.

        The migration deliberately does not do this: the DB layer has no business
        reading ``/etc``, and on a dev box the file does not exist. Doing it here,
        guarded by a meta flag rather than by "is the table empty", means an
        operator who genuinely deletes every manual prefix does not get the old
        file resurrected on the next restart.
        """
        if await self._db.get_meta(_ADOPTED_META_KEY) == "1":
            return
        existing = self._manager.read_list()
        if existing:
            await self._repo.set_manual_prefixes(existing)
            logger.info(
                "warp-split: adopted %d prefix(es) from %s as the manual set",
                len(existing),
                self._manager.list_path,
            )
        await self._db.set_meta(_ADOPTED_META_KEY, "1")

    # ── merge ─────────────────────────────────────────────────────────────────

    async def build_plan(self) -> MergePlan:
        """Compute the candidate list from stored state. Never touches the network.

        Raises :class:`WarpFeedError` when an enabled operand has no stored
        contribution at all. That is the "base fresh, subtrahend empty" case, and
        proceeding would apply the base *without* its subtraction — for the
        Google pair, the entire GCP customer space routed through WARP. Refusing
        to merge leaves the previous list in place, which is always safe.
        """
        sources = await self._repo.list_sources()
        stored = await self._repo.all_prefixes()
        manual = _to_networks(stored.get(MANUAL_ORIGIN, ()))
        exclusions = _to_networks(await self._repo.exclusions())

        contributions: list[SourceContribution] = []
        subtract_pairs: list[tuple[str, str]] = []
        for source in sources:
            if not source.enabled:
                continue
            if source.mode == "add" and not source.include_in_list:
                # Fetched for use as somebody else's operand, but not routed.
                continue
            prefixes = stored.get(source.slug, [])
            if not prefixes:
                raise WarpFeedError(
                    f"source '{source.slug}' is enabled but has never produced a usable "
                    "prefix set (no cache) — the list was left unchanged rather than "
                    "applied without it"
                )
            contributions.append(
                SourceContribution(
                    slug=source.slug,
                    mode=source.mode,
                    networks=tuple(_to_networks(prefixes)),
                    scope_slug=source.scope_slug,
                )
            )
            if source.mode == "subtract":
                subtract_pairs.append((source.scope_slug or "all", source.slug))

        report = merge_split_list(
            manual=manual, sources=contributions, exclusions=exclusions
        )
        return MergePlan(
            prefixes=report.prefixes,
            report=report,
            current=tuple(self._manager.read_list()),
            subtract_pairs=tuple(subtract_pairs),
        )

    async def preview(self) -> MergePlan:
        """Build a plan and validate it, so the confirmation screen shows the
        same verdict the apply would produce."""
        plan = await self.build_plan()
        try:
            await self._manager.check_candidate(plan.prefixes)
        except WarpSplitCapExceeded as exc:
            raise WarpFeedError(self._cap_message(exc, plan)) from exc
        return plan

    def _cap_message(self, exc: WarpSplitCapExceeded, plan: MergePlan) -> str:
        """Explain a cap rejection by its cause, and offer the two ways out.

        "Too many prefixes" on its own is unactionable when the cause is a
        subtraction: the operator did not add 163 prefixes, a subtrahend shattered
        the ones they had.
        """
        if plan.subtract_pairs:
            pairs = ", ".join(f"{base}-{minus}" for base, minus in plan.subtract_pairs)
            cause = (
                f"after subtracting {pairs} the list came to {exc.count} prefixes "
                f"(limit {exc.limit})"
            )
        else:
            cause = f"the merged list came to {exc.count} prefixes (limit {exc.limit})"
        return (
            f"{cause}. Nothing was applied. Either raise WARP_SPLIT_MAX_PREFIXES, "
            "or turn the subtraction off and take the base source whole."
        )

    # ── refresh ───────────────────────────────────────────────────────────────

    async def refresh(
        self,
        *,
        slugs: Sequence[str] | None = None,
        apply: bool = True,
        actor_user_id: int | None = None,
    ) -> RefreshResult:
        """Fetch the enabled sources, then merge and (optionally) apply.

        Every source is fetched independently and a failure is recorded on its
        row rather than raised: one dead feed must not stop the others from
        updating, and the merge that follows uses each source's last good
        contribution regardless.
        """
        await self.ensure_manual_adopted()
        refreshed = await self._refresh_sources(slugs)
        alerts = [
            f"WARP split feed '{item.slug}' failed: {item.error}"
            for item in refreshed
            if not item.ok
        ]

        try:
            plan = await self.build_plan()
        except WarpFeedError as exc:
            alerts.append(str(exc))
            await self._send_alerts(alerts)
            return RefreshResult(
                sources=tuple(refreshed), blocked_reason=str(exc), alerts=tuple(alerts)
            )

        if not apply:
            await self._send_alerts(alerts)
            return RefreshResult(sources=tuple(refreshed), plan=plan, alerts=tuple(alerts))

        try:
            outcome = await self.apply_plan(plan, actor_user_id=actor_user_id)
        except WarpFeedError as exc:
            alerts.append(str(exc))
            await self._send_alerts(alerts)
            return RefreshResult(
                sources=tuple(refreshed),
                plan=plan,
                blocked_reason=str(exc),
                alerts=tuple(alerts),
            )

        await self._send_alerts(alerts)
        return RefreshResult(
            sources=tuple(refreshed), plan=plan, outcome=outcome, alerts=tuple(alerts)
        )

    async def _refresh_sources(self, slugs: Sequence[str] | None) -> tuple[SourceRefresh, ...]:
        """Fetch every enabled source (or just *slugs*), one at a time."""
        sources = await self._repo.list_sources()
        wanted = [
            source
            for source in sources
            if source.enabled and (slugs is None or source.slug in slugs)
        ]
        return tuple([await self._refresh_one(source) for source in wanted])

    async def _refresh_one(self, source: SplitSource) -> SourceRefresh:
        await self._repo.record_attempt(source.slug)
        try:
            payload = await self._fetcher.fetch(
                slug=source.slug,
                url=source.url,
                etag=source.last_etag,
                last_modified=source.last_modified,
            )
            parsed = parse_feed(source.kind, payload.text)
        except (FeedFetchError, FeedParseError) as exc:
            # "Published nothing" is recorded as its own status, not folded into
            # "error": the merge still succeeds (from the last good cache), so the
            # unattended path needs to know the difference between "we could not
            # ask" and "we asked and the answer was nothing".
            status = "empty" if isinstance(exc, EmptyFeedError) else "error"
            await self._repo.record_failure(source.slug, status=status, error=str(exc))
            logger.warning("warp-split feed %s failed (%s): %s", source.slug, status, exc)
            return SourceRefresh(slug=source.slug, status=status, error=str(exc))

        prefixes = [str(net) for net in parsed.networks]
        await self._repo.replace_prefixes(source.slug, prefixes)
        await self._repo.record_success(
            source.slug,
            status=payload.status,
            prefix_count=len(prefixes),
            etag=payload.etag,
            last_modified=payload.last_modified,
        )
        if parsed.invalid_lines:
            logger.info(
                "warp-split feed %s: %d unparseable line(s) ignored, first=%r",
                source.slug,
                len(parsed.invalid_lines),
                parsed.invalid_lines[0],
            )
        return SourceRefresh(
            slug=source.slug, status=payload.status, prefix_count=len(prefixes)
        )

    async def apply_plan(
        self, plan: MergePlan, *, actor_user_id: int | None = None
    ) -> ApplyOutcome:
        """Write *plan* through the manager, recomputing under its lock.

        The plan is recomputed inside ``apply_computed`` rather than written as
        captured: between building a preview and confirming it, an admin may have
        added a prefix in another chat. Recomputing means the confirmation
        applies the current truth; the preview stays what it always was — a
        forecast, not a promise.
        """
        try:
            outcome = await self._manager.apply_computed(
                self._recompute_for_apply, actor_user_id=actor_user_id
            )
        except WarpSplitCapExceeded as exc:
            raise WarpFeedError(self._cap_message(exc, plan)) from exc
        await self._after_apply()
        return outcome

    async def _recompute_for_apply(self) -> Sequence[str]:
        return (await self.build_plan()).prefixes

    async def _apply_and_record(self, *, actor_user_id: int | None = None) -> ApplyOutcome:
        """Apply the current merge and move the baseline to what was applied.

        Every mutation in this service funnels through here so that the ratchet's
        reference point is "the last state a human or a guard accepted", no matter
        which button produced it. Skipping this on, say, an exclusion would leave
        the baseline describing a list that has not been routed for weeks, and the
        first unattended run would then measure the feed against fiction.
        """
        outcome = await self._manager.apply_computed(
            self._recompute_for_apply, actor_user_id=actor_user_id
        )
        await self._after_apply()
        return outcome

    # ── baseline ──────────────────────────────────────────────────────────────

    async def _after_apply(self) -> None:
        """Record what is now on disk, and per source, as the new baseline."""
        await self._capture_baseline()

    async def _capture_baseline(self) -> None:
        current = self._manager.read_list()
        if not current:
            # An empty file is not a state worth ratcheting against; the manager
            # refuses to write one, so this can only be a file that was removed
            # out from under us. Leaving the old baseline in place keeps the next
            # comparison meaningful.
            return
        stored = await self._repo.all_prefixes()
        coverages: dict[str, Coverage] = {LIST_SCOPE: coverage_of(current)}
        for origin, prefixes in stored.items():
            coverages[origin] = coverage_of(prefixes)
        await self._repo.set_baselines(
            coverages, list_hash=list_hash(current), now=self._clock()
        )

    async def _reconcile_baseline(self) -> None:
        """Adopt the list file as the baseline when it changed behind our back.

        The file has other writers: the split panel's add/delete buttons and the
        ``/warp_split_*`` commands go through the manager directly. Whatever they
        applied IS the last applied state, so adopting it is not a workaround —
        it is the definition. Detected by hash rather than by timestamp, so an
        edit-and-revert is correctly seen as no change at all.
        """
        current = self._manager.read_list()
        if not current:
            return
        stored_hash = await self._repo.baseline_list_hash()
        if stored_hash == list_hash(current):
            return
        if stored_hash is not None:
            logger.info(
                "warp-split: list file changed outside the feed path — adopting it as the baseline"
            )
        await self._capture_baseline()

    # ── unattended cycle ──────────────────────────────────────────────────────

    async def run_cycle(self) -> CycleResult:
        """One scheduled run: fetch, analyse, then apply, queue or hold back.

        The decision tree, in the order it is evaluated:

        1. a merge that cannot be computed at all is a **failure** — the previous
           list stays, and nobody is asked to approve anything;
        2. a candidate identical to the file is a **no-change**, and is logged
           rather than announced (a six-hourly "nothing happened" trains admins
           to swipe alerts away unread);
        3. a candidate the manager's guards reject is **rejected**, and is *not*
           queued: those guards do not describe a suspicious change, they describe
           an invalid one, and no approval can make it valid;
        4. in ``review`` everything else is **queued**, including a change that
           passed every threshold — that is what the mode is for;
        5. in ``auto`` a change that trips a threshold is **queued**, one that is
           pure re-aggregation is **applied**, and anything else is applied only
           once the same candidate has been seen ``WARP_SPLIT_CONFIRM_STREAK``
           runs in a row.
        """
        if self._mode == MODE_OFF:
            # Unreachable through main.py (the task is not started at all), kept
            # so that calling it in any other context cannot mutate routing.
            logger.debug("warp-split: cycle skipped, WARP_SPLIT_FEEDS_MODE=off")
            return CycleResult(mode=self._mode, decision=DECISION_NOCHANGE, reason="mode-off")

        await self.ensure_manual_adopted()
        await self._reconcile_baseline()
        refreshed = await self._refresh_sources(None)
        await self._alert_source_failures(refreshed)

        try:
            plan = await self.build_plan()
        except WarpFeedError as exc:
            # Keyed by the message, not just by "merge failed": two different
            # operands going missing are two different problems, and the cooldown
            # must not let the second hide behind the first.
            await self._alert(f"merge:{str(exc)[:80]}", str(exc))
            return await self._record(
                CycleResult(
                    mode=self._mode,
                    decision=DECISION_FAILED,
                    reason="merge-failed",
                    sources=refreshed,
                    detail=str(exc),
                )
            )

        analysis = await self._analyse(plan, refreshed)

        if analysis.identical:
            # Nothing to approve, so a card left over from an earlier run is now
            # about a change that no longer exists.
            await self._forget_pending()
            logger.info(
                "warp-split: no change (%d prefixes, %d addresses)",
                analysis.prefixes_after,
                analysis.addresses_after,
            )
            return await self._record(
                CycleResult(
                    mode=self._mode,
                    decision=DECISION_NOCHANGE,
                    reason="identical",
                    sources=refreshed,
                    analysis=analysis,
                )
            )

        try:
            await self._manager.check_candidate(plan.prefixes)
        except WarpSplitCapExceeded as exc:
            return await self._reject(refreshed, analysis, self._cap_message(exc, plan))
        except WarpSplitError as exc:
            return await self._reject(refreshed, analysis, str(exc))

        if self._mode == MODE_REVIEW:
            return await self._queue(
                refreshed, with_hold(analysis, Hold(code=HOLD_REVIEW_MODE)), plan
            )

        if analysis.suspicious:
            return await self._queue(refreshed, analysis, plan)

        if not analysis.pure_aggregation:
            streak = await self._bump_streak(analysis.list_hash)
            if streak < self._confirm_streak:
                logger.info(
                    "warp-split: candidate %s seen %d/%d times — holding for confirmation",
                    analysis.list_hash[:12],
                    streak,
                    self._confirm_streak,
                )
                return await self._record(
                    CycleResult(
                        mode=self._mode,
                        decision=DECISION_NOCHANGE,
                        reason=f"{HOLD_STREAK}:{streak}/{self._confirm_streak}",
                        sources=refreshed,
                        analysis=analysis,
                        streak=streak,
                    )
                )

        try:
            outcome = await self.apply_plan(plan)
        except WarpFeedError as exc:
            return await self._reject(refreshed, analysis, str(exc))

        await self._reset_streak()
        await self._forget_pending()
        if outcome.changed:
            await self._alert(
                f"applied:{analysis.list_hash[:12]}",
                self._applied_text(analysis, outcome),
                cooldown=False,
            )
        return await self._record(
            CycleResult(
                mode=self._mode,
                decision=DECISION_APPLIED if outcome.changed else DECISION_NOCHANGE,
                reason="auto-applied" if outcome.changed else "identical",
                sources=refreshed,
                analysis=analysis,
                outcome=outcome,
            )
        )

    async def _analyse(
        self, plan: MergePlan, refreshed: Sequence[SourceRefresh]
    ) -> ChangeAnalysis:
        """Measure *plan* against the file on disk and against the baselines."""
        sources = await self._repo.list_sources()
        report = plan.report
        now = self._clock()
        outcomes = {item.slug: item for item in refreshed}
        states: list[SourceState] = []
        for source in sources:
            if not source.enabled:
                continue
            outcome = outcomes.get(source.slug)
            states.append(
                SourceState(
                    slug=source.slug,
                    mode=source.mode,
                    coverage=Coverage(
                        prefixes=report.per_source_prefixes.get(source.slug, 0),
                        addresses=report.per_source_addresses.get(source.slug, 0),
                    ),
                    age_sec=None if source.last_success_ts <= 0 else now - source.last_success_ts,
                    empty_parse=outcome is not None and outcome.empty_parse,
                )
            )
        return analyse_change(
            current=plan.current,
            candidate=plan.prefixes,
            sources=states,
            baselines=await self._repo.baselines(),
            thresholds=self._thresholds,
        )

    # ── approval queue ────────────────────────────────────────────────────────

    async def _queue(
        self,
        refreshed: tuple[SourceRefresh, ...],
        analysis: ChangeAnalysis,
        plan: MergePlan,
    ) -> CycleResult:
        """Park the candidate for an admin and send the card, at most once."""
        pending = await self._repo.pending()
        already_queued = pending is not None and pending.list_hash == analysis.list_hash
        reason = ",".join(analysis.hold_keys)
        await self._repo.set_pending(
            list_hash=analysis.list_hash,
            prefixes=plan.prefixes,
            reason=reason,
            deltas=_deltas_payload(analysis),
            now=self._clock(),
        )
        if not already_queued:
            # One message per candidate, not one per run: replacing a waiting
            # candidate announces the replacement and nothing else, and re-queuing
            # the same one every six hours says nothing new. Never suppressed by
            # the cooldown — a card the admin never sees is a change that never
            # gets decided.
            await self._alert(
                f"queued:{analysis.list_hash[:12]}",
                self._card_text(analysis),
                cooldown=False,
                card=True,
            )
        logger.info(
            "warp-split: candidate %s queued for approval (%s)",
            analysis.list_hash[:12],
            reason or "no reason recorded",
        )
        return await self._record(
            CycleResult(
                mode=self._mode,
                decision=DECISION_QUEUED,
                reason=reason,
                sources=refreshed,
                analysis=analysis,
            )
        )

    async def pending(self) -> PendingCandidate | None:
        return await self._repo.pending()

    async def apply_pending(self, *, actor_user_id: int | None = None) -> ApplyOutcome:
        """Apply the queued candidate, if it is still the one that was approved.

        The hash is checked twice on purpose. Once here, cheaply, to answer the
        admin without taking the list lock; and once inside the recompute that
        runs *under* that lock, which is the check that counts — between reading
        the pending row and writing the file, another admin can add a prefix, and
        applying "what the card said" would silently drop it.
        """
        pending = await self._repo.pending()
        if pending is None:
            raise WarpFeedError("there is no change waiting for approval")
        plan = await self.build_plan()
        if list_hash(plan.prefixes) != pending.list_hash:
            raise WarpFeedStaleCandidate(
                "the merge no longer produces the list this card described — "
                "nothing was applied; refresh the sources and decide again"
            )

        expected = pending.list_hash

        async def _compute() -> Sequence[str]:
            prefixes = (await self.build_plan()).prefixes
            if list_hash(prefixes) != expected:
                raise WarpFeedStaleCandidate(
                    "the merge changed while the approval was being applied — "
                    "nothing was written; refresh the sources and decide again"
                )
            return prefixes

        try:
            outcome = await self._manager.apply_computed(
                _compute, actor_user_id=actor_user_id
            )
        except WarpSplitCapExceeded as exc:
            raise WarpFeedError(self._cap_message(exc, plan)) from exc

        # Measured BEFORE the baseline moves: after ``_after_apply`` the stored
        # baseline is the state that was just written, and every per-source line
        # would read "32 → 32" — a report of the change that erased itself.
        analysis = await self._analyse(plan, ())
        await self._after_apply()
        await self._repo.clear_pending()
        await self._reset_streak()
        if outcome.changed:
            await self._alert(
                f"applied:{expected[:12]}",
                self._applied_text(analysis, outcome, approved=True),
                cooldown=False,
            )
        await self._record(
            CycleResult(
                mode=self._mode,
                decision=DECISION_APPLIED if outcome.changed else DECISION_NOCHANGE,
                reason="approved",
                analysis=analysis,
                outcome=outcome,
            )
        )
        return outcome

    async def reject_pending(self, *, actor_user_id: int | None = None) -> None:
        """Discard the queued candidate. The baseline is deliberately untouched.

        Moving it here would be the one change that quietly destroys the ratchet:
        the next run would measure the feed against the state the admin just
        refused, so a shrink rejected today is a shrink accepted tomorrow.
        """
        pending = await self._repo.pending()
        await self._repo.clear_pending()
        await self._record(
            CycleResult(
                mode=self._mode,
                decision=DECISION_REJECTED,
                reason="declined",
                detail="" if pending is None else pending.reason,
            ),
            list_hash_override="" if pending is None else pending.list_hash,
        )
        logger.info("warp-split: queued candidate declined by admin %s", actor_user_id)

    async def _forget_pending(self) -> None:
        """Drop a queued candidate that no longer describes an open question.

        Both callers reach here having established that there is nothing left to
        decide — the candidate now matches the file, or it has just been applied —
        so the card is dropped whether or not the hashes agree. Leaving it would
        offer the admin a button that applies what is already applied.
        """
        pending = await self._repo.pending()
        if pending is None:
            return
        logger.info(
            "warp-split: pending candidate %s is no longer open", pending.list_hash[:12]
        )
        await self._repo.clear_pending()

    async def _reject(
        self,
        refreshed: tuple[SourceRefresh, ...],
        analysis: ChangeAnalysis,
        detail: str,
    ) -> CycleResult:
        """A guard refused the candidate: alert, record, queue nothing."""
        await self._alert(f"rejected:{analysis.list_hash[:12]}", f"⛔ {detail}")
        logger.warning("warp-split: candidate rejected by a guard: %s", detail)
        return await self._record(
            CycleResult(
                mode=self._mode,
                decision=DECISION_REJECTED,
                reason="guard",
                sources=refreshed,
                analysis=analysis,
                detail=detail,
            )
        )

    # ── confirmation streak ───────────────────────────────────────────────────

    async def _bump_streak(self, candidate_hash: str) -> int:
        """Count consecutive sightings of the same candidate; reset on any other."""
        previous = await self._db.get_meta(_STREAK_HASH_KEY)
        raw = await self._db.get_meta(_STREAK_COUNT_KEY)
        try:
            count = int(raw or 0)
        except ValueError:
            count = 0
        count = count + 1 if previous == candidate_hash else 1
        await self._db.set_meta(_STREAK_HASH_KEY, candidate_hash)
        await self._db.set_meta(_STREAK_COUNT_KEY, str(count))
        return count

    async def _reset_streak(self) -> None:
        await self._db.set_meta(_STREAK_HASH_KEY, "")
        await self._db.set_meta(_STREAK_COUNT_KEY, "0")

    # ── run journal ───────────────────────────────────────────────────────────

    async def _record(
        self, result: CycleResult, *, list_hash_override: str | None = None
    ) -> CycleResult:
        analysis = result.analysis
        sources = [
            {
                "slug": item.slug,
                "status": item.status,
                "prefixes": item.prefix_count,
                "error": (item.error or "")[:200],
            }
            for item in result.sources
        ]
        if analysis is not None:
            measured = {change.slug: change for change in analysis.sources}
            for row in sources:
                change = measured.get(str(row["slug"]))
                if change is None:
                    continue
                row["addresses"] = change.after.addresses
                row["addresses_before"] = 0 if change.before is None else change.before.addresses
                row["prefixes_before"] = 0 if change.before is None else change.before.prefixes
        metrics: dict[str, object] = {"detail": result.detail[:300]} if result.detail else {}
        if analysis is not None:
            metrics.update(
                {
                    "prefixes_before": analysis.prefixes_before,
                    "prefixes_after": analysis.prefixes_after,
                    "addresses_before": analysis.addresses_before,
                    "addresses_after": analysis.addresses_after,
                    "pure_aggregation": analysis.pure_aggregation,
                    "added": len(analysis.added),
                    "removed": len(analysis.removed),
                }
            )
        await self._repo.record_run(
            mode=result.mode,
            decision=result.decision,
            reason=result.reason,
            list_hash=(
                list_hash_override
                if list_hash_override is not None
                else ("" if analysis is None else analysis.list_hash)
            ),
            sources=sources,
            metrics=metrics,
            now=self._clock(),
        )
        return result

    async def recent_runs(self, limit: int = 10) -> list[SplitRun]:
        return await self._repo.recent_runs(limit)

    # ── manual prefixes and exclusions ────────────────────────────────────────

    async def add_manual(
        self, tokens: Sequence[str], *, actor_user_id: int | None = None
    ) -> tuple[list[CidrResult], ApplyOutcome | None]:
        """Validate and add hand-typed prefixes, then re-merge and apply.

        Returns the per-token report (for the panel) and the apply outcome, or
        None when nothing was accepted.
        """
        await self.ensure_manual_adopted()
        await self._manager.refresh_endpoint()
        current = set(await self._repo.manual_prefixes()) | set(self._manager.read_list())
        results, accepted = self._manager.process_add_tokens(list(tokens), current)
        if not accepted:
            return list(results), None
        await self._repo.add_manual_prefixes(accepted)
        outcome = await self._manager.apply_computed(
            self._recompute_for_apply, actor_user_id=actor_user_id
        )
        return list(results), outcome

    async def remove_manual(self, prefix: str, *, actor_user_id: int | None = None) -> ApplyOutcome:
        """Drop a hand-typed prefix and re-apply."""
        await self.ensure_manual_adopted()
        await self._repo.remove_manual_prefixes([prefix])
        return await self._manager.apply_computed(
            self._recompute_for_apply, actor_user_id=actor_user_id
        )

    async def exclude_prefix(self, prefix: str, *, actor_user_id: int | None = None) -> ApplyOutcome:
        """Veto a feed-supplied prefix and re-apply.

        Deleting it would be pointless — the next refresh puts it straight back —
        so the operator's intent is stored as an exclusion, which is subtracted at
        the same step as a global subtract source and therefore survives every
        future refresh.
        """
        await self.ensure_manual_adopted()
        await self._repo.add_exclusion(prefix)
        # A prefix can be both hand-typed and feed-supplied; drop the manual copy
        # too, or the exclusion would fight it on every merge.
        await self._repo.remove_manual_prefixes([prefix])
        return await self._manager.apply_computed(
            self._recompute_for_apply, actor_user_id=actor_user_id
        )

    async def unexclude_prefix(
        self, prefix: str, *, actor_user_id: int | None = None
    ) -> ApplyOutcome:
        await self._repo.remove_exclusion(prefix)
        return await self._manager.apply_computed(
            self._recompute_for_apply, actor_user_id=actor_user_id
        )

    async def migrate_manual_into_feeds(
        self, *, actor_user_id: int | None = None
    ) -> tuple[int, ApplyOutcome]:
        """Drop the manual prefixes that an enabled add-source already covers.

        The reason this exists: on a host whose manual list was seeded by hand
        from goog.json, every subtraction scoped to that source is inert, because
        the manual copies re-introduce exactly the ranges being carved out. The
        operator has to give up the duplicates for the scope to mean anything —
        so this is an explicit, previewable action, never an automatic migration.
        """
        await self.ensure_manual_adopted()
        stored = await self._repo.all_prefixes()
        sources = await self._repo.list_sources()
        covered: list[ipaddress.IPv4Network] = []
        for source in sources:
            if source.contributes_to_list:
                covered.extend(_to_networks(stored.get(source.slug, ())))
        manual = stored.get(MANUAL_ORIGIN, [])
        redundant = [
            prefix
            for prefix in manual
            if any(ipaddress.IPv4Network(prefix).subnet_of(net) for net in covered)
        ]
        if redundant:
            await self._repo.remove_manual_prefixes(redundant)
        outcome = await self._manager.apply_computed(
            self._recompute_for_apply, actor_user_id=actor_user_id
        )
        return len(redundant), outcome

    # ── source management ─────────────────────────────────────────────────────

    async def add_source(
        self,
        *,
        slug: str,
        title: str,
        url: str,
        kind: str,
        mode: str = "add",
        scope_slug: str | None = None,
    ) -> None:
        """Validate and store a new source. Raises WarpFeedError with a message
        meant to be shown to the admin as-is."""
        try:
            validate_slug(slug)
        except ValueError as exc:
            raise WarpFeedError(str(exc)) from exc
        if await self._repo.get_source(slug) is not None:
            raise WarpFeedError(f"a source with slug '{slug}' already exists")
        existing = {source.slug: source.mode for source in await self._repo.list_sources()}
        try:
            validate_source_relations(
                slug=slug, mode=mode, scope_slug=scope_slug, existing_modes=existing
            )
        except ValueError as exc:
            raise WarpFeedError(str(exc)) from exc
        await self._repo.add_source(
            slug=slug,
            title=title,
            url=url,
            kind=kind,
            mode=mode,
            scope_slug=scope_slug,
            enabled=False,
            include_in_list=mode == "add",
        )

    async def set_enabled(self, slug: str, enabled: bool) -> None:
        await self._repo.set_enabled(slug, enabled)

    async def delete_source(self, slug: str) -> None:
        await self._repo.delete_source(slug)

    async def list_sources(self) -> list[SplitSource]:
        return await self._repo.list_sources()

    async def contributions(self) -> dict[str, list[str]]:
        return await self._repo.all_prefixes()

    async def exclusions(self) -> list[str]:
        return await self._repo.exclusions()

    # ── alerts ────────────────────────────────────────────────────────────────

    async def _send_alerts(self, alerts: Sequence[str]) -> None:
        if self._notify is None:
            return
        for text in alerts:
            try:
                await self._notify(text)
            except Exception:
                logger.warning("warp-split: alert delivery failed", exc_info=True)

    async def _alert(
        self, key: str, text: str, *, cooldown: bool = True, card: bool = False
    ) -> None:
        """Deliver one message, optionally de-duplicated by *key*.

        ``key`` identifies the thing being said, not the wording: "this source
        has been failing" is one key per source, so a feed that is down for a week
        produces one message an hour at most instead of one per run per phrasing.

        The cooldown ledger is in memory. A restart clears it and the first run
        after may repeat a message the admin already has; persisting it would buy
        one avoided duplicate at the cost of a table whose staleness nobody would
        ever think about again. Stated in docs/warp.md so the behaviour is not a
        surprise.
        """
        now = self._clock()
        if cooldown and self._alert_cooldown_sec > 0:
            last = self._alerted_at.get(key)
            if last is not None and now - last < self._alert_cooldown_sec:
                logger.debug("warp-split: alert %s suppressed by cooldown", key)
                return
        self._alerted_at[key] = now
        sink = self._notify_card if card and self._notify_card is not None else self._notify
        if sink is None:
            return
        try:
            await sink(text)
        except Exception:
            logger.warning("warp-split: alert delivery failed", exc_info=True)

    async def _alert_source_failures(self, refreshed: Sequence[SourceRefresh]) -> None:
        """Announce feeds that have been failing for a while, or gone stale.

        Not every failure: one timeout on one run is noise, and the merge already
        falls back to the cache. What matters is a feed that has stopped working
        (``WARP_SPLIT_FEED_FAIL_STREAK`` runs in a row) or one whose last good
        answer is older than ``WARP_SPLIT_FEED_STALE_AFTER_SEC`` — at that point
        the routed list is being computed from a document nobody has been able to
        confirm for days.
        """
        sources = {source.slug: source for source in await self._repo.list_sources()}
        now = self._clock()
        for item in refreshed:
            source = sources.get(item.slug)
            if source is None:
                continue
            if not item.ok and source.fail_streak >= self._fail_streak_alert:
                await self._alert(
                    f"fail-streak:{item.slug}",
                    t(
                        "warp_split_alert_fail_streak",
                        slug=item.slug,
                        count=source.fail_streak,
                        error=(item.error or "")[:200],
                    ),
                )
            age = None if source.last_success_ts <= 0 else now - source.last_success_ts
            if age is not None and age > self._thresholds.stale_after_sec:
                await self._alert(
                    f"stale:{item.slug}",
                    t("warp_split_alert_stale", slug=item.slug, days=age // 86400),
                )

    # ── message bodies ────────────────────────────────────────────────────────

    def _applied_text(
        self, analysis: ChangeAnalysis, outcome: ApplyOutcome, *, approved: bool = False
    ) -> str:
        """Short summary of a change that has actually landed."""
        lines = [
            t("warp_split_applied_approved" if approved else "warp_split_applied_auto"),
            _counts_text(analysis, delta=outcome.delta_text),
        ]
        lines.extend(_source_lines(analysis))
        return "\n".join(lines)

    def _card_text(self, analysis: ChangeAnalysis) -> str:
        """The approval card: why it is held, what it would change, by source."""
        lines = [
            t("warp_split_card_title", mode=self._mode),
            "",
            *(f"• {_hold_text(hold)}" for hold in analysis.holds),
            "",
            _counts_text(analysis, delta=f"{analysis.delta_prefixes:+d}"),
        ]
        if analysis.pure_aggregation:
            lines.append(t("warp_split_card_pure"))
        lines.extend(_source_lines(analysis))
        if analysis.added:
            lines.append("")
            lines.append(
                t(
                    "warp_split_card_added",
                    count=len(analysis.added),
                    sample=_sample(analysis.added),
                )
            )
        if analysis.removed:
            lines.append(
                t(
                    "warp_split_card_removed",
                    count=len(analysis.removed),
                    sample=_sample(analysis.removed),
                )
            )
        return "\n".join(lines)


def _sample(prefixes: Sequence[str]) -> str:
    shown = ", ".join(prefixes[:_CARD_SAMPLE])
    return shown + ("…" if len(prefixes) > _CARD_SAMPLE else "")


def _addr(value: int) -> str:
    """Group an address count in threes, with spaces rather than commas.

    22 249 216 reads the same in both locales; 22,249,216 reads as a decimal in
    one of them.
    """
    return f"{value:,}".replace(",", " ")


def _counts_text(analysis: ChangeAnalysis, *, delta: str) -> str:
    return t(
        "warp_split_card_counts",
        before=analysis.prefixes_before,
        after=analysis.prefixes_after,
        delta=delta,
        addr_before=_addr(analysis.addresses_before),
        addr_after=_addr(analysis.addresses_after),
        addr_delta=("+" if analysis.delta_addresses >= 0 else "−")
        + _addr(abs(analysis.delta_addresses)),
    )


def _source_lines(analysis: ChangeAnalysis) -> list[str]:
    lines = [""]
    for change in analysis.sources:
        if change.before is None:
            lines.append(
                t(
                    "warp_split_card_source_new",
                    slug=change.slug,
                    prefixes=change.after.prefixes,
                    addresses=_addr(change.after.addresses),
                )
            )
            continue
        lines.append(
            t(
                "warp_split_card_source",
                slug=change.slug,
                p_before=change.before.prefixes,
                p_after=change.after.prefixes,
                a_before=_addr(change.before.addresses),
                a_after=_addr(change.after.addresses),
            )
        )
    return lines


def _hold_text(hold: Hold) -> str:
    """One line explaining why a candidate is held, in the admin's terms."""
    if hold.code == HOLD_SHRINK_ADD:
        return t(
            "warp_split_hold_shrink_add",
            slug=hold.slug,
            pct=f"{hold.pct:.0f}",
            before=_addr(hold.before),
            after=_addr(hold.after),
        )
    if hold.code == HOLD_SHRINK_SUBTRACT:
        return t(
            "warp_split_hold_shrink_subtract",
            slug=hold.slug,
            pct=f"{hold.pct:.0f}",
            before=_addr(hold.before),
            after=_addr(hold.after),
        )
    if hold.code == HOLD_GROWTH:
        return t(
            "warp_split_hold_growth",
            pct=f"{hold.pct:.0f}",
            before=_addr(hold.before),
            after=_addr(hold.after),
        )
    if hold.code == HOLD_EMPTY_SOURCE:
        return t("warp_split_hold_empty", slug=hold.slug)
    if hold.code == HOLD_STALE_SOURCE:
        return t("warp_split_hold_stale", slug=hold.slug, days=max(0, hold.before) // 86400)
    if hold.code == HOLD_STREAK:
        return t("warp_split_hold_streak")
    if hold.code == HOLD_REVIEW_MODE:
        return t("warp_split_hold_review")
    return hold.key


def _deltas_payload(analysis: ChangeAnalysis) -> dict[str, object]:
    """What the stored card needs to be re-rendered without recomputing."""
    return {
        "prefixes_before": analysis.prefixes_before,
        "prefixes_after": analysis.prefixes_after,
        "addresses_before": analysis.addresses_before,
        "addresses_after": analysis.addresses_after,
        "pure_aggregation": analysis.pure_aggregation,
        "added": list(analysis.added[:_CARD_STORE_SAMPLE]),
        "removed": list(analysis.removed[:_CARD_STORE_SAMPLE]),
        "added_total": len(analysis.added),
        "removed_total": len(analysis.removed),
        "holds": [
            {
                "code": hold.code,
                "slug": hold.slug,
                "pct": round(hold.pct, 2),
                "before": hold.before,
                "after": hold.after,
            }
            for hold in analysis.holds
        ],
        "sources": [
            {
                "slug": change.slug,
                "mode": change.mode,
                "prefixes_before": None if change.before is None else change.before.prefixes,
                "prefixes_after": change.after.prefixes,
                "addresses_before": None if change.before is None else change.before.addresses,
                "addresses_after": change.after.addresses,
                "stale": change.stale,
            }
            for change in analysis.sources
        ],
    }


def _to_networks(prefixes: Sequence[str]) -> list[ipaddress.IPv4Network]:
    """Parse stored prefix strings, skipping anything unparseable.

    Stored rows come from this code's own writes, so a bad one means corruption
    rather than user input; dropping it keeps the merge running on the rest
    instead of taking the whole subsystem down.
    """
    result: list[ipaddress.IPv4Network] = []
    for item in prefixes:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            logger.warning("warp-split: dropping unparseable stored prefix %r", item)
            continue
        if isinstance(net, ipaddress.IPv4Network):
            result.append(net)
    return result


def _jittered(interval: int) -> float:
    """Return *interval* nudged by up to +/-10%, so hosts do not synchronise.

    ``secrets`` rather than ``random`` purely to keep the bandit rule that bans
    non-cryptographic randomness from needing a per-call suppression here.
    """
    span = max(1, int(interval * _JITTER_FRACTION))
    return float(interval + secrets.randbelow(2 * span + 1) - span)


async def warp_split_feeds_loop(service: WarpSplitFeedService, interval: int) -> None:
    """Refresh the split-list feeds on a schedule.

    The first run is delayed rather than immediate. A feed refresh can rewrite
    the routing policy for every client, and doing that as part of "the bot came
    back up" would make a crash loop into a policy loop.

    What a run is allowed to *do* is decided by ``WARP_SPLIT_FEEDS_MODE`` inside
    :meth:`WarpSplitFeedService.run_cycle`, not here: the loop's only job is when
    to run, so that the two decisions cannot drift apart.
    """
    await asyncio.sleep(min(FIRST_RUN_DELAY_SECONDS, interval))
    while True:
        try:
            result = await service.run_cycle()
            logger.info(
                "WARP split feed cycle (%s): %s%s",
                result.mode,
                result.decision,
                f" — {result.reason}" if result.reason else "",
            )
        except Exception:
            logger.warning("WARP split feed refresh failed", exc_info=True)
        await asyncio.sleep(_jittered(interval))
