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
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass

from adapters.warp_feed_fetcher import FeedFetchError, WarpFeedFetcher
from db.database import Database
from repositories.warp_split_sources import WarpSplitSourceRepository
from warp.feed_state import SplitSource
from warp.split_manager import (
    ApplyOutcome,
    CidrResult,
    WarpSplitCapExceeded,
    WarpSplitError,
    WarpSplitManager,
)
from warp.split_merge import (
    MANUAL_ORIGIN,
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


class WarpFeedError(WarpSplitError):
    """A feed-level failure that is safe to show to the admin verbatim."""


@dataclass(frozen=True, slots=True)
class SourceRefresh:
    """What happened to one source during a refresh."""

    slug: str
    status: str                 # "ok" | "not-modified" | "cached" | "error"
    prefix_count: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status != "error"


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


class WarpSplitFeedService:
    """Fetches, merges and applies the split-list prefix feeds."""

    def __init__(
        self,
        *,
        db: Database,
        repo: WarpSplitSourceRepository,
        fetcher: WarpFeedFetcher,
        manager: WarpSplitManager,
        alert_delta_pct: int = 30,
        notify: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._db = db
        self._repo = repo
        self._fetcher = fetcher
        self._manager = manager
        self._alert_delta_pct = alert_delta_pct
        self._notify = notify

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
        sources = await self._repo.list_sources()
        wanted = [
            source
            for source in sources
            if source.enabled and (slugs is None or source.slug in slugs)
        ]
        refreshed = [await self._refresh_one(source) for source in wanted]
        alerts = [
            f"WARP split feed '{item.slug}' failed: {item.error}"
            for item in refreshed
            if item.status == "error"
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

        if outcome.changed and plan.delta_pct > self._alert_delta_pct:
            alerts.append(
                f"WARP split list changed by {plan.delta_pct:.0f}% "
                f"({outcome.delta_text}, now {outcome.count} prefixes) on an automatic refresh"
            )
        await self._send_alerts(alerts)
        return RefreshResult(
            sources=tuple(refreshed), plan=plan, outcome=outcome, alerts=tuple(alerts)
        )

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
            await self._repo.record_failure(source.slug, status="error", error=str(exc))
            logger.warning("warp-split feed %s failed: %s", source.slug, exc)
            return SourceRefresh(slug=source.slug, status="error", error=str(exc))

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
            return await self._manager.apply_computed(
                self._recompute_for_apply, actor_user_id=actor_user_id
            )
        except WarpSplitCapExceeded as exc:
            raise WarpFeedError(self._cap_message(exc, plan)) from exc

    async def _recompute_for_apply(self) -> Sequence[str]:
        return (await self.build_plan()).prefixes

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
    """
    await asyncio.sleep(min(FIRST_RUN_DELAY_SECONDS, interval))
    while True:
        try:
            result = await service.refresh(apply=True)
            if result.applied and result.outcome is not None:
                logger.info(
                    "WARP split feeds refreshed: %s (now %d prefixes)",
                    result.outcome.delta_text,
                    result.outcome.count,
                )
            elif result.blocked_reason is not None:
                logger.warning("WARP split feed refresh blocked: %s", result.blocked_reason)
        except Exception:
            logger.warning("WARP split feed refresh failed", exc_info=True)
        await asyncio.sleep(_jittered(interval))
