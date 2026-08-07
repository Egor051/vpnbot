"""Ratchet analysis for the WARP selective-split list.

Pure like :mod:`warp.split_merge`, and separate from it on purpose: that module
answers "what is the list?", this one answers "is this change safe to apply
unattended?". Nothing here touches the network, the database or the filesystem,
so every threshold below is a two-line test rather than an integration fixture.

Two rules shape the whole module.

**Coverage is counted in addresses, not in prefixes.** ``collapse`` merges
adjacent siblings, so a feed that changes nothing at all can still move the
prefix count: measured on this host, adopting the 108-entry list file yields 106
prefixes covering byte-identical address space. A prefix-count threshold would
call that a 2% change and a subtraction that quietly halves a feed a 0% one. The
address count is the only number that means "how much of the internet is routed
through the tunnel", so every threshold here is computed on it.

**The comparison point is the last state that was actually applied**, not the
previous run's candidate. That is what makes the guard a ratchet: a feed that
shrinks by 5% every run for four runs is caught on the fourth, because it is
still being measured against the state a human last accepted. Baselines therefore
move on an apply and never on a rejection — see
:mod:`services.warp_split_feeds`.
"""
from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Final

from warp.split_merge import LIST_SCOPE, collapse

IPv4Net = ipaddress.IPv4Network

# Hold codes. Stored verbatim in warp_split_pending.reason and
# warp_split_runs.reason, and rendered to the admin through an i18n key per code,
# so they are part of the on-disk format: rename one and old rows stop rendering.
HOLD_SHRINK_ADD: Final = "shrink-add"
HOLD_SHRINK_SUBTRACT: Final = "shrink-subtract"
HOLD_GROWTH: Final = "growth"
HOLD_EMPTY_SOURCE: Final = "empty-source"
HOLD_STALE_SOURCE: Final = "stale-source"
HOLD_STREAK: Final = "streak"
HOLD_REVIEW_MODE: Final = "review-mode"


@dataclass(frozen=True, slots=True)
class Thresholds:
    """The tunables from the environment, in one passable object."""

    max_shrink_pct: int = 20
    max_growth_pct: int = 50
    stale_after_sec: int = 259_200


# The defaults as a singleton, so :func:`analyse_change` can take them as a
# default argument without constructing one per call.
DEFAULT_THRESHOLDS: Final = Thresholds()


@dataclass(frozen=True, slots=True)
class Coverage:
    """How much address space a prefix set covers, and in how many entries."""

    prefixes: int = 0
    addresses: int = 0

    @property
    def empty(self) -> bool:
        return self.prefixes == 0


@dataclass(frozen=True, slots=True)
class SourceState:
    """One enabled source as the analyser sees it.

    Deliberately not :class:`warp.feed_state.SplitSource`: this module must stay
    free of storage shapes, and the two facts it needs from a row (how old the
    last success is, whether the last attempt died) are cheaper to pass than to
    re-derive.
    """

    slug: str
    mode: str                       # "add" | "subtract"
    coverage: Coverage              # what this source contributes to THIS candidate
    age_sec: int | None = None      # since the last successful fetch; None = never
    # This run's fetch parsed to zero IPv4 prefixes. Distinct from an empty
    # ``coverage``: the parse failure is treated as a failed fetch upstream, so the
    # contribution below is the last good one and the candidate is computable —
    # but it was computed from a source that has just published nothing, which is
    # precisely the state that must not be applied unattended.
    empty_parse: bool = False


@dataclass(frozen=True, slots=True)
class Hold:
    """One reason a candidate must not be applied unattended.

    ``pct`` is the measured movement and ``before``/``after`` the address counts
    behind it, so the admin card can say "google-goog shrank 34% (22.2M → 14.6M)"
    rather than "a threshold was exceeded".
    """

    code: str
    slug: str | None = None
    pct: float = 0.0
    before: int = 0
    after: int = 0

    @property
    def key(self) -> str:
        """Stable identifier used for storage and for alert de-duplication."""
        return self.code if self.slug is None else f"{self.code}:{self.slug}"


@dataclass(frozen=True, slots=True)
class SourceChange:
    """Per-source before/after, for the card and the run journal."""

    slug: str
    mode: str
    before: Coverage | None          # None when the source has no baseline yet
    after: Coverage
    age_sec: int | None = None
    stale: bool = False

    @property
    def shrink_pct(self) -> float:
        """How much coverage was lost, as a percentage of the baseline.

        Zero when there is no baseline (nothing to ratchet against) or when the
        source grew — growth of one operand is not what this measures.
        """
        if self.before is None or self.before.addresses <= 0:
            return 0.0
        lost = self.before.addresses - self.after.addresses
        return max(0.0, 100.0 * lost / self.before.addresses)

    @property
    def growth_pct(self) -> float:
        if self.before is None or self.before.addresses <= 0:
            return 0.0
        gained = self.after.addresses - self.before.addresses
        return max(0.0, 100.0 * gained / self.before.addresses)


@dataclass(frozen=True, slots=True)
class ChangeAnalysis:
    """The verdict on one candidate list.

    ``addresses_before``/``prefixes_before`` describe the list **currently on
    disk** (what the change would replace), because that is the change the admin
    is being shown. The thresholds, however, are measured against the stored
    baseline — normally the same thing, and deliberately not the same thing after
    someone applied a list through another path. See :func:`analyse_change`.

    Prefix counts here are raw entry counts; address counts are collapsed. Mixing
    the two is not sloppiness — it is the only way both numbers say something
    true: 108 → 106 is a real difference in the file, and 22 249 216 → 22 249 216
    is a real statement that nothing about the routing changed.
    """

    prefixes_before: int
    prefixes_after: int
    addresses_before: int
    addresses_after: int
    list_hash: str
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    sources: tuple[SourceChange, ...] = ()
    holds: tuple[Hold, ...] = ()
    baseline_addresses: int | None = None
    baseline_prefixes: int | None = None
    # Set by :func:`analyse_change`: the two sides describe the very same address
    # space once collapsed. Equality of the SETS, not of their sizes — 10.0.0.0/24
    # and 11.0.0.0/24 cover the same number of addresses and nothing else in
    # common, and calling that "safe re-aggregation" would be the worst possible
    # false negative.
    same_space: bool = False

    @property
    def identical(self) -> bool:
        return not self.added and not self.removed

    @property
    def pure_aggregation(self) -> bool:
        """True when the candidate re-cuts exactly the same address space.

        The 108 → 106 case: not a change in what is routed, only in how many lines
        it takes to say it. Exempt from the confirm-by-repetition streak, because
        waiting two runs to re-collapse a list nobody changed is delay without
        information.
        """
        return not self.identical and self.same_space

    @property
    def suspicious(self) -> bool:
        return bool(self.holds)

    @property
    def delta_prefixes(self) -> int:
        return self.prefixes_after - self.prefixes_before

    @property
    def delta_addresses(self) -> int:
        return self.addresses_after - self.addresses_before

    @property
    def hold_keys(self) -> tuple[str, ...]:
        return tuple(hold.key for hold in self.holds)


def collapsed_networks(prefixes: Sequence[str]) -> list[IPv4Net]:
    """Parse and collapse *prefixes*, ignoring anything unparseable or IPv6.

    Collapsing is what makes two sides comparable at all: the same address space
    written as 108 or as 106 entries must compare equal, or the ratchet would fire
    on formatting.
    """
    networks: list[IPv4Net] = []
    for item in prefixes:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if isinstance(net, IPv4Net):
            networks.append(net)
    return collapse(networks)


def coverage_of(prefixes: Sequence[str]) -> Coverage:
    """Measure *prefixes* as (collapsed entries, addresses)."""
    merged = collapsed_networks(prefixes)
    return Coverage(
        prefixes=len(merged), addresses=sum(net.num_addresses for net in merged)
    )


def list_hash(prefixes: Sequence[str]) -> str:
    """Content hash of a candidate list, order-insensitive.

    Order-insensitive because the identity that matters is "the same set of
    routes", and the renderer's sort is not part of the promise. Used to detect a
    stale approval card and to count the confirmation streak.
    """
    joined = "\n".join(sorted(set(prefixes)))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def analyse_change(
    *,
    current: Sequence[str],
    candidate: Sequence[str],
    sources: Sequence[SourceState],
    baselines: Mapping[str, Coverage],
    thresholds: Thresholds = DEFAULT_THRESHOLDS,
    list_baseline_key: str = LIST_SCOPE,
) -> ChangeAnalysis:
    """Compare *candidate* against what is applied now and against the baselines.

    A source with no baseline is never held: the first run after a source is
    enabled has nothing to ratchet against, and inventing a baseline from the
    same run it is measuring would make the guard vacuous. It gets a baseline the
    first time a list containing it is applied.

    The subtract direction is checked separately and explicitly, because it is
    the mirror image of the obvious one: a subtrahend that shrinks does not
    shrink the routed list, it **grows** it — on the Google pair, every GCP
    customer range that cloud.json stopped listing silently re-enters the tunnel.
    A reader who only remembers "shrinking is bad" would drop that check as
    redundant, so it is stated as its own rule with its own message.
    """
    before_nets = collapsed_networks(current)
    after_nets = collapsed_networks(candidate)
    before = Coverage(
        prefixes=len(before_nets), addresses=sum(net.num_addresses for net in before_nets)
    )
    after = Coverage(
        prefixes=len(after_nets), addresses=sum(net.num_addresses for net in after_nets)
    )
    current_set, candidate_set = set(current), set(candidate)

    changes: list[SourceChange] = []
    holds: list[Hold] = []
    for source in sources:
        baseline = baselines.get(source.slug)
        stale = (
            source.age_sec is None or source.age_sec > thresholds.stale_after_sec
        ) and baseline is not None
        change = SourceChange(
            slug=source.slug,
            mode=source.mode,
            before=baseline,
            after=source.coverage,
            age_sec=source.age_sec,
            stale=stale,
        )
        changes.append(change)

        if source.empty_parse or (source.coverage.empty and baseline is not None):
            # Two ways to get here, both "this operand has vanished": the feed
            # published a document with no usable prefixes on this run, or the
            # stored contribution is empty where the baseline had address space.
            # The second is not reachable through the normal path — it means the
            # state was emptied by something else — and is checked anyway, because
            # a guard that only covers the reachable case stops covering anything
            # the day the paths change.
            holds.append(
                Hold(
                    code=HOLD_EMPTY_SOURCE,
                    slug=source.slug,
                    before=0 if baseline is None else baseline.addresses,
                    after=source.coverage.addresses,
                )
            )
        elif change.shrink_pct > thresholds.max_shrink_pct:
            holds.append(
                Hold(
                    code=(
                        HOLD_SHRINK_SUBTRACT
                        if source.mode == "subtract"
                        else HOLD_SHRINK_ADD
                    ),
                    slug=source.slug,
                    pct=change.shrink_pct,
                    before=0 if baseline is None else baseline.addresses,
                    after=source.coverage.addresses,
                )
            )
        if stale:
            holds.append(
                Hold(
                    code=HOLD_STALE_SOURCE,
                    slug=source.slug,
                    pct=0.0,
                    before=-1 if source.age_sec is None else source.age_sec,
                    after=thresholds.stale_after_sec,
                )
            )

    list_baseline = baselines.get(list_baseline_key)
    if list_baseline is not None and list_baseline.addresses > 0:
        growth = 100.0 * (after.addresses - list_baseline.addresses) / list_baseline.addresses
        if growth > thresholds.max_growth_pct:
            holds.append(
                Hold(
                    code=HOLD_GROWTH,
                    pct=growth,
                    before=list_baseline.addresses,
                    after=after.addresses,
                )
            )

    return ChangeAnalysis(
        # Prefix counts are reported RAW — the number of entries on each side, not
        # the collapsed number — because that is what the operator sees in the file
        # and in the panel, and because the 108 → 106 case is invisible otherwise
        # (both sides collapse to 106). Address counts are always collapsed: an
        # overlap counted twice would not be a coverage measurement at all.
        prefixes_before=len(current),
        prefixes_after=len(candidate),
        addresses_before=before.addresses,
        addresses_after=after.addresses,
        list_hash=list_hash(candidate),
        added=tuple(sorted(candidate_set - current_set)),
        removed=tuple(sorted(current_set - candidate_set)),
        sources=tuple(changes),
        holds=tuple(holds),
        baseline_addresses=None if list_baseline is None else list_baseline.addresses,
        baseline_prefixes=None if list_baseline is None else list_baseline.prefixes,
        same_space=before_nets == after_nets,
    )


def with_hold(analysis: ChangeAnalysis, hold: Hold) -> ChangeAnalysis:
    """Return *analysis* with one more hold appended.

    Used for the two holds that are not properties of the address arithmetic —
    ``review-mode`` (the operator asked for every change to be approved) and
    ``streak`` (the same candidate has not been seen often enough yet) — so that
    the card renders them through exactly the same path as a threshold breach.

    ``replace`` rather than a field-by-field rebuild: a rebuild silently drops any
    field added later, and the first one to go missing that way was
    ``same_space`` — which turned every reviewed re-aggregation into "not pure
    aggregation" without changing a single number on the card.
    """
    return replace(analysis, holds=(*analysis.holds, hold))
