"""Row-shaped state for the WARP selective-split feed subsystem.

Mirrors ``warp_split_sources``, ``warp_split_pending`` and ``warp_split_runs``
one-to-one, the same way :mod:`warp.state` mirrors ``warp_settings``. Kept out of
:mod:`warp.split_merge` and :mod:`warp.split_analysis` on purpose: those modules
are pure arithmetic and must stay free of storage concerns.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SplitSource:
    """One configured prefix feed."""

    id: int
    slug: str
    title: str
    url: str
    kind: str                    # 'cidr_text' | 'google_json'
    mode: str                    # 'add' | 'subtract'
    scope_slug: str | None
    # ``enabled`` means "fetch it and let it take part in the computation".
    # ``include_in_list`` means "its prefixes may reach the routed list" and is
    # meaningless for a subtract source — see ``contributes_to_list``.
    enabled: bool
    include_in_list: bool
    refresh_interval_sec: int
    last_attempt_ts: int = 0
    last_success_ts: int = 0
    last_etag: str | None = None
    last_modified: str | None = None
    last_status: str | None = None
    prefix_count: int = 0
    last_error: str | None = None
    # Consecutive failed fetches; any success resets it. Drives the "this feed has
    # been dead N runs running" alert, which a per-failure alert cannot express.
    fail_streak: int = 0

    @property
    def is_subtract(self) -> bool:
        return self.mode == "subtract"

    @property
    def contributes_to_list(self) -> bool:
        """Whether this source's prefixes can end up in the routed list.

        A subtract source never does, regardless of ``include_in_list`` — that
        flag is ignored for it rather than merely defaulted, so an operator who
        flips it on a subtrahend does not silently route the very ranges they
        were carving out.
        """
        return self.enabled and not self.is_subtract and self.include_in_list

    @property
    def has_succeeded(self) -> bool:
        return self.last_success_ts > 0


@dataclass(frozen=True, slots=True)
class PendingCandidate:
    """The one candidate list waiting for an admin's decision.

    ``prefixes`` is the candidate as it was computed when the card was sent, kept
    so "show in full" needs no recomputation. It is NOT what gets applied: the
    apply recomputes under the manager's lock and refuses if the result no longer
    hashes to ``list_hash`` — see :meth:`services.warp_split_feeds.
    WarpSplitFeedService.apply_pending`.
    """

    ts: int
    list_hash: str
    prefixes: tuple[str, ...] = ()
    reason: str = ""
    deltas: Mapping[str, Any] = field(default_factory=dict)

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return tuple(code for code in self.reason.split(",") if code)


@dataclass(frozen=True, slots=True)
class SplitRun:
    """One row of the unattended-refresh journal."""

    ts: int
    mode: str
    decision: str              # applied | queued | nochange | rejected | failed
    reason: str = ""
    list_hash: str = ""
    sources: Sequence[Mapping[str, Any]] = ()
    metrics: Mapping[str, Any] = field(default_factory=dict)
