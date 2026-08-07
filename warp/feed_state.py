"""Row-shaped state for the WARP selective-split feed subsystem.

Mirrors ``warp_split_sources`` one-to-one, the same way :mod:`warp.state` mirrors
``warp_settings``. Kept out of :mod:`warp.split_merge` on purpose: that module is
pure address arithmetic and must stay free of storage concerns.
"""
from __future__ import annotations

from dataclasses import dataclass


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
