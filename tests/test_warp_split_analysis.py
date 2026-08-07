"""The ratchet arithmetic, in isolation.

Every case here is a statement about *coverage*, which is why none of them needs a
database, a feed or a list file. The question each one answers is the same: given
what was last applied and what the merge now proposes, is this a change a machine
may make on its own?

The numbers in the first test are the real ones from this host (2026-08-06): 108
prefixes in the list file collapse to 106 with byte-identical address coverage.
That measurement is the reason the thresholds count addresses at all.
"""
from __future__ import annotations

import pytest

from warp.split_analysis import (
    HOLD_EMPTY_SOURCE,
    HOLD_GROWTH,
    HOLD_SHRINK_ADD,
    HOLD_SHRINK_SUBTRACT,
    HOLD_STALE_SOURCE,
    Coverage,
    SourceState,
    Thresholds,
    analyse_change,
    coverage_of,
    list_hash,
)

THRESHOLDS = Thresholds(max_shrink_pct=20, max_growth_pct=50, stale_after_sec=259_200)


def _source(
    slug: str = "feed",
    *,
    mode: str = "add",
    addresses: int = 1024,
    prefixes: int = 4,
    age_sec: int | None = 60,
    empty_parse: bool = False,
) -> SourceState:
    return SourceState(
        slug=slug,
        mode=mode,
        coverage=Coverage(prefixes=prefixes, addresses=addresses),
        age_sec=age_sec,
        empty_parse=empty_parse,
    )


class TestCoverage:
    def test_collapsing_does_not_change_the_address_count(self):
        """The 108 → 106 case, in miniature.

        Two adjacent /24s and the /23 that contains them describe the same 512
        addresses. If coverage were counted in prefixes, re-expressing the same
        space would read as a change; in addresses it reads as what it is.
        """
        split = coverage_of(["10.0.0.0/24", "10.0.1.0/24"])
        joined = coverage_of(["10.0.0.0/23"])
        assert split.addresses == joined.addresses == 512
        assert split.prefixes == joined.prefixes == 1  # collapse merges the siblings

    def test_hash_ignores_order_and_duplicates(self):
        assert list_hash(["10.0.0.0/24", "10.0.1.0/24"]) == list_hash(
            ["10.0.1.0/24", "10.0.0.0/24", "10.0.0.0/24"]
        )


class TestPureAggregation:
    def test_same_addresses_fewer_prefixes_is_pure_aggregation(self):
        analysis = analyse_change(
            current=["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"],
            candidate=["10.0.0.0/23", "10.0.2.0/24"],
            sources=[],
            baselines={},
            thresholds=THRESHOLDS,
        )
        assert analysis.pure_aggregation
        assert analysis.addresses_before == analysis.addresses_after
        assert not analysis.suspicious

    def test_equal_address_counts_over_different_space_are_not_pure_aggregation(self):
        """The false negative worth guarding against.

        Two /24s and one /23 elsewhere cover the same 512 addresses and share none
        of them. Comparing coverage *sizes* would call this a harmless
        re-aggregation and let auto mode reroute half the list; comparing the
        collapsed sets calls it what it is.
        """
        analysis = analyse_change(
            current=["10.0.0.0/24", "10.0.1.0/24"],
            candidate=["11.0.0.0/23"],
            sources=[],
            baselines={},
            thresholds=THRESHOLDS,
        )
        assert analysis.addresses_before == analysis.addresses_after == 512
        assert not analysis.pure_aggregation

    def test_an_identical_list_is_not_pure_aggregation(self):
        """No change is not "a change that happens to be safe" — it is no change,
        and the caller must not queue anything for it."""
        analysis = analyse_change(
            current=["10.0.0.0/24"],
            candidate=["10.0.0.0/24"],
            sources=[],
            baselines={},
            thresholds=THRESHOLDS,
        )
        assert analysis.identical
        assert not analysis.pure_aggregation


class TestShrink:
    def test_an_add_source_losing_a_fifth_is_held(self):
        analysis = analyse_change(
            current=["10.0.0.0/16"],
            candidate=["10.0.0.0/17"],
            sources=[_source("telegram-cidr", addresses=32_768)],
            baselines={"telegram-cidr": Coverage(prefixes=8, addresses=65_536)},
            thresholds=THRESHOLDS,
        )
        assert [hold.code for hold in analysis.holds] == [HOLD_SHRINK_ADD]
        assert analysis.holds[0].pct == pytest.approx(50.0)

    def test_a_shrink_within_the_threshold_passes(self):
        analysis = analyse_change(
            current=["10.0.0.0/16"],
            candidate=["10.0.0.0/16"],
            sources=[_source("telegram-cidr", addresses=60_000)],
            baselines={"telegram-cidr": Coverage(prefixes=8, addresses=65_536)},
            thresholds=THRESHOLDS,
        )
        assert not analysis.suspicious

    def test_a_shrinking_subtrahend_is_held_under_its_own_code(self):
        """The mirrored direction, and the reason it is checked separately.

        google-cloud losing half its coverage does not shrink the routed list — it
        *grows* it, by exactly the GCP ranges cloud.json stopped listing. A reader
        who remembers only "shrinking is bad" would delete this check as a
        duplicate of the one above, so it has its own code and its own message.
        """
        analysis = analyse_change(
            current=["10.0.0.0/16"],
            candidate=["10.0.0.0/15"],
            sources=[_source("google-cloud", mode="subtract", addresses=1_000)],
            baselines={"google-cloud": Coverage(prefixes=900, addresses=19_100_000)},
            thresholds=THRESHOLDS,
        )
        assert [hold.code for hold in analysis.holds] == [HOLD_SHRINK_SUBTRACT]

    def test_a_source_without_a_baseline_is_never_held(self):
        """First run after enabling a source: there is nothing to ratchet against,
        and inventing a baseline from the run being measured would make the guard
        vacuous rather than lenient."""
        analysis = analyse_change(
            current=["10.0.0.0/16"],
            candidate=["10.0.0.0/24"],
            sources=[_source("brand-new", addresses=256)],
            baselines={},
            thresholds=THRESHOLDS,
        )
        assert not analysis.suspicious


class TestGrowth:
    def test_growth_beyond_the_threshold_is_held(self):
        analysis = analyse_change(
            current=["10.0.0.0/24"],
            candidate=["10.0.0.0/16"],
            sources=[],
            baselines={"list": Coverage(prefixes=1, addresses=256)},
            thresholds=THRESHOLDS,
        )
        assert [hold.code for hold in analysis.holds] == [HOLD_GROWTH]

    def test_growth_is_measured_against_the_baseline_not_the_file(self):
        """The ratchet's whole point.

        The file was changed by some other path to something small; the baseline
        still records what was last applied through this subsystem. Measuring
        against the file would let a series of small applies walk the list
        anywhere, one accepted step at a time.
        """
        analysis = analyse_change(
            current=["10.0.0.0/28"],
            candidate=["10.0.0.0/24"],
            sources=[],
            baselines={"list": Coverage(prefixes=1, addresses=256)},
            thresholds=THRESHOLDS,
        )
        assert not analysis.suspicious  # 256 → 256 against the baseline
        assert analysis.addresses_before == 16  # …while the file says otherwise


class TestSourceHealth:
    def test_an_empty_parse_is_held_even_though_the_merge_succeeded(self):
        analysis = analyse_change(
            current=["10.0.0.0/24"],
            candidate=["10.0.0.0/23"],
            sources=[_source("telegram-cidr", empty_parse=True)],
            baselines={"telegram-cidr": Coverage(prefixes=4, addresses=1024)},
            thresholds=THRESHOLDS,
        )
        assert [hold.code for hold in analysis.holds] == [HOLD_EMPTY_SOURCE]

    def test_a_stale_source_makes_the_state_incomplete(self):
        analysis = analyse_change(
            current=["10.0.0.0/24"],
            candidate=["10.0.0.0/23"],
            sources=[_source("telegram-cidr", age_sec=300_000)],
            baselines={"telegram-cidr": Coverage(prefixes=4, addresses=1024)},
            thresholds=THRESHOLDS,
        )
        assert [hold.code for hold in analysis.holds] == [HOLD_STALE_SOURCE]

    def test_freshness_is_measured_per_source(self):
        analysis = analyse_change(
            current=["10.0.0.0/24"],
            candidate=["10.0.0.0/23"],
            sources=[
                _source("fresh", age_sec=60),
                _source("old", age_sec=300_000),
            ],
            baselines={
                "fresh": Coverage(prefixes=4, addresses=1024),
                "old": Coverage(prefixes=4, addresses=1024),
            },
            thresholds=THRESHOLDS,
        )
        assert [(hold.code, hold.slug) for hold in analysis.holds] == [
            (HOLD_STALE_SOURCE, "old")
        ]
