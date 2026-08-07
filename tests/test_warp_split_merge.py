"""Tests for warp.split_merge — parsing, address-level subtraction, the merge.

Everything here is pure: no network, no filesystem beyond reading the fixtures,
no shell. The fixtures are slices of the real feeds captured on 2026-08-06, and
the Google pair was chosen so the cloud prefixes are genuinely *nested inside*
the goog ones — which is the only case where the string-difference bug hides.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from warp.split_merge import (
    MANUAL_ORIGIN,
    FeedParseError,
    SourceContribution,
    collapse,
    merge_split_list,
    parse_cidr_text,
    parse_feed,
    parse_google_json,
    resolve_origins,
    subtract_networks,
    validate_slug,
    validate_source_relations,
)

FIXTURES = Path(__file__).parent / "fixtures" / "warp_feeds"


def _nets(*items: str) -> list[ipaddress.IPv4Network]:
    return [ipaddress.IPv4Network(item) for item in items]


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


class TestParseCidrText:
    def test_drops_ipv6_and_keeps_ipv4(self):
        parsed = parse_cidr_text((FIXTURES / "telegram_cidr.txt").read_text(encoding="utf-8"))
        assert len(parsed.networks) == 9
        assert parsed.ipv6_skipped == 5
        assert all(net.version == 4 for net in parsed.networks)

    def test_bad_lines_do_not_abort_the_file(self):
        """One malformed line must cost one line, not the whole feed."""
        parsed = parse_cidr_text((FIXTURES / "telegram_cidr.txt").read_text(encoding="utf-8"))
        assert len(parsed.invalid_lines) == 3  # junk + bad octet + bad mask
        assert ipaddress.IPv4Network("91.108.56.0/22") in parsed.networks

    def test_comments_and_blanks_are_ignored(self):
        parsed = parse_cidr_text("# header\n\n1.2.3.0/24\n5.6.7.0/24 ; note\n")
        assert [str(n) for n in parsed.networks] == ["1.2.3.0/24", "5.6.7.0/24"]

    def test_host_bits_are_normalised(self):
        parsed = parse_cidr_text("1.2.3.4/24\n")
        assert [str(n) for n in parsed.networks] == ["1.2.3.0/24"]

    def test_empty_payload_is_an_error_not_an_empty_list(self):
        """An empty feed and a broken download are indistinguishable from here,
        and only one of them would be safe to act on."""
        with pytest.raises(FeedParseError):
            parse_cidr_text("")

    def test_ipv6_only_payload_is_an_error(self):
        with pytest.raises(FeedParseError):
            parse_cidr_text("2001:b28:f23d::/48\n")


class TestParseGoogleJson:
    def test_reads_ipv4_prefixes(self):
        parsed = parse_google_json((FIXTURES / "goog_sample.json").read_text(encoding="utf-8"))
        assert "8.8.4.0/24" in {str(n) for n in parsed.networks}
        assert parsed.ipv6_skipped == 1

    def test_ignores_extra_keys_so_one_parser_serves_both_documents(self):
        """cloud.json carries service/scope per entry; goog.json does not."""
        parsed = parse_google_json((FIXTURES / "cloud_sample.json").read_text(encoding="utf-8"))
        assert len(parsed.networks) == 19

    def test_malformed_json_raises(self):
        with pytest.raises(FeedParseError):
            parse_google_json("{not json")

    def test_missing_prefixes_array_raises(self):
        with pytest.raises(FeedParseError):
            parse_google_json('{"syncToken": "1"}')

    def test_unknown_kind_raises(self):
        with pytest.raises(FeedParseError):
            parse_feed("csv", "1.2.3.0/24")


# ---------------------------------------------------------------------------
# Subtraction — the cases that make or break this feature
# ---------------------------------------------------------------------------


class TestSubtractNetworks:
    def test_nested_prefix_is_really_carved_out(self):
        """The only interesting case: the subtrahend is strictly inside the base.

        A set-difference over the textual forms returns the base untouched here,
        which is exactly the silent failure this must not have.
        """
        result = subtract_networks(_nets("10.0.0.0/8"), _nets("10.1.0.0/16"))
        addresses = sum(net.num_addresses for net in result)
        assert addresses == 2**24 - 2**16
        assert ipaddress.IPv4Network("10.1.0.0/16") not in result
        assert all(not net.overlaps(ipaddress.IPv4Network("10.1.0.0/16")) for net in result)
        # and the string form would have changed nothing at all
        assert {str(n) for n in result} != {"10.0.0.0/8"}

    def test_covering_prefix_removes_the_base_entirely(self):
        assert subtract_networks(_nets("10.1.0.0/16"), _nets("10.0.0.0/8")) == []

    def test_equal_prefix_removes_the_base(self):
        assert subtract_networks(_nets("10.1.0.0/16"), _nets("10.1.0.0/16")) == []

    def test_disjoint_subtraction_changes_nothing(self):
        base = _nets("10.0.0.0/8", "192.168.0.0/16")
        assert subtract_networks(base, _nets("172.16.0.0/12")) == base

    def test_empty_subtrahend_is_identity(self):
        base = _nets("10.0.0.0/8")
        assert subtract_networks(base, []) == base

    def test_real_data_fragments_and_collapse_cannot_undo_it(self):
        """Measured property, not a guess: carving cloud out of goog makes the
        list LONGER, and the holes are real so collapse cannot put them back."""
        goog = parse_google_json((FIXTURES / "goog_sample.json").read_text(encoding="utf-8"))
        cloud = parse_google_json((FIXTURES / "cloud_sample.json").read_text(encoding="utf-8"))
        result = subtract_networks(list(goog.networks), list(cloud.networks))
        assert len(result) > len(goog.networks)
        assert len(collapse(result)) > len(goog.networks)
        # and the address space really shrank
        assert sum(n.num_addresses for n in result) < sum(n.num_addresses for n in goog.networks)


class TestCollapse:
    def test_overlapping_prefixes_collapse(self):
        assert [str(n) for n in collapse(_nets("10.0.0.0/8", "10.1.0.0/16"))] == ["10.0.0.0/8"]

    def test_adjacent_siblings_merge(self):
        merged = collapse(_nets("91.108.8.0/22", "91.108.12.0/22"))
        assert [str(n) for n in merged] == ["91.108.8.0/21"]

    def test_duplicates_are_removed(self):
        assert [str(n) for n in collapse(_nets("1.2.3.0/24", "1.2.3.0/24"))] == ["1.2.3.0/24"]


# ---------------------------------------------------------------------------
# merge_split_list
# ---------------------------------------------------------------------------


class TestMerge:
    def test_manual_only(self):
        report = merge_split_list(manual=_nets("1.2.3.0/24"), sources=[])
        assert report.prefixes == ("1.2.3.0/24",)
        assert not report.subtraction_applied

    def test_add_sources_union_with_manual(self):
        report = merge_split_list(
            manual=_nets("1.2.3.0/24"),
            sources=[SourceContribution("feed", "add", tuple(_nets("5.6.7.0/24")))],
        )
        assert set(report.prefixes) == {"1.2.3.0/24", "5.6.7.0/24"}

    def test_scope_limits_subtraction_to_the_named_source(self):
        """A scoped subtrahend touches its target's contribution and nothing else.

        The second half of this assertion is the one that matters on a real host:
        the same range present as a manual entry is NOT carved out, so the
        subtraction is inert until the manual copy is given up.
        """
        sources = [
            SourceContribution("base", "add", tuple(_nets("10.0.0.0/8"))),
            SourceContribution("other", "add", tuple(_nets("172.20.0.0/14"))),
            SourceContribution("minus", "subtract", tuple(_nets("10.1.0.0/16")), scope_slug="base"),
        ]
        scoped = merge_split_list(manual=[], sources=sources)
        assert all(
            not ipaddress.IPv4Network(p).overlaps(ipaddress.IPv4Network("10.1.0.0/16"))
            for p in scoped.prefixes
        )

        # Same subtraction, but the range also exists as a manual entry.
        with_manual = merge_split_list(manual=_nets("10.0.0.0/8"), sources=sources)
        assert "10.0.0.0/8" in with_manual.prefixes

    def test_global_subtraction_reaches_manual_too(self):
        report = merge_split_list(
            manual=_nets("10.0.0.0/8"),
            sources=[SourceContribution("minus", "subtract", tuple(_nets("10.1.0.0/16")))],
        )
        assert "10.0.0.0/8" not in report.prefixes
        assert all(
            not ipaddress.IPv4Network(p).overlaps(ipaddress.IPv4Network("10.1.0.0/16"))
            for p in report.prefixes
        )

    def test_exclusions_are_the_same_mechanism_as_a_global_subtract(self):
        via_exclusion = merge_split_list(
            manual=_nets("10.0.0.0/8"), sources=[], exclusions=_nets("10.1.0.0/16")
        )
        via_source = merge_split_list(
            manual=_nets("10.0.0.0/8"),
            sources=[SourceContribution("minus", "subtract", tuple(_nets("10.1.0.0/16")))],
        )
        assert via_exclusion.prefixes == via_source.prefixes

    def test_report_counts_describe_the_fragmentation(self):
        report = merge_split_list(
            manual=_nets("10.0.0.0/8"),
            sources=[SourceContribution("minus", "subtract", tuple(_nets("10.1.0.0/16")))],
        )
        assert report.n_before_subtract == 1
        assert report.n_after_subtract > 1
        assert report.prefixes_added_by_subtraction == report.n_after_collapse - 1
        assert report.addresses_removed == 2**16
        assert report.subtraction_applied

    def test_subtract_source_never_contributes_prefixes(self):
        report = merge_split_list(
            manual=_nets("1.2.3.0/24"),
            sources=[SourceContribution("minus", "subtract", tuple(_nets("9.9.9.0/24")))],
        )
        assert report.prefixes == ("1.2.3.0/24",)

    def test_scope_naming_a_missing_source_is_inert_not_an_error(self):
        report = merge_split_list(
            manual=_nets("10.0.0.0/8"),
            sources=[
                SourceContribution("minus", "subtract", tuple(_nets("10.1.0.0/16")), scope_slug="gone")
            ],
        )
        assert report.prefixes == ("10.0.0.0/8",)

    def test_output_is_sorted_and_stable(self):
        report = merge_split_list(manual=_nets("9.0.0.0/8", "1.0.0.0/8", "5.0.0.0/8"), sources=[])
        assert report.prefixes == ("1.0.0.0/8", "5.0.0.0/8", "9.0.0.0/8")

    def test_per_origin_counts_are_reported(self):
        report = merge_split_list(
            manual=_nets("1.2.3.0/24"),
            sources=[SourceContribution("feed", "add", tuple(_nets("5.6.7.0/24", "5.6.8.0/24")))],
        )
        assert report.per_origin[MANUAL_ORIGIN] == 1
        assert report.per_origin["feed"] == 2


# ---------------------------------------------------------------------------
# Origin resolution
# ---------------------------------------------------------------------------


class TestResolveOrigins:
    def test_exact_match(self):
        resolved = resolve_origins(["1.2.3.0/24"], {"feed": ["1.2.3.0/24"]})
        assert resolved["1.2.3.0/24"] == ("feed",)

    def test_collapsed_prefix_still_finds_its_origins(self):
        """collapse() erases provenance, so the lookup has to be by overlap —
        a lookup by exact text would label the merged /21 as unknown."""
        resolved = resolve_origins(
            ["91.108.8.0/21"], {"telegram": ["91.108.8.0/22", "91.108.12.0/22"]}
        )
        assert resolved["91.108.8.0/21"] == ("telegram",)

    def test_multiple_origins_are_all_reported(self):
        resolved = resolve_origins(
            ["10.0.0.0/8"], {"a": ["10.1.0.0/16"], "b": ["10.2.0.0/16"], "c": ["192.168.0.0/16"]}
        )
        assert resolved["10.0.0.0/8"] == ("a", "b")

    def test_unparseable_prefix_yields_no_origins(self):
        assert resolve_origins(["nonsense"], {"a": ["10.0.0.0/8"]})["nonsense"] == ()


# ---------------------------------------------------------------------------
# Source validation (recursion guard)
# ---------------------------------------------------------------------------


class TestValidateSourceRelations:
    def test_self_reference_is_rejected(self):
        with pytest.raises(ValueError, match="cannot subtract from itself"):
            validate_source_relations(
                slug="a", mode="subtract", scope_slug="a", existing_modes={"a": "add"}
            )

    def test_chained_subtraction_is_rejected(self):
        with pytest.raises(ValueError, match="chained subtraction"):
            validate_source_relations(
                slug="c", mode="subtract", scope_slug="b", existing_modes={"b": "subtract"}
            )

    def test_scope_on_an_add_source_is_rejected(self):
        with pytest.raises(ValueError, match="only meaningful for a subtract"):
            validate_source_relations(
                slug="a", mode="add", scope_slug="b", existing_modes={"b": "add"}
            )

    def test_unknown_scope_is_rejected(self):
        with pytest.raises(ValueError, match="unknown scope"):
            validate_source_relations(
                slug="a", mode="subtract", scope_slug="ghost", existing_modes={}
            )

    def test_unknown_mode_is_rejected(self):
        with pytest.raises(ValueError, match="unknown mode"):
            validate_source_relations(
                slug="a", mode="multiply", scope_slug=None, existing_modes={}
            )

    def test_global_subtract_and_plain_add_are_accepted(self):
        validate_source_relations(slug="a", mode="subtract", scope_slug=None, existing_modes={})
        validate_source_relations(slug="b", mode="add", scope_slug=None, existing_modes={})


class TestValidateSlug:
    @pytest.mark.parametrize("slug", ["../etc/passwd", "a/b", "UPPER", "x", "", "a" * 41, "-lead"])
    def test_rejects_unsafe_slugs(self, slug):
        with pytest.raises(ValueError):
            validate_slug(slug)

    def test_reserved_manual_origin_is_rejected(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_slug(MANUAL_ORIGIN)

    def test_accepts_a_normal_slug(self):
        validate_slug("google-goog")
