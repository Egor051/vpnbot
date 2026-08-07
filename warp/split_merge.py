"""Pure computation core for the WARP selective-split list.

Everything here is a function from parsed input to parsed output: no network, no
filesystem, no shell. That is deliberate. The interesting failure modes of the
feed feature are all set arithmetic over address space — a subtracted prefix
nested inside its base, a subtraction that shatters a /12 into dozens of
fragments, an operand that came back empty — and keeping them in a pure module
turns each one into a two-line test instead of an integration fixture.

One rule is worth stating before the code, because getting it wrong fails
silently rather than loudly:

    Subtraction is done over ADDRESSES, never over strings.

``cloud.json`` (GCP) lists prefixes that are, as a rule, *subnets inside*
``goog.json``'s prefixes. On the real data (2026-08-06) a set-difference of the
textual forms removes 7 of 99 entries and leaves every GCP customer range in the
routing table, while the address-level difference removes 19.1M of 22.2M
addresses. Nothing about the string version looks broken — that is the danger.
See :func:`subtract_networks`.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

IPv4Net = ipaddress.IPv4Network

# Origin marker for prefixes the operator typed in by hand, as opposed to a feed
# slug. Stored in warp_split_prefixes.origin and shown in the panel.
MANUAL_ORIGIN: Final = "manual"

FEED_KINDS: Final[frozenset[str]] = frozenset({"cidr_text", "google_json"})
FEED_MODES: Final[frozenset[str]] = frozenset({"add", "subtract"})

# Comment markers honoured in a plain-text feed. Telegram's cidr.txt has none
# today, but an operator-supplied text URL very well may.
_COMMENT_CHARS: Final = ("#", ";")

# Slugs are identifiers AND cache file stems, so the character set is pinned.
_SLUG_RE: Final = re.compile(r"[a-z0-9][a-z0-9-]{1,39}")


class FeedParseError(ValueError):
    """The payload could not be turned into a usable prefix set.

    Raised for a structurally broken document AND for one that yields zero IPv4
    prefixes. The second case is policy, not pedantry: an empty result is
    indistinguishable from a truncated download or a silently changed endpoint,
    and the safe response to both is to keep the last good cache rather than to
    apply "no prefixes". A feed that legitimately contains only IPv6 is
    therefore unusable here, which is correct — this host has no IPv6.
    """


# ── parsed shapes ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ParsedFeed:
    """Outcome of parsing one feed payload.

    ``ipv6_skipped`` and ``invalid_lines`` are reported for the panel and the log
    but are never errors on their own: one malformed line must not discard the
    other 98 good ones (that is exactly how a feed provider's stray footer would
    take the whole split list down).
    """

    networks: tuple[IPv4Net, ...]
    ipv6_skipped: int = 0
    invalid_lines: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SourceContribution:
    """One resolved source ready to take part in the merge.

    ``networks`` is what the source actually yielded (from a fresh fetch or from
    its last good cache — the merge does not care which, and must not: see
    :mod:`services.warp_split_feeds` for the rule that a subtract operand with
    no cache at all aborts the whole merge instead of contributing nothing).
    """

    slug: str
    mode: str                  # "add" | "subtract"
    networks: tuple[IPv4Net, ...]
    scope_slug: str | None = None


@dataclass(frozen=True, slots=True)
class MergeReport:
    """The merged list plus the numbers the UI and the cap check need.

    The three counts exist because subtraction makes the list *longer*, and that
    has to be visible rather than inferred. Punching cloud.json's holes out of
    goog.json's /12s and /14s takes 99 prefixes to 262 on the real data — and
    ``collapse`` cannot put them back, because the holes are real. See
    ``prefixes_added_by_subtraction``.
    """

    prefixes: tuple[str, ...]
    n_before_subtract: int
    n_after_subtract: int
    addresses_before: int
    addresses_after: int
    per_origin: Mapping[str, int]

    @property
    def n_after_collapse(self) -> int:
        return len(self.prefixes)

    @property
    def addresses_removed(self) -> int:
        return self.addresses_before - self.addresses_after

    @property
    def prefixes_added_by_subtraction(self) -> int:
        """How many extra prefixes the subtraction cost, after collapse.

        Negative is possible and fine (a subtraction that removes whole entries
        rather than punching holes shortens the list).
        """
        return self.n_after_collapse - self.n_before_subtract

    @property
    def subtraction_applied(self) -> bool:
        return self.addresses_removed > 0


# ── parsers ───────────────────────────────────────────────────────────────────


def parse_cidr_text(payload: str) -> ParsedFeed:
    """Parse a plain-text feed: one CIDR per line, ``#``/``;`` comments, blanks.

    Used for Telegram's ``core.telegram.org/resources/cidr.txt`` and for any
    text URL an admin adds. IPv6 entries are dropped without complaint (the
    host has no IPv6); unparseable lines are collected, not raised.
    """
    networks: list[IPv4Net] = []
    invalid: list[str] = []
    ipv6 = 0
    for raw in payload.splitlines():
        line = raw.strip()
        for marker in _COMMENT_CHARS:
            line = line.split(marker, 1)[0].strip()
        if not line:
            continue
        parsed = _parse_one(line)
        if parsed is None:
            invalid.append(line[:64])
        elif parsed.version != 4:
            ipv6 += 1
        else:
            networks.append(parsed)
    return _finish_parse(networks, ipv6, invalid, kind="cidr_text")


def parse_google_json(payload: str) -> ParsedFeed:
    """Parse a gstatic ipranges document (``goog.json``, ``cloud.json``).

    Shape: ``{"prefixes": [{"ipv4Prefix": "8.8.8.0/24"}, {"ipv6Prefix": …}, …]}``.
    ``cloud.json`` carries extra ``service``/``scope`` keys per entry; they are
    ignored, which is what keeps this one parser good for both documents.
    """
    try:
        document = json.loads(payload)
    except ValueError as exc:
        raise FeedParseError(f"invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise FeedParseError("expected a JSON object at the top level")
    entries = document.get("prefixes")
    if not isinstance(entries, list):
        raise FeedParseError("missing or non-list 'prefixes' array")

    networks: list[IPv4Net] = []
    invalid: list[str] = []
    ipv6 = 0
    for entry in entries:
        if not isinstance(entry, dict):
            invalid.append(str(entry)[:64])
            continue
        value = entry.get("ipv4Prefix")
        if value is None:
            if entry.get("ipv6Prefix") is not None:
                ipv6 += 1
            continue
        if not isinstance(value, str):
            invalid.append(str(value)[:64])
            continue
        parsed = _parse_one(value)
        if parsed is None or parsed.version != 4:
            invalid.append(value[:64])
        else:
            networks.append(parsed)
    return _finish_parse(networks, ipv6, invalid, kind="google_json")


def parse_feed(kind: str, payload: str) -> ParsedFeed:
    """Dispatch to the parser for *kind*; raises FeedParseError on an unknown one."""
    if kind == "cidr_text":
        return parse_cidr_text(payload)
    if kind == "google_json":
        return parse_google_json(payload)
    raise FeedParseError(f"unsupported feed kind {kind!r}")


def _parse_one(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def _finish_parse(
    networks: list[IPv4Net], ipv6: int, invalid: list[str], *, kind: str
) -> ParsedFeed:
    if not networks:
        raise FeedParseError(
            f"{kind}: no usable IPv4 prefixes "
            f"({ipv6} IPv6 skipped, {len(invalid)} unparseable) — "
            "treated as a failed fetch, not as an empty list"
        )
    return ParsedFeed(
        networks=tuple(sort_networks(networks)),
        ipv6_skipped=ipv6,
        invalid_lines=tuple(invalid),
    )


# ── set arithmetic ────────────────────────────────────────────────────────────


def sort_networks(networks: Iterable[IPv4Net]) -> list[IPv4Net]:
    """Stable, human-readable order: by address, then by mask length."""
    return sorted(networks, key=lambda net: (int(net.network_address), net.prefixlen))


def collapse(networks: Iterable[IPv4Net]) -> list[IPv4Net]:
    """Dedupe, absorb subnets into supernets, and merge adjacent siblings."""
    return sort_networks(ipaddress.collapse_addresses(list(networks)))


def subtract_networks(base: Sequence[IPv4Net], minus: Sequence[IPv4Net]) -> list[IPv4Net]:
    """Return *base* minus *minus*, computed over addresses.

    Two CIDR blocks are never partially overlapping — either they are disjoint,
    or one contains the other — so each base network meets exactly one of three
    fates per subtrahend:

      * disjoint            → kept verbatim;
      * covered by it       → dropped entirely;
      * strictly containing → replaced by ``address_exclude`` fragments.

    The result is NOT collapsed: the caller collapses once at the end, so the
    intermediate count stays available for the fragmentation report. Passing an
    empty *minus* returns *base* unchanged, which is the only reason this is
    safe to call unconditionally.
    """
    current = list(base)
    for hole in collapse(minus):
        if not current:
            break
        remaining: list[IPv4Net] = []
        for net in current:
            if not net.overlaps(hole):
                remaining.append(net)
            elif net.subnet_of(hole):
                continue  # fully covered (this includes net == hole)
            else:
                # hole is a strict subnet of net — punch it out.
                remaining.extend(net.address_exclude(hole))
        current = remaining
    return current


def merge_split_list(
    *,
    manual: Sequence[IPv4Net],
    sources: Sequence[SourceContribution],
    exclusions: Sequence[IPv4Net] = (),
) -> MergeReport:
    """Compute the final split list.

        result = collapse( union(add sources, manual) - subtract sources - exclusions )

    A subtract source with ``scope_slug`` set is applied to that one source's
    contribution only, *before* the union; one with ``scope_slug=None`` is
    applied to the whole union afterwards. Manual exclusions are the same
    mechanism at the same step as a global subtract — they are simply a
    subtrahend the operator typed rather than downloaded.

    Scoping is not cosmetic. On this host the manual list happens to duplicate
    goog.json exactly, so subtracting cloud.json scoped to ``google-goog``
    leaves the manual copies untouched and the GCP ranges still routed. That is
    the documented behaviour of a scope, not a bug in it — the panel warns, and
    the operator migrates the manual entries into the feed.
    """
    buckets: dict[str, list[IPv4Net]] = {MANUAL_ORIGIN: collapse(manual)}
    for source in sources:
        if source.mode == "add":
            buckets[source.slug] = collapse(source.networks)

    # "Before" is measured with no subtraction at all, so the report can say what
    # the subtraction actually cost rather than what it was asked to cost.
    union_before = collapse([net for bucket in buckets.values() for net in bucket])
    n_before = len(union_before)
    addresses_before = sum(net.num_addresses for net in union_before)

    scoped = [s for s in sources if s.mode == "subtract" and s.scope_slug is not None]
    globals_ = [s for s in sources if s.mode == "subtract" and s.scope_slug is None]

    for source in scoped:
        target = source.scope_slug
        if target is None or target not in buckets:
            # The scope names a source that is absent or disabled: there is
            # nothing to subtract from, so this operand simply does not apply.
            continue
        buckets[target] = subtract_networks(buckets[target], list(source.networks))

    merged = collapse([net for bucket in buckets.values() for net in bucket])
    for source in globals_:
        merged = subtract_networks(merged, list(source.networks))
    if exclusions:
        merged = subtract_networks(merged, list(exclusions))

    n_after_subtract = len(merged)
    final = collapse(merged)
    per_origin = {origin: len(bucket) for origin, bucket in buckets.items() if bucket}

    return MergeReport(
        prefixes=tuple(str(net) for net in final),
        n_before_subtract=n_before,
        n_after_subtract=n_after_subtract,
        addresses_before=addresses_before,
        addresses_after=sum(net.num_addresses for net in final),
        per_origin=per_origin,
    )


# ── source validation (pure policy, enforced when a source is added) ──────────


def resolve_origins(
    prefixes: Sequence[str], contributions: Mapping[str, Sequence[str]]
) -> dict[str, tuple[str, ...]]:
    """Map each of *prefixes* to the origins whose address space it covers.

    Needed because ``collapse`` erases provenance: two /22s from Telegram become
    one /21 that matches neither input string, so a lookup by exact text would
    label a routed prefix "unknown" and the panel would show no origin for it.
    Overlap is the honest test — a final prefix belongs to every origin that put
    address space inside it, and a collapsed one legitimately belongs to several.

    Call this per PAGE, not for the whole list: it is O(prefixes x contributions)
    and a subtract source alone contributes ~1000 networks.
    """
    parsed_contributions = {
        origin: collapse([ipaddress.IPv4Network(item) for item in items])
        for origin, items in contributions.items()
        if items
    }
    resolved: dict[str, tuple[str, ...]] = {}
    for prefix in prefixes:
        try:
            net = ipaddress.IPv4Network(prefix)
        except ValueError:
            resolved[prefix] = ()
            continue
        owners = [
            origin
            for origin, nets in parsed_contributions.items()
            if any(candidate.overlaps(net) for candidate in nets)
        ]
        resolved[prefix] = tuple(sorted(owners))
    return resolved


def validate_slug(slug: str) -> None:
    """Reject a slug that is unsafe as an identifier or as a file name.

    A slug becomes ``<slug>.raw`` under the feed cache directory, so the
    character set is pinned here rather than trusted from the admin's keyboard.
    Raises ValueError with a message meant for the admin.
    """
    if not _SLUG_RE.fullmatch(slug):
        raise ValueError(
            "slug may contain only lowercase letters, digits and '-', must start "
            "with a letter or digit, and must be 2-40 characters long"
        )
    if slug == MANUAL_ORIGIN:
        raise ValueError(f"'{MANUAL_ORIGIN}' is reserved for hand-typed prefixes")


def validate_source_relations(
    *,
    slug: str,
    mode: str,
    scope_slug: str | None,
    existing_modes: Mapping[str, str],
) -> None:
    """Reject an ill-formed source before it can be stored.

    ``existing_modes`` maps every already-known slug to its mode. The rules keep
    the evaluation order in :func:`merge_split_list` a single pass with no cycle
    detection to get wrong:

      * a scope only means something for a subtract source;
      * a source may not subtract from itself;
      * a subtract source may not scope onto another subtract source — chains
        deeper than one level are not supported, and a silently ignored chain
        would be worse than a rejected one.

    Raises ValueError with a message meant to be shown to the admin verbatim.
    """
    if mode not in FEED_MODES:
        raise ValueError(f"unknown mode {mode!r} (expected 'add' or 'subtract')")
    if mode == "add":
        if scope_slug is not None:
            raise ValueError("scope is only meaningful for a subtract source")
        return
    if scope_slug is None:
        return  # global subtraction — applies to the whole merged set
    if scope_slug == slug:
        raise ValueError(f"source '{slug}' cannot subtract from itself")
    target_mode = existing_modes.get(scope_slug)
    if target_mode is None:
        raise ValueError(f"unknown scope source '{scope_slug}'")
    if target_mode == "subtract":
        raise ValueError(
            f"'{scope_slug}' is itself a subtract source — chained subtraction "
            "is not supported; scope onto an add source or drop the scope"
        )
