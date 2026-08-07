"""Supervised unattended refresh: review, auto, and the approval queue.

The question every test here asks is the one the feature exists for: **can a
scheduled run change the routing policy without a human having agreed to this
particular change?** The answer must be no in `review` for every change at all,
and no in `auto` for anything that trips a threshold or has not been seen twice.

Offline by construction, like ``tests/test_warp_split_feeds.py``, whose harness
this file reuses: the fetcher is a stub, the privileged helper is a recording fake
shell that writes the list file exactly as ``vpn-bot-warp-split-apply`` does, and
``shell.apply_calls == []`` is the proof that nothing was applied — the manager
reaches the helper through exactly one code path.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from adapters.warp_feed_fetcher import FeedFetchError
from repositories.warp_split_sources import RUNS_KEPT
from services.warp_split_feeds import (
    DECISION_APPLIED,
    DECISION_FAILED,
    DECISION_NOCHANGE,
    DECISION_QUEUED,
    DECISION_REJECTED,
    MODE_AUTO,
    MODE_REVIEW,
    WarpFeedStaleCandidate,
)
from tests.test_warp_split_feeds import FIXTURES, _make
from warp.split_analysis import (
    HOLD_EMPTY_SOURCE,
    HOLD_GROWTH,
    HOLD_REVIEW_MODE,
    HOLD_SHRINK_ADD,
    HOLD_SHRINK_SUBTRACT,
    Coverage,
    list_hash,
)
from warp.split_merge import LIST_SCOPE


# 32 /24s in separate /16s, so nothing collapses and the arithmetic in each test is
# the arithmetic being tested: 32 × 256 = 8192 addresses of feed coverage plus 256 from
# the adopted manual prefix. Documentation space (203.0.113.0/24 is TEST-NET-3), which
# no guard network — AWG subnet, WARP range, the host's own WAN — can overlap.
_BASE_FEED = "".join(f"203.{octet}.0.0/24\n" for octet in range(32))


async def _prime(tmp_path: Path, *, mode: str = MODE_REVIEW, payload: str = _BASE_FEED):
    """Build a service that has already applied one state, with a baseline.

    Every ratchet test needs a "last applied state" to measure against, and the
    only honest way to get one is to apply something. Priming goes through
    ``refresh(apply=True)`` — the path the panel's own buttons take — so the
    fixture never depends on the mode or the thresholds under test.
    """
    db, shell, manager, fetcher, repo, service = await _make(tmp_path)
    try:
        manager.list_path.write_text("203.0.113.0/24\n", encoding="utf-8")
        await service.ensure_manual_adopted()
        fetcher.payloads["telegram-cidr"] = payload
        result = await service.refresh(apply=True)
        assert result.applied, "fixture must start from an applied state"
        service._mode = mode
        shell.calls.clear()
    except BaseException:
        # Leaving the connection open would leave aiosqlite's non-daemon thread
        # running, and the whole session would hang instead of failing.
        await db.close()
        raise
    return db, shell, manager, fetcher, repo, service


def _split_one_prefix(manager) -> None:
    """Rewrite the applied list with one /24 expressed as two /25s.

    Byte-for-byte the same routed address space, one line longer — which is
    exactly the shape of the 108 → 106 case on the real host, only small enough
    to read. The merge collapses it straight back, so the candidate differs from
    the file textually and not at all in coverage.
    """
    entries = manager.read_list()
    rewritten: list[str] = []
    for entry in entries:
        if entry == "203.0.0.0/24":
            rewritten.extend(["203.0.0.0/25", "203.0.0.128/25"])
        else:
            rewritten.append(entry)
    manager.list_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


def _sent(service):
    """Capture everything the service would send to the admins."""
    messages: list[str] = []

    async def _notify(text: str) -> None:
        messages.append(text)

    service._notify = _notify
    service._notify_card = _notify
    return messages


# ---------------------------------------------------------------------------
# review: nothing is applied, ever
# ---------------------------------------------------------------------------


class TestReviewMode:
    async def test_a_change_that_passes_every_threshold_is_still_queued(
        self, tmp_path: Path
    ):
        """The defining property of review mode.

        A small, plausible, threshold-clearing change — the kind auto mode exists
        to apply — must still not be applied here. If this test ever passes for
        the wrong reason (say, because the change did trip a threshold), the mode
        would be indistinguishable from auto on safe changes, so the analysis is
        asserted to be clean as well.
        """
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            before = manager.list_path.read_text(encoding="utf-8")
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"

            result = await service.run_cycle()

            assert result.decision == DECISION_QUEUED
            assert result.analysis is not None
            # The only hold is the mode itself: nothing about the change is odd.
            assert [hold.code for hold in result.analysis.holds] == [HOLD_REVIEW_MODE]
            assert shell.apply_calls == []
            assert manager.list_path.read_text(encoding="utf-8") == before
            pending = await repo.pending()
            assert pending is not None and pending.reason == HOLD_REVIEW_MODE
        finally:
            await db.close()

    async def test_pure_aggregation_is_queued_too(self, tmp_path: Path):
        """The 108 → 106 case in review: safe, and still nobody's decision but the
        admin's."""
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            applied = len(manager.read_list())
            _split_one_prefix(manager)

            result = await service.run_cycle()

            assert result.decision == DECISION_QUEUED
            assert result.analysis is not None and result.analysis.pure_aggregation
            assert result.analysis.addresses_before == result.analysis.addresses_after
            assert result.analysis.prefixes_before == applied + 1
            assert result.analysis.prefixes_after == applied
            assert shell.apply_calls == []
        finally:
            await db.close()

    async def test_approving_the_card_applies_and_moves_the_baseline(self, tmp_path: Path):
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()
            baseline_before = await repo.baselines()

            outcome = await service.apply_pending(actor_user_id=7)

            assert outcome.changed
            assert "203.200.0.0/24" in manager.list_path.read_text(encoding="utf-8")
            assert await repo.pending() is None
            baseline_after = await repo.baselines()
            assert (
                baseline_after[LIST_SCOPE].addresses
                > baseline_before[LIST_SCOPE].addresses
            )
            assert await repo.baseline_list_hash() == list_hash(manager.read_list())
        finally:
            await db.close()

    async def test_the_applied_notice_reports_the_change_not_its_aftermath(
        self, tmp_path: Path
    ):
        """Measured before the baseline moves.

        The apply and the baseline update happen in the same call; if the summary
        were computed after it, every per-source line would read "33 → 33" and the
        message would describe the change by erasing it.
        """
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()
            sent = _sent(service)

            await service.apply_pending(actor_user_id=7)

            assert len(sent) == 1
            # 8192 → 8448 addresses for the source, spelled with grouped digits.
            assert "8 192" in sent[0] and "8 448" in sent[0]
        finally:
            await db.close()

    async def test_declining_the_card_leaves_the_baseline_alone(self, tmp_path: Path):
        """Rejection must not become acceptance by another name.

        If a decline moved the baseline, the change refused today would be the
        reference point tomorrow, and the same shrink would sail through on the
        next run. That failure would be invisible — the list would simply drift.
        """
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()
            baseline_before = await repo.baselines()

            await service.reject_pending(actor_user_id=7)

            assert await repo.pending() is None
            assert await repo.baselines() == baseline_before
            assert shell.apply_calls == []
            runs = await repo.recent_runs(1)
            assert runs[0].decision == DECISION_REJECTED and runs[0].reason == "declined"
        finally:
            await db.close()

    async def test_a_stale_card_is_refused_rather_than_applied(self, tmp_path: Path):
        """Between the card and the button, the world moved.

        The admin approved a specific list. Applying "whatever the merge says now"
        under that approval is the one thing the card must never do — so the hash
        is checked, and the answer is a refusal with an instruction, not a write.
        """
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()
            before = manager.list_path.read_text(encoding="utf-8")

            # Someone adds a prefix in another chat: the merge now yields a
            # different list than the one on the card.
            await repo.add_manual_prefixes(["198.51.100.0/24"])

            with pytest.raises(WarpFeedStaleCandidate):
                await service.apply_pending(actor_user_id=7)

            assert shell.apply_calls == []
            assert manager.list_path.read_text(encoding="utf-8") == before
            assert await repo.pending() is not None  # still waiting for a decision
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# auto: applies the safe and confirmed, queues everything else
# ---------------------------------------------------------------------------


class TestAutoMode:
    async def test_a_safe_change_applies_after_the_streak(self, tmp_path: Path):
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path, mode=MODE_AUTO)
        try:
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"

            first = await service.run_cycle()
            assert first.decision == DECISION_NOCHANGE
            assert first.reason.startswith("streak")
            assert shell.apply_calls == []

            second = await service.run_cycle()
            assert second.decision == DECISION_APPLIED
            assert "203.200.0.0/24" in manager.list_path.read_text(encoding="utf-8")
        finally:
            await db.close()

    async def test_two_different_candidates_in_a_row_apply_nothing(self, tmp_path: Path):
        """A feed flapping between two states must not land either of them.

        This is the single-bad-publication case: the streak counts *identical*
        candidates, so an unstable source resets it every run and never reaches
        the threshold.
        """
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path, mode=MODE_AUTO)
        try:
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.201.0.0/24\n"
            second = await service.run_cycle()

            assert second.decision == DECISION_NOCHANGE
            assert second.streak == 1  # reset, not advanced
            assert shell.apply_calls == []
        finally:
            await db.close()

    async def test_pure_aggregation_skips_the_streak(self, tmp_path: Path):
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path, mode=MODE_AUTO)
        try:
            _split_one_prefix(manager)

            result = await service.run_cycle()

            assert result.decision == DECISION_APPLIED
            assert result.analysis is not None and result.analysis.pure_aggregation
        finally:
            await db.close()

    async def test_an_add_source_shrinking_past_the_threshold_is_queued(
        self, tmp_path: Path
    ):
        """21% is over the 20% line, and 20% would not be."""
        db, shell, manager, fetcher, repo, service = await _prime(
            tmp_path,
            mode=MODE_AUTO,
            # 100 × /24 = 25 600 addresses of baseline coverage.
            payload="".join(f"203.{octet}.0.0/24\n" for octet in range(100)),
        )
        try:
            fetcher.payloads["telegram-cidr"] = "".join(
                f"203.{octet}.0.0/24\n" for octet in range(79)
            )

            result = await service.run_cycle()

            assert result.decision == DECISION_QUEUED
            assert result.analysis is not None
            assert [hold.code for hold in result.analysis.holds] == [HOLD_SHRINK_ADD]
            assert result.analysis.holds[0].pct == pytest.approx(21.0)
            assert shell.apply_calls == []
        finally:
            await db.close()

    async def test_a_shrinking_subtract_source_is_queued_with_its_own_reason(
        self, tmp_path: Path
    ):
        """cloud.json shrank: less is carved out of goog.json, so MORE foreign
        address space would enter the tunnel. The routed list grows while the
        source that shrank is the one to blame — which is why the reason is
        reported against the subtrahend and not as generic growth."""
        db, shell, manager, fetcher, repo, service = await _make(tmp_path)
        try:
            manager.list_path.write_text("203.0.113.0/24\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            await repo.set_enabled("telegram-cidr", False)
            await repo.set_enabled("google-goog", True)
            await repo.set_enabled("google-cloud", True)
            fetcher.payloads["google-goog"] = (FIXTURES / "goog_sample.json").read_text()
            fetcher.payloads["google-cloud"] = (FIXTURES / "cloud_sample.json").read_text()
            primed = await service.refresh(apply=True)
            assert primed.applied
            service._mode = MODE_AUTO
            shell.calls.clear()

            # The subtrahend loses almost everything it used to carve out.
            fetcher.payloads["google-cloud"] = (
                '{"prefixes": [{"ipv4Prefix": "34.1.0.0/24"}]}'
            )
            result = await service.run_cycle()

            assert result.decision == DECISION_QUEUED
            assert result.analysis is not None
            codes = [hold.code for hold in result.analysis.holds]
            assert HOLD_SHRINK_SUBTRACT in codes
            assert any(hold.slug == "google-cloud" for hold in result.analysis.holds)
            assert shell.apply_calls == []
        finally:
            await db.close()

    async def test_growth_past_the_threshold_is_queued(self, tmp_path: Path):
        db, shell, manager, fetcher, repo, service = await _prime(
            tmp_path, mode=MODE_AUTO, payload="203.10.0.0/24\n"
        )
        try:
            # /24 → /16 is a 256-fold increase in the source, and the merged list
            # grows far past 50%.
            fetcher.payloads["telegram-cidr"] = "203.10.0.0/16\n"

            result = await service.run_cycle()

            assert result.decision == DECISION_QUEUED
            assert result.analysis is not None
            assert HOLD_GROWTH in [hold.code for hold in result.analysis.holds]
            assert shell.apply_calls == []
        finally:
            await db.close()

    async def test_an_empty_feed_is_queued_and_the_baseline_stays(self, tmp_path: Path):
        """A feed that publishes nothing usable.

        The merge still succeeds — it falls back to the cached contribution — so
        without this check the run would look completely ordinary. The candidate
        is held, and the baseline must not move, because nothing was applied.
        """
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path, mode=MODE_AUTO)
        try:
            baseline_before = await repo.baselines()
            await repo.add_manual_prefixes(["198.51.100.0/24"])  # gives the run a delta
            fetcher.payloads["telegram-cidr"] = "# nothing here any more\n"

            result = await service.run_cycle()

            assert result.decision == DECISION_QUEUED
            assert result.analysis is not None
            assert HOLD_EMPTY_SOURCE in [hold.code for hold in result.analysis.holds]
            assert shell.apply_calls == []
            assert await repo.baselines() == baseline_before
        finally:
            await db.close()

    async def test_a_stale_source_holds_the_change(self, tmp_path: Path):
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path, mode=MODE_AUTO)
        try:
            await repo.add_manual_prefixes(["198.51.100.0/24"])
            fetcher.errors["telegram-cidr"] = RuntimeError  # not used; see below
            del fetcher.errors["telegram-cidr"]
            # Pretend the clock moved four days on: the last success is now older
            # than WARP_SPLIT_FEED_STALE_AFTER_SEC even though the fetch succeeds.
            now = service._clock()
            service._clock = lambda: now + 4 * 86_400

            result = await service.run_cycle()

            assert result.decision == DECISION_QUEUED
            assert result.analysis is not None
            assert any(change.stale for change in result.analysis.sources)
            assert shell.apply_calls == []
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# fatal guards, which are refused rather than queued
# ---------------------------------------------------------------------------


class TestFatalGuards:
    async def test_a_cap_overflow_is_rejected_and_never_queued(self, tmp_path: Path):
        """A guard rejection is not a decision anyone can make differently.

        Offering an admin a button that applies a list the manager will refuse
        anyway would teach them that the buttons lie. So: a message, no card.
        """
        db, shell, manager, fetcher, repo, service = await _make(tmp_path, max_prefixes=3)
        try:
            service._mode = MODE_AUTO
            service._confirm_streak = 1
            sent = _sent(service)
            manager.list_path.write_text("203.0.113.0/24\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            fetcher.payloads["telegram-cidr"] = "".join(
                f"203.{octet}.0.0/24\n" for octet in range(10)
            )

            result = await service.run_cycle()

            assert result.decision == DECISION_REJECTED
            assert await repo.pending() is None
            assert shell.apply_calls == []
            assert any("WARP_SPLIT_MAX_PREFIXES" in text for text in sent)
        finally:
            await db.close()

    async def test_a_feed_covering_the_warp_endpoint_is_rejected_not_queued(
        self, tmp_path: Path
    ):
        """The guard whose breach takes the tunnel down for everyone.

        ``vpn-bot-warp-split`` pins ``<endpoint>/32 via <gw>`` into table T and
        then installs the list with ``ip route replace``, so a prefix covering the
        endpoint sends the tunnel's own packets into the tunnel. The fake status
        helper reports 162.159.195.1, and a feed that publishes that range must be
        refused outright — approving it could not make it safe.
        """
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path, mode=MODE_AUTO)
        try:
            sent = _sent(service)
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "162.159.195.0/24\n"

            result = await service.run_cycle()

            assert result.decision == DECISION_REJECTED
            assert await repo.pending() is None
            assert shell.apply_calls == []
            assert any("162.159.195.1" in text for text in sent)
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# the run journal
# ---------------------------------------------------------------------------


class TestRunJournal:
    async def test_every_outcome_is_recorded(self, tmp_path: Path):
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path, mode=MODE_AUTO)
        try:
            # nochange
            await service.run_cycle()
            # queued (growth), then rejected (declined), then applied
            fetcher.payloads["telegram-cidr"] = "203.0.0.0/8\n"
            await service.run_cycle()
            await service.reject_pending(actor_user_id=1)
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()
            await service.run_cycle()

            decisions = [run.decision for run in await repo.recent_runs(10)]
            assert DECISION_NOCHANGE in decisions
            assert DECISION_QUEUED in decisions
            assert DECISION_REJECTED in decisions
            assert DECISION_APPLIED in decisions
        finally:
            await db.close()

    async def test_a_failed_merge_is_recorded_as_failed(self, tmp_path: Path):
        """"Base fresh, subtrahend never fetched" — the case that would put every
        GCP range in the tunnel. The merge refuses, and the refusal is journalled
        rather than only logged, so the history shows *why* a day has no runs."""
        db, shell, manager, fetcher, repo, service = await _make(tmp_path)
        try:
            manager.list_path.write_text("203.0.113.0/24\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            await repo.set_enabled("telegram-cidr", False)
            await repo.set_enabled("google-goog", True)
            await repo.set_enabled("google-cloud", True)
            fetcher.payloads["google-goog"] = (FIXTURES / "goog_sample.json").read_text()
            fetcher.errors["google-cloud"] = FeedFetchError("transport error")

            result = await service.run_cycle()

            assert result.decision == DECISION_FAILED
            assert shell.apply_calls == []
            runs = await repo.recent_runs(1)
            assert runs[0].decision == DECISION_FAILED
            assert "google-cloud" in str(runs[0].metrics.get("detail", ""))
        finally:
            await db.close()

    async def test_the_journal_is_trimmed_to_the_limit(self, tmp_path: Path):
        """Trimming happens in the same run that writes, so a host whose operator
        never opens the panel cannot grow this table without bound."""
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            for index in range(RUNS_KEPT + 5):
                await repo.record_run(
                    mode=MODE_REVIEW, decision=DECISION_NOCHANGE, now=1_000 + index
                )
            assert await repo.count_runs() == RUNS_KEPT
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# the card itself
# ---------------------------------------------------------------------------


class TestCard:
    async def test_one_card_per_candidate_not_one_per_run(self, tmp_path: Path):
        """Re-queuing the same candidate says nothing new; replacing it says one
        thing, not two."""
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            sent = _sent(service)
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()
            await service.run_cycle()
            assert len(sent) == 1

            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.201.0.0/24\n"
            await service.run_cycle()
            assert len(sent) == 2
        finally:
            await db.close()

    async def test_the_card_reports_per_source_before_and_after(self, tmp_path: Path):
        db, shell, manager, fetcher, repo, service = await _prime(tmp_path)
        try:
            sent = _sent(service)
            fetcher.payloads["telegram-cidr"] = _BASE_FEED + "203.200.0.0/24\n"
            await service.run_cycle()

            card = sent[0]
            assert "telegram-cidr" in card
            assert "203.200.0.0/24" in card  # the added prefix is spelled out
            pending = await repo.pending()
            assert pending is not None
            sources = {row["slug"]: row for row in pending.deltas["sources"]}
            # 32 × /24 applied, 33 × /24 proposed — reported per source, in
            # addresses, against the baseline rather than against the file.
            assert sources["telegram-cidr"]["addresses_before"] == 32 * 256
            assert sources["telegram-cidr"]["addresses_after"] == 33 * 256
        finally:
            await db.close()
