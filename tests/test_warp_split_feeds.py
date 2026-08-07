"""Safety properties of the WARP split-list feed subsystem.

Every test here is about one question: **can a feed make the routed list worse?**
The subsystem's whole job is that the answer stays no — a dead network, an HTTP
500, an empty body, a missing operand or a cap overflow must all leave
`/etc/vpn-bot/warp-split.list` exactly as it was, with no helper invocation at
all.

Offline by construction: the fetcher is a stub, the privileged helper is a
recording fake shell, and the list file lives under ``tmp_path``. Nothing here
touches /etc, `ip`, `systemctl` or the network.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from adapters.warp_feed_fetcher import FeedFetchError, FeedPayload
from db.database import Database
from models.dto import ShellResult
from repositories.warp_split_sources import WarpSplitSourceRepository
from services.warp_split_feeds import WarpFeedError, WarpSplitFeedService
from warp.split_manager import WarpSplitManager

FIXTURES = Path(__file__).parent / "fixtures" / "warp_feeds"
AWG_NETWORK = "10.0.0.0/24"


class RecordingShell:
    """Fake ShellRunner standing in for the privileged helpers.

    It *writes the list file* on a successful apply, exactly as
    ``vpn-bot-warp-split-apply`` does, because most assertions here are about
    what ends up routed — a fake that only recorded the call would let a merge
    bug pass unnoticed while the file kept its old contents.

    ``apply_calls`` is the assertion surface for the opposite claim, "nothing was
    applied": the manager reaches the helper through exactly one code path, so an
    empty list proves no write and no service restart happened.
    """

    def __init__(self, list_path: Path, *, fail_first_apply: bool = False) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.list_path = list_path
        self.fail_first_apply = fail_first_apply
        self._applies = 0

    async def run(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
        sensitive_values: tuple[str, ...] = (),
        timeout: float = 60.0,
        max_output_chars: int = 2048,
    ) -> ShellResult:
        self.calls.append((list(command), input_text))
        joined = " ".join(command)
        if "warp-status" in joined:
            return ShellResult(args=(), returncode=0, stdout=_STATUS_OUTPUT, stderr="")
        if "split-apply" in joined:
            self._applies += 1
            if self.fail_first_apply and self._applies == 1:
                # Helper rejected the input before the atomic rename: nothing written.
                return ShellResult(args=(), returncode=1, stdout="", stderr="validation failed")
            self.list_path.write_text(input_text or "", encoding="utf-8")
            return ShellResult(args=(), returncode=0, stdout="", stderr="")
        return ShellResult(args=(), returncode=0, stdout="", stderr="")

    @property
    def apply_calls(self) -> list[str]:
        return [text or "" for cmd, text in self.calls if "split-apply" in " ".join(cmd)]


_STATUS_OUTPUT = """\
interface: out-warp
  fwmark: 0xca6c

peer: abc=
  endpoint: 162.159.195.1:2408
  latest handshake: 8 seconds ago
"""


class StubFetcher:
    """Feed fetcher with scripted per-slug outcomes and an in-memory cache."""

    def __init__(self) -> None:
        self.payloads: dict[str, str] = {}
        self.errors: dict[str, Exception] = {}
        self.cache: dict[str, str] = {}
        self.requests: list[str] = []

    def read_cache(self, slug: str) -> str | None:
        return self.cache.get(slug)

    async def fetch(
        self, *, slug: str, url: str, etag: str | None = None, last_modified: str | None = None
    ) -> FeedPayload:
        self.requests.append(slug)
        if slug in self.errors:
            raise self.errors[slug]
        text = self.payloads[slug]
        self.cache[slug] = text
        return FeedPayload(text=text, etag='"v1"', last_modified=None, status="ok")


async def _make(tmp_path: Path, *, fail_first_apply: bool = False, max_prefixes: int = 1500):
    """Build a service over a real DB, a real manager and a temp list file."""
    db = Database(tmp_path / "test.db")
    await db.connect()
    await db.bootstrap()
    shell = RecordingShell(tmp_path / "warp-split.list", fail_first_apply=fail_first_apply)
    manager = WarpSplitManager(
        list_path=tmp_path / "warp-split.list",
        apply_helper_path=Path("/usr/local/sbin/vpn-bot-warp-split-apply"),
        awg_network=AWG_NETWORK,
        shell=shell,  # type: ignore[arg-type]
        status_helper_path=Path("/usr/local/sbin/vpn-bot-warp-status"),
        marker_path=tmp_path / "marker",
        interface_name="out-warp-nonexistent-xyz",
        max_prefixes=max_prefixes,
    )
    fetcher = StubFetcher()
    repo = WarpSplitSourceRepository(db)
    service = WarpSplitFeedService(
        db=db, repo=repo, fetcher=fetcher, manager=manager  # type: ignore[arg-type]
    )
    return db, shell, manager, fetcher, repo, service


# ---------------------------------------------------------------------------
# Seeds and adoption
# ---------------------------------------------------------------------------


class TestSeedAndAdoption:
    async def test_migration_seeds_three_sources(self, tmp_path: Path):
        db, _shell, _mgr, _fetch, repo, _svc = await _make(tmp_path)
        try:
            slugs = {s.slug: s for s in await repo.list_sources()}
            assert set(slugs) == {"telegram-cidr", "google-goog", "google-cloud"}
            assert slugs["telegram-cidr"].enabled is True
            assert slugs["google-goog"].enabled is False
            assert slugs["google-cloud"].enabled is False
            assert slugs["google-cloud"].mode == "subtract"
            assert slugs["google-cloud"].scope_slug == "google-goog"
        finally:
            await db.close()

    async def test_existing_list_file_is_adopted_as_manual_once(self, tmp_path: Path):
        """The pre-feed list must become the manual set, or the first merge would
        drop every prefix the operator had typed before this feature existed."""
        db, _shell, manager, _fetch, repo, service = await _make(tmp_path)
        try:
            manager.list_path.write_text("1.2.3.0/24\n5.6.7.0/24\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            assert set(await repo.manual_prefixes()) == {"1.2.3.0/24", "5.6.7.0/24"}

            # Deleting every manual prefix must stick, not be undone on restart.
            await repo.set_manual_prefixes([])
            await service.ensure_manual_adopted()
            assert await repo.manual_prefixes() == []
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Backward compatibility (the deploy-day guarantee)
# ---------------------------------------------------------------------------


class TestNoFeedEnabled:
    async def test_no_enabled_feed_leaves_the_file_byte_identical_and_calls_nothing(
        self, tmp_path: Path
    ):
        """The checkable form of "deploying this changes nothing".

        With the scheduler off and no feed enabled, a refresh must reproduce the
        existing file exactly and skip the helper entirely — not rewrite it with
        equivalent content, and not restart the split service.
        """
        db, shell, manager, _fetch, repo, service = await _make(tmp_path)
        try:
            original = "1.2.3.0/24\n5.6.7.0/24\n8.8.8.0/24\n"
            manager.list_path.write_text(original, encoding="utf-8")
            for slug in ("telegram-cidr", "google-goog", "google-cloud"):
                await repo.set_enabled(slug, False)

            result = await service.refresh(apply=True)

            assert manager.list_path.read_text(encoding="utf-8") == original
            assert shell.apply_calls == []
            assert result.outcome is not None and result.outcome.unchanged is True
        finally:
            await db.close()

    async def test_reapply_still_forces_the_helper_on_an_unchanged_file(self, tmp_path: Path):
        """The byte-identity short-circuit must not disable the one button whose
        purpose is to re-run the helper and reconcile table T."""
        db, shell, manager, _f, _r, _s = await _make(tmp_path)
        try:
            manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
            await manager.reapply()
            assert shell.apply_calls == ["1.2.3.0/24\n"]
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Failure must never shorten the list
# ---------------------------------------------------------------------------


class TestFetchFailures:
    @pytest.mark.parametrize(
        "error",
        [
            FeedFetchError("transport error: cannot connect"),
            FeedFetchError("HTTP 500"),
            FeedFetchError("empty response body"),
        ],
    )
    async def test_failure_leaves_the_list_untouched_and_applies_nothing(
        self, tmp_path: Path, error: Exception
    ):
        db, shell, manager, fetcher, repo, service = await _make(tmp_path)
        try:
            original = "1.2.3.0/24\n"
            manager.list_path.write_text(original, encoding="utf-8")
            await service.ensure_manual_adopted()
            fetcher.errors["telegram-cidr"] = error

            result = await service.refresh(apply=True)

            assert manager.list_path.read_text(encoding="utf-8") == original
            assert shell.apply_calls == []
            source = await repo.get_source("telegram-cidr")
            assert source is not None and source.last_error is not None
            assert source.last_success_ts == 0
            assert any("telegram-cidr" in alert for alert in result.alerts)
        finally:
            await db.close()

    async def test_a_failed_feed_falls_back_to_its_last_good_contribution(self, tmp_path: Path):
        """A feed that succeeded once keeps contributing when the next fetch dies."""
        db, _shell, manager, fetcher, _repo, service = await _make(tmp_path)
        try:
            manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
            fetcher.payloads["telegram-cidr"] = "91.108.4.0/22\n"
            await service.refresh(apply=True)
            good = manager.list_path.read_text(encoding="utf-8")
            assert "91.108.4.0/22" in good

            fetcher.errors["telegram-cidr"] = FeedFetchError("HTTP 503")
            await service.refresh(apply=True)
            assert manager.list_path.read_text(encoding="utf-8") == good
        finally:
            await db.close()

    async def test_operand_that_never_succeeded_aborts_the_whole_merge(self, tmp_path: Path):
        """The "base fresh, subtrahend empty" case.

        google-goog downloads fine, google-cloud has never worked. Applying the
        base without its subtraction would route every GCP customer range through
        the tunnel — so nothing is applied at all.
        """
        db, shell, manager, fetcher, repo, service = await _make(tmp_path)
        try:
            original = "1.2.3.0/24\n"
            manager.list_path.write_text(original, encoding="utf-8")
            await service.ensure_manual_adopted()
            await repo.set_enabled("telegram-cidr", False)
            await repo.set_enabled("google-goog", True)
            await repo.set_enabled("google-cloud", True)
            fetcher.payloads["google-goog"] = (FIXTURES / "goog_sample.json").read_text()
            fetcher.errors["google-cloud"] = FeedFetchError("transport error")

            result = await service.refresh(apply=True)

            assert manager.list_path.read_text(encoding="utf-8") == original
            assert shell.apply_calls == []
            assert result.blocked_reason is not None
            assert "google-cloud" in result.blocked_reason
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Cap
# ---------------------------------------------------------------------------


class TestCap:
    async def test_exceeding_the_cap_refuses_everything_and_names_the_subtraction(
        self, tmp_path: Path
    ):
        """No partial apply, and the message must be actionable.

        The cap is reachable precisely because subtraction fragments: the
        operator did not add these prefixes, a subtrahend shattered the ones they
        had, so "too many prefixes" alone would be unactionable.
        """
        db, shell, manager, fetcher, repo, service = await _make(tmp_path, max_prefixes=10)
        try:
            original = "1.2.3.0/24\n"
            manager.list_path.write_text(original, encoding="utf-8")
            await service.ensure_manual_adopted()
            await repo.set_enabled("telegram-cidr", False)
            await repo.set_enabled("google-goog", True)
            await repo.set_enabled("google-cloud", True)
            fetcher.payloads["google-goog"] = (FIXTURES / "goog_sample.json").read_text()
            fetcher.payloads["google-cloud"] = (FIXTURES / "cloud_sample.json").read_text()

            result = await service.refresh(apply=True)

            assert manager.list_path.read_text(encoding="utf-8") == original
            assert shell.apply_calls == []
            assert result.blocked_reason is not None
            assert "google-goog-google-cloud" in result.blocked_reason
            assert "WARP_SPLIT_MAX_PREFIXES" in result.blocked_reason
            assert "turn the subtraction off" in result.blocked_reason
        finally:
            await db.close()

    async def test_preview_reports_the_same_refusal(self, tmp_path: Path):
        db, _shell, manager, fetcher, _repo, service = await _make(tmp_path, max_prefixes=2)
        try:
            manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            fetcher.payloads["telegram-cidr"] = (FIXTURES / "telegram_cidr.txt").read_text()
            await service.refresh(apply=False)
            with pytest.raises(WarpFeedError, match="limit 2"):
                await service.preview()
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------


class TestExclusions:
    async def test_exclusion_survives_a_feed_refresh(self, tmp_path: Path):
        """A plain delete would be undone by the next refresh; an exclusion is not."""
        db, _shell, manager, fetcher, _repo, service = await _make(tmp_path)
        try:
            manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
            fetcher.payloads["telegram-cidr"] = "91.108.4.0/22\n91.105.192.0/23\n"
            await service.refresh(apply=True)
            assert "91.108.4.0/22" in manager.read_list()

            await service.exclude_prefix("91.108.4.0/22")
            assert "91.108.4.0/22" not in manager.read_list()

            await service.refresh(apply=True)
            assert "91.108.4.0/22" not in manager.read_list()
            assert "91.105.192.0/23" in manager.read_list()
        finally:
            await db.close()

    async def test_unexclude_brings_the_prefix_back(self, tmp_path: Path):
        db, _shell, manager, fetcher, _repo, service = await _make(tmp_path)
        try:
            manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
            fetcher.payloads["telegram-cidr"] = "91.108.4.0/22\n"
            await service.refresh(apply=True)
            await service.exclude_prefix("91.108.4.0/22")
            await service.unexclude_prefix("91.108.4.0/22")
            assert "91.108.4.0/22" in manager.read_list()
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


class TestRollback:
    async def test_helper_failure_restores_the_previous_list(self, tmp_path: Path):
        """A non-zero rc does not say whether the helper wrote before failing, so
        the previous content is re-applied either way — a no-op rewrite in one
        case, a genuine undo in the other."""
        alerts: list[str] = []

        async def _capture(text: str) -> None:
            alerts.append(text)

        db, shell, manager, _f, _r, _s = await _make(tmp_path, fail_first_apply=True)
        try:
            manager._on_alert = _capture  # type: ignore[assignment]
            manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")

            from warp.split_manager import WarpSplitError

            with pytest.raises(WarpSplitError):
                await manager.apply_list(["1.2.3.0/24", "9.9.9.0/24"])

            # Two helper calls: the failed write, then the restore of the old list.
            assert shell.apply_calls == ["1.2.3.0/24\n9.9.9.0/24\n", "1.2.3.0/24\n"]
            assert manager.list_path.read_text(encoding="utf-8") == "1.2.3.0/24\n"
            assert alerts and "restored" in alerts[-1].lower()
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Source management
# ---------------------------------------------------------------------------


class TestSourceManagement:
    async def test_self_referencing_source_is_rejected_on_add(self, tmp_path: Path):
        db, _shell, _mgr, _f, _r, service = await _make(tmp_path)
        try:
            with pytest.raises(WarpFeedError, match="cannot subtract from itself"):
                await service.add_source(
                    slug="loop",
                    title="Loop",
                    url="https://example.test/x.txt",
                    kind="cidr_text",
                    mode="subtract",
                    scope_slug="loop",
                )
        finally:
            await db.close()

    async def test_chained_subtraction_is_rejected_on_add(self, tmp_path: Path):
        db, _shell, _mgr, _f, _r, service = await _make(tmp_path)
        try:
            with pytest.raises(WarpFeedError, match="chained subtraction"):
                await service.add_source(
                    slug="second",
                    title="Second",
                    url="https://example.test/x.txt",
                    kind="cidr_text",
                    mode="subtract",
                    scope_slug="google-cloud",  # itself a subtract source
                )
        finally:
            await db.close()

    async def test_unsafe_slug_is_rejected(self, tmp_path: Path):
        db, _shell, _mgr, _f, _r, service = await _make(tmp_path)
        try:
            with pytest.raises(WarpFeedError):
                await service.add_source(
                    slug="../../etc/passwd",
                    title="Evil",
                    url="https://example.test/x.txt",
                    kind="cidr_text",
                )
        finally:
            await db.close()

    async def test_duplicate_slug_is_rejected(self, tmp_path: Path):
        db, _shell, _mgr, _f, _r, service = await _make(tmp_path)
        try:
            with pytest.raises(WarpFeedError, match="already exists"):
                await service.add_source(
                    slug="telegram-cidr",
                    title="Dup",
                    url="https://example.test/x.txt",
                    kind="cidr_text",
                )
        finally:
            await db.close()

    async def test_deleting_a_scope_target_disables_its_operand(self, tmp_path: Path):
        """Never silently promote a scoped subtraction to a global one — that
        widens it from "carve GCP out of goog" to "carve GCP out of everything"."""
        db, _shell, _mgr, _f, repo, service = await _make(tmp_path)
        try:
            await repo.set_enabled("google-cloud", True)
            await service.delete_source("google-goog")
            cloud = await repo.get_source("google-cloud")
            assert cloud is not None
            assert cloud.enabled is False
            assert cloud.scope_slug is None
            assert cloud.last_error is not None and "google-goog" in cloud.last_error
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Manual -> feed migration
# ---------------------------------------------------------------------------


class TestMigrateManual:
    async def test_migration_drops_only_the_covered_manual_prefixes(self, tmp_path: Path):
        db, _shell, manager, fetcher, repo, service = await _make(tmp_path)
        try:
            manager.list_path.write_text("91.108.4.0/22\n203.0.113.0/24\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            fetcher.payloads["telegram-cidr"] = "91.108.4.0/22\n"
            await service.refresh(apply=True)

            moved, _outcome = await service.migrate_manual_into_feeds()

            assert moved == 1
            assert set(await repo.manual_prefixes()) == {"203.0.113.0/24"}
            # The prefix stays routed — it now comes from the feed instead.
            assert "91.108.4.0/22" in manager.read_list()
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Alert threshold
# ---------------------------------------------------------------------------


class TestAlerts:
    async def test_large_automatic_delta_alerts(self, tmp_path: Path):
        db, _shell, manager, fetcher, _repo, service = await _make(tmp_path)
        try:
            sent: list[str] = []

            async def _notify(text: str) -> None:
                sent.append(text)

            service._notify = _notify  # type: ignore[assignment]
            manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            fetcher.payloads["telegram-cidr"] = (FIXTURES / "telegram_cidr.txt").read_text()

            await service.refresh(apply=True)

            assert any("changed by" in text for text in sent)
        finally:
            await db.close()

    async def test_small_delta_does_not_alert(self, tmp_path: Path):
        db, _shell, manager, fetcher, _repo, service = await _make(tmp_path)
        try:
            sent: list[str] = []

            async def _notify(text: str) -> None:
                sent.append(text)

            service._notify = _notify  # type: ignore[assignment]
            # Even octets only: consecutive /24s would collapse into /21s and the
            # resulting delta would be huge for reasons that have nothing to do
            # with the feed.
            manual = [f"203.0.{octet * 2}.0/24" for octet in range(40)]
            manager.list_path.write_text("\n".join(manual) + "\n", encoding="utf-8")
            await service.ensure_manual_adopted()
            fetcher.payloads["telegram-cidr"] = "91.108.4.0/22\n"

            await service.refresh(apply=True)

            assert not any("changed by" in text for text in sent)
        finally:
            await db.close()


# ---------------------------------------------------------------------------
# Host-leak guards
# ---------------------------------------------------------------------------


def test_fixtures_are_ipv4_only_after_parsing():
    """The host has no IPv6; every fixture must survive parsing as IPv4-only."""
    from warp.split_merge import parse_cidr_text, parse_google_json

    for name, parser in (
        ("telegram_cidr.txt", parse_cidr_text),
        ("goog_sample.json", parse_google_json),
        ("cloud_sample.json", parse_google_json),
    ):
        parsed = parser((FIXTURES / name).read_text(encoding="utf-8"))
        assert parsed.networks
        assert all(isinstance(net, ipaddress.IPv4Network) for net in parsed.networks)
