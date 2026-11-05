"""traffic_hourly: the time-bucketed traffic history behind the dashboard windows.

The lifetime totals (vpn_key_traffic_stats + deleted_key_traffic_archive) say how
much a key has moved, never when, so "the last 7 days" needs a history of its own.
These tests pin the four properties that history is only useful with:

* the upgrade from a populated v38 database creates it without touching the
  totals, and the poller starts filling it (the path every deploy takes — a
  migration that only works on a fresh DB is the class of bug #269 shipped);
* every byte the poller adds to the totals lands in exactly one bucket, counter
  resets included, so the windows and the totals cannot drift apart;
* deleting a key keeps its buckets, so the windows include deleted keys;
* the window and retention boundaries are where the dashboard says they are.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import aiosqlite
import pytest
from test_schema_upgrade_path import _materialise

import bot.app as app_module
from bot.formatters import dashboard_text, dashboard_traffic_lines
from db.database import CURRENT_SCHEMA_VERSION, Database
from i18n import use_locale
from models.dto import TelegramUserProfile, VpnKey
from models.enums import UserRole, VpnKeyType
from repositories.dashboard import (
    TRAFFIC_WINDOW_DAYS,
    DashboardRepository,
    KeysSummary,
    TopUserTraffic,
    TrafficTotals,
    TrafficWindows,
    window_start_hour,
)
from repositories.traffic_stats import TRAFFIC_HOURLY_RETENTION_DAYS, TrafficStatsRepository, hour_utc_from_iso
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.dashboard import DashboardSnapshot
from services.traffic_stats import TrafficStatsService
from warp.state import WarpState

NOW = "2026-11-05T12:34:56+00:00"
HOUR = hour_utc_from_iso(NOW)


# ── harness ──────────────────────────────────────────────────────────────────


class _Clock:
    def __init__(self, now: str) -> None:
        self.value = now

    def now(self) -> str:
        return self.value


class _Xray:
    """xray statsquery: ``user>>>label>>>traffic>>>downlink|uplink`` → bytes."""

    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self.fail = False

    def set(self, label: str, *, down: int | None, up: int | None) -> None:
        for direction, value in (("downlink", down), ("uplink", up)):
            name = f"user>>>{label}>>>traffic>>>{direction}"
            if value is None:
                self.counters.pop(name, None)
            else:
                self.counters[name] = value

    async def query_all(self) -> dict[str, int]:
        if self.fail:
            raise RuntimeError("xray api down")
        return dict(self.counters)


class _Awg:
    """wg/awg show transfer: public key → (received = upload, sent = download)."""

    def __init__(self) -> None:
        self.transfers: dict[str, tuple[int, int]] = {}

    async def list_transfer(self) -> dict[str, tuple[int, int]]:
        return dict(self.transfers)


class _Hysteria:
    """hysteria2 /traffic: label → (tx = upload, rx = download)."""

    def __init__(self) -> None:
        self.traffic: dict[str, tuple[int, int]] = {}

    async def query_all(self) -> dict[str, tuple[int, int]]:
        return dict(self.traffic)


class _Poller:
    def __init__(self, db: Database, clock: _Clock) -> None:
        self.xray = _Xray()
        self.awg = _Awg()
        self.hysteria = _Hysteria()
        self.service = TrafficStatsService(
            stats=TrafficStatsRepository(db),
            vpn_keys=VpnKeyRepository(db),
            users_repo=UserRepository(db),
            users=SimpleNamespace(clock=clock),  # type: ignore[arg-type]
            awg=self.awg,  # type: ignore[arg-type]
            xray=self.xray,  # type: ignore[arg-type]
            hysteria=self.hysteria,  # type: ignore[arg-type]
        )

    async def run(self) -> None:
        """One pass of all three background pollers, as bot.app's loops do it."""
        await self.service.refresh_all_xray()
        await self.service.refresh_all_awg()
        await self.service.refresh_all_hysteria()


async def _open(path: Path) -> Database:
    db = Database(path)
    await db.connect()
    await db.bootstrap()
    return db


async def _active_key(
    db: Database, *, key_type: VpnKeyType, label: str | None = None, public_key: str | None = None,
    client_ip: str | None = None, uuid: str | None = None, owner: int = 100,
) -> VpnKey:
    repo = VpnKeyRepository(db)
    key = await repo.create_pending(
        owner_user_id=owner, username="user", key_type=key_type, note=None,
        payload={}, public_payload={}, created_by=owner, now=NOW,
        uuid=uuid, email_label=label, public_key=public_key, client_ip=client_ip,
    )
    await repo.mark_active(key.id, NOW)
    active = await repo.get_by_id(key.id)
    assert active is not None
    return active


async def _three_keys(db: Database) -> tuple[VpnKey, VpnKey, VpnKey]:
    await UserRepository(db).upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, NOW)
    xray = await _active_key(
        db, key_type=VpnKeyType.XRAY, label="xray_tcp_Aa111", uuid="00000000-0000-4000-8000-000000000001"
    )
    awg = await _active_key(
        db, key_type=VpnKeyType.AWG, public_key="awgPub0000000000000000000000000000000000001=", client_ip="10.8.0.2"
    )
    hy2 = await _active_key(db, key_type=VpnKeyType.HYSTERIA2, label="hy2_Bb222")
    return xray, awg, hy2


async def _totals(db: Database) -> dict[int, tuple[int, int]]:
    rows = await db.conn.execute_fetchall(
        "SELECT key_id, downloaded_bytes, uploaded_bytes FROM vpn_key_traffic_stats"
    )
    return {int(r["key_id"]): (int(r["downloaded_bytes"]), int(r["uploaded_bytes"])) for r in rows}


async def _bucket_sums(db: Database) -> dict[int, tuple[int, int]]:
    rows = await db.conn.execute_fetchall(
        "SELECT key_id, SUM(downloaded_bytes) AS d, SUM(uploaded_bytes) AS u FROM traffic_hourly GROUP BY key_id"
    )
    return {int(r["key_id"]): (int(r["d"]), int(r["u"])) for r in rows}


async def _buckets(db: Database) -> list[tuple[int, int, str, int, int]]:
    rows = await db.conn.execute_fetchall(
        "SELECT hour_utc, key_id, protocol, downloaded_bytes, uploaded_bytes FROM traffic_hourly "
        "ORDER BY hour_utc, key_id"
    )
    return [
        (int(r["hour_utc"]), int(r["key_id"]), str(r["protocol"]), int(r["downloaded_bytes"]), int(r["uploaded_bytes"]))
        for r in rows
    ]


async def _insert_bucket(db: Database, hour: int, key_id: int, down: int, up: int = 0, protocol: str = "xray") -> None:
    await db.conn.execute(
        "INSERT INTO traffic_hourly (hour_utc, key_id, protocol, downloaded_bytes, uploaded_bytes) VALUES (?, ?, ?, ?, ?)",
        (hour, key_id, protocol, down, up),
    )
    await db.commit()


def _diff(after: dict[int, tuple[int, int]], before: dict[int, tuple[int, int]]) -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    for key_id in set(after) | set(before):
        a = after.get(key_id, (0, 0))
        b = before.get(key_id, (0, 0))
        delta = (a[0] - b[0], a[1] - b[1])
        if delta != (0, 0):
            out[key_id] = delta
    return out


# ── upgrade path ─────────────────────────────────────────────────────────────


def test_upgrade_from_populated_v38_creates_table_keeps_totals_and_poller_fills_it(tmp_path: Path) -> None:
    """v38 database with real totals and archive → bootstrap → v39.

    The table exists and starts empty (no backfill), every lifetime figure is
    byte-for-byte what it was, the next poll writes buckets holding exactly the
    bytes it added to the totals, and a restart keeps them.
    """

    async def run() -> None:
        db_path = tmp_path / "upgraded.db"
        await _materialise(db_path, 38)
        async with aiosqlite.connect(db_path) as conn:
            stats_before = await (await conn.execute("SELECT * FROM vpn_key_traffic_stats ORDER BY key_id")).fetchall()
            archive_before = await (await conn.execute("SELECT * FROM deleted_key_traffic_archive ORDER BY id")).fetchall()
            has_table = await (
                await conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'traffic_hourly'")
            ).fetchone()
        assert len(stats_before) == 3 and len(archive_before) == 2, "the v38 seed must carry traffic"
        assert has_table is None, "traffic_hourly must not exist before the migration"

        clock = _Clock(NOW)
        db = await _open(db_path)
        try:
            version = await db.conn.execute_fetchone("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            assert version is not None and int(version["value"]) == CURRENT_SCHEMA_VERSION == 39
            assert await _buckets(db) == [], "nothing may be backfilled: the totals carry no time"
            fks = await db.conn.execute_fetchall("PRAGMA foreign_key_list(traffic_hourly)")
            assert list(fks) == [], "traffic_hourly must not reference vpn_keys"
            stats_after = await db.conn.execute_fetchall("SELECT * FROM vpn_key_traffic_stats ORDER BY key_id")
            archive_after = await db.conn.execute_fetchall("SELECT * FROM deleted_key_traffic_archive ORDER BY id")
            assert [tuple(r) for r in stats_after] == [tuple(r) for r in stats_before]
            assert [tuple(r) for r in archive_after] == [tuple(r) for r in archive_before]
            lifetime_before = await DashboardRepository(db).traffic_totals()

            # The first poll after the deploy diffs against the raw counters the
            # v38 database stored. Seed: xray 30 raw 4000/900, awg 31 raw
            # 8000/1200, hysteria2 32 raw 2000/300.
            poller = _Poller(db, clock)
            poller.xray.set("xray_tcp_Jj111", down=5000, up=1000)
            poller.awg.transfers["awgPubKeyV38seed000000000000000000000000000="] = (1200 + 300, 8000 + 2000)
            poller.hysteria.traffic["hy2_Kk222"] = (300 + 50, 2000 + 500)
            totals_before = await _totals(db)
            await poller.run()

            assert await _buckets(db) == [
                (HOUR, 30, "xray", 1000, 100),
                (HOUR, 31, "awg", 2000, 300),
                (HOUR, 32, "hysteria2", 500, 50),
            ]
            assert _diff(await _totals(db), totals_before) == await _bucket_sums(db)
            windows = await DashboardRepository(db).traffic_windows(HOUR)
            assert all(windows.bytes_by_days[d] == 1000 + 100 + 2000 + 300 + 500 + 50 for d in TRAFFIC_WINDOW_DAYS)
            assert windows.first_hour_utc == HOUR and windows.history_starts_inside
            lifetime_after = await DashboardRepository(db).traffic_totals()
            assert lifetime_after.total_bytes - lifetime_before.total_bytes == 3950
        finally:
            await db.close()

        # The bot restarts on every deploy: a second bootstrap must keep them.
        db = await _open(db_path)
        try:
            assert len(await _buckets(db)) == 3
        finally:
            await db.close()

    asyncio.run(run())


# ── the invariant: buckets == increments of the totals ─────────────────────────


def test_every_poll_books_exactly_its_total_increment_into_buckets(tmp_path: Path) -> None:
    """Sum of bucket deltas per poll == increment of downloaded/uploaded_bytes.

    Walks all three protocols through a first sample, steady growth, a counter
    reset (backend restart), a direction that is missing from the answer, a
    backend outage and an hour change. After every pass the increment the poll
    made to each key's totals must equal what it added to that key's buckets.
    """

    async def run() -> None:
        clock = _Clock("2026-11-05T10:05:00+00:00")
        db = await _open(tmp_path / "vpn.db")
        try:
            xray, awg, hy2 = await _three_keys(db)
            poller = _Poller(db, clock)
            assert awg.public_key is not None

            async def step(xray_raw: tuple[int | None, int | None], awg_raw: tuple[int, int], hy2_raw: tuple[int, int]) -> dict[int, tuple[int, int]]:
                poller.xray.set("xray_tcp_Aa111", down=xray_raw[0], up=xray_raw[1])
                poller.awg.transfers[awg.public_key or ""] = (awg_raw[1], awg_raw[0])
                poller.hysteria.traffic["hy2_Bb222"] = (hy2_raw[1], hy2_raw[0])
                totals_before, buckets_before = await _totals(db), await _bucket_sums(db)
                await poller.run()
                increment = _diff(await _totals(db), totals_before)
                booked = _diff(await _bucket_sums(db), buckets_before)
                assert increment == booked, (increment, booked)
                return increment

            # First sample of each key: the whole raw counter goes into the total.
            assert await step((1000, 100), (2000, 200), (3000, 300)) == {
                xray.id: (1000, 100), awg.id: (2000, 200), hy2.id: (3000, 300),
            }
            # Steady growth.
            assert await step((1500, 150), (2600, 260), (3700, 370)) == {
                xray.id: (500, 50), awg.id: (600, 60), hy2.id: (700, 70),
            }
            # Next hour, nothing moved: no bucket write at all, not even a zero row.
            first_hour = hour_utc_from_iso(clock.value)
            clock.value = "2026-11-05T11:00:01+00:00"
            assert await step((1500, 150), (2600, 260), (3700, 370)) == {}
            assert {row[0] for row in await _buckets(db)} == {first_hour}

            # Every backend restarted: raw counters dropped below the stored
            # ones. The reset branch adds the new raw value as is.
            assert await step((40, 4), (50, 5), (60, 6)) == {
                xray.id: (40, 4), awg.id: (50, 5), hy2.id: (60, 6),
            }
            # xray answers with the downlink only: the uplink keeps its raw value.
            assert await step((90, None), (50, 5), (60, 6)) == {xray.id: (50, 0)}
            assert await step((90, 10), (50, 5), (60, 6)) == {xray.id: (0, 6)}

            # xray is down: the key is marked unavailable, nothing is booked.
            poller.xray.fail = True
            assert await step((900, 900), (50, 5), (60, 6)) == {}
            poller.xray.fail = False

            # Over the whole run, the buckets hold the totals exactly — two hours.
            assert await _bucket_sums(db) == await _totals(db)
            assert {row[0] for row in await _buckets(db)} == {first_hour, first_hour + 1}
        finally:
            await db.close()

    asyncio.run(run())


def test_a_failed_batch_rolls_the_buckets_back_with_the_totals(tmp_path: Path) -> None:
    """Bucket and totals are one transaction: if the batch fails, neither moves."""

    async def run() -> None:
        clock = _Clock(NOW)
        db = await _open(tmp_path / "vpn.db")
        try:
            xray, _awg, _hy2 = await _three_keys(db)
            poller = _Poller(db, clock)
            poller.xray.set("xray_tcp_Aa111", down=1000, up=100)
            stats = poller.service.stats
            original = stats.upsert_success
            calls = 0

            async def flaky(**kwargs):  # type: ignore[no-untyped-def]
                nonlocal calls
                calls += 1
                result = await original(**kwargs)
                raise RuntimeError("disk full")  # after both writes of this key
                return result  # pragma: no cover

            stats.upsert_success = flaky  # type: ignore[method-assign]
            with pytest.raises(RuntimeError, match="disk full"):
                await poller.service.refresh_views([xray])
            assert calls == 1
            assert await _buckets(db) == []
            assert await _totals(db) == {}
        finally:
            await db.close()

    asyncio.run(run())


# ── deleted keys ─────────────────────────────────────────────────────────────


def test_deleting_a_key_keeps_its_buckets_in_the_windows(tmp_path: Path) -> None:
    """Hard delete (archive + row removal), soft delete and a restart all leave
    the buckets alone, so the windows keep counting the deleted key."""

    async def run() -> None:
        clock = _Clock(NOW)
        db_path = tmp_path / "vpn.db"
        db = await _open(db_path)
        try:
            xray, awg, hy2 = await _three_keys(db)
            poller = _Poller(db, clock)
            poller.xray.set("xray_tcp_Aa111", down=1000, up=100)
            assert awg.public_key is not None
            poller.awg.transfers[awg.public_key] = (200, 2000)
            poller.hysteria.traffic["hy2_Bb222"] = (300, 3000)
            await poller.run()
            before = await _buckets(db)
            assert len(before) == 3

            keys = VpnKeyRepository(db)
            await keys.hard_delete_with_stats(xray.id, NOW)
            await keys.hard_delete_with_stats(awg.id, NOW)
            await keys.mark_deleted(hy2.id, 100, NOW)
            assert await keys.get_by_id(xray.id) is None
            assert await _buckets(db) == before
            windows = await DashboardRepository(db).traffic_windows(HOUR)
            assert windows.bytes_by_days[1] == 1100 + 2200 + 3300
        finally:
            await db.close()

        # Boot-time integrity checks must not treat buckets of deleted keys as
        # orphans (there is no FK on purpose).
        db = await _open(db_path)
        try:
            assert await _buckets(db) == before
        finally:
            await db.close()

    asyncio.run(run())


# ── window boundaries ────────────────────────────────────────────────────────


@pytest.mark.parametrize("days", TRAFFIC_WINDOW_DAYS)
def test_window_boundary_bucket_inside_and_outside(days: int, tmp_path: Path) -> None:
    """"Nд" = hour_utc >= current_hour - N*24 + 1: the bucket exactly at that
    hour is in, the one an hour earlier is out (and in the next longer window)."""

    async def run() -> None:
        db = await _open(tmp_path / "vpn.db")
        try:
            start = HOUR - days * 24 + 1
            assert window_start_hour(HOUR, days) == start
            await _insert_bucket(db, start, 1, 1)  # on the boundary: inside
            await _insert_bucket(db, start - 1, 2, 10)  # an hour earlier: outside
            await _insert_bucket(db, HOUR, 3, 100, 1000)  # the current, incomplete hour
            windows = await DashboardRepository(db).traffic_windows(HOUR)
            assert windows.bytes_by_days[days] == 1 + 1100
            for longer in (d for d in TRAFFIC_WINDOW_DAYS if d > days):
                assert windows.bytes_by_days[longer] == 10 + 1 + 1100
            for shorter in (d for d in TRAFFIC_WINDOW_DAYS if d < days):
                assert windows.bytes_by_days[shorter] == 1100
            assert windows.first_hour_utc == start - 1
        finally:
            await db.close()

    asyncio.run(run())


def test_hour_utc_is_unix_hours_and_reads_naive_timestamps_as_utc() -> None:
    assert hour_utc_from_iso("1970-01-01T00:59:59+00:00") == 0
    assert hour_utc_from_iso("1970-01-01T01:00:00+00:00") == 1
    assert hour_utc_from_iso("2026-11-05T12:00:00+00:00") == hour_utc_from_iso("2026-11-05T12:59:59+00:00") == HOUR
    assert hour_utc_from_iso("2026-11-05T15:34:56+03:00") == HOUR
    assert hour_utc_from_iso("2026-11-05T12:34:56") == HOUR
    assert HOUR == int(datetime(2026, 11, 5, 12, tzinfo=timezone.utc).timestamp()) // 3600


def test_empty_table_reports_no_history(tmp_path: Path) -> None:
    async def run() -> None:
        db = await _open(tmp_path / "vpn.db")
        try:
            windows = await DashboardRepository(db).traffic_windows(HOUR)
            assert windows.empty and windows.first_hour_utc is None
            assert windows.bytes_by_days == dict.fromkeys(TRAFFIC_WINDOW_DAYS, 0)
            assert not windows.history_starts_inside
        finally:
            await db.close()

    asyncio.run(run())


def test_history_start_is_the_whole_tables_minimum_not_the_scanned_range(tmp_path: Path) -> None:
    """Data older than 365 days but none at the start of the 365-day window: the
    history is still longer than every window, so there is no "since" note."""

    async def run() -> None:
        db = await _open(tmp_path / "vpn.db")
        try:
            await _insert_bucket(db, HOUR - 380 * 24, 1, 5)
            await _insert_bucket(db, HOUR - 10, 1, 7)
            windows = await DashboardRepository(db).traffic_windows(HOUR)
            assert windows.first_hour_utc == HOUR - 380 * 24
            assert not windows.history_starts_inside
            assert windows.bytes_by_days[365] == 7
        finally:
            await db.close()

    asyncio.run(run())


# ── retention ────────────────────────────────────────────────────────────────


def test_retention_deletes_400_days_and_keeps_399(tmp_path: Path) -> None:
    async def run() -> None:
        db = await _open(tmp_path / "vpn.db")
        try:
            assert TRAFFIC_HOURLY_RETENTION_DAYS == 400
            await _insert_bucket(db, HOUR - 401 * 24, 1, 1)
            await _insert_bucket(db, HOUR - 400 * 24, 1, 2)  # 400 days old: deleted
            await _insert_bucket(db, HOUR - 400 * 24 + 1, 1, 3)  # first hour of the 400-day window: kept
            await _insert_bucket(db, HOUR - 399 * 24, 1, 4)  # 399 days old: kept
            await _insert_bucket(db, HOUR, 1, 5)
            removed = await TrafficStatsRepository(db).prune_hourly(current_hour_utc=HOUR)
            assert removed == 2
            assert [row[0] for row in await _buckets(db)] == [HOUR - 400 * 24 + 1, HOUR - 399 * 24, HOUR]
        finally:
            await db.close()

    asyncio.run(run())


def test_retention_runs_on_the_poller_loop_once_per_hour(tmp_path: Path) -> None:
    """No task of its own: the existing poller loop prunes after its pass, and the
    service throttles that to one DELETE per clock hour."""

    async def run() -> None:
        clock = _Clock(NOW)
        db = await _open(tmp_path / "vpn.db")
        try:
            poller = _Poller(db, clock)
            await _insert_bucket(db, HOUR - 400 * 24, 1, 1)

            loop = asyncio.create_task(app_module._xray_stats_loop(poller.service, 3600))
            for _ in range(100):
                await asyncio.sleep(0.01)
                if not await _buckets(db):
                    break
            loop.cancel()
            with pytest.raises(asyncio.CancelledError):
                await loop
            assert await _buckets(db) == [], "the poller loop must apply the retention"

            # Same hour: throttled, even though an expired bucket reappeared.
            await _insert_bucket(db, HOUR - 500 * 24, 1, 1)
            assert await poller.service.prune_hourly_history() == 0
            assert len(await _buckets(db)) == 1
            # Next hour: pruned.
            clock.value = "2026-11-05T13:00:00+00:00"
            assert await poller.service.prune_hourly_history() == 1
            assert await _buckets(db) == []
        finally:
            await db.close()

    asyncio.run(run())


def test_a_failing_retention_pass_does_not_stop_the_poller_loop() -> None:
    async def run() -> None:
        calls: list[str] = []

        class _Service:
            async def refresh_all_awg(self) -> None:
                calls.append("refresh")

            async def prune_hourly_history(self) -> int:
                calls.append("prune")
                raise RuntimeError("database is locked")

        loop = asyncio.create_task(app_module._awg_stats_loop(_Service(), 0))  # type: ignore[arg-type]
        for _ in range(100):
            await asyncio.sleep(0.01)
            if calls.count("refresh") >= 2:
                break
        loop.cancel()
        with pytest.raises(asyncio.CancelledError):
            await loop
        assert calls[:4] == ["refresh", "prune", "refresh", "prune"]

    asyncio.run(run())


# ── rendering ────────────────────────────────────────────────────────────────

_TOTALS = TrafficTotals(total_bytes=3 * 1024**3, xray_bytes=1024**3, awg_bytes=1024**3, hysteria2_bytes=1024**3, avg_per_key_bytes=512 * 1024**2)


def _windows(first_hour: int | None) -> TrafficWindows:
    sizes = {1: 1024, 7: 2 * 1024**2, 30: 3 * 1024**2, 90: 4 * 1024**2, 180: 5 * 1024**2, 365: 6 * 1024**2}
    if first_hour is None:
        sizes = dict.fromkeys(TRAFFIC_WINDOW_DAYS, 0)
    return TrafficWindows(current_hour_utc=HOUR, bytes_by_days=sizes, first_hour_utc=first_hour)


def _snapshot(windows: TrafficWindows) -> DashboardSnapshot:
    return DashboardSnapshot(
        refreshed_at="12:34:56",
        users_by_role={"APPROVED_USER": 1},
        new_users_7d=0, new_users_30d=0, users_with_active_keys=1,
        pending_access_requests=0, pending_trial_requests=0,
        keys=KeysSummary(total=1, active=1, xray_active=1, awg_active=0, hysteria2_active=0,
                         expiring_7d=0, expiring_30d=0, stuck=0, avg_per_user=1.0),
        traffic=_TOTALS,
        traffic_windows=windows,
        top_users=[TopUserTraffic(user_id=100, username="user", total_bytes=1024**3)],
        active_socks5=0, active_mtproto=0, stuck_proxies=0,
        backend_health=(), warp=WarpState(), active_modules=[], last_backup_at=None, db_size_bytes=0,
        audit_count_24h=0, audit_count_7d=0, recent_audit_entries=[], announcements_30d=0,
    )


def test_render_full_history_has_no_since_note() -> None:
    # The first bucket is exactly the first hour of the 365-day window.
    snap = _snapshot(_windows(window_start_hour(HOUR, 365)))
    with use_locale("ru"):
        lines = dashboard_traffic_lines(snap)
        text = dashboard_text(snap)
    assert lines == [
        "<b>📊 Трафик</b> (с учётом удалённых ключей)",
        "  Итого (всё время): <b>3.00 GB</b>  (Xray: 1.00 GB | AWG: 1.00 GB | Hy2: 1.00 GB)",
        "  За период:",
        "    1д: 1.00 KB · 7д: 2.00 MB · 30д: 3.00 MB",
        "    90д: 4.00 MB · 180д: 5.00 MB · 365д: 6.00 MB",
        "  Среднее на ключ: 512.00 MB",
        "  Топ-5 за всё время:",
        "    @user 1.00 GB",
    ]
    assert "\n".join(lines) in text
    assert "данные с" not in text


def test_render_short_history_names_where_it_starts() -> None:
    first = HOUR - 48  # 2026-11-03 12:00 UTC
    with use_locale("ru"):
        lines = dashboard_traffic_lines(_snapshot(_windows(first)))
    assert lines[3:6] == [
        "    1д: 1.00 KB · 7д: 2.00 MB · 30д: 3.00 MB",
        "    90д: 4.00 MB · 180д: 5.00 MB · 365д: 6.00 MB",
        "    (данные с 03.11.2026 12:00 UTC)",
    ]
    # One hour short of the full 365 days is still short.
    with use_locale("ru"):
        lines = dashboard_traffic_lines(_snapshot(_windows(window_start_hour(HOUR, 365) + 1)))
    assert any(line.startswith("    (данные с ") for line in lines)


def test_render_empty_history_says_no_data() -> None:
    with use_locale("ru"):
        lines = dashboard_traffic_lines(_snapshot(_windows(None)))
    assert lines[2:4] == ["  За период:", "    нет данных за период"]
    assert not any("1д:" in line or "данные с" in line for line in lines)


def test_render_english() -> None:
    with use_locale("en"):
        short = dashboard_traffic_lines(_snapshot(_windows(HOUR - 48)))
        empty = dashboard_traffic_lines(_snapshot(_windows(None)))
    assert short[:6] == [
        "<b>📊 Traffic</b> (including deleted keys)",
        "  Total (all time): <b>3.00 GB</b>  (Xray: 1.00 GB | AWG: 1.00 GB | Hy2: 1.00 GB)",
        "  By period:",
        "    1d: 1.00 KB · 7d: 2.00 MB · 30d: 3.00 MB",
        "    90d: 4.00 MB · 180d: 5.00 MB · 365d: 6.00 MB",
        "    (data since 03.11.2026 12:00 UTC)",
    ]
    assert empty[2:4] == ["  By period:", "    no data for the period"]
