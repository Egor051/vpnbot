"""TrafficStatsService: RBAC entry points, backend-failure paths and retention.

The accumulation maths (resets, hourly buckets) is pinned by
test_traffic_hourly.py; this module covers what that suite does not reach —
who may see which key, how each backend's failure or missing mapping is
recorded, and the once-per-hour retention claim. Real DB + repositories; the
three stats backends are in-memory fakes shared with test_traffic_hourly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
from test_traffic_hourly import NOW, _active_key, _Awg, _Clock, _Hysteria, _Xray

from db.database import Database
from models.dto import TelegramUserProfile, User
from models.enums import UserRole, VpnKeyType
from repositories.traffic_stats import TrafficStatsRepository, hour_utc_from_iso
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.errors import AccessDenied, NotFound
from services.traffic_stats import PUBLIC_BACKEND_STATS_ERROR, TrafficStatsService

ADMIN, ALICE, BOB = 1, 100, 200


class FakeUsers:
    roles: ClassVar[dict[int, UserRole]] = {ADMIN: UserRole.SUPERADMIN, ALICE: UserRole.APPROVED_USER, BOB: UserRole.APPROVED_USER}

    def __init__(self, clock: _Clock) -> None:
        self.clock = clock

    async def require_approved_or_admin(self, user_id: int) -> User:
        return User(user_id, "u", "U", self.roles[user_id], NOW, NOW, None)

    async def require_superadmin(self, user_id: int) -> User:
        if self.roles[user_id] != UserRole.SUPERADMIN:
            raise AccessDenied("superadmin only")
        return User(user_id, "u", "U", UserRole.SUPERADMIN, NOW, NOW, None)


class FailingBackend:
    async def query_all(self) -> Any:
        raise RuntimeError("backend down")

    async def list_transfer(self) -> Any:
        raise RuntimeError("backend down")


class World:
    def __init__(self, db: Database, *, hysteria: object | None = None, xray: object | None = None,
                 awg: object | None = None) -> None:
        self.db = db
        self.clock = _Clock(NOW)
        self.xray = xray or _Xray()
        self.awg = awg or _Awg()
        self.hysteria = hysteria
        self.stats = TrafficStatsRepository(db)
        self.service = TrafficStatsService(
            stats=self.stats,
            vpn_keys=VpnKeyRepository(db),
            users_repo=UserRepository(db),
            users=FakeUsers(self.clock),  # type: ignore[arg-type]
            awg=self.awg,  # type: ignore[arg-type]
            xray=self.xray,  # type: ignore[arg-type]
            hysteria=self.hysteria,  # type: ignore[arg-type]
        )


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "vpn.db")
    await database.connect()
    await database.bootstrap()
    users = UserRepository(database)
    for user_id, role in FakeUsers.roles.items():
        await users.upsert_profile(TelegramUserProfile(user_id, f"u{user_id}", "U"), role, NOW)
    try:
        yield database
    finally:
        await database.close()


async def _xray_key(db: Database, *, owner: int = ALICE, label: str | None = "xray_tcp_Aa111") -> Any:
    return await _active_key(db, key_type=VpnKeyType.XRAY, label=label, owner=owner,
                             uuid=f"00000000-0000-4000-8000-{owner:012d}")


# ── RBAC ─────────────────────────────────────────────────────────────────────


# Invariant: a key that does not exist, or is deleted, is NotFound for everyone.
async def test_refresh_for_actor_missing_or_deleted_key(db: Database) -> None:
    # Arrange
    w = World(db)
    key = await _xray_key(db)
    await VpnKeyRepository(db).mark_deleted(key.id, ADMIN, NOW)

    # Act / Assert
    for key_id in (key.id, 999):
        with pytest.raises(NotFound) as excinfo:
            await w.service.refresh_for_actor(ADMIN, key_id)
        assert excinfo.value.key == "err_key_not_found"


# Invariant: a regular user may refresh only their own key; a superadmin may
# refresh anyone's.
async def test_refresh_for_actor_ownership(db: Database) -> None:
    # Arrange
    w = World(db)
    key = await _xray_key(db, owner=ALICE)
    w.xray.set("xray_tcp_Aa111", down=10, up=5)  # type: ignore[attr-defined]

    # Act
    own = await w.service.refresh_for_actor(ALICE, key.id)
    admin = await w.service.refresh_for_actor(ADMIN, key.id)

    # Assert
    with pytest.raises(AccessDenied) as excinfo:
        await w.service.refresh_for_actor(BOB, key.id)
    assert excinfo.value.key == "err_foreign_stats_view"
    assert own.stats is not None and (own.stats.downloaded_bytes, own.stats.uploaded_bytes) == (10, 5)
    assert admin.owner is not None and admin.owner.telegram_user_id == ALICE


# Invariant: the fleet-wide count/list are superadmin-only and list returns a
# refreshed view per traffic-capable key.
async def test_superadmin_count_and_list(db: Database) -> None:
    # Arrange
    w = World(db)
    await _xray_key(db, owner=ALICE)
    await _xray_key(db, owner=BOB, label="xray_tcp_Bb222")

    # Act
    count = await w.service.count_for_superadmin(ADMIN)
    views = await w.service.list_for_superadmin(ADMIN, limit=10)

    # Assert
    assert count == 2
    assert len(views) == 2 and all(v.stats is not None for v in views)
    for call in (w.service.count_for_superadmin(ALICE), w.service.list_for_superadmin(ALICE)):
        with pytest.raises(AccessDenied):
            await call


# ── backend failures and missing mappings ────────────────────────────────────


# Invariant: a backend that raises marks every affected key unavailable with
# the PUBLIC error text (never the raw exception), per protocol.
@pytest.mark.parametrize("protocol", ["xray", "awg", "hysteria2"])
async def test_backend_failure_marks_unavailable(db: Database, protocol: str) -> None:
    # Arrange
    failing = FailingBackend()
    if protocol == "xray":
        w = World(db, xray=failing)
        key = await _xray_key(db)
    elif protocol == "awg":
        w = World(db, awg=failing)
        key = await _active_key(db, key_type=VpnKeyType.AWG, owner=ALICE,
                                public_key="awgPub0000000000000000000000000000000000001=", client_ip="10.8.0.2")
    else:
        w = World(db, hysteria=failing)
        key = await _active_key(db, key_type=VpnKeyType.HYSTERIA2, label="hy2_Bb222", owner=ALICE)

    # Act
    (view,) = await w.service.refresh_views([key])

    # Assert
    assert view.stats is not None
    assert view.stats.available is False
    assert view.stats.unavailable_reason == PUBLIC_BACKEND_STATS_ERROR


# Invariant: with the Hysteria2 stats API not configured, hy2 keys surface as
# unavailable, and the background hy2 poller is a no-op.
async def test_hysteria_not_configured(db: Database) -> None:
    # Arrange
    w = World(db, hysteria=None)
    key = await _active_key(db, key_type=VpnKeyType.HYSTERIA2, label="hy2_Bb222", owner=ALICE)

    # Act
    await w.service.refresh_all_hysteria()
    after_poller = await w.stats.get_by_key_id(key.id)
    (view,) = await w.service.refresh_views([key])

    # Assert
    assert after_poller is None
    assert view.stats is not None and view.stats.available is False
    assert view.stats.unavailable_reason == PUBLIC_BACKEND_STATS_ERROR


# Invariant: a key that cannot be matched to a backend counter (Xray/Hysteria2
# without a label, AWG without a public key) is unavailable with a reason that
# says so.
@pytest.mark.parametrize("protocol", ["xray", "awg", "hysteria2"])
async def test_unmappable_key_is_unavailable(db: Database, protocol: str) -> None:
    # Arrange
    w = World(db, hysteria=_Hysteria())
    if protocol == "xray":
        key = await _xray_key(db, label=None)
    elif protocol == "awg":
        key = await _active_key(db, key_type=VpnKeyType.AWG, owner=ALICE, public_key=None, client_ip="10.8.0.3")
    else:
        key = await _active_key(db, key_type=VpnKeyType.HYSTERIA2, label=None, owner=ALICE)

    # Act
    (view,) = await w.service.refresh_views([key])

    # Assert
    assert view.stats is not None and view.stats.available is False
    assert view.stats.unavailable_reason is not None
    assert "для сопоставления статистики" in view.stats.unavailable_reason


# Invariant: a Hysteria2 label absent from /traffic is "no traffic yet": only
# the attempt is touched, accumulated totals are kept and the key stays
# available.
async def test_hysteria_missing_label_keeps_totals(db: Database) -> None:
    # Arrange
    hysteria = _Hysteria()
    w = World(db, hysteria=hysteria)
    key = await _active_key(db, key_type=VpnKeyType.HYSTERIA2, label="hy2_Bb222", owner=ALICE)
    hysteria.traffic["hy2_Bb222"] = (40, 60)
    await w.service.refresh_views([key])
    hysteria.traffic.clear()

    # Act
    (view,) = await w.service.refresh_views([key])

    # Assert
    assert view.stats is not None and view.stats.available is True
    assert (view.stats.downloaded_bytes, view.stats.uploaded_bytes) == (60, 40)


# Invariant: cached_for_keys() reads stored stats and never polls a backend.
async def test_cached_for_keys_does_not_poll(db: Database) -> None:
    # Arrange
    w = World(db, xray=FailingBackend())
    key = await _xray_key(db)
    await w.stats.upsert_success(key_id=key.id, downloaded_bytes=1, uploaded_bytes=2, raw_downloaded_bytes=1,
                                 raw_uploaded_bytes=2, now=NOW, source="xray statsquery")

    # Act
    cached = await w.service.cached_for_keys([key])

    # Assert
    assert cached[key.id].available is True
    assert (cached[key.id].downloaded_bytes, cached[key.id].uploaded_bytes) == (1, 2)


# ── retention ────────────────────────────────────────────────────────────────


# Invariant: retention runs at most once per clock hour; a new hour runs it
# again.
async def test_prune_runs_once_per_hour(db: Database) -> None:
    # Arrange
    w = World(db)
    key = await _xray_key(db)
    old_hour = hour_utc_from_iso(NOW) - 401 * 24
    await db.conn.execute(
        "INSERT INTO traffic_hourly (hour_utc, key_id, protocol, downloaded_bytes, uploaded_bytes) VALUES (?, ?, 'xray', 1, 1)",
        (old_hour, key.id),
    )
    await db.commit()

    # Act
    first = await w.service.prune_hourly_history()
    second = await w.service.prune_hourly_history()
    w.clock.value = "2026-11-05T13:00:00+00:00"
    third = await w.service.prune_hourly_history()

    # Assert
    assert (first, second, third) == (1, 0, 0)
    assert w.service._pruned_hour_utc == hour_utc_from_iso("2026-11-05T13:00:00+00:00")


# Invariant: a failed prune releases the hourly claim, so the next poller in
# the same hour retries instead of skipping retention for the hour.
async def test_failed_prune_releases_claim(db: Database, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    w = World(db)
    calls = {"n": 0}
    real_prune = w.stats.prune_hourly

    async def flaky_prune(**kwargs: Any) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database is locked")
        return await real_prune(**kwargs)

    monkeypatch.setattr(w.stats, "prune_hourly", flaky_prune)

    # Act
    with pytest.raises(RuntimeError, match="locked"):
        await w.service.prune_hourly_history()
    claim_after_failure = w.service._pruned_hour_utc
    retried = await w.service.prune_hourly_history()

    # Assert
    assert claim_after_failure is None
    assert retried == 0
    assert calls["n"] == 2
