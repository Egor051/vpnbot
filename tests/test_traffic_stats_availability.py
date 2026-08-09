"""A missing backend counter is "no traffic yet", not "the backend is down".

xray creates its per-user counters lazily, on a key's first packet — right after
an xray restart ``statsquery`` lists none at all, and one real connection makes
exactly the counters that connection touched appear. hysteria2's ``/traffic``
behaves the same way: it lists only ids that have moved data since the server
started.

The collector treated both as a backend failure and wrote ``available = 0``, so
every screen that keyed off that flag blanked out — most visibly the bundle card,
which then summed a 0 into the subscription total. These tests pin the two
outcomes apart, against the real repository and a real SQLite database, because
the distinction lives in what gets written to the row.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from db.database import Database
from models.dto import TelegramUserProfile, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.traffic_stats import TrafficStatsRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.traffic_stats import TrafficStatsService


def _key(key_id: int, key_type: VpnKeyType, label: str) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=100,
        username="user",
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="uuid",
        email_label=label,
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


async def _setup(tmp_path: Path) -> tuple[Database, TrafficStatsRepository, TrafficStatsService, int]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await UserRepository(db).upsert_profile(
        TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now"
    )
    keys = VpnKeyRepository(db)
    created = await keys.create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        note=None,
        payload={},
        public_payload={},
        created_by=100,
        now="now",
        uuid="00000000-0000-4000-8000-000000000001",
        email_label="xray_http_base_abc",
    )
    stats = TrafficStatsRepository(db)
    service = TrafficStatsService(
        stats=stats,
        vpn_keys=keys,
        users_repo=SimpleNamespace(),  # type: ignore[arg-type]
        users=SimpleNamespace(clock=SimpleNamespace(now=lambda: "2026-08-09T10:00:00+00:00")),  # type: ignore[arg-type]
        awg=SimpleNamespace(),  # type: ignore[arg-type]
        xray=SimpleNamespace(),  # type: ignore[arg-type]
    )
    return db, stats, service, created.id


def test_absent_xray_counter_keeps_the_accumulated_totals_and_availability(tmp_path: Path) -> None:
    async def run() -> None:
        db, stats, service, key_id = await _setup(tmp_path)
        try:
            # A key that has already moved data: 1000 down / 400 up, confirmed.
            await stats.upsert_success(
                key_id=key_id,
                downloaded_bytes=1000,
                uploaded_bytes=400,
                raw_downloaded_bytes=1000,
                raw_uploaded_bytes=400,
                now="2026-08-09T09:00:00+00:00",
                source="xray statsquery",
            )
            previous = await stats.get_by_key_id(key_id)

            # xray answered, but has no counter for this label (restarted, or the
            # key simply has not been used since).
            result = await service._refresh_xray_key(  # noqa: SLF001
                _key(key_id, VpnKeyType.XRAY, "xray_http_base_abc"), previous, {}, None
            )

            assert result.available is True, "an absent counter is not a backend failure"
            assert result.unavailable_reason is None
            assert result.downloaded_bytes == 1000
            assert result.uploaded_bytes == 400
            assert result.last_success_at == "2026-08-09T09:00:00+00:00"
            # Only the attempt timestamp moved.
            assert result.last_attempt_at == "2026-08-09T10:00:00+00:00"
            # And the raw counters are untouched, so reset detection still works
            # the next time a real value shows up.
            assert result.last_raw_downloaded_bytes == 1000
            assert result.last_raw_uploaded_bytes == 400
        finally:
            await db.close()

    asyncio.run(run())


def test_backend_failure_still_marks_the_key_unavailable(tmp_path: Path) -> None:
    """The other branch must keep working: a failed query is still a failure."""

    async def run() -> None:
        db, stats, service, key_id = await _setup(tmp_path)
        try:
            await stats.upsert_success(
                key_id=key_id,
                downloaded_bytes=1000,
                uploaded_bytes=400,
                raw_downloaded_bytes=1000,
                raw_uploaded_bytes=400,
                now="2026-08-09T09:00:00+00:00",
                source="xray statsquery",
            )
            previous = await stats.get_by_key_id(key_id)

            result = await service._refresh_xray_key(  # noqa: SLF001
                _key(key_id, VpnKeyType.XRAY, "xray_http_base_abc"),
                previous,
                {},
                "Не удалось получить данные от backend",
            )

            assert result.available is False
            assert result.unavailable_reason == "Не удалось получить данные от backend"
            # Even then the accumulated totals survive — they are what the screens
            # print, marked stale.
            assert result.downloaded_bytes == 1000
            assert result.uploaded_bytes == 400
        finally:
            await db.close()

    asyncio.run(run())


def test_absent_counter_on_a_never_measured_key_records_zero_as_available(tmp_path: Path) -> None:
    """A brand-new key with no counter yet: the honest answer is 0 bytes, not "down"."""

    async def run() -> None:
        db, _stats, service, key_id = await _setup(tmp_path)
        try:
            result = await service._refresh_xray_key(  # noqa: SLF001
                _key(key_id, VpnKeyType.XRAY, "xray_http_base_abc"), None, {}, None
            )
            assert result.available is True
            assert result.downloaded_bytes == 0
            assert result.uploaded_bytes == 0
            assert result.last_success_at is None
            assert result.last_attempt_at == "2026-08-09T10:00:00+00:00"
        finally:
            await db.close()

    asyncio.run(run())


def test_touch_attempt_never_overwrites_a_stored_row(tmp_path: Path) -> None:
    """Repository-level guard: the upsert may only move last_attempt_at."""

    async def run() -> None:
        db, stats, _service, key_id = await _setup(tmp_path)
        try:
            await stats.upsert_unavailable(
                key_id=key_id, reason="backend down", now="2026-08-09T08:00:00+00:00", source="xray statsquery"
            )
            before = await stats.get_by_key_id(key_id)
            assert before is not None and before.available is False

            after = await stats.touch_attempt(
                key_id=key_id, now="2026-08-09T10:00:00+00:00", source="xray statsquery"
            )

            # available is NOT reset in either direction — a real failure stays a
            # real failure until a real measurement clears it.
            assert after.available is False
            assert after.unavailable_reason == "backend down"
            assert after.last_attempt_at == "2026-08-09T10:00:00+00:00"
        finally:
            await db.close()

    asyncio.run(run())


def test_absent_hysteria_counter_is_not_a_backend_failure(tmp_path: Path) -> None:
    async def run() -> None:
        db, stats, service, key_id = await _setup(tmp_path)
        try:
            await stats.upsert_success(
                key_id=key_id,
                downloaded_bytes=777,
                uploaded_bytes=111,
                raw_downloaded_bytes=777,
                raw_uploaded_bytes=111,
                now="2026-08-09T09:00:00+00:00",
                source="hysteria2 trafficStats",
            )
            previous = await stats.get_by_key_id(key_id)

            result = await service._refresh_hysteria_key(  # noqa: SLF001
                _key(key_id, VpnKeyType.HYSTERIA2, "hy2_abc"), previous, {}, None
            )

            assert result.available is True
            assert result.downloaded_bytes == 777
            assert result.uploaded_bytes == 111
        finally:
            await db.close()

    asyncio.run(run())
