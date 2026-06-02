
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.key_expiry import KeyExpiryService, _days_noun


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _setup_db(tmp_path: Path) -> tuple[Database, VpnKeyRepository]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await UserRepository(db).upsert_profile(
        TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-01-01T00:00:00"
    )
    return db, VpnKeyRepository(db)


async def _make_active_key(repo: VpnKeyRepository, expires_at: str, uid: str = "01") -> int:
    key = await repo.create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        note=None,
        payload={},
        public_payload={},
        created_by=100,
        now="2026-01-01T00:00:00",
        uuid=f"00000000-0000-4000-8000-0000000000{uid}",
        expires_at=expires_at,
    )
    await repo.mark_active(key.id, "2026-01-01T00:01:00")
    return key.id


def _make_service(repo: VpnKeyRepository, bot: object, notify_days: tuple[int, ...]) -> KeyExpiryService:
    clock = MagicMock()
    clock.now.return_value = "2026-01-10T00:00:00+00:00"
    return KeyExpiryService(
        vpn_keys=repo,
        xray=MagicMock(),
        awg=MagicMock(),
        audit=MagicMock(),
        clock=clock,
        bot=bot,  # type: ignore[arg-type]
        notify_days=notify_days,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_notify_expiring_keys_sends_message_within_threshold(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            # Expires in 2 days — within 3-day threshold
            key_id = await _make_active_key(repo, "2026-01-12T00:00:00+00:00")

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _make_service(repo, bot, notify_days=(3,))

            count = await service.notify_expiring_keys()

            assert count == 1
            bot.send_message.assert_awaited_once()
            call_args = bot.send_message.call_args
            assert call_args[0][0] == 100
            assert str(key_id) in call_args[0][1]
        finally:
            await db.close()

    asyncio.run(run())


def test_notify_expiring_keys_skips_key_outside_threshold(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            # Expires in 5 days — outside 3-day threshold
            await _make_active_key(repo, "2026-01-15T00:00:00+00:00")

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _make_service(repo, bot, notify_days=(3,))

            count = await service.notify_expiring_keys()

            assert count == 0
            bot.send_message.assert_not_awaited()
        finally:
            await db.close()

    asyncio.run(run())


def test_notify_expiring_keys_deduplicates_on_second_run(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            await _make_active_key(repo, "2026-01-12T00:00:00+00:00")

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _make_service(repo, bot, notify_days=(3,))

            first = await service.notify_expiring_keys()
            second = await service.notify_expiring_keys()

            assert first == 1
            assert second == 0  # already notified
            assert bot.send_message.await_count == 1
        finally:
            await db.close()

    asyncio.run(run())


def test_notify_expiring_keys_one_accurate_reminder_per_run(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            await _make_active_key(repo, "2026-01-11T00:00:00+00:00")  # 1 day away

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _make_service(repo, bot, notify_days=(3, 1))

            count = await service.notify_expiring_keys()

            # A key 1 day from expiry must get exactly ONE reminder this run, and
            # the text must state the real remaining time (1 day), not a higher
            # threshold like "3 days".
            assert count == 1
            assert bot.send_message.await_count == 1
            message = bot.send_message.await_args[0][1]
            assert "1 день" in message
            assert "3 дня" not in message and "3 дней" not in message

            # Both thresholds are recorded as handled, so a second run is silent.
            second = await service.notify_expiring_keys()
            assert second == 0
            assert bot.send_message.await_count == 1
        finally:
            await db.close()

    asyncio.run(run())


def test_notify_expiring_keys_no_bot_does_nothing(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            await _make_active_key(repo, "2026-01-12T00:00:00+00:00")

            clock = MagicMock()
            clock.now.return_value = "2026-01-10T00:00:00+00:00"
            service = KeyExpiryService(
                vpn_keys=repo,
                xray=MagicMock(),
                awg=MagicMock(),
                audit=MagicMock(),
                clock=clock,
                bot=None,
                notify_days=(3,),
            )

            count = await service.notify_expiring_keys()
            assert count == 0
        finally:
            await db.close()

    asyncio.run(run())


def test_notify_expiring_keys_no_notify_days_does_nothing(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            await _make_active_key(repo, "2026-01-12T00:00:00+00:00")

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _make_service(repo, bot, notify_days=())

            count = await service.notify_expiring_keys()
            assert count == 0
            bot.send_message.assert_not_awaited()
        finally:
            await db.close()

    asyncio.run(run())


def test_notify_skips_expired_keys(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            # Expires in the past
            await _make_active_key(repo, "2026-01-09T00:00:00+00:00")

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _make_service(repo, bot, notify_days=(3,))

            count = await service.notify_expiring_keys()
            assert count == 0
            bot.send_message.assert_not_awaited()
        finally:
            await db.close()

    asyncio.run(run())


def test_mark_expiry_notified_stores_and_deduplicates(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            key_id = await _make_active_key(repo, "2026-01-12T00:00:00+00:00")

            # Mark once for day 3, once for day 1
            await repo.mark_expiry_notified(key_id, 3)
            await repo.mark_expiry_notified(key_id, 1)

            # Neither threshold should appear in the "not notified" query
            now = "2026-01-10T00:00:00+00:00"
            deadline = "2026-01-13T00:00:00+00:00"
            assert await repo.list_not_notified_expiring(now, deadline, 3) == []
            assert await repo.list_not_notified_expiring(now, deadline, 1) == []
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# _days_noun unit tests
# ---------------------------------------------------------------------------

def test_notify_expired_key_calls_bot_send_message(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _setup_db(tmp_path)
        try:
            key_id = await _make_active_key(repo, "2026-01-09T12:00:00+00:00")  # expired (now is Jan 10)

            bot = MagicMock()
            bot.send_message = AsyncMock()

            xray_mock = MagicMock()
            xray_mock.revoke_xray_key_system = AsyncMock()

            clock = MagicMock()
            clock.now.return_value = "2026-01-10T00:00:00+00:00"
            service = KeyExpiryService(
                vpn_keys=repo,
                xray=xray_mock,
                awg=MagicMock(),
                audit=MagicMock(),
                clock=clock,
                bot=bot,
                notify_days=(3,),
            )

            count = await service.revoke_expired_keys()

            assert count == 1
            xray_mock.revoke_xray_key_system.assert_awaited_once_with(key_id)
            bot.send_message.assert_awaited_once()
            call_args = bot.send_message.call_args
            assert call_args[0][0] == 100
            assert str(key_id) in call_args[0][1]
            assert "истёк" in call_args[0][1]
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "days,expected",
    [
        (1, "день"),
        (2, "дня"),
        (3, "дня"),
        (4, "дня"),
        (5, "дней"),
        (11, "дней"),
        (21, "день"),
        (100, "дней"),
        (101, "день"),
    ],
)
def test_days_noun(days: int, expected: str) -> None:
    assert _days_noun(days) == expected
