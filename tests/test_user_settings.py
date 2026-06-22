
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import i18n
from i18n import en as en_mod
from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.key_expiry import KeyExpiryService, _days_noun_for


# ---------------------------------------------------------------------------
# i18n per-task locale
# ---------------------------------------------------------------------------

def test_set_locale_overrides_default_then_resets() -> None:
    i18n.configure("ru")
    try:
        # Without an active per-task locale, t() uses the configured default (ru).
        assert i18n.t("btn_settings") != en_mod.STRINGS["btn_settings"]
        token = i18n.set_locale("en")
        try:
            assert i18n.t("btn_settings") == en_mod.STRINGS["btn_settings"]
            assert i18n.resolve_locale() == "en"
        finally:
            i18n.reset_locale(token)
        # After reset the default is restored.
        assert i18n.resolve_locale() == "ru"
        assert i18n.t("btn_settings") != en_mod.STRINGS["btn_settings"]
    finally:
        i18n.configure("ru")


def test_use_locale_context_manager() -> None:
    i18n.configure("ru")
    with i18n.use_locale("en"):
        assert i18n.t("btn_settings") == en_mod.STRINGS["btn_settings"]
    assert i18n.resolve_locale() == "ru"


def test_unknown_locale_falls_back_to_default() -> None:
    i18n.configure("ru")
    with i18n.use_locale("zz"):
        # Unsupported locale is ignored and the default applies.
        assert i18n.resolve_locale() == "ru"


def test_days_noun_for_en() -> None:
    assert _days_noun_for("en", 1) == "day"
    assert _days_noun_for("en", 3) == "days"
    assert _days_noun_for("ru", 1) == "день"


# ---------------------------------------------------------------------------
# UserRepository: language + expiry-notification columns
# ---------------------------------------------------------------------------

async def _make_user_repo(tmp_path: Path) -> tuple[Database, UserRepository]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    repo = UserRepository(db)
    await repo.upsert_profile(
        TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-01-01T00:00:00"
    )
    return db, repo


def test_new_user_defaults(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _make_user_repo(tmp_path)
        try:
            user = await repo.get_by_id(100)
            assert user is not None
            assert user.language is None
            assert user.expiry_notifications_enabled is True
        finally:
            await db.close()

    asyncio.run(run())


def test_set_language_and_notifications_persist(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo = await _make_user_repo(tmp_path)
        try:
            await repo.set_language(100, "en", "2026-01-02T00:00:00")
            assert (await repo.get_by_id(100)).language == "en"

            await repo.set_language(100, None, "2026-01-03T00:00:00")
            assert (await repo.get_by_id(100)).language is None

            await repo.set_expiry_notifications_enabled(100, False, "2026-01-04T00:00:00")
            assert (await repo.get_by_id(100)).expiry_notifications_enabled is False

            await repo.set_expiry_notifications_enabled(100, True, "2026-01-05T00:00:00")
            assert (await repo.get_by_id(100)).expiry_notifications_enabled is True
        finally:
            await db.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# key_expiry opt-out
# ---------------------------------------------------------------------------

async def _setup_expiry(tmp_path: Path) -> tuple[Database, VpnKeyRepository, UserRepository]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users = UserRepository(db)
    await users.upsert_profile(
        TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "2026-01-01T00:00:00"
    )
    return db, VpnKeyRepository(db), users


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


def _service(repo: VpnKeyRepository, users: UserRepository, bot: object) -> KeyExpiryService:
    clock = MagicMock()
    clock.now.return_value = "2026-01-10T00:00:00+00:00"
    return KeyExpiryService(
        vpn_keys=repo,
        users=users,
        xray=MagicMock(),
        awg=MagicMock(),
        audit=MagicMock(),
        clock=clock,
        bot=bot,  # type: ignore[arg-type]
        notify_days=(3,),
    )


def test_expiry_reminder_respects_opt_out_and_does_not_mark(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo, users = await _setup_expiry(tmp_path)
        try:
            await _make_active_key(repo, "2026-01-12T00:00:00+00:00")  # 2 days away
            await users.set_expiry_notifications_enabled(100, False, "2026-01-09T00:00:00")

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _service(repo, users, bot)

            # Opted out: nothing sent, key NOT marked notified.
            assert await service.notify_expiring_keys() == 0
            bot.send_message.assert_not_awaited()

            # Re-enabling delivers the reminder on the next run (proves no mark).
            await users.set_expiry_notifications_enabled(100, True, "2026-01-09T12:00:00")
            assert await service.notify_expiring_keys() == 1
            bot.send_message.assert_awaited_once()
        finally:
            await db.close()

    asyncio.run(run())


def test_expired_revocation_notice_ignores_opt_out(tmp_path: Path) -> None:
    async def run() -> None:
        db, repo, users = await _setup_expiry(tmp_path)
        try:
            key_id = await _make_active_key(repo, "2026-01-09T12:00:00+00:00")  # already expired
            await users.set_expiry_notifications_enabled(100, False, "2026-01-09T00:00:00")

            bot = MagicMock()
            bot.send_message = AsyncMock()
            service = _service(repo, users, bot)
            service.xray.revoke_xray_key_system = AsyncMock()

            count = await service.revoke_expired_keys()
            assert count == 1
            # The "expired — access revoked" notice is always delivered.
            bot.send_message.assert_awaited_once()
            assert str(key_id) in bot.send_message.await_args[0][1]
        finally:
            await db.close()

    asyncio.run(run())
