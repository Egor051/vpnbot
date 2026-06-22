
import asyncio
from pathlib import Path

from adapters.clock import ClockProvider
from db.database import Database
from models.dto import RecipientFilter, TelegramUserProfile, User
from models.enums import UserRole
from repositories.announcements import AnnouncementRepository
from repositories.users import UserRepository
from services.announcements import AnnouncementService


class _Users:
    async def require_superadmin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)


class _AuditWithClock:
    def __init__(self) -> None:
        self.clock = ClockProvider()

    async def write(self, **kwargs: object) -> None:
        return None


class _Bot:
    def __init__(self) -> None:
        self.copied: list[int] = []

    async def copy_message(self, *, chat_id: int, from_chat_id: int, message_id: int) -> None:
        self.copied.append(chat_id)


async def _add_user(users: UserRepository, uid: int, role: UserRole, *, blocked: bool = False) -> None:
    await users.upsert_profile(TelegramUserProfile(uid, f"u{uid}", f"U{uid}"), role, "now")
    if blocked:
        await users.set_role(uid, UserRole.BLOCKED_USER, "now", blocked_at="now")


async def _add_vpn_key(db: Database, owner: int, key_type: str, status: str = "active", transport: str = "tcp") -> None:
    await db.conn.execute(
        """
        INSERT INTO vpn_keys (owner_user_id, key_type, status, payload_json, public_payload_json,
                              created_at, updated_at, created_by, transport)
        VALUES (?, ?, ?, '{}', '{}', 'now', 'now', ?, ?)
        """,
        (owner, key_type, status, owner, transport),
    )
    await db.commit()


async def _add_proxy(db: Database, owner: int, access_type: str, status: str = "active") -> None:
    await db.conn.execute(
        """
        INSERT INTO proxy_accesses (owner_user_id, access_type, status, payload_json, public_payload_json,
                                    created_at, updated_at, created_by)
        VALUES (?, ?, ?, '{}', '{}', 'now', 'now', ?)
        """,
        (owner, access_type, status, owner),
    )
    await db.commit()


# --- RecipientFilter unit tests (no DB) -------------------------------------


def test_recipient_filter_normalizes_and_drops_unknown_values() -> None:
    rf = RecipientFilter.create(
        roles=("BOGUS", "APPROVED_USER", "PENDING_USER"),
        protocols=("xray", "nope"),
        transports=("http",),
    )
    # Canonical ordering follows TARGETABLE_ROLES (SUPERADMIN, MODERATOR, APPROVED, PENDING).
    assert rf.roles == ("APPROVED_USER", "PENDING_USER")
    assert rf.protocols == ("xray",)
    assert rf.transports == ("http",)
    assert not rf.is_unfiltered()


def test_recipient_filter_clears_transports_without_xray() -> None:
    rf = RecipientFilter.create(protocols=("awg",), transports=("http", "tcp"))
    assert rf.transports == ()


def test_recipient_filter_json_round_trip() -> None:
    rf = RecipientFilter.create(roles=("APPROVED_USER",), protocols=("xray",), transports=("tcp",))
    restored = RecipientFilter.from_json(rf.to_json())
    assert restored == rf


def test_recipient_filter_from_json_handles_empty_and_invalid() -> None:
    assert RecipientFilter.from_json(None) is None
    assert RecipientFilter.from_json("") is None
    assert RecipientFilter.from_json("not json") is None
    assert RecipientFilter.from_json("[1,2,3]") is None


def test_recipient_filter_empty_is_unfiltered() -> None:
    assert RecipientFilter().is_unfiltered()
    assert RecipientFilter.create().is_unfiltered()


# --- Repository segment query tests (real DB) -------------------------------


def _ids(users: list[User]) -> list[int]:
    return [u.telegram_user_id for u in users]


def test_segment_queries_filter_by_role_protocol_and_transport(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await _add_user(users, 1, UserRole.SUPERADMIN)
            await _add_user(users, 2, UserRole.APPROVED_USER)
            await _add_user(users, 3, UserRole.MODERATOR)
            await _add_user(users, 4, UserRole.PENDING_USER)
            await _add_user(users, 5, UserRole.APPROVED_USER)
            await _add_user(users, 6, UserRole.APPROVED_USER)  # no access at all
            await _add_user(users, 7, UserRole.APPROVED_USER, blocked=True)  # always excluded
            await _add_vpn_key(db, 1, "xray", transport="tcp")
            await _add_vpn_key(db, 2, "xray", transport="http")
            await _add_vpn_key(db, 3, "awg")
            await _add_proxy(db, 4, "socks5")
            await _add_proxy(db, 5, "mtproto")
            await _add_vpn_key(db, 7, "xray", transport="tcp")  # blocked owner

            async def collect(rf: RecipientFilter) -> list[int]:
                out: list[int] = []
                last: int | None = None
                while True:
                    page = await users.list_segment_recipients_after(rf, last, limit=2)
                    if not page:
                        break
                    out.extend(_ids(page))
                    last = page[-1].telegram_user_id
                return out

            # Unfiltered: every non-blocked targetable role.
            unfiltered = RecipientFilter()
            assert await users.count_segment_recipients(unfiltered) == 6
            assert await collect(unfiltered) == [1, 2, 3, 4, 5, 6]

            # By role.
            assert await collect(RecipientFilter.create(roles=("APPROVED_USER",))) == [2, 5, 6]
            assert await collect(RecipientFilter.create(roles=("PENDING_USER",))) == [4]

            # By protocol.
            assert await collect(RecipientFilter.create(protocols=("xray",))) == [1, 2]
            assert await collect(RecipientFilter.create(protocols=("awg", "socks5"))) == [3, 4]
            assert await collect(RecipientFilter.create(protocols=("mtproto",))) == [5]

            # By transport (xray only).
            assert await collect(RecipientFilter.create(protocols=("xray",), transports=("http",))) == [2]
            assert await collect(RecipientFilter.create(protocols=("xray",), transports=("tcp",))) == [1]

            # Combined role + protocol.
            assert await collect(RecipientFilter.create(roles=("APPROVED_USER",), protocols=("xray",))) == [2]

            # is_segment_recipient mirrors the list query.
            xray_http = RecipientFilter.create(protocols=("xray",), transports=("http",))
            assert await users.is_segment_recipient(2, xray_http) is True
            assert await users.is_segment_recipient(1, xray_http) is False
            approved_only = RecipientFilter.create(roles=("APPROVED_USER",))
            assert await users.is_segment_recipient(1, approved_only) is False  # superadmin
            assert await users.is_segment_recipient(7, RecipientFilter()) is False  # blocked
        finally:
            await db.close()

    asyncio.run(run())


# --- Service tests (real DB + fake bot) -------------------------------------


def test_send_to_all_with_filter_targets_subset_and_persists_filter(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await _add_user(users, 1, UserRole.SUPERADMIN)
            await _add_user(users, 2, UserRole.APPROVED_USER)
            await _add_user(users, 3, UserRole.MODERATOR)
            await _add_user(users, 4, UserRole.PENDING_USER)
            await _add_vpn_key(db, 1, "xray", transport="tcp")
            await _add_vpn_key(db, 2, "xray", transport="http")
            await _add_vpn_key(db, 3, "awg")

            service = AnnouncementService(
                users=_Users(),  # type: ignore[arg-type]
                users_repo=users,
                announcements=AnnouncementRepository(db),
                audit=_AuditWithClock(),  # type: ignore[arg-type]
                delay_seconds=0,
            )
            bot = _Bot()
            rf = RecipientFilter.create(protocols=("xray",))

            assert await service.count_recipients(1, recipient_filter=rf) == 2

            result = await service.send_to_all(
                actor_user_id=1, bot=bot, from_chat_id=1, message_id=77, recipient_filter=rf
            )

            assert result.total == 2
            assert result.success == 2
            assert bot.copied == [1, 2]

            cursor = await db.conn.execute(
                "SELECT recipient_filter_json FROM announcement_batches WHERE id = ?",
                (result.announcement_id,),
            )
            row = await cursor.fetchone()
            assert row is not None
            assert RecipientFilter.from_json(row["recipient_filter_json"]) == rf
        finally:
            await db.close()

    asyncio.run(run())


def test_scheduled_segment_targets_pending_role_and_skips_blocked_on_send(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await _add_user(users, 1, UserRole.SUPERADMIN)
            await _add_user(users, 10, UserRole.PENDING_USER)
            await _add_user(users, 11, UserRole.PENDING_USER)
            await _add_user(users, 12, UserRole.APPROVED_USER)

            service = AnnouncementService(
                users=_Users(),  # type: ignore[arg-type]
                users_repo=users,
                announcements=AnnouncementRepository(db),
                audit=_AuditWithClock(),  # type: ignore[arg-type]
                delay_seconds=0,
            )
            rf = RecipientFilter.create(roles=("PENDING_USER",))

            batch = await service.schedule_to_all(
                actor_user_id=1,
                from_chat_id=1,
                message_id=77,
                scheduled_at="2099-01-01T00:00:00",
                recipient_filter=rf,
            )
            # Snapshot captured both pending users (approved user 12 excluded).
            assert batch.total_count == 2

            # One targeted user is blocked before the send fires.
            await users.set_role(11, UserRole.BLOCKED_USER, "now", blocked_at="now")

            bot = _Bot()
            result = await service.resume_batch(actor_user_id=1, bot=bot, announcement_id=batch.id, retry_failed=False)

            # Pending user 10 is honoured (not dropped by the approved-only re-check);
            # the now-blocked user 11 is skipped.
            assert bot.copied == [10]
            assert result.success == 1
            cursor = await db.conn.execute(
                "SELECT user_id, status FROM announcement_deliveries WHERE announcement_id = ? ORDER BY user_id",
                (batch.id,),
            )
            rows = await cursor.fetchall()
            assert [(row["user_id"], row["status"]) for row in rows] == [(10, "sent"), (11, "skipped")]
        finally:
            await db.close()

    asyncio.run(run())
