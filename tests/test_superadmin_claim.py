"""The first-superadmin claim (services/superadmin_claim.py, scripts/install.sh).

The installer leaves ADMIN_IDS empty and writes /etc/vpn-bot/claim.json with only
sha256(code) and an expiry; ``/start claim_<code>`` from a private chat makes the
sender the superadmin. Every rule of the module docstring has a test here — above
all the production one: with ADMIN_IDS set the claim is inert, claim.json or not.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import services.superadmin_claim as claim_module
from adapters.clock import ClockProvider
from aiogram.enums import ChatType
from aiogram.filters import CommandObject
from bot.handlers.start import start_command
from config.settings import SettingsError, load_settings
from db.database import Database
from i18n import t
from models.dto import TelegramUserProfile
from models.enums import UserRole
from repositories.audit_log import AuditLogRepository
from repositories.claimed_superadmins import ClaimedSuperadminRepository
from repositories.users import UserRepository
from services.audit import AuditService
from services.superadmin_claim import (
    GLOBAL_ATTEMPTS,
    PER_USER_ATTEMPTS,
    ClaimOutcome,
    SuperadminClaimService,
    claim_payload,
    claim_status,
)
from services.superadmins import SuperadminSet

CODE = "Zq3x_9Lk-2mNpQ7rS1tUvW"  # 22 chars, the installer's format
NOW = 1_800_000_000.0


def _write_claim(path: Path, code: str = CODE, *, expires_at: int | None = None, mode: int = 0o600) -> None:
    payload = {
        "version": 1,
        "code_sha256": hashlib.sha256(code.encode("ascii")).hexdigest(),
        "expires_at": int(NOW) + 1800 if expires_at is None else expires_at,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(mode)


def _profile(user_id: int = 4242) -> TelegramUserProfile:
    return TelegramUserProfile(telegram_user_id=user_id, username=f"user{user_id}", first_name="Op")


class World:
    def __init__(self, db: Database, claim_path: Path, superadmins: SuperadminSet) -> None:
        self.db = db
        self.claim_path = claim_path
        self.superadmins = superadmins
        self.users = UserRepository(db)
        self.claims = ClaimedSuperadminRepository(db)
        self.audit = AuditService(AuditLogRepository(db), ClockProvider(), self.users)
        self.clock_value = NOW
        self.service = SuperadminClaimService(
            db=db,
            claims=self.claims,
            users=self.users,
            audit=self.audit,
            superadmins=superadmins,
            claim_path=claim_path,
            clock=ClockProvider(),
            wall_clock=lambda: self.clock_value,
        )

    async def claim(self, code: str = CODE, user_id: int = 4242, *, private: bool = True) -> ClaimOutcome:
        return await self.service.claim(_profile(user_id), code, private_chat=private)

    async def audit_actions(self) -> list[str]:
        rows = await self.db.conn.execute_fetchall("SELECT action FROM audit_log ORDER BY id")
        return [str(row["action"]) for row in rows]


async def _world(tmp_path: Path, configured: frozenset[int] = frozenset()) -> World:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    etc = tmp_path / "etc-vpn-bot"
    etc.mkdir(mode=0o755)
    return World(db, etc / "claim.json", SuperadminSet(configured))


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    w = await _world(tmp_path)
    try:
        yield w
    finally:
        await w.db.close()


# ── parsing the deep link ─────────────────────────────────────────────────────


def test_claim_payload_only_matches_the_claim_prefix() -> None:
    assert claim_payload("claim_abc") == "abc"
    assert claim_payload("  claim_abc ") == "abc"
    assert claim_payload("ref_abc") is None
    assert claim_payload("") is None
    assert claim_payload(None) is None


# ── the happy path ────────────────────────────────────────────────────────────


async def test_valid_claim_makes_the_sender_superadmin_and_consumes_the_file(world: World) -> None:
    _write_claim(world.claim_path)

    assert await world.claim() is ClaimOutcome.CLAIMED

    user = await world.users.get_by_id(4242)
    assert user is not None and user.role == UserRole.SUPERADMIN
    assert await world.claims.list_ids() == frozenset({4242})
    assert 4242 in world.superadmins and world.superadmins.claimed == frozenset({4242})
    assert "superadmin_claimed" in await world.audit_actions()
    assert not world.claim_path.exists()
    assert list(world.claim_path.parent.iterdir()) == [], "no consumed leftovers"


async def test_a_second_claim_is_refused_even_with_a_fresh_valid_file(world: World) -> None:
    _write_claim(world.claim_path)
    assert await world.claim(user_id=1) is ClaimOutcome.CLAIMED

    _write_claim(world.claim_path)
    assert await world.claim(user_id=2) is ClaimOutcome.REJECTED

    assert await world.claims.list_ids() == frozenset({1})
    assert world.claim_path.exists(), "an inert claim never touches the file"
    user = await world.users.get_by_id(2)
    assert user is None


# ── inert whenever a superadmin exists ────────────────────────────────────────


async def test_claim_is_inert_on_production_with_admin_ids_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADMIN_IDS set: claim.json is not even opened, whatever it contains."""
    w = await _world(tmp_path, configured=frozenset({111}))
    try:
        _write_claim(w.claim_path)
        before = w.claim_path.stat()

        def never(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("claim.json must not be read while a superadmin exists")

        monkeypatch.setattr(claim_module, "read_pending_claim", never)

        assert await w.claim() is ClaimOutcome.REJECTED

        after = w.claim_path.stat()
        assert (after.st_ino, after.st_mtime_ns, after.st_size) == (before.st_ino, before.st_mtime_ns, before.st_size)
        assert await w.claims.list_ids() == frozenset()
        assert await w.users.get_by_id(4242) is None
        assert "superadmin_claimed" not in await w.audit_actions()
    finally:
        await w.db.close()


async def test_claim_is_inert_when_the_database_already_has_a_superadmin(world: World) -> None:
    """ADMIN_IDS emptied by mistake on a live host: its superadmins are still in users."""
    await world.users.create_admin_placeholders([777], ClockProvider().now())
    _write_claim(world.claim_path)

    assert await world.claim() is ClaimOutcome.REJECTED
    assert world.claim_path.exists()
    assert await world.claims.list_ids() == frozenset()


# ── every failure is the same answer ──────────────────────────────────────────


@pytest.mark.parametrize(
    ("label", "prepare", "code"),
    [
        ("wrong code", lambda p: _write_claim(p), "AAAAAAAAAAAAAAAAAAAAAA"),
        ("expired", lambda p: _write_claim(p, expires_at=int(NOW) - 1), CODE),
        ("no claim file", lambda p: None, CODE),
        ("malformed code", lambda p: _write_claim(p), "short"),
        ("code with illegal chars", lambda p: _write_claim(p), "Zq3x 9Lk/2mNpQ7rS1tUvW"),
        ("group-readable file", lambda p: _write_claim(p, mode=0o640), CODE),
        ("garbage file", lambda p: (p.write_text("{not json", encoding="utf-8"), p.chmod(0o600)), CODE),
    ],
)
async def test_invalid_claims_are_rejected_and_change_nothing(
    world: World, label: str, prepare: Any, code: str
) -> None:
    prepare(world.claim_path)
    existed = world.claim_path.exists()

    assert await world.claim(code) is ClaimOutcome.REJECTED, label

    assert world.claim_path.exists() == existed
    assert await world.claims.list_ids() == frozenset()
    assert len(world.superadmins) == 0


async def test_symlinked_claim_file_is_refused(world: World, tmp_path: Path) -> None:
    real = tmp_path / "elsewhere.json"
    _write_claim(real)
    world.claim_path.symlink_to(real)

    assert await world.claim() is ClaimOutcome.REJECTED
    assert real.exists()


async def test_group_chat_claim_is_refused(world: World) -> None:
    _write_claim(world.claim_path)

    assert await world.claim(private=False) is ClaimOutcome.REJECTED
    assert world.claim_path.exists()


async def test_code_is_compared_with_compare_digest(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    real = claim_module.hmac.compare_digest

    def spy(a: str, b: str) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(claim_module.hmac, "compare_digest", spy)
    _write_claim(world.claim_path)

    assert await world.claim() is ClaimOutcome.CLAIMED
    assert calls == [(hashlib.sha256(CODE.encode()).hexdigest(),) * 2]


# ── rate limits ───────────────────────────────────────────────────────────────


async def test_per_user_rate_limit_blocks_even_the_right_code(world: World) -> None:
    _write_claim(world.claim_path)
    for _ in range(PER_USER_ATTEMPTS):
        assert await world.claim("B" * 22, user_id=10) is ClaimOutcome.REJECTED

    assert await world.claim(CODE, user_id=10) is ClaimOutcome.REJECTED
    assert world.claim_path.exists()
    # Another user is not affected by user 10's window.
    assert await world.claim(CODE, user_id=11) is ClaimOutcome.CLAIMED


async def test_global_rate_limit_caps_all_users_together(world: World) -> None:
    _write_claim(world.claim_path)
    for attempt in range(GLOBAL_ATTEMPTS):
        assert await world.claim("C" * 22, user_id=1000 + attempt) is ClaimOutcome.REJECTED

    assert await world.claim(CODE, user_id=9999) is ClaimOutcome.REJECTED
    assert world.claim_path.exists()


# ── atomicity ─────────────────────────────────────────────────────────────────


async def test_failed_database_write_restores_the_claim_file(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    _write_claim(world.claim_path)

    async def broken_write(**_kwargs: object) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(world.audit, "write", broken_write)

    assert await world.claim() is ClaimOutcome.REJECTED
    assert world.claim_path.exists(), "the operator can retry the same link"
    assert await world.claims.list_ids() == frozenset()
    user = await world.users.get_by_id(4242)
    assert user is None, "the role change rolled back with the claim row"
    assert len(world.superadmins) == 0
    assert [p.name for p in world.claim_path.parent.iterdir()] == ["claim.json"]

    monkeypatch.undo()
    assert await world.claim() is ClaimOutcome.CLAIMED


# ── the code never reaches a log ──────────────────────────────────────────────


async def test_the_code_is_never_logged(world: World, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    _write_claim(world.claim_path)
    await world.claim("D" * 22, user_id=5)
    world.clock_value = NOW + 10_000
    await world.claim(CODE, user_id=6)
    world.clock_value = NOW
    await world.claim(CODE, user_id=7)

    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "Superadmin claimed by user 7" in text
    assert CODE not in text and "D" * 22 not in text
    assert hashlib.sha256(CODE.encode()).hexdigest() not in text


# ── claim.json status for the startup log ─────────────────────────────────────


def test_claim_status(tmp_path: Path) -> None:
    path = tmp_path / "claim.json"
    assert claim_status(path, NOW) == "absent"
    _write_claim(path)
    assert claim_status(path, NOW) == "pending"
    assert claim_status(path, NOW + 3600) == "expired"
    path.write_text("[]", encoding="utf-8")
    path.chmod(0o600)
    assert claim_status(path, NOW) == "invalid"


# ── the /start handler ────────────────────────────────────────────────────────


class _Message:
    def __init__(self, user_id: int, chat_type: ChatType = ChatType.PRIVATE) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="op", first_name="Op", is_bot=False)
        self.chat = SimpleNamespace(id=user_id, type=chat_type)
        self.answers: list[str] = []

    async def answer(self, text: str, **_kwargs: object) -> None:
        self.answers.append(text)


class _Bot:
    def __init__(self) -> None:
        self.commands: list[object] = []

    async def set_my_commands(self, commands: object, **kwargs: object) -> None:
        self.commands.append(kwargs.get("scope"))


class _NoAccess:
    async def create_or_get_request(self, _profile: object) -> object:
        raise AssertionError("a claim must never fall through to an access request")


async def test_start_handler_failed_claim_answers_one_generic_message(world: World) -> None:
    services = SimpleNamespace(superadmin_claim=world.service, access=_NoAccess())
    message = _Message(4242)

    await start_command(
        message,  # type: ignore[arg-type]
        services,  # type: ignore[arg-type]
        _Bot(),  # type: ignore[arg-type]
        command=CommandObject(prefix="/", command="start", args="claim_" + CODE),
    )

    assert message.answers == [t("superadmin_claim_failed")]


async def test_start_handler_successful_claim_publishes_admin_menu(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write_claim(world.claim_path)
    menus: list[int] = []

    async def fake_menu_markup(_services: object, user_id: int) -> None:
        menus.append(user_id)

    monkeypatch.setattr("bot.handlers.start.main_menu_markup", fake_menu_markup)
    services = SimpleNamespace(
        superadmin_claim=world.service,
        access=_NoAccess(),
        settings=SimpleNamespace(bot_language="ru"),
    )
    message = _Message(4242)
    bot = _Bot()

    await start_command(
        message,  # type: ignore[arg-type]
        services,  # type: ignore[arg-type]
        bot,  # type: ignore[arg-type]
        command=CommandObject(prefix="/", command="start", args="claim_" + CODE),
    )

    assert message.answers[0] == t("superadmin_claim_success")
    assert menus == [4242]
    assert bot.commands, "the new superadmin gets the admin command menu at once"


# ── settings ──────────────────────────────────────────────────────────────────


def _base_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "123456:" + "A" * 35)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))


@pytest.mark.parametrize("value", [None, "", "  "])
def test_empty_or_unset_admin_ids_is_allowed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str | None
) -> None:
    _base_env(monkeypatch, tmp_path)
    if value is None:
        monkeypatch.delenv("ADMIN_IDS", raising=False)
    else:
        monkeypatch.setenv("ADMIN_IDS", value)

    assert load_settings().admin_ids == frozenset()


def test_admin_ids_placeholder_is_still_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("ADMIN_IDS", "<telegram_user_id>,<telegram_user_id>")

    with pytest.raises(SettingsError, match="ADMIN_IDS"):
        load_settings()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        ("https://bot-api.example.com/", "https://bot-api.example.com"),
        ("http://127.0.0.1:8081", "http://127.0.0.1:8081"),
        ("http://localhost:8081", "http://localhost:8081"),
        ("http://[::1]:8081", "http://[::1]:8081"),
    ],
)
def test_telegram_api_base_accepted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str, expected: str
) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("TELEGRAM_API_BASE", value)

    assert load_settings().telegram_api_base == expected


@pytest.mark.parametrize(
    "value",
    [
        "http://bot-api.example.com",  # the token would travel in clear text
        "ftp://127.0.0.1",
        "127.0.0.1:8081",
        "https://user:pw@example.com",
        "https://example.com/?x=1",
    ],
)
def test_telegram_api_base_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("TELEGRAM_API_BASE", value)

    with pytest.raises(SettingsError, match="TELEGRAM_API_BASE"):
        load_settings()


def test_the_conftest_never_lets_a_test_see_the_hosts_claim() -> None:
    import config.settings as settings_module

    assert str(settings_module.SUPERADMIN_CLAIM_PATH).startswith("/nonexistent/")

