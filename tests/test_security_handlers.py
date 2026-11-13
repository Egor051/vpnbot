"""«🔐 Безопасность» end to end (bot/handlers/security.py over a real TotpService).

Enabling: QR + secret are sent → the typed code is deleted → the secret and QR
messages are deleted → the backup codes are shown once with «Я сохранил коды» →
pressing it deletes them. Disabling needs a code; reissuing needs a TOTP code.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage

from adapters.clock import ClockProvider
from bot.fsm.states import TotpStates
from bot.handlers import security
from db.database import Database
from repositories.audit_log import AuditLogRepository
from repositories.totp import TotpRepository
from repositories.users import UserRepository
from services.audit import AuditService
from services.totp import TotpKeyFile, TotpService
from utils import totp as otp

UID = 4242
pytestmark = pytest.mark.timeout(60)


class Clock:
    t = 1_700_000_000.0
    mono = 0.0


@dataclass
class Sent:
    message_id: int


class Bot:
    def __init__(self) -> None:
        self.n = 100
        self.photos: list[int] = []
        self.texts: dict[int, str] = {}
        self.markups: dict[int, Any] = {}
        self.deleted: list[int] = []
        self.edited: list[tuple[int, str]] = []

    async def send_photo(self, chat_id: int, photo: Any, caption: str = "", **_: Any) -> Sent:
        self.n += 1
        self.photos.append(self.n)
        return Sent(self.n)

    async def send_message(self, chat_id: int, text: str, reply_markup: Any = None, **_: Any) -> Sent:
        self.n += 1
        self.texts[self.n] = text
        self.markups[self.n] = reply_markup
        return Sent(self.n)

    async def delete_message(self, chat_id: int, message_id: int) -> None:
        self.deleted.append(message_id)

    async def edit_message_text(self, text: str, *, chat_id: int, message_id: int, reply_markup: Any = None) -> None:
        self.edited.append((message_id, text))


class Msg:
    def __init__(self, text: str = "", message_id: int = 1, bot: Bot | None = None) -> None:
        self.text = text
        self.message_id = message_id
        self.chat = SimpleNamespace(id=UID, type="private")
        self.from_user = SimpleNamespace(id=UID, username="alice")
        self.deleted = False
        self.bot = bot
        self.edits: list[str] = []

    async def delete(self) -> None:
        self.deleted = True

    async def edit_text(self, text: str, reply_markup: Any = None, **_: Any) -> None:
        self.edits.append(text)


class Callback:
    def __init__(self, data: str, bot: Bot) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=UID, username="alice")
        self.message = Msg(message_id=50)
        self.bot = bot
        self.alerts: list[tuple[str | None, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **_: Any) -> None:
        self.alerts.append((text, show_alert))


class Users:
    async def require_superadmin(self, user_id: int) -> object:
        return object()


@pytest.fixture(autouse=True)
def _private(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(*_: Any) -> bool:
        return True

    async def edit(message: Any, text: str, **_: Any) -> bool:
        message.edits.append(text)
        return True

    monkeypatch.setattr(security, "ensure_private_callback", ok)
    monkeypatch.setattr(security, "safe_edit_message_text", edit)


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[tuple[Any, Bot, FSMContext]]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, role, created_at, updated_at) VALUES (?, 'SUPERADMIN', 'x', 'x')", (UID,)
    )
    await db.commit()
    totp = TotpService(
        repo=TotpRepository(db),
        audit=AuditService(AuditLogRepository(db), ClockProvider(), UserRepository(db)),
        clock=ClockProvider(),
        key_file=TotpKeyFile(tmp_path / "totp.key"),
        now=lambda: Clock.t,
        monotonic=lambda: Clock.mono,
    )
    state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=UID, user_id=UID))
    try:
        yield SimpleNamespace(totp=totp, users=Users()), Bot(), state
    finally:
        await db.close()


def _secret(bot: Bot) -> bytes:
    text = next(t for t in bot.texts.values() if "otpauth://" in t)
    match = re.search(r"secret=([A-Z2-7]+)", text)
    assert match is not None
    return otp.decode_secret(match.group(1))


async def test_enable_flow_deletes_every_secret_message(world: tuple[Any, Bot, FSMContext]) -> None:
    services, bot, state = world
    await security.totp_enable_start(Callback("sec:totp:on", bot), state, services, bot)  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.enroll_code.state
    assert len(bot.photos) == 1  # the QR
    secret_msgs = [*bot.photos, *[i for i, t in bot.texts.items() if "otpauth://" in t]]
    key = _secret(bot)

    wrong = Msg("000000" if otp.totp(key, Clock.t) != "000000" else "111111")
    await security.totp_enroll_code(wrong, state, services, bot)  # type: ignore[arg-type]
    assert wrong.deleted and await state.get_state() == TotpStates.enroll_code.state
    assert not await services.totp.is_enabled(UID)

    code = Msg(otp.totp(key, Clock.t))
    await security.totp_enroll_code(code, state, services, bot)  # type: ignore[arg-type]
    assert code.deleted
    assert await state.get_state() is None
    assert await services.totp.is_enabled(UID)
    assert set(secret_msgs) <= set(bot.deleted)
    codes_id = max(bot.texts)
    codes = re.findall(r"<code>([a-z2-9]{5}-[a-z2-9]{5})</code>", bot.texts[codes_id])
    assert len(codes) == 10
    assert [b.callback_data for r in bot.markups[codes_id].inline_keyboard for b in r] == ["sec:codes:saved"]

    saved = Callback("sec:codes:saved", bot)
    saved.message = Msg(message_id=codes_id)
    await security.totp_codes_saved(saved, services)  # type: ignore[arg-type]
    assert saved.message.deleted


async def test_cancel_enrollment_deletes_the_secret(world: tuple[Any, Bot, FSMContext]) -> None:
    services, bot, state = world
    await security.totp_enable_start(Callback("sec:totp:on", bot), state, services, bot)  # type: ignore[arg-type]
    sent = [*bot.photos, *bot.texts]
    await security.totp_enable_cancel(Callback("sec:totp:cancel", bot), state, services, bot)  # type: ignore[arg-type]
    assert set(sent) <= set(bot.deleted) and await state.get_state() is None
    assert (await services.totp.status(UID)).enabled is False


async def test_reissue_then_disable(world: tuple[Any, Bot, FSMContext]) -> None:
    services, bot, state = world
    await security.totp_enable_start(Callback("sec:totp:on", bot), state, services, bot)  # type: ignore[arg-type]
    key = _secret(bot)
    await security.totp_enroll_code(Msg(otp.totp(key, Clock.t)), state, services, bot)  # type: ignore[arg-type]
    old_codes = re.findall(r"<code>([a-z2-9]{5}-[a-z2-9]{5})</code>", bot.texts[max(bot.texts)])

    await security.totp_code_prompt(Callback("sec:totp:codes", bot), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.reissue_code.state
    backup = Msg(old_codes[0])
    await security.totp_reissue_code(backup, state, services, bot)  # type: ignore[arg-type]
    assert backup.deleted and await state.get_state() == TotpStates.reissue_code.state  # a backup code is not enough
    Clock.t += 30
    await security.totp_reissue_code(Msg(otp.totp(key, Clock.t)), state, services, bot)  # type: ignore[arg-type]
    new_codes = re.findall(r"<code>([a-z2-9]{5}-[a-z2-9]{5})</code>", bot.texts[max(bot.texts)])
    assert len(new_codes) == 10 and not set(new_codes) & set(old_codes)

    await security.totp_code_prompt(Callback("sec:totp:off", bot), state, services)  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.disable_code.state
    await security.totp_disable_code(Msg(new_codes[0]), state, services, bot)  # type: ignore[arg-type]
    assert not await services.totp.is_enabled(UID)
    assert await state.get_state() is None


async def test_security_menu_reflects_the_state(world: tuple[Any, Bot, FSMContext]) -> None:
    services, bot, state = world
    _text, markup = await security.security_view(services.totp, UID)
    assert [b.callback_data for r in markup.inline_keyboard for b in r] == ["sec:totp:on", "admin:panel"]
    cb = Callback("sec:menu", bot)
    await security.security_menu(cb, state, services)  # type: ignore[arg-type]
    assert cb.message.edits
