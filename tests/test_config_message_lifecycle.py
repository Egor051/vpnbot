
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import CallbackQuery, Chat, Message, User as TgUser

from bot.handlers.keys import show_key_config
from bot.messages import (
    config_document_present,
    discard_config_document,
    remember_config_document,
)
from bot.middlewares.config_cleanup import ConfigDocumentCleanupMiddleware
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType

_TOKEN = "123456789:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQRS"


def _awg_key(key_id: int = 10, owner_user_id: int = 100) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=owner_user_id,
        username="user",
        key_type=VpnKeyType.AWG,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=None,
        email_label="awg_A7kQz",
        public_key="public",
        client_ip="10.0.0.2",
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=owner_user_id,
        revoked_by=None,
        deleted_by=None,
    )


class _Message:
    def __init__(self) -> None:
        self.chat = SimpleNamespace(id=100)
        self.documents: list[object] = []
        self._next_id = 555

    async def answer_document(self, document: object, **kwargs: object) -> SimpleNamespace:
        self.documents.append(document)
        sent = SimpleNamespace(message_id=self._next_id)
        self._next_id += 1
        return sent


class _Callback:
    def __init__(self, data: str, user_id: int = 100) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="user", first_name="User")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _RateLimiter:
    def check(self, *args: object) -> None:
        return None


def _make_state() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=100, user_id=100))


# ── helper-level coverage ─────────────────────────────────────────────────────


def test_remember_and_discard_config_document() -> None:
    deleted: list[tuple[int, int]] = []

    class FakeBot:
        async def delete_message(self, chat_id: int, message_id: int) -> None:
            deleted.append((chat_id, message_id))

    async def run() -> None:
        state = _make_state()
        assert await config_document_present(state, 10) is False

        await remember_config_document(state, key_id=10, message_id=777)
        assert await config_document_present(state, 10) is True
        # A different key must not match the tracked file.
        assert await config_document_present(state, 11) is False

        await discard_config_document(state, FakeBot(), chat_id=100)  # type: ignore[arg-type]
        assert deleted == [(100, 777)]
        assert await config_document_present(state, 10) is False

        # Discarding again is a no-op (nothing tracked).
        await discard_config_document(state, FakeBot(), chat_id=100)  # type: ignore[arg-type]
        assert deleted == [(100, 777)]

    asyncio.run(run())


# ── show_key_config: feature 1 (no duplicate file) ────────────────────────────


def test_show_config_sends_once_then_skips_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow_private(callback: object) -> bool:
        return True

    edits: list[str] = []

    async def fake_edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", allow_private)
    monkeypatch.setattr("bot.handlers.keys.safe_edit_message_text", fake_edit)
    monkeypatch.setattr("bot.handlers.keys.awg_config_text", lambda cfg: "awg config text")

    class Awg:
        def __init__(self) -> None:
            self.plain_calls = 0

        async def get_awg_client_config(self, actor_user_id: int, key_id: int) -> str:
            return "formatted"

        async def get_awg_client_config_plain(self, actor_user_id: int, key_id: int) -> str:
            self.plain_calls += 1
            return "PLAIN-CONFIG"

    class VpnKeys:
        async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
            return _awg_key(key_id)

    async def run() -> None:
        awg = Awg()
        services = SimpleNamespace(vpn_keys=VpnKeys(), awg=awg, xray=SimpleNamespace())
        state = _make_state()
        callback = _Callback("key:show:10")

        # First press: file is delivered and tracked.
        await show_key_config(callback, state, services, _RateLimiter(), None)  # type: ignore[arg-type]
        assert len(callback.message.documents) == 1
        assert awg.plain_calls == 1
        assert await config_document_present(state, 10) is True

        # Second press on the same key: no duplicate file, user gets a toast.
        await show_key_config(callback, state, services, _RateLimiter(), None)  # type: ignore[arg-type]
        assert len(callback.message.documents) == 1
        assert awg.plain_calls == 1
        assert callback.answers[-1][0] == "Файл конфигурации уже отправлен."

    asyncio.run(run())


# ── feature 2: cleanup middleware ─────────────────────────────────────────────


def _callback_query(data: str) -> CallbackQuery:
    chat = Chat(id=100, type="private")
    message = Message(message_id=1, date=datetime.now(timezone.utc), chat=chat)
    return CallbackQuery(
        id="cq",
        from_user=TgUser(id=100, is_bot=False, first_name="User"),
        chat_instance="instance",
        message=message,
        data=data,
    )


def test_cleanup_middleware_deletes_file_on_other_button(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        bot = Bot(_TOKEN)
        try:
            deleted: list[int] = []

            async def fake_delete(chat_id: int, message_id: int, **kwargs: object) -> bool:
                deleted.append(message_id)
                return True

            monkeypatch.setattr(bot, "delete_message", fake_delete)
            state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=bot.id, chat_id=100, user_id=100))
            await remember_config_document(state, key_id=10, message_id=999)

            middleware = ConfigDocumentCleanupMiddleware()
            handled: list[str] = []

            async def handler(event: object, data: dict[str, object]) -> str:
                handled.append("ran")
                return "ok"

            # A non-"show config" button deletes the tracked file before handling.
            result = await middleware(handler, _callback_query("key:stats:10"), {"state": state, "bot": bot})
            assert result == "ok"
            assert handled == ["ran"]
            assert deleted == [999]
            assert await config_document_present(state, 10) is False
        finally:
            await bot.session.close()

    asyncio.run(run())


def test_cleanup_middleware_keeps_file_on_show_config(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        bot = Bot(_TOKEN)
        try:
            deleted: list[int] = []

            async def fake_delete(chat_id: int, message_id: int, **kwargs: object) -> bool:
                deleted.append(message_id)
                return True

            monkeypatch.setattr(bot, "delete_message", fake_delete)
            state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=bot.id, chat_id=100, user_id=100))
            await remember_config_document(state, key_id=10, message_id=999)

            middleware = ConfigDocumentCleanupMiddleware()

            async def handler(event: object, data: dict[str, object]) -> str:
                return "ok"

            # Tapping "show config" must NOT delete the file it may reuse.
            await middleware(handler, _callback_query("key:show:10"), {"state": state, "bot": bot})
            assert deleted == []
            assert await config_document_present(state, 10) is True
        finally:
            await bot.session.close()

    asyncio.run(run())
