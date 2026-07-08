"""Regression tests for the P7 user-interface review fixes.

Covers: localized service errors (P7-003), note input validation (P7-004),
friendly key-type labels in stats (P7-005), TTL storage not resurrecting cleared
sessions (P7-006), protocol-availability gating (P7-007), and locale-aware
blocked-user banners (P7-002).
"""
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from aiogram.enums import ChatType
from aiogram.fsm.storage.base import StorageKey
from aiogram.types import Chat, Message, User as TgUser

import i18n
from bot.fsm.ttl_storage import TTLMemoryStorage
from bot.formatters import traffic_stats_text
from bot.handlers.common import service_error_text
from bot.handlers.keys import _note_input_error, _protocol_enabled
from bot.middlewares.access import BlockedUserMiddleware
from models.dto import KeyTrafficStatsView, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from services.errors import AccessDenied
from services.notes import MAX_NOTE_LENGTH


# ── P7-003: service errors rendered in the actor's active locale ──────────────
def test_service_error_text_renders_key_in_active_locale() -> None:
    exc = AccessDenied("Нельзя смотреть чужой ключ", key="err_foreign_key_view")
    with i18n.use_locale("en"):
        assert service_error_text(exc) == i18n.t("err_foreign_key_view")
        assert service_error_text(exc) != str(exc)  # localized, not the raw ru message
    with i18n.use_locale("ru"):
        assert service_error_text(exc) == i18n.t("err_foreign_key_view")


def test_service_error_text_falls_back_to_message_without_key() -> None:
    # Un-migrated raises (no key) keep the pre-i18n behaviour: show str(exc).
    exc = AccessDenied("Некий сырой текст")
    with i18n.use_locale("en"):
        assert service_error_text(exc) == "Некий сырой текст"


# ── P7-004: note validation happens at input, with a fixable message ──────────
def test_note_input_error_rejects_too_long() -> None:
    assert _note_input_error("a" * (MAX_NOTE_LENGTH + 1)) == i18n.t("note_too_long", max=MAX_NOTE_LENGTH)


def test_note_input_error_rejects_newlines() -> None:
    assert _note_input_error("line1\nline2") == i18n.t("note_no_newlines")
    assert _note_input_error("line1\rline2") == i18n.t("note_no_newlines")


def test_note_input_error_accepts_valid_and_empty() -> None:
    assert _note_input_error("a normal note") is None
    assert _note_input_error("a" * MAX_NOTE_LENGTH) is None
    assert _note_input_error(None) is None


# ── P7-005: stats show friendly protocol labels, not the raw enum ─────────────
def _key(key_type: VpnKeyType) -> VpnKey:
    return VpnKey(
        id=10,
        owner_user_id=100,
        username="owner",
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=None,
        email_label="label",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="2026-04-28T12:00:00+00:00",
        updated_at="2026-04-28T12:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


def test_traffic_stats_uses_friendly_key_type_labels() -> None:
    xray = traffic_stats_text(KeyTrafficStatsView(key=_key(VpnKeyType.XRAY), owner=None, stats=None), viewer_user_id=100)
    assert "VLESS (TCP)" in xray
    assert "XRAY" not in xray  # the raw enum value must not leak into the UI

    awg = traffic_stats_text(KeyTrafficStatsView(key=_key(VpnKeyType.AWG), owner=None, stats=None), viewer_user_id=100)
    assert "AmneziaWG" in awg
    assert "AWG ·" not in awg


# ── P7-006: clearing a session must not resurrect it in the TTL tracker ───────
def test_ttl_storage_cleared_session_not_tracked() -> None:
    async def run() -> None:
        storage = TTLMemoryStorage(ttl_seconds=1800)
        key = StorageKey(bot_id=1, chat_id=100, user_id=100)
        await storage.set_state(key, "CreateKeyStates:waiting_note")
        await storage.set_data(key, {"key_type": "xray"})
        assert key in storage._touched
        # Mirror aiogram's FSMContext.clear(): set_state(None) then set_data({}).
        await storage.set_state(key, None)
        await storage.set_data(key, {})
        assert key not in storage._touched
        # An empty-data write must never (re-)register a session either.
        await storage.set_data(key, {})
        assert key not in storage._touched

    asyncio.run(run())


# ── P7-007: a stale/crafted create callback for a disabled protocol is gated ──
def test_protocol_enabled_honors_module_and_settings_flags() -> None:
    async def run() -> None:
        class Modules:
            def __init__(self, enabled: bool) -> None:
                self._enabled = enabled

            async def is_enabled(self, name: str) -> bool:
                return self._enabled

        off = SimpleNamespace(modules=Modules(False), settings=SimpleNamespace())
        on = SimpleNamespace(modules=Modules(True), settings=SimpleNamespace())
        assert await _protocol_enabled(off, VpnKeyType.XRAY.value) is False
        assert await _protocol_enabled(on, VpnKeyType.XRAY.value) is True
        assert await _protocol_enabled(on, VpnKeyType.AWG.value) is True

        ready = SimpleNamespace(hysteria2_enabled=True, is_hysteria2_ready=lambda: True)
        assert await _protocol_enabled(SimpleNamespace(modules=Modules(True), settings=ready), VpnKeyType.HYSTERIA2.value) is True
        not_ready = SimpleNamespace(hysteria2_enabled=False, is_hysteria2_ready=lambda: True)
        assert await _protocol_enabled(SimpleNamespace(modules=Modules(True), settings=not_ready), VpnKeyType.HYSTERIA2.value) is False
        # Unknown protocol token is never enabled.
        assert await _protocol_enabled(on, "nope") is False

    asyncio.run(run())


# ── P7-002: the blocked-user banner renders in the user's active locale ───────
def test_blocked_banner_uses_active_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    answers: list[str] = []

    async def fake_answer(self: Message, text: str, **kwargs: object) -> None:
        answers.append(text)

    monkeypatch.setattr(Message, "answer", fake_answer)

    class Users:
        async def get_user(self, telegram_user_id: int) -> User:
            return User(telegram_user_id, "blocked", "Blocked", UserRole.BLOCKED_USER, "now", "now", "now")

    async def run() -> None:
        middleware = BlockedUserMiddleware(Users())  # type: ignore[arg-type]
        user = TgUser(id=100, is_bot=False, first_name="Blocked", username="blocked")
        message = Message(
            message_id=1,
            date=datetime.now(timezone.utc),
            chat=Chat(id=100, type=ChatType.PRIVATE),
            from_user=user,
            text="hi",
        )

        async def handler(event: object, data: dict[str, object]) -> None:
            pass

        with i18n.use_locale("en"):
            await middleware(handler, message, {"event_from_user": user, "state": None})

    ru_text = i18n.t("blocked_message")  # process default is ru
    asyncio.run(run())
    assert len(answers) == 1
    assert answers[0] != ru_text
    assert "blocked" in answers[0].lower()
