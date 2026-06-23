"""Tests for the Telegram slash-command menu published via set_my_commands."""
import asyncio
import re
from types import SimpleNamespace

from aiogram.exceptions import TelegramAPIError
from aiogram.types import BotCommandScopeChat, BotCommandScopeDefault

import i18n
from bot.commands import _ADMIN_COMMANDS, _USER_COMMANDS, setup_bot_commands

_NAME_RE = re.compile(r"^[a-z0-9_]{1,32}$")


class _RecordingBot:
    """Captures every set_my_commands call instead of hitting Telegram."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def set_my_commands(self, commands, scope=None, language_code=None):
        self.calls.append(
            {
                "names": [c.command for c in commands],
                "descriptions": [c.description for c in commands],
                "scope": scope,
                "language_code": language_code,
            }
        )


def _settings(admin_ids, language="ru") -> SimpleNamespace:
    return SimpleNamespace(admin_ids=admin_ids, bot_language=language)


def test_command_names_are_valid_telegram_identifiers() -> None:
    for name, _ in _USER_COMMANDS + _ADMIN_COMMANDS:
        assert _NAME_RE.match(name), name


def test_description_keys_resolve_in_both_locales() -> None:
    for locale in ("ru", "en"):
        with i18n.use_locale(locale):
            for _, key in _USER_COMMANDS + _ADMIN_COMMANDS:
                text = i18n.t(key)
                # A missing key degrades to the raw identifier — guard against that.
                assert text and text != key, f"{locale}:{key}"
                assert len(text) <= 256


def test_public_scope_gets_only_user_commands() -> None:
    bot = _RecordingBot()
    asyncio.run(setup_bot_commands(bot, _settings(admin_ids=[])))

    default_calls = [c for c in bot.calls if isinstance(c["scope"], BotCommandScopeDefault)]
    # One language-agnostic fallback + one per published locale (ru, en).
    assert len(default_calls) == 3
    expected_names = [name for name, _ in _USER_COMMANDS]
    for call in default_calls:
        assert call["names"] == expected_names


def test_admin_scope_includes_admin_commands_per_admin_chat() -> None:
    bot = _RecordingBot()
    asyncio.run(setup_bot_commands(bot, _settings(admin_ids=[111, 222])))

    chat_calls = [c for c in bot.calls if isinstance(c["scope"], BotCommandScopeChat)]
    chat_ids = {c["scope"].chat_id for c in chat_calls}
    assert chat_ids == {111, 222}

    expected_names = [name for name, _ in _USER_COMMANDS + _ADMIN_COMMANDS]
    for call in chat_calls:
        assert call["names"] == expected_names
        # Privileged commands must never leak into the public default scope.
        assert "admin" in call["names"] and "warp_split_reload" in call["names"]

    for call in bot.calls:
        if isinstance(call["scope"], BotCommandScopeDefault):
            assert "admin" not in call["names"]


def test_failed_sync_is_swallowed_and_does_not_raise() -> None:
    class _FailingBot:
        async def set_my_commands(self, *args, **kwargs):
            raise TelegramAPIError(method=None, message="boom")

    # Must not raise — a failed menu sync cannot block startup.
    asyncio.run(setup_bot_commands(_FailingBot(), _settings(admin_ids=[1])))
