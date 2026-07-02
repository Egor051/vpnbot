
"""Publish the bot's slash-command menu to Telegram via set_my_commands.

The handlers themselves already enforce authorization; these scopes only control
which commands Telegram *suggests* in the client's command menu. Regular users
see the public commands; superadmins additionally see the admin/WARP commands in
their own chat (BotCommandScopeChat) so privileged commands never leak into the
public menu.
"""

from __future__ import annotations

import logging

from aiogram import Bot
from aiogram.types import BotCommand, BotCommandScopeChat, BotCommandScopeDefault

from config.settings import Settings
from i18n import t, use_locale

logger = logging.getLogger(__name__)

# Locales we publish localized menus for, in addition to the bot's configured
# default locale (set without a language_code as the universal fallback).
_MENU_LOCALES: tuple[str, ...] = ("ru", "en")

# Public, user-facing commands: (command name, description i18n key).
_USER_COMMANDS: tuple[tuple[str, str], ...] = (
    ("start", "cmd_desc_start"),
    ("menu", "cmd_desc_menu"),
    ("settings", "cmd_desc_settings"),
    ("help", "cmd_desc_help"),
    ("faq", "cmd_desc_faq"),
    ("cancel", "cmd_desc_cancel"),
)

# Superadmin-only commands, appended after the public ones in the admin scope.
_ADMIN_COMMANDS: tuple[tuple[str, str], ...] = (
    ("admin", "cmd_desc_admin"),
    ("moderator", "cmd_desc_moderator"),
    ("warp_split_list", "cmd_desc_warp_split_list"),
    ("warp_split_add", "cmd_desc_warp_split_add"),
    ("warp_split_del", "cmd_desc_warp_split_del"),
    ("warp_split_reload", "cmd_desc_warp_split_reload"),
)


def _render(commands: tuple[tuple[str, str], ...], locale: str) -> list[BotCommand]:
    """Build BotCommand objects with descriptions rendered in the given locale."""
    with use_locale(locale):
        return [BotCommand(command=name, description=t(key)) for name, key in commands]


async def setup_bot_commands(bot: Bot, settings: Settings) -> None:
    """Publish the command menu to Telegram. Never raises — a failed sync is logged.

    The menu still works without this (commands can always be typed); it only adds
    the in-client suggestions. Failures must not block bot startup.
    """
    default_locale = settings.bot_language
    admin_commands = _USER_COMMANDS + _ADMIN_COMMANDS
    try:
        # Public menu: language-agnostic fallback in the configured default locale,
        # plus explicit ru/en variants so localized clients see native descriptions.
        await bot.set_my_commands(_render(_USER_COMMANDS, default_locale), scope=BotCommandScopeDefault())
        for locale in _MENU_LOCALES:
            await bot.set_my_commands(
                _render(_USER_COMMANDS, locale),
                scope=BotCommandScopeDefault(),
                language_code=locale,
            )

        # Admin menu: scoped per superadmin chat so the privileged commands never
        # appear for regular users. Telegram resolves the chat scope ahead of the
        # default one, preferring the language_code match when present.
        for admin_id in settings.admin_ids:
            scope = BotCommandScopeChat(chat_id=admin_id)
            await bot.set_my_commands(_render(admin_commands, default_locale), scope=scope)
            for locale in _MENU_LOCALES:
                await bot.set_my_commands(
                    _render(admin_commands, locale),
                    scope=scope,
                    language_code=locale,
                )
        logger.info(
            "Published bot command menu (%d public, %d admin commands for %d admin(s))",
            len(_USER_COMMANDS),
            len(admin_commands),
            len(settings.admin_ids),
        )
    except Exception:
        # Publishing the menu is best-effort and must never block startup: swallow every
        # error (Telegram API/network as well as e.g. a missing i18n key) and log it.
        logger.warning("Failed to publish bot command menu to Telegram", exc_info=True)
