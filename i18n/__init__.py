
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token

from i18n import en as _en_module
from i18n import ru as _ru_module

# Both catalogues are preloaded so the active locale can be switched per async
# task without re-importing modules. ru is the last-resort fallback so that a key
# missing from the active locale degrades to the translated default rather than
# leaking a raw identifier into the chat. Key parity is also enforced by
# tests/test_i18n_parity.py.
_CATALOGS: dict[str, dict[str, str]] = {
    "ru": dict(_ru_module.STRINGS),
    "en": dict(_en_module.STRINGS),
}
_FALLBACK_LOCALE = "ru"

# Process-wide default locale (set once at startup from BOT_LANGUAGE). Used when
# the current task has not selected a per-user locale.
_default_locale: str = _FALLBACK_LOCALE

# Per-task active locale. asyncio runs each Telegram update in its own task, so a
# ContextVar isolates concurrent users' languages without races. None means "use
# the process default" — see resolve_locale().
_current_locale: ContextVar[str | None] = ContextVar("i18n_current_locale", default=None)


def configure(locale: str) -> None:
    """Set the process-wide default locale used when no per-user locale is active."""
    global _default_locale
    _default_locale = locale if locale in _CATALOGS else _FALLBACK_LOCALE


def resolve_locale() -> str:
    """Return the effective locale for the current task."""
    locale = _current_locale.get()
    if locale is None:
        locale = _default_locale
    return locale if locale in _CATALOGS else _FALLBACK_LOCALE


def set_locale(locale: str | None) -> Token[str | None]:
    """Set the current task's locale and return a token for reset()."""
    normalized = locale if locale in _CATALOGS else None
    return _current_locale.set(normalized)


def reset_locale(token: Token[str | None]) -> None:
    """Restore the current task's locale to the value before set_locale()."""
    _current_locale.reset(token)


@contextmanager
def use_locale(locale: str | None) -> Iterator[None]:
    """Temporarily activate a locale for the current task (e.g. background jobs)."""
    token = set_locale(locale)
    try:
        yield
    finally:
        reset_locale(token)


def t(key: str, **kwargs: object) -> str:
    locale = resolve_locale()
    strings = _CATALOGS.get(locale, _CATALOGS[_FALLBACK_LOCALE])
    value = strings.get(key)
    if value is None:
        value = _CATALOGS[_default_locale].get(key) if _default_locale in _CATALOGS else None
    if value is None:
        value = _CATALOGS[_FALLBACK_LOCALE].get(key, key)
    if kwargs:
        return value.format_map(kwargs)
    return value


def all_variants(key: str) -> frozenset[str]:
    """Return every non-empty translation of *key* across all catalogues.

    Message-text filters (e.g. matching a reply-keyboard button press) are built
    once at import time, before any per-user locale is active, so a plain
    ``F.text == t(key)`` only ever matches the process-default locale. Matching
    against this set instead accepts the button in any language.
    """
    return frozenset(value for catalog in _CATALOGS.values() if (value := catalog.get(key)))
