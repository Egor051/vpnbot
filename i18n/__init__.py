
from __future__ import annotations

from i18n import ru as _ru_module

# Base catalogue (ru) used as the last-resort fallback so that a key missing from
# the active locale degrades to the translated default rather than leaking a raw
# identifier into the chat. Key parity is also enforced by tests/test_i18n_parity.py.
_DEFAULT_STRINGS: dict[str, str] = dict(_ru_module.STRINGS)
_strings: dict[str, str] = dict(_ru_module.STRINGS)


def configure(locale: str) -> None:
    global _strings
    if locale == "en":
        from i18n import en as _en
        _strings = dict(_en.STRINGS)
    else:
        from i18n import ru as _ru
        _strings = dict(_ru.STRINGS)


def t(key: str, **kwargs: object) -> str:
    value = _strings.get(key)
    if value is None:
        value = _DEFAULT_STRINGS.get(key, key)
    if kwargs:
        return value.format_map(kwargs)
    return value
