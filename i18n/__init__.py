
from __future__ import annotations

from i18n import ru as _ru_module

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
    value = _strings.get(key, key)
    if kwargs:
        return value.format_map(kwargs)
    return value
