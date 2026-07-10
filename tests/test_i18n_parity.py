"""Guard rails for i18n: ru/en must stay structurally identical.

These catch the classes of bug a manual review found once already:
- a key present in one locale but not the other (→ raw identifier shown to users
  in the locale that is missing it),
- a format placeholder like ``{name}`` present in one locale's string but not the
  other (→ ``KeyError`` / ``IndexError`` at ``str.format_map`` time),
- unbalanced HTML tags that would break ``parse_mode=HTML`` rendering.
"""
from __future__ import annotations

import re

import i18n
from i18n import en as en_mod
from i18n import ru as ru_mod

RU = ru_mod.STRINGS
EN = en_mod.STRINGS

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
# Matches a bare open (``<b>``) or close (``</b>``) tag; group(1) is the optional
# leading slash, group(2) the tag name.
_TAG = re.compile(r"<(/?)([a-zA-Z]+)>")


def _placeholders(text: str) -> set[str]:
    return set(_PLACEHOLDER.findall(text))


def test_key_sets_match() -> None:
    ru_keys, en_keys = set(RU), set(EN)
    missing_in_en = sorted(ru_keys - en_keys)
    missing_in_ru = sorted(en_keys - ru_keys)
    assert not missing_in_en, f"keys present in ru but missing in en: {missing_in_en}"
    assert not missing_in_ru, f"keys present in en but missing in ru: {missing_in_ru}"


def test_placeholders_match_per_key() -> None:
    mismatches = {
        key: (sorted(_placeholders(RU[key])), sorted(_placeholders(EN[key])))
        for key in RU
        if _placeholders(RU[key]) != _placeholders(EN[key])
    }
    assert not mismatches, f"placeholder drift between ru/en: {mismatches}"


def _first_tag_imbalance(value: str) -> str | None:
    """Return a description of the first tag-nesting error, or None if balanced.

    Uses a LIFO stack so *mis-nested* tags (e.g. ``<b><i>x</b></i>``) are caught,
    not merely count mismatches — a plain multiset comparison treats that broken
    string as balanced and would let a parse_mode=HTML render error through.
    """
    stack: list[str] = []
    for match in _TAG.finditer(value):
        is_close = match.group(1) == "/"
        name = match.group(2)
        if is_close:
            if not stack:
                return f"unexpected </{name}> with no matching open tag"
            top = stack.pop()
            if top != name:
                return f"</{name}> closes <{top}> (mis-nested)"
        else:
            stack.append(name)
    if stack:
        return f"unclosed tags: {stack}"
    return None


def test_html_tags_balanced() -> None:
    bad: dict[str, str] = {}
    for locale, table in (("ru", RU), ("en", EN)):
        for key, value in table.items():
            problem = _first_tag_imbalance(value)
            if problem is not None:
                bad[f"{locale}:{key}"] = problem
    assert not bad, f"unbalanced/mis-nested HTML tags: {bad}"


def test_no_empty_values() -> None:
    empties = [key for table in (RU, EN) for key, value in table.items() if not value]
    assert not empties, f"empty i18n values: {empties}"


def test_missing_key_falls_back_to_default_then_identifier() -> None:
    i18n.configure("en")
    try:
        # An unknown key returns the identifier itself (documented contract).
        assert i18n.t("totally_unknown_key_xyz") == "totally_unknown_key_xyz"
        # A real key still resolves in the active locale.
        assert i18n.t("btn_proxy") == EN["btn_proxy"]
    finally:
        i18n.configure("ru")
