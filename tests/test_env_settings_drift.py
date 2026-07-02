"""Documentation-drift guard for environment variables.

Every environment variable that ``config/settings.py`` actually reads must be
documented in the canonical reference (``docs/configuration.md``) and, unless it
is a legacy alias, also offered in the .env.example template. This catches the
case where a new tunable is wired into settings but never surfaced to operators
(exactly how ``WARP_PING_TARGET`` slipped through once).

The doc corpus is the README plus every English doc under ``docs/`` (``.ru.md``
mirrors are excluded), so a variable documented in any of them counts.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = ROOT / "config" / "settings.py"
ENV_EXAMPLE = ROOT / ".env.example"
README = ROOT / "README.md"
DOCS = ROOT / "docs"


def _docs_corpus() -> str:
    """README + every English doc (excluding ``*.ru.md`` mirrors)."""
    parts = [README.read_text()]
    parts.extend(
        p.read_text()
        for p in sorted(DOCS.rglob("*.md"))
        if not p.name.endswith(".ru.md")
    )
    return "\n".join(parts)


# Helper calls in settings.py whose first string argument is an env var name.
_ENV_CALL = re.compile(
    r"(?:os\.getenv|_required|_optional|_int|_int_range|_optional_int_range"
    r"|_int_list_positive|_bool|_choice|_fernet_key)\(\s*\"([A-Z][A-Z0-9_]*)\""
)

# Legacy aliases: accepted for backwards compatibility, documented as aliases in
# README, intentionally NOT advertised in .env.example for new deployments.
LEGACY_ALIASES = frozenset(
    {
        "XRAY_SERVER_ADDRESS",
        "XRAY_SERVER_PORT",
        "XRAY_PUBLIC_KEY",
        "XRAY_SERVER_NAME",
        "AWG_CLIENT_DNS",
        "WARP_PROXY_EGRESS",
    }
)


def _settings_env_vars() -> set[str]:
    return set(_ENV_CALL.findall(SETTINGS.read_text()))


def test_every_setting_is_documented_in_readme() -> None:
    corpus = _docs_corpus()
    undocumented = sorted(v for v in _settings_env_vars() if v not in corpus)
    assert not undocumented, f"env vars read by settings.py but absent from README.md/docs: {undocumented}"


def test_non_alias_settings_are_in_env_example() -> None:
    env_text = ENV_EXAMPLE.read_text()
    missing = sorted(
        v
        for v in _settings_env_vars()
        if v not in LEGACY_ALIASES and v not in env_text
    )
    assert not missing, f"env vars missing from .env.example (add as commented/placeholder): {missing}"


def test_env_example_has_no_dead_variables() -> None:
    """Anything assigned in .env.example must be a real setting (or a known alias)."""
    declared = set(re.findall(r"^\s*#?\s*([A-Z][A-Z0-9_]*)=", ENV_EXAMPLE.read_text(), re.M))
    known = _settings_env_vars() | LEGACY_ALIASES
    dead = sorted(declared - known)
    assert not dead, f".env.example declares variables not read by settings.py: {dead}"
