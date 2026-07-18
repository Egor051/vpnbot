"""Guards for the test-only Settings env isolation (`_isolate_settings_env` in
conftest.py).

The production settings loader auto-discovers a `.env` from the cwd and reads
`os.environ`; that is correct in production but makes tests non-deterministic on a
host where the live `/opt/vpn-service/.env` (and exported prod vars) are present —
a host-leak class that is green in clean CI and red on the box. These tests pin the
isolation from both sides so it can neither regress (leak again) nor over-reach
(blind the loader to values a test sets on purpose).
"""
from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import pytest

from config.settings import load_settings


# Simulate the box: prod control vars exported into the AMBIENT environment. This is
# module-scoped so it runs BEFORE the function-scoped `_isolate_settings_env` — i.e.
# the vars are already present when the isolation runs, exactly like a real host
# export (a value set in a test *body* would run after the isolation and so would be
# an EXPLICIT var, not an ambient one). The isolation must strip these.
_AMBIENT = {"SOCKS5_ENABLED": "true", "SOCKS5_HOST": "203.0.113.9", "HYSTERIA2_PORT": "50000"}


@pytest.fixture(autouse=True, scope="module")
def _simulate_ambient_prod_export() -> Generator[None, None, None]:
    saved = {k: os.environ.get(k) for k in _AMBIENT}
    os.environ.update(_AMBIENT)
    try:
        yield
    finally:
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _minimal_required(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))


def test_build_ignores_ambient_prod_env_vars(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The ambient SOCKS5_ENABLED=true / HYSTERIA2_PORT=50000 exported before the
    isolation ran must NOT reach the build — the result is host-independent."""
    _minimal_required(monkeypatch, tmp_path)

    settings = load_settings()

    assert settings.socks5_enabled is False          # ambient true was stripped
    assert settings.socks5_host == ""                # ambient 203.0.113.9 was stripped
    assert settings.hysteria2_port == 443            # default, not the ambient 50000


def test_build_ignores_auto_discovered_dotenv_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A discoverable `.env` carrying deliberately foreign values must NOT leak into
    a test Settings build — this is exactly the prod `/opt/vpn-service/.env` leak."""
    (tmp_path / ".env").write_text(
        "SOCKS5_ENABLED=true\nSOCKS5_HOST=198.51.100.7\nHYSTERIA2_PORT=40000\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    _minimal_required(monkeypatch, tmp_path)

    settings = load_settings()  # no explicit path -> would auto-discover the .env above

    assert settings.socks5_enabled is False          # default, not the file's true
    assert settings.socks5_host == ""                # default, not 198.51.100.7
    assert settings.hysteria2_port == 443            # default, not 40000


def test_isolation_does_not_blind_loader_to_explicit_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The isolation must not make "loader reads X from the environment" falsely
    green: a value the test sets explicitly (after the autouse fixture ran) still
    takes effect — even when the same var was ambient before."""
    _minimal_required(monkeypatch, tmp_path)
    # 34567 is neither the HYSTERIA2_PORT default (443) nor any other
    # project-significant port (51820 is the WARP policy table, not a port) —
    # a value that only proves "explicit env wins" if it differs from both the
    # default and the _AMBIENT value above.
    monkeypatch.setenv("HYSTERIA2_PORT", "34567")
    monkeypatch.setenv("SOCKS5_ENABLED", "true")
    monkeypatch.setenv("SOCKS5_HOST", "10.0.0.5")
    monkeypatch.setenv("SOCKS5_PORT", "1080")

    settings = load_settings()

    assert settings.hysteria2_port == 34567
    assert settings.socks5_enabled is True
    assert settings.socks5_host == "10.0.0.5"


def test_isolation_still_honours_explicit_env_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Blocking auto-discovery must not block an EXPLICIT env_path: tests that
    exercise real .env-file parsing must still read the file they name."""
    env_file = tmp_path / "custom.env"
    env_file.write_text("HYSTERIA2_PORT=8443\n", encoding="utf-8")
    _minimal_required(monkeypatch, tmp_path)

    settings = load_settings(env_path=str(env_file))

    assert settings.hysteria2_port == 8443


def test_hy2_auth_load_config_does_not_pollute_os_environ() -> None:
    """``hy2_auth/config.py`` has its own independent ``load_dotenv()`` call (it
    cannot import config.settings — see its module docstring) and is a SEPARATE
    leak surface from ``config.settings.load_settings()``. Left unpatched, a single
    test that reaches ``load_config()`` permanently pollutes ``os.environ`` with the
    live ``.env`` for every test that runs afterward in the session — this is
    exactly how ANOMALY_HYSTERIA2_MAX_CONN / HYSTERIA2_STATS_SECRET from the box's
    real .env were observed leaking into unrelated later tests and failing them."""
    import hy2_auth.config as hy2_auth_config_module

    before = dict(os.environ)
    hy2_auth_config_module.load_config({})
    after = dict(os.environ)

    assert after == before, "load_config() must not mutate os.environ under test isolation"
