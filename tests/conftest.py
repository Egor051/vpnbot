"""Shared pytest fixtures for CLI and integration tests."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
from collections.abc import Callable, Generator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Prod env-var families the settings loader reads. In tests a Settings build must
# come only from what the test sets explicitly (monkeypatch.setenv or an explicit
# env_path), NEVER from the host's ambient environment or the production
# /opt/vpn-service/.env that python-dotenv would auto-discover from the cwd. See
# _isolate_settings_env below. ANOMALY_ is included because
# ANOMALY_HYSTERIA2_MAX_CONN cross-validates against HYSTERIA2_STATS_SECRET (a
# Hysteria2-family value) — the two must be cleared together or a leaked
# HYSTERIA2_STATS_SECRET-less-but-ANOMALY_HYSTERIA2_MAX_CONN-set combination raises
# a spurious SettingsError.
_ISOLATED_ENV_PREFIXES: tuple[str, ...] = (
    "HYSTERIA2_",
    "SOCKS5_",
    "XRAY_",
    "MTPROTO_",
    "WARP_",
    "ANOMALY_",
)


@pytest.fixture(autouse=True)
def _isolate_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Settings construction deterministic and host-independent.

    Two leaks, both a host-only class (cf. #239/#241/#242 — green in clean CI, red
    on the box, because the box's live state bleeds in):

    1. ``load_settings()`` with no explicit path calls ``load_dotenv(None)``, which
       walks up from the cwd (``/opt/vpn-service`` in the test run) and slurps the
       **production** ``.env`` into ``os.environ`` — so a test that carefully
       ``delenv``'d ``SOCKS5_ENABLED`` gets it (and every other prod value) handed
       right back. We block ONLY dotenv auto-discovery: an **explicit** ``env_path``
       (used by tests that genuinely exercise .env-file parsing) is still honoured.
       ``hy2_auth/config.py`` has its own independent ``load_dotenv()`` call (it
       cannot import config.settings — see its module docstring) and must be
       blocked the same way, or a single test that reaches it (e.g.
       ``test_hy2_auth.py``) permanently pollutes ``os.environ`` with the live
       ``.env`` for every test that runs afterward in the same session — this is
       exactly how ``ANOMALY_HYSTERIA2_MAX_CONN``/``HYSTERIA2_STATS_SECRET`` from
       the box's real ``.env`` were observed leaking into unrelated later tests.

    2. Any of the prod control-var families already exported in the ambient
       environment would likewise leak. We strip them up-front so each test starts
       from the documented defaults.

    This is deliberately narrow. It does NOT stop the loader from reading the
    environment: a test that sets a var (this autouse fixture runs *before* the
    test body's ``monkeypatch.setenv``) still sees it, so "the loader reads X from
    the environment" tests keep their teeth.
    """
    for key in list(os.environ):
        if key.startswith(_ISOLATED_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)

    import dotenv

    real_dotenv_load_dotenv = dotenv.load_dotenv

    def _no_autodiscovery_load_dotenv(dotenv_path: Any = None, *args: Any, **kwargs: Any) -> bool:
        # Falsy path == python-dotenv auto-discovery (the prod-.env leak): no-op,
        # mirroring load_dotenv's "nothing loaded" return. An explicit path is
        # forwarded to the real loader untouched.
        if not dotenv_path:
            return False
        return bool(real_dotenv_load_dotenv(dotenv_path, *args, **kwargs))

    # Patch every module-local `load_dotenv` name bound via `from dotenv import
    # load_dotenv` — patching the `dotenv` package attribute alone would not reach
    # these, since `from ... import ...` copies the reference at import time.
    import config.settings as settings_module
    import hy2_auth.config as hy2_auth_config_module

    monkeypatch.setattr(settings_module, "load_dotenv", _no_autodiscovery_load_dotenv)
    monkeypatch.setattr(hy2_auth_config_module, "load_dotenv", _no_autodiscovery_load_dotenv)


def _load_module(module_name: str, path: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@contextlib.contextmanager
def _capture_stdout() -> Generator[io.StringIO, None, None]:
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old_stdout


@pytest.fixture
def checker() -> ModuleType:
    """Load check-nonroot-helper-mode.py CLI script as a fresh module per test."""
    return _load_module("check_nonroot", ROOT / "deploy" / "check-nonroot-helper-mode.py")


@pytest.fixture
def load_helper() -> Callable[[str], ModuleType]:
    """Factory fixture: call with a helper script name to get a fresh module."""
    def _load(name: str) -> ModuleType:
        return _load_module(name.replace("-", "_"), ROOT / "deploy" / "helpers" / name)
    return _load


@pytest.fixture
def captured_cli_output() -> Callable[[], contextlib.AbstractContextManager[io.StringIO]]:
    """Fixture providing a context manager that captures sys.stdout during CLI calls."""
    return _capture_stdout


@pytest.fixture(autouse=True)
def _isolate_i18n_locale() -> Generator[None, None, None]:
    """Restore global i18n locale state after every test.

    ``i18n.configure()`` mutates the process-wide default locale (a module global)
    and ``i18n.set_locale()`` mutates a ContextVar; tests that switch locale would
    otherwise leak that choice into later tests via collection order. Snapshot the
    default on entry and reset both on teardown so each test starts from a clean,
    order-independent locale state.
    """
    import i18n

    default_before = i18n._default_locale
    try:
        yield
    finally:
        i18n._default_locale = default_before
        i18n._current_locale.set(None)


async def wait_until_lock_contended(lock: asyncio.Lock, *, timeout: float = 5.0) -> None:
    """Wait until ``lock`` is held and at least one task is waiting to acquire it,
    then return.

    Preferred over ``await asyncio.sleep(0.05); assert not task.done()``: it
    returns the instant the contended state is observed (lock held + a waiter
    present), which is race-free, and only ever blocks until that happens.

    A launched task parks on ``lock.acquire()`` only after any *preceding* awaits
    resolve. Some of those awaits (e.g. aiosqlite queries) complete on a worker
    thread and therefore need wall-clock time, not just event-loop turns — so a
    fixed number of ``asyncio.sleep(0)`` spins can exhaust its budget in
    microseconds before the thread finishes and the task ever reaches the lock,
    which made this flaky on loaded CI runners. Poll against a wall-clock
    ``timeout`` instead, yielding briefly between checks. Raises if no task parks
    within ``timeout`` seconds.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if lock.locked() and lock._waiters:  # type: ignore[attr-defined]
            return
        if loop.time() >= deadline:
            raise AssertionError("no task parked on the lock")
        await asyncio.sleep(0.001)


async def wait_until_write_parked(db: object, *, timeout: float = 5.0) -> None:
    """Convenience wrapper: wait until a competing write/read has parked on the
    ``Database`` transaction serialization lock."""
    await wait_until_lock_contended(db._transaction_lock, timeout=timeout)  # type: ignore[attr-defined]
