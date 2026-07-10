"""Shared pytest fixtures for CLI and integration tests."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.machinery
import importlib.util
import io
import sys
from collections.abc import Callable, Generator
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


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


async def wait_until_lock_contended(lock: asyncio.Lock, *, max_spins: int = 2000) -> None:
    """Spin the event loop until ``lock`` is held and at least one task is waiting
    to acquire it, then return.

    Deterministic replacement for ``await asyncio.sleep(0.05); assert not
    task.done()``: on a single-threaded loop a launched task runs until it blocks
    on ``lock.acquire()``, registering as a waiter. Observing that state (lock held
    + a waiter present) is race-free and needs no wall-clock delay. Raises if no
    task parks within ``max_spins`` iterations.
    """
    for _ in range(max_spins):
        await asyncio.sleep(0)
        if lock.locked() and lock._waiters:  # type: ignore[attr-defined]
            return
    raise AssertionError("no task parked on the lock")


async def wait_until_write_parked(db: object, *, max_spins: int = 2000) -> None:
    """Convenience wrapper: wait until a competing write/read has parked on the
    ``Database`` transaction serialization lock."""
    await wait_until_lock_contended(db._transaction_lock, max_spins=max_spins)  # type: ignore[attr-defined]
