"""Shared pytest fixtures for CLI and integration tests."""
from __future__ import annotations

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
