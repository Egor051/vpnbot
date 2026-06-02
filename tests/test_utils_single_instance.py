
import os
from pathlib import Path

import pytest

from utils.single_instance import SingleInstanceError, SingleInstanceLock


def test_single_instance_lock_acquires_successfully(tmp_path: Path) -> None:
    lock_path = tmp_path / "test.lock"
    with SingleInstanceLock(lock_path):
        assert lock_path.exists()


def test_single_instance_lock_writes_pid(tmp_path: Path) -> None:
    lock_path = tmp_path / "test.lock"
    with SingleInstanceLock(lock_path):
        content = lock_path.read_text(encoding="utf-8").strip()
        assert content == str(os.getpid())


def test_single_instance_lock_creates_parent_dirs(tmp_path: Path) -> None:
    lock_path = tmp_path / "nested" / "dirs" / "test.lock"
    with SingleInstanceLock(lock_path):
        assert lock_path.exists()


def test_single_instance_second_lock_raises(tmp_path: Path) -> None:
    lock_path = tmp_path / "test.lock"
    with SingleInstanceLock(lock_path):
        with pytest.raises(SingleInstanceError):
            with SingleInstanceLock(lock_path):
                pass  # pragma: no cover


def test_single_instance_lock_released_after_context(tmp_path: Path) -> None:
    lock_path = tmp_path / "test.lock"
    with SingleInstanceLock(lock_path):
        pass
    # After the first context exits, acquiring again should succeed
    with SingleInstanceLock(lock_path):
        assert lock_path.exists()


def test_single_instance_error_is_runtime_error() -> None:
    assert issubclass(SingleInstanceError, RuntimeError)


def test_single_instance_non_posix_raises_without_creating_lock_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    lock_path = tmp_path / "test.lock"
    with pytest.raises(SingleInstanceError):
        with SingleInstanceLock(lock_path):
            pass  # pragma: no cover
    assert not lock_path.exists()
