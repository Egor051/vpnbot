from __future__ import annotations

from types import SimpleNamespace

from bot.middlewares.access import _is_start_command


def test_is_start_command_handles_empty_text() -> None:
    assert _is_start_command(SimpleNamespace(text=None)) is False
    assert _is_start_command(SimpleNamespace(text="")) is False
    assert _is_start_command(SimpleNamespace(text="   ")) is False


def test_is_start_command_detects_start_with_payload() -> None:
    assert _is_start_command(SimpleNamespace(text="/start")) is True
    assert _is_start_command(SimpleNamespace(text="/start payload")) is True
