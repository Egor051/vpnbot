"""WarpInterface: helper argv assembly and `awg show` handshake parsing.

The privileged runner is real (it builds the "sudo -n <helper> ..." argv and
applies its path checks); the ShellRunner under it is a recorder, so nothing
is executed.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest

import warp.interface as interface_module
from adapters.privileged_helpers import PrivilegedHelperError, PrivilegedHelperRunner
from models.dto import ShellResult
from warp.interface import WarpInterface, parse_handshake_seconds

NOW = 1_767_225_600


class RecordingShell:
    def __init__(self, result: ShellResult | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.result = result or ShellResult((), 0, "", "")

    async def run(self, args: list[str], **kwargs: Any) -> ShellResult:
        self.calls.append(tuple(args))
        return self.result


def _iface(tmp_path: Path, shell: RecordingShell, *, iface_helper: Path | None = None) -> WarpInterface:
    runner = PrivilegedHelperRunner(shell=shell, use_sudo=True)  # type: ignore[arg-type]
    return WarpInterface(
        runner=runner,
        iface_helper=iface_helper or tmp_path / "vpn-bot-warp-iface",
        status_helper=tmp_path / "vpn-bot-warp-status",
        config_path=tmp_path / "out-warp.conf",
        interface_name="out-warp",
    )


# Invariant: awg-quick availability is exactly "the binary path exists".
@pytest.mark.parametrize("present", [True, False])
def test_awg_quick_available_tracks_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, present: bool) -> None:
    # Arrange
    binary = tmp_path / "awg-quick"
    if present:
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(interface_module, "AWG_QUICK_BINARY", binary)

    # Act
    available = WarpInterface.awg_quick_available()

    # Assert
    assert available is present


# Invariant: up/down pass the verb and the config path to the iface helper
# under non-interactive sudo; status passes only the interface name to the
# status helper.
async def test_helper_argv(tmp_path: Path) -> None:
    # Arrange
    shell = RecordingShell()
    iface = _iface(tmp_path, shell)
    conf = str(tmp_path / "out-warp.conf")

    # Act
    await iface.up()
    await iface.down()
    await iface.status()

    # Assert
    assert shell.calls == [
        ("sudo", "-n", str(tmp_path / "vpn-bot-warp-iface"), "up", conf),
        ("sudo", "-n", str(tmp_path / "vpn-bot-warp-iface"), "down", conf),
        ("sudo", "-n", str(tmp_path / "vpn-bot-warp-status"), "out-warp"),
    ]


# Invariant: a relative helper path never reaches sudo (defence in depth in
# the runner the interface relies on).
async def test_relative_helper_is_refused(tmp_path: Path) -> None:
    # Arrange
    shell = RecordingShell()
    iface = _iface(tmp_path, shell, iface_helper=Path("vpn-bot-warp-iface"))

    # Act / Assert
    with pytest.raises(PrivilegedHelperError, match="absolute"):
        await iface.up()
    assert shell.calls == []


# Invariant: latest_handshake() converts "N ago" into an absolute unix time.
async def test_latest_handshake_absolute_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(time, "time", lambda: float(NOW))
    shell = RecordingShell(ShellResult((), 0, "  latest handshake: 2 hours, 1 minute ago\n", ""))

    # Act
    handshake = await _iface(tmp_path, shell).latest_handshake()

    # Assert
    assert handshake == NOW - 7260


# Invariant: a failed status read, or output without a handshake line, means
# "unknown" (0) — never an exception and never "just now".
@pytest.mark.parametrize(
    "result",
    [ShellResult((), 1, "latest handshake: 1 second ago", "err"), ShellResult((), 0, "peer: x\n", "")],
)
async def test_latest_handshake_unknown(tmp_path: Path, result: ShellResult) -> None:
    # Arrange
    shell = RecordingShell(result)

    # Act
    handshake = await _iface(tmp_path, shell).latest_handshake()

    # Assert
    assert handshake == 0


# Invariant: the human-readable duration is summed across every known unit,
# singular and plural, case-insensitively.
@pytest.mark.parametrize(
    ("text", "seconds"),
    [
        ("latest handshake: 1 day, 2 hours, 3 minutes, 4 seconds ago", 86400 + 7200 + 180 + 4),
        ("latest handshake: 2 Days ago", 172800),
        ("latest handshake: 1 hour ago", 3600),
        ("latest handshake: 45 seconds ago", 45),
    ],
)
def test_parse_handshake_sums_units(text: str, seconds: int) -> None:
    # Arrange — parametrised

    # Act
    parsed = parse_handshake_seconds(text)

    # Assert
    assert parsed == seconds


# Invariant: "0 seconds ago" and a blank phrase both mean a handshake just
# happened (0).
@pytest.mark.parametrize("text", ["latest handshake: 0 seconds ago", "latest handshake: \t"])
def test_parse_handshake_zero(text: str) -> None:
    # Arrange — parametrised

    # Act
    parsed = parse_handshake_seconds(text)

    # Assert
    assert parsed == 0


# Invariant: no handshake line, or a phrase with no recognisable unit, is None
# (unknown) — unknown units are skipped, not guessed.
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("interface: out-warp\n", None),
        ("latest handshake: Now", None),
        ("latest handshake: 5 fortnights ago", None),
        ("latest handshake: 5 fortnights, 10 seconds ago", 10),
    ],
)
def test_parse_handshake_unknown_units(text: str, expected: int | None) -> None:
    # Arrange — parametrised

    # Act
    parsed = parse_handshake_seconds(text)

    # Assert
    assert parsed == expected
