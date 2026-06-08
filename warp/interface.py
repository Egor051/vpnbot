"""Control of the ``out-warp`` AmneziaWG interface through sudo helpers.

The bot never runs ``awg-quick``/``awg`` directly; it invokes fixed sudo helper
scripts. This wrapper only assembles the helper calls and parses the ``awg show``
output for the latest handshake age.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from adapters.privileged_helpers import PrivilegedHelperRunner
from models.dto import ShellResult

logger = logging.getLogger(__name__)

# Path the iface helper execs. Used only for a presence check so the module can
# block with a clear error when AmneziaWG is not installed.
AWG_QUICK_BINARY = Path("/usr/bin/awg-quick")

_HANDSHAKE_RE = re.compile(r"latest handshake:\s*(.+)")
_DURATION_UNITS = {
    "day": 86400,
    "days": 86400,
    "hour": 3600,
    "hours": 3600,
    "minute": 60,
    "minutes": 60,
    "second": 1,
    "seconds": 1,
}


class WarpInterface:
    """Brings the WARP interface up/down and reads its status via sudo helpers."""

    def __init__(
        self,
        *,
        runner: PrivilegedHelperRunner,
        iface_helper: Path,
        status_helper: Path,
        config_path: Path,
        interface_name: str,
    ) -> None:
        self._runner = runner
        self._iface_helper = iface_helper
        self._status_helper = status_helper
        self._config_path = config_path
        self._interface_name = interface_name

    @staticmethod
    def awg_quick_available() -> bool:
        """Return whether the awg-quick binary is installed on the host."""
        return AWG_QUICK_BINARY.exists()

    async def up(self) -> ShellResult:
        return await self._runner.run(self._iface_helper, ["up", str(self._config_path)])

    async def down(self) -> ShellResult:
        return await self._runner.run(self._iface_helper, ["down", str(self._config_path)])

    async def status(self) -> ShellResult:
        return await self._runner.run(self._status_helper, [self._interface_name])

    async def latest_handshake(self) -> int:
        """Return the unix timestamp of the latest handshake, or 0 if unknown."""
        result = await self.status()
        if not result.ok:
            return 0
        ago = parse_handshake_seconds(result.stdout)
        if ago is None:
            return 0
        return int(time.time()) - ago


def parse_handshake_seconds(awg_show_output: str) -> int | None:
    """Parse ``awg show`` output into "seconds since latest handshake".

    Handles the human-readable form, e.g. ``latest handshake: 1 minute, 5
    seconds ago``. Returns ``None`` when no handshake line is present.
    """
    match = _HANDSHAKE_RE.search(awg_show_output)
    if match is None:
        return None
    phrase = match.group(1).strip()
    if not phrase or phrase.lower().startswith("0 second"):
        return 0
    total = 0
    found = False
    for amount, unit in re.findall(r"(\d+)\s*([A-Za-z]+)", phrase):
        seconds = _DURATION_UNITS.get(unit.lower())
        if seconds is None:
            continue
        total += int(amount) * seconds
        found = True
    return total if found else None
