"""Management of the system ``ip route`` entries for the WARP tunnel.

The CIDRs themselves are never hardcoded here: the routes helper reads them from
``/etc/amnezia/tg-warp-routes.list`` (written by the install helper from the
user's ``AllowedIPs``). This wrapper only triggers the add/del helper actions and
never touches the default route or the DNS resolver.
"""

from __future__ import annotations

import logging
from pathlib import Path

from adapters.privileged_helpers import PrivilegedHelperRunner
from models.dto import ShellResult

logger = logging.getLogger(__name__)


class WarpRoutes:
    """Adds/removes the WARP routes via the sudo routes helper."""

    def __init__(
        self,
        *,
        runner: PrivilegedHelperRunner,
        routes_helper: Path,
        interface_name: str,
    ) -> None:
        self._runner = runner
        self._routes_helper = routes_helper
        self._interface_name = interface_name

    async def add(self) -> ShellResult:
        """Install the tunnel routes (idempotent: helper uses ``ip route replace``)."""
        return await self._runner.run(self._routes_helper, ["add", self._interface_name])

    async def remove(self) -> ShellResult:
        """Remove the tunnel routes so traffic falls back to the direct path."""
        return await self._runner.run(self._routes_helper, ["del", self._interface_name])
