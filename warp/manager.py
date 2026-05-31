"""Facade orchestrating the WARP routing module.

``WarpManager`` is the single entry point used by the bot lifecycle (startup /
shutdown hooks) and the admin-panel handlers. It owns the interface/routes
helpers, the health monitor and the persisted state, and serialises every state
transition behind one lock so concurrent admin actions can't race.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from contextlib import suppress
from pathlib import Path

from adapters.privileged_helpers import (
    PrivilegedHelperRunner,
    cleanup_staging_path,
    write_private_staging_file,
)
from adapters.shell_runner import ShellRunner
from config.settings import Settings
from db.database import Database
from models.dto import ShellResult
from repositories.warp_settings import WarpSettingsRepository
from services.errors import ServiceError
from warp.constants import PING_TARGET, ROUTES_LIST
from warp.health import HealthSnapshot, WarpHealthMonitor, ping_interface
from warp.interface import WarpInterface
from warp.routes import WarpRoutes
from warp.state import WarpState

logger = logging.getLogger(__name__)

_INSTALLED_ROUTES_RE = re.compile(r"Installed:\s*(\d+)\s+routes")


class WarpError(ServiceError):
    """User-facing WARP failure (shown verbatim in the admin panel)."""


class WarpManager:
    def __init__(self, *, db: Database, settings: Settings, shell: ShellRunner) -> None:
        self._settings = settings
        self._repo = WarpSettingsRepository(db)
        self._runner = PrivilegedHelperRunner(shell=shell, use_sudo=True)
        self._config_path = settings.warp_config_path
        self._interface_name = settings.warp_interface
        self._install_helper = settings.warp_install_helper_path
        self._staging_dir = settings.warp_helper_staging_dir
        self._interface = WarpInterface(
            runner=self._runner,
            iface_helper=settings.warp_iface_helper_path,
            status_helper=settings.warp_status_helper_path,
            config_path=self._config_path,
            interface_name=self._interface_name,
        )
        self._routes = WarpRoutes(
            runner=self._runner,
            routes_helper=settings.warp_routes_helper_path,
            interface_name=self._interface_name,
        )
        self._lock = asyncio.Lock()
        self._running = False
        self._monitor: WarpHealthMonitor | None = None
        self._last_error: str | None = None

    # ── read-only accessors ────────────────────────────────────────────────

    @property
    def last_error(self) -> str | None:
        return self._last_error

    async def is_enabled(self) -> bool:
        return (await self._repo.get()).enabled

    async def get_state(self) -> WarpState:
        """Return the current persisted state without running any new probe."""
        return await self._repo.get()

    async def reset_runtime_state(self) -> None:
        """Clear stale runtime columns on bot startup."""
        await self._repo.reset_runtime()

    # ── lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        async with self._lock:
            await self._start_locked()

    async def stop(self) -> None:
        async with self._lock:
            await self._stop_locked()

    async def enable(self) -> None:
        async with self._lock:
            await self._start_locked()
            await self._repo.set_enabled(True)

    async def disable(self) -> None:
        async with self._lock:
            await self._stop_locked()
            await self._repo.set_enabled(False)
            self._last_error = None

    async def restart(self) -> None:
        async with self._lock:
            await self._stop_locked()
            await self._start_locked()

    # ── config management ──────────────────────────────────────────────────

    async def install_config(self, config_text: str) -> int:
        """Install a validated config via the sudo helper; return the route count.

        If the module is running it is restarted so the new config takes effect
        immediately. Raises ``WarpError`` (shown to the admin) on helper failure.
        """
        async with self._lock:
            was_running = self._running
            if was_running:
                await self._stop_locked()
            try:
                routes_count = await self._run_install(config_text)
            except WarpError:
                if was_running:
                    with suppress(Exception):
                        await self._start_locked()
                raise
            await self._repo.update_config(
                config_path=str(self._config_path),
                interface_name=self._interface_name,
                routes_count=routes_count,
            )
            self._last_error = None
            logger.info("WARP config installed with %d route(s)", routes_count)
            if was_running:
                await self._start_locked()
            return routes_count

    async def delete_config(self) -> None:
        """Stop the module, disable it and forget the installed config."""
        async with self._lock:
            await self._stop_locked()
            await self._repo.set_enabled(False)
            await self._repo.clear_config()
            self._last_error = None
            logger.info("WARP config removed; module disabled")

    # ── internals (lock held) ──────────────────────────────────────────────

    async def _start_locked(self) -> None:
        if self._running:
            return
        if not WarpInterface.awg_quick_available():
            self._last_error = (
                "Бинарник awg-quick не найден. Установите AmneziaWG на сервере, "
                "чтобы использовать WARP-туннель."
            )
            logger.warning("WARP start blocked: awg-quick binary not found")
            raise WarpError(self._last_error)
        state = await self._repo.get()
        if not state.config_present:
            self._last_error = "Конфиг WARP не загружен."
            raise WarpError(self._last_error)

        # Clean up any stale interface left by a previous run before bringing it up.
        with suppress(Exception):
            await self._interface.down()
        up = await self._interface.up()
        if not up.ok:
            self._last_error = _helper_error_message(up, "Не удалось поднять интерфейс tg-warp")
            logger.warning("WARP interface up failed rc=%s: %s", up.returncode, up.stderr)
            raise WarpError(self._last_error)

        added = await self._routes.add()
        routes_active = added.ok
        if not added.ok:
            logger.warning("WARP routes add failed rc=%s: %s", added.returncode, added.stderr)

        self._last_error = None
        self._running = True
        handshake = await self._safe_handshake()
        await self._repo.update_runtime(
            tunnel_up=True,
            routes_active=routes_active,
            fail_streak=0,
            success_streak=0,
            last_handshake=handshake,
            last_check_ts=int(time.time()),
        )
        self._monitor = WarpHealthMonitor(
            ping=self._ping,
            activate_routes=self._activate_routes,
            deactivate_routes=self._deactivate_routes,
            on_update=self._on_health_update,
            initial_routes_active=routes_active,
        )
        self._monitor.start()
        logger.info(
            "WARP module started: interface up, routes %s",
            "active" if routes_active else "inactive (fallback)",
        )

    async def _stop_locked(self) -> None:
        if self._monitor is not None:
            await self._monitor.stop()
            self._monitor = None
        if self._running:
            removed = await self._routes.remove()
            if not removed.ok:
                logger.warning("WARP routes remove failed rc=%s: %s", removed.returncode, removed.stderr)
            down = await self._interface.down()
            if not down.ok:
                logger.warning("WARP interface down failed rc=%s: %s", down.returncode, down.stderr)
            logger.info("WARP module stopped: routes removed, interface down")
        self._running = False
        await self._repo.update_runtime(
            tunnel_up=False,
            routes_active=False,
            fail_streak=0,
            success_streak=0,
            last_handshake=0,
            last_check_ts=int(time.time()),
        )

    async def _run_install(self, config_text: str) -> int:
        staging_file = write_private_staging_file(
            self._staging_dir,
            prefix="warp-upload-",
            suffix=".conf",
            content=config_text,
        )
        try:
            result = await self._runner.run(self._install_helper, [str(staging_file)])
        finally:
            cleanup_staging_path(staging_file)
        if not result.ok:
            message = _helper_error_message(result, "Не удалось установить конфиг WARP")
            self._last_error = message
            logger.warning("WARP config install failed rc=%s: %s", result.returncode, result.stderr)
            raise WarpError(message)
        return _count_routes(result.stdout)

    async def _ping(self) -> bool:
        return await ping_interface(PING_TARGET, self._interface_name)

    async def _activate_routes(self) -> None:
        result = await self._routes.add()
        if not result.ok:
            logger.warning("WARP route restore failed rc=%s: %s", result.returncode, result.stderr)

    async def _deactivate_routes(self) -> None:
        result = await self._routes.remove()
        if not result.ok:
            logger.warning("WARP route removal (fallback) failed rc=%s: %s", result.returncode, result.stderr)

    async def _on_health_update(self, snapshot: HealthSnapshot) -> None:
        handshake = await self._safe_handshake() if snapshot.tunnel_up else 0
        await self._repo.update_runtime(
            tunnel_up=snapshot.tunnel_up,
            routes_active=snapshot.routes_active,
            fail_streak=snapshot.fail_streak,
            success_streak=snapshot.success_streak,
            last_handshake=handshake,
            last_check_ts=int(time.time()),
        )

    async def _safe_handshake(self) -> int:
        try:
            return await self._interface.latest_handshake()
        except Exception:
            logger.debug("WARP handshake read failed", exc_info=True)
            return 0


def _count_routes(stdout: str) -> int:
    """Count installed routes, preferring the routes.list file over helper output."""
    try:
        text = Path(ROUTES_LIST).read_text(encoding="utf-8")
    except OSError:
        text = ""
    count = sum(1 for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))
    if count:
        return count
    match = _INSTALLED_ROUTES_RE.search(stdout)
    return int(match.group(1)) if match else 0


def _helper_error_message(result: ShellResult, fallback: str) -> str:
    detail = (result.stderr or result.stdout or "").strip()
    return f"{fallback}: {detail}" if detail else fallback
