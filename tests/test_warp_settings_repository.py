"""WarpSettingsRepository against a real bootstrapped SQLite database.

The table is a singleton (id = 1) seeded by schema.sql. Every write stamps
``updated_at`` from ``time.time()``; the tests pin that clock so the stamp is
asserted exactly instead of "> 0".
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

import repositories.warp_settings as warp_settings_module
from db.database import Database
from repositories.warp_settings import WarpSettingsRepository
from warp.state import WarpState

FROZEN_TS = 1_767_225_600  # 2026-01-01T00:00:00Z


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "vpn.db")
    await database.connect()
    await database.bootstrap()
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(warp_settings_module.time, "time", lambda: float(FROZEN_TS))
    return FROZEN_TS


# Invariant: a freshly bootstrapped database reads back as the WarpState
# defaults (the schema.sql DEFAULTs and the dataclass defaults agree).
async def test_get_on_fresh_db_matches_dataclass_defaults(db: Database) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)

    # Act
    state = await repo.get()

    # Assert
    assert state == WarpState()


# Invariant: if the singleton row is missing (hand-deleted), get() degrades to
# the defaults instead of raising.
async def test_get_without_row_returns_defaults(db: Database) -> None:
    # Arrange
    await db.conn.execute("DELETE FROM warp_settings")
    await db.commit()

    # Act
    state = await WarpSettingsRepository(db).get()

    # Assert
    assert state == WarpState()


# Invariant: set_enabled() toggles only `enabled` (both directions) and stamps
# updated_at.
async def test_set_enabled_toggles_and_stamps(db: Database, frozen_clock: int) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)

    # Act
    await repo.set_enabled(True)
    on = await repo.get()
    await repo.set_enabled(False)
    off = await repo.get()

    # Assert
    assert on.enabled is True and on.updated_at == frozen_clock
    assert off.enabled is False
    assert off.kill_switch is False and off.config_installed is False


# Invariant: set_kill_switch() toggles only `kill_switch` and leaves `enabled`
# untouched.
async def test_set_kill_switch_is_independent_of_enabled(db: Database, frozen_clock: int) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)
    await repo.set_enabled(True)

    # Act
    await repo.set_kill_switch(True)
    on = await repo.get()
    await repo.set_kill_switch(False)
    off = await repo.get()

    # Assert
    assert on.kill_switch is True and on.enabled is True and on.updated_at == frozen_clock
    assert off.kill_switch is False and off.enabled is True


# Invariant: update_config() records path/interface/routes AND sets
# config_installed=1 — even for a zero-route (full-tunnel) config, which is the
# case the flag exists for.
async def test_update_config_marks_installed_even_with_zero_routes(db: Database, frozen_clock: int) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)

    # Act
    await repo.update_config(config_path="/etc/amnezia/x.conf", interface_name="wx", routes_count=0)
    state = await repo.get()

    # Assert
    assert (state.config_path, state.interface_name, state.routes_count) == ("/etc/amnezia/x.conf", "wx", 0)
    assert state.config_installed is True
    assert state.config_present is True
    assert state.updated_at == frozen_clock


# Invariant: clear_config() zeroes routes_count and config_installed but keeps
# the remembered path and interface name.
async def test_clear_config_keeps_path_and_interface(db: Database, frozen_clock: int) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)
    await repo.update_config(config_path="/p.conf", interface_name="w0", routes_count=12)

    # Act
    await repo.clear_config()
    state = await repo.get()

    # Assert
    assert state.routes_count == 0
    assert state.config_installed is False
    assert state.config_present is False
    assert (state.config_path, state.interface_name) == ("/p.conf", "w0")


# Invariant: update_runtime() writes every runtime column exactly as given and
# leaves the persisted configuration columns alone.
async def test_update_runtime_writes_runtime_columns_only(db: Database, frozen_clock: int) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)
    await repo.set_enabled(True)
    await repo.update_config(config_path="/p.conf", interface_name="w0", routes_count=3)

    # Act
    await repo.update_runtime(
        tunnel_up=True,
        routes_active=True,
        fail_streak=2,
        success_streak=7,
        last_handshake=111,
        last_check_ts=222,
    )
    state = await repo.get()

    # Assert
    assert (state.tunnel_up, state.routes_active) == (True, True)
    assert (state.fail_streak, state.success_streak) == (2, 7)
    assert (state.last_handshake, state.last_check_ts) == (111, 222)
    assert (state.enabled, state.routes_count, state.config_installed) == (True, 3, True)


# Invariant: update_runtime() stores False flags as 0 (the mapping is two-way,
# not "only ever set to 1").
async def test_update_runtime_can_clear_flags(db: Database, frozen_clock: int) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)
    await repo.update_runtime(
        tunnel_up=True, routes_active=True, fail_streak=0, success_streak=0, last_handshake=0, last_check_ts=0
    )

    # Act
    await repo.update_runtime(
        tunnel_up=False, routes_active=False, fail_streak=1, success_streak=0, last_handshake=0, last_check_ts=5
    )
    state = await repo.get()

    # Assert
    assert (state.tunnel_up, state.routes_active, state.fail_streak) == (False, False, 1)


# Invariant: reset_runtime() (bot startup) zeroes every runtime column but
# preserves the persisted module configuration and operator switches.
async def test_reset_runtime_preserves_persisted_columns(db: Database, frozen_clock: int) -> None:
    # Arrange
    repo = WarpSettingsRepository(db)
    await repo.set_enabled(True)
    await repo.set_kill_switch(True)
    await repo.update_config(config_path="/p.conf", interface_name="w0", routes_count=4)
    await repo.update_runtime(
        tunnel_up=True, routes_active=True, fail_streak=3, success_streak=9, last_handshake=50, last_check_ts=60
    )

    # Act
    await repo.reset_runtime()
    state = await repo.get()

    # Assert
    assert state == WarpState(
        enabled=True,
        config_path="/p.conf",
        interface_name="w0",
        routes_count=4,
        config_installed=True,
        kill_switch=True,
        updated_at=frozen_clock,
    )


# Invariant: writes are durable — a second Database on the same file (a bot
# restart) reads back what the first one committed.
async def test_writes_survive_reconnect(tmp_path: Path, frozen_clock: int) -> None:
    # Arrange
    path = tmp_path / "vpn.db"
    first = Database(path)
    await first.connect()
    await first.bootstrap()
    await WarpSettingsRepository(first).update_config(config_path="/k.conf", interface_name="wk", routes_count=1)
    await first.close()
    second = Database(path)
    await second.connect()

    # Act
    try:
        state = await WarpSettingsRepository(second).get()
    finally:
        await second.close()

    # Assert
    assert (state.config_path, state.interface_name, state.routes_count) == ("/k.conf", "wk", 1)
