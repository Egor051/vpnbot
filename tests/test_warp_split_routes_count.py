"""Regression: a changing split-list size is not a health signal.

Feeds make the routed prefix count move on its own — Telegram publishes a new
block, Google reshuffles ``goog.json``, an operator enables ``google-goog`` and
the list goes from 9 entries to 108. Nothing in the monitoring path may read
that as the tunnel degrading, and ``warp_settings.routes_count`` (which describes
the *WARP module's* installed routes, not the split list) must not drift because
of it.

No production code is changed for this; the tests exist so a future "let's alert
when the route count drops" idea fails here first, with the reason written down.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from db.database import Database
from repositories.warp_settings import WarpSettingsRepository
from warp.health import HealthSnapshot, WarpHealthMonitor

ROOT = Path(__file__).resolve().parents[1]

# Every module this feature added or touched on the write path. None of them has
# any business reading or writing the WARP module's route counter.
SPLIT_MODULES = (
    "warp/split_manager.py",
    "warp/split_merge.py",
    "warp/feed_state.py",
    "services/warp_split_feeds.py",
    "repositories/warp_split_sources.py",
    "adapters/warp_feed_fetcher.py",
)


# ── the persisted counter ─────────────────────────────────────────────────────


async def test_split_modules_never_touch_warp_settings_routes_count() -> None:
    """``routes_count`` belongs to the WARP module install, not to the split list.

    ``WarpSettingsRepository.update_config`` is its only writer (and
    ``clear_config`` its only zeroer). If a split-list apply started maintaining
    it, the number would swing by hundreds every refresh and the panel's
    "config_present" test (``routes_count > 0``) would start meaning something
    else entirely.
    """
    offenders = [
        name
        for name in SPLIT_MODULES
        if "routes_count" in (ROOT / name).read_text(encoding="utf-8")
    ]
    assert offenders == []


async def test_applying_a_much_larger_list_leaves_routes_count_alone(tmp_path: Path) -> None:
    """The end-to-end form of the same claim, through a real database.

    Enabling a feed is exactly the scenario that grows the list by two orders of
    magnitude; the counter that drives the WARP panel must not notice.
    """
    from tests.test_warp_split_feeds import FIXTURES, _make

    db, _shell, manager, fetcher, _repo, service = await _make(tmp_path)
    try:
        settings_repo = WarpSettingsRepository(db)
        await settings_repo.update_config(
            config_path="/etc/wireguard/out-warp.conf", interface_name="out-warp", routes_count=4
        )

        manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
        await service.ensure_manual_adopted()
        fetcher.payloads["telegram-cidr"] = (FIXTURES / "telegram_cidr.txt").read_text(
            encoding="utf-8"
        )
        result = await service.refresh(slugs=["telegram-cidr"], apply=True)

        assert result.outcome is not None and result.outcome.changed
        assert len(manager.read_list()) > 4  # the list really did grow
        assert (await settings_repo.get()).routes_count == 4
    finally:
        await db.close()


# ── the monitor ───────────────────────────────────────────────────────────────


def test_health_snapshot_has_no_route_count_field() -> None:
    """The monitor reports *reachability*, and its data model says so.

    Adding a count here is the cheapest way to accidentally build "fewer routes
    than last time == degraded", so the absence is pinned.
    """
    assert set(HealthSnapshot.__annotations__) == {
        "tunnel_up",
        "routes_active",
        "fail_streak",
        "success_streak",
        "degraded",
    }


@pytest.mark.parametrize("route_count", [0, 9, 108, 269, 1500])
async def test_monitor_verdict_is_independent_of_how_many_prefixes_are_routed(
    route_count: int,
) -> None:
    """The monitor is handed no route count and asks for none.

    Parametrised over the counts this feature actually produces: 9 (telegram
    alone), 108 (today's live list), 269 (goog minus cloud, plus telegram) and
    1500 (the cap). A healthy probe stays healthy at every size.
    """
    calls: list[HealthSnapshot] = []

    async def ping() -> bool:
        return True

    async def on_update(snapshot: HealthSnapshot) -> None:
        calls.append(snapshot)

    async def noop() -> None:
        return None

    monitor = WarpHealthMonitor(
        ping=ping,
        activate_routes=noop,
        deactivate_routes=noop,
        on_update=on_update,
        observer_mode=True,
    )
    # The count is not an input to the monitor at all — the loop below is what a
    # refresh looks like from its side: nothing happens.
    for _ in range(route_count % 7 + 1):
        snapshot = await monitor.check_once()

    assert snapshot.tunnel_up is True
    assert snapshot.degraded is False
    assert snapshot.routes_active is True
    assert monitor.degraded is False


async def test_degraded_flag_comes_from_probe_loss_only() -> None:
    """Sanity anchor for the test above: the detector *does* fire, on the right input.

    Without this, "never degraded" could pass because the detector is broken
    rather than because it correctly ignores the route count.
    """
    from warp.constants import DEGRADED_MIN_SAMPLES

    outcomes = [False] * DEGRADED_MIN_SAMPLES
    ticks = iter(range(1000))

    async def ping() -> bool:
        return outcomes.pop(0) if outcomes else True

    async def on_update(snapshot: HealthSnapshot) -> None:
        return None

    async def noop() -> None:
        return None

    monitor = WarpHealthMonitor(
        ping=ping,
        activate_routes=noop,
        deactivate_routes=noop,
        on_update=on_update,
        observer_mode=True,
        fail_window=10_000,  # keep the down-latch out of the way
        clock=lambda: float(next(ticks)),
    )
    for _ in range(DEGRADED_MIN_SAMPLES):
        await monitor.check_once()

    assert monitor.degraded is True
