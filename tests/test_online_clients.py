import asyncio
from itertools import count

from services.online_clients import OnlineClients, OnlineClientsService


class _FakeAwg:
    """AWG adapter stub returning a scripted sequence of transfer snapshots."""

    def __init__(self, snapshots: list[dict[str, tuple[int, int]]]) -> None:
        self._snapshots = snapshots
        self.calls = 0

    async def list_transfer(self) -> dict[str, tuple[int, int]]:
        snap = self._snapshots[min(self.calls, len(self._snapshots) - 1)]
        self.calls += 1
        return snap


class _FakeXray:
    def __init__(self, snapshots: list[dict[str, int]]) -> None:
        self._snapshots = snapshots
        self.calls = 0

    async def query_all(self) -> dict[str, int]:
        snap = self._snapshots[min(self.calls, len(self._snapshots) - 1)]
        self.calls += 1
        return snap


def _xray_user(email: str, up: int, down: int) -> dict[str, int]:
    return {
        f"user>>>{email}>>>traffic>>>uplink": up,
        f"user>>>{email}>>>traffic>>>downlink": down,
    }


def test_first_poll_has_no_baseline() -> None:
    awg = _FakeAwg([{"p1": (10, 20)}])
    xray = _FakeXray([_xray_user("a@x", 1, 1)])
    svc = OnlineClientsService(awg_adapter=awg, xray_stats=xray, clock=lambda: 0.0)
    result = asyncio.run(svc.get())
    assert result == OnlineClients(wg=None, xray=None, total=None, available=False)


def test_second_poll_counts_increased_identities() -> None:
    # p1 grows (online), p2 flat (offline); xray user a grows, b flat.
    awg = _FakeAwg([{"p1": (10, 20), "p2": (5, 5)}, {"p1": (30, 40), "p2": (5, 5)}])
    xray = _FakeXray(
        [
            {**_xray_user("a@x", 1, 1), **_xray_user("b@x", 2, 2)},
            {**_xray_user("a@x", 5, 5), **_xray_user("b@x", 2, 2)},
        ]
    )
    clock = count(0, 100)  # each call advances well past the TTL
    svc = OnlineClientsService(awg_adapter=awg, xray_stats=xray, ttl=30.0, clock=lambda: next(clock))

    asyncio.run(svc.get())  # establishes baseline
    result = asyncio.run(svc.get())
    assert result.wg == 1
    assert result.xray == 1
    assert result.total == 2
    assert result.available is True


def test_cache_serves_within_ttl_without_re_polling() -> None:
    awg = _FakeAwg([{"p1": (10, 20)}, {"p1": (30, 40)}])
    xray = _FakeXray([_xray_user("a@x", 1, 1), _xray_user("a@x", 9, 9)])
    now = {"t": 0.0}
    svc = OnlineClientsService(awg_adapter=awg, xray_stats=xray, ttl=30.0, clock=lambda: now["t"])

    asyncio.run(svc.get())  # poll #1 (t=0)
    assert awg.calls == 1
    now["t"] = 5.0  # still within TTL
    asyncio.run(svc.get())  # served from cache, no new poll
    assert awg.calls == 1
    now["t"] = 40.0  # past TTL
    asyncio.run(svc.get())  # poll #2
    assert awg.calls == 2


def test_backend_failure_yields_none_without_raising() -> None:
    class _BrokenAwg:
        async def list_transfer(self) -> dict[str, tuple[int, int]]:
            raise RuntimeError("interface down")

    xray = _FakeXray([_xray_user("a@x", 1, 1), _xray_user("a@x", 5, 5)])
    clock = count(0, 100)
    svc = OnlineClientsService(awg_adapter=_BrokenAwg(), xray_stats=xray, clock=lambda: next(clock))

    asyncio.run(svc.get())  # baseline (xray only)
    result = asyncio.run(svc.get())
    assert result.wg is None  # WG unreadable
    assert result.xray == 1
    assert result.total == 1
    assert result.available is True


def test_xray_grouping_ignores_non_user_counters() -> None:
    stats = {
        **_xray_user("a@x", 1, 1),
        "inbound>>>api>>>traffic>>>uplink": 999,
        "outbound>>>direct>>>traffic>>>downlink": 999,
    }
    grouped = OnlineClientsService._group_xray_by_email(stats)
    assert grouped == {"a@x": 2}
