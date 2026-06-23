"""The server-status admin panel must read the *averaged* snapshot.

Both the initial render and the auto-refresh loop's tick should call
``server_status.snapshot_averaged()`` (smoothed head-line metrics), never the
raw ``snapshot()`` (a single 1s slice). These tests drive the handler functions
directly with light fakes — no real Telegram, sampler or sleeps.
"""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import bot.handlers.admin_dashboard as dash
from services.online_clients import OnlineClients
from services.server_status import ServerStatus

_ONLINE = OnlineClients(wg=None, xray=None, total=None, available=False)


def _status() -> ServerStatus:
    return ServerStatus(
        cpu_percent=5.0,
        cpu_available=True,
        ram_used_gb=1.0,
        ram_total_gb=2.0,
        disk_free_gb=5.0,
        disk_total_gb=10.0,
        net_in_mbps=1.0,
        net_out_mbps=2.0,
        net_available=True,
        sampled_at=datetime(2026, 6, 21, 12, 0, 0, tzinfo=timezone.utc),
    )


class _RecordingServerStatus:
    """Records which snapshot variant the panel asked for."""

    def __init__(self) -> None:
        self.snapshot_calls = 0
        self.snapshot_averaged_calls = 0
        self.reset_calls = 0
        self.detailed = False

    async def snapshot(self) -> ServerStatus:
        self.snapshot_calls += 1
        return _status()

    async def snapshot_averaged(self) -> ServerStatus:
        self.snapshot_averaged_calls += 1
        return _status()

    def reset_network_history(self) -> None:
        self.reset_calls += 1


class _Online:
    async def get(self) -> OnlineClients:
        return _ONLINE


class _FakeRefreshManager:
    """Captures the refresh closure handed to ``start`` so a test can run it."""

    def __init__(self) -> None:
        self.refresh = None
        self.on_expire = None
        self.started_key = None

    def start(self, key, *, refresh, on_expire) -> None:  # type: ignore[no-untyped-def]
        self.started_key = key
        self.refresh = refresh
        self.on_expire = on_expire

    def cancel(self, key) -> None:  # type: ignore[no-untyped-def]
        pass


class _Msg:
    def __init__(self) -> None:
        self.chat = SimpleNamespace(id=111)
        self.message_id = 222

    async def edit_text(self, *args: object, **kwargs: object) -> None:
        return None

    async def answer(self, *args: object, **kwargs: object) -> None:
        return None


def _services(server_status: _RecordingServerStatus) -> SimpleNamespace:
    return SimpleNamespace(
        server_status=server_status,
        online_clients=_Online(),
        auto_refresh=_FakeRefreshManager(),
    )


def test_render_server_status_uses_snapshot_averaged(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = _RecordingServerStatus()
    services = _services(srv)
    rendered: list[str] = []

    async def fake_super(_services: object, _uid: int) -> None:
        return None

    async def fake_edit(_message: object, text: str, **_kwargs: object) -> bool:
        rendered.append(text)
        return True

    monkeypatch.setattr(dash, "require_superadmin", fake_super)
    monkeypatch.setattr(dash, "safe_edit_message_text", fake_edit)

    callback = SimpleNamespace(from_user=SimpleNamespace(id=7), message=_Msg())
    asyncio.run(dash._render_server_status(callback, services))  # type: ignore[arg-type]

    assert srv.snapshot_averaged_calls == 1
    assert srv.snapshot_calls == 0
    assert rendered  # a render actually happened


def test_auto_refresh_tick_uses_snapshot_averaged(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = _RecordingServerStatus()
    services = _services(srv)

    async def fake_super(_services: object, _uid: int) -> None:
        return None

    async def fake_refresh_edit(_message: object, _text: str, **_kwargs: object) -> bool:
        return True

    monkeypatch.setattr(dash, "require_superadmin", fake_super)
    monkeypatch.setattr(dash, "edit_message_for_refresh", fake_refresh_edit)

    callback = SimpleNamespace(from_user=SimpleNamespace(id=7), message=_Msg())
    dash._start_server_status_auto_refresh(callback, services)  # type: ignore[arg-type]

    refresh = services.auto_refresh.refresh
    assert refresh is not None
    alive = asyncio.run(refresh())

    assert alive is True
    assert srv.snapshot_averaged_calls == 1
    assert srv.snapshot_calls == 0
    # The live tick must not wipe the sparkline window — only a fresh open does.
    assert srv.reset_calls == 0


def test_open_panel_resets_sparkline_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """Opening the panel clears stale sparkline columns from a previous viewing
    before the first render, so the window starts empty."""
    srv = _RecordingServerStatus()
    services = _services(srv)

    async def fake_private(_callback: object, _text: str) -> bool:
        return True

    async def fake_super(_services: object, _uid: int) -> None:
        return None

    async def fake_answer(_callback: object, _text: str = "") -> None:
        return None

    async def fake_edit(_message: object, _text: str, **_kwargs: object) -> bool:
        return True

    monkeypatch.setattr(dash, "ensure_private_callback", fake_private)
    monkeypatch.setattr(dash, "require_superadmin", fake_super)
    monkeypatch.setattr(dash, "safe_callback_answer", fake_answer)
    monkeypatch.setattr(dash, "safe_edit_message_text", fake_edit)

    callback = SimpleNamespace(from_user=SimpleNamespace(id=7), message=_Msg())
    asyncio.run(dash.admin_server_status(callback, services))  # type: ignore[arg-type]

    assert srv.reset_calls == 1
    assert srv.snapshot_averaged_calls == 1
