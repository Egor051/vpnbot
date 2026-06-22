import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from aiogram.types import CallbackQuery, Message

from bot.middlewares.maintenance import MaintenanceModeMiddleware


def _make_middleware(*, enabled: bool, admin_ids=frozenset({1})) -> MaintenanceModeMiddleware:
    maintenance = SimpleNamespace(
        is_enabled=lambda: enabled,
        banner_text=lambda: "works in progress",
    )
    settings = SimpleNamespace(admin_ids=admin_ids)
    return MaintenanceModeMiddleware(maintenance, settings)  # type: ignore[arg-type]


def test_disabled_passes_through_without_user_lookup() -> None:
    async def run() -> None:
        mw = _make_middleware(enabled=False)
        handler = AsyncMock(return_value="ok")
        event = MagicMock(spec=Message)
        result = await mw(handler, event, {"event_from_user": SimpleNamespace(id=555)})
        assert result == "ok"
        handler.assert_awaited_once()

    asyncio.run(run())


def test_superadmin_passes_through_when_enabled() -> None:
    async def run() -> None:
        mw = _make_middleware(enabled=True, admin_ids=frozenset({1}))
        handler = AsyncMock(return_value="ok")
        event = MagicMock(spec=Message)
        result = await mw(handler, event, {"event_from_user": SimpleNamespace(id=1)})
        assert result == "ok"
        handler.assert_awaited_once()

    asyncio.run(run())


def test_regular_user_gets_banner_and_state_cleared() -> None:
    async def run() -> None:
        mw = _make_middleware(enabled=True, admin_ids=frozenset({1}))
        handler = AsyncMock()
        event = MagicMock(spec=Message)
        event.answer = AsyncMock()
        state = SimpleNamespace(clear=AsyncMock())
        result = await mw(handler, event, {"event_from_user": SimpleNamespace(id=2), "state": state})
        assert result is None
        handler.assert_not_awaited()
        event.answer.assert_awaited_once_with("works in progress")
        state.clear.assert_awaited_once()

    asyncio.run(run())


def test_regular_user_callback_gets_alert() -> None:
    async def run() -> None:
        mw = _make_middleware(enabled=True, admin_ids=frozenset({1}))
        handler = AsyncMock()
        event = MagicMock(spec=CallbackQuery)
        event.answer = AsyncMock()
        result = await mw(handler, event, {"event_from_user": SimpleNamespace(id=2)})
        assert result is None
        handler.assert_not_awaited()
        event.answer.assert_awaited_once()
        # banner is shown as an alert
        assert event.answer.await_args.kwargs.get("show_alert") is True

    asyncio.run(run())


def test_missing_user_passes_through() -> None:
    async def run() -> None:
        mw = _make_middleware(enabled=True)
        handler = AsyncMock(return_value="ok")
        event = MagicMock(spec=Message)
        result = await mw(handler, event, {})
        assert result == "ok"
        handler.assert_awaited_once()

    asyncio.run(run())
