"""Cancelling the fingerprint wizard must land back on the card it started from.

The wizard shares one cancel handler with every other FSM flow
(``bot.handlers.callbacks.cancel_callback``), and that handler reads its
destination from ``cancel_target`` in the FSM data. The fingerprint entry points
were the only ones that never wrote it, so cancel fell through to the default —
``menu:main`` — and an admin one tap into "change fingerprint" was thrown out to
the main menu instead of back to the key. The note wizard, which sets it, was
already correct; these tests pin both entry points to that behaviour.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import bot.handlers.callbacks as callbacks_mod
import bot.handlers.key_bundles as bundles_mod
import bot.handlers.keys as keys_mod
from bot.handlers.callbacks import cancel_callback
from bot.handlers.key_bundles import change_bundle_fp_prompt
from bot.handlers.keys import edit_fp_prompt


class _Message:
    def __init__(self) -> None:
        self.message_id = 7
        self.chat = SimpleNamespace(id=1, type="private")
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))


class _Callback:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.message = _Message()
        self.answers: list[str] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append(text or "")


class _State:
    def __init__(self) -> None:
        self.data: dict[str, object] = {}
        self.state: object = None

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def update_data(self, **kwargs: object) -> None:
        self.data.update(kwargs)

    async def set_state(self, state: object) -> None:
        self.state = state

    async def clear(self) -> None:
        self.state = None
        self.data.clear()


def _key(key_id: int = 42) -> SimpleNamespace:
    return SimpleNamespace(id=key_id, owner_user_id=100, key_type=SimpleNamespace(value="xray"))


def _services(*, key_id: int = 42, bundle_id: int = 5) -> SimpleNamespace:
    bundle = SimpleNamespace(id=bundle_id, owner_user_id=100)
    return SimpleNamespace(
        vpn_keys=SimpleNamespace(get_for_actor=lambda actor, kid: _awaitable(_key(kid))),
        key_bundle_views=SimpleNamespace(
            get_for_actor=lambda actor, bid: _awaitable(bundle),
            list_keys_for_actor=lambda actor, bid: _awaitable([]),
        ),
        settings=SimpleNamespace(subscription_enabled=True, xray_xhttp_enabled=False, hysteria2_enabled=False),
    )


async def _awaitable(value: object) -> object:
    return value


def _patch_guards(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def ok_cb(callback: object, text: str | None = None) -> bool:
        return True

    async def edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> None:
        message.edits.append((text, reply_markup))  # type: ignore[attr-defined]

    for module in (keys_mod, bundles_mod, callbacks_mod):
        monkeypatch.setattr(module, "ensure_private_callback", ok_cb, raising=False)
        monkeypatch.setattr(module, "safe_edit_message_text", edit, raising=False)
    monkeypatch.setattr(bundles_mod, "require_subscription_ui", lambda services: None, raising=False)
    monkeypatch.setattr(callbacks_mod, "require_subscription_ui", lambda services: None, raising=False)


def test_key_fp_wizard_stores_the_key_card_as_its_cancel_target(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_guards(monkeypatch)

    async def run() -> None:
        state = _State()
        await edit_fp_prompt(_Callback("key:fp:42"), state, _services())  # type: ignore[arg-type]
        assert state.data["cancel_target"] == "key:open:42"
        # bundle_id is still cleared: the two entities share the states.
        assert state.data["bundle_id"] is None

    asyncio.run(run())


def test_bundle_fp_wizard_stores_the_bundle_card_as_its_cancel_target(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_guards(monkeypatch)

    async def run() -> None:
        state = _State()
        await change_bundle_fp_prompt(_Callback("bundle:fp:5"), state, _services())  # type: ignore[arg-type]
        assert state.data["cancel_target"] == "bundle:open:5"
        assert state.data["key_id"] is None

    asyncio.run(run())


def test_cancel_with_a_key_target_returns_to_the_key_card_not_the_main_menu(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The other half of the fix: the shared handler honours what the wizard stored."""
    _patch_guards(monkeypatch)

    async def run() -> None:
        state = _State()
        state.data["cancel_target"] = "key:open:42"
        callback = _Callback("cancel")
        services = _services()
        rendered: list[object] = []

        monkeypatch.setattr(
            callbacks_mod,
            "key_screen_text",
            lambda key, viewer_user_id, stats=None: f"KEY-CARD-{key.id}",
            raising=False,
        )
        monkeypatch.setattr(callbacks_mod, "key_actions_keyboard", lambda key, **kw: rendered.append(key) or "KB", raising=False)

        async def no_views(services_, limiter, user_id, keys):  # type: ignore[no-untyped-def]
            return []

        monkeypatch.setattr(callbacks_mod, "stats_views_for_screen", no_views, raising=False)

        await cancel_callback(callback, state, SimpleNamespace(), services)  # type: ignore[arg-type]

        assert callback.message.edits, "cancel rendered nothing"
        text, _markup = callback.message.edits[-1]
        assert text == "KEY-CARD-42"

    asyncio.run(run())


def test_cancel_with_a_bundle_target_returns_to_the_bundle_card(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_guards(monkeypatch)

    async def run() -> None:
        state = _State()
        state.data["cancel_target"] = "bundle:open:5"
        callback = _Callback("cancel")

        monkeypatch.setattr(
            callbacks_mod,
            "bundle_detail_text",
            lambda bundle, keys, viewer_user_id, views=None: f"BUNDLE-CARD-{bundle.id}",
            raising=False,
        )
        monkeypatch.setattr(callbacks_mod, "bundle_actions_keyboard", lambda bundle, has_vless: "KB", raising=False)
        monkeypatch.setattr(callbacks_mod, "bundle_has_vless", lambda keys: False, raising=False)

        async def no_views(services_, limiter, user_id, keys):  # type: ignore[no-untyped-def]
            return []

        monkeypatch.setattr(callbacks_mod, "stats_views_for_screen", no_views, raising=False)

        await cancel_callback(callback, state, SimpleNamespace(), _services())  # type: ignore[arg-type]

        assert callback.message.edits, "cancel rendered nothing"
        text, _markup = callback.message.edits[-1]
        assert text == "BUNDLE-CARD-5"

    asyncio.run(run())
