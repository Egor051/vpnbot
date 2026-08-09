"""A key card must offer the same buttons however it was reached.

`bot/handlers/keys.py` computes an owner context for every key screen it renders:
non-None means "an admin is looking at somebody else's key", and the keyboard
then drops the owner-only actions (note, fingerprint) and sends «to list» back to
that user's key list. `bot/handlers/callbacks.py` re-renders the very same card
when a wizard is cancelled — and did it without that context, so an admin who
cancelled out of a wizard on a foreign key got the owner's keyboard on it.

Both paths now call one `admin_owner_context`, and these tests compare the two
keyboards button for button rather than asserting a particular layout, so the
guarantee survives the next change to what the keyboard contains.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import bot.handlers.callbacks as callbacks_mod
from bot.handlers.callbacks import cancel_callback
from bot.handlers.common import admin_owner_context
from bot.keyboards.keys import key_actions_keyboard
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType

ADMIN_ID = 1
OWNER_ID = 100
KEY_ID = 42


def _key(owner_user_id: int = OWNER_ID) -> VpnKey:
    return VpnKey(
        id=KEY_ID,
        owner_user_id=owner_user_id,
        username="user",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="00000000-0000-4000-8000-000000000001",
        email_label="xray_tcp_abc",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        created_by=ADMIN_ID,
        revoked_by=None,
        deleted_by=None,
    )


class _Message:
    def __init__(self) -> None:
        self.message_id = 7
        self.chat = SimpleNamespace(id=ADMIN_ID, type="private")
        self.from_user = SimpleNamespace(id=ADMIN_ID, username="admin", first_name="Admin")
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))


class _Callback:
    def __init__(self) -> None:
        self.data = "cancel"
        self.from_user = SimpleNamespace(id=ADMIN_ID, username="admin", first_name="Admin")
        self.message = _Message()
        self.answers: list[str] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append(text or "")


class _State:
    def __init__(self, data: dict[str, object]) -> None:
        self.data = dict(data)

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def clear(self) -> None:
        self.data.clear()


def _services(key: VpnKey) -> SimpleNamespace:
    async def get_for_actor(actor_user_id: int, key_id: int) -> VpnKey:
        return key

    return SimpleNamespace(vpn_keys=SimpleNamespace(get_for_actor=get_for_actor))


def _buttons(markup: object) -> list[tuple[str, str | None]]:
    rows = getattr(markup, "inline_keyboard", [])
    return [(button.text, button.callback_data) for row in rows for button in row]


def _cancel_to_key_card(key: VpnKey, monkeypatch) -> object:  # type: ignore[no-untyped-def]
    async def ok(callback: object, text: str | None = None) -> bool:
        return True

    async def edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> None:
        message.edits.append((text, reply_markup))  # type: ignore[attr-defined]

    async def no_views(services, limiter, user_id, keys):  # type: ignore[no-untyped-def]
        return []

    monkeypatch.setattr(callbacks_mod, "ensure_private_callback", ok, raising=False)
    monkeypatch.setattr(callbacks_mod, "safe_edit_message_text", edit, raising=False)
    monkeypatch.setattr(callbacks_mod, "stats_views_for_screen", no_views, raising=False)
    monkeypatch.setattr(
        callbacks_mod, "key_screen_text", lambda k, viewer_user_id, stats=None: "CARD", raising=False
    )

    callback = _Callback()
    state = _State({"cancel_target": f"key:open:{key.id}"})
    asyncio.run(cancel_callback(callback, state, SimpleNamespace(), _services(key)))  # type: ignore[arg-type]
    assert callback.message.edits, "cancel rendered nothing"
    return callback.message.edits[-1][1]


def test_cancelling_on_a_foreign_key_gives_the_admin_keyboard(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The bug: an admin got the OWNER's keyboard on someone else's key."""
    key = _key()
    markup = _cancel_to_key_card(key, monkeypatch)

    direct = key_actions_keyboard(key, owner_user_id=admin_owner_context(key, ADMIN_ID))
    assert _buttons(markup) == _buttons(direct)

    callbacks = [data for _text, data in _buttons(markup)]
    # Owner-only actions are absent, and «to list» goes to that user's key list.
    assert f"key:note:{KEY_ID}" not in callbacks
    assert f"key:fp:{KEY_ID}" not in callbacks
    assert f"admin:ukeys:{OWNER_ID}:0" in callbacks
    assert "keys:list" not in callbacks


def test_cancelling_on_your_own_key_is_unchanged(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The owner's own card keeps every action it had — the fix is not a blanket lockout."""
    key = _key(owner_user_id=ADMIN_ID)
    markup = _cancel_to_key_card(key, monkeypatch)

    direct = key_actions_keyboard(key, owner_user_id=admin_owner_context(key, ADMIN_ID))
    assert _buttons(markup) == _buttons(direct)

    callbacks = [data for _text, data in _buttons(markup)]
    assert f"key:note:{KEY_ID}" in callbacks
    assert f"key:fp:{KEY_ID}" in callbacks
    assert "keys:list" in callbacks


def test_admin_owner_context_is_none_only_for_your_own_key() -> None:
    assert admin_owner_context(_key(owner_user_id=ADMIN_ID), ADMIN_ID) is None
    assert admin_owner_context(_key(owner_user_id=OWNER_ID), ADMIN_ID) == OWNER_ID
