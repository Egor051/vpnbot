"""The «Подключение: напрямую / через relay» wizard step, user and admin flows.

Pinned here:

* the step appears ONLY while RELAY_ENABLED, after the protocol (and XHTTP
  profile) choice and before the note, and only for the protocols the relay
  carries (VLESS, Hysteria2 — never AmneziaWG);
* the choice travels in the FSM next to key_type/transport/xhttp_profile and
  reaches ``create_xray_key`` / ``hysteria.issue`` as ``relay=``;
* a stale relay callback after RELAY_ENABLED was switched off is refused up
  front, the way a stale protocol callback is;
* the confirm screen names the relay.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bot.fsm.states import AdminCreateKeyStates, CreateKeyStates
from bot.handlers.admin import (
    admin_issue_confirm,
    admin_issue_expiry,
    admin_issue_route,
    admin_issue_type_selected,
    admin_issue_xhttp_profile,
)
from bot.handlers.keys import (
    create_key_choose,
    create_key_choose_route,
    create_key_choose_xhttp_profile,
    create_key_confirm,
    create_key_expiry,
)
from bot.rate_limit import RateLimiter
from i18n import t
from models.dto import User, VpnKey, VpnKeyCreateResult
from models.enums import UserRole, VpnKeyStatus, VpnKeyType

OWNER = 100
ADMIN = 1


def _settings(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = dict(
        relay_enabled=True,
        relay_name="ru1",
        relay_host="relay.anycastedge.net",
        hysteria2_enabled=True,
        xray_xhttp_enabled=True,
        key_max_trial_days=30,
        subscription_enabled=False,
    )
    values.update(overrides)
    settings = SimpleNamespace(**values)
    settings.is_hysteria2_ready = lambda: True  # type: ignore[attr-defined]
    return settings


class _Message:
    def __init__(self) -> None:
        self.message_id = 1
        self.chat = SimpleNamespace(id=OWNER)
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None, **kwargs: object) -> None:
        self.edits.append((text, reply_markup))

    async def answer(self, text: str, reply_markup: object = None, **kwargs: object) -> None:
        self.edits.append((text, reply_markup))

    @property
    def last_text(self) -> str:
        return self.edits[-1][0]

    @property
    def last_markup(self) -> object:
        return self.edits[-1][1]


class _Callback:
    def __init__(self, data: str, user_id: int = OWNER) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="user", first_name="User")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))

    @property
    def alerts(self) -> list[str]:
        return [text for text, show_alert in self.answers if show_alert]


class _State:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self.data: dict[str, object] = data or {}
        self.state: object | None = None
        self.cleared = False

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def set_state(self, state: object) -> None:
        self.state = state

    async def update_data(self, data: dict[str, object] | None = None, **kwargs: object) -> None:
        self.data.update(data or {})
        self.data.update(kwargs)

    async def clear(self) -> None:
        self.cleared = True
        self.data.clear()
        self.state = None


class _Users:
    async def require_approved_or_admin(self, user_id: int) -> User:
        role = UserRole.SUPERADMIN if user_id == ADMIN else UserRole.APPROVED_USER
        return User(user_id, "user", "User", role, "now", "now", None)

    async def require_superadmin(self, user_id: int) -> User:
        return await self.require_approved_or_admin(user_id)

    async def get_user(self, user_id: int) -> User:
        return await self.require_approved_or_admin(user_id)


def _key(key_type: VpnKeyType, relay: str | None) -> VpnKey:
    return VpnKey(
        id=7, owner_user_id=OWNER, username="user", key_type=key_type, status=VpnKeyStatus.ACTIVE,
        note=None, uuid=None, email_label="xray_tcp_ab12c", public_key=None, client_ip=None,
        payload={}, public_payload={}, created_at="now", updated_at="now", revoked_at=None,
        deleted_at=None, created_by=OWNER, revoked_by=None, deleted_by=None, relay=relay,
    )


class _Creator:
    """Records what the wizard hands to the per-protocol create paths."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def create_xray_key(self, *args: object, **kwargs: object) -> VpnKeyCreateResult:
        self.calls.append(("xray", kwargs))
        return VpnKeyCreateResult(key=_key(VpnKeyType.XRAY, kwargs.get("relay")), config_text="cfg")  # type: ignore[arg-type]

    async def issue(self, *args: object, **kwargs: object) -> VpnKeyCreateResult:
        self.calls.append(("hy2", kwargs))
        return VpnKeyCreateResult(key=_key(VpnKeyType.HYSTERIA2, kwargs.get("relay")), config_text="cfg")  # type: ignore[arg-type]


def _services(settings: SimpleNamespace | None = None, creator: _Creator | None = None) -> SimpleNamespace:
    async def _enabled(name: str) -> bool:
        return True

    creator = creator or _Creator()
    return SimpleNamespace(
        settings=settings or _settings(),
        users=_Users(),
        modules=SimpleNamespace(is_enabled=_enabled),
        xray=creator,
        hysteria=creator,
    )


def _callbacks(markup: object) -> list[str]:
    return [button.callback_data for row in markup.inline_keyboard for button in row]  # type: ignore[attr-defined]


async def _allow(*args: object, **kwargs: object) -> bool:
    return True


async def _no_delivery(*args: object, **kwargs: object) -> tuple[str, None]:
    return "link", None


async def _no_send(*args: object, **kwargs: object) -> None:
    return None


@pytest.fixture(autouse=True)
def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    for module in ("bot.handlers.keys", "bot.handlers.admin"):
        monkeypatch.setattr(f"{module}.ensure_private_callback", _allow)
        monkeypatch.setattr(f"{module}.config_delivery", _no_delivery)
        monkeypatch.setattr(f"{module}.send_config_with_qr", _no_send)


# ── user wizard ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize("data", ["keys:create:xray", "keys:create:hy2"])
async def test_relay_step_follows_the_protocol_choice(data: str) -> None:
    callback = _Callback(data)
    state = _State()
    await create_key_choose(callback, state, _services())  # type: ignore[arg-type]
    assert state.state == CreateKeyStates.waiting_route
    assert callback.message.last_text == t("choose_relay_route")
    assert _callbacks(callback.message.last_markup) == ["keys:route:direct", "keys:route:relay", "cancel"]
    assert state.data["relay"] is None
    assert state.data["cancel_target"] == "keys:create"


async def test_relay_step_follows_the_xhttp_profile_choice() -> None:
    callback = _Callback("keys:xhttp:profile:multi")
    state = _State()
    await create_key_choose_xhttp_profile(callback, state, _services())  # type: ignore[arg-type]
    assert state.state == CreateKeyStates.waiting_route
    assert state.data["xhttp_profile"] == "multi"
    assert state.data["transport"] == "http"


@pytest.mark.parametrize("settings", [_settings(relay_enabled=False), _settings(relay_host="")])
async def test_without_a_relay_the_wizard_goes_straight_to_the_note(settings: SimpleNamespace) -> None:
    callback = _Callback("keys:create:xray")
    state = _State()
    await create_key_choose(callback, state, _services(settings))  # type: ignore[arg-type]
    assert state.state == CreateKeyStates.waiting_note
    assert t("key_note_prompt") in callback.message.last_text
    assert state.data["relay"] is None


async def test_awg_never_gets_the_relay_step() -> None:
    callback = _Callback("keys:create:awg")
    state = _State()
    await create_key_choose(callback, state, _services())  # type: ignore[arg-type]
    assert state.state == CreateKeyStates.waiting_note


@pytest.mark.parametrize(("data", "relay"), [("keys:route:direct", None), ("keys:route:relay", "ru1")])
async def test_route_choice_is_stored_and_leads_to_the_note(data: str, relay: str | None) -> None:
    callback = _Callback(data)
    state = _State({"key_type": "xray", "transport": "tcp", "relay": None})
    await create_key_choose_route(callback, state, _services())  # type: ignore[arg-type]
    assert state.state == CreateKeyStates.waiting_note
    assert state.data["relay"] == relay
    assert t("key_note_prompt") in callback.message.last_text


async def test_stale_relay_callback_is_refused_when_relay_is_off() -> None:
    callback = _Callback("keys:route:relay")
    state = _State({"key_type": "xray", "transport": "tcp", "relay": None})
    await create_key_choose_route(callback, state, _services(_settings(relay_enabled=False)))  # type: ignore[arg-type]
    assert callback.alerts == [t("relay_unavailable")]
    assert state.state is None
    assert state.data["relay"] is None


async def test_confirm_screen_and_create_carry_the_relay() -> None:
    creator = _Creator()
    services = _services(creator=creator)
    state = _State({"key_type": "hysteria2", "transport": "tcp", "relay": "ru1", "note": None})
    expiry = _Callback("expiry:permanent")
    await create_key_expiry(expiry, state, services)  # type: ignore[arg-type]
    assert f"Hysteria2 · {t('relay_marker')}" in expiry.message.last_text

    confirm = _Callback("create:confirm")
    await create_key_confirm(confirm, state, services, RateLimiter())  # type: ignore[arg-type]
    assert creator.calls == [("hy2", {"expires_at": None, "relay": "ru1"})]


async def test_confirm_without_relay_passes_none() -> None:
    creator = _Creator()
    state = _State({"key_type": "xray", "transport": "http", "xhttp_profile": "base", "note": None})
    await create_key_confirm(_Callback("create:confirm"), state, _services(creator=creator), RateLimiter())  # type: ignore[arg-type]
    assert creator.calls[0][0] == "xray"
    assert creator.calls[0][1]["relay"] is None


# ── admin wizard ──────────────────────────────────────────────────────────────


async def test_admin_type_choice_offers_the_relay_step() -> None:
    callback = _Callback(f"admin:ctype:hy2:{OWNER}", user_id=ADMIN)
    state = _State({"owner_user_id": OWNER})
    await admin_issue_type_selected(callback, state, _services())  # type: ignore[arg-type]
    assert state.state == AdminCreateKeyStates.waiting_route
    assert _callbacks(callback.message.last_markup) == [
        f"admin:croute:direct:{OWNER}",
        f"admin:croute:relay:{OWNER}",
        "cancel",
    ]


async def test_admin_xhttp_profile_offers_the_relay_step() -> None:
    callback = _Callback(f"admin:cxprof:antisib:{OWNER}", user_id=ADMIN)
    state = _State({"owner_user_id": OWNER})
    await admin_issue_xhttp_profile(callback, state, _services())  # type: ignore[arg-type]
    assert state.state == AdminCreateKeyStates.waiting_route
    assert state.data["xhttp_profile"] == "antisib"


async def test_admin_awg_and_relay_off_skip_the_step() -> None:
    callback = _Callback(f"admin:ctype:awg:{OWNER}", user_id=ADMIN)
    state = _State({"owner_user_id": OWNER})
    await admin_issue_type_selected(callback, state, _services())  # type: ignore[arg-type]
    assert state.state == AdminCreateKeyStates.waiting_note

    callback = _Callback(f"admin:ctype:xray:{OWNER}", user_id=ADMIN)
    state = _State({"owner_user_id": OWNER})
    await admin_issue_type_selected(callback, state, _services(_settings(relay_enabled=False)))  # type: ignore[arg-type]
    assert state.state == AdminCreateKeyStates.waiting_note


async def test_admin_route_full_flow_reaches_the_service() -> None:
    creator = _Creator()
    services = _services(creator=creator)
    state = _State({"owner_user_id": OWNER, "key_type": "xray", "transport": "tcp", "relay": None})
    await admin_issue_route(_Callback(f"admin:croute:relay:{OWNER}", user_id=ADMIN), state, services)  # type: ignore[arg-type]
    assert state.state == AdminCreateKeyStates.waiting_note
    assert state.data["relay"] == "ru1"

    state.data["note"] = None
    expiry = _Callback("expiry:permanent", user_id=ADMIN)
    await admin_issue_expiry(expiry, state, services)  # type: ignore[arg-type]
    assert f"VLESS (TCP) · {t('relay_marker')}" in expiry.message.last_text

    await admin_issue_confirm(_Callback("admin:cconfirm", user_id=ADMIN), state, services, RateLimiter(), SimpleNamespace())  # type: ignore[arg-type]
    assert creator.calls[0][0] == "xray"
    assert creator.calls[0][1]["relay"] == "ru1"


async def test_admin_stale_relay_callback_is_refused() -> None:
    state = _State({"owner_user_id": OWNER, "key_type": "xray", "transport": "tcp", "relay": None})
    callback = _Callback(f"admin:croute:relay:{OWNER}", user_id=ADMIN)
    await admin_issue_route(callback, state, _services(_settings(relay_enabled=False)))  # type: ignore[arg-type]
    assert callback.alerts == [t("relay_unavailable")]
    assert state.data["relay"] is None


async def test_admin_route_for_another_owner_is_stale() -> None:
    state = _State({"owner_user_id": OWNER, "key_type": "xray", "transport": "tcp"})
    callback = _Callback("admin:croute:direct:999", user_id=ADMIN)
    await admin_issue_route(callback, state, _services())  # type: ignore[arg-type]
    assert callback.alerts == [t("action_stale")]
    assert state.cleared is True
