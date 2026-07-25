"""Bot-UI tests for all-in-one subscription bundles.

Two things are pinned here above all else:

* the **flag gate** — with ``SUBSCRIPTION_ENABLED`` false the create menu, the key
  list and every ``bundle:*`` callback behave exactly as they did before this
  feature existed, and a hand-crafted callback is refused rather than merely
  unreachable;
* the **sub-URL** — built from settings (shared hy2 domain + public port), never
  hardcoded, and never written to a log.
"""

import asyncio
import logging
from types import SimpleNamespace

import pytest

from bot.bundles import (
    bundle_config_text,
    bundle_created_text,
    bundle_detail_text,
    bundle_stats_text,
    bundles_section_text,
    subscription_url,
)
from bot.fsm.states import EditNoteStates
from bot.handlers.key_bundles import (
    confirm_bundle_action,
    delete_bundle_prompt,
    edit_bundle_note_prompt,
    open_bundle,
    revoke_bundle_prompt,
    show_bundle_config,
    show_bundle_stats,
)
from bot.handlers.keys import create_key_confirm, create_key_menu, list_keys
from bot.keyboards.key_bundles import bundle_actions_keyboard
from bot.rate_limit import RateLimiter
from i18n import t, use_locale
from models.dto import KeyBundle, KeyTrafficStatsView, TrafficStats, User, VpnKey
from models.enums import KeyBundleStatus, UserRole, VpnKeyStatus, VpnKeyType
from services.errors import InvalidOperation
from services.key_bundles import BundleMember, KeyBundleCreateResult

OWNER = 100
TOKEN = "s3cr3t-subscription-token-value-not-in-logs"


# ── stubs ─────────────────────────────────────────────────────────────────────


def _settings(**overrides: object) -> SimpleNamespace:
    values: dict[str, object] = dict(
        subscription_enabled=True,
        subscription_public_port=2096,
        hysteria2_sni="anycastedge.duckdns.org",
        hysteria2_host="203.0.113.10",
        hysteria2_enabled=True,
        xray_xhttp_enabled=True,
        key_max_trial_days=30,
    )
    values.update(overrides)
    settings = SimpleNamespace(**values)
    settings.is_hysteria2_ready = lambda: True  # type: ignore[attr-defined]
    return settings


def _bundle(bundle_id: int = 7, status: KeyBundleStatus = KeyBundleStatus.ACTIVE, note: str | None = None) -> KeyBundle:
    return KeyBundle(
        id=bundle_id,
        user_id=OWNER,
        label=f"bundle_{bundle_id:05d}",
        note=note,
        status=status,
        token=TOKEN,
        created_at="2026-07-01T10:00:00+00:00",
        updated_at="2026-07-01T10:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
    )


def _key(
    key_id: int,
    key_type: VpnKeyType = VpnKeyType.XRAY,
    transport: str = "tcp",
    xhttp_profile: str = "base",
) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=OWNER,
        username="user",
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=f"uuid-{key_id}",
        email_label=f"label_{key_id}",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="2026-07-01T10:00:00+00:00",
        updated_at="2026-07-01T10:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        created_by=OWNER,
        revoked_by=None,
        deleted_by=None,
        transport=transport,
        xhttp_profile=xhttp_profile,
    )


def _stats(key_id: int, downloaded: int, uploaded: int, *, available: bool = True) -> TrafficStats:
    return TrafficStats(
        key_id=key_id,
        downloaded_bytes=downloaded,
        uploaded_bytes=uploaded,
        last_raw_downloaded_bytes=None,
        last_raw_uploaded_bytes=None,
        last_success_at="2026-07-02T10:00:00+00:00" if available else None,
        last_attempt_at="2026-07-02T10:00:00+00:00",
        available=available,
        unavailable_reason=None,
        source="test",
    )


class _Message:
    def __init__(self) -> None:
        self.message_id = 1
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))

    async def answer(self, text: str, reply_markup: object = None) -> None:
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

    async def update_data(self, **kwargs: object) -> None:
        self.data.update(kwargs)

    async def clear(self) -> None:
        self.cleared = True
        self.data.clear()
        self.state = None


class _Users:
    async def require_approved_or_admin(self, user_id: int) -> User:
        return User(user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

    async def get_user(self, user_id: int) -> User:
        return await self.require_approved_or_admin(user_id)


class _BundleViews:
    """Recording stand-in for KeyBundleViewService."""

    def __init__(self, bundles: list[KeyBundle], keys: list[VpnKey] | None = None) -> None:
        self._bundles = bundles
        self._keys = keys if keys is not None else []
        self.calls: list[tuple[str, object]] = []

    async def list_for_actor(self, actor_user_id: int, *, limit: int = 20, offset: int = 0) -> list[KeyBundle]:
        self.calls.append(("list", limit))
        return self._bundles[offset : offset + limit]

    async def count_for_actor(self, actor_user_id: int) -> int:
        self.calls.append(("count", actor_user_id))
        return len(self._bundles)

    async def get_for_actor(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
        self.calls.append(("get", bundle_id))
        return next(bundle for bundle in self._bundles if bundle.id == bundle_id)

    async def list_keys_for_actor(self, actor_user_id: int, bundle_id: int) -> list[VpnKey]:
        self.calls.append(("keys", bundle_id))
        return self._keys

    async def update_note(self, actor_user_id: int, bundle_id: int, note: str | None) -> None:
        self.calls.append(("note", (bundle_id, note)))


class _BundleLifecycle:
    """Recording stand-in for KeyBundleService (create/revoke/delete)."""

    def __init__(self, create_result: object | None = None, create_error: Exception | None = None) -> None:
        self.calls: list[tuple[str, object]] = []
        self._create_result = create_result
        self._create_error = create_error

    async def create_bundle(
        self, actor_user_id: int, owner: object, note: str | None = None, *, expires_at: str | None = None
    ) -> object:
        self.calls.append(("create", (actor_user_id, note, expires_at)))
        if self._create_error is not None:
            raise self._create_error
        return self._create_result

    async def revoke_bundle(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
        self.calls.append(("revoke", bundle_id))
        return _bundle(bundle_id, status=KeyBundleStatus.REVOKED)

    async def delete_bundle(self, actor_user_id: int, bundle_id: int) -> None:
        self.calls.append(("delete", bundle_id))


class _VpnKeys:
    def __init__(self, keys: list[VpnKey] | None = None) -> None:
        self._keys = keys or []

    async def count_for_actor(self, actor_user_id: int, owner_user_id: int | None = None) -> int:
        return len(self._keys)

    async def list_for_actor(
        self, actor_user_id: int, owner_user_id: int | None = None, limit: int = 20, offset: int = 0
    ) -> list[VpnKey]:
        return self._keys[offset : offset + limit]


class _TrafficStats:
    def __init__(self, views: list[KeyTrafficStatsView]) -> None:
        self._views = views
        self.calls: list[list[VpnKey]] = []

    async def refresh_views(self, keys: list[VpnKey]) -> list[KeyTrafficStatsView]:
        self.calls.append(keys)
        return self._views


def _modules_enabled() -> SimpleNamespace:
    async def _is_enabled(name: str) -> bool:
        return True

    return SimpleNamespace(is_enabled=_is_enabled)


def _services(
    *,
    settings: SimpleNamespace | None = None,
    views: _BundleViews | None = None,
    lifecycle: _BundleLifecycle | None = None,
    vpn_keys: _VpnKeys | None = None,
    traffic_stats: _TrafficStats | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        settings=settings or _settings(),
        users=_Users(),
        modules=_modules_enabled(),
        key_bundle_views=views or _BundleViews([]),
        key_bundles=lifecycle or _BundleLifecycle(),
        vpn_keys=vpn_keys or _VpnKeys(),
        traffic_stats=traffic_stats or _TrafficStats([]),
    )


async def _allow_private(*args: object, **kwargs: object) -> bool:
    return True


def _callbacks(markup: object) -> list[str]:
    return [button.callback_data for row in markup.inline_keyboard for button in row]  # type: ignore[attr-defined]


@pytest.fixture(autouse=True)
def _private_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    for module in ("bot.handlers.key_bundles", "bot.handlers.keys"):
        monkeypatch.setattr(f"{module}.ensure_private_callback", _allow_private)


# ── 1. flag off: nothing about bundles is visible or reachable ────────────────


def test_create_menu_hides_all_in_one_while_flag_is_off() -> None:
    async def run() -> None:
        callback = _Callback("keys:create:menu")
        await create_key_menu(callback, _services(settings=_settings(subscription_enabled=False)))  # type: ignore[arg-type]

        assert all("bundle" not in (data or "") for data in _callbacks(callback.message.last_markup))

    asyncio.run(run())


def test_create_menu_offers_all_in_one_while_flag_is_on() -> None:
    async def run() -> None:
        callback = _Callback("keys:create:menu")
        await create_key_menu(callback, _services())  # type: ignore[arg-type]

        assert "keys:create:bundle" in _callbacks(callback.message.last_markup)

    asyncio.run(run())


def test_keys_list_has_no_bundle_group_while_flag_is_off() -> None:
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("keys:list")
        services = _services(settings=_settings(subscription_enabled=False), views=views)
        await list_keys(callback, services)  # type: ignore[arg-type]

        assert t("bundles_group_title") not in callback.message.last_text
        assert all("bundle" not in (data or "") for data in _callbacks(callback.message.last_markup))
        # The view service is not even consulted while the feature is off.
        assert views.calls == []

    asyncio.run(run())


def test_keys_list_shows_bundle_group_while_flag_is_on() -> None:
    async def run() -> None:
        callback = _Callback("keys:list")
        services = _services(views=_BundleViews([_bundle()]))
        await list_keys(callback, services)  # type: ignore[arg-type]

        text = callback.message.last_text
        assert t("bundles_group_title") in text
        assert t("bundle_title", id=7) in text
        assert "bundle:open:7" in _callbacks(callback.message.last_markup)

    asyncio.run(run())


def test_bundle_group_states_overflow_instead_of_hiding_it() -> None:
    bundles = [_bundle(bundle_id) for bundle_id in range(1, 8)]

    section = bundles_section_text(bundles[:5], viewer_user_id=OWNER, total=len(bundles))

    assert t("bundles_more_hint", shown=5, total=7) in section


@pytest.mark.parametrize(
    "handler, data",
    [
        (open_bundle, "bundle:open:7"),
        (revoke_bundle_prompt, "bundle:revoke:7"),
        (delete_bundle_prompt, "bundle:delete:7"),
    ],
)
def test_direct_bundle_callback_is_refused_while_flag_is_off(handler: object, data: str) -> None:
    views = _BundleViews([_bundle()])
    lifecycle = _BundleLifecycle()

    async def run() -> None:
        callback = _Callback(data)
        services = _services(settings=_settings(subscription_enabled=False), views=views, lifecycle=lifecycle)
        await handler(callback, services)  # type: ignore[operator]

        assert callback.alerts == [t("err_subscription_disabled")]
        assert callback.message.edits == []
        assert views.calls == []
        assert lifecycle.calls == []

    asyncio.run(run())


def test_direct_bundle_config_and_stats_callbacks_are_refused_while_flag_is_off() -> None:
    views = _BundleViews([_bundle()], keys=[_key(1)])
    traffic = _TrafficStats([])

    async def run() -> None:
        services = _services(settings=_settings(subscription_enabled=False), views=views, traffic_stats=traffic)
        for handler, data in ((show_bundle_config, "bundle:show:7"), (show_bundle_stats, "bundle:stats:7")):
            callback = _Callback(data)
            await handler(callback, services, RateLimiter())  # type: ignore[operator]
            assert callback.alerts == [t("err_subscription_disabled")]
            assert callback.message.edits == []
        assert views.calls == []
        assert traffic.calls == []

    asyncio.run(run())


def test_direct_bundle_confirm_callback_is_refused_while_flag_is_off() -> None:
    lifecycle = _BundleLifecycle()

    async def run() -> None:
        services = _services(settings=_settings(subscription_enabled=False), lifecycle=lifecycle)
        for action in ("revoke", "delete"):
            callback = _Callback(f"bundle:confirm:{action}:7")
            await confirm_bundle_action(callback, services, RateLimiter())  # type: ignore[arg-type]
            assert callback.alerts == [t("err_subscription_disabled")]
        assert lifecycle.calls == []

    asyncio.run(run())


def test_bundle_create_confirm_is_refused_while_flag_is_off() -> None:
    lifecycle = _BundleLifecycle(create_result=None)

    async def run() -> None:
        callback = _Callback("create:confirm")
        state = _State({"key_type": "bundle", "note": "note", "expires_at": None})
        services = _services(settings=_settings(subscription_enabled=False), lifecycle=lifecycle)
        await create_key_confirm(callback, state, services, RateLimiter())  # type: ignore[arg-type]

        assert callback.alerts == [t("err_subscription_disabled")]
        assert lifecycle.calls == []

    asyncio.run(run())


# ── 2. creation ───────────────────────────────────────────────────────────────


def _create_result(keys: tuple[VpnKey, ...], skipped: tuple[BundleMember, ...] = ()) -> KeyBundleCreateResult:
    return KeyBundleCreateResult(
        bundle=_bundle(),
        keys=keys,
        included=tuple(BundleMember(key.key_type, key.transport, key.xhttp_profile) for key in keys),
        skipped=skipped,
    )


def test_create_confirm_calls_the_bundle_service_and_shows_the_card() -> None:
    result = _create_result((_key(1), _key(2, VpnKeyType.HYSTERIA2)))
    lifecycle = _BundleLifecycle(create_result=result)

    async def run() -> None:
        callback = _Callback("create:confirm")
        state = _State({"key_type": "bundle", "note": "phone", "expires_at": "2030-01-01T00:00:00+00:00"})
        await create_key_confirm(callback, state, _services(lifecycle=lifecycle), RateLimiter())  # type: ignore[arg-type]

        assert lifecycle.calls == [("create", (OWNER, "phone", "2030-01-01T00:00:00+00:00"))]
        text = callback.message.last_text
        assert t("bundle_created_title") in text
        assert "VLESS (TCP)" in text and "Hysteria2" in text
        assert state.cleared is True

    asyncio.run(run())


def test_create_confirm_screen_names_the_bundle_and_its_expiry() -> None:
    from bot.bundles import bundle_create_confirm_text

    text = bundle_create_confirm_text("phone", expires_at="2030-01-01T00:00:00+00:00")

    assert t("bundle_create_confirm_title") in text
    assert t("bundle_type_label") in text
    assert "phone" in text
    assert t("bundle_awg_separate") in text


def test_partial_provisioning_names_what_actually_went_in_and_what_did_not() -> None:
    result = _create_result((_key(1),), skipped=(BundleMember(VpnKeyType.HYSTERIA2),))

    text = bundle_created_text(result, viewer_user_id=OWNER)

    assert "VLESS (TCP)" in text
    # The omission is spelled out rather than silently missing from the list.
    assert t("bundle_created_skipped", skipped="Hysteria2") in text


def test_degraded_backend_yields_a_plain_retry_message_and_no_traceback(caplog: pytest.LogCaptureFixture) -> None:
    # Exactly what BackendHealth.require_mutation_allowed raises: an unkeyed
    # InvalidOperation carrying operator-facing text about the backend.
    degraded = InvalidOperation(
        "Hysteria2-операции временно заблокированы: backend degraded (hy2_auth /healthz недоступен). "
        "Проверьте конфиг/runtime на сервере и перезапустите бота после восстановления."
    )
    lifecycle = _BundleLifecycle(create_error=degraded)

    async def run() -> None:
        callback = _Callback("create:confirm")
        state = _State({"key_type": "bundle", "note": None, "expires_at": None})
        with caplog.at_level(logging.WARNING):
            await create_key_confirm(callback, state, _services(lifecycle=lifecycle), RateLimiter())  # type: ignore[arg-type]

        assert callback.alerts == [t("bundle_create_failed")]
        assert "backend degraded" not in callback.alerts[0]
        assert "Traceback" not in callback.alerts[0]
        # No unexpected-error path: a safe exception must not be logged as one.
        assert all(record.levelno < logging.ERROR for record in caplog.records)

    asyncio.run(run())


# ── 3. the card and its five buttons ──────────────────────────────────────────


def test_active_bundle_card_has_exactly_the_five_actions() -> None:
    assert _callbacks(bundle_actions_keyboard(_bundle())) == [
        "bundle:show:7",
        "bundle:stats:7",
        "bundle:revoke:7",
        "bundle:note:7",
        "bundle:delete:7",
        "keys:list",
    ]


def test_revoked_bundle_card_drops_config_and_revoke() -> None:
    callbacks = _callbacks(bundle_actions_keyboard(_bundle(status=KeyBundleStatus.REVOKED)))

    assert "bundle:show:7" not in callbacks
    assert "bundle:revoke:7" not in callbacks
    assert "bundle:delete:7" in callbacks


def test_key_list_rows_drop_config_and_revoke_for_a_revoked_bundle() -> None:
    from bot.keyboards.key_bundles import bundle_list_rows

    active = [button.callback_data for row in bundle_list_rows([_bundle()]) for button in row]
    revoked = [
        button.callback_data
        for row in bundle_list_rows([_bundle(status=KeyBundleStatus.REVOKED)])
        for button in row
    ]

    assert active == ["bundle:open:7", "bundle:show:7", "bundle:stats:7", "bundle:revoke:7", "bundle:note:7", "bundle:delete:7"]
    assert revoked == ["bundle:open:7", "bundle:stats:7", "bundle:note:7", "bundle:delete:7"]


def test_open_bundle_renders_the_card_with_its_contents() -> None:
    views = _BundleViews([_bundle()], keys=[_key(1), _key(2, VpnKeyType.HYSTERIA2)])

    async def run() -> None:
        callback = _Callback("bundle:open:7")
        await open_bundle(callback, _services(views=views))  # type: ignore[arg-type]

        text = callback.message.last_text
        assert t("bundle_composition") in text
        assert "VLESS (TCP)" in text and "Hysteria2" in text
        assert ("get", 7) in views.calls

    asyncio.run(run())


def test_bundle_card_shows_the_shared_expiry_of_its_children() -> None:
    import dataclasses

    expiring = dataclasses.replace(_key(1), expires_at="2030-01-01T00:00:00+00:00")

    text = bundle_detail_text(_bundle(), [expiring], viewer_user_id=OWNER)

    assert t("field_expires") in text


def test_bundle_with_no_children_says_so_instead_of_showing_empty_stats() -> None:
    assert t("bundle_stats_empty") in bundle_stats_text(_bundle(), [])
    assert t("none") in bundle_detail_text(_bundle(), [], viewer_user_id=OWNER)


def test_note_button_enters_the_shared_note_wizard_for_the_bundle() -> None:
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("bundle:note:7")
        state = _State()
        await edit_bundle_note_prompt(callback, state, _services(views=views))  # type: ignore[arg-type]

        assert state.state == EditNoteStates.waiting_note
        assert state.data["bundle_id"] == 7
        assert state.data["cancel_target"] == "bundle:open:7"

    asyncio.run(run())


# ── 4. config: the sub-URL comes from settings and never from a log ───────────


def test_subscription_url_is_built_from_settings() -> None:
    assert (
        subscription_url(_settings(), TOKEN)  # type: ignore[arg-type]
        == f"https://anycastedge.duckdns.org:2096/sub/{TOKEN}"
    )
    # A different deployment yields a different URL — nothing is hardcoded.
    assert (
        subscription_url(_settings(hysteria2_sni="vpn.example.net", subscription_public_port=8443), TOKEN)  # type: ignore[arg-type]
        == f"https://vpn.example.net:8443/sub/{TOKEN}"
    )
    # Standard HTTPS port is omitted, and HYSTERIA2_HOST is the fallback host.
    assert (
        subscription_url(_settings(hysteria2_sni="", subscription_public_port=443), TOKEN)  # type: ignore[arg-type]
        == f"https://203.0.113.10/sub/{TOKEN}"
    )


def test_subscription_url_is_none_when_the_endpoint_is_not_published() -> None:
    assert subscription_url(_settings(subscription_public_port=0), TOKEN) is None  # type: ignore[arg-type]
    assert subscription_url(_settings(hysteria2_sni="", hysteria2_host=""), TOKEN) is None  # type: ignore[arg-type]


def test_config_screen_shows_the_url_and_keeps_the_token_out_of_the_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("bundle:show:7")
        with caplog.at_level(logging.DEBUG):
            await show_bundle_config(callback, _services(views=views), RateLimiter())  # type: ignore[arg-type]

        assert f"https://anycastedge.duckdns.org:2096/sub/{TOKEN}" in callback.message.last_text
        assert all(TOKEN not in record.getMessage() for record in caplog.records)

    asyncio.run(run())


def test_config_screen_says_so_when_no_public_endpoint_is_configured() -> None:
    text = bundle_config_text(_bundle(), _settings(subscription_public_port=0))  # type: ignore[arg-type]

    assert t("bundle_config_unavailable") in text
    assert TOKEN not in text


# ── 5. stats: totals with the per-protocol split ──────────────────────────────


def test_bundle_stats_split_traffic_per_protocol() -> None:
    vless = _key(1)
    vless_http = _key(2, transport="http", xhttp_profile="multi")
    hy2 = _key(3, VpnKeyType.HYSTERIA2)
    views = [
        KeyTrafficStatsView(key=vless, owner=None, stats=_stats(1, 1024, 512)),
        KeyTrafficStatsView(key=vless_http, owner=None, stats=_stats(2, 1024, 512)),
        KeyTrafficStatsView(key=hy2, owner=None, stats=_stats(3, 4096, 2048)),
    ]

    text = bundle_stats_text(_bundle(), views)

    assert t("bundle_stats_by_protocol") in text
    assert "VLESS" in text and "Hysteria2" in text
    # VLESS rolls the two Xray children into one row: 2 KiB down / 1 KiB up.
    assert "2.00 KB" in text
    assert "4.00 KB" in text
    # ... and the total is the sum of both sources.
    assert "6.00 KB" in text


def test_bundle_stats_marks_a_source_that_is_unavailable() -> None:
    views = [
        KeyTrafficStatsView(key=_key(1), owner=None, stats=_stats(1, 1024, 512)),
        KeyTrafficStatsView(
            key=_key(3, VpnKeyType.HYSTERIA2), owner=None, stats=_stats(3, 0, 0, available=False)
        ),
    ]

    text = bundle_stats_text(_bundle(), views)

    assert t("bundle_stats_unavailable") in text
    assert "VLESS" in text


def test_stats_handler_refreshes_the_children_of_the_bundle() -> None:
    keys = [_key(1), _key(3, VpnKeyType.HYSTERIA2)]
    traffic = _TrafficStats(
        [
            KeyTrafficStatsView(key=keys[0], owner=None, stats=_stats(1, 1024, 512)),
            KeyTrafficStatsView(key=keys[1], owner=None, stats=_stats(3, 2048, 1024)),
        ]
    )
    views = _BundleViews([_bundle()], keys=keys)

    async def run() -> None:
        callback = _Callback("bundle:stats:7")
        await show_bundle_stats(callback, _services(views=views, traffic_stats=traffic), RateLimiter())  # type: ignore[arg-type]

        assert traffic.calls == [keys]
        assert t("bundle_stats_by_protocol") in callback.message.last_text

    asyncio.run(run())


# ── 6. revoke / delete: confirmation, then the right service call ─────────────


def test_revoke_asks_for_confirmation_before_touching_the_service() -> None:
    lifecycle = _BundleLifecycle()
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("bundle:revoke:7")
        await revoke_bundle_prompt(callback, _services(views=views, lifecycle=lifecycle))  # type: ignore[arg-type]

        assert t("bundle_revoke_prompt", bundle_id=7) in callback.message.last_text
        assert _callbacks(callback.message.last_markup) == ["bundle:confirm:revoke:7", "bundle:open:7"]
        assert lifecycle.calls == []

    asyncio.run(run())


def test_delete_asks_for_confirmation_before_touching_the_service() -> None:
    lifecycle = _BundleLifecycle()
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("bundle:delete:7")
        await delete_bundle_prompt(callback, _services(views=views, lifecycle=lifecycle))  # type: ignore[arg-type]

        assert t("bundle_delete_prompt", bundle_id=7) in callback.message.last_text
        assert _callbacks(callback.message.last_markup) == ["bundle:confirm:delete:7", "bundle:open:7"]
        assert lifecycle.calls == []

    asyncio.run(run())


def test_confirmed_revoke_and_delete_reach_the_bundle_service() -> None:
    lifecycle = _BundleLifecycle()

    async def run() -> None:
        services = _services(lifecycle=lifecycle)
        revoke = _Callback("bundle:confirm:revoke:7")
        await confirm_bundle_action(revoke, services, RateLimiter())  # type: ignore[arg-type]
        delete = _Callback("bundle:confirm:delete:7")
        await confirm_bundle_action(delete, services, RateLimiter())  # type: ignore[arg-type]

        assert lifecycle.calls == [("revoke", 7), ("delete", 7)]
        assert t("bundle_revoked") in revoke.message.last_text
        assert t("bundle_deleted") in delete.message.last_text

    asyncio.run(run())


def test_malformed_bundle_callback_is_rejected() -> None:
    lifecycle = _BundleLifecycle()

    async def run() -> None:
        callback = _Callback("bundle:confirm:revoke:not-a-number")
        await confirm_bundle_action(callback, _services(lifecycle=lifecycle), RateLimiter())  # type: ignore[arg-type]

        assert callback.alerts == [t("invalid_callback_btn")]
        assert lifecycle.calls == []

    asyncio.run(run())


# ── 7. the AmneziaWG explanation, in both locales ─────────────────────────────


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_awg_is_explained_on_every_bundle_surface(locale: str) -> None:
    with use_locale(locale):
        note = t("bundle_awg_separate")
        assert "AmneziaWG" in note
        assert note != "bundle_awg_separate"

        assert note in bundle_detail_text(_bundle(), [_key(1)], viewer_user_id=OWNER)
        assert note in bundles_section_text([_bundle()], viewer_user_id=OWNER, total=1)
        assert note in bundle_config_text(_bundle(), _settings())  # type: ignore[arg-type]
        assert note in bundle_created_text(_create_result((_key(1),)), viewer_user_id=OWNER)


# ── 8. note privacy ───────────────────────────────────────────────────────────


def test_bundle_note_is_hidden_from_a_viewer_who_is_not_the_owner() -> None:
    bundle = _bundle(note="my phone")

    assert "my phone" in bundle_detail_text(bundle, [], viewer_user_id=OWNER)
    assert "my phone" not in bundle_detail_text(bundle, [], viewer_user_id=OWNER + 1)


# ── 9. the note wizard is the SAME FSM the per-key flow uses ──────────────────


class _NoteMessage:
    def __init__(self, text: str) -> None:
        self.text = text
        self.from_user = SimpleNamespace(id=OWNER, username="user", first_name="User")
        self.chat = SimpleNamespace(id=OWNER)
        self.answers: list[tuple[str, object]] = []

    async def answer(self, text: str, reply_markup: object = None) -> None:
        self.answers.append((text, reply_markup))


class _Bot:
    async def delete_message(self, chat_id: int, message_id: int) -> None:
        return None


def test_note_wizard_confirms_then_saves_the_note_on_the_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _allow_private_message(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("bot.handlers.keys.ensure_private_message", _allow_private_message)
    views = _BundleViews([_bundle()])

    async def run() -> None:
        from bot.handlers.keys import edit_note_confirm, edit_note_waiting

        services = _services(views=views)
        state = _State({"bundle_id": 7, "note_prompt_msg_id": 5})
        message = _NoteMessage("home router")
        await edit_note_waiting(message, state, services, _Bot())  # type: ignore[arg-type]

        assert state.state == EditNoteStates.confirming
        assert t("bundle_title", id=7) in message.answers[-1][0]

        callback = _Callback("note:confirm")
        await edit_note_confirm(callback, state, services, RateLimiter())  # type: ignore[arg-type]

        assert ("note", (7, "home router")) in views.calls
        assert t("note_updated") in callback.message.last_text

    asyncio.run(run())


# ── 10. the read service: flag gate and ownership ─────────────────────────────


class _StubBundleRepo:
    def __init__(self, bundles: list[KeyBundle]) -> None:
        self._bundles = bundles
        self.notes: list[tuple[int, str | None]] = []

    async def list_by_user(self, user_id: int, limit: int = 50, offset: int = 0) -> list[KeyBundle]:
        return [bundle for bundle in self._bundles if bundle.user_id == user_id][offset : offset + limit]

    async def count_by_user(self, user_id: int) -> int:
        return len([bundle for bundle in self._bundles if bundle.user_id == user_id])

    async def get_by_id(self, bundle_id: int) -> KeyBundle | None:
        return next((bundle for bundle in self._bundles if bundle.id == bundle_id), None)

    async def list_keys_of_bundle(self, bundle_id: int) -> list[VpnKey]:
        return [_key(1)]

    async def update_note(self, bundle_id: int, note: str | None, now: str) -> None:
        self.notes.append((bundle_id, note))


def _view_service(*, enabled: bool = True, bundles: list[KeyBundle] | None = None) -> tuple[object, _StubBundleRepo]:
    from services.key_bundle_views import KeyBundleViewService

    repo = _StubBundleRepo(bundles if bundles is not None else [_bundle()])
    users = _Users()
    users.clock = SimpleNamespace(now=lambda: "2026-07-02T10:00:00+00:00")  # type: ignore[attr-defined]

    async def _write_best_effort(**kwargs: object) -> None:
        return None

    service = KeyBundleViewService(
        bundles=repo,  # type: ignore[arg-type]
        users=users,  # type: ignore[arg-type]
        settings=_settings(subscription_enabled=enabled),  # type: ignore[arg-type]
        audit=SimpleNamespace(write_best_effort=_write_best_effort),  # type: ignore[arg-type]
    )
    return service, repo


def test_view_service_refuses_every_read_while_flag_is_off() -> None:
    service, _repo = _view_service(enabled=False)

    async def run() -> None:
        for call in (
            service.count_for_actor(OWNER),  # type: ignore[attr-defined]
            service.list_for_actor(OWNER),  # type: ignore[attr-defined]
            service.get_for_actor(OWNER, 7),  # type: ignore[attr-defined]
            service.update_note(OWNER, 7, "x"),  # type: ignore[attr-defined]
        ):
            with pytest.raises(InvalidOperation) as excinfo:
                await call
            assert excinfo.value.key == "err_subscription_disabled"

    asyncio.run(run())


def test_view_service_reads_only_the_actors_own_bundles() -> None:
    mine = _bundle(7)
    theirs = KeyBundle(
        id=8,
        user_id=OWNER + 1,
        label="bundle_00008",
        note=None,
        status=KeyBundleStatus.ACTIVE,
        token="other-token",
        created_at="2026-07-01T10:00:00+00:00",
        updated_at="2026-07-01T10:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
    )
    service, _repo = _view_service(bundles=[mine, theirs])

    async def run() -> None:
        assert await service.count_for_actor(OWNER) == 1  # type: ignore[attr-defined]
        assert await service.list_for_actor(OWNER) == [mine]  # type: ignore[attr-defined]
        assert [key.id for key in await service.list_keys_for_actor(OWNER, 7)] == [1]  # type: ignore[attr-defined]

    asyncio.run(run())


def test_view_service_reports_a_missing_bundle_as_not_found() -> None:
    from services.errors import NotFound

    service, _repo = _view_service()

    async def run() -> None:
        with pytest.raises(NotFound) as excinfo:
            await service.get_for_actor(OWNER, 999)  # type: ignore[attr-defined]
        assert excinfo.value.key == "err_bundle_not_found"

    asyncio.run(run())


def test_view_service_refuses_a_foreign_bundle() -> None:
    from services.errors import AccessDenied

    service, repo = _view_service()

    async def run() -> None:
        with pytest.raises(AccessDenied) as excinfo:
            await service.get_for_actor(OWNER + 1, 7)  # type: ignore[attr-defined]
        assert excinfo.value.key == "err_foreign_bundle_view"

        with pytest.raises(AccessDenied):
            await service.update_note(OWNER + 1, 7, "x")  # type: ignore[attr-defined]
        assert repo.notes == []

    asyncio.run(run())


def test_view_service_normalizes_and_stores_the_note() -> None:
    service, repo = _view_service()

    async def run() -> None:
        await service.update_note(OWNER, 7, "  laptop  ")  # type: ignore[attr-defined]
        # "-" is the documented "clear the note" input.
        await service.update_note(OWNER, 7, "-")  # type: ignore[attr-defined]

        assert repo.notes == [(7, "laptop"), (7, None)]

    asyncio.run(run())
