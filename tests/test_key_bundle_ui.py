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
    bundle_stats_block,
    subscription_url,
)
from bot.formatters import bundle_card_text
from bot.fsm.states import CreateKeyStates, EditFpStates, EditNoteStates
from bot.handlers.key_bundles import (
    change_bundle_fp_prompt,
    confirm_bundle_action,
    delete_bundle_prompt,
    edit_bundle_note_prompt,
    open_bundle,
    revoke_bundle_prompt,
    show_bundle_config,
)
from bot.handlers.keys import (
    KEYS_PAGE_SIZE,
    create_key_bundle_ack,
    create_key_choose_bundle,
    create_key_confirm,
    create_key_menu,
    create_key_note,
    edit_fp_select,
    list_keys,
)
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


# What a bundle's `display_no` is offset by, relative to its row id, in these
# fixtures. Non-zero on purpose: the displayed number comes from the shared
# key/bundle counter while callback data still addresses the row id, and a fixture
# where the two were equal could not tell the one being used from the other.
DISPLAY_OFFSET = 100


def _bundle(
    bundle_id: int = 7,
    status: KeyBundleStatus = KeyBundleStatus.ACTIVE,
    note: str | None = None,
    created_at: str = "2026-07-01T10:00:00+00:00",
) -> KeyBundle:
    return KeyBundle(
        id=bundle_id,
        user_id=OWNER,
        label=f"bundle_{bundle_id:05d}",
        note=note,
        status=status,
        token=TOKEN,
        created_at=created_at,
        updated_at=created_at,
        revoked_at=None,
        deleted_at=None,
        display_no=bundle_id + DISPLAY_OFFSET,
    )


def _key(
    key_id: int,
    key_type: VpnKeyType = VpnKeyType.XRAY,
    transport: str = "tcp",
    xhttp_profile: str = "base",
    created_at: str = "2026-07-01T10:00:00+00:00",
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
        created_at=created_at,
        updated_at=created_at,
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
        # Newest first, like the repository's ``ORDER BY created_at DESC, id DESC``:
        # ``load_list_page`` reads a bounded window off the top of each source, so a
        # stub in insertion order would hide the very entries the merge is about.
        ordered = sorted(self._bundles, key=lambda b: (b.created_at, b.id), reverse=True)
        return ordered[offset : offset + limit]

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
        self,
        actor_user_id: int,
        owner: object,
        note: str | None = None,
        *,
        expires_at: str | None = None,
        fingerprint: str | None = None,
    ) -> object:
        self.calls.append(("create", (actor_user_id, note, expires_at, fingerprint)))
        if self._create_error is not None:
            raise self._create_error
        return self._create_result

    async def change_fingerprint(
        self, actor_user_id: int, bundle_id: int, fingerprint: str
    ) -> tuple[KeyBundle, int]:
        self.calls.append(("fingerprint", (bundle_id, fingerprint)))
        return _bundle(bundle_id), 4

    async def revoke_bundle(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
        self.calls.append(("revoke", bundle_id))
        return _bundle(bundle_id, status=KeyBundleStatus.REVOKED)

    async def delete_bundle(self, actor_user_id: int, bundle_id: int) -> None:
        self.calls.append(("delete", bundle_id))


class _VpnKeys:
    """Stand-in for VpnKeyQueryService that honours ``exclude_bundled``.

    ``bundled`` are the keys that belong to a bundle; a real query drops them when
    the flag is set, so the stub does too — otherwise a test could not tell the
    filtered list from the unfiltered one.
    """

    def __init__(self, keys: list[VpnKey] | None = None, bundled: list[VpnKey] | None = None) -> None:
        self._keys = keys or []
        self._bundled = bundled or []
        self.exclude_bundled_calls: list[bool] = []

    def _visible(self, exclude_bundled: bool) -> list[VpnKey]:
        self.exclude_bundled_calls.append(exclude_bundled)
        visible = self._keys if exclude_bundled else [*self._keys, *self._bundled]
        # Newest first, like the repository's ``ORDER BY created_at DESC``.
        return sorted(visible, key=lambda k: (k.created_at, k.id), reverse=True)

    async def count_for_actor(
        self, actor_user_id: int, owner_user_id: int | None = None, *, exclude_bundled: bool = False
    ) -> int:
        return len(self._visible(exclude_bundled))

    async def list_for_actor(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
        *,
        exclude_bundled: bool = False,
    ) -> list[VpnKey]:
        return self._visible(exclude_bundled)[offset : offset + limit]


class _TrafficStats:
    def __init__(self, views: list[KeyTrafficStatsView]) -> None:
        self._views = views
        self.calls: list[list[VpnKey]] = []

    async def refresh_views(self, keys: list[VpnKey]) -> list[KeyTrafficStatsView]:
        self.calls.append(keys)
        return self._views

    async def cached_for_keys(self, keys: list[VpnKey]) -> dict[int, TrafficStats]:
        return {view.key.id: view.stats for view in self._views if view.stats is not None}


def _modules_enabled(*disabled: str) -> SimpleNamespace:
    async def _is_enabled(name: str) -> bool:
        return name not in disabled

    return SimpleNamespace(is_enabled=_is_enabled)


def _services(
    *,
    settings: SimpleNamespace | None = None,
    views: _BundleViews | None = None,
    lifecycle: _BundleLifecycle | None = None,
    vpn_keys: _VpnKeys | None = None,
    traffic_stats: _TrafficStats | None = None,
    modules: SimpleNamespace | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        settings=settings or _settings(),
        users=_Users(),
        modules=modules or _modules_enabled(),
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
    monkeypatch.setattr("bot.handlers.keys.ensure_private_message", _allow_private)


class _NoteMessage:
    """Minimal Message stand-in for the text steps of the create/note wizards."""

    def __init__(self, text: str = "phone") -> None:
        self.text = text
        self.from_user = SimpleNamespace(id=OWNER, username="user", first_name="User")
        self.chat = SimpleNamespace(id=OWNER)
        self.answers: list[tuple[str, object]] = []

    async def answer(self, text: str, reply_markup: object = None) -> None:
        self.answers.append((text, reply_markup))

    @property
    def last_text(self) -> str:
        return self.answers[-1][0]

    @property
    def last_markup(self) -> object:
        return self.answers[-1][1]


class _Bot:
    async def delete_message(self, chat_id: int, message_id: int) -> None:
        return None


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


def test_keys_list_has_no_bundle_entry_while_flag_is_off() -> None:
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("keys:list")
        services = _services(settings=_settings(subscription_enabled=False), views=views)
        await list_keys(callback, services)  # type: ignore[arg-type]

        assert t("bundle_title", id=7 + DISPLAY_OFFSET) not in callback.message.last_text
        assert all("bundle" not in (data or "") for data in _callbacks(callback.message.last_markup))
        # The view service is not even consulted while the feature is off.
        assert views.calls == []

    asyncio.run(run())


def test_keys_list_shows_the_bundle_as_an_ordinary_entry_while_flag_is_on() -> None:
    async def run() -> None:
        callback = _Callback("keys:list")
        services = _services(views=_BundleViews([_bundle()]))
        await list_keys(callback, services)  # type: ignore[arg-type]

        text = callback.message.last_text
        # Numbered from the shared counter, not from the bundle's row id.
        assert t("bundle_title", id=7 + DISPLAY_OFFSET) in text
        assert t("bundle_title", id=7) not in text
        assert "bundle:open:7" in _callbacks(callback.message.last_markup)

    asyncio.run(run())


def test_keys_and_bundles_share_one_date_sorted_page() -> None:
    """Keys and subscriptions interleave by date, KEYS_PAGE_SIZE entries to a page."""
    keys = [
        _key(1, created_at="2026-07-01T00:00:00+00:00"),
        _key(2, created_at="2026-07-03T00:00:00+00:00"),
        _key(3, created_at="2026-07-05T00:00:00+00:00"),
        _key(4, created_at="2026-07-07T00:00:00+00:00"),
    ]
    bundles = [
        _bundle(11, created_at="2026-07-02T00:00:00+00:00"),
        _bundle(12, created_at="2026-07-06T00:00:00+00:00"),
    ]

    async def run() -> None:
        services = _services(views=_BundleViews(bundles), vpn_keys=_VpnKeys(keys))

        first = _Callback("keys:list")
        await list_keys(first, services)  # type: ignore[arg-type]
        page_one = [data for data in _callbacks(first.message.last_markup) if ":open:" in (data or "")]

        second = _Callback("keys:list:1")
        await list_keys(second, services)  # type: ignore[arg-type]
        page_two = [data for data in _callbacks(second.message.last_markup) if ":open:" in (data or "")]

        # Newest first, across both kinds, capped at one page worth of entries.
        assert KEYS_PAGE_SIZE == 3
        assert page_one == ["key:open:4", "bundle:open:12", "key:open:3"]
        # ...and the tail continues on page 2 with nothing repeated or dropped.
        assert page_two == ["key:open:2", "bundle:open:11", "key:open:1"]

    asyncio.run(run())


@pytest.mark.parametrize(
    "handler, data",
    [
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


def test_direct_bundle_open_callback_is_refused_while_flag_is_off() -> None:
    views = _BundleViews([_bundle()])
    traffic = _TrafficStats([])

    async def run() -> None:
        callback = _Callback("bundle:open:7")
        services = _services(
            settings=_settings(subscription_enabled=False), views=views, traffic_stats=traffic
        )
        await open_bundle(callback, services, RateLimiter())  # type: ignore[arg-type]

        assert callback.alerts == [t("err_subscription_disabled")]
        assert callback.message.edits == []
        assert views.calls == []
        # …and no backend was sampled on the way to the refusal.
        assert traffic.calls == []

    asyncio.run(run())


def test_direct_bundle_config_callback_is_refused_while_flag_is_off() -> None:
    views = _BundleViews([_bundle()], keys=[_key(1)])
    traffic = _TrafficStats([])

    async def run() -> None:
        services = _services(settings=_settings(subscription_enabled=False), views=views, traffic_stats=traffic)
        callback = _Callback("bundle:show:7")
        await show_bundle_config(callback, services, RateLimiter())  # type: ignore[arg-type]
        assert callback.alerts == [t("err_subscription_disabled")]
        assert callback.message.edits == []
        assert views.calls == []
        assert traffic.calls == []

    asyncio.run(run())


def test_direct_bundle_fingerprint_callback_is_refused_while_flag_is_off() -> None:
    views = _BundleViews([_bundle()])
    lifecycle = _BundleLifecycle()

    async def run() -> None:
        callback = _Callback("bundle:fp:7")
        state = _State()
        services = _services(settings=_settings(subscription_enabled=False), views=views, lifecycle=lifecycle)
        await change_bundle_fp_prompt(callback, state, services)  # type: ignore[arg-type]

        assert callback.alerts == [t("err_subscription_disabled")]
        assert callback.message.edits == []
        assert views.calls == []
        assert lifecycle.calls == []

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


# ── 1b. the key list shows the bundle, not its children ───────────────────────


def test_keys_list_asks_for_the_children_of_bundles_to_be_left_out() -> None:
    """«Мои ключи» lists standalone keys plus the All-in-One card — never both.

    A bundle's five children used to be rendered as five ordinary keys with their
    own Revoke/Delete buttons, which at ``KEYS_PAGE_SIZE = 5`` filled the whole
    first page and pushed the bundle card (first page only) out of sight.
    """
    standalone = _key(1)
    children = [_key(20 + index) for index in range(5)]
    vpn_keys = _VpnKeys([standalone], bundled=children)
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("keys:list")
        await list_keys(callback, _services(views=views, vpn_keys=vpn_keys))  # type: ignore[arg-type]

        # Both the count and the page must be filtered, or the two disagree about
        # how many pages there are.
        assert vpn_keys.exclude_bundled_calls == [True, True]
        rows = _callbacks(callback.message.last_markup)
        assert "bundle:open:7" in rows
        assert "key:open:1" in rows
        assert not [row for row in rows if row.startswith(("key:open:2", "key:revoke:2"))]

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
        state = _State(
            {
                "key_type": "bundle",
                "note": "phone",
                "expires_at": "2030-01-01T00:00:00+00:00",
                "fingerprint": "safari",
            }
        )
        await create_key_confirm(callback, state, _services(lifecycle=lifecycle), RateLimiter())  # type: ignore[arg-type]

        # The fingerprint chosen once in the wizard reaches the service, which
        # hands it to every VLESS child.
        assert lifecycle.calls == [("create", (OWNER, "phone", "2030-01-01T00:00:00+00:00", "safari"))]
        text = callback.message.last_text
        assert t("bundle_created_title") in text
        assert "VLESS (TCP)" in text and "Hysteria2" in text
        # The wizard ends with the credential on screen, like the single-key flow.
        assert f"https://anycastedge.duckdns.org:2096/sub/{TOKEN}" in text
        assert state.cleared is True

    asyncio.run(run())


def test_create_confirm_screen_names_the_bundle_and_its_expiry() -> None:
    from bot.bundles import bundle_create_confirm_text

    text = bundle_create_confirm_text("phone", expires_at="2030-01-01T00:00:00+00:00")

    assert t("bundle_create_confirm_title") in text
    assert t("bundle_type_label") in text
    assert "phone" in text
    assert t("bundle_awg_separate") in text


def test_bundle_wizard_asks_for_a_fingerprint_once() -> None:
    """The note step hands a bundle to the shared fingerprint step, not to expiry.

    The prompt is the bundle-specific one, because the answer is applied to all
    four VLESS children at once rather than to a single key.
    """

    async def run() -> None:
        message = _NoteMessage()
        state = _State({"key_type": "bundle", "note_prompt_msg_id": 1})
        await create_key_note(message, state, _services(), _Bot())  # type: ignore[arg-type]

        assert state.state == CreateKeyStates.waiting_fp
        assert message.last_text == t("bundle_fp_prompt")
        assert "fp:safari" in _callbacks(message.last_markup)

    asyncio.run(run())


def test_bundle_wizard_skips_the_fingerprint_step_when_xray_is_off() -> None:
    """No VLESS child means nothing to apply a fingerprint to — so do not ask."""

    async def run() -> None:
        message = _NoteMessage()
        state = _State({"key_type": "bundle", "note_prompt_msg_id": 1})
        await create_key_note(  # type: ignore[arg-type]
            message, state, _services(modules=_modules_enabled("xray")), _Bot()
        )

        assert state.state == CreateKeyStates.waiting_expiry
        assert message.last_text == t("expiry_prompt")

    asyncio.run(run())


def test_created_screen_says_so_when_no_public_endpoint_is_configured() -> None:
    """A bundle with nowhere to publish it says so instead of leaking a bare token."""
    text = bundle_created_text(  # type: ignore[arg-type]
        _create_result((_key(1),)),
        viewer_user_id=OWNER,
        settings=_settings(subscription_public_port=0),
    )

    assert t("bundle_config_unavailable") in text
    assert TOKEN not in text


def test_created_screen_carries_the_same_secret_warning_as_the_config_screen() -> None:
    """The link is a credential wherever it is shown, so the warning travels with it."""
    text = bundle_created_text(  # type: ignore[arg-type]
        _create_result((_key(1),)), viewer_user_id=OWNER, settings=_settings()
    )

    assert f"https://anycastedge.duckdns.org:2096/sub/{TOKEN}" in text
    assert t("bundle_config_secret_warning") in text
    assert t("bundle_config_hint") in text


def test_partial_provisioning_names_what_actually_went_in_and_what_did_not() -> None:
    result = _create_result((_key(1),), skipped=(BundleMember(VpnKeyType.HYSTERIA2),))

    text = bundle_created_text(result, viewer_user_id=OWNER, settings=_settings())  # type: ignore[arg-type]

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


# ── 3. the card and its buttons ───────────────────────────────────────────────


def test_active_bundle_card_follows_the_shared_action_order() -> None:
    """config · note · fingerprint · revoke · delete — the same order, in the same
    places, as a single key's menu. No stats row: the traffic is on the screen."""
    assert _callbacks(bundle_actions_keyboard(_bundle(), has_vless=True)) == [
        "bundle:show:7",
        "bundle:note:7",
        "bundle:fp:7",
        "bundle:revoke:7",
        "bundle:delete:7",
        "keys:list",
    ]


def test_bundle_without_a_vless_child_offers_no_fingerprint_row() -> None:
    """A fingerprint is a VLESS setting: with Xray off there is nothing to set it
    on, so the row is absent rather than present-and-failing."""
    assert "bundle:fp:7" not in _callbacks(bundle_actions_keyboard(_bundle(), has_vless=False))


def test_revoked_bundle_card_drops_config_revoke_and_fingerprint() -> None:
    callbacks = _callbacks(
        bundle_actions_keyboard(_bundle(status=KeyBundleStatus.REVOKED), has_vless=True)
    )

    assert "bundle:show:7" not in callbacks
    assert "bundle:revoke:7" not in callbacks
    assert "bundle:fp:7" not in callbacks
    assert "bundle:delete:7" in callbacks


def test_key_list_row_is_a_single_button_that_opens_the_bundle() -> None:
    """The list only navigates — every action lives on the bundle's own screen."""
    from bot.keyboards.key_bundles import bundle_list_row

    active = [button.callback_data for button in bundle_list_row(_bundle())]
    revoked = [button.callback_data for button in bundle_list_row(_bundle(status=KeyBundleStatus.REVOKED))]

    assert active == ["bundle:open:7"]
    assert revoked == ["bundle:open:7"]


def test_composition_is_listed_in_the_order_the_subscription_serves_it() -> None:
    """«Состав» previews the profile list the client imports, so the two must agree
    — best connection first — even for a bundle whose rows were created in another
    order."""
    keys = [
        _key(1, transport="http", xhttp_profile="antisib"),
        _key(2, transport="http", xhttp_profile="base"),
        _key(3, VpnKeyType.HYSTERIA2),
        _key(4),
        _key(5, transport="http", xhttp_profile="multi"),
    ]

    text = bundle_detail_text(_bundle(), keys, viewer_user_id=OWNER)
    listed = [line for line in text.splitlines() if line.startswith("• ")]

    assert listed == [
        "• VLESS (TCP) #4",
        "• Hysteria2 #3",
        "• VLESS (HTTP) #2",
        f"• VLESS (HTTP) · {t('xhttp_profile_multi_name')} #5",
        f"• VLESS (HTTP) · {t('xhttp_profile_antisib_name')} #1",
    ]


def test_open_bundle_renders_the_card_with_its_contents() -> None:
    views = _BundleViews([_bundle()], keys=[_key(1), _key(2, VpnKeyType.HYSTERIA2)])

    async def run() -> None:
        callback = _Callback("bundle:open:7")
        await open_bundle(callback, _services(views=views), RateLimiter())  # type: ignore[arg-type]

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
    assert t("bundle_stats_empty") in "\n".join(bundle_stats_block([]))
    assert t("none") in bundle_detail_text(_bundle(), [], viewer_user_id=OWNER)


def test_bundle_card_says_so_when_no_traffic_could_be_read_at_all() -> None:
    """None is "we could not sample", [] is "there is nothing to sample" — a
    backend outage must not be rendered as a subscription that burned no traffic."""
    assert t("stats_not_available_yet") in "\n".join(bundle_stats_block(None))


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

    text = "\n".join(bundle_stats_block(views))

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

    text = "\n".join(bundle_stats_block(views))

    assert t("bundle_stats_unavailable") in text
    assert "VLESS" in text


def test_opening_a_bundle_samples_and_prints_the_traffic_of_its_children() -> None:
    """No «Статистика» tap: opening the subscription is what shows its traffic."""
    keys = [_key(1), _key(3, VpnKeyType.HYSTERIA2)]
    traffic = _TrafficStats(
        [
            KeyTrafficStatsView(key=keys[0], owner=None, stats=_stats(1, 1024, 512)),
            KeyTrafficStatsView(key=keys[1], owner=None, stats=_stats(3, 2048, 1024)),
        ]
    )
    views = _BundleViews([_bundle()], keys=keys)

    async def run() -> None:
        callback = _Callback("bundle:open:7")
        await open_bundle(callback, _services(views=views, traffic_stats=traffic), RateLimiter())  # type: ignore[arg-type]

        assert traffic.calls == [keys]
        assert t("bundle_stats_by_protocol") in callback.message.last_text

    asyncio.run(run())


def test_a_throttled_open_falls_back_to_cached_traffic_instead_of_failing() -> None:
    """Navigation must never be refused because the last sample was seconds ago:
    within the cooldown the card shows the cached counters."""
    keys = [_key(1)]
    traffic = _TrafficStats([KeyTrafficStatsView(key=keys[0], owner=None, stats=_stats(1, 1024, 512))])
    views = _BundleViews([_bundle()], keys=keys)
    limiter = RateLimiter()

    async def run() -> None:
        services = _services(views=views, traffic_stats=traffic)
        first = _Callback("bundle:open:7")
        await open_bundle(first, services, limiter)  # type: ignore[arg-type]
        second = _Callback("bundle:open:7")
        await open_bundle(second, services, limiter)  # type: ignore[arg-type]

        assert traffic.calls == [keys]  # sampled once, not twice
        assert second.alerts == []
        assert t("bundle_stats_by_protocol") in second.message.last_text

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
        assert note in bundle_config_text(_bundle(), _settings())  # type: ignore[arg-type]
        assert note in bundle_created_text(  # type: ignore[arg-type]
            _create_result((_key(1),)), viewer_user_id=OWNER, settings=_settings()
        )

        # …but NOT on the «My keys» card: there the question "why is there no
        # WireGuard in the subscription?" is out of context, and an AmneziaWG key
        # may well be sitting a few lines above it in the same list.
        assert note not in bundle_card_text(_bundle(), viewer_user_id=OWNER)


# ── 8. note privacy ───────────────────────────────────────────────────────────


def test_bundle_note_is_hidden_from_a_viewer_who_is_not_the_owner() -> None:
    bundle = _bundle(note="my phone")

    assert "my phone" in bundle_detail_text(bundle, [], viewer_user_id=OWNER)
    assert "my phone" not in bundle_detail_text(bundle, [], viewer_user_id=OWNER + 1)


# ── 9. the note wizard is the SAME FSM the per-key flow uses ──────────────────


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
        assert t("bundle_title", id=7 + DISPLAY_OFFSET) in message.answers[-1][0]

        callback = _Callback("note:confirm")
        await edit_note_confirm(callback, state, services, RateLimiter())  # type: ignore[arg-type]

        assert ("note", (7, "home router")) in views.calls
        assert t("note_updated") in callback.message.last_text

    asyncio.run(run())


# ── 9b. the fingerprint wizard is the SAME FSM the per-key flow uses ──────────


def test_fingerprint_button_enters_the_shared_fp_wizard_for_the_bundle() -> None:
    views = _BundleViews([_bundle()])

    async def run() -> None:
        callback = _Callback("bundle:fp:7")
        state = _State({"key_id": 99})
        await change_bundle_fp_prompt(callback, state, _services(views=views))  # type: ignore[arg-type]

        assert state.state == EditFpStates.waiting_fp
        assert state.data["bundle_id"] == 7
        # The per-key target is cleared, or the shared step would re-stamp key 99.
        assert state.data["key_id"] is None
        assert callback.message.last_text == t("bundle_fp_change_prompt")
        assert "fp:safari" in _callbacks(callback.message.last_markup)

    asyncio.run(run())


def test_chosen_fingerprint_is_applied_to_every_vless_child_of_the_bundle() -> None:
    keys = [_key(1), _key(2, transport="http", xhttp_profile="multi"), _key(3, VpnKeyType.HYSTERIA2)]
    views = _BundleViews([_bundle()], keys=keys)
    lifecycle = _BundleLifecycle()

    async def run() -> None:
        callback = _Callback("fp:chrome")
        state = _State({"bundle_id": 7})
        services = _services(views=views, lifecycle=lifecycle)
        await edit_fp_select(callback, state, services, RateLimiter())  # type: ignore[arg-type]

        assert lifecycle.calls == [("fingerprint", (7, "chrome"))]
        text = callback.message.last_text
        assert t("bundle_fp_updated", count=4) in text
        # …and the bundle screen comes back, keyboard included.
        assert t("bundle_composition") in text
        assert "bundle:fp:7" in _callbacks(callback.message.last_markup)

    asyncio.run(run())


def test_fingerprint_wizard_still_targets_a_single_key_without_a_bundle_id() -> None:
    """The shared step must not treat a plain per-key change as a bundle one."""
    lifecycle = _BundleLifecycle()
    changed: list[tuple[int, str]] = []

    class _Xray:
        async def change_fingerprint(self, actor_user_id: int, key_id: int, fingerprint: str) -> None:
            changed.append((key_id, fingerprint))

    class _Keys:
        async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
            return _key(key_id)

    async def run() -> None:
        callback = _Callback("fp:edge")
        state = _State({"key_id": 5})
        services = _services(lifecycle=lifecycle)
        services.xray = _Xray()
        services.vpn_keys = _Keys()
        await edit_fp_select(callback, state, services, RateLimiter())  # type: ignore[arg-type]

        assert changed == [(5, "edge")]
        assert lifecycle.calls == []

    asyncio.run(run())


# ── 9c. the AmneziaWG notice gates the create wizard ──────────────────────────


def test_all_in_one_choice_shows_the_awg_notice_before_the_wizard() -> None:
    """Picking All-in-One must not walk into the note step: the set cannot carry
    AmneziaWG, and that is said up front behind a single acknowledgement."""

    async def run() -> None:
        callback = _Callback("keys:create:bundle")
        await create_key_choose_bundle(callback, _services())  # type: ignore[arg-type]

        assert callback.message.last_text == t("bundle_awg_separate")
        assert _callbacks(callback.message.last_markup) == ["keys:create:bundle:ack"]

    asyncio.run(run())


def test_acknowledging_the_notice_starts_the_note_step() -> None:
    async def run() -> None:
        callback = _Callback("keys:create:bundle:ack")
        state = _State()
        await create_key_bundle_ack(callback, state, _services())  # type: ignore[arg-type]

        assert state.state == CreateKeyStates.waiting_note
        assert state.data["key_type"] == "bundle"
        assert t("key_note_prompt") in callback.message.last_text

    asyncio.run(run())


def test_the_awg_notice_step_is_refused_while_the_flag_is_off() -> None:
    async def run() -> None:
        services = _services(settings=_settings(subscription_enabled=False))
        callback = _Callback("keys:create:bundle")
        await create_key_choose_bundle(callback, services)  # type: ignore[arg-type]
        ack = _Callback("keys:create:bundle:ack")
        state = _State()
        await create_key_bundle_ack(ack, state, services)  # type: ignore[arg-type]

        assert callback.alerts == [t("err_subscription_disabled")]
        assert ack.alerts == [t("err_subscription_disabled")]
        assert state.state is None

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
        display_no=8 + DISPLAY_OFFSET,
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
