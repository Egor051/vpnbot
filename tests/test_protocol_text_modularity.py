"""Protocol modularity reaches every user-facing text, not only the backends.

Pinned here:

1. **golden** — with everything on, every text that is now composed from
   fragments is byte-identical to what the catalogue held before
   (``tests/fixtures/protocol_texts/full_availability_golden.json``), and the
   «Какой протокол выбрать?» answer is byte-identical to the spec text;
2. **the whole matrix** — every subset of {xray_tcp, xhttp, awg, hy2} (XHTTP only
   together with Xray, as the code has it), in both locales: the FAQ, the create
   menu with its follow-up steps, the card of every available key type, the
   All-in-One wizard start and the bundle screens name no switched-off protocol,
   the «что выбрать» block follows its rules, and no fragment seam leaves a gap;
3. the All-in-One wizard without AWG has no «✅ Понятно» step — checked on the
   keyboard, not only on the text;
4. **runtime** — a module switched off through the real toggle, in the same
   process and container, is gone from the very next render (no import-time
   caching anywhere on the path).
"""

from __future__ import annotations

import asyncio
import itertools
import json
import re
from collections.abc import Iterable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from conftest import availability_settings, relay_services

from bot.availability import FULL_AVAILABILITY, Availability, current_availability
from bot.bundles import bundle_config_text, bundle_created_text
from bot.formatters import (
    awg_config_text,
    hysteria2_config_text,
    key_list_card,
    key_screen_text,
    personal_cabinet_text,
    user_proxy_stats_text,
    xray_config_text,
)
from bot.fsm.states import CreateKeyStates
from bot.handlers.callbacks import cancel_callback
from bot.handlers.common import faq_answer_callback, faq_page_callback, help_callback
from bot.handlers.key_bundles import open_bundle
from bot.handlers.keys import (
    _create_confirm_screen,
    create_key_bundle_ack,
    create_key_choose_bundle,
    create_key_choose_xhttp,
    create_key_menu,
    create_key_proto_vless,
    trial_request_start,
)
from bot.handlers.proxy import _proxy_menu_view
from bot.keyboards.common import FAQ_TOPICS
from bot.keyboards.keys import key_actions_keyboard
from bot.protocol_texts import (
    _BUNDLE_AWG_NOTICE,
    _BUNDLE_KIND_DESC,
    _FAQ_SPECS,
    Block,
    Part,
    bundle_kind_description,
    bundle_kinds,
    compose,
    faq_answer,
    faq_topics,
)
from bot.rate_limit import RateLimiter
from i18n import en as en_mod
from i18n import ru as ru_mod
from i18n import t, use_locale
from models.dto import (
    KeyBundle,
    OwnerTrafficSummary,
    ProxyAccessStatsItem,
    ProxyUserStats,
    TrafficScopeTotals,
    User,
    VpnKey,
)
from models.enums import (
    KeyBundleKind,
    KeyBundleStatus,
    ProxyAccessStatus,
    ProxyAccessType,
    UserRole,
    VpnKeyStatus,
    VpnKeyType,
)
from services.key_bundles import (
    BundleMember,
    KeyBundleCreateResult,
    KeyBundleService,
    available_composition,
    bundle_composition,
)
from services.protocol_availability import ALL_PROTOCOLS, Protocol, available_protocols

OWNER = 100
ADMIN = 1
LOCALES = ("ru", "en")
GOLDEN = json.loads(
    (Path(__file__).parent / "fixtures" / "protocol_texts" / "full_availability_golden.json").read_text(
        encoding="utf-8"
    )
)

# The «Какой протокол выбрать?» answer exactly as the spec words it (bold markup
# as the catalogue always carried it).
SPEC_CHOICE_RU = (
    "<b>Xray (VLESS + REALITY)</b> — лучше всех обходит блокировки и DPI, особенно если подобран "
    "правильный конфиг (транспорт и fingerprint). Расплата за это — соединение может быть медленнее "
    "и с более высоким пингом. Хорошо подходит для обычного повседневного использования.\n\n"
    "<b>AWG (AmneziaWG)</b> — на базе WireGuard: даёт минимальный и стабильный пинг. Но в некоторых "
    "сетях легко блокируется, поэтому хорош в первую очередь для игр или звонков на домашнем "
    "интернете, где блокировок нет.\n\n"
    "<b>Hysteria2</b> — работает на том же транспорте, что и AWG, поэтому обеспечивает такой же низкий "
    "пинг, но при этом лучше мимикрирует под обычный веб-трафик и увереннее держит соединение на "
    "нестабильных сетях — это также даёт более высокую скорость в таких условиях. На некоторых "
    "сетях всё же может уступать Xray.\n\n"
    "Если не знаете, что выбрать, начните с Xray — он надёжнее работает при блокировках. Если важен "
    "минимальный пинг и блокировок нет — берите AWG. На нестабильной мобильной связи с потерями "
    "пакетов попробуйте Hysteria2."
)


# ── the matrix ────────────────────────────────────────────────────────────────

VPN_FLAGS = ("xray_tcp", "xhttp", "awg", "hy2")


def _vpn_subsets() -> list[frozenset[str]]:
    subsets = [
        frozenset(combo)
        for size in range(len(VPN_FLAGS) + 1)
        for combo in itertools.combinations(VPN_FLAGS, size)
        # XHTTP is a transport of Xray: there is no XHTTP without Xray in the code.
        if "xhttp" not in combo or "xray_tcp" in combo
    ]
    return sorted(subsets, key=lambda s: (len(s), sorted(s)))


VPN_SUBSETS = _vpn_subsets()
assert len(VPN_SUBSETS) == 12

# Case-insensitive tokens that must not appear anywhere on a user screen while the
# flag is off. Xray off implies XHTTP off, so its screens are checked for both.
FORBIDDEN: dict[str, tuple[str, ...]] = {
    "xray_tcp": ("xray", "vless", "reality", "fingerprint"),
    "xhttp": (
        "xhttp",
        "vless (http)",
        "мультиподключение",
        "антисибирский",
        "multi-connection",
        "anti-blocking",
        "транспорт и",
        "транспортами",
        "transport and",
        "transports",
    ),
    "awg": ("awg", "amneziawg", "wireguard", "amnezia", "mtu"),
    "hy2": ("hysteria", "hy2", "quic"),
    "socks5": ("socks",),
    "mtproto": ("mtproto",),
}


def _ids(subset: frozenset[str]) -> str:
    return "+".join(sorted(subset)) or "none"


# ── stubs ─────────────────────────────────────────────────────────────────────


class _Message:
    def __init__(self) -> None:
        self.message_id = 1
        self.chat = SimpleNamespace(id=OWNER)
        self.edits: list[tuple[str, Any]] = []

    async def edit_text(self, text: str, reply_markup: Any = None) -> None:
        self.edits.append((text, reply_markup))

    async def answer(self, text: str, reply_markup: Any = None) -> None:
        self.edits.append((text, reply_markup))

    @property
    def last_text(self) -> str:
        return self.edits[-1][0]

    @property
    def last_markup(self) -> Any:
        return self.edits[-1][1]


class _Callback:
    def __init__(self, data: str) -> None:
        self.from_user = SimpleNamespace(id=OWNER, username="user", first_name="User")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))

    @property
    def alerts(self) -> list[str]:
        return [text for text, alert in self.answers if alert]


class _State:
    def __init__(self, data: dict[str, Any] | None = None) -> None:
        self.data: dict[str, Any] = data or {}
        self.state: Any = None

    async def get_data(self) -> dict[str, Any]:
        return dict(self.data)

    async def set_state(self, state: Any) -> None:
        self.state = state

    async def update_data(self, data: dict[str, Any] | None = None, **kwargs: Any) -> None:
        self.data.update(data or {})
        self.data.update(kwargs)

    async def clear(self) -> None:
        self.data.clear()
        self.state = None


def _user() -> User:
    return User(
        telegram_user_id=OWNER,
        username="user",
        first_name="User",
        role=UserRole.APPROVED_USER,
        created_at="2026-07-01T10:00:00+00:00",
        updated_at="2026-07-01T10:00:00+00:00",
        blocked_at=None,
    )


class _Users:
    async def require_approved_or_admin(self, user_id: int) -> User:
        return _user()

    async def get_user(self, user_id: int) -> User:
        return _user()

    async def require_superadmin(self, user_id: int) -> None:
        return None


class _Toggles:
    """The module toggle as the bot sees it: a set of switched-off modules."""

    def __init__(self, disabled: Iterable[str] = ()) -> None:
        self.disabled = set(disabled)

    async def is_enabled(self, name: str) -> bool:
        return name not in self.disabled


class _TrafficStats:
    async def refresh_views(self, keys: list[VpnKey]) -> list[Any]:
        return []

    async def cached_for_keys(self, keys: list[VpnKey]) -> dict[int, Any]:
        return {}


class _TrialAccess:
    async def can_request_trial(self, user_id: int) -> bool:
        return True


def _bundle() -> KeyBundle:
    return KeyBundle(
        id=7,
        user_id=OWNER,
        label="bundle_00007",
        note=None,
        status=KeyBundleStatus.ACTIVE,
        token="token-value",
        created_at="2026-07-01T10:00:00+00:00",
        updated_at="2026-07-01T10:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        display_no=7,
    )


def _key(key_id: int, key_type: VpnKeyType, transport: str = "tcp", xhttp_profile: str = "base") -> VpnKey:
    payload: dict[str, Any] = {}
    if key_type is VpnKeyType.XRAY:
        payload["fingerprint"] = "firefox"
    if key_type is VpnKeyType.AWG:
        payload["mtu"] = 1280
    return VpnKey(
        id=key_id,
        owner_user_id=OWNER,
        username="user",
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note="phone",
        uuid=f"uuid-{key_id}",
        email_label=f"label_{key_id}",
        public_key=None,
        client_ip=None,
        payload=payload,
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


def _member_key(key_id: int, member: BundleMember) -> VpnKey:
    return _key(key_id, member.key_type, member.transport, member.xhttp_profile)


class _BundleViews:
    def __init__(self, keys: list[VpnKey]) -> None:
        self.keys = keys

    async def get_for_actor(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
        return _bundle()

    async def list_keys_for_actor(self, actor_user_id: int, bundle_id: int) -> list[VpnKey]:
        return list(self.keys)


def _settings(
    *,
    xhttp: bool = True,
    hy2: bool = True,
    socks5: bool = True,
    mtproto: bool = True,
    subscription: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(
        **availability_settings(
            xray_xhttp_enabled=xhttp,
            hysteria2_enabled=hy2,
            socks5_enabled=socks5,
            mtproto_enabled=mtproto,
            subscription_enabled=subscription,
        ),
        subscription_public_port=2096,
        hysteria2_sni="sub.example.org",
        hysteria2_host="203.0.113.10",
        key_max_trial_days=30,
        server_flag_emoji="🇫🇮",
        mtproto_mode="static",
    )


def _services(
    vpn: frozenset[str],
    *,
    proxies: frozenset[str] = frozenset({"socks5", "mtproto"}),
    subscription: bool = True,
    modules: Any = None,
) -> SimpleNamespace:
    """A container in which exactly *vpn* (and *proxies*) are switched on.

    Xray and AWG are switched off through the module toggle (they have no .env
    flag); XHTTP, Hysteria2 and the proxies through their .env flags.
    """
    disabled = set()
    if "xray_tcp" not in vpn:
        disabled.add("xray")
    if "awg" not in vpn:
        disabled.add("awg")
    return SimpleNamespace(
        settings=_settings(
            xhttp="xhttp" in vpn,
            hy2="hy2" in vpn,
            socks5="socks5" in proxies,
            mtproto="mtproto" in proxies,
            subscription=subscription,
        ),
        modules=modules if modules is not None else _Toggles(disabled),
        users=_Users(),
        relays=relay_services(),
        traffic_stats=_TrafficStats(),
        trial_access=_TrialAccess(),
        key_bundle_views=_BundleViews([]),
    )


async def _allow(*args: object, **kwargs: object) -> bool:
    return True


@pytest.fixture(autouse=True)
def _private_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    for module in ("bot.handlers.common", "bot.handlers.keys", "bot.handlers.key_bundles", "bot.handlers.callbacks"):
        monkeypatch.setattr(f"{module}.ensure_private_callback", _allow)


def _labels(markup: Any) -> list[str]:
    if markup is None:
        return []
    return [button.text for row in markup.inline_keyboard for button in row]


def _callbacks(markup: Any) -> list[str]:
    if markup is None:
        return []
    return [button.callback_data for row in markup.inline_keyboard for button in row]


# ── what a screen may never look like ─────────────────────────────────────────

_SEAM_DEFECTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("blank lines in a row", re.compile(r"\n[ \t]*\n[ \t]*\n")),
    ("double space", re.compile(r"(?<=\S) {2,}(?=\S)")),
    ("trailing whitespace on a line", re.compile(r"[ \t]+\n")),
    ("dangling comma", re.compile(r",\s*(?:[,.;:)\]]|$|\n)")),
    ("space before punctuation", re.compile(r" [,.;:)]")),
    ("empty or padded brackets", re.compile(r"\(\s*\)|\(\s|\s\)")),
    ("dangling conjunction", re.compile(r"(?:\s(?:и|или|and|or))\s*(?:[,.;:)]|$|\n)")),
    ("empty bullet", re.compile(r"(?:^|\n)[ \t]*•[ \t]*(?:[;.]?\s*)(?:\n|$)")),
    ("unformatted placeholder", re.compile(r"\{[a-z_]*\}")),
    ("leaked None", re.compile(r"\bNone\b")),
)


def _assert_clean(text: str, where: str) -> None:
    assert text, f"{where}: empty text"
    assert text == text.strip(), f"{where}: leading/trailing whitespace: {text!r}"
    for name, pattern in _SEAM_DEFECTS:
        match = pattern.search(text)
        assert match is None, f"{where}: {name} at {match.start() if match else -1}: {text!r}"


def _assert_no_forbidden(texts: dict[str, str], off: Iterable[str]) -> None:
    for flag in off:
        for token in FORBIDDEN[flag]:
            for where, text in texts.items():
                assert token not in text.lower(), f"{flag} is off but {where!r} mentions {token!r}: {text!r}"


# ── rendering every user screen of one configuration ──────────────────────────


async def _render_faq(services: SimpleNamespace, texts: dict[str, str]) -> dict[str, str]:
    """Every FAQ page and every topic answer, through the real handlers."""
    callback = _Callback("help")
    await help_callback(callback, services)  # type: ignore[arg-type]
    title, markup = callback.message.edits[-1]
    texts["faq:list:1"] = title
    texts["faq:list:1:buttons"] = "\n".join(_labels(markup))
    page = 2
    while any(data == f"faq_page:{page}" for data in _callbacks(markup)):
        callback = _Callback(f"faq_page:{page}")
        await faq_page_callback(callback, services)  # type: ignore[arg-type]
        title, markup = callback.message.edits[-1]
        texts[f"faq:list:{page}"] = title
        texts[f"faq:list:{page}:buttons"] = "\n".join(_labels(markup))
        page += 1

    answers: dict[str, str] = {}
    for topic, _button in FAQ_TOPICS:
        callback = _Callback(f"faq:{topic}:1")
        await faq_answer_callback(callback, services)  # type: ignore[arg-type]
        answers[topic] = callback.message.last_text
        texts[f"faq:{topic}"] = callback.message.last_text
    return answers


async def _render_create(services: SimpleNamespace, texts: dict[str, str]) -> list[str]:
    """The create menu and every step its buttons lead to; returns its callbacks."""
    callback = _Callback("keys:create:menu")
    await create_key_menu(callback, services)  # type: ignore[arg-type]
    text, markup = callback.message.edits[-1]
    texts["create:menu"] = text
    texts["create:menu:buttons"] = "\n".join(_labels(markup))
    menu = _callbacks(markup)

    if "keys:proto:vless" in menu:
        step = _Callback("keys:proto:vless")
        await create_key_proto_vless(step, services)  # type: ignore[arg-type]
        texts["create:vless"] = step.message.last_text
        texts["create:vless:buttons"] = "\n".join(_labels(step.message.last_markup))
        if "keys:create:xhttp" in _callbacks(step.message.last_markup):
            profiles = _Callback("keys:create:xhttp")
            await create_key_choose_xhttp(profiles, _State(), services)  # type: ignore[arg-type]
            texts["create:xhttp"] = profiles.message.last_text

    trial = _Callback("trial:request")
    await trial_request_start(trial, _State(), services)  # type: ignore[arg-type]
    texts["trial:menu:buttons"] = "\n".join(_labels(trial.message.last_markup))

    cancel = _Callback("cancel")
    await cancel_callback(cancel, _State({"cancel_target": "keys:create"}), RateLimiter(), services)  # type: ignore[arg-type]
    texts["cancel:create:buttons"] = "\n".join(_labels(cancel.message.last_markup))
    assert _callbacks(cancel.message.last_markup)[:-1] == menu[:-1], "«Отмена» must rebuild the same menu"
    return menu


def _render_key_cards(available: Availability, texts: dict[str, str]) -> None:
    keys: list[tuple[VpnKey, str]] = []
    if Protocol.XRAY in available:
        keys.append((_key(11, VpnKeyType.XRAY), xray_config_text("vless://uuid-11@203.0.113.10:443")))
    if Protocol.XHTTP in available:
        keys.append(
            (_key(12, VpnKeyType.XRAY, "http", "multi"), xray_config_text("vless://uuid-12@203.0.113.10:443"))
        )
    if Protocol.AWG in available:
        keys.append((_key(13, VpnKeyType.AWG), awg_config_text("[Interface]\nPrivateKey = x")))
    if Protocol.HYSTERIA2 in available:
        keys.append((_key(14, VpnKeyType.HYSTERIA2), hysteria2_config_text("hysteria2://u@203.0.113.10:443")))
    for key, config in keys:
        name = f"key:{key.key_type.value}:{key.transport}"
        texts[f"{name}:screen"] = key_screen_text(key, viewer_user_id=OWNER, stats=None)
        texts[f"{name}:list"] = key_list_card(key, viewer_user_id=OWNER)
        texts[f"{name}:config"] = config
        texts[f"{name}:buttons"] = "\n".join(_labels(key_actions_keyboard(key)))


async def _render_bundle(
    services: SimpleNamespace, available: Availability, menu: list[str], texts: dict[str, str]
) -> None:
    """The All-in-One wizard start, its kind step, confirm screens and the bundle screens."""
    if not available.bundle_offered:
        assert "keys:create:bundle" not in menu
        refused = _Callback("keys:create:bundle")
        await create_key_choose_bundle(refused, _State(), services)  # type: ignore[arg-type]
        assert refused.alerts == [t("err_bundle_no_backends")]
        return

    assert "keys:create:bundle" in menu
    state = _State()
    start = _Callback("keys:create:bundle")
    await create_key_choose_bundle(start, state, services)  # type: ignore[arg-type]
    texts["bundle:start"] = start.message.last_text
    texts["bundle:start:buttons"] = "\n".join(_labels(start.message.last_markup))
    if "keys:create:bundle:ack" in _callbacks(start.message.last_markup):
        ack = _Callback("keys:create:bundle:ack")
        await create_key_bundle_ack(ack, state, services)  # type: ignore[arg-type]
        kind_text, kind_markup = ack.message.edits[-1]
    else:
        kind_text, kind_markup = start.message.edits[-1]
    assert state.state == CreateKeyStates.waiting_bundle_kind
    texts["bundle:kinds"] = kind_text
    texts["bundle:kinds:buttons"] = "\n".join(_labels(kind_markup))
    kinds = [data.rsplit(":", 1)[-1] for data in _callbacks(kind_markup) if data.startswith("keys:create:bundle:kind:")]
    assert kinds == [kind.value for kind in bundle_kinds(available)]
    for kind in kinds:
        data = {
            "key_type": "bundle",
            "bundle_kind": kind,
            "note": "phone",
            "fingerprint": "firefox" if Protocol.XRAY in available else None,
        }
        texts[f"bundle:confirm:{kind}"] = _create_confirm_screen(data, "2030-01-01T00:00:00+00:00", available)

    members = available_composition(KeyBundleKind.EXTENDED, available.protocols)
    keys = [_member_key(20 + index, member) for index, member in enumerate(members)]
    services.key_bundle_views = _BundleViews(keys)
    card = _Callback("bundle:open:7")
    await open_bundle(card, services, RateLimiter())  # type: ignore[arg-type]
    texts["bundle:card"] = card.message.last_text
    texts["bundle:card:buttons"] = "\n".join(_labels(card.message.last_markup))
    texts["bundle:config"] = bundle_config_text(_bundle(), services.settings, available)
    skipped = tuple(m for m in bundle_composition(KeyBundleKind.EXTENDED) if m not in members)
    result = KeyBundleCreateResult(bundle=_bundle(), keys=tuple(keys), included=members, skipped=skipped)
    texts["bundle:created"] = bundle_created_text(
        result, viewer_user_id=OWNER, settings=services.settings, available=available
    )


def _render_settings_and_proxy(available: Availability, texts: dict[str, str]) -> None:
    counts = {
        "active_xray": int(Protocol.XRAY in available),
        "active_awg": int(Protocol.AWG in available),
        "active_hysteria2": int(Protocol.HYSTERIA2 in available),
    }
    texts["settings:cabinet"] = personal_cabinet_text(
        _user(),
        traffic=OwnerTrafficSummary(
            current_keys=TrafficScopeTotals(0, 0), all_time=TrafficScopeTotals(0, 0)
        ),
        proxy_count=0,
        available=available,
        **counts,
    )
    accesses = tuple(
        _proxy_item(index, access_type)
        for index, (protocol, access_type) in enumerate(
            ((Protocol.SOCKS5, ProxyAccessType.SOCKS5), (Protocol.MTPROTO, ProxyAccessType.MTPROTO))
        )
        if protocol in available
    )
    texts["proxy:stats"] = user_proxy_stats_text(ProxyUserStats(owner_user_id=OWNER, accesses=accesses), available)


def _proxy_item(index: int, access_type: ProxyAccessType) -> ProxyAccessStatsItem:
    return ProxyAccessStatsItem(
        id=50 + index,
        owner_user_id=OWNER,
        username="user",
        access_type=access_type,
        status=ProxyAccessStatus.ACTIVE,
        created_at="2026-07-01T10:00:00+00:00",
        updated_at="2026-07-01T10:00:00+00:00",
        activated_at="2026-07-01T10:00:00+00:00",
        last_shown_at=None,
        revoked_at=None,
        deleted_at=None,
        host="203.0.113.10",
        port=1080,
        login="vpn_user",
    )


# ── 1. golden ─────────────────────────────────────────────────────────────────


def test_spec_choice_text_is_byte_identical_with_everything_on() -> None:
    with use_locale("ru"):
        assert faq_answer("choice", FULL_AVAILABILITY) == SPEC_CHOICE_RU
        # The same text, as the spec quotes it (no markup), paragraph for paragraph.
        plain = re.sub(r"</?b>", "", faq_answer("choice", FULL_AVAILABILITY) or "")
        assert plain.startswith("Xray (VLESS + REALITY) — лучше всех обходит блокировки и DPI")


@pytest.mark.parametrize("locale", LOCALES)
@pytest.mark.parametrize("topic", [topic for topic, _ in FAQ_TOPICS])
def test_every_faq_answer_is_unchanged_with_everything_on(locale: str, topic: str) -> None:
    with use_locale(locale):
        assert faq_answer(topic, FULL_AVAILABILITY) == GOLDEN[locale][f"faq_{topic}"]


@pytest.mark.parametrize("locale", LOCALES)
def test_bundle_and_settings_texts_are_unchanged_with_everything_on(locale: str) -> None:
    golden = GOLDEN[locale]
    with use_locale(locale):
        assert bundle_kind_description(KeyBundleKind.BASIC, FULL_AVAILABILITY) == golden["bundle_kind_basic_desc"]
        assert (
            bundle_kind_description(KeyBundleKind.EXTENDED, FULL_AVAILABILITY) == golden["bundle_kind_extended_desc"]
        )
        assert compose(_BUNDLE_AWG_NOTICE, FULL_AVAILABILITY) == golden["bundle_awg_separate"]
        cabinet = personal_cabinet_text(
            _user(),
            active_xray=1,
            active_awg=2,
            active_hysteria2=3,
            traffic=OwnerTrafficSummary(TrafficScopeTotals(0, 0), TrafficScopeTotals(0, 0)),
            proxy_count=0,
            available=FULL_AVAILABILITY,
        )
        assert golden["cabinet_active_keys"].format(total=6, xray=1, awg=2, hysteria2=3) in cabinet.splitlines()
        stats = user_proxy_stats_text(
            ProxyUserStats(owner_user_id=OWNER, accesses=(_proxy_item(0, ProxyAccessType.SOCKS5),)),
            FULL_AVAILABILITY,
        )
        assert golden["proxy_traffic_unavailable"] in stats.splitlines()


def test_full_list_of_faq_topics_with_everything_on() -> None:
    assert faq_topics(FULL_AVAILABILITY) == list(FAQ_TOPICS)


# ── 2. the matrix ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("locale", LOCALES)
@pytest.mark.parametrize("vpn", VPN_SUBSETS, ids=_ids)
def test_no_screen_mentions_a_switched_off_protocol(vpn: frozenset[str], locale: str) -> None:
    async def run() -> None:
        services = _services(vpn)
        available = await current_availability(services)  # type: ignore[arg-type]
        texts: dict[str, str] = {}
        with use_locale(locale):
            answers = await _render_faq(services, texts)
            menu = await _render_create(services, texts)
            _render_key_cards(available, texts)
            await _render_bundle(services, available, menu, texts)
            _render_settings_and_proxy(available, texts)

            _assert_no_forbidden(texts, set(VPN_FLAGS) - vpn)
            for where, text in texts.items():
                if where.endswith(":buttons"):
                    continue
                _assert_clean(text, where)
            _assert_choice_rules(vpn, answers, available)
            _assert_hidden_topics_answer_not_found(answers, available)

    asyncio.run(run())


def _assert_choice_rules(vpn: frozenset[str], answers: dict[str, str], available: Availability) -> None:
    protocols = vpn - {"xhttp"}
    choice = answers["choice"]
    advice = {
        "faq_choice_start_xray": "xray_tcp",
        "faq_choice_start_hy2": "hy2",
        "faq_choice_pick_awg": "awg",
        "faq_choice_pick_hy2": "hy2",
    }
    if not protocols:
        assert choice == t("faq_not_found")
        return
    if len(protocols) <= 1:
        # No «что выбрать» at all with nothing to choose between…
        assert all(t(key) not in choice for key in advice)
        # …and no «лучше всех» with no one to be better than.
        if "xray_tcp" in protocols:
            assert choice.startswith(t("faq_choice_xray_solo_transport" if "xhttp" in vpn else "faq_choice_xray_solo"))
        return
    start = next(flag for flag in ("xray_tcp", "hy2", "awg") if flag in protocols)
    assert start != "awg"
    advice_paragraph = choice.split("\n\n")[-1]
    expected = [t("faq_choice_start_xray" if start == "xray_tcp" else "faq_choice_start_hy2")]
    if "awg" in protocols:
        expected.append(t("faq_choice_pick_awg"))
    if "hy2" in protocols and start != "hy2":
        expected.append(t("faq_choice_pick_hy2"))
    assert advice_paragraph == " ".join(expected)
    for key, flag in advice.items():
        if flag not in protocols:
            assert t(key) not in choice


def _assert_hidden_topics_answer_not_found(answers: dict[str, str], available: Availability) -> None:
    visible = {topic for topic, _ in faq_topics(available)}
    for topic, answer in answers.items():
        if topic in visible:
            assert answer != t("faq_not_found"), topic
        else:
            assert answer == t("faq_not_found"), topic


PROXY_SUBSETS = [frozenset(c) for n in range(3) for c in itertools.combinations(("socks5", "mtproto"), n)]


@pytest.mark.parametrize("locale", LOCALES)
@pytest.mark.parametrize("proxies", PROXY_SUBSETS, ids=_ids)
def test_proxy_texts_follow_the_proxy_switches(proxies: frozenset[str], locale: str) -> None:
    async def run() -> None:
        services = _services(frozenset(VPN_FLAGS), proxies=proxies)
        available = await current_availability(services)  # type: ignore[arg-type]
        texts: dict[str, str] = {}
        with use_locale(locale):
            answers = await _render_faq(services, texts)
            proxy_menu, proxy_markup = await _proxy_menu_view(services, OWNER, accesses=[])  # type: ignore[arg-type]
            texts["proxy:menu"] = proxy_menu
            texts["proxy:menu:buttons"] = "\n".join(_labels(proxy_markup))
            _render_settings_and_proxy(available, texts)
            _assert_no_forbidden(texts, {"socks5", "mtproto"} - proxies)
            for where, text in texts.items():
                if not where.endswith(":buttons"):
                    _assert_clean(text, where)
            if not proxies:
                assert answers["proxy"] == t("faq_not_found")
            elif len(proxies) == 1:
                assert answers["proxy"].startswith(t("faq_proxy_intro_one") + "\n")

    asyncio.run(run())


# ── literal spot checks of the spec's variants (ru) ───────────────────────────


@pytest.mark.parametrize(
    ("vpn", "expected"),
    [
        (
            frozenset({"xray_tcp"}),
            "<b>Xray (VLESS + REALITY)</b> — хорошо обходит блокировки и DPI, особенно если подобран "
            "правильный конфиг (fingerprint). Расплата за это — соединение может быть медленнее и с более "
            "высоким пингом. Хорошо подходит для обычного повседневного использования.",
        ),
        (
            frozenset({"xray_tcp", "hy2"}),
            "<b>Xray (VLESS + REALITY)</b> — лучше всех обходит блокировки и DPI, особенно если подобран "
            "правильный конфиг (fingerprint). Расплата за это — соединение может быть медленнее и с более "
            "высоким пингом. Хорошо подходит для обычного повседневного использования.\n\n"
            "<b>Hysteria2</b> — работает поверх UDP (QUIC), поэтому обеспечивает низкий пинг, хорошо "
            "мимикрирует под обычный веб-трафик и уверенно держит соединение на нестабильных сетях — это "
            "также даёт более высокую скорость в таких условиях. На некоторых сетях всё же может уступать Xray.\n\n"
            "Если не знаете, что выбрать, начните с Xray — он надёжнее работает при блокировках. "
            "На нестабильной мобильной связи с потерями пакетов попробуйте Hysteria2.",
        ),
        (
            frozenset({"awg", "hy2"}),
            "<b>AWG (AmneziaWG)</b> — на базе WireGuard: даёт минимальный и стабильный пинг. Но в некоторых "
            "сетях легко блокируется, поэтому хорош в первую очередь для игр или звонков на домашнем "
            "интернете, где блокировок нет.\n\n"
            "<b>Hysteria2</b> — работает на том же транспорте, что и AWG, поэтому обеспечивает такой же низкий "
            "пинг, но при этом лучше мимикрирует под обычный веб-трафик и увереннее держит соединение на "
            "нестабильных сетях — это также даёт более высокую скорость в таких условиях.\n\n"
            "Если не знаете, что выбрать, начните с Hysteria2 — он лучше переносит блокировки и нестабильную "
            "связь. Если важен минимальный пинг и блокировок нет — берите AWG.",
        ),
        (
            frozenset({"awg"}),
            "<b>AWG (AmneziaWG)</b> — на базе WireGuard: даёт минимальный и стабильный пинг. Но в некоторых "
            "сетях легко блокируется, поэтому хорош в первую очередь для игр или звонков на домашнем "
            "интернете, где блокировок нет.",
        ),
    ],
    ids=["xray-only", "xray+hy2", "awg+hy2", "awg-only"],
)
def test_choice_variants_read_as_specified(vpn: frozenset[str], expected: str) -> None:
    async def run() -> None:
        available = await current_availability(_services(vpn))  # type: ignore[arg-type]
        with use_locale("ru"):
            assert faq_answer("choice", available) == expected

    asyncio.run(run())


# ── 3. no «✅ Понятно» step without AWG ───────────────────────────────────────


@pytest.mark.parametrize("vpn", [s for s in VPN_SUBSETS if "awg" not in s and s & {"xray_tcp", "hy2"}], ids=_ids)
def test_all_in_one_wizard_starts_without_the_awg_step_when_awg_is_off(vpn: frozenset[str]) -> None:
    async def run() -> None:
        services = _services(vpn)
        state = _State()
        callback = _Callback("keys:create:bundle")
        await create_key_choose_bundle(callback, state, services)  # type: ignore[arg-type]

        markup = callback.message.last_markup
        assert "keys:create:bundle:ack" not in _callbacks(markup)
        assert t("btn_understood") not in _labels(markup)
        assert t("bundle_awg_separate") not in callback.message.last_text
        # Straight to the kind step: the state moved on and the kinds are offered.
        assert state.state == CreateKeyStates.waiting_bundle_kind
        assert any(data.startswith("keys:create:bundle:kind:") for data in _callbacks(markup))

    asyncio.run(run())


def test_all_in_one_wizard_keeps_the_awg_step_while_awg_is_on() -> None:
    async def run() -> None:
        state = _State()
        callback = _Callback("keys:create:bundle")
        await create_key_choose_bundle(callback, state, _services(frozenset(VPN_FLAGS)))  # type: ignore[arg-type]

        assert _callbacks(callback.message.last_markup) == ["keys:create:bundle:ack"]
        assert _labels(callback.message.last_markup) == [t("btn_understood")]
        assert callback.message.last_text == t("bundle_awg_separate")
        assert state.state is None

    asyncio.run(run())


def test_all_in_one_is_not_offered_while_the_subscription_flag_is_off() -> None:
    async def run() -> None:
        services = _services(frozenset(VPN_FLAGS), subscription=False)
        callback = _Callback("keys:create:menu")
        await create_key_menu(callback, services)  # type: ignore[arg-type]
        assert "keys:create:bundle" not in _callbacks(callback.message.last_markup)
        with use_locale("ru"):
            connect = faq_answer("connect", await current_availability(services))  # type: ignore[arg-type]
        assert connect is not None and "All-in-One" not in connect

    asyncio.run(run())


# ── 4. runtime: the real toggle, the same container ───────────────────────────


def test_switching_a_module_off_takes_effect_on_the_next_render(tmp_path: Path) -> None:
    from db.database import Database
    from models.dto import TelegramUserProfile
    from repositories.protocol_modules import ProtocolModulesRepository
    from repositories.proxy_accesses import ProxyAccessRepository
    from repositories.users import UserRepository
    from repositories.vpn_keys import VpnKeyRepository
    from services.protocol_modules import ProtocolModulesService

    class _Audit:
        async def write_best_effort(self, **kwargs: object) -> None:
            return None

    async def purge(*args: object) -> None:
        return None

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await UserRepository(db).upsert_profile(
                TelegramUserProfile(ADMIN, "admin", "Admin"), UserRole.SUPERADMIN, "now"
            )
            modules = ProtocolModulesService(ProtocolModulesRepository(db), db)
            modules.attach_purge_handlers(
                users=_Users(),
                audit=_Audit(),
                vpn_keys=VpnKeyRepository(db),
                proxy_accesses=ProxyAccessRepository(db),
                key_purgers={VpnKeyType.AWG: purge, VpnKeyType.XRAY: purge, VpnKeyType.HYSTERIA2: purge},
                proxy_purgers={},
            )
            services = _services(frozenset(VPN_FLAGS), modules=modules)

            async def screens() -> dict[str, str]:
                texts: dict[str, str] = {}
                with use_locale("ru"):
                    await _render_faq(services, texts)
                    await _render_create(services, texts)
                    start = _Callback("keys:create:bundle")
                    await create_key_choose_bundle(start, _State(), services)  # type: ignore[arg-type]
                    texts["bundle:start"] = start.message.last_text
                    texts["bundle:start:buttons"] = "\n".join(_labels(start.message.last_markup))
                return texts

            before = await screens()
            assert "amneziawg" in before["create:menu:buttons"].lower()
            assert "AWG" in before["faq:choice"]
            assert before["bundle:start"] == t("bundle_awg_separate")

            # The admin switches AWG off — no restart, same container, same objects.
            await modules.disable_protocol("awg", ADMIN)
            after = await screens()
            _assert_no_forbidden(after, {"awg"})
            assert t("btn_understood") not in after["bundle:start:buttons"]

            # …and back on: the very next render offers it again.
            await modules.enable_protocol("awg", ADMIN)
            again = await screens()
            assert again == before

            # Xray off at runtime takes XHTTP with it.
            await modules.disable_protocol("xray", ADMIN)
            _assert_no_forbidden(await screens(), {"xray_tcp", "xhttp"})
        finally:
            await db.close()

    asyncio.run(run())


# ── availability source of truth ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("settings_overrides", "disabled", "expected_missing"),
    [
        ({}, set(), set()),
        ({}, {"xray"}, {Protocol.XRAY, Protocol.XHTTP}),
        ({"xray_xhttp_enabled": False}, set(), {Protocol.XHTTP}),
        ({}, {"awg"}, {Protocol.AWG}),
        ({"hysteria2_enabled": False}, set(), {Protocol.HYSTERIA2}),
        ({"is_hysteria2_ready": lambda: False}, set(), {Protocol.HYSTERIA2}),
        ({}, {"hysteria2"}, {Protocol.HYSTERIA2}),
        ({"socks5_enabled": False}, set(), {Protocol.SOCKS5}),
        ({}, {"socks5"}, {Protocol.SOCKS5}),
        ({"mtproto_enabled": False}, set(), {Protocol.MTPROTO}),
        ({}, {"mtproto"}, {Protocol.MTPROTO}),
    ],
)
def test_available_protocols_combines_env_flags_and_the_toggle(
    settings_overrides: dict[str, Any], disabled: set[str], expected_missing: set[Protocol]
) -> None:
    settings = SimpleNamespace(
        **availability_settings(
            **{
                "xray_xhttp_enabled": True,
                "hysteria2_enabled": True,
                "socks5_enabled": True,
                "mtproto_enabled": True,
                **settings_overrides,
            }
        )
    )
    result = asyncio.run(available_protocols(settings, _Toggles(disabled)))  # type: ignore[arg-type]
    assert result == ALL_PROTOCOLS - expected_missing


@pytest.mark.parametrize("vpn", VPN_SUBSETS, ids=_ids)
def test_text_composition_matches_what_creating_a_bundle_would_provision(vpn: frozenset[str]) -> None:
    """The texts describe exactly the members KeyBundleService would create."""

    async def run() -> None:
        services = _services(vpn)
        available = await current_availability(services)  # type: ignore[arg-type]
        service = object.__new__(KeyBundleService)
        service.modules = services.modules  # type: ignore[assignment]
        service.settings = services.settings  # type: ignore[assignment]
        service.relays = services.relays  # type: ignore[assignment]
        for kind in KeyBundleKind:
            included, _skipped = await service._resolve_composition(kind)
            assert available.bundle_members(kind) == included

    asyncio.run(run())


def test_extended_kind_is_hidden_while_it_would_equal_basic() -> None:
    async def run() -> None:
        no_xhttp = await current_availability(_services(frozenset({"xray_tcp", "hy2"})))  # type: ignore[arg-type]
        assert bundle_kinds(no_xhttp) == (KeyBundleKind.BASIC,)
        with_xhttp = await current_availability(_services(frozenset({"xray_tcp", "xhttp"})))  # type: ignore[arg-type]
        assert bundle_kinds(with_xhttp) == (KeyBundleKind.BASIC, KeyBundleKind.EXTENDED)
        with use_locale("ru"):
            assert bundle_kind_description(KeyBundleKind.BASIC, with_xhttp) == (
                "VLESS (TCP) — основной протокол. Подходит большинству."
            )
            assert bundle_kind_description(KeyBundleKind.EXTENDED, with_xhttp).startswith(
                "VLESS (TCP) и три специальных профиля VLESS (HTTP). "
            )

    asyncio.run(run())


def test_the_xhttp_wording_counts_the_xhttp_members_of_the_composition() -> None:
    """«три специальных профиля» stays true only while there are three of them."""
    xhttp = [m for m in bundle_composition(KeyBundleKind.EXTENDED) if m.transport == "http"]
    assert len(xhttp) == 3
    assert "три" in ru_mod.STRINGS["bundle_part_vless_http"]
    assert "three" in en_mod.STRINGS["bundle_part_vless_http"]


def test_skipped_members_are_named_only_while_their_protocol_is_visible() -> None:
    available = Availability(frozenset({Protocol.XRAY}), subscription_enabled=True)
    tcp = BundleMember(VpnKeyType.XRAY)
    relay_tcp = BundleMember(VpnKeyType.XRAY, relay="ru1")
    hy2 = BundleMember(VpnKeyType.HYSTERIA2)
    result = KeyBundleCreateResult(
        bundle=_bundle(), keys=(_member_key(1, tcp),), included=(tcp,), skipped=(hy2, relay_tcp)
    )
    with use_locale("ru"):
        text = bundle_created_text(result, viewer_user_id=OWNER, settings=_settings(), available=available)
    assert "Hysteria2" not in text
    assert "VLESS (TCP)" in text.split(t("bundle_created_skipped", skipped=""))[-1]


# ── structure guards ──────────────────────────────────────────────────────────


def _spec_keys() -> set[str]:
    specs: list[tuple[Block, ...]] = [*_FAQ_SPECS.values(), *_BUNDLE_KIND_DESC.values(), _BUNDLE_AWG_NOTICE]
    return {part.key for spec in specs for block in spec for part in block.parts}


def test_every_faq_topic_has_a_spec_and_every_fragment_exists_in_both_locales() -> None:
    assert {topic for topic, _ in FAQ_TOPICS} == set(_FAQ_SPECS)
    keys = _spec_keys() | {
        "faq_connect_apps_awg",
        "faq_connect_apps_links",
        "bundle_part_vless_tcp",
        "bundle_part_vless_http",
        "bundle_part_hysteria2",
        "bundle_part_hysteria2_alt",
        "cabinet_active_keys",
        "cabinet_active_keys_by_protocol",
        "proxy_traffic_unavailable",
        "proxy_traffic_unavailable_generic",
        "list_and",
        "list_or",
    }
    for key in keys:
        assert key in ru_mod.STRINGS, key
        assert key in en_mod.STRINGS, key


def test_compose_drops_parts_and_whole_paragraphs_that_do_not_apply() -> None:
    spec = (
        Block((Part("faq_choice_awg", lambda a: Protocol.AWG in a),)),
        Block((Part("faq_choice_pick_awg", lambda a: False), Part("faq_choice_pick_hy2"))),
    )
    with use_locale("ru"):
        assert compose(spec, Availability(frozenset())) == t("faq_choice_pick_hy2")
        assert compose(spec, Availability(frozenset({Protocol.AWG}))) == (
            f"{t('faq_choice_awg')}\n\n{t('faq_choice_pick_hy2')}"
        )


def _strings_naming_several_protocols(strings: dict[str, str]) -> set[str]:
    """Catalogue keys whose text names more than one VPN protocol."""
    names = {
        "xray": re.compile(r"xray|vless", re.IGNORECASE),
        "awg": re.compile(r"\bawg|amnezia|wireguard", re.IGNORECASE),
        "hy2": re.compile(r"hysteria", re.IGNORECASE),
    }
    return {key for key, text in strings.items() if sum(bool(p.search(text)) for p in names.values()) > 1}


def test_user_texts_naming_several_protocols_are_composed_variants_only() -> None:
    """No user-facing catalogue string lists several protocols on its own.

    A string that names two protocols is allowed only as a composed variant (it is
    picked exactly when both are on) or on an admin-only screen, which is out of
    scope by design — an admin must see a disabled protocol to re-enable it.
    """
    composed = _spec_keys()
    # Admin-panel screens (block/unblock reports, the module toggle itself).
    admin_only = {
        "unblock_no_auto_fix",
        "unblock_vpn_check_warning",
        "user_blocked_with_errors",
        "modules_panel_title",
        "module_disable_confirm1",
        "aio_panel_title",
    }
    offenders = {
        key
        for key in _strings_naming_several_protocols(ru_mod.STRINGS)
        if key not in composed and key not in admin_only
    }
    assert offenders == set(), offenders


# Variant groups: alternatives of one sentence, of which EXACTLY one must apply
# whenever the group applies at all — none would leave a hole in the text, two
# would say the same thing twice. Keyed by group name: (member keys, when the
# group applies).
_X, _XH, _A, _H = Protocol.XRAY, Protocol.XHTTP, Protocol.AWG, Protocol.HYSTERIA2
VARIANT_GROUPS: dict[str, tuple[tuple[str, ...], Any]] = {
    "connect intro": (("faq_connect_intro_file", "faq_connect_intro"), lambda a: bool(a.vpn)),
    "connect delivery": (
        (
            "faq_connect_delivery_xray_hy2_awg",
            "faq_connect_delivery_xray_awg",
            "faq_connect_delivery_hy2_awg",
            "faq_connect_delivery_awg",
            "faq_connect_delivery_link",
        ),
        lambda a: bool(a.vpn),
    ),
    "connect tip": (
        ("faq_connect_tip_protocols_transports", "faq_connect_tip_protocols", "faq_connect_tip_transports"),
        lambda a: len(a.vpn) > 1 or _XH in a,
    ),
    "choice xray": (
        (
            "faq_choice_xray_best_transport",
            "faq_choice_xray_best",
            "faq_choice_xray_solo_transport",
            "faq_choice_xray_solo",
        ),
        lambda a: _X in a,
    ),
    "choice hy2": (("faq_choice_hy2_vs_awg", "faq_choice_hy2"), lambda a: _H in a),
    "choice start": (("faq_choice_start_xray", "faq_choice_start_hy2"), lambda a: len(a.vpn) > 1),
    "trouble xray": (("faq_trouble_xray_transport", "faq_trouble_xray"), lambda a: _X in a),
    "trouble hy2 udp": (
        (
            "faq_trouble_hy2_udp_switch_xray_awg",
            "faq_trouble_hy2_udp_switch_xray",
            "faq_trouble_hy2_udp_switch_awg",
            "faq_trouble_hy2_udp",
        ),
        lambda a: _H in a,
    ),
    "trouble hy2 settings": (
        ("faq_trouble_hy2_no_mtu_fp", "faq_trouble_hy2_no_fp", "faq_trouble_hy2_no_mtu"),
        lambda a: _H in a and (_X in a or _A in a),
    ),
    "fingerprint scope": (("faq_fingerprint_scope_awg", "faq_fingerprint_scope"), lambda a: _X in a),
    "proxy intro": (
        ("faq_proxy_intro_both", "faq_proxy_intro_one"),
        lambda a: Protocol.SOCKS5 in a or Protocol.MTPROTO in a,
    ),
    "security encryption": (
        ("faq_security_encryption_many", "faq_security_encryption_one"),
        lambda a: bool(a.vpn),
    ),
    "support key line": (("faq_support_key_type", "faq_support_key_number"), lambda a: True),
    "basic kind": (
        ("bundle_kind_basic_desc_pair", "bundle_kind_basic_desc_single"),
        lambda a: bool(a.bundle_members(KeyBundleKind.BASIC)),
    ),
}


def _all_availabilities() -> list[Availability]:
    snapshots = []
    for vpn in VPN_SUBSETS:
        for proxies in PROXY_SUBSETS:
            for subscription in (False, True):
                protocols = {
                    Protocol.XRAY: "xray_tcp" in vpn,
                    Protocol.XHTTP: "xhttp" in vpn,
                    Protocol.AWG: "awg" in vpn,
                    Protocol.HYSTERIA2: "hy2" in vpn,
                    Protocol.SOCKS5: "socks5" in proxies,
                    Protocol.MTPROTO: "mtproto" in proxies,
                }
                snapshots.append(
                    Availability(frozenset(p for p, on in protocols.items() if on), subscription_enabled=subscription)
                )
    return snapshots


@pytest.mark.parametrize("group", sorted(VARIANT_GROUPS))
def test_exactly_one_variant_of_every_sentence_applies(group: str) -> None:
    keys, applies = VARIANT_GROUPS[group]
    parts = {
        part.key: part
        for spec in (*_FAQ_SPECS.values(), *_BUNDLE_KIND_DESC.values())
        for block in spec
        for part in block.parts
        if part.key in keys
    }
    assert set(parts) == set(keys), f"{group}: unknown keys {set(keys) - set(parts)}"
    for available in _all_availabilities():
        chosen = [key for key in keys if parts[key].when(available)]
        # Where the group does not apply its topic is hidden or the sentence has
        # nothing to say; what matters there is only that variants never stack.
        if applies(available):
            assert len(chosen) == 1, f"{group}: {chosen} for {sorted(available.protocols)}"
        else:
            assert len(chosen) <= 1, f"{group}: {chosen} for {sorted(available.protocols)}"
