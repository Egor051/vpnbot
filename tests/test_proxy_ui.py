from __future__ import annotations

import asyncio
from types import SimpleNamespace

from bot.formatters import (
    mtproto_proxy_text,
    proxy_access_text,
    proxy_admin_status_text,
    proxy_section_separator,
    socks5_proxy_text,
)
from bot.handlers.proxy import proxy_confirm
from bot.keyboards.proxy import proxy_menu_keyboard
from models.dto import ProxyAccess, ProxyLifecycleStats, ProxyServiceStatus
from models.enums import ProxyAccessStatus, ProxyAccessType


def _access(access_type: ProxyAccessType, payload: dict[str, object] | None = None) -> ProxyAccess:
    return ProxyAccess(
        id=1 if access_type == ProxyAccessType.SOCKS5 else 2,
        owner_user_id=100,
        username="user",
        access_type=access_type,
        status=ProxyAccessStatus.ACTIVE,
        payload=payload or {},
        public_payload={},
        created_at="now",
        updated_at="now",
        last_shown_at=None,
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
        reason=None,
        error=None,
    )


class _Callback:
    def __init__(self, data: str) -> None:
        self.from_user = SimpleNamespace(id=100, username="user", first_name="User")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _Message:
    def __init__(self) -> None:
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))

    async def answer(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))


class _State:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self.data = data or {}
        self.cleared = False

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def clear(self) -> None:
        self.cleared = True
        self.data.clear()


async def _allow_private(*args: object, **kwargs: object) -> bool:
    return True


def _buttons(markup: object) -> list[tuple[str, str | None]]:
    return [(button.text, button.callback_data) for row in markup.inline_keyboard for button in row]


def test_proxy_keyboard_no_accesses_has_get_buttons_and_no_pagination_or_revoke() -> None:
    markup = proxy_menu_keyboard([], socks5_enabled=True, mtproto_enabled=True)

    buttons = _buttons(markup)
    assert buttons == [
        ("Получить SOCKS5", "proxy:get:socks5"),
        ("Получить MTProto", "proxy:get:mtproto"),
        ("Вернуться", "proxy:back"),
    ]
    assert all("show:" not in str(data) for _text, data in buttons)
    assert all("revoke" not in str(data) and "delete" not in str(data) and "note" not in str(data) for _text, data in buttons)


def test_proxy_keyboard_hides_disabled_or_already_issued_types() -> None:
    socks5 = _access(ProxyAccessType.SOCKS5)

    buttons = _buttons(proxy_menu_keyboard([socks5], socks5_enabled=True, mtproto_enabled=False))

    assert buttons == [("Вернуться", "proxy:back")]


def test_socks5_proxy_text_contains_credentials_and_url() -> None:
    text = socks5_proxy_text(
        {
            "host": "150.251.152.243",
            "port": 31337,
            "login": "vpn_socks_100_abcd",
            "password": "secret",
            "url": "socks5://vpn_socks_100_abcd:secret@150.251.152.243:31337",
        }
    )

    assert "Host:" in text
    assert "Port:" in text
    assert "Login:" in text
    assert "Password:" in text
    assert "URL:" in text


def test_mtproto_proxy_text_shows_plain_link_before_dd_link() -> None:
    text = mtproto_proxy_text(
        {
            "host": "150.251.152.243",
            "port": 8443,
            "link": "https://t.me/proxy?server=150.251.152.243&port=8443&secret=abc",
            "link_dd": "https://t.me/proxy?server=150.251.152.243&port=8443&secret=ddabc",
        }
    )

    assert text.index("secret=abc") < text.index("secret=ddabc")
    assert "Сначала попробуйте первый вариант" in text


def test_mtproto_proxy_text_managed_mentions_individual_revoke() -> None:
    text = mtproto_proxy_text(
        {
            "mode": "managed",
            "host": "150.251.152.243",
            "port": 8443,
            "link": "https://t.me/proxy?server=150.251.152.243&port=8443&secret=abc",
            "link_dd": "https://t.me/proxy?server=150.251.152.243&port=8443&secret=ddabc",
        }
    )

    assert "индивидуальный MTProto-доступ" in text
    assert text.index("secret=abc") < text.index("secret=ddabc")


def test_proxy_access_text_uses_central_separator_for_two_blocks() -> None:
    socks5 = _access(ProxyAccessType.SOCKS5, {"host": "h", "port": 1, "login": "l", "password": "p", "url": "u"})
    mtproto = _access(ProxyAccessType.MTPROTO, {"host": "h", "port": 2, "link": "plain", "link_dd": "dd"})

    text = proxy_access_text([socks5, mtproto])

    assert "<b>SOCKS5</b>" in text
    assert "<b>Telegram MTProto Proxy</b>" in text
    assert proxy_section_separator() in text


def test_proxy_admin_status_does_not_show_secrets_and_marks_traffic_unavailable() -> None:
    text = proxy_admin_status_text(
        ProxyServiceStatus(
            socks5_enabled=True,
            socks5_host="150.251.152.243",
            socks5_port=31337,
            socks5_public_name="SOCKS5 Proxy",
            socks5_service_name="danted",
            mtproto_enabled=True,
            mtproto_host="150.251.152.243",
            mtproto_port=8443,
            mtproto_public_name="Telegram MTProto Proxy",
            mtproto_stats_url_configured=True,
        ),
        ProxyLifecycleStats(
            socks5_issued=2,
            socks5_active=1,
            socks5_revoked=1,
            mtproto_issued=2,
            mtproto_active=1,
            mtproto_deactivated=1,
        ),
    )

    assert "secret" in text.lower()
    assert "0123456789abcdef" not in text
    assert "статистика трафика недоступна" in text


def test_proxy_confirm_issues_socks5_and_edits_same_message(monkeypatch) -> None:
    monkeypatch.setattr("bot.handlers.proxy.ensure_private_callback", _allow_private)

    socks5_access = _access(
        ProxyAccessType.SOCKS5,
        {"host": "h", "port": 31337, "login": "l", "password": "p", "url": "u"},
    )

    class Proxy:
        def __init__(self) -> None:
            self.accesses: list[ProxyAccess] = []

        async def list_user_accesses(self, user_id: int) -> list[ProxyAccess]:
            return list(self.accesses)

    class Socks5:
        def __init__(self, proxy: Proxy) -> None:
            self.calls = 0
            self.proxy = proxy

        async def issue_socks5_proxy(self, actor_user_id: int, profile: object) -> ProxyAccess:
            self.calls += 1
            self.proxy.accesses = [socks5_access]
            return socks5_access

    async def run() -> None:
        proxy = Proxy()
        socks5 = Socks5(proxy)
        services = SimpleNamespace(
            proxy=proxy,
            socks5=socks5,
            mtproto=SimpleNamespace(),
            settings=SimpleNamespace(socks5_enabled=True, mtproto_enabled=True),
        )
        state = _State({"proxy_type": "socks5", "nonce": "abc"})
        callback = _Callback("proxy:confirm:socks5:abc")
        await proxy_confirm(callback, state, services)  # type: ignore[arg-type]

        assert state.cleared is True
        assert socks5.calls == 1
        assert callback.message.edits
        assert "SOCKS5" in callback.message.edits[-1][0]

    asyncio.run(run())


def test_proxy_confirm_stale_without_existing_access_returns_to_proxy(monkeypatch) -> None:
    monkeypatch.setattr("bot.handlers.proxy.ensure_private_callback", _allow_private)

    class Proxy:
        async def list_user_accesses(self, user_id: int) -> list[ProxyAccess]:
            return []

    async def run() -> None:
        state = _State({"proxy_type": "socks5", "nonce": "fresh"})
        callback = _Callback("proxy:confirm:socks5:old")
        services = SimpleNamespace(proxy=Proxy(), settings=SimpleNamespace(socks5_enabled=True, mtproto_enabled=True))
        await proxy_confirm(callback, state, services)  # type: ignore[arg-type]

        assert state.cleared is True
        assert callback.answers == [("Действие устарело", True)]
        buttons = _buttons(callback.message.edits[-1][1])
        assert buttons == [("Вернуться в Прокси", "proxy:show")]

    asyncio.run(run())


def test_proxy_confirm_stale_with_existing_access_shows_existing_without_reissue(monkeypatch) -> None:
    monkeypatch.setattr("bot.handlers.proxy.ensure_private_callback", _allow_private)

    mtproto_access = _access(
        ProxyAccessType.MTPROTO,
        {"mode": "managed", "host": "h", "port": 8443, "link": "plain", "link_dd": "dd"},
    )

    class Proxy:
        async def list_user_accesses(self, user_id: int) -> list[ProxyAccess]:
            return [mtproto_access]

    class MtProto:
        def __init__(self) -> None:
            self.calls = 0

        async def issue_mtproto_proxy(self, actor_user_id: int, profile: object) -> ProxyAccess:
            self.calls += 1
            return mtproto_access

    async def run() -> None:
        mtproto = MtProto()
        state = _State({})
        callback = _Callback("proxy:confirm:mtproto:old")
        services = SimpleNamespace(
            proxy=Proxy(),
            socks5=SimpleNamespace(),
            mtproto=mtproto,
            settings=SimpleNamespace(socks5_enabled=True, mtproto_enabled=True),
        )
        await proxy_confirm(callback, state, services)  # type: ignore[arg-type]

        assert mtproto.calls == 0
        assert callback.message.edits
        assert "Telegram MTProto Proxy" in callback.message.edits[-1][0]

    asyncio.run(run())
