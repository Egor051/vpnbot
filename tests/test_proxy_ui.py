
import asyncio
from types import SimpleNamespace

from bot.formatters import (
    admin_proxy_stats_text,
    mtproto_proxy_text,
    proxy_access_text,
    proxy_admin_status_text,
    proxy_section_separator,
    socks5_proxy_text,
    user_proxy_stats_text,
)
from bot.handlers.admin import admin_proxy_stats
from bot.handlers.proxy import proxy_confirm, proxy_stats
from bot.keyboards.admin import admin_panel_keyboard
from bot.keyboards.proxy import proxy_menu_keyboard
from models.dto import (
    ProxyAccess,
    ProxyAccessStatsItem,
    ProxyActiveAccessRef,
    ProxyAdminStats,
    ProxyAdminUserStats,
    ProxyLifecycleStats,
    ProxyRuntimeStats,
    ProxyServiceStatus,
    ProxyUserStats,
)
from models.enums import ProxyAccessStatus, ProxyAccessType
from services.errors import AccessDenied


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


def _stats_item(
    access_id: int,
    access_type: ProxyAccessType,
    status: ProxyAccessStatus,
    *,
    created_at: str = "2026-05-06T18:19:00+00:00",
    updated_at: str | None = None,
) -> ProxyAccessStatsItem:
    if access_type == ProxyAccessType.SOCKS5:
        return ProxyAccessStatsItem(
            id=access_id,
            owner_user_id=100,
            username="user",
            access_type=access_type,
            status=status,
            created_at=created_at,
            updated_at=updated_at or created_at,
            activated_at=created_at if status == ProxyAccessStatus.ACTIVE else None,
            last_shown_at=None,
            revoked_at=created_at if status == ProxyAccessStatus.REVOKED else None,
            deleted_at=created_at if status == ProxyAccessStatus.DELETED else None,
            host="150.251.152.243",
            port=31337,
            login=f"vpn_socks_100_{access_id}",
        )
    return ProxyAccessStatsItem(
        id=access_id,
        owner_user_id=100,
        username="user",
        access_type=access_type,
        status=status,
        created_at=created_at,
        updated_at=updated_at or created_at,
        activated_at=created_at if status == ProxyAccessStatus.ACTIVE else None,
        last_shown_at=None,
        revoked_at=created_at if status == ProxyAccessStatus.REVOKED else None,
        deleted_at=created_at if status == ProxyAccessStatus.DELETED else None,
        host="150.251.152.243",
        port=8443,
        mtproto_mode="managed",
        secret_fingerprint=f"fingerprint{access_id}",
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


def test_admin_keyboard_has_proxy_stats_button() -> None:
    buttons = _buttons(admin_panel_keyboard())

    assert ("📊 Статистика прокси", "admin:proxy_stats") in buttons



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


def test_user_proxy_stats_empty_message() -> None:
    text = user_proxy_stats_text(ProxyUserStats(owner_user_id=100, accesses=()))

    assert "У вас пока нет выданных прокси" in text


def test_user_proxy_stats_socks5_omits_password() -> None:
    text = user_proxy_stats_text(
        ProxyUserStats(
            owner_user_id=100,
            accesses=(
                ProxyAccessStatsItem(
                    id=10,
                    owner_user_id=100,
                    username="user",
                    access_type=ProxyAccessType.SOCKS5,
                    status=ProxyAccessStatus.ACTIVE,
                    created_at="2026-05-06T20:19:00+00:00",
                    updated_at="2026-05-06T20:19:00+00:00",
                    activated_at="2026-05-06T20:19:00+00:00",
                    last_shown_at="2026-05-06T20:20:00+00:00",
                    revoked_at=None,
                    deleted_at=None,
                    host="150.251.152.243",
                    port=31337,
                    login="vpn_socks_100_abcd",
                ),
            ),
        )
    )

    assert "SOCKS5" in text
    assert "active" in text
    assert "150.251.152.243" in text
    assert "31337" in text
    assert "vpn_socks_100_abcd" in text
    assert "secret-password" not in text
    assert "Password:" not in text


def test_user_proxy_stats_mtproto_omits_secret_and_links() -> None:
    raw_secret = "0123456789abcdef0123456789abcdef"
    text = user_proxy_stats_text(
        ProxyUserStats(
            owner_user_id=100,
            accesses=(
                ProxyAccessStatsItem(
                    id=11,
                    owner_user_id=100,
                    username="user",
                    access_type=ProxyAccessType.MTPROTO,
                    status=ProxyAccessStatus.ACTIVE,
                    created_at="2026-05-06T20:19:00+00:00",
                    updated_at="2026-05-06T20:19:00+00:00",
                    activated_at="2026-05-06T20:19:00+00:00",
                    last_shown_at=None,
                    revoked_at=None,
                    deleted_at=None,
                    host="150.251.152.243",
                    port=8443,
                    mtproto_mode="managed",
                    secret_fingerprint="f3bff43850e88441",
                ),
            ),
        )
    )

    assert "MTProto" in text
    assert "managed" in text
    assert "f3bff43850e88441" in text
    assert raw_secret not in text
    assert "t.me/proxy" not in text


def test_user_proxy_stats_shows_active_and_limits_apply_failed_history() -> None:
    accesses = (
        _stats_item(10, ProxyAccessType.SOCKS5, ProxyAccessStatus.ACTIVE),
        _stats_item(11, ProxyAccessType.MTPROTO, ProxyAccessStatus.ACTIVE),
        _stats_item(12, ProxyAccessType.SOCKS5, ProxyAccessStatus.REVOKED),
        _stats_item(13, ProxyAccessType.MTPROTO, ProxyAccessStatus.DELETED),
        _stats_item(14, ProxyAccessType.SOCKS5, ProxyAccessStatus.INACTIVE),
        _stats_item(1, ProxyAccessType.SOCKS5, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:11:00+00:00"),
        _stats_item(2, ProxyAccessType.MTPROTO, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:12:00+00:00"),
        _stats_item(3, ProxyAccessType.SOCKS5, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:13:00+00:00"),
        _stats_item(4, ProxyAccessType.MTPROTO, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:14:00+00:00"),
        _stats_item(5, ProxyAccessType.SOCKS5, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:15:00+00:00"),
        _stats_item(6, ProxyAccessType.MTPROTO, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:16:00+00:00"),
        _stats_item(7, ProxyAccessType.SOCKS5, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:17:00+00:00"),
        _stats_item(8, ProxyAccessType.MTPROTO, ProxyAccessStatus.APPLY_FAILED, updated_at="2026-05-06T18:18:00+00:00"),
    )

    text = user_proxy_stats_text(ProxyUserStats(owner_user_id=100, accesses=accesses))

    assert "Активные прокси" in text
    assert "SOCKS5 #10" in text
    assert "MTProto #11" in text
    assert "Последние ошибки выдачи" in text
    assert "MTProto #8" in text
    assert "SOCKS5 #7" in text
    assert "MTProto #6" in text
    assert "SOCKS5 #5" not in text
    assert "Старые неудачные попытки скрыты: 5" in text
    assert "revoked" not in text
    assert "deleted" not in text
    assert "inactive" not in text
    assert "Ещё" not in text


def test_user_proxy_stats_does_not_show_old_apply_failed_when_no_recent_slot() -> None:
    accesses = tuple(
        _stats_item(
            access_id,
            ProxyAccessType.SOCKS5 if access_id % 2 else ProxyAccessType.MTPROTO,
            ProxyAccessStatus.APPLY_FAILED,
            updated_at=f"2026-05-06T18:{access_id:02d}:00+00:00",
        )
        for access_id in range(1, 7)
    )

    text = user_proxy_stats_text(ProxyUserStats(owner_user_id=100, accesses=accesses))

    assert text.count("apply_failed") == 3
    assert "Старые неудачные попытки скрыты: 3" in text
    assert "#3" not in text
    assert "#4" in text
    assert "#5" in text
    assert "#6" in text


def test_admin_proxy_stats_contains_aggregates_users_and_no_raw_credentials() -> None:
    text = admin_proxy_stats_text(
        ProxyAdminStats(
            total_accesses=4,
            active_total=2,
            active_socks5=1,
            active_mtproto=1,
            apply_failed=1,
            revoked=1,
            deleted=0,
            pending=0,
            users_with_active_proxies=1,
            last_issued_at="2026-05-06T20:19:00+00:00",
            last_failed_at="2026-05-06T20:21:00+00:00",
            type_status_counts={
                ProxyAccessType.SOCKS5: {
                    ProxyAccessStatus.ACTIVE: 1,
                    ProxyAccessStatus.APPLY_FAILED: 1,
                },
                ProxyAccessType.MTPROTO: {
                    ProxyAccessStatus.ACTIVE: 1,
                    ProxyAccessStatus.REVOKED: 1,
                },
            },
            mtproto_mode_counts={"managed": 1, "static": 1},
            users=(
                ProxyAdminUserStats(
                    telegram_user_id=1278023784,
                    username="username",
                    active_socks5_count=1,
                    active_mtproto_count=1,
                    failed_count=1,
                    last_proxy_issued_at="2026-05-06T20:19:00+00:00",
                    active_accesses=(
                        ProxyActiveAccessRef(10, ProxyAccessType.SOCKS5),
                        ProxyActiveAccessRef(11, ProxyAccessType.MTPROTO),
                    ),
                ),
            ),
            total_users=1,
            runtime=ProxyRuntimeStats(
                socks5_enabled=True,
                socks5_host="150.251.152.243",
                socks5_port=31337,
                mtproto_enabled=True,
                mtproto_host="150.251.152.243",
                mtproto_port=8443,
                mtproto_mode="managed",
                mtproto_systemd_active=True,
                mtproto_port_listening=True,
                mtproto_runtime_secret_count=1,
            ),
        )
    )

    assert "total proxy accesses: 4" in text
    assert "active SOCKS5: 1" in text
    assert "active MTProto: 1" in text
    assert "failed total: 1" in text
    assert "users with active proxies: 1" in text
    assert "1278023784" in text
    assert "@username" in text
    assert "SOCKS5 #10" in text
    assert "MTProto #11" in text
    assert "secret-password" not in text
    assert "0123456789abcdef0123456789abcdef" not in text
    assert "t.me/proxy" not in text


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


def test_proxy_stats_callback_shows_current_user_stats(monkeypatch) -> None:
    monkeypatch.setattr("bot.handlers.proxy.ensure_private_callback", _allow_private)

    class Proxy:
        async def get_user_proxy_stats(self, user_id: int) -> ProxyUserStats:
            assert user_id == 100
            return ProxyUserStats(owner_user_id=100, accesses=())

    async def run() -> None:
        callback = _Callback("proxy:stats")
        services = SimpleNamespace(proxy=Proxy())
        await proxy_stats(callback, services)  # type: ignore[arg-type]

        assert callback.message.edits
        assert "У вас пока нет выданных прокси" in callback.message.edits[-1][0]
        assert _buttons(callback.message.edits[-1][1]) == [("Вернуться в Прокси", "proxy:show")]

    asyncio.run(run())


def test_admin_proxy_stats_denies_non_admin(monkeypatch) -> None:
    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)

    class Users:
        async def require_superadmin(self, user_id: int) -> None:
            raise AccessDenied("Нет доступа")

    async def run() -> None:
        callback = _Callback("admin:proxy_stats")
        services = SimpleNamespace(users=Users())
        await admin_proxy_stats(callback, services)  # type: ignore[arg-type]

        assert callback.answers[-1] == ("Нет доступа", True)
        assert callback.message.edits == []

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
