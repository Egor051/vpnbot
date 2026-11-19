"""SOCKS5 (and MTProto) through the hub in the fallback mode (docs/proxy.md «Через hub»).

he2 is the hub; main's IPv4 is banned at the Russian border, the hub still reaches main.
The proxies were handed out as SOCKS5_HOST:SOCKS5_PORT — main's address, dead for users
in Russia. Pinned here:

* **One source of the address** (services/proxy_endpoint.py): in the mode, with the hub
  forwarding the port, every proxy a user sees — host, port, ``socks5://``, the
  ``t.me/socks`` link, the MTProto ``t.me/proxy`` links, the stats — carries the hub's
  IPv4; outside the mode SOCKS5_HOST. Credentials never change.
* **The hub's port set**: switching the mode on adds SOCKS5_PORT/tcp (the agent's
  ``apply``, the same as 443/2096), switching it off — or the module off — takes it away.
* **The preflight**: a proxy row of its own; an unreachable main:SOCKS5_PORT is a clear
  refusal of the PROXY — never a VPN switch that does not happen, and never a hub that
  looks unable to reach main on 443.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_fallback_mode import HUB, MAIN, ORIGIN, Fallback, _ready
from test_relay import ADMIN

from bot.fallback import preflight_text, proxy_notice_text, report_text
from bot.formatters import socks5_proxy_text
from i18n import t
from models.dto import ProxyAccess
from models.enums import ProxyAccessStatus, ProxyAccessType
from services.fallback import FallbackService, check_reaches
from services.proxy_endpoint import ProxyEndpoint, ProxyEndpoints
from services.relay_ssh import AgentReply

SOCKS_PORT = 31337
pytestmark = pytest.mark.timeout(60)


class Modules:
    def __init__(self) -> None:
        self.on = {"socks5": True, "mtproto": True}

    async def is_enabled(self, name: str) -> bool:
        return self.on.get(name, True)


@pytest.fixture
async def fb(tmp_path: Path) -> Any:
    world = await Fallback(tmp_path).start(socks5_enabled=True, socks5_host=MAIN, socks5_port=SOCKS_PORT)
    world.endpoints = ProxyEndpoints(world.settings)
    world.modules = Modules()
    world.service = FallbackService(
        repo=world.repo, relays_repo=world.relays_repo, relays=world.relay_service, users=world.service.users,
        audit=world.audit, clock=world.service.clock, settings=world.settings, token_file=world.token_file,
        dns=world.service.dns, doh=world.service._doh, sleep=world.service._sleep,
        monotonic=world.service._monotonic, verify_timeout=20.0, verify_interval=5.0,
        endpoints=world.endpoints, modules=world.modules,
    )
    yield world
    await world.close()


def _access(kind: ProxyAccessType, payload: dict[str, object]) -> ProxyAccess:
    return ProxyAccess(
        id=1, owner_user_id=7, username="u", access_type=kind, status=ProxyAccessStatus.ACTIVE, payload=payload,
        public_payload={"host": MAIN, "port": SOCKS_PORT}, created_by=7, created_at="t", updated_at="t",
        last_shown_at=None, revoked_at=None, deleted_at=None, revoked_by=None, deleted_by=None, reason=None,
        error=None,
    )


# ── one source of the address ─────────────────────────────────────────────────


def test_a_proxy_is_rendered_with_the_hub_in_the_mode_and_with_socks5_host_outside(tmp_path: Path) -> None:
    from test_relay import _settings

    settings = _settings(tmp_path, socks5_enabled=True, socks5_host=MAIN, socks5_port=SOCKS_PORT,
                         mtproto_enabled=True, mtproto_host=MAIN, mtproto_port=8443)
    endpoints = ProxyEndpoints(settings)
    socks = _access(ProxyAccessType.SOCKS5, {"host": MAIN, "port": SOCKS_PORT, "login": "u_1", "password": "p&w",
                                             "url": f"socks5://u_1:p@{MAIN}:{SOCKS_PORT}"})
    mt = _access(ProxyAccessType.MTPROTO, {"host": MAIN, "port": 8443, "secret": "ab" * 16})
    assert endpoints.socks5() == ProxyEndpoint(MAIN, SOCKS_PORT, via_hub=False)
    text = socks5_proxy_text(endpoints.current(socks).payload)
    assert f"<code>{MAIN}</code>" in text and HUB not in text
    endpoints.set_via_hub({"socks5": HUB, "mtproto": HUB})
    shown = endpoints.current(socks)
    assert shown.payload["host"] == HUB and shown.payload["port"] == SOCKS_PORT
    assert shown.payload["url"] == f"socks5://u_1:p%26w@{HUB}:{SOCKS_PORT}"
    assert shown.payload["tg_link"] == f"https://t.me/socks?server={HUB}&port={SOCKS_PORT}&user=u_1&pass=p%26w"
    assert (shown.payload["login"], shown.payload["password"]) == ("u_1", "p&w"), "credentials untouched"
    assert shown.public_payload["host"] == HUB
    text = socks5_proxy_text(shown.payload)
    assert f"<code>{HUB}</code>" in text and MAIN not in text and "t.me/socks" in text
    mt_shown = endpoints.current(mt).payload
    assert mt_shown["link"] == f"https://t.me/proxy?server={HUB}&port=8443&secret={'ab' * 16}"
    assert str(mt_shown["link_dd"]).endswith(f"secret=dd{'ab' * 16}")
    endpoints.set_via_hub({})
    assert endpoints.current(socks).payload["host"] == MAIN, "the mode off: SOCKS5_HOST again"


def test_the_templates_do_not_read_the_proxy_host_settings() -> None:
    """ONE source: nothing that renders a proxy reads SOCKS5_HOST / MTPROTO_HOST itself."""
    root = Path(__file__).resolve().parents[1]
    for path in ("bot/formatters.py", "bot/handlers/proxy.py", "bot/keyboards/proxy.py"):
        text = (root / path).read_text(encoding="utf-8")
        assert "settings.socks5_host" not in text and "settings.mtproto_host" not in text, path
    for path, kind in (("services/socks5.py", "socks5"), ("services/mtproto.py", "mtproto")):
        text = (root / path).read_text(encoding="utf-8")
        assert f"{kind}_host}}" not in text, f"{path}: a link built from the setting, not the endpoint"
        assert f'"host": self.settings.{kind}_host' not in text, path
        assert f"self.endpoints.{kind}()" in text, path


# ── the hub's port set ────────────────────────────────────────────────────────


async def test_the_mode_on_adds_socks5_port_to_the_hub_and_off_takes_it_away(fb: Any) -> None:
    await _ready(fb)
    report = await fb.service.enable(ADMIN)
    assert report.complete
    applies = [c["request"] for c in fb.client.calls if c["request"].startswith("apply")]
    assert applies == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
    hub = await fb.service.overview(ADMIN)
    assert hub.hub is not None and hub.hub.agent is not None and SOCKS_PORT in hub.hub.agent.tcp_ports
    assert fb.endpoints.socks5() == ProxyEndpoint(HUB, SOCKS_PORT, via_hub=True)
    assert [(r.kind, r.port, r.ok, r.via_hub) for r in report.proxies] == [("socks5", SOCKS_PORT, True, True)]
    assert t("fb_route_on", proxy="SOCKS5", port=SOCKS_PORT) in report_text(report)
    assert hub.proxy_notice == ("socks5",), "the users may want the new address — offered, not sent"
    fb.client.calls.clear()
    back = await fb.service.disable(ADMIN)
    assert [c["request"] for c in fb.client.calls if c["request"].startswith("apply")] == [
        f"apply target={ORIGIN} tcp=443,2096 udp=443"]
    assert fb.endpoints.socks5() == ProxyEndpoint(MAIN, SOCKS_PORT, via_hub=False)
    assert [(r.kind, r.ok, r.via_hub) for r in back.proxies] == [("socks5", True, False)]


async def test_the_module_off_takes_the_port_off_the_hub_while_the_mode_is_on(fb: Any) -> None:
    await _ready(fb)
    await fb.service.enable(ADMIN)
    fb.client.calls.clear()
    fb.modules.on["socks5"] = False
    await fb.service.sync_proxies(ADMIN)
    assert [c["request"] for c in fb.client.calls] == [f"apply target={ORIGIN} tcp=443,2096 udp=443"]
    assert fb.endpoints.socks5().via_hub is False
    fb.client.calls.clear()
    fb.modules.on["socks5"] = True
    await fb.service.sync_proxies(ADMIN)
    assert [c["request"] for c in fb.client.calls] == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
    await fb.service.disable(ADMIN)
    fb.client.calls.clear()
    assert await fb.service.sync_proxies(ADMIN) == (), "the mode off: the hub is not touched"
    assert fb.client.calls == []


async def test_mtproto_follows_the_same_code(fb: Any) -> None:
    fb.settings = replace(fb.settings, mtproto_enabled=True, mtproto_host=MAIN, mtproto_port=8443)
    fb.service.settings = fb.settings
    fb.endpoints.settings = fb.settings
    await _ready(fb)
    await fb.service.enable(ADMIN)
    assert [c["request"] for c in fb.client.calls if c["request"].startswith("apply")] == [
        f"apply target={ORIGIN} tcp=443,2096,8443,{SOCKS_PORT} udp=443"]
    assert fb.endpoints.mtproto() == ProxyEndpoint(HUB, 8443, via_hub=True)


# ── the preflight ─────────────────────────────────────────────────────────────


async def test_an_unreachable_main_socks5_port_is_a_clear_refusal_of_the_proxy_not_of_the_switch(fb: Any) -> None:
    await _ready(fb)
    fb.client.replies["apply"] = AgentReply(4, {"ok": False, "error": (
        f"the new forward did not work (vpn-relay-apply exit 13), rolled back (restored): "
        f"FAIL: TCP connect {MAIN}:{SOCKS_PORT} failed: timed out")})
    report = await fb.service.enable(ADMIN)
    assert report.complete, "the VPN switched all the same"
    [route] = report.proxies
    assert (route.ok, route.via_hub) == (False, False) and f"{MAIN}:{SOCKS_PORT}" in (route.error or "")
    text = report_text(report)
    assert t("fb_route_failed", proxy="SOCKS5", port=SOCKS_PORT, error="").split("(")[0] in text
    assert fb.endpoints.socks5() == ProxyEndpoint(MAIN, SOCKS_PORT), "users keep the address that works"


async def test_check_shows_the_proxy_row_and_tolerates_its_failure(fb: Any) -> None:
    await _ready(fb)
    preflight = await fb.service.preflight(ADMIN)
    [later] = [item for item in preflight.items if item.key.startswith("fb_pf_proxy")]
    assert later.key == "fb_pf_proxy_later" and later.info and preflight.passed
    assert "ℹ️" in preflight_text(preflight)
    await fb.service.enable(ADMIN)
    fb.client.replies["status"] = fb.status_reply(rc=13, tcp=[443, 2096, SOCKS_PORT], lines=[
        f"vpn-relay-apply: ok: TCP connect {MAIN}:443", f"vpn-relay-apply: ok: TCP connect {MAIN}:2096",
        f"vpn-relay-apply: FAIL: TCP connect {MAIN}:{SOCKS_PORT} failed: connection refused",
    ])
    preflight = await fb.service.preflight(ADMIN)
    items = {item.key: item for item in preflight.items}
    assert items["fb_pf_reach"].ok, "a dead danted is not a hub that cannot reach main on 443"
    assert not items["fb_pf_proxy_reach"].ok and items["fb_pf_proxy_reach"].warning
    assert preflight.passed
    text = preflight_text(preflight)
    assert "⚠️ " + t("fb_pf_proxy_reach", proxy="SOCKS5", name="he1", main=MAIN, port=SOCKS_PORT) in text


async def test_a_proxy_port_on_the_hubs_ssh_is_refused_before_the_agent(fb: Any) -> None:
    fb.settings = replace(fb.settings, socks5_port=22)
    fb.service.settings = fb.settings
    fb.endpoints.settings = fb.settings
    await _ready(fb)
    report = await fb.service.enable(ADMIN)
    assert [c["request"] for c in fb.client.calls if c["request"].startswith("apply")] == []
    assert [(r.port, r.ok, r.error) for r in report.proxies] == [(22, False, "ssh")]


def test_check_reaches_tolerates_only_the_proxy_ports() -> None:
    base = [f"ok: TCP connect {MAIN}:443", f"ok: TCP connect {MAIN}:2096"]
    dead_proxy = {"check": {"rc": 13, "lines": [*base, f"FAIL: TCP connect {MAIN}:{SOCKS_PORT} failed: x"]}}
    assert check_reaches(dead_proxy, MAIN, [443, 2096], tolerated=[SOCKS_PORT]) == (True, [])
    assert check_reaches(dead_proxy, MAIN, [443, 2096]) == (False, [])
    dead_vpn = {"check": {"rc": 13, "lines": [f"ok: TCP connect {MAIN}:443", f"FAIL: TCP connect {MAIN}:2096 failed: x"]}}
    assert check_reaches(dead_vpn, MAIN, [443, 2096], tolerated=[SOCKS_PORT]) == (False, [2096])


# ── the broadcast (offered, never sent by itself) ─────────────────────────────


async def test_the_notice_names_the_new_address_and_is_cleared(fb: Any) -> None:
    await _ready(fb)
    await fb.service.enable(ADMIN)
    assert await fb.service.proxy_notice() == ("socks5",)
    text = proxy_notice_text(("socks5",), fb.endpoints)
    assert f"{HUB}:{SOCKS_PORT}" in text and t("fb_proxy_notice_user_tail") in text
    await fb.service.clear_proxy_notice(ADMIN)
    assert await fb.service.proxy_notice() == ()


# ── the broadcast's screens (bot/handlers/admin_fallback.py) ──────────────────


class _Announcements:
    def __init__(self) -> None:
        self.counted: list[Any] = []
        self.sent: list[dict[str, Any]] = []

    async def count_recipients(self, actor: int, *, recipient_filter: Any = None) -> int:
        self.counted.append(recipient_filter)
        return 3

    async def send_to_all(self, **kw: Any) -> Any:
        from services.announcements import AnnouncementResult

        self.sent.append(kw)
        return AnnouncementResult(announcement_id=1, total=3, success=3, failed=0)


class _Bot:
    def __init__(self) -> None:
        self.messages: list[str] = []

    async def send_message(self, chat_id: int, text: str, **_: Any) -> Any:
        from types import SimpleNamespace

        self.messages.append(text)
        return SimpleNamespace(message_id=99)


async def test_the_broadcast_is_offered_counted_and_sent_through_the_announcements(
    fb: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from test_admin_fallback_ui import FakeCallback, _callbacks, _fsm

    from bot.handlers import admin_fallback

    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_fallback, "ensure_private_callback", yes)
    await _ready(fb)
    await fb.service.enable(ADMIN)
    announcements = _Announcements()
    services = SimpleNamespace(fallback=fb.service, users=fb.service.users, totp=None, settings=fb.settings,
                               announcements=announcements)
    screen = FakeCallback("admin:fb")
    await admin_fallback.fallback_panel(screen, _fsm(), services)  # type: ignore[arg-type]
    assert "admin:fb:pxn" in _callbacks(screen.message.edits[-1][1]), "offered after the switch"
    ask = FakeCallback("admin:fb:pxn")
    await admin_fallback.fallback_proxy_notice(ask, services)  # type: ignore[arg-type]
    text, markup = ask.message.edits[-1]
    assert t("fb_proxy_notice_confirm", count=3) in text and f"{HUB}:{SOCKS_PORT}" in text
    assert announcements.counted[-1].protocols == ("socks5",)
    assert _callbacks(markup)[:2] == ["admin:fb:pxn:ok", "admin:fb:pxn:no"]
    assert announcements.sent == [], "nothing sent before the confirmation"
    bot = _Bot()
    send = FakeCallback("admin:fb:pxn:ok")
    await admin_fallback.fallback_proxy_notice_send(send, _fsm(), services, bot)  # type: ignore[arg-type]
    [sent] = announcements.sent
    assert sent["message_id"] == 99 and sent["recipient_filter"].protocols == ("socks5",)
    assert f"{HUB}:{SOCKS_PORT}" in bot.messages[-1]
    assert await fb.service.proxy_notice() == ()
    assert t("fb_proxy_notice_sent", total=3, success=3, failed=0) in send.message.edits[-1][0]
