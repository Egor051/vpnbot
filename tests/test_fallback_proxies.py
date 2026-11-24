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

import ipaddress
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_fallback_mode import HUB, MAIN, ORIGIN, Fallback, _ready
from test_relay import ADMIN

from bot.fallback import preflight_text, proxy_notice_text, proxy_reconcile_text, report_text
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


# ── the reconcile: the mode's proxies whenever the bot looks, not only at the switch ──
#
# Prod: the mode was switched on (2026-11-18, hub he2) BEFORE the version that forwards the
# proxies was installed — the switch never ran with it, the hub never got SOCKS5_PORT, and
# «Прокси» kept handing out main's banned address. The reconcile brings it there.


async def _mode_on_without_the_proxy(fb: Any) -> Any:
    """The mode on in the database, the hub forwarding only the VPN ports (no switch ran
    with the proxy code) — prod's state after the update."""
    hub = await _ready(fb)
    await fb.repo.set_mode(True, now="2026-11-18T10:00:00+00:00")
    await fb.service.refresh_state()
    assert hub.agent is not None and set(hub.agent.tcp_ports) == {443, 2096} and SOCKS_PORT not in hub.agent.tcp_ports
    assert fb.endpoints.socks5() == ProxyEndpoint(MAIN, SOCKS_PORT), "the bug: main's address in the mode"
    return hub


def _applies(fb: Any) -> list[str]:
    return [c["request"] for c in fb.client.calls if c["request"].startswith("apply")]


async def test_a_mode_switched_on_before_the_update_gets_the_proxy_on_the_hub_at_startup(fb: Any) -> None:
    await _mode_on_without_the_proxy(fb)
    result = await fb.service.reconcile_in_background()  # bot/app.py, right after refresh_state()
    assert _applies(fb) == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"], "443/2096 sent as they are"
    assert [(r.kind, r.port, r.ok, r.via_hub) for r in result.routes] == [("socks5", SOCKS_PORT, True, True)]
    endpoint = fb.endpoints.socks5()
    assert endpoint == ProxyEndpoint(HUB, SOCKS_PORT, via_hub=True)
    assert str(ipaddress.IPv4Address(endpoint.host)) == HUB, "the hub's IPv4, not a name"
    overview = await fb.service.overview(ADMIN)
    assert overview.proxy_notice == ("socks5",), "«📣 Разослать» offered — the address moved"
    assert overview.proxies_direct == ()
    fb.client.calls.clear()
    again = await fb.service.reconcile_proxies()
    assert _applies(fb) == [] and not again.applied and again.settled, "reconciled: nothing more to send"


def test_the_bot_reconciles_right_after_the_startup_refresh() -> None:
    text = (Path(__file__).resolve().parents[1] / "bot" / "app.py").read_text(encoding="utf-8")
    refresh = text.index("await fallback_service.refresh_state()")
    reconcile = text.index("fallback_service.reconcile_in_background()")
    assert refresh < reconcile < text.index("relay_health_supervisor.behind_hub = fallback_service.behind_hub")
    assert "fallback_service.proxy_alert = " in text


async def test_a_failed_apply_is_not_repeated_before_the_backoff_and_is_told_once(fb: Any) -> None:
    from bot.fallback import proxy_alert_text
    from services.fallback import RECONCILE_BACKOFF_SECONDS

    await _mode_on_without_the_proxy(fb)
    error = (f"the new forward did not work (vpn-relay-apply exit 13), rolled back (restored): "
             f"FAIL: TCP connect {MAIN}:{SOCKS_PORT} failed: timed out")
    fb.client.replies["apply"] = AgentReply(4, {"ok": False, "error": error})
    alerts: list[Any] = []

    async def alert(item: Any) -> None:
        alerts.append(item)

    fb.service.proxy_alert = alert
    first = await fb.service.reconcile_proxies()
    [route] = first.routes
    assert (route.ok, route.via_hub) == (False, False) and f"{MAIN}:{SOCKS_PORT}" in (route.error or "")
    assert fb.endpoints.socks5() == ProxyEndpoint(MAIN, SOCKS_PORT), "users keep the address that works"
    assert len(_applies(fb)) == 1 and len(alerts) == 1
    [told] = alerts
    assert told.mode_on and told.hub == "he1" and told.route.port == SOCKS_PORT and told.main == MAIN
    text = proxy_alert_text(told)
    assert f"{MAIN}:{SOCKS_PORT}" in text and "SOCKS5:31337" in text and t("btn_fb_proxy_reconcile") in text
    assert "модул" not in text.lower(), "never: switch the SOCKS5 module off and on (that deletes every access)"
    # every pass of the health loop within the hour: not sent again, not told again
    for _ in range(5):
        fb.clock_value[0] += 60
        later = await fb.service.reconcile_proxies()
        assert not later.applied and [(r.port, r.error) for r in later.deferred] == [(SOCKS_PORT, error[:300])]
    fb.clock_value[0] += RECONCILE_BACKOFF_SECONDS - 300 - 1
    await fb.service.reconcile_proxies()
    assert len(_applies(fb)) == 1, "not before the backoff"
    fb.clock_value[0] += 1
    await fb.service.reconcile_proxies()
    assert len(_applies(fb)) == 2 and len(alerts) == 1, "tried again after the hour; the same error is not news"
    # «🔁 Довести прокси до hub» does not wait for the backoff
    await fb.service.reconcile_proxies(ADMIN, force=True)
    assert len(_applies(fb)) == 3 and len(alerts) == 1
    assert all(a.startswith(f"apply target={ORIGIN} tcp=443,2096,") and a.endswith(" udp=443") for a in _applies(fb))
    # main's danted is back: on the hub, and a later failure is a new incident again
    fb.client.replies["apply"] = AgentReply(0, {"ok": True, "live_target": MAIN, "resolved": [MAIN]})
    fixed = await fb.service.reconcile_proxies(ADMIN, force=True)
    assert fixed.settled and fb.endpoints.socks5().via_hub
    assert fb.service.proxy_failure(SOCKS_PORT) is None


async def test_only_the_port_the_agent_could_not_reach_waits_the_other_proxy_goes_next_pass(fb: Any) -> None:
    fb.settings = replace(fb.settings, mtproto_enabled=True, mtproto_host=MAIN, mtproto_port=8443)
    fb.service.settings = fb.settings
    fb.endpoints.settings = fb.settings
    await _mode_on_without_the_proxy(fb)
    dead = AgentReply(4, {"ok": False, "error": f"rolled back: FAIL: TCP connect {MAIN}:{SOCKS_PORT} failed: refused"})
    ok = AgentReply(0, {"ok": True, "live_target": MAIN, "resolved": [MAIN]})
    call = fb.client.call

    async def danted_down(host: str, port: int, request: str, **kw: Any) -> AgentReply:
        fb.client.replies["apply"] = dead if f",{SOCKS_PORT}" in request else ok
        return await call(host, port, request, **kw)

    fb.client.call = danted_down
    first = await fb.service.reconcile_proxies()
    assert {(r.port, r.ok) for r in first.routes} == {(8443, False), (SOCKS_PORT, False)}
    assert fb.service.proxy_failure(SOCKS_PORT) and fb.service.proxy_failure(8443) is None
    second = await fb.service.reconcile_proxies()
    assert _applies(fb)[-1] == f"apply target={ORIGIN} tcp=443,2096,8443 udp=443", "MTProto without the dead port"
    assert [(r.port, r.ok) for r in second.routes] == [(8443, True)] and [r.port for r in second.deferred] == [SOCKS_PORT]
    assert fb.endpoints.mtproto().via_hub and not fb.endpoints.socks5().via_hub


async def test_an_alert_raised_before_the_bot_is_up_is_delivered_later_once(fb: Any) -> None:
    await _mode_on_without_the_proxy(fb)
    fb.client.replies["apply"] = AgentReply(4, {"ok": False, "error": f"FAIL: TCP connect {MAIN}:{SOCKS_PORT} failed"})
    assert fb.service.proxy_alert is None  # the startup reconcile runs before the bot exists
    await fb.service.reconcile_proxies()
    alerts: list[Any] = []

    async def alert(item: Any) -> None:
        alerts.append(item)

    fb.service.proxy_alert = alert
    await fb.service.reconcile_proxies()  # the next health pass: within the backoff
    await fb.service.reconcile_proxies()
    assert len(_applies(fb)) == 1 and len(alerts) == 1


async def test_a_transient_refusal_is_neither_backed_off_nor_told(fb: Any) -> None:
    await _mode_on_without_the_proxy(fb)
    alerts: list[Any] = []

    async def alert(item: Any) -> None:
        alerts.append(item)

    fb.service.proxy_alert = alert
    hub = (await fb.service.overview(ADMIN)).hub
    fb.relay_service._busy.add(hub.id)  # another long call on the hub right now
    busy = await fb.service.reconcile_proxies()
    assert [r.ok for r in busy.routes] == [False] and alerts == []
    fb.relay_service._busy.discard(hub.id)
    done = await fb.service.reconcile_proxies()
    assert done.settled and fb.endpoints.socks5().via_hub, "the next pass, no backoff"


async def test_the_mode_off_takes_a_left_over_proxy_port_off_and_keeps_every_other_port(fb: Any) -> None:
    hub = await _ready(fb)
    assert hub.agent is not None
    # The mode off, yet the hub still forwards SOCKS5_PORT (a switch-off whose proxy step
    # failed, an older version) — and one more port nobody here owns.
    await fb.relays_repo.update_agent_forward(
        hub.id, target_host=ORIGIN, tcp_ports=(443, 2096, 8080, SOCKS_PORT), udp_ports=(443,),
    )
    fb.client.replies["status"] = fb.status_reply(tcp=[443, 2096, 8080, SOCKS_PORT])  # the live hub agrees
    await fb.service.refresh_state()
    result = await fb.service.reconcile_proxies()
    assert _applies(fb) == [f"apply target={ORIGIN} tcp=443,2096,8080 udp=443"], "only the proxy port goes"
    assert [(r.kind, r.port, r.ok, r.via_hub) for r in result.routes] == [("socks5", SOCKS_PORT, True, False)]
    assert fb.endpoints.socks5() == ProxyEndpoint(MAIN, SOCKS_PORT)
    fb.client.calls.clear()
    assert not (await fb.service.reconcile_proxies()).applied and _applies(fb) == []


async def test_the_reconcile_never_sends_a_set_without_the_vpn_ports(fb: Any) -> None:
    hub = await _ready(fb)
    await fb.repo.set_mode(True, now="2026-11-18T10:00:00+00:00")
    await fb.relays_repo.update_agent_forward(hub.id, target_host=ORIGIN, tcp_ports=(443,), udp_ports=(443,))
    await fb.service.refresh_state()
    result = await fb.service.reconcile_proxies(ADMIN, force=True)
    assert not result.applied and _applies(fb) == [], "a hub without 2096 is the preflight's, not the reconcile's"
    assert result.skipped == "vpn_gap" and not result.settled
    text = proxy_reconcile_text(result)
    assert t("fb_proxy_reconcile_vpn_gap", name="he1", have="443", missing="2096") == text
    assert text != t("fb_proxy_reconcile_nothing"), "the button never says «nothing to change» then"


async def test_the_reconcile_does_not_stand_behind_a_running_switch(fb: Any) -> None:
    await _mode_on_without_the_proxy(fb)
    async with fb.service._lock:  # a switch (DNS, DoH) is running
        result = await fb.service.reconcile_proxies(wait=False)
    assert not result.applied and _applies(fb) == [] and result.skipped == "busy"


async def test_the_health_loop_reconciles_on_every_pass_without_waiting_for_the_agent(fb: Any) -> None:
    import asyncio

    from services.fallback_auto import FallbackAutoSwitch

    await _mode_on_without_the_proxy(fb)
    auto = FallbackAutoSwitch(fb.service, clock=lambda: 0.0)
    release = asyncio.Event()
    call = fb.client.call

    async def slow_hub(host: str, port: int, request: str, **kw: Any) -> AgentReply:
        if request.startswith("apply"):
            await release.wait()  # the agent's apply takes minutes (its timeout is 300 s)
        return await call(host, port, request, **kw)

    fb.client.call = slow_hub
    await asyncio.wait_for(auto.observe([], {}), timeout=1.0)  # the pass's switch decision does not wait
    task = fb.service._reconcile_task
    assert task is not None and not task.done()
    await auto.observe([], {})
    assert fb.service._reconcile_task is task, "one reconcile at a time"
    release.set()
    await task
    assert _applies(fb) == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
    assert fb.endpoints.socks5().via_hub
    await auto.observe([], {})
    await fb.service._reconcile_task
    assert len(_applies(fb)) == 1


async def test_a_forward_changed_on_the_hub_by_hand_is_not_overwritten(fb: Any) -> None:
    await _mode_on_without_the_proxy(fb)
    alerts: list[Any] = []

    async def alert(item: Any) -> None:
        alerts.append(item)

    fb.service.proxy_alert = alert
    # The live hub forwards one more port than the bot's copy says (an edit on the relay).
    fb.client.replies["status"] = fb.status_reply(tcp=[443, 2096, 9000])
    result = await fb.service.reconcile_proxies()
    assert _applies(fb) == [], "the live forward is not the bot's copy: nothing is overwritten"
    [route] = result.routes
    assert not route.ok and "not the bot's copy" in (route.error or "") and "9000" in (route.error or "")
    assert len(alerts) == 1 and fb.endpoints.socks5().via_hub is False
    # The live hub already forwards what the mode wants: the apply only syncs the copy.
    fb.client.replies["status"] = fb.status_reply(tcp=[443, 2096, SOCKS_PORT])
    synced = await fb.service.reconcile_proxies(ADMIN, force=True)
    assert synced.settled and _applies(fb) == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
    # Another upstream on the hub: not overwritten either.
    await fb.relays_repo.update_agent_forward(
        (await fb.service.overview(ADMIN)).hub.id, target_host=ORIGIN, tcp_ports=(443, 2096), udp_ports=(443,),
    )
    await fb.service.refresh_state()
    fb.client.replies["status"] = fb.status_reply(target="relay.example.net")
    moved = await fb.service.reconcile_proxies(ADMIN, force=True)
    assert len(_applies(fb)) == 1 and "relay.example.net" in (moved.routes[0].error or "")


async def test_the_screen_reconciles_when_it_opens(fb: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from test_admin_fallback_ui import FakeCallback, _fsm

    from bot.handlers import admin_fallback

    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_fallback, "ensure_private_callback", yes)
    await _mode_on_without_the_proxy(fb)
    services = SimpleNamespace(fallback=fb.service, users=fb.service.users, totp=None, settings=fb.settings)
    screen = FakeCallback("admin:fb")
    await admin_fallback.fallback_panel(screen, _fsm(), services)  # type: ignore[arg-type]
    assert _applies(fb) == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
    assert t("fb_proxy_via_hub", proxy="SOCKS5", address=f"<code>{HUB}:{SOCKS_PORT}</code>") in screen.message.edits[-1][0]


async def test_check_says_the_hub_does_not_forward_the_proxy_and_the_button_fixes_it(
    fb: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from test_admin_fallback_ui import FakeCallback, _callbacks, _fsm

    from bot.handlers import admin_fallback

    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_fallback, "ensure_private_callback", yes)
    await _mode_on_without_the_proxy(fb)
    services = SimpleNamespace(fallback=fb.service, users=fb.service.users, totp=None, settings=fb.settings)
    check = FakeCallback("admin:fb:pf")
    await admin_fallback.fallback_preflight(check, services)  # type: ignore[arg-type]
    text, markup = check.message.edits[-1]
    assert "⚠️ " + t("fb_pf_proxy_not_forwarded", name="he1", proxy="SOCKS5", port=SOCKS_PORT, main=MAIN) in text
    assert "admin:fb:pxr" in _callbacks(markup)
    assert t("btn_fb_proxy_reconcile") in [b.text for row in markup.inline_keyboard for b in row]
    assert _applies(fb) == [], "«Проверить» changes nothing"
    overview = await fb.service.overview(ADMIN)
    assert overview.proxies_direct == ("socks5",)
    assert "admin:fb:pxr" in _callbacks(admin_fallback.fallback_keyboard(overview)), "on the main screen too"
    fix = FakeCallback("admin:fb:pxr")
    await admin_fallback.fallback_proxy_reconcile(fix, _fsm(), services)  # type: ignore[arg-type]
    assert _applies(fb) == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
    shown, after = fix.message.edits[-1]
    assert t("fb_route_on", proxy="SOCKS5", port=SOCKS_PORT) in shown
    assert "admin:fb:pxr" not in _callbacks(after) and "admin:fb:pxn" in _callbacks(after)
    # The hub forwards it now (its live status says so): «Проверить» shows the proxy's reach.
    fb.client.replies["status"] = fb.status_reply(tcp=[443, 2096, SOCKS_PORT], lines=[
        f"vpn-relay-apply: ok: TCP connect {MAIN}:443", f"vpn-relay-apply: ok: TCP connect {MAIN}:2096",
        f"vpn-relay-apply: ok: TCP connect {MAIN}:{SOCKS_PORT}", "vpn-relay-apply: check OK",
    ])
    again = FakeCallback("admin:fb:pf")
    await admin_fallback.fallback_preflight(again, services)  # type: ignore[arg-type]
    text, markup = again.message.edits[-1]
    assert "✅ " + t("fb_pf_proxy_reach", proxy="SOCKS5", name="he1", main=MAIN, port=SOCKS_PORT) in text
    assert "admin:fb:pxr" not in _callbacks(markup)


async def test_the_reconcile_button_is_behind_totp() -> None:
    from bot.totp_gate import DANGEROUS_ACTIONS

    assert "fallback_proxy_reconcile" in DANGEROUS_ACTIONS
    root = Path(__file__).resolve().parents[1]
    handler = (root / "bot" / "handlers" / "admin_fallback.py").read_text(encoding="utf-8")
    assert 'require_totp(callback, state, services, action="fallback_proxy_reconcile")' in handler


# ── the SOCKS5 card: a link to tap, not a «Telegram key»; MTProto off — nothing of it ──


def test_the_socks5_card_has_a_link_to_tap_not_a_telegram_value() -> None:
    link = f"https://t.me/socks?server={HUB}&port={SOCKS_PORT}&user=u_1&pass=p%26w"
    text = socks5_proxy_text({"host": HUB, "port": SOCKS_PORT, "login": "u_1", "password": "p&w",
                              "url": f"socks5://u_1:p%26w@{HUB}:{SOCKS_PORT}", "tg_link": link})
    href = link.replace("&", "&amp;")
    assert f'<a href="{href}">{t("socks5_tg_link")}</a>' in text
    assert "Telegram:" not in text, "no «Telegram:» value to be taken for a key"
    assert f"<code>{href}</code>" not in text and f"<code>{link}</code>" not in text
    assert "t.me/proxy" not in text and "MTProto" not in text
    from i18n import use_locale

    with use_locale("en"):
        assert f'>{t("socks5_tg_link")}</a>' in socks5_proxy_text({"host": HUB, "port": SOCKS_PORT, "tg_link": link})
        assert t("socks5_tg_link") == "➕ Add the proxy to Telegram"
    assert "<a " not in socks5_proxy_text({"host": HUB, "port": SOCKS_PORT, "tg_link": "javascript:alert(1)"})


async def test_mtproto_off_shows_nothing_of_it_in_proxy_or_the_broadcast(fb: Any, tmp_path: Path) -> None:
    from types import SimpleNamespace

    from test_relay import _settings

    from bot.handlers.proxy import _proxy_menu_view

    assert fb.settings.mtproto_enabled is False
    socks = fb.endpoints.current(_access(ProxyAccessType.SOCKS5, {
        "host": MAIN, "port": SOCKS_PORT, "login": "u_1", "password": "pw",
        "url": f"socks5://u_1:pw@{MAIN}:{SOCKS_PORT}", "tg_link": f"https://t.me/socks?server={MAIN}"}))
    stale_mt = fb.endpoints.current(replace(_access(ProxyAccessType.MTPROTO, {
        "host": MAIN, "port": 8443, "secret": "ab" * 16}), id=2))

    class _Proxy:
        async def list_user_accesses(self, user_id: int) -> list[ProxyAccess]:
            return [socks, stale_mt]  # an MTProto access left ACTIVE from before MTProto was switched off

    settings = _settings(tmp_path, socks5_enabled=True, socks5_host=MAIN, socks5_port=SOCKS_PORT, mtproto_enabled=False)
    services = SimpleNamespace(proxy=_Proxy(), settings=settings, modules=Modules())
    text, markup = await _proxy_menu_view(services, 7)  # type: ignore[arg-type]
    assert "SOCKS5" in text and t("socks5_tg_link") in text
    assert "MTProto" not in text and "t.me/proxy" not in text
    assert "proxy:get:mtproto" not in [b.callback_data for row in markup.inline_keyboard for b in row]
    # the broadcast: a stored notice naming MTProto is not offered while MTProto is off
    await _ready(fb)
    await fb.repo.set_setting("fallback_proxy_notice", "mtproto,socks5")
    assert await fb.service.proxy_notice() == ("socks5",)
    notice = proxy_notice_text(await fb.service.proxy_notice(), fb.endpoints)
    assert "MTProto" not in notice and "t.me/proxy" not in notice


async def test_the_screen_does_not_wait_for_a_slow_agent(fb: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio
    from types import SimpleNamespace

    from test_admin_fallback_ui import FakeCallback, _fsm

    from bot.handlers import admin_fallback

    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_fallback, "ensure_private_callback", yes)
    monkeypatch.setattr(admin_fallback, "_SCREEN_RECONCILE_WAIT", 0.05)
    await _mode_on_without_the_proxy(fb)
    release = asyncio.Event()
    call = fb.client.call

    async def slow_hub(host: str, port: int, request: str, **kw: Any) -> AgentReply:
        if request.startswith("apply"):
            await release.wait()
        return await call(host, port, request, **kw)

    fb.client.call = slow_hub
    services = SimpleNamespace(fallback=fb.service, users=fb.service.users, totp=None, settings=fb.settings)
    screen = FakeCallback("admin:fb")
    await asyncio.wait_for(admin_fallback.fallback_panel(screen, _fsm(), services), timeout=2.0)  # type: ignore[arg-type]
    assert t("fb_proxy_direct", proxy="SOCKS5", address=f"<code>{MAIN}:{SOCKS_PORT}</code>") in screen.message.edits[-1][0]
    release.set()
    await fb.service._reconcile_task
    assert fb.endpoints.socks5().via_hub, "the reconcile went on after the screen was drawn"


async def test_a_switch_does_not_wait_behind_a_slow_reconcile_and_a_stale_plan_is_redone(fb: Any) -> None:
    import asyncio

    hub = await _ready(fb)
    # The mode off with SOCKS5_PORT left on the hub: the reconcile takes it off — slowly.
    await fb.relays_repo.update_agent_forward(
        hub.id, target_host=ORIGIN, tcp_ports=(443, 2096, SOCKS_PORT), udp_ports=(443,),
    )
    fb.client.replies["status"] = fb.status_reply(tcp=[443, 2096, SOCKS_PORT])
    await fb.service.refresh_state()
    started, release = asyncio.Event(), asyncio.Event()
    call = fb.client.call

    async def slow_hub(host: str, port: int, request: str, **kw: Any) -> AgentReply:
        if request.startswith("apply") and not release.is_set():
            started.set()
            await release.wait()  # the agent's apply takes minutes (its timeout is 300 s)
        return await call(host, port, request, **kw)

    fb.client.call = slow_hub
    task = fb.service.reconcile_in_background()
    await asyncio.wait_for(started.wait(), timeout=2.0)
    assert not fb.service._lock.locked(), "the agent call is made without the switch's lock"
    report = await asyncio.wait_for(fb.service.enable(ADMIN), timeout=5.0)  # the switch goes at once
    assert report.complete and fb.service.mode_on
    release.set()
    result = await task
    # The removal planned for the mode off went out; the mode is on now: planned again at once.
    assert _applies(fb)[-2:] == [f"apply target={ORIGIN} tcp=443,2096 udp=443",
                                 f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
    assert result.mode_on and result.settled and fb.endpoints.socks5().via_hub


async def test_a_hub_that_does_not_answer_its_status_is_asked_again_next_pass(fb: Any) -> None:
    from services.relay_ssh import RelaySshError

    await _mode_on_without_the_proxy(fb)
    alerts: list[Any] = []

    async def alert(item: Any) -> None:
        alerts.append(item)

    fb.service.proxy_alert = alert
    status = fb.relay_service.system_status

    async def timed_out(relay_id: int) -> Any:
        raise RelaySshError("relay не ответил вовремя", key="relay_ssh_timeout")

    fb.relay_service.system_status = timed_out
    blip = await fb.service.reconcile_proxies()
    assert _applies(fb) == [] and [r.ok for r in blip.routes] == [False]
    assert fb.service.proxy_failure(SOCKS_PORT) is None and alerts == [], "nothing was sent: no backoff, no alert"
    fb.relay_service.system_status = status
    back = await fb.service.reconcile_proxies()  # the next pass, well within the hour
    assert back.settled and _applies(fb) == [f"apply target={ORIGIN} tcp=443,2096,{SOCKS_PORT} udp=443"]
