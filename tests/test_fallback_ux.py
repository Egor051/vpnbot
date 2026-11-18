"""The fallback mode's UX (C) and its automatics (C3).

Driven against the real FallbackService of tests/test_fallback_mode.py and the
screens of bot/handlers/admin_fallback.py (the fakes of tests/test_admin_fallback_ui.py):

* C1 — «⚙️ Настроить фолбэк»: the token (deleted, checked against the zone at once),
  the hub among the relays with an agent outside Russia, the origin offered, the
  failover set filled with explained candidates — all checked, one confirmation — and
  the preflight. Nothing of it is a button of the main screen.
* C2 — the main screen, set up: the switch, «Проверить», «⚙️ Настройки», back — no
  «Обновить»; names, token, the IPv4s, direct host and fallback-url are in «Настройки».
* C4 — «Включить» with an empty set opens the candidates, checked, each with why; the
  «enable with these names» button adds them and the SAME action switches. Every refusal
  names its cause and offers the button that removes it.
* C3 — RU relays cut from main stably (N passes AND M minutes, the hub reachable): one
  suggestion per incident, or — with «Автопереключение» — the switch itself, always
  told; nothing within the cooldown after a switch; never back by itself.
"""

from __future__ import annotations

from typing import Any

import pytest
from test_admin_fallback_ui import FakeCallback, FakeMessage, _callbacks, _fsm, _services
from test_fallback_mode import HUB, MAIN, ORIGIN, ZONE, Fallback, _ready
from test_relay import ADMIN

from bot.fsm.states import AdminFallbackStates
from bot.handlers import admin_fallback
from bot.keyboards.admin_fallback import name_tag
from i18n import t
from models.dto import Relay
from services import fallback as fallback_module
from services.fallback_auto import FallbackAutoSwitch, relay_cut
from services.relay_health import AgentCheck, ProbeResult

pytestmark = pytest.mark.timeout(60)


@pytest.fixture(autouse=True)
def _private_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_fallback, "ensure_private_callback", yes)
    monkeypatch.setattr(admin_fallback, "ensure_private_message", yes)


@pytest.fixture
async def world(tmp_path: Any) -> Any:
    w = await Fallback(tmp_path).start()
    yield w
    await w.close()


# ── C2: the screens ───────────────────────────────────────────────────────────


async def test_not_set_up_the_screen_offers_only_the_setup(world: Fallback) -> None:
    callback = FakeCallback("admin:fb")
    await admin_fallback.fallback_panel(callback, _fsm(), _services(world))  # type: ignore[arg-type]
    text, markup = callback.message.edits[-1]
    assert _callbacks(markup) == ["admin:fb:setup", "admin:relays"]
    assert t("fb_setup_needed") in text and "✅ " + t("fb_setup_item_token") in text
    assert "⚪ " + t("fb_setup_item_hub") in text


async def test_set_up_the_screen_has_four_buttons_and_no_refresh(world: Fallback) -> None:
    await _ready(world)
    callback = FakeCallback("admin:fb")
    await admin_fallback.fallback_panel(callback, _fsm(), _services(world))  # type: ignore[arg-type]
    text, markup = callback.message.edits[-1]
    assert _callbacks(markup) == ["admin:fb:on", "admin:fb:pf", "admin:fb:set", "admin:relays"]
    assert "he1" in text and ZONE in text
    settings = FakeCallback("admin:fb:set")
    await admin_fallback.fallback_settings(settings, _fsm(), _services(world))  # type: ignore[arg-type]
    buttons = _callbacks(settings.message.edits[-1][1])
    for data in ("admin:fb:names", "admin:fb:token", "admin:fb:addr:main", "admin:fb:addr:hub", "admin:fb:direct",
                 "admin:fb:subfb", "admin:fb:auto", "admin:fb"):
        assert data in buttons, data


# ── C4: «Включить» with an empty set ──────────────────────────────────────────


async def test_enable_with_an_empty_set_opens_the_checked_candidates_then_switches(world: Fallback) -> None:
    hub = await world.hub()
    world.cf.add(ZONE, MAIN)
    await world.relay("ru1", target=ZONE, ssh="198.51.100.7", source="198.51.100.7/32")
    services = _services(world)
    state = _fsm()
    on = FakeCallback("admin:fb:on")
    await admin_fallback.fallback_confirm(on, services, state)  # type: ignore[arg-type]
    text, markup = on.message.edits[-1]
    assert f"☑️ <code>{ZONE}</code>" in text, "the candidate is checked"
    assert t("fb_cand_why_sni") in text and t("fb_cand_why_relay", relays="ru1") in text, "each with why"
    assert f"admin:fb:cand:o:{name_tag(ZONE)}" in _callbacks(markup)
    assert "admin:fb:on:names" in _callbacks(markup)
    assert await world.repo.list_names() == [], "nothing was added before the confirmation"

    go = FakeCallback("admin:fb:on:names")
    await admin_fallback.fallback_on_with_names(go, state, services)  # type: ignore[arg-type]
    assert [n.name for n in await world.repo.list_names()] == [ZONE]
    overview = await world.service.overview(ADMIN)
    assert overview.mode_on and overview.state == "on", "the SAME action switched"
    final = go.message.edits[-1][0]
    assert "✅ " + t("fb_step_dns") in final and HUB in final
    assert hub.is_hub


async def test_unchecking_every_candidate_is_refused_with_a_reason(world: Fallback) -> None:
    await world.hub()
    services = _services(world)
    state = _fsm()
    toggle = FakeCallback(f"admin:fb:cand:o:{name_tag(ZONE)}")
    await admin_fallback.fallback_candidate_toggle(toggle, state, services)  # type: ignore[arg-type]
    assert f"⬜ <code>{ZONE}</code>" in toggle.message.edits[-1][0]
    go = FakeCallback("admin:fb:on:names")
    await admin_fallback.fallback_on_with_names(go, state, services)  # type: ignore[arg-type]
    assert go.alerts[-1] == (t("fb_cand_nothing_checked"), True)
    assert not (await world.service.overview(ADMIN)).mode_on


async def test_a_refused_switch_names_the_cause_and_the_button_that_fixes_it(world: Fallback) -> None:
    await _ready(world)
    world.cf.token_status = "disabled"
    run = FakeCallback("admin:fb:on:ok")
    await admin_fallback.fallback_switch(run, _fsm(), _services(world))  # type: ignore[arg-type]
    text, markup = run.message.edits[-1]
    assert "❌" in text and "❌ " + t("fb_step_preflight") in text
    assert "admin:fb:tok:set" in _callbacks(markup), "the token's fix"
    assert not (await world.service.overview(ADMIN)).mode_on


async def test_enable_before_the_setup_offers_the_setup(world: Fallback) -> None:
    on = FakeCallback("admin:fb:on")
    await admin_fallback.fallback_confirm(on, _services(world), _fsm())  # type: ignore[arg-type]
    text, markup = on.message.edits[-1]
    assert text == t("fb_on_not_configured") and "admin:fb:setup" in _callbacks(markup)


async def test_the_confirmation_is_the_plan_with_every_step_waiting(world: Fallback) -> None:
    await _ready(world)
    on = FakeCallback("admin:fb:on")
    await admin_fallback.fallback_confirm(on, _services(world), _fsm())  # type: ignore[arg-type]
    text, markup = on.message.edits[-1]
    assert text.count("⚪") == 4 and _callbacks(markup)[0] == "admin:fb:on:ok"


# ── C1: the setup ─────────────────────────────────────────────────────────────


async def test_the_setup_walks_token_hub_origin_names_preflight(world: Fallback, monkeypatch: pytest.MonkeyPatch) -> None:
    services = _services(world)
    world.token_file.delete()
    he1 = await world.relay("he1", ssh=HUB)
    await world.relay("ru1", target=ZONE, ssh="198.51.100.7", source="198.51.100.7/32")
    monkeypatch.setattr(fallback_module, "lookup_country", lambda ip: "RU" if ip == "198.51.100.7" else "DE")
    state = _fsm()

    start = FakeCallback("admin:fb:setup")
    await admin_fallback.fallback_setup(start, state, services)  # type: ignore[arg-type]
    assert await state.get_state() == AdminFallbackStates.token.state
    assert t("fb_setup_step", step=1, total=5) in start.message.answers[-1][0]

    typed = FakeMessage("a" * 40)
    from test_fallback_mode import TOKEN

    typed.text = TOKEN
    await admin_fallback.fallback_token_input(typed, state, services)  # type: ignore[arg-type]
    assert typed.deleted and TOKEN not in typed.everything()
    step2, markup = typed.answers[-1]
    assert t("fb_token_zone_ok", zone=f"<code>{ZONE}</code>") in step2
    assert t("fb_setup_step", step=2, total=5) in step2
    assert _callbacks(markup)[0] == f"admin:fb:setup:hub:{he1.id}", "outside Russia only"
    assert "ru1" not in str(_callbacks(markup)) and "DE" in step2

    pick = FakeCallback(f"admin:fb:setup:hub:{he1.id}")
    await admin_fallback.fallback_setup_hub(pick, state, services)  # type: ignore[arg-type]
    assert ORIGIN in pick.message.edits[-1][0] and f"admin:fb:setup:origin:{he1.id}" in _callbacks(pick.message.edits[-1][1])

    origin = FakeCallback(f"admin:fb:setup:origin:{he1.id}")
    await admin_fallback.fallback_setup_origin(origin, state, services)  # type: ignore[arg-type]
    assert (await world.relays_repo.get_by_id(he1.id)).is_hub  # type: ignore[union-attr]
    step4 = origin.message.edits[-1][0]
    assert t("fb_setup_step", step=4, total=5) in step4 and f"☑️ <code>{ZONE}</code>" in step4

    world.cf.add(ZONE, MAIN)
    names = FakeCallback("admin:fb:setup:names:ok")
    await admin_fallback.fallback_setup_names(names, state, services)  # type: ignore[arg-type]
    assert [n.name for n in await world.repo.list_names()] == [ZONE]
    assert t("fb_setup_step", step=5, total=5) in names.message.edits[-1][0]
    assert await world.service.configured()


async def test_a_token_that_does_not_see_the_zone_says_so(world: Fallback) -> None:
    await world.hub()
    with pytest.raises(Exception) as caught:
        await world.service.check_zone(ADMIN, "other.example.org")
    assert getattr(caught.value, "key", "") == "fb_err_token_zone"
    assert await world.service.check_zone(ADMIN) == ZONE


# ── C3: the automatics ────────────────────────────────────────────────────────


def _probe(*, tcp: bool = True, rc: int | None = None, error: str | None = None) -> ProbeResult:
    agent = None
    if rc is not None or error is not None:
        agent = AgentCheck(ok=False, rc=rc, error_key=error)
    return ProbeResult(ok=tcp and agent is None, checked_at="x", host="h", tcp=tcp, agent=agent)


def test_what_counts_as_cut() -> None:
    assert relay_cut(_probe(rc=13)) and relay_cut(_probe(rc=14))
    assert relay_cut(_probe(tcp=False, error="relay_ssh_failed"))
    assert not relay_cut(_probe(rc=11)), "a broken table is not the TSPU"
    assert not relay_cut(_probe(tcp=False)), "a relay without an agent proves nothing"
    assert not relay_cut(None) and not relay_cut(_probe())


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


async def _auto(world: Fallback, *, auto: bool) -> tuple[FallbackAutoSwitch, list[tuple[str, Any]], _Clock, list[Relay]]:
    hub = await _ready(world)
    ru1 = next(r for r in await world.relays_repo.list_all() if r.name == "ru1")
    if auto:
        await world.service.set_auto_switch(ADMIN, True)
    told: list[tuple[str, Any]] = []

    async def notify(text: str, markup: Any) -> None:
        told.append((text, markup))

    clock = _Clock()
    return FallbackAutoSwitch(world.service, notify=notify, clock=clock, passes=3, min_seconds=600,
                              cooldown_seconds=3600), told, clock, [hub, ru1]


async def _passes(sw: FallbackAutoSwitch, relays: list[Relay], clock: _Clock, n: int, *, cut: bool = True,
                  step: float = 300.0) -> None:
    hub, ru1 = relays
    for _ in range(n):
        await sw.observe(relays, {hub.id: _probe(), ru1.id: _probe(rc=13) if cut else _probe()})
        clock.now += step


async def test_a_stable_cut_is_suggested_once_with_one_button(world: Fallback) -> None:
    sw, told, clock, relays = await _auto(world, auto=False)
    await _passes(sw, relays, clock, 2)
    assert told == [], "two passes are not stable"
    await _passes(sw, relays, clock, 4)
    assert len(told) == 1, "one message per incident"
    text, markup = told[0]
    assert "ru1" in text and _callbacks(markup) == ["admin:fb:on"]
    assert not (await world.service.overview(ADMIN)).mode_on, "a suggestion switches nothing"


async def test_hysteresis_needs_both_the_passes_and_the_minutes(world: Fallback) -> None:
    sw, told, clock, relays = await _auto(world, auto=False)
    await _passes(sw, relays, clock, 5, step=60.0)          # 5 passes, 4 minutes
    assert told == []
    await _passes(sw, relays, clock, 1, cut=False)           # one good pass: the incident ends
    await _passes(sw, relays, clock, 2, step=600.0)          # 2 passes, 10 minutes: not 3 passes
    assert told == []


async def test_with_the_auto_switch_it_switches_and_always_tells(world: Fallback) -> None:
    sw, told, clock, relays = await _auto(world, auto=True)
    await _passes(sw, relays, clock, 3)
    overview = await world.service.overview(ADMIN)
    assert overview.mode_on and overview.state == "on"
    assert len(told) == 1 and "ru1" in told[0][0]
    # Back to normal only by hand: passes on, cut or not, change nothing.
    await _passes(sw, relays, clock, 5, cut=False)
    assert (await world.service.overview(ADMIN)).mode_on


async def test_no_automatic_switch_within_the_cooldown_after_a_switch(world: Fallback) -> None:
    sw, told, clock, relays = await _auto(world, auto=True)
    await _passes(sw, relays, clock, 1, cut=False)
    await world.service.enable(ADMIN)
    await _passes(sw, relays, clock, 1, cut=False)
    await world.service.disable(ADMIN)                       # by hand, a moment ago
    await _passes(sw, relays, clock, 6, step=300.0)          # 30 min of cut passes: within the hour
    assert told == [] and not (await world.service.overview(ADMIN)).mode_on


async def test_a_hub_main_cannot_reach_is_no_reason_to_switch(world: Fallback) -> None:
    sw, told, clock, relays = await _auto(world, auto=True)
    hub, ru1 = relays
    for _ in range(6):
        await sw.observe(relays, {hub.id: _probe(tcp=False), ru1.id: _probe(rc=13)})
        clock.now += 300
    assert told == [] and not (await world.service.overview(ADMIN)).mode_on


async def test_the_automatic_preflight_asks_the_hub_as_the_bot_itself(world: Fallback) -> None:
    await _ready(world)
    report = await world.service._switch("failover", None)
    assert report.started and report.complete
    assert "fb_pf_agent_failed" not in [i.key for i in report.preflight.items]  # type: ignore[union-attr]
