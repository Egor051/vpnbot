"""«Довести relay до нормы»: a relay the bot added leaves SSH 22 and gets its input filter.

scripts/install.sh relay_write_env writes a NEW relay SSH_PORT=<the port sshd has> and
RELAY_INPUT_FILTER=off (so the first deploy cannot cut the bot off) and nothing moved
them on: he2, the hub, ran SSH on 22 with no filter. Pinned here:

* what is left, read from the agent's status (``hardening_of``);
* ONE bold alert per pairing — after the pairing's hello and from a kept status /
  the card — with «Довести» / «Позже»; «Позже» remembered;
* «Довести» (RelayService.harden): the filter first — ``input-filter on``, the bot's
  NEW-session ``input-confirm``, ``input-filter on`` again to commit — then SSH:
  ``ssh-port-set port=54321`` and the finish ON 54321; each step rolled back when it
  fails (``input-filter off`` / ``ssh-port-set port=22``), the step before it kept;
* an agent older than the requests: «сначала обновите агент», nothing sent;
* the screens: the alert's plan (⚪) and run (progress), the card's warning line and
  button, the wizard's «🔑 SSH-порт relay» and «🛡 Входной фильтр relay».
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_relay import ADMIN
from test_relay_agents import TARGET, _hello
from test_relay_unified import RU1_IP, Callback, Env, FakeTotp, _services, fsm

from bot.fsm.states import TotpStates
from bot.handlers import admin_relays as relay_ui
from bot.handlers import relay_hardening as ui
from bot.handlers import ssh_port as sshp
from bot.wizard_views import menu_keyboard
from i18n import t
from services.errors import InvalidOperation
from services.relay_hardening import LATER_META_KEY, RelayHardeningMonitor, parse_callback
from services.relay_ssh import AgentReply, RelaySshError
from services.relays import HARDEN_SSH_PORT, RelayAgentError, hardening_of, hardening_of_status

pytestmark = pytest.mark.timeout(60)


@pytest.fixture
async def env(tmp_path: Path) -> Any:
    world = await Env(tmp_path).start()
    yield world
    await world.close()


@pytest.fixture
async def prod(tmp_path: Path) -> Any:
    world = await Env(tmp_path).start(production=True)
    yield world
    await world.close()


SINCE = 1763460000
OFF = "off (RELAY_INPUT_FILTER=off)"


class RelaySim:
    """The relay's agent as «Довести» talks to it. The filter: off → pending (applied
    from the stage, the dead-man armed) → confirmed (input-confirm from a NEW session)
    → on (.env committed); SSH: 22 → 22+54321 (phase 1) → 54321. Every request is
    recorded with the port the bot came in on."""

    def __init__(self, world: Env, *, agent: str = "4", probe_confirms: bool = False, confirm_ok: bool = True,
                 off_reachable: bool = True, finish_ok: bool = True) -> None:
        self.agent, self.probe_confirms, self.confirm_ok = agent, probe_confirms, confirm_ok
        self.off_reachable, self.finish_ok = off_reachable, finish_ok
        self.filter = "off"
        self.ssh_port, self.listening, self.since = 22, [22], 0
        self.requests: list[tuple[str, int]] = []
        world.client.call = self.call  # type: ignore[method-assign]

    def status(self) -> dict[str, Any]:
        input_status = {"off": OFF, "on": "OK (tcp 22; confirmed 2026-11-18T21:01:00Z by ssh-session)"}.get(
            self.filter, "off (RELAY_INPUT_FILTER=off) but table inet vpnrelay_input is still loaded — re-apply")
        phase1 = len(self.listening) > 1
        plan = {"ssh_port": str(self.ssh_port), "current": ",".join(map(str, self.listening)),
                "state": "phase1" if phase1 else "steady", "action": "wait" if phase1 else "none",
                "from": "22", "to": str(self.ssh_port), "since": str(self.since), "hold": "0", "proof": "none"}
        return {"ok": True, "agent": self.agent, "check": {"rc": 0}, "input_status": input_status,
                "ssh_ports": list(self.listening), "ssh_migration": plan}

    async def call(self, host: str, port: int, request: str, *, alias: str, host_key: str | None,
                   timeout: float = 60.0, sensitive: Any = (), via: Any = None) -> AgentReply:
        self.requests.append((request, port))
        if request == "status":
            return AgentReply(0, self.status())
        if request == "input-filter on":
            if self.filter == "off":
                self.filter = "on" if self.probe_confirms else "pending"
            elif self.filter == "confirmed":
                self.filter = "on"
            return AgentReply(0, {"ok": True, "input_filter": {"state": "on", "committed": self.filter == "on"},
                                  "input_status": "PENDING CONFIRM (reverts at …)" if self.filter == "pending" else "OK"})
        if request == "input-confirm":
            if self.confirm_ok and self.filter == "pending":
                self.filter = "confirmed"
                return AgentReply(0, {"ok": True, "input_status": "OK"})
            if not self.off_reachable:
                raise RelaySshError("relay не ответил вовремя", key="relay_ssh_timeout")
            return AgentReply(4, {"ok": False, "error": "vpn-relay-apply input-confirm exit 19: nothing to confirm"})
        if request == "input-filter off":
            if not self.off_reachable:
                raise RelaySshError("relay не ответил вовремя", key="relay_ssh_timeout")
            self.filter = "off"
            return AgentReply(0, {"ok": True, "input_filter": {"state": "off", "committed": True}})
        if request.startswith("ssh-port-set port="):
            to = int(request.rsplit("=", 1)[1])
            if to == 22:
                self.ssh_port, self.listening, self.since = 22, [22], 0
            else:
                self.ssh_port, self.listening, self.since = to, [22, to], SINCE
            return AgentReply(0, {"ok": True, **self.status()})
        if request.startswith("ssh-port-finish "):
            if not self.finish_ok or port != self.ssh_port:
                raise RelaySshError("relay не ответил вовремя", key="relay_ssh_timeout")
            self.listening, self.since = [self.ssh_port], self.since
            return AgentReply(0, {"ok": True, **self.status()})
        return AgentReply(2, {"ok": False, "error": "refused: not an agent command"})

    def asked(self) -> list[str]:
        return [r for r, _ in self.requests if r != "status"]


async def _he2(world: Env, **kw: Any) -> RelaySim:
    """ru1 paired, its agent's status as he2's: SSH 22, the filter off."""
    issued = await world.service.issue_attach(ADMIN, 1, target_host=TARGET)
    await world.service.complete(ADMIN, issued.pairing.id, RU1_IP)
    sim = RelaySim(world, **kw)
    await world.service.agent_status(ADMIN, 1)
    return sim


def _monitor(world: Env) -> tuple[RelayHardeningMonitor, list[tuple[str, Any]]]:
    sent: list[tuple[str, Any]] = []

    async def send(text: str, markup: Any) -> None:
        sent.append((text, markup))

    monitor = RelayHardeningMonitor(store=world.db, admin_ids=frozenset({ADMIN}), send=send)
    world.service.status_listeners.append(monitor.relay_status)
    return monitor, sent


def _buttons(markup: Any) -> list[str]:
    return [b.callback_data for row in markup.inline_keyboard for b in row]


# ── what is left ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("status", "port", "ssh", "filt"),
    [
        ({"input_status": OFF, "ssh_migration": {"ssh_port": "22", "state": "steady"}}, 22, True, True),  # he2
        ({"input_status": "OK (tcp 54321)", "ssh_migration": {"ssh_port": "54321", "state": "steady"}}, 54321, False, False),
        ({"input_status": OFF, "ssh_migration": {"ssh_port": "22", "state": "phase1"}}, 22, False, True),
        ({"input_status": "PENDING CONFIRM (reverts at x)", "ssh_ports": [22]}, 22, True, False),  # agent 2: no plan
        ({"ssh_ports": [22, 2222]}, 22, False, False),
        ({"input_status": OFF, "ssh_migration": {"ssh_port": "2222", "state": "steady"}}, 2222, False, True),
    ],
)
def test_what_is_left_comes_from_the_status(status: dict[str, Any], port: int, ssh: bool, filt: bool) -> None:
    found = hardening_of_status(status, port)
    assert found is not None and (found.ssh_on_22, found.filter_off) == (ssh, filt)


def test_a_status_that_tells_nothing_is_no_verdict() -> None:
    assert hardening_of_status({"agent": "1", "check": {"rc": 0}}, 22) is None


# ── the alert: once per pairing, «Позже» remembered ─────────────────────────────


async def test_a_new_relay_left_on_22_without_a_filter_is_told_once_after_its_pairing(env: Env) -> None:
    _, sent = _monitor(env)
    env.client.replies["hello"] = _hello(agent="4", input_status=OFF, ssh_ports=[22],
                                         ssh_migration={"ssh_port": "22", "state": "steady"})
    issued = await env.service.issue_new(ADMIN, name="he2", host="203.0.113.50", target_host=TARGET)
    relay = (await env.service.complete(ADMIN, issued.pairing.id, "203.0.113.50")).relay
    assert len(sent) == 1, "told right after the pairing"
    text, markup = sent[0]
    assert text.startswith("<b>⚠️ relay he2: " + t("relay_harden_what_ssh") + ", " + t("relay_harden_what_filter"))
    assert _buttons(markup) == [f"rhard:go:{relay.id}", f"rhard:later:{relay.id}"]
    env.client.replies["status"] = AgentReply(0, {"ok": True, "agent": "4", "input_status": OFF, "ssh_ports": [22],
                                                  "ssh_migration": {"ssh_port": "22", "state": "steady"}})
    await env.service.agent_status(ADMIN, relay.id)
    assert len(sent) == 1, "a later status does not repeat it"


async def test_the_card_tells_an_existing_relay_once_and_later_is_remembered(prod: Env) -> None:
    monitor, sent = _monitor(prod)
    prod.service.status_listeners.remove(monitor.relay_status)  # an existing relay: the card is the trigger
    await _he2(prod)
    services = _services(prod)
    services.relay_hardening = monitor
    card = Callback("admin:relay:1")
    await relay_ui.relay_card(card, fsm(), services)  # type: ignore[arg-type]
    assert len(sent) == 1 and "rhard:go:1" in _buttons(card.message.markups[-1])
    assert t("relay_harden_card_line", what=t("relay_harden_what_ssh") + ", " + t("relay_harden_what_filter")) in (
        card.message.edits[-1])
    await relay_ui.relay_card(Callback("admin:relay:1"), fsm(), services)  # type: ignore[arg-type]
    assert len(sent) == 1, "once"
    later = Callback("rhard:later:1")
    await ui.relay_harden_later(later, services)  # type: ignore[arg-type]
    assert t("relay_harden_later_done", name="ru1") in later.message.edits[-1]
    assert await monitor.postponed(await prod.relay()) and "1" in (await prod.db.get_meta(LATER_META_KEY) or "")
    assert "rhard:go:1" in _buttons(later.message.markups[-1]), "the way back stays"


def test_the_buttons_parse_and_nothing_else_does() -> None:
    assert parse_callback("rhard:go:7") == ("go", 7) and parse_callback("rhard:later:7") == ("later", 7)
    assert parse_callback("rhard:rm:7") is None and parse_callback("rhard:go:x") is None


# ── «Довести»: the filter first, then SSH; each step rolled back ────────────────


async def test_harden_brings_he2_to_the_defaults_filter_first(prod: Env) -> None:
    sim = await _he2(prod)
    moves: list[tuple[str, str]] = []

    async def on_progress(step: str, state: str) -> None:
        moves.append((step, state))

    assert await prod.service.harden(ADMIN, 1, on_progress) == ("filter", "ssh")
    asked = sim.asked()
    assert asked[:3] == ["input-filter on", "input-confirm", "input-filter on"], "staged, confirmed, committed"
    assert asked.index("input-filter on") < asked.index(f"ssh-port-set port={HARDEN_SSH_PORT}"), "the filter first"
    finish = [(r, p) for r, p in sim.requests if r.startswith("ssh-port-finish")]
    assert finish == [(f"ssh-port-finish port={HARDEN_SSH_PORT} since={SINCE}", HARDEN_SSH_PORT)], "proven ON 54321"
    assert [s for s, st in moves if st == "ok"] == ["filter_on", "filter_confirm", "ssh_set", "ssh_finish"]
    relay = await prod.relay()
    assert relay.agent is not None and relay.agent.ssh_port == HARDEN_SSH_PORT
    found = hardening_of(relay)
    assert found is not None and not found.needed, "the status after it says: at the defaults"
    assert "relay_input_filter_on" in prod.audit.actions()


async def test_a_filter_mains_probe_confirmed_needs_no_second_session(prod: Env) -> None:
    sim = await _he2(prod, probe_confirms=True)
    await prod.service.harden(ADMIN, 1)
    assert "input-confirm" not in sim.asked()[: sim.asked().index(f"ssh-port-set port={HARDEN_SSH_PORT}")]


async def test_an_unconfirmed_filter_is_rolled_back_and_ssh_is_not_touched(prod: Env) -> None:
    sim = await _he2(prod, confirm_ok=False)
    moves: list[tuple[str, str]] = []

    async def on_progress(step: str, state: str) -> None:
        moves.append((step, state))

    with pytest.raises(RelayAgentError) as exc:
        await prod.service.harden(ADMIN, 1, on_progress)
    assert exc.value.key == "relay_harden_filter_failed"
    assert sim.asked() == ["input-filter on", "input-confirm", "input-filter off"], "rolled back, nothing else"
    assert sim.filter == "off" and ("filter_confirm", "fail") in moves


async def test_an_unreachable_relay_leaves_the_rollback_to_the_dead_man(prod: Env) -> None:
    sim = await _he2(prod, confirm_ok=False, off_reachable=False)
    with pytest.raises(RelayAgentError) as exc:
        await prod.service.harden(ADMIN, 1)
    assert exc.value.key == "relay_harden_filter_failed_deadman"
    assert "dead-man" in t(exc.value.key, **exc.value.params)
    assert not [r for r in sim.asked() if r.startswith("ssh-port")]


async def test_a_new_port_that_does_not_answer_puts_ssh_back_and_keeps_the_filter(prod: Env) -> None:
    sim = await _he2(prod, finish_ok=False)
    with pytest.raises(RelayAgentError) as exc:
        await prod.service.harden(ADMIN, 1)
    assert exc.value.key == "relay_harden_ssh_failed"
    assert sim.asked()[-1] == "ssh-port-set port=22", "phase 1 cancelled"
    assert sim.listening == [22] and sim.filter == "on", "the filter step stays done"
    relay = await prod.relay()
    assert relay.agent is not None and relay.agent.ssh_port == 22
    found = hardening_of(relay)
    assert found is not None and found.ssh_on_22 and not found.filter_off


async def test_an_agent_older_than_input_filter_is_told_to_update_first(prod: Env) -> None:
    sim = await _he2(prod, agent="3")
    with pytest.raises(InvalidOperation) as exc:
        await prod.service.harden(ADMIN, 1)
    assert exc.value.key == "relay_harden_agent_old" and sim.asked() == []


async def test_nothing_to_do_is_said(prod: Env) -> None:
    sim = await _he2(prod)
    sim.filter, sim.ssh_port, sim.listening = "on", HARDEN_SSH_PORT, [HARDEN_SSH_PORT]
    await prod.service.agent_status(ADMIN, 1)
    with pytest.raises(InvalidOperation) as exc:
        await prod.service.harden(ADMIN, 1)
    assert exc.value.key == "relay_harden_nothing"


# ── the screens ───────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _private(monkeypatch: pytest.MonkeyPatch) -> None:
    async def ok(*_: Any) -> bool:
        return True

    async def edit(message: Any, text: str, reply_markup: Any = None, **_: Any) -> bool:
        message.edits.append(text)
        message.markups.append(reply_markup)
        return True

    for module in (ui, sshp, relay_ui):
        monkeypatch.setattr(module, "ensure_private_callback", ok)
        monkeypatch.setattr(module, "safe_edit_message_text", edit)


async def test_doveste_shows_the_plan_then_runs_with_progress(prod: Env) -> None:
    sim = await _he2(prod)
    totp = FakeTotp(enabled=True)
    state = fsm()
    await ui.relay_harden_plan(Callback("rhard:go:1"), state, _services(prod, totp))  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.gate_code.state, "a change: the TOTP gate first"
    totp.elevated = True
    plan = Callback("rhard:go:1")
    await ui.relay_harden_plan(plan, fsm(), _services(prod, totp))  # type: ignore[arg-type]
    text = plan.message.edits[-1]
    assert text.count("⚪") == 4 and t("relay_harden_step_filter_on") in text
    assert text.index(t("relay_harden_step_filter_on")) < text.index(t("relay_harden_step_ssh_set", port=HARDEN_SSH_PORT))
    assert _buttons(plan.message.markups[-1])[:2] == ["rhard:ok:1", "rhard:later:1"]
    assert sim.asked() == [], "nothing ran before the confirmation"
    run = Callback("rhard:ok:1")
    await ui.relay_harden_run(run, fsm(), _services(prod, totp))  # type: ignore[arg-type]
    final = run.message.edits[-1]
    assert final.count("✅") >= 5 and t("relay_harden_done", name="ru1", port=HARDEN_SSH_PORT) in final
    assert "🔄" not in final


async def test_a_failed_run_marks_its_step(prod: Env) -> None:
    await _he2(prod, finish_ok=False)
    run = Callback("rhard:ok:1")
    await ui.relay_harden_run(run, fsm(), _services(prod))  # type: ignore[arg-type]
    final = run.message.edits[-1]
    assert "❌ " + t("relay_harden_step_ssh_finish", port=HARDEN_SSH_PORT) in final
    assert "✅ " + t("relay_harden_step_filter_confirm") in final
    assert t("relay_harden_ssh_failed", port=HARDEN_SSH_PORT, error="").split("(")[0] in final


async def test_an_old_agent_gets_update_first_not_a_plan(prod: Env) -> None:
    await _he2(prod, agent="2")
    plan = Callback("rhard:go:1")
    await ui.relay_harden_plan(plan, fsm(), _services(prod))  # type: ignore[arg-type]
    assert t("relay_harden_agent_old", name="ru1", version="#2") in plan.message.edits[-1]
    assert "admin:relay:1:ag:up" in _buttons(plan.message.markups[-1])
    assert "rhard:ok:1" not in _buttons(plan.message.markups[-1])


async def test_the_wizard_leads_back_to_it(prod: Env) -> None:
    await _he2(prod)
    assert {"admin:sshp", "admin:rfilt"} <= set(_buttons(menu_keyboard(active=None, daily=False)))
    services = _services(prod)
    screen = Callback("admin:rfilt")
    await ui.relay_filter_list(screen, services)  # type: ignore[arg-type]
    assert t("relay_filter_line", name="ru1", status=OFF) in screen.message.edits[-1]
    assert "rhard:go:1" in _buttons(screen.message.markups[-1])
    card = Callback("admin:sshp:1")
    await sshp.relay_ssh_port_card(card, fsm(), services)
    assert "rhard:go:1" in _buttons(card.message.markups[-1])
    assert t("relay_harden_what_filter") in card.message.edits[-1]


async def test_a_relay_at_the_defaults_has_no_warning(prod: Env) -> None:
    sim = await _he2(prod)
    sim.filter, sim.ssh_port, sim.listening = "on", HARDEN_SSH_PORT, [HARDEN_SSH_PORT]
    await prod.service.agent_status(ADMIN, 1)
    card = Callback("admin:relay:1")
    await relay_ui.relay_card(card, fsm(), _services(prod))  # type: ignore[arg-type]
    assert "rhard:go:1" not in _buttons(card.message.markups[-1])
    assert t("relay_harden_what_ssh") not in card.message.edits[-1]
