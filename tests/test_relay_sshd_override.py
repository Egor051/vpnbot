"""A foreign sshd override on a relay (docs/relay.md «Чужой sshd-override»).

he2 (hub), 2026-11-18: a hoster's «password reset» dropped
/etc/ssh/sshd_config.d/00-password-login.conf (PasswordAuthentication yes, PermitRootLogin
yes); sorted before the repo's 00-vpnrelay-keyonly.conf it wins, the host check reports
it BEATEN and the relay's deploy stopped in Phase 1 — while the bot showed only «2 fatal
finding(s)» and could not fix it. Pinned here, on the bot's side (the agent's command is
pinned in tests/test_vpn_relay_agent.py):

* **The findings reach the result**: the structured ``findings`` of an agent 5, and the
  ones deploy.sh puts into its die message (which an agent 3.2.0 forwards verbatim) —
  rendered as key, file:line, what beat what.
* **The button**: only for a foreign file in sshd_config.d beating a repo auth key; the
  service maps the agent's refusals (no own key, an old agent) to their messages.
* **The detector**: a status that names the file tells the superadmins ONCE per file and
  mtime — and again when it comes back; a drift alone asks ``sshd-check`` at most hourly.
* **One list**: the auth keys and the repo's drop-ins are the same in deploy.sh, the
  agent and the bot.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_relay import ADMIN
from test_relay_agents import World, _hello, _paired

from bot.deploy_views import deploy_failure_text
from i18n import t
from models.dto import Relay
from services.deploy_result import (
    REPO_SSHD_DROPINS,
    SSHD_AUTH_KEYS,
    HostFinding,
    deploy_failure_from,
    findings_from_text,
)
from services.errors import InvalidOperation
from services.relay_sshd_override import (
    RECHECK_SECONDS,
    SshdOverrideMonitor,
    parse_callback,
    path_tag,
    remove_button,
)
from services.relay_ssh import AgentReply
from services.relays import RelayAgentError, SshdCheck, SshdOverride, hardening_of_status, sshd_overrides_of

ROOT = Path(__file__).resolve().parents[1]
OVERRIDE = "/etc/ssh/sshd_config.d/00-password-login.conf"
KEYONLY = "/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf"
BEATEN_PW = f"{OVERRIDE}:1 = yes wins over the repo value no of {KEYONLY} (the first value wins)"
BEATEN_ROOT = f"{OVERRIDE}:2 = yes wins over the repo value prohibit-password of {KEYONLY} (the first value wins)"
# What an agent 3.2.0 hands the bot for he2 once deploy.sh carries the findings in its die.
OLD_AGENT_MESSAGE = (
    "the deploy of v3.2.3 stopped before any change (exit 1): host invariants: 2 fatal finding(s) — nothing was "
    f"changed. Fatal: BEATEN sshd passwordauthentication: {BEATEN_PW}; BEATEN sshd permitrootlogin: {BEATEN_ROOT}"
)

pytestmark = pytest.mark.timeout(60)


@pytest.fixture
async def world(tmp_path: Path) -> Any:
    w = await World(tmp_path).start()
    yield w
    await w.close()


# ── one list ──────────────────────────────────────────────────────────────────


def _agent_tuple(name: str) -> tuple[str, ...]:
    text = (ROOT / "scripts" / "vpn-relay-agent").read_text(encoding="utf-8")
    m = re.search(rf"^{name} = \(([^)]*)\)", text, re.MULTILINE)
    assert m, name
    return tuple(re.findall(r'"([a-z]+)"', m.group(1)))


def test_the_auth_keys_are_one_list_in_deploy_sh_the_agent_and_the_bot() -> None:
    text = (ROOT / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    m = re.search(r"^HOST_CHECK_SSHD_AUTH_KEYS=\(([^)]*)\)", text, re.MULTILINE)
    assert m
    assert tuple(m.group(1).split()) == SSHD_AUTH_KEYS == _agent_tuple("SSHD_AUTH_KEYS")


def test_the_repos_drop_ins_are_what_deploy_sh_installs_in_sshd_config_d() -> None:
    text = (ROOT / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    installed = set(re.findall(r'"deploy/host/ssh/[^|]+\|/etc/ssh/sshd_config\.d/([^|]+)\|', text))
    assert installed == REPO_SSHD_DROPINS
    # The agent reads them from its checkout (deploy/host/ssh/*.conf): a superset — the
    # socket drop-in there never lies in sshd_config.d.
    assert REPO_SSHD_DROPINS <= {p.name for p in (ROOT / "deploy/host/ssh").glob("*.conf")}


def test_the_bot_and_the_agent_take_the_same_drop_in_paths() -> None:
    text = (ROOT / "scripts" / "vpn-relay-agent").read_text(encoding="utf-8")
    m = re.search(r'^_SSHD_DROPIN = r"(.*)"$', text, re.MULTILINE)
    assert m
    from services.deploy_result import SSHD_DROPIN

    assert m.group(1) == SSHD_DROPIN.pattern


# ── the findings in the result ────────────────────────────────────────────────


def test_an_old_agents_message_carries_the_findings_and_names_the_step() -> None:
    failure = deploy_failure_from(None, message=OLD_AGENT_MESSAGE)
    assert (failure.reason, failure.step) == ("checks", "checks")
    assert [(f.verdict, f.family, f.key, f.path) for f in failure.findings] == [
        ("BEATEN", "sshd", "passwordauthentication", OVERRIDE), ("BEATEN", "sshd", "permitrootlogin", OVERRIDE),
    ]
    assert failure.sshd_overrides == (OVERRIDE,)
    text = deploy_failure_text(failure)
    assert t("deploy_fail_findings") in text and "00-password-login.conf</code>:1" in text
    assert "<code>yes</code>" in text and "<code>prohibit-password</code>" in text and KEYONLY in text
    assert ". Fatal:" not in text, "the findings are listed once, not again in the message"
    assert t("deploy_fail_step_unknown") not in text


def test_structured_findings_win_and_are_validated() -> None:
    failure = deploy_failure_from({
        "reason": "checks", "step": "checks",
        "findings": [
            {"verdict": "BEATEN", "family": "sshd", "key": "passwordauthentication", "path": "", "text": BEATEN_PW},
            {"verdict": "rm -rf", "family": "sshd", "key": "x", "path": "/x", "text": "x"},
            {"verdict": "MISMATCH", "family": "unit", "key": "x.timer", "path": "/etc/systemd/system/x.timer",
             "text": "timer is disabled <b>"},
            "junk",
        ],
    }, message=OLD_AGENT_MESSAGE)
    assert [f.verdict for f in failure.findings] == ["BEATEN", "MISMATCH"]
    assert failure.findings[0].path == OVERRIDE, "the path from «<file>:<line> = …»"
    text = deploy_failure_text(failure)
    assert "timer is disabled &lt;b&gt;" in text


def test_a_truncated_brief_keeps_what_is_whole() -> None:
    cut = OLD_AGENT_MESSAGE[: OLD_AGENT_MESSAGE.index("permitrootlogin: ") + 30]
    found = findings_from_text(cut)
    assert len(found) == 2 and found[0].path == OVERRIDE
    assert found[1].path == "" or found[1].path == OVERRIDE
    assert findings_from_text("no brief here") == ()


@pytest.mark.parametrize(
    ("finding", "foreign"),
    [
        (HostFinding("BEATEN", "sshd", "passwordauthentication", OVERRIDE, BEATEN_PW), True),
        (HostFinding("BEATEN", "sshd", "passwordauthentication", KEYONLY), False),          # the repo's own
        (HostFinding("BEATEN", "sshd", "passwordauthentication", "/etc/ssh/sshd_config"), False),
        (HostFinding("BEATEN", "sshd", "x11forwarding", OVERRIDE), False),                  # not an auth key
        (HostFinding("LATENT", "sshd", "passwordauthentication", OVERRIDE), False),
        (HostFinding("BEATEN", "sysctl", "passwordauthentication", OVERRIDE), False),
    ],
)
def test_the_button_is_only_for_a_foreign_file_beating_an_auth_key(finding: HostFinding, foreign: bool) -> None:
    assert finding.foreign_sshd_override is foreign


def test_deploy_sh_puts_the_findings_into_its_die(tmp_path: Path) -> None:
    rows = [f"BEATEN|sshd|passwordauthentication|{OVERRIDE}|{BEATEN_PW}",
            f"BEATEN|sshd|permitrootlogin|{OVERRIDE}|{BEATEN_ROOT}",
            "pristine|/etc/ssh/sshd_config"]
    driver = tmp_path / "d.sh"
    driver.write_text(
        "set -euo pipefail\nexport DEPLOY_SELFTEST=1\n"
        f'source "{ROOT / "scripts" / "deploy.sh"}"\n'
        'hc_fatal_brief "$@"\n', encoding="utf-8")
    out = subprocess.run(["bash", str(driver), *rows], capture_output=True, text=True, check=True).stdout
    assert out.startswith(". Fatal: BEATEN sshd passwordauthentication: ")
    found = findings_from_text("host invariants: 3 fatal finding(s) — nothing was changed" + out)
    assert [f.key for f in found] == ["passwordauthentication", "permitrootlogin", "/etc/ssh/sshd_config"]
    many = subprocess.run(["bash", str(driver), *(rows[:1] * 6)], capture_output=True, text=True, check=True).stdout
    assert many.endswith("; … 2 more") and len(many) < 1200


# ── the service ───────────────────────────────────────────────────────────────


async def _relay_v5(world: World) -> int:
    world.client.replies["hello"] = _hello(agent="5")
    return await _paired(world)


async def test_remove_maps_the_agents_answers(world: World) -> None:
    relay_id = await _relay_v5(world)
    world.client.replies["sshd-override-off"] = AgentReply(4, {
        "ok": False, "error": "… add your own key first", "sshd_override": {"refused": "no_personal_key"}})
    with pytest.raises(RelayAgentError) as caught:
        await world.service.remove_sshd_override(ADMIN, relay_id, OVERRIDE)
    assert caught.value.key == "relay_sshd_override_no_key"
    world.client.replies["sshd-override-off"] = AgentReply(4, {"ok": False, "error": "sshd -t failed — restored"})
    with pytest.raises(RelayAgentError) as caught:
        await world.service.remove_sshd_override(ADMIN, relay_id, OVERRIDE)
    assert caught.value.key == "relay_sshd_override_error" and "sshd -t failed" in caught.value.params["error"]
    world.client.replies["sshd-override-off"] = AgentReply(0, {
        "ok": True, "sshd_override": {"path": OVERRIDE, "moved_to": "/root/attic/00-password-login.conf.1",
                                      "keys": ["passwordauthentication"], "still_beaten_by": []}})
    world.client.replies["status"] = AgentReply(0, {"ok": True, "agent": "5", "check": {"rc": 0, "lines": []}})
    result = await world.service.remove_sshd_override(ADMIN, relay_id, OVERRIDE)
    assert result["moved_to"] == "/root/attic/00-password-login.conf.1"
    assert [c["request"] for c in world.client.calls if c["request"].startswith("sshd")][-1] == (
        f"sshd-override-off path={OVERRIDE}")
    audit = [r for r in world.audit.rows if r["action"] == "relay_sshd_override_off"]
    assert [r["details"]["ok"] for r in audit] == [False, False, True]
    assert relay_id not in world.service._busy


@pytest.mark.parametrize("path", [KEYONLY, "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/x.conf;id"])
async def test_remove_refuses_a_path_that_is_not_a_foreign_drop_in(world: World, path: str) -> None:
    relay_id = await _relay_v5(world)
    with pytest.raises(InvalidOperation):
        await world.service.remove_sshd_override(ADMIN, relay_id, path)
    assert not [c for c in world.client.calls if c["request"].startswith("sshd")]


async def test_an_old_agent_cannot_remove_it(world: World) -> None:
    world.client.replies["hello"] = _hello(agent="2")
    relay_id = await _paired(world)
    with pytest.raises(RelayAgentError) as caught:
        await world.service.remove_sshd_override(ADMIN, relay_id, OVERRIDE)
    assert caught.value.key == "relay_sshd_override_agent_old"


async def test_sshd_check_is_validated(world: World) -> None:
    relay_id = await _relay_v5(world)
    world.client.replies["sshd-check"] = AgentReply(0, {"ok": True, "sshd_overrides": [
        {"path": OVERRIDE, "keys": ["passwordauthentication", "bogus"], "texts": [BEATEN_PW], "mtime": 1763490180},
        {"path": KEYONLY, "keys": ["passwordauthentication"]},
        {"path": "/tmp/x.conf", "keys": ["passwordauthentication"]},
    ], "sshd_drift": {"passwordauthentication": {"have": "yes", "want": "no"}, "x": {"have": 1}}})
    check = await world.service.sshd_check(None, relay_id)
    assert check.overrides == (SshdOverride(OVERRIDE, ("passwordauthentication",), (BEATEN_PW,), 1763490180),)
    assert check.drift == {"passwordauthentication": ("yes", "no")}


async def test_harden_moves_the_override_first(world: World) -> None:
    relay_id = await _relay_v5(world)
    world.client.replies["status"] = AgentReply(0, {
        "ok": True, "agent": "5", "check": {"rc": 0, "lines": []}, "input_status": "OK",
        "ssh_migration": {"ssh_port": "54321", "state": "done"},
        "sshd_overrides": [{"path": OVERRIDE, "keys": ["passwordauthentication"]}],
    })
    await world.service.agent_status(ADMIN, relay_id)
    relay = await world.service.get(ADMIN, relay_id)
    assert relay.agent is not None
    hardening = hardening_of_status(relay.agent.last_status or {}, relay.agent.ssh_port)
    assert hardening is not None and hardening.overrides == (OVERRIDE,) and hardening.needed
    world.client.replies["sshd-check"] = AgentReply(0, {"ok": True, "sshd_overrides": [
        {"path": OVERRIDE, "keys": ["passwordauthentication"]}]})
    world.client.replies["sshd-override-off"] = AgentReply(0, {"ok": True, "sshd_override": {"moved_to": "/root/attic/x"}})
    steps: list[tuple[str, str]] = []

    async def progress(step: str, state: str) -> None:
        steps.append((step, state))

    done = await world.service.harden(ADMIN, relay_id, progress)
    assert done == ("sshd",) and steps == [("sshd_check", "run"), ("sshd_check", "ok")]
    requests = [c["request"] for c in world.client.calls]
    assert requests.index("sshd-check") < requests.index(f"sshd-override-off path={OVERRIDE}")


# ── the detector ──────────────────────────────────────────────────────────────


class Store:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get_meta(self, key: str) -> str | None:
        return self.data.get(key)

    async def set_meta(self, key: str, value: str) -> None:
        self.data[key] = value


async def _a_relay(world: World) -> Relay:
    relay_id = await _relay_v5(world)
    return await world.service.get(ADMIN, relay_id)


async def test_the_detector_tells_once_per_file_and_again_when_it_comes_back(world: World) -> None:
    relay = await _a_relay(world)
    sent: list[tuple[str, Any]] = []

    async def send(text: str, markup: Any) -> None:
        sent.append((text, markup))

    store = Store()
    monitor = SshdOverrideMonitor(store=store, admin_ids=frozenset({ADMIN}), send=send)
    status = {"sshd_overrides": [{"path": OVERRIDE, "keys": ["passwordauthentication", "permitrootlogin"],
                                  "texts": [BEATEN_PW], "mtime": 100}]}
    await monitor.relay_status(relay, status)
    await monitor.relay_status(relay, status)
    assert len(sent) == 1, "once per file and mtime — a restart reads the same schema_meta"
    text, markup = sent[0]
    assert "00-password-login.conf" in text and "passwordauthentication" in text
    button = markup.inline_keyboard[0][0].callback_data
    assert button == f"rsov:go:{relay.id}:{path_tag(OVERRIDE)}" and len(button) <= 64
    assert parse_callback(button) == ("go", relay.id, path_tag(OVERRIDE))
    assert await monitor.resolve(relay, path_tag(OVERRIDE)) == OVERRIDE
    # The panel's «password reset» again: a new file, a new mtime — told again.
    status["sshd_overrides"][0]["mtime"] = 200  # type: ignore[index]
    await SshdOverrideMonitor(store=store, admin_ids=frozenset({ADMIN}), send=send).relay_status(relay, status)
    assert len(sent) == 2


async def test_a_drift_alone_asks_sshd_check_at_most_hourly(world: World) -> None:
    relay = await _a_relay(world)
    sent: list[str] = []
    asked: list[int] = []
    now = [1000.0]

    async def send(text: str, markup: Any) -> None:
        sent.append(text)

    async def check(relay_id: int) -> SshdCheck:
        asked.append(relay_id)
        return SshdCheck(overrides=(SshdOverride(OVERRIDE, ("passwordauthentication",), (), 5),), drift={})

    monitor = SshdOverrideMonitor(store=Store(), admin_ids=frozenset(), send=send, check=check, clock=lambda: now[0])
    drift = {"sshd_drift": {"passwordauthentication": {"have": "yes", "want": "no"}}}
    await monitor.relay_status(relay, drift)
    await monitor.relay_status(relay, drift)
    assert asked == [relay.id] and len(sent) == 1
    now[0] += RECHECK_SECONDS + 1
    await monitor.relay_status(relay, drift)
    assert asked == [relay.id, relay.id] and len(sent) == 1, "the same file: not told again"
    await monitor.relay_status(relay, {"sshd_drift": {}})
    assert len(asked) == 2


async def test_remember_keeps_the_paths_a_button_names(world: World) -> None:
    relay = await _a_relay(world)
    monitor = SshdOverrideMonitor(store=Store(), admin_ids=frozenset())
    assert await monitor.resolve(relay, path_tag(OVERRIDE)) is None
    await monitor.remember(relay.id, [OVERRIDE])
    assert await monitor.resolve(relay, path_tag(OVERRIDE)) == OVERRIDE
    assert json.loads((monitor._store.data)["relay_sshd_override_paths"]) == {str(relay.id): [OVERRIDE]}  # type: ignore[attr-defined]
    assert remove_button(relay.id, OVERRIDE)[0].text == t("btn_relay_sshd_override", name="00-password-login.conf")


def test_status_overrides_are_validated() -> None:
    assert sshd_overrides_of([{"path": OVERRIDE, "keys": ["passwordauthentication"], "mtime": True}])[0].mtime is None
    assert sshd_overrides_of("junk") == ()
    assert sshd_overrides_of([{"path": OVERRIDE, "keys": []}]) == ()


# ── the button's screens (bot/handlers/relay_sshd.py) ─────────────────────────


class _Msg:
    def __init__(self) -> None:
        self.message_id = 10
        self.chat = type("C", (), {"id": ADMIN, "type": "private"})()
        self.edits: list[tuple[str, Any]] = []


class _Cb:
    def __init__(self, data: str) -> None:
        self.data = data
        self.from_user = type("U", (), {"id": ADMIN})()
        self.message = _Msg()
        self.alerts: list[tuple[str | None, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **_: Any) -> None:
        self.alerts.append((text, show_alert))


class _Relays:
    def __init__(self, relay: Relay) -> None:
        self.relay = relay
        self.removed: list[str] = []
        self.fail: Exception | None = None

    async def get(self, actor: int, relay_id: int) -> Relay:
        return self.relay

    async def remove_sshd_override(self, actor: int, relay_id: int, path: str) -> dict[str, Any]:
        if self.fail is not None:
            raise self.fail
        self.removed.append(path)
        return {"moved_to": "/root/attic/00-password-login.conf.1", "still_beaten_by": ["/etc/ssh/sshd_config.d/x.conf"]}


@pytest.fixture
def _ui(monkeypatch: pytest.MonkeyPatch) -> Any:
    from bot.handlers import relay_sshd

    async def ok(*_: Any) -> bool:
        return True

    async def edit(message: Any, text: str, reply_markup: Any = None, **_: Any) -> bool:
        message.edits.append((text, reply_markup))
        return True

    monkeypatch.setattr(relay_sshd, "ensure_private_callback", ok)
    monkeypatch.setattr(relay_sshd, "safe_edit_message_text", edit)
    return relay_sshd


async def test_the_button_shows_the_plan_then_moves_the_file(world: World, _ui: Any) -> None:
    from types import SimpleNamespace

    from aiogram.fsm.context import FSMContext
    from aiogram.fsm.storage.base import StorageKey
    from aiogram.fsm.storage.memory import MemoryStorage

    relay = await _a_relay(world)
    monitor = SshdOverrideMonitor(store=Store(), admin_ids=frozenset())
    await monitor.remember(relay.id, [OVERRIDE])
    relays = _Relays(relay)
    services = SimpleNamespace(relays=relays, sshd_override=monitor, totp=None, users=world.service.users)
    state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=ADMIN, user_id=ADMIN))
    go = _Cb(f"rsov:go:{relay.id}:{path_tag(OVERRIDE)}")
    await _ui.relay_sshd_override(go, state, services)
    text, markup = go.message.edits[-1]
    assert OVERRIDE in text and "/root/attic/" in text and relays.removed == []
    assert [b.callback_data for r in markup.inline_keyboard for b in r] == [
        f"rsov:ok:{relay.id}:{path_tag(OVERRIDE)}", f"admin:relay:{relay.id}"]
    ok = _Cb(f"rsov:ok:{relay.id}:{path_tag(OVERRIDE)}")
    await _ui.relay_sshd_override(ok, state, services)
    assert relays.removed == [OVERRIDE]
    final, back = ok.message.edits[-1]
    assert "00-password-login.conf.1" in final and "/etc/ssh/sshd_config.d/x.conf" in final
    assert [b.callback_data for r in back.inline_keyboard for b in r] == [f"admin:relay:{relay.id}"]
    relays.fail = RelayAgentError("x", key="relay_sshd_override_no_key", params={"name": relay.name})
    again = _Cb(f"rsov:ok:{relay.id}:{path_tag(OVERRIDE)}")
    await _ui.relay_sshd_override(again, state, services)
    assert t("relay_sshd_override_no_key", name=relay.name).split(" — ")[0] in again.message.edits[-1][0]
    stale = _Cb(f"rsov:go:{relay.id}:{'0' * 10}")
    await _ui.relay_sshd_override(stale, state, services)
    assert stale.alerts[-1] == (t("relay_sshd_override_stale"), True)


async def test_an_old_agents_button_shows_the_fix_by_hand(world: World, _ui: Any) -> None:
    from types import SimpleNamespace

    from aiogram.fsm.context import FSMContext
    from aiogram.fsm.storage.base import StorageKey
    from aiogram.fsm.storage.memory import MemoryStorage

    world.client.replies["hello"] = _hello(agent="2")
    relay = await world.service.get(ADMIN, await _paired(world))
    monitor = SshdOverrideMonitor(store=Store(), admin_ids=frozenset())
    await monitor.remember(relay.id, [OVERRIDE])
    services = SimpleNamespace(relays=_Relays(relay), sshd_override=monitor, totp=None, users=world.service.users)
    state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=ADMIN, user_id=ADMIN))
    go = _Cb(f"rsov:go:{relay.id}:{path_tag(OVERRIDE)}")
    await _ui.relay_sshd_override(go, state, services)
    assert f"mv {OVERRIDE} /root/attic/" in go.message.edits[-1][0]
