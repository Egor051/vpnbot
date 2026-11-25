"""«🧭 Первичная настройка» (services/first_setup.py) on a real wizard_runs table with fakes of
the services it drives (DNS, certificate, installs, firewall, TOTP, the wizard's runs).

* The whole path: domain → token → dns → cert → protocols → install → ufw → totp →
  selfcheck, each step acting only on what is missing.
* Resumable: a NEW service object (what the restarted bot builds) continues the open
  setup — after a run it waited for finished while the bot was down too.
* A failed step waits for «🔁 Повторить», which re-checks first.
* What is done already is skipped (token set, the name resolving here, the certificate,
  a protocol on the host).
* The token never lands in the setup's row.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from adapters.clock import ClockProvider
from db.database import Database
from models.dto import WizardRun
from repositories.wizard_runs import WizardRunRepository
from services.errors import InvalidOperation
from services.first_setup import FirstSetupService, SetupError

ADMIN = 4242
DOMAIN = "vpn.example.com"
HOST_IP = "203.0.113.7"
TOKEN = "cfTOKEN_0123456789abcdefghijklmnop"
pytestmark = pytest.mark.timeout(60)


def _run(rid: int, mode: str, *, active: bool, state: str = "running", summary: str = "") -> WizardRun:
    return WizardRun(id=rid, mode=mode, state=state, phase="execute", current_step="apply", params={},
                     started_by=ADMIN, origin="manual", chat_id=1, message_id=None, log_path="", summary=summary,
                     plan_ready=False, active=active, created_at="x", updated_at="x",
                     finished_at=None if active else "y", reported_at=None)


class FakeWizard:
    def __init__(self) -> None:
        self.runs: dict[int, WizardRun] = {}
        self.started: list[tuple[str, dict[str, object], bool]] = []
        self.listeners: list[Callable[[WizardRun], Awaitable[None]]] = []
        self.hooks: list[Callable[[], Awaitable[None]]] = []
        self.next_id = 100

    async def active(self) -> WizardRun | None:
        return next((r for r in self.runs.values() if r.active), None)

    async def get(self, run_id: int) -> WizardRun:
        return self.runs[run_id]

    async def start(self, actor: int | None, mode: str, raw: dict[str, object] | None = None, **kw: Any) -> WizardRun:
        self.next_id += 1
        run = _run(self.next_id, mode, active=True)
        self.runs[run.id] = run
        self.started.append((mode, dict(raw or {}), bool(kw.get("confirmed"))))
        return run

    def add_finish_listener(self, listener: Callable[[WizardRun], Awaitable[None]]) -> None:
        self.listeners.append(listener)

    def add_startup_hook(self, hook: Callable[[], Awaitable[None]]) -> None:
        self.hooks.append(hook)

    async def finish(self, run_id: int, state: str = "succeeded", summary: str = "", *, notify: bool = True) -> None:
        run = replace(self.runs[run_id], active=False, state=state, summary=summary, finished_at="z")
        self.runs[run_id] = run
        if notify:
            for listener in self.listeners:
                await listener(run)


class FakeDns:
    def __init__(self) -> None:
        self.token: str | None = None
        self.records: dict[str, str] = {}

    def token_set(self) -> bool:
        return self.token is not None

    async def set_token(self, actor: int, token: str, name: str) -> object:
        if not token.startswith("cf"):
            raise InvalidOperation("bad token", key="dns_err_token_format")
        self.token = token
        return SimpleNamespace(fingerprint="ab12cd34")

    async def upsert_a(self, actor: int | None, name: str, ipv4: str, *, purpose: str, allowed: set[str] | None = None) -> object:
        assert purpose == "host"
        self.records[name] = ipv4
        return SimpleNamespace(change="created")


class FakeCert:
    def __init__(self, wizard: FakeWizard) -> None:
        self.wizard = wizard
        self.covered = False
        self.calls: list[tuple[str, list[str], bool]] = []

    async def status(self, actor: int) -> Any:
        dom = {"key_ok": True, "days_left": 80.0, "san": [DOMAIN]}
        return SimpleNamespace(adopted=self.covered, domain=dom if self.covered else None, candidates=[])

    async def start(self, actor: int, action: str, *, names: Any = (), chat_id: int | None = None,
                    message_id: int | None = None, confirmed: bool = False) -> WizardRun:
        self.calls.append((action, list(names), confirmed))
        return await self.wizard.start(actor, "cert", {"action": action}, confirmed=confirmed)


class FakeInstall:
    def __init__(self) -> None:
        self.installed: set[str] = set()

    def host_state(self, name: str) -> str:
        return "installed" if name in self.installed else "absent"

    def installable(self, name: str) -> bool:
        return name not in self.installed


class FakeFirewall:
    def __init__(self) -> None:
        self.ok = True
        self.calls = 0

    async def apply(self, reason: str) -> Any:
        self.calls += 1
        return SimpleNamespace(ok=self.ok, summary="+443/tcp +443/udp")


class FakeTotp:
    def __init__(self) -> None:
        self.on = False

    async def is_enabled(self, user_id: int) -> bool:
        return self.on


class FakeUsers:
    async def require_superadmin(self, user_id: int) -> object:
        if user_id != ADMIN:
            raise InvalidOperation("no", key="access_denied")
        return object()


class World:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.wizard = FakeWizard()
        self.dns = FakeDns()
        self.cert = FakeCert(self.wizard)
        self.install = FakeInstall()
        self.firewall = FakeFirewall()
        self.totp = FakeTotp()
        self.resolved: dict[str, list[str]] = {}
        self.shown: list[tuple[str, bool]] = []

    def service(self) -> FirstSetupService:
        async def resolve(name: str) -> list[str]:
            return self.resolved.get(name, [])

        async def host() -> list[str]:
            return [HOST_IP]

        svc = FirstSetupService(repo=WizardRunRepository(self.db), clock=ClockProvider(), users=FakeUsers(),
                                wizard=self.wizard, dns=self.dns, cert=self.cert, install=self.install,  # type: ignore[arg-type]
                                firewall=self.firewall, totp=self.totp, resolve=resolve, host_addresses=host)

        async def notify(view: Any, fresh: bool) -> None:
            self.shown.append((view.step, fresh))

        svc.notify = notify
        return svc

    async def finish_child(self, svc: FirstSetupService, state: str = "succeeded", summary: str = "") -> None:
        view = await svc.current()
        assert view is not None and view.child is not None, view
        await self.wizard.finish(view.child, state, summary)


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, role, created_at, updated_at) VALUES (?, 'SUPERADMIN', 'x', 'x')", (ADMIN,)
    )
    await db.commit()
    try:
        yield World(db)
    finally:
        await db.close()


async def test_the_whole_path_from_a_bare_host(world: World) -> None:
    svc = world.service()
    assert await svc.needed()
    view = await svc.begin(ADMIN, chat_id=1)
    assert view.step == "domain" and view.input_needed == "domain"
    with pytest.raises(SetupError):
        await svc.submit_domain(ADMIN, view.run_id, "not a domain")
    view = await svc.submit_domain(ADMIN, view.run_id, "VPN.Example.com.")
    assert view.domain == DOMAIN and view.input_needed == "token"
    with pytest.raises(InvalidOperation):
        await svc.submit_token(ADMIN, view.run_id, "nope")
    view = await svc.submit_token(ADMIN, view.run_id, TOKEN)
    # dns: the name did not resolve here → the A record → this host; cert: issue, confirmed.
    assert world.dns.records == {DOMAIN: HOST_IP}
    assert view.step == "cert" and view.waiting == "run"
    assert world.cert.calls == [("issue", [DOMAIN], True)]
    world.cert.covered = True
    await world.finish_child(svc)
    view = await svc.current()  # type: ignore[assignment]
    assert view.step == "protocols" and view.input_needed == "protocols" and view.protocols == ["xray", "hysteria2"]
    view = await svc.toggle(ADMIN, view.run_id, "socks5")
    view = await svc.toggle(ADMIN, view.run_id, "hysteria2")
    assert view.protocols == ["xray", "socks5"]
    view = await svc.confirm_protocols(ADMIN, view.run_id)
    assert view.step == "install" and world.wizard.started[-1] == ("protocol", {"proto": "xray", "domain": DOMAIN}, True)
    world.install.installed.add("xray")
    await world.finish_child(svc)
    assert world.wizard.started[-1] == ("protocol", {"proto": "socks5", "domain": DOMAIN}, True)
    world.install.installed.add("socks5")
    await world.finish_child(svc)
    view = await svc.current()  # type: ignore[assignment]
    assert view.step == "totp" and view.input_needed == "totp" and world.firewall.calls == 1
    view = await svc.totp_choice(ADMIN, view.run_id, skip=True)
    assert view.step == "selfcheck" and world.wizard.started[-1][0] == "selfcheck"
    await world.finish_child(svc, "succeeded", "green=9 yellow=1 red=0")
    assert await svc.current() is None
    last = await WizardRunRepository(world.db).last_setup()
    assert last is not None and last.state == "succeeded"
    assert not await svc.needed()
    # The token typed into the chat never lands in the setup's row.
    rows = await world.db.conn.execute_fetchall("SELECT params_json, summary FROM wizard_runs")
    assert all(TOKEN not in (r["params_json"] + r["summary"]) for r in rows)


async def test_what_is_done_already_is_skipped(world: World) -> None:
    world.dns.token = TOKEN
    world.resolved[DOMAIN] = [HOST_IP]
    world.cert.covered = True
    world.install.installed.add("xray")
    world.totp.on = True
    svc = world.service()
    view = await svc.begin(ADMIN, chat_id=1)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    assert view.step == "protocols"
    assert view.states["token"] == "skip" and view.states["dns"] == "skip" and view.states["cert"] == "skip"
    view = await svc.toggle(ADMIN, view.run_id, "hysteria2")  # off: only xray, which is there
    view = await svc.confirm_protocols(ADMIN, view.run_id)
    assert [m for m, _, _ in world.wizard.started] == ["selfcheck"], "no cert run, no install run"
    assert view.states["install"] == "ok" and view.states["totp"] == "ok"
    assert world.dns.records == {}


async def test_a_restart_resumes_where_the_setup_stopped(world: World) -> None:
    svc = world.service()
    view = await svc.begin(ADMIN, chat_id=1)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    view = await svc.submit_token(ADMIN, view.run_id, TOKEN)
    assert view.step == "cert" and view.waiting == "run"
    # The bot restarts (an install does it); the cert run finished meanwhile, unseen.
    world.cert.covered = True
    child = view.child
    assert child is not None
    await world.wizard.finish(child, notify=False)
    world.wizard.listeners.clear()
    world.wizard.hooks.clear()
    fresh = world.service()
    for hook in world.wizard.hooks:
        await hook()
    resumed = await fresh.current()
    assert resumed is not None and resumed.step == "protocols" and resumed.input_needed == "protocols"
    assert resumed.domain == DOMAIN and resumed.states["cert"] == "ok"
    assert world.shown and world.shown[-1] == ("protocols", True), "the setup's message is sent anew"
    # «Начать» again: the same setup, not a second one.
    again = await fresh.begin(ADMIN, chat_id=1)
    assert again.run_id == resumed.run_id


async def test_a_failed_step_waits_for_retry_which_checks_again(world: World) -> None:
    world.dns.token = TOKEN
    world.resolved[DOMAIN] = [HOST_IP]
    world.cert.covered = True
    world.firewall.ok = False
    svc = world.service()
    view = await svc.begin(ADMIN, chat_id=1)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    world.install.installed.update({"xray", "hysteria2"})
    view = await svc.confirm_protocols(ADMIN, view.run_id)
    assert view.step == "ufw" and view.waiting == "retry" and view.states["ufw"] == "fail"
    world.firewall.ok = True
    view = await svc.retry(ADMIN, view.run_id)
    assert view.states["ufw"] == "ok" and view.step == "totp"


async def test_a_failed_install_run_is_retried_with_a_new_run(world: World) -> None:
    world.dns.token = TOKEN
    world.resolved[DOMAIN] = [HOST_IP]
    world.cert.covered = True
    svc = world.service()
    view = await svc.begin(ADMIN, chat_id=1)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    view = await svc.toggle(ADMIN, view.run_id, "hysteria2")
    view = await svc.confirm_protocols(ADMIN, view.run_id)
    await world.finish_child(svc, "rolled_back", "verify: tls")
    view = await svc.current()  # type: ignore[assignment]
    assert view.step == "install" and view.waiting == "retry" and "rolled_back" in view.note
    view = await svc.retry(ADMIN, view.run_id)
    assert [m for m, _, _ in world.wizard.started] == ["protocol", "protocol"], "a new run, not the failed one"


async def test_a_red_selfcheck_fails_the_setup_step(world: World) -> None:
    world.dns.token = TOKEN
    world.resolved[DOMAIN] = [HOST_IP]
    world.cert.covered = True
    world.totp.on = True
    world.install.installed.add("xray")
    svc = world.service()
    view = await svc.begin(ADMIN, chat_id=1)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    view = await svc.toggle(ADMIN, view.run_id, "hysteria2")
    await svc.confirm_protocols(ADMIN, view.run_id)
    await world.finish_child(svc, "succeeded", "green=5 yellow=0 red=2")
    view = await svc.current()  # type: ignore[assignment]
    assert view.step == "selfcheck" and view.waiting == "retry"


async def test_a_busy_wizard_is_waited_for(world: World) -> None:
    world.dns.token = TOKEN
    world.resolved[DOMAIN] = [HOST_IP]
    other = await world.wizard.start(ADMIN, "update")
    svc = world.service()
    view = await svc.begin(ADMIN, chat_id=1)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    assert view.step == "cert" and view.waiting == "run" and view.child is None and "update" in view.note
    await world.wizard.finish(other.id)
    view = await svc.current()  # type: ignore[assignment]
    assert view.child is not None and world.cert.calls, "the cert run starts once the lock is free"


async def test_only_a_superadmin_and_only_the_current_step(world: World) -> None:
    svc = world.service()
    with pytest.raises(InvalidOperation):
        await svc.begin(ADMIN + 1, chat_id=1)
    view = await svc.begin(ADMIN, chat_id=1)
    with pytest.raises(SetupError):
        await svc.confirm_protocols(ADMIN, view.run_id)
    cancelled = await svc.cancel(ADMIN, view.run_id)
    assert cancelled.finished == "cancelled" and await svc.current() is None


async def test_the_next_run_waits_for_the_unit_of_the_one_before(world: World) -> None:
    """The launcher refuses while any wizard unit is active: the setup waits for the
    previous run's unit to end, and the monitor's tick starts the next run then."""
    world.dns.token = TOKEN
    world.resolved[DOMAIN] = [HOST_IP]
    world.cert.covered = True
    alive: dict[int, bool] = {}

    async def unit_alive(run_id: int) -> bool | None:
        return alive.get(run_id, False)

    world.wizard.unit_alive = unit_alive  # type: ignore[attr-defined]
    ticks: list[Callable[[], Awaitable[bool]]] = []
    world.wizard.add_tick_hook = ticks.append  # type: ignore[attr-defined]
    svc = world.service()
    view = await svc.begin(ADMIN, chat_id=1)
    view = await svc.submit_domain(ADMIN, view.run_id, DOMAIN)
    view = await svc.confirm_protocols(ADMIN, view.run_id)
    first = view.child
    assert first is not None
    alive[first] = True  # its unit outlives its last status line
    world.install.installed.add("xray")
    await world.wizard.finish(first)
    view = await svc.current()  # type: ignore[assignment]
    assert view.child is None and view.waiting == "run" and "unit" in view.note
    assert [m for m, _, _ in world.wizard.started] == ["protocol"]
    assert [await tick() for tick in ticks] == [True]  # still waits: the monitor polls often
    alive[first] = False
    assert [await tick() for tick in ticks] == [False]
    view = await svc.current()  # type: ignore[assignment]
    assert view.child is not None and [m for m, _, _ in world.wizard.started] == ["protocol", "protocol"]
