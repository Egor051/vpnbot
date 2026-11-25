"""«🧭 Первичная настройка» — the bot's first setup after scripts/install.sh (docs/first-setup.md).

After the claim a bot has no protocol. The first setup walks the superadmin through what
the rest of the bot already knows how to do, in this order, and never does any of it a
second way:

  domain     the name the server serves; it must resolve to this host (A record) —
             checked here, else the dns step creates it
  token      the bot's ONE Cloudflare token (services/dns.py: checked against the zone,
             the message deleted at once) — skipped when it is set
  dns        the A record of the domain → this host, through DnsService.upsert_a
             (purpose 'host') — skipped when the domain already resolves here
  cert       a run of the wizard's «cert» mode: adopt the acme.sh domain that covers
             the name, else issue — skipped when the bot's certificate covers it
  protocols  the superadmin picks (default VLESS REALITY + Hysteria2), then confirms
             the whole rest at once (TOTP when it is on)
  install    one run of the wizard's «protocol» mode per protocol not on the host
  ufw        vpn-bot-ufw-apply apply (its own dead-man guards a policy change)
  totp       optional: the second factor (the existing enrollment), or skipped
  selfcheck  a run of the wizard's «selfcheck» mode: green (no red item) ends the setup

RESUMABLE. Every step is idempotent: it asks the host / the services whether its work is
done first and only acts on what is missing. The progress — each step's state, the domain,
the protocols, the run the setup waits for — is one row of ``wizard_runs`` (mode
``setup``, not holding the wizard's lock: its steps are runs of other modes, which do).
After a restart (an install restarts the bot) the open setup is found and continues where
it stopped; a run it waited for that finished meanwhile moves it on (WizardService's
finish listeners); a failed step waits for «🔁 Повторить».
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from adapters.clock import ClockProvider
from models.dto import WizardRun
from repositories.wizard_runs import WizardRunRepository
from services.errors import InvalidOperation, ServiceError
from services.wizard_modes import MODES

logger = logging.getLogger(__name__)

STEPS: tuple[str, ...] = ("domain", "token", "dns", "cert", "protocols", "install", "ufw", "totp", "selfcheck")
INPUT_STEPS = frozenset({"domain", "token", "protocols", "totp"})
PROTOCOL_CHOICES: tuple[str, ...] = MODES["protocol"].params["proto"].choices
DEFAULT_PROTOCOLS: tuple[str, ...] = ("xray", "hysteria2")
CERT_MIN_DAYS = 7
DNS_PURPOSE = "host"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class SetupError(InvalidOperation):
    """A refused step the superadmin must see (``key`` is the i18n message)."""


# --------------------------------------------------------------------------- #
# What the setup uses — the real services in the bot, fakes in the tests
# --------------------------------------------------------------------------- #
class _Users(Protocol):
    async def require_superadmin(self, user_id: int) -> object: ...


class _Wizard(Protocol):
    async def active(self) -> WizardRun | None: ...

    async def get(self, run_id: int) -> WizardRun: ...

    async def start(self, actor_user_id: int | None, mode_key: str, raw_params: dict[str, object] | None = None, *,
                    chat_id: int | None = None, message_id: int | None = None, origin: str = "manual",
                    confirmed: bool = False) -> WizardRun: ...

    def add_finish_listener(self, listener: Callable[[WizardRun], Awaitable[None]]) -> None: ...


class _Dns(Protocol):
    def token_set(self) -> bool: ...

    async def set_token(self, actor_user_id: int, token: str, name: str) -> object: ...

    async def upsert_a(self, actor_user_id: int | None, name: str, ipv4: str, *, purpose: str,
                       allowed: set[str] | None = None) -> object: ...


class _Cert(Protocol):
    async def status(self, actor_user_id: int) -> Any: ...

    async def start(self, actor_user_id: int, action: str, *, names: Sequence[str] = (), chat_id: int | None = None,
                    message_id: int | None = None, confirmed: bool = False) -> WizardRun: ...


class _Install(Protocol):
    def host_state(self, name: str) -> str: ...

    def installable(self, name: str) -> bool: ...


class _Firewall(Protocol):
    async def apply(self, reason: str) -> Any: ...


class _Totp(Protocol):
    async def is_enabled(self, user_id: int) -> bool: ...


Resolver = Callable[[str], Awaitable[list[str]]]
HostAddresses = Callable[[], Awaitable[list[str]]]
Notify = Callable[["SetupView", bool], Awaitable[None]]


# --------------------------------------------------------------------------- #
# The state
# --------------------------------------------------------------------------- #
@dataclass
class SetupView:
    """One setup as the bot shows it."""

    run_id: int
    started_by: int | None
    chat_id: int | None
    message_id: int | None
    step: str
    states: dict[str, str]
    domain: str = ""
    protocols: list[str] = field(default_factory=list)
    child: int | None = None
    waiting: str = ""            # what the setup waits for: input | run | retry | ""
    note: str = ""               # the last result / error line
    finished: str = ""           # succeeded | failed | cancelled once over
    notes: dict[str, str] = field(default_factory=dict)  # per step: what it found or did

    @property
    def input_needed(self) -> str:
        return self.step if self.waiting == "input" else ""

    def params(self) -> dict[str, str]:
        return {
            "states": json.dumps(self.states, sort_keys=True), "domain": self.domain,
            "protocols": ",".join(self.protocols), "child": str(self.child or ""), "waiting": self.waiting,
            "note": self.note, "notes": json.dumps(self.notes, sort_keys=True, ensure_ascii=False),
            "message_id": str(self.message_id or ""),
        }


def _view(run: WizardRun) -> SetupView:
    p = run.params

    def loads(key: str) -> dict[str, str]:
        try:
            data = json.loads(p.get(key) or "{}")
        except ValueError:
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    states = {s: "wait" for s in STEPS}
    states.update({k: v for k, v in loads("states").items() if k in states})
    child = p.get("child") or ""
    message = p.get("message_id") or ""
    protocols = [x for x in (p.get("protocols") or "").split(",") if x in PROTOCOL_CHOICES]
    return SetupView(
        run_id=run.id, started_by=run.started_by, chat_id=run.chat_id,
        message_id=int(message) if message.isdigit() else run.message_id,
        step=run.current_step or STEPS[0], states=states, domain=p.get("domain") or "",
        protocols=protocols, child=int(child) if child.isdigit() else None, waiting=p.get("waiting") or "",
        note=p.get("note") or "", notes=loads("notes"),
        finished=run.state if run.state in ("succeeded", "failed", "cancelled") and run.finished_at else "",
    )


# --------------------------------------------------------------------------- #
# The service
# --------------------------------------------------------------------------- #
class FirstSetupService:
    def __init__(
        self,
        *,
        repo: WizardRunRepository,
        clock: ClockProvider,
        users: _Users,
        wizard: _Wizard | None,
        dns: _Dns | None,
        cert: _Cert | None,
        install: _Install | None,
        firewall: _Firewall | None,
        totp: _Totp | None,
        resolve: Resolver,
        host_addresses: HostAddresses,
    ) -> None:
        self.repo = repo
        self.clock = clock
        self.users = users
        self.wizard = wizard
        self.dns = dns
        self.cert = cert
        self.install = install
        self.firewall = firewall
        self.totp = totp
        self.resolve = resolve
        self.host_addresses = host_addresses
        self.notify: Notify | None = None
        if wizard is not None:
            wizard.add_finish_listener(self.on_run_finished)
            add_hook = getattr(wizard, "add_startup_hook", None)
            if callable(add_hook):
                add_hook(self.resume)

    # ------------------------------------------------------------- reading
    def available(self) -> bool:
        return all(x is not None for x in (self.wizard, self.dns, self.cert, self.install))

    def nothing_installed(self) -> bool:
        """No protocol of the bot's is on the host (a fresh install.sh host)."""
        if self.install is None:
            return False
        states = [self.install.host_state(p) for p in PROTOCOL_CHOICES]
        return all(s in ("absent", "uninstalled") for s in states)

    async def needed(self) -> bool:
        """Offered on its own after the claim: available, nothing installed, none done."""
        if not self.available() or not self.nothing_installed():
            return False
        last = await self.repo.last_setup()
        return last is None or last.state != "succeeded"

    async def current(self) -> SetupView | None:
        run = await self.repo.open_setup()
        return _view(run) if run is not None else None

    async def get(self, run_id: int) -> SetupView:
        run = await self.repo.get(run_id)
        if run is None or run.mode != "setup":
            raise SetupError("нет такой настройки", key="setup_not_found")
        return _view(run)

    # ------------------------------------------------------------- saving
    async def _save(self, view: SetupView) -> None:
        summary = view.note[:500]
        await self.repo.save_setup(view.run_id, self.clock.now(), step=view.step, params=view.params(), summary=summary)

    async def _emit(self, view: SetupView, fresh: bool = False) -> None:
        if self.notify is not None:
            try:
                await self.notify(view, fresh)
            except Exception as exc:  # the setup goes on; the screen is shown on the next pass
                logger.warning("first setup %d: message failed (%s: %s)", view.run_id, type(exc).__name__, exc)

    def _mark(self, view: SetupView, step: str, state: str, note: str = "") -> None:
        view.states[step] = state
        if note:
            view.notes[step] = note[:300]

    # ------------------------------------------------------------- lifecycle
    async def begin(self, actor: int, *, chat_id: int | None) -> SetupView:
        """The open setup (resumed), else a new one. SUPERADMIN."""
        await self.users.require_superadmin(actor)
        if not self.available():
            raise ServiceError("первичная настройка недоступна", key="setup_unavailable")
        current = await self.current()
        if current is not None:
            return await self.advance(current)
        run = await self.repo.create_setup(started_by=actor, chat_id=chat_id, params={}, now=self.clock.now())
        view = _view(run)
        view.protocols = list(DEFAULT_PROTOCOLS)
        view.step = STEPS[0]
        await self._save(view)
        return await self.advance(view)

    async def cancel(self, actor: int, run_id: int) -> SetupView:
        await self.users.require_superadmin(actor)
        view = await self.get(run_id)
        await self.repo.finish_setup(run_id, "cancelled", "cancelled by a superadmin", self.clock.now())
        view.finished = "cancelled"
        return view

    async def attach_message(self, run_id: int, message_id: int) -> None:
        view = await self.get(run_id)
        view.message_id = message_id
        await self._save(view)

    # ------------------------------------------------------------- inputs
    async def submit_domain(self, actor: int, run_id: int, text: str) -> SetupView:
        await self.users.require_superadmin(actor)
        view = await self._at(run_id, "domain")
        domain = (text or "").strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(domain):
            raise SetupError("не доменное имя", key="setup_bad_domain", params={"value": domain[:80]})
        view.domain = domain
        self._mark(view, "domain", "ok", domain)
        view.waiting = ""
        view.step = "token"
        await self._save(view)
        return await self.advance(view)

    async def submit_token(self, actor: int, run_id: int, token: str) -> SetupView:
        """The token typed into the chat (the handler deleted the message already): checked
        against the domain's zone BEFORE it is stored (DnsService.set_token)."""
        await self.users.require_superadmin(actor)
        view = await self._at(run_id, "token")
        assert self.dns is not None
        await self.dns.set_token(actor, token, view.domain)
        self._mark(view, "token", "ok", "stored")
        view.waiting = ""
        view.step = "dns"
        await self._save(view)
        return await self.advance(view)

    async def toggle(self, actor: int, run_id: int, proto: str) -> SetupView:
        await self.users.require_superadmin(actor)
        view = await self._at(run_id, "protocols")
        if proto not in PROTOCOL_CHOICES:
            raise SetupError("нет такого протокола", key="setup_bad_protocol")
        view.protocols = [p for p in PROTOCOL_CHOICES if (p in view.protocols) != (p == proto)]
        await self._save(view)
        return view

    async def confirm_protocols(self, actor: int, run_id: int) -> SetupView:
        """The one confirmation of everything that follows (the handler asked TOTP)."""
        await self.users.require_superadmin(actor)
        view = await self._at(run_id, "protocols")
        if not view.protocols:
            raise SetupError("не выбран ни один протокол", key="setup_no_protocol")
        self._mark(view, "protocols", "ok", ", ".join(view.protocols))
        view.waiting = ""
        view.step = "install"
        await self._save(view)
        return await self.advance(view)

    async def totp_choice(self, actor: int, run_id: int, *, skip: bool) -> SetupView:
        """«Пропустить», or «▶️ Продолжить» after the enrollment (checked: TOTP is on)."""
        await self.users.require_superadmin(actor)
        view = await self._at(run_id, "totp")
        if skip:
            self._mark(view, "totp", "skip", "skipped")
        elif self.totp is not None and await self.totp.is_enabled(actor):
            self._mark(view, "totp", "ok", "on")
        else:
            raise SetupError("TOTP ещё не включён", key="setup_totp_not_on")
        view.waiting = ""
        view.step = "selfcheck"
        await self._save(view)
        return await self.advance(view)

    async def retry(self, actor: int, run_id: int) -> SetupView:
        """A failed step again (each step re-checks the host first)."""
        await self.users.require_superadmin(actor)
        view = await self.get(run_id)
        if view.finished:
            raise SetupError("настройка уже завершена", key="setup_finished")
        if view.states.get(view.step) == "fail":
            view.states[view.step] = "wait"
        view.waiting = ""
        view.note = ""
        view.child = None  # the failed run stays failed: the step starts a new one
        await self._save(view)
        return await self.advance(view)

    async def _at(self, run_id: int, step: str) -> SetupView:
        view = await self.get(run_id)
        if view.finished or view.step != step:
            raise SetupError("этот шаг уже пройден", key="setup_step_stale")
        return view

    # ------------------------------------------------------------- the driver
    async def on_run_finished(self, run: WizardRun) -> None:
        """A wizard run ended: the setup that waits for it (or for the lock) moves on."""
        view = await self.current()
        if view is None or view.waiting != "run":
            return
        if view.child is not None and view.child != run.id:
            return
        try:
            advanced = await self.advance(view)
        except Exception as exc:
            logger.warning("first setup %d: could not move on after run #%d (%s: %s)", view.run_id, run.id,
                           type(exc).__name__, exc)
            return
        await self._emit(advanced, fresh=True)

    async def resume(self) -> None:
        """At start: an open setup that waits for nothing it can see (a run that finished
        while the bot was down) moves on; one that waits for input stays."""
        view = await self.current()
        if view is None:
            return
        logger.info("First setup: resuming #%d at step %s", view.run_id, view.step)
        if view.waiting == "run" and view.child is not None and self.wizard is not None:
            child = await self.wizard.get(view.child)
            if child.active:
                return  # still running: its finish moves the setup on
        if view.waiting in ("input", "retry"):
            return
        await self._emit(await self.advance(view), fresh=True)

    async def advance(self, view: SetupView) -> SetupView:
        """Run the steps that need nobody, from the current one, until one needs input,
        waits for a run, failed, or the setup is done."""
        if view.finished:
            return view
        actor = view.started_by
        assert actor is not None
        while True:
            step = view.step
            if view.waiting in ("input", "retry"):
                break
            handler = getattr(self, f"_step_{step}")
            try:
                done = await handler(view, actor)
            except (InvalidOperation, ServiceError) as exc:
                self._fail(view, step, _err(exc))
                break
            except Exception as exc:
                logger.warning("first setup %d: step %s crashed (%s: %s)", view.run_id, step, type(exc).__name__, exc)
                self._fail(view, step, f"{type(exc).__name__}: {exc}")
                break
            if not done:
                break
            index = STEPS.index(step)
            if index + 1 >= len(STEPS):
                await self._save(view)
                await self.repo.finish_setup(view.run_id, "succeeded", view.note or "ok", self.clock.now())
                view.finished = "succeeded"
                return view
            view.step = STEPS[index + 1]
            view.child = None
        await self._save(view)
        return view

    def _fail(self, view: SetupView, step: str, why: str) -> None:
        self._mark(view, step, "fail", why)
        view.note = why
        view.waiting = "retry"

    async def _wait_run(self, view: SetupView, step: str, start: Callable[[], Awaitable[WizardRun]]) -> bool | None:
        """The child run of *step*: None = started or still running (wait); True = it
        succeeded; False = it failed (the step failed)."""
        assert self.wizard is not None
        if view.child is not None:
            run = await self.wizard.get(view.child)
            if run.active:
                view.waiting = "run"
                return None
            view.waiting = ""
            if run.state == "succeeded":
                return True
            self._fail(view, step, f"run #{run.id} {run.state}: {run.summary[:200]}")
            return False
        active = await self.wizard.active()
        if active is not None:
            view.waiting = "run"
            view.note = f"waiting for run #{active.id} ({active.mode})"
            return None
        run = await start()
        view.child = run.id
        view.waiting = "run"
        self._mark(view, step, "run")
        return None

    # ------------------------------------------------------------- the steps
    async def _step_domain(self, view: SetupView, actor: int) -> bool:
        if view.domain:
            self._mark(view, "domain", "ok", view.domain)
            return True
        view.waiting = "input"
        return False

    async def _step_token(self, view: SetupView, actor: int) -> bool:
        assert self.dns is not None
        if self.dns.token_set():
            self._mark(view, "token", "ok" if view.states.get("token") == "ok" else "skip", "the bot's token is set")
            return True
        view.waiting = "input"
        return False

    async def _resolves_here(self, domain: str) -> tuple[bool, list[str], list[str]]:
        resolved = await self.resolve(domain)
        mine = await self.host_addresses()
        return bool(set(resolved) & set(mine)), resolved, mine

    async def _step_dns(self, view: SetupView, actor: int) -> bool:
        assert self.dns is not None
        here, resolved, mine = await self._resolves_here(view.domain)
        if here:
            self._mark(view, "dns", "ok" if view.states.get("dns") == "ok" else "skip",
                       f"{view.domain} → {', '.join(resolved)} (this host)")
            return True
        if not mine:
            raise SetupError("адрес сервера не найден", key="setup_no_host_address")
        result = await self.dns.upsert_a(actor, view.domain, mine[0], purpose=DNS_PURPOSE)
        change = getattr(result, "change", "written")
        self._mark(view, "dns", "ok", f"{view.domain} → {mine[0]} ({change}; was {', '.join(resolved) or 'none'})")
        return True

    async def _step_cert(self, view: SetupView, actor: int) -> bool:
        assert self.cert is not None
        if view.child is None:
            status = await self.cert.status(actor)
            covered = _cert_covers(status, view.domain)
            if covered:
                self._mark(view, "cert", "ok" if view.states.get("cert") in ("ok", "run") else "skip",
                           f"the bot's certificate covers {view.domain}")
                return True
            candidates = [c for c in (getattr(status, "candidates", []) or []) if c]
            adopt = (not getattr(status, "adopted", False)) and view.domain in candidates
            action, names = ("adopt", [view.domain]) if adopt else ("issue", [view.domain])
            view.notes["cert"] = f"{action} {view.domain}"
            cert = self.cert

            async def start() -> WizardRun:
                return await cert.start(actor, action, names=names, chat_id=view.chat_id, confirmed=True)

            return bool(await self._wait_run(view, "cert", start))
        result = await self._wait_run(view, "cert", _never)
        if result:
            self._mark(view, "cert", "ok", view.notes.get("cert", "issued"))
        return bool(result)

    async def _step_protocols(self, view: SetupView, actor: int) -> bool:
        if view.states.get("protocols") == "ok" and view.protocols:
            return True
        view.waiting = "input"
        return False

    async def _step_install(self, view: SetupView, actor: int) -> bool:
        assert self.install is not None and self.wizard is not None
        if view.child is not None:
            result = await self._wait_run(view, "install", _never)
            if result is None or result is False:
                return False
            view.child = None
        for proto in view.protocols:
            if self.install.host_state(proto) == "installed":
                continue
            if not self.install.installable(proto):
                raise SetupError("протокол не ставится", key="setup_cannot_install", params={"name": proto})
            view.notes["install"] = f"installing {proto}"
            await self._wait_run(view, "install", self._install_starter(actor, view, proto))
            return False
        self._mark(view, "install", "ok", ", ".join(f"{p} ✓" for p in view.protocols))
        return True

    def _install_starter(self, actor: int, view: SetupView, proto: str) -> Callable[[], Awaitable[WizardRun]]:
        wizard = self.wizard
        assert wizard is not None

        async def start() -> WizardRun:
            return await wizard.start(actor, "protocol", {"proto": proto, "domain": view.domain},
                                      chat_id=view.chat_id, confirmed=True)

        return start

    async def _step_ufw(self, view: SetupView, actor: int) -> bool:
        if self.firewall is None:
            self._mark(view, "ufw", "skip", "no firewall helper in this process")
            return True
        result = await self.firewall.apply("first setup")
        if not getattr(result, "ok", False):
            raise SetupError(str(getattr(result, "summary", "")), key="setup_ufw_failed",
                             params={"summary": str(getattr(result, "summary", ""))[:200]})
        self._mark(view, "ufw", "ok", str(getattr(result, "summary", "")))
        return True

    async def _step_totp(self, view: SetupView, actor: int) -> bool:
        if view.states.get("totp") in ("ok", "skip"):
            return True
        if self.totp is None:
            self._mark(view, "totp", "skip", "TOTP is not available here")
            return True
        if await self.totp.is_enabled(actor):
            self._mark(view, "totp", "ok", "on")
            return True
        view.waiting = "input"
        return False

    async def _step_selfcheck(self, view: SetupView, actor: int) -> bool:
        assert self.wizard is not None
        wizard = self.wizard
        if view.child is None:
            async def start() -> WizardRun:
                return await wizard.start(actor, "selfcheck", {}, chat_id=view.chat_id)

            return bool(await self._wait_run(view, "selfcheck", start))
        run = await wizard.get(view.child)
        result = await self._wait_run(view, "selfcheck", _never)
        if not result:
            return False
        counts = dict(re.findall(r"(green|yellow|red)=(\d+)", run.summary))
        if int(counts.get("red", "0")):
            self._fail(view, "selfcheck", f"self-check: {run.summary}")
            view.child = None
            return False
        self._mark(view, "selfcheck", "ok", run.summary or "green")
        view.note = "done"
        return True


async def _never() -> WizardRun:  # pragma: no cover — a step only waits for a run it started
    raise AssertionError("no new run here")


def _err(exc: Exception) -> str:
    key = getattr(exc, "key", None)
    return f"{key}: {exc}" if key else str(exc)


def _cert_covers(status: Any, domain: str) -> bool:
    if status is None or not getattr(status, "adopted", False):
        return False
    dom = getattr(status, "domain", None)
    if not isinstance(dom, dict) or dom.get("key_ok") is not True:
        return False
    days = dom.get("days_left")
    if not isinstance(days, (int, float)) or days < CERT_MIN_DAYS:
        return False
    for entry in (str(e).lower() for e in dom.get("san") or []):
        if entry == domain or (entry.startswith("*.") and domain.count(".") == entry.count(".")
                               and domain.split(".", 1)[1] == entry[2:]):
            return True
    return False


async def host_ipv4s(shell: Any) -> list[str]:
    """The host's global IPv4 addresses (`ip -4 -o addr show scope global`), public first."""
    import ipaddress

    result = await shell.run(["ip", "-4", "-o", "addr", "show", "scope", "global"], timeout=15)
    found: list[str] = []
    for m in re.finditer(r"\binet\s+([0-9.]+)/", result.stdout or ""):
        with contextlib.suppress(ValueError):
            found.append(str(ipaddress.IPv4Address(m.group(1))))
    return sorted(set(found), key=lambda a: (ipaddress.IPv4Address(a).is_private, a))

