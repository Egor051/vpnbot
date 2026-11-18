"""Shared pytest fixtures for CLI and integration tests."""
from __future__ import annotations

import asyncio
import contextlib
import errno
import importlib.machinery
import importlib.util
import io
import ipaddress
import os
import re
import socket
import sys
import sysconfig
import threading
import traceback
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple

import aiosqlite
import pytest

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# No network from a test
#
# deploy.sh Phase 1 runs this suite ON the production host. A test that reaches
# the real network there does not just flake: it talks to the live services. The
# relay health test did exactly that — build_relay_health_supervisor wired the
# real udp_relay_probe, whose control probe found the live hysteria-server on
# 127.0.0.1:443 and then sent a QUIC packet to the production relay named in the
# test's constant. In CI nothing listens on 127.0.0.1:443, so it was green there.
#
# The guard below makes that class impossible to miss. For the duration of every
# test it wraps the socket entry points (and asyncio's loop.getaddrinfo, so an
# async lookup is reported with its caller's stack, not the executor thread's);
# any attempt to reach a non-loopback
# address, or to resolve any name but ``localhost``, is RECORDED and refused with
# the errno an offline host would give. The record is what fails the test (on
# teardown, with the address, the port and the stack): the probes swallow every
# exception by design, so an exception alone would only make the test pass
# silently with another result.
# --------------------------------------------------------------------------- #
_LOOPBACK_NAMES = frozenset({"localhost", "localhost."})


@dataclass(frozen=True, slots=True)
class NetworkViolation:
    call: str
    target: str
    port: object
    thread: str
    stack: str

    def render(self) -> str:
        return f"  {self.call}({self.target!r}, port={self.port!r}) [thread {self.thread}]\n{self.stack}"


def _host_text(host: object) -> str | None:
    if isinstance(host, bytes):
        return host.decode("ascii", "replace")
    return host if isinstance(host, str) else None


def _is_loopback_ip(text: str) -> bool | None:
    """True/False for an IP literal (loopback or the unspecified address, which
    Linux connects to locally), None when *text* is not an IP literal at all."""
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def _is_local_destination(host: str) -> bool:
    loopback = _is_loopback_ip(host)
    if loopback is not None:
        return loopback
    return host.lower() in _LOOPBACK_NAMES


def _is_local_lookup(host: object) -> bool:
    """A name resolution that never leaves the box: no host (a passive bind), an
    IP literal (no DNS query; the connect that follows is checked on its own) or
    ``localhost``."""
    text = _host_text(host)
    if not text:
        return True
    return _is_loopback_ip(text) is not None or text.lower() in _LOOPBACK_NAMES


_STDLIB_DIR = sysconfig.get_paths()["stdlib"]
_RUNNER_PARTS = tuple(f"{os.sep}{name}{os.sep}" for name in ("_pytest", "pytest", "pluggy", "pytest_asyncio"))


def _caller_stack() -> str:
    """The frames that matter: the guard's own, the standard library's and pytest's
    left out (a running coroutine's awaiting chain is on the stack, so an async test
    shows the probe and the test that called it)."""
    frames = [f for f in traceback.extract_stack() if f.filename != __file__]
    ours = [
        f for f in frames
        if not f.filename.startswith((_STDLIB_DIR, "<frozen"))
        and not any(part in f.filename for part in _RUNNER_PARTS)
    ]
    return "".join(traceback.format_list((ours or frames)[-15:])).rstrip()


class NetworkGuard:
    """Wraps the socket entry points: records — and refuses — every connection or
    datagram to a non-loopback address and every DNS lookup but ``localhost``.

    Local servers on 127.0.0.1/::1 (a test's own listener) and AF_UNIX sockets are
    untouched. It patches through its OWN MonkeyPatch, never the shared
    ``monkeypatch``: a test that stubs ``socket.getaddrinfo`` itself patches over
    the guard and is undone first, then the guard goes. A guard installed inside
    another one refuses before the outer one is reached (tests of the guard).
    """

    def __init__(self) -> None:
        self.violations: list[NetworkViolation] = []
        self._lock = threading.Lock()
        self._patch = pytest.MonkeyPatch()

    def _record(self, call: str, target: str, port: object) -> None:
        violation = NetworkViolation(call, target, port, threading.current_thread().name, _caller_stack())
        with self._lock:
            self.violations.append(violation)

    def _refuse_lookup(self, call: str, host: object, port: object) -> None:
        self._record(call, str(_host_text(host)), port)
        raise socket.gaierror(socket.EAI_NONAME, f"{call}({host!r}) refused: no DNS in tests (tests/conftest.py)")

    def _refuse(self, call: str, target: tuple[str, object]) -> OSError:
        self._record(call, *target)
        return OSError(errno.ENETUNREACH, f"{call} to {target[0]}:{target[1]} refused: no network in tests")

    @staticmethod
    def _outside(sock: socket.socket, address: object) -> tuple[str, object] | None:
        """(host, port) when *address* leaves the box, None when it does not."""
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or not isinstance(address, tuple) or not address:
            return None
        host = _host_text(address[0])
        if host is None or _is_local_destination(host):
            return None
        return host, address[1] if len(address) > 1 else None

    def install(self) -> None:
        guard = self
        real_loop_getaddrinfo = asyncio.base_events.BaseEventLoop.getaddrinfo
        real_getaddrinfo = socket.getaddrinfo
        real_gethostbyname = socket.gethostbyname
        real_gethostbyname_ex = socket.gethostbyname_ex
        real_connect = socket.socket.connect
        real_connect_ex = socket.socket.connect_ex
        real_sendto = socket.socket.sendto
        real_sendmsg = socket.socket.sendmsg

        async def loop_getaddrinfo(loop: Any, host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            # asyncio resolves in an executor thread, whose stack shows nothing of
            # the caller: refuse here, in the task, where the stack is the caller's.
            if not _is_local_lookup(host):
                guard._refuse_lookup("getaddrinfo", host, port)
            return await real_loop_getaddrinfo(loop, host, port, *args, **kwargs)

        def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            if not _is_local_lookup(host):
                guard._refuse_lookup("getaddrinfo", host, port)
            return real_getaddrinfo(host, port, *args, **kwargs)

        def gethostbyname(host: str) -> str:
            if not _is_local_lookup(host):
                guard._refuse_lookup("gethostbyname", host, None)
            return real_gethostbyname(host)

        def gethostbyname_ex(host: str) -> tuple[str, list[str], list[str]]:
            if not _is_local_lookup(host):
                guard._refuse_lookup("gethostbyname_ex", host, None)
            return real_gethostbyname_ex(host)

        def connect(self: socket.socket, address: Any) -> None:
            target = guard._outside(self, address)
            if target is not None:
                raise guard._refuse("connect", target)
            real_connect(self, address)

        def connect_ex(self: socket.socket, address: Any) -> int:
            target = guard._outside(self, address)
            if target is not None:
                guard._record("connect_ex", *target)
                return errno.ENETUNREACH
            return real_connect_ex(self, address)

        def sendto(self: socket.socket, data: Any, *args: Any) -> int:
            # sendto(data, address) or sendto(data, flags, address)
            target = guard._outside(self, args[-1]) if args else None
            if target is not None:
                raise guard._refuse("sendto", target)
            return real_sendto(self, data, *args)

        def sendmsg(self: socket.socket, buffers: Any, *args: Any) -> int:
            # sendmsg(buffers[, ancdata[, flags[, address]]])
            target = guard._outside(self, args[2]) if len(args) >= 3 else None
            if target is not None:
                raise guard._refuse("sendmsg", target)
            return real_sendmsg(self, buffers, *args)

        self._patch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", loop_getaddrinfo)
        self._patch.setattr(socket, "getaddrinfo", getaddrinfo)
        self._patch.setattr(socket, "gethostbyname", gethostbyname)
        self._patch.setattr(socket, "gethostbyname_ex", gethostbyname_ex)
        self._patch.setattr(socket.socket, "connect", connect)
        self._patch.setattr(socket.socket, "connect_ex", connect_ex)
        self._patch.setattr(socket.socket, "sendto", sendto)
        self._patch.setattr(socket.socket, "sendmsg", sendmsg)

    def uninstall(self) -> None:
        self._patch.undo()

    def report(self, nodeid: str) -> str:
        return (
            f"{nodeid} reached the network outside loopback ({len(self.violations)} time(s)). "
            "This suite runs on the production host (deploy.sh Phase 1): stub the probe/client "
            "instead of reaching a real address.\n" + "\n".join(v.render() for v in self.violations)
        )


@pytest.fixture(autouse=True)
def _forbid_network(request: pytest.FixtureRequest) -> Generator[None, None, None]:
    """Fail the test (on teardown) when it reached the network outside loopback.

    Defined FIRST among the autouse fixtures, so it is set up first and torn down
    last: a connection opened while another fixture tears down is still seen. Fix
    a flagged test by stubbing what it reaches — never by allowlisting an address.
    """
    guard = NetworkGuard()
    guard.install()
    try:
        yield
    finally:
        guard.uninstall()
    if guard.violations:
        pytest.fail(guard.report(request.node.nodeid), pytrace=False)


# Prod env-var families the settings loader reads. In tests a Settings build must
# come only from what the test sets explicitly (monkeypatch.setenv or an explicit
# env_path), NEVER from the host's ambient environment or the production
# /opt/vpn-service/.env that python-dotenv would auto-discover from the cwd. See
# _isolate_settings_env below. ANOMALY_ is included because
# ANOMALY_HYSTERIA2_MAX_CONN cross-validates against HYSTERIA2_STATS_SECRET (a
# Hysteria2-family value) — the two must be cleared together or a leaked
# HYSTERIA2_STATS_SECRET-less-but-ANOMALY_HYSTERIA2_MAX_CONN-set combination raises
# a spurious SettingsError.
_ISOLATED_ENV_PREFIXES: tuple[str, ...] = (
    "HYSTERIA2_",
    "SOCKS5_",
    "XRAY_",
    "MTPROTO_",
    "WARP_",
    "ANOMALY_",
    # SUBSCRIPTION_* for the same reason: the box's live .env sets the endpoint's
    # bind/TLS values, and a test asserting the documented defaults would read the
    # host's ports instead (green in CI, red on the box).
    "SUBSCRIPTION_",
    # RELAY_* for the same reason: they seed the relays table and make the bot
    # warn that they are ignored, so a host's live RELAY_* would change what a
    # test of that behaviour observes.
    "RELAY_",
    # TELEGRAM_API_BASE points the bot at another Bot API server (the installer's
    # CI mock): a host or CI job exporting it must not redirect a test's bot.
    "TELEGRAM_",
)


@pytest.fixture(autouse=True)
def _isolate_settings_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Settings construction deterministic and host-independent.

    Two leaks, both a host-only class (cf. #239/#241/#242 — green in clean CI, red
    on the box, because the box's live state bleeds in):

    1. ``load_settings()`` with no explicit path calls ``load_dotenv(None)``, which
       walks up from the cwd (``/opt/vpn-service`` in the test run) and slurps the
       **production** ``.env`` into ``os.environ`` — so a test that carefully
       ``delenv``'d ``SOCKS5_ENABLED`` gets it (and every other prod value) handed
       right back. We block ONLY dotenv auto-discovery: an **explicit** ``env_path``
       (used by tests that genuinely exercise .env-file parsing) is still honoured.
       ``hy2_auth/config.py`` has its own independent ``load_dotenv()`` call (it
       cannot import config.settings — see its module docstring) and must be
       blocked the same way, or a single test that reaches it (e.g.
       ``test_hy2_auth.py``) permanently pollutes ``os.environ`` with the live
       ``.env`` for every test that runs afterward in the same session — this is
       exactly how ``ANOMALY_HYSTERIA2_MAX_CONN``/``HYSTERIA2_STATS_SECRET`` from
       the box's real ``.env`` were observed leaking into unrelated later tests.

    2. Any of the prod control-var families already exported in the ambient
       environment would likewise leak. We strip them up-front so each test starts
       from the documented defaults.

    This is deliberately narrow. It does NOT stop the loader from reading the
    environment: a test that sets a var (this autouse fixture runs *before* the
    test body's ``monkeypatch.setenv``) still sees it, so "the loader reads X from
    the environment" tests keep their teeth.
    """
    for key in list(os.environ):
        if key.startswith(_ISOLATED_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)

    import dotenv

    real_dotenv_load_dotenv = dotenv.load_dotenv

    def _no_autodiscovery_load_dotenv(dotenv_path: Any = None, *args: Any, **kwargs: Any) -> bool:
        # Falsy path == python-dotenv auto-discovery (the prod-.env leak): no-op,
        # mirroring load_dotenv's "nothing loaded" return. An explicit path is
        # forwarded to the real loader untouched.
        if not dotenv_path:
            return False
        return bool(real_dotenv_load_dotenv(dotenv_path, *args, **kwargs))

    # Patch every module-local `load_dotenv` name bound via `from dotenv import
    # load_dotenv` — patching the `dotenv` package attribute alone would not reach
    # these, since `from ... import ...` copies the reference at import time.
    import config.settings as settings_module
    import hy2_auth.config as hy2_auth_config_module

    monkeypatch.setattr(settings_module, "load_dotenv", _no_autodiscovery_load_dotenv)
    monkeypatch.setattr(hy2_auth_config_module, "load_dotenv", _no_autodiscovery_load_dotenv)
    # The protocol-uninstall markers live in /etc/vpn-bot/uninstalled on the host
    # this suite runs on (deploy.sh Phase 1): a load_settings() here must never see
    # them, or an uninstalled protocol on the box would change what a test observes.
    monkeypatch.setattr(
        settings_module, "PROTOCOL_UNINSTALL_MARKER_DIR", Path("/nonexistent/vpn-bot-test/uninstalled")
    )
    # Same for the installer's pending superadmin claim (/etc/vpn-bot/claim.json):
    # a bot built in a test must never see — let alone consume — the host's claim.
    monkeypatch.setattr(
        settings_module, "SUPERADMIN_CLAIM_PATH", Path("/nonexistent/vpn-bot-test/claim.json")
    )


# The operator knobs scripts/deploy.sh reads from its environment
# (`NAME="${NAME:-0}"`): the run mode and every gate bypass. deploy.sh runs this
# suite as its Phase 1 gate, in its own environment, so whatever the operator set
# for THAT deploy reaches every test — `CHECK=1 redeploy` exports PHASE1_ONLY=1,
# `FORCE=1` and the ALLOW_* are passed through as given. tests/test_deploy_knob_isolation.py
# fails when deploy.sh gains a knob that is missing here, or drops one listed here.
#
# DEPLOY_REF and DEPLOY_HANDOVER_SHA too: the relay agent's `update` (the bot's path)
# runs `DEPLOY_REF=<tag> redeploy.sh`, and a relay's handover exports
# DEPLOY_HANDOVER_SHA — so the bot's path handed the Phase 1 suite an environment the
# operator's `redeploy.sh` never did. Stripped, both paths test the same thing.
DEPLOY_ENV_KNOBS: tuple[str, ...] = (
    "PHASE1_ONLY",
    "FORCE",
    "FORCE_TESTS",
    "PHASE1_STAMP",
    "PHASE1_STAMP_TTL",
    "DEPLOY_REF",
    "DEPLOY_HANDOVER_SHA",
    "ALLOW_MODEL_SWITCH",
    "ALLOW_UNIT_DRIFT",
    "ALLOW_BACKEND_CONFIG_DRIFT",
    "ALLOW_SCHEMA_DOWNGRADE",
    "ALLOW_SSH_CHANGE",
)


@pytest.fixture(autouse=True)
def _isolate_deploy_knobs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip deploy.sh's operator knobs from every test's environment.

    The same host-only class as ``_isolate_settings_env`` (cf. #239/#246/#318):
    a test that sources deploy.sh and leaves a knob at its default inherits the
    value of the deploy that is running the suite. Under ``CHECK=1 redeploy``
    ``test_relay_phase1_stops_on_an_auth_latent`` saw PHASE1_ONLY=1, and Phase 1
    reported the LATENT instead of stopping on it — red on the box, green in CI.

    ``delenv`` only: a test that sets a knob itself (``monkeypatch.setenv``, which
    runs after this fixture, or a ``NAME=value`` line in its bash driver) still
    gets exactly that value. DEPLOY_SELFTEST is not a knob and is left alone.
    """
    for key in DEPLOY_ENV_KNOBS:
        monkeypatch.delenv(key, raising=False)


def _load_module(module_name: str, path: Path) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(module_name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@contextlib.contextmanager
def _capture_stdout() -> Generator[io.StringIO, None, None]:
    buf = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old_stdout


@pytest.fixture
def checker() -> ModuleType:
    """Load check-nonroot-helper-mode.py CLI script as a fresh module per test."""
    return _load_module("check_nonroot", ROOT / "deploy" / "check-nonroot-helper-mode.py")


@pytest.fixture
def load_helper() -> Callable[[str], ModuleType]:
    """Factory fixture: call with a helper script name to get a fresh module."""
    def _load(name: str) -> ModuleType:
        return _load_module(name.replace("-", "_"), ROOT / "deploy" / "helpers" / name)
    return _load


@pytest.fixture
def captured_cli_output() -> Callable[[], contextlib.AbstractContextManager[io.StringIO]]:
    """Fixture providing a context manager that captures sys.stdout during CLI calls."""
    return _capture_stdout


@pytest.fixture(autouse=True)
def fake_timer(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Every progress message of every test runs on a fake clock (tests/fake_timer.py).

    A progress view's edit throttle, its animation tick and the pollers next to an
    operation (a relay's ``update-status``) wait through ``bot.progress.TIMER``; here
    that timer only moves when a test calls ``fake_timer.advance(...)``. Without it a
    test's outcome depended on how many real milliseconds a step took — on deploy.sh's
    Phase 1 gate (one vCPU, the whole suite) a poll answered after the update had
    finished and the final card still showed «🔄 тесты».
    """
    from bot import progress
    from fake_timer import FakeTimer

    timer = FakeTimer()
    monkeypatch.setattr(progress, "TIMER", timer)
    return timer


@pytest.fixture(autouse=True)
def _isolate_i18n_locale() -> Generator[None, None, None]:
    """Restore global i18n locale state after every test.

    ``i18n.configure()`` mutates the process-wide default locale (a module global)
    and ``i18n.set_locale()`` mutates a ContextVar; tests that switch locale would
    otherwise leak that choice into later tests via collection order. Snapshot the
    default on entry and reset both on teardown so each test starts from a clean,
    order-independent locale state.
    """
    import i18n

    default_before = i18n._default_locale
    try:
        yield
    finally:
        i18n._default_locale = default_before
        i18n._current_locale.set(None)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "scrypt_production_cost: keep utils.totp's real scrypt cost (see _cheap_scrypt)",
    )
    config.addinivalue_line(
        "markers",
        "real_bootstrap: run Database.bootstrap()'s full migration chain even on a "
        "fresh database (see _bootstrap_from_template)",
    )


# Test-only scrypt cost for backup codes. utils/totp.py hashes every backup code with
# N=2**14, r=8 (16 MiB, tens of ms — chosen for interactive logins), and one
# enrollment hashes ten codes while a redeem checks up to ten: ~1 s per TOTP test,
# and 16 MiB allocations at a time on the 1 GiB production host that runs this suite
# as its Phase 1 gate. Nothing in a test depends on the cost — every digest is
# produced and checked inside the same process — so the work factor is dropped to
# the minimum scrypt accepts. The production parameters are pinned by
# tests/test_totp.py::test_the_production_scrypt_cost_is_pinned, which opts out with
# @pytest.mark.scrypt_production_cost and also hashes once at the real cost.
CHEAP_SCRYPT_N = 2**4


@pytest.fixture(autouse=True)
def _cheap_scrypt(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    if request.node.get_closest_marker("scrypt_production_cost") is not None:
        return
    import utils.totp as totp_module

    monkeypatch.setattr(totp_module, "SCRYPT_N", CHEAP_SCRYPT_N)


# --------------------------------------------------------------------------- #
# synchronous=NORMAL for test databases
#
# Database() defaults to synchronous=FULL (the production default, settings
# SQLITE_SYNCHRONOUS), which in WAL mode means one fdatasync() per COMMIT. Over the
# suite that is ~60 000 fdatasyncs: free on a CI runner's page cache, but on the
# production host that runs this suite as its deploy gate every one is a real disk
# flush. Only power-loss durability differs between FULL and NORMAL (in WAL mode
# NORMAL syncs at checkpoints, not commits) and no test can observe that, so a
# Database built WITHOUT an explicit `synchronous` gets NORMAL here. An explicit
# value (bot/app.py and init_db.py pass settings.sqlite_synchronous; tests that pin
# the PRAGMA pass their own) is untouched. Patched through __init__.__defaults__, so
# the function object — and the bootstrap-template fingerprint below — is unchanged.
# --------------------------------------------------------------------------- #
TEST_SQLITE_SYNCHRONOUS = "NORMAL"


@pytest.fixture(autouse=True)
def _relaxed_sqlite_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    from db.database import Database

    monkeypatch.setattr(Database.__init__, "__defaults__", (TEST_SQLITE_SYNCHRONOUS,))


# --------------------------------------------------------------------------- #
# Fresh-database bootstrap from a session template
#
# ~1100 tests open an empty database and call Database.bootstrap(), which runs
# schema.sql, the whole v1..CURRENT migration chain and indexes.sql — hundreds of
# round trips to the aiosqlite worker thread and ~50 fdatasync()s each (synchronous
# = FULL), on every test. The result is byte-for-byte the same every time, so the
# FIRST eligible bootstrap of the session runs the real chain into a template file,
# and every later one copies that template into the test's open connection with
# SQLite's online backup API (one page copy, a few fsyncs) and then finishes the way
# bootstrap() does (spiderX backfill, commit, chmod).
#
# The shortcut is taken ONLY when it cannot change what a test observes:
#   * the database is pristine (no schema object at all) — an old snapshot being
#     upgraded, or a second bootstrap, always runs the real chain;
#   * default schema/index files (a test passing its own runs the real chain);
#   * exactly `Database`, not a subclass;
#   * nothing that bootstrap reads was replaced since the test started: every
#     attribute of the Database class and of the db.database module is compared by
#     identity against a snapshot taken when this fixture ran, and the instance must
#     not shadow a class attribute. A test that monkeypatches a migration to fail
#     therefore gets the real chain and its real failure;
#   * the test is not marked @pytest.mark.real_bootstrap.
# tests/test_bootstrap_template.py proves the template equals a real fresh
# bootstrap (full SQL dump + header pragmas) and that each guard falls back.
# --------------------------------------------------------------------------- #
_BOOTSTRAP_TEMPLATE: list[Path] = []


def _db_fingerprint() -> tuple[tuple[tuple[str, int], ...], tuple[tuple[str, int], ...]]:
    import db.database as db_module

    return (
        tuple((name, id(value)) for name, value in vars(db_module.Database).items()),
        tuple((name, id(value)) for name, value in vars(db_module).items()),
    )


def _template_backup_into(raw: Any, template: Path) -> Callable[[], None]:
    import sqlite3

    def _copy() -> None:
        # Runs ON the aiosqlite worker thread, which owns raw._conn; the source
        # connection is opened there too.
        src = sqlite3.connect(template)
        try:
            src.backup(raw._conn)
        finally:
            src.close()

    return _copy


@pytest.fixture(autouse=True)
def _bootstrap_from_template(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    if request.node.get_closest_marker("real_bootstrap") is not None:
        return
    from db.database import Database

    real_bootstrap = Database.bootstrap

    async def bootstrap(self: Database, schema_path: Path | None = None, indexes_path: Path | None = None) -> None:
        if (
            schema_path is not None
            or indexes_path is not None
            or type(self) is not Database
            or _db_fingerprint() != fingerprint
            or any(name in vars(Database) for name in vars(self))
        ):
            return await real_bootstrap(self, schema_path, indexes_path)
        raw = self._raw_conn()
        cursor = await raw.execute("SELECT count(*) FROM sqlite_master")
        row = await cursor.fetchone()
        await cursor.close()
        if row is None or row[0] != 0:
            return await real_bootstrap(self, schema_path, indexes_path)
        if not _BOOTSTRAP_TEMPLATE:
            # Built exactly the way a test (or the bot) builds a fresh database:
            # its own Database, connect(), the REAL bootstrap, close() — which
            # checkpoints the WAL into the main file, so the template is one file.
            template = tmp_path_factory.mktemp("bootstrap-template") / "template.db"
            seed = Database(template, synchronous=self.synchronous)
            await seed.connect()
            try:
                await real_bootstrap(seed)
            finally:
                await seed.close()
            _BOOTSTRAP_TEMPLATE.append(template)
        await raw._execute(_template_backup_into(raw, _BOOTSTRAP_TEMPLATE[0]))
        # The tail of the real bootstrap(): the backfill reads the test's env (a
        # no-op on an empty vpn_keys), then commit and the private-file chmod.
        try:
            await self._ensure_spider_x_backfill()
            await self.commit()
            self._chmod_sqlite_files()
        except Exception:
            await self.rollback()
            raise
        return None

    monkeypatch.setattr(Database, "bootstrap", bootstrap)
    fingerprint = _db_fingerprint()


async def wait_until_lock_contended(lock: asyncio.Lock, *, timeout: float = 5.0) -> None:
    """Wait until ``lock`` is held and at least one task is waiting to acquire it,
    then return.

    Preferred over ``await asyncio.sleep(0.05); assert not task.done()``: it
    returns the instant the contended state is observed (lock held + a waiter
    present), which is race-free, and only ever blocks until that happens.

    A launched task parks on ``lock.acquire()`` only after any *preceding* awaits
    resolve. Some of those awaits (e.g. aiosqlite queries) complete on a worker
    thread and therefore need wall-clock time, not just event-loop turns — so a
    fixed number of ``asyncio.sleep(0)`` spins can exhaust its budget in
    microseconds before the thread finishes and the task ever reaches the lock,
    which made this flaky on loaded CI runners. Poll against a wall-clock
    ``timeout`` instead, yielding briefly between checks. Raises if no task parks
    within ``timeout`` seconds.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if lock.locked() and lock._waiters:  # type: ignore[attr-defined]
            return
        if loop.time() >= deadline:
            raise AssertionError("no task parked on the lock")
        await asyncio.sleep(0.001)


async def wait_until_write_parked(db: object, *, timeout: float = 5.0) -> None:
    """Convenience wrapper: wait until a competing write/read has parked on the
    ``Database`` transaction serialization lock."""
    await wait_until_lock_contended(db._transaction_lock, timeout=timeout)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Schema shape helpers
#
# One definition of "what a database looks like", shared by the two schema
# guards: test_schema_drift.py (fresh bootstrap vs the SQL files) and
# test_schema_upgrade_path.py (an old snapshot upgraded through bootstrap vs a
# fresh bootstrap). Both compare SchemaShape values, so a divergence either
# construction path can produce is caught by whichever guard sees it first.
# --------------------------------------------------------------------------- #
class SchemaShape(NamedTuple):
    """Everything the schema guards compare between two databases.

    tables:  user table names.
    columns: table -> column name -> (type, notnull, default, pk). Keyed by column
             NAME so a legitimate column-ORDER divergence (an ALTER appends at the
             end while schema.sql lists the column mid-table — e.g. spider_x,
             bundle_id) is not treated as drift, while any type / nullability /
             default / primary-key difference still is.
    fks:     table -> {(from_col, parent_table, to_col, on_update, on_delete)}, a
             SET so ON DELETE actions (e.g. bundle_id RESTRICT vs user_id CASCADE)
             are compared regardless of the order SQLite reports them in.
    indexes: index name -> (unique, partial, columns). Compared structurally rather
             than by sqlite_master SQL text, because the same index is created by
             different statements on different paths (a table-rebuild migration
             re-creates it with its own formatting), and the whitespace difference
             is not drift.
    checks:  table -> {normalised CHECK expression}. No PRAGMA exposes CHECK
             constraints, so these come out of the sqlite_master DDL — and they
             have to be compared, because a CHECK is the one part of a table that
             ONLY a full rebuild can change. A migration that widens an enum in
             schema.sql but forgets the rebuild leaves every column, foreign key
             and index identical and still rejects the new value at INSERT time,
             which is exactly how the Hysteria2 trial button stayed broken.
    """

    tables: frozenset[str]
    columns: dict[str, dict[str, tuple[str, int, object, int]]]
    fks: dict[str, set[tuple[str, str, str, str, str]]]
    indexes: dict[str, tuple[int, int, tuple[str, ...]]]
    checks: dict[str, frozenset[str]]


async def table_names(conn: aiosqlite.Connection) -> frozenset[str]:
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    return frozenset(str(row[0]) for row in await cursor.fetchall())


async def named_indexes(conn: aiosqlite.Connection) -> set[str]:
    cursor = await conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
    )
    return {str(row[0]) for row in await cursor.fetchall()}


async def column_details(
    conn: aiosqlite.Connection, table: str
) -> dict[str, tuple[str, int, object, int]]:
    cursor = await conn.execute(f"PRAGMA table_info({table})")
    return {
        str(row[1]): (str(row[2]).upper(), int(row[3]), row[4], int(row[5]))
        for row in await cursor.fetchall()
    }


async def foreign_keys(conn: aiosqlite.Connection, table: str) -> set[tuple[str, str, str, str, str]]:
    cursor = await conn.execute(f"PRAGMA foreign_key_list({table})")
    return {
        (str(row[3]), str(row[2]), str(row[4]), str(row[5]), str(row[6]))
        for row in await cursor.fetchall()
    }


async def index_details(
    conn: aiosqlite.Connection, tables: frozenset[str]
) -> dict[str, tuple[int, int, tuple[str, ...]]]:
    details: dict[str, tuple[int, int, tuple[str, ...]]] = {}
    for table in tables:
        cursor = await conn.execute(f"PRAGMA index_list({table})")
        for row in await cursor.fetchall():
            name = str(row[1])
            if not name.startswith("idx_"):
                continue  # sqlite_autoindex_* — implied by UNIQUE/PK, not our DDL
            info = await conn.execute(f"PRAGMA index_info({name})")
            # index_list columns: (seq, name, unique, origin, partial). An
            # expression index reports NULL column names, which str() renders as
            # 'None' — stable across both construction paths.
            columns = tuple(str(col[2]) for col in await info.fetchall())
            details[name] = (int(row[2]), int(row[4]), columns)
    return details


_SQL_COMMENT = re.compile(r"--[^\n]*")
_SQL_WHITESPACE = re.compile(r"\s+")


def _normalise_check(body: str) -> str:
    """Strip formatting from a CHECK body so only its meaning is compared.

    The same constraint is written differently on the two construction paths —
    schema.sql indents it, a rebuild migration inlines it — and that difference
    is not drift.
    """
    body = _SQL_WHITESPACE.sub(" ", body).strip()
    return re.sub(r"\s*([(),])\s*", r"\1", body)


def _table_checks(create_sql: str) -> frozenset[str]:
    """Every CHECK expression in a CREATE TABLE statement, normalised.

    Parses the parentheses rather than regexing the body, so a nested one
    (``CHECK(x IN ('a','b'))``) is captured whole instead of cut at its first
    closing bracket.
    """
    sql = _SQL_COMMENT.sub(" ", create_sql or "")
    checks: list[str] = []
    for match in re.finditer(r"\bCHECK\s*\(", sql, re.IGNORECASE):
        start = match.end() - 1
        depth = 0
        for pos in range(start, len(sql)):
            if sql[pos] == "(":
                depth += 1
            elif sql[pos] == ")":
                depth -= 1
                if depth == 0:
                    checks.append(_normalise_check(sql[start + 1 : pos]))
                    break
    return frozenset(checks)


async def table_checks(conn: aiosqlite.Connection, tables: frozenset[str]) -> dict[str, frozenset[str]]:
    cursor = await conn.execute(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    )
    found = {str(row[0]): _table_checks(str(row[1] or "")) for row in await cursor.fetchall()}
    return {table: found.get(table, frozenset()) for table in tables}


async def schema_shape(conn: aiosqlite.Connection) -> SchemaShape:
    tables = await table_names(conn)
    return SchemaShape(
        tables=tables,
        columns={table: await column_details(conn, table) for table in tables},
        fks={table: await foreign_keys(conn, table) for table in tables},
        indexes=await index_details(conn, tables),
        checks=await table_checks(conn, tables),
    )


def assert_same_shape(actual: SchemaShape, expected: SchemaShape, context: str) -> None:
    """Compare two shapes field by field, failing on the smallest difference first
    so the message names the table/index at fault instead of dumping both schemas."""
    assert actual.tables == expected.tables, f"{context}: table set differs"
    for table in sorted(expected.tables):
        assert actual.columns[table] == expected.columns[table], f"{context}: column drift in {table}"
        assert actual.fks[table] == expected.fks[table], f"{context}: foreign-key drift in {table}"
        assert actual.checks[table] == expected.checks[table], f"{context}: CHECK drift in {table}"
    assert set(actual.indexes) == set(expected.indexes), f"{context}: index set differs"
    for name in sorted(expected.indexes):
        assert actual.indexes[name] == expected.indexes[name], f"{context}: index {name} differs"


# ── relays ────────────────────────────────────────────────────────────────────


def make_relay(
    relay_id: int = 1,
    name: str = "ru1",
    *,
    label: str = "relay",
    host: str = "relay.example.net",
    source_ips: str = "198.51.100.7",
    enabled: bool = True,
    in_subscriptions: bool = True,
    note: str | None = None,
    basic_visible: bool = True,
) -> Any:
    """A :class:`models.dto.Relay` as the relays table would hold it."""
    from config.validators import parse_ipv4_networks
    from models.dto import Relay

    return Relay(
        id=relay_id,
        name=name,
        label=label,
        host=host,
        source_ips=parse_ipv4_networks("source_ips", source_ips),
        enabled=enabled,
        in_subscriptions=in_subscriptions,
        note=note,
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
        created_by=None,
        updated_by=None,
        basic_visible=basic_visible,
    )


def relay_snapshot(*relays: Any) -> Any:
    """A :class:`services.relay.RelaySnapshot` of *relays* (default: one ``ru1``)."""
    from services.relay import RelaySnapshot

    return RelaySnapshot.of(relays if relays else (make_relay(),))


def relay_services(*relays: Any) -> Any:
    """The ``services.relays`` stand-in a handler test needs: just ``.snapshot``."""
    from types import SimpleNamespace

    from services.relay import RelaySnapshot

    return SimpleNamespace(snapshot=RelaySnapshot.of(relays))


def availability_settings(**overrides: Any) -> dict[str, Any]:
    """The Settings fields ``services.protocol_availability`` reads, all switched off.

    For handler tests whose ``settings`` stub is a SimpleNamespace: every screen
    that names a protocol now reads availability at render time, so the stub has
    to carry these fields. Spread it into the stub and override what the test
    needs on.
    """
    values: dict[str, Any] = {
        "xray_xhttp_enabled": False,
        "hysteria2_enabled": False,
        "is_hysteria2_ready": lambda: True,
        "socks5_enabled": False,
        "mtproto_enabled": False,
        "subscription_enabled": False,
    }
    values.update(overrides)
    return values
