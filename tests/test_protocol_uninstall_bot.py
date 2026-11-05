"""The bot's side of the protocol uninstall (removal from the host).

* the marker registry and its boot-time reconcile against protocol_modules;
* everything that talks to a backend skips a removed protocol: startup reconcile
  (Xray/AWG used to be asked unconditionally, MTProto is fatal on error), the
  stats collectors, the Hysteria2 health probe, BackendHealth (removed, never
  degraded), the anomaly detector, the subscription composition;
* "Enable" is blocked for a removed protocol;
* ProtocolUninstallService: the sha check BEFORE the purge, a purge failure
  stopping the helper, the audit trail, both privilege models;
* the panel: buttons, the plan and report screens, the dead socks5/hysteria2
  callbacks;
* end to end through the REAL helper on a fake host (the seam of
  tests/test_protocol_uninstall_helper.py), so the plan JSON contract and the
  marker are the helper's own.

No test reads the real /etc: every registry points into tmp_path.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bot.app as app_module
import bot.handlers.admin_modules as handlers
from adapters.clock import ClockProvider
from adapters.health_server import create_health_app
from bot.keyboards.admin_modules import (
    module_disable_confirm1_keyboard,
    module_uninstall_plan_keyboard,
    modules_panel_keyboard,
)
from bot.uninstall_texts import MAX_MESSAGE, uninstall_plan_text, uninstall_report_text
from db.database import Database
from i18n import t
from models.dto import ShellResult, TelegramUserProfile
from models.enums import ProxyAccessType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.audit_log import AuditLogRepository
from repositories.protocol_modules import PROTOCOL_DISPLAY, PROTOCOL_NAMES, ProtocolModulesRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation
from services.health import check_backends
from services.key_bundles import BundleMember, KeyBundleService
from services.protocol_modules import ProtocolModulesService
from services.protocol_uninstall import (
    INSTALLED_HELPER_PATH,
    REPO_HELPER_PATH,
    PlanChangedError,
    ProtocolUninstallService,
    PurgeFailedError,
    UninstallPlan,
    UninstallRegistry,
    UninstallReport,
    resolve_helper_path,
)
from services.users import UserService

from test_proxy_services import _settings

ADMIN = 1
OWNER = 100
ROOT = Path(__file__).resolve().parents[1]


def _marker(directory: Path, name: str, **fields: object) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps({"protocol": name, "ts": "2026-11-05T10:00:00Z", **fields}), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
def test_registry_reads_markers_and_nothing_without_a_dir(tmp_path: Path) -> None:
    d = tmp_path / "uninstalled"
    _marker(d, "xray", sha256="a" * 64, backup="/var/backups/vpn-bot/uninstall/xray-1.tar.gz")
    (d / "awg").write_text("not json", encoding="utf-8")
    (d / "unknown").write_text("{}", encoding="utf-8")
    reg = UninstallRegistry(d)
    assert reg.refresh() == frozenset({"xray", "awg"})
    assert reg.is_uninstalled("xray") and reg.is_uninstalled("awg") and not reg.is_uninstalled("socks5")
    marker = reg.marker("xray")
    assert marker is not None and marker.backup and marker.backup.endswith("xray-1.tar.gz")
    assert reg.marker("awg") is not None, "an unreadable marker still counts"
    assert UninstallRegistry(None).refresh() == frozenset()


def test_load_settings_never_points_at_the_real_marker_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from config.settings import load_settings

    monkeypatch.setenv("BOT_TOKEN", "123:abc")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    settings = load_settings(tmp_path / "missing.env")
    assert settings.protocol_uninstall_marker_dir is not None
    assert not str(settings.protocol_uninstall_marker_dir).startswith("/etc/"), "conftest fences the real dir"
    assert _settings(tmp_path).protocol_uninstall_marker_dir is None


def test_helper_path_follows_the_privilege_model(tmp_path: Path) -> None:
    assert resolve_helper_path(_settings(tmp_path)) == REPO_HELPER_PATH
    assert REPO_HELPER_PATH == ROOT / "deploy" / "helpers" / "vpn-bot-protocol-uninstall"
    assert resolve_helper_path(_settings(tmp_path, privilege_helpers_enabled=True)) == INSTALLED_HELPER_PATH
    custom = Path("/opt/x/vpn-bot-protocol-uninstall")
    assert resolve_helper_path(_settings(tmp_path, protocol_uninstall_helper_path=custom)) == custom


# --------------------------------------------------------------------------- #
# A small world: DB, users, modules, purgers
# --------------------------------------------------------------------------- #
class FakeRunner:
    """Stands in for PrivilegedHelperRunner: canned helper answers, every call logged."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.plans: list[dict[str, Any]] = []
        self.apply_rc = 0
        self.apply_out: dict[str, Any] = {}
        self.on_apply: Any = None

    async def run(self, helper_path: Path, args: list[str], **kwargs: object) -> ShellResult:
        self.calls.append(list(args))
        if args[0] == "plan":
            plan = self.plans.pop(0) if len(self.plans) > 1 else self.plans[0]
            return ShellResult(("helper",), 0, json.dumps(plan), "")
        if self.on_apply is not None:
            self.on_apply()
        return ShellResult(("helper",), self.apply_rc, json.dumps(self.apply_out), "")


def _plan(proto: str = "xray", sha: str = "a" * 64, **over: Any) -> dict[str, Any]:
    plan: dict[str, Any] = {
        "ok": True, "version": 1, "protocol": proto, "sha256": sha, "state": "installed", "nothing_to_do": False,
        "blocking": [], "warnings": [],
        "units": [{"unit": "xray.service", "load": "loaded", "active": "active", "file_state": "enabled",
                   "actions": "stop disable", "state": "act"}],
        "files": [{"path": "/usr/local/etc/xray", "kind": "dir", "state": "delete", "reason": "", "size": 4096,
                   "entries": 37, "step": "files", "group": ""}],
        "ufw": [{"rule": "443/tcp", "state": "delete", "line": "ufw allow 443/tcp", "reason": ""}],
        "packages": [], "users": [], "env": {"key": "", "state": "none"},
        "marker": {"path": f"/etc/vpn-bot/uninstalled/{proto}", "state": "create"},
        "skipped_shared": [{"what": "/etc/nginx", "reason": "shared"}],
        "backup_dir": "/var/backups/vpn-bot/uninstall", "backup_estimate_bytes": 1000,
    }
    plan.update(over)
    return plan


async def _world(tmp_path: Path, *, keys: int = 2, fail_purge: bool = False) -> SimpleNamespace:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users_repo = UserRepository(db)
    for uid, role in ((ADMIN, UserRole.SUPERADMIN), (OWNER, UserRole.APPROVED_USER)):
        await users_repo.upsert_profile(TelegramUserProfile(uid, f"u{uid}", f"U{uid}"), role, "now")
    keys_repo = VpnKeyRepository(db)
    ids = []
    for i in range(keys):
        key = await keys_repo.create_pending(
            owner_user_id=OWNER, username=f"u{OWNER}", key_type=VpnKeyType.XRAY, note=None, payload={},
            public_payload={}, created_by=OWNER, now="now", uuid=f"00000000-0000-4000-8000-{i:012d}",
            email_label=f"xray_{i:05d}",
        )
        await keys_repo.mark_active(key.id, "now")
        ids.append(key.id)

    async def purger(actor_id: int, key_id: int) -> None:
        if fail_purge and key_id == ids[0]:
            await keys_repo.set_status(key_id, VpnKeyStatus.DELETE_FAILED, "now")
            raise RuntimeError("remove_client failed")
        await keys_repo.hard_delete_with_stats(key_id, "now")

    settings = _settings(tmp_path, protocol_uninstall_marker_dir=tmp_path / "uninstalled")
    audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
    user_service = UserService(users=users_repo, settings=settings, clock=ClockProvider(), audit=audit)
    repo = ProtocolModulesRepository(db)
    modules = ProtocolModulesService(repo, db)
    modules.attach_purge_handlers(users=user_service, audit=audit, vpn_keys=keys_repo,
                                  proxy_accesses=ProxyAccessRepository(db), key_purgers={VpnKeyType.XRAY: purger},
                                  proxy_purgers={})
    registry = UninstallRegistry(settings.protocol_uninstall_marker_dir)
    registry.refresh()
    modules.attach_uninstall_registry(registry)
    health = BackendHealth()
    runner = FakeRunner()
    service = ProtocolUninstallService(settings=settings, shell=None, registry=registry, modules=modules,  # type: ignore[arg-type]
                                       modules_repo=repo, users=user_service, audit=audit, backend_health=health,
                                       runner=runner)  # type: ignore[arg-type]
    return SimpleNamespace(db=db, settings=settings, modules=modules, repo=repo, registry=registry, health=health,
                           runner=runner, service=service, users=user_service, keys=keys_repo, key_ids=ids,
                           audit_repo=AuditLogRepository(db))


async def _audit_actions(w: SimpleNamespace) -> list[tuple[str, dict[str, Any]]]:
    rows = await w.db.conn.execute_fetchall("SELECT action, details_json FROM audit_log ORDER BY id")
    return [(row["action"], json.loads(row["details_json"] or "{}")) for row in rows]


# --------------------------------------------------------------------------- #
# Marker <-> DB at boot
# --------------------------------------------------------------------------- #
async def test_boot_reconcile_follows_the_marker(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    w = await _world(tmp_path, keys=0)
    try:
        _marker(tmp_path / "uninstalled", "awg", backup="/var/backups/vpn-bot/uninstall/awg-1.tar.gz")
        await w.repo.set_uninstalled("mtproto", uninstalled_at="2026-11-01T00:00:00Z", uninstalled_by=ADMIN,
                                     backup="/x.tar.gz")
        with caplog.at_level("WARNING", logger="services.protocol_uninstall"):
            changes = await w.service.reconcile_markers()
        assert changes == {"awg": "marked_uninstalled", "mtproto": "cleared"}
        assert "marker" in caplog.text and "source of truth" in caplog.text
        mods = {m.name: m for m in await w.repo.get_all()}
        assert mods["awg"].uninstalled_at == "2026-11-05T10:00:00Z" and not mods["awg"].enabled
        assert mods["awg"].uninstall_backup == "/var/backups/vpn-bot/uninstall/awg-1.tar.gz"
        assert mods["mtproto"].uninstalled_at is None and mods["mtproto"].uninstall_backup is None
        assert w.health.is_uninstalled(VpnKeyType.AWG)
        caplog.clear()
        assert await w.service.reconcile_markers() == {}, "in agreement: nothing to say"
    finally:
        await w.db.close()


async def test_a_removed_protocol_is_off_and_cannot_be_enabled(tmp_path: Path) -> None:
    w = await _world(tmp_path, keys=0)
    try:
        _marker(tmp_path / "uninstalled", "socks5")
        w.registry.refresh()
        assert await w.modules.is_enabled("socks5") is False
        assert await w.repo.is_enabled("socks5") is True, "the DB toggle alone would say on"
        with pytest.raises(InvalidOperation) as err:
            await w.modules.enable_protocol("socks5", ADMIN)
        assert err.value.key == "module_enable_blocked_uninstalled"
        assert t("module_enable_blocked_uninstalled") == "Протокол удалён с сервера, нужна переустановка."
        await w.modules.enable_protocol("xray", ADMIN)
    finally:
        await w.db.close()


# --------------------------------------------------------------------------- #
# Nothing talks to a removed backend
# --------------------------------------------------------------------------- #
class _Reg:
    def __init__(self, *names: str) -> None:
        self.names = frozenset(names)

    def is_uninstalled(self, name: str) -> bool:
        return name in self.names


def test_startup_reconcile_skips_removed_backends_and_mtproto_cannot_stop_the_boot() -> None:
    called: list[str] = []

    def backend(name: str, fail: bool = False) -> Any:
        async def reconcile() -> dict[str, int]:
            called.append(name)
            if fail:
                raise RuntimeError("backend gone")
            return {"checked": 1, "failed": 0}
        return reconcile

    services = SimpleNamespace(
        xray=SimpleNamespace(startup_reconcile=backend("xray"), reconcile_email_labels=backend("labels")),
        awg=SimpleNamespace(startup_reconcile=backend("awg")),
        mtproto=SimpleNamespace(reconcile_mtproto_state=backend("mtproto", fail=True)),
        socks5=SimpleNamespace(reconcile_socks5_state=backend("socks5")),
        backend_health=BackendHealth(),
        audit=SimpleNamespace(write=backend("audit")),
        protocol_uninstall=SimpleNamespace(registry=_Reg("xray", "awg", "mtproto", "socks5")),
    )
    asyncio.run(app_module._startup_reconcile_keys(services))  # type: ignore[arg-type]
    assert called == [], called
    assert not any(s.degraded for s in services.backend_health.snapshot())


def test_startup_reconcile_still_runs_what_is_installed() -> None:
    called: list[str] = []

    async def ok() -> dict[str, int]:
        called.append("x")
        return {"checked": 0, "failed": 0}

    services = SimpleNamespace(
        xray=SimpleNamespace(startup_reconcile=ok), awg=SimpleNamespace(startup_reconcile=ok),
        backend_health=BackendHealth(), protocol_uninstall=SimpleNamespace(registry=_Reg("awg")),
    )
    asyncio.run(app_module._startup_reconcile_keys(services))  # type: ignore[arg-type]
    assert called == ["x"], "Xray reconciled, AWG skipped"


async def _one_pass(coro: Any) -> None:
    """Run a background loop until its first sleep."""
    task = asyncio.create_task(coro)
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize(("loop", "method", "name"), [
    ("_xray_stats_loop", "refresh_all_xray", "xray"),
    ("_awg_stats_loop", "refresh_all_awg", "awg"),
    ("_hysteria_stats_loop", "refresh_all_hysteria", "hysteria2"),
])
async def test_stats_loops_skip_a_removed_protocol(loop: str, method: str, name: str) -> None:
    calls: list[str] = []

    async def refresh() -> None:
        calls.append(method)

    stats = SimpleNamespace(**{method: refresh})
    await _one_pass(getattr(app_module, loop)(stats, 3600, _Reg(name)))
    assert calls == []
    await _one_pass(getattr(app_module, loop)(stats, 3600, _Reg()))
    assert calls == [method]


async def test_the_hysteria_probe_reports_removed_not_degraded() -> None:
    probed: list[int] = []

    class Probe:
        async def healthy(self) -> bool:
            probed.append(1)
            return False

    health = BackendHealth()
    await _one_pass(app_module._hysteria_health_loop(Probe(), health, 3600, _Reg("hysteria2")))  # type: ignore[arg-type]
    assert probed == []
    status = next(s for s in health.snapshot() if s.backend_type is VpnKeyType.HYSTERIA2)
    assert status.uninstalled and not status.degraded


async def test_relay_probes_stop_once_xray_is_removed() -> None:
    from services.relay_health import relay_health_loop

    probes: list[int] = []

    class Monitor:
        async def check_once(self) -> None:
            probes.append(1)

    await _one_pass(relay_health_loop(Monitor(), 3600, _Reg("xray")))  # type: ignore[arg-type]
    assert probes == []
    await _one_pass(relay_health_loop(Monitor(), 3600, _Reg("awg")))  # type: ignore[arg-type]
    assert probes == [1]


async def test_backend_health_removed_is_not_a_fault() -> None:
    health = BackendHealth()
    health.mark_degraded(VpnKeyType.XRAY, "reconcile failed")
    health.mark_uninstalled(VpnKeyType.XRAY)
    health.mark_degraded(VpnKeyType.XRAY, "late probe")
    status = next(s for s in health.snapshot() if s.backend_type is VpnKeyType.XRAY)
    assert status.uninstalled and not status.degraded and status.reason is None
    item = next(i for i in check_backends(health.snapshot()) if i.name == "backend_xray")
    assert item.status == "ok" and "UNINSTALLED" in item.message
    with pytest.raises(InvalidOperation):
        health.require_mutation_allowed(VpnKeyType.XRAY)
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(create_health_app(health))) as client:
        resp = await client.get("/health")
        body = await resp.json()
    assert resp.status == 200 and body["status"] == "healthy"
    assert body["backends"]["xray"] == {"degraded": False, "uninstalled": True, "reason": None}


async def test_the_anomaly_detector_skips_removed_backends() -> None:
    from services.anomaly_detection import AnomalyDetectionService

    seen: list[str] = []
    detector = AnomalyDetectionService.__new__(AnomalyDetectionService)
    detector._uninstalled = _Reg("xray", "awg", "hysteria2")  # type: ignore[attr-defined]

    async def mark(name: str, *args: object) -> None:
        seen.append(name)

    async def nothing(*args: object) -> None:
        return None

    detector._refresh_relay_source_ips = nothing  # type: ignore[method-assign]
    detector._evict_stale_last_alerted = lambda now: None  # type: ignore[method-assign]
    detector._sample_awg_endpoints = lambda now: mark("awg")  # type: ignore[method-assign]
    detector._sample_xray_log = lambda now: mark("xray")  # type: ignore[method-assign]
    detector._check_thresholds = nothing  # type: ignore[method-assign]
    detector._check_hysteria_online = lambda now: mark("hysteria2")  # type: ignore[method-assign]
    await detector.check_all()
    assert seen == []
    detector._uninstalled = _Reg("awg")  # type: ignore[attr-defined]
    await detector.check_all()
    assert seen == ["xray", "hysteria2"]


async def test_a_removed_protocol_never_joins_a_subscription(tmp_path: Path) -> None:
    class Modules:
        def is_uninstalled(self, name: str) -> bool:
            return name == "xray"

        async def is_enabled(self, name: str) -> bool:
            return True

    me = SimpleNamespace(modules=Modules(), settings=_settings(tmp_path, hysteria2_enabled=False),
                         relays=SimpleNamespace(snapshot=None))
    assert await KeyBundleService._member_enabled(me, BundleMember(VpnKeyType.XRAY)) is False  # type: ignore[arg-type]


async def test_available_protocols_drop_a_removed_protocol(tmp_path: Path) -> None:
    from services.protocol_availability import Protocol, available_protocols

    w = await _world(tmp_path, keys=0)
    try:
        before = await available_protocols(w.settings, w.modules)
        assert Protocol.XRAY in before and Protocol.AWG in before
        _marker(tmp_path / "uninstalled", "xray")
        w.registry.refresh()
        after = await available_protocols(w.settings, w.modules)
        assert Protocol.XRAY not in after and Protocol.AWG in after
    finally:
        await w.db.close()


# --------------------------------------------------------------------------- #
# The service: sha before purge, purge before helper, audit
# --------------------------------------------------------------------------- #
async def test_plan_is_remembered_and_resolved_by_prefix(tmp_path: Path) -> None:
    w = await _world(tmp_path)
    try:
        w.runner.plans = [_plan(sha="b" * 64)]
        plan = await w.service.plan("xray", ADMIN)
        assert plan.sha256 == "b" * 64 and plan.sha_prefix == "b" * 12
        assert w.service.resolve_sha(ADMIN, "xray", "b" * 12) == "b" * 64
        assert w.service.resolve_sha(ADMIN, "xray", "c" * 12) is None
        assert w.service.resolve_sha(OWNER, "xray", "b" * 12) is None
        with pytest.raises(AccessDenied):
            await w.service.plan("xray", OWNER)
    finally:
        await w.db.close()


async def test_a_changed_host_is_refused_before_the_purge(tmp_path: Path) -> None:
    w = await _world(tmp_path)
    try:
        w.runner.plans = [_plan(sha="c" * 64)]
        with pytest.raises(PlanChangedError) as err:
            await w.service.apply("xray", "b" * 64, ADMIN)
        assert err.value.plan.sha256 == "c" * 64
        assert [c[0] for c in w.runner.calls] == ["plan"]
        assert len(await w.keys.list_by_type_statuses(VpnKeyType.XRAY, {VpnKeyStatus.ACTIVE})) == 2, "no purge"
        assert w.service.resolve_sha(ADMIN, "xray", "c" * 12) == "c" * 64, "the new plan is the pending one"
    finally:
        await w.db.close()


async def test_a_purge_failure_never_runs_the_helper(tmp_path: Path) -> None:
    w = await _world(tmp_path, fail_purge=True)
    try:
        w.runner.plans = [_plan()]
        with pytest.raises(PurgeFailedError) as err:
            await w.service.apply("xray", "a" * 64, ADMIN)
        assert err.value.failed == 1
        assert [c[0] for c in w.runner.calls] == ["plan"], "apply never called"
        actions = await _audit_actions(w)
        failed = [d for a, d in actions if a == "protocol_uninstall_failed"]
        assert failed and failed[0]["step"] == "purge" and failed[0]["failed"] == 1
        assert not w.registry.is_uninstalled("xray")
    finally:
        await w.db.close()


async def test_a_successful_apply_records_everything(tmp_path: Path) -> None:
    w = await _world(tmp_path)
    try:
        backup = "/var/backups/vpn-bot/uninstall/xray-20261105T100000Z.tar.gz"
        w.runner.plans = [_plan()]
        w.runner.apply_out = {"ok": True, "protocol": "xray", "sha256": "a" * 64, "nothing_to_do": False,
                              "backup": backup, "removed": [{"kind": "dir", "item": "/usr/local/etc/xray", "detail": ""}],
                              "already_absent": [], "skipped": [], "errors": [], "failed_step": "",
                              "rolled_back": False, "rollback_errors": [], "rollback_command": "tar -xzf ..."}
        w.runner.on_apply = lambda: _marker(tmp_path / "uninstalled", "xray", sha256="a" * 64, backup=backup)
        report = await w.service.apply("xray", "a" * 64, ADMIN)
        assert report.ok and report.purged == 2 and report.backup == backup
        assert w.runner.calls == [["plan", "xray"], ["apply", "xray", "a" * 64]]
        assert w.registry.is_uninstalled("xray") and w.health.is_uninstalled(VpnKeyType.XRAY)
        mod = next(m for m in await w.repo.get_all() if m.name == "xray")
        assert not mod.enabled and mod.uninstalled_by == ADMIN and mod.uninstall_backup == backup
        done = [d for a, d in await _audit_actions(w) if a == "protocol_uninstalled"]
        assert done == [{"protocol": "xray", "plan_sha256": "-".join(["a" * 16] * 4), "backup": backup,
                         "purged": 2, "removed": 1, "already_absent": 0, "skipped": 0}]
        assert await w.modules.is_enabled("xray") is False
    finally:
        await w.db.close()


async def test_a_helper_failure_is_audited_with_its_step(tmp_path: Path) -> None:
    w = await _world(tmp_path)
    try:
        w.runner.plans = [_plan()]
        w.runner.apply_rc = 70
        w.runner.apply_out = {"ok": False, "protocol": "xray", "backup": "/b.tar.gz", "failed_step": "ufw",
                              "errors": ["ufw delete allow 443/tcp failed"], "rolled_back": True,
                              "rollback_errors": []}
        report = await w.service.apply("xray", "a" * 64, ADMIN)
        assert not report.ok and report.rolled_back and report.failed_step == "ufw"
        failed = [d for a, d in await _audit_actions(w) if a == "protocol_uninstall_failed"]
        assert failed[0]["step"] == "ufw" and failed[0]["rolled_back"] is True and failed[0]["backup"] == "/b.tar.gz"
        assert not w.registry.is_uninstalled("xray")
        mod = next(m for m in await w.repo.get_all() if m.name == "xray")
        assert mod.uninstalled_at is None
    finally:
        await w.db.close()


async def test_nothing_to_do_neither_purges_nor_applies(tmp_path: Path) -> None:
    w = await _world(tmp_path)
    try:
        w.runner.plans = [_plan(nothing_to_do=True, state="uninstalled")]
        report = await w.service.apply("xray", "0" * 64, ADMIN)
        assert report.ok and report.nothing_to_do
        assert [c[0] for c in w.runner.calls] == ["plan"]
        assert len(await w.keys.list_by_type_statuses(VpnKeyType.XRAY, {VpnKeyStatus.ACTIVE})) == 2
    finally:
        await w.db.close()


async def test_relays_are_warned_about_in_an_xray_plan(tmp_path: Path) -> None:
    w = await _world(tmp_path)
    try:
        w.service._relays = SimpleNamespace(list_all=_async([SimpleNamespace(name="ru1")]))
        w.runner.plans = [_plan()]
        plan = await w.service.plan("xray", ADMIN)
        assert plan.bot_warnings == ("relays:ru1",)
        assert "ru1" in uninstall_plan_text(plan) and "VLESS" in uninstall_plan_text(plan)
    finally:
        await w.db.close()


def _async(value: object) -> Any:
    async def fn(*args: object, **kwargs: object) -> object:
        return value
    return fn


# --------------------------------------------------------------------------- #
# Texts
# --------------------------------------------------------------------------- #
def test_a_long_awg_plan_fits_one_message() -> None:
    files = [{"path": f"/etc/amnezia/amneziawg/awg0.conf.2026-11-0{i % 9}T000000_0000.{i}.x.bak", "kind": "file",
              "state": "delete", "size": 1430, "entries": 0, "step": "files", "group": "awg", "reason": ""}
             for i in range(400)]
    plan = UninstallPlan.from_json(_plan("awg", files=files, units=[], ufw=[]))
    text = uninstall_plan_text(plan)
    assert len(text) <= MAX_MESSAGE
    assert "400" in text


def test_plan_text_lists_every_section() -> None:
    plan = UninstallPlan.from_json(_plan(
        "hysteria2",
        files=[{"path": "/etc/hysteria", "kind": "dir", "state": "delete", "size": 10, "entries": 3, "step": "files"},
               {"path": "/usr/local/bin/hysteria", "kind": "absent", "state": "absent"},
               {"path": "/usr/local/bin/x", "kind": "file", "state": "skip", "reason": "owned by the package p"}],
        users=[{"name": "hysteria", "uid": "992", "state": "delete"},
               {"name": "vpn_socks_x", "uid": "990", "state": "keep", "reason": "owns files"}],
        packages=[{"name": "dante-server", "state": "purge", "version": "1.4.3"}],
        env={"key": "HYSTERIA2_ENABLED", "state": "set_false"},
    ))
    text = uninstall_plan_text(plan)
    for key in ("module_uninstall_section_units", "module_uninstall_section_files", "module_uninstall_section_ufw",
                "module_uninstall_section_packages", "module_uninstall_section_users",
                "module_uninstall_section_absent", "module_uninstall_section_shared",
                "module_uninstall_section_kept"):
        assert t(key) in text, key
    assert "HYSTERIA2_ENABLED=false" in text and "/var/backups/vpn-bot/uninstall" in text
    assert "/usr/local/bin/hysteria" in text and "owned by the package p" in text


def test_a_blocked_plan_offers_no_confirm_button() -> None:
    plan = UninstallPlan.from_json(_plan(blocking=["/usr/local/etc/xray: is a symlink"]))
    assert t("module_uninstall_section_blocking") in uninstall_plan_text(plan)
    kb = handlers._plan_markup("xray", plan)
    assert not any(":x:" in (b.callback_data or "") for row in kb.inline_keyboard for b in row)
    ok = handlers._plan_markup("xray", UninstallPlan.from_json(_plan()))
    assert any(b.callback_data == "admin:module:uninst:xray:x:" + "a" * 12 for row in ok.inline_keyboard for b in row)


def test_report_texts() -> None:
    ok = UninstallReport(protocol="xray", ok=True, purged=3, backup="/b.tar.gz", rollback_command="tar -xzf /b",
                         removed=({"kind": "dir", "item": "/usr/local/etc/xray", "detail": ""},))
    text = uninstall_report_text(ok)
    assert t("module_uninstall_ok", label=PROTOCOL_DISPLAY["xray"], purged=3) in text
    assert "/b.tar.gz" in text and "tar -xzf /b" in text
    rb = UninstallReport(protocol="awg", ok=False, failed_step="ufw", rolled_back=True, errors=("boom",))
    assert "UFW" in uninstall_report_text(rb) and "boom" in uninstall_report_text(rb)
    bad = UninstallReport(protocol="awg", ok=False, failed_step="users", rolled_back=True,
                          rollback_errors=("ufw allow 11880/udp",), rollback_command="tar")
    assert t("module_uninstall_failed_rollback_incomplete", label=PROTOCOL_DISPLAY["awg"],
             step=t("module_uninstall_step_users")) in uninstall_report_text(bad)


# --------------------------------------------------------------------------- #
# The panel
# --------------------------------------------------------------------------- #
def _buttons(kb: Any) -> list[tuple[str, str]]:
    return [(b.text, b.callback_data or "") for row in kb.inline_keyboard for b in row]


def test_the_panel_shows_three_states(tmp_path: Path) -> None:
    from repositories.protocol_modules import ProtocolModule

    mods = [ProtocolModule("xray", True), ProtocolModule("awg", False), ProtocolModule("socks5", True),
            ProtocolModule("mtproto", False), ProtocolModule("hysteria2", True)]
    buttons = _buttons(modules_panel_keyboard(mods, frozenset({"mtproto"})))
    assert (f"🗑 {PROTOCOL_DISPLAY['mtproto']}", "noop") in buttons
    assert (t("btn_module_enable_locked"), "admin:module:enable:mtproto") in buttons
    assert (t("btn_module_uninstall", label=PROTOCOL_DISPLAY["awg"]), "admin:module:uninst:awg") in buttons
    assert not any(cb == "admin:module:uninst:mtproto" for _, cb in buttons)
    assert (t("btn_module_disable"), "admin:module:disable:socks5") in buttons
    confirm = _buttons(module_disable_confirm1_keyboard("hysteria2"))
    assert confirm[:2] == [(t("btn_module_disable_only"), "admin:module:disable:hysteria2:2"),
                           (t("btn_module_disable_uninstall"), "admin:module:uninst:hysteria2")]
    plan_kb = _buttons(module_uninstall_plan_keyboard("hysteria2", "f" * 12))
    assert all(len(cb.encode()) <= 64 for _, cb in plan_kb)


def test_every_module_callback_reaches_a_handler() -> None:
    """The old patterns were [a-z]+: socks5 and hysteria2 matched no handler at all."""
    source = Path(handlers.__file__).read_text(encoding="utf-8")
    patterns = [re.compile(p) for p in re.findall(r'F\.data\.regexp\(r"([^"]+)"\)', source)]
    assert "[a-z]+" not in source
    for name in PROTOCOL_NAMES:
        for data in (f"admin:module:disable:{name}", f"admin:module:disable:{name}:2",
                     f"admin:module:disable:{name}:exec", f"admin:module:enable:{name}",
                     f"admin:module:enable:{name}:exec", f"admin:module:uninst:{name}",
                     f"admin:module:uninst:{name}:x:{'0' * 12}"):
            assert sum(bool(p.fullmatch(data)) for p in patterns) == 1, data


class _Message:
    def __init__(self) -> None:
        self.sent: list[tuple[str, Any]] = []

    async def edit_text(self, text: str, reply_markup: Any = None, **kwargs: object) -> None:
        self.sent.append((text, reply_markup))


class _Callback:
    def __init__(self, data: str, user_id: int = ADMIN) -> None:
        self.from_user = SimpleNamespace(id=user_id)
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


@pytest.fixture(autouse=True)
def _allow_private(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr(handlers, "ensure_private_callback", allow)


async def test_enable_of_a_removed_protocol_is_refused_in_the_panel(tmp_path: Path) -> None:
    w = await _world(tmp_path, keys=0)
    try:
        _marker(tmp_path / "uninstalled", "mtproto")
        w.registry.refresh()
        services = SimpleNamespace(users=w.users, modules=w.modules, protocol_uninstall=w.service)
        cb = _Callback("admin:module:enable:mtproto")
        await handlers.admin_module_enable_confirm(cb, services)  # type: ignore[arg-type]
        assert (t("module_enable_blocked_uninstalled"), True) in cb.answers
        assert cb.message.sent == []
    finally:
        await w.db.close()


async def test_the_plan_screen_and_the_confirmed_apply(tmp_path: Path) -> None:
    w = await _world(tmp_path)
    try:
        services = SimpleNamespace(users=w.users, modules=w.modules, protocol_uninstall=w.service)
        w.runner.plans = [_plan()]
        cb = _Callback("admin:module:uninst:xray")
        await handlers.admin_module_uninstall_plan(cb, services)  # type: ignore[arg-type]
        text, kb = cb.message.sent[-1]
        assert PROTOCOL_DISPLAY["xray"] in text and "/usr/local/etc/xray" in text
        assert ("⚠️ ПОДТВЕРДИТЬ УДАЛЕНИЕ С СЕРВЕРА", "admin:module:uninst:xray:x:" + "a" * 12) in _buttons(kb)

        stale = _Callback("admin:module:uninst:xray:x:" + "e" * 12)
        await handlers.admin_module_uninstall_exec(stale, services)  # type: ignore[arg-type]
        assert (t("module_uninstall_plan_expired"), True) in stale.answers
        assert [c[0] for c in w.runner.calls] == ["plan"]

        w.runner.apply_out = {"ok": True, "protocol": "xray", "backup": "/b.tar.gz", "removed": [],
                              "already_absent": [], "skipped": [], "errors": []}
        go = _Callback("admin:module:uninst:xray:x:" + "a" * 12)
        await handlers.admin_module_uninstall_exec(go, services)  # type: ignore[arg-type]
        assert go.message.sent[0][0] == t("module_uninstall_running")
        assert t("module_uninstall_ok", label=PROTOCOL_DISPLAY["xray"], purged=2) in go.message.sent[-1][0]
    finally:
        await w.db.close()


async def test_a_purge_failure_is_written_into_the_message(tmp_path: Path) -> None:
    w = await _world(tmp_path, fail_purge=True)
    try:
        services = SimpleNamespace(users=w.users, modules=w.modules, protocol_uninstall=w.service)
        w.runner.plans = [_plan()]
        await handlers.admin_module_uninstall_plan(_Callback("admin:module:uninst:xray"), services)  # type: ignore[arg-type]
        go = _Callback("admin:module:uninst:xray:x:" + "a" * 12)
        await handlers.admin_module_uninstall_exec(go, services)  # type: ignore[arg-type]
        assert go.message.sent[-1][0] == t("module_uninstall_purge_failed", failed=1)
        assert [c[0] for c in w.runner.calls] == ["plan", "plan"]
    finally:
        await w.db.close()


# --------------------------------------------------------------------------- #
# End to end through the REAL helper, root model, on a fake host
# --------------------------------------------------------------------------- #
async def test_end_to_end_with_the_real_helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from adapters.shell_runner import ShellRunner
    from test_protocol_uninstall_helper import Host, xray_host

    host = Host(tmp_path / "host")
    xray_host(host)
    for name, value in {
        "PATH": f"{host.bin}:/usr/bin:/bin", "ST": str(host.st), "CALLS": str(host.calls),
        "ROOTFS": str(host.root.resolve()), "VPN_BOT_UNINSTALL_ROOT": str(host.root),
        "VPN_BOT_UNINSTALL_SELFTEST_BIN": str(host.bin), "GIT_CONFIG_GLOBAL": "/dev/null",
    }.items():
        monkeypatch.setenv(name, value)
    w = await _world(tmp_path)
    try:
        marker_dir = host.p("etc/vpn-bot/uninstalled")
        registry = UninstallRegistry(marker_dir)
        w.modules.attach_uninstall_registry(registry)
        service = ProtocolUninstallService(
            settings=w.settings, shell=ShellRunner(), registry=registry, modules=w.modules, modules_repo=w.repo,
            users=w.users, backend_health=w.health,
        )
        assert service.helper_path == REPO_HELPER_PATH
        plan = await service.plan("xray", ADMIN)
        assert plan.state == "installed" and not plan.blocking
        report = await service.apply("xray", plan.sha256, ADMIN)
        assert report.ok, report
        assert registry.is_uninstalled("xray") and not host.p("usr/local/etc/xray").exists()
        assert host.p("etc/nginx/nginx.conf").exists()
        assert report.backup.startswith("/var/backups/vpn-bot/uninstall/xray-")
        again = await service.apply("xray", plan.sha256, ADMIN)
        assert again.nothing_to_do
    finally:
        await w.db.close()


def test_proxy_type_backends_are_mapped() -> None:
    from services.protocol_uninstall import BACKEND_OF

    assert BACKEND_OF["socks5"] is ProxyAccessType.SOCKS5 and BACKEND_OF["mtproto"] is ProxyAccessType.MTPROTO
    assert set(BACKEND_OF) == set(PROTOCOL_NAMES)
