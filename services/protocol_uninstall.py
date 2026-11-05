"""Cascade removal of a protocol from the HOST ("uninstall").

"Disable" (ProtocolModulesService.disable_protocol) revokes every client and
switches the module off in the database; the services, configs, binaries, units
and firewall rules stay on the server. "Uninstall" goes further: after that very
purge, the root helper ``deploy/helpers/vpn-bot-protocol-uninstall`` removes what
its compiled-in manifest names for the protocol — and nothing else.

Two-phase, so the admin confirms what is actually on the host:

1. :meth:`ProtocolUninstallService.plan` runs ``helper plan <proto>`` (read-only)
   and returns its JSON: units, files with sizes, ufw rules, packages, users, what
   is kept as shared and why, and the plan's sha256.
2. :meth:`ProtocolUninstallService.apply` re-plans and refuses when the sha256
   differs (the host changed — a fresh plan has to be confirmed), runs the purge
   (any purge failure stops here: the backend is NOT removed while clients may
   still be live on it), then ``helper apply <proto> <sha256>``, which backs up,
   removes, and rolls itself back on any error.

The marker ``/etc/vpn-bot/uninstalled/<proto>`` the helper writes last is the
source of truth that a protocol is gone; the ``protocol_modules.uninstalled_*``
columns only mirror it for the panel and the audit trail. :class:`UninstallRegistry`
is the in-process view of the markers every backend consumer asks — startup
reconcile, the stats collectors, the health probe, the anomaly detector, the
subscription composition — so nothing keeps talking to a backend that is gone.

Both privilege models: in the root model the helper runs directly from this
checkout (same code version as the bot, no installed copy to drift); in helper
mode it runs as ``sudo -n /usr/local/sbin/vpn-bot-protocol-uninstall`` under the
exact-path sudoers grant. ``PROTOCOL_UNINSTALL_HELPER_PATH`` overrides either.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adapters.privileged_helpers import PrivilegedHelperRunner
from adapters.shell_runner import COMMAND_NOT_FOUND_RETURNCODE, TIMEOUT_RETURNCODE, ShellRunner
from config.settings import Settings
from models.enums import AuditEntityType, ProxyAccessType, VpnKeyType
from repositories.protocol_modules import PROTOCOL_NAMES, ProtocolModulesRepository
from services.backend_health import BackendHealth, BackendType
from services.errors import InvalidOperation

logger = logging.getLogger(__name__)

HELPER_NAME = "vpn-bot-protocol-uninstall"
INSTALLED_HELPER_PATH = Path("/usr/local/sbin") / HELPER_NAME
REPO_HELPER_PATH = Path(__file__).resolve().parents[1] / "deploy" / "helpers" / HELPER_NAME

# The backend each module drives, for BackendHealth.
BACKEND_OF: dict[str, BackendType] = {
    "xray": VpnKeyType.XRAY,
    "awg": VpnKeyType.AWG,
    "hysteria2": VpnKeyType.HYSTERIA2,
    "socks5": ProxyAccessType.SOCKS5,
    "mtproto": ProxyAccessType.MTPROTO,
}

PLAN_TIMEOUT_SECONDS = 300.0
# A purge of dante-server, a tar of /var/log/xray and a `find /` per user check
# all fit in here. The runner SIGKILLs on timeout, which a root helper cannot
# trap — so this is generous on purpose: a killed apply is the one case its own
# rollback cannot cover.
APPLY_TIMEOUT_SECONDS = 1800.0
HELPER_OUTPUT_LIMIT = 2_000_000
# A confirmed plan expires: the button under an old plan message must not apply.
PLAN_TTL_SECONDS = 15 * 60
SHA_PREFIX_LEN = 12

# Helper exit codes (see the helper's header).
EXIT_VALIDATION = 64
EXIT_PLAN_CHANGED = 65
EXIT_REFUSED = 66
EXIT_BACKUP = 67
EXIT_ROLLED_BACK = 70
EXIT_ROLLBACK_FAILED = 71


# --------------------------------------------------------------------------- #
# Errors (InvalidOperation: the panel shows them as an alert)
# --------------------------------------------------------------------------- #
class UninstallError(InvalidOperation):
    """A refusal or failure the admin must see."""


class ProtocolUninstalledError(UninstallError):
    """The protocol is removed from the host: it cannot simply be switched on."""


class PlanChangedError(UninstallError):
    """The host no longer matches the confirmed plan; ``plan`` is the fresh one."""

    def __init__(self, plan: UninstallPlan) -> None:
        super().__init__(
            "План удаления устарел: сервер изменился. Проверьте новый план.",
            key="module_uninstall_plan_changed",
        )
        self.plan = plan


class PurgeFailedError(UninstallError):
    """The per-client purge left records behind: the backend is not removed."""

    def __init__(self, failed: int) -> None:
        super().__init__(
            f"Не удалось снять доступ у {failed} записей — удаление с сервера не запускалось.",
            key="module_uninstall_purge_failed",
            params={"failed": failed},
        )
        self.failed = failed


# --------------------------------------------------------------------------- #
# Markers
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class UninstallMarker:
    protocol: str
    ts: str | None = None
    sha256: str | None = None
    backup: str | None = None


class UninstallRegistry:
    """Which protocols are removed from this host — read from the marker files.

    ``marker_dir=None`` (every Settings a test builds by hand) means "no marker
    ever": nothing on the real host is read. A marker that exists but cannot be
    parsed still counts — its existence is the fact, its content only detail.
    """

    def __init__(self, marker_dir: Path | None) -> None:
        self._dir = marker_dir
        self._markers: dict[str, UninstallMarker] = {}

    @property
    def marker_dir(self) -> Path | None:
        return self._dir

    def refresh(self) -> frozenset[str]:
        markers: dict[str, UninstallMarker] = {}
        if self._dir is not None:
            for name in PROTOCOL_NAMES:
                path = self._dir / name
                try:
                    if not path.is_file():
                        continue
                except OSError:
                    continue
                markers[name] = _read_marker(name, path)
        self._markers = markers
        return frozenset(markers)

    def is_uninstalled(self, name: str) -> bool:
        return name in self._markers

    def marker(self, name: str) -> UninstallMarker | None:
        return self._markers.get(name)

    @property
    def names(self) -> frozenset[str]:
        return frozenset(self._markers)


def _read_marker(name: str, path: Path) -> UninstallMarker:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("Protocol uninstall marker %s is unreadable; %s still counts as removed", path, name)
        return UninstallMarker(protocol=name)
    if not isinstance(data, dict):
        return UninstallMarker(protocol=name)
    return UninstallMarker(
        protocol=name,
        ts=_opt_str(data.get("ts")),
        sha256=_opt_str(data.get("sha256")),
        backup=_opt_str(data.get("backup")),
    )


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _str(value: object) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _records(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, dict))


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(_str(item) for item in value)


# --------------------------------------------------------------------------- #
# Plan and report
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class UninstallPlan:
    protocol: str
    sha256: str
    state: str
    nothing_to_do: bool
    blocking: tuple[str, ...]
    warnings: tuple[str, ...]
    units: tuple[dict[str, object], ...]
    files: tuple[dict[str, object], ...]
    ufw: tuple[dict[str, object], ...]
    packages: tuple[dict[str, object], ...]
    users: tuple[dict[str, object], ...]
    skipped_shared: tuple[dict[str, object], ...]
    env_key: str
    env_state: str
    marker_path: str
    marker_state: str
    backup_dir: str
    backup_estimate_bytes: int
    # Added by the bot, not by the helper (it cannot see the database).
    bot_warnings: tuple[str, ...] = ()

    @property
    def sha_prefix(self) -> str:
        return self.sha256[:SHA_PREFIX_LEN]

    @classmethod
    def from_json(cls, data: Mapping[str, Any], *, bot_warnings: Sequence[str] = ()) -> UninstallPlan:
        env = data.get("env") if isinstance(data.get("env"), dict) else {}
        marker = data.get("marker") if isinstance(data.get("marker"), dict) else {}
        assert isinstance(env, dict) and isinstance(marker, dict)
        return cls(
            protocol=_str(data.get("protocol")),
            sha256=_str(data.get("sha256")),
            state=_str(data.get("state")),
            nothing_to_do=bool(data.get("nothing_to_do")),
            blocking=_strings(data.get("blocking")),
            warnings=_strings(data.get("warnings")),
            units=_records(data.get("units")),
            files=_records(data.get("files")),
            ufw=_records(data.get("ufw")),
            packages=_records(data.get("packages")),
            users=_records(data.get("users")),
            skipped_shared=_records(data.get("skipped_shared")),
            env_key=_str(env.get("key")),
            env_state=_str(env.get("state")),
            marker_path=_str(marker.get("path")),
            marker_state=_str(marker.get("state")),
            backup_dir=_str(data.get("backup_dir")),
            backup_estimate_bytes=_int(data.get("backup_estimate_bytes")),
            bot_warnings=tuple(bot_warnings),
        )


@dataclass(frozen=True, slots=True)
class UninstallReport:
    protocol: str
    ok: bool
    nothing_to_do: bool = False
    sha256: str = ""
    backup: str = ""
    removed: tuple[dict[str, object], ...] = ()
    already_absent: tuple[dict[str, object], ...] = ()
    skipped: tuple[dict[str, object], ...] = ()
    errors: tuple[str, ...] = ()
    failed_step: str = ""
    rolled_back: bool = False
    rollback_errors: tuple[str, ...] = ()
    rollback_command: str = ""
    purged: int = 0
    exit_code: int = 0

    @classmethod
    def from_json(cls, protocol: str, data: Mapping[str, Any], *, exit_code: int, purged: int) -> UninstallReport:
        return cls(
            protocol=protocol,
            ok=bool(data.get("ok")) and exit_code == 0,
            nothing_to_do=bool(data.get("nothing_to_do")),
            sha256=_str(data.get("sha256")),
            backup=_str(data.get("backup")),
            removed=_records(data.get("removed")),
            already_absent=_records(data.get("already_absent")),
            skipped=_records(data.get("skipped")),
            errors=_strings(data.get("errors")) or ((_str(data.get("detail")),) if data.get("detail") else ()),
            failed_step=_str(data.get("failed_step")),
            rolled_back=bool(data.get("rolled_back")),
            rollback_errors=_strings(data.get("rollback_errors")),
            rollback_command=_str(data.get("rollback_command")),
            purged=purged,
            exit_code=exit_code,
        )


@dataclass(slots=True)
class _PendingPlan:
    sha256: str
    created: float = field(default_factory=time.monotonic)


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #
class ProtocolUninstallService:
    def __init__(
        self,
        *,
        settings: Settings,
        shell: ShellRunner,
        registry: UninstallRegistry,
        modules: Any,
        modules_repo: ProtocolModulesRepository,
        users: Any,
        audit: Any = None,
        backend_health: BackendHealth | None = None,
        relays: Any = None,
        runner: PrivilegedHelperRunner | None = None,
        helper_path: Path | None = None,
    ) -> None:
        self._settings = settings
        self._registry = registry
        self._modules = modules
        self._repo = modules_repo
        self._users = users
        self._audit = audit
        self._backend_health = backend_health
        self._relays = relays
        self._runner = runner or PrivilegedHelperRunner(shell=shell, use_sudo=settings.privilege_helpers_enabled)
        self._helper_path = helper_path or resolve_helper_path(settings)
        self._lock = asyncio.Lock()
        self._pending: dict[tuple[int, str], _PendingPlan] = {}

    @property
    def registry(self) -> UninstallRegistry:
        return self._registry

    @property
    def helper_path(self) -> Path:
        return self._helper_path

    def is_uninstalled(self, name: str) -> bool:
        return self._registry.is_uninstalled(name)

    # ── boot ────────────────────────────────────────────────────────────────
    async def reconcile_markers(self) -> dict[str, str]:
        """Bring the DB columns in line with the markers (the truth) and say so.

        Returns {protocol: what was done} for every mismatch; a mismatch is a
        warning in the log, never a startup failure.
        """
        self._registry.refresh()
        changes: dict[str, str] = {}
        modules = {m.name: m for m in await self._repo.get_all()}
        for name in PROTOCOL_NAMES:
            marker = self._registry.marker(name)
            module = modules.get(name)
            db_uninstalled = module is not None and module.uninstalled_at is not None
            if marker is not None and not db_uninstalled:
                logger.warning(
                    "Protocol %s: marker %s says removed from the host, the database did not — "
                    "recording it (the marker is the source of truth)",
                    name, self._marker_path(name),
                )
                await self._repo.set_uninstalled(
                    name,
                    uninstalled_at=marker.ts or _now(),
                    uninstalled_by=None,
                    backup=marker.backup,
                )
                changes[name] = "marked_uninstalled"
            elif marker is None and db_uninstalled:
                logger.warning(
                    "Protocol %s: the database says removed from the host, but there is no marker %s "
                    "(reinstalled by hand?) — clearing the flag; the module stays switched off",
                    name, self._marker_path(name),
                )
                await self._repo.clear_uninstalled(name)
                changes[name] = "cleared"
            if marker is not None:
                self._mark_backend(name)
        return changes

    def _marker_path(self, name: str) -> str:
        d = self._registry.marker_dir
        return str(d / name) if d is not None else f"<no marker dir>/{name}"

    def _mark_backend(self, name: str) -> None:
        backend = BACKEND_OF.get(name)
        if self._backend_health is not None and backend is not None:
            self._backend_health.mark_uninstalled(backend)

    # ── plan ────────────────────────────────────────────────────────────────
    async def plan(self, name: str, actor_id: int) -> UninstallPlan:
        await self._require_superadmin(actor_id)
        _check_name(name)
        plan = await self._run_plan(name)
        self._pending[actor_id, name] = _PendingPlan(plan.sha256)
        return plan

    async def _run_plan(self, name: str) -> UninstallPlan:
        rc, data = await self._helper(["plan", name], timeout=PLAN_TIMEOUT_SECONDS)
        if rc != 0 or not data.get("ok"):
            raise _helper_failure("plan", rc, data)
        return UninstallPlan.from_json(data, bot_warnings=await self._bot_warnings(name))

    async def _bot_warnings(self, name: str) -> tuple[str, ...]:
        warnings: list[str] = []
        if name == "xray" and self._relays is not None:
            try:
                relays = await self._relays.list_all()
            except Exception:
                logger.warning("Cannot list relays for the Xray uninstall plan", exc_info=True)
                relays = []
            if relays:
                warnings.append("relays:" + ",".join(sorted(str(getattr(r, "name", r)) for r in relays)))
        return tuple(warnings)

    def resolve_sha(self, actor_id: int, name: str, prefix: str) -> str | None:
        """The full sha256 of the plan this admin was last shown, if it is still valid
        and *prefix* (the one in the button) belongs to it."""
        pending = self._pending.get((actor_id, name))
        if pending is None or time.monotonic() - pending.created > PLAN_TTL_SECONDS:
            return None
        if not prefix or not pending.sha256.startswith(prefix):
            return None
        return pending.sha256

    # ── apply ───────────────────────────────────────────────────────────────
    async def apply(self, name: str, sha256: str, actor_id: int) -> UninstallReport:
        await self._require_superadmin(actor_id)
        _check_name(name)
        if self._lock.locked():
            raise UninstallError("Удаление протокола уже выполняется.", key="module_uninstall_busy")
        async with self._lock:
            # 1. The host must still be the one the admin confirmed.
            fresh = await self._run_plan(name)
            if fresh.nothing_to_do:
                self._registry.refresh()
                await self.reconcile_markers()
                return UninstallReport(protocol=name, ok=True, nothing_to_do=True, sha256=fresh.sha256)
            if fresh.sha256 != sha256:
                self._pending[actor_id, name] = _PendingPlan(fresh.sha256)
                raise PlanChangedError(fresh)
            if fresh.blocking:
                raise UninstallError(
                    "План содержит блокирующие находки — удаление невозможно.", key="module_uninstall_blocked"
                )
            # 2. Revoke every client first (the existing disable path). Anything it
            #    could not revoke may still be live on the backend: stop here.
            deleted, failed = await self._modules.disable_protocol(name, actor_id)
            if failed > 0:
                await self._write_audit(
                    actor_id,
                    "protocol_uninstall_failed",
                    {"protocol": name, "plan_sha256": _audit_sha(sha256), "step": "purge", "purged": deleted, "failed": failed},
                )
                raise PurgeFailedError(failed)
            # 3-10. The helper: backup, removal, rollback on error.
            rc, data = await self._helper(["apply", name, sha256], timeout=APPLY_TIMEOUT_SECONDS)
            if rc == EXIT_PLAN_CHANGED:
                # The purge itself changed something the plan covers.
                fresh = await self._run_plan(name)
                self._pending[actor_id, name] = _PendingPlan(fresh.sha256)
                await self._write_audit(
                    actor_id,
                    "protocol_uninstall_failed",
                    {"protocol": name, "plan_sha256": _audit_sha(sha256), "step": "plan", "error": "plan_changed",
                     "new_plan_sha256": _audit_sha(fresh.sha256), "purged": deleted},
                )
                raise PlanChangedError(fresh)
            report = UninstallReport.from_json(name, data, exit_code=rc, purged=deleted)
            self._pending.pop((actor_id, name), None)
            if report.ok:
                self._registry.refresh()
                await self._repo.set_uninstalled(
                    name, uninstalled_at=_now(), uninstalled_by=actor_id, backup=report.backup or None
                )
                self._mark_backend(name)
                await self._write_audit(
                    actor_id,
                    "protocol_uninstalled",
                    {
                        "protocol": name,
                        "plan_sha256": _audit_sha(sha256),
                        "backup": report.backup,
                        "purged": deleted,
                        "removed": len(report.removed),
                        "already_absent": len(report.already_absent),
                        "skipped": len(report.skipped),
                    },
                )
                logger.info("Protocol %s removed from the host by %d; backup %s", name, actor_id, report.backup)
            else:
                await self._write_audit(
                    actor_id,
                    "protocol_uninstall_failed",
                    {
                        "protocol": name,
                        "plan_sha256": _audit_sha(sha256),
                        "step": report.failed_step or "helper",
                        "exit_code": rc,
                        "errors": list(report.errors)[:5],
                        "rolled_back": report.rolled_back,
                        "rollback_errors": list(report.rollback_errors)[:5],
                        "backup": report.backup,
                        "purged": deleted,
                    },
                )
                logger.error(
                    "Protocol %s uninstall failed at step %s (exit %d, rolled back=%s): %s",
                    name, report.failed_step or "?", rc, report.rolled_back, "; ".join(report.errors),
                )
            return report

    # ── helpers ─────────────────────────────────────────────────────────────
    async def _helper(self, args: list[str], *, timeout: float) -> tuple[int, dict[str, Any]]:
        result = await self._runner.run(
            self._helper_path, args, timeout=timeout, max_output_chars=HELPER_OUTPUT_LIMIT
        )
        if result.returncode == TIMEOUT_RETURNCODE:
            raise UninstallError(
                "Хелпер удаления не ответил вовремя — проверьте /var/log/vpn-bot-uninstall.log на сервере.",
                key="module_uninstall_helper_timeout",
            )
        if result.returncode == COMMAND_NOT_FOUND_RETURNCODE:
            raise UninstallError(
                f"Хелпер удаления не найден: {self._helper_path}", key="module_uninstall_helper_missing",
                params={"path": str(self._helper_path)},
            )
        try:
            data = json.loads(result.stdout.strip() or "{}")
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if not data:
            raise UninstallError(
                f"Хелпер удаления завершился с кодом {result.returncode} без ответа: {result.stderr[-300:]}",
                key="module_uninstall_helper_failed",
                params={"code": result.returncode, "detail": result.stderr[-300:]},
            )
        return result.returncode, data

    async def _require_superadmin(self, actor_id: int) -> None:
        require = getattr(self._users, "require_superadmin", None)
        if require is None:
            raise InvalidOperation("Protocol RBAC не подключён")
        await require(actor_id)

    async def _write_audit(self, actor_id: int, action: str, details: dict[str, object]) -> None:
        audit = self._audit
        if audit is None:
            return
        writer = getattr(audit, "write_best_effort", None) or getattr(audit, "write", None)
        if writer is None:
            return
        try:
            await writer(
                actor_user_id=actor_id,
                action=action,
                entity_type=AuditEntityType.SYSTEM,
                entity_id=None,
                details=details,
            )
        except Exception:
            logger.warning("Audit write failed for %s", action, exc_info=True)


def resolve_helper_path(settings: Settings) -> Path:
    """The helper for this privilege model (see the module docstring)."""
    if settings.protocol_uninstall_helper_path is not None:
        return settings.protocol_uninstall_helper_path
    if settings.privilege_helpers_enabled:
        return INSTALLED_HELPER_PATH
    return REPO_HELPER_PATH


def _check_name(name: str) -> None:
    if name not in PROTOCOL_NAMES:
        raise InvalidOperation(f"Неизвестный протокол: {name}")


def _helper_failure(action: str, rc: int, data: Mapping[str, Any]) -> UninstallError:
    error = _str(data.get("error")) or f"exit {rc}"
    detail = _str(data.get("detail"))
    return UninstallError(
        f"Хелпер удаления ({action}) отказал: {error}{': ' + detail if detail else ''}",
        key="module_uninstall_helper_refused",
        params={"error": error, "detail": detail},
    )


def _audit_sha(sha256: str) -> str:
    """The plan hash as the audit log can keep it.

    AuditService masks every run of 32+ hex characters as a probable secret, which
    would turn a plan hash into "***". Grouped by 16 it stays whole and readable.
    """
    return "-".join(sha256[i : i + 16] for i in range(0, len(sha256), 16))


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
