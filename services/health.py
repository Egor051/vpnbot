
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from services.backend_health import BackendHealthStatus
from utils.redact import redact

if TYPE_CHECKING:
    from services.backend_health import BackendHealth

HealthStatus = Literal["ok", "warning", "degraded", "failed"]

_STATUS_RANK: dict[HealthStatus, int] = {"ok": 0, "warning": 1, "degraded": 2, "failed": 3}


@dataclass(frozen=True, slots=True)
class HealthCheckItem:
    name: str
    status: HealthStatus
    severity: Literal["info", "warning", "critical"]
    message: str
    details: str = field(default="")


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    overall: HealthStatus
    checks: tuple[HealthCheckItem, ...]
    timestamp: str


def aggregate_status(statuses: list[HealthStatus]) -> HealthStatus:
    """Return the most severe status from the given list."""
    if not statuses:
        return "ok"
    return max(statuses, key=lambda s: _STATUS_RANK[s])


def build_result(checks: list[HealthCheckItem]) -> HealthCheckResult:
    """Combine individual health checks into an overall timestamped result."""
    overall = aggregate_status([c.status for c in checks])
    return HealthCheckResult(
        overall=overall,
        checks=tuple(checks),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def check_bot_non_root() -> HealthCheckItem:
    """Check that the bot process is not running as root."""
    if os.name != "posix":
        return HealthCheckItem(
            name="bot_runtime",
            status="warning",
            severity="warning",
            message="Non-POSIX: cannot check process UID",
        )
    uid = os.getuid()
    if uid == 0:
        return HealthCheckItem(
            name="bot_runtime",
            status="warning",
            severity="warning",
            message="Bot running as root — OK for Xray API, use vpn-bot user in production",
        )
    return HealthCheckItem(
        name="bot_runtime",
        status="ok",
        severity="info",
        message=f"Non-root OK (uid={uid})",
    )


def check_helper_mode(enabled: bool) -> HealthCheckItem:
    """Report whether privilege helper mode is enabled."""
    if enabled:
        return HealthCheckItem(
            name="helper_mode",
            status="ok",
            severity="info",
            message="PRIVILEGE_HELPERS_ENABLED=true",
        )
    return HealthCheckItem(
        name="helper_mode",
        status="warning",
        severity="warning",
        message="PRIVILEGE_HELPERS_ENABLED=false — OK for Xray API and normal operation",
    )


def check_backends(statuses: tuple[BackendHealthStatus, ...]) -> list[HealthCheckItem]:
    """Convert backend health statuses into health check items."""
    items: list[HealthCheckItem] = []
    for s in statuses:
        if s.degraded:
            items.append(
                HealthCheckItem(
                    name=f"backend_{s.backend_type.value}",
                    status="degraded",
                    severity="warning",
                    message=f"{s.label}: DEGRADED",
                    details=redact(s.reason) if s.reason else "",
                )
            )
        else:
            items.append(
                HealthCheckItem(
                    name=f"backend_{s.backend_type.value}",
                    status="ok",
                    severity="info",
                    message=f"{s.label}: OK",
                )
            )
    return items


async def check_sqlite_quick(db: Any) -> HealthCheckItem:
    """Run SQLite PRAGMA quick_check and report the result."""
    try:
        cursor = await db.conn.execute("PRAGMA quick_check")
        row = await cursor.fetchone()
        result = str(row[0]) if row else ""
        if result == "ok":
            return HealthCheckItem(
                name="db_sqlite",
                status="ok",
                severity="info",
                message="SQLite PRAGMA quick_check: ok",
            )
        return HealthCheckItem(
            name="db_sqlite",
            status="failed",
            severity="critical",
            message="SQLite PRAGMA quick_check: failed",
            details=result[:120],
        )
    except Exception as exc:
        return HealthCheckItem(
            name="db_sqlite",
            status="failed",
            severity="critical",
            message=f"SQLite quick_check error: {type(exc).__name__}",
        )


async def check_service_active(service_name: str) -> HealthCheckItem:
    """Check whether a systemd service is currently active."""
    if os.name != "posix":
        return HealthCheckItem(
            name=f"service_{service_name}",
            status="warning",
            severity="warning",
            message=f"{service_name}: systemctl check skipped (non-POSIX)",
        )
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemctl",
            "is-active",
            "--quiet",
            service_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if proc.returncode == 0:
            return HealthCheckItem(
                name=f"service_{service_name}",
                status="ok",
                severity="info",
                message=f"{service_name}: active",
            )
        return HealthCheckItem(
            name=f"service_{service_name}",
            status="degraded",
            severity="warning",
            message=f"{service_name}: not active (rc={proc.returncode})",
        )
    except FileNotFoundError:
        return HealthCheckItem(
            name=f"service_{service_name}",
            status="warning",
            severity="warning",
            message=f"{service_name}: systemctl not found",
        )
    except Exception as exc:
        return HealthCheckItem(
            name=f"service_{service_name}",
            status="warning",
            severity="warning",
            message=f"{service_name}: systemctl check failed ({type(exc).__name__})",
        )


async def run_bot_health(
    *,
    backend_health: BackendHealth,
    db: Any,
    privilege_helpers_enabled: bool,
    service_names: list[str],
) -> HealthCheckResult:
    """Run all on-demand bot health checks. Read-only. Never modifies config or restarts services."""
    checks: list[HealthCheckItem] = []
    checks.append(check_bot_non_root())
    checks.append(check_helper_mode(privilege_helpers_enabled))
    checks.extend(check_backends(backend_health.snapshot()))
    skipped = getattr(backend_health, "skipped_revocation_count", 0)
    if skipped:
        checks.append(
            HealthCheckItem(
                name="skipped_revocations",
                status="warning",
                severity="warning",
                message=f"Skipped revocations since last restart: {skipped}",
                details="Auto-revoke or expiry-revoke was skipped because a backend was degraded. Check logs for key_id details.",
            )
        )
    sqlite_result, *service_results = await asyncio.gather(
        check_sqlite_quick(db),
        *(check_service_active(name) for name in service_names),
    )
    checks.append(sqlite_result)
    checks.extend(service_results)
    return build_result(checks)
