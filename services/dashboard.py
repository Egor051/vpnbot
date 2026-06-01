
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from adapters.clock import ClockProvider
from models.enums import AccessRequestStatus
from repositories.access_requests import AccessRequestRepository
from repositories.audit_log import AuditLogRepository
from repositories.dashboard import (
    DashboardRepository,
    KeysSummary,
    TopUserTraffic,
    TrafficTotals,
)
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.trial_requests import TrialKeyRequestRepository
from services.backend_health import BackendHealth, BackendHealthStatus
from services.offsite_backup import OffsiteBackupService
from services.protocol_modules import ProtocolModulesService
from warp.manager import WarpManager
from warp.state import WarpState


@dataclass(frozen=True, slots=True)
class DashboardSnapshot:
    refreshed_at: str

    # Users
    users_by_role: dict[str, int]
    new_users_7d: int
    new_users_30d: int
    users_with_active_keys: int
    pending_access_requests: int
    pending_trial_requests: int

    # Keys
    keys: KeysSummary

    # Traffic
    traffic: TrafficTotals
    top_users: list[TopUserTraffic]

    # Proxy
    active_socks5: int
    active_mtproto: int
    stuck_proxies: int

    # System
    backend_health: tuple[BackendHealthStatus, ...]
    warp: WarpState
    active_modules: list[str]
    last_backup_at: datetime | None
    db_size_bytes: int

    # Activity
    audit_count_24h: int
    audit_count_7d: int
    recent_audit_entries: list[dict]
    announcements_30d: int


class DashboardService:
    def __init__(
        self,
        *,
        repo: DashboardRepository,
        access_requests: AccessRequestRepository,
        trial_requests: TrialKeyRequestRepository,
        proxy_accesses: ProxyAccessRepository,
        audit_log: AuditLogRepository,
        backend_health: BackendHealth,
        warp: WarpManager,
        offsite_backup: OffsiteBackupService,
        modules: ProtocolModulesService,
        clock: ClockProvider,
        db_path: Path,
    ) -> None:
        self._repo = repo
        self._access_requests = access_requests
        self._trial_requests = trial_requests
        self._proxy_accesses = proxy_accesses
        self._audit_log = audit_log
        self._backend_health = backend_health
        self._warp = warp
        self._offsite_backup = offsite_backup
        self._modules = modules
        self._clock = clock
        self._db_path = db_path

    async def build_snapshot(self) -> DashboardSnapshot:
        now_dt = datetime.now(timezone.utc)
        now_str = self._clock.now()

        cutoff_7d_past = (now_dt - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
        cutoff_30d_past = (now_dt - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
        cutoff_24h_past = (now_dt - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
        cutoff_7d_future = (now_dt + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
        cutoff_30d_future = (now_dt + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")

        (
            users_by_role,
            new_7d,
            new_30d,
            users_active_keys,
            pending_access,
            pending_trial,
            keys_summary,
            traffic,
            top_users,
            proxy_lifecycle,
            audit_24h,
            audit_7d,
            recent_audit,
            ann_30d,
            all_modules,
            last_backup,
            warp_state,
        ) = await asyncio.gather(
            self._repo.count_users_by_role(),
            self._repo.count_new_users_since(cutoff_7d_past),
            self._repo.count_new_users_since(cutoff_30d_past),
            self._repo.count_users_with_active_keys(),
            self._access_requests.count_by_status(AccessRequestStatus.PENDING),
            self._trial_requests.count_pending(),
            self._repo.keys_summary(now_str, cutoff_7d_future, cutoff_30d_future),
            self._repo.traffic_totals(),
            self._repo.top_users_by_traffic(limit=5),
            self._proxy_accesses.lifecycle_stats(),
            self._repo.count_audit_since(cutoff_24h_past),
            self._repo.count_audit_since(cutoff_7d_past),
            self._audit_log.list_recent(limit=5),
            self._repo.count_announcements_since(cutoff_30d_past),
            self._modules.get_all(),
            self._offsite_backup.get_last_backup_time(),
            self._warp.get_state(),
        )

        active_socks5 = proxy_lifecycle.socks5_active
        active_mtproto = proxy_lifecycle.mtproto_active
        stuck_proxies = proxy_lifecycle.mtproto_apply_failed + proxy_lifecycle.mtproto_revoke_failed

        db_size = 0
        try:
            db_size = os.path.getsize(self._db_path)
        except OSError:
            pass

        active_module_names = [m.name for m in all_modules if m.enabled]

        return DashboardSnapshot(
            refreshed_at=now_dt.strftime("%H:%M:%S"),
            users_by_role=users_by_role,
            new_users_7d=new_7d,
            new_users_30d=new_30d,
            users_with_active_keys=users_active_keys,
            pending_access_requests=pending_access,
            pending_trial_requests=pending_trial,
            keys=keys_summary,
            traffic=traffic,
            top_users=top_users,
            active_socks5=active_socks5,
            active_mtproto=active_mtproto,
            stuck_proxies=stuck_proxies,
            backend_health=self._backend_health.snapshot(),
            warp=warp_state,
            active_modules=active_module_names,
            last_backup_at=last_backup,
            db_size_bytes=db_size,
            audit_count_24h=audit_24h,
            audit_count_7d=audit_7d,
            recent_audit_entries=recent_audit,
            announcements_30d=ann_30d,
        )
