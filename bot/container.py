
from dataclasses import dataclass

from adapters.hysteria_auth_health import Hysteria2AuthHealthProbe
from config.settings import Settings
from db.database import Database
from services.access_approval import AccessApprovalService
from services.announcements import AnnouncementService
from services.audit import AuditService
from services.awg import AwgService
from services.backend_health import BackendHealth
from services.dashboard import DashboardService
from services.hysteria import HysteriaService
from services.key_expiry import KeyExpiryService
from services.maintenance import MaintenanceService
from services.mtproto import MtProtoService
from services.notes import NotesService
from services.anomaly_detection import AnomalyDetectionService
from services.auto_refresh import LiveRefreshManager
from services.offsite_backup import OffsiteBackupService
from services.online_clients import OnlineClientsService
from services.protocol_modules import ProtocolModulesService
from services.proxy import ProxyService
from services.server_status import ServerStatusService
from services.socks5 import Socks5Service
from services.traffic_stats import TrafficStatsService
from services.trial_access import TrialAccessService
from services.users import UserService
from services.vpn_keys import VpnKeyQueryService
from services.xray import XrayService
from repositories.server_status_settings import ServerStatusSettingsRepository
from warp.manager import WarpManager
from warp.split_manager import WarpSplitManager


@dataclass(slots=True)
class Services:
    settings: Settings
    db: Database
    users: UserService
    access: AccessApprovalService
    xray: XrayService
    awg: AwgService
    hysteria: HysteriaService
    proxy: ProxyService
    socks5: Socks5Service
    mtproto: MtProtoService
    notes: NotesService
    vpn_keys: VpnKeyQueryService
    traffic_stats: TrafficStatsService
    audit: AuditService
    announcements: AnnouncementService
    backend_health: BackendHealth
    key_expiry: KeyExpiryService
    trial_access: TrialAccessService
    offsite_backup: OffsiteBackupService
    anomaly_detection: AnomalyDetectionService
    warp: WarpManager
    warp_split: WarpSplitManager
    modules: ProtocolModulesService
    dashboard: DashboardService
    server_status: ServerStatusService
    server_status_settings: ServerStatusSettingsRepository
    online_clients: OnlineClientsService
    auto_refresh: LiveRefreshManager
    maintenance: MaintenanceService
    # Loopback /healthz probe for the hy2_auth data plane; None when Hysteria2 is
    # disabled. Drives the background health loop that marks the Hysteria2 backend
    # degraded/healthy in BackendHealth.
    hysteria_health_probe: Hysteria2AuthHealthProbe | None = None
