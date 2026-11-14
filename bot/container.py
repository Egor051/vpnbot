
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
from services.host_check import HostCheckMonitor
from services.hysteria import HysteriaService
from services.key_bundle_views import KeyBundleViewService
from services.key_bundles import KeyBundleService
from services.key_expiry import KeyExpiryService
from services.maintenance import MaintenanceService
from services.mtproto import MtProtoService
from services.notes import NotesService
from services.anomaly_detection import AnomalyDetectionService
from services.auto_refresh import LiveRefreshManager
from services.offsite_backup import OffsiteBackupService
from services.online_clients import OnlineClientsService
from services.protocol_modules import ProtocolModulesService
from services.protocol_uninstall import ProtocolUninstallService
from services.proxy import ProxyService
from services.relay_agents import RelayAgentService
from services.relay_health import RelayHealthSupervisor
from services.relay_management import RelayService
from services.server_status import ServerStatusService
from services.ssh_port import SshPortMonitor
from services.ufw import UfwDeadmanMonitor
from services.socks5 import Socks5Service
from services.superadmin_claim import SuperadminClaimService
from services.totp import TotpService
from services.wizard import WizardService
from services.traffic_stats import TrafficStatsService
from services.trial_access import TrialAccessService
from services.users import UserService
from services.vpn_keys import VpnKeyQueryService
from services.warp_split_feeds import WarpSplitFeedService
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
    # Prefix feeds for the split list. Wired unconditionally so the panel can
    # always manage sources; WARP_SPLIT_FEEDS_INTERVAL_SEC gates only the
    # unattended refresh loop, never the manual one.
    warp_split_feeds: WarpSplitFeedService
    modules: ProtocolModulesService
    dashboard: DashboardService
    server_status: ServerStatusService
    server_status_settings: ServerStatusSettingsRepository
    online_clients: OnlineClientsService
    auto_refresh: LiveRefreshManager
    maintenance: MaintenanceService
    # All-in-one subscription bundles: lifecycle (create/revoke/delete) and the
    # read side the UI renders. Wired unconditionally; SUBSCRIPTION_ENABLED gates
    # every method on both, so with the flag off neither is reachable.
    key_bundles: KeyBundleService
    key_bundle_views: KeyBundleViewService
    # L4 relays (the admin panel's «🛰 Управлять relay»): the service owns the
    # in-process snapshot every link builder reads (``relays.snapshot``); the
    # supervisor runs the health loop and keeps each relay's latest probe.
    relays: RelayService
    relay_health: RelayHealthSupervisor
    # Loopback /healthz probe for the hy2_auth data plane; None when Hysteria2 is
    # disabled. Drives the background health loop that marks the Hysteria2 backend
    # degraded/healthy in BackendHealth.
    hysteria_health_probe: Hysteria2AuthHealthProbe | None = None
    # Cascade removal of a protocol from the host (Protocol modules panel). Its
    # registry (the /etc/vpn-bot/uninstalled markers) is what every backend
    # consumer asks before talking to a backend. None only in lightweight test
    # doubles; the real app always wires it.
    protocol_uninstall: ProtocolUninstallService | None = None
    # Superadmin alerts from the host invariants check (scripts/vpn-bot-host-check):
    # reads /var/lib/vpn-bot-host-check/last.json, alerts on a change. None only in
    # lightweight test doubles; HOST_CHECK_INTERVAL gates the loop in main.py.
    host_check: HostCheckMonitor | None = None
    # The SSH port migration (SSH_PORT, scripts/vpn-bot-ssh-port): tells the
    # superadmins when phase 1 starts (with «Подтвердить») and when it is done; the
    # button runs the helper's confirm. None only in lightweight test doubles.
    ssh_port: SshPortMonitor | None = None
    # The UFW dead-man (scripts/vpn-bot-ufw-apply): tells the superadmins when a change
    # of the incoming policy waits for its proof (with «Подтвердить») and how it ended.
    # None only in lightweight test doubles.
    ufw_deadman: UfwDeadmanMonitor | None = None
    # The first-superadmin claim (/start claim_<code>, scripts/install.sh). Inert
    # while any superadmin exists. None only in lightweight test doubles.
    superadmin_claim: SuperadminClaimService | None = None
    # The superadmins' TOTP second factor (services/totp.py, «🔐 Безопасность») and
    # the gate in front of dangerous actions (bot/totp_gate.py). None only in
    # lightweight test doubles: the gate is then open.
    totp: TotpService | None = None
    # The setup wizard (services/wizard.py, «🧙 Мастер настройки»): runs of fixed root
    # helper modes in their own systemd units. None only in lightweight test doubles.
    wizard: WizardService | None = None
    # Relays the bot installs and manages over SSH («🧙 Мастер настройки → 🛰 Relay»,
    # services/relay_agents.py). None only in lightweight test doubles.
    relay_agents: RelayAgentService | None = None
