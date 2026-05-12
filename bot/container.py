
from dataclasses import dataclass

from config.settings import Settings
from db.database import Database
from services.access_approval import AccessApprovalService
from services.announcements import AnnouncementService
from services.audit import AuditService
from services.awg import AwgService
from services.backend_health import BackendHealth
from services.mtproto import MtProtoService
from services.notes import NotesService
from services.proxy import ProxyService
from services.socks5 import Socks5Service
from services.traffic_stats import TrafficStatsService
from services.users import UserService
from services.vpn_keys import VpnKeyQueryService
from services.xray import XrayService


@dataclass(slots=True)
class Services:
    settings: Settings
    db: Database
    users: UserService
    access: AccessApprovalService
    xray: XrayService
    awg: AwgService
    proxy: ProxyService
    socks5: Socks5Service
    mtproto: MtProtoService
    notes: NotesService
    vpn_keys: VpnKeyQueryService
    traffic_stats: TrafficStatsService
    audit: AuditService
    announcements: AnnouncementService
    backend_health: BackendHealth
