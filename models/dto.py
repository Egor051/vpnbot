
import json
from collections.abc import Iterable
from dataclasses import dataclass, fields

from models.enums import AccessRequestStatus, ProxyAccessStatus, ProxyAccessType, ProxyStatus, UserRole, VpnKeyStatus, VpnKeyType


def _redacted_repr(obj: object, redacted: frozenset[str]) -> str:
    """Build a dataclass-style repr with the named fields masked.

    Defence-in-depth so secret-bearing fields (e.g. AWG private_key/preshared_key
    inside ``payload``, or a proxy ``password``) can never leak through logs,
    tracebacks, or f-strings that interpolate the whole DTO.
    """
    parts = [
        f"{f.name}=" + ("'<redacted>'" if f.name in redacted else repr(getattr(obj, f.name)))
        for f in fields(obj)  # type: ignore[arg-type]
    ]
    return f"{type(obj).__name__}({', '.join(parts)})"


@dataclass(frozen=True, slots=True)
class TelegramUserProfile:
    telegram_user_id: int
    username: str | None
    first_name: str | None


@dataclass(frozen=True, slots=True)
class User:
    telegram_user_id: int
    username: str | None
    first_name: str | None
    role: UserRole
    created_at: str
    updated_at: str
    blocked_at: str | None
    note: str | None = None
    # Per-user language override; None follows the global BOT_LANGUAGE default.
    language: str | None = None
    # Opt-out toggle for "key expires in N days" reminders.
    expiry_notifications_enabled: bool = True


# Roles that may be targeted by a segmented announcement. BLOCKED_USER is always
# excluded (blocked users never receive announcements); an empty role filter means
# "every role in this tuple".
TARGETABLE_ROLES: tuple[str, ...] = (
    UserRole.SUPERADMIN.value,
    UserRole.MODERATOR.value,
    UserRole.APPROVED_USER.value,
    UserRole.PENDING_USER.value,
)
# Protocols available for segmentation: VPN key types plus proxy access types.
SEGMENT_PROTOCOLS: tuple[str, ...] = (
    VpnKeyType.XRAY.value,
    VpnKeyType.AWG.value,
    ProxyAccessType.SOCKS5.value,
    ProxyAccessType.MTPROTO.value,
)
# VLESS (xray) transports; only meaningful when xray is among the chosen protocols.
SEGMENT_TRANSPORTS: tuple[str, ...] = ("tcp", "http")


@dataclass(frozen=True, slots=True)
class RecipientFilter:
    """Audience selector for a segmented announcement.

    An empty tuple in any dimension means "no constraint on this dimension":
    empty ``roles`` targets every role in :data:`TARGETABLE_ROLES`, empty
    ``protocols`` places no protocol requirement, and empty ``transports`` places
    no transport requirement. ``transports`` only narrows the xray subset and is
    forced empty when xray is not among ``protocols``.
    """

    roles: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    transports: tuple[str, ...] = ()

    @staticmethod
    def _clean(values: Iterable[str], allowed: tuple[str, ...]) -> tuple[str, ...]:
        chosen = {value for value in values if value in allowed}
        return tuple(value for value in allowed if value in chosen)

    @classmethod
    def create(
        cls,
        *,
        roles: Iterable[str] = (),
        protocols: Iterable[str] = (),
        transports: Iterable[str] = (),
    ) -> "RecipientFilter":
        """Build a normalized filter, dropping unknown values and ordering canonically."""
        roles_t = cls._clean(roles, TARGETABLE_ROLES)
        protocols_t = cls._clean(protocols, SEGMENT_PROTOCOLS)
        transports_t = cls._clean(transports, SEGMENT_TRANSPORTS)
        if VpnKeyType.XRAY.value not in protocols_t:
            transports_t = ()
        return cls(roles=roles_t, protocols=protocols_t, transports=transports_t)

    def is_unfiltered(self) -> bool:
        """Return whether the filter constrains nothing (all targetable roles)."""
        return not self.roles and not self.protocols and not self.transports

    def to_json(self) -> str:
        """Serialize the filter to a compact JSON string for storage."""
        return json.dumps(
            {"roles": list(self.roles), "protocols": list(self.protocols), "transports": list(self.transports)},
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str | None) -> "RecipientFilter | None":
        """Parse a stored filter, returning None for empty/invalid input."""
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        return cls.create(
            roles=tuple(data.get("roles") or ()),
            protocols=tuple(data.get("protocols") or ()),
            transports=tuple(data.get("transports") or ()),
        )


@dataclass(frozen=True, slots=True)
class AccessRequest:
    id: int
    telegram_user_id: int
    username: str | None
    status: AccessRequestStatus
    requested_at: str
    decided_by: int | None
    decided_at: str | None
    decision_note: str | None


@dataclass(frozen=True, slots=True)
class AccessRequestResult:
    user: User
    request: AccessRequest | None
    created: bool


@dataclass(frozen=True, slots=True)
class VpnKey:
    id: int
    owner_user_id: int
    username: str | None
    key_type: VpnKeyType
    status: VpnKeyStatus
    note: str | None
    uuid: str | None
    email_label: str | None
    public_key: str | None
    client_ip: str | None
    payload: dict[str, object]
    public_payload: dict[str, object]
    created_at: str
    updated_at: str
    revoked_at: str | None
    deleted_at: str | None
    created_by: int
    revoked_by: int | None
    deleted_by: int | None
    expires_at: str | None = None
    # VLESS transport selector: "tcp" (vless-in, flow=xtls-rprx-vision) or "http"
    # (vless-xhttp-reality, no flow). Always "tcp" for AWG keys and legacy rows.
    transport: str = "tcp"

    def __repr__(self) -> str:
        # payload carries AWG private_key/preshared_key — never expose it in repr.
        return _redacted_repr(self, frozenset({"payload"}))


@dataclass(frozen=True, slots=True)
class TrialKeyRequest:
    id: int
    telegram_user_id: int
    key_type: VpnKeyType
    status: str
    key_id: int | None
    requested_at: str
    decided_by: int | None
    decided_at: str | None


@dataclass(frozen=True, slots=True)
class TrafficStats:
    key_id: int
    downloaded_bytes: int
    uploaded_bytes: int
    last_raw_downloaded_bytes: int | None
    last_raw_uploaded_bytes: int | None
    last_success_at: str | None
    last_attempt_at: str | None
    available: bool
    unavailable_reason: str | None
    source: str | None


@dataclass(frozen=True, slots=True)
class KeyTrafficStatsView:
    key: VpnKey
    owner: User | None
    stats: TrafficStats | None


@dataclass(frozen=True, slots=True)
class VpnKeyCreateResult:
    key: VpnKey
    config_text: str


@dataclass(frozen=True, slots=True)
class KeyOperationError:
    key_id: int
    key_type: VpnKeyType | ProxyAccessType
    error: str


@dataclass(frozen=True, slots=True)
class BlockUserResult:
    user: User
    revoked_key_ids: tuple[int, ...]
    errors: tuple[KeyOperationError, ...]
    revoked_proxy_ids: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class UnblockUserWarning:
    user: User
    has_warning: bool
    active_or_problem_key_count: int
    previous_revoke_error_count: int
    last_block_error_at: str | None
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProxyEntry:
    id: int
    proxy_type: str
    host: str
    port: int
    login: str | None
    password: str | None
    note: str | None
    status: ProxyStatus
    created_at: str
    updated_at: str

    def __repr__(self) -> str:
        # password is the upstream proxy credential — never expose it in repr.
        return _redacted_repr(self, frozenset({"password"}))


@dataclass(frozen=True, slots=True)
class ProxyAccess:
    id: int
    owner_user_id: int
    username: str | None
    access_type: ProxyAccessType
    status: ProxyAccessStatus
    payload: dict[str, object]
    public_payload: dict[str, object]
    created_at: str
    updated_at: str
    last_shown_at: str | None
    revoked_at: str | None
    deleted_at: str | None
    created_by: int
    revoked_by: int | None
    deleted_by: int | None
    reason: str | None
    error: str | None
    secret_fingerprint: str | None = None
    apply_generation: int = 0
    activated_at: str | None = None
    last_apply_at: str | None = None

    def __repr__(self) -> str:
        # payload may carry proxy secrets/credentials — never expose it in repr.
        return _redacted_repr(self, frozenset({"payload"}))


@dataclass(frozen=True, slots=True)
class ProxyAccessStatsItem:
    id: int
    owner_user_id: int
    username: str | None
    access_type: ProxyAccessType
    status: ProxyAccessStatus
    created_at: str
    updated_at: str
    activated_at: str | None
    last_shown_at: str | None
    revoked_at: str | None
    deleted_at: str | None
    host: str | None = None
    port: int | None = None
    login: str | None = None
    mtproto_mode: str | None = None
    mtproto_source: str | None = None
    secret_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class ProxyUserStats:
    owner_user_id: int
    accesses: tuple[ProxyAccessStatsItem, ...]


@dataclass(frozen=True, slots=True)
class ProxyActiveAccessRef:
    id: int
    access_type: ProxyAccessType


@dataclass(frozen=True, slots=True)
class ProxyAdminUserStats:
    telegram_user_id: int
    username: str | None
    active_socks5_count: int
    active_mtproto_count: int
    failed_count: int
    last_proxy_issued_at: str | None
    active_accesses: tuple[ProxyActiveAccessRef, ...] = ()


@dataclass(frozen=True, slots=True)
class ProxyRuntimeStats:
    socks5_enabled: bool = False
    socks5_host: str = ""
    socks5_port: int | None = None
    socks5_service_name: str = ""
    socks5_systemd_active: bool | None = None
    socks5_port_listening: bool | None = None
    mtproto_enabled: bool = False
    mtproto_host: str = ""
    mtproto_port: int | None = None
    mtproto_mode: str = "static"
    mtproto_service_name: str = "mtproxy"
    mtproto_systemd_active: bool | None = None
    mtproto_port_listening: bool | None = None
    mtproto_runtime_secret_count: int | None = None


@dataclass(frozen=True, slots=True)
class ProxyAdminStats:
    total_accesses: int
    active_total: int
    active_socks5: int
    active_mtproto: int
    apply_failed: int
    revoked: int
    deleted: int
    pending: int
    users_with_active_proxies: int
    last_issued_at: str | None
    last_failed_at: str | None
    type_status_counts: dict[ProxyAccessType, dict[ProxyAccessStatus, int]]
    mtproto_mode_counts: dict[str, int]
    users: tuple[ProxyAdminUserStats, ...]
    total_users: int
    hidden_users: int = 0
    runtime: ProxyRuntimeStats | None = None


@dataclass(frozen=True, slots=True)
class ProxyLifecycleStats:
    socks5_issued: int
    socks5_active: int
    socks5_revoked: int
    mtproto_issued: int
    mtproto_active: int
    mtproto_deactivated: int
    mtproto_managed_issued: int = 0
    mtproto_managed_active: int = 0
    mtproto_managed_revoked: int = 0
    mtproto_legacy_static: int = 0
    mtproto_apply_failed: int = 0
    mtproto_revoke_failed: int = 0


@dataclass(frozen=True, slots=True)
class ProxyServiceStatus:
    socks5_enabled: bool
    socks5_host: str
    socks5_port: int | None
    socks5_public_name: str
    socks5_service_name: str
    mtproto_enabled: bool
    mtproto_host: str
    mtproto_port: int
    mtproto_public_name: str
    mtproto_stats_url_configured: bool
    mtproto_mode: str = "static"
    mtproto_service_name: str = "mtproxy"
    mtproto_systemd_active: bool | None = None
    mtproto_port_listening: bool | None = None


@dataclass(frozen=True, slots=True)
class ShellResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0
