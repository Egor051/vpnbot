from __future__ import annotations

from dataclasses import dataclass

from models.enums import AccessRequestStatus, ProxyAccessStatus, ProxyAccessType, ProxyStatus, UserRole, VpnKeyStatus, VpnKeyType


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
