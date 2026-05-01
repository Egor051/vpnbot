from __future__ import annotations

from dataclasses import dataclass

from models.enums import AccessRequestStatus, ProxyStatus, UserRole, VpnKeyStatus, VpnKeyType


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
    key_type: VpnKeyType
    error: str


@dataclass(frozen=True, slots=True)
class BlockUserResult:
    user: User
    revoked_key_ids: tuple[int, ...]
    errors: tuple[KeyOperationError, ...]


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
class ShellResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0
