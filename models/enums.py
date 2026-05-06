from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    SUPERADMIN = "SUPERADMIN"
    APPROVED_USER = "APPROVED_USER"
    PENDING_USER = "PENDING_USER"
    BLOCKED_USER = "BLOCKED_USER"


LEGACY_BLOCKED_USER_ROLE_VALUES = frozenset({"blocked", "blocked_user", "banned", "ban", "revoked"})
BLOCKED_USER_ROLE_VALUES = frozenset({UserRole.BLOCKED_USER.value, *LEGACY_BLOCKED_USER_ROLE_VALUES})


def parse_user_role(value: str | UserRole) -> UserRole:
    if isinstance(value, UserRole):
        return value
    try:
        return UserRole(value)
    except ValueError:
        normalized = value.strip().lower()
        aliases = {
            "superadmin": UserRole.SUPERADMIN,
            "super_admin": UserRole.SUPERADMIN,
            "approved": UserRole.APPROVED_USER,
            "approved_user": UserRole.APPROVED_USER,
            "pending": UserRole.PENDING_USER,
            "pending_user": UserRole.PENDING_USER,
            **{role: UserRole.BLOCKED_USER for role in LEGACY_BLOCKED_USER_ROLE_VALUES},
        }
        if normalized in aliases:
            return aliases[normalized]
        raise


class AccessRequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class VpnKeyType(StrEnum):
    XRAY = "xray"
    AWG = "awg"


class VpnKeyStatus(StrEnum):
    PENDING_APPLY = "pending_apply"
    ACTIVE = "active"
    APPLY_FAILED = "apply_failed"
    PENDING_REVOKE = "pending_revoke"
    REVOKED = "revoked"
    PENDING_DELETE = "pending_delete"
    DELETE_FAILED = "delete_failed"
    DELETED = "deleted"
    FAILED = "failed"


class ProxyAccessType(StrEnum):
    SOCKS5 = "socks5"
    MTPROTO = "mtproto"


class ProxyAccessStatus(StrEnum):
    PENDING_APPLY = "pending_apply"
    ACTIVE = "active"
    APPLY_FAILED = "apply_failed"
    PENDING_REVOKE = "pending_revoke"
    REVOKED = "revoked"
    REVOKE_FAILED = "revoke_failed"
    INACTIVE = "inactive"
    PENDING_DELETE = "pending_delete"
    DELETE_FAILED = "delete_failed"
    DELETED = "deleted"


class ProxyStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class AuditEntityType(StrEnum):
    USER = "user"
    ACCESS_REQUEST = "access_request"
    VPN_KEY = "vpn_key"
    PROXY = "proxy"
    SYSTEM = "system"
