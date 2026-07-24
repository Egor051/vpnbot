
from enum import StrEnum


class UserRole(StrEnum):
    SUPERADMIN = "SUPERADMIN"
    MODERATOR = "MODERATOR"
    APPROVED_USER = "APPROVED_USER"
    PENDING_USER = "PENDING_USER"
    BLOCKED_USER = "BLOCKED_USER"


def parse_user_role(value: str | UserRole) -> UserRole:
    if isinstance(value, UserRole):
        return value
    try:
        return UserRole(value)
    except ValueError:
        raise


class AccessRequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class VpnKeyType(StrEnum):
    XRAY = "xray"
    AWG = "awg"
    HYSTERIA2 = "hysteria2"


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


class KeyBundleStatus(StrEnum):
    """Lifecycle status of an all-in-one subscription bundle.

    Shares the exact string vocabulary of :class:`VpnKeyStatus` (so a bundle and
    its child keys speak the same status language), restricted to the states a
    bundle can occupy. A bundle has no backend of its own to apply, so the
    apply-side states (``pending_apply`` / ``apply_failed`` / ``failed``) are
    intentionally absent.
    """

    ACTIVE = "active"
    PENDING_REVOKE = "pending_revoke"
    REVOKED = "revoked"
    PENDING_DELETE = "pending_delete"
    DELETE_FAILED = "delete_failed"
    DELETED = "deleted"


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
