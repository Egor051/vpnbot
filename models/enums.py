from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    SUPERADMIN = "SUPERADMIN"
    APPROVED_USER = "APPROVED_USER"
    PENDING_USER = "PENDING_USER"
    BLOCKED_USER = "BLOCKED_USER"


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


class ProxyStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class AuditEntityType(StrEnum):
    USER = "user"
    ACCESS_REQUEST = "access_request"
    VPN_KEY = "vpn_key"
    PROXY = "proxy"
    SYSTEM = "system"
