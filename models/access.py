from __future__ import annotations

from models.dto import User
from models.enums import UserRole


def is_blocked_user(user: User) -> bool:
    if user.role == UserRole.SUPERADMIN:
        return False
    return user.role == UserRole.BLOCKED_USER or user.blocked_at is not None
