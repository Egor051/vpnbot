
from models.dto import User
from models.enums import UserRole, parse_user_role


def is_blocked_user(user: User) -> bool:
    role = parse_user_role(user.role)
    if role == UserRole.SUPERADMIN:
        return False
    return role == UserRole.BLOCKED_USER or user.blocked_at is not None
