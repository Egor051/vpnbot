from __future__ import annotations

from typing import Any

from models.dto import User


async def require_superadmin(services: Any, user_id: int) -> User:
    return await services.users.require_superadmin(user_id)


async def require_approved(services: Any, user_id: int) -> User:
    return await services.users.require_approved_or_admin(user_id)
