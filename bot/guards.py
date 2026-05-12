
from bot.container import Services
from models.dto import User


async def require_superadmin(services: Services, user_id: int) -> User:
    return await services.users.require_superadmin(user_id)


async def require_approved(services: Services, user_id: int) -> User:
    return await services.users.require_approved_or_admin(user_id)
