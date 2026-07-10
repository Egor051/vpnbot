
import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from models.dto import User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from services.errors import AccessDenied, NotFound
from services.vpn_keys import VpnKeyQueryService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _active_xray_key(owner_user_id: int = 100) -> VpnKey:
    return VpnKey(
        id=10,
        owner_user_id=owner_user_id,
        username="alice",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="00000000-0000-4000-8000-000000000001",
        email_label="xray_Ab3dE",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=owner_user_id,
        revoked_by=None,
        deleted_by=None,
    )


def _user(user_id: int, role: UserRole = UserRole.APPROVED_USER) -> User:
    return User(user_id, "user", "User", role, "now", "now", None)


def _make_query_service(key: VpnKey, actor_role: UserRole = UserRole.APPROVED_USER) -> VpnKeyQueryService:
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    users_mock = MagicMock()

    async def _require_approved_or_admin(uid: int) -> User:
        return _user(uid, actor_role)

    users_mock.require_approved_or_admin = _require_approved_or_admin

    return VpnKeyQueryService(vpn_keys=vpn_keys_mock, users=users_mock)


# ---------------------------------------------------------------------------
# IDOR: get_for_actor
# ---------------------------------------------------------------------------


def test_get_for_actor_owner_can_access_own_key() -> None:
    """Key owner can always access their own key."""
    key = _active_xray_key(owner_user_id=100)
    svc = _make_query_service(key, actor_role=UserRole.APPROVED_USER)

    result = asyncio.run(svc.get_for_actor(actor_user_id=100, key_id=10))

    assert result.id == 10


def test_get_for_actor_non_owner_regular_user_is_denied() -> None:
    """A regular approved user cannot access another user's key — IDOR protection."""
    key = _active_xray_key(owner_user_id=100)
    svc = _make_query_service(key, actor_role=UserRole.APPROVED_USER)

    with pytest.raises(AccessDenied):
        asyncio.run(svc.get_for_actor(actor_user_id=999, key_id=10))


def test_get_for_actor_superadmin_can_access_any_key() -> None:
    """SUPERADMIN can access any user's key."""
    key = _active_xray_key(owner_user_id=100)
    svc = _make_query_service(key, actor_role=UserRole.SUPERADMIN)

    result = asyncio.run(svc.get_for_actor(actor_user_id=1, key_id=10))

    assert result.id == 10


def test_get_for_actor_deleted_key_raises_not_found() -> None:
    """DELETED keys are treated as not found regardless of actor."""
    key = _active_xray_key(owner_user_id=100)
    from dataclasses import replace
    deleted_key = replace(key, status=VpnKeyStatus.DELETED)

    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = deleted_key
    users_mock = MagicMock()
    svc = VpnKeyQueryService(vpn_keys=vpn_keys_mock, users=users_mock)

    with pytest.raises(NotFound):
        asyncio.run(svc.get_for_actor(actor_user_id=100, key_id=10))


def test_get_for_actor_missing_key_raises_not_found() -> None:
    """Non-existent key raises NotFound, not AccessDenied — no information leak."""
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = None
    users_mock = MagicMock()
    svc = VpnKeyQueryService(vpn_keys=vpn_keys_mock, users=users_mock)

    with pytest.raises(NotFound):
        asyncio.run(svc.get_for_actor(actor_user_id=999, key_id=10))


# ---------------------------------------------------------------------------
# IDOR: NotesService.update_key_note
# ---------------------------------------------------------------------------


def test_update_key_note_owner_can_update() -> None:
    """Key owner can update their own key's note."""
    from services.notes import NotesService

    key = _active_xray_key(owner_user_id=100)
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key
    vpn_keys_mock.update_note = AsyncMock()

    users_mock = MagicMock()

    async def _require_approved_or_admin(uid: int) -> User:
        return _user(uid, UserRole.APPROVED_USER)

    users_mock.require_approved_or_admin = _require_approved_or_admin
    users_mock.clock = MagicMock()
    users_mock.clock.now.return_value = "now"

    audit_mock = AsyncMock()

    svc = NotesService(
        vpn_keys=vpn_keys_mock,
        proxies=MagicMock(),
        users=users_mock,
        users_repo=MagicMock(),
        audit=audit_mock,
    )

    asyncio.run(svc.update_key_note(actor_user_id=100, key_id=10, note="my note"))
    vpn_keys_mock.update_note.assert_awaited_once()


def test_update_key_note_non_owner_is_denied() -> None:
    """A user cannot update another user's key note — IDOR protection."""
    from services.notes import NotesService

    key = _active_xray_key(owner_user_id=100)
    vpn_keys_mock = AsyncMock()
    vpn_keys_mock.get_by_id.return_value = key

    users_mock = MagicMock()

    async def _require_approved_or_admin(uid: int) -> User:
        return _user(uid, UserRole.APPROVED_USER)

    users_mock.require_approved_or_admin = _require_approved_or_admin

    svc = NotesService(
        vpn_keys=vpn_keys_mock,
        proxies=MagicMock(),
        users=users_mock,
        users_repo=MagicMock(),
        audit=AsyncMock(),
    )

    with pytest.raises(AccessDenied):
        asyncio.run(svc.update_key_note(actor_user_id=999, key_id=10, note="injected"))
