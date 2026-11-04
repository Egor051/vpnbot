"""Protocol-modules admin panel: the disable result shown to the superadmin.

The handler runs against a real ProtocolModulesService on a temp DB; only the
per-protocol purger is faked, so the (deleted, failed) counts come from the
service exactly as in production.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bot.handlers.admin_modules as handlers
from adapters.clock import ClockProvider
from db.database import Database
from i18n import t
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.audit_log import AuditLogRepository
from repositories.protocol_modules import PROTOCOL_DISPLAY, ProtocolModulesRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.protocol_modules import ProtocolModulesService
from services.users import UserService

from test_proxy_services import _settings

ADMIN = 1
OWNER = 100
XRAY_LABEL = PROTOCOL_DISPLAY["xray"]


class _Message:
    def __init__(self) -> None:
        self.sent: list[tuple[str, Any]] = []

    async def edit_text(self, text: str, reply_markup: Any = None, **kwargs: object) -> None:
        self.sent.append((text, reply_markup))

    @property
    def last_text(self) -> str:
        return self.sent[-1][0]


class _Callback:
    def __init__(self, data: str, user_id: int = ADMIN) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="admin", first_name="Admin")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))

    @property
    def alerts(self) -> list[str]:
        return [text for text, show_alert in self.answers if show_alert]


@pytest.fixture(autouse=True)
def _allow_private(monkeypatch: pytest.MonkeyPatch) -> None:
    async def allow(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr(handlers, "ensure_private_callback", allow)


async def _world(tmp_path: Path, *, fail_on: set[int]) -> tuple[Database, Any, VpnKeyRepository, list[int]]:
    """Three active Xray keys; the purger raises for the 0-based indices in *fail_on*."""
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users_repo = UserRepository(db)
    for uid, role in ((ADMIN, UserRole.SUPERADMIN), (OWNER, UserRole.APPROVED_USER)):
        await users_repo.upsert_profile(TelegramUserProfile(uid, f"u{uid}", f"U{uid}"), role, "now")
    keys_repo = VpnKeyRepository(db)
    key_ids: list[int] = []
    for i in range(3):
        key = await keys_repo.create_pending(
            owner_user_id=OWNER, username=f"u{OWNER}", key_type=VpnKeyType.XRAY, note=None,
            payload={}, public_payload={}, created_by=OWNER, now="now",
            uuid=f"00000000-0000-4000-8000-{i:012d}", email_label=f"xray_{i:05d}",
        )
        await keys_repo.mark_active(key.id, "now")
        key_ids.append(key.id)
    failing = {key_ids[i] for i in fail_on}

    async def xray_purger(actor_id: int, key_id: int) -> None:
        # Mirrors delete_xray_key: a backend failure leaves the row DELETE_FAILED and raises.
        if key_id in failing:
            await keys_repo.set_status(key_id, VpnKeyStatus.DELETE_FAILED, "now")
            raise RuntimeError("xray remove_client failed")
        await keys_repo.hard_delete_with_stats(key_id, "now")

    audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
    user_service = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)
    modules = ProtocolModulesService(ProtocolModulesRepository(db), db)
    modules.attach_purge_handlers(
        users=user_service, audit=audit, vpn_keys=keys_repo,
        proxy_accesses=ProxyAccessRepository(db),
        key_purgers={VpnKeyType.XRAY: xray_purger}, proxy_purgers={},
    )
    services = SimpleNamespace(users=user_service, modules=modules)
    return db, services, keys_repo, key_ids


async def test_disable_warns_when_a_purger_fails(tmp_path: Path) -> None:
    db, services, keys_repo, key_ids = await _world(tmp_path, fail_on={1})
    try:
        callback = _Callback("admin:module:disable:xray:exec")
        await handlers.admin_module_disable_exec(callback, services)  # type: ignore[arg-type]

        assert callback.alerts == []
        text = callback.message.last_text
        assert t("module_disabled_ok", label=XRAY_LABEL, deleted=2) in text
        assert t("module_disabled_partial", failed=1) in text
        # The failed row is kept (not orphaned) in DELETE_FAILED; the others are gone.
        failed_row = await keys_repo.get_by_id(key_ids[1])
        assert failed_row is not None and failed_row.status == VpnKeyStatus.DELETE_FAILED
        assert await keys_repo.get_by_id(key_ids[0]) is None
        assert await keys_repo.get_by_id(key_ids[2]) is None
        assert await services.modules.is_enabled("xray") is False
    finally:
        await db.close()


async def test_disable_without_failures_shows_no_warning(tmp_path: Path) -> None:
    db, services, _keys_repo, _key_ids = await _world(tmp_path, fail_on=set())
    try:
        callback = _Callback("admin:module:disable:xray:exec")
        await handlers.admin_module_disable_exec(callback, services)  # type: ignore[arg-type]

        assert callback.alerts == []
        assert callback.message.last_text == t("module_disabled_ok", label=XRAY_LABEL, deleted=3)
    finally:
        await db.close()
