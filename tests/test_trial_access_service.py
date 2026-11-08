"""TrialAccessService: request → approve/reject lifecycle and its failure paths.

Real: Database (tmp_path), TrialKeyRequestRepository, UserRepository,
VpnKeyRepository and AuditService. Fake: the three key provisioners (they
insert a real vpn_keys row so the trial_key_requests.key_id foreign key is
honoured, but touch no backend) and the Telegram bot.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from db.database import Database
from models.dto import TelegramUserProfile, VpnKeyCreateResult
from models.enums import UserRole, VpnKeyType
from repositories.audit_log import AuditLogRepository
from repositories.trial_requests import TrialKeyRequestRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, NotFound
from services.trial_access import TRIAL_DAYS, TrialAccessService, _trial_expires_at

ADMIN, ALICE, BLOCKED, MOD = 1, 100, 200, 300
LOGGER = "services.trial_access"


class StepClock:
    """Each now() is one second later, so 'requested after reset' is strict."""

    def __init__(self) -> None:
        self.tick = 0

    def now(self) -> str:
        self.tick += 1
        return f"2026-05-01T00:00:{self.tick:02d}+00:00"


class FakeProvisioner:
    """Stands in for Xray/AWG/Hysteria2 services: records issue/revoke calls."""

    def __init__(self, db: Database, key_type: VpnKeyType) -> None:
        self.db = db
        self.key_type = key_type
        self.issued: list[dict[str, Any]] = []
        self.issued_ids: list[int] = []
        self.revoked: list[int] = []
        self.revoke_error: BaseException | None = None

    async def _issue(self, actor: int, profile: TelegramUserProfile, note: object, **kwargs: Any) -> VpnKeyCreateResult:
        self.issued.append({"actor": actor, "owner": profile.telegram_user_id, **kwargs})
        cursor = await self.db.conn.execute(
            """
            INSERT INTO vpn_keys (owner_user_id, key_type, status, email_label, payload_json, public_payload_json,
                                  created_at, updated_at, created_by, expires_at)
            VALUES (?, ?, 'active', ?, '{}', '{}', 'now', 'now', ?, ?)
            """,
            (profile.telegram_user_id, self.key_type.value, f"{self.key_type.value}_Trial", actor, kwargs["expires_at"]),
        )
        await self.db.commit()
        assert cursor.lastrowid is not None
        key = await VpnKeyRepository(self.db).get_by_id(int(cursor.lastrowid))
        assert key is not None
        self.issued_ids.append(key.id)
        return VpnKeyCreateResult(key=key, config_text=f"{self.key_type.value}://config")

    async def create_xray_key(self, *a: Any, **kw: Any) -> VpnKeyCreateResult:
        return await self._issue(*a, **kw)

    async def create_awg_key(self, *a: Any, **kw: Any) -> VpnKeyCreateResult:
        return await self._issue(*a, **kw)

    async def issue(self, *a: Any, **kw: Any) -> VpnKeyCreateResult:
        return await self._issue(*a, **kw)

    async def _revoke(self, key_id: int, *, actor_user_id: int) -> None:
        if self.revoke_error is not None:
            raise self.revoke_error
        self.revoked.append(key_id)

    async def revoke_xray_key_system(self, key_id: int, *, actor_user_id: int) -> None:
        await self._revoke(key_id, actor_user_id=actor_user_id)

    async def revoke_awg_key_system(self, key_id: int, *, actor_user_id: int) -> None:
        await self._revoke(key_id, actor_user_id=actor_user_id)

    async def revoke_hysteria2_key_system(self, key_id: int, *, actor_user_id: int) -> None:
        await self._revoke(key_id, actor_user_id=actor_user_id)


class FakeBot:
    def __init__(self, error: BaseException | None = None) -> None:
        self.messages: list[tuple[int, str]] = []
        self.documents: list[tuple[int, str, str]] = []
        self.error = error

    async def send_message(self, chat_id: int, text: str, **kwargs: Any) -> None:
        if self.error is not None:
            raise self.error
        self.messages.append((chat_id, text))

    async def send_document(self, chat_id: int, *, document: Any, caption: str) -> None:
        if self.error is not None:
            raise self.error
        self.documents.append((chat_id, document.filename, caption))


class World:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.users = UserRepository(db)
        self.requests = TrialKeyRequestRepository(db)
        self.xray = FakeProvisioner(db, VpnKeyType.XRAY)
        self.awg = FakeProvisioner(db, VpnKeyType.AWG)
        self.hysteria = FakeProvisioner(db, VpnKeyType.HYSTERIA2)
        self.bot = FakeBot()
        self.clock = StepClock()
        self.service = TrialAccessService(
            trial_requests=self.requests,
            users_repo=self.users,
            xray=self.xray,
            awg=self.awg,
            hysteria=self.hysteria,
            audit=AuditService(AuditLogRepository(db), self.clock),  # type: ignore[arg-type]
            clock=self.clock,  # type: ignore[arg-type]
            bot=self.bot,  # type: ignore[arg-type]
        )

    async def audit_actions(self) -> list[str]:
        rows = await self.db.conn.execute_fetchall("SELECT action FROM audit_log ORDER BY id")
        return [str(r["action"]) for r in rows]


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users = UserRepository(db)
    for user_id, role in {
        ADMIN: UserRole.SUPERADMIN,
        ALICE: UserRole.PENDING_USER,
        BLOCKED: UserRole.BLOCKED_USER,
        MOD: UserRole.MODERATOR,
    }.items():
        await users.upsert_profile(TelegramUserProfile(user_id, f"u{user_id}", "U"), role, "2026-01-01T00:00:00+00:00")
    try:
        yield World(db)
    finally:
        await db.close()


# Invariant: a trial key expires exactly TRIAL_DAYS after approval, with the
# timezone kept and microseconds dropped.
def test_trial_expiry_is_seven_days_later() -> None:
    # Arrange
    now = "2026-05-01T10:20:30.123456+00:00"

    # Act
    expires = _trial_expires_at(now)

    # Assert
    assert TRIAL_DAYS == 7
    assert expires == "2026-05-08T10:20:30+00:00"


# ── request ──────────────────────────────────────────────────────────────────


# Invariant: an unknown requester is NotFound; a blocked one is AccessDenied —
# both before any request row is written.
@pytest.mark.parametrize(("user_id", "exc", "key"), [(999, NotFound, "err_user_not_found"), (BLOCKED, AccessDenied, "err_access_blocked")])
async def test_request_refused_for_unknown_or_blocked(world: World, user_id: int, exc: type[Exception], key: str) -> None:
    # Arrange — fixture users

    # Act / Assert
    with pytest.raises(exc) as excinfo:
        await world.service.create_trial_request(user_id, VpnKeyType.XRAY)
    assert excinfo.value.key == key  # type: ignore[attr-defined]
    assert await world.requests.count_pending() == 0


# Invariant: one trial per quota period — the second request is refused, and
# the first one is audited.
async def test_second_request_is_refused(world: World) -> None:
    # Arrange
    first = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)

    # Act / Assert
    with pytest.raises(AccessDenied) as excinfo:
        await world.service.create_trial_request(ALICE, VpnKeyType.AWG)
    assert excinfo.value.key == "err_trial_already_used"
    assert first.status == "pending"
    assert await world.audit_actions() == ["trial_key_requested"]


# Invariant: a rejected request does not consume the quota.
async def test_rejected_request_does_not_consume_quota(world: World) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)
    await world.service.reject_trial_request(ADMIN, req.id)

    # Act
    can = await world.service.can_request_trial(ALICE)

    # Assert
    assert can is True


# Invariant: an admin quota reset lets a user who already used a trial request
# another one, and the reset is audited.
async def test_admin_reset_restores_quota(world: World) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)
    await world.service.approve_trial_request(ADMIN, req.id)
    before = await world.service.can_request_trial(ALICE)

    # Act
    await world.service.admin_reset_trial_quota(ADMIN, ALICE)

    # Assert
    assert before is False
    assert await world.service.can_request_trial(ALICE) is True
    assert "trial_quota_reset" in await world.audit_actions()


# ── RBAC ─────────────────────────────────────────────────────────────────────


# Invariant: every decision/admin entry point is superadmin-only (a moderator
# and an unknown id are both refused).
@pytest.mark.parametrize("actor", [MOD, 999])
@pytest.mark.parametrize("op", ["count", "list", "approve", "reject", "reset"])
async def test_admin_operations_require_superadmin(world: World, actor: int, op: str) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)
    calls = {
        "count": lambda: world.service.count_pending_requests(actor),
        "list": lambda: world.service.list_pending_requests(actor),
        "approve": lambda: world.service.approve_trial_request(actor, req.id),
        "reject": lambda: world.service.reject_trial_request(actor, req.id),
        "reset": lambda: world.service.admin_reset_trial_quota(actor, ALICE),
    }

    # Act / Assert
    with pytest.raises(AccessDenied) as excinfo:
        await calls[op]()
    assert excinfo.value.key == "err_insufficient_rights"
    assert (await world.requests.get_by_id(req.id)).status == "pending"  # type: ignore[union-attr]


# Invariant: a superadmin sees the pending queue (count and page agree).
async def test_superadmin_lists_pending(world: World) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.AWG)

    # Act
    count = await world.service.count_pending_requests(ADMIN)
    page = await world.service.list_pending_requests(ADMIN)

    # Assert
    assert count == 1
    assert [r.id for r in page] == [req.id]


# ── approve ──────────────────────────────────────────────────────────────────


# Invariant: approval provisions the key through the provisioner matching the
# requested type (allow_pending_owner, 7-day expiry), links it on the request,
# audits it and delivers it — Xray/Hysteria2 as text, AWG as a .conf document.
@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.HYSTERIA2, VpnKeyType.AWG])
async def test_approve_provisions_matching_type(world: World, key_type: VpnKeyType) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, key_type)
    provisioners = {VpnKeyType.XRAY: world.xray, VpnKeyType.HYSTERIA2: world.hysteria, VpnKeyType.AWG: world.awg}

    # Act
    result = await world.service.approve_trial_request(ADMIN, req.id)

    # Assert
    (issued,) = provisioners[key_type].issued
    assert issued["owner"] == ALICE and issued["allow_pending_owner"] is True
    assert issued["expires_at"].startswith("2026-05-08")
    assert sum(len(p.issued) for p in provisioners.values()) == 1
    stored = await world.requests.get_by_id(req.id)
    assert stored is not None and (stored.status, stored.key_id, stored.decided_by) == ("approved", result.key.id, ADMIN)
    assert (await world.audit_actions())[-1] == "trial_key_approved"
    if key_type is VpnKeyType.AWG:
        assert world.bot.documents[0][0] == ALICE and world.bot.documents[0][1].endswith(".conf")
        assert world.bot.messages == []
    else:
        label = "Hysteria2" if key_type is VpnKeyType.HYSTERIA2 else "Xray"
        assert world.bot.messages[0][0] == ALICE and label in world.bot.messages[0][1]


# Invariant: a request can be decided only once — approving or rejecting an
# already approved request is refused and provisions nothing.
@pytest.mark.parametrize("op", ["approve", "reject"])
async def test_decided_request_cannot_be_decided_again(world: World, op: str) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)
    await world.service.approve_trial_request(ADMIN, req.id)

    # Act / Assert
    with pytest.raises(AccessDenied) as excinfo:
        if op == "approve":
            await world.service.approve_trial_request(ADMIN, req.id)
        else:
            await world.service.reject_trial_request(ADMIN, req.id)
    assert excinfo.value.key == "err_trial_request_processed"
    assert len(world.xray.issued) == 1


# Invariant: deciding a request id that does not exist is NotFound.
@pytest.mark.parametrize("op", ["approve", "reject"])
async def test_decide_missing_request_is_not_found(world: World, op: str) -> None:
    # Arrange — no request 999

    # Act / Assert
    with pytest.raises(NotFound) as excinfo:
        if op == "approve":
            await world.service.approve_trial_request(ADMIN, 999)
        else:
            await world.service.reject_trial_request(ADMIN, 999)
    assert excinfo.value.key == "err_trial_request_not_found"


# Invariant: if the request owner cannot be loaded, approval stops before any
# key is provisioned.
async def test_approve_without_owner_provisions_nothing(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)
    real_get = world.users.get_by_id

    async def get_by_id(user_id: int) -> Any:
        return None if user_id == ALICE else await real_get(user_id)

    monkeypatch.setattr(world.users, "get_by_id", get_by_id)

    # Act / Assert
    with pytest.raises(NotFound) as excinfo:
        await world.service.approve_trial_request(ADMIN, req.id)
    assert excinfo.value.key == "err_trial_owner_not_found"
    assert world.xray.issued == []


# Invariant: if the request cannot be marked approved after the key was
# provisioned, the orphan key is revoked through the matching provisioner, the
# rollback is audited, the original error propagates and the request stays
# pending.
@pytest.mark.parametrize("key_type", [VpnKeyType.XRAY, VpnKeyType.HYSTERIA2, VpnKeyType.AWG])
async def test_approve_rolls_back_orphan_key(world: World, monkeypatch: pytest.MonkeyPatch, key_type: VpnKeyType) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, key_type)
    provisioner = {VpnKeyType.XRAY: world.xray, VpnKeyType.HYSTERIA2: world.hysteria, VpnKeyType.AWG: world.awg}[key_type]

    async def broken_approve(**kwargs: Any) -> None:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(world.requests, "approve", broken_approve)

    # Act / Assert
    with pytest.raises(RuntimeError, match="database is locked"):
        await world.service.approve_trial_request(ADMIN, req.id)
    assert provisioner.revoked == provisioner.issued_ids and len(provisioner.issued_ids) == 1
    assert (await world.requests.get_by_id(req.id)).status == "pending"  # type: ignore[union-attr]
    assert (await world.audit_actions())[-1] == "trial_key_approve_rolled_back"
    assert world.bot.messages == [] and world.bot.documents == []


# Invariant: a rollback that itself fails is logged for manual cleanup and never
# masks the original approve() error.
async def test_failed_rollback_is_logged_not_raised(
    world: World, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)
    world.xray.revoke_error = RuntimeError("xray api down")

    async def broken_approve(**kwargs: Any) -> None:
        raise RuntimeError("original failure")

    monkeypatch.setattr(world.requests, "approve", broken_approve)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act / Assert
    with pytest.raises(RuntimeError, match="original failure"):
        await world.service.approve_trial_request(ADMIN, req.id)
    assert "ручная очистка" in caplog.text
    assert "trial_key_approve_rolled_back" not in await world.audit_actions()


# Invariant: an audit failure after a successful rollback is logged, and the
# original approve() error still propagates.
async def test_rollback_audit_failure_is_logged(
    world: World, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Arrange
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)

    async def broken_approve(**kwargs: Any) -> None:
        raise RuntimeError("original failure")

    real_write = world.service.audit.write

    async def audit_write(**kwargs: Any) -> None:
        if kwargs["action"] == "trial_key_approve_rolled_back":
            raise RuntimeError("audit down")
        await real_write(**kwargs)

    monkeypatch.setattr(world.requests, "approve", broken_approve)
    monkeypatch.setattr(world.service.audit, "write", audit_write)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act / Assert
    with pytest.raises(RuntimeError, match="original failure"):
        await world.service.approve_trial_request(ADMIN, req.id)
    assert len(world.xray.revoked) == 1
    assert "Audit write failed after trial key rollback" in caplog.text


# Invariant: a Telegram delivery failure after approval is logged — the key is
# still approved and returned.
async def test_delivery_failure_is_logged_not_raised(world: World, caplog: pytest.LogCaptureFixture) -> None:
    # Arrange
    world.bot.error = RuntimeError("Forbidden: bot was blocked by the user")
    req = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act
    result = await world.service.approve_trial_request(ADMIN, req.id)

    # Assert
    assert result.key.id > 0
    assert (await world.requests.get_by_id(req.id)).status == "approved"  # type: ignore[union-attr]
    assert "Не удалось доставить" in caplog.text


# Invariant: without a bot, approval and rejection still complete (delivery is
# optional).
async def test_no_bot_still_completes(world: World) -> None:
    # Arrange
    world.service.bot = None
    first = await world.service.create_trial_request(ALICE, VpnKeyType.XRAY)

    # Act
    await world.service.reject_trial_request(ADMIN, first.id)
    second = await world.service.create_trial_request(ALICE, VpnKeyType.AWG)
    await world.service.approve_trial_request(ADMIN, second.id)

    # Assert
    assert (await world.requests.get_by_id(second.id)).status == "approved"  # type: ignore[union-attr]
    assert world.bot.messages == [] and world.bot.documents == []


# ── reject ───────────────────────────────────────────────────────────────────


# Invariant: rejection marks the request rejected with the decider, audits it
# and notifies the requester; a notification failure is swallowed.
@pytest.mark.parametrize("bot_error", [None, RuntimeError("chat not found")])
async def test_reject_marks_audits_and_notifies(world: World, bot_error: BaseException | None) -> None:
    # Arrange
    world.bot.error = bot_error
    req = await world.service.create_trial_request(ALICE, VpnKeyType.AWG)

    # Act
    await world.service.reject_trial_request(ADMIN, req.id)

    # Assert
    stored = await world.requests.get_by_id(req.id)
    assert stored is not None and (stored.status, stored.decided_by, stored.key_id) == ("rejected", ADMIN, None)
    assert (await world.audit_actions())[-1] == "trial_key_rejected"
    if bot_error is None:
        assert world.bot.messages == [(ALICE, "К сожалению, ваша заявка на пробный доступ была отклонена.")]
    assert world.awg.issued == []


# Invariant: the request audit row carries the key type and request id.
async def test_request_audit_details(world: World) -> None:
    # Arrange / Act
    req = await world.service.create_trial_request(ALICE, VpnKeyType.HYSTERIA2)

    # Assert
    row = await world.db.conn.execute_fetchone("SELECT details_json FROM audit_log WHERE action = 'trial_key_requested'")
    assert row is not None
    assert json.loads(str(row["details_json"])) == {"key_type": "hysteria2", "request_id": req.id}
