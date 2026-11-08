"""Socks5Service: issue / revoke / delete / startup-reconcile state machine.

Real: Database (tmp_path) + ProxyAccessRepository + AuditService, so every
status transition and every audit row is asserted as persisted.
Fake: the Dante user adapter (an in-memory "Linux user database" with
injectable failures — no useradd/passwd/userdel ever runs) and the user
service (role table).
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

import pytest
from test_proxy_services import _settings

import services.socks5 as socks5_module
from adapters.errors import DanteUserNotFoundError
from db.database import Database
from models.dto import ProxyAccess, TelegramUserProfile, User
from models.enums import ProxyAccessStatus, ProxyAccessType, UserRole
from repositories.audit_log import AuditLogRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.users import UserRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.socks5 import Socks5Service

NOW = "2026-04-01T00:00:00+00:00"
ADMIN, ALICE, BOB, MOD = 1, 100, 200, 300
LOGGER = "services.socks5"


class FixedClock:
    def now(self) -> str:
        return NOW


class FakeUsers:
    roles: ClassVar[dict[int, UserRole]] = {
        ADMIN: UserRole.SUPERADMIN,
        ALICE: UserRole.APPROVED_USER,
        BOB: UserRole.APPROVED_USER,
        MOD: UserRole.MODERATOR,
        # Extra owners: the schema allows one LIVE socks5 access per owner, so a
        # test that needs several live rows at once spreads them over these.
        **{owner: UserRole.APPROVED_USER for owner in range(101, 109)},
    }

    def _user(self, user_id: int) -> User:
        return User(user_id, f"u{user_id}", "U", self.roles[user_id], NOW, NOW, None)

    async def require_approved_or_admin(self, user_id: int) -> User:
        return self._user(user_id)

    async def require_superadmin(self, user_id: int) -> User:
        user = self._user(user_id)
        if user.role != UserRole.SUPERADMIN:
            raise AccessDenied("superadmin only")
        return user


class FakeDante:
    """In-memory Linux user DB. `fail[method]` raises on that call."""

    def __init__(self) -> None:
        self.users: set[str] = set()
        self.locked: set[str] = set()
        self.calls: list[tuple[str, str]] = []
        self.fail: dict[str, BaseException] = {}

    def _maybe_fail(self, method: str, login: str) -> None:
        self.calls.append((method, login))
        exc = self.fail.get(method)
        if exc is not None:
            raise exc

    async def exists(self, login: str) -> bool:
        self._maybe_fail("exists", login)
        return login in self.users

    async def create_user(self, login: str, password: str) -> None:
        self._maybe_fail("create_user", login)
        self.users.add(login)

    async def lock_user(self, login: str) -> None:
        self._maybe_fail("lock_user", login)
        self.locked.add(login)

    async def delete_user(self, login: str) -> None:
        self._maybe_fail("delete_user", login)
        self.users.discard(login)


class World:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.repo = ProxyAccessRepository(db)
        self.dante = FakeDante()
        self.health = BackendHealth()
        self.audit = AuditService(AuditLogRepository(db), FixedClock())  # type: ignore[arg-type]
        self.service = self.make()

    def make(self, **settings_overrides: Any) -> Socks5Service:
        return Socks5Service(
            accesses=self.repo,
            users=FakeUsers(),  # type: ignore[arg-type]
            adapter=self.dante,  # type: ignore[arg-type]
            settings=replace(_settings(), **settings_overrides),
            clock=FixedClock(),  # type: ignore[arg-type]
            audit=self.audit,
            backend_health=self.health,
        )

    async def audit_actions(self) -> list[str]:
        rows = await self.db.conn.execute_fetchall("SELECT action FROM audit_log ORDER BY id")
        return [str(r["action"]) for r in rows]

    async def audit_details(self, action: str) -> list[dict[str, object]]:
        rows = await self.db.conn.execute_fetchall(
            "SELECT details_json FROM audit_log WHERE action = ? ORDER BY id", (action,)
        )
        return [json.loads(str(r["details_json"])) for r in rows]

    async def audit_text(self) -> str:
        rows = await self.db.conn.execute_fetchall("SELECT action, details_json FROM audit_log ORDER BY id")
        return json.dumps([dict(r) for r in rows], ensure_ascii=False)

    async def seed(
        self,
        status: ProxyAccessStatus,
        *,
        owner: int = ALICE,
        login: str | None = "vpn_socks_100_aaaa",
        access_type: ProxyAccessType = ProxyAccessType.SOCKS5,
    ) -> ProxyAccess:
        payload: dict[str, object] = {"type": access_type.value}
        if login is not None:
            payload["login"] = login
            payload["password"] = "pw"
        return await self.repo.create(
            owner_user_id=owner,
            username=f"u{owner}",
            access_type=access_type,
            status=status,
            payload=payload,
            public_payload={"type": access_type.value},
            created_by=ADMIN,
            now=NOW,
        )

    async def status(self, access_id: int) -> ProxyAccessStatus:
        access = await self.repo.get_by_id(access_id)
        assert access is not None
        return access.status


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users = UserRepository(db)
    for user_id, role in FakeUsers.roles.items():
        await users.upsert_profile(TelegramUserProfile(user_id, f"u{user_id}", "U"), role, NOW)
    try:
        yield World(db)
    finally:
        await db.close()


def _profile(user_id: int) -> TelegramUserProfile:
    return TelegramUserProfile(user_id, f"u{user_id}", "U")


# ── issue: guards ────────────────────────────────────────────────────────────


# Invariant: issue is refused (with an i18n key) while SOCKS5 is disabled or
# missing its host/port, before any DB row or Linux user is created.
@pytest.mark.parametrize(
    ("overrides", "key"),
    [
        ({"socks5_enabled": False}, "err_socks5_unavailable"),
        ({"socks5_host": ""}, "err_socks5_not_configured"),
        ({"socks5_port": None}, "err_socks5_not_configured"),
    ],
)
async def test_issue_refused_when_not_enabled_or_configured(world: World, overrides: dict[str, Any], key: str) -> None:
    # Arrange
    service = world.make(**overrides)

    # Act / Assert
    with pytest.raises(InvalidOperation) as excinfo:
        await service.issue_socks5_proxy(ALICE, _profile(ALICE))
    assert excinfo.value.key == key
    assert await world.repo.list_by_owner(ALICE) == []
    assert world.dante.calls == []


# Invariant: a degraded SOCKS5 backend blocks issuing.
async def test_issue_refused_when_backend_degraded(world: World) -> None:
    # Arrange
    world.health.mark_degraded(ProxyAccessType.SOCKS5, "compensation failed")

    # Act / Assert
    with pytest.raises(Exception, match="SOCKS5|socks5|degraded|недоступ"):
        await world.service.issue_socks5_proxy(ALICE, _profile(ALICE))
    assert world.dante.calls == []


# Invariant: a non-superadmin may only issue a proxy for themself.
async def test_issue_for_another_user_needs_superadmin(world: World) -> None:
    # Arrange — ALICE (approved user) issuing for BOB

    # Act / Assert
    with pytest.raises(AccessDenied) as excinfo:
        await world.service.issue_socks5_proxy(ALICE, _profile(BOB))
    assert excinfo.value.key == "err_create_proxy_for_other"


# Invariant: the OWNER must be an approved user or superadmin — a moderator
# cannot own a SOCKS5 proxy even when a superadmin issues it.
async def test_issue_refused_for_owner_without_proxy_access(world: World) -> None:
    # Arrange — superadmin issuing for MOD

    # Act / Assert
    with pytest.raises(AccessDenied) as excinfo:
        await world.service.issue_socks5_proxy(ADMIN, _profile(MOD))
    assert excinfo.value.key == "err_proxy_owner_no_access"


# Invariant: a login prefix that leaves fewer than 4 characters of random
# suffix under the 32-char Linux limit is rejected.
async def test_issue_refused_for_overlong_login_prefix(world: World) -> None:
    # Arrange
    # 32 - len(prefix) - len("100") - 1 == 3 < 4
    service = world.make(socks5_login_prefix="p" * 25)

    # Act / Assert
    with pytest.raises(InvalidOperation, match="слишком длинный"):
        await service.issue_socks5_proxy(ALICE, _profile(ALICE))


# ── issue: login generation ──────────────────────────────────────────────────


# Invariant: a login that already exists as a Linux user is never reused; the
# generator retries with a new suffix.
async def test_unique_login_skips_existing_linux_user(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    suffixes = iter(["aaaa", "bbbb"])
    monkeypatch.setattr(socks5_module.secrets, "token_hex", lambda n: next(suffixes))
    world.dante.users.add("vpn_socks_100_aaaa")

    # Act
    access = await world.service.issue_socks5_proxy(ALICE, _profile(ALICE))

    # Assert
    assert access.payload["login"] == "vpn_socks_100_bbbb"


# Invariant: after 10 colliding attempts the issue fails cleanly and creates no
# DB row.
async def test_unique_login_gives_up_after_ten_collisions(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(socks5_module.secrets, "token_hex", lambda n: "dupe")
    world.dante.users.add("vpn_socks_100_dupe")

    # Act / Assert
    with pytest.raises(InvalidOperation, match="уникальный"):
        await world.service.issue_socks5_proxy(ALICE, _profile(ALICE))
    assert await world.repo.list_by_owner(ALICE) == []
    assert len([c for c in world.dante.calls if c[0] == "exists"]) == 10


# ── issue: backend failures ──────────────────────────────────────────────────


# Invariant: a create failure whose message contains the generated password is
# stored and audited with the password redacted, and the caller gets a generic
# InvalidOperation instead of the raw message.
async def test_issue_create_failure_redacts_password(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(Socks5Service, "_generate_password", lambda self: "LEAKY-PASSWORD")
    world.dante.fail["create_user"] = RuntimeError("chpasswd: bad line 'x:LEAKY-PASSWORD'")

    # Act / Assert
    with pytest.raises(InvalidOperation, match="redacted"):
        await world.service.issue_socks5_proxy(ALICE, _profile(ALICE))
    (access,) = await world.repo.list_by_owner(ALICE)
    assert access.status is ProxyAccessStatus.APPLY_FAILED
    assert access.error is not None and "LEAKY-PASSWORD" not in access.error and "***" in access.error
    assert "LEAKY-PASSWORD" not in await world.audit_text()
    assert "socks5_proxy_apply_failed" in await world.audit_actions()


# Invariant: a create failure that does not contain the password re-raises the
# original exception and marks the access APPLY_FAILED.
async def test_issue_create_failure_reraises_original(world: World) -> None:
    # Arrange
    world.dante.fail["create_user"] = RuntimeError("useradd: cannot lock /etc/passwd")

    # Act / Assert
    with pytest.raises(RuntimeError, match="cannot lock"):
        await world.service.issue_socks5_proxy(ALICE, _profile(ALICE))
    (access,) = await world.repo.list_by_owner(ALICE)
    assert access.status is ProxyAccessStatus.APPLY_FAILED


# Invariant: if the DB cannot mark the access active after the Linux user was
# created and deleting that user fails, compensation falls back to LOCKING it,
# the access ends APPLY_FAILED, and the backend is NOT marked degraded.
async def test_issue_compensation_falls_back_to_lock(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    async def broken_mark_active(*args: object, **kwargs: object) -> None:
        raise RuntimeError("disk I/O error")

    monkeypatch.setattr(world.repo, "mark_active", broken_mark_active)
    world.dante.fail["delete_user"] = RuntimeError("userdel: user is logged in")

    # Act / Assert
    with pytest.raises(RuntimeError, match="disk I/O error"):
        await world.service.issue_socks5_proxy(ALICE, _profile(ALICE))
    (access,) = await world.repo.list_by_owner(ALICE)
    assert access.status is ProxyAccessStatus.APPLY_FAILED
    assert str(access.payload["login"]) in world.dante.locked
    assert world.health.snapshot() == BackendHealth().snapshot()
    assert "lock_user" in await world.audit_text()


# Invariant: a compensation that disabled the Linux user but then cannot record
# APPLY_FAILED only warns — the original DB error is still what propagates.
async def test_issue_compensation_status_write_failure_only_warns(
    world: World, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Arrange
    async def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("db gone")

    monkeypatch.setattr(world.repo, "mark_active", broken)
    real_set_status = world.repo.set_status

    async def set_status(access_id: int, status: ProxyAccessStatus, now: str, **kwargs: Any) -> None:
        if status is ProxyAccessStatus.APPLY_FAILED:
            raise RuntimeError("still gone")
        await real_set_status(access_id, status, now, **kwargs)

    monkeypatch.setattr(world.repo, "set_status", set_status)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    # Act / Assert
    with pytest.raises(RuntimeError, match="db gone"):
        await world.service.issue_socks5_proxy(ALICE, _profile(ALICE))
    assert "failed to mark access apply_failed" in caplog.text
    assert world.dante.users == set()


# ── read paths ───────────────────────────────────────────────────────────────


# Invariant: asking for a config without an ACTIVE access is NotFound.
async def test_get_config_without_active_access(world: World) -> None:
    # Arrange
    await world.seed(ProxyAccessStatus.REVOKED)

    # Act / Assert
    with pytest.raises(NotFound) as excinfo:
        await world.service.get_socks5_proxy_config(ALICE)
    assert excinfo.value.key == "err_socks5_access_not_found"


# Invariant: showing an active config stamps last_shown_at and audits the view.
async def test_get_config_marks_shown(world: World) -> None:
    # Arrange
    seeded = await world.seed(ProxyAccessStatus.ACTIVE)

    # Act
    access = await world.service.get_socks5_proxy_config(ALICE)

    # Assert
    assert access.id == seeded.id
    assert access.last_shown_at == NOW
    assert await world.audit_actions() == ["socks5_proxy_shown"]


# Invariant: a user lists only their own accesses.
async def test_list_user_accesses_is_owner_scoped(world: World) -> None:
    # Arrange
    mine = await world.seed(ProxyAccessStatus.ACTIVE)
    await world.seed(ProxyAccessStatus.ACTIVE, owner=BOB, login="vpn_socks_200_bbbb")

    # Act
    listed = await world.service.list_user_proxy_accesses(ALICE)

    # Assert
    assert [a.id for a in listed] == [mine.id]


# Invariant: a missing access id is NotFound with an i18n key.
async def test_revoke_missing_access_is_not_found(world: World) -> None:
    # Arrange — no rows

    # Act / Assert
    with pytest.raises(NotFound) as excinfo:
        await world.service.revoke_socks5_proxy(ADMIN, 999)
    assert excinfo.value.key == "err_proxy_access_not_found"


# ── revoke ───────────────────────────────────────────────────────────────────


# Invariant: revoke is superadmin-only on the public entry point.
async def test_revoke_requires_superadmin(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.ACTIVE)

    # Act / Assert
    with pytest.raises(AccessDenied):
        await world.service.revoke_socks5_proxy(ALICE, access.id)
    assert await world.status(access.id) is ProxyAccessStatus.ACTIVE


# Invariant: revoke/delete refuse a non-SOCKS5 access.
@pytest.mark.parametrize("op", ["revoke", "delete"])
async def test_revoke_and_delete_refuse_other_types(world: World, op: str) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.ACTIVE, access_type=ProxyAccessType.MTPROTO, login=None)

    # Act / Assert
    with pytest.raises(InvalidOperation) as excinfo:
        if op == "revoke":
            await world.service.revoke_socks5_proxy(ADMIN, access.id)
        else:
            await world.service.delete_socks5_proxy(ADMIN, access.id)
    assert excinfo.value.key == "err_not_socks5_access"


# Invariant: revoking locks the Linux user and records who revoked and why.
async def test_revoke_locks_user(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.ACTIVE)
    world.dante.users.add("vpn_socks_100_aaaa")

    # Act
    revoked = await world.service.revoke_socks5_proxy(ADMIN, access.id, reason="abuse")

    # Assert
    assert revoked.status is ProxyAccessStatus.REVOKED
    assert (revoked.revoked_by, revoked.reason) == (ADMIN, "abuse")
    assert world.dante.locked == {"vpn_socks_100_aaaa"}
    assert await world.audit_actions() == ["socks5_proxy_revoked"]


# Invariant: a Linux user that is already gone counts as revoked (idempotent
# convergence), and an access without a login revokes without any adapter call.
@pytest.mark.parametrize("login", ["vpn_socks_100_aaaa", None])
async def test_revoke_tolerates_missing_linux_user(world: World, login: str | None) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.ACTIVE, login=login)
    world.dante.fail["lock_user"] = DanteUserNotFoundError("gone")

    # Act
    revoked = await world.service.revoke_socks5_proxy_system(ADMIN, access.id)

    # Assert
    assert revoked.status is ProxyAccessStatus.REVOKED
    if login is None:
        assert world.dante.calls == []


# Invariant: a failed lock restores the PREVIOUS status (not a stuck
# pending_revoke), records the error, audits the failure and re-raises.
async def test_revoke_failure_restores_previous_status(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.APPLY_FAILED)
    world.dante.fail["lock_user"] = RuntimeError("passwd: permission denied")

    # Act / Assert
    with pytest.raises(RuntimeError, match="permission denied"):
        await world.service.revoke_socks5_proxy(ADMIN, access.id)
    after = await world.repo.get_by_id(access.id)
    assert after is not None
    assert after.status is ProxyAccessStatus.APPLY_FAILED
    assert after.error == "passwd: permission denied"
    assert await world.audit_actions() == ["socks5_proxy_revoke_failed"]


# Invariant: revoking an already revoked/inactive/deleted access is a no-op
# (no adapter call, no audit row).
@pytest.mark.parametrize("status", [ProxyAccessStatus.REVOKED, ProxyAccessStatus.INACTIVE, ProxyAccessStatus.DELETED])
async def test_revoke_terminal_status_is_noop(world: World, status: ProxyAccessStatus) -> None:
    # Arrange
    access = await world.seed(status)

    # Act
    result = await world.service.revoke_socks5_proxy(ADMIN, access.id)

    # Assert
    assert result.status is status
    assert world.dante.calls == []
    assert await world.audit_actions() == []


# ── delete ───────────────────────────────────────────────────────────────────


# Invariant: delete removes the Linux user and marks the access DELETED.
async def test_delete_removes_user(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.REVOKED)
    world.dante.users.add("vpn_socks_100_aaaa")

    # Act
    deleted = await world.service.delete_socks5_proxy(ADMIN, access.id, reason="cleanup")

    # Assert
    assert deleted.status is ProxyAccessStatus.DELETED
    assert deleted.deleted_by == ADMIN
    assert world.dante.users == set()


# Invariant: an access without a login is deleted without touching the adapter.
async def test_delete_without_login_skips_adapter(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.APPLY_FAILED, login=None)

    # Act
    deleted = await world.service.delete_socks5_proxy(ADMIN, access.id)

    # Assert
    assert deleted.status is ProxyAccessStatus.DELETED
    assert world.dante.calls == []


# Invariant: a failed userdel leaves the access DELETE_FAILED (retryable by the
# startup reconcile), audits the failure and re-raises.
async def test_delete_failure_marks_delete_failed(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.ACTIVE)
    world.dante.fail["delete_user"] = RuntimeError("userdel: busy")

    # Act / Assert
    with pytest.raises(RuntimeError, match="busy"):
        await world.service.delete_socks5_proxy(ADMIN, access.id)
    assert await world.status(access.id) is ProxyAccessStatus.DELETE_FAILED
    assert await world.audit_actions() == ["socks5_proxy_delete_failed"]


# Invariant: deleting an already deleted access is a no-op.
async def test_delete_already_deleted_is_noop(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.DELETED)

    # Act
    result = await world.service.delete_socks5_proxy(ADMIN, access.id)

    # Assert
    assert result.status is ProxyAccessStatus.DELETED
    assert world.dante.calls == []


# Invariant: delete is superadmin-only.
async def test_delete_requires_superadmin(world: World) -> None:
    # Arrange
    access = await world.seed(ProxyAccessStatus.ACTIVE)

    # Act / Assert
    with pytest.raises(AccessDenied):
        await world.service.delete_socks5_proxy(BOB, access.id)


# ── startup reconcile ────────────────────────────────────────────────────────


# Invariant: startup reconcile converges every in-flight status against the
# Linux user DB — pending/failed apply with a user → ACTIVE, pending apply
# without one → APPLY_FAILED, pending revoke → REVOKED (user locked), pending /
# failed delete → DELETED (user removed) — and reports what it changed.
async def test_reconcile_converges_all_inflight_statuses(world: World) -> None:
    # Arrange
    apply_present = await world.seed(ProxyAccessStatus.PENDING_APPLY, owner=101, login="vpn_socks_100_a001")
    apply_missing = await world.seed(ProxyAccessStatus.PENDING_APPLY, owner=102, login="vpn_socks_100_a002")
    failed_present = await world.seed(ProxyAccessStatus.APPLY_FAILED, owner=103, login="vpn_socks_100_a003")
    failed_missing = await world.seed(ProxyAccessStatus.APPLY_FAILED, owner=104, login="vpn_socks_100_a004")
    revoke = await world.seed(ProxyAccessStatus.PENDING_REVOKE, owner=105, login="vpn_socks_100_a005")
    delete = await world.seed(ProxyAccessStatus.PENDING_DELETE, owner=106, login="vpn_socks_100_a006")
    delete_failed = await world.seed(ProxyAccessStatus.DELETE_FAILED, owner=107, login="vpn_socks_100_a007")
    active = await world.seed(ProxyAccessStatus.ACTIVE, owner=108, login="vpn_socks_100_a008")
    world.dante.users |= {"vpn_socks_100_a001", "vpn_socks_100_a003", "vpn_socks_100_a005", "vpn_socks_100_a006"}

    # Act
    summary = await world.service.reconcile_socks5_state()

    # Assert
    assert summary == {"checked": 7, "recovered": 6, "failed": 0}
    assert await world.status(apply_present.id) is ProxyAccessStatus.ACTIVE
    assert await world.status(apply_missing.id) is ProxyAccessStatus.APPLY_FAILED
    assert await world.status(failed_present.id) is ProxyAccessStatus.ACTIVE
    assert await world.status(failed_missing.id) is ProxyAccessStatus.APPLY_FAILED
    assert await world.status(revoke.id) is ProxyAccessStatus.REVOKED
    assert await world.status(delete.id) is ProxyAccessStatus.DELETED
    assert await world.status(delete_failed.id) is ProxyAccessStatus.DELETED
    assert await world.status(active.id) is ProxyAccessStatus.ACTIVE
    assert "vpn_socks_100_a005" in world.dante.locked
    assert "vpn_socks_100_a006" not in world.dante.users


# Invariant: reconcile is idempotent — a second run changes nothing and only
# re-checks the accesses that legitimately stay APPLY_FAILED.
async def test_reconcile_is_idempotent(world: World) -> None:
    # Arrange
    await world.seed(ProxyAccessStatus.PENDING_APPLY, login="vpn_socks_100_b001")
    await world.service.reconcile_socks5_state()

    # Act
    second = await world.service.reconcile_socks5_state()

    # Assert
    assert second == {"checked": 1, "recovered": 0, "failed": 0}


# Invariant: a revoke/delete whose Linux user vanished between `exists` and the
# lock/delete call still converges, and the audit records that the user did
# not exist.
@pytest.mark.parametrize(
    ("status", "method", "final", "action"),
    [
        (ProxyAccessStatus.PENDING_REVOKE, "lock_user", ProxyAccessStatus.REVOKED, "socks5_startup_revoke_completed"),
        (ProxyAccessStatus.PENDING_DELETE, "delete_user", ProxyAccessStatus.DELETED, "socks5_startup_delete_completed"),
    ],
)
async def test_reconcile_tolerates_user_vanishing_mid_flight(
    world: World, status: ProxyAccessStatus, method: str, final: ProxyAccessStatus, action: str
) -> None:
    # Arrange
    access = await world.seed(status)
    world.dante.users.add("vpn_socks_100_aaaa")
    world.dante.fail[method] = DanteUserNotFoundError("raced")

    # Act
    summary = await world.service.reconcile_socks5_state()

    # Assert
    assert summary["recovered"] == 1
    assert await world.status(access.id) is final
    (details,) = await world.audit_details(action)
    assert details["linux_user_existed"] is False


# Invariant: an access with no login is skipped with a warning (not counted as
# recovered), and one access raising does not stop the others — it is counted
# as failed and logged.
async def test_reconcile_skips_loginless_and_isolates_failures(
    world: World, caplog: pytest.LogCaptureFixture
) -> None:
    # Arrange
    loginless = await world.seed(ProxyAccessStatus.PENDING_APPLY, login=None)
    broken = await world.seed(ProxyAccessStatus.PENDING_DELETE, login="vpn_socks_100_c001")
    caplog.set_level(logging.WARNING, logger=LOGGER)
    world.dante.fail["exists"] = RuntimeError("getent crashed")

    # Act
    summary = await world.service.reconcile_socks5_state()

    # Assert
    assert summary == {"checked": 2, "recovered": 0, "failed": 1}
    assert await world.status(loginless.id) is ProxyAccessStatus.PENDING_APPLY
    assert await world.status(broken.id) is ProxyAccessStatus.PENDING_DELETE
    assert "has no login" in caplog.text
    assert "reconcile failed" in caplog.text


# Invariant: when the audit sink has no write_best_effort, the service falls
# back to the plain write() so audit is never silently dropped.
async def test_audit_falls_back_to_plain_write(world: World) -> None:
    # Arrange
    written: list[dict[str, object]] = []

    class PlainAudit:
        async def write(self, **kwargs: object) -> None:
            written.append(kwargs)

    service = world.make()
    service.audit = PlainAudit()  # type: ignore[assignment]
    await world.seed(ProxyAccessStatus.ACTIVE)

    # Act
    await service.get_socks5_proxy_config(ALICE)

    # Assert
    assert [w["action"] for w in written] == ["socks5_proxy_shown"]
