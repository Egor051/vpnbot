"""Regression tests for the service-layer review fixes.

Covers:
  H1  moderator-initiated block_user revokes backend access (system revokers)
  H3  concurrent trial approval provisions exactly one key
  M1  trial decisions require superadmin at the service layer
  M3  scheduled announcements skip recipients blocked after scheduling
  M5  AuditService.recent_for_entity is access-gated
  L1  UserService.set_role refuses to block (must use block_user)
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from adapters.clock import ClockProvider
from db.database import Database
from models.dto import ProxyAccess, TelegramUserProfile
from models.enums import (
    AuditEntityType,
    ProxyAccessStatus,
    ProxyAccessType,
    UserRole,
    VpnKeyStatus,
    VpnKeyType,
)
from repositories.audit_log import AuditLogRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.trial_requests import TrialKeyRequestRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation
from services.announcements import AnnouncementService
from services.protocol_modules import ProtocolModulesService
from services.socks5 import Socks5Service
from services.trial_access import TrialAccessService
from services.user_locks import UserLockManager
from services.users import UserService
from repositories.announcements import AnnouncementRepository
from repositories.protocol_modules import ProtocolModulesRepository

from test_proxy_services import _LockOnlyAdapter, _settings


async def _db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    return db


async def _user(repo: UserRepository, uid: int, role: UserRole) -> None:
    await repo.upsert_profile(TelegramUserProfile(uid, f"u{uid}", f"U{uid}"), role, "now")


# --------------------------------------------------------------------------- H1


async def test_moderator_block_revokes_keys_and_proxies(tmp_path: Path) -> None:
    """A moderator block must actually revoke keys/proxies (system revokers)."""
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 2, UserRole.MODERATOR)
        await _user(users_repo, 100, UserRole.APPROVED_USER)

        keys_repo = VpnKeyRepository(db)
        access_repo = ProxyAccessRepository(db)
        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        user_locks = UserLockManager()
        user_service = UserService(
            users=users_repo,
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            audit=audit,
            user_locks=user_locks,
        )

        key = await keys_repo.create_pending(
            owner_user_id=100, username="u100", key_type=VpnKeyType.XRAY, note=None,
            payload={"short_id_managed": False}, public_payload={}, created_by=100,
            now="now", uuid="00000000-0000-4000-8000-000000000001", email_label="xray_aaaaa",
        )
        await keys_repo.mark_active(key.id, "now")

        socks5 = Socks5Service(
            accesses=access_repo, users=user_service, adapter=_LockOnlyAdapter(),  # type: ignore[arg-type]
            settings=_settings(tmp_path), clock=ClockProvider(), audit=audit, user_locks=user_locks,
        )
        access = await socks5.issue_socks5_proxy(100, TelegramUserProfile(100, "u100", "U100"))

        # System revokers, exactly as wired in bot/app.py.
        async def revoke_xray(actor: int, key_id: int):
            return await _SystemKeyRevoke(keys_repo, actor, key_id).run()

        user_service.attach_key_management(keys_repo, {VpnKeyType.XRAY: revoke_xray})
        user_service.attach_proxy_access_management(
            access_repo, {ProxyAccessType.SOCKS5: socks5.revoke_socks5_proxy_system},
        )

        # Actor 2 is a MODERATOR — neither superadmin nor the key owner.
        result = await user_service.block_user(2, 100)

        assert result.errors == ()
        assert result.revoked_key_ids == (key.id,)
        assert result.revoked_proxy_ids == (access.id,)
        stored_key = await keys_repo.get_by_id(key.id)
        stored_access = await access_repo.get_by_id(access.id)
        assert stored_key is not None and stored_key.status == VpnKeyStatus.REVOKED
        assert stored_access is not None and stored_access.status == ProxyAccessStatus.REVOKED
    finally:
        await db.close()


class _SystemKeyRevoke:
    """Minimal stand-in mirroring revoke_*_key_system: no actor role check."""

    def __init__(self, repo: VpnKeyRepository, actor: int, key_id: int) -> None:
        self._repo = repo
        self._actor = actor
        self._key_id = key_id

    async def run(self):
        await self._repo.mark_revoked(self._key_id, self._actor, "now")
        return await self._repo.get_by_id(self._key_id)


async def test_public_socks5_revoke_requires_superadmin_but_system_does_not(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 2, UserRole.MODERATOR)
        await _user(users_repo, 100, UserRole.APPROVED_USER)
        access_repo = ProxyAccessRepository(db)
        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        user_service = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)
        socks5 = Socks5Service(
            accesses=access_repo, users=user_service, adapter=_LockOnlyAdapter(),  # type: ignore[arg-type]
            settings=_settings(tmp_path), clock=ClockProvider(), audit=audit,
        )
        access = await socks5.issue_socks5_proxy(100, TelegramUserProfile(100, "u100", "U100"))

        # Public method rejects a non-superadmin actor.
        with pytest.raises(AccessDenied):
            await socks5.revoke_socks5_proxy(2, access.id)
        # System method (trusted caller) performs the revoke.
        revoked = await socks5.revoke_socks5_proxy_system(2, access.id, "hard_block")
        assert revoked.status == ProxyAccessStatus.REVOKED
    finally:
        await db.close()


# --------------------------------------------------------------------------- H3 / M1


class _FakeXray:
    """Provisions a real VPN key row and counts how many keys it created."""

    def __init__(self, keys_repo: VpnKeyRepository) -> None:
        self._keys = keys_repo
        self.created = 0

    async def create_xray_key(self, actor_user_id, owner, note, *, expires_at=None, allow_pending_owner=False):
        self.created += 1
        key = await self._keys.create_pending(
            owner_user_id=owner.telegram_user_id, username=owner.username, key_type=VpnKeyType.XRAY,
            note=None, payload={"uuid": f"u{self.created}"}, public_payload={}, created_by=actor_user_id,
            now="now", uuid=f"00000000-0000-4000-8000-{self.created:012d}", email_label=f"xray_{self.created:05d}",
            expires_at=expires_at,
        )
        await self._keys.mark_active(key.id, "now")
        from models.dto import VpnKeyCreateResult
        stored = await self._keys.get_by_id(key.id)
        assert stored is not None
        return VpnKeyCreateResult(key=stored, config_text="cfg")


def _trial_service(db: Database, fake_xray: _FakeXray) -> TrialAccessService:
    return TrialAccessService(
        trial_requests=TrialKeyRequestRepository(db),
        users_repo=UserRepository(db),
        xray=fake_xray,
        awg=object(),
        hysteria=object(),
        audit=AuditService(AuditLogRepository(db), ClockProvider()),
        clock=ClockProvider(),
    )


async def test_concurrent_trial_approve_provisions_one_key(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 100, UserRole.PENDING_USER)
        trial_repo = TrialKeyRequestRepository(db)
        req = await trial_repo.create(telegram_user_id=100, key_type=VpnKeyType.XRAY, requested_at="now")
        fake_xray = _FakeXray(VpnKeyRepository(db))
        svc = _trial_service(db, fake_xray)

        async def approve():
            try:
                await svc.approve_trial_request(1, req.id)
                return "ok"
            except Exception as exc:  # noqa: BLE001
                return type(exc).__name__

        results = await asyncio.gather(approve(), approve())

        assert results.count("ok") == 1, results
        assert fake_xray.created == 1, "exactly one key must be provisioned"
        keys = await VpnKeyRepository(db).list_by_owner(100, limit=50, offset=0)
        assert len(keys) == 1
    finally:
        await db.close()


async def test_trial_decisions_require_superadmin(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 2, UserRole.MODERATOR)
        await _user(users_repo, 100, UserRole.PENDING_USER)
        trial_repo = TrialKeyRequestRepository(db)
        req = await trial_repo.create(telegram_user_id=100, key_type=VpnKeyType.XRAY, requested_at="now")
        svc = _trial_service(db, _FakeXray(VpnKeyRepository(db)))

        with pytest.raises(AccessDenied):
            await svc.reject_trial_request(2, req.id)
        with pytest.raises(AccessDenied):
            await svc.admin_reset_trial_quota(2, 100)
        with pytest.raises(AccessDenied):
            await svc.approve_trial_request(2, req.id)
        # Request stays pending (no decision applied by the unauthorised actor).
        again = await trial_repo.get_by_id(req.id)
        assert again is not None and again.status == "pending"
    finally:
        await db.close()


# --------------------------------------------------------------------------- M5


async def test_recent_for_entity_requires_superadmin(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 2, UserRole.MODERATOR)
        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        await audit.write(actor_user_id=1, action="x", entity_type=AuditEntityType.USER, entity_id=100, details={})

        with pytest.raises(AccessDenied):
            await audit.recent_for_entity(2, entity_type=AuditEntityType.USER, entity_id=100)
        ok = await audit.recent_for_entity(1, entity_type=AuditEntityType.USER, entity_id=100)
        assert isinstance(ok, list)
        # Internal (trusted) reader is not access-gated.
        internal = await audit.recent_for_entity_internal(entity_type=AuditEntityType.USER, entity_id=100)
        assert isinstance(internal, list)
    finally:
        await db.close()


# --------------------------------------------------------------------------- L1


async def test_set_role_refuses_to_block(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 100, UserRole.APPROVED_USER)
        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        user_service = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)

        with pytest.raises(InvalidOperation):
            await user_service.set_role(1, 100, UserRole.BLOCKED_USER)
        # Role unchanged.
        user = await users_repo.get_by_id(100)
        assert user is not None and user.role == UserRole.APPROVED_USER
    finally:
        await db.close()


# --------------------------------------------------------------------------- M3


async def test_scheduled_announcement_skips_user_blocked_after_scheduling(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 2, UserRole.APPROVED_USER)
        await _user(users_repo, 3, UserRole.APPROVED_USER)
        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        user_service = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)
        service = AnnouncementService(
            users=user_service,
            users_repo=users_repo,
            announcements=AnnouncementRepository(db),
            audit=audit,
            delay_seconds=0,
        )

        # Snapshot recipients [1, 2, 3] at schedule time (in the past so it is due).
        batch = await service.schedule_to_all(
            actor_user_id=1, from_chat_id=1, message_id=77, scheduled_at="2000-01-01T00:00:00+00:00",
        )

        sent: list[int] = []

        async def fake_copy(_bot, target_id, from_chat_id, message_id):
            sent.append(target_id)
            return True, None

        service._copy_message = fake_copy  # type: ignore[method-assign]

        # User 3 is blocked AFTER the snapshot was taken.
        await user_service.block_user(1, 3, revoke_active_keys=False)

        results = await service.check_and_send_due(bot=object())  # type: ignore[arg-type]
        assert len(results) == 1
        assert sorted(sent) == [1, 2], "blocked recipient must be skipped"

        cursor = await db.conn.execute(
            "SELECT status FROM announcement_deliveries WHERE announcement_id = ? AND user_id = 3",
            (batch.id,),
        )
        row = await cursor.fetchone()
        assert row is not None and row["status"] == "skipped"
    finally:
        await db.close()


# --------------------------------------------------------------------------- H2


async def test_disable_protocol_revokes_backend_before_delete(tmp_path: Path) -> None:
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 2, UserRole.MODERATOR)
        await _user(users_repo, 100, UserRole.APPROVED_USER)
        keys_repo = VpnKeyRepository(db)
        for i in range(3):
            key = await keys_repo.create_pending(
                owner_user_id=100, username="u100", key_type=VpnKeyType.XRAY, note=None,
                payload={}, public_payload={}, created_by=100, now="now",
                uuid=f"00000000-0000-4000-8000-{i:012d}", email_label=f"xray_{i:05d}",
            )
            await keys_repo.mark_active(key.id, "now")

        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        user_service = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)

        purged: list[int] = []

        async def xray_purger(actor_id: int, key_id: int):
            # Mirrors delete_xray_key: backend revoke happens here, then hard delete.
            purged.append(key_id)
            await keys_repo.hard_delete_with_stats(key_id, "now")

        svc = ProtocolModulesService(ProtocolModulesRepository(db), db)

        # Without purgers wired, disabling must refuse (never silently orphan).
        with pytest.raises(InvalidOperation):
            await svc.disable_protocol("xray", 1)

        svc.attach_purge_handlers(
            users=user_service, audit=audit, vpn_keys=keys_repo,
            proxy_accesses=ProxyAccessRepository(db),
            key_purgers={VpnKeyType.XRAY: xray_purger}, proxy_purgers={},
        )

        # Non-superadmin is rejected at the service layer (defense-in-depth).
        with pytest.raises(AccessDenied):
            await svc.disable_protocol("xray", 2)

        deleted = await svc.disable_protocol("xray", 1)
        assert deleted == 3
        assert sorted(purged) == [k for k in purged]  # every key went through the purger
        assert len(purged) == 3
        assert await svc.is_enabled("xray") is False
        remaining = await keys_repo.list_by_owner(100, limit=50, offset=0)
        assert remaining == []
    finally:
        await db.close()


# ===========================================================================
# P4 review fixes
# ===========================================================================


class _CapturingAudit:
    """Records every audit write so tests can assert on redaction/actions."""

    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    async def write(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    async def write_best_effort(self, **kwargs: object) -> None:
        self.items.append(kwargs)


class _NullXrayAdapter:
    async def add_client(self, **kwargs: object) -> None:
        return None

    async def remove_client(self, **kwargs: object) -> None:
        return None


class _FailingXrayAdapter:
    async def add_client(self, **kwargs: object) -> None:
        raise RuntimeError("apply blew up secret=deadbeefdeadbeefdeadbeefdeadbeef")

    async def remove_client(self, **kwargs: object) -> None:
        return None


class _XrayIds:
    def uuid4(self) -> str:
        return "00000000-0000-4000-8000-000000000123"

    def generated_key_name(self, prefix: str) -> str:
        return f"{prefix}_AbCdE"

    def xray_short_id(self) -> str:
        return "abcd1234"


class _FakeXrayTrackingRevoke(_FakeXray):
    """Provisions a real key and records system-revoke calls (rollback tracking)."""

    def __init__(self, keys_repo: VpnKeyRepository) -> None:
        super().__init__(keys_repo)
        self.revoked: list[int] = []

    async def revoke_xray_key_system(
        self, key_id: int, *, actor_user_id: int | None = None, action: str = "xray_key_expired"
    ):
        self.revoked.append(key_id)
        await self._keys.mark_revoked(key_id, actor_user_id or 0, "now")
        return await self._keys.get_by_id(key_id)


async def test_trial_list_and_count_require_superadmin(tmp_path: Path) -> None:
    """F2 (P4-010): reading trial requests is gated at the service, not only in the UI."""
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 2, UserRole.MODERATOR)
        await _user(users_repo, 100, UserRole.PENDING_USER)
        await TrialKeyRequestRepository(db).create(
            telegram_user_id=100, key_type=VpnKeyType.XRAY, requested_at="now"
        )
        svc = _trial_service(db, _FakeXray(VpnKeyRepository(db)))

        with pytest.raises(AccessDenied):
            await svc.count_pending_requests(2)
        with pytest.raises(AccessDenied):
            await svc.list_pending_requests(2)

        assert await svc.count_pending_requests(1) == 1
        assert len(await svc.list_pending_requests(1)) == 1
    finally:
        await db.close()


async def test_protocol_enable_disable_fail_closed_without_rbac(tmp_path: Path) -> None:
    """F1 (P4-004): enable/disable must refuse when the RBAC dependency is unwired."""
    db = await _db(tmp_path)
    try:
        svc = ProtocolModulesService(ProtocolModulesRepository(db), db)
        before = await svc.is_enabled("xray")
        with pytest.raises(InvalidOperation):
            await svc.enable_protocol("xray", 1)
        with pytest.raises(InvalidOperation):
            await svc.disable_protocol("xray", 1)
        # State must be untouched by the unauthorised calls.
        assert await svc.is_enabled("xray") == before
    finally:
        await db.close()


async def test_block_user_audit_reports_proxy_incomplete_when_unwired(tmp_path: Path) -> None:
    """F4 (P4-006): proxy_revoke_complete is False when proxy revokers are not wired."""
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 100, UserRole.APPROVED_USER)
        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        user_service = UserService(
            users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit
        )
        # No key/proxy revokers attached at all.
        await user_service.block_user(1, 100, revoke_active_keys=True)
        items = await audit.recent_for_entity_internal(
            entity_type=AuditEntityType.USER,
            entity_id=100,
            actions={"user_blocked", "user_blocked_with_revoke_errors"},
            limit=5,
        )
        detail = next(
            i["details"]
            for i in items
            if isinstance(i.get("details"), dict) and "proxy_revoke_complete" in i["details"]
        )
        assert detail["proxy_revoke_complete"] is False
    finally:
        await db.close()


async def test_inspect_unblock_risk_flags_inactive_static_mtproto(tmp_path: Path) -> None:
    """F6 (P4-002): a deactivated static-MTProto access (working shared secret) is
    surfaced as residual-access risk before unblocking."""
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 100, UserRole.APPROVED_USER)
        audit = AuditService(AuditLogRepository(db), ClockProvider(), users=users_repo)
        user_service = UserService(
            users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit
        )
        proxy_repo = ProxyAccessRepository(db)
        user_service.attach_proxy_access_management(proxy_repo, {})
        access = await proxy_repo.create(
            owner_user_id=100,
            username="u100",
            access_type=ProxyAccessType.MTPROTO,
            status=ProxyAccessStatus.ACTIVE,
            payload={"mode": "static"},
            public_payload={"mode": "static"},
            created_by=1,
            now="now",
        )
        await proxy_repo.mark_inactive(access.id, 1, "now")

        warning = await user_service.inspect_unblock_risk(1, 100)
        assert warning.has_warning
        assert warning.active_or_problem_key_count >= 1
        assert any("MTPROTO_SECRET" in reason for reason in warning.reasons)
    finally:
        await db.close()


async def test_xray_create_failure_audit_redacts_error(tmp_path: Path) -> None:
    """F5 (P4-008): a raw backend error string is redacted before landing in the audit."""
    from services.xray import XrayService

    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 100, UserRole.APPROVED_USER)
        audit = _CapturingAudit()
        user_svc = UserService(
            users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit  # type: ignore[arg-type]
        )
        xray = XrayService(
            vpn_keys=VpnKeyRepository(db),
            users=user_svc,
            adapter=_FailingXrayAdapter(),  # type: ignore[arg-type]
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=_XrayIds(),  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
        )
        with pytest.raises(RuntimeError):
            await xray.create_xray_key(100, TelegramUserProfile(100, "u100", "U"), None)

        failed = [i for i in audit.items if i.get("action") == "xray_create_failed"]
        assert failed, "expected an xray_create_failed audit entry"
        error_text = str(failed[0]["details"]["error"])  # type: ignore[index]
        assert "deadbeef" not in error_text
        assert "***" in error_text
    finally:
        await db.close()


async def test_xray_create_rechecks_degraded_under_lock(tmp_path: Path) -> None:
    """F7 (P4-003): a backend that becomes degraded while a create waits on the
    serialization lock must cause that create to be refused."""
    from services.backend_health import BackendHealth
    from services.xray import XrayService

    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 100, UserRole.APPROVED_USER)
        audit = _CapturingAudit()
        bh = BackendHealth()
        user_svc = UserService(
            users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit  # type: ignore[arg-type]
        )
        xray = XrayService(
            vpn_keys=VpnKeyRepository(db),
            users=user_svc,
            adapter=_NullXrayAdapter(),  # type: ignore[arg-type]
            settings=_settings(tmp_path),
            clock=ClockProvider(),
            ids=_XrayIds(),  # type: ignore[arg-type]
            audit=audit,  # type: ignore[arg-type]
            backend_health=bh,
        )

        # Hold the service lock so a create that has already passed the pre-lock
        # health check blocks inside the critical section.
        await xray._lock.acquire()
        started = asyncio.Event()

        async def do_create() -> object:
            started.set()
            return await xray.create_xray_key(100, TelegramUserProfile(100, "u100", "U"), None)

        task = asyncio.create_task(do_create())
        await started.wait()
        await asyncio.sleep(0.05)  # let the create block on _lock
        bh.mark_degraded(VpnKeyType.XRAY, "reconcile in progress")
        xray._lock.release()

        with pytest.raises(InvalidOperation):
            await task
    finally:
        await db.close()


async def test_trial_approve_rolls_back_key_when_mark_approved_fails(tmp_path: Path) -> None:
    """F8 (P4-012): if the request cannot be marked approved after provisioning, the
    just-created key is rolled back so no live key survives a still-pending request."""
    db = await _db(tmp_path)
    try:
        users_repo = UserRepository(db)
        await _user(users_repo, 1, UserRole.SUPERADMIN)
        await _user(users_repo, 100, UserRole.PENDING_USER)
        trial_repo = TrialKeyRequestRepository(db)
        req = await trial_repo.create(telegram_user_id=100, key_type=VpnKeyType.XRAY, requested_at="now")
        fake_xray = _FakeXrayTrackingRevoke(VpnKeyRepository(db))
        svc = _trial_service(db, fake_xray)

        async def _boom(**kwargs: object) -> None:
            raise RuntimeError("db down")

        svc.trial_requests.approve = _boom  # type: ignore[method-assign]

        with pytest.raises(RuntimeError):
            await svc.approve_trial_request(1, req.id)

        assert fake_xray.created == 1
        assert len(fake_xray.revoked) == 1, "provisioned key must be rolled back"
        rolled_back = await VpnKeyRepository(db).get_by_id(fake_xray.revoked[0])
        assert rolled_back is not None and rolled_back.status == VpnKeyStatus.REVOKED
        # The request stays pending (no false 'approved' record).
        again = await trial_repo.get_by_id(req.id)
        assert again is not None and again.status == "pending"
    finally:
        await db.close()
