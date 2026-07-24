"""Service-layer tests for all-in-one subscription bundles.

These drive the REAL ``XrayService``/``HysteriaService`` against a real SQLite DB
with recording Xray adapters, so every assertion covers both sides at once: what
is left on the backend and what is left in the database.
"""

import asyncio
import re
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from adapters.clock import ClockProvider
from config.settings import Settings
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import KeyBundleStatus, UserRole, VpnKeyStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.hysteria import HysteriaService
from services.key_bundles import BundleMember, KeyBundleService, bundle_composition
from services.xray import XRAY_MANAGED_LABEL_RE, XrayService

OWNER = 100
ADMIN = 1
EXPIRES_AT = "2030-01-01T00:00:00+00:00"


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = dict(
        bot_token="token",
        admin_ids=frozenset({ADMIN}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="vless-in",
        xray_public_host="vpn.example.com",
        xray_public_port=443,
        xray_reality_public_key="public",
        xray_sni="example.com",
        xray_flow="xtls-rprx-vision",
        xray_fingerprint="chrome",
        xray_network_type="tcp",
        xray_short_id="abcd",
        xray_manage_short_ids=False,
        xray_allow_restart_on_rollback=False,
        xray_stats_server="",
        awg_config_path=tmp_path / "awg.conf",
        awg_interface="awg0",
        awg_network="10.0.0.0/24",
        awg_server_address="10.0.0.1",
        awg_endpoint_host="vpn.example.com",
        awg_endpoint_port=443,
        awg_server_public_key="server-public",
        awg_client_dns="1.1.1.1",
        awg_mtu=None,
        awg_allowed_ips="0.0.0.0/0, ::/0",
        awg_persistent_keepalive=25,
        awg_use_preshared_key=True,
        default_proxy_type="",
        default_proxy_host="",
        default_proxy_port=None,
        default_proxy_login="",
        default_proxy_password="",
        default_proxy_note="",
        audit_retention_days=180,
        config_backup_keep_last=20,
        xray_xhttp_enabled=True,
        xray_xhttp_inbound_tag="vless-xhttp-reality",
        xray_xhttp_port=8443,
        xray_xhttp_path="/v1/messages/stream",
        xray_xhttp_mode="stream-one",
        hysteria2_enabled=True,
        hysteria2_host="vpn.example.com",
        hysteria2_port=443,
        hysteria2_sni="anycastedge.duckdns.org",
        hysteria2_insecure=False,
        subscription_enabled=True,
    )
    values.update(overrides)
    return Settings(**values)


class _Users:
    """RBAC stub: ADMIN is superadmin, everyone else an approved user."""

    async def require_approved_or_admin(self, user_id: int) -> User:
        role = UserRole.SUPERADMIN if user_id == ADMIN else UserRole.APPROVED_USER
        return User(user_id, f"user{user_id}", "User", role, "now", "now", None)

    async def require_superadmin(self, user_id: int) -> User:
        return User(user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

    async def get_user(self, user_id: int) -> User:
        return await self.require_approved_or_admin(user_id)


class _Audit:
    def __init__(self) -> None:
        self.items: list[dict[str, object]] = []

    async def write_best_effort(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    async def write(self, **kwargs: object) -> None:
        self.items.append(kwargs)

    def actions(self) -> list[str]:
        return [str(item.get("action")) for item in self.items]

    def details_for(self, action: str) -> dict[str, object]:
        for item in self.items:
            if item.get("action") == action:
                details = item.get("details")
                return details if isinstance(details, dict) else {}
        raise AssertionError(f"no audit record for {action}: {self.actions()}")


class _Modules:
    def __init__(self, **enabled: bool) -> None:
        self._enabled = {"xray": True, "awg": True, "hysteria2": True}
        self._enabled.update(enabled)

    async def is_enabled(self, name: str) -> bool:
        return self._enabled.get(name, False)


class _Ids:
    """Deterministic identifiers; every call consumes a fresh counter value."""

    def __init__(self, fixed_key_name: str | None = None) -> None:
        self._n = 0
        self._fixed_key_name = fixed_key_name

    def _next(self) -> int:
        self._n += 1
        return self._n

    def uuid4(self) -> str:
        return f"00000000-0000-4000-8000-{self._next():012d}"

    def generated_key_name(self, prefix: str) -> str:
        if self._fixed_key_name is not None:
            return f"{prefix}_{self._fixed_key_name}"
        return f"{prefix}_{self._next():05d}"

    def xray_short_id(self) -> str:
        return "ff69b6f523de0d17"

    def hysteria2_label(self) -> str:
        return f"hy2_{self._next():016x}"


class _RecordingAdapter:
    """Stand-in for one Xray inbound: records calls and tracks live clients.

    ``fail_add_on`` / ``fail_remove`` let a test break exactly one backend step so
    the create-rollback and rollback-failure paths can be exercised for real.
    """

    def __init__(self, *, fail_add_on: int | None = None, fail_remove: bool = False) -> None:
        self.add_calls: list[dict[str, object]] = []
        self.remove_calls: list[dict[str, object]] = []
        self.clients: list[dict[str, str]] = []
        self.short_ids: set[str] = set()
        self._fail_add_on = fail_add_on
        self._fail_remove = fail_remove

    async def add_client(self, **kwargs: object) -> object:
        self.add_calls.append(dict(kwargs))
        if self._fail_add_on is not None and len(self.add_calls) == self._fail_add_on:
            raise RuntimeError("xray apply exploded")
        self.clients.append({"id": str(kwargs["uuid_value"]), "email": str(kwargs["email_label"])})
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        self.remove_calls.append(dict(kwargs))
        if self._fail_remove:
            raise RuntimeError("xray rollback exploded")
        uuid_value = kwargs.get("uuid_value")
        email_label = kwargs.get("email_label")
        self.clients = [
            c
            for c in self.clients
            if not ((uuid_value and c["id"] == uuid_value) or (email_label and c["email"] == email_label))
        ]

    def find_client(self, *, uuid_value: str | None = None, email_label: str | None = None) -> dict[str, str] | None:
        for c in self.clients:
            if uuid_value and c["id"] == uuid_value:
                return dict(c)
            if email_label and c["email"] == email_label:
                return dict(c)
        return None

    def list_clients(self) -> list[dict[str, str]]:
        return [dict(c) for c in self.clients]

    def list_short_ids(self) -> set[str]:
        return set(self.short_ids)


class _OrderRecordingBundles(KeyBundleRepository):
    """Records how many children were still attached when the bundle row was deleted."""

    def __init__(self, db: Database) -> None:
        super().__init__(db)
        self.children_at_delete: list[int] | None = None

    async def delete(self, bundle_id: int) -> None:
        self.children_at_delete = [key.id for key in await self.list_keys_of_bundle(bundle_id)]
        await super().delete(bundle_id)


class _Harness:
    def __init__(
        self,
        db: Database,
        service: KeyBundleService,
        bundles: _OrderRecordingBundles,
        vpn_keys: VpnKeyRepository,
        tcp: _RecordingAdapter,
        http: _RecordingAdapter,
        audit: _Audit,
        backend_health: BackendHealth,
    ) -> None:
        self.db = db
        self.service = service
        self.bundles = bundles
        self.vpn_keys = vpn_keys
        self.tcp = tcp
        self.http = http
        self.audit = audit
        self.backend_health = backend_health

    @property
    def owner(self) -> TelegramUserProfile:
        return TelegramUserProfile(OWNER, f"user{OWNER}", "User")

    async def count(self, table: str) -> int:
        row = await self.db.conn.execute_fetchone(f"SELECT COUNT(*) AS cnt FROM {table}")  # noqa: S608
        assert row is not None
        return int(row["cnt"])

    async def all_keys(self) -> list[VpnKey]:
        return await self.vpn_keys.list_by_owner(OWNER, limit=100)

    def live_clients(self) -> list[str]:
        return [c["email"] for c in self.tcp.list_clients() + self.http.list_clients()]


async def _build(
    tmp_path: Path,
    *,
    fail_add_on: tuple[int | None, int | None] = (None, None),
    fail_remove: tuple[bool, bool] = (False, False),
    modules: _Modules | None = None,
    ids: _Ids | None = None,
    **settings_overrides: object,
) -> _Harness:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users_repo = UserRepository(db)
    for uid in (ADMIN, OWNER):
        await users_repo.upsert_profile(
            TelegramUserProfile(uid, f"user{uid}", "User"), UserRole.APPROVED_USER, "now"
        )

    settings = _settings(tmp_path, **settings_overrides)
    clock = ClockProvider()
    id_gen = ids or _Ids()
    audit = _Audit()
    backend_health = BackendHealth()
    vpn_keys = VpnKeyRepository(db)
    tcp = _RecordingAdapter(fail_add_on=fail_add_on[0], fail_remove=fail_remove[0])
    http = _RecordingAdapter(fail_add_on=fail_add_on[1], fail_remove=fail_remove[1])
    modules_service = modules or _Modules()

    xray = XrayService(
        vpn_keys=vpn_keys,
        users=_Users(),  # type: ignore[arg-type]
        adapter=tcp,  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=id_gen,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        backend_health=backend_health,
        xhttp_adapter=http,  # type: ignore[arg-type]
    )
    hysteria = HysteriaService(
        vpn_keys=vpn_keys,
        users=_Users(),  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=id_gen,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        modules=modules_service,  # type: ignore[arg-type]
    )
    bundles = _OrderRecordingBundles(db)
    service = KeyBundleService(
        bundles=bundles,
        users=_Users(),  # type: ignore[arg-type]
        xray=xray,
        hysteria=hysteria,
        modules=modules_service,  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=id_gen,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        backend_health=backend_health,
    )
    return _Harness(db, service, bundles, vpn_keys, tcp, http, audit, backend_health)


# ── the composition seam ──────────────────────────────────────────────


def test_bundle_composition_is_pinned_to_the_current_set() -> None:
    """The seam is the ONLY place the composition may change — pin it explicitly.

    AWG never rides a base64 v2ray subscription and the SOCKS5/MTProto proxies are
    a different entity, so neither may appear here.
    """
    assert bundle_composition() == (
        BundleMember(VpnKeyType.XRAY, transport="tcp", xhttp_profile="base"),
        BundleMember(VpnKeyType.XRAY, transport="http", xhttp_profile="base"),
        BundleMember(VpnKeyType.XRAY, transport="http", xhttp_profile="antisib"),
        BundleMember(VpnKeyType.XRAY, transport="http", xhttp_profile="multi"),
        BundleMember(VpnKeyType.HYSTERIA2, transport="tcp", xhttp_profile="base"),
    )
    assert all(member.key_type is not VpnKeyType.AWG for member in bundle_composition())


# ── creation: happy path ──────────────────────────────────────────────


def test_create_bundle_provisions_every_enabled_protocol(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            result = await h.service.create_bundle(ADMIN, h.owner, "note", expires_at=EXPIRES_AT)

            assert len(result.keys) == 5
            assert result.skipped == ()
            assert result.bundle.status is KeyBundleStatus.ACTIVE
            assert result.bundle.label.startswith("bundle_")
            # secrets.token_urlsafe(32): 256 bits of entropy, URL-safe alphabet.
            assert len(result.bundle.token) >= 40
            assert re.fullmatch(r"[A-Za-z0-9_-]+", result.bundle.token)

            children = await h.bundles.list_keys_of_bundle(result.bundle.id)
            assert [key.id for key in children] == [key.id for key in result.keys]
            # One parent, one expiry: children expire together so key-expiry needs
            # no bundle awareness at all.
            assert {key.expires_at for key in children} == {EXPIRES_AT}
            assert all(key.status is VpnKeyStatus.ACTIVE for key in children)

            labels = [key.email_label or "" for key in children]
            xray_labels = [label for label in labels if label.startswith("xray_")]
            assert len(xray_labels) == 4
            # Existing per-protocol naming scheme — anything else breaks
            # reconcile_email_labels and the startup orphan detection.
            assert all(XRAY_MANAGED_LABEL_RE.fullmatch(label) for label in xray_labels)
            assert sorted(label.rsplit("_", 1)[0] for label in xray_labels) == [
                "xray_http_antisib",
                "xray_http_base",
                "xray_http_multi",
                "xray_tcp",
            ]
            assert sum(1 for label in labels if label.startswith("hy2_")) == 1

            # Both inbounds actually got their clients.
            assert len(h.tcp.add_calls) == 1
            assert len(h.http.add_calls) == 3

            details = h.audit.details_for("key_bundle_created")
            assert details["included"] == [
                "xray_tcp",
                "xray_http_base",
                "xray_http_antisib",
                "xray_http_multi",
                "hysteria2",
            ]
            assert details["skipped"] == []
        finally:
            await h.db.close()

    asyncio.run(run())


# ── creation: a disabled backend is skipped silently ──────────────────


def test_create_bundle_skips_backend_disabled_in_env(tmp_path: Path) -> None:
    """XHTTP off in .env: the bundle is still created, just without those members."""

    async def run() -> None:
        h = await _build(tmp_path, xray_xhttp_enabled=False)
        try:
            result = await h.service.create_bundle(ADMIN, h.owner, None)

            assert len(result.keys) == 2
            assert [member.xhttp_profile for member in result.skipped] == ["base", "antisib", "multi"]
            assert all(member.transport == "http" for member in result.skipped)
            assert h.http.add_calls == []
            assert {key.key_type for key in result.keys} == {VpnKeyType.XRAY, VpnKeyType.HYSTERIA2}
            # The composition that actually went in is recorded, not inferred later.
            details = h.audit.details_for("key_bundle_created")
            assert details["included"] == ["xray_tcp", "hysteria2"]
            assert details["skipped"] == ["xray_http_base", "xray_http_antisib", "xray_http_multi"]
        finally:
            await h.db.close()

    asyncio.run(run())


def test_create_bundle_skips_protocol_disabled_by_module_toggle(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path, modules=_Modules(hysteria2=False))
        try:
            result = await h.service.create_bundle(ADMIN, h.owner, None)

            assert len(result.keys) == 4
            assert all(key.key_type is VpnKeyType.XRAY for key in result.keys)
            assert [member.key_type for member in result.skipped] == [VpnKeyType.HYSTERIA2]
        finally:
            await h.db.close()

    asyncio.run(run())


def test_create_bundle_refuses_when_every_backend_is_disabled(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path, modules=_Modules(xray=False, hysteria2=False))
        try:
            with pytest.raises(InvalidOperation) as exc:
                await h.service.create_bundle(ADMIN, h.owner, None)
            assert exc.value.key == "err_bundle_no_backends"
            assert await h.count("key_bundles") == 0
        finally:
            await h.db.close()

    asyncio.run(run())


# ── creation: an enabled-but-degraded backend aborts everything ───────


def test_create_bundle_aborts_when_an_enabled_backend_is_degraded(tmp_path: Path) -> None:
    """A thirty-second Hysteria2 blip must NOT silently yield an hy2-less bundle."""

    async def run() -> None:
        h = await _build(tmp_path)
        try:
            h.backend_health.mark_degraded(VpnKeyType.HYSTERIA2, "hy2_auth /healthz недоступен")

            with pytest.raises(InvalidOperation):
                await h.service.create_bundle(ADMIN, h.owner, None)

            # Nothing anywhere: no bundle, no keys, no backend clients.
            assert await h.count("key_bundles") == 0
            assert await h.count("vpn_keys") == 0
            assert h.tcp.add_calls == []
            assert h.http.add_calls == []
        finally:
            await h.db.close()

    asyncio.run(run())


def test_degraded_backend_that_is_disabled_does_not_block_creation(tmp_path: Path) -> None:
    """Degraded only matters for backends that are actually part of the bundle."""

    async def run() -> None:
        h = await _build(tmp_path, hysteria2_enabled=False)
        try:
            h.backend_health.mark_degraded(VpnKeyType.HYSTERIA2, "hy2_auth /healthz недоступен")
            result = await h.service.create_bundle(ADMIN, h.owner, None)
            assert len(result.keys) == 4
            assert [member.key_type for member in result.skipped] == [VpnKeyType.HYSTERIA2]
        finally:
            await h.db.close()

    asyncio.run(run())


# ── creation: rollback ────────────────────────────────────────────────


def test_create_bundle_rolls_back_children_on_midway_failure(tmp_path: Path) -> None:
    """The 3rd child (2nd XHTTP profile) fails: the first two are unwound on the
    backend AND in the DB, and the bundle row is gone."""

    async def run() -> None:
        h = await _build(tmp_path, fail_add_on=(None, 2))
        try:
            with pytest.raises(RuntimeError, match="xray apply exploded"):
                await h.service.create_bundle(ADMIN, h.owner, None, expires_at=EXPIRES_AT)

            # No bundle row, and no live client left on either inbound.
            assert await h.count("key_bundles") == 0
            assert h.live_clients() == []
            # Every successfully created child was hard-deleted; nothing still
            # points at the (now gone) bundle. The single surviving row is the
            # child whose own apply failed — apply_failed and never attached,
            # exactly the trace a standalone failed create leaves behind.
            rows = await h.db.conn.execute_fetchall("SELECT id, status, bundle_id FROM vpn_keys")
            assert len(rows) == 1
            assert rows[0]["status"] == VpnKeyStatus.APPLY_FAILED.value
            assert rows[0]["bundle_id"] is None
            assert h.audit.actions().count("key_bundle_create_rolled_back") == 1
        finally:
            await h.db.close()

    asyncio.run(run())


def test_create_bundle_never_looks_successful_when_rollback_itself_fails(tmp_path: Path) -> None:
    """Rollback cannot unwind the VLESS (TCP) child: the bundle must be marked
    failed (never left active) and the original error must reach the caller."""

    async def run() -> None:
        h = await _build(tmp_path, fail_add_on=(None, 2), fail_remove=(True, False))
        try:
            with pytest.raises(RuntimeError, match="xray apply exploded"):
                await h.service.create_bundle(ADMIN, h.owner, None)

            bundles = await h.bundles.list_by_user(OWNER)
            assert len(bundles) == 1
            assert bundles[0].status is KeyBundleStatus.DELETE_FAILED
            assert bundles[0].status is not KeyBundleStatus.ACTIVE
            assert "key_bundle_rollback_failed" in h.audit.actions()
            details = h.audit.details_for("key_bundle_rollback_failed")
            assert details["rollback_failed_key_ids"]
        finally:
            await h.db.close()

    asyncio.run(run())


def test_create_bundle_gives_up_on_repeated_label_collisions(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path, ids=_Ids(fixed_key_name="FIXED"))
        try:
            await h.bundles.create(user_id=OWNER, label="bundle_FIXED", now="t0")
            with pytest.raises(InvalidOperation, match="метку подписки"):
                await h.service.create_bundle(ADMIN, h.owner, None)
            assert await h.count("key_bundles") == 1
        finally:
            await h.db.close()

    asyncio.run(run())


# ── revocation ────────────────────────────────────────────────────────


def test_revoke_bundle_revokes_children_rotates_token_and_sets_status(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)
            old_token = created.bundle.token

            bundle = await h.service.revoke_bundle(ADMIN, created.bundle.id)

            assert bundle.status is KeyBundleStatus.REVOKED
            assert bundle.revoked_at
            children = await h.bundles.list_keys_of_bundle(created.bundle.id)
            assert len(children) == 5
            assert all(key.status is VpnKeyStatus.REVOKED for key in children)
            # Every Xray client is gone from its inbound.
            assert h.live_clients() == []
            # Defence in depth: the old sub-URL no longer resolves at all.
            assert bundle.token != old_token
            assert await h.bundles.get_by_token(old_token) is None
        finally:
            await h.db.close()

    asyncio.run(run())


def test_revoke_bundle_is_idempotent(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)
            await h.service.revoke_bundle(ADMIN, created.bundle.id)
            again = await h.service.revoke_bundle(ADMIN, created.bundle.id)
            assert again.status is KeyBundleStatus.REVOKED
        finally:
            await h.db.close()

    asyncio.run(run())


def test_revoke_bundle_kills_the_token_even_when_a_child_revoke_fails(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)
            old_token = created.bundle.token
            h.tcp._fail_remove = True

            with pytest.raises(InvalidOperation) as exc:
                await h.service.revoke_bundle(ADMIN, created.bundle.id)
            assert exc.value.key == "err_bundle_revoke_partial"

            bundle = await h.bundles.get_by_id(created.bundle.id)
            assert bundle is not None
            # Left retryable, never "revoked"; the sub-URL is already dead.
            assert bundle.status is KeyBundleStatus.PENDING_REVOKE
            assert bundle.token != old_token
            assert await h.bundles.get_by_token(old_token) is None
        finally:
            await h.db.close()

    asyncio.run(run())


# ── deletion ──────────────────────────────────────────────────────────


def test_delete_bundle_removes_children_first_and_never_trips_restrict(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)

            await h.service.delete_bundle(ADMIN, created.bundle.id)

            # The bundle row was deleted only once no child pointed at it.
            assert h.bundles.children_at_delete == []
            assert await h.count("key_bundles") == 0
            assert await h.count("vpn_keys") == 0
            assert h.live_clients() == []
            assert "key_bundle_deleted" in h.audit.actions()
        finally:
            await h.db.close()

    asyncio.run(run())


def test_deleting_the_bundle_first_unblocks_removing_the_owner_row(tmp_path: Path) -> None:
    """User hard-delete is unsupported today (``block_user`` flips the role
    instead), and the FK topology fails closed if one is attempted while a bundle
    is live. This pins the bundle-aware order that makes it safe: run the bundle
    through ``delete_bundle`` first, and the owner row is no longer blocked."""

    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)

            with pytest.raises(sqlite3.IntegrityError):
                await h.db.conn.execute("DELETE FROM users WHERE telegram_user_id = ?", (OWNER,))
            await h.db.rollback()
            assert await h.count("key_bundles") == 1

            await h.service.delete_bundle(ADMIN, created.bundle.id)

            await h.db.conn.execute("DELETE FROM users WHERE telegram_user_id = ?", (OWNER,))
            await h.db.commit()
            assert await h.count("key_bundles") == 0
            assert await h.count("vpn_keys") == 0
        finally:
            await h.db.close()

    asyncio.run(run())


def test_delete_bundle_with_live_children_reports_the_restrict_clearly(tmp_path: Path) -> None:
    """PR-1's ON DELETE RESTRICT is the backstop that makes the wrong order
    impossible; when it fires the service must say so, not orphan anything."""

    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)

            async def _leave_children_in_place(actor_user_id: int, key: VpnKey) -> None:
                return None

            h.service._delete_child = _leave_children_in_place  # type: ignore[method-assign]

            with pytest.raises(InvalidOperation) as exc:
                await h.service.delete_bundle(ADMIN, created.bundle.id)
            assert exc.value.key == "err_bundle_has_keys"
            assert isinstance(exc.value.__cause__, sqlite3.IntegrityError)

            bundle = await h.bundles.get_by_id(created.bundle.id)
            assert bundle is not None
            assert bundle.status is KeyBundleStatus.DELETE_FAILED
            assert len(await h.bundles.list_keys_of_bundle(created.bundle.id)) == 5
        finally:
            await h.db.close()

    asyncio.run(run())


def test_delete_bundle_marks_failed_when_a_child_delete_fails(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)
            h.tcp._fail_remove = True

            with pytest.raises(RuntimeError, match="xray rollback exploded"):
                await h.service.delete_bundle(ADMIN, created.bundle.id)

            bundle = await h.bundles.get_by_id(created.bundle.id)
            assert bundle is not None
            assert bundle.status is KeyBundleStatus.DELETE_FAILED
            assert await h.count("key_bundles") == 1
        finally:
            await h.db.close()

    asyncio.run(run())


# ── the feature flag has teeth from day one ───────────────────────────


def test_service_refuses_everything_while_subscription_is_disabled(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path, subscription_enabled=False)
        try:
            for call in (
                h.service.create_bundle(ADMIN, h.owner, None),
                h.service.revoke_bundle(ADMIN, 1),
                h.service.delete_bundle(ADMIN, 1),
            ):
                with pytest.raises(InvalidOperation) as exc:
                    await call
                assert exc.value.key == "err_subscription_disabled"
            assert await h.count("key_bundles") == 0
            assert await h.count("vpn_keys") == 0
        finally:
            await h.db.close()

    asyncio.run(run())


# ── ownership ─────────────────────────────────────────────────────────


def test_foreign_bundle_cannot_be_managed_by_another_user(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)

            with pytest.raises(AccessDenied) as exc:
                await h.service.revoke_bundle(OWNER + 1, created.bundle.id)
            assert exc.value.key == "err_foreign_bundle_manage"
        finally:
            await h.db.close()

    asyncio.run(run())


def test_non_admin_cannot_create_a_bundle_for_someone_else(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            with pytest.raises(AccessDenied) as exc:
                await h.service.create_bundle(OWNER + 1, h.owner, None)
            assert exc.value.key == "err_create_for_other"
            assert await h.count("key_bundles") == 0
        finally:
            await h.db.close()

    asyncio.run(run())


def test_unknown_bundle_is_reported_as_not_found(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            with pytest.raises(NotFound) as exc:
                await h.service.revoke_bundle(ADMIN, 4242)
            assert exc.value.key == "err_bundle_not_found"
        finally:
            await h.db.close()

    asyncio.run(run())


def test_a_failed_bundle_cannot_be_revoked_as_if_it_were_active(tmp_path: Path) -> None:
    async def run() -> None:
        h = await _build(tmp_path)
        try:
            created = await h.service.create_bundle(ADMIN, h.owner, None)
            await h.bundles.set_status(created.bundle.id, KeyBundleStatus.DELETE_FAILED, "t9")

            with pytest.raises(InvalidOperation) as exc:
                await h.service.revoke_bundle(ADMIN, created.bundle.id)
            assert exc.value.key == "err_bundle_revoke_active_only"
        finally:
            await h.db.close()

    asyncio.run(run())
