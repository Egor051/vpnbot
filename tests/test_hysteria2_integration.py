import asyncio
import re
from pathlib import Path

import aiosqlite
import pytest

from adapters.clock import ClockProvider
from adapters.id_generator import IdGenerator
from bot.formatters import format_hysteria2_link
from config.settings import Settings
from db.database import CURRENT_SCHEMA_VERSION, Database
from models.dto import TelegramUserProfile, User
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.protocol_modules import ProtocolModulesRepository
from repositories.proxy_accesses import ProxyAccessRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.errors import AccessDenied, InvalidOperation
from services.hysteria import HysteriaService
from services.protocol_modules import ProtocolModulesService
from services.vpn_keys import VpnKeyQueryService


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = dict(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="",
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
        hysteria2_enabled=True,
        hysteria2_host="vpn.example.com",
        hysteria2_port=15650,
        hysteria2_sni="googletagmanager.com",
        hysteria2_obfs_password="obfs pw/with=special:&chars",
        hysteria2_insecure=True,
    )
    values.update(overrides)
    return Settings(**values)


class _Users:
    """Lightweight RBAC stub: user 1 is superadmin, everyone else approved."""

    async def require_approved_or_admin(self, user_id: int) -> User:
        role = UserRole.SUPERADMIN if user_id == 1 else UserRole.APPROVED_USER
        return User(user_id, "user", "User", role, "now", "now", None)

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


class _Modules:
    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled

    async def is_enabled(self, name: str) -> bool:
        return self._enabled


class _FakeStats:
    """Traffic Stats API stub recording every /kick call (and optionally failing)."""

    def __init__(self, *, fail: bool = False) -> None:
        self.kicked: list[list[str]] = []
        self._fail = fail

    async def kick(self, labels: list[str]) -> None:
        self.kicked.append(list(labels))
        if self._fail:
            raise RuntimeError("stats API down")


async def _build(tmp_path: Path, *, owners: tuple[int, ...] = (100, 200), module_enabled: bool = True,
                 stats: object | None = None,
                 **settings_overrides: object) -> tuple[Database, HysteriaService]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users_repo = UserRepository(db)
    for uid in owners:
        await users_repo.upsert_profile(TelegramUserProfile(uid, f"user{uid}", "User"), UserRole.APPROVED_USER, "now")
    service = HysteriaService(
        vpn_keys=VpnKeyRepository(db),
        users=_Users(),  # type: ignore[arg-type]
        settings=_settings(tmp_path, **settings_overrides),
        clock=ClockProvider(),
        ids=IdGenerator(),
        audit=_Audit(),  # type: ignore[arg-type]
        modules=_Modules(module_enabled),  # type: ignore[arg-type]
        stats=stats,  # type: ignore[arg-type]
    )
    return db, service


# ── enum + secret format ────────────────────────────────────────────────────

def test_enum_round_trip() -> None:
    assert VpnKeyType("hysteria2") is VpnKeyType.HYSTERIA2
    assert VpnKeyType.HYSTERIA2.value == "hysteria2"


def test_issued_secret_has_uri_safe_format(tmp_path: Path) -> None:
    async def run() -> None:
        db, service = await _build(tmp_path)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            secret = str(result.key.payload["secret"])
            assert re.fullmatch(r"[0-9a-f]+", secret)  # token_hex output
            assert len(secret) == 48  # token_hex(24)
            for forbidden in ("+", "/", "=", ":"):
                assert forbidden not in secret
            # public_payload must never carry the secret.
            assert "secret" not in result.key.public_payload
            assert result.key.status == VpnKeyStatus.ACTIVE
            assert result.key.email_label is not None and result.key.email_label.startswith("hy2_")
        finally:
            await db.close()

    asyncio.run(run())


# ── readiness gate (L7) ──────────────────────────────────────────────────────

def test_is_hysteria2_ready_reflects_required_settings(tmp_path: Path) -> None:
    # Fully configured → ready.
    assert _settings(tmp_path).is_hysteria2_ready() is True
    # Any required field missing → not ready (button stays hidden, no raise).
    assert _settings(tmp_path, hysteria2_host="").is_hysteria2_ready() is False
    assert _settings(tmp_path, hysteria2_sni="").is_hysteria2_ready() is False
    assert _settings(tmp_path, hysteria2_obfs_password="").is_hysteria2_ready() is False


# ── link formatting ─────────────────────────────────────────────────────────

def test_format_hysteria2_link_round_trip() -> None:
    from urllib.parse import parse_qs, unquote, urlsplit

    secret = "deadbeef" * 6
    obfs = "p@ss w/ord=+:&x"
    link = format_hysteria2_link(
        "hy2_abc123",
        secret,
        host="vpn.example.com",
        port=15650,
        sni="googletagmanager.com",
        obfs_password=obfs,
        insecure=True,
    )
    parts = urlsplit(link)
    assert parts.scheme == "hysteria2"
    assert parts.hostname == "vpn.example.com"
    assert parts.port == 15650
    # userinfo is the single token (the secret), round-trips exactly.
    assert unquote(parts.username or "") == secret
    assert parts.password is None
    query = parse_qs(parts.query)
    assert query["obfs"] == ["salamander"]
    assert query["obfs-password"] == [obfs]  # special chars survived URL-encoding
    assert query["sni"] == ["googletagmanager.com"]
    assert query["insecure"] == ["1"]
    assert unquote(parts.fragment) == "hy2_abc123"
    # The encoded password must not leak raw metacharacters into the link.
    assert " " not in link and "&chars" not in link


def test_format_hysteria2_link_insecure_false() -> None:
    link = format_hysteria2_link(
        "hy2_x", "abcd", host="h", port=1, sni="s", obfs_password="o", insecure=False
    )
    assert "insecure=0" in link


# ── IDOR ─────────────────────────────────────────────────────────────────────

def test_idor_user_cannot_revoke_or_view_others_key(tmp_path: Path) -> None:
    async def run() -> None:
        db, service = await _build(tmp_path)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            key_id = result.key.id
            # User B (200) must not revoke user A's (100) key.
            with pytest.raises(AccessDenied):
                await service.revoke(200, key_id)
            # ...nor view its config...
            with pytest.raises(AccessDenied):
                await service.get_config(200, key_id)
            # ...nor delete it.
            with pytest.raises(AccessDenied):
                await service.delete_hysteria2_key(200, key_id)
            # The owner still can.
            revoked = await service.revoke(100, key_id)
            assert revoked.status == VpnKeyStatus.REVOKED
        finally:
            await db.close()

    asyncio.run(run())


# ── cabinet summary counts hysteria2 (L3) ────────────────────────────────────

def test_personal_summary_counts_active_hysteria2(tmp_path: Path) -> None:
    async def run() -> None:
        db, service = await _build(tmp_path)
        try:
            await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            query = VpnKeyQueryService(vpn_keys=VpnKeyRepository(db), users=_Users())  # type: ignore[arg-type]
            active_xray, active_awg, active_hy2, _down, _up = await query.personal_summary_for_actor(100)
            assert active_hy2 == 1
            assert active_xray == 0 and active_awg == 0
            # A revoked key drops out of the active count.
            keys = await service.list_user_keys(100)
            await service.revoke(100, keys[0].id)
            _, _, active_hy2_after, _d, _u = await query.personal_summary_for_actor(100)
            assert active_hy2_after == 0
        finally:
            await db.close()

    asyncio.run(run())


# ── issuance gated by protocol toggle ────────────────────────────────────────

def test_issue_rejected_when_module_disabled(tmp_path: Path) -> None:
    async def run() -> None:
        db, service = await _build(tmp_path, module_enabled=False)
        try:
            with pytest.raises(InvalidOperation):
                await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
        finally:
            await db.close()

    asyncio.run(run())


def test_issue_rejected_when_settings_flag_off(tmp_path: Path) -> None:
    async def run() -> None:
        db, service = await _build(tmp_path, hysteria2_enabled=False)
        try:
            with pytest.raises(InvalidOperation):
                await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
        finally:
            await db.close()

    asyncio.run(run())


def test_revoke_blocks_new_handshakes_but_row_stays(tmp_path: Path) -> None:
    async def run() -> None:
        db, service = await _build(tmp_path)
        repo = VpnKeyRepository(db)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            await service.revoke(100, result.key.id)
            # Revoked keys no longer appear among active hy2 keys (endpoint won't match).
            active = await repo.list_active_hysteria2()
            assert all(k.id != result.key.id for k in active)
            # ...but the row itself is NOT deleted — it persists as REVOKED (revoke
            # is a status flip, not a delete; only delete_hysteria2_key drops it).
            row = await repo.get_by_id(result.key.id)
            assert row is not None
            assert row.status == VpnKeyStatus.REVOKED
        finally:
            await db.close()

    asyncio.run(run())


def test_disable_protocol_purges_hysteria2_keys(tmp_path: Path) -> None:
    async def run() -> None:
        db, service = await _build(tmp_path, owners=(1, 100, 200))
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            modules = ProtocolModulesService(ProtocolModulesRepository(db), db)
            modules.attach_purge_handlers(
                users=_Users(),
                audit=_Audit(),
                vpn_keys=VpnKeyRepository(db),
                proxy_accesses=ProxyAccessRepository(db),
                key_purgers={VpnKeyType.HYSTERIA2: service.delete_hysteria2_key},
                proxy_purgers={},
            )
            deleted = await modules.disable_protocol("hysteria2", actor_id=1)
            assert deleted == 1
            assert not await modules.is_enabled("hysteria2")
            # The key row is hard-deleted (cascade-purge mirrors MTProto disable).
            assert await VpnKeyRepository(db).get_by_id(result.key.id) is None
        finally:
            await db.close()

    asyncio.run(run())


# ── revoke/delete kick live sessions via the Traffic Stats API ────────────────

def test_revoke_kicks_live_session_when_stats_configured(tmp_path: Path) -> None:
    async def run() -> None:
        stats = _FakeStats()
        db, service = await _build(tmp_path, stats=stats)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            label = result.key.email_label
            await service.revoke(100, result.key.id)
            assert stats.kicked == [[label]]
        finally:
            await db.close()

    asyncio.run(run())


def test_delete_kicks_live_session_when_stats_configured(tmp_path: Path) -> None:
    async def run() -> None:
        stats = _FakeStats()
        db, service = await _build(tmp_path, stats=stats)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            label = result.key.email_label
            await service.delete_hysteria2_key(100, result.key.id)
            assert stats.kicked == [[label]]
        finally:
            await db.close()

    asyncio.run(run())


def test_system_revoke_kicks_live_session(tmp_path: Path) -> None:
    async def run() -> None:
        stats = _FakeStats()
        db, service = await _build(tmp_path, stats=stats)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            label = result.key.email_label
            # The path used by expiry + block-user (no interactive role check).
            await service.revoke_hysteria2_key_system(result.key.id)
            assert stats.kicked == [[label]]
        finally:
            await db.close()

    asyncio.run(run())


def test_revoke_succeeds_even_if_kick_fails(tmp_path: Path) -> None:
    async def run() -> None:
        stats = _FakeStats(fail=True)
        db, service = await _build(tmp_path, stats=stats)
        repo = VpnKeyRepository(db)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            # A failing /kick must not abort the revoke: the DB flip is what blocks
            # new handshakes, so the key still lands in REVOKED.
            updated = await service.revoke(100, result.key.id)
            assert updated.status == VpnKeyStatus.REVOKED
            assert stats.kicked == [[result.key.email_label]]
            row = await repo.get_by_id(result.key.id)
            assert row is not None and row.status == VpnKeyStatus.REVOKED
        finally:
            await db.close()

    asyncio.run(run())


def test_revoke_without_stats_adapter_skips_kick(tmp_path: Path) -> None:
    async def run() -> None:
        # No stats adapter wired: revoke still works, just no kick (pre-API behaviour).
        db, service = await _build(tmp_path, stats=None)
        try:
            result = await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)
            updated = await service.revoke(100, result.key.id)
            assert updated.status == VpnKeyStatus.REVOKED
        finally:
            await db.close()

    asyncio.run(run())


# ── migration: idempotency + UUID preservation ───────────────────────────────

_LEGACY_VPN_KEYS_DDL = """
CREATE TABLE vpn_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_user_id INTEGER NOT NULL REFERENCES users(telegram_user_id) ON DELETE CASCADE,
  username TEXT,
  key_type TEXT NOT NULL CHECK(key_type IN ('xray','awg')),
  status TEXT NOT NULL CHECK(status IN ('pending_apply','active','apply_failed','pending_revoke','revoked','pending_delete','delete_failed','deleted','failed')),
  note TEXT,
  uuid TEXT,
  email_label TEXT,
  public_key TEXT,
  client_ip TEXT,
  payload_json TEXT NOT NULL,
  public_payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  expires_at TEXT DEFAULT NULL,
  expiry_notified_days TEXT DEFAULT NULL,
  transport TEXT NOT NULL DEFAULT 'tcp',
  xhttp_profile TEXT NOT NULL DEFAULT 'base',
  deleted_at TEXT,
  created_by INTEGER NOT NULL,
  revoked_by INTEGER,
  deleted_by INTEGER
)
"""

# Full literal (no interpolation) so it is not flagged as a built SQL expression.
_LEGACY_COPY_SQL = (
    "INSERT INTO vpn_keys ("
    "id, owner_user_id, username, key_type, status, note, uuid, email_label, public_key, "
    "client_ip, payload_json, public_payload_json, created_at, updated_at, revoked_at, "
    "expires_at, expiry_notified_days, transport, xhttp_profile, deleted_at, created_by, "
    "revoked_by, deleted_by) "
    "SELECT "
    "id, owner_user_id, username, key_type, status, note, uuid, email_label, public_key, "
    "client_ip, payload_json, public_payload_json, created_at, updated_at, revoked_at, "
    "expires_at, expiry_notified_days, transport, xhttp_profile, deleted_at, created_by, "
    "revoked_by, deleted_by "
    "FROM vpn_keys_tmp"
)


async def _revert_to_legacy_check(path: Path) -> None:
    """Rebuild vpn_keys with the pre-v29 CHECK and roll schema_version back to 28."""
    conn = await aiosqlite.connect(path)
    try:
        await conn.execute("PRAGMA foreign_keys = OFF")
        await conn.execute("ALTER TABLE vpn_keys RENAME TO vpn_keys_tmp")
        await conn.executescript(_LEGACY_VPN_KEYS_DDL)
        await conn.execute(_LEGACY_COPY_SQL)
        await conn.execute("DROP TABLE vpn_keys_tmp")
        await conn.execute("UPDATE schema_meta SET value = '28' WHERE key = 'schema_version'")
        await conn.commit()
    finally:
        await conn.close()


def test_migration_v29_widens_check_idempotently_and_preserves_uuids(tmp_path: Path) -> None:
    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        # 1) Fresh bootstrap, seed a user and an xray key carrying a UUID.
        db = Database(db_path)
        await db.connect()
        await db.bootstrap()
        users = UserRepository(db)
        await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
        repo = VpnKeyRepository(db)
        xray = await repo.create_pending(
            owner_user_id=100,
            username="user",
            key_type=VpnKeyType.XRAY,
            note=None,
            payload={"uuid": "uuid-keep-me"},
            public_payload={},
            created_by=100,
            now="now",
            uuid="uuid-keep-me",
            email_label="xray_tcp_AAAAA",
        )
        await db.close()

        # 2) Simulate a pre-v29 DB (legacy CHECK, version 28).
        await _revert_to_legacy_check(db_path)

        # 3) Reopen → migration v29 must run, widening the CHECK.
        db = Database(db_path)
        await db.connect()
        await db.bootstrap()
        repo = VpnKeyRepository(db)
        assert int(await db.get_meta("schema_version") or "0") == CURRENT_SCHEMA_VERSION
        cur = await db.conn.execute("SELECT sql FROM sqlite_master WHERE name = 'vpn_keys'")
        assert "hysteria2" in (await cur.fetchone())["sql"]
        # UUID of the pre-existing key preserved verbatim.
        kept = await repo.find_by_uuid("uuid-keep-me")
        assert kept is not None and kept.id == xray.id
        # A hysteria2 row is now insertable (CHECK widened).
        hy2 = await repo.create_pending(
            owner_user_id=100,
            username="user",
            key_type=VpnKeyType.HYSTERIA2,
            note=None,
            payload={"secret": "s"},
            public_payload={},
            created_by=100,
            now="now",
            email_label="hy2_deadbeefdeadbeef",
        )
        await repo.mark_active(hy2.id, "now")
        await db.close()

        # 4) Re-bootstrap is a no-op (idempotent); data intact.
        db = Database(db_path)
        await db.connect()
        await db.bootstrap()
        repo = VpnKeyRepository(db)
        assert int(await db.get_meta("schema_version") or "0") == CURRENT_SCHEMA_VERSION
        assert (await repo.find_by_uuid("uuid-keep-me")) is not None
        active = await repo.list_active_hysteria2()
        assert len(active) == 1 and active[0].email_label == "hy2_deadbeefdeadbeef"
        await db.close()

    asyncio.run(run())


# ── migration v29: crash safety (H1) ─────────────────────────────────────────


async def _seed_v28_with_xray_uuid(db_path: Path) -> None:
    """Bootstrap a DB, seed a user + xray key (uuid=keep-me), revert to v28."""
    db = Database(db_path)
    await db.connect()
    await db.bootstrap()
    await UserRepository(db).upsert_profile(
        TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now"
    )
    await VpnKeyRepository(db).create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        note=None,
        payload={"uuid": "uuid-keep-me"},
        public_payload={},
        created_by=100,
        now="now",
        uuid="uuid-keep-me",
        email_label="xray_tcp_AAAAA",
    )
    await db.close()
    await _revert_to_legacy_check(db_path)


def test_migration_v29_recovers_from_orphan_vpn_keys_new(tmp_path: Path) -> None:
    """A leftover vpn_keys_new (from an older non-atomic rebuild that crashed
    mid-way) must not wedge the migration: the DROP IF EXISTS guard clears it and
    the rebuild completes, preserving every other key's UUID."""

    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        await _seed_v28_with_xray_uuid(db_path)

        # Simulate the orphan an old crash would have autocommitted: an empty
        # vpn_keys_new table sitting next to the live (still-legacy) vpn_keys.
        conn = await aiosqlite.connect(db_path)
        try:
            await conn.execute("CREATE TABLE vpn_keys_new (id INTEGER PRIMARY KEY)")
            await conn.commit()
        finally:
            await conn.close()

        db = Database(db_path)
        await db.connect()
        await db.bootstrap()  # must NOT raise "table vpn_keys_new already exists"
        try:
            assert int(await db.get_meta("schema_version") or "0") == CURRENT_SCHEMA_VERSION
            cur = await db.conn.execute("SELECT sql FROM sqlite_master WHERE name = 'vpn_keys'")
            assert "hysteria2" in (await cur.fetchone())["sql"]
            # No orphan left behind after recovery.
            cur = await db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vpn_keys_new'"
            )
            assert await cur.fetchone() is None
            # The pre-existing xray UUID survived the rebuild verbatim.
            kept = await VpnKeyRepository(db).find_by_uuid("uuid-keep-me")
            assert kept is not None
        finally:
            await db.close()

    asyncio.run(run())


def test_migration_v29_rebuild_rolls_back_atomically_on_crash(tmp_path: Path) -> None:
    """A crash partway through the rebuild must roll back as a unit: the explicit
    BEGIN…COMMIT leaves the original vpn_keys (and schema_version 28) untouched
    and drops no orphan, so the next clean run still succeeds."""

    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        await _seed_v28_with_xray_uuid(db_path)

        db = Database(db_path)
        await db.connect()
        # Inject a failure at the RENAME step — the last statement of the rebuild,
        # well after CREATE TABLE vpn_keys_new and the data copy. Without the
        # surrounding transaction the CREATE would have autocommitted and orphaned.
        original_execute = db._conn.execute  # type: ignore[union-attr]

        async def failing_execute(sql, *args, **kwargs):  # type: ignore[no-untyped-def]
            if isinstance(sql, str) and "ALTER TABLE vpn_keys_new RENAME" in sql:
                raise RuntimeError("simulated crash mid-rebuild")
            return await original_execute(sql, *args, **kwargs)

        db._conn.execute = failing_execute  # type: ignore[union-attr]
        with pytest.raises(RuntimeError, match="simulated crash"):
            await db.bootstrap()
        db._conn.execute = original_execute  # type: ignore[union-attr]

        raw = db._conn
        # Original table is intact: still the legacy CHECK, data still present.
        cur = await raw.execute("SELECT sql FROM sqlite_master WHERE name = 'vpn_keys'")
        vpn_keys_sql = (await cur.fetchone())["sql"]
        assert "hysteria2" not in vpn_keys_sql
        cur = await raw.execute("SELECT uuid FROM vpn_keys WHERE uuid = 'uuid-keep-me'")
        assert await cur.fetchone() is not None
        # The half-built table was rolled back, not autocommitted.
        cur = await raw.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vpn_keys_new'"
        )
        assert await cur.fetchone() is None
        # schema_version never advanced past 28.
        assert int(await db.get_meta("schema_version") or "0") == 28
        await db.close()

        # A subsequent clean bootstrap completes the migration normally.
        db = Database(db_path)
        await db.connect()
        await db.bootstrap()
        try:
            assert int(await db.get_meta("schema_version") or "0") == CURRENT_SCHEMA_VERSION
            cur = await db.conn.execute("SELECT sql FROM sqlite_master WHERE name = 'vpn_keys'")
            assert "hysteria2" in (await cur.fetchone())["sql"]
            assert await VpnKeyRepository(db).find_by_uuid("uuid-keep-me") is not None
        finally:
            await db.close()

    asyncio.run(run())


# ── F3 (P4-005): mark_active failure during issue ────────────────────────────

def test_issue_marks_apply_failed_when_mark_active_fails(tmp_path: Path) -> None:
    """A mark_active failure during issue leaves the key APPLY_FAILED (not a dangling
    PENDING_APPLY, which Hysteria has no startup reconcile to clean up) and audits it."""
    async def run() -> None:
        db, service = await _build(tmp_path)
        try:
            async def _boom(*args: object, **kwargs: object) -> None:
                raise RuntimeError("db write failed")

            service.vpn_keys.mark_active = _boom  # type: ignore[method-assign]

            with pytest.raises(RuntimeError):
                await service.issue(100, TelegramUserProfile(100, "user100", "User"), note=None)

            keys = await service.vpn_keys.list_by_owner(100, limit=50, offset=0)
            assert len(keys) == 1
            assert keys[0].status == VpnKeyStatus.APPLY_FAILED
            actions = [i.get("action") for i in service.audit.items]
            assert "hysteria2_apply_failed" in actions
        finally:
            await db.close()

    asyncio.run(run())
