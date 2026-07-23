"""Tests for the per-key REALITY spiderX (spx) client parameter.

spiderX is purely client-side: it is emitted into VLESS client links only and is
never written to the server inbound. Covered here:

  (a) spider_x NULL  -> the link carries no ``spx`` substring at all;
  (b) spider_x set   -> a correctly ``quote(value, safe="")``-encoded ``&spx=``
                        (path separators become %2F);
  (c) the value is deterministic for a given UUID (stable across calls);
  (d) both link families — raw+Vision (tcp) and every xhttp profile (base /
      antisib / multi) — honour (a) and (b);
  plus the v31 migration: column add, deterministic pool backfill, idempotency,
  and NULL-when-pool-empty.
"""

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from adapters.clock import ClockProvider
from config.settings import Settings, SettingsError, load_settings
from db.database import Database
from models.dto import TelegramUserProfile, User
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.backend_health import BackendHealth
from services.user_locks import UserLockManager
from services.xray import XrayService
from utils.spider_x import parse_spider_x_pool, pick_spider_x


def _settings(tmp_path: Path, *, pool: tuple[str, ...] = (), xhttp_enabled: bool = True) -> Settings:
    return Settings(
        bot_token="token",
        admin_ids=frozenset({1}),
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
        xray_xhttp_enabled=xhttp_enabled,
        xray_xhttp_inbound_tag="vless-xhttp-reality",
        xray_xhttp_port=8443,
        xray_xhttp_path="/v1/messages/stream",
        xray_xhttp_mode="stream-one",
        xray_spider_x_pool=pool,
    )


class _Users:
    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)


class _Audit:
    async def write(self, **kwargs: object) -> None:
        return None

    async def write_best_effort(self, **kwargs: object) -> None:
        return None


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def uuid4(self) -> str:
        self._n += 1
        return f"00000000-0000-4000-8000-0000000000{self._n:02d}"

    def generated_key_name(self, prefix: str) -> str:
        return f"{prefix}_A{self._n:04d}"

    def xray_short_id(self) -> str:
        return "ff69b6f523de0d17"


class _RecordingAdapter:
    async def add_client(self, **kwargs: object) -> object:
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        return None


def _link_service(tmp_path: Path, *, pool: tuple[str, ...] = ()) -> XrayService:
    """A service wired only for the pure ``_build_vless_link`` unit tests."""
    return XrayService(
        vpn_keys=object(),  # type: ignore[arg-type]
        users=object(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=_settings(tmp_path, pool=pool),
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=object(),  # type: ignore[arg-type]
    )


async def _make_service(tmp_path: Path, *, pool: tuple[str, ...] = ()) -> tuple[XrayService, VpnKeyRepository, Database]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    repo = VpnKeyRepository(db)
    await repo.db.conn.execute(
        "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (100, "user", "User", UserRole.APPROVED_USER.value, "now", "now"),
    )
    await repo.db.commit()
    service = XrayService(
        vpn_keys=repo,
        users=_Users(),  # type: ignore[arg-type]
        adapter=_RecordingAdapter(),  # type: ignore[arg-type]
        settings=_settings(tmp_path, pool=pool),
        clock=ClockProvider(),
        ids=_Ids(),  # type: ignore[arg-type]
        audit=_Audit(),  # type: ignore[arg-type]
        user_locks=UserLockManager(),
        backend_health=BackendHealth(),
        xhttp_adapter=_RecordingAdapter(),  # type: ignore[arg-type]
    )
    return service, repo, db


# --- pure helpers ---------------------------------------------------------

def test_parse_spider_x_pool_splits_strips_and_drops_blanks() -> None:
    assert parse_spider_x_pool(None) == ()
    assert parse_spider_x_pool("") == ()
    assert parse_spider_x_pool("   ") == ()
    assert parse_spider_x_pool("/, /api ,,/blog/") == ("/", "/api", "/blog/")


def test_pick_spider_x_is_deterministic_and_in_pool() -> None:
    pool = ("/", "/api", "/blog/", "/static/app.js")
    uuid_value = "11111111-2222-4333-8444-555555555555"
    first = pick_spider_x(uuid_value, pool)
    second = pick_spider_x(uuid_value, pool)
    # (c): stable across calls, and always a member of the pool.
    assert first == second
    assert first in pool
    # Empty pool -> None (spx not emitted).
    assert pick_spider_x(uuid_value, ()) is None
    # Distinct UUIDs are able to land on distinct entries (not a constant).
    picks = {pick_spider_x(f"{i:08d}-0000-4000-8000-000000000000", pool) for i in range(50)}
    assert len(picks) > 1


# --- link emission: (a) NULL, (b) set, (d) both families / all profiles ---

def test_link_omits_spx_when_spider_x_is_none(tmp_path: Path) -> None:
    service = _link_service(tmp_path)
    tcp = service._build_vless_link("u", "abcd", "xray_tcp_A0001", transport="tcp", spider_x=None)
    assert "spx" not in tcp
    for profile in ("base", "antisib", "multi"):
        link = service._build_vless_link(
            "u", "abcd", f"xray_http_{profile}_A0001", transport="http", profile=profile, spider_x=None,
        )
        assert "spx" not in link


def test_link_emits_urlencoded_spx_for_all_families(tmp_path: Path) -> None:
    service = _link_service(tmp_path)
    # A value with slashes must be percent-encoded (safe="") -> %2F, and must sit
    # in the query, before the #fragment.
    value = "/api/v2"
    tcp = service._build_vless_link("u", "abcd", "xray_tcp_A0001", transport="tcp", spider_x=value)
    assert "&spx=%2Fapi%2Fv2" in tcp
    assert tcp.endswith("#xray_tcp_A0001")
    # No raw slash leaked into the encoded value.
    assert "spx=/api" not in tcp
    for profile in ("base", "antisib", "multi"):
        link = service._build_vless_link(
            "u", "abcd", f"xray_http_{profile}_A0001", transport="http", profile=profile, spider_x=value,
        )
        assert "&spx=%2Fapi%2Fv2" in link
        assert link.endswith(f"#xray_http_{profile}_A0001")


def test_link_spx_encodes_bare_slash(tmp_path: Path) -> None:
    service = _link_service(tmp_path)
    link = service._build_vless_link("u", "abcd", "xray_tcp_A0001", transport="tcp", spider_x="/")
    assert "&spx=%2F" in link


# --- create_xray_key end-to-end ------------------------------------------

def test_create_without_pool_leaves_spider_x_null_and_no_spx(tmp_path: Path) -> None:
    async def run() -> None:
        service, repo, db = await _make_service(tmp_path, pool=())
        try:
            result = await service.create_xray_key(
                100, TelegramUserProfile(100, "user", "User"), None, transport="tcp"
            )
            persisted = await repo.get_by_id(result.key.id)
            assert persisted is not None
            assert persisted.spider_x is None
            assert "spx" not in str(persisted.public_payload["link"])
            assert "spx" not in await service.get_xray_key_config(100, result.key.id)
        finally:
            await db.close()

    asyncio.run(run())


def test_create_with_pool_persists_deterministic_spider_x_and_emits_spx(tmp_path: Path) -> None:
    async def run() -> None:
        pool = ("/", "/api", "/blog/")
        service, repo, db = await _make_service(tmp_path, pool=pool)
        try:
            for transport, profile in (("tcp", "base"), ("http", "base"), ("http", "antisib"), ("http", "multi")):
                result = await service.create_xray_key(
                    100, TelegramUserProfile(100, "user", "User"), None,
                    transport=transport, xhttp_profile=profile,
                )
                persisted = await repo.get_by_id(result.key.id)
                assert persisted is not None
                uuid_value = str(persisted.payload["uuid"])
                expected = pick_spider_x(uuid_value, pool)
                # (c): the stored value is exactly the deterministic pick for this UUID.
                assert persisted.spider_x == expected
                assert persisted.payload["spider_x"] == expected
                # (b)+(d): the config link carries the encoded spx, on every family.
                from urllib.parse import quote
                assert f"&spx={quote(expected, safe='')}" in str(persisted.public_payload["link"])
                assert "spx=" in await service.get_xray_key_config(100, result.key.id)
        finally:
            await db.close()

    asyncio.run(run())


# --- v31 migration --------------------------------------------------------

def test_v31_adds_nullable_spider_x_column(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            cols = await db._table_columns("vpn_keys")
            assert "spider_x" in cols
        finally:
            await db.close()

    asyncio.run(run())


def test_v31_backfills_only_with_pool_and_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def run() -> None:
        pool = ("/", "/api", "/blog/")
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            repo = VpnKeyRepository(db)
            await db.conn.execute(
                "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (100, "user", "User", UserRole.APPROVED_USER.value, "now", "now"),
            )
            await db.commit()
            xray_uuids = ["aaaa1111-0000-4000-8000-000000000001", "bbbb2222-0000-4000-8000-000000000002"]
            for uuid_value in xray_uuids:
                await repo.create_pending(
                    owner_user_id=100, username="user", key_type=VpnKeyType.XRAY, note=None,
                    payload={"uuid": uuid_value}, public_payload={}, created_by=100, now="now",
                    uuid=uuid_value,
                )
            # An AWG key must never be backfilled (spx is xray/REALITY-only).
            awg_key = await repo.create_pending(
                owner_user_id=100, username="user", key_type=VpnKeyType.AWG, note=None,
                payload={}, public_payload={}, created_by=100, now="now",
                public_key="wg-pub-key",
            )

            # No pool env -> the backfill left every row NULL (default behaviour).
            for uuid_value in xray_uuids:
                key = await repo.find_by_uuid(uuid_value)
                assert key is not None and key.spider_x is None

            # With the pool set, the backfill fills the NULL xray rows only, each to
            # its deterministic pick.
            monkeypatch.setenv("XRAY_SPIDER_X_POOL", ",".join(pool))
            await db._ensure_spider_x_backfill()
            await db.commit()
            assigned: dict[str, str | None] = {}
            for uuid_value in xray_uuids:
                key = await repo.find_by_uuid(uuid_value)
                assert key is not None
                assert key.spider_x == pick_spider_x(uuid_value, pool)
                assigned[uuid_value] = key.spider_x
            awg_after = await repo.get_by_id(awg_key.id)
            assert awg_after is not None and awg_after.spider_x is None

            # Idempotent: a second run overwrites nothing (only NULL rows are filled).
            await db._ensure_spider_x_backfill()
            await db.commit()
            for uuid_value in xray_uuids:
                key = await repo.find_by_uuid(uuid_value)
                assert key is not None and key.spider_x == assigned[uuid_value]
        finally:
            await db.close()

    asyncio.run(run())


def test_enabling_pool_after_v31_backfills_on_next_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a deployment that first boots v31 with an empty pool and enables
    it on a LATER restart must still backfill its pre-existing xray keys — the
    every-bootstrap backfill covers what the one-shot v31 migration cannot."""

    async def run() -> None:
        pool = ("/", "/api", "/blog/")
        db_path = tmp_path / "vpn.db"
        uuid_value = "cccc3333-0000-4000-8000-000000000003"

        # First boot: empty pool. v31 adds the column; the key stays NULL.
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            repo = VpnKeyRepository(db)
            await db.conn.execute(
                "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (100, "user", "User", UserRole.APPROVED_USER.value, "now", "now"),
            )
            await db.commit()
            await repo.create_pending(
                owner_user_id=100, username="user", key_type=VpnKeyType.XRAY, note=None,
                payload={"uuid": uuid_value}, public_payload={}, created_by=100, now="now",
                uuid=uuid_value,
            )
            key = await repo.find_by_uuid(uuid_value)
            assert key is not None and key.spider_x is None
        finally:
            await db.close()

        # Second boot: pool enabled. schema is already v31, so the migration never
        # re-runs — the every-bootstrap backfill is what fills the existing key.
        monkeypatch.setenv("XRAY_SPIDER_X_POOL", ",".join(pool))
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            repo = VpnKeyRepository(db)
            key = await repo.find_by_uuid(uuid_value)
            assert key is not None
            assert key.spider_x == pick_spider_x(uuid_value, pool)
        finally:
            await db.close()

    asyncio.run(run())


# --- settings validation --------------------------------------------------

def test_settings_rejects_pool_entry_without_leading_slash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com")
    monkeypatch.setenv("XRAY_REALITY_PUBLIC_KEY", "public")
    monkeypatch.setenv("XRAY_SNI", "example.com")
    monkeypatch.setenv("XRAY_SHORT_ID", "abcd")
    monkeypatch.setenv("XRAY_SPIDER_X_POOL", "/ok,bad")
    with pytest.raises(SettingsError):
        load_settings()


def test_settings_accepts_valid_pool(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com")
    monkeypatch.setenv("XRAY_REALITY_PUBLIC_KEY", "public")
    monkeypatch.setenv("XRAY_SNI", "example.com")
    monkeypatch.setenv("XRAY_SHORT_ID", "abcd")
    monkeypatch.setenv("XRAY_SPIDER_X_POOL", "/, /api ,/blog/")
    settings = load_settings()
    assert settings.xray_spider_x_pool == ("/", "/api", "/blog/")
