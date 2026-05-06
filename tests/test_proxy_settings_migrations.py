from __future__ import annotations

import asyncio
import re
import sqlite3
from pathlib import Path

import pytest

from config.settings import SettingsError, load_settings
from db.database import CURRENT_SCHEMA_VERSION, Database


def _base_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    for name in (
        "SOCKS5_ENABLED",
        "SOCKS5_HOST",
        "SOCKS5_PORT",
        "SOCKS5_LOGIN_PREFIX",
        "MTPROTO_ENABLED",
        "MTPROTO_MODE",
        "MTPROTO_HOST",
        "MTPROTO_PORT",
        "MTPROTO_SECRET",
        "MTPROTO_SERVICE_NAME",
        "MTPROTO_BINARY_PATH",
        "MTPROTO_RUN_USER",
        "MTPROTO_RUN_GROUP",
        "MTPROTO_CONFIG_DIR",
        "MTPROTO_PROXY_SECRET_PATH",
        "MTPROTO_PROXY_MULTI_CONF_PATH",
        "MTPROTO_MANAGED_DIR",
        "MTPROTO_MANAGED_SECRETS_PATH",
        "MTPROTO_MANAGED_ENV_PATH",
        "MTPROTO_MANAGED_WRAPPER_PATH",
        "MTPROTO_BACKUP_DIR",
        "MTPROTO_INTERNAL_STATS_PORT",
        "MTPROTO_WORKERS",
        "MTPROTO_APPLY_TIMEOUT_SECONDS",
        "MTPROTO_ROLLBACK_ON_APPLY_FAILURE",
        "MTPROTO_KEEP_LAST_BACKUPS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_socks5_disabled_does_not_require_host_or_port(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)

    settings = load_settings()

    assert settings.socks5_enabled is False
    assert settings.socks5_host == ""
    assert settings.socks5_port is None


def test_socks5_enabled_requires_host_and_port(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("SOCKS5_ENABLED", "true")
    monkeypatch.setenv("SOCKS5_PORT", "31337")

    with pytest.raises(SettingsError, match="SOCKS5_HOST"):
        load_settings()

    monkeypatch.setenv("SOCKS5_HOST", "127.0.0.1")
    monkeypatch.delenv("SOCKS5_PORT", raising=False)

    with pytest.raises(SettingsError, match="SOCKS5_PORT"):
        load_settings()


@pytest.mark.parametrize("port", ["0", "65536", "bad"])
def test_socks5_port_validation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, port: str) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("SOCKS5_ENABLED", "true")
    monkeypatch.setenv("SOCKS5_HOST", "127.0.0.1")
    monkeypatch.setenv("SOCKS5_PORT", port)

    with pytest.raises(SettingsError, match="SOCKS5_PORT"):
        load_settings()


@pytest.mark.parametrize("prefix", ["root", "admin", "user", "test", "ubuntu", "www", "daemon", "bad-prefix"])
def test_socks5_login_prefix_validation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prefix: str) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("SOCKS5_LOGIN_PREFIX", prefix)

    with pytest.raises(SettingsError, match="SOCKS5_LOGIN_PREFIX"):
        load_settings()


def test_mtproto_disabled_does_not_require_host_or_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)

    settings = load_settings()

    assert settings.mtproto_enabled is False
    assert settings.mtproto_host == ""
    assert settings.mtproto_secret == ""


def test_mtproto_enabled_requires_host_and_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MTPROTO_ENABLED", "true")
    monkeypatch.setenv("MTPROTO_SECRET", "a" * 32)

    with pytest.raises(SettingsError, match="MTPROTO_HOST"):
        load_settings()

    monkeypatch.setenv("MTPROTO_HOST", "127.0.0.1")
    monkeypatch.delenv("MTPROTO_SECRET", raising=False)

    with pytest.raises(SettingsError, match="MTPROTO_SECRET"):
        load_settings()


def test_mtproto_managed_does_not_require_static_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MTPROTO_ENABLED", "true")
    monkeypatch.setenv("MTPROTO_MODE", "managed")
    monkeypatch.setenv("MTPROTO_HOST", "127.0.0.1")

    settings = load_settings()

    assert settings.mtproto_enabled is True
    assert settings.mtproto_mode == "managed"
    assert settings.mtproto_secret == ""
    assert settings.mtproto_service_name == "mtproxy"
    assert settings.mtproto_managed_dir == Path("/etc/mtproxy/vpnbot")
    assert settings.mtproto_managed_secrets_path == Path("/etc/mtproxy/vpnbot/managed-secrets.json")
    assert settings.mtproto_managed_env_path == Path("/etc/mtproxy/vpnbot/mtproxy.env")
    assert settings.mtproto_backup_dir == Path("/etc/mtproxy/vpnbot/backups")


def test_mtproto_managed_requires_managed_paths_when_blank(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MTPROTO_ENABLED", "true")
    monkeypatch.setenv("MTPROTO_MODE", "managed")
    monkeypatch.setenv("MTPROTO_HOST", "127.0.0.1")
    monkeypatch.setenv("MTPROTO_MANAGED_SECRETS_PATH", "")

    with pytest.raises(SettingsError, match="MTPROTO_MANAGED_SECRETS_PATH"):
        load_settings()


@pytest.mark.parametrize("port", ["0", "65536", "bad"])
def test_mtproto_port_validation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, port: str) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MTPROTO_PORT", port)

    with pytest.raises(SettingsError, match="MTPROTO_PORT"):
        load_settings()


@pytest.mark.parametrize(("name", "value"), [("MTPROTO_WORKERS", "0"), ("MTPROTO_APPLY_TIMEOUT_SECONDS", "0")])
def test_mtproto_managed_numeric_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
    value: str,
) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MTPROTO_ENABLED", "true")
    monkeypatch.setenv("MTPROTO_MODE", "managed")
    monkeypatch.setenv("MTPROTO_HOST", "127.0.0.1")
    monkeypatch.setenv(name, value)

    with pytest.raises(SettingsError, match=name):
        load_settings()


def test_mtproto_secret_is_not_in_settings_repr(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("MTPROTO_ENABLED", "true")
    monkeypatch.setenv("MTPROTO_HOST", "127.0.0.1")
    monkeypatch.setenv("MTPROTO_SECRET", "super-secret")

    settings = load_settings()

    assert "super-secret" not in repr(settings)


def test_proxy_accesses_migration_from_legacy_schema_is_idempotent(tmp_path: Path) -> None:
    schema = Path("db/schema.sql").read_text(encoding="utf-8")
    schema = re.sub(
        r"\nCREATE TABLE IF NOT EXISTS proxy_accesses \(.*?\n\);\n",
        "\n",
        schema,
        flags=re.S,
    )
    schema = re.sub(r"\nCREATE(?: UNIQUE)? INDEX IF NOT EXISTS idx_proxy_accesses_[^;]+;", "\n", schema, flags=re.S)
    old_schema_path = tmp_path / "schema_v7.sql"
    old_schema_path.write_text(schema, encoding="utf-8")

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap(old_schema_path)
            await db.bootstrap(old_schema_path)
            row = await db.conn.execute_fetchone("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            assert row is not None
            assert int(row["value"]) == CURRENT_SCHEMA_VERSION == 10
            table = await db.conn.execute_fetchone(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'proxy_accesses'"
            )
            assert table is not None
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_accesses_v9_migration_preserves_static_records_and_is_idempotent(tmp_path: Path) -> None:
    old_schema = Path("db/schema.sql").read_text(encoding="utf-8")
    old_schema = old_schema.replace("'revoked','revoke_failed','inactive'", "'revoked','inactive'")
    old_schema = old_schema.replace("  secret_fingerprint TEXT,\n  apply_generation INTEGER NOT NULL DEFAULT 0,\n", "")
    old_schema = old_schema.replace("  activated_at TEXT,\n  last_apply_at TEXT,\n", "")
    old_schema = re.sub(r"\nCREATE INDEX IF NOT EXISTS idx_proxy_accesses_mtproto_fingerprint [^;]+;", "\n", old_schema)
    old_schema = re.sub(r"\nCREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_accesses_one_live_per_user_type.*?;\n", "\n", old_schema, flags=re.S)
    old_schema_path = tmp_path / "schema_v8.sql"
    old_schema_path.write_text(old_schema, encoding="utf-8")

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.conn.executescript(old_schema)
            await db.conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '8') "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )
            await db.conn.execute(
                """
                INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                VALUES (1, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now'),
                       (100, 'user', 'User', 'APPROVED_USER', 'now', 'now')
                """
            )
            await db.conn.execute(
                """
                INSERT INTO proxy_accesses (
                  owner_user_id, username, access_type, status,
                  payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (100, 'user', 'mtproto', 'active', '{"type":"mtproto"}', '{"type":"mtproto"}', 'now', 'now', 100)
                """
            )
            await db.commit()

            await db.bootstrap(old_schema_path)
            await db.bootstrap(old_schema_path)

            row = await db.conn.execute_fetchone("SELECT value FROM schema_meta WHERE key = 'schema_version'")
            assert row is not None
            assert int(row["value"]) == CURRENT_SCHEMA_VERSION == 10
            columns = await db.conn.execute_fetchall("PRAGMA table_info(proxy_accesses)")
            column_names = {str(item["name"]) for item in columns}
            assert {"secret_fingerprint", "apply_generation", "activated_at", "last_apply_at"} <= column_names
            access = await db.conn.execute_fetchone("SELECT * FROM proxy_accesses WHERE access_type = 'mtproto'")
            assert access is not None
            assert access["status"] == "active"
            await db.conn.execute(
                """
                INSERT INTO proxy_accesses (
                  owner_user_id, access_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (100, 'mtproto', 'revoke_failed', '{}', '{}', 'now', 'now', 1)
                """
            )
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_access_unique_live_per_user_type(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            await db.conn.execute(
                """
                INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                VALUES (1, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now'),
                       (100, 'user', 'User', 'APPROVED_USER', 'now', 'now')
                """
            )
            await db.conn.execute(
                """
                INSERT INTO proxy_accesses (
                  owner_user_id, access_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (100, 'mtproto', 'active', '{}', '{}', 'now', 'now', 1)
                """
            )
            await db.commit()
            with pytest.raises(sqlite3.IntegrityError):
                await db.conn.execute(
                    """
                    INSERT INTO proxy_accesses (
                      owner_user_id, access_type, status, payload_json, public_payload_json,
                      created_at, updated_at, created_by
                    )
                    VALUES (100, 'mtproto', 'pending_apply', '{}', '{}', 'now', 'now', 1)
                    """
                )
            await db.rollback()
            await db.conn.execute(
                """
                INSERT INTO proxy_accesses (
                  owner_user_id, access_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (100, 'socks5', 'active', '{}', '{}', 'now', 'now', 1),
                       (100, 'mtproto', 'revoked', '{}', '{}', 'now', 'now', 1)
                """
            )
        finally:
            await db.close()

    asyncio.run(run())


def test_proxy_access_unique_live_migration_fails_on_existing_duplicates(tmp_path: Path) -> None:
    old_schema = Path("db/schema.sql").read_text(encoding="utf-8")
    old_schema = re.sub(r"\nCREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_accesses_one_live_per_user_type.*?;\n", "\n", old_schema, flags=re.S)
    old_schema_path = tmp_path / "schema_v9_duplicate.sql"
    old_schema_path.write_text(old_schema, encoding="utf-8")

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.conn.executescript(old_schema)
            await db.conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '9') "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            )
            await db.conn.execute(
                """
                INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at)
                VALUES (1, 'admin', 'Admin', 'SUPERADMIN', 'now', 'now'),
                       (100, 'user', 'User', 'APPROVED_USER', 'now', 'now')
                """
            )
            await db.conn.execute(
                """
                INSERT INTO proxy_accesses (
                  owner_user_id, access_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (100, 'mtproto', 'active', '{}', '{}', 'now', 'now', 1),
                       (100, 'mtproto', 'pending_revoke', '{}', '{}', 'now', 'now', 1)
                """
            )
            await db.commit()

            with pytest.raises(RuntimeError, match="дубли live proxy_accesses"):
                await db.bootstrap(old_schema_path)
        finally:
            await db.close()

    asyncio.run(run())
