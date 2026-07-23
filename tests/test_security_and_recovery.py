
import asyncio
import json
import re
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.errors import AwgApplyError, AwgConfigError
from adapters.shell_runner import ShellRunner
from config.settings import Settings, SettingsError, load_settings
from db.database import CURRENT_SCHEMA_VERSION, Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from repositories.access_requests import AccessRequestRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.awg import AwgService
from services.xray import XrayService


def _settings(tmp_path: Path | None = None, **overrides: object) -> Settings:
    values = dict(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db" if tmp_path is not None else Path("/tmp/vpn.db"),
        log_dir=Path("/tmp/logs"),
        bot_lock_path=Path("/tmp/vpn.lock"),
        bot_drop_pending_updates=False,
        xray_config_path=Path("/tmp/xray.json"),
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="",
        xray_public_host="2001:db8::1",
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
        awg_config_path=Path("/tmp/awg.conf"),
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
    )
    values.update(overrides)
    return Settings(**values)


def test_xray_vless_ipv6_host_is_bracketed() -> None:
    service = XrayService(
        vpn_keys=object(),  # type: ignore[arg-type]
        users=object(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=_settings(),
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=object(),  # type: ignore[arg-type]
    )

    link = service._build_vless_link("00000000-0000-4000-8000-000000000000", "abcd", "label")

    assert "vless://00000000-0000-4000-8000-000000000000@[2001:db8::1]:443?" in link
    assert link.endswith("#label")


def test_settings_reject_invalid_xray_short_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com")
    monkeypatch.setenv("XRAY_REALITY_PUBLIC_KEY", "public")
    monkeypatch.setenv("XRAY_SNI", "example.com")
    monkeypatch.setenv("XRAY_SHORT_ID", "not-hex")

    with pytest.raises(SettingsError):
        load_settings()


def test_settings_drop_pending_updates_defaults_false_and_can_be_enabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.delenv("BOT_DROP_PENDING_UPDATES", raising=False)
    monkeypatch.delenv("XRAY_APPLY_MODE", raising=False)

    settings = load_settings()
    assert settings.bot_drop_pending_updates is False
    assert settings.xray_apply_mode == "api"

    monkeypatch.setenv("BOT_DROP_PENDING_UPDATES", "true")

    assert load_settings().bot_drop_pending_updates is True


def test_settings_repr_does_not_leak_bot_token_or_proxy_password(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("BOT_TOKEN", "123456789:super-secret-bot-token-value")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("DEFAULT_PROXY_PASSWORD", "proxy-password-secret-value")

    rendered = repr(load_settings())

    assert "super-secret-bot-token-value" not in rendered
    assert "proxy-password-secret-value" not in rendered


def test_create_app_closes_db_when_startup_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import bot.app as app_module

    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    settings = load_settings()

    closed: list[bool] = []
    real_close = Database.close

    async def tracking_close(self: Database) -> None:
        closed.append(True)
        await real_close(self)

    async def boom(_settings: object, _db: object) -> None:
        raise RuntimeError("startup failed")

    monkeypatch.setattr(Database, "close", tracking_close)
    monkeypatch.setattr(app_module, "_build_app", boom)

    with pytest.raises(RuntimeError, match="startup failed"):
        asyncio.run(app_module.create_app(settings))

    # create_app must release the DB connection it opened before the failure.
    assert closed == [True]


def test_validate_awg_ready_requires_server_public_key_and_port() -> None:
    base = _settings()
    base.validate_awg_ready()  # baseline is complete

    with pytest.raises(SettingsError, match="AWG_SERVER_PUBLIC_KEY"):
        replace(base, awg_server_public_key="").validate_awg_ready()

    with pytest.raises(SettingsError, match="AWG_ENDPOINT_PORT"):
        replace(base, awg_endpoint_port=0).validate_awg_ready()


def test_settings_reject_non_positive_admin_ids(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "-5")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))

    with pytest.raises(SettingsError, match="ADMIN_IDS"):
        load_settings()


def test_settings_reject_control_chars_in_network_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com\nInjected: line")

    with pytest.raises(SettingsError, match="XRAY_PUBLIC_HOST"):
        load_settings()


def test_settings_blank_health_host_falls_back_to_loopback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("HEALTH_HOST", "")

    assert load_settings().health_host == "127.0.0.1"


def test_settings_reject_malformed_fernet_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    # Right length and charset, but does not decode to a 32-byte Fernet key.
    monkeypatch.setenv("OFFSITE_BACKUP_ENCRYPTION_KEY", "A" * 44)

    with pytest.raises(SettingsError, match="OFFSITE_BACKUP_ENCRYPTION_KEY"):
        load_settings()


def test_settings_accept_valid_fernet_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import base64
    import os as _os

    # A Fernet key is 32 random bytes encoded as URL-safe base64 (44 chars).
    valid_key = base64.urlsafe_b64encode(_os.urandom(32)).decode()

    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("OFFSITE_BACKUP_ENCRYPTION_KEY", valid_key)

    assert load_settings().offsite_backup_encryption_key == valid_key


def test_settings_reject_invalid_xray_apply_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_APPLY_MODE", "bad")

    with pytest.raises(SettingsError, match="XRAY_APPLY_MODE"):
        load_settings()


def test_settings_allow_xray_apply_mode_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_APPLY_MODE", "api")

    settings = load_settings()
    assert settings.xray_apply_mode == "api"


def test_validate_xray_ready_api_mode_requires_inbound_tag() -> None:
    settings = _settings(
        xray_apply_mode="api",
        xray_stats_server="127.0.0.1:10085",
        xray_inbound_tag="",
    )
    with pytest.raises(SettingsError, match="XRAY_INBOUND_TAG"):
        settings.validate_xray_ready()


def test_validate_xray_ready_api_mode_requires_stats_server() -> None:
    settings = _settings(
        xray_apply_mode="api",
        xray_stats_server="",
        xray_inbound_tag="vless-in",
    )
    with pytest.raises(SettingsError, match="XRAY_STATS_SERVER"):
        settings.validate_xray_ready()


def test_validate_xray_ready_api_mode_passes_with_required_fields() -> None:
    settings = _settings(
        xray_apply_mode="api",
        xray_stats_server="127.0.0.1:10085",
        xray_inbound_tag="vless-in",
    )
    settings.validate_xray_ready()


def test_readme_uses_env_example_as_canonical_source() -> None:
    # The README is a short overview; the deep content moved into docs/. Each
    # assertion is checked against the file that now owns it (drift guard).
    readme = Path("README.md").read_text(encoding="utf-8")
    configuration = Path("docs/configuration.md").read_text(encoding="utf-8")
    deployment = Path("docs/deployment.md").read_text(encoding="utf-8")
    operations = Path("docs/operations.md").read_text(encoding="utf-8")

    # README still points at .env.example as the copy-paste template.
    assert ".env.example" in readme
    assert "pip install -r requirements.txt -c constraints.txt" in readme

    # Configuration reference owns the variable docs and legacy-alias guidance.
    assert "AWG_DNS" in configuration
    assert "legacy alias" in configuration
    assert "AWG_CLIENT_DNS=" not in configuration
    assert "SQLITE_SYNCHRONOUS=FULL" in configuration

    # Deployment owns the install commands and apply-mode guidance.
    assert "install -o root -g root -m 0600 .env.example .env" in deployment
    assert "XRAY_APPLY_MODE=restart" in deployment

    # Operations runbook owns the day-2 sections.
    assert "Production Operations Runbook" in operations
    assert "Backup" in operations
    assert "Restore" in operations
    assert "Firewall" in operations
    assert "Read-only health checks" in operations
    assert "Rollback after a bad deploy" in operations
    assert "Never expose the Xray stats API to the internet" in operations


def _pins(text: str) -> dict[str, str]:
    return dict(re.findall(r"^([A-Za-z0-9._-]+)==([^\s\\]+)", text, re.M))


def test_constraints_file_pins_runtime_dependency_tree() -> None:
    constraints = Path("constraints.txt").read_text(encoding="utf-8")

    # Direct runtime deps (pinned in requirements.txt) must be present and exact.
    for package in (
        "aiogram==3.29.1",
        "aiohttp==3.14.1",
        "aiosqlite==0.22.1",
        "cryptography==48.0.1",
        "python-dotenv==1.2.2",
    ):
        assert package in constraints


def test_constraints_txt_is_unhashed_mirror_of_hashed() -> None:
    # constraints.txt (scanned by pip-audit) is generated from constraints-hashed.txt
    # (installed with --require-hashes) by scripts/sync-constraints.py. The two pin
    # sets must match exactly, otherwise the audited set drifts from the installed
    # set. Regenerate with `make sync-constraints` / `make update-hashes`.
    constraints = _pins(Path("constraints.txt").read_text(encoding="utf-8"))
    hashed = _pins(Path("constraints-hashed.txt").read_text(encoding="utf-8"))
    assert constraints == hashed


def test_audit_sanitizer_masks_nested_secrets() -> None:
    audit = AuditService(audit_logs=object(), clock=ClockProvider())  # type: ignore[arg-type]

    clean = audit._sanitize(
        {
            "errors": [
                {"private_key": "secret", "nested": {"shortId": "abcd", "token": "bot"}},
                {"message": "ok"},
            ],
            "uuid": "00000000-0000-4000-8000-000000000000",
        }
    )

    assert clean["errors"][0]["private_key"] == "***"
    assert clean["errors"][0]["nested"]["shortId"] == "***"
    assert clean["errors"][0]["nested"]["token"] == "***"
    assert clean["uuid"] == "***"


def test_audit_sanitizer_masks_secret_under_extended_key_names() -> None:
    # P5-002: credential/token synonyms are masked even when the value has no
    # high-entropy pattern the value-regex would otherwise catch.
    audit = AuditService(audit_logs=object(), clock=ClockProvider())  # type: ignore[arg-type]

    clean = audit._sanitize(
        {
            "access_token": "hunter2",
            "api_key": "plainkey",
            "client_secret": "s3cr3t",
            "cookie": "sessionid=abc",
            "note": "ok",
        }
    )

    assert clean["access_token"] == "***"
    assert clean["api_key"] == "***"
    assert clean["client_secret"] == "***"
    assert clean["cookie"] == "***"
    assert clean["note"] == "ok"


def test_audit_sanitizer_redacts_secret_straddling_truncation_boundary() -> None:
    # P5-001: a base64 key that crosses the 256-char cap must be fully masked.
    # Redaction runs BEFORE truncation, so the whole pattern is matched and no
    # prefix of the secret survives into the stored details.
    audit = AuditService(audit_logs=object(), clock=ClockProvider())  # type: ignore[arg-type]

    fernet_like = "A" * 43 + "="  # matches the WG/base64 private-key pattern
    # Place the key so it straddles the 256-char cap (a word boundary — here a
    # space — precedes it, as with any real space/punctuation-separated secret):
    # with truncate-first (the old order) value[:256] would keep ~36 chars of the
    # key, too short for the 43-char pattern to match, so that prefix would leak.
    # Redact-first masks the whole key before the cap is applied.
    filler = "x" * 219 + " "
    payload = f"{filler}{fernet_like} trailing"

    clean = audit._sanitize({"message": payload})

    assert fernet_like not in clean["message"]
    # No long run of the original key survives anywhere in the stored value.
    assert "A" * 30 not in clean["message"]


def test_awg_remove_managed_block() -> None:
    adapter = AwgConfigAdapter(
        config_path=Path("/tmp/unused-awg.conf"),
        interface="awg0",
        backup=BackupAdapter(ClockProvider()),
        shell=ShellRunner(),
        persistent_keepalive=25,
    )
    text = """[Interface]
PrivateKey = server

# vpn-bot peer start key_id=10 owner=100 label=test
[Peer]
PublicKey = client
AllowedIPs = 10.0.0.2/32
# vpn-bot peer end key_id=10
"""

    updated = adapter._remove_managed_block(text, 10)

    assert "PublicKey = client" not in updated
    assert "[Interface]" in updated


def test_awg_candidate_validation_fails_when_quick_tools_are_missing(tmp_path: Path) -> None:
    class Shell:
        async def run(self, args: list[str], **kwargs: object) -> object:
            # Mirror ShellRunner's FileNotFoundError sentinel (rc 127 + "command not found"),
            # which is how a genuinely missing awg-quick/wg-quick binary surfaces.
            return type("Result", (), {"returncode": 127, "ok": False, "stdout": "", "stderr": "command not found"})()

    config_path = tmp_path / "awg.conf"
    config_path.write_text("[Interface]\nPrivateKey = server\n", encoding="utf-8")
    adapter = AwgConfigAdapter(
        config_path=config_path,
        interface="awg0",
        backup=BackupAdapter(ClockProvider()),
        shell=Shell(),  # type: ignore[arg-type]
        persistent_keepalive=25,
    )

    async def run() -> None:
        with pytest.raises(AwgConfigError, match="Не найден awg-quick или wg-quick"):
            await adapter._validate_candidate_config("[Interface]\nPrivateKey = server\n")

    asyncio.run(run())


def test_awg_remove_peer_restores_runtime_from_config_after_runtime_remove_failure(tmp_path: Path) -> None:
    class Shell:
        def __init__(self) -> None:
            self.syncconf_calls = 0

        async def run(self, args: list[str], **kwargs: object) -> object:
            if args[:3] == ["awg", "show", "awg0"]:
                return type("Result", (), {"returncode": 0, "ok": True, "stdout": "peer: public\n", "stderr": ""})()
            if args[:6] == ["awg", "set", "awg0", "peer", "public", "remove"]:
                return type("Result", (), {"returncode": 0, "ok": True, "stdout": "", "stderr": ""})()
            if args[:2] == ["awg-quick", "strip"]:
                return type("Result", (), {"returncode": 0, "ok": True, "stdout": "[Interface]\nPrivateKey = server\n", "stderr": ""})()
            if args[:3] == ["awg", "syncconf", "awg0"]:
                self.syncconf_calls += 1
                return type("Result", (), {"returncode": 0, "ok": True, "stdout": "", "stderr": ""})()
            raise AssertionError(f"unexpected command: {args}")

    config_path = tmp_path / "awg.conf"
    config_path.write_text(
        """[Interface]
PrivateKey = server

# vpn-bot peer start key_id=10 owner=100 label=test
[Peer]
PublicKey = public
AllowedIPs = 10.0.0.2/32
# vpn-bot peer end key_id=10
""",
        encoding="utf-8",
    )
    shell = Shell()
    adapter = AwgConfigAdapter(
        config_path=config_path,
        interface="awg0",
        backup=BackupAdapter(ClockProvider()),
        shell=shell,  # type: ignore[arg-type]
        persistent_keepalive=25,
    )

    async def run() -> None:
        with pytest.raises(AwgApplyError, match="всё ещё найден"):
            await adapter.remove_peer(key_id=10, public_key="public")

    asyncio.run(run())

    assert "PublicKey = public" in config_path.read_text(encoding="utf-8")
    assert shell.syncconf_calls == 1


def test_awg_delete_failed_retry_removes_access_before_deleted() -> None:
    class Repo:
        def __init__(self) -> None:
            self.key = VpnKey(
                id=10,
                owner_user_id=100,
                username="user",
                key_type=VpnKeyType.AWG,
                status=VpnKeyStatus.DELETE_FAILED,
                note=None,
                uuid=None,
                email_label="label",
                public_key="public",
                client_ip="10.0.0.2",
                payload={"public_key": "public"},
                public_payload={},
                created_at="now",
                updated_at="now",
                revoked_at=None,
                deleted_at=None,
                created_by=100,
                revoked_by=None,
                deleted_by=None,
            )

        async def get_by_id(self, key_id: int) -> VpnKey | None:
            return self.key if key_id == self.key.id else None

        async def set_status(self, key_id: int, status: VpnKeyStatus, now: str) -> None:
            self.key = self._replace(status=status)

        async def hard_delete_with_stats(self, key_id: int, now: str) -> None:
            self.key = None

        def _replace(self, **changes: object) -> VpnKey:
            if self.key is None:
                raise RuntimeError("key is deleted")
            return replace(self.key, **changes)

    class Users:
        async def require_approved_or_admin(self, actor_user_id: int) -> User:
            return User(actor_user_id, "user", "User", UserRole.APPROVED_USER, "now", "now", None)

        async def require_superadmin(self, actor_user_id: int) -> User:
            return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

    class Adapter:
        def __init__(self) -> None:
            self.removed = False

        async def remove_peer(self, *, key_id: int, public_key: str | None) -> None:
            self.removed = True

    class Audit:
        async def write(self, **kwargs: object) -> None:
            return None

    repo = Repo()
    adapter = Adapter()
    service = AwgService(
        vpn_keys=repo,  # type: ignore[arg-type]
        users=Users(),  # type: ignore[arg-type]
        adapter=adapter,  # type: ignore[arg-type]
        ip_allocator=object(),  # type: ignore[arg-type]
        settings=_settings(),
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=Audit(),  # type: ignore[arg-type]
    )

    asyncio.run(service.delete_awg_key(100, 10))

    assert adapter.removed is True
    assert repo.key is None


def test_db_v7_prevents_two_pending_requests_and_tolerates_corrupted_json(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            assert CURRENT_SCHEMA_VERSION >= 10
            users = UserRepository(db)
            profile = TelegramUserProfile(telegram_user_id=100, username="user", first_name="User")
            await users.upsert_profile(profile, UserRole.PENDING_USER, "now")
            requests = AccessRequestRepository(db)
            first, created_first = await requests.create_pending_idempotent(100, "user", "now")
            second, created_second = await requests.create_pending_idempotent(100, "user", "now")
            assert created_first is True
            assert created_second is False
            assert first.id == second.id

            await db.conn.execute(
                """
                INSERT INTO vpn_keys (
                  owner_user_id, username, key_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (100, "user", "xray", "active", "{bad json", json.dumps({}), "now", "now", 100),
            )
            await db.commit()
            keys = await VpnKeyRepository(db).list_by_owner(100)
            assert len(keys) == 1
            assert keys[0].payload == {"_corrupted": True}
        finally:
            await db.close()

    asyncio.run(run())


def test_bootstrap_fails_fast_on_legacy_orphan_rows(tmp_path: Path) -> None:
    async def run() -> None:
        import aiosqlite

        db_path = tmp_path / "legacy-orphan.db"
        async with aiosqlite.connect(db_path) as conn:
            await conn.executescript(
                """
                CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO schema_meta VALUES ('schema_version','4');
                CREATE TABLE users (
                  telegram_user_id INTEGER PRIMARY KEY,
                  username TEXT,
                  first_name TEXT,
                  role TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  blocked_at TEXT
                );
                CREATE TABLE access_requests (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  telegram_user_id INTEGER NOT NULL,
                  username TEXT,
                  status TEXT NOT NULL,
                  requested_at TEXT NOT NULL,
                  decided_by INTEGER,
                  decided_at TEXT,
                  decision_note TEXT
                );
                CREATE TABLE vpn_keys (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  owner_user_id INTEGER NOT NULL,
                  username TEXT,
                  key_type TEXT NOT NULL,
                  status TEXT NOT NULL,
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
                  deleted_at TEXT,
                  created_by INTEGER NOT NULL,
                  revoked_by INTEGER,
                  deleted_by INTEGER
                );
                CREATE TABLE proxy_entries (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  proxy_type TEXT NOT NULL,
                  host TEXT NOT NULL,
                  port INTEGER NOT NULL,
                  login TEXT,
                  password TEXT,
                  note TEXT,
                  status TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                CREATE TABLE audit_log (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  actor_user_id INTEGER,
                  action TEXT NOT NULL,
                  entity_type TEXT NOT NULL,
                  entity_id TEXT,
                  details_json TEXT,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE vpn_key_traffic_stats (
                  key_id INTEGER PRIMARY KEY,
                  downloaded_bytes INTEGER NOT NULL DEFAULT 0,
                  uploaded_bytes INTEGER NOT NULL DEFAULT 0,
                  last_raw_downloaded_bytes INTEGER,
                  last_raw_uploaded_bytes INTEGER,
                  last_success_at TEXT,
                  last_attempt_at TEXT,
                  available INTEGER NOT NULL DEFAULT 0,
                  unavailable_reason TEXT,
                  source TEXT
                );
                INSERT INTO vpn_keys (
                  owner_user_id, username, key_type, status, payload_json, public_payload_json,
                  created_at, updated_at, created_by
                )
                VALUES (999, 'orphan', 'xray', 'active', '{}', '{}', 'now', 'now', 999);
                """
            )
            await conn.commit()

        db = Database(db_path)
        await db.connect()
        try:
            with pytest.raises(RuntimeError, match="orphan"):
                await db.bootstrap()
        finally:
            await db.close()

    asyncio.run(run())


def test_access_request_idempotency_does_not_swallow_unrelated_integrity_error() -> None:
    class Repo(AccessRequestRepository):
        async def create(self, telegram_user_id: int, username: str | None, now: str):
            raise sqlite3.IntegrityError("FOREIGN KEY constraint failed")

        async def get_pending_for_user(self, telegram_user_id: int):
            raise AssertionError("unexpected pending lookup")

    async def run() -> None:
        repo = Repo(Database(Path(":memory:")))
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            await repo.create_pending_idempotent(100, "user", "now")

    asyncio.run(run())


def test_managed_short_id_counts_cleanup_statuses_but_not_revoked(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
            repo = VpnKeyRepository(db)
            keys: list[VpnKey] = []
            for index, status in enumerate(
                (
                    VpnKeyStatus.ACTIVE,
                    VpnKeyStatus.PENDING_REVOKE,
                    VpnKeyStatus.PENDING_DELETE,
                    VpnKeyStatus.DELETE_FAILED,
                    VpnKeyStatus.REVOKED,
                ),
                start=1,
            ):
                key = await repo.create_pending(
                    owner_user_id=100,
                    username="user",
                    key_type=VpnKeyType.XRAY,
                    note=None,
                    payload={"short_id": "abcd", "short_id_managed": True},
                    public_payload={},
                    created_by=100,
                    now=f"now-{index}",
                    uuid=f"00000000-0000-4000-8000-00000000000{index}",
                    email_label=f"label-{index}",
                )
                await repo.set_status(key.id, status, f"status-{index}")
                keys.append(key)

            assert await repo.count_active_managed_short_id("abcd", exclude_key_id=keys[0].id) == 3
        finally:
            await db.close()

    asyncio.run(run())
