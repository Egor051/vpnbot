from __future__ import annotations

import asyncio
import logging
import os
import stat
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.errors import AwgConfigError, XrayConfigError
from adapters.file_lock import ConfigFileLock, ConfigLockBusyError
from adapters.xray_config import XrayConfigAdapter
from bot.messages import cap_telegram_html
from config.settings import SettingsError, load_settings
from db.database import Database
from utils.logging import setup_logging


def _base_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("BOT_LOCK_PATH", str(tmp_path / "bot.lock"))
    monkeypatch.setenv("XRAY_CONFIG_PATH", str(tmp_path / "xray.json"))
    monkeypatch.setenv("AWG_CONFIG_PATH", str(tmp_path / "awg.conf"))
    monkeypatch.setenv("AWG_ENDPOINT_PORT", "443")


def test_strict_bool_env_rejects_invalid_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XRAY_MANAGE_SHORT_IDS", "treu")

    with pytest.raises(SettingsError, match="boolean"):
        load_settings()


def test_strict_bool_env_accepts_explicit_false(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("BOT_DROP_PENDING_UPDATES", "off")
    monkeypatch.setenv("AWG_USE_PRESHARED_KEY", "0")

    settings = load_settings()

    assert settings.bot_drop_pending_updates is False
    assert settings.awg_use_preshared_key is False


def test_sqlite_synchronous_defaults_full_and_accepts_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.delenv("SQLITE_SYNCHRONOUS", raising=False)

    assert load_settings().sqlite_synchronous == "FULL"

    monkeypatch.setenv("SQLITE_SYNCHRONOUS", "normal")
    assert load_settings().sqlite_synchronous == "NORMAL"


def test_sqlite_synchronous_rejects_invalid_value(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("SQLITE_SYNCHRONOUS", "unsafe")

    with pytest.raises(SettingsError, match="SQLITE_SYNCHRONOUS"):
        load_settings()


def test_xray_invalid_network_type_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XRAY_NETWORK_TYPE", "ws")

    with pytest.raises(SettingsError, match="XRAY_NETWORK_TYPE"):
        load_settings()


def test_xray_invalid_public_key_rejected_when_ready(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com")
    monkeypatch.setenv("XRAY_REALITY_PUBLIC_KEY", "bad key!")
    monkeypatch.setenv("XRAY_SNI", "example.com")
    monkeypatch.setenv("XRAY_MANAGE_SHORT_IDS", "true")
    settings = load_settings()

    with pytest.raises(SettingsError, match="XRAY_REALITY_PUBLIC_KEY"):
        settings.validate_xray_ready()


def test_xray_current_valid_values_pass(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com")
    monkeypatch.setenv("XRAY_REALITY_PUBLIC_KEY", "abc_DEF-123")
    monkeypatch.setenv("XRAY_SNI", "example.com")
    monkeypatch.setenv("XRAY_NETWORK_TYPE", "raw")
    monkeypatch.setenv("XRAY_FINGERPRINT", "firefox")
    monkeypatch.setenv("XRAY_MANAGE_SHORT_IDS", "true")

    load_settings().validate_xray_ready()


def test_symlink_config_path_rejected(tmp_path: Path) -> None:
    real_path = tmp_path / "real.json"
    real_path.write_text("{}", encoding="utf-8")
    link_path = tmp_path / "linked.json"
    try:
        link_path.symlink_to(real_path)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(XrayConfigError, match="symlink"):
        XrayConfigAdapter(
            config_path=link_path,
            service_name="xray",
            apply_mode="restart",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=SimpleNamespace(),
            systemctl=SimpleNamespace(),
        )
    with pytest.raises(AwgConfigError, match="symlink"):
        AwgConfigAdapter(
            config_path=link_path,
            interface="awg0",
            backup=SimpleNamespace(),
            shell=SimpleNamespace(),
            persistent_keepalive=25,
        )


@pytest.mark.skipif(os.name != "posix", reason="fcntl lock timeout is POSIX-only")
def test_config_file_lock_times_out_when_held(tmp_path: Path) -> None:
    import fcntl

    target = tmp_path / "config.json"
    target.write_text("{}", encoding="utf-8")
    lock_path = target.with_name(f".{target.name}.lock")
    lock_path.touch()
    with lock_path.open("a+", encoding="utf-8") as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        started = time.monotonic()
        with pytest.raises(ConfigLockBusyError, match="config lock busy"):
            with ConfigFileLock(target, timeout=0.05, poll_interval=0.01):
                pass
        assert time.monotonic() - started < 0.5
        fcntl.flock(held.fileno(), fcntl.LOCK_UN)


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes are Linux-only")
def test_sqlite_and_log_files_are_private_on_posix(tmp_path: Path) -> None:
    async def run() -> None:
        db = Database(tmp_path / "data" / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            for path in (db.path, db.path.with_name(db.path.name + "-wal"), db.path.with_name(db.path.name + "-shm")):
                if path.exists():
                    assert stat.S_IMODE(path.stat().st_mode) == 0o600
        finally:
            await db.close()

    asyncio.run(run())
    setup_logging(tmp_path / "logs")
    try:
        assert stat.S_IMODE((tmp_path / "logs" / "bot.log").stat().st_mode) == 0o600
    finally:
        logging.getLogger().handlers.clear()


def test_cap_telegram_html_closes_tags_and_limits_length() -> None:
    text = "<b>" + ("x" * 5000)

    capped = cap_telegram_html(text, limit=100)

    assert len(capped) <= 100
    assert capped.endswith("...обрезано")
    assert "</b>" in capped
