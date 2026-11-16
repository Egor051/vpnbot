"""Xray config.json backups are pruned in the source: the adapter keeps its newest N.

XrayConfigAdapter writes one ``config.json.<stamp>.<ns>.<token>.bak`` per mutation (two
per key bundle: the REALITY and the XHTTP adapter share the file). Retention used to
be BackupAdapter.create_backup's own cleanup, which ran BEFORE the mutation, matched the
loose glob ``config.json.*.bak`` (an operator's ``config.json.pre-migration.bak`` was a
candidate too) and failed the mutation when it raised. Now:

1. The adapter keeps the newest ``XRAY_CONFIG_BACKUP_KEEP`` (default 10, 1-500) —
   pruned AFTER the change is installed and applied, never on a failed one.
2. Only names matching the exact template create_backup writes are candidates; every
   other file in the directory stays, whatever it is called.
3. A cleanup error is a WARNING; the mutation still succeeds.
4. The other backends (AmneziaWG, ...) keep BackupAdapter's create-time cleanup with
   CONFIG_BACKUP_KEEP_LAST, unchanged.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from pathlib import Path

import pytest

from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.errors import XrayApplyError
from adapters.shell_runner import ShellResult
from adapters.xray_config import XrayConfigAdapter
from config.settings import SettingsError, load_settings

ROOT = Path(__file__).resolve().parents[1]


def _own_name(name: str = "config.json", ns: int | None = None) -> str:
    """A name exactly as BackupAdapter.create_backup writes it."""
    stamp = ClockProvider().now().replace(":", "").replace("+", "_").replace(".", "")
    return f"{name}.{stamp}.{ns if ns is not None else time.time_ns()}.{secrets.token_urlsafe(16)}.bak"


def _write_config(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "inbounds": [
                    {
                        "protocol": "vless",
                        "settings": {"clients": []},
                        "streamSettings": {"security": "reality", "realitySettings": {"shortIds": []}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


class _Systemctl:
    def __init__(self, *, reload_ok: bool = True) -> None:
        self.reload_ok = reload_ok

    async def xray_test_config(self, path: Path) -> ShellResult:
        json.loads(path.read_text(encoding="utf-8"))
        return ShellResult(("xray",), 0, "", "")

    async def reload(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl",), 0 if self.reload_ok else 1, "", "")

    async def restart(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl",), 0, "", "")

    async def is_active(self, service_name: str) -> ShellResult:
        return ShellResult(("systemctl",), 0, "active", "")


def _adapter(config: Path, *, keep: int, systemctl: _Systemctl | None = None, backup: BackupAdapter | None = None) -> XrayConfigAdapter:
    return XrayConfigAdapter(
        config_path=config,
        service_name="xray",
        apply_mode="reload",
        inbound_tag="",
        allow_restart_on_rollback=False,
        # keep_last=1: were the create-time cleanup to run (loose glob, before the
        # mutation), it would delete the foreign files and all but one backup — the
        # adapter must not let it run (create_backup(prune=False)).
        backup=backup or BackupAdapter(ClockProvider(), keep_last=1),
        systemctl=systemctl or _Systemctl(),  # type: ignore[arg-type]
        backup_keep=keep,
    )


async def _add(adapter: XrayConfigAdapter, i: int) -> None:
    await adapter.add_client(
        uuid_value=f"00000000-0000-4000-8000-{i:012d}",
        email_label=f"user{i}",
        short_id=f"{i:04x}",
        flow="",
        manage_short_id=False,
    )


def _own(tmp_path: Path) -> list[Path]:
    rx = BackupAdapter.backup_name_re(tmp_path / "config.json")
    return sorted(p for p in tmp_path.iterdir() if rx.fullmatch(p.name))


# Files a careless glob would take for backups — none of them may ever be deleted.
FOREIGN = (
    "config.json.pre-migration.bak",       # an operator's own copy
    "config.json.1794823936074532507.bak",  # the privileged helper's template
    "config.json.bak",
    "config.json.bak-2026-11-01",
    "other.json.2026-11-16T101216_0000.1794823936074532507.c38IjaFrzovrmAmw9o8pIQ.bak",
    "config.json.2026-11-16T101216_0000.1794823936074532507.c38IjaFrzovrmAmw9o8pIQ.bak.orig",
    "config.json.2026-11-16T101216_0000.1794823936074532507.tooShort.bak",
)


def _plant_foreign(tmp_path: Path) -> None:
    for name in FOREIGN:
        (tmp_path / name).write_text("foreign\n", encoding="utf-8")


def _assert_foreign_intact(tmp_path: Path) -> None:
    for name in FOREIGN:
        assert (tmp_path / name).read_text(encoding="utf-8") == "foreign\n", name


# --------------------------------------------------------------------------- #
# BackupAdapter: the exact template and prune_backups
# --------------------------------------------------------------------------- #
def test_template_matches_what_create_backup_writes(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    written = BackupAdapter(ClockProvider()).create_backup(config, prune=False)
    assert BackupAdapter.backup_name_re(config).fullmatch(written.name)
    for name in FOREIGN:
        assert not BackupAdapter.backup_name_re(config).fullmatch(name), name


def test_prune_keeps_the_newest_n_and_only_its_own_names(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    _plant_foreign(tmp_path)
    own = []
    for i in range(8):
        p = tmp_path / _own_name(ns=1_000 + i)
        p.write_text(str(i), encoding="utf-8")
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))
        own.append(p)
    removed = BackupAdapter(ClockProvider()).prune_backups(config, 3)
    assert removed == 5
    assert _own(tmp_path) == sorted(own[-3:])
    _assert_foreign_intact(tmp_path)
    assert config.exists()


def test_prune_never_goes_below_one(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    for i in range(3):
        p = tmp_path / _own_name(ns=i)
        p.write_text("x", encoding="utf-8")
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))
    BackupAdapter(ClockProvider()).prune_backups(config, 0)
    assert len(_own(tmp_path)) == 1


def test_create_backup_without_prune_deletes_nothing(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    _plant_foreign(tmp_path)
    backup = BackupAdapter(ClockProvider(), keep_last=1)
    for _ in range(3):
        backup.create_backup(config, prune=False)
    assert len(_own(tmp_path)) == 3
    _assert_foreign_intact(tmp_path)


def test_other_backends_keep_the_create_time_cleanup(tmp_path: Path) -> None:
    """AmneziaWG calls create_backup(target): CONFIG_BACKUP_KEEP_LAST still applies there."""
    awg = tmp_path / "awg0.conf"
    awg.write_text("[Interface]\n", encoding="utf-8")
    backup = BackupAdapter(ClockProvider(), keep_last=2)
    for _ in range(4):
        backup.create_backup(awg)
    assert len(list(tmp_path.glob("awg0.conf.*.bak"))) == 2


# --------------------------------------------------------------------------- #
# XrayConfigAdapter
# --------------------------------------------------------------------------- #
def test_adapter_keeps_the_newest_n_after_successful_mutations(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    _plant_foreign(tmp_path)

    async def run() -> None:
        adapter = _adapter(config, keep=3)
        for i in range(7):
            await _add(adapter, i)

    asyncio.run(run())
    assert len(_own(tmp_path)) == 3
    _assert_foreign_intact(tmp_path)
    assert len(json.loads(config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"]) == 7


def test_failed_mutation_prunes_nothing(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    for i in range(5):
        p = tmp_path / _own_name(ns=i)
        p.write_text("old", encoding="utf-8")
        os.utime(p, (1_700_000_000 + i, 1_700_000_000 + i))

    async def run() -> None:
        adapter = _adapter(config, keep=2, systemctl=_Systemctl(reload_ok=False))
        with pytest.raises(XrayApplyError):
            await _add(adapter, 1)

    asyncio.run(run())
    # The five old ones plus the backup of the failed mutation (restored, evidence).
    assert len(_own(tmp_path)) == 6


def test_cleanup_error_is_a_warning_not_a_failed_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    backup = BackupAdapter(ClockProvider())

    def boom(target: Path, keep_last: int) -> int:
        raise PermissionError("read-only directory")

    monkeypatch.setattr(backup, "prune_backups", boom)

    async def run() -> None:
        await _add(_adapter(config, keep=1, backup=backup), 1)

    with caplog.at_level(logging.WARNING, logger="adapters.xray_config"):
        asyncio.run(run())
    assert json.loads(config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"][0]["email"] == "user1"
    assert any(
        r.levelno == logging.WARNING and "Xray config backup cleanup failed" in r.getMessage() for r in caplog.records
    ), caplog.text


def test_two_adapters_on_one_config_share_the_retention(tmp_path: Path) -> None:
    """REALITY + XHTTP write two backups per bundle; N bounds the file, not each adapter."""
    config = tmp_path / "config.json"
    _write_config(config)

    async def run() -> None:
        a, b = _adapter(config, keep=4), _adapter(config, keep=4)
        for i in range(5):
            await _add(a, i)
            await _add(b, 100 + i)

    asyncio.run(run())
    assert len(_own(tmp_path)) == 4


def test_no_op_mutations_write_no_backup(tmp_path: Path) -> None:
    """Codex review on #345: the startup label reconcile runs on every boot and is a
    no-op there; with create-time pruning off it piled up one backup per boot. A backup
    is now taken only once a change is known to be needed."""
    config = tmp_path / "config.json"
    _write_config(config)
    uuid = "00000000-0000-4000-8000-000000000001"

    async def run() -> None:
        adapter = _adapter(config, keep=1)
        await adapter.add_client(uuid_value=uuid, email_label="user1", short_id="abcd", flow="", manage_short_id=True)
        assert len(_own(tmp_path)) == 1
        for _ in range(5):
            assert await adapter.rename_clients({uuid: "user1"}, prefer_restart=True) == 0
            assert await adapter.ensure_short_id("abcd") is False
            await adapter.remove_client(uuid_value="00000000-0000-4000-8000-0000000000ff", email_label=None,
                                        short_id=None, remove_short_id=False)
            with pytest.raises(Exception, match="уже существует"):
                await adapter.add_client(uuid_value=uuid, email_label="user1", short_id="abcd", flow="",
                                         manage_short_id=False)

    asyncio.run(run())
    assert len(_own(tmp_path)) == 1, [p.name for p in _own(tmp_path)]


def test_a_real_rename_is_still_backed_up_and_bounded(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    _write_config(config)
    uuid = "00000000-0000-4000-8000-000000000001"

    async def run() -> None:
        adapter = _adapter(config, keep=2)
        await adapter.add_client(uuid_value=uuid, email_label="user0", short_id="abcd", flow="", manage_short_id=False)
        for i in range(1, 5):
            assert await adapter.rename_clients({uuid: f"user{i}"}) == 1

    asyncio.run(run())
    assert len(_own(tmp_path)) == 2
    assert json.loads(config.read_text(encoding="utf-8"))["inbounds"][0]["settings"]["clients"][0]["email"] == "user4"


# --------------------------------------------------------------------------- #
# The setting
# --------------------------------------------------------------------------- #
def test_setting_default_and_range(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.delenv("XRAY_CONFIG_BACKUP_KEEP", raising=False)
    assert load_settings().xray_config_backup_keep == 10
    monkeypatch.setenv("XRAY_CONFIG_BACKUP_KEEP", "25")
    assert load_settings().xray_config_backup_keep == 25
    for bad in ("0", "501", "ten"):
        monkeypatch.setenv("XRAY_CONFIG_BACKUP_KEEP", bad)
        with pytest.raises(SettingsError, match="XRAY_CONFIG_BACKUP_KEEP"):
            load_settings()


def test_env_example_offers_the_setting() -> None:
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    assert "XRAY_CONFIG_BACKUP_KEEP=10" in lines


def test_app_wires_the_setting_into_both_xray_adapters() -> None:
    text = (ROOT / "bot" / "app.py").read_text(encoding="utf-8")
    assert text.count("backup_keep=settings.xray_config_backup_keep") == 2
