from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path

import pytest

from adapters.errors import MtProxyApplyError
from adapters.mtproxy import MtProxyAdapter, MtProxyManagedSecret
from models.dto import ShellResult


class _Shell:
    def __init__(self, port: int = 8443) -> None:
        self.port = port
        self.calls: list[tuple[str, ...]] = []

    async def run(self, args: list[str], **kwargs: object) -> ShellResult:
        self.calls.append(tuple(args))
        assert isinstance(args, list)
        if args == ["ss", "-tln"]:
            return ShellResult(tuple(args), 0, f"LISTEN 0 4096 0.0.0.0:{self.port} 0.0.0.0:*", "")
        raise AssertionError(f"unexpected shell command: {args}")


class _SystemCtl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []
        self.fail_restart = False

    async def daemon_reload(self) -> ShellResult:
        self.calls.append(("daemon-reload", None))
        return ShellResult(("systemctl", "daemon-reload"), 0, "", "")

    async def restart(self, service_name: str) -> ShellResult:
        self.calls.append(("restart", service_name))
        return ShellResult(("systemctl", "restart", service_name), 1 if self.fail_restart else 0, "", "")

    async def is_active(self, service_name: str) -> ShellResult:
        self.calls.append(("is-active", service_name))
        return ShellResult(("systemctl", "is-active", service_name), 0, "active", "")


def _adapter(tmp_path: Path, systemctl: _SystemCtl | None = None) -> MtProxyAdapter:
    return MtProxyAdapter(
        shell=_Shell(),  # type: ignore[arg-type]
        systemctl=systemctl or _SystemCtl(),  # type: ignore[arg-type]
        service_name="mtproxy",
        binary_path=Path("/usr/local/bin/mtproto-proxy"),
        run_user="mtproxy",
        run_group="mtproxy",
        proxy_secret_path=tmp_path / "proxy-secret",
        proxy_multi_conf_path=tmp_path / "proxy-multi.conf",
        managed_secrets_path=tmp_path / "vpnbot-managed-secrets.json",
        managed_env_path=tmp_path / "vpnbot-mtproxy.env",
        port=8443,
        internal_stats_port=8888,
        workers=1,
        apply_timeout_seconds=10,
        rollback_on_apply_failure=True,
        keep_last_backups=10,
    )


def _secret(value: str, access_id: int = 1) -> MtProxyManagedSecret:
    return MtProxyManagedSecret(secret=value, fingerprint=f"fp-{access_id}", owner_user_id=100 + access_id, access_id=access_id)


def test_mtproxy_adapter_apply_writes_managed_files_and_restarts(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        result = await adapter.apply_managed_secrets([_secret("a" * 32)])

        assert result.changed is True
        document = json.loads((tmp_path / "vpnbot-managed-secrets.json").read_text(encoding="utf-8"))
        assert document["secrets"][0]["secret"] == "a" * 32
        assert "a" * 32 not in (tmp_path / "vpnbot-mtproxy.env").read_text(encoding="utf-8")
        assert ("daemon-reload", None) not in systemctl.calls
        assert ("restart", "mtproxy") in systemctl.calls
        assert not (tmp_path / "run-mtproxy-managed").exists()
        assert not (tmp_path / "mtproxy.service.d" / "vpnbot-managed.conf").exists()
        if os.name == "posix":
            assert stat.S_IMODE((tmp_path / "vpnbot-managed-secrets.json").stat().st_mode) == 0o600

    asyncio.run(run())


def test_mtproxy_adapter_backups_with_secrets_are_private(tmp_path: Path) -> None:
    async def run() -> None:
        adapter = _adapter(tmp_path)
        await adapter.apply_managed_secrets([_secret("a" * 32)])
        await adapter.apply_managed_secrets([_secret("b" * 32, access_id=2)])

        backup_root = tmp_path / "vpnbot-backups"
        backup_dirs = [path for path in backup_root.iterdir() if path.is_dir()]
        assert backup_dirs
        secret_backups = list(backup_root.glob("*/vpnbot-managed-secrets.json"))
        assert secret_backups
        assert any("a" * 32 in path.read_text(encoding="utf-8") for path in secret_backups)
        if os.name == "posix":
            for directory in backup_dirs:
                assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            for path in secret_backups:
                assert stat.S_IMODE(path.stat().st_mode) == 0o600

    asyncio.run(run())


def test_vpn_bot_unit_does_not_allow_runtime_write_to_systemd_system() -> None:
    unit = Path("deploy/vpn-bot.service").read_text(encoding="utf-8")
    read_write_lines = [line for line in unit.splitlines() if line.startswith("ReadWritePaths=")]
    assert read_write_lines
    assert "/etc/systemd/system" not in read_write_lines[0]


def test_mtproxy_systemd_dropin_template_contains_no_raw_secret_surface() -> None:
    dropin = Path("deploy/mtproxy-vpnbot-managed.conf").read_text(encoding="utf-8")
    assert "-S" not in dropin
    assert "MTPROTO_SECRET" not in dropin
    assert "vpnbot-managed-secrets.json" not in dropin
    assert "ExecStart=/opt/vpn-service/scripts/run-mtproxy-managed" in dropin


def test_mtproxy_adapter_noop_does_not_restart_when_files_match(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await adapter.apply_managed_secrets([_secret("a" * 32)])
        result = await adapter.apply_managed_secrets([_secret("a" * 32)])

        assert result.changed is False
        assert [call for call in systemctl.calls if call == ("restart", "mtproxy")] == [("restart", "mtproxy")]

    asyncio.run(run())


def test_mtproxy_adapter_rollback_restores_previous_secrets_and_redacts_failure(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await adapter.apply_managed_secrets([_secret("a" * 32)])

        systemctl.fail_restart = True
        with pytest.raises(MtProxyApplyError) as exc_info:
            await adapter.apply_managed_secrets([_secret("b" * 32, access_id=2)])

        assert "b" * 32 not in str(exc_info.value)
        document = json.loads((tmp_path / "vpnbot-managed-secrets.json").read_text(encoding="utf-8"))
        assert document["secrets"][0]["secret"] == "a" * 32
        assert all(item["secret"] != "b" * 32 for item in document["secrets"])

    asyncio.run(run())


def test_mtproxy_adapter_empty_desired_list_uses_private_runtime_placeholder(tmp_path: Path) -> None:
    async def run() -> None:
        adapter = _adapter(tmp_path)
        await adapter.apply_managed_secrets([])

        document = json.loads((tmp_path / "vpnbot-managed-secrets.json").read_text(encoding="utf-8"))
        assert document["secrets"] == []
        assert document["runtime_secrets"][0]["purpose"] == "empty-placeholder"
        assert len(document["runtime_secrets"][0]["secret"]) == 32

    asyncio.run(run())
