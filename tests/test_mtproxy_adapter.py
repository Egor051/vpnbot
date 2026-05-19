
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
    def __init__(self, port: int = 8443, process_name: str | None = "mtproto-proxy") -> None:
        self.port = port
        self.process_name = process_name
        self.calls: list[tuple[str, ...]] = []

    async def run(self, args: list[str], **kwargs: object) -> ShellResult:
        self.calls.append(tuple(args))
        assert isinstance(args, list)
        if args == ["ss", "-tlnp"]:
            users = "" if self.process_name is None else f' users:(("{self.process_name}",pid=123,fd=7))'
            return ShellResult(tuple(args), 0, f"LISTEN 0 4096 0.0.0.0:{self.port} 0.0.0.0:*{users}", "")
        raise AssertionError(f"unexpected shell command: {args}")


class _SequencedListeningShell:
    def __init__(self, stdout: list[str]) -> None:
        self.stdout = list(stdout)
        self.calls: list[tuple[str, ...]] = []

    async def run(self, args: list[str], **kwargs: object) -> ShellResult:
        self.calls.append(tuple(args))
        assert args == ["ss", "-tlnp"]
        if self.stdout:
            stdout = self.stdout.pop(0)
        else:
            stdout = ""
        return ShellResult(tuple(args), 0, stdout, "")


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


def _adapter(
    tmp_path: Path,
    systemctl: _SystemCtl | None = None,
    *,
    shell: _Shell | None = None,
) -> MtProxyAdapter:
    wrapper = tmp_path / "run-mtproxy-managed"
    wrapper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    if os.name == "posix":
        wrapper.chmod(0o700)
    return MtProxyAdapter(
        shell=shell or _Shell(),  # type: ignore[arg-type]
        systemctl=systemctl or _SystemCtl(),  # type: ignore[arg-type]
        service_name="mtproxy",
        binary_path=Path("/usr/local/bin/mtproto-proxy"),
        run_user="mtproxy",
        run_group="mtproxy",
        proxy_secret_path=tmp_path / "proxy-secret",
        proxy_multi_conf_path=tmp_path / "proxy-multi.conf",
        managed_secrets_path=tmp_path / "managed-secrets.json",
        managed_env_path=tmp_path / "mtproxy.env",
        managed_wrapper_path=wrapper,
        backup_dir=tmp_path / "backups",
        port=8443,
        internal_stats_port=8888,
        workers=1,
        apply_timeout_seconds=10,
        rollback_on_apply_failure=True,
        keep_last_backups=10,
    )


def _secret(value: str, access_id: int = 1) -> MtProxyManagedSecret:
    return MtProxyManagedSecret(secret=value, fingerprint=f"fp-{access_id}", owner_user_id=100 + access_id, access_id=access_id)


def _ss_listener(port: int = 8443, process_name: str = "mtproto-proxy") -> str:
    return f'LISTEN 0 4096 0.0.0.0:{port} 0.0.0.0:* users:(("{process_name}",pid=123,fd=7))'


async def _init_baseline(adapter: MtProxyAdapter, systemctl: _SystemCtl | None = None) -> None:
    await adapter.init_managed_runtime_baseline()
    if systemctl is not None:
        systemctl.calls.clear()


def test_mtproxy_adapter_apply_writes_managed_files_and_restarts(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await _init_baseline(adapter, systemctl)
        result = await adapter.apply_managed_secrets([_secret("a" * 32)])

        assert result.changed is True
        document = json.loads((tmp_path / "managed-secrets.json").read_text(encoding="utf-8"))
        assert document["secrets"][0]["secret"] == "a" * 32
        assert "a" * 32 not in (tmp_path / "mtproxy.env").read_text(encoding="utf-8")
        assert ("daemon-reload", None) not in systemctl.calls
        assert ("restart", "mtproxy") in systemctl.calls
        assert not (tmp_path / "mtproxy.service.d" / "vpnbot-managed.conf").exists()
        if os.name == "posix":
            assert stat.S_IMODE((tmp_path / "managed-secrets.json").stat().st_mode) == 0o600

    asyncio.run(run())


def test_mtproxy_adapter_backups_with_secrets_are_private(tmp_path: Path) -> None:
    async def run() -> None:
        adapter = _adapter(tmp_path)
        await _init_baseline(adapter)
        await adapter.apply_managed_secrets([_secret("a" * 32)])
        await adapter.apply_managed_secrets([_secret("b" * 32, access_id=2)])

        backup_root = tmp_path / "backups"
        backup_dirs = [path for path in backup_root.iterdir() if path.is_dir()]
        assert backup_dirs
        secret_backups = list(backup_root.glob("*/managed-secrets.json"))
        assert secret_backups
        assert any("a" * 32 in path.read_text(encoding="utf-8") for path in secret_backups)
        if os.name == "posix":
            for directory in backup_dirs:
                assert stat.S_IMODE(directory.stat().st_mode) == 0o700
            for path in secret_backups:
                assert stat.S_IMODE(path.stat().st_mode) == 0o600

    asyncio.run(run())


def test_vpn_bot_unit_does_not_allow_runtime_write_to_systemd_system() -> None:
    # Root+api mode: no ReadWritePaths at all (root runs without sandbox path
    # restrictions). The nonroot example still must not list /etc/systemd/system.
    unit = Path("deploy/vpn-bot.service").read_text(encoding="utf-8")
    read_write_lines = [line for line in unit.splitlines() if line.startswith("ReadWritePaths=")]
    assert read_write_lines == [], "production (root+api) service should have no ReadWritePaths"

    nonroot = Path("deploy/vpn-bot.nonroot.example.service").read_text(encoding="utf-8")
    nonroot_rw = [line for line in nonroot.splitlines() if line.startswith("ReadWritePaths=")]
    if nonroot_rw:
        assert "/etc/systemd/system" not in nonroot_rw[0]


def test_vpn_bot_service_write_paths_are_narrow() -> None:
    # Root+api mode has no ReadWritePaths; the nonroot example's paths are the
    # reference for what a narrowly-scoped non-root deployment should declare.
    unit = Path("deploy/vpn-bot.service").read_text(encoding="utf-8")
    read_write_lines = [line for line in unit.splitlines() if line.startswith("ReadWritePaths=")]
    assert read_write_lines == [], "production (root+api) service should have no ReadWritePaths"

    nonroot = Path("deploy/vpn-bot.nonroot.example.service").read_text(encoding="utf-8")
    nonroot_rw = [line for line in nonroot.splitlines() if line.startswith("ReadWritePaths=")]
    if nonroot_rw:
        read_write = nonroot_rw[0]
        assert "/etc/mtproxy/vpnbot" not in read_write
        assert "/etc/systemd/system" not in read_write


def test_mtproxy_systemd_dropin_template_contains_no_raw_secret_surface() -> None:
    dropin = Path("deploy/mtproxy-vpnbot-managed.conf").read_text(encoding="utf-8")
    assert "-S" not in dropin
    assert "MTPROTO_SECRET" not in dropin
    assert "managed-secrets.json" not in dropin
    assert "User=\n" in dropin
    assert "Group=\n" in dropin
    assert "ExecStart=/opt/vpn-service/scripts/run-mtproxy-managed" in dropin


def test_readme_documents_root_wrapper_permissions_model() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    assert "systemctl show mtproxy -p User -p Group -p ExecStart" in text
    assert "wrapper запускается от root" in text
    assert "root:root" in text
    assert "0600" in text and "0700" in text


def test_mtproxy_adapter_noop_does_not_restart_when_files_match(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await _init_baseline(adapter, systemctl)
        await adapter.apply_managed_secrets([_secret("a" * 32)])
        systemctl.calls.clear()
        result = await adapter.apply_managed_secrets([_secret("a" * 32)])

        assert result.changed is False
        assert [call for call in systemctl.calls if call == ("restart", "mtproxy")] == []

    asyncio.run(run())


def test_noop_apply_repairs_permissions_drift_without_restart(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await _init_baseline(adapter, systemctl)
        await adapter.apply_managed_secrets([_secret("a" * 32)])
        if os.name != "posix":
            return
        (tmp_path / "managed-secrets.json").chmod(0o644)
        (tmp_path / "mtproxy.env").chmod(0o644)
        (tmp_path / "backups").chmod(0o755)
        systemctl.calls.clear()

        result = await adapter.apply_managed_secrets([_secret("a" * 32)])

        assert result.changed is False
        assert [call for call in systemctl.calls if call == ("restart", "mtproxy")] == []
        assert stat.S_IMODE((tmp_path / "managed-secrets.json").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "mtproxy.env").stat().st_mode) == 0o600
        assert stat.S_IMODE((tmp_path / "backups").stat().st_mode) == 0o700

    asyncio.run(run())


def test_mtproxy_adapter_rollback_restores_previous_secrets_and_redacts_failure(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await _init_baseline(adapter, systemctl)
        await adapter.apply_managed_secrets([_secret("a" * 32)])

        systemctl.fail_restart = True
        with pytest.raises(MtProxyApplyError) as exc_info:
            await adapter.apply_managed_secrets([_secret("b" * 32, access_id=2)])

        assert "b" * 32 not in str(exc_info.value)
        document = json.loads((tmp_path / "managed-secrets.json").read_text(encoding="utf-8"))
        assert document["secrets"][0]["secret"] == "a" * 32
        assert all(item["secret"] != "b" * 32 for item in document["secrets"])

    asyncio.run(run())


def test_managed_first_apply_rollback_preserves_baseline(tmp_path: Path) -> None:
    async def run() -> None:
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await _init_baseline(adapter, systemctl)
        baseline = (tmp_path / "managed-secrets.json").read_text(encoding="utf-8")

        systemctl.fail_restart = True
        with pytest.raises(MtProxyApplyError):
            await adapter.apply_managed_secrets([_secret("c" * 32, access_id=3)])

        assert (tmp_path / "managed-secrets.json").read_text(encoding="utf-8") == baseline
        assert "c" * 32 not in baseline

    asyncio.run(run())


def test_managed_preflight_missing_baseline_blocks_apply(tmp_path: Path) -> None:
    async def run() -> None:
        adapter = _adapter(tmp_path)

        with pytest.raises(MtProxyApplyError, match="managed runtime is not initialized"):
            await adapter.apply_managed_secrets([_secret("a" * 32)])

        assert not (tmp_path / "managed-secrets.json").exists()
        assert not (tmp_path / "mtproxy.env").exists()

    asyncio.run(run())


def test_mtproxy_adapter_empty_desired_list_uses_private_runtime_placeholder(tmp_path: Path) -> None:
    async def run() -> None:
        adapter = _adapter(tmp_path)
        await adapter.init_managed_runtime_baseline()

        document = json.loads((tmp_path / "managed-secrets.json").read_text(encoding="utf-8"))
        assert document["secrets"] == []
        assert document["runtime_secrets"][0]["purpose"] == "empty-placeholder"
        assert len(document["runtime_secrets"][0]["secret"]) == 32

    asyncio.run(run())


def test_listening_check_rejects_wrong_process(tmp_path: Path) -> None:
    async def run() -> None:
        adapter = _adapter(tmp_path, shell=_Shell(process_name="nginx"))
        adapter.apply_timeout_seconds = 0

        assert await adapter.check_mtproxy_listening() is False

    asyncio.run(run())


def test_listening_check_waits_for_listener_after_restart_without_rollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        systemctl = _SystemCtl()
        adapter = _adapter(tmp_path, systemctl)
        await _init_baseline(adapter, systemctl)
        shell = _SequencedListeningShell(
            [
                "LISTEN 0 4096 127.0.0.1:22 0.0.0.0:*",
                _ss_listener(),
            ]
        )
        adapter.shell = shell  # type: ignore[assignment]

        result = await adapter.apply_managed_secrets([_secret("b" * 32, access_id=2)])

        assert result.changed is True
        assert result.rollback_performed is False
        assert shell.calls == [("ss", "-tlnp"), ("ss", "-tlnp")]
        assert sleeps == [0.25]
        assert [call for call in systemctl.calls if call == ("restart", "mtproxy")] == [("restart", "mtproxy")]

    asyncio.run(run())


def test_listening_check_returns_false_when_listener_appears_after_deadline(tmp_path: Path) -> None:
    async def run() -> None:
        shell = _SequencedListeningShell(
            [
                "LISTEN 0 4096 127.0.0.1:22 0.0.0.0:*",
                _ss_listener(),
            ]
        )
        adapter = _adapter(tmp_path, shell=shell)  # type: ignore[arg-type]
        adapter.apply_timeout_seconds = 0

        assert await adapter.check_mtproxy_listening() is False
        assert shell.calls == [("ss", "-tlnp")]

    asyncio.run(run())


def test_listening_check_accepts_no_process_info_when_service_active(tmp_path: Path) -> None:
    async def run() -> None:
        adapter = _adapter(tmp_path, shell=_Shell(process_name=None))

        assert await adapter.check_mtproxy_listening() is True

    asyncio.run(run())
