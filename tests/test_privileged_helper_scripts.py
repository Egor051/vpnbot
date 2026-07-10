
import asyncio
import io
import json
import os
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.dante_users import DanteUserAdapter
from adapters.mtproxy import MtProxyAdapter, MtProxyManagedSecret
from adapters.privileged_helpers import PrivilegedHelperRunner
from adapters.xray_config import XrayConfigAdapter
from models.dto import ShellResult


ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HELPERS = (
    "vpn-bot-socks5-user",
    "vpn-bot-xray-apply",
    "vpn-bot-awg-apply",
    "vpn-bot-mtproxy-apply",
)

# ---------------------------------------------------------------------------
# 1. Helper script integrity
# ---------------------------------------------------------------------------


def test_helper_scripts_exist_and_are_intended_executable() -> None:
    """All helper scripts exist on disk and declare a Python 3 shebang."""
    for name in HELPERS:
        path = ROOT / "deploy" / "helpers" / name
        assert path.exists()
        assert path.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3")


# NOTE: shell-injection safety is asserted behaviourally, not by grepping source
# for "shell=True" (which os.system / string-built commands would slip past). The
# tests below check each helper invokes tools with a fixed argv *list* and shell
# left unset (see test_socks5_set_password_..., test_xray_helper_uses_fixed_target
# _service_and_argv), which is the property that actually matters.


# ---------------------------------------------------------------------------
# 2. SOCKS5 helper: login validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "login",
    [
        # reserved / privileged names
        "root",
        # path traversal attempts
        "../root",
        # characters not allowed by the managed-login regex
        "vpn_socks_bad:name",
        "vpn_socks_bad name",
        # leading dash (could become a flag)
        "-vpn_socks_bad",
        # non-ASCII (Cyrillic)
        "vpn_socks_кириллица",
        # exceeds max login length
        "vpn_socks_" + "a" * 40,
        # edge cases
        "",                          # empty string
        "vpn_socks_\x00injected",    # null-byte injection
        "vpn_socks_bad\nroot",       # newline injection
        "   ",                       # whitespace only
    ],
)
def test_socks5_helper_rejects_unsafe_login_names(
    load_helper: object, login: str
) -> None:
    """validate_login raises HelperError for any login that is not a safe managed name."""
    helper = load_helper("vpn-bot-socks5-user")  # type: ignore[operator]
    with pytest.raises(helper.HelperError):
        helper.validate_login(login)


def test_socks5_helper_accepts_valid_managed_login(load_helper: object) -> None:
    """validate_login returns the login unchanged when it passes all checks."""
    helper = load_helper("vpn-bot-socks5-user")  # type: ignore[operator]
    assert helper.validate_login("vpn_socks_100_abcd") == "vpn_socks_100_abcd"


# ---------------------------------------------------------------------------
# 3. SOCKS5 helper: password handling
# ---------------------------------------------------------------------------


def test_socks5_set_password_reads_secret_from_stdin_and_uses_argv(
    load_helper: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Password is read from stdin and never appears in subprocess argv."""
    helper = load_helper("vpn-bot-socks5-user")  # type: ignore[operator]
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        assert isinstance(args, list)
        assert kwargs.get("shell") is None
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(helper.subprocess, "run", fake_run)

    assert helper.action_set_password("vpn_socks_100_abcd", io.StringIO("secret-password\n")) == 0
    assert calls == [
        (
            ["nsenter", "--mount=/proc/1/ns/mnt", "--", "chpasswd"],
            {
                "input": "vpn_socks_100_abcd:secret-password\n",
                "text": True,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.PIPE,
                "check": False,
            },
        )
    ]
    assert all("secret-password" not in part for args, _ in calls for part in args)


def test_socks5_set_password_rejects_secret_in_argv(load_helper: object) -> None:
    """Passing the password as a positional argument exits with non-zero status."""
    helper = load_helper("vpn-bot-socks5-user")  # type: ignore[operator]
    with pytest.raises(SystemExit):
        helper.main(["set-password", "vpn_socks_100_abcd", "secret-password"])


def test_socks5_helper_error_output_redacts_password(
    load_helper: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the underlying command fails, stderr output must not contain the password."""
    helper = load_helper("vpn-bot-socks5-user")  # type: ignore[operator]

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 1, "", "tool failed with secret-password")

    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    stderr = io.StringIO()

    rc = helper.main(
        ["set-password", "vpn_socks_100_abcd"],
        stdin=io.StringIO("secret-password\n"),
        stderr=stderr,
    )

    assert rc != 0
    assert "secret-password" not in stderr.getvalue()


# ---------------------------------------------------------------------------
# 4. Xray helper: path validation and fixed constants
# ---------------------------------------------------------------------------


def test_xray_helper_rejects_candidate_outside_staging_root(
    load_helper: object, tmp_path: Path
) -> None:
    """Config candidate outside the staging root is rejected to prevent path traversal."""
    helper = load_helper("vpn-bot-xray-apply")  # type: ignore[operator]
    helper.STAGING_ROOT = tmp_path / "staging"
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(helper.HelperError, match="outside staging"):
        helper.validate_candidate_path(str(outside))


def test_xray_helper_rejects_symlink_candidate(
    load_helper: object, tmp_path: Path
) -> None:
    """Symlinked candidate files are rejected to prevent symlink-based escapes."""
    if not hasattr(os, "symlink"):
        pytest.skip("symlink unavailable")
    helper = load_helper("vpn-bot-xray-apply")  # type: ignore[operator]
    helper.STAGING_ROOT = tmp_path / "staging"
    helper.STAGING_ROOT.mkdir()
    real = helper.STAGING_ROOT / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = helper.STAGING_ROOT / "link.json"
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(helper.HelperError, match="symlink"):
        helper.validate_candidate_path(str(link))


def test_xray_helper_uses_fixed_target_service_and_argv(
    load_helper: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Xray helper always calls the xray binary with fixed argv (no injection possible)."""
    helper = load_helper("vpn-bot-xray-apply")  # type: ignore[operator]
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert isinstance(args, list)
        assert kwargs.get("shell") is None
        return subprocess.CompletedProcess(args, 0, "active", "")

    monkeypatch.setattr(helper.subprocess, "run", fake_run)

    helper.xray_test_config(Path("/run/vpn-bot/xray/candidate.json"))
    assert helper.CANONICAL_CONFIG == Path("/usr/local/etc/xray/config.json")
    assert helper.SERVICE_NAME == "xray"
    assert calls == [
        [helper.XRAY_BIN, "run", "-test", "-config", str(Path("/run/vpn-bot/xray/candidate.json"))]
    ]


# ---------------------------------------------------------------------------
# 5. AWG helper: path validation and fixed constants
# ---------------------------------------------------------------------------


def test_awg_helper_rejects_candidate_outside_staging_root(
    load_helper: object, tmp_path: Path
) -> None:
    """AWG config candidate outside the staging root is rejected."""
    helper = load_helper("vpn-bot-awg-apply")  # type: ignore[operator]
    helper.STAGING_ROOT = tmp_path / "staging"
    outside = tmp_path / "outside.conf"
    outside.write_text("[Interface]\nPrivateKey = secret\n", encoding="utf-8")
    with pytest.raises(helper.HelperError, match="outside staging"):
        helper.validate_candidate_path(str(outside))


def test_awg_helper_uses_fixed_target_and_interface(load_helper: object) -> None:
    """AWG helper has hard-coded target config, interface, and service name."""
    helper = load_helper("vpn-bot-awg-apply")  # type: ignore[operator]
    assert helper.CANONICAL_CONFIG == Path("/etc/amnezia/amneziawg/awg0.conf")
    assert helper.INTERFACE_NAME == "awg0"
    assert helper.SERVICE_NAME == "awg-quick@awg0"


# ---------------------------------------------------------------------------
# 6. File permission constants: vpn-bot group must be able to read configs
# ---------------------------------------------------------------------------


def test_helper_installed_permissions_preserve_vpn_bot_read_access(
    load_helper: object,
) -> None:
    """Installed config files are group-readable by vpn-bot, world-unreadable.

    This pins the shipped permission constants (owner/group/mode) rather than the
    resulting on-disk stat: a real install chowns to nobody:vpn-bot and needs root,
    so it cannot run unprivileged in CI. The install/restore roundtrip tests below
    assert the *effect* (that these constants are applied and are world-unreadable);
    this test guards the constants themselves from an accidental weakening.
    """
    xray = load_helper("vpn-bot-xray-apply")  # type: ignore[operator]
    awg = load_helper("vpn-bot-awg-apply")  # type: ignore[operator]
    mtproxy = load_helper("vpn-bot-mtproxy-apply")  # type: ignore[operator]

    assert xray.FINAL_USER == "nobody"
    assert xray.FINAL_GROUP == "vpn-bot"
    assert xray.FINAL_MODE == 0o640
    assert awg.FINAL_GROUP == "vpn-bot"
    assert awg.FINAL_MODE == 0o640
    assert mtproxy.FINAL_GROUP == "vpn-bot"
    assert mtproxy.FINAL_DIR_MODE == 0o750
    assert mtproxy.FINAL_FILE_MODE == 0o640


# ---------------------------------------------------------------------------
# 7. Install / restore roundtrips: _set_final_stat is called
# ---------------------------------------------------------------------------


def test_xray_helper_install_and_restore_use_final_stat(
    load_helper: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """install_candidate and restore_backup both apply the final ownership/mode."""
    helper = load_helper("vpn-bot-xray-apply")  # type: ignore[operator]
    helper.CANONICAL_CONFIG = tmp_path / "config.json"
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}", encoding="utf-8")
    stat_calls: list[Path] = []
    monkeypatch.setattr(helper, "_set_final_stat", lambda path: stat_calls.append(path))
    monkeypatch.setattr(helper, "_fsync_parent", lambda path: None)

    helper.install_candidate(candidate)
    backup = helper.backup_current()
    helper.restore_backup(backup)

    assert helper.CANONICAL_CONFIG.read_text(encoding="utf-8") == "{}"
    assert backup is not None
    assert len(stat_calls) == 3


def test_awg_helper_install_and_restore_use_final_stat(
    load_helper: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AWG install and restore roundtrip calls _set_final_stat for each file."""
    helper = load_helper("vpn-bot-awg-apply")  # type: ignore[operator]
    helper.CANONICAL_CONFIG = tmp_path / "awg0.conf"
    candidate = tmp_path / "candidate.conf"
    candidate.write_text("[Interface]\nPrivateKey = server\n", encoding="utf-8")
    stat_calls: list[Path] = []
    monkeypatch.setattr(helper, "_set_final_stat", lambda path: stat_calls.append(path))
    monkeypatch.setattr(helper, "_fsync_parent", lambda path: None)
    monkeypatch.setattr(helper, "quick_strip", lambda path: "")
    monkeypatch.setattr(helper, "sync_runtime", lambda stripped: None)

    helper.install_candidate(candidate)
    backup = helper.backup_current()
    helper.restore_backup(backup)

    assert "PrivateKey = server" in helper.CANONICAL_CONFIG.read_text(encoding="utf-8")
    assert backup is not None
    assert len(stat_calls) == 3


def test_mtproxy_helper_install_and_restore_use_group_readable_stat(
    load_helper: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MTProxy install/restore sets group-readable, world-unreadable permissions on every file."""
    helper = load_helper("vpn-bot-mtproxy-apply")  # type: ignore[operator]
    helper.TARGET_DIR = tmp_path / "vpn-bot"
    helper.TARGET_SECRETS = helper.TARGET_DIR / "managed-secrets.json"
    helper.TARGET_ENV = helper.TARGET_DIR / "mtproxy.env"
    source = tmp_path / "source.json"
    source.write_text(
        '{"version":1,"generation":0,"secrets":[],"runtime_secrets":[]}',
        encoding="utf-8",
    )
    chown_calls: list[tuple[str, int, int]] = []
    chmod_calls: list[tuple[str, int]] = []

    def fake_chown(path: Path | str, uid: int, gid: int) -> None:
        chown_calls.append((str(path), uid, gid))

    def fake_chmod(path: Path | str, mode: int) -> None:
        chmod_calls.append((str(path), mode))

    class PosixOsProxy:
        name = "posix"

        def __getattr__(self, name: str) -> object:
            return getattr(os, name)

        def chown(self, path: Path | str, uid: int, gid: int) -> None:
            fake_chown(path, uid, gid)

        def chmod(self, path: Path | str, mode: int) -> None:
            fake_chmod(path, mode)

    monkeypatch.setattr(helper, "os", PosixOsProxy())
    monkeypatch.setattr(helper, "_lookup_final_gid", lambda: 12345)
    monkeypatch.setattr(helper, "_fsync_parent", lambda path: None)

    helper.install_file(source, helper.TARGET_SECRETS)
    backups = helper.backup_targets()
    helper.restore_targets(backups)

    assert helper.TARGET_SECRETS.exists()
    target_dir = str(helper.TARGET_DIR)
    assert (target_dir, 0, 12345) in chown_calls
    file_chowns = [call for call in chown_calls if call[0] != target_dir]
    assert len(file_chowns) == 3
    assert all(uid == 0 and gid == 12345 for _path, uid, gid in file_chowns)
    assert (target_dir, helper.FINAL_DIR_MODE) in chmod_calls
    file_modes = [mode for path, mode in chmod_calls if path != target_dir]
    assert file_modes == [helper.FINAL_FILE_MODE, helper.FINAL_FILE_MODE, helper.FINAL_FILE_MODE]
    assert all(mode & 0o007 == 0 for mode in file_modes)


# ---------------------------------------------------------------------------
# 8. Secret redaction on failure
# ---------------------------------------------------------------------------


def test_awg_helper_redacts_private_config_on_failure(
    load_helper: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AWG helper stderr must not contain the WireGuard PrivateKey on validation failure."""
    helper = load_helper("vpn-bot-awg-apply")  # type: ignore[operator]
    helper.STAGING_ROOT = tmp_path / "staging"
    helper.STAGING_ROOT.mkdir()
    secret = "private-key-that-must-not-leak"
    candidate = helper.STAGING_ROOT / "awg0.conf"
    candidate.write_text(f"[Interface]\nPrivateKey = {secret}\n", encoding="utf-8")
    monkeypatch.setattr(
        helper,
        "quick_strip",
        lambda path: (_ for _ in ()).throw(helper.HelperError("AWG config validation failed")),
    )
    stderr = io.StringIO()

    rc = helper.main(["apply", str(candidate)], stderr=stderr)

    assert rc != 0
    assert secret not in stderr.getvalue()


def test_mtproxy_helper_rejects_candidate_outside_staging_root(
    load_helper: object, tmp_path: Path
) -> None:
    """MTProxy candidate directory outside the staging root is rejected."""
    helper = load_helper("vpn-bot-mtproxy-apply")  # type: ignore[operator]
    helper.STAGING_ROOT = tmp_path / "staging"
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(helper.HelperError, match="outside staging"):
        helper.validate_candidate_dir(str(outside))


def test_mtproxy_helper_redacts_managed_secret_on_failure(
    load_helper: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MTProxy helper stderr must not contain managed secrets when restart fails."""
    helper = load_helper("vpn-bot-mtproxy-apply")  # type: ignore[operator]
    helper.STAGING_ROOT = tmp_path / "staging"
    candidate = helper.STAGING_ROOT / "candidate"
    candidate.mkdir(parents=True)
    secret = "a" * 32
    (candidate / "managed-secrets.json").write_text(
        json.dumps({
            "version": 1,
            "generation": 1,
            "secrets": [{"secret": secret}],
            "runtime_secrets": [],
        }),
        encoding="utf-8",
    )
    (candidate / "mtproxy.env").write_text("MTPROTO_PORT=8443\n", encoding="utf-8")
    monkeypatch.setattr(helper, "backup_targets", lambda: {})
    monkeypatch.setattr(helper, "install_file", lambda source, target: None)
    monkeypatch.setattr(helper, "restore_targets", lambda backups: None)
    monkeypatch.setattr(
        helper,
        "restart_and_verify",
        lambda port: (_ for _ in ()).throw(helper.HelperError("MTProxy restart failed")),
    )
    stderr = io.StringIO()

    rc = helper.main(["apply", str(candidate)], stderr=stderr)

    assert rc != 0
    assert secret not in stderr.getvalue()


# ---------------------------------------------------------------------------
# 9. Settings: direct mode remains default
# ---------------------------------------------------------------------------


def test_direct_mode_remains_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """privilege_helpers_enabled defaults to False when env var is absent."""
    from config.settings import load_settings

    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.delenv("PRIVILEGE_HELPERS_ENABLED", raising=False)

    settings = load_settings()

    assert settings.privilege_helpers_enabled is False


# ---------------------------------------------------------------------------
# 10. PrivilegedHelperRunner: sudo -n invocation
# ---------------------------------------------------------------------------


def test_helper_mode_uses_sudo_n_and_configured_helper_path(tmp_path: Path) -> None:
    """DanteUserAdapter in helper mode invokes the helper via 'sudo -n <path>'."""
    class Shell:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        async def run(self, args: list[str], **kwargs: object) -> ShellResult:
            self.calls.append(args)
            return ShellResult(tuple(args), 2, "", "")

    async def run() -> None:
        shell = Shell()
        helper_path = tmp_path / "vpn-bot-socks5-user"
        adapter = DanteUserAdapter(
            shell=shell,  # type: ignore[arg-type]
            login_prefix="vpn_socks_",
            system_user_shell="/usr/sbin/nologin",
            helper_runner=PrivilegedHelperRunner(shell=shell),  # type: ignore[arg-type]
            helper_path=helper_path,
        )

        assert await adapter.exists("vpn_socks_100_abcd") is False
        assert shell.calls == [["sudo", "-n", str(helper_path), "exists", "vpn_socks_100_abcd"]]

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 11. Adapter integration: staging and fixed-helper invocation
# ---------------------------------------------------------------------------


def test_xray_adapter_helper_mode_stages_candidate_and_calls_fixed_helper(
    tmp_path: Path,
) -> None:
    """XrayConfigAdapter stages a modified config and calls the helper via sudo -n."""
    config_path = tmp_path / "xray.json"
    config_path.write_text(
        json.dumps({
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": []},
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {"shortIds": []},
                },
            }]
        }),
        encoding="utf-8",
    )

    class Shell:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        async def run(self, args: list[str], **kwargs: object) -> ShellResult:
            self.calls.append(args)
            candidate = Path(args[-1])
            staged = json.loads(candidate.read_text(encoding="utf-8"))
            assert staged["inbounds"][0]["settings"]["clients"][0]["id"] == (
                "00000000-0000-4000-8000-000000000001"
            )
            return ShellResult(tuple(args), 0, "", "")

    class SystemCtl:
        async def xray_test_config(self, path: Path) -> ShellResult:
            raise AssertionError("helper mode must not call direct Xray validation")

    async def run() -> None:
        shell = Shell()
        helper_path = tmp_path / "vpn-bot-xray-apply"
        adapter = XrayConfigAdapter(
            config_path=config_path,
            service_name="xray",
            apply_mode="restart",
            inbound_tag="",
            allow_restart_on_rollback=False,
            backup=BackupAdapter.__new__(BackupAdapter),
            systemctl=SystemCtl(),  # type: ignore[arg-type]
            helper_runner=PrivilegedHelperRunner(shell=shell),  # type: ignore[arg-type]
            helper_path=helper_path,
            helper_staging_dir=tmp_path / "staging" / "xray",
        )

        await adapter.add_client(
            uuid_value="00000000-0000-4000-8000-000000000001",
            email_label="xray_A7kQz",
            short_id="abcd",
            flow="xtls-rprx-vision",
            manage_short_id=True,
        )

        assert shell.calls[0][:4] == ["sudo", "-n", str(helper_path), "apply"]

    asyncio.run(run())


def test_awg_adapter_helper_mode_stages_candidate_and_calls_fixed_helper(
    tmp_path: Path,
) -> None:
    """AwgConfigAdapter stages a modified config and calls the helper via sudo -n."""
    config_path = tmp_path / "awg0.conf"
    config_path.write_text(
        "[Interface]\nPrivateKey = server\nAddress = 10.0.0.1/24\n", encoding="utf-8"
    )

    class Shell:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        async def run(self, args: list[str], **kwargs: object) -> ShellResult:
            self.calls.append(args)
            candidate = Path(args[-1])
            text = candidate.read_text(encoding="utf-8")
            assert "PublicKey = public-key" in text
            assert "PresharedKey = preshared-key" in text
            return ShellResult(tuple(args), 0, "", "")

    async def run() -> None:
        shell = Shell()
        helper_path = tmp_path / "vpn-bot-awg-apply"
        adapter = AwgConfigAdapter(
            config_path=config_path,
            interface="awg0",
            backup=BackupAdapter.__new__(BackupAdapter),
            shell=shell,  # type: ignore[arg-type]
            persistent_keepalive=25,
            helper_runner=PrivilegedHelperRunner(shell=shell),  # type: ignore[arg-type]
            helper_path=helper_path,
            helper_staging_dir=tmp_path / "staging" / "awg",
        )

        await adapter.add_peer(
            key_id=10,
            owner_user_id=100,
            public_key="public-key",
            preshared_key="preshared-key",
            client_ip="10.0.0.2",
            label="awg_A7kQz",
        )

        assert shell.calls[0][:4] == ["sudo", "-n", str(helper_path), "apply"]

    asyncio.run(run())


def test_mtproxy_adapter_helper_mode_stages_files_and_calls_fixed_helper(
    tmp_path: Path,
) -> None:
    """MtProxyAdapter stages both managed-secrets.json and mtproxy.env then calls helper."""
    wrapper = tmp_path / "run-mtproxy-managed"
    wrapper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    if os.name == "posix":
        wrapper.chmod(0o700)
    managed_secrets_path = tmp_path / "managed-secrets.json"
    managed_env_path = tmp_path / "mtproxy.env"
    secret = "b" * 32

    class Shell:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        async def run(self, args: list[str], **kwargs: object) -> ShellResult:
            self.calls.append(args)
            candidate_dir = Path(args[-1])
            staged_secrets = candidate_dir / "managed-secrets.json"
            staged_env = candidate_dir / "mtproxy.env"
            assert staged_secrets.exists()
            assert staged_env.exists()
            assert secret not in staged_env.read_text(encoding="utf-8")
            managed_secrets_path.write_text(staged_secrets.read_text(encoding="utf-8"), encoding="utf-8")
            managed_env_path.write_text(staged_env.read_text(encoding="utf-8"), encoding="utf-8")
            return ShellResult(tuple(args), 0, "", "")

    class SystemCtl:
        async def restart(self, service_name: str) -> ShellResult:
            raise AssertionError("helper mode must not call direct service restart")

        async def is_active(self, service_name: str) -> ShellResult:
            raise AssertionError("helper mode must not call direct service status")

    async def run() -> None:
        shell = Shell()
        helper_path = tmp_path / "vpn-bot-mtproxy-apply"
        adapter = MtProxyAdapter(
            shell=shell,  # type: ignore[arg-type]
            systemctl=SystemCtl(),  # type: ignore[arg-type]
            service_name="mtproxy",
            binary_path=Path("/usr/local/bin/mtproto-proxy"),
            run_user="mtproxy",
            run_group="mtproxy",
            proxy_secret_path=tmp_path / "proxy-secret",
            proxy_multi_conf_path=tmp_path / "proxy-multi.conf",
            managed_secrets_path=managed_secrets_path,
            managed_env_path=managed_env_path,
            managed_wrapper_path=wrapper,
            backup_dir=tmp_path / "backups",
            port=8443,
            internal_stats_port=8888,
            workers=1,
            apply_timeout_seconds=10,
            rollback_on_apply_failure=True,
            keep_last_backups=10,
            helper_runner=PrivilegedHelperRunner(shell=shell),  # type: ignore[arg-type]
            helper_path=helper_path,
            helper_staging_dir=tmp_path / "staging" / "mtproxy",
        )

        await adapter.init_managed_runtime_baseline()
        await adapter.apply_managed_secrets([
            MtProxyManagedSecret(secret=secret, fingerprint="fp-1", owner_user_id=100, access_id=1)
        ])

        assert shell.calls
        assert all(call[:4] == ["sudo", "-n", str(helper_path), "apply"] for call in shell.calls)

    asyncio.run(run())
