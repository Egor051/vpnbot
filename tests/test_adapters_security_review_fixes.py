
import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.backup import BackupAdapter
from adapters.clock import ClockProvider
from adapters.errors import AwgConfigError, MtProxyError, MtProxyRollbackError, XrayConfigError
from adapters.hysteria_auth_health import Hysteria2AuthHealthProbe
from adapters.hysteria_stats import HysteriaStatsAdapter, HysteriaStatsUnavailable
from adapters.mtproxy import MtProxyAdapter
from adapters.shell_runner import ShellRunner
from adapters.validation import reject_option_like, validate_ip, validate_wireguard_key
from adapters.xray_config import XrayConfigAdapter


# --- adapters.validation -----------------------------------------------------


@pytest.mark.parametrize("bad", ["", "-flag", "with space", "line\nbreak", "\ttab"])
def test_reject_option_like_rejects(bad: str) -> None:
    with pytest.raises(ValueError):
        reject_option_like(bad, "field")


def test_reject_option_like_passes_and_returns() -> None:
    assert reject_option_like("awg0", "field") == "awg0"


def test_reject_option_like_uses_custom_error() -> None:
    with pytest.raises(XrayConfigError):
        reject_option_like("-x", "svc", error=XrayConfigError)


@pytest.mark.parametrize("bad", ["", "-abc", "key with space", "key\nline", "ctrl\x01char"])
def test_validate_wireguard_key_rejects(bad: str) -> None:
    with pytest.raises(AwgConfigError):
        validate_wireguard_key(bad, "AWG public_key", error=AwgConfigError)


def test_validate_wireguard_key_accepts_real_and_placeholder_keys() -> None:
    real = "QD03d1s8b0i8Ux1s5Zr6oQwqk3wV2mJt0bJb8m1a2c="  # base64-ish, 44 chars
    assert validate_wireguard_key(real, "k") == real
    # Readable placeholders used across the test-suite must still pass.
    assert validate_wireguard_key("public-managed-orphan", "k") == "public-managed-orphan"


@pytest.mark.parametrize("bad", ["", "not-an-ip", "10.0.0.5/32", "999.1.1.1"])
def test_validate_ip_rejects(bad: str) -> None:
    with pytest.raises(AwgConfigError):
        validate_ip(bad, "AWG client_ip", error=AwgConfigError)


def test_validate_ip_accepts_v4_and_v6() -> None:
    assert validate_ip("10.0.0.2", "ip") == "10.0.0.2"
    assert validate_ip("fd00::2", "ip") == "fd00::2"


# --- shell_runner: returned args are redacted (P3-002) -----------------------


def test_shell_result_args_are_redacted() -> None:
    runner = ShellRunner()
    result = asyncio.run(runner.run(["echo", "TOPSECRET"], sensitive_values=["TOPSECRET"]))
    assert "TOPSECRET" not in " ".join(result.args)
    assert result.args == ("echo", "***")
    # stdout is documented as verbatim (some callers consume generated keys).
    assert "TOPSECRET" in result.stdout


# --- awg_config --------------------------------------------------------------


def _awg_adapter(tmp_path: Path, *, interface: str = "awg0") -> AwgConfigAdapter:
    config_path = tmp_path / "awg0.conf"
    config_path.write_text("[Interface]\nPrivateKey = x\nAddress = 10.0.0.1/24\n", encoding="utf-8")
    return AwgConfigAdapter(
        config_path=config_path,
        interface=interface,
        backup=BackupAdapter(ClockProvider()),
        shell=ShellRunner(),
        persistent_keepalive=25,
    )


def test_awg_constructor_rejects_option_like_interface(tmp_path: Path) -> None:
    with pytest.raises(AwgConfigError):
        _awg_adapter(tmp_path, interface="-x")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"public_key": "abc\ndef", "preshared_key": None, "client_ip": "10.0.0.2"},
        {"public_key": "good", "preshared_key": "psk\nINJECT", "client_ip": "10.0.0.2"},
        {"public_key": "good", "preshared_key": None, "client_ip": "not-an-ip"},
    ],
)
def test_awg_add_peer_validates_inputs(tmp_path: Path, kwargs: dict[str, object]) -> None:
    adapter = _awg_adapter(tmp_path)
    with pytest.raises(AwgConfigError):
        asyncio.run(adapter.add_peer(key_id=1, owner_user_id=1, label=None, **kwargs))  # type: ignore[arg-type]


def test_awg_parse_transfer_skips_malformed_lines() -> None:
    text = "\n".join([
        "pubkeyA 100 200",
        "garbage line here",
        "pubkeyB notanumber 5",
        "pubkeyC 7 8",
    ])
    parsed = AwgConfigAdapter.parse_transfer_output(text, source="awg")
    assert parsed == {"pubkeyA": (100, 200), "pubkeyC": (7, 8)}


# --- xray_config: constructor identifier validation (P3-004) ------------------


def _xray_kwargs(config_path: Path) -> dict[str, object]:
    config_path.write_text("{}", encoding="utf-8")
    return dict(
        config_path=config_path,
        apply_mode="reload",
        allow_restart_on_rollback=False,
        backup=SimpleNamespace(),
        systemctl=SimpleNamespace(),
    )


def test_xray_constructor_rejects_option_like_service(tmp_path: Path) -> None:
    with pytest.raises(XrayConfigError):
        XrayConfigAdapter(service_name="-bad", inbound_tag="vless-in", **_xray_kwargs(tmp_path / "c.json"))  # type: ignore[arg-type]


def test_xray_constructor_rejects_option_like_inbound_tag(tmp_path: Path) -> None:
    with pytest.raises(XrayConfigError):
        XrayConfigAdapter(service_name="xray", inbound_tag="-bad", **_xray_kwargs(tmp_path / "c.json"))  # type: ignore[arg-type]


# --- hysteria base-url building (P3-016) -------------------------------------


def test_hysteria_stats_build_base_url_empty_host_is_loopback() -> None:
    assert HysteriaStatsAdapter(listen=":9999", secret="s")._base_url == "http://127.0.0.1:9999"


def test_hysteria_stats_build_base_url_ipv6_bracketed() -> None:
    assert HysteriaStatsAdapter(listen="[::1]:9999", secret="s")._base_url == "http://[::1]:9999"


@pytest.mark.parametrize("listen", ["127.0.0.1:", "9999", "127.0.0.1:notaport"])
def test_hysteria_stats_build_base_url_rejects_bad(listen: str) -> None:
    with pytest.raises(HysteriaStatsUnavailable):
        HysteriaStatsAdapter(listen=listen, secret="s")


def test_hysteria_auth_probe_empty_host_is_loopback() -> None:
    assert Hysteria2AuthHealthProbe(auth_listen=":8444")._url == "http://127.0.0.1:8444/healthz"


@pytest.mark.parametrize("listen", ["127.0.0.1:", "8444"])
def test_hysteria_auth_probe_rejects_bad(listen: str) -> None:
    with pytest.raises(ValueError):
        Hysteria2AuthHealthProbe(auth_listen=listen)


# --- mtproxy -----------------------------------------------------------------


def _mtproxy_adapter(tmp_path: Path) -> MtProxyAdapter:
    wrapper = tmp_path / "run-mtproxy-managed"
    wrapper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
    if os.name == "posix":
        wrapper.chmod(0o700)
    return MtProxyAdapter(
        shell=SimpleNamespace(),  # type: ignore[arg-type]
        systemctl=SimpleNamespace(),  # type: ignore[arg-type]
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


def test_mtproxy_constructor_rejects_option_like_service(tmp_path: Path) -> None:
    adapter = _mtproxy_adapter(tmp_path)
    assert adapter.service_name == "mtproxy"
    with pytest.raises(MtProxyError):
        MtProxyAdapter(
            shell=SimpleNamespace(),  # type: ignore[arg-type]
            systemctl=SimpleNamespace(),  # type: ignore[arg-type]
            service_name="-bad",
            binary_path=Path("/usr/local/bin/mtproto-proxy"),
            run_user="mtproxy",
            run_group="mtproxy",
            proxy_secret_path=tmp_path / "proxy-secret",
            proxy_multi_conf_path=tmp_path / "proxy-multi.conf",
            managed_secrets_path=tmp_path / "managed-secrets.json",
            managed_env_path=tmp_path / "mtproxy.env",
            port=8443,
            internal_stats_port=8888,
            workers=1,
            apply_timeout_seconds=10,
            rollback_on_apply_failure=True,
            keep_last_backups=10,
        )


def test_mtproxy_env_content_rejects_control_chars(tmp_path: Path) -> None:
    adapter = _mtproxy_adapter(tmp_path)
    adapter.run_user = "mtproxy\nINJECT=1"
    with pytest.raises(MtProxyError):
        adapter._env_content()


def test_mtproxy_restore_backup_rejects_target_outside_managed_set(tmp_path: Path) -> None:
    adapter = _mtproxy_adapter(tmp_path)
    backup_dir = tmp_path / "backups" / "b1"
    backup_dir.mkdir(parents=True)
    stray_backup = backup_dir / "passwd"
    stray_backup.write_text("x", encoding="utf-8")
    manifest = {"version": 1, "files": [{"target": "/etc/passwd", "backup": str(stray_backup)}]}
    (backup_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(MtProxyRollbackError, match="outside the managed set"):
        adapter.restore_backup("b1")


def test_mtproxy_restore_backup_rejects_symlink_target(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("symlink semantics are POSIX-only")
    adapter = _mtproxy_adapter(tmp_path)
    # Managed target is a symlink pointing elsewhere -> restore must refuse to write through it.
    outside = tmp_path / "outside.json"
    outside.write_text("original", encoding="utf-8")
    adapter.managed_secrets_path.symlink_to(outside)
    backup_dir = tmp_path / "backups" / "b2"
    backup_dir.mkdir(parents=True)
    backup_file = backup_dir / "managed-secrets.json"
    backup_file.write_text("restored", encoding="utf-8")
    manifest = {"version": 1, "files": [{"target": str(adapter.managed_secrets_path), "backup": str(backup_file)}]}
    (backup_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(MtProxyRollbackError, match="must not be a symlink"):
        adapter.restore_backup("b2")
    assert outside.read_text(encoding="utf-8") == "original"
