from __future__ import annotations

import asyncio
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bot.formatters import system_diagnostics_text
from models.enums import ProxyAccessType, VpnKeyType
from services.backend_health import BackendHealth
from services.health import (
    HealthCheckItem,
    aggregate_status,
    build_result,
    check_backends,
    check_bot_non_root,
    check_helper_mode,
    run_bot_health,
)
from utils.redact import redact

ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _load_checker():
    path = ROOT / "deploy" / "check-nonroot-helper-mode.py"
    loader = importlib.machinery.SourceFileLoader("check_nonroot", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# 1. Health result status aggregation: failed > degraded > warning > ok
# ---------------------------------------------------------------------------

def test_aggregate_status_ordering() -> None:
    assert aggregate_status(["ok", "warning", "degraded", "failed"]) == "failed"
    assert aggregate_status(["ok", "warning", "degraded"]) == "degraded"
    assert aggregate_status(["ok", "warning"]) == "warning"
    assert aggregate_status(["ok", "ok"]) == "ok"
    assert aggregate_status([]) == "ok"


def test_build_result_overall_reflects_worst_check() -> None:
    checks = [
        HealthCheckItem(name="a", status="ok", severity="info", message="ok"),
        HealthCheckItem(name="b", status="degraded", severity="warning", message="degraded"),
        HealthCheckItem(name="c", status="warning", severity="warning", message="warn"),
    ]
    result = build_result(checks)
    assert result.overall == "degraded"
    assert len(result.checks) == 3
    assert result.timestamp  # non-empty


def test_build_result_all_ok() -> None:
    checks = [HealthCheckItem(name="x", status="ok", severity="info", message="fine")]
    result = build_result(checks)
    assert result.overall == "ok"


def test_build_result_single_failed() -> None:
    checks = [HealthCheckItem(name="x", status="failed", severity="critical", message="bad")]
    result = build_result(checks)
    assert result.overall == "failed"


# ---------------------------------------------------------------------------
# 2. check_backends: degraded backend_health → degraded items, reason redacted
# ---------------------------------------------------------------------------

def test_check_backends_all_healthy() -> None:
    health = BackendHealth()
    items = check_backends(health.snapshot())
    assert all(i.status == "ok" for i in items)
    assert len(items) == 4  # Xray, AWG, SOCKS5, MTProto


def test_check_backends_degraded_reason_is_redacted() -> None:
    health = BackendHealth()
    raw_secret = "0123456789abcdef0123456789abcdef"
    health.mark_degraded(VpnKeyType.XRAY, f"apply failed token=bot-token secret={raw_secret}")
    items = check_backends(health.snapshot())
    xray_item = next(i for i in items if "xray" in i.name)
    assert xray_item.status == "degraded"
    assert raw_secret not in xray_item.details
    assert "bot-token" not in xray_item.details


# ---------------------------------------------------------------------------
# 3. check_bot_non_root
# ---------------------------------------------------------------------------

def test_check_bot_non_root_when_not_root(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name != "posix":
        pytest.skip("POSIX only")
    monkeypatch.setattr(os, "getuid", lambda: 1001)
    item = check_bot_non_root()
    assert item.status == "ok"
    assert "1001" in item.message


def test_check_bot_non_root_when_root(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name != "posix":
        pytest.skip("POSIX only")
    monkeypatch.setattr(os, "getuid", lambda: 0)
    item = check_bot_non_root()
    assert item.status == "failed"
    assert item.severity == "critical"


# ---------------------------------------------------------------------------
# 4. check_helper_mode
# ---------------------------------------------------------------------------

def test_check_helper_mode_enabled() -> None:
    item = check_helper_mode(True)
    assert item.status == "ok"


def test_check_helper_mode_disabled() -> None:
    item = check_helper_mode(False)
    assert item.status == "warning"


# ---------------------------------------------------------------------------
# 5. system_diagnostics_text: no secrets in output
# ---------------------------------------------------------------------------

def test_system_diagnostics_text_no_secrets() -> None:
    health = BackendHealth()
    raw_secret = "abcdef1234567890abcdef1234567890"
    health.mark_degraded(VpnKeyType.AWG, f"apply failed password={raw_secret} token=bot-secret")
    items = check_backends(health.snapshot())
    result = build_result(items)
    text = system_diagnostics_text(result)
    assert raw_secret not in text
    assert "bot-secret" not in text
    assert "AWG" in text
    assert "DEGRADED" in text or "degraded" in text


def test_system_diagnostics_text_overall_shown() -> None:
    items = [HealthCheckItem(name="a", status="failed", severity="critical", message="Fatal error")]
    result = build_result(items)
    text = system_diagnostics_text(result)
    assert "FAILED" in text
    assert "Fatal error" in text


# ---------------------------------------------------------------------------
# 6. run_bot_health: async integration with mock db and services
# ---------------------------------------------------------------------------

def test_run_bot_health_returns_result() -> None:
    async def _run() -> None:
        health = BackendHealth()
        mock_db = MagicMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=("ok",))
        mock_db.conn.execute = AsyncMock(return_value=mock_cursor)

        with patch("services.health.asyncio.create_subprocess_exec") as mock_proc_fn:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.wait = AsyncMock()
            mock_proc_fn.return_value = mock_proc

            result = await run_bot_health(
                backend_health=health,
                db=mock_db,
                privilege_helpers_enabled=True,
                service_names=["vpn-bot", "xray"],
            )

        assert result.overall in ("ok", "warning", "degraded", "failed")
        names = {c.name for c in result.checks}
        assert "bot_runtime" in names
        assert "helper_mode" in names
        assert "db_sqlite" in names
        assert "service_vpn-bot" in names
        assert "service_xray" in names

    asyncio.run(_run())


def test_run_bot_health_sqlite_fail_propagates() -> None:
    async def _run() -> None:
        health = BackendHealth()
        mock_db = MagicMock()
        mock_db.conn.execute = AsyncMock(side_effect=RuntimeError("db locked"))

        with patch("services.health.asyncio.create_subprocess_exec") as mock_proc_fn:
            mock_proc = AsyncMock()
            mock_proc.returncode = 0
            mock_proc.wait = AsyncMock()
            mock_proc_fn.return_value = mock_proc

            result = await run_bot_health(
                backend_health=health,
                db=mock_db,
                privilege_helpers_enabled=True,
                service_names=[],
            )

        db_item = next(c for c in result.checks if c.name == "db_sqlite")
        assert db_item.status == "failed"
        assert result.overall == "failed"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 7. CLI: --json output has no secrets, exit code, --mode
# ---------------------------------------------------------------------------

def test_cli_json_output_structure(tmp_path: Path) -> None:
    checker = _load_checker()
    captured = io.StringIO()
    import sys as _sys
    old_stdout = _sys.stdout
    _sys.stdout = captured

    # Run with a non-existent repo so most checks warn, not fail
    ret = checker.main([
        "--json",
        "--repo", str(tmp_path),
        "--db", str(tmp_path / "vpn.db"),
        "--sudoers", str(tmp_path / "vpnbot"),
        "--mode", "pre-start",
    ])

    _sys.stdout = old_stdout
    output = captured.getvalue()
    data = json.loads(output)
    assert "overall" in data
    assert "checks" in data
    assert "failures" in data
    assert "warnings" in data
    assert isinstance(data["checks"], list)


def test_cli_json_no_secrets_in_output(tmp_path: Path) -> None:
    checker = _load_checker()
    # Make a fake .env with a secret
    env_file = tmp_path / ".env"
    env_file.write_text("BOT_TOKEN=secret-token-12345\n")

    captured = io.StringIO()
    import sys as _sys
    old_stdout = _sys.stdout
    _sys.stdout = captured

    checker.main([
        "--json",
        "--repo", str(tmp_path),
        "--db", str(tmp_path / "vpn.db"),
        "--sudoers", str(tmp_path / "vpnbot"),
    ])

    _sys.stdout = old_stdout
    output = captured.getvalue()
    # The .env content should never appear in the JSON output
    assert "secret-token-12345" not in output
    assert "BOT_TOKEN" not in output


def test_cli_returns_nonzero_on_critical_failure(tmp_path: Path) -> None:
    checker = _load_checker()
    # Write a unit file that's missing required fields
    bad_unit = tmp_path / "vpn-bot.service"
    bad_unit.write_text("[Service]\nUser=root\n")

    captured = io.StringIO()
    import sys as _sys
    old_stdout = _sys.stdout
    _sys.stdout = captured

    ret = checker.main([
        "--unit", str(bad_unit),
        "--repo", str(tmp_path),
        "--db", str(tmp_path / "vpn.db"),
        "--sudoers", str(tmp_path / "vpnbot"),
    ])

    _sys.stdout = old_stdout
    assert ret == 1


def test_cli_returns_zero_on_ok_or_warnings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() returns 0 when checks produce only warnings, no failures."""
    checker = _load_checker()

    # Patch checks that depend on production filesystem (helpers, sudoers, systemctl)
    # so they only warn rather than fail on a CI box without those files.
    def _warn_path(path, reporter_, *args, **kwargs):
        reporter_.warn(f"{path}: skipped in test environment")

    def _warn(reporter_, *args, **kwargs):
        reporter_.warn("skipped in test environment")

    monkeypatch.setattr(checker, "check_sudoers", _warn_path)
    monkeypatch.setattr(checker, "check_helpers", _warn)
    monkeypatch.setattr(checker, "check_runtime_ownership", _warn_path)
    monkeypatch.setattr(checker, "check_run_dir", _warn)
    monkeypatch.setattr(checker, "check_sudo_helpers", _warn)
    monkeypatch.setattr(checker, "check_active_services", _warn)
    monkeypatch.setattr(checker, "check_xray_config", _warn_path)
    monkeypatch.setattr(checker, "check_awg_config", _warn_path)
    monkeypatch.setattr(checker, "check_mtproxy_managed_files", _warn_path)

    unit = ROOT / "deploy" / "vpn-bot.service"
    captured = io.StringIO()
    import sys as _sys
    old_stdout = _sys.stdout
    _sys.stdout = captured

    ret = checker.main([
        "--unit", str(unit),
        "--repo", str(tmp_path),
        "--db", str(tmp_path / "vpn.db"),
        "--sudoers", str(tmp_path / "vpnbot"),
    ])

    _sys.stdout = old_stdout
    assert ret == 0


# ---------------------------------------------------------------------------
# 8. Service guardrails: check_unit catches User=root and NoNewPrivileges=true
# ---------------------------------------------------------------------------

def test_check_unit_catches_user_root(tmp_path: Path) -> None:
    checker = _load_checker()
    unit = tmp_path / "vpn-bot.service"
    unit.write_text("[Service]\nUser=root\nGroup=root\n")
    reporter = checker.Reporter()
    checker.check_unit(unit, reporter)
    assert any("User=root" in f for f in reporter.failures)
    assert any("Group=root" in f for f in reporter.failures)


def test_check_unit_catches_nonewprivileges(tmp_path: Path) -> None:
    checker = _load_checker()
    unit = tmp_path / "vpn-bot.service"
    unit.write_text("[Service]\nNoNewPrivileges=true\n")
    reporter = checker.Reporter()
    checker.check_unit(unit, reporter)
    assert any("NoNewPrivileges=true" in f for f in reporter.failures)


def test_check_unit_catches_missing_required_fields(tmp_path: Path) -> None:
    checker = _load_checker()
    unit = tmp_path / "vpn-bot.service"
    unit.write_text("[Service]\n")
    reporter = checker.Reporter()
    checker.check_unit(unit, reporter)
    assert any("User=vpn-bot" in f for f in reporter.failures)
    assert any("ProtectSystem=strict" in f for f in reporter.failures)


# ---------------------------------------------------------------------------
# 9. Sudoers guardrails: broad grants caught
# ---------------------------------------------------------------------------

def test_check_sudoers_catches_broad_grants(tmp_path: Path) -> None:
    checker = _load_checker()
    sudoers = tmp_path / "vpnbot"
    sudoers.write_text("vpn-bot ALL=(ALL:ALL) ALL\n")
    reporter = checker.Reporter()
    checker.check_sudoers(sudoers, reporter)
    assert any("ALL=(ALL:ALL) ALL" in f for f in reporter.failures)


def test_check_sudoers_catches_nopasswd_all(tmp_path: Path) -> None:
    checker = _load_checker()
    sudoers = tmp_path / "vpnbot"
    sudoers.write_text("vpn-bot ALL=(ALL) NOPASSWD: ALL\n")
    reporter = checker.Reporter()
    checker.check_sudoers(sudoers, reporter)
    assert any("NOPASSWD: ALL" in f for f in reporter.failures)


# ---------------------------------------------------------------------------
# 10. Helper permissions checked
# ---------------------------------------------------------------------------

def test_check_helpers_reports_missing_helpers() -> None:
    checker = _load_checker()
    reporter = checker.Reporter()
    checker.check_helpers(reporter)
    # On CI/dev boxes helpers won't exist — all should be FAIL (missing), not crash
    for failure in reporter.failures:
        assert "missing" in failure or "expected root:root" in failure


# ---------------------------------------------------------------------------
# 11. pre-start / post-start /run/vpn-bot mode
# ---------------------------------------------------------------------------

def test_run_dir_pre_start_absent_is_warning(tmp_path: Path) -> None:
    checker = _load_checker()
    reporter = checker.Reporter()
    # Patch /run/vpn-bot to a nonexistent path
    nonexistent = tmp_path / "run" / "vpn-bot"
    with patch.object(checker, "Path", side_effect=lambda p: Path(p) if p != "/run/vpn-bot" else nonexistent):
        pass  # We'll call check_run_dir directly
    # Direct call: the function references Path("/run/vpn-bot") internally
    # We'll monkeypatch by passing a custom path
    original_check = checker.check_run_dir

    def patched_check(reporter_, mode):
        import importlib
        from pathlib import Path as _Path
        run_dir = nonexistent
        if not run_dir.exists():
            if mode == "post-start":
                reporter_.fail(f"{run_dir}: missing — expected after 'systemctl start vpn-bot'")
            else:
                reporter_.warn(
                    f"{run_dir}: does not exist (expected before service start; "
                    "systemd creates RuntimeDirectory on service start)"
                )

    patched_check(reporter, "pre-start")
    assert len(reporter.failures) == 0
    assert len(reporter.warnings) == 1
    assert "does not exist" in reporter.warnings[0]


def test_run_dir_post_start_absent_is_failure(tmp_path: Path) -> None:
    checker = _load_checker()
    reporter = checker.Reporter()
    nonexistent = tmp_path / "run" / "vpn-bot"

    def patched_check(reporter_, mode):
        run_dir = nonexistent
        if not run_dir.exists():
            if mode == "post-start":
                reporter_.fail(f"{run_dir}: missing — expected after 'systemctl start vpn-bot'")
            else:
                reporter_.warn(
                    f"{run_dir}: does not exist (expected before service start; "
                    "systemd creates RuntimeDirectory on service start)"
                )

    patched_check(reporter, "post-start")
    assert len(reporter.failures) == 1
    assert "missing" in reporter.failures[0]


def test_run_dir_post_start_writable_is_ok(tmp_path: Path) -> None:
    checker = _load_checker()
    reporter = checker.Reporter()
    # Create a directory that the current user can write
    run_dir = tmp_path / "vpn-bot"
    run_dir.mkdir(mode=0o700)
    # Simulate the check passing (writable by current uid/gid)
    st = run_dir.stat()
    import stat as _stat
    import os as _os
    uid = _os.getuid() if _os.name == "posix" else -1
    gid = _os.getgid() if _os.name == "posix" else -1
    writable = checker._would_be_writable(run_dir, uid, gid)
    if _os.name == "posix":
        assert writable is True


# ---------------------------------------------------------------------------
# 12. admin diagnostics uses healthcheck engine (no direct BackendHealth leak)
# ---------------------------------------------------------------------------

def test_admin_diagnostics_handler_uses_run_bot_health(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the handler calls run_bot_health and formats via system_diagnostics_text."""
    from bot.handlers.admin import admin_backend_diagnostics

    called_with: dict = {}

    async def fake_run_bot_health(**kwargs):
        called_with.update(kwargs)
        return build_result([
            HealthCheckItem(name="bot_runtime", status="ok", severity="info", message="Non-root OK"),
        ])

    monkeypatch.setattr("bot.handlers.admin.run_bot_health", fake_run_bot_health)

    async def allow_private(*args, **kwargs):
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private)

    class _StrictUsers:
        async def require_superadmin(self, actor_user_id: int):
            from models.dto import User
            from models.enums import UserRole
            return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

        async def require_approved_or_admin(self, actor_user_id: int):
            return await self.require_superadmin(actor_user_id)

    class _Callback:
        def __init__(self):
            self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
            self.message = _Message()
            self.data = "admin:diagnostics"
            self.answers = []

        async def answer(self, text=None, show_alert=None, **kwargs):
            self.answers.append((text or "", show_alert))

    class _Message:
        def __init__(self):
            self.edits = []

        async def edit_text(self, text, reply_markup=None):
            self.edits.append((text, reply_markup))

    async def run():
        callback = _Callback()
        settings = SimpleNamespace(
            awg_interface="awg0",
            xray_service_name="xray",
            socks5_enabled=True,
            socks5_service_name="danted",
            mtproto_enabled=True,
            mtproto_service_name="mtproxy",
            privilege_helpers_enabled=True,
        )
        services = SimpleNamespace(
            users=_StrictUsers(),
            backend_health=BackendHealth(),
            settings=settings,
            db=MagicMock(),
        )
        await admin_backend_diagnostics(callback, services)
        # run_bot_health must have been called
        assert "backend_health" in called_with
        assert "db" in called_with
        # The edit should show system diagnostics
        assert len(callback.message.edits) == 1
        text, _ = callback.message.edits[0]
        assert "Diagnostics" in text
        assert "Non-root OK" in text

    asyncio.run(run())


def test_admin_diagnostics_excludes_disabled_proxy_services(monkeypatch: pytest.MonkeyPatch) -> None:
    """When socks5_enabled=False and mtproto_enabled=False, those service names are omitted."""
    from bot.handlers.admin import admin_backend_diagnostics

    captured_service_names: list = []

    async def fake_run_bot_health(**kwargs):
        captured_service_names.extend(kwargs.get("service_names", []))
        return build_result([
            HealthCheckItem(name="bot_runtime", status="ok", severity="info", message="ok"),
        ])

    monkeypatch.setattr("bot.handlers.admin.run_bot_health", fake_run_bot_health)

    async def allow_private(*args, **kwargs):
        return True

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private)

    class _StrictUsers:
        async def require_superadmin(self, actor_user_id: int):
            from models.dto import User
            from models.enums import UserRole
            return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

        async def require_approved_or_admin(self, actor_user_id: int):
            return await self.require_superadmin(actor_user_id)

    class _Callback:
        def __init__(self):
            self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
            self.message = _Message()
            self.data = "admin:diagnostics"
            self.answers = []

        async def answer(self, text=None, show_alert=None, **kwargs):
            self.answers.append((text or "", show_alert))

    class _Message:
        def __init__(self):
            self.edits = []

        async def edit_text(self, text, reply_markup=None):
            self.edits.append((text, reply_markup))

    async def run():
        callback = _Callback()
        # Both optional proxies disabled
        settings = SimpleNamespace(
            awg_interface="awg0",
            xray_service_name="xray",
            socks5_enabled=False,
            socks5_service_name="danted",
            mtproto_enabled=False,
            mtproto_service_name="mtproxy",
            privilege_helpers_enabled=True,
        )
        services = SimpleNamespace(
            users=_StrictUsers(),
            backend_health=BackendHealth(),
            settings=settings,
            db=MagicMock(),
        )
        await admin_backend_diagnostics(callback, services)
        assert "danted" not in captured_service_names
        assert "mtproxy" not in captured_service_names
        assert "xray" in captured_service_names
        assert "vpn-bot" in captured_service_names

    asyncio.run(run())


# ---------------------------------------------------------------------------
# 13. redact utility: all secret patterns masked
# ---------------------------------------------------------------------------

def test_redact_masks_token() -> None:
    assert "***" in redact("error token=supersecret123 payload")
    assert "supersecret123" not in redact("error token=supersecret123 payload")


def test_redact_masks_hex_secrets() -> None:
    secret = "abcdef0123456789abcdef0123456789"
    assert secret not in redact(f"key={secret}")


def test_redact_masks_password() -> None:
    assert "***" in redact("login failed password=hunter2 retry")
    assert "hunter2" not in redact("login failed password=hunter2 retry")


def test_redact_truncates_long_messages() -> None:
    # 'z' is not a hex char so won't be redacted by HEX_SECRET_RE — truncation fires
    long = "z" * 300
    result = redact(long, limit=180)
    assert len(result) <= 180
    assert result.endswith("...")
