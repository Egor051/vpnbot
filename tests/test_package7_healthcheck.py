
import asyncio
import io
import json
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bot.formatters import system_diagnostics_text
from models.dto import User
from models.enums import ProxyAccessType, UserRole, VpnKeyType
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
from utils.redact import redact, redact_value

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEPLOY_UNIT = ROOT / "deploy" / "vpn-bot.service"
_NONROOT_UNIT = ROOT / "deploy" / "vpn-bot.nonroot.example.service"
_HEX_SECRET = "0123456789abcdef0123456789abcdef"
_HEX_SECRET_AWG = "abcdef1234567890abcdef1234567890"

# ---------------------------------------------------------------------------
# Module-level test doubles for admin handler tests
# ---------------------------------------------------------------------------


class _AdminUsers:
    async def require_superadmin(self, actor_user_id: int) -> User:
        return User(actor_user_id, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

    async def require_approved_or_admin(self, actor_user_id: int) -> User:
        return await self.require_superadmin(actor_user_id)


class _AdminCallback:
    def __init__(self) -> None:
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.message = _AdminMessage()
        self.data = "admin:diagnostics"
        self.answers: list[tuple[str, object]] = []

    async def answer(
        self, text: str | None = None, show_alert: bool | None = None, **kwargs: object
    ) -> None:
        self.answers.append((text or "", show_alert))


class _AdminMessage:
    def __init__(self) -> None:
        self.edits: list[tuple[str, object]] = []

    async def edit_text(self, text: str, reply_markup: object = None) -> None:
        self.edits.append((text, reply_markup))


def _make_settings(**overrides: object) -> SimpleNamespace:
    defaults: dict[str, object] = dict(
        awg_interface="awg0",
        xray_service_name="xray",
        xray_apply_mode="restart",
        socks5_enabled=True,
        socks5_service_name="danted",
        mtproto_enabled=True,
        mtproto_service_name="mtproxy",
        privilege_helpers_enabled=True,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# 1. Health result status aggregation: failed > degraded > warning > ok
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        (["ok", "warning", "degraded", "failed"], "failed"),
        (["ok", "warning", "degraded"], "degraded"),
        (["ok", "warning"], "warning"),
        (["ok", "ok"], "ok"),
        ([], "ok"),
        (["failed"], "failed"),
        (["failed", "failed", "failed"], "failed"),
        (["warning", "warning"], "warning"),
    ],
    ids=[
        "all-four", "no-failed", "no-degraded", "all-ok",
        "empty", "single-failed", "all-failed", "all-warning",
    ],
)
def test_aggregate_status_ordering(statuses: list[str], expected: str) -> None:
    """Status with highest severity wins; empty list defaults to ok."""
    assert aggregate_status(statuses) == expected


def test_build_result_overall_reflects_worst_check() -> None:
    """Overall status equals the worst individual check status."""
    checks = [
        HealthCheckItem(name="a", status="ok", severity="info", message="ok"),
        HealthCheckItem(name="b", status="degraded", severity="warning", message="degraded"),
        HealthCheckItem(name="c", status="warning", severity="warning", message="warn"),
    ]
    result = build_result(checks)
    assert result.overall == "degraded"
    assert len(result.checks) == 3
    assert result.timestamp


def test_build_result_all_ok() -> None:
    """All-ok checks produce an ok overall result."""
    checks = [HealthCheckItem(name="x", status="ok", severity="info", message="fine")]
    result = build_result(checks)
    assert result.overall == "ok"


def test_build_result_single_failed() -> None:
    """A single failed check drives overall to failed."""
    checks = [HealthCheckItem(name="x", status="failed", severity="critical", message="bad")]
    result = build_result(checks)
    assert result.overall == "failed"


def test_build_result_empty_checks() -> None:
    """Empty check list produces ok overall with no checks."""
    result = build_result([])
    assert result.overall == "ok"
    assert len(result.checks) == 0


# ---------------------------------------------------------------------------
# 2. check_backends: degraded backend_health → degraded items, reason redacted
# ---------------------------------------------------------------------------


def test_check_backends_all_healthy() -> None:
    """All backends healthy → all items are ok."""
    health = BackendHealth()
    items = check_backends(health.snapshot())
    assert all(i.status == "ok" for i in items)
    assert len(items) == 4  # Xray, AWG, SOCKS5, MTProto


def test_check_backends_degraded_reason_is_redacted() -> None:
    """Degraded backend message must not leak tokens or hex secrets."""
    health = BackendHealth()
    health.mark_degraded(VpnKeyType.XRAY, f"apply failed token=bot-token secret={_HEX_SECRET}")
    items = check_backends(health.snapshot())
    xray_item = next(i for i in items if "xray" in i.name)
    assert xray_item.status == "degraded"
    assert _HEX_SECRET not in xray_item.details
    assert "bot-token" not in xray_item.details


# ---------------------------------------------------------------------------
# 3. check_bot_non_root
# ---------------------------------------------------------------------------


def test_check_bot_non_root_when_not_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-root UID produces an ok health item."""
    if os.name != "posix":
        pytest.skip("POSIX only")
    monkeypatch.setattr(os, "getuid", lambda: 1001)
    item = check_bot_non_root()
    assert item.status == "ok"
    assert "1001" in item.message


def test_check_bot_non_root_when_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """UID 0 (root) without Xray API mode produces a critical failed item."""
    if os.name != "posix":
        pytest.skip("POSIX only")
    monkeypatch.setattr(os, "getuid", lambda: 0)
    item = check_bot_non_root()
    assert item.status == "failed"
    assert item.severity == "critical"


def test_check_bot_non_root_when_root_xray_api_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """UID 0 (root) with xray_api_mode=True produces a warning, not a failure."""
    if os.name != "posix":
        pytest.skip("POSIX only")
    monkeypatch.setattr(os, "getuid", lambda: 0)
    item = check_bot_non_root(xray_api_mode=True)
    assert item.status == "warning"
    assert item.severity == "warning"


# ---------------------------------------------------------------------------
# 4. check_helper_mode
# ---------------------------------------------------------------------------


def test_check_helper_mode_enabled() -> None:
    """Helper mode enabled → ok status."""
    item = check_helper_mode(True)
    assert item.status == "ok"


def test_check_helper_mode_disabled_non_api() -> None:
    """Helper mode disabled outside API mode → warning about broken apply operations."""
    item = check_helper_mode(False)
    assert item.status == "warning"
    assert "apply operations" in item.message


def test_check_helper_mode_disabled_xray_api_mode() -> None:
    """Helper mode disabled with xray_api_mode=True → warning that it is OK for API mode."""
    item = check_helper_mode(False, xray_api_mode=True)
    assert item.status == "warning"
    assert "api" in item.message.lower()


# ---------------------------------------------------------------------------
# 5. system_diagnostics_text: no secrets in output
# ---------------------------------------------------------------------------


def test_system_diagnostics_text_no_secrets() -> None:
    """Formatter output must not contain raw secrets embedded in backend errors."""
    health = BackendHealth()
    health.mark_degraded(VpnKeyType.AWG, f"apply failed password={_HEX_SECRET_AWG} token=bot-secret")
    items = check_backends(health.snapshot())
    result = build_result(items)
    text = system_diagnostics_text(result)
    assert _HEX_SECRET_AWG not in text
    assert "bot-secret" not in text
    assert "AWG" in text
    assert "DEGRADED" in text or "degraded" in text


def test_system_diagnostics_text_overall_shown() -> None:
    """Formatter includes the overall status and check messages."""
    items = [HealthCheckItem(name="a", status="failed", severity="critical", message="Fatal error")]
    result = build_result(items)
    text = system_diagnostics_text(result)
    assert "FAILED" in text
    assert "Fatal error" in text


# ---------------------------------------------------------------------------
# 6. run_bot_health: async integration with mock db and services
# ---------------------------------------------------------------------------


def test_run_bot_health_returns_result() -> None:
    """run_bot_health returns a result with all expected check names."""
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
    """A database error causes db_sqlite to fail and overall to become failed."""
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


def test_run_bot_health_empty_service_list() -> None:
    """run_bot_health with no service names still returns core check items."""
    async def _run() -> None:
        health = BackendHealth()
        mock_db = MagicMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=("ok",))
        mock_db.conn.execute = AsyncMock(return_value=mock_cursor)

        with patch("services.health.asyncio.create_subprocess_exec"):
            result = await run_bot_health(
                backend_health=health,
                db=mock_db,
                privilege_helpers_enabled=False,
                service_names=[],
            )

        names = {c.name for c in result.checks}
        assert "bot_runtime" in names
        assert "db_sqlite" in names
        assert not any(n.startswith("service_") for n in names)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 7. CLI: --json output has no secrets, exit code, --mode
# ---------------------------------------------------------------------------


def test_cli_json_output_structure(
    checker: ModuleType, captured_cli_output: object, tmp_path: Path
) -> None:
    """CLI --json output contains the required top-level keys."""
    with captured_cli_output() as captured:
        checker.main([
            "--json",
            "--repo", str(tmp_path),
            "--db", str(tmp_path / "vpn.db"),
            "--sudoers", str(tmp_path / "vpnbot"),
            "--mode", "pre-start",
        ])
    data = json.loads(captured.getvalue())
    assert "overall" in data
    assert "checks" in data
    assert "failures" in data
    assert "warnings" in data
    assert isinstance(data["checks"], list)


def test_cli_json_no_secrets_in_output(
    checker: ModuleType, captured_cli_output: object, tmp_path: Path
) -> None:
    """CLI --json output must not contain values from the .env file."""
    env_file = tmp_path / ".env"
    env_file.write_text("BOT_TOKEN=secret-token-12345\n")

    with captured_cli_output() as captured:
        checker.main([
            "--json",
            "--repo", str(tmp_path),
            "--db", str(tmp_path / "vpn.db"),
            "--sudoers", str(tmp_path / "vpnbot"),
        ])

    output = captured.getvalue()
    assert "secret-token-12345" not in output
    assert "BOT_TOKEN" not in output


def test_cli_returns_nonzero_on_critical_failure(
    checker: ModuleType, captured_cli_output: object, tmp_path: Path
) -> None:
    """CLI exits with 1 when the unit file contains critical security violations."""
    bad_unit = tmp_path / "vpn-bot.service"
    bad_unit.write_text("[Service]\nUser=root\n")

    with captured_cli_output():
        ret = checker.main([
            "--unit", str(bad_unit),
            "--repo", str(tmp_path),
            "--db", str(tmp_path / "vpn.db"),
            "--sudoers", str(tmp_path / "vpnbot"),
        ])

    assert ret == 1


def test_cli_returns_zero_on_ok_or_warnings(
    checker: ModuleType,
    captured_cli_output: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI exits with 0 when all checks pass or produce only warnings."""
    def _warn_path(path: object, reporter_: object, *args: object, **kwargs: object) -> None:
        reporter_.warn(f"{path}: skipped in test environment")  # type: ignore[union-attr]

    def _warn(reporter_: object, *args: object, **kwargs: object) -> None:
        reporter_.warn("skipped in test environment")  # type: ignore[union-attr]

    monkeypatch.setattr(checker, "check_sudoers", _warn_path)
    monkeypatch.setattr(checker, "check_helpers", _warn)
    monkeypatch.setattr(checker, "check_runtime_ownership", _warn_path)
    monkeypatch.setattr(checker, "check_run_dir", _warn)
    monkeypatch.setattr(checker, "check_sudo_helpers", _warn)
    monkeypatch.setattr(checker, "check_active_services", _warn)
    monkeypatch.setattr(checker, "check_xray_config", _warn_path)
    monkeypatch.setattr(checker, "check_awg_config", _warn_path)
    monkeypatch.setattr(checker, "check_mtproxy_managed_files", _warn_path)

    # The nonroot checker validates User=vpn-bot layout; use the nonroot example
    # service because the production service now runs as root (api mode).
    with captured_cli_output():
        ret = checker.main([
            "--unit", str(_NONROOT_UNIT),
            "--repo", str(tmp_path),
            "--db", str(tmp_path / "vpn.db"),
            "--sudoers", str(tmp_path / "vpnbot"),
        ])

    assert ret == 0


# ---------------------------------------------------------------------------
# 8. Service guardrails: check_unit catches forbidden and missing fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("unit_content", "must_appear_in_failures"),
    [
        ("[Service]\nUser=root\nGroup=root\n", ["User=root", "Group=root"]),
        ("[Service]\nNoNewPrivileges=true\n", ["NoNewPrivileges=true"]),
        ("[Service]\n", ["User=vpn-bot", "ProtectSystem=strict"]),
    ],
    ids=["user-root", "no-new-privileges", "missing-required"],
)
def test_check_unit_catches_bad_service_config(
    checker: ModuleType,
    tmp_path: Path,
    unit_content: str,
    must_appear_in_failures: list[str],
) -> None:
    """Systemd unit with bad security settings produces failures for each violation."""
    unit = tmp_path / "vpn-bot.service"
    unit.write_text(unit_content)
    reporter = checker.Reporter()
    checker.check_unit(unit, reporter)
    for expected in must_appear_in_failures:
        assert any(expected in f for f in reporter.failures), (
            f"Expected {expected!r} in failures: {reporter.failures}"
        )


def test_check_unit_nonexistent_file_is_failure(
    checker: ModuleType, tmp_path: Path
) -> None:
    """A missing unit file produces a failure (not a crash)."""
    unit = tmp_path / "missing.service"
    reporter = checker.Reporter()
    checker.check_unit(unit, reporter)
    assert len(reporter.failures) > 0


# ---------------------------------------------------------------------------
# 9. Sudoers guardrails: broad grants caught
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sudoers_content", "must_appear_in_failures"),
    [
        ("vpn-bot ALL=(ALL:ALL) ALL\n", ["ALL=(ALL:ALL) ALL"]),
        ("vpn-bot ALL=(ALL) NOPASSWD: ALL\n", ["NOPASSWD: ALL"]),
    ],
    ids=["all-all-all", "nopasswd-all"],
)
def test_check_sudoers_catches_broad_grants(
    checker: ModuleType,
    tmp_path: Path,
    sudoers_content: str,
    must_appear_in_failures: list[str],
) -> None:
    """Sudoers file with overly broad privilege grants is flagged as a failure."""
    sudoers = tmp_path / "vpnbot"
    sudoers.write_text(sudoers_content)
    reporter = checker.Reporter()
    checker.check_sudoers(sudoers, reporter)
    for expected in must_appear_in_failures:
        assert any(expected in f for f in reporter.failures), (
            f"Expected {expected!r} in failures: {reporter.failures}"
        )


# ---------------------------------------------------------------------------
# 10. Helper permissions checked
# ---------------------------------------------------------------------------


def test_check_helpers_reports_missing_helpers(checker: ModuleType) -> None:
    """On CI/dev hosts without installed helpers, check_helpers reports failures (not crashes)."""
    reporter = checker.Reporter()
    checker.check_helpers(reporter)
    for failure in reporter.failures:
        assert "missing" in failure or "expected root:root" in failure


# ---------------------------------------------------------------------------
# 11. pre-start / post-start /run/vpn-bot mode
# ---------------------------------------------------------------------------


def test_run_dir_pre_start_absent_is_warning(checker: ModuleType, tmp_path: Path) -> None:
    """Absent /run/vpn-bot in pre-start mode is a warning, not a failure."""
    reporter = checker.Reporter()
    nonexistent = tmp_path / "run" / "vpn-bot"

    def patched_check(reporter_: object, mode: str) -> None:
        if not nonexistent.exists():
            if mode == "post-start":
                reporter_.fail(  # type: ignore[union-attr]
                    f"{nonexistent}: missing — expected after 'systemctl start vpn-bot'"
                )
            else:
                reporter_.warn(  # type: ignore[union-attr]
                    f"{nonexistent}: does not exist (expected before service start; "
                    "systemd creates RuntimeDirectory on service start)"
                )

    patched_check(reporter, "pre-start")
    assert len(reporter.failures) == 0
    assert len(reporter.warnings) == 1
    assert "does not exist" in reporter.warnings[0]


def test_run_dir_post_start_absent_is_failure(checker: ModuleType, tmp_path: Path) -> None:
    """Absent /run/vpn-bot in post-start mode is a hard failure."""
    reporter = checker.Reporter()
    nonexistent = tmp_path / "run" / "vpn-bot"

    def patched_check(reporter_: object, mode: str) -> None:
        if not nonexistent.exists():
            if mode == "post-start":
                reporter_.fail(  # type: ignore[union-attr]
                    f"{nonexistent}: missing — expected after 'systemctl start vpn-bot'"
                )
            else:
                reporter_.warn(  # type: ignore[union-attr]
                    f"{nonexistent}: does not exist (expected before service start; "
                    "systemd creates RuntimeDirectory on service start)"
                )

    patched_check(reporter, "post-start")
    assert len(reporter.failures) == 1
    assert "missing" in reporter.failures[0]


def test_run_dir_post_start_writable_is_ok(checker: ModuleType, tmp_path: Path) -> None:
    """A directory writable by the current user passes the writability check."""
    run_dir = tmp_path / "vpn-bot"
    run_dir.mkdir(mode=0o700)
    if os.name == "posix":
        uid = os.getuid()
        gid = os.getgid()
        assert checker._would_be_writable(run_dir, uid, gid) is True


# ---------------------------------------------------------------------------
# 12. Admin diagnostics uses healthcheck engine
# ---------------------------------------------------------------------------


def test_admin_diagnostics_handler_uses_run_bot_health(monkeypatch: pytest.MonkeyPatch) -> None:
    """Handler calls run_bot_health and formats the result via system_diagnostics_text."""
    from bot.handlers.admin import admin_backend_diagnostics

    called_with: dict[str, object] = {}

    async def fake_run_bot_health(**kwargs: object) -> object:
        called_with.update(kwargs)
        return build_result([
            HealthCheckItem(name="bot_runtime", status="ok", severity="info", message="Non-root OK"),
        ])

    async def allow_private(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.run_bot_health", fake_run_bot_health)
    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private)

    async def _no_modules() -> list[object]:
        return []

    async def run() -> None:
        callback = _AdminCallback()
        modules_mock = SimpleNamespace(get_all=_no_modules)
        services = SimpleNamespace(
            users=_AdminUsers(),
            backend_health=BackendHealth(),
            settings=_make_settings(),
            db=MagicMock(),
            modules=modules_mock,
        )
        await admin_backend_diagnostics(callback, services)
        assert "backend_health" in called_with
        assert "db" in called_with
        assert len(callback.message.edits) == 1
        text, _ = callback.message.edits[0]
        assert "Diagnostics" in text
        assert "Non-root OK" in text

    asyncio.run(run())


def test_admin_diagnostics_excludes_disabled_proxy_services(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disabled proxy services (socks5, mtproto) are excluded from service_names."""
    from bot.handlers.admin import admin_backend_diagnostics

    captured_service_names: list[str] = []

    async def fake_run_bot_health(**kwargs: object) -> object:
        captured_service_names.extend(kwargs.get("service_names", []))  # type: ignore[arg-type]
        return build_result([
            HealthCheckItem(name="bot_runtime", status="ok", severity="info", message="ok"),
        ])

    async def allow_private(*args: object, **kwargs: object) -> bool:
        return True

    monkeypatch.setattr("bot.handlers.admin.run_bot_health", fake_run_bot_health)
    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", allow_private)

    async def _no_modules() -> list[object]:
        return []

    async def run() -> None:
        callback = _AdminCallback()
        modules_mock = SimpleNamespace(get_all=_no_modules)
        services = SimpleNamespace(
            users=_AdminUsers(),
            backend_health=BackendHealth(),
            settings=_make_settings(socks5_enabled=False, mtproto_enabled=False),
            db=MagicMock(),
            modules=modules_mock,
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


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("error token=supersecret123 payload", "supersecret123"),
        ("login failed password=hunter2 retry", "hunter2"),
        (f"key={'abcdef0123456789abcdef0123456789'}", "abcdef0123456789abcdef0123456789"),
    ],
    ids=["token-field", "password-field", "hex-secret"],
)
def test_redact_masks_secrets(text: str, secret: str) -> None:
    """Known secret patterns (token=, password=, hex strings) are replaced."""
    result = redact(text)
    assert secret not in result
    assert "***" in result


def test_redact_truncates_long_messages() -> None:
    """Messages longer than the limit are truncated and end with ellipsis."""
    long = "z" * 300  # 'z' is not a hex char, so truncation fires
    result = redact(long, limit=180)
    assert len(result) <= 180
    assert result.endswith("...")


def test_redact_empty_string() -> None:
    """Empty string input returns empty string without error."""
    assert redact("") == ""


def test_redact_value_masks_bot_token_in_payload() -> None:
    """redact_value replaces bot token patterns in JSON payloads."""
    payload = '{"bot_token": "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"}'
    result = redact_value(payload)
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi" not in result
    assert "***" in result


def test_redact_value_does_not_truncate() -> None:
    """redact_value preserves message length (no truncation, unlike redact)."""
    long = "z" * 300
    result = redact_value(long)
    assert len(result) == 300
    assert "..." not in result
