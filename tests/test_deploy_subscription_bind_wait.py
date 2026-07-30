"""Phase 1 subscription port check: never fatal, and tolerant of a slow bind.

`vpn-bot-subscription.service` needs ~20 seconds between `systemctl start` and
holding its sockets: before binding it imports `services.xray` +
`bot.formatters` (the single source of truth for the vless:// and hy2:// link
formats, reused so subscription links stay byte-identical to the per-key ones),
and that import pulls in most of the bot's service layer.

Two properties therefore have to hold for `subscription_endpoint_status()` in
`scripts/deploy.sh`, and both are asserted here by driving the real bash through
the documented `DEPLOY_SELFTEST=1` seam with stubbed `systemctl` / `ss` / `sleep`:

1. **Never fatal.** A non-zero return is a `warn` line and nothing else — under
   the script's own `set -euo pipefail` it must not abort the deploy. Locked in
   by running the actual call-site idiom and asserting execution continues.
2. **Tolerant of a not-yet-bound port.** While the unit is ACTIVE the check
   re-tests for up to `SUBSCRIPTION_BIND_WAIT` seconds instead of immediately
   reporting "NOT listening", so a deploy that lands inside the start-to-bind
   window does not flag a healthy service. A unit that is NOT active is not
   waited on (it is never going to bind), and a port that never appears is still
   reported — the tolerance must not turn into blindness.

No systemctl, no network, no host paths, no production .env: every external
command is a stub on PATH and the .env is a fixture under tmp_path.
"""

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

# Per-test wall-clock ceiling (pytest-timeout). The slowest test here deliberately
# lets a short bind wait run out (a few seconds), so anything near this limit is a
# hang, not slow work. Belt-and-braces on top of the real rule — these suites stub
# every host command they can reach — because deploy.sh runs this suite as a Phase 1
# gate on the production host, where a wedged test blocks the deploy it should guard.
pytestmark = pytest.mark.timeout(60)


ENV_FIXTURE = """\
SUBSCRIPTION_ENABLED=true
SUBSCRIPTION_BIND_HOST=127.0.0.1
SUBSCRIPTION_BIND_PORT=8445
SUBSCRIPTION_PUBLIC_PORT=2096
"""

# `ss -tln` output with both configured ports bound.
SS_BOTH_BOUND = (
    "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    "LISTEN 0      128        127.0.0.1:8445       0.0.0.0:*\n"
    "LISTEN 0      128                *:2096             *:*\n"
)
SS_NOTHING_BOUND = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"


def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(
    tmp_path: Path,
    body: str,
    *,
    active_state: str = "active",
    load_state: str = "loaded",
    ss_script: str,
    bind_wait: int = 30,
) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh (selftest seam) and run `body` with the externals stubbed.

    ss_script:    body of the fake `ss`; it may consult/advance the call counter
                  file at $SS_CALLS to simulate a port that shows up late.
    active_state: what `systemctl show -p ActiveState --value` reports.
    """
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    # Instant sleep, and a tally so a test can assert whether waiting happened at
    # all (a non-active unit must not be waited on).
    _make_stub(stub_dir / "sleep", f'echo x >> "{tmp_path}/sleeps"\nexit 0\n')
    _make_stub(
        stub_dir / "systemctl",
        "case \"$*\" in\n"
        f'  *LoadState*)   printf "%s" "{load_state}" ;;\n'
        f'  *ActiveState*) printf "%s" "{active_state}" ;;\n'
        "  *) printf '' ;;\n"
        "esac\n",
    )
    _make_stub(stub_dir / "ss", ss_script)

    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FIXTURE, encoding="utf-8")

    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub_dir}:$PATH"\n'
        f'export ENV_FILE="{env_file}"\n'
        f'export SUBSCRIPTION_BIND_WAIT={bind_wait}\n'
        f'export SS_CALLS="{tmp_path}/ss_calls"\n'
        f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic for the test environment.
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        f"{body}\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True
    )
    proc.stdout += "\n---STDERR---\n" + proc.stderr
    return proc


def _ss_bound_after(n_calls: int) -> str:
    """Fake `ss` that reports nothing bound for the first `n_calls` invocations.

    Models the real start-to-bind window: the unit is up, the sockets are not
    there yet, and they appear a few seconds later.
    """
    return (
        'c=0\n'
        '[[ -f "$SS_CALLS" ]] && c="$(cat "$SS_CALLS")"\n'
        'c=$((c + 1)); printf "%s" "$c" > "$SS_CALLS"\n'
        f'if (( c > {n_calls} )); then\n'
        f'  cat <<\'EOF\'\n{SS_BOTH_BOUND}EOF\n'
        'else\n'
        f'  cat <<\'EOF\'\n{SS_NOTHING_BOUND}EOF\n'
        'fi\n'
    )


def _sleep_count(tmp_path: Path) -> int:
    log = tmp_path / "sleeps"
    return len(log.read_text(encoding="utf-8").splitlines()) if log.exists() else 0


# --------------------------------------------------------------------------- #
# Never fatal
# --------------------------------------------------------------------------- #
def test_status_failure_never_aborts_the_deploy(tmp_path: Path) -> None:
    """The real call-site idiom, run under the script's own `set -e`.

    A port that never binds must produce a warning and let the deploy carry on;
    the sentinel after the call proves errexit/ERR-trap never fired.
    """
    proc = _run(
        tmp_path,
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"\n'
        'echo "MSG=[$MSG]"\n'
        'echo "CONTINUED"\n',
        ss_script=f"cat <<'EOF'\n{SS_NOTHING_BOUND}EOF\n",
        bind_wait=4,
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[1]" in proc.stdout
    assert "NOT listening on" in proc.stdout
    # The one assertion that matters: execution reached the next statement.
    assert "CONTINUED" in proc.stdout


def test_missing_unit_is_reported_but_not_fatal(tmp_path: Path) -> None:
    proc = _run(
        tmp_path,
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"; echo "MSG=[$MSG]"; echo "CONTINUED"\n',
        load_state="not-found",
        active_state="inactive",
        ss_script=f"cat <<'EOF'\n{SS_BOTH_BOUND}EOF\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[1]" in proc.stdout
    assert "is not installed" in proc.stdout
    assert "CONTINUED" in proc.stdout


# --------------------------------------------------------------------------- #
# Start-to-bind tolerance
# --------------------------------------------------------------------------- #
def test_slow_bind_is_waited_out_and_reported_healthy(tmp_path: Path) -> None:
    """~20s start-to-bind must not be reported as a broken endpoint."""
    proc = _run(
        tmp_path,
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"; echo "MSG=[$MSG]"\n',
        ss_script=_ss_bound_after(3),
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[0]" in proc.stdout
    assert "listening on 127.0.0.1:8445 and :2096" in proc.stdout
    assert "NOT listening" not in proc.stdout
    assert "start-to-bind" in proc.stdout
    assert _sleep_count(tmp_path) >= 1


def test_already_bound_endpoint_does_not_wait(tmp_path: Path) -> None:
    """The happy path stays instant — the retry only exists for the warn path."""
    proc = _run(
        tmp_path,
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"; echo "MSG=[$MSG]"\n',
        ss_script=f"cat <<'EOF'\n{SS_BOTH_BOUND}EOF\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[0]" in proc.stdout
    assert "listening on 127.0.0.1:8445 and :2096" in proc.stdout
    assert "start-to-bind" not in proc.stdout
    assert _sleep_count(tmp_path) == 0


def test_port_that_never_binds_is_still_reported(tmp_path: Path) -> None:
    """Tolerance is bounded: past the window a dead port is named, both ports."""
    proc = _run(
        tmp_path,
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"; echo "MSG=[$MSG]"\n',
        ss_script=f"cat <<'EOF'\n{SS_NOTHING_BOUND}EOF\n",
        bind_wait=4,
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[1]" in proc.stdout
    assert "127.0.0.1:8445 (loopback)" in proc.stdout
    assert ":2096 (public HTTPS)" in proc.stdout
    assert "start-to-bind window has passed" in proc.stdout


def test_inactive_unit_is_not_waited_on(tmp_path: Path) -> None:
    """A failed/inactive unit will never bind — waiting only slows the report."""
    proc = _run(
        tmp_path,
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"; echo "MSG=[$MSG]"\n',
        active_state="failed",
        ss_script=f"cat <<'EOF'\n{SS_NOTHING_BOUND}EOF\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[1]" in proc.stdout
    assert "NOT listening on" in proc.stdout
    assert _sleep_count(tmp_path) == 0


def test_bind_wait_zero_disables_the_retry(tmp_path: Path) -> None:
    """SUBSCRIPTION_BIND_WAIT=0 restores the previous single-shot behaviour."""
    proc = _run(
        tmp_path,
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"; echo "MSG=[$MSG]"\n',
        ss_script=_ss_bound_after(3),
        bind_wait=0,
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[1]" in proc.stdout
    assert _sleep_count(tmp_path) == 0


def test_feature_off_is_informational_and_instant(tmp_path: Path) -> None:
    proc = _run(
        tmp_path,
        # env_val reads ENV_FILE, so blank the flag there rather than in the shell.
        f'printf "SUBSCRIPTION_ENABLED=false\\n" > "{tmp_path}/.env"\n'
        'MSG="$(subscription_endpoint_status)" && RC=0 || RC=$?\n'
        'echo "RC=[$RC]"; echo "MSG=[$MSG]"\n',
        ss_script=f"cat <<'EOF'\n{SS_NOTHING_BOUND}EOF\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=[0]" in proc.stdout
    assert "intentionally inert" in proc.stdout
    assert _sleep_count(tmp_path) == 0
