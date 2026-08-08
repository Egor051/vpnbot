"""Phase 2 sidecar restart: the half of a deploy that used to never move.

`vpn-bot.service` is not the only process running the deployed checkout. The
subscription endpoint (`subscription_server/`) and the Hysteria2 auth endpoint
(`hy2_auth/`) run the same tree from their own systemd units, each holding the
code in memory. `scripts/deploy.sh` Phase 2 restarted the bot only, so any PR
touching `subscription_server/`, `hy2_auth/`, `services/key_bundles.py` or the
shared link formatters shipped HALF-DEPLOYED — with a fully green report. On
2026-08-08 the bot moved at 13:56 and the subscription endpoint kept serving the
previous link order, without preference marks, until an unrelated host reboot at
15:20 restarted it by accident.

The properties asserted here, all by driving the real bash through the documented
`DEPLOY_SELFTEST=1` seam with stubbed `systemctl` / `ss` / `sleep`:

1. **Derived, never hardcoded.** The unit list comes from `$SUBSCRIPTION_UNIT` and
   the `.env` key `HYSTERIA2_AUTH_SERVICE_NAME`, so a renamed unit stays covered.
2. **Pre-state decides.** A sidecar that was ACTIVE before the deploy is
   restarted; one that was inactive/failed is left alone, and one that is not
   installed is skipped. The deploy never installs, enables or starts either unit
   — both are drift-installed by hand and that policy is unchanged.
3. **Fatal in exactly one case.** Active before and not back to active after our
   restart is a regression this deploy caused, and goes through `rollback_now`.
   An absent unit, an inactive unit, or a port that does not answer while the
   unit itself is active are all informational — never a rollback.
4. **Reported.** One report line per unit (restarted / skipped (was inactive) /
   skipped (absent)), so a half-deployed host is visible instead of silent.

No systemctl, no network, no host paths, no production `.env`: every external
command is a stub on PATH and the `.env` is a fixture under tmp_path.
"""

import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

# Per-test wall-clock ceiling (pytest-timeout). Every wait in these tests runs
# against a stubbed `sleep`, so anything near this limit is a hang, not slow work.
# deploy.sh runs this suite as a Phase 1 gate on the production host, where a
# wedged test blocks the deploy it is supposed to guard.
pytestmark = pytest.mark.timeout(60)


SUB_UNIT = "vpn-bot-subscription.service"
# Deliberately NOT the deploy.sh default (`vpn-bot-hy2-auth`): the live host runs
# `vpnbot-hy2-auth`, and reading the name from .env is the requirement.
HY2_UNIT = "vpnbot-hy2-auth.service"

ENV_FIXTURE = """\
SUBSCRIPTION_ENABLED=true
SUBSCRIPTION_BIND_HOST=127.0.0.1
SUBSCRIPTION_BIND_PORT=8445
SUBSCRIPTION_PUBLIC_PORT=2096
HYSTERIA2_AUTH_SERVICE_NAME=vpnbot-hy2-auth
HYSTERIA2_AUTH_LISTEN=127.0.0.1:8444
"""

# `ss -tln` with every port these tests care about held.
SS_ALL_BOUND = (
    "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    "LISTEN 0      128        127.0.0.1:8445       0.0.0.0:*\n"
    "LISTEN 0      128                *:2096             *:*\n"
    "LISTEN 0      128        127.0.0.1:8444       0.0.0.0:*\n"
)
SS_NOTHING_BOUND = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"

# A `systemctl` stub backed by per-unit files under $STATE_DIR:
#   <unit>.load        LoadState        (default: not-found)
#   <unit>.state       ActiveState      (default: inactive)
#   <unit>.after       state to install on `restart` (simulates the outcome)
#   <unit>.restart_rc  exit code for `restart` (default: 0)
# Every invocation is appended to $SYSTEMCTL_LOG so a test can assert which units
# were restarted — and, just as importantly, which were not.
SYSTEMCTL_STUB = r"""
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
unit="${!#}"
sd="$STATE_DIR"
_state() { [[ -f "$sd/${unit}.state" ]] && cat "$sd/${unit}.state" || printf 'inactive'; }
_load()  { [[ -f "$sd/${unit}.load"  ]] && cat "$sd/${unit}.load"  || printf 'not-found'; }
case "$1" in
  restart)
    [[ -f "$sd/${unit}.after" ]] && cp "$sd/${unit}.after" "$sd/${unit}.state"
    [[ -f "$sd/${unit}.restart_rc" ]] && exit "$(cat "$sd/${unit}.restart_rc")"
    exit 0 ;;
  is-active)
    s="$(_state)"; printf '%s\n' "$s"
    [[ "$s" == "active" ]] && exit 0 || exit 3 ;;
  show)
    case "$*" in
      *LoadState*)   printf '%s' "$(_load)" ;;
      *ActiveState*) printf '%s' "$(_state)" ;;
      *)             printf '' ;;
    esac
    exit 0 ;;
  *) printf ''; exit 0 ;;
esac
"""


def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _unit_state(
    state_dir: Path,
    unit: str,
    *,
    load: str = "loaded",
    state: str = "active",
    after: str | None = None,
    restart_rc: int | None = None,
) -> None:
    """Describe one unit to the systemctl stub. `load="not-found"` = absent."""
    (state_dir / f"{unit}.load").write_text(load, encoding="utf-8")
    (state_dir / f"{unit}.state").write_text(state, encoding="utf-8")
    if after is not None:
        (state_dir / f"{unit}.after").write_text(after, encoding="utf-8")
    if restart_rc is not None:
        (state_dir / f"{unit}.restart_rc").write_text(str(restart_rc), encoding="utf-8")


def _run(
    tmp_path: Path,
    body: str,
    *,
    units: dict[str, dict] | None = None,
    ss_output: str = SS_ALL_BOUND,
    env_fixture: str = ENV_FIXTURE,
    active_wait: int = 4,
) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh (selftest seam) and run `body` with the externals stubbed."""
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    state_dir = tmp_path / "units"
    state_dir.mkdir(parents=True, exist_ok=True)

    _make_stub(stub_dir / "sleep", f'echo x >> "{tmp_path}/sleeps"\nexit 0\n')
    _make_stub(stub_dir / "systemctl", SYSTEMCTL_STUB)
    _make_stub(stub_dir / "ss", f"cat <<'EOF'\n{ss_output}EOF\n")

    for unit, spec in (units or {}).items():
        _unit_state(state_dir, unit, **spec)

    env_file = tmp_path / ".env"
    env_file.write_text(env_fixture, encoding="utf-8")

    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub_dir}:$PATH"\n'
        f'export ENV_FILE="{env_file}"\n'
        f'export STATE_DIR="{state_dir}"\n'
        f'export SYSTEMCTL_LOG="{tmp_path}/systemctl.log"\n'
        f"export SIDECAR_ACTIVE_WAIT={active_wait}\n"
        "export SUBSCRIPTION_BIND_WAIT=2\n"
        f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic for the test environment.
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        # rollback_now would unpack a backup and bounce the data plane. Replace it
        # with a loud sentinel: any call is visible, and only the fatal-path test
        # expects one.
        "rollback_now() { printf 'ROLLBACK_NOW: %s\\n' \"$*\"; exit 9; }\n"
        f"{body}\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True
    )
    proc.stdout += "\n---STDERR---\n" + proc.stderr
    return proc


def _restarted(tmp_path: Path) -> list[str]:
    """Units the script actually asked systemd to restart, in order."""
    log = tmp_path / "systemctl.log"
    if not log.exists():
        return []
    return [
        line.split(maxsplit=1)[1]
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.startswith("restart ")
    ]


# The real Phase 2 sequence: snapshot the pre-states, then restart. Both halves
# run in one bash process, which is the only way the pre-state can decide anything.
SNAPSHOT_AND_RESTART = (
    "resolve_backend_units\n"
    "snapshot_sidecar_units\n"
    "restart_sidecar_units\n"
    "sidecar_report_block\n"
    "echo CONTINUED\n"
)


# --------------------------------------------------------------------------- #
# The unit list is derived, not hardcoded
# --------------------------------------------------------------------------- #
def test_unit_list_comes_from_env_and_existing_variables(tmp_path: Path) -> None:
    """`.env`'s HYSTERIA2_AUTH_SERVICE_NAME wins over deploy.sh's own default."""
    proc = _run(tmp_path, "resolve_backend_units\nsidecar_units\n")
    assert proc.returncode == 0, proc.stdout
    names = [ln for ln in proc.stdout.splitlines() if ln.endswith(".service")]
    assert names == [SUB_UNIT, HY2_UNIT], proc.stdout
    # The default name is what a hardcoded list would have produced.
    assert "vpn-bot-hy2-auth.service" not in names


def test_renamed_subscription_unit_is_followed(tmp_path: Path) -> None:
    """SUBSCRIPTION_UNIT is the single source of the endpoint's unit name."""
    proc = _run(
        tmp_path,
        "SUBSCRIPTION_UNIT=vpn-bot-sub-renamed.service\n"
        "resolve_backend_units\n"
        "sidecar_units\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "vpn-bot-sub-renamed.service" in proc.stdout
    assert SUB_UNIT not in proc.stdout.replace("vpn-bot-sub-renamed.service", "")


# --------------------------------------------------------------------------- #
# Pre-state decides whether a sidecar is restarted
# --------------------------------------------------------------------------- #
def test_active_sidecars_are_restarted(tmp_path: Path) -> None:
    """The whole point: a sidecar that was up gets the new code."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "active"},
            HY2_UNIT: {"load": "loaded", "state": "active"},
        },
    )
    assert proc.returncode == 0, proc.stdout
    assert _restarted(tmp_path) == [SUB_UNIT, HY2_UNIT], proc.stdout
    assert f"{SUB_UNIT}: restarted" in proc.stdout
    assert f"{HY2_UNIT}: restarted" in proc.stdout
    assert "CONTINUED" in proc.stdout


def test_inactive_sidecar_is_left_alone(tmp_path: Path) -> None:
    """A unit the operator stopped stays stopped — the deploy starts nothing."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "inactive"},
            HY2_UNIT: {"load": "loaded", "state": "active"},
        },
    )
    assert proc.returncode == 0, proc.stdout
    assert _restarted(tmp_path) == [HY2_UNIT], proc.stdout
    assert f"{SUB_UNIT}: skipped (was inactive)" in proc.stdout
    assert "CONTINUED" in proc.stdout


def test_failed_sidecar_is_not_resurrected(tmp_path: Path) -> None:
    """`failed` is a pre-existing fault, not something this deploy caused."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "failed"},
            HY2_UNIT: {"load": "not-found", "state": "inactive"},
        },
    )
    assert proc.returncode == 0, proc.stdout
    assert _restarted(tmp_path) == [], proc.stdout
    assert f"{SUB_UNIT}: skipped (was inactive)" in proc.stdout
    assert "ROLLBACK_NOW" not in proc.stdout


def test_absent_units_are_skipped_and_never_fail_the_deploy(tmp_path: Path) -> None:
    """Modular protocols + drift-installed units: neither present is normal."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "not-found", "state": "inactive"},
            HY2_UNIT: {"load": "not-found", "state": "inactive"},
        },
    )
    assert proc.returncode == 0, proc.stdout
    assert _restarted(tmp_path) == [], proc.stdout
    assert f"{SUB_UNIT}: skipped (absent)" in proc.stdout
    assert f"{HY2_UNIT}: skipped (absent)" in proc.stdout
    assert "ROLLBACK_NOW" not in proc.stdout
    assert "CONTINUED" in proc.stdout


def test_deploy_never_installs_or_enables_a_sidecar(tmp_path: Path) -> None:
    """The drift policy is unchanged: no install, no enable, no start."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "not-found", "state": "inactive"},
            HY2_UNIT: {"load": "loaded", "state": "inactive"},
        },
    )
    assert proc.returncode == 0, proc.stdout
    calls = (tmp_path / "systemctl.log").read_text(encoding="utf-8")
    for verb in ("enable", "start ", "link", "daemon-reload"):
        assert verb not in calls, f"unexpected `systemctl {verb}` in:\n{calls}"


# --------------------------------------------------------------------------- #
# Fatal in exactly one case
# --------------------------------------------------------------------------- #
def test_active_sidecar_that_does_not_come_back_rolls_back(tmp_path: Path) -> None:
    """Active before, dead after OUR restart: a regression this deploy caused."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "active", "after": "failed"},
            HY2_UNIT: {"load": "loaded", "state": "active"},
        },
    )
    assert proc.returncode == 9, proc.stdout
    assert "ROLLBACK_NOW" in proc.stdout
    assert SUB_UNIT in proc.stdout
    assert "active before, failed after" in proc.stdout
    # The rollback pre-empts everything downstream, hy2-auth included.
    assert _restarted(tmp_path) == [SUB_UNIT], proc.stdout
    assert "CONTINUED" not in proc.stdout


def test_restart_command_failure_is_also_a_rollback(tmp_path: Path) -> None:
    """A non-zero `systemctl restart` on a previously-active unit is the same case."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {
                "load": "loaded",
                "state": "active",
                "after": "inactive",
                "restart_rc": 1,
            },
            HY2_UNIT: {"load": "not-found", "state": "inactive"},
        },
    )
    assert proc.returncode == 9, proc.stdout
    assert "ROLLBACK_NOW" in proc.stdout
    assert "restart rc=1" in proc.stdout


def test_already_restarted_sidecars_are_named_on_the_fatal_path(tmp_path: Path) -> None:
    """The rollback restores the tree but not the sidecars we already bounced."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "active"},
            HY2_UNIT: {"load": "loaded", "state": "active", "after": "failed"},
        },
    )
    assert proc.returncode == 9, proc.stdout
    assert "restart them by hand" in proc.stdout
    assert SUB_UNIT in proc.stdout.split("restart them by hand")[0][-200:]


def test_port_that_does_not_answer_is_informational(tmp_path: Path) -> None:
    """An ACTIVE unit whose port is closed is a warn line, never a rollback."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "active"},
            HY2_UNIT: {"load": "loaded", "state": "active"},
        },
        ss_output=SS_NOTHING_BOUND,
    )
    assert proc.returncode == 0, proc.stdout
    assert "ROLLBACK_NOW" not in proc.stdout
    assert _restarted(tmp_path) == [SUB_UNIT, HY2_UNIT], proc.stdout
    assert "informational, not a deploy failure" in proc.stdout
    assert "NOT listening on 127.0.0.1:8444" in proc.stdout
    # Both are still reported as restarted — the restart itself succeeded.
    assert f"{SUB_UNIT}: restarted" in proc.stdout
    assert f"{HY2_UNIT}: restarted" in proc.stdout
    assert "CONTINUED" in proc.stdout


def test_subscription_bind_wait_is_reused_not_reimplemented(tmp_path: Path) -> None:
    """The post-restart port check goes through subscription_endpoint_status.

    Proven by its fingerprint: only that function waits out the start-to-bind
    window and says so in its message.
    """
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "active"},
            HY2_UNIT: {"load": "not-found", "state": "inactive"},
        },
        ss_output=SS_NOTHING_BOUND,
    )
    assert proc.returncode == 0, proc.stdout
    assert "start-to-bind window has passed" in proc.stdout


# --------------------------------------------------------------------------- #
# The report
# --------------------------------------------------------------------------- #
def test_report_has_one_line_per_sidecar(tmp_path: Path) -> None:
    """A half-deployed host must be visible in the deploy report."""
    proc = _run(
        tmp_path,
        SNAPSHOT_AND_RESTART,
        units={
            SUB_UNIT: {"load": "loaded", "state": "active"},
            HY2_UNIT: {"load": "not-found", "state": "inactive"},
        },
    )
    assert proc.returncode == 0, proc.stdout
    block = proc.stdout.split("sidecar units    :", 1)[1]
    assert f"    {SUB_UNIT}: restarted" in block
    assert f"    {HY2_UNIT}: skipped (absent)" in block


def test_report_block_is_safe_before_any_snapshot(tmp_path: Path) -> None:
    """set -u safety: a run that ends before Phase 1's snapshot still reports."""
    proc = _run(tmp_path, "sidecar_report_block\necho CONTINUED\n")
    assert proc.returncode == 0, proc.stdout
    assert "sidecar units    : none" in proc.stdout
    assert "CONTINUED" in proc.stdout
