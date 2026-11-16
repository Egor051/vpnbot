"""A rollback restarts the sidecars the deploy restarted — onto the restored code.

``restart_sidecar_units`` bounces vpn-bot-subscription / hy2-auth onto the new code
once the bot is up. A rollback after that point (a log-scan hit, a failing PR hook,
the second sidecar failing after the first came back) used to restore the tree, the
venv and the DB and leave both sidecars running the NEW code out of memory — the
half-deployed host of 2026-08-08, produced by the rollback this time.

Pinned here by driving the REAL ``rollback()`` through the ``DEPLOY_SELFTEST=1`` seam,
with ``systemctl`` / ``git`` / ``ss`` / ``sleep`` stubbed and one shared call log, so
the ORDER of what the rollback does is visible:

1. **Exactly the restarted units.** Every sidecar ``restart_sidecar_units`` asked
   systemd to restart is restarted again; an absent or inactive one is never touched.
2. **After the tree and the venv** (and the DB, and the bot start): never on the new
   code still on disk.
3. **The same checks** as the deploy's restart: ``wait_unit_active``, then
   ``subscription_endpoint_status`` (its start-to-bind window) / ``hy2_auth_listen_status``.
4. **A failure is a loud report line, nothing more**: no second rollback, no retry, no
   loop; the bot is still started and the next sidecar still handled.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

# Every wait runs against a stubbed `sleep`: anything near this is a hang.
pytestmark = pytest.mark.timeout(60)

SUB = "vpn-bot-subscription.service"
HY2 = "vpnbot-hy2-auth.service"
BOT = "vpn-bot.service"

ENV_FIXTURE = """\
SUBSCRIPTION_ENABLED=true
SUBSCRIPTION_BIND_HOST=127.0.0.1
SUBSCRIPTION_BIND_PORT=8445
SUBSCRIPTION_PUBLIC_PORT=2096
HYSTERIA2_AUTH_SERVICE_NAME=vpnbot-hy2-auth
HYSTERIA2_AUTH_LISTEN=127.0.0.1:8444
"""

SS_ALL_BOUND = (
    "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
    "LISTEN 0      128        127.0.0.1:8445       0.0.0.0:*\n"
    "LISTEN 0      128                *:2096             *:*\n"
    "LISTEN 0      128        127.0.0.1:8444       0.0.0.0:*\n"
)
SS_NOTHING_BOUND = "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"

# Per-unit files under $STATE_DIR: <unit>.load, <unit>.state, and <unit>.after — one
# state per line, the next one installed by each `restart` (so the deploy's restart
# and the rollback's can end differently). Every call goes to the shared $CALLS log.
SYSTEMCTL_STUB = r"""#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "$CALLS"
unit="${!#}"
sd="$STATE_DIR"
_state() { [[ -f "$sd/${unit}.state" ]] && cat "$sd/${unit}.state" || printf 'inactive'; }
_load()  { [[ -f "$sd/${unit}.load"  ]] && cat "$sd/${unit}.load"  || printf 'not-found'; }
case "$1" in
  restart)
    if [[ -s "$sd/${unit}.after" ]]; then
      head -n 1 "$sd/${unit}.after" > "$sd/${unit}.state"
      tail -n +2 "$sd/${unit}.after" > "$sd/${unit}.after.next"
      mv "$sd/${unit}.after.next" "$sd/${unit}.after"
    fi
    exit 0 ;;
  start) printf 'active' > "$sd/${unit}.state"; exit 0 ;;
  stop)  printf 'inactive' > "$sd/${unit}.state"; exit 0 ;;
  is-active)
    s="$(_state)"
    [[ "$2" == "--quiet" ]] || printf '%s\n' "$s"
    [[ "$s" == "active" ]] && exit 0 || exit 3 ;;
  show)
    case "$*" in
      *LoadState*)   printf '%s' "$(_load)" ;;
      *ActiveState*) printf '%s' "$(_state)" ;;
    esac
    exit 0 ;;
  *) exit 0 ;;
esac
"""


def _stub(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _run(
    tmp_path: Path,
    body: str,
    *,
    units: dict[str, tuple[str, str, list[str]]],
    ss_output: str = SS_ALL_BOUND,
) -> subprocess.CompletedProcess[str]:
    """units: name -> (LoadState, ActiveState, states installed by successive restarts)."""
    stub = tmp_path / "stub"
    stub.mkdir()
    state = tmp_path / "units"
    state.mkdir()
    calls = tmp_path / "calls.log"
    _stub(stub / "systemctl", SYSTEMCTL_STUB)
    _stub(stub / "git", f'#!/usr/bin/env bash\necho "git $*" >> "{calls}"\nexit 0\n')
    _stub(stub / "ss", f"#!/usr/bin/env bash\ncat <<'EOF'\n{ss_output}EOF\n")
    _stub(stub / "sleep", "#!/usr/bin/env bash\nexit 0\n")
    for unit, (load, active, after) in units.items():
        (state / f"{unit}.load").write_text(load, encoding="utf-8")
        (state / f"{unit}.state").write_text(active, encoding="utf-8")
        (state / f"{unit}.after").write_text("".join(f"{s}\n" for s in after), encoding="utf-8")
    (state / f"{BOT}.load").write_text("loaded", encoding="utf-8")
    (state / f"{BOT}.state").write_text("active", encoding="utf-8")
    # The venv the snapshot step saved; its pip logs the post-restore check, so the
    # call log shows WHEN the venv came back.
    prev = tmp_path / "venv.prev" / "bin"
    prev.mkdir(parents=True)
    _stub(prev / "python", "#!/usr/bin/env bash\nexit 0\n")
    _stub(prev / "pip", f'#!/usr/bin/env bash\necho "pip $*" >> "{calls}"\nexit 0\n')
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    env_file = tmp_path / ".env"
    env_file.write_text(ENV_FIXTURE, encoding="utf-8")

    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub}:$PATH"\n'
        f'export ENV_FILE="{env_file}" STATE_DIR="{state}" CALLS="{calls}"\n'
        "export SIDECAR_ACTIVE_WAIT=4 SUBSCRIPTION_BIND_WAIT=2 HY2_AUTH_BIND_TIMEOUT=2\n"
        f'source "{DEPLOY_SH}"\n'
        'WT=""; STAGE=""\n'
        f'VENV="{tmp_path}/venv"; VENV_PREV="{tmp_path}/venv.prev"\n'
        'PREV_SHA=prevsha0000; VENV_SNAPSHOT_DONE=1; ARCHIVE=""\n'
        f'DB_PATH="{tmp_path}/data/vpn.db"; XRAY_CONF="{tmp_path}/none.json"; AWG_CONF="{tmp_path}/none.conf"\n'
        # The DB/host-file halves of the rollback have their own suites.
        "fix_db_perms() { return 0; }\n"
        "assert_db_ownership() { echo 'ok'; }\n"
        "assert_restore_permissions() { echo 'ok'; }\n"
        "host_files_rollback() { :; }\n"
        "resolve_backend_units\n"
        "snapshot_sidecar_units\n"
        f"{body}\n",
        encoding="utf-8",
    )
    return subprocess.run(["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True)


def _calls(tmp_path: Path) -> list[str]:
    return (tmp_path / "calls.log").read_text(encoding="utf-8").splitlines()


def _restarts(tmp_path: Path, unit: str) -> list[int]:
    return [i for i, c in enumerate(_calls(tmp_path)) if c == f"systemctl restart {unit}"]


def _index(tmp_path: Path, call: str) -> int:
    return _calls(tmp_path).index(call)


# A rollback that comes AFTER the sidecar step succeeded: the log scan.
LATE_ROLLBACK = 'restart_sidecar_units\nrollback_now "vpn-bot logged errors after start (test)"\n'


# --------------------------------------------------------------------------- #
# Exactly the restarted units, after the tree and the venv
# --------------------------------------------------------------------------- #
def test_rollback_restarts_every_sidecar_the_deploy_restarted(tmp_path: Path) -> None:
    proc = _run(
        tmp_path,
        LATE_ROLLBACK,
        units={SUB: ("loaded", "active", ["active", "active"]), HY2: ("loaded", "active", ["active", "active"])},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "ROLLBACK REPORT" in proc.stderr
    sub, hy2 = _restarts(tmp_path, SUB), _restarts(tmp_path, HY2)
    assert len(sub) == 2 and len(hy2) == 2, _calls(tmp_path)
    tree = _index(tmp_path, "git checkout --quiet --force -B main prevsha0000")
    venv = _index(tmp_path, "pip check")
    bot = _index(tmp_path, f"systemctl start {BOT}")
    # The deploy's restarts come before the rollback; the rollback's after the tree,
    # the venv and the bot start — in the deploy's own order.
    assert sub[0] < hy2[0] < tree < venv < bot < sub[1] < hy2[1]
    assert f"sidecar {SUB}: restarted back onto prevsha0000 — active; " in proc.stderr
    assert f"sidecar {HY2}: restarted back onto prevsha0000 — active; listening on 127.0.0.1:8444" in proc.stderr
    assert "SIDECAR NOT RESTORED" not in proc.stderr


def test_rollback_restarts_only_what_was_restarted(tmp_path: Path) -> None:
    """An inactive sidecar was never restarted: the rollback does not start it."""
    proc = _run(
        tmp_path,
        LATE_ROLLBACK,
        units={SUB: ("loaded", "inactive", []), HY2: ("loaded", "active", ["active", "active"])},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert _restarts(tmp_path, SUB) == []
    assert len(_restarts(tmp_path, HY2)) == 2
    assert not any(c.startswith("systemctl start") and SUB in c for c in _calls(tmp_path))
    assert f"sidecar {HY2}: restarted back onto prevsha0000" in proc.stderr
    assert f"sidecar {SUB}:" not in proc.stderr


def test_absent_sidecars_are_never_touched(tmp_path: Path) -> None:
    proc = _run(
        tmp_path,
        LATE_ROLLBACK,
        units={SUB: ("not-found", "inactive", []), HY2: ("not-found", "inactive", [])},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert _restarts(tmp_path, SUB) == [] and _restarts(tmp_path, HY2) == []
    assert "sidecar units: none was restarted by this deploy — nothing to put back" in proc.stderr


def test_rollback_before_the_sidecar_step_restarts_nothing(tmp_path: Path) -> None:
    """A rollback from the schema gate, say: the sidecars still run the old code."""
    proc = _run(
        tmp_path,
        'rollback_now "schema migration did not reach 40 (test)"\n',
        units={SUB: ("loaded", "active", ["active"]), HY2: ("loaded", "active", ["active"])},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert _restarts(tmp_path, SUB) == [] and _restarts(tmp_path, HY2) == []
    assert "none was restarted by this deploy" in proc.stderr


def test_second_sidecar_failing_puts_both_back(tmp_path: Path) -> None:
    """The deploy's own fatal path: SUB came back, HY2 did not -> both restarted again."""
    proc = _run(
        tmp_path,
        "restart_sidecar_units\necho CONTINUED\n",
        units={SUB: ("loaded", "active", ["active", "active"]), HY2: ("loaded", "active", ["failed", "active"])},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "CONTINUED" not in proc.stdout
    assert f"{HY2} did not come back from the deploy restart" in proc.stderr
    assert "the rollback restarts them again once the tree and the venv are back on prevsha0000" in proc.stderr
    assert len(_restarts(tmp_path, SUB)) == 2 and len(_restarts(tmp_path, HY2)) == 2
    assert f"sidecar {SUB}: restarted back onto prevsha0000" in proc.stderr
    assert f"sidecar {HY2}: restarted back onto prevsha0000" in proc.stderr


# --------------------------------------------------------------------------- #
# A failure is loud, and only that
# --------------------------------------------------------------------------- #
def test_failed_rollback_restart_is_loud_and_never_loops(tmp_path: Path) -> None:
    proc = _run(
        tmp_path,
        LATE_ROLLBACK,
        units={SUB: ("loaded", "active", ["active", "failed"]), HY2: ("loaded", "active", ["active", "active"])},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert (
        f"!!! SIDECAR NOT RESTORED: {SUB} did not come back after the rollback restart (failed after 4s, "
        "systemctl restart rc=0)" in proc.stderr
    )
    assert f"MANUAL ACTION REQUIRED: systemctl restart {SUB}" in proc.stderr
    # One try, no second rollback.
    assert len(_restarts(tmp_path, SUB)) == 2
    assert proc.stderr.count("ROLLBACK: restoring PREV_SHA") == 1
    assert proc.stderr.count("===== ROLLBACK REPORT =====") == 1
    # The rest of the rollback still happened: the bot, and the next sidecar.
    assert "vpn-bot is-active: yes" in proc.stderr
    assert f"sidecar {HY2}: restarted back onto prevsha0000" in proc.stderr


def test_rollback_port_checks_are_the_deploys_and_informational(tmp_path: Path) -> None:
    proc = _run(
        tmp_path,
        LATE_ROLLBACK,
        units={SUB: ("loaded", "active", ["active", "active"]), HY2: ("loaded", "active", ["active", "active"])},
        ss_output=SS_NOTHING_BOUND,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    lines = [ln for ln in proc.stderr.splitlines() if "restarted back onto" in ln]
    assert len(lines) == 2, proc.stderr
    sub_line = next(ln for ln in lines if SUB in ln)
    hy2_line = next(ln for ln in lines if HY2 in ln)
    # subscription_endpoint_status's own fingerprint (its start-to-bind window) ...
    assert "start-to-bind window has passed" in sub_line and sub_line.endswith("(informational)")
    # ... and hy2_auth_listen_status's.
    assert "NOT listening on 127.0.0.1:8444 within 2s" in hy2_line and hy2_line.endswith("(informational)")
    assert "SIDECAR NOT RESTORED" not in proc.stderr


# --------------------------------------------------------------------------- #
# Shape of the code
# --------------------------------------------------------------------------- #
def _body(text: str, header: str) -> str:
    start = text.index(header)
    return text[start : text.index("\n}\n", start)]


def test_rollback_calls_it_after_the_bot_start() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    rb = _body(text, "\nrollback() {")
    tree = rb.index('restore_tree_to "$PREV_SHA"')
    venv = rb.index('mv "$VENV_PREV" "$VENV"')
    db = rb.index("restore_archive_into_root")
    start = rb.index('systemctl start "$BOT_UNIT"')
    sidecars = rb.index("rollback_restart_sidecars")
    assert tree < venv < db < start < sidecars


def test_the_rollback_restart_never_rolls_back_again() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    body = _body(text, "\nrollback_restart_sidecars() {")
    assert "rollback_now" not in body and "rollback;" not in body
    assert "wait_unit_active" in body
    assert "subscription_endpoint_status" in body and "hy2_auth_listen_status" in body
    # The record is taken before the restart is asked for.
    rs = _body(text, "\nrestart_sidecar_units() {")
    assert rs.index('SIDECAR_RESTARTED+=("$u")') < rs.index('systemctl restart "$u"')
