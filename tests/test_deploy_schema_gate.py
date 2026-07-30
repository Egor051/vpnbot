"""Behavioural coverage for the deploy.sh schema-migration gate.

Drives the real bash functions `schema_version`, `resolve_expected_schema`, and
`verify_schema_migration` through the `DEPLOY_SELFTEST=1` seam (which sources every
definition and returns before a real deploy), with a stubbed `sqlite3` and an
instant `sleep`.

These lock in the fix for the schema-version race + dead gate + false rollback
observed on the 4d4b066 -> e025656 deploy:

* An unreadable schema is NEVER coerced to 0 (the old `[[ =~ ]] || v=0` made a
  transient SQLITE_BUSY indistinguishable from a schema that regressed to 0, which
  drove a rollback on a healthy deploy). `schema_version` now yields EMPTY on an
  unreadable read and passes the CLI a `.timeout` so a momentary busy is waited out.
* The gate waits for the DEPLOYED code's `CURRENT_SCHEMA_VERSION` (read post
  `git reset`) instead of `>= before`, so a migration that has not run yet can no
  longer masquerade as success ("30 -> 30" DEPLOY OK).
* A stuck / regressed migration rolls back; a schema NEWER than the target rolls
  back unless `ALLOW_SCHEMA_DOWNGRADE=1`; an UNREADABLE schema hard-fails (die)
  rather than rolling back on a fabricated zero.
"""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"


def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(tmp_path: Path, body: str, *, sqlite3_body: str | None = None,
         app_files: dict[str, str] | None = None, systemctl_body: str | None = None,
         journalctl_body: str | None = None) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh (selftest seam) and run `body`, with a stubbed sqlite3.

    body:            bash to execute after the seam returns (calls the function under
                     test and echoes what the assertions look for).
    sqlite3_body:    body of the fake `sqlite3` on PATH (omit when the tested function
                     never shells out to sqlite3, e.g. resolve_expected_schema).
    app_files:       repo-relative path -> contents, written under the run's CWD so a
                     function reading e.g. db/database.py sees a controlled fixture.
    systemctl_body:  body of the fake `systemctl` (the crash-loop detector reads
                     NRestarts and is-active through it). Defaults to a healthy unit
                     that never restarts, so the schema-only tests are unaffected.
    journalctl_body: body of the fake `journalctl` used for the crash-tail dump.
    """
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    # `sleep` -> instant, so the 2s poll loop never actually waits in tests.
    _make_stub(stub_dir / "sleep", "exit 0\n")
    if sqlite3_body is not None:
        _make_stub(stub_dir / "sqlite3", sqlite3_body)
    # Healthy default: NRestarts=0 forever, unit active — i.e. the crash-loop
    # detector must stay silent unless a test deliberately makes the unit flap.
    _make_stub(
        stub_dir / "systemctl",
        systemctl_body
        or 'case "$*" in *NRestarts*) echo 0;; *is-active*) echo active;; esac\nexit 0\n',
    )
    if journalctl_body is not None:
        _make_stub(stub_dir / "journalctl", journalctl_body)

    for rel, content in (app_files or {}).items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub_dir}:$PATH"\n'
        f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic for the test environment.
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        f'DB_PATH="{tmp_path}/vpn.db"\n'
        # Detect rollback vs hard fail: rollback prints a sentinel and exits 42;
        # `die` (unchanged) prints [deploy][FAIL] and exits 1.
        'rollback() { echo "ROLLBACK_CALLED"; exit 42; }\n'
        f"{body}\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path),
        capture_output=True, text=True,
    )
    # Fold stderr (warn/die/log-to-stderr) into stdout so assertions see one stream.
    proc.stdout += "\n---STDERR---\n" + proc.stderr
    return proc


# --------------------------------------------------------------------------- #
# schema_version(): empty-vs-number split + the CLI busy timeout
# --------------------------------------------------------------------------- #
def test_schema_version_reads_number_and_passes_busy_timeout(tmp_path: Path) -> None:
    args_log = tmp_path / "sqlite3.args"
    proc = _run(
        tmp_path,
        'echo "OUT=[$(schema_version)]"\n',
        sqlite3_body=f'echo "$@" >> "{args_log}"\necho 31\n',
    )
    assert proc.returncode == 0, proc.stdout
    assert "OUT=[31]" in proc.stdout
    # The CLI busy-wait MUST be passed so a transient SQLITE_BUSY (default CLI
    # busy_timeout is 0) is ridden out, matching the bot's PRAGMA busy_timeout=5000.
    assert ".timeout 5000" in args_log.read_text()


def test_schema_version_unreadable_is_empty_not_zero(tmp_path: Path) -> None:
    """An unreadable read must yield EMPTY, never a coerced 0 — that coercion was
    the root of the false rollback on a healthy deploy."""
    proc = _run(
        tmp_path,
        'v="$(schema_version)"; echo "OUT=[$v]"\n',
        sqlite3_body="exit 1\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "OUT=[]" in proc.stdout
    assert "OUT=[0]" not in proc.stdout


# --------------------------------------------------------------------------- #
# resolve_expected_schema(): the gate's target comes from the deployed code
# --------------------------------------------------------------------------- #
def test_resolve_expected_schema_reads_current_constant(tmp_path: Path) -> None:
    proc = _run(
        tmp_path,
        'resolve_expected_schema; echo "EXPECT=[$SCHEMA_EXPECT]"\n',
        app_files={"db/database.py": "CURRENT_SCHEMA_VERSION = 31\n"},
    )
    assert proc.returncode == 0, proc.stdout
    assert "EXPECT=[31]" in proc.stdout


def test_resolve_expected_schema_anchored_to_line_start(tmp_path: Path) -> None:
    """Only a top-level `^CURRENT_SCHEMA_VERSION =` assignment counts; a comment or
    an indented/attribute reference must not be matched (exactly-one rule holds)."""
    proc = _run(
        tmp_path,
        'resolve_expected_schema; echo "EXPECT=[$SCHEMA_EXPECT]"\n',
        app_files={"db/database.py": (
            "# CURRENT_SCHEMA_VERSION = 99 (historical note)\n"
            "CURRENT_SCHEMA_VERSION = 31\n"
            "    CURRENT_SCHEMA_VERSION = 7  # indented, not top-level\n"
        )},
    )
    assert proc.returncode == 0, proc.stdout
    assert "EXPECT=[31]" in proc.stdout


def test_resolve_expected_schema_zero_matches_hard_fails(tmp_path: Path) -> None:
    """Constant renamed/moved -> hard fail with an explicit message, never a silent
    default and never a rollback."""
    proc = _run(
        tmp_path,
        'resolve_expected_schema; echo "NOTREACHED SCHEMA_EXPECT=[$SCHEMA_EXPECT]"\n',
        app_files={"db/database.py": "SOME_OTHER = 1\n"},
    )
    assert proc.returncode == 1, proc.stdout          # die -> exit 1 (not 42)
    assert "found 0" in proc.stdout
    assert "NOTREACHED" not in proc.stdout
    assert "ROLLBACK_CALLED" not in proc.stdout


def test_resolve_expected_schema_multiple_matches_hard_fails(tmp_path: Path) -> None:
    """Ambiguous target (>1 match) -> hard fail, never guess which one is live."""
    proc = _run(
        tmp_path,
        'resolve_expected_schema; echo "NOTREACHED"\n',
        app_files={"db/database.py": (
            "CURRENT_SCHEMA_VERSION = 31\n"
            "CURRENT_SCHEMA_VERSION = 32\n"
        )},
    )
    assert proc.returncode == 1, proc.stdout
    assert "found 2" in proc.stdout
    assert "NOTREACHED" not in proc.stdout
    assert "ROLLBACK_CALLED" not in proc.stdout


# --------------------------------------------------------------------------- #
# verify_schema_migration(): poll-until-target, then gate on the ACTUAL value
# --------------------------------------------------------------------------- #
def test_verify_waits_and_passes_when_migration_reaches_target(tmp_path: Path) -> None:
    """Migration lands on the 3rd poll -> deploy passes, prints the actual value,
    does not roll back. Proves it POLLS (not a single read that races bootstrap)."""
    cnt = tmp_path / "cnt"
    calls = tmp_path / "calls"
    proc = _run(
        tmp_path,
        "SCHEMA_WAIT_TIMEOUT=60\n"
        "verify_schema_migration 31\n"
        'echo "AFTER=[$SCHEMA_AFTER]"\n',
        sqlite3_body=(
            f'echo x >> "{calls}"\n'
            f'c=$(cat "{cnt}" 2>/dev/null || echo 0); c=$((c + 1)); echo "$c" > "{cnt}"\n'
            "if (( c >= 3 )); then echo 31; else echo 30; fi\n"
        ),
    )
    assert proc.returncode == 0, proc.stdout
    assert "AFTER=[31]" in proc.stdout
    assert "ROLLBACK_CALLED" not in proc.stdout
    assert "[deploy][FAIL]" not in proc.stdout
    # schema_version ran 3 times -> the gate waited across polls, not one read.
    assert len(calls.read_text().split()) == 3


def test_verify_rolls_back_when_migration_never_reaches_target(tmp_path: Path) -> None:
    """Schema stuck below the target after the timeout -> rollback with a message
    naming the target and where it stalled."""
    proc = _run(
        tmp_path,
        "SCHEMA_WAIT_TIMEOUT=0\n"
        "verify_schema_migration 31\n"
        'echo "NOTREACHED"\n',
        sqlite3_body="echo 30\n",
    )
    assert proc.returncode == 42, proc.stdout          # rollback stub exit code
    assert "ROLLBACK_CALLED" in proc.stdout
    assert "did not reach 31" in proc.stdout
    assert "stuck at 30" in proc.stdout
    assert "NOTREACHED" not in proc.stdout


def test_verify_rolls_back_on_regression_below_before(tmp_path: Path) -> None:
    """A DB that went backwards (after < before <= expected) still rolls back, as
    the pre-fix `>= SCHEMA_BEFORE` gate did — now via the 'did not reach' branch."""
    proc = _run(
        tmp_path,
        "SCHEMA_BEFORE=31\n"            # was 31 before; live read regresses to 30
        "SCHEMA_WAIT_TIMEOUT=0\n"
        "verify_schema_migration 31\n"
        'echo "NOTREACHED"\n',
        sqlite3_body="echo 30\n",
    )
    assert proc.returncode == 42, proc.stdout
    assert "ROLLBACK_CALLED" in proc.stdout
    assert "NOTREACHED" not in proc.stdout


def test_verify_hard_fails_on_unreadable_schema_not_rollback(tmp_path: Path) -> None:
    """sqlite3 unavailable / empty read -> HARD FAIL (die, exit 1), never a silent
    rollback on a coerced zero. This is the defence-in-depth backstop."""
    proc = _run(
        tmp_path,
        "SCHEMA_WAIT_TIMEOUT=0\n"
        "verify_schema_migration 31\n"
        'echo "NOTREACHED"\n',
        sqlite3_body="exit 1\n",
    )
    assert proc.returncode == 1, proc.stdout           # die -> exit 1, NOT 42
    assert "ROLLBACK_CALLED" not in proc.stdout
    assert "unreadable" in proc.stdout
    assert "NOTREACHED" not in proc.stdout


def test_verify_rolls_back_when_schema_newer_than_target(tmp_path: Path) -> None:
    """Live schema newer than the deployed target (downgrade/foreign) -> rollback
    by default, pointing at the ALLOW_SCHEMA_DOWNGRADE override."""
    proc = _run(
        tmp_path,
        "ALLOW_SCHEMA_DOWNGRADE=0\n"
        "SCHEMA_WAIT_TIMEOUT=0\n"
        "verify_schema_migration 31\n"
        'echo "NOTREACHED"\n',
        sqlite3_body="echo 32\n",
    )
    assert proc.returncode == 42, proc.stdout
    assert "ROLLBACK_CALLED" in proc.stdout
    assert "newer than the deployed code target 31" in proc.stdout
    assert "ALLOW_SCHEMA_DOWNGRADE=1" in proc.stdout
    assert "NOTREACHED" not in proc.stdout


def test_verify_allows_deliberate_downgrade_with_flag(tmp_path: Path) -> None:
    """ALLOW_SCHEMA_DOWNGRADE=1 lets a newer-than-target schema through (deliberate
    rollback to an older, forward-compatible release) without a rollback."""
    proc = _run(
        tmp_path,
        "ALLOW_SCHEMA_DOWNGRADE=1\n"
        "SCHEMA_WAIT_TIMEOUT=0\n"
        "verify_schema_migration 31\n"
        'echo "AFTER=[$SCHEMA_AFTER]"\n',
        sqlite3_body="echo 32\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "ROLLBACK_CALLED" not in proc.stdout
    assert "AFTER=[32]" in proc.stdout
    assert "proceeding with the downgrade" in proc.stdout


# --------------------------------------------------------------------------- #
# Crash-loop detection DURING the schema wait
#
# The v32 -> v33 deploy: bootstrap() raised inside the baseline DDL, systemd
# restarted the bot 17 times, and the gate — which sampled NRestarts exactly once,
# ~7s after start and therefore BEFORE the first crash — saw NRestarts=0, called it
# healthy, then waited out the whole schema window and rolled back with "schema
# migration did not reach 33". True, and useless: the schema was never going to
# move because the process was dying, and the traceback that said so was in the
# journal nobody printed.
# --------------------------------------------------------------------------- #
_FLAPPING_SYSTEMCTL = """\
case "$*" in
  *NRestarts*)
    c=$(cat "$CNT" 2>/dev/null || echo 0); c=$((c + 1)); echo "$c" > "$CNT"
    # First call is verify_schema_migration's baseline read (still 0); every poll
    # after it sees the counter climb, exactly like a unit systemd keeps restarting.
    if (( c >= 2 )); then echo $((c - 1)); else echo 0; fi
    ;;
  *is-active*) echo activating;;
esac
exit 0
"""


def test_verify_aborts_early_when_bot_crash_loops(tmp_path: Path) -> None:
    """A climbing NRestarts short-circuits the wait on the very next poll and rolls
    back naming the restarts — instead of burning SCHEMA_WAIT_TIMEOUT first."""
    cnt = tmp_path / "nrestarts.cnt"
    calls = tmp_path / "sqlite.calls"
    proc = _run(
        tmp_path,
        f'export CNT="{cnt}"\n'
        "SCHEMA_WAIT_TIMEOUT=30\n"           # a wait that is NOT aborted would poll ~15 times
        "verify_schema_migration 33\n"
        'echo "NOTREACHED"\n',
        sqlite3_body=f'echo x >> "{calls}"\necho 32\n',
        systemctl_body=_FLAPPING_SYSTEMCTL,
    )
    assert proc.returncode == 42, proc.stdout          # rollback stub exit code
    assert "ROLLBACK_CALLED" in proc.stdout
    assert "restarted 1 time(s) during the schema wait" in proc.stdout
    assert "NOTREACHED" not in proc.stdout
    # Aborted on the FIRST poll: one schema read, not a full window of them.
    assert len(calls.read_text().split()) == 1
    # And it says why the schema never moved, rather than blaming the migration.
    assert "not staying up" in proc.stdout


def test_verify_crash_abort_prints_the_journal_tail(tmp_path: Path) -> None:
    """The whole point of aborting early: the operator gets the real traceback."""
    cnt = tmp_path / "nrestarts.cnt"
    proc = _run(
        tmp_path,
        f'export CNT="{cnt}"\n'
        'DEPLOY_START="2026-07-30 10:00:00"\n'
        "SCHEMA_WAIT_TIMEOUT=30\n"
        "verify_schema_migration 33\n",
        sqlite3_body="echo 32\n",
        systemctl_body=_FLAPPING_SYSTEMCTL,
        journalctl_body=(
            'echo "args: $*"\n'
            'echo "  File \\"db/database.py\\", line 114, in bootstrap"\n'
            'echo "sqlite3.OperationalError: no such column: display_no"\n'
        ),
    )
    assert proc.returncode == 42, proc.stdout
    assert "sqlite3.OperationalError: no such column: display_no" in proc.stdout
    # Scoped to this deploy and to the bot unit.
    assert "--since 2026-07-30 10:00:00" in proc.stdout
    assert "-u vpn-bot.service" in proc.stdout


def test_verify_aborts_when_unit_sits_in_failed_state(tmp_path: Path) -> None:
    """A unit that exhausted its start limit stops flapping, so NRestarts freezes
    while the bot is definitively down. `failed` is caught on its own."""
    proc = _run(
        tmp_path,
        "SCHEMA_WAIT_TIMEOUT=30\n"
        "verify_schema_migration 33\n"
        'echo "NOTREACHED"\n',
        sqlite3_body="echo 32\n",
        systemctl_body='case "$*" in *NRestarts*) echo 5;; *is-active*) echo failed;; esac\nexit 0\n',
    )
    assert proc.returncode == 42, proc.stdout
    assert "in failed state during the schema wait" in proc.stdout
    assert "NOTREACHED" not in proc.stdout


def test_verify_compares_restarts_against_the_baseline_not_zero(tmp_path: Path) -> None:
    """A unit carrying restarts from an earlier incident, but stable NOW, must not
    trip the detector — otherwise the gate rolls back healthy deploys."""
    proc = _run(
        tmp_path,
        "SCHEMA_WAIT_TIMEOUT=60\n"
        "verify_schema_migration 33\n"
        'echo "AFTER=[$SCHEMA_AFTER]"\n',
        sqlite3_body="echo 33\n",
        systemctl_body='case "$*" in *NRestarts*) echo 7;; *is-active*) echo active;; esac\nexit 0\n',
    )
    assert proc.returncode == 0, proc.stdout
    assert "AFTER=[33]" in proc.stdout
    assert "ROLLBACK_CALLED" not in proc.stdout


def test_verify_does_not_abort_while_a_healthy_bot_migrates(tmp_path: Path) -> None:
    """A long migration on a healthy unit still gets its full wait: the detector
    must not turn a slow bootstrap into a rollback."""
    cnt = tmp_path / "polls.cnt"
    proc = _run(
        tmp_path,
        "SCHEMA_WAIT_TIMEOUT=60\n"
        "verify_schema_migration 33\n"
        'echo "AFTER=[$SCHEMA_AFTER]"\n',
        sqlite3_body=(
            f'c=$(cat "{cnt}" 2>/dev/null || echo 0); c=$((c + 1)); echo "$c" > "{cnt}"\n'
            "if (( c >= 4 )); then echo 33; else echo 32; fi\n"
        ),
    )
    assert proc.returncode == 0, proc.stdout
    assert "AFTER=[33]" in proc.stdout
    assert "ROLLBACK_CALLED" not in proc.stdout


def test_bot_journal_tail_caps_the_number_of_lines(tmp_path: Path) -> None:
    """The dump is bounded — enough for a traceback, not the whole journal."""
    proc = _run(
        tmp_path,
        "CRASH_JOURNAL_LINES=5\n"
        'bot_journal_tail | wc -l\n',
        journalctl_body='seq 1 100\n',
    )
    assert proc.returncode == 0, proc.stdout
    assert "5" in proc.stdout.split("---STDERR---")[0].split()


def test_bot_journal_tail_is_silent_without_journalctl(tmp_path: Path) -> None:
    """No journalctl on the host (or an empty journal) must not abort the deploy
    under `set -e` — the crash message is still worth printing on its own."""
    proc = _run(
        tmp_path,
        'PATH="/nonexistent"; out="$(bot_journal_tail)"; echo "RC=$? OUT=[$out]"\n',
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=0 OUT=[]" in proc.stdout
