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
         app_files: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh (selftest seam) and run `body`, with a stubbed sqlite3.

    body:         bash to execute after the seam returns (calls the function under
                  test and echoes what the assertions look for).
    sqlite3_body: body of the fake `sqlite3` on PATH (omit when the tested function
                  never shells out to sqlite3, e.g. resolve_expected_schema).
    app_files:    repo-relative path -> contents, written under the run's CWD so a
                  function reading e.g. db/database.py sees a controlled fixture.
    """
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    # `sleep` -> instant, so the 2s poll loop never actually waits in tests.
    _make_stub(stub_dir / "sleep", "exit 0\n")
    if sqlite3_body is not None:
        _make_stub(stub_dir / "sqlite3", sqlite3_body)

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
