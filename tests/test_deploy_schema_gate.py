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

Hermeticity
-----------
Every host command these functions can reach is stubbed on PATH (`sqlite3`,
`systemctl`, `journalctl`, `sleep`); nothing here reads the state of the machine
running the tests. That rule was learned the hard way: `journalctl` was stubbed
only when a test opted in, so the crash-abort tests ran the host's real journalctl
against the host's real vpn-bot.service. On CI — an empty journal — they passed in
milliseconds. On the production host they read days of logs at 100% CPU and never
finished, so the deploy's own test gate became the thing blocking the deploy.
"""

import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

# Per-test wall-clock ceiling (pytest-timeout). Every test in this module drives
# bash through stubs with an instant `sleep`, so a healthy run is milliseconds —
# anything approaching this limit is a hang, not slow work. Belt-and-braces only:
# the actual defence against a hang is that the harness stubs EVERY host command
# (see `_run`), so nothing here can read host state in the first place. Without
# this marker a wedged shell-out eats the whole pytest run instead of failing one
# test, which is how an unbounded `journalctl` read blocked a production deploy.
TEST_TIMEOUT_SECONDS = 60

# Where the fake `journalctl` records its argv, relative to a test's tmp_path.
JOURNALCTL_ARGS = "journalctl.args"

# Any bounding flag that stops journalctl reading the journal from the head, as it
# appears in a RECORDED ARGV (the shell has already expanded it, so the value is
# literal digits): `-n N` / `--lines N` / `--lines=N`. `--since` alone does NOT
# count — it filters, but the abort path must also cap the entry count.
JOURNAL_LINE_CAP_RE = re.compile(r"(?:^|\s)(?:-n\s+\d+|--lines(?:[=\s])\d+)(?:\s|$)")

pytestmark = pytest.mark.timeout(TEST_TIMEOUT_SECONDS)


def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _journalctl_stub(args_log: Path, body: str) -> str:
    """Body of the fake `journalctl`: record the exact argv, then behave like the
    real thing with respect to `-n`.

    Honouring `-n` matters. A stub that ignored it would make "the dump is capped"
    assertions vacuous — they would pass just as happily against a caller that read
    the whole journal and trimmed afterwards, which is exactly the bug this module
    now guards. Here the canned journal comes back IN FULL unless the caller asked
    journalctl itself to cap it.
    """
    return (
        f'printf "%s\\n" "$*" >> "{args_log}"\n'
        '_n=""; _prev=""\n'
        'for _a in "$@"; do\n'
        '  case "$_prev" in -n|--lines) _n="$_a";; esac\n'
        '  case "$_a" in --lines=*) _n="${_a#--lines=}";; esac\n'
        '  _prev="$_a"\n'
        "done\n"
        "_journal() {\n"
        f"{body}"
        "}\n"
        'if [[ "$_n" =~ ^[0-9]+$ ]]; then _journal | tail -n "$_n"; else _journal; fi\n'
        "exit 0\n"
    )


def _journalctl_calls(tmp_path: Path) -> list[str]:
    """Every `journalctl` argv the run produced, one string per invocation."""
    log = tmp_path / JOURNALCTL_ARGS
    if not log.exists():
        return []
    return [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _run(tmp_path: Path, body: str, *, sqlite3_body: str | None = None,
         app_files: dict[str, str] | None = None, systemctl_body: str | None = None,
         journalctl_body: str | None = None) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh (selftest seam) and run `body` against stubbed host tools.

    EVERY host command deploy.sh can reach from these functions is stubbed on PATH:
    `sqlite3`, `systemctl`, `journalctl` and `sleep`. That is not tidiness, it is the
    contract — a shell-function test must not depend on the state of the machine it
    runs on. `journalctl` used to be the exception (stubbed only when a test passed
    `journalctl_body`), so the crash-abort tests shelled out to the host's REAL
    journalctl for the REAL vpn-bot.service. In CI that is an empty journal and the
    tests pass in milliseconds; on the production host it is days of logs and the
    test wedges, which is how this suite blocked a deploy instead of guarding one.

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
                     Defaults to an empty journal; the argv is always recorded to
                     `tmp_path/JOURNALCTL_ARGS` whether or not a body is given.
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
    # ALWAYS stubbed — never conditional on the test asking for a body. `:` is an
    # empty journal, the honest default for a host with nothing logged.
    _make_stub(
        stub_dir / "journalctl",
        _journalctl_stub(tmp_path / JOURNALCTL_ARGS, journalctl_body or ":\n"),
    )

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
        # A hang here must fail THIS test, not hold the pytest process open, even
        # when pytest-timeout is not installed. Generous next to a millisecond run.
        timeout=TEST_TIMEOUT_SECONDS,
    )
    # Whatever the test under way is about, no run in this module may ask journald
    # to read from the head of the journal — that cost is what wedged the deploy.
    # Asserting it here (rather than in one dedicated test) means a future function
    # that grows an unbounded read is caught by whichever test first reaches it.
    for call in _journalctl_calls(tmp_path):
        assert JOURNAL_LINE_CAP_RE.search(call), (
            f"unbounded journalctl read: `journalctl {call}` has no -n/--lines cap. "
            "Without one journald reads the unit's journal from the head; on a host "
            "with days of logs that is minutes of CPU on a path that runs while the "
            "bot is already crashing. Bound it at the journalctl call, not with a "
            "later $(...)/`| tail` trim of a full read."
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
    # This test is the one that wedged production: it takes the crash path, which
    # dumps the journal. It must have gone through the STUB (proof: an argv was
    # recorded at all) and the read must have been capped — `_run` asserts the cap
    # on every call, so a bare `journalctl -u vpn-bot.service` fails here now.
    assert _journalctl_calls(tmp_path), "the crash abort never dumped the journal"


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
            'echo "  File \\"db/database.py\\", line 114, in bootstrap"\n'
            'echo "sqlite3.OperationalError: no such column: display_no"\n'
        ),
    )
    assert proc.returncode == 42, proc.stdout
    assert "sqlite3.OperationalError: no such column: display_no" in proc.stdout
    # Scoped to this deploy, to the bot unit, and — the point of this PR — capped
    # at the journalctl call so journald seeks to the tail instead of reading the
    # unit's whole journal (`_run` enforces the cap on every recorded call).
    (args,) = _journalctl_calls(tmp_path)
    assert "--since 2026-07-30 10:00:00" in args
    assert "-u vpn-bot.service" in args
    assert "-n 40" in args, args        # CRASH_JOURNAL_LINES default


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
    # The other crash-abort path, and the other test that used to shell out to the
    # host's real journalctl. Same contract: stubbed, and capped.
    assert _journalctl_calls(tmp_path), "the failed-state abort never dumped the journal"


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


# --------------------------------------------------------------------------- #
# bot_journal_tail(): the cap is asked of journalctl, not applied afterwards
#
# The crash path runs when the bot is ALREADY down and an operator is waiting on
# the traceback, so it has no budget to spend. Reading the unit's whole journal and
# trimming the result is O(journal): on the production host — 1 CPU, a journal kept
# since 29 July, an observer logging every ~3s — a single such read pinned a core
# at ~98% and did not finish inside a 60s test timeout. `-n` makes journald seek to
# the tail and walk back N entries instead, which costs the same on any host.
# --------------------------------------------------------------------------- #
def test_bot_journal_tail_asks_journalctl_for_the_cap(tmp_path: Path) -> None:
    """The regression guard. The stub returns its canned journal IN FULL unless
    journalctl itself was told to cap, so a `$(...)`-then-`tail` implementation
    fails here on the line count even though its final output looks identical."""
    proc = _run(
        tmp_path,
        "CRASH_JOURNAL_LINES=5\n"
        "bot_journal_tail | wc -l\n",
        journalctl_body="seq 1 100\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "5" in proc.stdout.split("---STDERR---")[0].split()
    # ... and the cap travelled as an argument, with no unbounded read anywhere.
    (args,) = _journalctl_calls(tmp_path)
    assert "-n 5" in args, args


def test_bot_journal_tail_caps_even_without_a_deploy_window(tmp_path: Path) -> None:
    """The DEPLOY_START-less branch — the one the crash-abort tests take, and the
    one that ran unbounded against the production journal — is capped too. Its only
    bound IS `-n`: with no deploy window there is no `--since` to lean on."""
    proc = _run(
        tmp_path,
        'DEPLOY_START=""\n'
        "bot_journal_tail | wc -l\n",
        journalctl_body="seq 1 100\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "40" in proc.stdout.split("---STDERR---")[0].split()   # CRASH_JOURNAL_LINES
    (args,) = _journalctl_calls(tmp_path)
    assert "-n 40" in args, args
    assert "--since" not in args, args


def test_bot_journal_tail_falls_back_on_a_junk_line_knob(tmp_path: Path) -> None:
    """CRASH_JOURNAL_LINES is an env knob. A non-numeric value must not reach `-n`:
    journalctl would reject it, stderr is silenced, and the crash dump would come
    back EMPTY at the one moment it is the whole point of the abort."""
    proc = _run(
        tmp_path,
        'CRASH_JOURNAL_LINES="all the lines"\n'
        "bot_journal_tail | wc -l\n",
        journalctl_body="seq 1 100\n",
    )
    assert proc.returncode == 0, proc.stdout
    assert "40" in proc.stdout.split("---STDERR---")[0].split()
    (args,) = _journalctl_calls(tmp_path)
    assert "-n 40" in args, args


def test_bot_journal_tail_is_silent_without_journalctl(tmp_path: Path) -> None:
    """No journalctl on the host (or an empty journal) must not abort the deploy
    under `set -e` — the crash message is still worth printing on its own."""
    proc = _run(
        tmp_path,
        'PATH="/nonexistent"; out="$(bot_journal_tail)"; echo "RC=$? OUT=[$out]"\n',
    )
    assert proc.returncode == 0, proc.stdout
    assert "RC=0 OUT=[]" in proc.stdout


# --------------------------------------------------------------------------- #
# Static guard: no unbounded journal read anywhere in deploy.sh
#
# The functional tests above cover the crash path because that is the path that
# bit us. This covers the ones nobody has written a test for yet: any `journalctl`
# deploy.sh grows from here must bound its read at the call, by entry count (`-n`)
# or by time (`--since`), so journald seeks instead of walking the journal from the
# head. Same shape as the SIGPIPE static guard in test_deploy_sigpipe_guard.py.
# --------------------------------------------------------------------------- #
# `journalctl` in COMMAND position: at the start of a line or right after a shell
# separator (`|`, `&&`, `;`, `(`, `$(`). This is what distinguishes an invocation
# from a mention — `require_tools ... date journalctl stat` names the binary in a
# tool list and `command -v journalctl` only probes for it; neither reads anything.
JOURNALCTL_CALL_RE = re.compile(r"(?:^|[|&;(]|\$\()\s*journalctl\b")
# The same caps as JOURNAL_LINE_CAP_RE but read from SOURCE, where the count is
# usually still a shell expansion (`-n "$lines"`) rather than a literal.
JOURNAL_LINE_CAP_SRC_RE = re.compile(r"(?:^|\s)(?:-n|--lines)[=\s]+(?:\d+|\"?\$\{?\w+)")
JOURNAL_TIME_BOUND_RE = re.compile(r"--since[=\s]")


def _journalctl_arg_spans(line: str) -> list[str]:
    """The argument list of each `journalctl` invocation on `line`.

    Cut at the first `|`, `;` or `)` after the command word, so the bound has to be
    journalctl's OWN argument. Without that scoping a line like
    `out="$(journalctl -u x)"; printf %s "$out" | tail -n 40` would read as bounded
    because a `-n 40` appears SOMEWHERE on it — and that line is precisely the
    read-everything-then-trim shape this guard exists to reject.
    """
    spans: list[str] = []
    for m in JOURNALCTL_CALL_RE.finditer(line):
        rest = line[m.end():]
        cut = min((rest.index(c) for c in "|;)" if c in rest), default=len(rest))
        spans.append(rest[:cut])
    return spans


def _unbounded_journalctl_calls(text: str) -> list[tuple[int, str]]:
    """(1-based lineno, source) for every journalctl call with no read bound."""
    found: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue                      # documentation, not an executed command
        for args in _journalctl_arg_spans(stripped):
            if JOURNAL_LINE_CAP_SRC_RE.search(args) or JOURNAL_TIME_BOUND_RE.search(args):
                continue
            found.append((i, stripped))
    return found


def test_every_journalctl_call_in_deploy_sh_is_bounded() -> None:
    unbounded = _unbounded_journalctl_calls(DEPLOY_SH.read_text(encoding="utf-8"))
    if unbounded:
        detail = "\n".join(f"  scripts/deploy.sh:{n}: {src}" for n, src in unbounded)
        pytest.fail(
            f"{len(unbounded)} unbounded journalctl read(s):\n{detail}\n\n"
            "A journalctl call with neither `-n N` nor `--since` reads the unit's "
            "journal from the head. On a host with days of logs that is minutes of "
            "CPU, and deploy.sh reads the journal on its crash and log-scan paths — "
            "exactly when something is already wrong and nobody can afford to wait. "
            "Bound it at the call; trimming a full read afterwards with $(...) or "
            "`| tail` costs the same and fixes nothing."
        )


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        # Bounded invocations — accepted.
        ('journalctl -u "$U" -n "$lines" --no-pager -o cat 2>/dev/null || true', False),
        ('journalctl -u "$U" -n 40 --since "$START" --no-pager', False),
        ('out="$(journalctl -u "$U" --since "$START" -o cat)"', False),
        ("foo | journalctl --lines=10 -u x", False),
        # Unbounded invocations — flagged. The second is the shape the whole PR is
        # about: the cap must be journalctl's argument, not a downstream `tail`.
        ('journalctl -u "$U" --no-pager -o cat', True),
        ('out="$(journalctl -u "$U" -o cat)"; printf %s "$out" | tail -n 40', True),
        # Mentions, not invocations — never flagged.
        ("require_tools git awk date journalctl stat tail", False),
        ("command -v journalctl >/dev/null 2>&1 || return 0", False),
        ("# journalctl -u x  (a comment describing the old unbounded call)", False),
    ],
)
def test_journalctl_static_guard_recognises_calls_and_bounds(line: str, flagged: bool) -> None:
    """Guard the guard: a detector that quietly stopped matching would turn the test
    above into decoration that passes on anything."""
    assert bool(_unbounded_journalctl_calls(line)) is flagged, line
