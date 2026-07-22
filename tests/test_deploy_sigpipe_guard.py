"""SIGPIPE-under-pipefail guards for the deploy shell scripts.

Background
----------
`scripts/deploy.sh` and `scripts/redeploy.sh` run under `set -euo pipefail`. In
that mode a pipeline whose *consumer* closes its input early — `head -N` after N
lines, `grep -q` on the first match — sends SIGPIPE to the still-writing
*producer*. The producer exits 141, `pipefail` propagates that 141 as the
pipeline's status, and `errexit` aborts the whole deploy. It only triggers when
the producer actually has more to write than the consumer reads (e.g. a log scan
that finds MANY matches), so it is invisible on clean input and detonates exactly
on the dirty input you were scanning for. This class already bit this project
twice (`xray version | head -1`, `grep -q` inside a pipe); the 2026-07-22 run died
on `grep -E ... | head -n3` in the Phase 1 report with `printf: write error:
Broken pipe`.

The remedy is a consumer that reads its input to EOF: `awk 'NR<=N'` instead of
`head -N` (it stops PRINTING at N but keeps reading), and a plain `grep ...
>/dev/null` instead of `grep -q ...` inside a pipe.

This module has two independent guards:

1. A STATIC guard that reads both scripts as text and fails on any `| head` /
   `|head` or `| grep -q` left in a pipeline, unless the line carries an explicit
   `# sigpipe-safe: <reason>` opt-out marker (same line or the line above).

2. A FUNCTIONAL guard that drives the extracted `print_log_scan_examples` printer
   through the `DEPLOY_SELFTEST=1` seam with input carrying far more matches than
   the print limit, asserting exit 0, exactly N lines, and no "Broken pipe".

Both guards only read files inside the repo and run bash on a self-sourced copy of
the script via the documented selftest seam — no systemctl, no network, no host
paths, no production .env.
"""

import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
REDEPLOY_SH = ROOT / "scripts" / "redeploy.sh"

# A `|` (optionally with whitespace) feeding `head` — a pipe CONSUMER that closes
# early. `head -n N file` (head reading a FILE, no leading pipe) is safe and is NOT
# matched, because there is no `|` immediately before `head`.
HEAD_IN_PIPE_RE = re.compile(r"\|\s*head\b")
# A `|` feeding `grep` with a quiet/first-match flag (`-q`, bundled like `-qvE`, or
# the long `--quiet`/`--silent`): grep exits on the first match and SIGPIPEs upstream.
GREPQ_IN_PIPE_RE = re.compile(r"\|\s*grep\s+(?:-[a-zA-Z]*q[a-zA-Z]*|--quiet|--silent)\b")
# Conscious opt-out marker, on the offending line or the line directly above it.
SIGPIPE_SAFE_RE = re.compile(r"#\s*sigpipe-safe:")

# The failure text every static-guard assertion carries: it must name the bug
# CLASS and the REMEDY, not just say "found a match".
REMEDY = (
    "SIGPIPE-under-pipefail bug: under `set -euo pipefail` a `| head -N` / `| grep -q` "
    "consumer closes the pipe early, the upstream producer takes SIGPIPE and exits 141, "
    "pipefail propagates 141 and errexit aborts the deploy — and it only fires when the "
    "producer has MORE output than the consumer reads (a dirty log), so it hides on clean "
    "input.\nFIX: use a consumer that reads to EOF — `awk 'NR<=N'` instead of `head -N`, "
    "and `grep ... >/dev/null` instead of `grep -q ...` in a pipe. If a pipeline is "
    "genuinely safe (e.g. a single-token producer that finishes before the consumer can "
    "exit), annotate it with `# sigpipe-safe: <reason>` on that line or the line above."
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _pipeline_violations(text: str) -> list[tuple[int, str, str]]:
    """Return (1-based lineno, line, kind) for every unmarked early-closing pipe
    consumer. Pure comment lines are ignored (they cannot be a live pipeline);
    a `# sigpipe-safe:` marker on the line itself or the line above exempts it.
    """
    lines = text.splitlines()
    violations: list[tuple[int, str, str]] = []
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        # A full-line comment is documentation, never an executed pipeline — the
        # SIGPIPE-safety note in deploy.sh literally spells out `grep ... | head -n N`.
        if stripped.startswith("#"):
            continue
        kind = None
        if HEAD_IN_PIPE_RE.search(line):
            kind = "| head"
        elif GREPQ_IN_PIPE_RE.search(line):
            kind = "| grep -q"
        if kind is None:
            continue
        prev = lines[i - 1] if i > 0 else ""
        if SIGPIPE_SAFE_RE.search(line) or SIGPIPE_SAFE_RE.search(prev):
            continue  # consciously opted out
        violations.append((i + 1, line.strip(), kind))
    return violations


@pytest.mark.parametrize("script", [DEPLOY_SH, REDEPLOY_SH], ids=lambda p: p.name)
def test_no_early_closing_pipe_consumers(script: Path) -> None:
    violations = _pipeline_violations(_read(script))
    if violations:
        detail = "\n".join(
            f"  {script.name}:{lineno}: {kind} -> {src}" for lineno, src, kind in violations
        )
        pytest.fail(
            f"{len(violations)} early-closing pipe consumer(s) in {script.name}:\n"
            f"{detail}\n\n{REMEDY}"
        )


# --------------------------------------------------------------------------- #
# Guard-the-guard: prove the detector actually catches violations and honours the
# opt-out marker, so a future regression cannot pass by silently breaking the scan.
# --------------------------------------------------------------------------- #
def test_guard_flags_head_in_pipe() -> None:
    v = _pipeline_violations("foo | grep -E bar | head -n3\n")
    assert v and v[0][2] == "| head"


def test_guard_flags_head_no_space() -> None:
    assert _pipeline_violations("foo |head -n3\n")


def test_guard_flags_grep_q_in_pipe() -> None:
    for snippet in ("printf x | grep -qE pat\n", "cmd | grep -qvF s\n", "cmd |grep -q s\n"):
        v = _pipeline_violations(snippet)
        assert v and v[0][2] == "| grep -q", snippet


def test_guard_ignores_head_on_a_file() -> None:
    # head reading a FILE (no leading pipe) is safe and must not be flagged.
    assert _pipeline_violations('head -n 5 "$file"\n') == []
    assert _pipeline_violations('head -n 5 "$file" | grep x\n') == []


def test_guard_ignores_grep_without_quiet() -> None:
    assert _pipeline_violations("cmd | grep -E pat >/dev/null\n") == []


def test_guard_ignores_pure_comment_lines() -> None:
    assert _pipeline_violations("  # never do `foo | head -n3` or `x | grep -q y`\n") == []


def test_marker_on_same_line_exempts() -> None:
    assert _pipeline_violations("cmd | grep -q x  # sigpipe-safe: tiny fixed producer\n") == []


def test_marker_on_previous_line_exempts() -> None:
    assert _pipeline_violations("# sigpipe-safe: tiny fixed producer\ncmd | grep -q x\n") == []


def test_deploy_sh_still_has_one_marked_optout() -> None:
    """The running-but-not-watched probe is a single-token producer, kept as grep -q
    and consciously marked. This pins that the marker mechanism is exercised on real
    code, not only synthetic snippets — if that line is ever un-marked, the static
    guard above turns it into a failure."""
    text = _read(DEPLOY_SH)
    assert "# sigpipe-safe:" in text
    # and the whole file is clean once markers are honoured
    assert _pipeline_violations(text) == []


# --------------------------------------------------------------------------- #
# Functional guard: drive the real printer through the DEPLOY_SELFTEST seam.
# --------------------------------------------------------------------------- #
def test_print_log_scan_examples_survives_more_matches_than_limit(tmp_path: Path) -> None:
    """With 2000 matching lines and a print limit of 3 the old `grep | head -n3`
    would SIGPIPE the grep (rc 141) and, under errexit, abort. The awk-based printer
    must instead exit 0, print exactly 3 indented lines, and emit no Broken pipe."""
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic (WT/STAGE are unset before
        # the seam's early return; the cleanup trap reads them under `set -u`).
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        # Observe the printer's own exit status instead of dying on it.
        "set +e\n"
        # 2000 matching lines >> the limit of 3 — the condition that used to detonate.
        "big=\"$(printf 'ERROR %s\\n' {1..2000})\"\n"
        'echo "___BEGIN___"\n'
        'print_log_scan_examples "$big" 3\n'
        "rc=$?\n"
        'echo "___END___"\n'
        'echo "___RC=${rc}___"\n',
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True
    )
    assert proc.returncode == 0, f"driver died: {proc.stdout}\n{proc.stderr}"
    assert "___RC=0___" in proc.stdout, f"printer returned non-zero:\n{proc.stdout}\n{proc.stderr}"
    assert "Broken pipe" not in proc.stderr, proc.stderr
    assert "Broken pipe" not in proc.stdout, proc.stdout

    # Exactly the limit (3) lines were printed, each indented by six spaces.
    body = proc.stdout.split("___BEGIN___", 1)[1].split("___END___", 1)[0]
    printed = [ln for ln in body.splitlines() if ln.strip()]
    assert len(printed) == 3, f"expected exactly 3 example lines, got {printed!r}"
    assert all(ln.startswith("      ERROR ") for ln in printed), printed
