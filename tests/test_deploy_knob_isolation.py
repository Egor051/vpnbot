"""deploy.sh's operator knobs never reach a test through the environment.

deploy.sh runs this suite as its Phase 1 gate, on the host and in the deploy's own
environment. `CHECK=1 redeploy` puts PHASE1_ONLY=1 there; FORCE=1 and the ALLOW_*
gate bypasses are passed through as the operator gave them. A test that sources
deploy.sh and leaves a knob at its default inherits that value and runs another
code path than in CI — green in CI, red on the box (the class of #239/#246/#318).
test_relay_phase1_stops_on_an_auth_latent was the last one: under
`CHECK=1 redeploy` it saw PHASE1_ONLY=1, and Phase 1 reported the LATENT instead
of stopping on it (`assert 0 == 1`).

The fix is in tests/ only: tests/conftest.py strips the knobs (autouse
`_isolate_deploy_knobs`) and RelayHost.run pins PHASE1_ONLY=0 in its prelude.

1. **Parity.** conftest.DEPLOY_ENV_KNOBS == the knobs deploy.sh reads. A new
   ALLOW_* in deploy.sh that is missing from the list fails here.
2. **Scrub.** A child pytest started with every knob exported sees none of them
   inside a test; DEPLOY_SELFTEST, which is not a knob, still passes through.
3. **Regression.** A child pytest started with PHASE1_ONLY=1 exported (the
   `CHECK=1 redeploy` environment) passes test_relay_phase1_stops_on_an_auth_latent.
4. **Class pristine.** sshd_config goes back to its package default WITHOUT
   ALLOW_SSH_CHANGE, and a key only the hand edit carries stops Phase 1: both hold in
   a child started with ALLOW_SSH_CHANGE=1 and PHASE1_ONLY=1 exported — a leaked knob
   would make the first pass for the wrong reason and turn the second into a report.

A monkeypatch.setenv in this process cannot stand in for 2 and 3: it runs after
the autouse fixture, so it would test a leak the fixture never sees. Only an
environment the pytest process starts with is what deploy.sh hands the suite.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import DEPLOY_ENV_KNOBS

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

# A child pytest run is ~1-2 s; anything near this is a hang.
pytestmark = pytest.mark.timeout(90)
CHILD_TIMEOUT = 75

# Same pattern as tests/test_redeploy_env_passthrough.py (digits allowed, so a
# future ALLOW_V2_FOO is not truncated into a different name).
ALLOW_RE = re.compile(r"\bALLOW_[A-Z0-9_]+")
# The run-mode knobs, read the way deploy.sh reads every knob: NAME="${NAME:-...}".
RUN_MODE_KNOBS = ("PHASE1_ONLY", "FORCE")

# Set in the child's environment, the probe below writes the names it sees there.
PROBE_OUT = "VPNBOT_TEST_ENV_PROBE_OUT"
PROBE = "tests/test_deploy_knob_isolation.py::test_no_deploy_knob_reaches_a_test"
AUTH_LATENT = "tests/test_relay_deploy.py::test_relay_phase1_stops_on_an_auth_latent"
PRISTINE_SSH = ("tests/test_deploy_pristine.py::"
                "test_sshd_config_with_yes_lines_after_the_include_is_restored_without_the_knob")
PRISTINE_FAIL = "tests/test_deploy_pristine.py::test_a_key_no_repo_file_carries_stops_phase1[journald]"


def _read_env_assignment(text: str, name: str) -> bool:
    return re.search(rf'^\s*{name}="\$\{{{name}:-', text, re.MULTILINE) is not None


def _child_pytest(tmp_path: Path, node: str, **env: str) -> subprocess.CompletedProcess[str]:
    """Run one test in a fresh pytest whose environment starts with `env`.

    The child gets this process's environment (already scrubbed by conftest) plus
    `env`, minus PYTEST_ADDOPTS, which could add -k/--cov to the child. Its own
    basetemp and no cache: it touches nothing outside tmp_path, on the box too.
    """
    child_env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    child_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         f"--basetemp={tmp_path / 'basetemp'}", node],
        cwd=str(ROOT), env=child_env, capture_output=True, text=True,
        timeout=CHILD_TIMEOUT, check=False,
    )


def _passed_once(proc: subprocess.CompletedProcess[str]) -> bool:
    return proc.returncode == 0 and re.search(r"\b1 passed\b", proc.stdout) is not None


# --------------------------------------------------------------------------- #
# 1. Parity with deploy.sh
# --------------------------------------------------------------------------- #
def test_deploy_env_knobs_match_what_deploy_sh_reads() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    allow = set(ALLOW_RE.findall(text))
    assert allow, "no ALLOW_* found in deploy.sh — did the pattern break?"
    for name in RUN_MODE_KNOBS:
        assert _read_env_assignment(text, name), f'deploy.sh no longer reads {name}="${{{name}:-...}}"'

    listed = set(DEPLOY_ENV_KNOBS)
    assert len(listed) == len(DEPLOY_ENV_KNOBS), "duplicate name in DEPLOY_ENV_KNOBS"
    expected = allow | set(RUN_MODE_KNOBS)
    assert not expected - listed, (
        f"deploy.sh reads {sorted(expected - listed)}, which tests/conftest.py DEPLOY_ENV_KNOBS "
        "does not strip: a host deploy run with it set would leak it into the tests"
    )
    assert not listed - expected, f"DEPLOY_ENV_KNOBS lists {sorted(listed - expected)}, which deploy.sh no longer reads"


# --------------------------------------------------------------------------- #
# 2. The conftest scrub, under an environment pytest starts with
# --------------------------------------------------------------------------- #
def test_no_deploy_knob_reaches_a_test() -> None:
    """The probe: run in-process it checks this run; run by the test below, the child's."""
    out = os.environ.get(PROBE_OUT)
    if out:
        Path(out).write_text("".join(f"{k}\n" for k in sorted(os.environ)), encoding="utf-8")
    leaked = {k: os.environ[k] for k in DEPLOY_ENV_KNOBS if k in os.environ}
    assert leaked == {}


def test_conftest_strips_every_knob_from_an_ambient_deploy_environment(tmp_path: Path) -> None:
    seen = tmp_path / "probe-env.txt"
    knobs = dict.fromkeys(DEPLOY_ENV_KNOBS, "1")
    proc = _child_pytest(tmp_path, PROBE, **knobs, DEPLOY_SELFTEST="1", **{PROBE_OUT: str(seen)})
    assert _passed_once(proc), proc.stdout + proc.stderr
    names = set(seen.read_text(encoding="utf-8").split())
    assert not names & set(DEPLOY_ENV_KNOBS), "a knob reached the test"
    assert "DEPLOY_SELFTEST" in names, "the scrub is for knobs only; DEPLOY_SELFTEST passes through"


# --------------------------------------------------------------------------- #
# 3. The reported failure: `CHECK=1 redeploy` runs the suite with PHASE1_ONLY=1
# --------------------------------------------------------------------------- #
def test_relay_auth_latent_stop_holds_under_check_redeploy(tmp_path: Path) -> None:
    proc = _child_pytest(tmp_path, AUTH_LATENT, PHASE1_ONLY="1")
    assert _passed_once(proc), proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# 4. Class pristine under the operator's knobs
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("node", [PRISTINE_SSH, PRISTINE_FAIL], ids=["sshd-without-the-knob", "phase1-fail"])
def test_pristine_holds_under_the_operators_knobs(tmp_path: Path, node: str) -> None:
    proc = _child_pytest(tmp_path, node, ALLOW_SSH_CHANGE="1", PHASE1_ONLY="1")
    assert _passed_once(proc), proc.stdout + proc.stderr
