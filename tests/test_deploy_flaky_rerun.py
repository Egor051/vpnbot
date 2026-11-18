"""deploy.sh Phase 1: ONE re-run of exactly the tests that failed (phase1_pytest).

he2 (one vCPU, v3.2.1): 1 failed, 5808 passed — a progress test racing the real clock
— and the relay's deploy stopped. Now the full run is what it always was; when it fails
with pytest's exit 1 and at most PHASE1_RERUN_MAX tests failed, ONLY those run once
more: green -> the gate passed, a loud «flaky: <node ids>», the same in DEPLOY OK and
``[deploy:warn flaky_tests]`` for the bot; red -> it stops, as before.

Driven through the DEPLOY_SELFTEST=1 seam on a tiny REAL pytest project in tmp_path
(the node ids come from pytest itself — a parametrized one with a space included), run
by this interpreter through a ``TEST_VENV/bin/python`` wrapper.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from bot.deploy_views import deploy_warnings_text
from i18n import t
from services.deploy_result import deploy_warnings_from

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
AGENT = ROOT / "scripts" / "vpn-relay-agent"

pytestmark = pytest.mark.timeout(120)

# Each test appends its name to runs.log; a «flaky» one fails while its mark is absent.
FLAKY = '''
import os, pytest
LOG = os.environ["PHASE1_SELFTEST_LOG"]

def _ran(name):
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(name + "\\n")

def _first_time(name):
    mark = os.path.join(os.path.dirname(LOG), "mark-" + name.replace(" ", "_"))
    if os.path.exists(mark):
        return False
    open(mark, "w").close()
    return True

def test_ok():
    _ran("test_ok")

def test_flaky():
    _ran("test_flaky")
    assert not _first_time("test_flaky"), "fails once"

@pytest.mark.parametrize("x", ["a b"])
def test_param(x):
    _ran("test_param")
    assert not _first_time("test_param"), "fails once"
'''


def _project(tmp_path: Path, body: str) -> tuple[Path, Path]:
    wt = tmp_path / "wt"
    (wt / "tests").mkdir(parents=True)
    (wt / "tests" / "test_m.py").write_text(body, encoding="utf-8")
    (wt / "pytest.ini").write_text("[pytest]\ntestpaths = tests\n", encoding="utf-8")
    venv = tmp_path / "test-venv"
    (venv / "bin").mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    python.chmod(0o755)
    return wt, venv


def _gate(tmp_path: Path, body: str, *, total: str = "3") -> subprocess.CompletedProcess[str]:
    wt, venv = _project(tmp_path, body)
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -euo pipefail\nexport DEPLOY_SELFTEST=1\n"
        f'export PHASE1_SELFTEST_LOG="{tmp_path}/runs.log"\n'
        f'source "{DEPLOY_SH}"\nVENV=/nonexistent; VENV_PREV=/nonexistent; STAGE=""\n'
        f'WT="{wt}"; TEST_VENV="{venv}"; DEPLOY_TARGET_LABEL="tag v9.9.9"\n'
        "step tests\nDEPLOY_FAIL_REASON=tests\n"
        f'phase1_pytest "{total}"\n'
        'echo "FLAKY=${PHASE1_FLAKY[*]}"\nWT=""\ndeploy_result_ok\n',
        encoding="utf-8",
    )
    return subprocess.run(["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True, check=False)


def _runs(tmp_path: Path) -> list[str]:
    log = tmp_path / "runs.log"
    return log.read_text(encoding="utf-8").split() if log.exists() else []


def test_a_flaky_test_is_rerun_alone_once_and_the_deploy_goes_on(tmp_path: Path) -> None:
    proc = _gate(tmp_path, FLAKY)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    ids = "tests/test_m.py::test_flaky tests/test_m.py::test_param[a b]"
    assert f"FLAKY={ids}" in proc.stdout
    assert sorted(_runs(tmp_path)) == sorted(["test_ok", "test_flaky", "test_param", "test_flaky", "test_param"]), (
        "the full run once, then ONLY the two that failed"
    )
    assert "running ONLY them once more" in proc.stderr and f"flaky: {ids}" in proc.stderr
    assert f"[deploy:warn flaky_tests] flaky: {ids}" in proc.stdout, "the marker the bot reads"
    assert "!! FLAKY TESTS" in proc.stdout and "!!     tests/test_m.py::test_param[a b]" in proc.stdout
    assert "[deploy:tests total=5]" in proc.stdout, "the re-run is added to the total (3 + 2)"
    assert proc.stdout.rstrip().endswith("[deploy:result ok]")


def test_a_test_that_fails_again_stops_the_deploy(tmp_path: Path) -> None:
    proc = _gate(tmp_path, "def test_ok():\n    pass\n\ndef test_broken():\n    assert False\n", total="2")
    assert proc.returncode == 1
    assert "failed again when re-run alone" in proc.stderr and "tests/test_m.py::test_broken" in proc.stderr
    assert "[deploy:result failed step=tests reason=tests]" in proc.stderr
    assert "FLAKY=" not in proc.stdout and "flaky_tests" not in proc.stdout


def test_too_many_failures_are_no_flake_and_are_not_rerun(tmp_path: Path) -> None:
    body = "import os\n" + "".join(
        f"def test_{i}():\n    open(os.environ['PHASE1_SELFTEST_LOG'], 'a').write('t{i}\\n')\n    assert False\n"
        for i in range(6)
    )
    proc = _gate(tmp_path, body, total="6")
    assert proc.returncode == 1
    assert "6 tests failed — more than 5" in proc.stderr and "no re-run" in proc.stderr
    assert len(_runs(tmp_path)) == 6, "each ran once: no re-run"
    assert "reason=tests" in proc.stderr


def test_a_collection_error_is_not_rerun(tmp_path: Path) -> None:
    proc = _gate(tmp_path, "import nonexistent_module_for_the_selftest\n")
    assert proc.returncode == 1
    assert "exit 2: not a test failure that can be re-run" in proc.stderr
    assert "running ONLY them" not in proc.stderr


def test_a_green_run_is_just_green(tmp_path: Path) -> None:
    proc = _gate(tmp_path, "def test_ok():\n    pass\n", total="1")
    assert proc.returncode == 0, proc.stderr
    assert "FLAKY=\n" in proc.stdout and "flaky" not in proc.stderr and "flaky_tests" not in proc.stdout


def test_the_gate_uses_it_and_keeps_the_cache_off() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    body = text[text.index("run_checkout_tests() {"):]
    body = body[: body.index("\n}\n")]
    assert 'phase1_pytest "$total"' in body and "-m pytest -q -p no:cacheprovider )" not in body
    assert '-m pytest -q -p no:cacheprovider -p "$PHASE1_PLUGIN_NAME"' in text, "the full run is unchanged otherwise"


def test_the_agent_carries_the_warning_and_the_bot_says_it_loud() -> None:
    from importlib.machinery import SourceFileLoader
    from importlib.util import module_from_spec, spec_from_loader

    loader = SourceFileLoader("vpn_relay_agent_flaky", str(AGENT))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    agent = module_from_spec(spec)
    loader.exec_module(agent)
    out = "[deploy:warn flaky_tests] flaky: tests/test_a.py::test_x\n[deploy:result ok]\n"
    verdict = agent.deploy_verdict(out, 0)
    assert verdict["warnings"] == [{"code": "flaky_tests", "text": "flaky: tests/test_a.py::test_x"}]
    text = deploy_warnings_text(deploy_warnings_from(verdict["warnings"]))
    assert text == "⚠️ " + t("deploy_warn_flaky_tests") + ": flaky: tests/test_a.py::test_x"
    from i18n.en import STRINGS as EN

    assert "deploy_warn_flaky_tests" in EN
