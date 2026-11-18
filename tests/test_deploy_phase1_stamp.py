"""deploy.sh: the test venv's precondition (ensurepip) and the Phase 1 stamp.

A2 — a fresh Ubuntu 24.04 relay stopped in Phase 1 with "ensurepip is not available":
python3-venv was never installed there (install.sh's relay mode did not install it).
`ensure_python_venv` checks `python3 -m ensurepip --version` before the test venv is
built and installs python3.X-venv for THIS python3 (apt-get, noninteractive), or stops
with the command to run — reason=no_venv, before anything changed.

A3 — on a one-vCPU relay the pytest gate takes ~13 minutes and `CHECK=1` + the deploy
ran it twice. A fully green PHASE1_ONLY run writes the stamp (sha, constraints, python,
role, time; atomically, 0600); a real deploy of the same within PHASE1_STAMP_TTL skips
the gate and says on which stamp; FORCE_TESTS=1 always runs it.

Driven through the DEPLOY_SELFTEST=1 seam; every path is under tmp_path.
"""

from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

pytestmark = pytest.mark.timeout(60)


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(tmp_path: Path, body: str, *, cwd: Path | None = None, extra_path: Path | None = None,
         **env: str) -> subprocess.CompletedProcess[str]:
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -euo pipefail\nexport DEPLOY_SELFTEST=1\n"
        + (f'export PATH="{extra_path}:$PATH"\n' if extra_path else "")
        + "".join(f"export {k}='{v}'\n" for k, v in env.items())
        + f'source "{DEPLOY_SH}"\nVENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        # deploy.sh resets NODE_ROLE when sourced (resolve_node_role sets it): set it after.
        + (f'NODE_ROLE={env["NODE_ROLE"]}\n' if "NODE_ROLE" in env else "")
        + body,
        encoding="utf-8",
    )
    return subprocess.run(["bash", str(driver)], cwd=str(cwd or tmp_path), capture_output=True, text=True, check=False)


# --------------------------------------------------------------------------- #
# A2. ensurepip
# --------------------------------------------------------------------------- #
PYTHON3_STUB = r"""
if [[ "$1 $2" == "-m ensurepip" ]]; then [[ -f "$SD/ensurepip" ]]; exit; fi
if [[ "$1" == "-c" ]]; then echo 3.12; exit 0; fi
exit 0
"""

APT_STUB = r"""
echo "apt-get $* DEBIAN_FRONTEND=${DEBIAN_FRONTEND:-}" >> "$SD/apt.log"
case " $* " in
  *" update "*) [[ -f "$SD/index_after_update" ]] && touch "$SD/index"; exit 0 ;;
  *" install "*) if [[ -f "$SD/index" ]]; then touch "$SD/ensurepip"; exit 0; fi
                 echo "E: Unable to locate package python3.12-venv" >&2; exit 100 ;;
esac
exit 0
"""


@pytest.fixture
def venv_host(tmp_path: Path) -> tuple[Path, Path]:
    stub, sd = tmp_path / "stub", tmp_path / "sd"
    stub.mkdir()
    sd.mkdir()
    _stub(stub / "python3", PYTHON3_STUB)
    _stub(stub / "apt-get", APT_STUB)
    return stub, sd


def _ensure(tmp_path: Path, stub: Path, sd: Path) -> subprocess.CompletedProcess[str]:
    return _run(tmp_path, "step tests\nensure_python_venv\necho ENSURED\n", extra_path=stub, SD=str(sd))


def test_ensurepip_present_installs_nothing(tmp_path: Path, venv_host: tuple[Path, Path]) -> None:
    stub, sd = venv_host
    (sd / "ensurepip").touch()
    proc = _ensure(tmp_path, stub, sd)
    assert proc.returncode == 0 and "ENSURED" in proc.stdout
    assert not (sd / "apt.log").exists()


def test_missing_ensurepip_installs_the_venv_package_of_this_python(tmp_path: Path, venv_host: tuple[Path, Path]) -> None:
    stub, sd = venv_host
    (sd / "index").touch()
    proc = _ensure(tmp_path, stub, sd)
    assert proc.returncode == 0, proc.stderr
    assert "ENSURED" in proc.stdout and "ensurepip available (python3.12-venv installed)" in proc.stdout
    log = (sd / "apt.log").read_text(encoding="utf-8").splitlines()
    assert log == [
        "apt-get -o DPkg::Lock::Timeout=300 install -y -qq --no-install-recommends python3.12-venv "
        "DEBIAN_FRONTEND=noninteractive"
    ]


def test_a_stale_package_index_is_refreshed_once(tmp_path: Path, venv_host: tuple[Path, Path]) -> None:
    stub, sd = venv_host
    (sd / "index_after_update").touch()
    proc = _ensure(tmp_path, stub, sd)
    assert proc.returncode == 0, proc.stderr
    verbs = [line.split()[3] if "Timeout" in line else line for line in (sd / "apt.log").read_text().splitlines()]
    assert [v for v in verbs] == ["install", "update", "install"]


def test_no_way_to_install_it_stops_with_the_command_and_no_venv(tmp_path: Path, venv_host: tuple[Path, Path]) -> None:
    stub, sd = venv_host
    proc = _ensure(tmp_path, stub, sd)
    assert proc.returncode == 1 and "ENSURED" not in proc.stdout
    assert "run: apt install python3.12-venv; nothing was changed" in proc.stderr
    assert "[deploy:result failed step=tests reason=no_venv]" in proc.stderr


def test_no_apt_get_stops_with_the_package_name(tmp_path: Path, venv_host: tuple[Path, Path]) -> None:
    stub, sd = venv_host
    (stub / "apt-get").unlink()
    # The stub dir comes first; a real apt-get later on PATH would be found, so hide it.
    proc = _run(tmp_path, 'command() { [[ "$2" == apt-get ]] && return 1; builtin command "$@"; }\n'
                "step tests\nensure_python_venv\n", extra_path=stub, SD=str(sd))
    assert proc.returncode == 1
    assert "install python3.12-venv by hand" in proc.stderr and "reason=no_venv" in proc.stderr


def test_the_test_venv_is_built_only_after_the_check() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    body = text[text.index("run_checkout_tests() {"):]
    body = body[: body.index("\n}\n")]
    assert body.index("ensure_python_venv") < body.index('python3 -m venv "$TEST_VENV"')


def test_install_sh_relay_mode_installs_python3_venv() -> None:
    text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines() if ln.startswith("APT_RELAY_PACKAGES=("))
    assert "python3-venv" in line.split()[-1] or "python3-venv" in line


# --------------------------------------------------------------------------- #
# A3. The Phase 1 stamp
# --------------------------------------------------------------------------- #
def _git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.net",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.net"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "constraints-hashed.txt").write_text("a==1\n", encoding="utf-8")
    (r / "constraints-dev-hashed.txt").write_text("b==2\n", encoding="utf-8")
    _git(r, "add", ".")
    _git(r, "commit", "-qm", "c1")
    return r


def _stamp_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    return {"PHASE1_STAMP": str(tmp_path / "state" / "phase1-ok"), "NODE_ROLE": "relay", **extra}


def _write_stamp(tmp_path: Path, repo: Path, **env: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "state").mkdir(exist_ok=True)
    return _run(tmp_path, f'WT="{repo}"; TESTS_RAN=1\n' + env.pop("BODY", "") + "phase1_stamp_write\nWT=''\n",
                cwd=repo, **_stamp_env(tmp_path, PHASE1_ONLY="1", **env))


def _usable(tmp_path: Path, repo: Path, **env: str) -> subprocess.CompletedProcess[str]:
    return _run(tmp_path, f'WT="{repo}"\nif phase1_stamp_usable; then echo "USABLE $PHASE1_STAMP_USED"; '
                "else echo NOT-USABLE; fi\nWT=''\n", cwd=repo, **_stamp_env(tmp_path, **env))


def test_a_green_inspection_writes_the_stamp(tmp_path: Path, repo: Path) -> None:
    proc = _write_stamp(tmp_path, repo)
    assert proc.returncode == 0, proc.stderr
    stamp = tmp_path / "state" / "phase1-ok"
    assert stat.S_IMODE(stamp.stat().st_mode) == 0o600
    fields = dict(line.split("=", 1) for line in stamp.read_text(encoding="utf-8").splitlines())
    assert fields["version"] == "1" and fields["role"] == "relay"
    assert fields["sha"] == _git(repo, "rev-parse", "HEAD")
    assert len(fields["constraints"]) == 64 and fields["python"].count(".") == 2
    assert abs(int(fields["at"]) - time.time()) < 60
    assert not list((tmp_path / "state").glob(".phase1-ok.*")), "written atomically: no temp file left"


def test_no_stamp_when_a_real_deploy_would_have_stopped(tmp_path: Path, repo: Path) -> None:
    proc = _write_stamp(tmp_path, repo, BODY='phase1_would_stop "unit drift"\n')
    assert proc.returncode == 0
    assert "not written — a real deploy would stop on: unit drift" in proc.stdout
    assert not (tmp_path / "state" / "phase1-ok").exists()


def test_no_stamp_without_the_tests_or_outside_an_inspection(tmp_path: Path, repo: Path) -> None:
    (tmp_path / "state").mkdir()
    proc = _run(tmp_path, f'WT="{repo}"; TESTS_RAN=0\nphase1_stamp_write\nWT=""\n', cwd=repo,
                **_stamp_env(tmp_path, PHASE1_ONLY="1"))
    assert proc.returncode == 0 and not (tmp_path / "state" / "phase1-ok").exists()
    proc = _run(tmp_path, f'WT="{repo}"; TESTS_RAN=1\nphase1_stamp_write\nWT=""\n', cwd=repo,
                **_stamp_env(tmp_path, PHASE1_ONLY="0"))
    assert proc.returncode == 0 and not (tmp_path / "state" / "phase1-ok").exists()


def test_a_deploy_of_the_same_commit_relies_on_the_stamp(tmp_path: Path, repo: Path) -> None:
    assert _write_stamp(tmp_path, repo).returncode == 0
    proc = _usable(tmp_path, repo)
    assert proc.stdout.startswith("USABLE commit "), proc.stdout + proc.stderr
    assert "role relay" in proc.stdout and "min ago" in proc.stdout


@pytest.mark.parametrize(
    ("change", "env", "why"),
    [
        ("commit", {}, "for another commit"),
        ("constraints", {}, "for another commit"),
        ("role", {"NODE_ROLE": "main"}, "for another commit"),
        ("none", {"FORCE_TESTS": "1"}, "FORCE_TESTS=1"),
        ("none", {"PHASE1_ONLY": "1"}, ""),
        ("none", {"PHASE1_STAMP_TTL": "0"}, ""),
    ],
)
def test_anything_else_runs_the_tests(tmp_path: Path, repo: Path, change: str, env: dict[str, str], why: str) -> None:
    assert _write_stamp(tmp_path, repo).returncode == 0
    if change == "commit":
        (repo / "x").write_text("x", encoding="utf-8")
        _git(repo, "add", "x")
        _git(repo, "commit", "-qm", "c2")
    elif change == "constraints":
        (repo / "constraints-dev-hashed.txt").write_text("b==3\n", encoding="utf-8")
    proc = _usable(tmp_path, repo, **env)
    assert "NOT-USABLE" in proc.stdout, proc.stdout
    assert why in proc.stdout + proc.stderr


def test_an_expired_stamp_runs_the_tests(tmp_path: Path, repo: Path) -> None:
    assert _write_stamp(tmp_path, repo).returncode == 0
    stamp = tmp_path / "state" / "phase1-ok"
    text = stamp.read_text(encoding="utf-8")
    old = int(text.rsplit("at=", 1)[1]) - 7300
    stamp.write_text(text.rsplit("at=", 1)[0] + f"at={old}\n", encoding="utf-8")
    proc = _usable(tmp_path, repo)
    assert "NOT-USABLE" in proc.stdout and "min old" in proc.stdout


@pytest.mark.parametrize("mode", [0o644, 0o660])
def test_a_stamp_others_could_write_or_read_is_ignored(tmp_path: Path, repo: Path, mode: int) -> None:
    assert _write_stamp(tmp_path, repo).returncode == 0
    (tmp_path / "state" / "phase1-ok").chmod(mode)
    proc = _usable(tmp_path, repo)
    assert "NOT-USABLE" in proc.stdout and "ignoring the Phase 1 stamp" in proc.stderr


def test_a_symlinked_stamp_is_ignored(tmp_path: Path, repo: Path) -> None:
    assert _write_stamp(tmp_path, repo).returncode == 0
    real = tmp_path / "state" / "phase1-ok"
    real.rename(tmp_path / "state" / "elsewhere")
    real.symlink_to(tmp_path / "state" / "elsewhere")
    proc = _usable(tmp_path, repo)
    assert "NOT-USABLE" in proc.stdout and "ignoring" in proc.stderr


def test_run_checkout_tests_skips_the_gate_on_the_stamp(tmp_path: Path, repo: Path) -> None:
    assert _write_stamp(tmp_path, repo).returncode == 0
    proc = _run(
        tmp_path,
        'DEPLOY_TARGET=HEAD; DEPLOY_TARGET_LABEL="origin/main"; TAG=abc\n'
        f'TEST_VENV="{tmp_path}/no-venv"\nstep tests\nrun_checkout_tests\necho "TESTS_RAN=$TESTS_RAN"\n',
        cwd=repo, **_stamp_env(tmp_path),
    )
    assert proc.returncode == 0, proc.stderr
    assert "[deploy:skip tests] Phase 1 stamp: commit " in proc.stdout
    assert "tests: SKIPPED — the Phase 1 stamp" in proc.stdout and "TESTS_RAN=0" in proc.stdout
    assert "building test venv" not in proc.stdout and not (tmp_path / "no-venv").exists()


def test_the_stamp_is_fenced_in_the_selftest() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert 'PHASE1_STAMP="${PHASE1_STAMP:-/nonexistent/vpn-bot-selftest/phase1-ok}"' in text


def test_redeploy_forwards_the_stamp_knobs() -> None:
    text = (ROOT / "scripts" / "redeploy.sh").read_text(encoding="utf-8")
    block = text[text.index("DEPLOY_ENV_PASSTHROUGH=("):]
    block = block[: block.index(")")]
    assert "FORCE_TESTS" in block.split() and "PHASE1_STAMP_TTL" in block.split()
