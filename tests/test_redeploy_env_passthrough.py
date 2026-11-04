"""scripts/redeploy.sh forwards deploy.sh's gate bypasses — or refuses to run.

deploy.sh runs under `systemd-run`, which starts it in a fresh environment, so a
knob reaches it only if redeploy.sh puts it on the `env` line of the launch
command. The wrapper used to forward CHECK (as PHASE1_ONLY) and FORCE only, so
`ALLOW_BACKEND_CONFIG_DRIFT=1 bash scripts/redeploy.sh` was dropped without a
word and deploy.sh stopped on the very gate the flag was meant to open; the only
way through was `systemd-run ... env ALLOW_X=1 bash /tmp/deploy.sh` by hand.

Asserted here:

1. **Parity.** The ALLOW_* names deploy.sh reads == the ALLOW_* names in the
   wrapper's DEPLOY_ENV_PASSTHROUGH. A new deploy.sh flag that nobody adds there
   turns this red.
2. **Forwarding.** An allowlisted variable that is set reaches the systemd-run
   argv (between `env` and `bash`) and is named on the `deploy.sh env:` line; an
   empty one is not forwarded.
3. **Refusal.** An ALLOW_* outside the allowlist stops the wrapper with a non-zero
   exit before it runs anything — no git, no systemctl, no systemd-run.
4. **No regression.** With none of these set, the printed lines and the launch
   argv are exactly what the wrapper produced before.

Driven through the REDEPLOY_SELFTEST=1 seam (source the file, call its functions)
with systemd-run/date stubbed on PATH; the refusal tests run the real script end
to end. Every subprocess gets a minimal environment: deploy.sh runs this suite as
a Phase 1 gate, where the operator's own ALLOW_* may well be exported.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
REDEPLOY_SH = ROOT / "scripts" / "redeploy.sh"

# Nothing here waits on anything; a test near this ceiling is a hang.
pytestmark = pytest.mark.timeout(60)

# Same pattern as `grep -noE '\bALLOW_[A-Z_]+' scripts/deploy.sh`, digits allowed
# so a future ALLOW_V2_FOO is not truncated into a different name.
ALLOW_RE = re.compile(r"\bALLOW_[A-Z0-9_]+")

TS = "20261104T000000Z"
TMP_DEPLOY = "/T/deploy.sh"
LOG_DIR = "/L"
LOG_FILE = f"{LOG_DIR}/deploy-{TS}.log"
BASH_C = f"bash {TMP_DEPLOY} 2>&1 | tee {LOG_FILE}"

# Records every call to the stubbed host commands; systemd-run also writes its
# argv one element per line so a test can compare it exactly.
CALL_LOGGER = 'printf "%s\\n" "$(basename "$0") $*" >> "$CALLS"\n'


def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _env(tmp_path: Path, extra: dict[str, str]) -> dict[str, str]:
    """A minimal environment: stubs first on PATH, nothing inherited but PATH."""
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir(parents=True, exist_ok=True)
    _make_stub(stub_dir / "systemd-run", CALL_LOGGER + 'printf "%s\\n" "$@" > "$ARGV_LOG"\n')
    _make_stub(stub_dir / "date", CALL_LOGGER + f"echo {TS}\n")
    for name in ("git", "systemctl"):
        _make_stub(stub_dir / name, CALL_LOGGER)
    env = {
        "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(tmp_path),
        "CALLS": str(tmp_path / "calls"),
        "ARGV_LOG": str(tmp_path / "argv"),
        "APP_DIR": str(tmp_path / "app-does-not-exist"),
        "TMP_DEPLOY": TMP_DEPLOY,
        "REDEPLOY_LOG_DIR": LOG_DIR,
    }
    env.update(extra)
    return env


def _source(tmp_path: Path, body: str, **extra: str) -> subprocess.CompletedProcess[str]:
    """Source redeploy.sh through its selftest seam and run `body`."""
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "export REDEPLOY_SELFTEST=1\n"
        f'source "{REDEPLOY_SH}"\n'
        f"{body}\n",
        encoding="utf-8",
    )
    return subprocess.run(
        ["bash", str(driver)],
        cwd=str(tmp_path),
        env=_env(tmp_path, extra),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _execute(tmp_path: Path, **extra: str) -> subprocess.CompletedProcess[str]:
    """Run the real redeploy.sh end to end (no seam)."""
    return subprocess.run(
        ["bash", str(REDEPLOY_SH)],
        cwd=str(tmp_path),
        env=_env(tmp_path, extra),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _argv(tmp_path: Path) -> list[str]:
    return (tmp_path / "argv").read_text(encoding="utf-8").splitlines()


def _allowlist(tmp_path: Path) -> list[str]:
    proc = _source(tmp_path, 'printf "%s\\n" "${DEPLOY_ENV_PASSTHROUGH[@]}"')
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.splitlines()


def _unforwarded(deploy_text: str, allowlist: list[str]) -> set[str]:
    """ALLOW_* names deploy.sh reads that the wrapper would silently drop."""
    return set(ALLOW_RE.findall(deploy_text)) - set(allowlist)


def _stale(deploy_text: str, allowlist: list[str]) -> set[str]:
    """ALLOW_* names the wrapper forwards that deploy.sh no longer reads."""
    return {n for n in allowlist if n.startswith("ALLOW_")} - set(ALLOW_RE.findall(deploy_text))


# The launch, exactly as main runs it after the fetch.
LAUNCH = "check_allow_env\nbuild_deploy_env\nlaunch_deploy\n"


def _expected_argv(*deploy_env: str) -> list[str]:
    return ["--unit=vpn-bot-deploy", "--collect", "--pty", "env", *deploy_env, "bash", "-c", BASH_C]


def _expected_stdout(env_line: str) -> str:
    return (
        f"redeploy: launching vpn-bot-deploy (log: {LOG_FILE})\n"
        f"redeploy:   deploy.sh env: {env_line}\n"
    )


# --------------------------------------------------------------------------- #
# 1. Parity with deploy.sh
# --------------------------------------------------------------------------- #
def test_allow_flags_in_deploy_sh_match_the_redeploy_allowlist(tmp_path: Path) -> None:
    deploy_text = DEPLOY_SH.read_text(encoding="utf-8")
    allowlist = _allowlist(tmp_path)
    assert ALLOW_RE.findall(deploy_text), "no ALLOW_* found in deploy.sh — did the pattern break?"
    assert len(allowlist) == len(set(allowlist)), f"duplicate names in DEPLOY_ENV_PASSTHROUGH: {allowlist}"
    assert not _unforwarded(deploy_text, allowlist), (
        f"deploy.sh reads {sorted(_unforwarded(deploy_text, allowlist))} but scripts/redeploy.sh "
        "does not forward them: add each to DEPLOY_ENV_PASSTHROUGH"
    )
    assert not _stale(deploy_text, allowlist), (
        f"DEPLOY_ENV_PASSTHROUGH forwards {sorted(_stale(deploy_text, allowlist))}, which deploy.sh no longer reads"
    )


def test_parity_check_goes_red_for_a_new_unforwarded_flag(tmp_path: Path) -> None:
    """The check above is not vacuous: a new deploy.sh flag shows up as a gap."""
    allowlist = _allowlist(tmp_path)
    grown = DEPLOY_SH.read_text(encoding="utf-8") + '\nALLOW_NEW_GATE="${ALLOW_NEW_GATE:-0}"\n'
    assert _unforwarded(grown, allowlist) == {"ALLOW_NEW_GATE"}


def test_every_other_forwarded_name_is_a_deploy_sh_knob(tmp_path: Path) -> None:
    """The tuning timeouts in the allowlist are real deploy.sh env knobs."""
    deploy_text = DEPLOY_SH.read_text(encoding="utf-8")
    others = [n for n in _allowlist(tmp_path) if not n.startswith("ALLOW_")]
    assert others, "expected the tuning timeouts in DEPLOY_ENV_PASSTHROUGH"
    for name in others:
        assert f'{name}="${{{name}:-' in deploy_text, f"{name} is forwarded but deploy.sh never reads it"


# --------------------------------------------------------------------------- #
# 2. Forwarding
# --------------------------------------------------------------------------- #
def test_allow_flag_reaches_the_launch_command(tmp_path: Path) -> None:
    """The reported case: the flag gets through, and the report line says so."""
    proc = _source(tmp_path, LAUNCH, CHECK="1", ALLOW_BACKEND_CONFIG_DRIFT="1")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == _expected_stdout("PHASE1_ONLY=1 ALLOW_BACKEND_CONFIG_DRIFT=1")
    assert _argv(tmp_path) == _expected_argv("PHASE1_ONLY=1", "ALLOW_BACKEND_CONFIG_DRIFT=1")


def test_every_allowlisted_name_is_forwarded(tmp_path: Path) -> None:
    allowlist = _allowlist(tmp_path)
    values = {name: str(10 + i) for i, name in enumerate(allowlist)}
    proc = _source(tmp_path, LAUNCH, **values)
    assert proc.returncode == 0, proc.stderr
    words = [f"{name}={values[name]}" for name in allowlist]
    assert _argv(tmp_path) == _expected_argv(*words)
    assert proc.stdout == _expected_stdout(" ".join(words))


def test_empty_allowlisted_variable_is_not_forwarded(tmp_path: Path) -> None:
    proc = _source(tmp_path, LAUNCH, ALLOW_UNIT_DRIFT="", SCHEMA_WAIT_TIMEOUT="")
    assert proc.returncode == 0, proc.stderr
    assert _argv(tmp_path) == _expected_argv()
    assert proc.stdout == _expected_stdout("<none>")


def test_value_is_forwarded_verbatim_as_one_argument(tmp_path: Path) -> None:
    """argv, not a shell string: a value cannot split into, or inject, more words."""
    proc = _source(tmp_path, LAUNCH, SCHEMA_WAIT_TIMEOUT="120 ; touch pwned")
    assert proc.returncode == 0, proc.stderr
    assert _argv(tmp_path) == _expected_argv("SCHEMA_WAIT_TIMEOUT=120 ; touch pwned")
    assert not (tmp_path / "pwned").exists()


# --------------------------------------------------------------------------- #
# 3. Refusal of an unknown ALLOW_*
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "extra",
    [
        {"ALLOW_FOO": "1"},
        {"ALLOW_BACKEND_CONFIG_DRFT": "1"},              # the typo this guards against
        {"ALLOW_FOO": "0"},                              # any value: the name is the mistake
        {"ALLOW_FOO": ""},
        {"ALLOW_UNIT_DRIFT": "1", "ALLOW_FOO": "1"},     # a valid flag does not excuse it
    ],
)
def test_unknown_allow_variable_refuses_before_anything_runs(tmp_path: Path, extra: dict[str, str]) -> None:
    proc = _execute(tmp_path, CHECK="1", **extra)
    unknown = [n for n in extra if n not in ("ALLOW_UNIT_DRIFT",)]
    assert proc.returncode != 0, proc.stdout
    assert f"unknown ALLOW_* variable(s): {' '.join(unknown)}\n" in proc.stderr
    for name in _allowlist(tmp_path):
        assert name in proc.stderr.split("names this wrapper forwards:", 1)[1]
    # Nothing ran: no fetch, no reset-failed, no launch — and it stopped before
    # the root guard too, so the message is the same with or without root.
    assert _calls(tmp_path) == []
    assert proc.stdout == ""
    assert "run as root" not in proc.stderr


def test_selftest_seam_refuses_when_executed(tmp_path: Path) -> None:
    """REDEPLOY_SELFTEST=1 outside `source` must not become a silent no-op deploy."""
    proc = _execute(tmp_path, REDEPLOY_SELFTEST="1")
    assert proc.returncode == 1, proc.stdout
    assert "test seam" in proc.stderr
    assert _calls(tmp_path) == []


# --------------------------------------------------------------------------- #
# 4. Nothing set: byte-for-byte the previous launch
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("extra", "deploy_env"),
    [
        ({}, []),
        ({"CHECK": "1"}, ["PHASE1_ONLY=1"]),
        ({"FORCE": "1"}, ["FORCE=1"]),
        ({"CHECK": "1", "FORCE": "1"}, ["PHASE1_ONLY=1", "FORCE=1"]),
        ({"CHECK": "0", "FORCE": "0"}, []),
    ],
)
def test_launch_without_forwarded_knobs_is_unchanged(
    tmp_path: Path, extra: dict[str, str], deploy_env: list[str]
) -> None:
    proc = _source(tmp_path, LAUNCH, **extra)
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert proc.stdout == _expected_stdout(" ".join(deploy_env) or "<none>")
    assert _argv(tmp_path) == _expected_argv(*deploy_env)
    assert _calls(tmp_path) == ["date -u +%Y%m%dT%H%M%SZ", "systemd-run " + " ".join(_expected_argv(*deploy_env))]
