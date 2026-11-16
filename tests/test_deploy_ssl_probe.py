"""Phase 2 probes the new prod venv's TLS context before the bot ever starts on it.

The PR #269 incident: after the dependency install the new bot died on its first
start with FileNotFoundError on certifi/cacert.pem — aiogram's AiohttpSession builds
``ssl.create_default_context(cafile=certifi.where())`` on its first request — systemd
restarted it in a loop and the deploy rolled back. ``pip check`` cannot see such a
fault: the metadata is fine, only the data file certifi names is missing.

Pinned here, by driving the real bash through the ``DEPLOY_SELFTEST=1`` seam with a
fake venv whose ``bin/python`` is the interpreter running this suite:

1. **The exact expression.** ``venv_ssl_probe`` runs
   ``ssl.create_default_context(cafile=certifi.where())`` in the venv's python. With
   the real certifi it reports OK and the bundle path; with a certifi whose
   ``where()`` names a missing file it reports the FileNotFoundError — the incident,
   reproduced with the real ``ssl`` module.
2. **Read-only.** ``-B``: the probe writes no ``.pyc``, so Phase 1 may run it.
3. **Failure goes through the existing rollback.** In Phase 2 the venv is already
   replaced when the probe runs (the deps are installed into the live venv after the
   bot is stopped), so ``assert_venv_ssl`` leaves through ``rollback_now`` — and the
   real ``rollback`` puts ``.venv`` back from ``.venv.prev``.
4. **Placement and reports.** After ``pip check``, before the helpers, the host files,
   the unit and the bot start; one line in the PHASE1_ONLY report and in DEPLOY OK.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

# Every external the probe needs is local; anything near this is a hang.
pytestmark = pytest.mark.timeout(60)


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _fake_venv(root: Path) -> Path:
    """A venv whose bin/python is the interpreter running this suite (real ssl)."""
    venv = root / "venv"
    (venv / "bin").mkdir(parents=True)
    py = venv / "bin" / "python"
    py.write_text(f'#!/usr/bin/env bash\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    py.chmod(0o755)
    return venv


def _broken_certifi(root: Path) -> tuple[Path, Path]:
    """A certifi package whose where() names a cacert.pem that is not on disk."""
    pkg_root = root / "fake-site"
    pkg = pkg_root / "certifi"
    pkg.mkdir(parents=True)
    missing = root / "gone" / "certifi" / "cacert.pem"
    (pkg / "__init__.py").write_text(
        f"def where() -> str:\n    return {str(missing)!r}\n", encoding="utf-8"
    )
    return pkg_root, missing


def _run(
    tmp_path: Path, body: str, *, pythonpath: Path | None = None, real_rollback: bool = False
) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH", "PYTHONDONTWRITEBYTECODE"}}
    if pythonpath is not None:
        env["PYTHONPATH"] = str(pythonpath)
    stub = (
        ""
        if real_rollback
        else "rollback_now() { printf 'ROLLBACK_NOW: %s\\n' \"$*\"; exit 9; }\n"
    )
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'source "{DEPLOY_SH}"\n'
        'WT=""; STAGE=""\n'
        f'VENV="{tmp_path}/venv"; VENV_PREV="{tmp_path}/venv.prev"\n'
        f"{stub}"
        f"{body}\n",
        encoding="utf-8",
    )
    return subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True, env=env
    )


# --------------------------------------------------------------------------- #
# The probe itself
# --------------------------------------------------------------------------- #
def test_probe_ok_reports_the_real_bundle(tmp_path: Path) -> None:
    certifi = pytest.importorskip("certifi")
    _fake_venv(tmp_path)
    proc = _run(tmp_path, 'venv_ssl_probe "$VENV" && rc=0 || rc=$?; echo " RC=$rc"')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"OK — {certifi.where()} RC=0" in proc.stdout


def test_probe_reproduces_the_missing_cacert_incident(tmp_path: Path) -> None:
    _fake_venv(tmp_path)
    site, missing = _broken_certifi(tmp_path)
    proc = _run(tmp_path, 'venv_ssl_probe "$VENV" && rc=0 || rc=$?; echo " RC=$rc"', pythonpath=site)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FAILED (exit 1)" in proc.stdout
    assert "FileNotFoundError" in proc.stdout
    assert proc.stdout.rstrip().endswith("RC=1")
    assert not missing.exists()


def test_probe_writes_no_bytecode(tmp_path: Path) -> None:
    """Phase 1 runs the probe on the live venv: it must not write into it."""
    _fake_venv(tmp_path)
    site, _ = _broken_certifi(tmp_path)
    _run(tmp_path, 'venv_ssl_probe "$VENV"', pythonpath=site)
    assert not list(site.rglob("__pycache__")), "the probe wrote .pyc files (no -B?)"


def test_probe_of_a_venv_without_python_fails(tmp_path: Path) -> None:
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    proc = _run(tmp_path, 'venv_ssl_probe "$VENV" && rc=0 || rc=$?; echo " RC=$rc"')
    assert "FAILED — " in proc.stdout and "missing or not executable" in proc.stdout
    assert proc.stdout.rstrip().endswith("RC=1")


def test_probe_runs_the_exact_aiogram_expression() -> None:
    text = _read(DEPLOY_SH)
    assert "ssl.create_default_context(cafile=certifi.where())" in text
    assert '"$py" -B -c "$SSL_PROBE_PY"' in text


# --------------------------------------------------------------------------- #
# Phase 2: assert_venv_ssl
# --------------------------------------------------------------------------- #
def test_assert_ok_path_continues_and_records_the_line(tmp_path: Path) -> None:
    certifi = pytest.importorskip("certifi")
    _fake_venv(tmp_path)
    proc = _run(tmp_path, 'assert_venv_ssl\necho "POST=${SSL_PROBE_POST}"\necho CONTINUED')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ROLLBACK_NOW" not in proc.stdout
    assert f"POST=OK — {certifi.where()}" in proc.stdout
    assert "CONTINUED" in proc.stdout


def test_assert_failure_path_rolls_back_with_a_clear_message(tmp_path: Path) -> None:
    _fake_venv(tmp_path)
    site, _ = _broken_certifi(tmp_path)
    proc = _run(tmp_path, "assert_venv_ssl\necho CONTINUED", pythonpath=site)
    assert proc.returncode == 9, proc.stdout + proc.stderr
    assert "CONTINUED" not in proc.stdout
    line = next(ln for ln in proc.stdout.splitlines() if ln.startswith("ROLLBACK_NOW: "))
    assert "ssl.create_default_context(cafile=certifi.where())" in line
    assert "FileNotFoundError" in line
    assert "PR #269" in line
    assert f"{tmp_path}/venv.prev" in line, "the message names where the venv comes back from"


def test_failure_goes_through_the_real_rollback_and_restores_the_venv(tmp_path: Path) -> None:
    """The existing rollback path, not a new one: .venv <- .venv.prev, tree -> PREV_SHA."""
    _fake_venv(tmp_path)
    site, _ = _broken_certifi(tmp_path)
    # The pre-deploy venv the snapshot step saved; its pip logs the post-restore check.
    prev = tmp_path / "venv.prev" / "bin"
    prev.mkdir(parents=True)
    for name in ("python", "pip"):
        (prev / name).write_text(
            f'#!/usr/bin/env bash\necho "OLD-VENV {name} $*" >> "{tmp_path}/calls.log"\n', encoding="utf-8"
        )
        (prev / name).chmod(0o755)
    stub = tmp_path / "stub"
    stub.mkdir()
    for name in ("git", "systemctl", "tar"):
        (stub / name).write_text(
            f'#!/usr/bin/env bash\necho "{name} $*" >> "{tmp_path}/calls.log"\nexit 0\n', encoding="utf-8"
        )
        (stub / name).chmod(0o755)
    body = (
        f'export PATH="{stub}:$PATH"\n'
        'PREV_SHA=prevsha0000; VENV_SNAPSHOT_DONE=1; ARCHIVE=""\n'
        f'DB_PATH="{tmp_path}/data/vpn.db"; XRAY_CONF="{tmp_path}/none.json"; AWG_CONF="{tmp_path}/none.conf"\n'
        "fix_db_perms() { return 0; }\n"
        "assert_db_ownership() { echo 'ok'; }\n"
        "assert_restore_permissions() { echo 'ok'; }\n"
        "host_files_rollback() { :; }\n"
        "assert_venv_ssl\n"
        "echo CONTINUED\n"
    )
    proc = _run(tmp_path, body, pythonpath=site, real_rollback=True)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "CONTINUED" not in proc.stdout
    assert "ROLLBACK REPORT" in proc.stderr
    assert "venv restored from snapshot: rc=0" in proc.stderr
    assert "git checkout -f -B main prevsha0000: rc=0" in proc.stderr
    # The live venv IS the pre-deploy one again.
    assert (tmp_path / "venv" / "bin" / "pip").exists()
    assert not (tmp_path / "venv.prev").exists()
    assert "OLD-VENV pip check" in _read(tmp_path / "calls.log")


# --------------------------------------------------------------------------- #
# Placement in the main flow and the two reports
# --------------------------------------------------------------------------- #
def _main_flow() -> str:
    text = _read(DEPLOY_SH)
    return text[text.index('if [[ "${DEPLOY_SELFTEST:-0}" == "1" ]]; then return 0') :]


def test_phase2_probe_sits_after_pip_check_and_before_any_other_mutation() -> None:
    flow = _main_flow()
    phase2 = flow[flow.index("# PHASE 2 — mutate") :]
    armed = phase2.index("\narm_rollback ")
    snapshot = phase2.index("VENV_SNAPSHOT_DONE=1")
    pip_check = phase2.index('"${VENV}/bin/pip" check')
    probe = phase2.index("\nassert_venv_ssl\n")
    helpers = phase2.index("\ninstall_out_of_repo_helpers\n")
    host_files = phase2.index("\ninstall_managed_host_files\n")
    start = phase2.index('systemctl start "$BOT_UNIT"')
    # Armed + snapshotted first: a failure restores the venv from .venv.prev.
    assert armed < snapshot < pip_check < probe < helpers < host_files < start


def test_phase1_probes_the_live_venv_without_gating() -> None:
    flow = _main_flow()
    phase1 = flow[: flow.index("# PHASE 2 — mutate")]
    at = phase1.index('SSL_PROBE_PRE="$(venv_ssl_probe "$VENV")"')
    block = phase1[at : phase1.index("\nfi\n", at)]
    assert "die" not in block, "the Phase 1 probe of the CURRENT deps is report-only"
    assert phase1.index('"prod venv missing at ${VENV}"') < at < phase1.index("phase1_report() {")


def test_both_reports_carry_the_ssl_line() -> None:
    text = _read(DEPLOY_SH)
    report = text[text.index("\nphase1_report() {") : text.index("\n}\n", text.index("\nphase1_report() {"))]
    assert "ssl/certifi" in report and "${SSL_PROBE_PRE" in report
    ok = text[text.index("===== DEPLOY OK =====") :]
    assert "ssl/certifi      : ${SSL_PROBE_POST" in ok[: ok.index("EOF")]
