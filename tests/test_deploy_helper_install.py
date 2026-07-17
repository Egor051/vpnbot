"""Guards + behavioural coverage for the deploy helper-install step and the
`scripts/redeploy.sh` wrapper.

Two kinds of checks live here:

1. Content guards on the shipped shell (`scripts/deploy.sh`, `scripts/redeploy.sh`)
   and the deploy docs, so the documented env knobs, the out-of-repo helper
   refresh, and the redeploy wrapper cannot be silently removed or reworded away.

2. Behavioural tests that drive the real bash functions
   `scan_out_of_repo_helpers` / `install_out_of_repo_helpers` through the
   `DEPLOY_SELFTEST=1` seam (which sources every definition and returns before a
   real deploy), with stubbed `systemctl`/`install`. These assert the actual
   drift-close logic: which helpers get reinstalled, when `warp-routes` is
   restarted, and that a restart failure routes through rollback while a skipped
   data-plane probe (exit 0) does not.
"""

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
REDEPLOY_SH = ROOT / "scripts" / "redeploy.sh"

WARP_HELPERS = (
    "vpn-bot-warp-install",
    "vpn-bot-warp-iface",
    "vpn-bot-warp-routes",
    "vpn-bot-warp-status",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Content guards: deploy.sh env-knob documentation (Task 3a)
# --------------------------------------------------------------------------- #
def test_deploy_sh_documents_every_behaviour_env_knob() -> None:
    text = _read(DEPLOY_SH)
    # The header carries a dedicated ENVIRONMENT KNOBS block documenting each one.
    assert "ENVIRONMENT KNOBS" in text
    for knob in ("PHASE1_ONLY", "FORCE", "ALLOW_MODEL_SWITCH", "ALLOW_UNIT_DRIFT", "DEPLOY_SELFTEST"):
        assert knob in text, f"env knob {knob} must be documented in the header"


def test_allow_unit_drift_doc_flags_it_as_a_real_gate_bypass() -> None:
    """ALLOW_UNIT_DRIFT must be documented as bypassing the real drift gate, to be
    applied only consciously when the drift is known and safe (Task 3a)."""
    text = _read(DEPLOY_SH)
    # Locate the ALLOW_UNIT_DRIFT knob paragraph in the header block.
    idx = text.index("ALLOW_UNIT_DRIFT=1")
    window = text[idx : idx + 900].lower()
    assert "gate" in window and ("bypass" in window or "bypasses" in window)
    assert "known" in window and "safe" in window


# --------------------------------------------------------------------------- #
# Content guards: deploy.sh out-of-repo helper refresh (Task 1)
# --------------------------------------------------------------------------- #
def test_deploy_sh_defines_and_calls_helper_install_step() -> None:
    text = _read(DEPLOY_SH)
    # The function exists and is actually invoked in Phase 2.
    assert "install_out_of_repo_helpers()" in text
    assert "\ninstall_out_of_repo_helpers\n" in text, "Phase 2 must call the helper-install step"
    # The exact install command the task requires.
    assert "install -o root -g root -m 0755" in text
    # daemon-reload + restart warp-routes on a changed routes helper.
    assert "systemctl daemon-reload" in text
    assert 'systemctl restart "$WARP_ROUTES_UNIT"' in text


def test_deploy_sh_lists_all_four_warp_helpers() -> None:
    text = _read(DEPLOY_SH)
    for helper in WARP_HELPERS:
        assert f"/usr/local/sbin/{helper}" in text, f"{helper} must be in OUT_OF_REPO_HELPERS"


def test_deploy_sh_helper_step_runs_after_tree_advance_and_before_unit_install() -> None:
    """The refresh must happen after `git reset --hard origin/main` (fresh source)
    and before the unit install (so units execute the current helper)."""
    text = _read(DEPLOY_SH)
    tree_advance = text.index("git reset --hard origin/main")
    helper_call = text.index("\ninstall_out_of_repo_helpers\n")
    unit_install = text.index('install -m0644 "deploy/vpn-bot.service"')
    assert tree_advance < helper_call < unit_install


def test_deploy_sh_helper_restart_tolerates_skipped_dataplane_probe() -> None:
    """A skipped data-plane self-check (idle client, #242) exits 0 and must not
    fail the deploy; only a real routing failure does. The code comments must pin
    that intent so it is not "cleaned up" into a hard fail on skip."""
    text = _read(DEPLOY_SH).lower()
    assert "skip" in text and "self-check" in text
    # The restart handler explicitly frames a non-zero exit as a REAL failure.
    assert "real routing failure" in text


def test_deploy_sh_phase1_reports_helper_drift_without_a_gate() -> None:
    text = _read(DEPLOY_SH)
    # Phase 1 scans helper drift read-only against the origin/main worktree ($WT).
    assert 'scan_out_of_repo_helpers "$WT"' in text
    # The report has a dedicated helper-drift section.
    assert "Out-of-repo helper drift" in text


# --------------------------------------------------------------------------- #
# Content guards: redeploy.sh wrapper (Task 2)
# --------------------------------------------------------------------------- #
def test_redeploy_sh_exists_and_is_executable() -> None:
    assert REDEPLOY_SH.exists()
    assert os.access(REDEPLOY_SH, os.X_OK)


def test_redeploy_sh_structure() -> None:
    text = _read(REDEPLOY_SH)
    assert "set -euo pipefail" in text
    # root guard
    assert 'EUID' in text and 'run as root' in text
    # operates from the checkout
    assert "cd \"$APP_DIR\"" in text
    # fetch origin/main only
    assert "git fetch origin main" in text
    # shows host HEAD vs origin/main
    assert "rev-parse --short HEAD" in text and "rev-parse --short origin/main" in text
    # takes deploy.sh from tip-of-main, not the working tree
    assert "git show origin/main:scripts/deploy.sh" in text
    # clears stale failed state, then launches detached under systemd
    assert "systemctl reset-failed" in text
    assert "systemd-run --unit=\"$DEPLOY_UNIT\"" in text
    assert "--collect --pty" in text
    assert "| tee" in text


def test_redeploy_sh_maps_check_and_force_to_deploy_env() -> None:
    text = _read(REDEPLOY_SH)
    # CHECK=1 -> PHASE1_ONLY=1; FORCE passed through.
    assert 'PHASE1_ONLY=1' in text
    assert '[[ "$CHECK" == "1" ]] && deploy_env+=("PHASE1_ONLY=1")' in text
    assert '[[ "$FORCE" == "1" ]] && deploy_env+=("FORCE=1")' in text


def test_redeploy_sh_does_not_install_helpers_itself() -> None:
    """The wrapper must delegate the helper refresh to deploy.sh, not duplicate it.
    (It may *mention* install_out_of_repo_helpers in a comment, but must never run
    an install command or invoke the function itself.)"""
    text = _read(REDEPLOY_SH)
    assert "install -o root -g root" not in text
    assert "install -m0" not in text
    # No line invokes the function as a command (a comment reference is fine).
    assert "\ninstall_out_of_repo_helpers" not in text


def test_redeploy_sh_parses() -> None:
    subprocess.run(["bash", "-n", str(REDEPLOY_SH)], check=True)


# --------------------------------------------------------------------------- #
# Content guards: docs (Task 3b / 3c)
# --------------------------------------------------------------------------- #
def test_operations_runbook_documents_rollback_data_window() -> None:
    text = _read(ROOT / "docs" / "operations.md")
    # The specific rule: rollback discards writes made in the ~60s health-poll
    # window, so mutating deploys go in a low-traffic window.
    assert "health-poll" in text or "health poll" in text
    assert "HEALTH_TIMEOUT" in text and "60" in text
    assert "low-traffic" in text
    assert "vanish" in text.lower() or "lost" in text.lower()


def test_docs_reference_redeploy_wrapper() -> None:
    readme = _read(ROOT / "README.md")
    ops = _read(ROOT / "docs" / "operations.md")
    assert "scripts/redeploy.sh" in readme
    assert "sudo CHECK=1 bash scripts/redeploy.sh" in readme
    assert "scripts/redeploy.sh" in ops


# --------------------------------------------------------------------------- #
# Behavioural tests: drive the real bash functions via the DEPLOY_SELFTEST seam
# --------------------------------------------------------------------------- #
def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _driver(tmp_path: Path, *, installed: dict[str, str], sources: dict[str, str],
            mode: str, warp_pre: str = "active", fail_restart: bool = False,
            stub_rollback: bool = False) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh (selftest seam) and call one helper function under stubs.

    installed: helper basename -> file contents to place in the fake /usr/local/sbin
               (omit a name to leave it absent).
    sources:   helper basename -> file contents for the fake checkout scripts/ dir.
    mode:      'scan' or 'install'.
    """
    stub_dir = tmp_path / "stub"
    app_dir = tmp_path / "repo"
    sbin = tmp_path / "sbin"
    for d in (stub_dir, app_dir / "scripts", sbin):
        d.mkdir(parents=True, exist_ok=True)

    for name, content in sources.items():
        (app_dir / "scripts" / name).write_text(content, encoding="utf-8")
    for name, content in installed.items():
        (sbin / name).write_text(content, encoding="utf-8")

    sc_log = tmp_path / "systemctl.log"
    _make_stub(stub_dir / "systemctl", (
        f'echo "systemctl $*" >> "{sc_log}"\n'
        'if [[ "${SYSTEMCTL_FAIL_RESTART:-0}" == "1" && "$1" == "restart" ]]; then exit 1; fi\n'
        'exit 0\n'
    ))
    # Minimal `install` stub: ignore -o/-g/-m, copy the last two args (src dst).
    _make_stub(stub_dir / "install", (
        'args=()\n'
        'while [[ $# -gt 0 ]]; do case "$1" in\n'
        '  -o|-g|-m) shift 2 ;;\n'
        '  -d) shift ;;\n'
        '  *) args+=("$1"); shift ;;\n'
        'esac; done\n'
        'cp "${args[0]}" "${args[1]}"\n'
    ))

    helper_lines = "\n".join(
        f'  "scripts/{name}|{sbin}/{name}"' for name in WARP_HELPERS
    )
    rollback_override = (
        'rollback() { echo "ROLLBACK_CALLED"; exit 42; }\n' if stub_rollback else ""
    )
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub_dir}:$PATH"\n'
        f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic for the test environment.
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        f'APP_DIR="{app_dir}"\n'
        f"OUT_OF_REPO_HELPERS=(\n{helper_lines}\n)\n"
        f'WARP_ROUTES_HELPER="{sbin}/vpn-bot-warp-routes"\n'
        'WARP_ROUTES_UNIT="warp-routes.service"\n'
        f'U_PRE_ACTIVE["warp-routes.service"]="{warp_pre}"\n'
        f"{rollback_override}"
        f'if [[ "{mode}" == "scan" ]]; then scan_out_of_repo_helpers "$APP_DIR"; '
        f'else install_out_of_repo_helpers; fi\n',
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["SYSTEMCTL_FAIL_RESTART"] = "1" if fail_restart else "0"
    proc = subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path), env=env,
        capture_output=True, text=True,
    )
    # Fold stderr (where `warn`/`die` write) and the recorded systemctl calls into
    # the searchable stdout so assertions can see log AND warn lines uniformly.
    proc.stdout += (
        "\n---STDERR---\n" + proc.stderr
        + "\n---SYSTEMCTL---\n" + (sc_log.read_text() if sc_log.exists() else "")
    )
    # Stash resolved paths for assertions.
    proc.args = {"sbin": sbin, "app_dir": app_dir}  # type: ignore[assignment]
    return proc


def test_scan_classifies_absent_synced_and_drift(tmp_path: Path) -> None:
    proc = _driver(
        tmp_path,
        sources={n: "SRC\n" for n in WARP_HELPERS},
        installed={
            "vpn-bot-warp-routes": "OLD\n",     # drift
            "vpn-bot-warp-status": "SRC\n",     # synced
            # install + iface absent
        },
        mode="scan",
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "vpn-bot-warp-routes|" in out and "|drift" in out
    assert "vpn-bot-warp-status|" in out and "|synced" in out
    assert "vpn-bot-warp-install|" in out and "|absent" in out
    assert "vpn-bot-warp-iface|" in out and "|absent" in out


def test_install_reinstalls_drifted_routes_and_restarts_when_active(tmp_path: Path) -> None:
    proc = _driver(
        tmp_path,
        sources={n: "NEW\n" for n in WARP_HELPERS},
        installed={
            "vpn-bot-warp-routes": "OLD\n",   # drift -> reinstall + restart
            "vpn-bot-warp-status": "NEW\n",   # synced
        },
        mode="install",
        warp_pre="active",
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    sbin = proc.args["sbin"]  # type: ignore[index]
    # The drifted routes helper now matches the fresh source.
    assert (sbin / "vpn-bot-warp-routes").read_text() == "NEW\n"
    # A changed routes helper on an active unit triggers reload + restart.
    assert "systemctl daemon-reload" in proc.stdout
    assert "systemctl restart warp-routes.service" in proc.stdout
    # Absent helpers were left absent (WARP partly deployed here).
    assert not (sbin / "vpn-bot-warp-install").exists()
    assert "drift closed" in proc.stdout


def test_install_does_not_restart_when_only_a_nonroutes_helper_drifts(tmp_path: Path) -> None:
    proc = _driver(
        tmp_path,
        sources={n: "NEW\n" for n in WARP_HELPERS},
        installed={
            "vpn-bot-warp-routes": "NEW\n",    # synced -> no restart
            "vpn-bot-warp-status": "OLD\n",    # drift, but not the routes helper
        },
        mode="install",
        warp_pre="active",
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    sbin = proc.args["sbin"]  # type: ignore[index]
    assert (sbin / "vpn-bot-warp-status").read_text() == "NEW\n"
    assert "systemctl restart warp-routes.service" not in proc.stdout


def test_install_reinstalls_routes_but_skips_restart_when_inactive(tmp_path: Path) -> None:
    """A drifted routes helper is still refreshed, but warp-routes is NOT restarted
    when it was not active pre-deploy (respect operator intent)."""
    proc = _driver(
        tmp_path,
        sources={n: "NEW\n" for n in WARP_HELPERS},
        installed={"vpn-bot-warp-routes": "OLD\n"},
        mode="install",
        warp_pre="inactive",
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    sbin = proc.args["sbin"]  # type: ignore[index]
    assert (sbin / "vpn-bot-warp-routes").read_text() == "NEW\n"  # still refreshed
    assert "systemctl restart warp-routes.service" not in proc.stdout
    assert "not restarted" in proc.stdout.lower()


def test_install_routes_a_real_restart_failure_through_rollback(tmp_path: Path) -> None:
    """A non-zero warp-routes restart (a REAL routing failure, not a skip) must
    route through rollback — proving the deploy is not left half-applied."""
    proc = _driver(
        tmp_path,
        sources={n: "NEW\n" for n in WARP_HELPERS},
        installed={"vpn-bot-warp-routes": "OLD\n"},
        mode="install",
        warp_pre="active",
        fail_restart=True,
        stub_rollback=True,
    )
    assert proc.returncode == 42, proc.stdout + proc.stderr
    assert "ROLLBACK_CALLED" in proc.stdout


def test_install_is_noop_when_everything_is_in_sync(tmp_path: Path) -> None:
    proc = _driver(
        tmp_path,
        sources={n: "SAME\n" for n in WARP_HELPERS},
        installed={n: "SAME\n" for n in WARP_HELPERS},
        mode="install",
        warp_pre="active",
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "systemctl restart warp-routes.service" not in proc.stdout
    assert "no drift to close" in proc.stdout
