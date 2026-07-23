"""Self-diagnostic allowlist for the running-but-not-watched detector.

Background
----------
`scripts/redeploy.sh` launches `scripts/deploy.sh` DETACHED as a transient systemd
unit (`systemd-run --unit="${DEPLOY_UNIT:-vpn-bot-deploy}"`). So while a deploy is
running, the host is genuinely running a `vpn-bot-deploy.service` — the deploy
EXECUTOR itself. That name matches the `vpn|xray|awg|...` filter inside
`running_not_watched()`, so on the 2026-07-22 run the Phase 1 report flagged its own
carrier unit as a "RUNNING but NOT WATCHED" rename/config-gap. It is a guaranteed
false positive on EVERY run, and a block that cries wolf every time trains the eye to
skip it — defeating the detector that exists to catch REAL renames.

The fix adds a named `DEPLOY_SELF_UNITS` allowlist next to `UNIT_SET` and excludes
those units from THIS detector only (UNIT_SET, the health check, and every drift/
absent scan are untouched). The genuine reverse-drift signal must survive intact.

These guards drive the real `running_not_watched()` through the documented
`DEPLOY_SELFTEST=1` source seam, shadowing `systemctl` with a bash function that
prints canned `list-units` output. Nothing here runs a real `systemctl`, touches the
network, reads a production `.env`, or looks at host paths — it only reads files
inside the repo and runs bash on a self-sourced copy of the script.
"""

import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
REDEPLOY_SH = ROOT / "scripts" / "redeploy.sh"

# A realistic `systemctl list-units --no-legend` block: first column is the unit
# name; the detector's awk grabs the first `*.service` token per line. Mixes the
# deploy carrier, two genuine reverse-drifts (one of them a `vpn-*` name, to prove
# the allowlist is EXACT and does not broadly mute every vpn/awg service), a watched
# unit, and services that do not match the filter at all.
LIST_UNITS = """\
vpn-bot-deploy.service       loaded active running Transient carrier for the running deploy
vpn-extra.service            loaded active running Some unwatched vpn-ish backend
xray.service                 loaded active running Xray backend (watched)
awg-office.service           loaded active running AmneziaWG tunnel (unwatched)
sshd.service                 loaded active running OpenSSH server
systemd-journald.service     loaded active running Journal
"""


def _run_detector(
    list_units_output: str,
    unit_set: list[str],
    self_units: list[str] | None = None,
) -> list[str]:
    """Source deploy.sh via the selftest seam, shadow `systemctl`, and return the
    lines `running_not_watched` prints for the given running set / UNIT_SET.

    `self_units=None` keeps the real `DEPLOY_SELF_UNITS` from the script; passing a
    list overrides it (used to reproduce the false positive and to prove suffix
    tolerance).
    """
    unit_set_lit = " ".join(f'"{u}"' for u in unit_set)
    override = ""
    if self_units is not None:
        self_lit = " ".join(f'"{u}"' for u in self_units)
        override = f"DEPLOY_SELF_UNITS=({self_lit})\n"

    driver = (
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic (WT/STAGE/VENV are unset
        # before the seam's early return; the cleanup trap reads them under set -u).
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        "set +e\n"
        # Shadow the real systemctl: only the detector's list-units query is
        # intercepted; everything else is a harmless no-op.
        "systemctl() {\n"
        '  if [[ "${1:-}" == "list-units" ]]; then\n'
        "    cat <<'__LU__'\n"
        f"{list_units_output}"
        "__LU__\n"
        "    return 0\n"
        "  fi\n"
        "  return 0\n"
        "}\n"
        f"UNIT_SET=({unit_set_lit})\n"
        f"{override}"
        'echo "___BEGIN___"\n'
        "running_not_watched\n"
        "rc=$?\n"
        'echo "___END___"\n'
        'echo "___RC=${rc}___"\n'
    )
    proc = subprocess.run(
        ["bash", "-c", driver], capture_output=True, text=True, cwd="/tmp"
    )
    assert proc.returncode == 0, f"driver died: {proc.stdout}\n{proc.stderr}"
    assert "___RC=0___" in proc.stdout, f"detector returned non-zero:\n{proc.stdout}\n{proc.stderr}"
    assert "Broken pipe" not in proc.stderr, proc.stderr
    body = proc.stdout.split("___BEGIN___", 1)[1].split("___END___", 1)[0]
    return [ln.strip() for ln in body.splitlines() if ln.strip()]


# --------------------------------------------------------------------------- #
# Functional guards: drive the real running_not_watched() through the seam.
# --------------------------------------------------------------------------- #
def test_deploy_carrier_unit_is_filtered_out() -> None:
    """`vpn-bot-deploy.service` (the deploy executor) must NOT be reported, even
    though it matches the vpn filter and is not in UNIT_SET."""
    reported = _run_detector(LIST_UNITS, unit_set=["xray.service"])
    assert "vpn-bot-deploy.service" not in reported, reported


def test_genuine_reverse_drift_still_reported() -> None:
    """The allowlist must be surgical: real unwatched services — including other
    `vpn-*` names — are still flagged. Only the deploy carrier is suppressed."""
    reported = _run_detector(LIST_UNITS, unit_set=["xray.service"])
    assert set(reported) == {"vpn-extra.service", "awg-office.service"}, reported


def test_watched_and_nonmatching_units_are_untouched() -> None:
    """A watched unit (in UNIT_SET) and services outside the filter never appear —
    the allowlist does not change either behaviour."""
    reported = _run_detector(LIST_UNITS, unit_set=["xray.service"])
    assert "xray.service" not in reported  # in UNIT_SET
    assert "sshd.service" not in reported  # outside the vpn/xray/... filter
    assert "systemd-journald.service" not in reported


def test_empty_allowlist_reproduces_the_false_positive() -> None:
    """Guard-the-guard: with the allowlist emptied, the deploy carrier reappears in
    the report. This proves the allowlist (not some coincidence) is what suppresses
    the false positive, so silently emptying DEPLOY_SELF_UNITS would fail here."""
    reported = _run_detector(LIST_UNITS, unit_set=["xray.service"], self_units=[])
    assert "vpn-bot-deploy.service" in reported, reported


def test_allowlist_is_suffix_tolerant() -> None:
    """DEPLOY_UNIT is overridable and systemd-run appends `.service` only when the
    name lacks a unit suffix, so membership is tested on the suffix-stripped name.
    A bare `vpn-bot-deploy` allowlist entry must still filter `vpn-bot-deploy.service`."""
    reported = _run_detector(
        LIST_UNITS, unit_set=["xray.service"], self_units=["vpn-bot-deploy"]
    )
    assert "vpn-bot-deploy.service" not in reported, reported


def test_only_carrier_running_yields_empty_list() -> None:
    """When the deploy carrier is the ONLY matching service running, the detector
    returns nothing — so the report's `else` branch prints an explicit 'none' rather
    than the alarm block. The block is never suppressed wholesale, only filtered."""
    only_carrier = (
        "vpn-bot-deploy.service   loaded active running Transient carrier\n"
        "sshd.service             loaded active running OpenSSH server\n"
    )
    reported = _run_detector(only_carrier, unit_set=["xray.service"])
    assert reported == [], reported


# --------------------------------------------------------------------------- #
# Static guards: the allowlist exists, is documented, and stays in sync with the
# unit name redeploy.sh actually launches the deploy under.
# --------------------------------------------------------------------------- #
def test_deploy_sh_declares_the_allowlist_with_the_default_unit() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert "declare -a DEPLOY_SELF_UNITS=(" in text
    assert "vpn-bot-deploy.service" in text
    # running_not_watched must actually consult it.
    detector = text.split("running_not_watched()", 1)[1]
    assert "DEPLOY_SELF_UNITS" in detector.split("\n}", 1)[0]


def test_allowlist_matches_redeploy_default_deploy_unit() -> None:
    """The allowlist entry must track the transient unit name redeploy.sh launches:
    `DEPLOY_UNIT="${DEPLOY_UNIT:-vpn-bot-deploy}"`. If that default is ever renamed,
    this fails so the allowlist is updated in lockstep."""
    redeploy = REDEPLOY_SH.read_text(encoding="utf-8")
    m = re.search(r'DEPLOY_UNIT="\$\{DEPLOY_UNIT:-([a-z0-9-]+)\}"', redeploy)
    assert m, "could not find the DEPLOY_UNIT default in redeploy.sh"
    default_unit = m.group(1)
    assert default_unit == "vpn-bot-deploy"
    deploy = DEPLOY_SH.read_text(encoding="utf-8")
    assert f"{default_unit}.service" in deploy
