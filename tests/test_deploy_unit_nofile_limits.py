"""Guard on the file-descriptor ceiling of the shipped Python systemd units.

Measured on the production host 2026-08-11: both long-running Python services ran
with the systemd default soft limit of 1024 open files —

    PID 1050  /opt/vpn-service/.venv/bin/python /opt/vpn-service/main.py
    PID  700  /opt/vpn-service/.venv/bin/python -m subscription_server

— because their units carried no LimitNOFILE, while the backends beside them set
theirs explicitly (xray 1000000, hysteria 524287). The subscription endpoint is a
network service listening on the public port, so 1024 is a low ceiling for it.

These tests parse the unit FILES IN THE REPO and nothing else: no `systemctl`, no
`/proc`, no network. That is deliberate — this suite runs as a Phase 1 gate on the
production host itself (see the pytest timeout note in pyproject.toml), and tests
that peeked at the live host have failed here before. What ships in deploy/ is what
is under test; whether a given host has caught up is a deploy question, not a test
question.

Style follows tests/test_deploy_helper_install.py: content guards over shipped
deploy artifacts, keyed on the repo checkout.
"""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_DIR = ROOT / "deploy"

# Per-test wall-clock ceiling (pytest-timeout). Everything here is a handful of
# small file reads, so anything near this limit is a hang, not slow work.
pytestmark = pytest.mark.timeout(60)

# Interpreter path that marks a unit as one of this project's Python services.
PROJECT_PYTHON = "/opt/vpn-service/.venv/bin/python"

# The floor this repo commits to. A literal, not `infinity`: the host hard limit is
# 524288 and none of these processes work with hundreds of thousands of descriptors.
MIN_NOFILE = 65536

# Every Python unit shipped under deploy/, pinned by name so a rename or a typo in
# the discovery below cannot quietly make the whole guard vacuous, and so a NEW
# Python unit has to be added here consciously (with its LimitNOFILE).
#
# NOTE ON NAMES: the repo ships deploy/vpn-bot-hy2-auth.service while the host runs
# it as `vpnbot-hy2-auth.service`. That divergence is known and intentional here —
# deploy.sh reports the repo file as "not installed / reconcile if this is a rename"
# rather than failing. Do not "fix" it by renaming the file.
EXPECTED_PYTHON_UNITS = frozenset(
    {
        "vpn-bot.service",                        # main.py — the only unit deploy.sh installs
        "vpn-bot-subscription.service",           # -m subscription_server — installed by hand
        "vpn-bot-hy2-auth.service",               # -m hy2_auth — installed by hand (vpnbot-hy2-auth)
        "vpn-bot.nonroot.example.service",        # reference variants of vpn-bot.service; not
        "vpn-bot.root-legacy.example.service",    # installed by deploy.sh, but same process
    }
)


def _active_lines(text: str, section: str) -> list[str]:
    """Return the non-comment, non-blank lines of one section of a unit file.

    Comments are dropped so a directive named only in a unit's prose header can
    neither satisfy nor trip a check — the same rule deploy/check-nonroot-helper-mode.py
    applies.
    """
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            continue
        if current == section:
            lines.append(line)
    return lines


def _values(lines: list[str], directive: str) -> list[str]:
    prefix = f"{directive}="
    return [line[len(prefix) :].strip() for line in lines if line.startswith(prefix)]


def _python_units() -> dict[str, list[str]]:
    """Map unit filename -> active [Service] lines, for units running project Python."""
    units: dict[str, list[str]] = {}
    for path in sorted(DEPLOY_DIR.glob("*.service")):
        service = _active_lines(path.read_text(encoding="utf-8"), "Service")
        if any(PROJECT_PYTHON in value for value in _values(service, "ExecStart")):
            units[path.name] = service
    return units


def test_discovery_matches_the_pinned_python_unit_inventory() -> None:
    """The set of Python units in deploy/ is exactly the pinned one.

    Without this, a renamed unit (or a broken ExecStart match) would silently reduce
    the guard below to "assert nothing about nothing".
    """
    assert set(_python_units()) == set(EXPECTED_PYTHON_UNITS)


@pytest.mark.parametrize("unit", sorted(EXPECTED_PYTHON_UNITS))
def test_python_unit_sets_limitnofile_once(unit: str) -> None:
    """Exactly one LimitNOFILE per unit — a second one silently wins over the first."""
    service = _python_units()[unit]
    values = _values(service, "LimitNOFILE")
    assert len(values) == 1, f"{unit}: expected one LimitNOFILE in [Service], found {len(values)}"


@pytest.mark.parametrize("unit", sorted(EXPECTED_PYTHON_UNITS))
def test_python_unit_limitnofile_is_at_least_the_floor(unit: str) -> None:
    """Both the soft and the hard column must be >= 65536.

    `LimitNOFILE=` takes either a single value (applied to both) or `soft:hard`, so
    both forms are checked here.
    """
    (value,) = _values(_python_units()[unit], "LimitNOFILE")
    parts = value.split(":")
    assert len(parts) in (1, 2), f"{unit}: unparseable LimitNOFILE={value}"
    for part in parts:
        assert part.isdigit(), (
            f"{unit}: LimitNOFILE={value} must be a decimal literal, not {part!r} — "
            "`infinity` is deliberately not used (host hard limit is 524288)"
        )
        assert int(part) >= MIN_NOFILE, (
            f"{unit}: LimitNOFILE={value} is below the {MIN_NOFILE} floor"
        )


def test_the_two_measured_services_are_covered() -> None:
    """Anchor on the ExecStart lines of the two processes measured at soft 1024, so
    the guard stays tied to the real services and not just to filenames."""
    units = _python_units()
    execs = {unit: " ".join(_values(service, "ExecStart")) for unit, service in units.items()}
    assert "/opt/vpn-service/main.py" in execs["vpn-bot.service"]
    assert "-m subscription_server" in execs["vpn-bot-subscription.service"]
    assert "-m hy2_auth" in execs["vpn-bot-hy2-auth.service"]
