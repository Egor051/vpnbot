"""The relay role's unit set: one rule, installed whole by the relay deploy.

The 2026-11 relay deploy rolled back on its own host invariants gate: scripts/install.sh
(relay mode) installs vpn-relay.service AND vpn-relay-resolve.{service,timer}, the host
check expects every deploy/relay/*.service|*.timer, but scripts/deploy.sh (NODE_ROLE=
relay) installed vpn-relay.service only — so the gate found the two resolve units
missing ("MISMATCH unit ... the repo installs ..., but it is not on the host") and
rolled a healthy relay back. Pinned here:

1. **One rule.** ``relay_unit_names`` — every deploy/relay/*.service|*.timer, never an
   *.example.* — is carried verbatim by deploy.sh, install.sh and vpn-bot-host-check;
   the three sets are equal on the repo and on a checkout with units the repo does not
   have; neither installer names a unit of the set in code; every other .service of the
   set is the oneshot a timer of the set runs.
2. **install.sh** installs, enables and (re)starts by that set.
3. **deploy.sh, end to end against the REAL host check**: the production relay — a
   repo vpn-relay.service, no resolve units — gets them installed, the timer enabled
   and started, the oneshot never started by hand, host invariants clean, DEPLOY OK;
   a second deploy finds everything synced and changes nothing; ANY unit of the set
   missing after Phase 2 rolls the deploy back (the gate stays where it is).
4. **The rollback** backs up every unit, removes the ones that were not there, stops /
   disables a timer that was not active / enabled, keeps one that was, and its report
   names every unit.
5. **`vpn-relay-apply resolve`** with RELAY_UPSTREAM_IPV4 (the production relay) is a
   no-op that exits 0, touching nothing.
6. **The absent-ok reason** comes from the registry entry: the relay agent is "installed
   at pairing from the bot", never "WARP not deployed".

deploy.sh runs this suite AS ROOT on the relay itself in Phase 1: everything lives
under tmp_path, every command that could touch the host is a stub.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from tests.test_host_check import (
    CHECK,
    DPKG,
    DPKG_QUERY,
    EMPTY_INVARIANTS,
    LOGROTATE,
    SSHD,
    SYSTEMD_ANALYZE,
    HostLab,
)
from tests.test_install_relay import _ok, _run
from tests.test_relay_deploy import (
    FAKE_HELPER,
    INSTALL_STUB,
    MANUAL_UNIT,
    RELAY_SYSTEMCTL,
    RELAY_UNIT_FILES,
    RELAY_UNIT_NAMES,
    REPO_UNIT,
    RESOLVE_SERVICE,
    RESOLVE_TIMER,
    RelayHost,
    _phase1_worktree,
    _read,
    _shared_functions_output,
    _stub,
)
from tests.test_vpn_relay_apply import Relay

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
INSTALL_SH = ROOT / "scripts" / "install.sh"
HOST_CHECK = ROOT / "scripts" / "vpn-bot-host-check"
ENV_EXAMPLE = ROOT / "deploy" / "relay" / "relay.env.example"
DATA_PLANE = "vpn-relay.service"

pytestmark = pytest.mark.timeout(60)


def _function(path: Path, name: str) -> str:
    text = _read(path)
    start = text.index(f"\n{name}() {{\n") + 1
    return text[start : text.index("\n}\n", start) + 3]


def _names_by(script: Path, checkout: Path) -> set[str]:
    """relay_unit_names of <script> run on <checkout>."""
    proc = subprocess.run(
        ["bash", "-c", _function(script, "relay_unit_names") + 'relay_unit_names "$1"\n', "x", str(checkout)],
        capture_output=True, text=True, check=True,
    )
    lines = proc.stdout.splitlines()
    assert len(lines) == len(set(lines)), lines
    return set(lines)


def _odd_checkout(tmp_path: Path) -> Path:
    """The repo's units plus ones the repo does not have, an example and a non-unit."""
    checkout = tmp_path / "checkout"
    (checkout / "deploy" / "relay").mkdir(parents=True)
    for src in RELAY_UNIT_FILES:
        (checkout / "deploy" / "relay" / src.name).write_text(_read(src), encoding="utf-8")
    extra = {
        "vpn-relay-extra.timer": "[Timer]\nOnUnitActiveSec=1h\nUnit=vpn-relay-extra.service\n[Install]\nWantedBy=timers.target\n",
        "vpn-relay-extra.service": "[Service]\nType=oneshot\nExecStart=/bin/true\n",
        "x.example.service": "[Service]\n",
        "relay.env.example": "NODE_ROLE=relay\n",
        "notes.txt": "not a unit\n",
    }
    for name, body in extra.items():
        (checkout / "deploy" / "relay" / name).write_text(body, encoding="utf-8")
    return checkout


# --------------------------------------------------------------------------- #
# 1. One rule
# --------------------------------------------------------------------------- #
def test_the_three_scripts_carry_one_relay_unit_names_body() -> None:
    bodies = {p.name: _function(p, "relay_unit_names") for p in (DEPLOY_SH, INSTALL_SH, HOST_CHECK)}
    assert len(set(bodies.values())) == 1, bodies
    assert '/deploy/relay/*.service' in bodies["deploy.sh"] and '/deploy/relay/*.timer' in bodies["deploy.sh"]
    assert "*.example.*" in bodies["deploy.sh"]


@pytest.mark.parametrize("which", ["repo", "odd"])
def test_install_deploy_and_host_check_see_the_same_set(tmp_path: Path, which: str) -> None:
    checkout = ROOT if which == "repo" else _odd_checkout(tmp_path)
    sets = {p.name: _names_by(p, checkout) for p in (DEPLOY_SH, INSTALL_SH, HOST_CHECK)}
    assert sets["deploy.sh"] == sets["install.sh"] == sets["vpn-bot-host-check"], sets
    if which == "repo":
        assert sets["deploy.sh"] == RELAY_UNIT_NAMES == {DATA_PLANE, RESOLVE_SERVICE, RESOLVE_TIMER}
    else:
        assert sets["deploy.sh"] == RELAY_UNIT_NAMES | {"vpn-relay-extra.timer", "vpn-relay-extra.service"}


def test_the_real_host_check_expects_exactly_that_set(tmp_path: Path) -> None:
    """Not just the function: what vpn-bot-host-check (role relay) actually judges."""
    lab = HostLab(tmp_path / "lab")
    checkout = _odd_checkout(tmp_path)
    for f in (checkout / "deploy" / "relay").iterdir():
        lab.repo_file(f"deploy/relay/{f.name}", _read(f))
    names = _names_by(DEPLOY_SH, lab.repo)
    for name in names:
        lab.host(f"etc/systemd/system/{name}", _read(lab.repo / "deploy" / "relay" / name))
        lab.unit(name, LoadState="loaded", FragmentPath=f"/etc/systemd/system/{name}", NeedDaemonReload="no",
                 DropInPaths="", UnitFileState="enabled", ActiveState="active")
    res = lab.run(role="relay")
    judged = {r[2] for r in res.rows if r[1] == "unit"}
    assert judged == names, res.out
    assert {r[2] for r in res.verdicts("OK") if r[1] == "unit"} == names, res.out


def test_neither_installer_names_a_unit_of_the_set_in_code() -> None:
    """No hard-coded list: a unit is in the set because it is in deploy/relay/. The
    data plane (vpn-relay.service) is the one unit addressed by name."""
    for path in (DEPLOY_SH, INSTALL_SH):
        code = [ln for ln in _read(path).splitlines() if not ln.lstrip().startswith("#")]
        hits = [ln for ln in code if "vpn-relay-resolve" in ln]
        assert hits == [], f"{path.name}: {hits}"
    assert "RELAY_UNITS=(vpn-relay" not in _read(INSTALL_SH)


def test_every_other_service_of_the_set_is_run_by_a_timer_of_the_set() -> None:
    """deploy.sh installs such a service and never starts it (relay_unit_kind
    timer-run): that is only right while a timer of the set runs it."""
    timers = {p.name: _read(p) for p in RELAY_UNIT_FILES if p.suffix == ".timer"}
    assert timers, "the set has a timer"
    for unit in RELAY_UNIT_FILES:
        if unit.suffix != ".service" or unit.name == DATA_PLANE:
            continue
        runners = [
            t for t, body in timers.items()
            if re.search(rf"^Unit={re.escape(unit.name)}$", body, re.M)
            or (t.removesuffix(".timer") == unit.name.removesuffix(".service") and not re.search(r"^Unit=", body, re.M))
        ]
        assert runners, f"{unit.name}: no timer of deploy/relay/ runs it"
        assert "Type=oneshot" in _read(unit), unit.name


# --------------------------------------------------------------------------- #
# 2. install.sh (relay mode) by the set
# --------------------------------------------------------------------------- #
def _installer_checkout(tmp_path: Path, *, data_plane: bool = True) -> Path:
    app = tmp_path / "opt" / "vpn-service"
    checkout = _odd_checkout(tmp_path)
    (app / "deploy").mkdir(parents=True)
    (checkout / "deploy" / "relay").rename(app / "deploy" / "relay")
    if not data_plane:
        (app / "deploy" / "relay" / DATA_PLANE).unlink()
    (app / "scripts").mkdir()
    for name in ("vpn-relay-apply", "vpn-relay-agent"):
        (app / "scripts" / name).write_text("#!/bin/sh\n", encoding="utf-8")
    return app


def test_install_sh_installs_enables_and_starts_by_the_set(tmp_path: Path) -> None:
    _installer_checkout(tmp_path)
    result = _ok(_run(
        tmp_path,
        'open_log; arm_rollback; relay_require_checkout_files; relay_install_files; relay_start; '
        'echo "UNITS=$(printf "%s\\n" "${RELAY_UNITS[@]}" | sort | paste -sd" ")"',
    ))
    expected = sorted(RELAY_UNIT_NAMES | {"vpn-relay-extra.timer", "vpn-relay-extra.service"})
    assert f"UNITS={' '.join(expected)}" in result.stdout
    installed = sorted(p.name for p in (tmp_path / "etc" / "systemd" / "system").iterdir() if p.name != "vpn-bot.service")
    assert installed == expected, "every unit of the set, nothing else (no example)"
    for name in expected:
        src = tmp_path / "opt" / "vpn-service" / "deploy" / "relay" / name
        assert _read(tmp_path / "etc" / "systemd" / "system" / name) == _read(src)
    calls = (tmp_path / "systemctl.args").read_text(encoding="utf-8").splitlines()
    enable = [c for c in calls if c.startswith("enable ")]
    assert len(enable) == 1 and set(enable[0].split()[1:]) == {DATA_PLANE, RESOLVE_TIMER, "vpn-relay-extra.timer"}
    assert {c for c in calls if c.startswith("restart ")} == {f"restart {RESOLVE_TIMER}", "restart vpn-relay-extra.timer"}
    for service in (RESOLVE_SERVICE, "vpn-relay-extra.service"):
        assert not [c for c in calls if c.split()[0] in {"start", "restart", "enable"} and service in c.split()], (
            f"{service} is its timer's to run"
        )


def test_install_sh_refuses_a_checkout_without_the_data_plane(tmp_path: Path) -> None:
    _installer_checkout(tmp_path, data_plane=False)
    result = _run(tmp_path, "open_log; relay_require_checkout_files; echo REACHED")
    assert result.returncode != 0 and "REACHED" not in result.stdout
    assert "deploy/relay/vpn-relay.service" in result.stderr


def test_install_sh_never_resets_every_failed_unit_of_the_host() -> None:
    """`systemctl reset-failed` with no unit resets ALL of them: the rollback only calls
    it with the set, and only once the set is known."""
    text = _read(INSTALL_SH)
    line = next(ln for ln in text.splitlines() if 'reset-failed "${RELAY_UNITS[@]}"' in ln)
    assert "${#RELAY_UNITS[@]} -gt 0" in line


# --------------------------------------------------------------------------- #
# 3. deploy.sh end to end against the real host check
# --------------------------------------------------------------------------- #
# systemd as the host check sees it, on top of the relay deploy's systemctl stub:
# `daemon-reload` loads every unit file of $UNITDIR (a copy in $SD/loaded); `show`
# answers from that (LoadState, FragmentPath, NeedDaemonReload = the file differs from
# what was loaded) and from the enable/active state the relay stub keeps.
SHOW_AND_RELOAD = r"""
if [[ "$1" == show ]]; then
  shift; props=(); unit=""; value=0
  while (( $# )); do
    case "$1" in -p) props+=("$2"); shift 2 ;; --value) value=1; shift ;; --) unit="$2"; shift 2 ;; *) unit="$1"; shift ;; esac
  done
  f="$UNITDIR/$unit"; l="$SD/loaded/$unit"
  for p in "${props[@]}"; do
    case "$p" in
      LoadState) if [[ -f "$l" ]]; then v=loaded; else v=not-found; fi ;;
      FragmentPath) if [[ -f "$l" ]]; then v="/etc/systemd/system/$unit"; else v=""; fi ;;
      NeedDaemonReload) if [[ -f "$l" ]] && ! cmp -s "$l" "$f"; then v=yes; else v=no; fi ;;
      UnitFileState) if [[ -f "$SD/$unit.enabled" ]]; then v=enabled; elif [[ -f "$l" ]]; then v=disabled; else v=""; fi ;;
      ActiveState) v="$(cat "$SD/$unit.active" 2>/dev/null || echo inactive)" ;;
      *) v="" ;;
    esac
    if (( value )); then echo "$v"; else echo "$p=$v"; fi
  done
  exit 0
fi
if [[ "$1" == daemon-reload ]]; then
  mkdir -p "$SD/loaded"; rm -f "$SD/loaded/"*
  for f in "$UNITDIR"/*.service "$UNITDIR"/*.timer; do if [[ -f "$f" ]]; then cp "$f" "$SD/loaded/"; fi; done
fi
"""

# The relay deploy's install stub, except that a destination named in $SD/skip_install
# is not written: a unit that is missing after Phase 2.
INSTALL_SKIPPING = INSTALL_STUB.replace(
    'else cp "${args[0]}" "${args[1]}"; fi',
    'elif ! grep -qxF "${args[1]##*/}" "$SD/skip_install" 2>/dev/null; then cp "${args[0]}" "${args[1]}"; fi',
)
assert INSTALL_SKIPPING != INSTALL_STUB


class RealCheckRelay(RelayHost):
    """RelayHost whose Phase 1/2 gate is the REAL scripts/vpn-bot-host-check, reading
    the fake host root the deploy installs the units into."""

    def __init__(self, tmp_path: Path) -> None:
        super().__init__(tmp_path)
        self.unit_dir = self.host_root / "etc" / "systemd" / "system"
        self.unit_dir.mkdir(parents=True)
        self.unit = self.unit_dir / DATA_PLANE
        self.checker = CHECK
        (self.repo / "deploy" / "host").mkdir(parents=True, exist_ok=True)
        (self.repo / "deploy" / "host" / "invariants.list").write_text(EMPTY_INVARIANTS, encoding="utf-8")
        _stub(self.stub / "systemctl", SHOW_AND_RELOAD + RELAY_SYSTEMCTL)
        _stub(self.stub / "install", INSTALL_SKIPPING)
        for name, body in (("sshd", SSHD), ("systemd-analyze", SYSTEMD_ANALYZE), ("dpkg", DPKG),
                           ("dpkg-query", DPKG_QUERY), ("logrotate", LOGROTATE)):
            _stub(self.stub / name, body)
        for name in ("dpkg_owned", "conffiles"):
            (self.sd / name).write_text("", encoding="utf-8")
        (self.sd / "loaded").mkdir()
        self.env = tmp_path / "relay.env"
        self.env.write_text(
            "NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4=203.0.113.43\nRELAY_WAN_IFACE=eth0\n", encoding="utf-8"
        )
        self.wt = _phase1_worktree(tmp_path)
        (self.wt / "deploy" / "host").mkdir(parents=True)
        (self.wt / "deploy" / "host" / "invariants.list").write_text(EMPTY_INVARIANTS, encoding="utf-8")

    def run(self, body: str) -> subprocess.CompletedProcess[str]:
        return super().run(f'export UNITDIR="{self.unit_dir}" HC_ROOT="{self.host_root}"\n' + body)

    def deploy(self) -> subprocess.CompletedProcess[str]:
        """Phase 1 (read-only, on the worktree) then Phase 2 — relay_deploy without the
        fetch and the test gate."""
        for log in self.logs.iterdir():
            log.unlink()
        return self.run(f'ENV_FILE="{self.env}"; WT="{self.wt}"\nrelay_phase1\nrelay_phase2\necho DEPLOY-RETURNED\n')

    def installed_before_the_resolve_units(self) -> None:
        """The production relay on 2026-11-15: vpn-relay.service from an earlier repo
        deploy (synced, active, enabled, its tables live, the input filter confirmed),
        vpn-relay-apply in place, no vpn-relay-resolve.* at all."""
        self.unit.write_text(_read(REPO_UNIT), encoding="utf-8")
        (self.sd / "loaded" / DATA_PLANE).write_text(_read(REPO_UNIT), encoding="utf-8")
        (self.sd / f"{DATA_PLANE}.active").write_text("active", encoding="utf-8")
        (self.sd / f"{DATA_PLANE}.enabled").write_text("enabled", encoding="utf-8")
        (self.sd / "table").touch()
        self.helper.write_text(FAKE_HELPER, encoding="utf-8")
        self.helper.chmod(0o755)
        self.on_this_version()
        self.set_forward("1")
        self.set_conntrack("65536", "86400")

    def hc_rows(self) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = json.loads((self.tmp / "hc" / "last.json").read_text(encoding="utf-8"))["rows"]
        return rows


def _mutating(host: RelayHost) -> list[str]:
    return [c.removeprefix("systemctl ") for c in host.log("systemctl")
            if c.split()[1] not in {"is-active", "is-enabled", "show"}]


def test_the_production_relay_gets_the_resolve_units_and_deploys_ok(tmp_path: Path) -> None:
    host = RealCheckRelay(tmp_path)
    host.installed_before_the_resolve_units()
    proc = host.deploy()
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "DEPLOY-RETURNED" in proc.stdout and "DEPLOY OK (relay)" in proc.stdout
    assert "ROLLBACK" not in out

    # Phase 1 shows every unit of the set with its state.
    assert f"relay unit {host.unit}: synced — matches deploy/relay/{DATA_PLANE}" in out
    assert (f"relay unit {host.unit_dir / RESOLVE_TIMER}: absent — not installed — Phase 2 installs "
            f"deploy/relay/{RESOLVE_TIMER}, enables it and starts it") in out
    assert (f"relay unit {host.unit_dir / RESOLVE_SERVICE}: absent — not installed — Phase 2 installs "
            f"deploy/relay/{RESOLVE_SERVICE} (its timer runs it; never started by hand)") in out

    # Phase 2: each verbatim, the timer enabled and started, the oneshot never started.
    for src in RELAY_UNIT_FILES:
        assert _read(host.unit_dir / src.name) == _read(src), src.name
    assert _mutating(host) == [
        "daemon-reload", f"enable --quiet {DATA_PLANE}", f"enable --quiet {RESOLVE_TIMER}",
        f"reload-or-restart {DATA_PLANE}", f"start {RESOLVE_TIMER}",
    ]
    assert host.state(f"{RESOLVE_TIMER}.active") == "active"
    assert host.state(f"{RESOLVE_TIMER}.enabled") == "enabled"
    assert host.state(f"{RESOLVE_SERVICE}.active") == "<absent>", "nobody ran the oneshot"

    # The gate that rolled the deploy back: clean now, every unit judged OK.
    assert "host invariants  : beaten 0, mismatch 0, latent 0 (accepted 0), warn 0" in proc.stdout
    units = {r["key"]: r["verdict"] for r in host.hc_rows() if r["family"] == "unit"}
    assert units == dict.fromkeys(RELAY_UNIT_NAMES, "OK")
    assert f"  unit             : {RESOLVE_TIMER} active, enabled (before: active=inactive, installed copy absent)" in proc.stdout
    assert f"  unit             : {RESOLVE_SERVICE} installed, run by its timer (installed copy absent before)" in proc.stdout


def test_a_second_deploy_finds_everything_synced_and_changes_nothing(tmp_path: Path) -> None:
    host = RealCheckRelay(tmp_path)
    host.installed_before_the_resolve_units()
    assert host.deploy().returncode == 0
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in host.unit_dir.iterdir()}

    proc = host.deploy()
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "DEPLOY OK (relay)" in proc.stdout
    for name in sorted(RELAY_UNIT_NAMES):
        assert f"relay unit {host.unit_dir / name}: synced — matches deploy/relay/{name}" in out
        assert f"{name}: {host.unit_dir / name} matches deploy/relay/{name} — left as it is" in out
    assert "installing vpn-relay" not in out
    assert f"{RESOLVE_TIMER}: active — left running" in out
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in host.unit_dir.iterdir()}
    assert after == before, "no unit file rewritten"
    mutating = _mutating(host)
    assert not [c for c in mutating if c.split()[0] in {"start", "stop", "disable"}], mutating
    assert host.state(f"{RESOLVE_TIMER}.active") == "active" and host.state(f"{RESOLVE_TIMER}.enabled") == "enabled"
    assert {r["key"]: r["verdict"] for r in host.hc_rows() if r["family"] == "unit"} == dict.fromkeys(RELAY_UNIT_NAMES, "OK")
    assert f"  unit             : {RESOLVE_TIMER} active, enabled (before: active=active, installed copy synced)" in proc.stdout


@pytest.mark.parametrize("missing", sorted(RELAY_UNIT_NAMES))
def test_any_unit_of_the_set_missing_after_phase2_rolls_the_deploy_back(tmp_path: Path, missing: str) -> None:
    """The order stays: host invariants after the install is the gate. A fresh relay,
    so Phase 2 installs every unit — one of them does not land."""
    host = RealCheckRelay(tmp_path)
    (host.sd / "skip_install").write_text(missing + "\n", encoding="utf-8")
    proc = host.deploy()
    out = proc.stdout + proc.stderr
    assert proc.returncode == 1, out
    assert "DEPLOY OK" not in proc.stdout and "DEPLOY-RETURNED" not in proc.stdout
    assert re.search(
        rf"FAIL MISMATCH\s+unit {re.escape(missing)} — the repo installs /etc/systemd/system/{re.escape(missing)}, "
        r"but it is not on the host", proc.stderr), proc.stderr
    assert "host invariants after the install: 1 BEATEN/MISMATCH finding(s)" in proc.stderr
    assert "ROLLBACK REPORT (relay)" in proc.stderr
    # Back to the fresh relay: no unit file, the timer neither enabled nor active.
    assert sorted(p.name for p in host.unit_dir.iterdir()) == []
    assert host.state(f"{RESOLVE_TIMER}.active") == "inactive"
    assert host.state(f"{RESOLVE_TIMER}.enabled") == "<absent>"
    assert host.state(f"{DATA_PLANE}.enabled") == "<absent>"
    for name in RELAY_UNIT_NAMES:
        assert f"unit {name}: now file absent, active=inactive" in proc.stderr, name


# --------------------------------------------------------------------------- #
# 4. The rollback, unit by unit (the fake host check: the verify fails)
# --------------------------------------------------------------------------- #
def _report(proc: subprocess.CompletedProcess[str]) -> list[str]:
    block = proc.stderr.split("===== ROLLBACK REPORT (relay) =====\n", 1)[1].split("\n=====", 1)[0]
    return [ln.removeprefix("  - ") for ln in block.splitlines()]


def test_a_fresh_relay_rollback_removes_every_unit_and_names_each(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.fail_check(13)
    proc = host.phase2()
    assert proc.returncode == 1
    report = _report(proc)
    unit_dir = host.unit.parent
    for name in sorted(RELAY_UNIT_NAMES):
        assert not (unit_dir / name).exists(), f"{name} was not there before the deploy"
        assert f"remove {unit_dir / name} (absent before the deploy): rc=0" in report, name
        assert (f"unit {name}: now file absent, active=inactive enabled=<none> "
                "(before the deploy: file absent, active=inactive enabled=<none>)") in report, name
    for name in (RESOLVE_TIMER, RESOLVE_SERVICE):
        assert f"stop {name} (not installed before the deploy): rc=0" in report
        assert f"disable {name} (not installed before the deploy; its file is removed below): rc=0" in report
    i_disable = report.index(f"disable {RESOLVE_TIMER} (not installed before the deploy; its file is removed below): rc=0")
    assert i_disable < report.index(f"remove {unit_dir / RESOLVE_TIMER} (absent before the deploy): rc=0"), (
        "disabled while its file is still there — no dangling timers.target.wants link"
    )
    assert host.state(f"{RESOLVE_TIMER}.active") == "inactive" and host.state(f"{RESOLVE_TIMER}.enabled") == "<absent>"


def test_the_rollback_keeps_a_timer_that_was_active_and_enabled(tmp_path: Path) -> None:
    """A relay already on the set, its timer file an older copy: the verify fails, the
    old file comes back, and the timer stays enabled and running."""
    host = RelayHost(tmp_path)
    host.hand_installed()
    unit_dir = host.unit.parent
    old_timer = _read(ROOT / "deploy" / "relay" / RESOLVE_TIMER) + "# an older copy\n"
    (unit_dir / RESOLVE_TIMER).write_text(old_timer, encoding="utf-8")
    (unit_dir / RESOLVE_SERVICE).write_text(_read(ROOT / "deploy" / "relay" / RESOLVE_SERVICE), encoding="utf-8")
    (host.sd / f"{RESOLVE_TIMER}.active").write_text("active", encoding="utf-8")
    (host.sd / f"{RESOLVE_TIMER}.enabled").write_text("enabled", encoding="utf-8")
    host.fail_check(11)
    proc = host.phase2()
    assert proc.returncode == 1
    report = _report(proc)
    assert _read(unit_dir / RESOLVE_TIMER) == old_timer
    assert f"restore {unit_dir / RESOLVE_TIMER}: rc=0" in report
    assert f"restore {unit_dir / RESOLVE_SERVICE}: rc=0" in report
    assert not [ln for ln in report if ln.startswith((f"stop {RESOLVE_TIMER}", f"disable {RESOLVE_TIMER}"))], report
    assert host.state(f"{RESOLVE_TIMER}.active") == "active" and host.state(f"{RESOLVE_TIMER}.enabled") == "enabled"
    assert (f"unit {RESOLVE_TIMER}: now file present, active=active enabled=enabled "
            "(before the deploy: file present, active=active enabled=enabled)") in report
    sc = _mutating(host)
    assert f"start {RESOLVE_TIMER}" not in sc, "an active timer is left running by the deploy too"


def test_the_backup_holds_every_unit_of_the_set_that_exists(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    (host.unit.parent / RESOLVE_TIMER).write_text("[Timer]\n# old\n", encoding="utf-8")
    assert host.phase2().returncode == 0
    (archive,) = host.backups.glob("backup-relay-abc1234-*.tar.gz")
    listing = subprocess.run(["tar", "-tzf", str(archive)], capture_output=True, text=True, check=True).stdout
    assert str(host.unit).lstrip("/") in listing
    assert str(host.unit.parent / RESOLVE_TIMER).lstrip("/") in listing
    assert str(host.unit.parent / RESOLVE_SERVICE).lstrip("/") not in listing, "absent: recorded as absent"


def test_phase1_reports_the_state_of_every_unit(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()                                   # vpn-relay.service: legacy
    unit_dir = host.unit.parent
    (unit_dir / RESOLVE_SERVICE).write_text(_read(ROOT / "deploy" / "relay" / RESOLVE_SERVICE), encoding="utf-8")
    (unit_dir / RESOLVE_TIMER).write_text("[Timer]\n# hand edit\n", encoding="utf-8")
    wt = _phase1_worktree(tmp_path)
    env = tmp_path / "relay.env"
    env.write_text("NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4=203.0.113.43\nRELAY_WAN_IFACE=eth0\n", encoding="utf-8")
    proc = host.run(f'ENV_FILE="{env}"; WT="{wt}"\nPHASE1_ONLY=1\nrelay_phase1\nrelay_phase1_report\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    block = proc.stdout.split("  --- Units (deploy/relay/*.service|*.timer", 1)[1].split("\n\n", 1)[0]
    assert re.search(rf"{DATA_PLANE}\s+: legacy — the hand-installed unit", block), block
    assert re.search(rf"{RESOLVE_SERVICE}\s+: synced — matches deploy/relay/{RESOLVE_SERVICE}", block), block
    assert re.search(rf"{RESOLVE_TIMER}\s+: differs — differs from deploy/relay/{RESOLVE_TIMER}", block), block
    assert _read(host.unit) == _read(MANUAL_UNIT), "Phase 1 changes nothing"


# --------------------------------------------------------------------------- #
# 5. vpn-relay-apply resolve on the production relay (RELAY_UPSTREAM_IPV4)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("extra", ["", "RELAY_UPSTREAM_HOST=\n", "# RELAY_UPSTREAM_HOST=vpn.example.com\n"])
def test_resolve_with_an_address_upstream_is_a_no_op(tmp_path: Path, extra: str) -> None:
    """vpn-relay-resolve.timer is installed and active on every relay; with an address
    upstream its service must finish at once, exit 0 (not failed), touching nothing."""
    relay = Relay(tmp_path)
    relay.write_env(_read(ENV_EXAMPLE) + extra)
    result = relay.run("resolve")
    assert result.returncode == 0, result.stderr
    assert result.stdout == "vpn-relay-apply: resolve: no RELAY_UPSTREAM_HOST (the upstream is an address) — nothing to do\n"
    assert result.stderr == ""
    touched = [c for c in relay.calls()
               if c.split()[0] in {"nft", "getent", "sysctl", "systemd-run", "curl", "modprobe", "ip", "ss", "probe"}]
    assert touched == [], touched
    assert not (relay.state_dir / "upstream.resolved").exists()
    assert not relay.sysctl_file.exists()
    assert not relay.applied.exists() or relay.applied_files() == [], "nothing applied"


def test_the_resolve_service_runs_exactly_the_helper_s_resolve() -> None:
    service = _read(ROOT / "deploy" / "relay" / RESOLVE_SERVICE)
    body = service.split("[Unit]", 1)[1]
    assert re.findall(r"^Exec\w+=.*$", body, re.M) == ["ExecStart=/usr/local/sbin/vpn-relay-apply resolve"]
    assert "Type=oneshot" in body and "RemainAfterExit" not in body
    assert "Environment" not in body, "the helper reads the relay's .env (its default RELAY_ENV)"
    assert '\nRELAY_ENV="${RELAY_ENV:-/opt/vpn-service/.env}"\n' in _read(ROOT / "scripts" / "vpn-relay-apply")


# --------------------------------------------------------------------------- #
# 6. The absent-ok reason comes from the registry entry
# --------------------------------------------------------------------------- #
def test_the_relay_agent_absent_is_left_absent_for_its_own_reason(tmp_path: Path) -> None:
    out = _shared_functions_output(tmp_path, "NODE_ROLE=relay\n", "install_out_of_repo_helpers")
    assert ("vpn-relay-agent: not installed on this host (installed at pairing from the bot — there is none "
            "before pairing) — leaving absent") in out
    assert "WARP" not in out


def test_a_warp_helper_absent_on_main_still_says_warp(tmp_path: Path) -> None:
    out = _shared_functions_output(tmp_path, None, "install_out_of_repo_helpers")
    assert "vpn-bot-warp-routes: not installed on this host (WARP not deployed here) — leaving absent" in out
    assert "pairing" not in out


def test_the_leaving_absent_line_has_no_hard_coded_reason() -> None:
    body = _function(DEPLOY_SH, "install_out_of_repo_helpers")
    line = next(ln for ln in body.splitlines() if "leaving absent" in ln)
    assert "WARP" not in line and '$(helper_absent_reason "$dst")' in line
