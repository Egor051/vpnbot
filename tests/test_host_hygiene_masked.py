"""Host hygiene: units the repo keeps masked (class masked) and the retired apt source.

The deploy does it itself (zero-CLI): MANAGED_HOST_FILES class ``masked`` says that
``/etc/systemd/system/<unit>`` must be the symlink to /dev/null that ``systemctl mask``
writes. Pinned here, through the same labs as the other host-file classes:

deploy.sh (tests/test_deploy_host_state.py's ``Lab``: a fake host, stubbed systemctl)
  * Phase 1 reports ``unmasked`` / ``masked`` and STOPS on ``mask-conflict`` (anything
    else at the path) before any mutation; PHASE1_ONLY reports it instead.
  * Phase 2 creates the symlink, daemon-reloads once, stops the unit only if it ran,
    and the summary counts it; an already masked unit is left alone.
  * The rollback removes the mask, daemon-reloads and starts the unit again only if it
    ran before.
scripts/vpn-bot-host-check (tests/test_host_check.py's ``HostLab``)
  * OK / PENDING (pre-install) / MISMATCH (not masked, something else there, not
    reloaded, still running) / BEATEN (a higher-priority unit file wins).
The real registry
  * the apt list is retired and ModemManager / udisks2 are masked, on both roles.
"""

from __future__ import annotations

import re
from pathlib import Path

from test_deploy_host_state import BOTH, PHASE1, PHASE2, Lab, _registry
from test_host_check import HostLab

UNIT = "ModemManager.service"


def _mask_entry(lab: Lab, unit: str = UNIT, role: str = "main") -> Path:
    dst = lab.unitdir / unit
    lab.entries.append(f"-|{dst}|-|-|masked|{role}")
    return dst


def _running(lab: Lab, unit: str = UNIT) -> None:
    lab.flag(f"{unit}.active", "active")
    lab.flag(f"{unit}.enabled", "enabled")
    lab.flag(f"{unit}.loaded")


# --------------------------------------------------------------------------- #
# deploy.sh — Phase 1
# --------------------------------------------------------------------------- #
def test_phase1_reports_an_unmasked_unit_and_changes_nothing(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    _running(lab)
    proc = lab.run(PHASE1)
    assert proc.returncode == 0, proc.stdout
    assert "PHASE1-OK" in proc.stdout
    assert re.search(rf"masked\s+unmasked\s+{re.escape(str(dst))} — {UNIT} is enabled/active now", proc.stdout), proc.stdout
    assert not dst.exists() and not dst.is_symlink()
    assert lab.mutating_systemctl() == []


def test_phase1_stops_when_something_else_sits_where_the_mask_goes(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    dst.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
    proc = lab.run(PHASE1)
    assert proc.returncode != 0
    assert "PHASE1-OK" not in proc.stdout
    assert "mask-conflict" in proc.stdout and "a unit file of its own" in proc.stdout
    assert "nothing was changed" in proc.stdout
    assert dst.read_text(encoding="utf-8").startswith("[Service]")


def test_phase1_only_reports_the_conflict_instead_of_stopping(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    dst.symlink_to("/usr/lib/systemd/system/other.service")
    proc = lab.run(PHASE1, PHASE1_ONLY="1")
    assert proc.returncode == 0, proc.stdout
    assert "PHASE1-OK" in proc.stdout
    assert "a symlink to /usr/lib/systemd/system/other.service, not the mask" in proc.stdout


# --------------------------------------------------------------------------- #
# deploy.sh — Phase 2
# --------------------------------------------------------------------------- #
def test_phase2_masks_reloads_and_stops_a_running_unit(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    _running(lab)
    proc = lab.run(BOTH + 'echo "SUMMARY: $(host_files_summary)"\n')
    assert proc.returncode == 0, proc.stdout
    assert "PHASE2-OK" in proc.stdout
    assert dst.is_symlink() and str(dst.readlink()) == "/dev/null"
    calls = [c.removeprefix("systemctl ") for c in lab.mutating_systemctl()]
    assert calls == ["daemon-reload", f"stop {UNIT}"], calls
    assert f"{UNIT}: masked and stopped (it was running)" in proc.stdout
    assert "SUMMARY: 0 installed, 0 removed, 0 mode/owner fixed, 1 unit(s) masked" in proc.stdout


def test_phase2_does_not_stop_a_unit_that_did_not_run(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab, "udisks2.service")
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert dst.is_symlink() and str(dst.readlink()) == "/dev/null"
    calls = [c.removeprefix("systemctl ") for c in lab.mutating_systemctl()]
    assert calls == ["daemon-reload"], calls
    assert "udisks2.service: masked (was inactive — nothing to stop)" in proc.stdout


def test_an_already_masked_unit_is_left_alone(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    dst.symlink_to("/dev/null")
    proc = lab.run(BOTH + 'echo "SUMMARY: $(host_files_summary)"\n')
    assert proc.returncode == 0, proc.stdout
    assert f"{dst}: masked (in sync)" in proc.stdout
    assert lab.mutating_systemctl() == []
    assert "SUMMARY: all in sync, nothing changed" in proc.stdout


def test_the_mask_is_staged_like_every_host_file(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    proc = lab.run('managed_host_stage_paths\n')
    assert str(dst) in proc.stdout.split("--STDERR--")[0].splitlines()


# --------------------------------------------------------------------------- #
# deploy.sh — the rollback
# --------------------------------------------------------------------------- #
def test_rollback_unmasks_and_starts_a_unit_that_ran(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    _running(lab)
    proc = lab.run(PHASE2 + 'rollback_now "a later step failed (test)"\n')
    assert proc.returncode == 42, proc.stdout
    assert "ROLLBACK_CALLED" in proc.stdout
    assert not dst.exists() and not dst.is_symlink(), "the mask did not exist before the deploy"
    calls = [c.removeprefix("systemctl ") for c in lab.mutating_systemctl()]
    # Phase 2: reload + stop; rollback: reload + start, in that order.
    assert calls == ["daemon-reload", f"stop {UNIT}", "daemon-reload", f"start {UNIT}"], calls
    assert f"start {UNIT} (active before the deploy): rc=0" in proc.stdout
    assert "no unit file after the restore" not in proc.stdout


def test_rollback_leaves_a_unit_that_did_not_run_stopped(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = _mask_entry(lab)
    proc = lab.run(PHASE2 + 'rollback_now "a later step failed (test)"\n')
    assert proc.returncode == 42, proc.stdout
    assert not dst.is_symlink()
    calls = [c.removeprefix("systemctl ") for c in lab.mutating_systemctl()]
    assert calls == ["daemon-reload", "daemon-reload"], calls


# --------------------------------------------------------------------------- #
# vpn-bot-host-check — the effect
# --------------------------------------------------------------------------- #
DST = f"/etc/systemd/system/{UNIT}"


def _hc(tmp_path: Path) -> HostLab:
    lab = HostLab(tmp_path)
    lab.registry.append(f"-|{DST}|-|-|masked|main")
    return lab


def _masked_rows(res: object) -> list[tuple[str, str, str, str, str]]:
    return [r for r in res.rows if r[1] == "masked"]  # type: ignore[attr-defined]


def test_host_check_ok_when_masked_and_not_running(tmp_path: Path) -> None:
    lab = _hc(tmp_path)
    lab.link(DST.lstrip("/"), "/dev/null")
    lab.unit(UNIT, LoadState="masked", ActiveState="inactive", NeedDaemonReload="no")
    res = lab.run()
    assert _masked_rows(res) == [("OK", "masked", UNIT, DST, "masked (LoadState=masked, inactive)")], res.out
    assert res.rc == 0, res.out


def test_host_check_mismatch_when_not_masked(tmp_path: Path) -> None:
    lab = _hc(tmp_path)
    res = lab.run()
    rows = _masked_rows(res)
    assert [r[0] for r in rows] == ["MISMATCH"] and "is not masked" in rows[0][4], res.out
    assert res.rc == 1


def test_host_check_pre_install_is_pending_until_phase2(tmp_path: Path) -> None:
    lab = _hc(tmp_path)
    res = lab.run("--pre-install")
    rows = _masked_rows(res)
    assert [r[0] for r in rows] == ["PENDING"], res.out
    assert "the deploy masks" in rows[0][4]


def test_host_check_mismatch_when_something_else_is_there(tmp_path: Path) -> None:
    lab = _hc(tmp_path)
    lab.host(DST.lstrip("/"), "[Service]\nExecStart=/bin/true\n")
    for args in ((), ("--pre-install",)):
        rows = _masked_rows(lab.run(*args))
        assert [r[0] for r in rows] == ["MISMATCH"], rows
        assert "a unit file of its own" in rows[0][4]


def test_host_check_mismatch_when_masked_but_still_running(tmp_path: Path) -> None:
    lab = _hc(tmp_path)
    lab.link(DST.lstrip("/"), "/dev/null")
    lab.unit(UNIT, LoadState="masked", ActiveState="active", NeedDaemonReload="no")
    rows = _masked_rows(lab.run())
    assert [r[0] for r in rows] == ["MISMATCH"] and "still active" in rows[0][4], rows


def test_host_check_mismatch_when_not_reloaded(tmp_path: Path) -> None:
    lab = _hc(tmp_path)
    lab.link(DST.lstrip("/"), "/dev/null")
    lab.unit(UNIT, LoadState="loaded", ActiveState="inactive", NeedDaemonReload="yes",
             FragmentPath=f"/usr/lib/systemd/system/{UNIT}")
    rows = _masked_rows(lab.run())
    assert [r[0] for r in rows] == ["MISMATCH"] and "daemon-reload" in rows[0][4], rows


def test_host_check_beaten_when_a_higher_priority_unit_file_wins(tmp_path: Path) -> None:
    lab = _hc(tmp_path)
    lab.link(DST.lstrip("/"), "/dev/null")
    lab.unit(UNIT, LoadState="loaded", ActiveState="inactive", NeedDaemonReload="no",
             FragmentPath=f"/run/systemd/transient/{UNIT}")
    rows = _masked_rows(lab.run())
    assert [r[0] for r in rows] == ["BEATEN"], rows
    assert f"/run/systemd/transient/{UNIT}" in rows[0][4]


def test_host_check_reads_masked_entries_from_the_real_deploy_sh(tmp_path: Path) -> None:
    """Without --registry the array is parsed out of deploy.sh: a masked entry has no
    repo source, and must not turn into a 'source is not there' WARN."""
    root = Path(__file__).resolve().parents[1]
    lab = HostLab(tmp_path)
    res = lab.run(role="relay", registry=False, repo=root)
    assert not [r for r in res.rows if r[1] == "registry" and r[2].endswith("/-")], res.out
    units = {r[2] for r in res.rows if r[1] == "masked"}
    assert {"ModemManager.service", "udisks2.service"} <= units, res.out


# --------------------------------------------------------------------------- #
# The real registry
# --------------------------------------------------------------------------- #
def test_registry_carries_the_host_hygiene_entries_on_both_roles() -> None:
    reg = {(e[1], e[5]): e[4] for e in _registry()}
    for role in ("main", "relay"):
        assert reg["/etc/apt/sources.list.d/ookla_speedtest-cli.list", role] == "absent", role
        assert reg["/etc/systemd/system/ModemManager.service", role] == "masked", role
        assert reg["/etc/systemd/system/udisks2.service", role] == "masked", role


def test_snapd_is_masked_on_main_only_socket_first() -> None:
    main = [e[1] for e in _registry() if e[5] == "main" and e[4] == "masked"]
    snapd = [d for d in main if "/snapd" in d]
    assert snapd == ["/etc/systemd/system/snapd.socket", "/etc/systemd/system/snapd.service",
                     "/etc/systemd/system/snapd.seeded.service"], "the socket first: it cannot re-activate the service"
    assert not [e for e in _registry() if e[5] == "relay" and "/snapd" in e[1]]
