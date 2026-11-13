"""scripts/deploy.sh — the "Host invariants" gates around scripts/vpn-bot-host-check.

Driven through the DEPLOY_SELFTEST=1 seam. The policy is tested against a fake
checker that prints chosen rows (what deploy.sh does with each verdict); the wiring
end to end against the real checker on a fake host (tests/test_host_check.py's lab).
deploy.sh runs this suite AS ROOT on the production host in Phase 1: HOST_CHECK_ROOT,
HOST_CHECK_STATE and every registry path point under tmp_path.

1. Phase 1: BEATEN / MISMATCH -> FAIL before any mutation; LATENT on an sshd auth
   key -> FAIL unless accepted (ACCEPTED); any other LATENT and WARN -> WARN;
   PHASE1_ONLY=1 reports instead of stopping; a checker that cannot run -> FAIL.
2. Phase 1 runs the checkout's checker with --pre-install --no-state and this role's
   registry with the gates evaluated by deploy.sh.
3. Phase 2: BEATEN / MISMATCH -> rollback_now; LATENT / WARN -> reported; the state
   file is written, fenced under MH_SELFTEST_ROOT in the selftest.
4. Both reports carry the rows; the flow calls the gates where the spec puts them.
5. There is no new ALLOW_* knob; the CI host-like job runs the whole suite.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from tests.test_host_check import CHECK, RELAY_KEYONLY, RELAY_SSHD_T, HostLab

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

pytestmark = pytest.mark.timeout(60)

FAKE_CHECK = r"""#!/usr/bin/env bash
echo "host-check $*" >> "$LOGS/host-check.log"
rows="$(cat "$SD/hc_rows" 2>/dev/null)"
[[ -n "$rows" ]] && printf '%s\n' "$rows"
[[ -f "$SD/hc_no_summary" ]] && exit 0
b=$(grep -c '^BEATEN|' <<< "$rows"); m=$(grep -c '^MISMATCH|' <<< "$rows")
l=$(grep -c '^LATENT|' <<< "$rows"); a=$(grep -c '^ACCEPTED|' <<< "$rows"); w=$(grep -c '^WARN|' <<< "$rows")
echo "SUMMARY|role=main|mode=x|beaten=$b|mismatch=$m|latent=$l|accepted=$a|warn=$w|pending=0|info=0|ok=3"
[[ -f "$SD/hc_rc" ]] && exit "$(cat "$SD/hc_rc")"
(( b + m == 0 ))
"""


class Deploy:
    """deploy.sh sourced through the seam, the checker faked (or real), paths in tmp."""

    def __init__(self, tmp: Path, *, real: HostLab | None = None) -> None:
        self.tmp = tmp
        self.sd = tmp / "sd"
        self.logs = tmp / "logs"
        self.repo = real.repo if real else tmp / "repo"
        self.hostroot = real.root if real else tmp / "hostroot"
        for d in (self.sd, self.logs, self.repo, self.hostroot):
            d.mkdir(parents=True, exist_ok=True)
        self.real = real
        self.fake = tmp / "fake-check"
        self.fake.write_text(FAKE_CHECK, encoding="utf-8")
        self.fake.chmod(0o755)
        self.state = tmp / "hc" / "last.json"
        self.state.parent.mkdir(exist_ok=True)
        self.env = tmp / "dot.env"
        self.env.write_text("MTPROTO_ENABLED=false\n", encoding="utf-8")
        self.entries: list[str] = []

    def rows(self, *rows: str) -> None:
        (self.sd / "hc_rows").write_text("".join(f"{r}\n" for r in rows), encoding="utf-8")

    def run(self, body: str, *, role: str = "main", **knobs: str) -> subprocess.CompletedProcess[str]:
        entries = "\n".join(f'  "{e}"' for e in self.entries)
        bin_ = CHECK if self.real else self.fake
        path = f"{self.real.stub}:" if self.real else ""
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -uo pipefail\n"
            "export DEPLOY_SELFTEST=1\n"
            f'export PATH="{path}$PATH" SD="{self.real.sd if self.real else self.sd}" '
            f'LOGS="{self.real.logs if self.real else self.logs}" HC_ROOT="{self.hostroot}"\n'
            f'source "{DEPLOY_SH}"\n'
            'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
            f'APP_DIR="{self.repo}"; ENV_FILE="{self.env}"; MH_SELFTEST_ROOT="{self.tmp}"\n'
            f'HOST_CHECK_BIN="{bin_}"; HOST_CHECK_ROOT="{self.hostroot}"; HOST_CHECK_STATE="{self.state}"\n'
            f"PHASE1_ONLY=0; NODE_ROLE={role}\n"
            f"MANAGED_HOST_FILES=(\n{entries}\n)\n"
            'rollback() { set +e; echo "ROLLBACK_CALLED"; exit 42; }\n'
            'relay_rollback() { set +e; echo "RELAY_ROLLBACK_CALLED"; exit 43; }\n'
            + "".join(f'{k}="{v}"\n' for k, v in knobs.items())
            + "resolve_backend_units\n"
            + body,
            encoding="utf-8",
        )
        proc = subprocess.run(["bash", str(driver)], cwd=str(self.tmp), capture_output=True, text=True, check=False)
        proc.stdout = proc.stdout + "\n--STDERR--\n" + proc.stderr
        return proc

    def calls(self) -> list[str]:
        p = self.logs / "host-check.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


PHASE1 = 'host_invariants_phase1 "$APP_DIR"; echo PHASE1-OK\nhost_invariants_report_block\n'
PHASE2 = 'host_invariants_phase2 "$APP_DIR"; echo PHASE2-OK\necho "SUMMARY-LINE: $(hc_summary_text)"\nhost_invariants_report_rows\n'


# --------------------------------------------------------------------------- #
# 1. Phase 1 policy
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("row", [
    "BEATEN|sysctl|net.ipv4.ip_forward|/etc/sysctl.d/99-zz.conf|/etc/sysctl.d/99-zz.conf:1 = 0 wins over the repo value 1",
    "MISMATCH|unit|even-day-reboot.timer|/etc/systemd/system/even-day-reboot.timer|timer is disabled/inactive",
    "LATENT|sshd|passwordauthentication|/etc/ssh/sshd_config.d/50-cloud-init.conf|winner ... ; winner gone -> yes",
    "LATENT|sshd|permitrootlogin|/etc/ssh/sshd_config|winner ... ; winner gone -> yes",
    "LATENT|sshd|authenticationmethods|/etc/ssh/sshd_config|winner ...",
])
def test_phase1_fails_before_any_mutation(tmp_path: Path, row: str) -> None:
    d = Deploy(tmp_path)
    d.rows(row, "OK|sshd|pubkeyauthentication|/etc/ssh/x|yes")
    proc = d.run(PHASE1)
    assert proc.returncode == 1, proc.stdout
    assert "PHASE1-OK" not in proc.stdout
    assert "host invariants: 1 fatal finding(s) — nothing was changed" in proc.stdout
    assert re.search(r"\[WARN\]\s+FAIL (BEATEN|MISMATCH|LATENT) ", proc.stdout)
    assert "deploy/host/accepted-overrides.list" in proc.stdout, "the operator is told how to accept a LATENT"
    assert not d.state.exists()


@pytest.mark.parametrize("row", [
    "LATENT|sshd|x11forwarding|/etc/ssh/sshd_config|winner ...",
    "LATENT|sysctl|vm.swappiness|/etc/sysctl.d/10-mine.conf|winner ...",
    "LATENT|unit|ssh.socket|/run/systemd/generator/ssh.socket.d/addresses.conf|foreign drop-in",
    "INFO|unit|ssh.socket|/run/systemd/generator/ssh.socket.d/addresses.conf|generated by "
    "/usr/lib/systemd/system-generators/sshd-socket-generator (openssh-server, unmodified) from ...",
    "WARN|logrotate|logrotate -d|/etc/logrotate.conf|error: /etc/logrotate.d/x:3 unknown option",
    "ACCEPTED|sshd|passwordauthentication|/etc/ssh/sshd_config|... — accepted (deploy/host/accepted-overrides.list): why",
    "PENDING|unit|vpn-bot-host-check.timer|/etc/systemd/system/vpn-bot-host-check.timer|the deploy installs it",
])
def test_phase1_reports_but_passes(tmp_path: Path, row: str) -> None:
    d = Deploy(tmp_path)
    d.rows(row)
    proc = d.run(PHASE1)
    assert proc.returncode == 0, proc.stdout
    assert "PHASE1-OK" in proc.stdout
    verdict = row.split("|", 1)[0]
    sev = "WARN" if verdict in {"LATENT", "WARN"} else "INFO"
    assert re.search(rf"{sev}\s+{verdict}\s", proc.stdout), proc.stdout


def test_phase1_only_reports_a_fail_without_stopping(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    d.rows("BEATEN|sshd|passwordauthentication|/etc/ssh/sshd_config.d/50-cloud-init.conf|50-cloud-init.conf:1 = yes wins")
    proc = d.run(PHASE1, PHASE1_ONLY="1")
    assert proc.returncode == 0 and "PHASE1-OK" in proc.stdout, proc.stdout
    assert "PHASE1_ONLY=1: reported, not fatal in inspection mode — a real deploy stops here" in proc.stdout
    report = proc.stdout.split("PHASE1-OK", 1)[1]
    assert "--- Host invariants (scripts/vpn-bot-host-check, role main" in report
    assert "beaten 1, mismatch 0, latent 0 (accepted 0), warn 0" in report
    assert "FAIL BEATEN   sshd passwordauthentication — 50-cloud-init.conf:1 = yes wins" in report
    assert "[/etc/ssh/sshd_config.d/50-cloud-init.conf]" in report, "the path when the text does not name it"


@pytest.mark.parametrize("how", ["rc3", "no-summary"])
def test_phase1_fails_when_the_check_cannot_run(tmp_path: Path, how: str) -> None:
    d = Deploy(tmp_path)
    d.rows()
    if how == "rc3":
        (d.sd / "hc_rc").write_text("3", encoding="utf-8")
    else:
        (d.sd / "hc_no_summary").write_text("", encoding="utf-8")
    proc = d.run(PHASE1)
    assert proc.returncode == 1, proc.stdout
    assert "host invariants: the check could not run (exit 3, see above) — nothing was changed" in proc.stdout


def test_phase1_passes_the_role_registry_with_gates_evaluated(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    d.rows()
    d.entries = [
        f"deploy/a|{tmp_path}/hostroot/etc/a|0644|root:root|sysctl|main",
        f"deploy/b|{tmp_path}/hostroot/etc/b|0644|root:root|unit|main|gate=MTPROTO",
        f"deploy/c|{tmp_path}/hostroot/etc/c|0644|root:root|ssh|relay",
        f"-|{tmp_path}/hostroot/etc/d|-|-|absent|main",
        f"deploy/e|{tmp_path}/hostroot/etc/e|0755|root:root|hook|main|when={tmp_path}/nowhere",
    ]
    reg_seen = tmp_path / "reg-seen"
    d.fake.write_text(FAKE_CHECK.replace(
        'echo "host-check $*" >> "$LOGS/host-check.log"',
        f'echo "host-check $*" >> "$LOGS/host-check.log"\n'
        f'while (( $# )); do [[ "$1" == --registry ]] && cp "$2" "{reg_seen}"; shift; done'), encoding="utf-8")
    proc = d.run(PHASE1)
    assert proc.returncode == 0, proc.stdout
    (call,) = d.calls()
    assert f"--repo {d.repo} --role main --registry " in call
    assert call.endswith(f"--env {d.env} --root {d.hostroot} --pre-install --no-state")
    assert reg_seen.read_text(encoding="utf-8").splitlines() == [d.entries[0], d.entries[3]]


def test_the_checker_is_the_checkouts_copy_by_default(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    (d.repo / "scripts").mkdir()
    (d.repo / "scripts" / "vpn-bot-host-check").write_text(FAKE_CHECK.replace("host-check $*", "checkout-copy $*"),
                                                            encoding="utf-8")
    d.rows()
    proc = d.run(PHASE1, HOST_CHECK_BIN="")
    assert proc.returncode == 0, proc.stdout
    assert d.calls()[0].startswith("checkout-copy --repo"), "run through bash from <checkout>/scripts/"


def test_the_selftest_refuses_to_judge_the_real_host(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    proc = d.run(PHASE1, HOST_CHECK_ROOT="")
    assert proc.returncode == 1
    assert "DEPLOY_SELFTEST: HOST_CHECK_ROOT is empty" in proc.stdout
    assert d.calls() == []


# --------------------------------------------------------------------------- #
# 3. Phase 2
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("verdict", ["BEATEN", "MISMATCH"])
def test_phase2_rolls_back_on_beaten_or_mismatch(tmp_path: Path, verdict: str) -> None:
    d = Deploy(tmp_path)
    d.rows(f"{verdict}|journald|Journal.SystemMaxUse|/etc/systemd/journald.conf.d/20-x.conf|20-x.conf:2 = 1G wins")
    proc = d.run(PHASE2)
    assert proc.returncode == 42 and "ROLLBACK_CALLED" in proc.stdout, proc.stdout
    assert "PHASE2-OK" not in proc.stdout
    assert "host invariants after the install: 1 BEATEN/MISMATCH finding(s)" in proc.stdout
    (call,) = d.calls()
    assert call.endswith(f"--state {d.state}") and "--pre-install" not in call


def test_phase2_relay_rolls_back_through_the_relay_rollback(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    d.rows("BEATEN|sshd|passwordauthentication|/etc/ssh/sshd_config.d/50-cloud-init.conf|yes wins")
    proc = d.run(PHASE2, role="relay")
    assert proc.returncode == 43 and "RELAY_ROLLBACK_CALLED" in proc.stdout


def test_phase2_reports_latent_and_warn_without_rolling_back(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    d.rows("LATENT|sshd|passwordauthentication|/etc/ssh/sshd_config|winner ... gone -> yes",
           "WARN|account|ubuntu|-|non-root account ubuntu has a usable password",
           "OK|sysctl|vm.swappiness|/etc/sysctl.d/99-swap-tuning.conf|10")
    proc = d.run(PHASE2)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert "SUMMARY-LINE: beaten 0, mismatch 0, latent 1 (accepted 0), warn 1" in proc.stdout
    rows = proc.stdout.split("SUMMARY-LINE", 1)[1]
    assert "WARN LATENT   sshd passwordauthentication" in rows, "an auth LATENT never fails Phase 2"
    assert "WARN WARN     account ubuntu" in rows
    assert "vm.swappiness" not in rows, "OK rows are not listed"


def test_phase2_state_write_failure_is_a_warning(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    d.rows()
    (d.sd / "hc_rc").write_text("4", encoding="utf-8")
    proc = d.run(PHASE2)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert f"{d.state} could not be written" in proc.stdout
    assert f"{d.state} NOT written" in proc.stdout


@pytest.mark.parametrize("rc", ["2", "3"])
def test_phase2_rolls_back_when_the_check_cannot_run(tmp_path: Path, rc: str) -> None:
    d = Deploy(tmp_path)
    d.rows()
    (d.sd / "hc_rc").write_text(rc, encoding="utf-8")
    proc = d.run(PHASE2)
    assert proc.returncode == 42, proc.stdout
    assert f"the check could not run after the install (exit {rc})" in proc.stdout


def test_phase2_state_file_is_fenced_in_the_selftest(tmp_path: Path) -> None:
    d = Deploy(tmp_path)
    d.rows()
    proc = d.run(PHASE2, HOST_CHECK_STATE="/var/lib/vpn-bot-host-check/last.json")
    assert proc.returncode == 1
    assert "DEPLOY_SELFTEST: refusing to write /var/lib/vpn-bot-host-check/last.json" in proc.stdout
    assert d.calls() == []


# --------------------------------------------------------------------------- #
# End to end with the real checker on a fake host
# --------------------------------------------------------------------------- #
def _relay_e2e(tmp_path: Path, *, retire_cloud_init: bool) -> Deploy:
    lab = HostLab(tmp_path / "lab")
    lab.repo_file("deploy/host/ssh/00-vpnrelay-keyonly.conf", RELAY_KEYONLY)
    lab.host("etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf", RELAY_KEYONLY)
    lab.host("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    lab.sshd_t(**RELAY_SSHD_T)
    for name in ("dpkg_owned", "conffiles"):
        (lab.sd / name).write_text("", encoding="utf-8")
    d = Deploy(tmp_path, real=lab)
    d.entries = [f"deploy/host/ssh/00-vpnrelay-keyonly.conf|{lab.root}/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf"
                 "|0644|root:root|ssh|relay"]
    if retire_cloud_init:
        d.entries.append(f"-|{lab.root}/etc/ssh/sshd_config.d/50-cloud-init.conf|-|-|absent|relay")
    return d


def test_e2e_the_relay_case_stops_phase1(tmp_path: Path) -> None:
    d = _relay_e2e(tmp_path, retire_cloud_init=False)
    proc = d.run(PHASE1, role="relay")
    assert proc.returncode == 1, proc.stdout
    assert re.search(r"FAIL LATENT\s+sshd passwordauthentication — winner /etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf:3 = no",
                     proc.stdout), proc.stdout
    assert "winner gone -> yes from /etc/ssh/sshd_config.d/50-cloud-init.conf" in proc.stdout


def test_e2e_retiring_cloud_init_s_file_clears_phase1(tmp_path: Path) -> None:
    d = _relay_e2e(tmp_path, retire_cloud_init=True)
    proc = d.run(PHASE1, role="relay")
    assert proc.returncode == 0 and "PHASE1-OK" in proc.stdout, proc.stdout
    assert "beaten 0, mismatch 0, latent 0 (accepted 0)" in proc.stdout
    assert d.real is not None and (d.real.root / "etc/ssh/sshd_config.d/50-cloud-init.conf").exists(), "read-only"


def test_e2e_phase2_writes_the_state_file(tmp_path: Path) -> None:
    d = _relay_e2e(tmp_path, retire_cloud_init=True)
    assert d.real is not None
    (d.real.root / "etc/ssh/sshd_config.d/50-cloud-init.conf").unlink()   # Phase 2 removed it
    proc = d.run(PHASE2, role="relay")
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    data = json.loads(d.state.read_text(encoding="utf-8"))
    assert data["role"] == "relay" and data["mode"] == "installed"
    assert data["counts"]["beaten"] == data["counts"]["mismatch"] == 0


# --------------------------------------------------------------------------- #
# 4. Where the gates sit; the reports
# --------------------------------------------------------------------------- #
def _main_flow() -> str:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    return text[text.index('if [[ "${DEPLOY_SELFTEST:-0}" == "1" ]]; then return 0'):]


def test_main_phase1_gate_sits_before_any_mutation() -> None:
    flow = _main_flow()
    at = flow.index('host_invariants_phase1 "$WT"')
    assert flow.index('host_state_phase1 "$WT"') < at
    assert at < flow.index('if [[ "$PHASE1_ONLY" == "1" ]]; then\n  phase1_report')
    assert at < flow.index('systemctl stop "$BOT_UNIT"')


def test_main_phase2_gate_sits_after_the_install_and_before_the_start() -> None:
    flow = _main_flow()
    at = flow.index('host_invariants_phase2 "$APP_DIR"')
    assert flow.index("install_managed_host_files\n") < at
    assert flow.index('install -m0644 "deploy/vpn-bot.service" "$SYSTEM_UNIT"') < at
    assert at < flow.index('systemctl start "$BOT_UNIT"')
    assert at < flow.index("===== DEPLOY OK =====")


def test_the_relay_calls_both_gates() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    p1 = text[text.index("relay_phase1() {"):]
    p1 = p1[: p1.index("\n}\n")]
    assert p1.index('host_state_phase1 "$WT"') < p1.index('host_invariants_phase1 "$WT"')
    p2 = text[text.index("relay_phase2() {"):]
    p2 = p2[: p2.index("\n}\n")]
    assert p2.index("vpn-relay-apply check failed after the restart") < p2.index('host_invariants_phase2 "$APP_DIR"')
    assert p2.index('host_invariants_phase2 "$APP_DIR"') < p2.index("disarm")


def test_both_reports_carry_the_rows() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert text.count("host_invariants_report_block") == 3, "defined + the two PHASE1_ONLY reports"
    assert text.count("  host invariants  : $(hc_summary_text)") == 2, "both DEPLOY OK reports"
    assert text.count("host_invariants_report_rows\n") >= 3


def test_no_allow_knob_was_added() -> None:
    """A FAIL has no override: redeploy.sh forwards only the knobs it knows."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    knobs = set(re.findall(r'^(ALLOW_[A-Z_]+)="\$\{ALLOW_', text, re.M))
    assert knobs == {"ALLOW_MODEL_SWITCH", "ALLOW_UNIT_DRIFT", "ALLOW_BACKEND_CONFIG_DRIFT",
                     "ALLOW_SCHEMA_DOWNGRADE", "ALLOW_SSH_CHANGE"}
    assert "ALLOW_" not in "".join(ln for ln in text.splitlines() if "host_invariants" in ln or "HOST_CHECK" in ln)


def test_the_host_like_ci_job_runs_the_whole_suite() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    job = ci[ci.index("  tests-host-like:"):]
    assert "run: python -m pytest -q -p no:cacheprovider\n" in job, "no path or -k filter: these suites run there"
