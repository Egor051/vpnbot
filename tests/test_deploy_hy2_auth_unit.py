"""The hy2-auth unit: ONE name, installed by the deploy under the name .env gives it.

Measured on the main server 2026-11-16: HYSTERIA2_AUTH_SERVICE_NAME=vpnbot-hy2-auth, the
installed /etc/systemd/system/vpnbot-hy2-auth.service differed from the repo's
deploy/vpn-bot-hy2-auth.service (comments, Description, NO LimitNOFILE=65536), and every
DEPLOY OK said "units skipped: vpn-bot-hy2-auth.service": nothing compared or installed
the live file. Pinned here:

* **One canonical name** — vpnbot-hy2-auth, the hosts' name since #222 — for the repo
  file, deploy.sh, config/settings.py, .env.example and the protocol-uninstall helper.
* **Phase 1** compares deploy/vpnbot-hy2-auth.service with
  ``${HYSTERIA2_AUTH_SERVICE_NAME}.service`` (off | absent | synced | differs, the diff
  shown) and refuses a symlink there; only while Hysteria2 is enabled.
* **Phase 2** stages it, installs it verbatim (synced: untouched; absent: installed,
  never enabled or started), and the sidecar restart then runs the new file — DEPLOY OK
  shows the open-files limit of the restarted process.
* **Rollback** puts the previous file back (or removes one that was not there).
* **UNIT_SET / drift**: the repo file maps to the .env name, so neither "units skipped"
  nor the drift gate names a hy2-auth unit the host does not run.

Driven through the DEPLOY_SELFTEST=1 seam with systemctl stubbed. The "checkout" is a
COPY of deploy/ under tmp_path and WT stays empty: deploy.sh's EXIT trap runs
`git worktree remove --force "$WT"`, so WT must never name a real checkout.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
REPO_UNIT = ROOT / "deploy" / "vpnbot-hy2-auth.service"

pytestmark = pytest.mark.timeout(60)

# The live file of 2026-11-16 in substance: the repo unit without LimitNOFILE.
LIVE_UNIT = "\n".join(ln for ln in REPO_UNIT.read_text(encoding="utf-8").splitlines() if "LimitNOFILE" not in ln) + "\n"

SYSTEMCTL = r"""
printf '%s\n' "$*" >> "$LOGS/systemctl.log"
unit="${!#}"
case "$1" in
  is-active) s="$(cat "$SD/$unit.state" 2>/dev/null || echo inactive)"; echo "$s"; [[ "$s" == active ]]; exit ;;
  is-enabled) [[ -f "$SD/$unit.enabled" ]] && { echo enabled; exit 0; }; echo disabled; exit 1 ;;
  show)
    case "$*" in
      *LoadState*)   [[ -f "$SD/$unit.state" ]] && printf loaded || printf not-found ;;
      *ActiveState*) cat "$SD/$unit.state" 2>/dev/null || printf inactive ;;
      *MainPID*)     cat "$SD/$unit.pid" 2>/dev/null || printf 0 ;;
    esac
    exit 0 ;;
  restart) echo active > "$SD/$unit.state"; echo 4242 > "$SD/$unit.pid"; exit 0 ;;
esac
exit 0
"""

ENV = "HYSTERIA2_ENABLED=true\nHYSTERIA2_AUTH_LISTEN=127.0.0.1:8444\n"
SS = "LISTEN 0 128 127.0.0.1:8444 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:8445 0.0.0.0:*\n"


class Host:
    def __init__(self, tmp: Path, env: str = ENV) -> None:
        self.tmp = tmp
        self.stub = tmp / "stub"
        self.sd = tmp / "state"
        self.logs = tmp / "logs"
        self.unitdir = tmp / "etc" / "systemd" / "system"
        self.proc = tmp / "proc"
        self.checkout = tmp / "checkout"
        for d in (self.stub, self.sd, self.logs, self.unitdir, self.proc / "4242"):
            d.mkdir(parents=True, exist_ok=True)
        shutil.copytree(ROOT / "deploy", self.checkout / "deploy")
        (self.stub / "systemctl").write_text("#!/usr/bin/env bash\n" + SYSTEMCTL, encoding="utf-8")
        (self.stub / "ss").write_text(f"#!/usr/bin/env bash\ncat <<'EOF'\n{SS}EOF\n", encoding="utf-8")
        (self.stub / "sleep").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        (self.stub / "systemd-analyze").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        for f in self.stub.iterdir():
            f.chmod(0o755)
        (self.proc / "4242" / "limits").write_text(
            "Limit                     Soft Limit           Hard Limit           Units     \n"
            "Max open files            65536                65536                files     \n",
            encoding="utf-8",
        )
        self.env = tmp / ".env"
        self.env.write_text(env, encoding="utf-8")

    def running(self, unit: str = "vpnbot-hy2-auth.service", body: str = LIVE_UNIT) -> Path:
        dst = self.unitdir / unit
        dst.write_text(body, encoding="utf-8")
        (self.sd / f"{unit}.state").write_text("active", encoding="utf-8")
        (self.sd / f"{unit}.pid").write_text("1111", encoding="utf-8")
        return dst

    def run(self, body: str, **knobs: str) -> subprocess.CompletedProcess[str]:
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -uo pipefail\nexport DEPLOY_SELFTEST=1\n"
            f'export PATH="{self.stub}:$PATH" SD="{self.sd}" LOGS="{self.logs}"\n'
            + "".join(f"export {k}={v!r}\n" for k, v in knobs.items())
            + f'source "{DEPLOY_SH}"\n'
            f'ENV_FILE="{self.env}"; SYSTEMD_UNIT_DIR="{self.unitdir}"; PROC_DIR="{self.proc}"\n'
            f'MH_SELFTEST_ROOT="{self.tmp}"; APP_DIR="{self.checkout}"; CHECKOUT="{self.checkout}"\n'
            'WT=""; VENV=/nonexistent; VENV_PREV=/nonexistent; STAGE=""\n'
            "SIDECAR_ACTIVE_WAIT=2; HY2_AUTH_BIND_TIMEOUT=0; SUBSCRIPTION_BIND_WAIT=0\n"
            "rollback_now() { printf 'ROLLBACK_NOW: %s\\n' \"$*\"; exit 9; }\n"
            "resolve_backend_units\n"
            f"{body}\n",
            encoding="utf-8",
        )
        return subprocess.run(["bash", str(driver)], cwd=str(self.checkout), capture_output=True, text=True)

    def systemctl(self) -> list[str]:
        p = self.logs / "systemctl.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


STATE = 'hy2_auth_unit_phase1 "$CHECKOUT"\necho "STATE=$HY2_AUTH_UNIT_STATE DST=$HY2_AUTH_UNIT_DST"\n'


# --------------------------------------------------------------------------- #
# One name
# --------------------------------------------------------------------------- #
def test_one_canonical_name_everywhere() -> None:
    assert REPO_UNIT.is_file() and not (ROOT / "deploy" / "vpn-bot-hy2-auth.service").exists()
    deploy = DEPLOY_SH.read_text(encoding="utf-8")
    assert 'HY2_AUTH_DEFAULT_NAME="vpnbot-hy2-auth"' in deploy
    assert 'HY2_AUTH_UNIT_SRC="deploy/vpnbot-hy2-auth.service"' in deploy
    assert "env_or HYSTERIA2_AUTH_SERVICE_NAME vpn-bot-hy2-auth" not in deploy
    settings = (ROOT / "config" / "settings.py").read_text(encoding="utf-8")
    assert settings.count('"vpnbot-hy2-auth"') == 2 and '"vpn-bot-hy2-auth"' not in settings
    assert "\nHYSTERIA2_AUTH_SERVICE_NAME=vpnbot-hy2-auth\n" in (ROOT / ".env.example").read_text(encoding="utf-8")
    helper = (ROOT / "deploy" / "helpers" / "vpn-bot-protocol-uninstall").read_text(encoding="utf-8")
    assert "read_unit_base HY2_AUTH_SVC HYSTERIA2_AUTH_SERVICE_NAME vpnbot-hy2-auth" in helper
    for doc in ("docs/hysteria.md", "docs/hysteria.ru.md", "docs/deployment.md", "docs/deployment.ru.md",
                "docs/configuration.md", "docs/configuration.ru.md", "docs/operations.md", "docs/operations.ru.md",
                "docs/subscription.md", "docs/subscription.ru.md"):
        text = (ROOT / doc).read_text(encoding="utf-8")
        assert "vpnbot-hy2-auth" in text, doc
        # Only the history note of hysteria.md may still name the old repo file.
        history = ("`deploy/vpn-bot-hy2-auth.service`", "`units skipped: vpn-bot-hy2-auth.service`")
        for old in history:
            text = text.replace(old, "")
        assert "vpn-bot-hy2-auth" not in text, doc


def test_the_settings_default_is_the_canonical_name() -> None:
    from config.settings import Settings

    assert Settings.__dataclass_fields__["hysteria2_auth_service_name"].default == "vpnbot-hy2-auth"


# --------------------------------------------------------------------------- #
# Phase 1
# --------------------------------------------------------------------------- #
def test_phase1_finds_the_live_file_differing_and_shows_the_missing_limit(host: Host) -> None:
    dst = host.running()
    proc = host.run(STATE)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"STATE=differs DST={dst}" in proc.stdout
    assert "(HYSTERIA2_AUTH_SERVICE_NAME=vpnbot-hy2-auth): differs from deploy/vpnbot-hy2-auth.service" in proc.stdout
    assert re.search(r"^\s+\+LimitNOFILE=65536$", proc.stdout, re.MULTILINE), "the diff shows what is missing"
    assert host.systemctl() == [], "Phase 1 changes nothing"
    assert dst.read_text(encoding="utf-8") == LIVE_UNIT


def test_phase1_follows_the_env_name(tmp_path: Path) -> None:
    host = Host(tmp_path, ENV + "HYSTERIA2_AUTH_SERVICE_NAME=hy2-auth-custom\n")
    proc = host.run(STATE)
    assert f"STATE=absent DST={host.unitdir}/hy2-auth-custom.service" in proc.stdout, proc.stdout + proc.stderr
    assert "neither enabled nor started (enable it once: systemctl enable --now hy2-auth-custom)" in proc.stdout


def test_phase1_synced_and_off(tmp_path: Path) -> None:
    host = Host(tmp_path / "on")
    host.running(body=REPO_UNIT.read_text(encoding="utf-8"))
    assert "STATE=synced" in host.run(STATE).stdout
    off = Host(tmp_path / "off", "HYSTERIA2_ENABLED=false\n")
    proc = off.run(STATE)
    assert "STATE=off" in proc.stdout and "not managed here — Hysteria2 is not enabled" in proc.stdout


def test_phase1_refuses_a_symlink_where_the_unit_goes(host: Host) -> None:
    (host.unitdir / "vpnbot-hy2-auth.service").symlink_to("/dev/null")
    proc = host.run(STATE + "echo NOT-REACHED\n")
    assert proc.returncode == 1 and "NOT-REACHED" not in proc.stdout
    assert "is a symlink (-> /dev/null), not a unit file — the deploy does not replace it" in proc.stderr
    inspect = host.run(STATE, PHASE1_ONLY="1")
    assert inspect.returncode == 0 and "STATE=symlink" in inspect.stdout and "a real deploy stops here" in inspect.stderr


# --------------------------------------------------------------------------- #
# Phase 2: install, restart, report; rollback
# --------------------------------------------------------------------------- #
PHASE2 = (
    STATE
    + 'STAGE="$(make_stage_dir)"; manifest=()\n'
    'stage_host_paths "$HY2_AUTH_UNIT_DST"\n'
    "snapshot_sidecar_units\n"
    "hy2_auth_unit_install\n"
    "restart_sidecar_units\n"
    'echo "REPORT=$(hy2_auth_unit_report)"\n'
)


def test_phase2_installs_the_repo_unit_and_the_restart_puts_the_limit_in_effect(host: Host) -> None:
    dst = host.running()
    proc = host.run(PHASE2)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert dst.read_text(encoding="utf-8") == REPO_UNIT.read_text(encoding="utf-8"), "verbatim"
    assert "restart vpnbot-hy2-auth.service" in host.systemctl()
    assert "vpnbot-hy2-auth.service: restarted — listening on 127.0.0.1:8444" in proc.stdout
    assert (f"REPORT={dst} installed from deploy/vpnbot-hy2-auth.service (was differs); vpnbot-hy2-auth.service "
            "active, open files 65536/65536 (soft/hard) in pid 4242") in proc.stdout
    assert "vpn-bot-hy2-auth" not in proc.stdout


def test_a_synced_unit_is_left_alone(host: Host) -> None:
    dst = host.running(body=REPO_UNIT.read_text(encoding="utf-8"))
    before = dst.stat().st_mtime_ns
    proc = host.run(PHASE2)
    assert proc.returncode == 0, proc.stderr
    assert dst.stat().st_mtime_ns == before
    assert f"REPORT={dst} matches deploy/vpnbot-hy2-auth.service — left as it is" in proc.stdout


def test_an_absent_unit_is_installed_but_never_enabled_or_started(host: Host) -> None:
    proc = host.run(PHASE2)
    assert proc.returncode == 0, proc.stderr
    dst = host.unitdir / "vpnbot-hy2-auth.service"
    assert dst.read_text(encoding="utf-8") == REPO_UNIT.read_text(encoding="utf-8")
    assert not [c for c in host.systemctl() if c.split()[0] in {"enable", "start", "restart"}]
    assert "skipped (absent" in proc.stdout


def test_off_touches_nothing(tmp_path: Path) -> None:
    host = Host(tmp_path, "HYSTERIA2_ENABLED=false\n")
    dst = host.running()
    proc = host.run(STATE + 'hy2_auth_unit_install\necho "REPORT=$(hy2_auth_unit_report)"\n')
    assert proc.returncode == 0, proc.stderr
    assert dst.read_text(encoding="utf-8") == LIVE_UNIT
    assert "REPORT=not managed — Hysteria2 is not enabled here" in proc.stdout


@pytest.mark.parametrize("existed", [True, False])
def test_the_rollback_puts_the_previous_file_back(host: Host, existed: bool) -> None:
    dst = host.running() if existed else host.unitdir / "vpnbot-hy2-auth.service"
    proc = host.run(PHASE2 + "restore_host_paths\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    if existed:
        assert dst.read_text(encoding="utf-8") == LIVE_UNIT, "the pre-deploy file is back"
        assert f"restore {dst}: rc=0" in proc.stdout
    else:
        assert not dst.exists()
        assert f"remove {dst} (absent before the deploy): rc=0" in proc.stdout


def test_main_phase2_order() -> None:
    """Scanned in Phase 1; staged before the archive; installed before the daemon-reload
    of vpn-bot.service; the sidecar restart (which loads it) after the bot is up; reported
    in DEPLOY OK; and the rollback restores host paths before its daemon-reload and the
    sidecar restart on PREV_SHA."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    top = text[text.index('if [[ "${DEPLOY_SELFTEST:-0}" == "1" ]]; then return 0'):]
    order = [top.index(s) for s in (
        'hy2_auth_unit_phase1 "$WT"',
        'stage_host_paths "$HY2_AUTH_UNIT_DST"',
        'create_backup_archive "$ARCHIVE"',
        "arm_rollback ",
        "\nhy2_auth_unit_install\n",
        'install -m0644 "deploy/vpn-bot.service" "$SYSTEM_UNIT"\nsystemctl daemon-reload',
        "\nrestart_sidecar_units\n",
        "hy2-auth unit    : $(hy2_auth_unit_report)",
    )]
    assert order == sorted(order)
    rb = text[text.index("\nrollback() {"):]
    rb = rb[: rb.index("\n}\n")]
    assert rb.index("host_files_rollback") < rb.index("daemon-reload") < rb.index("rollback_restart_sidecars")


# --------------------------------------------------------------------------- #
# UNIT_SET and the drift gate see the live name
# --------------------------------------------------------------------------- #
def test_unit_set_maps_the_repo_file_to_the_env_name(host: Host) -> None:
    host.running()
    proc = host.run('WT="$CHECKOUT"; assemble_unit_set; WT=""\n'
                    'echo "UNIT_SET=${UNIT_SET[*]}"\necho "SKIPPED=${skipped[*]:-}"\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    unit_set = proc.stdout.split("UNIT_SET=", 1)[1].splitlines()[0].split()
    skipped = proc.stdout.split("SKIPPED=", 1)[1].splitlines()[0].split()
    assert unit_set.count("vpnbot-hy2-auth.service") == 1
    assert not [u for u in unit_set + skipped if "hy2-auth" in u and u != "vpnbot-hy2-auth.service"]
    assert "vpnbot-hy2-auth.service" not in skipped, "the live unit is watched, not skipped"


def test_the_drift_gate_leaves_the_hy2_auth_unit_to_its_installer() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    loop = text[text.index("# Unit drift check (R3)"): text.index("# Backend config drift (R3c)")]
    assert '[[ "$base" == "${HY2_AUTH_UNIT_SRC##*/}" ]] && continue' in loop
