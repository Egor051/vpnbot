"""scripts/deploy.sh and the protocol-uninstall markers.

deploy/helpers/vpn-bot-protocol-uninstall leaves /etc/vpn-bot/uninstalled/<proto>
behind. From then on a deploy must not watch, compare, reinstall or restart what
was removed on purpose:

* Xray has no *_ENABLED flag — without the marker its absent unit would stay
  "expected" forever;
* MANAGED_HOST_FILES used to install the danted drop-in with no gate at all, and
  its "did not exist before -> enable + start" branch would then start a danted
  that apt-get purge took away (gate=SOCKS5 + the marker now);
* awg-quick@awg0 stays MASKED on purpose (warp-routes only Wants= it), which is
  neither drift nor a failure;
* vpnbot-hy2-warp-mark is in UNIT_SET, OUT_OF_REPO_HELPERS and WARP_ONESHOTS.

Plus two hosts facts the uninstall relies on, pinned here: the acme hook copes
with Hysteria2 gone, and vpn-bot-warp-routes passes without the awg0 client
interface (the skip-not-fail branch of #241).

Driven through the DEPLOY_SELFTEST seam with systemctl stubbed; every path is
under tmp_path (deploy.sh runs this suite as root on the production host).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from test_deploy_host_state import BOTH, Lab, _read

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
HOOK = ROOT / "deploy" / "vpn-bot-acme-reload.sh"

pytestmark = pytest.mark.timeout(60)

# LoadState from <unit>.load (default not-found), ActiveState from <unit>.state.
SYSTEMCTL = r"""
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
unit="${!#}"
case "$1" in
  show)
    case "$*" in
      *LoadState*) cat "$STATE_DIR/$unit.load" 2>/dev/null || printf 'not-found' ;;
      *ActiveState*) cat "$STATE_DIR/$unit.state" 2>/dev/null || printf 'inactive' ;;
      *Type*) printf 'simple' ;;
    esac
    exit 0 ;;
  is-active) s="$(cat "$STATE_DIR/$unit.state" 2>/dev/null || echo inactive)"; echo "$s"; [[ "$s" == active ]]; exit ;;
  is-enabled) echo enabled; exit 0 ;;
esac
exit 0
"""

HOST_ENV = (
    "BOT_TOKEN=x\nXRAY_SERVICE_NAME=xray\nAWG_INTERFACE=awg0\nSOCKS5_ENABLED=true\nSOCKS5_SERVICE_NAME=danted\n"
    "HYSTERIA2_ENABLED=true\nHYSTERIA2_SERVICE_NAME=hysteria-server\nHYSTERIA2_AUTH_SERVICE_NAME=vpnbot-hy2-auth\n"
)
LOADED = ["xray.service", "danted.service", "hysteria-server.service", "vpnbot-hy2-auth.service",
          "vpnbot-hy2-warp-mark.service", "awg-quick@awg0.service", "awg-quick@out-warp.service",
          "warp-routes.service"]


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(tmp_path: Path, body: str, *, removed: tuple[str, ...] = (), env: str = HOST_ENV,
         masked: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str]:
    stub, state, wt, markers = (tmp_path / n for n in ("stub", "state", "wt", "markers"))
    for d in (stub, state, wt / "deploy", markers):
        d.mkdir(parents=True, exist_ok=True)
    _stub(stub / "systemctl", SYSTEMCTL)
    for unit in LOADED:
        (state / f"{unit}.load").write_text("masked" if unit in masked else "loaded", encoding="utf-8")
        (state / f"{unit}.state").write_text("inactive" if unit in masked else "active", encoding="utf-8")
    for name in removed:
        (markers / name).write_text('{"protocol": "%s"}\n' % name, encoding="utf-8")
    shutil.copy(ROOT / "deploy" / "managed-units.list", wt / "deploy" / "managed-units.list")
    for unit in (ROOT / "deploy").glob("*.service"):
        shutil.copy(unit, wt / "deploy" / unit.name)
    (tmp_path / ".env").write_text(env, encoding="utf-8")
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\nexport DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub}:$PATH" STATE_DIR="{state}" SYSTEMCTL_LOG="{tmp_path}/systemctl.log"\n'
        f'export ENV_FILE="{tmp_path}/.env" UNINSTALL_MARKER_DIR="{markers}"\n'
        f'source "{DEPLOY_SH}"\n'
        f'VENV=/nonexistent; VENV_PREV=/nonexistent; STAGE=""; WT="{wt}"\n'
        "rollback_now() { printf 'ROLLBACK_NOW: %s\\n' \"$*\"; exit 9; }\n"
        "resolve_backend_units\nassemble_unit_set\n"
        'printf "UNIT_SET=%s\\n" "${UNIT_SET[*]}"\n'
        'printf "REMOVED_UNITS=%s\\n" "${UNINSTALLED_UNITS[*]}"\n'
        f"{body}\n",
        encoding="utf-8",
    )
    proc = subprocess.run(["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True, check=False)
    proc.stdout += "\n---STDERR---\n" + proc.stderr
    return proc


def _line(out: str, key: str) -> list[str]:
    for line in out.splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].split()
    raise AssertionError(f"{key} not printed:\n{out}")


PROTO_MATRIX = (
    'for i in "${!PROTO_UNIT[@]}"; do '
    'printf "PROTO %s %s\\n" "${PROTO_LABEL[$i]}" "$(classify_proto "${PROTO_LABEL[$i]}" '
    '"${PROTO_GATE[$i]}" "${PROTO_ON[$i]}" "${PROTO_UNIT[$i]}")"; done'
)


# --------------------------------------------------------------------------- #
# UNIT_SET
# --------------------------------------------------------------------------- #
def test_without_markers_everything_is_watched(tmp_path: Path) -> None:
    proc = _run(tmp_path, PROTO_MATRIX)
    assert proc.returncode == 0, proc.stdout
    units = _line(proc.stdout, "UNIT_SET")
    for unit in ("xray.service", "danted.service", "hysteria-server.service", "vpnbot-hy2-auth.service",
                 "vpnbot-hy2-warp-mark.service", "awg-quick@awg0.service"):
        assert unit in units, unit
    assert _line(proc.stdout, "REMOVED_UNITS") == []


def test_removed_xray_is_not_expected_any_more(tmp_path: Path) -> None:
    (tmp_path / "state").mkdir(parents=True)
    proc = _run(tmp_path, PROTO_MATRIX + '\necho "XRAY_ON=$XRAY_ON"', removed=("xray",))
    assert proc.returncode == 0, proc.stdout
    assert "xray.service" not in _line(proc.stdout, "UNIT_SET")
    assert "xray.service|xray" in _line(proc.stdout, "REMOVED_UNITS")
    assert "XRAY_ON=no" in proc.stdout
    xray = next(ln for ln in proc.stdout.splitlines() if ln.startswith("PROTO Xray "))
    assert "INFO: removed from this host" in xray and "WARN" not in xray


def test_without_the_marker_a_missing_xray_is_still_a_warning(tmp_path: Path) -> None:
    proc = _run(tmp_path, 'rm -f "$STATE_DIR/xray.service.load"\n' + PROTO_MATRIX)
    assert "PROTO Xray WARN: expected backend not loaded" in proc.stdout


def test_removed_awg_masked_unit_is_neither_drift_nor_failure(tmp_path: Path) -> None:
    proc = _run(tmp_path, 'echo "SKIPPED=${skipped[*]}"', removed=("awg",), masked=("awg-quick@awg0.service",))
    assert proc.returncode == 0, proc.stdout
    assert "awg-quick@awg0.service" not in _line(proc.stdout, "UNIT_SET")
    assert "awg-quick@awg0.service|awg" in _line(proc.stdout, "REMOVED_UNITS")
    assert "awg-quick@awg0.service" not in _line(proc.stdout, "SKIPPED"), "not even reported as not-installed"
    assert "awg-quick@out-warp.service" in _line(proc.stdout, "UNIT_SET"), "WARP egress stays watched"
    assert "warp-routes.service" in _line(proc.stdout, "UNIT_SET")


def test_removed_hysteria2_takes_its_three_units_and_the_repo_name_along(tmp_path: Path) -> None:
    proc = _run(tmp_path, 'echo "HY2=$HYSTERIA2_ON"', removed=("hysteria2",))
    assert proc.returncode == 0, proc.stdout
    units = _line(proc.stdout, "UNIT_SET")
    for unit in ("hysteria-server.service", "vpnbot-hy2-auth.service", "vpnbot-hy2-warp-mark.service",
                 "vpn-bot-hy2-auth.service"):
        assert unit not in units, unit
    assert "HY2=no" in proc.stdout
    assert "xray.service" in units and "danted.service" in units


def test_removed_socks5_and_mtproto_follow_the_env_names(tmp_path: Path) -> None:
    env = HOST_ENV.replace("SOCKS5_SERVICE_NAME=danted", "SOCKS5_SERVICE_NAME=sockd") + "MTPROTO_SERVICE_NAME=mtg\n"
    proc = _run(tmp_path, 'for u in sockd.service danted.service mtg.service mtproxy.service; do '
                          'echo "OWNER $u=$(unit_uninstalled_owner "$u")"; done', removed=("socks5", "mtproto"), env=env)
    assert "OWNER sockd.service=socks5" in proc.stdout and "OWNER danted.service=" + "\n" in proc.stdout + "\n"
    assert "OWNER mtg.service=mtproto" in proc.stdout
    assert re.search(r"^OWNER mtproxy\.service=$", proc.stdout, re.M)


# --------------------------------------------------------------------------- #
# OUT_OF_REPO_HELPERS + the warp-mark re-apply
# --------------------------------------------------------------------------- #
def test_the_warp_mark_helper_is_left_alone_after_hysteria2_is_removed(tmp_path: Path) -> None:
    src = tmp_path / "repo" / "scripts"
    src.mkdir(parents=True)
    (src / "vpnbot-hy2-warp-mark").write_text("#!/bin/bash\n# new\n", encoding="utf-8")
    dst = tmp_path / "sbin" / "vpnbot-hy2-warp-mark"
    dst.parent.mkdir()
    dst.write_text("#!/bin/bash\n# old\n", encoding="utf-8")
    body = (
        f'OUT_OF_REPO_HELPERS=("scripts/vpnbot-hy2-warp-mark|{dst}|absent-ok")\n'
        f'helper_uninstalled_owner() {{ [[ "$1" == "{dst}" ]] && proto_uninstalled hysteria2 && printf hysteria2; return 0; }}\n'
        f'APP_DIR="{tmp_path / "repo"}"\n'
        'U_PRE_ACTIVE[vpnbot-hy2-warp-mark.service]=active\n'
        "install_out_of_repo_helpers\n"
    )
    proc = _run(tmp_path, body, removed=("hysteria2",))
    assert proc.returncode == 0, proc.stdout
    assert dst.read_text(encoding="utf-8").endswith("# old\n"), "not reinstalled"
    assert "removed from this host (uninstall marker) — left as it is" in proc.stdout
    assert "Hysteria2 was removed from this host (uninstall marker) — not re-applied" in proc.stdout
    log = (tmp_path / "systemctl.log").read_text(encoding="utf-8")
    assert "restart vpnbot-hy2-warp-mark.service" not in log
    assert "ROLLBACK_NOW" not in proc.stdout


def test_the_real_helper_mapping_names_the_installed_warp_mark() -> None:
    text = _read(DEPLOY_SH)
    assert 'if [[ "$1" == /usr/local/sbin/vpnbot-hy2-warp-mark ]] && proto_uninstalled hysteria2' in text
    assert '"scripts/vpnbot-hy2-warp-mark|/usr/local/sbin/vpnbot-hy2-warp-mark|absent-ok"' in text


def test_the_rollback_skips_the_oneshots_of_a_removed_protocol() -> None:
    text = _read(DEPLOY_SH)
    loop = text[text.index('for w in "${WARP_ONESHOTS[@]}"; do'):]
    loop = loop[: loop.index("done")]
    assert 'unit_uninstalled_owner "$w"' in loop and "its protocol was removed from this host" in loop


def test_the_unit_drift_scan_skips_removed_units() -> None:
    text = _read(DEPLOY_SH)
    drift = text[text.index('for f in "$WT"/deploy/*.service; do\n  base="$(basename "$f")"\n  [[ "$base" == *.example.service ]] && continue\n  [[ "$base" == "$BOT_UNIT" ]]'):]
    drift = drift[: drift.index("done")]
    assert 'unit_uninstalled_owner "$base"' in drift


# --------------------------------------------------------------------------- #
# MANAGED_HOST_FILES: the danted drop-in
# --------------------------------------------------------------------------- #
DANTED_DROPIN = "[Unit]\nAfter=warp-routes.service\n"


def _danted_lab(tmp_path: Path) -> tuple[Lab, Path, Path]:
    lab = Lab(tmp_path)
    dst = lab.add("unit", "etc/systemd/system/danted.service.d/vpn-bot-warp.conf", DANTED_DROPIN,
                  src="deploy/danted-warp.conf", opts="gate=SOCKS5")
    markers = tmp_path / "markers"
    markers.mkdir()
    return lab, dst, markers


def test_the_danted_dropin_is_gated_on_socks5_in_the_real_registry() -> None:
    text = _read(DEPLOY_SH)
    assert ('"deploy/danted-warp.conf|/etc/systemd/system/danted.service.d/vpn-bot-warp.conf|0644|root:root|'
            'unit|main|gate=SOCKS5"') in text


def test_without_a_marker_the_dropin_is_installed(tmp_path: Path) -> None:
    lab, dst, markers = _danted_lab(tmp_path)
    proc = lab.run(BOTH, SOCKS5_ON="yes", SOCKS5_SERVICE_NAME_V="danted", UNINSTALL_MARKER_DIR=str(markers))
    assert proc.returncode == 0, proc.stdout
    assert dst.exists()


def test_after_socks5_removal_the_dropin_is_not_put_back(tmp_path: Path) -> None:
    """Even with SOCKS5_ENABLED still true in .env: the marker shuts the gate."""
    lab, dst, markers = _danted_lab(tmp_path)
    (markers / "socks5").write_text("{}\n", encoding="utf-8")
    proc = lab.run(BOTH, SOCKS5_ON="yes", SOCKS5_SERVICE_NAME_V="danted", UNINSTALL_MARKER_DIR=str(markers))
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"unit\s+gated-off\s+", proc.stdout)
    assert "socks5 was removed from this host" in proc.stdout
    assert not dst.exists() and not dst.parent.exists()
    assert lab.mutating_systemctl() == [], "no daemon-reload, no enable --now of a purged danted"
    assert lab.log("install") == []


def test_socks5_switched_off_in_env_also_leaves_the_dropin_out(tmp_path: Path) -> None:
    lab, dst, markers = _danted_lab(tmp_path)
    proc = lab.run(BOTH, SOCKS5_ON="no", UNINSTALL_MARKER_DIR=str(markers))
    assert proc.returncode == 0, proc.stdout
    assert not dst.exists()


# --------------------------------------------------------------------------- #
# Host facts the uninstall relies on
# --------------------------------------------------------------------------- #
def test_the_acme_hook_needs_no_change_once_hysteria2_is_gone(tmp_path: Path) -> None:
    """No /etc/hysteria: the copy is skipped. No hysteria-server unit: its restart is
    skipped (unit_exists = systemctl cat). nginx and the subscription still get theirs."""
    stub, logs, tls = tmp_path / "stub", tmp_path / "logs", tmp_path / "tls"
    for d in (stub, logs, tls):
        d.mkdir()
    (tls / "fullchain.pem").write_text("chain\n", encoding="utf-8")
    (tls / "privkey.pem").write_text("key\n", encoding="utf-8")
    _stub(stub / "systemctl", 'echo "systemctl $*" >> "$LOGS/hook.log"\n'
                              '[[ "$1" == cat ]] && { [[ "${!#}" == hysteria-server ]] && exit 1; exit 0; }\nexit 0\n')
    for tool in ("chown", "chmod", "install", "mv"):
        _stub(stub / tool, f'echo "{tool} $*" >> "$LOGS/hook.log"\nexit 0\n')
    env = {"PATH": f"{stub}:{os.environ.get('PATH', '/usr/bin:/bin')}", "LOGS": str(logs), "TLS_DIR": str(tls),
           "HYSTERIA_CERT": str(tmp_path / "etc-hysteria-removed" / "cert.pem"),
           "HYSTERIA_KEY": str(tmp_path / "etc-hysteria-removed" / "key.pem"), "LANG": "C.UTF-8"}
    proc = subprocess.run(["bash", str(HOOK)], env=env, capture_output=True, text=True, check=False)
    log = (logs / "hook.log").read_text(encoding="utf-8").splitlines()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "skipping the Hysteria2 copy" in proc.stdout
    assert "skipping hysteria-server (not installed on this host)" in proc.stdout
    assert not any(ln.startswith(("install ", "mv ")) for ln in log)
    assert "systemctl reload -- nginx" in log and "systemctl try-restart -- vpn-bot-subscription" in log
    assert not any("restart -- hysteria-server" in ln for ln in log)


def test_warp_routes_passes_without_the_awg0_client(tmp_path: Path) -> None:
    """awg0 is gone (AWG removed, its unit masked): `awg show awg0` fails, the rp_filter
    sysctl for awg0 fails, the FORWARD -i/-o awg0 rules are still accepted by
    iptables. The self-check's data-plane probe SKIPS (no live client) — #241's
    skip-not-fail — and `add` exits 0, so warp-routes.service stays up."""
    from test_warp_helpers import _INITIAL_RULES, _WARP_CONFIG, SCRIPTS, _make_bin

    bindir = _make_bin(tmp_path)
    real_awg = (bindir / "awg").read_text(encoding="utf-8")
    (bindir / "awg-real").write_text(real_awg, encoding="utf-8")
    (bindir / "awg-real").chmod(0o755)
    _stub(bindir / "awg", 'printf "awg %s\\n" "$*" >> "$CMD_LOG"\n'
                          '[[ "${2:-}" == awg0 ]] && { echo "Unable to access interface: No such device" >&2; exit 1; }\n'
                          f'exec "{bindir}/awg-real" "$@"\n')
    _stub(bindir / "sysctl", 'printf "sysctl %s\\n" "$*" >> "$CMD_LOG"\n[[ "$*" == *awg0* ]] && exit 255\nexit 0\n')
    rules = tmp_path / "rules"
    rules.write_text(_INITIAL_RULES, encoding="utf-8")
    conf = tmp_path / "out-warp.conf"
    conf.write_text(_WARP_CONFIG, encoding="utf-8")
    cmd_log = tmp_path / "cmd.log"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}", "CMD_LOG": str(cmd_log), "IP_RULES": str(rules),
           "MOCK_FWMARK": "0xca6c", "MOCK_ENDPOINT": "162.159.195.1", "WARP_CONFIG": str(conf),
           "MOCK_MTPROXY_PRESENT": "0", "SELF_CHECK_INTERVAL": "0"}
    proc = subprocess.run(["bash", str(SCRIPTS / "vpn-bot-warp-routes"), "add", "out-warp"], env=env,
                          capture_output=True, text=True, timeout=30, check=False)
    log = cmd_log.read_text(encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    assert "skipping data-plane check" in proc.stderr and "rolling back" not in proc.stderr
    assert "awg show awg0 latest-handshakes" in log
    assert "iptables -I FORWARD 1 -i awg0 -o out-warp -j ACCEPT" in log
    assert "sysctl -w net.ipv4.conf.awg0.rp_filter=2" in log
