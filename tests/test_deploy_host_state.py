"""Host state as code: MANAGED_HOST_FILES in scripts/deploy.sh.

Pinned here, through the DEPLOY_SELFTEST=1 seam with every host command stubbed and
every path under the test's temp dir:

1. **Per class** (logrotate, sysctl, unit, journald, networkd, hook, ssh, resolved): absent ->
   installed + post-action; synced -> nothing; drift -> reinstalled; a candidate the
   validator refuses -> Phase 1 fails with nothing changed; a failure after the
   install -> rollback puts the host copy back.
2. **ssh**: a differing file is refused before any mutation without
   ALLOW_SSH_CHANGE=1; with it, the change is applied and a dead port rolls it back;
   a restored config that fails `sshd -t` is NOT reloaded.
3. **absent** (retired files): disable --now + remove, the rollback restores both
   file and unit state; already gone -> no-op; still named by cron / a unit / .env ->
   Phase 1 FAILS.
4. **mtproxy drop-in** (gate=MTPROTO + legacy name): gate closed + orphan legacy
   file; gate open + identical legacy (rename, no restart, reversible); gate open +
   different legacy (Phase 1 stops).
5. **Roles**: a relay sees only relay entries, a main server only main ones.
6. **Static guards** on the real registry and deploy/host/: every source exists, the
   entry format, the byte-for-byte sha256 of the ssh files and the unchanged sysctl
   files (the first deploy must show them "synced"), known-unmanaged.list reasons.
7. **Unaccounted host files**: a stray file is a WARN with its mtime; package files,
   known-unmanaged globs, deployed files and links are not.
8. **One restore mechanism**: restore_host_paths reproduces the relay's previous
   three-path restore line for line.
9. **The acme hook**: --dry-run prints exactly the host's TLS ownership/modes, and a
   failing step does not stop the other consumers from being reloaded.
10. **plain** (installed verbatim, nothing reloaded), **resolved** (reload, then
    `getent ahosts` or roll back — the rollback reloads too), and a retired
    sshd_config.d file (sshd -t + reload + port check, like an ssh change).

deploy.sh runs this suite AS ROOT on the production host in Phase 1, so nothing
here may reach a real path: every test registry points under tmp_path and
MH_SELFTEST_ROOT fences the writers to it.
"""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
HOOK = ROOT / "deploy" / "vpn-bot-acme-reload.sh"
KNOWN_UNMANAGED = ROOT / "deploy" / "host" / "known-unmanaged.list"

pytestmark = pytest.mark.timeout(60)

OWNER = f"{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}"

# sha256 of the host copies, measured on 2026-11-04. The repo copies must be
# byte-identical: an ssh file that differs is refused without ALLOW_SSH_CHANGE=1,
# and these sysctl files are meant to read "synced" on the first deploy.
HOST_SHA256 = {
    "deploy/host/ssh/00-root-key-only.conf": "69ef0a66254cbbe22c0d5e9b98f030410ab27b3e3ca87961347b6f5ed11a73a6",
    "deploy/host/ssh/ssh.socket-override.conf": "0a66a1fd2b14fca1ece3e0f48be3cf1a6ed149de26571891d021c28933896e6b",
    "deploy/host/ssh/00-vpnrelay-keyonly.conf": "118292b73f50c9a063ba73828fae66a8a30835ff89c4c98e814963e1d533b309",
    "deploy/host/sysctl/90-no-mptcp.conf": "9434089e550fa95e2794830827154512eac9c7b09d81bf4865eb9a07e25c36de",
    "deploy/host/sysctl/99-bbr.conf": "ed6843d5835be86035d56196c7b1ef8b5d3f07558ebff6d17ff4cf5bec7b2a07",
    "deploy/host/sysctl/99-network-buffers.conf": "735896de105ea0f5d3defda9a4cea1b3090d0611f0581155dfd43ab2ae286996",
    "deploy/host/sysctl/99-swap-tuning.conf": "4afe1c8fd814e15718256ff5796866f25a083d8eabb5f63cd1967fb4637fd2a8",
    "deploy/host/sysctl/99-vpn-forwarding.conf": "7de9e61bfd3ef0b34bcacfba0fcbd0896611812ed74015f2dac1446c3bacd743",
    # `sha256sum /etc/resolv.conf` on the main server, 2026-11-11 (a plain file there,
    # not resolved's stub symlink): the repo copy must read "synced" on the first deploy.
    "deploy/host/dns/resolv.conf": "bfb36a68f16a2d677cd490d7fe7742ed80075203eb7a382e610783d0b74a6d5b",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


# --------------------------------------------------------------------------- #
# Stubs. State lives in $SD, call logs in $LOGS; nothing touches the real host.
# --------------------------------------------------------------------------- #
SYSTEMCTL = r"""
shopt -s nullglob
echo "systemctl $*" >> "$LOGS/systemctl.log"
verb="$1"; unit="${!#}"
case "$verb" in
  is-active)  s="$(cat "$SD/$unit.active" 2>/dev/null || echo inactive)"; echo "$s"; [[ "$s" == active ]]; exit ;;
  is-enabled) s="$(cat "$SD/$unit.enabled" 2>/dev/null || echo disabled)"; echo "$s"; [[ "$s" == enabled ]]; exit ;;
  show)       [[ -f "$SD/$unit.loaded" ]] && echo loaded || echo not-found; exit 0 ;;
  cat)        found=0
              for x in "$UNITDIR/$unit" "$UNITDIR/$unit.d/"*.conf; do [[ -f "$x" ]] || continue; found=1; cat "$x"; done
              [[ $found == 1 ]]; exit ;;
esac
[[ -f "$SD/fail_${verb}" || -f "$SD/fail_${verb}_${unit}" ]] && exit 1
case "$verb" in
  enable)  echo enabled > "$SD/$unit.enabled"; [[ " $* " == *" --now "* ]] && echo active > "$SD/$unit.active" ;;
  disable) rm -f "$SD/$unit.enabled"; [[ " $* " == *" --now "* ]] && echo inactive > "$SD/$unit.active" ;;
  start|restart|reload|try-restart) echo active > "$SD/$unit.active" ;;
  stop)    echo inactive > "$SD/$unit.active" ;;
esac
exit 0
"""

SYSCTL = r"""
echo "sysctl $*" >> "$LOGS/sysctl.log"
mkdir -p "$SD/sysctl"
if [[ "$1" == -n ]]; then [[ -f "$SD/sysctl/$2" ]] || exit 255; cat "$SD/sysctl/$2"; exit 0; fi
if [[ "$1" == -e && "$2" == -p ]]; then
  [[ -f "$SD/fail_sysctl_p" ]] && { echo "sysctl: setting key: Invalid argument"; exit 1; }
  while IFS= read -r l; do
    [[ "$l" =~ ^[[:space:]]*([#\;]|$) ]] && continue
    k="$(echo ${l%%=*})"; v="$(echo ${l#*=})"; echo "$v" > "$SD/sysctl/$k"
  done < "$3"
  exit 0
fi
for a in "$@"; do case "$a" in *=*) echo "${a#*=}" > "$SD/sysctl/${a%%=*}" ;; esac; done
exit 0
"""

LOGROTATE = r"""
echo "logrotate $*" >> "$LOGS/logrotate.log"
grep -q BROKEN "$2" && echo "error: $2:2 unknown option 'BROKEN' -- ignoring line"
exit 0
"""

SYSTEMD_ANALYZE = r"""
echo "systemd-analyze $*" >> "$LOGS/systemd-analyze.log"
if [[ "$1" == verify ]]; then grep -q BROKEN "$2" && echo "$2:3: Unknown lvalue 'BROKEN' in section 'Unit'"; fi
exit 0
"""

SSHD = r"""
echo "sshd $*" >> "$LOGS/sshd.log"
cfg="$SSHD_CONFIG_DEFAULT"; mode=""
while [[ $# -gt 0 ]]; do case "$1" in -t) mode=t ;; -T) mode=T ;; -f) cfg="$2"; shift ;; esac; shift; done
if [[ -f "$SD/sshd_live_fail" && "$cfg" == "$SSHD_CONFIG_DEFAULT" ]]; then echo "$cfg: line 3: Bad configuration option"; exit 255; fi
files=("$cfg")
while read -r inc; do for g in $inc; do [[ -f "$g" ]] && files+=("$g"); done; done < <(awk 'tolower($1)=="include"{print $2}' "$cfg")
if cat "${files[@]}" | grep -q BadOption; then echo "$cfg: line 1: Bad configuration option: BadOption"; exit 255; fi
[[ "$mode" == T ]] && echo "port $(cat "$SD/sshd_port" 2>/dev/null || echo 22)"
exit 0
"""

SS = r"""
echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port"
if [[ -f "$SD/listen" ]]; then while read -r p; do echo "LISTEN 0 128 0.0.0.0:$p 0.0.0.0:*"; done < "$SD/listen"; fi
exit 0
"""

DPKG = r"""
echo "dpkg $*" >> "$LOGS/dpkg.log"
[[ "$1" == -S ]] || exit 0
shift; rc=1
for p in "$@"; do
  if grep -qxF "$p" "$SD/dpkg_owned" 2>/dev/null; then echo "somepkg: $p"; rc=0
  else echo "dpkg-query: no path found matching pattern $p" >&2; fi
done
exit $rc
"""

GETENT = r"""
echo "getent $*" >> "$LOGS/getent.log"
[[ -f "$SD/getent_fail" ]] && exit 2
echo "140.82.121.4    STREAM github.com"
exit 0
"""

INSTALL = r"""
echo "install $*" >> "$LOGS/install.log"
mode=""; dirs=0; args=()
while [[ $# -gt 0 ]]; do case "$1" in
  -o|-g) shift 2 ;;
  -m) mode="$2"; shift 2 ;;
  -m0*) mode="${1#-m}"; shift ;;
  -d) dirs=1; shift ;;
  *) args+=("$1"); shift ;;
esac; done
if (( dirs )); then mkdir -p "${args[@]}"; [[ -z "$mode" ]] || chmod "$mode" "${args[@]}"; exit 0; fi
[[ -f "$SD/fail_install" ]] && exit 1
cp "${args[0]}" "${args[1]}" || exit 1
[[ -z "$mode" ]] || chmod "$mode" "${args[1]}"
# A copy that does not stick: the post-install rescan must catch it.
[[ -f "$SD/install_corrupt" ]] && echo "# corrupted" >> "${args[1]}"
exit 0
"""


class Lab:
    """A fake host (tmp/host), a fake checkout (tmp/repo) and the stubs."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.repo = tmp / "repo"
        self.host = tmp / "host"
        self.stub = tmp / "stub"
        self.sd = tmp / "sd"
        self.logs = tmp / "logs"
        self.stage = tmp / "stage"
        self.proc = tmp / "proc" / "sys"
        for d in (self.repo, self.host, self.stub, self.sd, self.logs, self.stage, self.proc):
            d.mkdir(parents=True, exist_ok=True)
        self.unitdir = self.h("etc/systemd/system")
        self.unitdir.mkdir(parents=True)
        self.sshd_config = self.put("etc/ssh/sshd_config",
                                    f"Include {self.h('etc/ssh/sshd_config.d')}/*.conf\nPort 22\n")
        for key in ("net/ipv4/ip_forward", "net/core/somaxconn"):
            (self.proc / key).parent.mkdir(parents=True, exist_ok=True)
            (self.proc / key).write_text("0\n", encoding="utf-8")
        self.env_file = tmp / "dot.env"
        self.env_file.write_text("BOT_TOKEN=x\n", encoding="utf-8")
        self.entries: list[str] = []
        self.helpers: list[str] = []
        self.scan_dirs: list[Path] = []
        for name, body in (("systemctl", SYSTEMCTL), ("sysctl", SYSCTL), ("logrotate", LOGROTATE),
                           ("systemd-analyze", SYSTEMD_ANALYZE), ("sshd", SSHD), ("ss", SS),
                           ("dpkg", DPKG), ("install", INSTALL), ("getent", GETENT), ("sleep", "exit 0\n")):
            _stub(self.stub / name, body)

    # --- fixtures -----------------------------------------------------------
    def h(self, rel: str) -> Path:
        return self.host / rel

    def put(self, rel: str, content: str, mode: int = 0o644) -> Path:
        p = self.h(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        p.chmod(mode)
        return p

    def add(self, cls: str, rel: str, content: str, *, mode: str = "0644", role: str = "main",
            opts: str = "", src: str | None = None) -> Path:
        src = src or f"deploy/host/{cls}/{Path(rel).name}"
        s = self.repo / src
        s.parent.mkdir(parents=True, exist_ok=True)
        s.write_text(content, encoding="utf-8")
        entry = f"{src}|{self.h(rel)}|{mode}|{OWNER}|{cls}|{role}"
        self.entries.append(entry + (f"|{opts}" if opts else ""))
        return self.h(rel)

    def retire(self, rel: str, role: str = "main") -> Path:
        self.entries.append(f"-|{self.h(rel)}|-|-|absent|{role}")
        return self.h(rel)

    def flag(self, name: str, value: str = "") -> None:
        (self.sd / name).parent.mkdir(parents=True, exist_ok=True)
        (self.sd / name).write_text(value, encoding="utf-8")

    def ssh_up(self, *ports: str) -> None:
        self.flag("ssh.service.active", "active")
        self.flag("listen", "".join(f"{p}\n" for p in ports))

    # --- running ----------------------------------------------------------
    def run(self, body: str, **knobs: str) -> subprocess.CompletedProcess[str]:
        entries = "\n".join(f'  "{e}"' for e in self.entries)
        helpers = "\n".join(f'  "{e}"' for e in self.helpers)
        scan = " ".join(f'"{d}"' for d in self.scan_dirs)
        knob_lines = "".join(f'{k}="{v}"\n' for k, v in knobs.items())
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -uo pipefail\n"
            "export DEPLOY_SELFTEST=1\n"
            f'export PATH="{self.stub}:$PATH" SD="{self.sd}" LOGS="{self.logs}" UNITDIR="{self.unitdir}"\n'
            f'export SSHD_CONFIG_DEFAULT="{self.sshd_config}"\n'
            f'source "{DEPLOY_SH}"\n'
            'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""\n'
            f'STAGE="{self.stage}"; APP_DIR="{self.repo}"; ENV_FILE="{self.env_file}"\n'
            f'MH_SELFTEST_ROOT="{self.tmp}"\n'
            f'SYSTEMD_UNIT_DIR="{self.unitdir}"; PROC_SYS="{self.proc}"; SSHD_CONFIG="{self.sshd_config}"\n'
            "SSH_LISTEN_WAIT=2; RESOLVED_PROBE_WAIT=3\n"
            f'ABSENT_REF_PATHS=("{self.h("etc/crontab")}" "{self.h("etc/cron.d")}" "{self.h("var/spool/cron")}" '
            f'"{self.unitdir}" "{self.h("usr/lib/systemd/system")}")\n'
            f"UNMANAGED_SCAN_DIRS=({scan})\n"
            "CONFFILE_REPORT_PATHS=()\n"
            # The operator's own knobs may be exported when deploy.sh runs this suite.
            "ALLOW_SSH_CHANGE=0; ALLOW_UNIT_DRIFT=0; PHASE1_ONLY=0; NODE_ROLE=main\n"
            f"MANAGED_HOST_FILES=(\n{entries}\n)\n"
            f"OUT_OF_REPO_HELPERS=(\n{helpers}\n)\n"
            # The real probe opens TCP connections; it has its own test below.
            'ssh_banner_ok() { [[ ! -f "$SD/no_banner_$1" ]]; }\n'
            'rollback() { set +e; echo "ROLLBACK_CALLED"; host_files_rollback; exit 42; }\n'
            'relay_rollback() { set +e; echo "RELAY_ROLLBACK_CALLED"; host_files_rollback; exit 43; }\n'
            + knob_lines + body,
            encoding="utf-8",
        )
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.tmp), "LANG": "C.UTF-8"}
        proc = subprocess.run(["bash", str(driver)], cwd=str(self.tmp), env=env,
                              capture_output=True, text=True, check=False)
        proc.stdout = proc.stdout + "\n--STDERR--\n" + proc.stderr
        return proc

    def log(self, name: str) -> list[str]:
        p = self.logs / f"{name}.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def mutating_systemctl(self) -> list[str]:
        reads = {"is-active", "is-enabled", "show", "cat"}
        return [ln for ln in self.log("systemctl") if ln.split()[1] not in reads]


PHASE1 = 'host_state_phase1 "$APP_DIR"; echo PHASE1-OK\n'
PHASE2 = (
    'readarray -t _p < <(managed_host_stage_paths); stage_host_paths "${_p[@]}"\n'
    "install_managed_host_files; echo PHASE2-OK\n"
)
BOTH = PHASE1 + PHASE2


# --------------------------------------------------------------------------- #
# 1. Every class through the same five situations
# --------------------------------------------------------------------------- #
@dataclass
class Case:
    cls: str
    rel: str
    good: str      # the repo copy
    older: str     # what the host has in a drift
    bad: str       # a repo copy the validator refuses
    mode: str = "0644"

    def setup_ok(self, lab: Lab) -> None:
        if self.cls == "ssh":
            lab.ssh_up("22")

    def setup_post_failure(self, lab: Lab) -> None:
        """Make something AFTER the install fail."""
        {
            "sysctl": lambda: lab.flag("fail_sysctl_p"),
            "unit": lambda: lab.flag("fail_daemon-reload"),
            "journald": lambda: lab.flag("fail_restart_systemd-journald"),
            "resolved": lambda: lab.flag("getent_fail"),
            "ssh": lambda: lab.flag("ssh.service.active", "active"),  # but nothing listens
        }.get(self.cls, lambda: lab.flag("install_corrupt"))()

    def knobs(self) -> dict[str, str]:
        return {"ALLOW_SSH_CHANGE": "1"} if self.cls == "ssh" else {}

    def assert_post_action(self, lab: Lab, out: str) -> None:
        sc = lab.mutating_systemctl()
        dst = str(lab.h(self.rel))
        if self.cls == "sysctl":
            assert f"sysctl -e -p {dst}" in lab.log("sysctl")
            assert sc == []
        elif self.cls == "unit":
            assert sc[0] == "systemctl daemon-reload", sc
            assert "systemctl enable --now --quiet x.timer" in sc
        elif self.cls == "journald":
            assert sc == ["systemctl restart systemd-journald"]
        elif self.cls == "resolved":
            assert sc == ["systemctl try-reload-or-restart systemd-resolved"]
            assert lab.log("getent") == ["getent ahosts github.com"]
            assert "getent ahosts github.com: resolves (after 0s)" in out
        elif self.cls == "ssh":
            assert any(ln.startswith("sshd -t") for ln in lab.log("sshd"))
            assert sc == ["systemctl reload ssh.service"]
            assert "ssh.service active, listening on :22" in out
        else:
            assert sc == [], f"class {self.cls} has no post-action: {sc}"
            assert lab.log("sysctl") == []
        if self.cls == "networkd":
            assert "next systemd-networkd restart" in out


TIMER = "[Unit]\nDescription={d}\n\n[Timer]\nOnCalendar=daily\n\n[Install]\nWantedBy=timers.target\n"
HOOK_SCRIPT = '#!/usr/bin/env bash\n# {v}\n[[ "${{1:-}}" == --dry-run ]] && exit {rc}\nexit 0\n'

CASES = [
    Case("logrotate", "etc/logrotate.d/xray",
         "/var/log/x.log {\n    daily\n}\n", "/var/log/x.log {\n    weekly\n}\n", "/var/log/x.log {\n    BROKEN\n}\n"),
    Case("sysctl", "etc/sysctl.d/99-x.conf",
         "net.ipv4.ip_forward = 1\n", "net.ipv4.ip_forward = 0\n", "net.ipv4.no_such_key = 1\n"),
    Case("unit", "etc/systemd/system/x.timer",
         TIMER.format(d="new"), TIMER.format(d="old"), TIMER.format(d="x") + "BROKEN=1\n"),
    Case("journald", "etc/systemd/journald.conf.d/10-vpn-bot.conf",
         "[Journal]\nSystemMaxUse=500M\n", "[Journal]\nSystemMaxUse=400M\n", "SystemMaxUse=500M\n"),
    Case("resolved", "etc/systemd/resolved.conf.d/10-vpn-bot.conf",
         "[Resolve]\nDNS=1.1.1.1 8.8.8.8\n", "[Resolve]\nDNS=9.9.9.9\n", "[Journal]\nDNS=1.1.1.1\n"),
    Case("networkd", "etc/systemd/networkd.conf.d/10-keep.conf",
         "[Network]\nManageForeignRoutes=no\n", "[Network]\n", "[Journal]\nManageForeignRoutes=no\n"),
    Case("hook", "usr/local/sbin/acme-reload.sh",
         HOOK_SCRIPT.format(v="v2", rc=0), HOOK_SCRIPT.format(v="v1", rc=0), HOOK_SCRIPT.format(v="v3", rc=3),
         mode="0755"),
    Case("ssh", "etc/ssh/sshd_config.d/00-x.conf",
         "PasswordAuthentication no\n", "PasswordAuthentication yes\n", "BadOption yes\n"),
]
IDS = [c.cls for c in CASES]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_absent_is_installed_and_the_post_action_runs(tmp_path: Path, case: Case) -> None:
    lab = Lab(tmp_path)
    dst = lab.add(case.cls, case.rel, case.good, mode=case.mode)
    case.setup_ok(lab)
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert "PHASE2-OK" in proc.stdout
    assert _read(dst) == case.good
    assert oct(dst.stat().st_mode & 0o777) == oct(int(case.mode, 8))
    case.assert_post_action(lab, proc.stdout)
    assert "1 installed, 0 removed, 0 mode/owner fixed" in proc.stdout


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_synced_changes_nothing(tmp_path: Path, case: Case) -> None:
    lab = Lab(tmp_path)
    dst = lab.add(case.cls, case.rel, case.good, mode=case.mode)
    lab.put(case.rel, case.good, int(case.mode, 8))
    case.setup_ok(lab)
    before = dst.stat().st_mtime_ns
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert re.search(rf"{case.cls}\s+synced\s+{re.escape(str(dst))}", proc.stdout)
    assert dst.stat().st_mtime_ns == before
    assert not [ln for ln in lab.log("install") if str(dst) in ln]
    assert lab.mutating_systemctl() == []
    assert lab.log("sysctl") == []
    assert "all in sync, nothing changed" in proc.stdout


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_drift_is_reinstalled_with_the_diff_shown(tmp_path: Path, case: Case) -> None:
    lab = Lab(tmp_path)
    dst = lab.add(case.cls, case.rel, case.good, mode=case.mode)
    lab.put(case.rel, case.older, int(case.mode, 8))
    case.setup_ok(lab)
    if case.cls == "unit":
        lab.flag("x.timer.enabled", "enabled")
    proc = lab.run(BOTH, **case.knobs())
    assert proc.returncode == 0, proc.stdout
    assert re.search(rf"{case.cls}\s+drift\s+{re.escape(str(dst))}", proc.stdout)
    assert f"--- host: {dst}" in proc.stdout, "Phase 1 shows the diff of a drift"
    assert _read(dst) == case.good
    case.assert_post_action(lab, proc.stdout)


@pytest.mark.parametrize("case", CASES, ids=IDS)
@pytest.mark.parametrize("host_has", ["absent", "older"])
def test_a_refused_candidate_stops_phase1_before_any_mutation(tmp_path: Path, case: Case, host_has: str) -> None:
    lab = Lab(tmp_path)
    dst = lab.add(case.cls, case.rel, case.bad, mode=case.mode)
    if host_has == "older":
        lab.put(case.rel, case.older, int(case.mode, 8))
    case.setup_ok(lab)
    proc = lab.run(BOTH, **case.knobs())
    assert proc.returncode == 1, proc.stdout
    assert "PHASE1-OK" not in proc.stdout
    assert "the validator refused the repo candidate" in proc.stdout
    assert "Phase 1 refused 1 entr(y/ies)" in proc.stdout and "nothing was changed" in proc.stdout
    if host_has == "absent":
        assert not dst.exists()
    else:
        assert _read(dst) == case.older
    assert lab.log("install") == [] and lab.mutating_systemctl() == []
    assert "backed up" not in proc.stdout, "nothing was even staged"


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_a_failure_after_the_install_rolls_the_file_back(tmp_path: Path, case: Case) -> None:
    lab = Lab(tmp_path)
    dst = lab.add(case.cls, case.rel, case.good, mode=case.mode)
    lab.put(case.rel, case.older, int(case.mode, 8))
    case.setup_post_failure(lab)
    if case.cls == "sysctl":
        lab.flag("sysctl/net.ipv4.ip_forward", "0")
    proc = lab.run(BOTH, **case.knobs())
    assert proc.returncode == 42, proc.stdout
    assert "PHASE2-OK" not in proc.stdout and "ROLLBACK_CALLED" in proc.stdout
    assert _read(dst) == case.older, "the pre-deploy copy is back"
    assert f"restore {dst}: rc=0" in proc.stdout
    if case.cls == "sysctl":
        assert "sysctl -q -w net.ipv4.ip_forward=0" in lab.log("sysctl")
    if case.cls == "ssh":
        assert "NOT listening on :22" in proc.stdout
        assert "sshd -t on the restored ssh config: ok" in proc.stdout
        assert lab.mutating_systemctl()[-1] == "systemctl reload ssh.service", "re-applied after the restore"
    if case.cls == "resolved":
        assert "name resolution fails after the systemd-resolved drop-in change" in proc.stdout
        assert "getent ahosts github.com found nothing for 3s" in proc.stdout
        assert len(lab.log("getent")) == 4, "retried once a second for RESOLVED_PROBE_WAIT"
        assert "try-reload-or-restart systemd-resolved (drop-in restored): rc=0" in proc.stdout
        assert lab.mutating_systemctl()[-1] == "systemctl try-reload-or-restart systemd-resolved", "the restored file is reloaded"


def test_a_file_that_did_not_exist_is_removed_again_with_its_new_directory(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.add("journald", "etc/systemd/journald.conf.d/10-vpn-bot.conf", "[Journal]\nSystemMaxUse=500M\n")
    lab.flag("fail_restart_systemd-journald")
    proc = lab.run(BOTH)
    assert proc.returncode == 42, proc.stdout
    assert not dst.exists() and not dst.parent.exists()
    assert f"remove {dst} (absent before the deploy): rc=0" in proc.stdout
    assert f"remove {dst.parent} (created by this deploy, empty again): rc=0" in proc.stdout
    assert "restart systemd-journald (drop-in restored)" in proc.stdout


def test_mode_and_owner_are_repaired_without_a_post_action(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.add("hook", "usr/local/sbin/acme-reload.sh", HOOK_SCRIPT.format(v="v", rc=0), mode="0755")
    lab.put("usr/local/sbin/acme-reload.sh", HOOK_SCRIPT.format(v="v", rc=0), 0o644)
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"hook\s+meta\s+", proc.stdout)
    assert dst.stat().st_mode & 0o777 == 0o755
    assert not [ln for ln in lab.log("install") if str(dst) in ln and " -d " not in ln]
    assert "0 installed, 0 removed, 1 mode/owner fixed" in proc.stdout


def test_a_disabled_timer_stays_disabled_after_a_reinstall(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    lab.add("unit", "etc/systemd/system/x.timer", TIMER.format(d="new"))
    lab.put("etc/systemd/system/x.timer", TIMER.format(d="old"))
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert lab.mutating_systemctl() == ["systemctl daemon-reload"]
    assert "was disabled before — left so" in proc.stdout


def test_the_deploy_never_starts_a_timers_service(tmp_path: Path) -> None:
    """even-day-reboot.service reboots the host: only its timer is ever enabled."""
    lab = Lab(tmp_path)
    lab.add("unit", "etc/systemd/system/x.service", "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n")
    lab.add("unit", "etc/systemd/system/x.timer", TIMER.format(d="t"))
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    sc = lab.mutating_systemctl()
    assert sc == ["systemctl daemon-reload", "systemctl enable --now --quiet x.timer"], sc


def test_a_module_sysctl_key_only_warns(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    lab.add("sysctl", "etc/sysctl.d/90-no-mptcp.conf", "net.mptcp.enabled = 0\n")
    proc = lab.run(PHASE1)
    assert proc.returncode == 0, proc.stdout
    assert "[WARN]" in proc.stdout and "net.mptcp.enabled is not under" in proc.stdout


# --------------------------------------------------------------------------- #
# 2. ssh
# --------------------------------------------------------------------------- #
SOCKET = "[Socket]\nListenStream=\nListenStream=0.0.0.0:{p}\nListenStream=[::]:{p}\n"


def _ssh_lab(tmp_path: Path) -> tuple[Lab, Path]:
    lab = Lab(tmp_path)
    dst = lab.add("ssh", "etc/ssh/sshd_config.d/00-root-key-only.conf", "PasswordAuthentication no\n")
    lab.put("etc/ssh/sshd_config.d/00-root-key-only.conf", "PasswordAuthentication yes\n")
    lab.ssh_up("22")
    return lab, dst


def test_ssh_drift_is_refused_before_any_mutation(tmp_path: Path) -> None:
    lab, dst = _ssh_lab(tmp_path)
    proc = lab.run(BOTH)
    assert proc.returncode == 1, proc.stdout
    assert "refusing to deploy without ALLOW_SSH_CHANGE=1; nothing was changed" in proc.stdout
    assert "-PasswordAuthentication yes" in proc.stdout and "+PasswordAuthentication no" in proc.stdout
    assert "SECOND ssh session" in proc.stdout
    assert _read(dst) == "PasswordAuthentication yes\n"
    assert lab.log("install") == [] and lab.mutating_systemctl() == []


def test_ssh_drift_is_only_reported_in_inspection_mode(tmp_path: Path) -> None:
    lab, dst = _ssh_lab(tmp_path)
    proc = lab.run(PHASE1, PHASE1_ONLY="1")
    assert proc.returncode == 0, proc.stdout
    assert "a real deploy refuses this without ALLOW_SSH_CHANGE=1" in proc.stdout
    assert _read(dst) == "PasswordAuthentication yes\n"


def test_ssh_drift_with_the_knob_is_applied_and_checked(tmp_path: Path) -> None:
    lab, dst = _ssh_lab(tmp_path)
    proc = lab.run(BOTH, ALLOW_SSH_CHANGE="1")
    assert proc.returncode == 0, proc.stdout
    assert "keep a SECOND ssh session open" in proc.stdout
    assert _read(dst) == "PasswordAuthentication no\n"
    assert lab.mutating_systemctl() == ["systemctl reload ssh.service"]
    assert "ssh.service active, listening on :22" in proc.stdout


def test_a_listenstream_change_restarts_the_socket_and_checks_the_new_port(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.add("ssh", "etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="2222"))
    lab.put("etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="54321"))
    lab.flag("ssh.socket.active", "active")
    lab.flag("listen", "2222\n")
    proc = lab.run(BOTH, ALLOW_SSH_CHANGE="1")
    assert proc.returncode == 0, proc.stdout
    assert "ListenStream port(s): 2222" in proc.stdout
    assert lab.mutating_systemctl() == ["systemctl daemon-reload", "systemctl restart ssh.socket"]
    assert "ssh.socket active, listening on :2222" in proc.stdout
    assert _read(dst) == SOCKET.format(p="2222")


def test_a_socket_change_also_restarts_a_running_sshd(tmp_path: Path) -> None:
    """Accept=no: a running sshd keeps the sockets it was started with, so restarting
    ssh.socket alone would leave it on the old port while systemd holds the new one."""
    lab = Lab(tmp_path)
    lab.add("ssh", "etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="2222"))
    lab.put("etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="54321"))
    lab.flag("ssh.socket.active", "active")
    lab.flag("ssh.service.active", "active")
    lab.flag("listen", "2222\n")
    proc = lab.run(BOTH, ALLOW_SSH_CHANGE="1")
    assert proc.returncode == 0, proc.stdout
    assert lab.mutating_systemctl() == [
        "systemctl daemon-reload", "systemctl restart ssh.socket", "systemctl restart ssh.service",
    ]
    assert "listening on :2222 and answering SSH" in proc.stdout


def test_a_listener_that_does_not_answer_ssh_rolls_back(tmp_path: Path) -> None:
    """systemd can hold the new port while no sshd ever accepts on it."""
    lab = Lab(tmp_path)
    dst = lab.add("ssh", "etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="2222"))
    lab.put("etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="54321"))
    lab.flag("ssh.socket.active", "active")
    lab.flag("ssh.service.active", "active")
    lab.flag("listen", "2222\n54321\n")
    lab.flag("no_banner_2222")
    proc = lab.run(BOTH, ALLOW_SSH_CHANGE="1")
    assert proc.returncode == 42, proc.stdout
    assert ":2222 (listening, but no SSH banner)" in proc.stdout
    assert _read(dst) == SOCKET.format(p="54321")
    assert lab.mutating_systemctl()[-2:] == ["systemctl restart ssh.socket", "systemctl restart ssh.service"]
    assert "restart ssh.service (takes the restored sockets): rc=0" in proc.stdout


def _banner_server(payload: bytes):
    import socket
    import threading
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    srv.settimeout(5)

    def serve() -> None:
        try:
            while True:
                conn, _ = srv.accept()
                if payload:
                    conn.sendall(payload)
                threading.Timer(2.0, conn.close).start()
        except OSError:
            return

    threading.Thread(target=serve, daemon=True).start()
    return srv, srv.getsockname()[1]


@pytest.mark.parametrize(("payload", "ok"), [(b"SSH-2.0-OpenSSH_9.6\r\n", True), (b"", False), (b"HTTP/1.1 400\r\n", False)])
def test_the_real_banner_probe(tmp_path: Path, payload: bytes, ok: bool) -> None:
    """The real ssh_banner_ok (not the Lab stub), against a loopback TCP server."""
    srv, port = _banner_server(payload)
    try:
        listening = f"LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*"
        driver = tmp_path / "probe.sh"
        driver.write_text(
            f'set -uo pipefail\nexport DEPLOY_SELFTEST=1\nsource "{DEPLOY_SH}"\n'
            'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\nSSH_BANNER_TIMEOUT=1\n'
            f'if ssh_banner_ok {port} "{listening}"; then echo PROBE=ok; else echo PROBE=no; fi\n',
            encoding="utf-8",
        )
        proc = subprocess.run(["bash", str(driver)], capture_output=True, text=True, check=False)
    finally:
        srv.close()
    assert ("PROBE=ok" if ok else "PROBE=no") in proc.stdout, proc.stdout + proc.stderr


def test_a_dead_port_after_the_socket_change_rolls_back(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.add("ssh", "etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="2222"))
    lab.put("etc/systemd/system/ssh.socket.d/override.conf", SOCKET.format(p="54321"))
    lab.flag("ssh.socket.active", "active")
    lab.flag("listen", "54321\n")          # the new port never comes up
    proc = lab.run(BOTH, ALLOW_SSH_CHANGE="1")
    assert proc.returncode == 42, proc.stdout
    assert "NOT listening on :2222" in proc.stdout
    assert _read(dst) == SOCKET.format(p="54321")
    sc = lab.mutating_systemctl()
    assert sc[-2:] == ["systemctl daemon-reload", "systemctl restart ssh.socket"], "the old socket is re-applied"


def test_a_restored_config_that_fails_sshd_t_is_not_reloaded(tmp_path: Path) -> None:
    lab, dst = _ssh_lab(tmp_path)
    lab.flag("sshd_live_fail")          # sshd -t on the live config fails, before and after
    proc = lab.run(BOTH, ALLOW_SSH_CHANGE="1")
    assert proc.returncode == 42, proc.stdout
    assert "sshd -t fails on the installed ssh configuration" in proc.stdout
    assert "sshd -t on the RESTORED ssh config FAILED" in proc.stdout
    assert "ssh NOT reloaded or restarted — MANUAL ACTION REQUIRED" in proc.stdout
    assert _read(dst) == "PasswordAuthentication yes\n"
    assert not any("reload" in ln or "restart" in ln for ln in lab.mutating_systemctl())


def test_an_absent_ssh_file_needs_no_knob(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.add("ssh", "etc/ssh/sshd_config.d/00-x.conf", "PasswordAuthentication no\n")
    lab.ssh_up("22")
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert _read(dst) == "PasswordAuthentication no\n"


def test_sshd_t_sees_the_candidate_in_place_of_the_host_copy(tmp_path: Path) -> None:
    """The validator composes sshd_config + every drop-in with the CANDIDATE swapped
    in: a bad option in another, untouched drop-in fails it as well."""
    lab = Lab(tmp_path)
    lab.add("ssh", "etc/ssh/sshd_config.d/00-x.conf", "PasswordAuthentication no\n")
    lab.put("etc/ssh/sshd_config.d/50-other.conf", "BadOption yes\n")
    lab.ssh_up("22")
    proc = lab.run(PHASE1)
    assert proc.returncode == 1, proc.stdout
    assert "Bad configuration option: BadOption" in proc.stdout


# --------------------------------------------------------------------------- #
# 3. absent (retired files)
# --------------------------------------------------------------------------- #
def _retired_units(tmp_path: Path) -> tuple[Lab, Path, Path]:
    lab = Lab(tmp_path)
    timer = lab.retire("etc/systemd/system/warp-sample.timer")
    service = lab.retire("etc/systemd/system/warp-sample.service")
    lab.put("etc/systemd/system/warp-sample.timer", "[Timer]\nOnCalendar=daily\nUnit=warp-sample.service\n")
    lab.put("etc/systemd/system/warp-sample.service", "[Service]\nExecStart=/bin/true\n")
    lab.flag("warp-sample.timer.enabled", "enabled")
    lab.flag("warp-sample.timer.active", "active")
    return lab, timer, service


def test_a_retired_unit_is_disabled_then_removed(tmp_path: Path) -> None:
    lab, timer, service = _retired_units(tmp_path)
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert not timer.exists() and not service.exists()
    assert lab.mutating_systemctl() == [
        "systemctl disable --now --quiet warp-sample.timer",
        "systemctl disable --now --quiet warp-sample.service",
        "systemctl daemon-reload",
    ]
    assert "0 installed, 2 removed" in proc.stdout


def test_the_rollback_brings_a_retired_unit_back_enabled_and_running(tmp_path: Path) -> None:
    lab, timer, service = _retired_units(tmp_path)
    lab.add("journald", "etc/systemd/journald.conf.d/10.conf", "[Journal]\nSystemMaxUse=1M\n")
    lab.flag("fail_restart_systemd-journald")
    proc = lab.run(BOTH)
    assert proc.returncode == 42, proc.stdout
    assert timer.exists() and service.exists()
    assert (lab.sd / "warp-sample.timer.enabled").read_text().strip() == "enabled"
    assert (lab.sd / "warp-sample.timer.active").read_text().strip() == "active"
    assert "enable warp-sample.timer (enabled before the deploy): rc=0" in proc.stdout
    assert "start warp-sample.timer (active before the deploy): rc=0" in proc.stdout


def test_a_retired_file_already_gone_is_a_noop(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    lab.retire("usr/local/sbin/site-freshen.sh")
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"absent\s+gone\s+", proc.stdout)
    assert lab.mutating_systemctl() == [] and lab.log("install") == []


@pytest.mark.parametrize(
    ("where", "content"),
    [
        ("var/spool/cron/crontabs/root", "7 3 * * * {path} >/dev/null 2>&1\n"),
        ("etc/cron.d/freshen", "7 3 * * * root /usr/local/sbin/site-freshen.sh\n"),
        ("etc/crontab", "7 3 * * * root site-freshen.sh\n"),
        ("usr/lib/systemd/system/decoy.service.d/override.conf", "[Service]\nExecStart={path}\n"),
        ("etc/systemd/system/decoy.timer", "[Timer]\nUnit=site-freshen.sh\n"),
        (".env", "DECOY_FRESHEN_HOOK={path}\n"),
    ],
)
def test_a_retired_file_something_still_names_fails_phase1(tmp_path: Path, where: str, content: str) -> None:
    lab = Lab(tmp_path)
    path = lab.retire("usr/local/sbin/site-freshen.sh")
    lab.put("usr/local/sbin/site-freshen.sh", "#!/bin/sh\n", 0o755)
    ref = lab.env_file if where == ".env" else lab.h(where)
    ref.parent.mkdir(parents=True, exist_ok=True)
    ref.write_text(content.format(path=path), encoding="utf-8")
    proc = lab.run(BOTH)
    assert proc.returncode == 1, proc.stdout
    assert "PHASE1-OK" not in proc.stdout
    assert re.search(rf"{re.escape(str(ref))}:\d+:", proc.stdout), "the referencing file and line are named"
    assert f"{path}: retired, but still named by the line(s) above" in proc.stdout
    assert path.exists() and lab.mutating_systemctl() == []


def test_the_retired_files_do_not_count_as_references_to_each_other(tmp_path: Path) -> None:
    """warp-sample.timer names warp-sample.service; both are going."""
    lab, _, _ = _retired_units(tmp_path)
    proc = lab.run(PHASE1)
    assert proc.returncode == 0, proc.stdout


# --------------------------------------------------------------------------- #
# 4. The MTProxy drop-in: gate + legacy name
# --------------------------------------------------------------------------- #
DROPIN = "[Service]\nUser=\nGroup=\nExecStart=\nExecStart=/opt/vpn-service/scripts/run-mtproxy-managed\n"


def _mtproxy_lab(tmp_path: Path, legacy_content: str | None) -> tuple[Lab, Path, Path]:
    lab = Lab(tmp_path)
    legacy = lab.h("etc/systemd/system/mtproxy.service.d/vpnbot-managed.conf")
    dst = lab.add("unit", "etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf", DROPIN,
                  src="deploy/mtproxy-vpn-bot-managed.conf", opts=f"gate=MTPROTO;legacy={legacy}")
    if legacy_content is not None:
        lab.put("etc/systemd/system/mtproxy.service.d/vpnbot-managed.conf", legacy_content)
    return lab, dst, legacy


def test_mtproxy_off_leaves_the_orphan_and_the_scanner_names_it(tmp_path: Path) -> None:
    lab, dst, legacy = _mtproxy_lab(tmp_path, DROPIN)
    lab.scan_dirs = [lab.unitdir]
    proc = lab.run(BOTH, MTPROTO_ON="no")
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"unit\s+gated-off\s+", proc.stdout)
    assert f"{legacy}" in proc.stdout and "orphan drop-in for absent unit mtproxy.service" in proc.stdout
    assert legacy.exists() and not dst.exists()
    assert lab.mutating_systemctl() == [] and lab.log("install") == []
    assert str(legacy) not in "\n".join(lab.log("install")), "not even staged for a write"


def test_mtproxy_on_renames_an_identical_legacy_dropin_without_a_restart(tmp_path: Path) -> None:
    lab, dst, legacy = _mtproxy_lab(tmp_path, DROPIN)
    lab.flag("mtproxy.service.active", "active")
    proc = lab.run(BOTH, MTPROTO_ON="yes", MTPROTO_SERVICE_NAME_V="mtproxy")
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"unit\s+rename\s+", proc.stdout)
    assert _read(dst) == DROPIN and not legacy.exists()
    assert lab.mutating_systemctl() == ["systemctl daemon-reload"], "renamed, not restarted"


def test_mtproxy_rename_is_undone_by_the_rollback(tmp_path: Path) -> None:
    lab, dst, legacy = _mtproxy_lab(tmp_path, DROPIN)
    lab.flag("fail_daemon-reload")
    proc = lab.run(BOTH, MTPROTO_ON="yes", MTPROTO_SERVICE_NAME_V="mtproxy")
    assert proc.returncode == 42, proc.stdout
    assert not dst.exists() and _read(legacy) == DROPIN


def test_mtproxy_on_with_a_different_legacy_dropin_stops_phase1(tmp_path: Path) -> None:
    lab, dst, legacy = _mtproxy_lab(tmp_path, DROPIN + "LimitNOFILE=1\n")
    proc = lab.run(BOTH, MTPROTO_ON="yes", MTPROTO_SERVICE_NAME_V="mtproxy")
    assert proc.returncode == 1, proc.stdout
    assert "host file legacy drift" in proc.stdout and "+LimitNOFILE=1" not in proc.stdout
    assert "-LimitNOFILE=1" in proc.stdout, "the diff shows what the legacy copy has extra"
    assert not dst.exists() and legacy.exists()
    assert lab.mutating_systemctl() == []


def test_a_different_legacy_dropin_is_left_alone_with_allow_unit_drift(tmp_path: Path) -> None:
    lab, dst, legacy = _mtproxy_lab(tmp_path, DROPIN + "LimitNOFILE=1\n")
    proc = lab.run(BOTH, MTPROTO_ON="yes", MTPROTO_SERVICE_NAME_V="mtproxy", ALLOW_UNIT_DRIFT="1")
    assert proc.returncode == 0, proc.stdout
    assert not dst.exists() and _read(legacy) == DROPIN + "LimitNOFILE=1\n"


def test_a_gated_dropin_for_another_unit_name_stops_phase1(tmp_path: Path) -> None:
    lab, _, _ = _mtproxy_lab(tmp_path, None)
    proc = lab.run(BOTH, MTPROTO_ON="yes", MTPROTO_SERVICE_NAME_V="mtg")
    assert proc.returncode == 1, proc.stdout
    assert "drop-in for mtproxy.service, but .env runs MTPROTO as another unit" in proc.stdout


def test_a_when_gate_skips_the_entry_where_its_path_is_absent(tmp_path: Path) -> None:
    """The acme hook only belongs where there is renewal material: its --dry-run
    validator fails by design without it, and must not block a host without TLS."""
    lab = Lab(tmp_path)
    tls = lab.h("etc/vpn-bot/tls/fullchain.pem")
    dst = lab.add("hook", "usr/local/sbin/acme-reload.sh", HOOK_SCRIPT.format(v="v", rc=3), mode="0755",
                  opts=f"when={tls}")
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"hook\s+gated-off\s+", proc.stdout) and f"{tls} is absent on this host" in proc.stdout
    assert not dst.exists() and "--dry-run" not in proc.stdout
    lab.put("etc/vpn-bot/tls/fullchain.pem", "chain\n")
    proc = lab.run(BOTH)
    assert proc.returncode == 1, "with the material present the entry is live — and this candidate is refused"
    assert "the validator refused the repo candidate" in proc.stdout


# --------------------------------------------------------------------------- #
# 5. Roles
# --------------------------------------------------------------------------- #
def _registry() -> list[list[str]]:
    text = _read(DEPLOY_SH)
    body = text[text.index("MANAGED_HOST_FILES=(") :].split("\n)\n", 1)[0].splitlines()[1:]
    return [ln.strip().strip('"').split("|") for ln in body if ln.strip().startswith('"')]


@pytest.mark.parametrize("role", ["main", "relay"])
def test_each_role_sees_only_its_own_entries(tmp_path: Path, role: str) -> None:
    """Read-only on the REAL registry: scan + stage list, no writer is called."""
    lab = Lab(tmp_path)
    body = (f"NODE_ROLE={role}\nMANAGED_HOST_FILES=(\n"
            + "\n".join(f'  "{"|".join(e)}"' for e in _registry())
            + "\n)\nscan_managed_host_files \"$APP_DIR\" | cut -d'|' -f1\necho --\nmanaged_host_stage_paths\n")
    proc = lab.run(body, MTPROTO_ON="no")
    assert proc.returncode == 0, proc.stdout
    scanned, staged = proc.stdout.split("--STDERR--")[0].split("--\n")
    want = [e[1] for e in _registry() if e[5] == role]
    assert scanned.split() == want
    assert set(staged.split()) <= set(want)


def test_a_relay_installs_only_the_relay_entry(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    main = lab.add("sysctl", "etc/sysctl.d/99-main.conf", "net.ipv4.ip_forward = 1\n")
    relay = lab.add("ssh", "etc/ssh/sshd_config.d/00-relay.conf", "PasswordAuthentication no\n", role="relay")
    lab.ssh_up("22")
    proc = lab.run(BOTH, NODE_ROLE="relay")
    assert proc.returncode == 0, proc.stdout
    assert relay.exists() and not main.exists()
    assert str(main) not in proc.stdout.split("--STDERR--")[0]


# --------------------------------------------------------------------------- #
# 6. Static guards on the real registry and deploy/host/
# --------------------------------------------------------------------------- #
VALID_CLASSES = {"logrotate", "sysctl", "unit", "journald", "networkd", "hook", "ssh", "plain", "resolved", "absent"}
VALID_GATES = {"MTPROTO", "SOCKS5", "HYSTERIA2"}


def test_registry_entries_are_well_formed() -> None:
    entries = _registry()
    assert entries, "MANAGED_HOST_FILES is empty — the parser is broken"
    # One entry per destination AND role: both roles carry e.g. the cloud-init marker.
    dsts = [(e[1], e[5]) for e in entries]
    assert len(dsts) == len(set(dsts)), "duplicate destinations within one role"
    for e in entries:
        assert len(e) in (6, 7), f"6 or 7 fields: {e}"
        src, dst, mode, owner, cls, role = e[:6]
        assert dst.startswith("/") and ".." not in dst, e
        assert cls in VALID_CLASSES, e
        assert role in {"main", "relay"}, e
        if cls == "absent":
            assert (src, mode, owner) == ("-", "-", "-"), f"a retired entry carries no source: {e}"
            assert len(e) == 6
            continue
        assert re.fullmatch(r"0[0-7]{3}", mode), e
        assert re.fullmatch(r"[a-z_][a-z0-9_-]*:[a-z_][a-z0-9_-]*", owner), e
        if len(e) == 7:
            for kv in e[6].split(";"):
                key, _, value = kv.partition("=")
                assert key in {"gate", "legacy", "when"}, e
                if key == "gate":
                    assert value in VALID_GATES, e
                elif key == "when":
                    assert value.startswith("/"), e
                else:
                    assert value.startswith("/") and Path(value).parent == Path(dst).parent, e


def test_every_registry_source_exists() -> None:
    for e in _registry():
        if e[4] != "absent":
            assert (ROOT / e[0]).is_file(), f"{e[1]}: source {e[0]} missing from the checkout"


def test_hook_and_ssh_entries_point_where_the_host_expects() -> None:
    reg = {e[1]: e for e in _registry()}
    assert reg["/usr/local/sbin/acme-reload.sh"] == [
        "deploy/vpn-bot-acme-reload.sh", "/usr/local/sbin/acme-reload.sh", "0755", "root:root", "hook", "main",
        "when=/etc/vpn-bot/tls/fullchain.pem"]
    assert reg["/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf"][5] == "relay"
    for dst in ("/etc/ssh/sshd_config.d/00-root-key-only.conf", "/etc/systemd/system/ssh.socket.d/override.conf"):
        assert reg[dst][4:6] == ["ssh", "main"]


def test_networkd_entry_is_the_dropin_the_phase1_check_reports() -> None:
    text = _read(DEPLOY_SH)
    src = re.search(r'NETWORKD_DROPIN_SRC="\$\{NETWORKD_DROPIN_SRC:-([^}]+)\}"', text).group(1)
    dst = re.search(r'NETWORKD_DROPIN_DST="\$\{NETWORKD_DROPIN_DST:-([^}]+)\}"', text).group(1)
    entry = [e for e in _registry() if e[4] == "networkd"][0]
    assert (entry[0], entry[1]) == (src, dst)


def test_site_freshen_py_is_kept_and_only_the_wrapper_is_retired() -> None:
    retired = {e[1] for e in _registry() if e[4] == "absent"}
    assert "/usr/local/sbin/site-freshen.sh" in retired
    assert "/usr/local/sbin/site-freshen.py" not in retired, "the decoy rewriter's only copy"
    assert re.search(r"^/usr/local/sbin/site-freshen\.py\s+# deployment-local — ", _read(KNOWN_UNMANAGED), re.M)


def test_the_mtproxy_dropin_is_gated_with_its_legacy_name() -> None:
    e = [e for e in _registry() if e[0] == "deploy/mtproxy-vpn-bot-managed.conf"][0]
    assert e[1] == "/etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf"
    assert e[6] == "gate=MTPROTO;legacy=/etc/systemd/system/mtproxy.service.d/vpnbot-managed.conf"


@pytest.mark.parametrize("rel", sorted(HOST_SHA256))
def test_repo_copy_is_byte_identical_to_the_host(rel: str) -> None:
    digest = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
    assert digest == HOST_SHA256[rel], (
        f"{rel} no longer matches the host copy byte for byte — the first deploy would "
        "reinstall it (ssh: refuse it without ALLOW_SSH_CHANGE=1)"
    )


def test_every_pinned_file_is_in_the_registry() -> None:
    sources = {e[0] for e in _registry()}
    assert set(HOST_SHA256) <= sources


KNOWN_LINE_RE = re.compile(
    r"^(?P<glob>/\S+)\s+#\s*(?P<cls>backup-only|installer|provider|deployment-local)\s+—\s+(?P<why>.+)$"
)


def test_known_unmanaged_list_is_well_formed() -> None:
    entries = 0
    for n, raw in enumerate(_read(KNOWN_UNMANAGED).splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = KNOWN_LINE_RE.match(raw)
        assert m, f"line {n}: expected '<abs glob>  # <class> — <reason>': {raw!r}"
        assert len(m.group("why").strip()) >= 20, f"line {n}: the reason needs at least 20 characters"
        entries += 1
    assert entries >= 10


def test_known_unmanaged_list_never_silences_a_deployed_file() -> None:
    import fnmatch
    globs = [KNOWN_LINE_RE.match(ln).group("glob") for ln in _read(KNOWN_UNMANAGED).splitlines()
             if KNOWN_LINE_RE.match(ln)]
    for e in _registry():
        for g in globs:
            assert not fnmatch.fnmatchcase(e[1], g), f"{e[1]} is deployed, but {g} would hide it"


def test_docs_list_every_host_file_and_the_ssh_knob() -> None:
    doc = _read(ROOT / "docs" / "host-state.md")
    for e in _registry():
        assert e[1] in doc, f"docs/host-state.md does not list {e[1]}"
    assert "ALLOW_SSH_CHANGE" in doc and "second ssh session" in doc.lower()
    assert "deploy/host/known-unmanaged.list" in doc


def test_deploy_sh_documents_the_ssh_knob_and_redeploy_forwards_it() -> None:
    text = _read(DEPLOY_SH)
    window = text[text.index("ALLOW_SSH_CHANGE=1") :][:1500]
    assert "BYPASSES" in window and "LOCKOUT" in window and "second ssh session" in window
    assert "ALLOW_SSH_CHANGE" in _read(ROOT / "scripts" / "redeploy.sh")


def test_the_writers_refuse_a_real_path_under_the_selftest_seam(tmp_path: Path) -> None:
    """The fence: a test that forgot to override the registry must not write /etc."""
    lab = Lab(tmp_path)
    lab.entries = ["deploy/host/x|/etc/vpnbot-selftest-must-not-exist|0644|root:root|sysctl|main"]
    (lab.repo / "deploy/host").mkdir(parents=True)
    (lab.repo / "deploy/host/x").write_text("x\n", encoding="utf-8")
    proc = lab.run("install_managed_host_files\n")
    assert proc.returncode == 1, proc.stdout
    assert "DEPLOY_SELFTEST: refusing to write /etc/vpnbot-selftest-must-not-exist" in proc.stdout
    assert not Path("/etc/vpnbot-selftest-must-not-exist").exists()


# --------------------------------------------------------------------------- #
# 7. Files nothing accounts for
# --------------------------------------------------------------------------- #
def test_the_unaccounted_scan(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    lab.scan_dirs = [lab.h("etc/sysctl.d"), lab.h("usr/local/sbin"), lab.unitdir]
    lab.add("sysctl", "etc/sysctl.d/99-managed.conf", "net.ipv4.ip_forward = 1\n")
    lab.put("etc/sysctl.d/99-managed.conf", "net.ipv4.ip_forward = 1\n")
    stray = lab.put("etc/sysctl.d/50-stray.conf", "vm.swappiness = 1\n")
    pkg = lab.put("etc/sysctl.d/10-pkg.conf", "kernel.x = 1\n")
    lab.flag("dpkg_owned", f"{pkg}\n")
    known = lab.put("usr/local/sbin/site-freshen.py", "print()\n")
    (lab.repo / "deploy/host").mkdir(parents=True, exist_ok=True)
    (lab.repo / "deploy/host/known-unmanaged.list").write_text(
        f"{lab.h('usr/local/sbin')}/site-*.py  # deployment-local — rewriter decoy-сайта, в репо не хранится\n",
        encoding="utf-8")
    helper = lab.put("usr/local/sbin/vpn-bot-warp-routes", "#!/bin/sh\n", 0o755)
    lab.helpers = [f"scripts/vpn-bot-warp-routes|{helper}|absent-ok"]
    (lab.repo / "deploy/vpn-bot.service").write_text("[Service]\n", encoding="utf-8")
    shipped = lab.put("etc/systemd/system/vpn-bot.service", "[Service]\n")
    wants = lab.unitdir / "multi-user.target.wants"
    wants.mkdir()
    (wants / "vpn-bot.service").symlink_to(shipped)
    (lab.unitdir / "sshd.service").symlink_to(shipped)
    orphan = lab.put("etc/systemd/system/gone.service.d/override.conf", "[Service]\n")
    lab.put("etc/systemd/system/here.service", "[Service]\n")
    kept = lab.put("etc/systemd/system/here.service.d/override.conf", "[Service]\n")
    proc = lab.run(PHASE1)
    assert proc.returncode == 0, proc.stdout
    warned = [ln for ln in proc.stdout.splitlines() if "[WARN]     " in ln]
    named = {ln.split()[1] for ln in warned}
    assert named == {str(stray), str(orphan), str(kept), str(lab.unitdir / "here.service")}, warned
    assert any(str(stray) in ln and "(mtime 20" in ln for ln in warned)
    assert any(str(orphan) in ln and "orphan drop-in for absent unit gone.service" in ln for ln in warned)
    assert not any(str(kept) in ln and "orphan" in ln for ln in warned)
    assert str(known) not in proc.stdout.split("--STDERR--")[1]
    assert len([ln for ln in lab.log("dpkg") if ln.startswith("dpkg -S")]) == 1, "one batched dpkg -S"


def test_the_unaccounted_report_section_and_conffile_state(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    lab.scan_dirs = [lab.h("etc/sysctl.d")]
    lab.put("etc/sysctl.d/50-stray.conf", "vm.swappiness = 1\n")
    conf = lab.put("etc/systemd/journald.conf", "[Journal]\nSystemMaxUse=500M\n")
    lab.flag("dpkg_owned", f"{conf}\n")
    _stub(lab.stub / "dpkg-query", f'echo " {conf} 0123456789abcdef0123456789abcdef"\n')
    proc = lab.run(f'CONFFILE_REPORT_PATHS=("{conf}")\n' + PHASE1 + "host_state_report_block\n")
    assert proc.returncode == 0, proc.stdout
    assert "Host files nothing accounts for (WARN, not fatal)" in proc.stdout
    assert re.search(r"WARN \S+/50-stray\.conf\s+20\d\d-", proc.stdout)
    assert f"conffile {conf} : MODIFIED somepkg conffile" in proc.stdout


# --------------------------------------------------------------------------- #
# 8. One restore mechanism: the relay's three paths, line for line
# --------------------------------------------------------------------------- #
# The relay rollback's restore loop as it stood before restore_host_paths replaced
# it — kept verbatim here as the reference implementation.
OLD_RELAY_RESTORE = r"""
old_restore() {
  local p
  for p in "$RELAY_HELPER" "$RELAY_SYSTEM_UNIT" "$RELAY_SYSCTL_FILE"; do
    if [[ -e "${STAGE}${p}" ]]; then
      cp -a "${STAGE}${p}" "$p"; echo "restore ${p}: rc=$?"
    else
      rm -f "$p"; echo "remove ${p} (absent before the deploy): rc=$?"
    fi
  done
}
"""


@pytest.mark.parametrize(
    "before",
    [("x", None, "x"), (None, None, None), ("x", "x", "x"), (None, "x", None)],
    ids=["mixed", "fresh", "all-present", "unit-only"],
)
def test_restore_host_paths_reproduces_the_old_relay_restore(tmp_path: Path, before: tuple) -> None:
    lab = Lab(tmp_path)
    results = {}
    for impl in ("old", "new"):
        base = tmp_path / impl
        paths = [base / "sbin/vpn-relay-apply", base / "etc/systemd/system/vpn-relay.service",
                 base / "etc/sysctl.d/90-vpn-relay.conf"]
        for p, content in zip(paths, before, strict=True):
            p.parent.mkdir(parents=True, exist_ok=True)
            if content is not None:
                p.write_text(f"{content}-{p.name}\n", encoding="utf-8")
        stage = base / "stage"
        stage.mkdir()
        assign = (f'STAGE="{stage}"; RELAY_HELPER="{paths[0]}"; RELAY_SYSTEM_UNIT="{paths[1]}"; '
                  f'RELAY_SYSCTL_FILE="{paths[2]}"\n')
        if impl == "old":
            stage_cmd = 'for p in "$RELAY_HELPER" "$RELAY_SYSTEM_UNIT" "$RELAY_SYSCTL_FILE"; do stage_path "$p"; done\n'
            restore = "old_restore\n"
        else:
            stage_cmd = 'stage_host_paths "$RELAY_HELPER" "$RELAY_SYSTEM_UNIT" "$RELAY_SYSCTL_FILE"\n'
            restore = "restore_host_paths\n"
        # The deploy: every file rewritten, and one that was absent created.
        mutate = "".join(f'echo deployed > "{p}"\n' for p in paths)
        proc = lab.run(OLD_RELAY_RESTORE + assign + stage_cmd + mutate + "echo ==REPORT==\n" + restore)
        assert proc.returncode == 0, proc.stdout
        report = proc.stdout.split("==REPORT==\n", 1)[1].split("--STDERR--")[0]
        tree = {str(p.relative_to(base)): (p.read_text() if p.exists() else None) for p in paths}
        results[impl] = (report.replace(str(base), "<B>"), tree)
    assert results["new"] == results["old"]
    assert len(results["new"][0].strip().splitlines()) == 3


# --------------------------------------------------------------------------- #
# 9. The acme hook
# --------------------------------------------------------------------------- #
HOOK_SYSTEMCTL = r"""
echo "systemctl $*" >> "$LOGS/hook.log"
[[ "$1" == cat ]] && exit 0
[[ -f "$SD/fail_systemctl_$1" ]] && exit 1
exit 0
"""


def _hook(tmp_path: Path, *args: str, fail: tuple[str, ...] = ()) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    stub, sd, logs, tls, hy = (tmp_path / n for n in ("stub", "sd", "logs", "tls", "hy"))
    for d in (stub, sd, logs, tls, hy):
        d.mkdir()
    (tls / "fullchain.pem").write_text("chain\n", encoding="utf-8")
    (tls / "privkey.pem").write_text("key\n", encoding="utf-8")
    (tls / "cert.pem").write_text("leaf\n", encoding="utf-8")
    _stub(stub / "systemctl", HOOK_SYSTEMCTL)
    for tool in ("chown", "chmod", "install", "mv"):
        _stub(stub / tool, (
            f'echo "{tool} $*" >> "$LOGS/hook.log"\n'
            f'[[ -f "$SD/fail_{tool}" ]] && exit 1\n'
            # fail only the copy whose destination matches "$SD/fail_{tool}_dst" (e.g. key.pem)
            f'[[ -f "$SD/fail_{tool}_dst" && "${{!#}}" == *"$(cat "$SD/fail_{tool}_dst")"* ]] && exit 1\n'
            "exit 0\n"))
    for f in fail:
        (sd / f).write_text("", encoding="utf-8")
    env = {"PATH": f"{stub}:{os.environ.get('PATH', '/usr/bin:/bin')}", "SD": str(sd), "LOGS": str(logs),
           "TLS_DIR": str(tls), "HYSTERIA_CERT": str(hy / "cert.pem"), "HYSTERIA_KEY": str(hy / "key.pem"),
           "LANG": "C.UTF-8"}
    proc = subprocess.run(["bash", str(HOOK), *args], env=env, capture_output=True, text=True, check=False)
    log = (logs / "hook.log").read_text(encoding="utf-8").splitlines() if (logs / "hook.log").exists() else []
    proc.stdout = proc.stdout.replace(str(tmp_path), "<T>")
    return proc, [ln.replace(str(tmp_path), "<T>") for ln in log]


def test_hook_dry_run_prints_exactly_the_hosts_tls_ownership(tmp_path: Path) -> None:
    proc, log = _hook(tmp_path, "--dry-run")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    would = [ln.split("DRY-RUN would run: ", 1)[1] for ln in proc.stdout.splitlines() if "DRY-RUN would run: " in ln]
    assert would == [
        "chown root:root <T>/tls",
        "chmod 0755 <T>/tls",
        "chown root:vpn-bot <T>/tls/fullchain.pem",
        "chmod 0640 <T>/tls/fullchain.pem",
        "chown root:vpn-bot <T>/tls/privkey.pem",
        "chmod 0640 <T>/tls/privkey.pem",
        "install -o hysteria -g hysteria -m 0644 <T>/tls/fullchain.pem <T>/hy/cert.pem.acme-new",
        "install -o hysteria -g hysteria -m 0600 <T>/tls/privkey.pem <T>/hy/key.pem.acme-new",
        "mv -f -- <T>/hy/cert.pem.acme-new <T>/hy/cert.pem",
        "mv -f -- <T>/hy/key.pem.acme-new <T>/hy/key.pem",
        "systemctl reload -- nginx",
        "systemctl restart -- hysteria-server",
        "systemctl try-restart -- vpn-bot-subscription",
    ]
    assert "cert.pem" not in " ".join(w for w in would if "/tls/" in w and "install" not in w)
    assert [ln for ln in log if not ln.startswith("systemctl cat")] == [], "a dry run changes nothing"


def test_hook_keeps_going_when_one_step_fails(tmp_path: Path) -> None:
    """The hand-written predecessor's `|| rc=1` per step: a failed nginx reload must not
    leave hysteria or the subscription endpoint on the old certificate."""
    proc, log = _hook(tmp_path, fail=("fail_systemctl_reload",))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    acted = [ln for ln in log if not ln.startswith("systemctl cat")]
    assert acted[-3:] == [
        "systemctl reload -- nginx",
        "systemctl restart -- hysteria-server",
        "systemctl try-restart -- vpn-bot-subscription",
    ]
    assert "FAILED: reload:nginx" in proc.stdout and "every other step was still attempted" in proc.stdout


@pytest.mark.parametrize("failing", ["cert.pem.acme-new", "key.pem.acme-new"])
def test_a_failed_hysteria_copy_keeps_the_old_pair_and_skips_only_its_restart(tmp_path: Path, failing: str) -> None:
    """A new cert next to the old key would stop the healthy daemon on restart (and at
    the next boot): the pair is staged and moved together, and hysteria-server is not
    restarted unless both landed. The other consumers are still refreshed."""
    _hook(tmp_path)  # builds the stubs and the TLS/hysteria dirs; re-run with the failure armed
    sd = tmp_path / "sd"
    (sd / "fail_install_dst").write_text(failing, encoding="utf-8")
    (tmp_path / "logs" / "hook.log").unlink()
    env = {"PATH": f"{tmp_path / 'stub'}:{os.environ.get('PATH', '/usr/bin:/bin')}", "SD": str(sd),
           "LOGS": str(tmp_path / "logs"), "TLS_DIR": str(tmp_path / "tls"),
           "HYSTERIA_CERT": str(tmp_path / "hy" / "cert.pem"), "HYSTERIA_KEY": str(tmp_path / "hy" / "key.pem"),
           "LANG": "C.UTF-8"}
    proc = subprocess.run(["bash", str(HOOK)], env=env, capture_output=True, text=True, check=False)
    log = (tmp_path / "logs" / "hook.log").read_text(encoding="utf-8").splitlines()
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert not any(ln.startswith("mv ") for ln in log), "nothing is moved into place"
    assert "systemctl reload -- nginx" in log
    assert "systemctl try-restart -- vpn-bot-subscription" in log
    assert not any("restart -- hysteria-server" in ln and "try" not in ln for ln in log)
    assert "NOT restarting hysteria-server: its certificate copy failed" in proc.stdout


def test_hook_never_starts_a_stopped_subscription_endpoint(tmp_path: Path) -> None:
    proc, log = _hook(tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "systemctl restart -- hysteria-server" in log
    assert "systemctl try-restart -- vpn-bot-subscription" in log
    assert not any(ln.startswith("systemctl restart -- vpn-bot-subscription") for ln in log)


def test_hook_refuses_before_touching_anything_without_the_renewed_files(tmp_path: Path) -> None:
    tls = tmp_path / "tls"
    _hook(tmp_path)  # creates the files; now remove one and run again
    (tls / "privkey.pem").unlink()
    env = {"PATH": f"{tmp_path / 'stub'}:{os.environ.get('PATH', '/usr/bin:/bin')}", "SD": str(tmp_path / "sd"),
           "LOGS": str(tmp_path / "logs2"), "TLS_DIR": str(tls), "LANG": "C.UTF-8"}
    (tmp_path / "logs2").mkdir()
    proc = subprocess.run(["bash", str(HOOK)], env=env, capture_output=True, text=True, check=False)
    assert proc.returncode == 1
    assert "FATAL" in proc.stdout
    assert not (tmp_path / "logs2" / "hook.log").exists()


def test_hook_has_no_errexit() -> None:
    """`set -e` would end the hook at the first failed step (the bug this replaces)."""
    code = [ln for ln in _read(HOOK).splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert "set -uo pipefail" in code
    assert not any(re.match(r"\s*set\s+-[a-z]*e", ln) for ln in code)


# --------------------------------------------------------------------------- #
# 10. plain, resolved, a retired sshd drop-in
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host_has", ["absent", "older", "same"])
def test_plain_is_installed_verbatim_and_nothing_is_reloaded(tmp_path: Path, host_has: str) -> None:
    lab = Lab(tmp_path)
    dst = lab.add("plain", "etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 8.8.8.8\n\n")
    if host_has == "older":
        lab.put("etc/resolv.conf", "nameserver 127.0.0.53\n")
    elif host_has == "same":
        lab.put("etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 8.8.8.8\n\n")
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert "plain file — installed verbatim, nothing to validate" in proc.stdout or host_has == "same"
    assert _read(dst) == "nameserver 1.1.1.1\nnameserver 8.8.8.8\n\n"
    assert oct(dst.stat().st_mode & 0o777) == oct(0o644)
    assert lab.mutating_systemctl() == [] and lab.log("sysctl") == [] and lab.log("getent") == []
    if host_has == "same":
        assert "all in sync, nothing changed" in proc.stdout
    else:
        assert "installed verbatim (nothing reloaded)" in proc.stdout


def test_an_empty_plain_file_is_installed(tmp_path: Path) -> None:
    """The cloud-init marker: an empty file is a file."""
    lab = Lab(tmp_path)
    dst = lab.add("plain", "etc/cloud/cloud-init.disabled", "")
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert dst.is_file() and dst.stat().st_size == 0


def test_a_failed_reload_of_resolved_rolls_back_too(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.add("resolved", "etc/systemd/resolved.conf.d/10-vpn-bot.conf", "[Resolve]\nDNS=1.1.1.1\n")
    lab.flag("fail_try-reload-or-restart")
    proc = lab.run(BOTH)
    assert proc.returncode == 42 and "ROLLBACK_CALLED" in proc.stdout, proc.stdout
    assert "try-reload-or-restart systemd-resolved failed after the drop-in change" in proc.stdout
    assert not dst.exists(), "it did not exist before the deploy"
    assert lab.log("getent") == []


SSHD_DROPIN_YES = "PasswordAuthentication yes\n"


def test_a_retired_sshd_dropin_is_removed_and_ssh_reloaded(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.retire("etc/ssh/sshd_config.d/50-cloud-init.conf")
    lab.put("etc/ssh/sshd_config.d/50-cloud-init.conf", SSHD_DROPIN_YES)
    lab.ssh_up("22")
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert not dst.exists()
    assert any(ln.startswith("sshd -t") for ln in lab.log("sshd"))
    assert lab.mutating_systemctl() == ["systemctl reload ssh.service"]
    assert "ssh.service active, listening on :22" in proc.stdout


def test_a_retired_sshd_dropin_comes_back_with_a_reload_on_rollback(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.retire("etc/ssh/sshd_config.d/50-cloud-init.conf")
    lab.put("etc/ssh/sshd_config.d/50-cloud-init.conf", SSHD_DROPIN_YES)
    lab.flag("ssh.service.active", "active")   # active, but nothing listens: the check fails
    proc = lab.run(BOTH)
    assert proc.returncode == 42 and "ROLLBACK_CALLED" in proc.stdout, proc.stdout
    assert _read(dst) == SSHD_DROPIN_YES
    assert "sshd -t on the restored ssh config: ok" in proc.stdout
    assert lab.mutating_systemctl()[-1] == "systemctl reload ssh.service"


def test_a_retired_sudoers_file_is_just_removed(tmp_path: Path) -> None:
    lab = Lab(tmp_path)
    dst = lab.retire("etc/sudoers.d/90-cloud-init-users")
    lab.put("etc/sudoers.d/90-cloud-init-users", "ubuntu ALL=(ALL) NOPASSWD:ALL\n", 0o440)
    proc = lab.run(BOTH)
    assert proc.returncode == 0, proc.stdout
    assert not dst.exists() and lab.mutating_systemctl() == [] and lab.log("sshd") == []


def test_the_real_registry_carries_the_cloud_init_and_dns_entries() -> None:
    reg = {(e[1], e[5]): e for e in _registry()}
    for role in ("main", "relay"):
        assert reg["/etc/cloud/cloud-init.disabled", role][2:5] == ["0644", "root:root", "plain"]
        assert reg["/etc/ssh/sshd_config.d/50-cloud-init.conf", role][4] == "absent"
        assert reg["/etc/sudoers.d/90-cloud-init-users", role][4] == "absent"
        for unit in ("vpn-bot-host-check.service", "vpn-bot-host-check.timer"):
            assert reg[f"/etc/systemd/system/{unit}", role][:5] == [
                f"deploy/host/systemd/{unit}", f"/etc/systemd/system/{unit}", "0644", "root:root", "unit"]
    assert reg["/etc/resolv.conf", "main"][:5] == ["deploy/host/dns/resolv.conf", "/etc/resolv.conf", "0644", "root:root", "plain"]
    assert ("/etc/resolv.conf", "relay") not in reg
    assert reg["/etc/systemd/resolved.conf.d/10-vpn-bot.conf", "main"][:5] == [
        "deploy/host/resolved/10-vpn-bot.conf", "/etc/systemd/resolved.conf.d/10-vpn-bot.conf", "0644", "root:root", "resolved"]
    assert (ROOT / "deploy/host/cloud/cloud-init.disabled").read_bytes() == b""


def test_the_resolved_dropin_sets_exactly_the_hosts_upstreams() -> None:
    lines = [ln for ln in _read(ROOT / "deploy/host/resolved/10-vpn-bot.conf").splitlines()
             if ln.strip() and not ln.lstrip().startswith("#")]
    assert lines == ["[Resolve]", "DNS=1.1.1.1 8.8.8.8", "FallbackDNS=1.0.0.1 8.8.4.4"]


def test_the_resolved_conffile_is_reported_never_written() -> None:
    text = _read(DEPLOY_SH)
    assert re.search(r"^CONFFILE_REPORT_PATHS=\(.*/etc/systemd/resolved\.conf.*\)$", text, re.M)
    assert not [e for e in _registry() if e[1] == "/etc/systemd/resolved.conf"]
