"""MANAGED_HOST_FILES class ``pristine``: a file goes back to the PACKAGE DEFAULT.

A host file whose hand edit only duplicates a repo drop-in (journald.conf's
SystemMaxUse, resolved.conf's DNS) or is a provider's leftover behind our drop-in
(sshd_config's active ``PasswordAuthentication yes`` / ``PermitRootLogin yes``) is
restored by the deploy itself — never to content written in the repo, only to a copy
the package manager's own md5 vouches for, and only after Phase 1 has proven that the
effective configuration does not change. Pinned here, deploy.sh driven through the
DEPLOY_SELFTEST=1 seam with every host command stubbed (dpkg-query, dpkg-deb, apt-get,
sshd, systemctl, getent, ...) and the REAL scripts/vpn-bot-host-check judging the same
fake host:

1. Where the copy comes from: the apt cache (an epoch's ":" is "%3a" in the file
   name), else ``apt-get download`` into the deploy's private work directory; neither
   -> WARN "cannot restore", the file untouched, the deploy goes on. A copy whose md5
   is not dpkg's -> WARN. ucf: the template must carry dpkg's md5 and ucf must register
   the destination; what ucf registered itself (the template as the maintainer script
   rendered it from debconf answers) is reported, not restored.
2. The effect proof, before any mutation: a hand edit that duplicates a drop-in is
   restored and nothing effective changes; a key only the hand edit carries stops
   Phase 1 and is named; sshd_config with ``yes`` lines after the Include is restored
   WITHOUT ALLOW_SSH_CHANGE and ``sshd -T`` stays the same; a different ``sshd -T`` or
   one that does not run stops Phase 1. The sshd -T proof sees the drop-in directory
   as Phase 2 leaves it (the new-host case: our drop-in installed, cloud-init's removed).
3. Phase 2: atomic install, the family's post-action; its failure rolls back, and the
   rollback repeats the post-action on the restored file. Already the package default
   -> synced, not a single mutation.
4. vpn-bot-host-check: a modified conffile with a pristine copy is PENDING in
   --pre-install, WARN without one; --pristine needs --pre-install and a registry entry.
5. Static: every pristine entry of the real registry names dpkg:<package> or
   ucf:<template>, and its destination is that package's conffile / what ucf registers.

The knobs: every driver pins ALLOW_SSH_CHANGE=0 and PHASE1_ONLY=0, and
tests/test_deploy_knob_isolation.py runs the sshd and the FAIL case again in a child
pytest that starts with ALLOW_SSH_CHANGE=1 / PHASE1_ONLY=1 exported (#325).
deploy.sh runs this suite AS ROOT on the production host in Phase 1: every path is
under tmp_path, MH_SELFTEST_ROOT fences the writers, HOST_CHECK_ROOT the checker.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from tests.test_deploy_host_state import GETENT, INSTALL, OWNER
from tests.test_host_check import CHECK, LOGROTATE, SYSCTL, SYSTEMD_ANALYZE

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

pytestmark = pytest.mark.timeout(60)


def _md5(data: str) -> str:
    return hashlib.md5(data.encode()).hexdigest()  # noqa: S324 — dpkg's own digest


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


# --------------------------------------------------------------------------- #
# Stubs that serve BOTH deploy.sh (real paths under the fake root) and the host
# check (--root: logical paths). $HC_ROOT is the fake root.
# --------------------------------------------------------------------------- #
SYSTEMCTL = r"""
echo "systemctl $*" >> "$LOGS/systemctl.log"
verb="$1"
if [[ "$verb" == show ]]; then
  shift; props=(); unit=""
  while (( $# )); do case "$1" in -p) props+=("$2"); shift 2 ;; --) unit="$2"; shift 2 ;; --value) shift ;; *) unit="$1"; shift ;; esac; done
  for p in "${props[@]}"; do
    if [[ -f "$SD/units/$unit" ]]; then grep -E "^${p}=" "$SD/units/$unit" || true
    elif [[ "$p" == LoadState ]]; then echo "LoadState=not-found"; fi
  done
  exit 0
fi
unit="${!#}"
case "$verb" in
  is-active)  s="$(cat "$SD/$unit.active" 2>/dev/null || echo inactive)"; echo "$s"; [[ "$s" == active ]]; exit ;;
  is-enabled) s="$(cat "$SD/$unit.enabled" 2>/dev/null || echo disabled)"; echo "$s"; [[ "$s" == enabled ]]; exit ;;
  cat)        exit 1 ;;
esac
[[ -f "$SD/fail_${verb}" || -f "$SD/fail_${verb}_${unit}" ]] && exit 1
case "$verb" in
  start|restart|reload|try-reload-or-restart) echo active > "$SD/$unit.active" ;;
  stop) echo inactive > "$SD/$unit.active" ;;
esac
exit 0
"""

# sshd -t / -T over the files themselves: Include expanded in place (relative to
# /etc/ssh; an /etc path is the host check's logical one and is read under $HC_ROOT,
# never on the machine running the suite), the rest of a file after Match left out,
# first value wins, built-in defaults after, sorted like `sshd -T`.
SSHD = r"""
echo "sshd $*" >> "$LOGS/sshd.log"
cfg=""; mode=""
while (( $# )); do case "$1" in -t) mode=t ;; -T) mode=T ;; -f) cfg="$2"; shift ;; esac; shift; done
if [[ "$mode" == T && -f "$SD/sshd_T_fail" ]]; then echo "Missing privilege separation directory: /run/sshd" >&2; exit 255; fi
resolve() {
  local a="$1"
  [[ "$a" == /* ]] || a="/etc/ssh/$a"
  if [[ "$a" == /etc/* ]]; then a="${HC_ROOT:?}$a"; fi
  compgen -G "$a" | LC_ALL=C sort
}
walk() {
  local f="$1" line kw rest g x
  local -a args=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    kw="${line%%[[:space:]=]*}"; rest="${line:${#kw}}"; rest="${rest#"${rest%%[![:space:]=]*}"}"
    case "${kw,,}" in
      include) read -r -a args <<< "$rest"
               for g in "${args[@]}"; do while IFS= read -r x; do [[ -f "$x" ]] && walk "$x"; done < <(resolve "$g"); done ;;
      match) return 0 ;;
      *) printf '%s %s\n' "${kw,,}" "$rest" ;;
    esac
  done < "$f"
}
body="$(walk "$cfg")"
if grep -qi '^badoption' <<< "$body"; then echo "$cfg: line 1: Bad configuration option: BadOption" >&2; exit 255; fi
[[ "$mode" == T ]] || exit 0
{ printf '%s\n' "$body"
  printf '%s\n' "port 22" "permitrootlogin without-password" "passwordauthentication yes" \
    "kbdinteractiveauthentication yes" "pubkeyauthentication yes" "usepam no" "x11forwarding no" "printmotd yes"
} | awk 'NF { k = $1; if (k in seen) next; seen[k] = 1; v = $0; sub(/^[^ ]+ /, "", v); gsub(/[ \t]+/, " ", v)
             if (v ~ /^[A-Za-z-]+$/) v = tolower(v); if (v == "prohibit-password") v = "without-password"; print k " " v }' \
  | LC_ALL=C sort
"""

DPKG = r"""
echo "dpkg $*" >> "$LOGS/dpkg.log"
[[ "$1" == -S ]] || { echo "REFUSED: dpkg $*" >&2; exit 99; }
shift; rc=1
for p in "$@"; do
  l="$p"; [[ -n "${HC_ROOT:-}" ]] && l="${p#"$HC_ROOT"}"
  pkg="$(awk -F': ' -v p="$l" '$2 == p { print $1 }' "$SD/dpkg_owned" 2>/dev/null | awk 'NR == 1')"
  if [[ -n "$pkg" ]]; then echo "$pkg: $p"; rc=0; else echo "dpkg-query: no path found matching pattern $p" >&2; fi
done
exit $rc
"""

# Packages in $SD/dpkg_db ("pkg|status|version|arch"), their conffiles in
# $SD/conffiles_<pkg> (" /logical/path md5"), their md5sums in $SD/md5sums_<pkg>.
# The host check asks for every package (logical paths); deploy.sh for one (real).
DPKG_QUERY = r"""
echo "dpkg-query $*" >> "$LOGS/dpkg-query.log"
case "$1" in
  --control-path|-c) [[ -f "$SD/md5sums_$2" ]] && echo "$SD/md5sums_$2"; exit 0 ;;
  -W) ;;
  *) echo "REFUSED: dpkg-query $*" >&2; exit 99 ;;
esac
fmt="${2#-f=}"; pkg="${3:-}"
if [[ -z "$pkg" ]]; then
  for f in "$SD"/conffiles_*; do [[ -f "$f" ]] || continue; echo "${f##*/conffiles_}"; cat "$f"; done
  exit 0
fi
line="$(grep "^${pkg}|" "$SD/dpkg_db" 2>/dev/null)" || { echo "dpkg-query: no packages found matching $pkg" >&2; exit 1; }
IFS='|' read -r _ st ver arch <<< "$line"
case "$fmt" in
  *Conffiles*) [[ -f "$SD/conffiles_$pkg" ]] && awk -v r="${HC_ROOT:-}" '{ print " " r $1 " " $2 (NF > 2 ? " " $3 : "") }' "$SD/conffiles_$pkg" ;;
  *Status*)    printf '%s|%s|%s\n' "$st" "$ver" "$arch" ;;
esac
exit 0
"""

DPKG_DEB = r"""
echo "dpkg-deb $*" >> "$LOGS/dpkg-deb.log"
[[ "$1" == --fsys-tarfile ]] || { echo "REFUSED: dpkg-deb $*" >&2; exit 99; }
cat "$2"
"""

APT_GET = r"""
echo "apt-get $* (cwd $PWD)" >> "$LOGS/apt-get.log"
[[ "$1" == download ]] || { echo "REFUSED: apt-get $*" >&2; exit 99; }
pkg="${2%%=*}"; ver="${2#*=}"
for f in "$SD/apt/${pkg}_${ver//:/%3a}_"*.deb; do [[ -f "$f" ]] && cp "$f" . && exit 0; done
echo "E: Can't find a source to download version '$ver' of '$pkg'" >&2
exit 100
"""

SS = r"""
echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port"
if [[ -f "$SD/listen" ]]; then while read -r p; do echo "LISTEN 0 128 0.0.0.0:$p 0.0.0.0:*"; done < "$SD/listen"; fi
exit 0
"""

STOCK_JOURNALD = "#  This file is part of systemd.\n[Journal]\n#Storage=auto\n#SystemMaxUse=\n"
STOCK_RESOLVED = "#  This file is part of systemd.\n[Resolve]\n#DNS=\n#FallbackDNS=\n"
JOURNALD_DROPIN = "[Journal]\nSystemMaxUse=500M\n"
RESOLVED_DROPIN = "[Resolve]\nDNS=1.1.1.1 8.8.8.8\nFallbackDNS=1.0.0.1 8.8.4.4\n"
KEY_ONLY = (ROOT / "deploy/host/ssh/00-root-key-only.conf").read_text(encoding="utf-8")


def template(include: str) -> str:
    """openssh-server's /usr/share/openssh/sshd_config, cut down: the Include first,
    the auth keywords commented out, a few active lines."""
    return (f"Include {include}/*.conf\n\n#PermitRootLogin prohibit-password\n#PasswordAuthentication yes\n"
            "KbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding yes\nPrintMotd no\n"
            "AcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n")


def provider_edit(tpl: str) -> str:
    """What the provider image leaves: both auth lines uncommented, AFTER the Include."""
    return (tpl.replace("#PermitRootLogin prohibit-password", "PermitRootLogin yes")
               .replace("#PasswordAuthentication yes", "PasswordAuthentication yes"))


class PLab:
    """A fake host under tmp/root, a checkout under tmp/repo, one set of stubs."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.repo = tmp / "repo"
        self.stub = tmp / "stub"
        self.sd = tmp / "sd"
        self.logs = tmp / "logs"
        self.stage = tmp / "stage"
        self.archives = tmp / "archives"
        self.hashfile = tmp / "ucf-hashfile"
        self.state = tmp / "hc" / "last.json"
        for d in (self.root, self.repo, self.stub, self.sd / "units", self.sd / "live", self.sd / "apt",
                  self.logs, self.stage, self.archives, self.state.parent):
            d.mkdir(parents=True, exist_ok=True)
        (self.root / "etc/systemd/system").mkdir(parents=True)
        (self.root / "etc/ssh/sshd_config.d").mkdir(parents=True)
        self.dropdir_logical = "/etc/ssh/sshd_config.d"
        self.env = tmp / "dot.env"
        self.env.write_text("BOT_TOKEN=x\n", encoding="utf-8")
        self.repo_file("deploy/host/invariants.list", "# none\n")
        self.entries: list[str] = []
        self.packages: dict[str, tuple[str, str]] = {}
        for name in ("dpkg_db", "dpkg_owned"):
            (self.sd / name).write_text("", encoding="utf-8")
        for name, body in (("systemctl", SYSTEMCTL), ("sshd", SSHD), ("dpkg", DPKG), ("dpkg-query", DPKG_QUERY),
                           ("dpkg-deb", DPKG_DEB), ("apt-get", APT_GET), ("getent", GETENT), ("ss", SS),
                           ("install", INSTALL), ("systemd-analyze", SYSTEMD_ANALYZE), ("sysctl", SYSCTL),
                           ("logrotate", LOGROTATE), ("sleep", "exit 0\n")):
            _stub(self.stub / name, body)

    # --- fixtures -----------------------------------------------------------
    def h(self, rel: str) -> Path:
        return self.root / rel

    def put(self, rel: str, content: str, mode: int = 0o644) -> Path:
        p = self.h(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        p.chmod(mode)
        return p

    def repo_file(self, rel: str, content: str) -> Path:
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def add(self, cls: str, rel: str, content: str, *, installed: bool = True, role: str = "main") -> Path:
        src = f"deploy/host/{cls}/{Path(rel).name}"
        self.repo_file(src, content)
        if installed:
            self.put(rel, content)
        self.entries.append(f"{src}|{self.h(rel)}|0644|{OWNER}|{cls}|{role}")
        return self.h(rel)

    def retire(self, rel: str, role: str = "main") -> None:
        self.entries.append(f"-|{self.h(rel)}|-|-|absent|{role}")

    def pristine(self, src: str, rel: str, role: str = "main") -> Path:
        self.entries.append(f"{src}|{self.h(rel)}|0644|{OWNER}|pristine|{role}")
        return self.h(rel)

    def package(self, pkg: str, version: str, conffiles: dict[str, str], *, recorded: dict[str, str] | None = None,
                arch: str = "amd64", status: str = "ii ") -> Path:
        """An installed package, its conffiles (logical path -> shipped content) as dpkg
        records them, and its .deb (a tar stream: the dpkg-deb stub only cats it)."""
        with (self.sd / "dpkg_db").open("a", encoding="utf-8") as f:
            f.write(f"{pkg}|{status}|{version}|{arch}\n")
        recorded = recorded or {}
        (self.sd / f"conffiles_{pkg}").write_text(
            "".join(f" {p} {recorded.get(p, _md5(c))}\n" for p, c in conffiles.items()), encoding="utf-8")
        with (self.sd / "dpkg_owned").open("a", encoding="utf-8") as f:
            f.write("".join(f"{pkg}: {p}\n" for p in conffiles))
        deb = self.tmp / "debs" / f"{pkg}_{version.replace(':', '%3a')}_{arch}.deb"
        deb.parent.mkdir(exist_ok=True)
        with tarfile.open(deb, "w") as tf:
            for p, content in conffiles.items():
                data = content.encode()
                info = tarfile.TarInfo("./" + str(self.root / p.lstrip("/")).lstrip("/"))
                info.size = len(data)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(data))
        self.packages[pkg] = (version, arch)
        return deb

    def cache(self, deb: Path) -> None:
        shutil.copy(deb, self.archives / deb.name)

    def downloadable(self, deb: Path) -> None:
        shutil.copy(deb, self.sd / "apt" / deb.name)

    def ucf(self, tpl_text: str, *, registered: str | None, recorded: str | None = None) -> str:
        """openssh-server's template, its md5 in the package's md5sums, and the ucf
        hashfile (registered = the md5 ucf holds for sshd_config; None = no line)."""
        tpl = self.put("usr/share/openssh/sshd_config", tpl_text)
        with (self.sd / "dpkg_owned").open("a", encoding="utf-8") as f:
            f.write("openssh-server: /usr/share/openssh/sshd_config\n")
        (self.sd / "md5sums_openssh-server").write_text(
            f"{recorded or _md5(tpl_text)}  {str(tpl).lstrip('/')}\n", encoding="utf-8")
        lines = "0123456789abcdef0123456789abcdef  /etc/default/other\n"
        if registered is not None:
            lines += f"{registered}  {self.h('etc/ssh/sshd_config')}\n"
        self.hashfile.write_text(lines, encoding="utf-8")
        return f"ucf:{tpl}"

    def flag(self, name: str, value: str = "") -> None:
        (self.sd / name).write_text(value, encoding="utf-8")

    def ssh_up(self) -> None:
        self.flag("ssh.service.active", "active")
        self.flag("listen", "22\n")

    # --- running ----------------------------------------------------------
    def run(self, body: str, **knobs: str) -> subprocess.CompletedProcess[str]:
        entries = "\n".join(f'  "{e}"' for e in self.entries)
        knob_lines = "".join(f'{k}="{v}"\n' for k, v in knobs.items())
        r = self.root
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -uo pipefail\n"
            "export DEPLOY_SELFTEST=1\n"
            f'export PATH="{self.stub}:$PATH" SD="{self.sd}" LOGS="{self.logs}" HC_ROOT="{r}"\n'
            f'source "{DEPLOY_SH}"\n'
            'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""\n'
            f'STAGE="{self.stage}"; APP_DIR="{self.repo}"; ENV_FILE="{self.env}"\n'
            f'MH_SELFTEST_ROOT="{self.tmp}"\n'
            f'SYSTEMD_UNIT_DIR="{r}/etc/systemd/system"; PROC_SYS="{self.tmp}/proc"; SSHD_CONFIG="{r}/etc/ssh/sshd_config"\n'
            "SSH_LISTEN_WAIT=2; RESOLVED_PROBE_WAIT=2\n"
            f'ABSENT_REF_PATHS=("{r}/etc/crontab" "{r}/etc/systemd/system")\n'
            "UNMANAGED_SCAN_DIRS=()\n"
            f'CONFFILE_REPORT_PATHS=("{r}/etc/systemd/journald.conf" "{r}/etc/systemd/resolved.conf")\n'
            f'APT_ARCHIVES="{self.archives}"; UCF_HASHFILE="{self.hashfile}"\n'
            f'HOST_CHECK_BIN="{CHECK}"; HOST_CHECK_ROOT="{r}"; HOST_CHECK_STATE="{self.state}"\n'
            # Pinned, never inherited (deploy.sh runs this suite with the operator's knobs).
            "ALLOW_SSH_CHANGE=0; ALLOW_UNIT_DRIFT=0; PHASE1_ONLY=0; NODE_ROLE=main\n"
            f"MANAGED_HOST_FILES=(\n{entries}\n)\n"
            "OUT_OF_REPO_HELPERS=()\n"
            'ssh_banner_ok() { [[ ! -f "$SD/no_banner_$1" ]]; }\n'
            'rollback() { set +e; echo "ROLLBACK_CALLED"; host_files_rollback; exit 42; }\n'
            'relay_rollback() { set +e; echo "RELAY_ROLLBACK_CALLED"; host_files_rollback; exit 43; }\n'
            'echo "KNOBS ALLOW_SSH_CHANGE=${ALLOW_SSH_CHANGE} PHASE1_ONLY=${PHASE1_ONLY}"\n'
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

    def tree(self) -> dict[str, tuple[int, bytes]]:
        out = {}
        for p in sorted(self.root.rglob("*")):
            if p.is_file():
                out[str(p.relative_to(self.root))] = (p.stat().st_mtime_ns, p.read_bytes())
        return out


STATE_ONLY = 'host_state_phase1 "$APP_DIR"; echo PHASE1-OK\n'
PHASE1 = 'host_state_phase1 "$APP_DIR"; host_invariants_phase1 "$APP_DIR"; echo PHASE1-OK\nhost_state_report_block\nhost_invariants_report_block\n'
INSTALL_ONLY = (
    'readarray -t _p < <(managed_host_stage_paths); stage_host_paths "${_p[@]}"\n'
    'install_managed_host_files; echo PHASE2-OK\necho "SUMMARY-LINE: $(host_files_summary)"\n'
)
PHASE2 = INSTALL_ONLY.replace("echo PHASE2-OK", 'host_invariants_phase2 "$APP_DIR"; echo PHASE2-OK')


def _journald_lab(tmp_path: Path, hand: str, *, version: str = "255.4-1ubuntu8.18") -> tuple[PLab, Path, Path]:
    """main today: the drop-in carries SystemMaxUse=500M, journald.conf a hand edit."""
    lab = PLab(tmp_path)
    lab.add("journald", "etc/systemd/journald.conf.d/10-vpn-bot.conf", JOURNALD_DROPIN)
    conf = lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
    lab.put("etc/systemd/journald.conf", hand)
    deb = lab.package("systemd", version, {"/etc/systemd/journald.conf": STOCK_JOURNALD})
    return lab, conf, deb


# --------------------------------------------------------------------------- #
# 1. Where the package default comes from
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("source", ["cache", "download"])
def test_a_hand_edit_that_duplicates_the_dropin_is_restored(tmp_path: Path, source: str) -> None:
    """journald.conf carries SystemMaxUse=500M by hand — the drop-in's value. With an
    epoch in the version the .deb name carries "%3a"."""
    lab, conf, deb = _journald_lab(tmp_path, "[Journal]\nSystemMaxUse=500M\n", version="1:255.4-1ubuntu8.18")
    assert deb.name == "systemd_1%3a255.4-1ubuntu8.18_amd64.deb"
    lab.cache(deb) if source == "cache" else lab.downloadable(deb)
    before = lab.tree()
    proc = lab.run(PHASE1)
    assert proc.returncode == 0 and "PHASE1-OK" in proc.stdout, proc.stdout
    assert lab.tree() == before, "Phase 1 changes nothing on the host"
    if source == "cache":
        assert f"from {lab.archives}/{deb.name} (md5 {_md5(STOCK_JOURNALD)} = dpkg's)" in proc.stdout
        assert lab.log("apt-get") == []
    else:
        (call,) = lab.log("apt-get")
        assert call.startswith("apt-get download systemd=1:255.4-1ubuntu8.18 (cwd ")
        cwd = call.split("(cwd ", 1)[1].rstrip(")")
        assert cwd.endswith("/pristine-apt") and not cwd.startswith(str(lab.root)), "the deploy's private work dir"
        assert "from apt-get download (md5" in proc.stdout
    assert re.search(r"pristine\s+drift\s+\S+/etc/systemd/journald\.conf", proc.stdout)
    proof = re.compile(r"OK\s+OK\s+pristine /etc/systemd/journald\.conf — restoring the package default \(dpkg:systemd\) "
                       r"changes nothing effective: \d+ journald key\(s\) compared with and without it")
    log_part, report = proc.stdout.split("PHASE1-OK", 1)
    assert proof.search(log_part) and proof.search(report), "the effect proof is in the log and in the report"
    assert "MODIFIED systemd conffile — local edits; Phase 2 restores the package default (class pristine)" in report
    assert re.search(r"INFO PENDING\s+conffile systemd — locally modified systemd conffile — Phase 2 restores the package default",
                     report), report
    assert "WARN WARN     conffile" not in report

    proc = lab.run(PHASE1 + PHASE2)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert conf.read_text(encoding="utf-8") == STOCK_JOURNALD
    assert oct(conf.stat().st_mode & 0o777) == "0o644"
    assert lab.mutating_systemctl() == ["systemctl restart systemd-journald"]
    assert "SUMMARY-LINE: 0 installed, 0 removed, 0 mode/owner fixed, 1 restored to the package default" in proc.stdout
    assert not list(conf.parent.glob(".journald.conf.vpn-bot-pristine.*")), "no temporary file left behind"
    state = json.loads(lab.state.read_text(encoding="utf-8"))
    assert state["mode"] == "installed" and state["counts"]["mismatch"] == 0
    assert not [r for r in state["rows"] if r["family"] == "conffile"], "the conffile WARN is gone by itself"


def test_a_version_found_nowhere_is_a_warn_and_the_file_is_untouched(tmp_path: Path) -> None:
    lab, conf, _ = _journald_lab(tmp_path, "[Journal]\nSystemMaxUse=500M\n")
    proc = lab.run(PHASE1 + PHASE2)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    warn = ("cannot restore: systemd 255.4-1ubuntu8.18 is neither in "
            f"{lab.archives} nor downloadable (apt-get download exit 100: "
            "E: Can't find a source to download version '255.4-1ubuntu8.18' of 'systemd')")
    assert re.search(r"\[WARN\]\s+pristine\s+cannot-restore\s+\S+journald\.conf — " + re.escape(warn), proc.stdout), proc.stdout
    assert conf.read_text(encoding="utf-8") == "[Journal]\nSystemMaxUse=500M\n"
    assert lab.mutating_systemctl() == []
    assert "SUMMARY-LINE: all in sync, nothing changed" in proc.stdout
    assert "its class pristine entry cannot restore it now" in proc.stdout, "the conffile stays a WARN"


@pytest.mark.parametrize(("status", "restored"), [("hi ", True), ("ri ", True), ("rc ", False), ("un ", False)])
def test_a_held_package_is_still_installed(tmp_path: Path, status: str, restored: bool) -> None:
    """${db:Status-Abbrev}: the FIRST letter is the selection (h = hold, r = remove), the
    second the state — `hi` is installed. Only that second letter decides."""
    lab = PLab(tmp_path)
    conf = lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
    lab.put("etc/systemd/journald.conf", "[Journal]\n#SystemMaxUse=\n# edited\n")
    lab.cache(lab.package("systemd", "255.4-1ubuntu8.18", {"/etc/systemd/journald.conf": STOCK_JOURNALD}, status=status))
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    if restored:
        assert conf.read_text(encoding="utf-8") == STOCK_JOURNALD
    else:
        assert f"cannot restore: package systemd is not installed (dpkg-query: '{status}')" in proc.stdout
        assert conf.read_text(encoding="utf-8") == "[Journal]\n#SystemMaxUse=\n# edited\n"


def test_a_copy_whose_md5_is_not_dpkgs_is_a_warn(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    conf = lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
    lab.put("etc/systemd/journald.conf", "[Journal]\nSystemMaxUse=500M\n")
    deb = lab.package("systemd", "255.4-1ubuntu8.18", {"/etc/systemd/journald.conf": STOCK_JOURNALD},
                      recorded={"/etc/systemd/journald.conf": "f" * 32})
    lab.cache(deb)
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert f"has md5 {_md5(STOCK_JOURNALD)}, dpkg records {'f' * 32} for it" in proc.stdout
    assert conf.read_text(encoding="utf-8") == "[Journal]\nSystemMaxUse=500M\n"
    assert lab.mutating_systemctl() == []


def test_a_file_that_is_not_a_conffile_of_the_package_is_a_warn(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
    lab.put("etc/systemd/journald.conf", "[Journal]\n")
    lab.package("systemd", "255.4-1ubuntu8.18", {"/etc/systemd/logind.conf": "[Login]\n"})
    proc = lab.run(STATE_ONLY)
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"cannot restore: \S+/etc/systemd/journald\.conf is not a conffile of systemd 255\.4-1ubuntu8\.18", proc.stdout)


def test_ucf_a_template_that_is_not_dpkgs_is_a_warn(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    tpl = template(lab.dropdir_logical)
    src = lab.ucf(tpl, registered=_md5(tpl), recorded="e" * 32)
    conf = lab.pristine(src, "etc/ssh/sshd_config")
    lab.put("etc/ssh/sshd_config", provider_edit(tpl))
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert f"has md5 {_md5(tpl)}, dpkg records {'e' * 32} for it (openssh-server) — changed on this host" in proc.stdout
    assert conf.read_text(encoding="utf-8") == provider_edit(tpl)
    assert lab.log("sshd") == [] and lab.mutating_systemctl() == []


def test_ucf_a_destination_ucf_does_not_register_is_a_warn(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    tpl = template(lab.dropdir_logical)
    src = lab.ucf(tpl, registered=None)
    conf = lab.pristine(src, "etc/ssh/sshd_config")
    lab.put("etc/ssh/sshd_config", provider_edit(tpl))
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 0, proc.stdout
    assert f"cannot restore: ucf does not register {conf} (no line in {lab.hashfile})" in proc.stdout
    assert conf.read_text(encoding="utf-8") == provider_edit(tpl)


# --------------------------------------------------------------------------- #
# 2. The effect proof
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("fam", "hand", "key", "value"), [
    ("journald", "[Journal]\nSystemMaxUse=500M\nStorage=volatile\n", "Journal.Storage", "volatile"),
    ("resolved", "[Resolve]\nDNS=9.9.9.9\nFallbackDNS=1.0.0.1 8.8.4.4\n", "Resolve.DNS", "9.9.9.9"),
], ids=["journald", "resolved"])
def test_a_key_no_repo_file_carries_stops_phase1(tmp_path: Path, fam: str, hand: str, key: str, value: str) -> None:
    lab = PLab(tmp_path)
    if fam == "journald":
        lab.add("journald", "etc/systemd/journald.conf.d/10-vpn-bot.conf", JOURNALD_DROPIN)
        stock, pkg = STOCK_JOURNALD, "systemd"
    else:
        lab.add("resolved", "etc/systemd/resolved.conf.d/10-vpn-bot.conf", RESOLVED_DROPIN)
        stock, pkg = STOCK_RESOLVED, "systemd-resolved"
    conf = lab.pristine(f"dpkg:{pkg}", f"etc/systemd/{fam}.conf")
    lab.put(f"etc/systemd/{fam}.conf", hand)
    lab.cache(lab.package(pkg, "255.4-1ubuntu8.18", {f"/etc/systemd/{fam}.conf": stock}))
    before = lab.tree()
    proc = lab.run(PHASE1 + PHASE2)
    assert proc.returncode == 1, proc.stdout
    assert "PHASE1-OK" not in proc.stdout and "PHASE2-OK" not in proc.stdout
    assert re.search(rf"FAIL MISMATCH\s+pristine {re.escape(key)} — /etc/systemd/{fam}\.conf sets {re.escape(key)}={re.escape(value)} "
                     r"that no repo file carries — move it into a repo drop-in first", proc.stdout), proc.stdout
    assert "host invariants: 1 fatal finding(s) — nothing was changed" in proc.stdout
    assert lab.tree() == before and lab.mutating_systemctl() == []
    assert conf.read_text(encoding="utf-8") == hand


def test_sshd_config_with_yes_lines_after_the_include_is_restored_without_the_knob(tmp_path: Path) -> None:
    """The provider image's sshd_config: both auth lines active behind our drop-in. ucf
    registered the template as the postinst rendered it (PermitRootLogin yes from the
    preseeded debconf answer) — reported; the template itself is restored."""
    lab = PLab(tmp_path)
    lab.add("ssh", "etc/ssh/sshd_config.d/00-root-key-only.conf", KEY_ONLY)
    tpl = template(lab.dropdir_logical)
    rendered = tpl.replace("#PermitRootLogin prohibit-password", "PermitRootLogin yes")
    conf = lab.pristine(lab.ucf(tpl, registered=_md5(rendered)), "etc/ssh/sshd_config")
    lab.put("etc/ssh/sshd_config", provider_edit(tpl))
    lab.ssh_up()

    control = PLab(tmp_path / "control")   # the same host without the pristine entry
    control.add("ssh", "etc/ssh/sshd_config.d/00-root-key-only.conf", KEY_ONLY)
    control.put("etc/ssh/sshd_config", provider_edit(tpl))
    proc = control.run(PHASE1)
    assert proc.returncode == 1 and re.search(r"FAIL LATENT\s+sshd passwordauthentication", proc.stdout), proc.stdout

    proc = lab.run(PHASE1 + PHASE2)
    assert "KNOBS ALLOW_SSH_CHANGE=0 PHASE1_ONLY=0" in proc.stdout
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert f"ucf registered {_md5(rendered)} for {conf}: the template as the maintainer script rendered it" in proc.stdout
    assert re.search(r"sshd -T: byte-for-byte the same with the package default \(\d+ lines\)", proc.stdout)
    assert "ALLOW_SSH_CHANGE" not in proc.stdout.replace("KNOBS ALLOW_SSH_CHANGE=0", "").replace("no ALLOW_SSH_CHANGE", "")
    assert not re.search(r"LATENT\s+sshd", proc.stdout), "the provider's lines are gone with the package default"
    assert conf.read_text(encoding="utf-8") == tpl
    assert any(ln.startswith(f"sshd -t -f {conf}") for ln in lab.log("sshd"))
    assert lab.mutating_systemctl() == ["systemctl reload ssh.service"]
    assert "ssh.service active, listening on :22 and answering SSH" in proc.stdout
    state = json.loads(lab.state.read_text(encoding="utf-8"))
    assert state["counts"]["latent"] == 0 and state["counts"]["mismatch"] == 0, state


@pytest.mark.parametrize("listening", [True, False], ids=["restored", "rolled-back"])
def test_the_relay_restores_its_sshd_config_too(tmp_path: Path, listening: bool) -> None:
    lab = PLab(tmp_path)
    keyonly = (ROOT / "deploy/host/ssh/00-vpnrelay-keyonly.conf").read_text(encoding="utf-8")
    lab.add("ssh", "etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf", keyonly, role="relay")
    tpl = template(lab.dropdir_logical)
    conf = lab.pristine(lab.ucf(tpl, registered=_md5(tpl)), "etc/ssh/sshd_config", role="relay")
    lab.put("etc/ssh/sshd_config", provider_edit(tpl))
    lab.flag("ssh.service.active", "active")
    if listening:
        lab.flag("listen", "22\n")
    proc = lab.run(PHASE1 + PHASE2, NODE_ROLE="relay")
    if listening:
        assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
        assert conf.read_text(encoding="utf-8") == tpl
        assert json.loads(lab.state.read_text(encoding="utf-8"))["role"] == "relay"
    else:
        assert proc.returncode == 43 and "RELAY_ROLLBACK_CALLED" in proc.stdout, proc.stdout
        assert conf.read_text(encoding="utf-8") == provider_edit(tpl)
        assert lab.mutating_systemctl() == ["systemctl reload ssh.service"] * 2


def _real_path_ssh_lab(tmp_path: Path) -> tuple[PLab, str, Path]:
    """deploy.sh only (no host check): the Include names the real drop-in directory."""
    lab = PLab(tmp_path)
    tpl = template(str(lab.h("etc/ssh/sshd_config.d")))
    conf = lab.pristine(lab.ucf(tpl, registered=_md5(tpl)), "etc/ssh/sshd_config")
    lab.ssh_up()
    return lab, tpl, conf


def test_a_different_sshd_T_with_the_package_default_stops_phase1(tmp_path: Path) -> None:
    """Port is a multi-value keyword the host check does not judge: only sshd -T sees it."""
    lab, tpl, conf = _real_path_ssh_lab(tmp_path)
    lab.put("etc/ssh/sshd_config", tpl + "Port 2222\n")
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 1, proc.stdout
    assert "-port 2222" in proc.stdout and "+port 22" in proc.stdout, "the diff of the two sshd -T"
    assert "sshd -T differs with the package default (above)" in proc.stdout
    assert "Phase 1 refused 1 entr(y/ies)" in proc.stdout and "nothing was changed" in proc.stdout
    assert conf.read_text(encoding="utf-8") == tpl + "Port 2222\n"
    assert lab.mutating_systemctl() == []


def test_an_sshd_T_that_does_not_run_stops_phase1(tmp_path: Path) -> None:
    lab, tpl, conf = _real_path_ssh_lab(tmp_path)
    lab.put("etc/ssh/sshd_config", provider_edit(tpl))
    lab.flag("sshd_T_fail")
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 1, proc.stdout
    assert "sshd -T on the host's sshd_config exited 255 — no proof that the restore changes nothing" in proc.stdout
    assert conf.read_text(encoding="utf-8") == provider_edit(tpl)


def test_no_sshd_is_no_proof(tmp_path: Path) -> None:
    lab, tpl, _ = _real_path_ssh_lab(tmp_path)
    lab.put("etc/ssh/sshd_config", provider_edit(tpl))
    proc = lab.run('command() { [[ "$1 $2" == "-v sshd" ]] && return 1; builtin command "$@"; }\n' + STATE_ONLY)
    assert proc.returncode == 1, proc.stdout
    assert "sshd not found — no proof that the restore leaves sshd's effective configuration unchanged" in proc.stdout


def test_the_new_host_case_needs_no_hand_step(tmp_path: Path) -> None:
    """A fresh host from the provider image: our key-only drop-in not there yet,
    cloud-init's password drop-in still there, PermitRootLogin yes behind them. Live,
    sshd -T says permitrootlogin yes — but the proof compares the drop-in directory as
    Phase 2 leaves it, where the repo's drop-in decides either way: restored."""
    lab, tpl, conf = _real_path_ssh_lab(tmp_path)
    keyonly = lab.add("ssh", "etc/ssh/sshd_config.d/00-root-key-only.conf", KEY_ONLY, installed=False)
    lab.put("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    lab.retire("etc/ssh/sshd_config.d/50-cloud-init.conf")
    lab.put("etc/ssh/sshd_config", provider_edit(tpl))
    live = subprocess.run(["bash", str(lab.stub / "sshd"), "-T", "-f", str(conf)], capture_output=True, text=True,
                          env={**os.environ, "LOGS": str(lab.logs), "SD": str(lab.sd), "HC_ROOT": str(lab.root)}, check=False)
    assert "permitrootlogin yes" in live.stdout, "live sshd -T would differ: the proof must not compare with it"
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert conf.read_text(encoding="utf-8") == tpl
    assert keyonly.read_text(encoding="utf-8") == KEY_ONLY
    assert not lab.h("etc/ssh/sshd_config.d/50-cloud-init.conf").exists()
    assert lab.mutating_systemctl() == ["systemctl reload ssh.service"], "one reload for all three changes"
    assert "SUMMARY-LINE: 1 installed, 1 removed, 0 mode/owner fixed, 1 restored to the package default" in proc.stdout


# --------------------------------------------------------------------------- #
# 3. Phase 2: post-action, rollback, synced
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("fam", ["journald", "resolved", "ssh"])
def test_a_failed_post_action_rolls_back_and_repeats_it(tmp_path: Path, fam: str) -> None:
    lab = PLab(tmp_path)
    if fam == "ssh":
        lab.add("ssh", "etc/ssh/sshd_config.d/00-root-key-only.conf", KEY_ONLY)
        tpl = template(str(lab.h("etc/ssh/sshd_config.d")))
        conf = lab.pristine(lab.ucf(tpl, registered=_md5(tpl)), "etc/ssh/sshd_config")
        hand = provider_edit(tpl)
        lab.flag("ssh.service.active", "active")   # but nothing listens
        again = "systemctl reload ssh.service"
    else:
        stock = STOCK_JOURNALD if fam == "journald" else STOCK_RESOLVED
        pkg = "systemd" if fam == "journald" else "systemd-resolved"
        conf = lab.pristine(f"dpkg:{pkg}", f"etc/systemd/{fam}.conf")
        hand = stock + "# a comment someone added\n"
        lab.cache(lab.package(pkg, "255.4-1ubuntu8.18", {f"/etc/systemd/{fam}.conf": stock}))
        if fam == "journald":
            lab.flag("fail_restart_systemd-journald")
            again = "systemctl restart systemd-journald"
        else:
            lab.flag("getent_fail")
            again = "systemctl try-reload-or-restart systemd-resolved"
    lab.put(conf.relative_to(lab.root).as_posix(), hand)
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 42 and "ROLLBACK_CALLED" in proc.stdout, proc.stdout
    assert "PHASE2-OK" not in proc.stdout
    assert conf.read_text(encoding="utf-8") == hand, "the original is back"
    assert f"restore {conf}: rc=0" in proc.stdout
    assert lab.mutating_systemctl().count(again) == 2, "the post-action ran again on the restored file"
    if fam == "ssh":
        assert "NOT listening on :22" in proc.stdout
        assert "sshd -t on the restored ssh config: ok" in proc.stdout


@pytest.mark.parametrize("fam", ["journald", "ssh"])
def test_already_the_package_default_is_synced_with_no_mutation(tmp_path: Path, fam: str) -> None:
    lab = PLab(tmp_path)
    if fam == "ssh":
        tpl = template(lab.dropdir_logical)
        conf = lab.pristine(lab.ucf(tpl, registered=_md5(tpl)), "etc/ssh/sshd_config")
        lab.put("etc/ssh/sshd_config", tpl)
    else:
        conf = lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
        lab.put("etc/systemd/journald.conf", STOCK_JOURNALD)
        lab.package("systemd", "255.4-1ubuntu8.18", {"/etc/systemd/journald.conf": STOCK_JOURNALD})
    before = lab.tree()
    proc = lab.run(PHASE1 + PHASE2)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert re.search(rf"pristine\s+synced\s+{re.escape(str(conf))}", proc.stdout)
    assert lab.tree() == before
    assert lab.mutating_systemctl() == [] and lab.log("apt-get") == [] and lab.log("dpkg-deb") == []
    assert [ln for ln in lab.log("sshd") if ln.startswith("sshd -t")] == [], "no sshd -t, no reload"
    assert "SUMMARY-LINE: all in sync, nothing changed" in proc.stdout
    if fam == "journald":
        assert "the host copy already is it (md5" in proc.stdout, "nothing fetched"


def test_mode_and_owner_of_a_pristine_file_are_repaired(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    conf = lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
    lab.put("etc/systemd/journald.conf", STOCK_JOURNALD, mode=0o600)
    lab.package("systemd", "255.4-1ubuntu8.18", {"/etc/systemd/journald.conf": STOCK_JOURNALD})
    proc = lab.run(STATE_ONLY + INSTALL_ONLY)
    assert proc.returncode == 0, proc.stdout
    assert re.search(r"pristine\s+meta\s+", proc.stdout)
    assert conf.stat().st_mode & 0o777 == 0o644 and lab.mutating_systemctl() == []


def test_without_phase1_phase2_restores_nothing(tmp_path: Path) -> None:
    """The verified copy exists only in the process that ran Phase 1."""
    lab, conf, deb = _journald_lab(tmp_path, "[Journal]\nSystemMaxUse=500M\n")
    lab.cache(deb)
    proc = lab.run(INSTALL_ONLY)
    assert proc.returncode == 0, proc.stdout
    assert "cannot restore: the package default was not obtained" in proc.stdout
    assert conf.read_text(encoding="utf-8") == "[Journal]\nSystemMaxUse=500M\n"


def test_a_missing_effect_proof_stops_phase1(tmp_path: Path) -> None:
    """A host check that prints no pristine row (an old checker) proves nothing."""
    lab, _, deb = _journald_lab(tmp_path, "[Journal]\nSystemMaxUse=500M\n")
    lab.cache(deb)
    quiet = tmp_path / "quiet-check"
    quiet.write_text(f'#!/usr/bin/env bash\nbash "{CHECK}" "$@" | grep -v "^OK|pristine|"\nexit "${{PIPESTATUS[0]}}"\n',
                     encoding="utf-8")
    proc = lab.run(PHASE1, HOST_CHECK_BIN=str(quiet))
    assert proc.returncode == 1, proc.stdout
    assert "FAIL pristine /etc/systemd/journald.conf — the host check gave no effect proof" in proc.stdout


# --------------------------------------------------------------------------- #
# 4. The host check on its own
# --------------------------------------------------------------------------- #
def _check(lab: PLab, *extra: str) -> subprocess.CompletedProcess[str]:
    reg = lab.tmp / "registry"
    reg.write_text("".join(f"{e}\n" for e in lab.entries), encoding="utf-8")
    env = {"PATH": f"{lab.stub}:{os.environ.get('PATH', '')}", "SD": str(lab.sd), "LOGS": str(lab.logs),
           "HC_ROOT": str(lab.root)}
    return subprocess.run(["bash", str(CHECK), "--repo", str(lab.repo), "--role", "main", "--root", str(lab.root),
                           "--env", str(lab.env), "--registry", str(reg), "--no-state", *extra],
                          env=env, capture_output=True, text=True, check=False)


def test_check_pristine_needs_pre_install_and_an_entry(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    copy = tmp_path / "copy"
    copy.write_text(STOCK_JOURNALD, encoding="utf-8")
    proc = _check(lab, "--pristine", f"{lab.h('etc/systemd/journald.conf')}={copy}")
    assert proc.returncode == 2 and "--pristine needs --pre-install" in proc.stderr
    proc = _check(lab, "--pre-install", "--pristine", f"{lab.h('etc/systemd/journald.conf')}={copy}")
    assert proc.returncode == 2 and "no class pristine entry of role main names it" in proc.stderr


def test_check_a_pristine_entry_is_never_a_repo_file(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
    lab.put("etc/systemd/journald.conf", "[Journal]\nSystemMaxUse=1G\n")
    lab.package("systemd", "255", {"/etc/systemd/journald.conf": STOCK_JOURNALD})
    proc = _check(lab)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "registry|" not in proc.stdout, "no 'repo source missing' WARN"
    warn = [ln for ln in proc.stdout.splitlines() if ln.startswith("WARN|conffile|systemd|/etc/systemd/journald.conf|")]
    assert warn and "a class pristine entry: the next deploy restores the package default" in warn[0]


def test_check_match_blocks_are_part_of_the_proof(tmp_path: Path) -> None:
    lab = PLab(tmp_path)
    tpl = template(lab.dropdir_logical)
    lab.entries.append(f"ucf:/usr/share/openssh/sshd_config|{lab.h('etc/ssh/sshd_config')}|0644|{OWNER}|pristine|main")
    lab.put("etc/ssh/sshd_config", tpl + "Match User backup\n    PasswordAuthentication yes\n")
    copy = tmp_path / "copy"
    copy.write_text(tpl, encoding="utf-8")
    proc = _check(lab, "--pre-install", "--pristine", f"/etc/ssh/sshd_config={copy}")
    rows = [ln for ln in proc.stdout.splitlines() if "|pristine|" in ln]
    assert rows == ["MISMATCH|pristine|Match|/etc/ssh/sshd_config|the settings inside Match blocks change with the "
                    "package default of /etc/ssh/sshd_config — move what the hand edit puts in a Match block into a "
                    "repo drop-in first"], proc.stdout
    assert proc.returncode == 1


def test_check_match_scoped_multi_value_keywords_are_part_of_the_proof(tmp_path: Path) -> None:
    """DenyUsers inside a Match block: excluded from the global analysis (multi-value),
    invisible to `sshd -T` without -C — the structural comparison must still see it."""
    lab = PLab(tmp_path)
    tpl = template(lab.dropdir_logical)
    lab.entries.append(f"ucf:/usr/share/openssh/sshd_config|{lab.h('etc/ssh/sshd_config')}|0644|{OWNER}|pristine|main")
    lab.put("etc/ssh/sshd_config", tpl + "Match Address 192.0.2.0/24\n    DenyUsers root\n")
    copy = tmp_path / "copy"
    copy.write_text(tpl, encoding="utf-8")
    proc = _check(lab, "--pre-install", "--pristine", f"/etc/ssh/sshd_config={copy}")
    rows = [ln for ln in proc.stdout.splitlines() if "|pristine|" in ln]
    assert [r.split("|")[:3] for r in rows] == [["MISMATCH", "pristine", "Match"]], proc.stdout
    assert proc.returncode == 1


def test_check_an_accumulating_resolved_setting_is_a_list(tmp_path: Path) -> None:
    """DNSStubListenerExtra= adds a listener per assignment: the conffile's listener is in
    effect next to the drop-in's, and restoring the package default drops it."""
    lab = PLab(tmp_path)
    lab.add("resolved", "etc/systemd/resolved.conf.d/10-vpn-bot.conf",
            RESOLVED_DROPIN + "DNSStubListenerExtra=127.0.0.3\n")
    lab.pristine("dpkg:systemd-resolved", "etc/systemd/resolved.conf")
    lab.put("etc/systemd/resolved.conf", "[Resolve]\nDNSStubListenerExtra=127.0.0.2\n")
    copy = tmp_path / "copy"
    copy.write_text(STOCK_RESOLVED, encoding="utf-8")
    proc = _check(lab, "--pre-install", "--pristine", f"/etc/systemd/resolved.conf={copy}")
    rows = [ln.split("|") for ln in proc.stdout.splitlines() if "|pristine|" in ln]
    assert [r[:3] for r in rows] == [["MISMATCH", "pristine", "Resolve.DNSStubListenerExtra"]], proc.stdout
    assert "sets Resolve.DNSStubListenerExtra=127.0.0.2 that no repo file carries" in rows[0][4]
    assert "127.0.0.2 127.0.0.3" in rows[0][4], "the listeners add up"


@pytest.mark.parametrize(("hand", "ok"), [("SystemMaxUse=500M", True), ("SystemMaxUse=1G", False)],
                         ids=["duplicate", "overridden"])
def test_check_a_hand_value_another_file_overrides_is_not_provably_dead(tmp_path: Path, hand: str, ok: bool) -> None:
    """A setting the check does not know to accumulate: a hand edit that repeats the
    drop-in is provably harmless, one that another file overrides with ANOTHER value is
    dead only if the setting really is last-wins — refused rather than guessed."""
    lab = PLab(tmp_path)
    lab.add("journald", "etc/systemd/journald.conf.d/10-vpn-bot.conf", JOURNALD_DROPIN)
    lab.pristine("dpkg:systemd", "etc/systemd/journald.conf")
    lab.put("etc/systemd/journald.conf", f"[Journal]\n{hand}\n")
    copy = tmp_path / "copy"
    copy.write_text(STOCK_JOURNALD, encoding="utf-8")
    proc = _check(lab, "--pre-install", "--pristine", f"/etc/systemd/journald.conf={copy}")
    rows = [ln.split("|") for ln in proc.stdout.splitlines() if "|pristine|" in ln]
    if ok:
        assert [r[:3] for r in rows] == [["OK", "pristine", "/etc/systemd/journald.conf"]], proc.stdout
    else:
        assert [r[:3] for r in rows] == [["MISMATCH", "pristine", "Journal.SystemMaxUse"]], proc.stdout
        assert "/etc/systemd/journald.conf.d/10-vpn-bot.conf:" in rows[0][4] and "cannot prove" in rows[0][4]


# --------------------------------------------------------------------------- #
# 5. The real registry
# --------------------------------------------------------------------------- #
def _registry() -> list[list[str]]:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    body = text[text.index("MANAGED_HOST_FILES=(") :].split("\n)\n", 1)[0].splitlines()[1:]
    return [ln.strip().strip('"').split("|") for ln in body if ln.strip().startswith('"')]


# What the package manager says about each seeded destination, measured on both hosts
# on 2026-11-11: `dpkg-query -W -f='${Conffiles}' systemd systemd-resolved` lists the two
# conffiles; /var/lib/ucf/hashfile has a line for /etc/ssh/sshd_config.
PACKAGE_FACTS = {
    "dpkg:systemd": {"/etc/systemd/journald.conf"},
    "dpkg:systemd-resolved": {"/etc/systemd/resolved.conf"},
    "ucf:/usr/share/openssh/sshd_config": {"/etc/ssh/sshd_config"},
}
FAMILY_RE = re.compile(r"/etc/ssh/sshd_config|/etc/systemd/(journald|networkd|resolved|logind|timesyncd|system)\.conf"
                       r"|/etc/sysctl\.conf|/etc/sysctl\.d/[^/]+\.conf")


def test_the_seeded_pristine_entries() -> None:
    got = {(e[0], e[1], e[5]) for e in _registry() if e[4] == "pristine"}
    assert got == {
        ("dpkg:systemd", "/etc/systemd/journald.conf", "main"),
        ("dpkg:systemd-resolved", "/etc/systemd/resolved.conf", "main"),
        ("ucf:/usr/share/openssh/sshd_config", "/etc/ssh/sshd_config", "main"),
        ("ucf:/usr/share/openssh/sshd_config", "/etc/ssh/sshd_config", "relay"),
    }


def test_every_pristine_entry_names_a_package_default() -> None:
    entries = [e for e in _registry() if e[4] == "pristine"]
    assert entries
    for e in entries:
        src, dst, mode, owner = e[:4]
        assert re.fullmatch(r"dpkg:[a-z0-9][a-z0-9+.-]+|ucf:/[^\s|]+", src), e
        assert dst in PACKAGE_FACTS.get(src, set()), f"{dst} is not a conffile / ucf file of {src}: {e}"
        assert FAMILY_RE.fullmatch(dst), f"no effect proof exists for {dst}"
        assert (mode, owner, len(e)) == ("0644", "root:root", 6), e


def test_the_package_manager_agrees_where_the_package_is_installed() -> None:
    """On a host that has the package (the deploy runs this suite on the box), ask dpkg
    and ucf themselves; elsewhere there is nothing to ask."""
    if not shutil.which("dpkg-query"):
        pytest.skip("no dpkg-query here")
    asked = 0
    for e in _registry():
        if e[4] != "pristine":
            continue
        src, dst = e[0], e[1]
        if src.startswith("dpkg:"):
            status = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", src[5:]], capture_output=True,
                                    text=True, check=False)
            if status.returncode != 0 or status.stdout[1:2] != "i":
                continue   # known to dpkg, but not installed here
            out = subprocess.run(["dpkg-query", "-W", "-f=${Conffiles}\\n", src[5:]], capture_output=True, text=True,
                                 check=False)
            assert any(ln.split()[:1] == [dst] for ln in out.stdout.splitlines()), f"{dst} is not a conffile of {src[5:]}"
            asked += 1
        else:
            hashfile = Path("/var/lib/ucf/hashfile")
            if not hashfile.is_file() or not Path(src[4:]).is_file():
                continue
            assert any(ln.split()[1:2] == [dst] for ln in hashfile.read_text(encoding="utf-8").splitlines())
            asked += 1
    if not asked:
        pytest.skip("none of the packages is installed here")
