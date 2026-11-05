"""deploy/helpers/vpn-bot-protocol-uninstall — cascade removal of a protocol.

Every case runs the REAL helper against a fake host: VPN_BOT_UNINSTALL_ROOT
prefixes every path, and every privileged tool (systemctl, ufw, apt-get,
dpkg-query, userdel/useradd/groupadd/usermod, getent, iptables-save, pgrep,
nsenter) is a stub on PATH that keeps its state under the test's tmp dir. `find`
is a stub too: ownership (-uid) is faked, every other call goes to the real find.
The helper itself refuses to run under the seam when a privileged tool does not
resolve to a stub (pinned below), so a forgotten stub can never run the real
systemctl — deploy.sh runs this suite as root on the production host.

The fixtures mirror the read-only host measurement of 2026-11-05 (unit names and
states, the file lists, the ufw rules, the users).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "deploy" / "helpers" / "vpn-bot-protocol-uninstall"

pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.skipif(shutil.which("bash") is None or shutil.which("tar") is None, reason="bash + tar required"),
]

EXIT_VALIDATION = 64
EXIT_PLAN_CHANGED = 65
EXIT_REFUSED = 66
EXIT_BACKUP = 67
EXIT_ROLLED_BACK = 70


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


SYSTEMCTL = r"""
echo "systemctl $*" >> "$CALLS"
args=(); for a in "$@"; do [[ "$a" == -- ]] || args+=("$a"); done
set -- "${args[@]}"
U="$ST/units"; mkdir -p "$U"
get() { sed -n "s/^$2=//p" "$U/$1" 2>/dev/null | tail -n1; }
put() { local f="$U/$1"; touch "$f"; grep -v "^$2=" "$f" > "$f.tmp"; echo "$2=$3" >> "$f.tmp"; mv "$f.tmp" "$f"; }
fail() {
  local f
  for f in "$ST/fail_systemctl_$1" "$ST/fail_systemctl_$1_$2"; do
    [[ -f "$f" ]] || continue
    [[ "$(cat "$f")" == once ]] && rm -f "$f"
    return 0
  done
  return 1
}
hook() { [[ -f "$ST/hook_systemctl_$1" ]] && bash "$ST/hook_systemctl_$1"; return 0; }
verb="$1"; shift
case "$verb" in
show)
  prop=""; while [[ $# -gt 0 ]]; do case "$1" in -p) prop="$2"; shift 2 ;; --value) shift ;; *) unit="$1"; shift ;; esac; done
  case "$prop" in
    LoadState) v="$(get "$unit" load)"; echo "${v:-not-found}" ;;
    ActiveState) v="$(get "$unit" active)"; echo "${v:-inactive}" ;;
    UnitFileState) get "$unit" filestate ;;
    FragmentPath) get "$unit" fragment ;;
  esac
  exit 0 ;;
is-enabled) v="$(get "$1" filestate)"; echo "${v:-disabled}"; [[ "$v" == enabled ]]; exit ;;
list-units)
  pat="${!#}"
  for f in "$U"/*; do [[ -f "$f" ]] || continue; n="${f##*/}"
    [[ "$n" == $pat && "$(get "$n" load)" == loaded ]] && echo "$n loaded $(get "$n" active) running -"
  done; exit 0 ;;
daemon-reload)
  fail daemon-reload && exit 1
  for f in "$U"/*; do [[ -f "$f" ]] || continue; n="${f##*/}"; fr="$(get "$n" fragment)"
    [[ "$(get "$n" load)" == masked || -z "$fr" ]] && continue
    if [[ -e "$ROOTFS$fr" ]]; then [[ "$(get "$n" load)" == not-found ]] && put "$n" load loaded
    else put "$n" load not-found; put "$n" active inactive; put "$n" filestate ""; fi
  done
  hook daemon-reload; exit 0 ;;
stop) fail stop "$1" && exit 1; put "$1" active inactive; hook "stop_$1"; exit 0 ;;
start) fail start "$1" && exit 1; put "$1" active active; hook "start_$1"; exit 0 ;;
disable) fail disable "$1" && exit 1; put "$1" filestate disabled; rm -f "$ROOTFS/etc/systemd/system/multi-user.target.wants/$1"; exit 0 ;;
enable) fail enable "$1" && exit 1; put "$1" filestate enabled; exit 0 ;;
mask) fail mask "$1" && exit 1; put "$1" premask_load "$(get "$1" load)"; put "$1" load masked; put "$1" filestate masked
  ln -sfn /dev/null "$ROOTFS/etc/systemd/system/$1"; exit 0 ;;
unmask) rm -f "$ROOTFS/etc/systemd/system/$1"; put "$1" load "$(get "$1" premask_load)"; put "$1" filestate disabled; exit 0 ;;
reset-failed) exit 0 ;;
esac
exit 0
"""

UFW = r"""
echo "ufw $*" >> "$CALLS"
[[ "$1" == --force ]] && shift
R="$ST/ufw_rules"; touch "$R"
case "$1" in
show) echo "Added user rules (see 'ufw status' for running firewall):"
      if [[ -s "$R" ]]; then cat "$R"; else echo "(None)"; fi; exit 0 ;;
status)
  echo "Status: active"; echo
  n=1
  while IFS= read -r l; do s="${l#ufw allow }"; s="${s%% comment *}"
    if [[ "$2" == numbered ]]; then printf '[%2d] %-20s ALLOW IN    Anywhere\n' "$n" "$s"; else printf '%-20s ALLOW       Anywhere\n' "$s"; fi
    n=$((n+1)); done < "$R"
  while IFS= read -r l; do s="${l#ufw allow }"; s="${s%% comment *}"
    printf '%-20s ALLOW       Anywhere (v6)\n' "$s (v6)"; done < "$R"
  exit 0 ;;
delete)
  [[ -f "$ST/fail_ufw_delete" ]] && exit 1
  [[ -f "$ST/ufw_delete_noop" ]] && exit 0
  spec="$3"; grep -vE "^ufw allow ${spec}( comment .*)?$" "$R" > "$R.tmp"; mv "$R.tmp" "$R"; exit 0 ;;
allow)
  [[ -f "$ST/fail_ufw_allow" ]] && exit 1
  grep -qE "^ufw allow $2( comment .*)?$" "$R" && { echo "Skipping adding existing rule"; exit 0; }
  if [[ "${3:-}" == comment ]]; then echo "ufw allow $2 comment '$4'" >> "$R"; else echo "ufw allow $2" >> "$R"; fi; exit 0 ;;
esac
exit 0
"""

DPKG_QUERY = r"""
echo "dpkg-query $*" >> "$CALLS"
if [[ "$1" == -S ]]; then
  p="${!#}"; line="$(grep -F ": $p" "$ST/dpkg_owned" 2>/dev/null | head -n1)"
  [[ -n "$line" ]] && { echo "$line"; exit 0; }
  echo "dpkg-query: no path found matching pattern $p" >&2; exit 1
fi
if [[ "$1" == -W ]]; then
  fmt="${2#-f=}"; pkg="$3"; f="$ST/pkg_$pkg"
  [[ -f "$f" ]] || { echo "dpkg-query: no packages found matching $pkg" >&2; exit 1; }
  st="$(cut -d'|' -f1 "$f")"; ver="$(cut -d'|' -f2 "$f")"
  case "$fmt" in
    *Conffiles*) [[ "$st" == ii ]] && cat "$f.conffiles" 2>/dev/null; exit 0 ;;
    *Version*) printf '%s |%s' "$st" "$ver"; exit 0 ;;
    *) printf '%s ' "$st"; exit 0 ;;
  esac
fi
exit 0
"""

APT_GET = r"""
echo "apt-get $*" >> "$CALLS"
args=(); for a in "$@"; do case "$a" in -y|-q|-s) [[ "$a" == -s ]] && sim=1 ;; -o) skip=1 ;; *) if [[ -n "${skip:-}" ]]; then skip=; else args+=("$a"); fi ;; esac; done
verb="${args[0]}"; pkg="${args[1]%%=*}"; ver="${args[1]#*=}"
f="$ST/pkg_$pkg"
if [[ -n "${sim:-}" ]]; then echo "Purg $pkg [$(cut -d'|' -f2 "$f" 2>/dev/null)]"; cat "$ST/apt_extra" 2>/dev/null; exit 0; fi
case "$verb" in
purge)
  [[ -f "$ST/fail_apt_purge" ]] && exit 100
  # Keep what the package shipped, so a reinstall brings back the same bytes.
  while IFS= read -r p; do
    [[ -e "$ROOTFS$p" ]] || continue
    mkdir -p "$(dirname "$ST/pkgfiles$p")"; cp -p "$ROOTFS$p" "$ST/pkgfiles$p"; rm -f "$ROOTFS$p"
  done < "$f.files"
  rm -f "$f"; exit 0 ;;
install)
  [[ -f "$ST/fail_apt_install" ]] && exit 100
  echo "ii|$ver" > "$f"
  while IFS= read -r p; do
    [[ -e "$ROOTFS$p" ]] && continue   # --force-confold keeps an existing conffile
    mkdir -p "$(dirname "$ROOTFS$p")"; cp -p "$ST/pkgfiles$p" "$ROOTFS$p"
  done < "$f.files.orig"
  exit 0 ;;
esac
exit 0
"""

GETENT = r"""
echo "getent $*" >> "$CALLS"
db="$1"; shift; [[ "${1:-}" == -- ]] && shift; key="${1:-}"
f="$ST/$db"; [[ -f "$f" ]] || exit 2
if [[ -z "$key" ]]; then cat "$f"; exit 0; fi
awk -F: -v k="$key" '$1 == k || $3 == k {print; found=1} END {exit found ? 0 : 2}' "$f"
"""

USERDEL = r"""
echo "userdel $*" >> "$CALLS"
[[ -f "$ST/fail_userdel" ]] && exit 1
n="${!#}"
grep -v "^$n:" "$ST/passwd" > "$ST/passwd.tmp"; mv "$ST/passwd.tmp" "$ST/passwd"
grep -v "^$n:" "$ST/group" > "$ST/group.tmp"; mv "$ST/group.tmp" "$ST/group"
grep -v "^$n:" "$ST/shadow" > "$ST/shadow.tmp" 2>/dev/null; mv "$ST/shadow.tmp" "$ST/shadow"
exit 0
"""

USERADD = r"""
echo "useradd $*" >> "$CALLS"
while [[ $# -gt 0 ]]; do case "$1" in -u) u="$2"; shift 2 ;; -g) g="$2"; shift 2 ;; -c) c="$2"; shift 2 ;;
  -d) d="$2"; shift 2 ;; -s) s="$2"; shift 2 ;; -M) shift ;; --) shift ;; *) n="$1"; shift ;; esac; done
echo "$n:x:$u:$g:$c:$d:$s" >> "$ST/passwd"; echo "$n:!:1::::::" >> "$ST/shadow"
"""

GROUPADD = r"""
echo "groupadd $*" >> "$CALLS"
while [[ $# -gt 0 ]]; do case "$1" in -g) g="$2"; shift 2 ;; --) shift ;; *) n="$1"; shift ;; esac; done
echo "$n:x:$g:" >> "$ST/group"
"""

USERMOD = r"""
echo "usermod (args hidden)" >> "$CALLS"
while [[ $# -gt 0 ]]; do case "$1" in -p) h="$2"; shift 2 ;; --) shift ;; *) n="$1"; shift ;; esac; done
awk -F: -v OFS=: -v n="$n" -v h="$h" '$1 == n {$2 = h} {print}' "$ST/shadow" > "$ST/shadow.tmp"; mv "$ST/shadow.tmp" "$ST/shadow"
"""

IPTABLES_SAVE = r"""
echo "iptables-save $*" >> "$CALLS"
cat "$ST/mangle" 2>/dev/null; exit 0
"""

PGREP = r"""
echo "pgrep $*" >> "$CALLS"
[[ -f "$ST/procs_${2:-}" ]]
"""

NSENTER = r"""
echo "nsenter $*" >> "$CALLS"
echo "nsenter must never run under the test seam" >&2; exit 99
"""

# Ownership is faked: $ST/owned_<uid> lists host paths that "belong" to the uid.
FIND = r"""
uids=(); mode=""
for a in "$@"; do
  [[ "${prev:-}" == -uid ]] && uids+=("$a")
  case "$a" in -printf) mode=printf ;; -print) mode=print ;; esac
  prev="$a"
done
if [[ ${#uids[@]} -eq 0 ]]; then exec /usr/bin/find "$@"; fi
echo "find -uid ${uids[*]}" >> "$CALLS"
root="${1%/}"
for u in "${uids[@]}"; do
  [[ -f "$ST/owned_$u" ]] || continue
  while IFS= read -r p; do
    [[ -e "$root$p" ]] || continue
    if [[ "$mode" == printf ]]; then printf '%s\t%s\n' "$u" "$root$p"; else echo "$root$p"; exit 0; fi
  done < "$ST/owned_$u"
done
exit 0
"""

STUBS = {
    "systemctl": SYSTEMCTL, "ufw": UFW, "dpkg-query": DPKG_QUERY, "apt-get": APT_GET, "getent": GETENT,
    "userdel": USERDEL, "useradd": USERADD, "groupadd": GROUPADD, "usermod": USERMOD,
    "iptables-save": IPTABLES_SAVE, "pgrep": PGREP, "nsenter": NSENTER, "find": FIND,
}

PASSWD_BASE = [
    "root:x:0:0:root:/root:/bin/bash",
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
    "vpn-bot:x:996:996:VPN Telegram Bot:/var/lib/vpn-bot:/usr/sbin/nologin",
]
GROUP_BASE = ["root:x:0:", "nogroup:x:65534:", "vpn-bot:x:996:"]


class Host:
    """A fake host under tmp/root plus the stubs and their state."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.st = tmp / "state"
        self.calls = tmp / "calls.log"
        for d in (self.root, self.bin, self.st, self.st / "units"):
            d.mkdir(parents=True, exist_ok=True)
        for name, body in STUBS.items():
            _stub(self.bin / name, body)
        self.passwd = list(PASSWD_BASE)
        self.group = list(GROUP_BASE)
        self.shadow = [f"{line.split(':')[0]}:*:20000:0:99999:7:::" for line in PASSWD_BASE]
        self.env = {"BOT_TOKEN": "x"}
        self.ufw: list[str] = []
        self._flush_accounts()
        self.put("etc/systemd/system/multi-user.target.wants/.keep", "")
        self.put("opt/vpn-service/.keep", "")
        # Where the helper keeps its own bookkeeping (lock, log, backups) exists on a real host.
        for d in ("run", "var/log", "var/backups"):
            self.p(d).mkdir(parents=True, exist_ok=True)

    # --- fixtures -----------------------------------------------------------
    def p(self, rel: str) -> Path:
        return self.root / rel.lstrip("/")

    def put(self, rel: str, content: str = "x\n", mode: int = 0o644) -> Path:
        path = self.p(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    def link(self, rel: str, target: str) -> Path:
        path = self.p(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            path.unlink()
        path.symlink_to(target)
        return path

    def unit(self, name: str, *, load: str = "loaded", active: str = "active", filestate: str = "enabled",
             fragment: str = "", file_in_etc: bool = True, wants: bool = True) -> None:
        if not fragment:
            fragment = f"/etc/systemd/system/{name}"
        if file_in_etc and fragment.startswith("/etc/systemd/system/"):
            self.put(fragment, f"[Unit]\nDescription={name}\n[Service]\nExecStart=/bin/true\n")
        elif fragment and not fragment.startswith("/etc/"):
            self.put(fragment, f"[Service]\nExecStart=/bin/true # {name}\n")
        (self.st / "units" / name).write_text(
            f"load={load}\nactive={active}\nfilestate={filestate}\nfragment={fragment}\n", encoding="utf-8")
        if wants and filestate == "enabled":
            self.link(f"etc/systemd/system/multi-user.target.wants/{name}", fragment)

    def unit_state(self, name: str) -> dict[str, str]:
        f = self.st / "units" / name
        if not f.exists():
            return {}
        out: dict[str, str] = {}
        for line in f.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            out[k] = v
        out.pop("premask_load", None)
        return out

    def user(self, name: str, uid: int, login_shell: str = "/usr/sbin/nologin", home: str = "/nonexistent") -> None:
        self.passwd.append(f"{name}:x:{uid}:{uid}::{home}:{login_shell}")
        self.group.append(f"{name}:x:{uid}:")
        self.shadow.append(f"{name}:$6$salt$hash{uid}:20000:0:99999:7:::")
        self._flush_accounts()

    def _flush_accounts(self) -> None:
        (self.st / "passwd").write_text("\n".join(self.passwd) + "\n", encoding="utf-8")
        (self.st / "group").write_text("\n".join(self.group) + "\n", encoding="utf-8")
        (self.st / "shadow").write_text("\n".join(self.shadow) + "\n", encoding="utf-8")

    def set_ufw(self, *lines: str) -> None:
        (self.st / "ufw_rules").write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")

    def ufw_rules(self) -> list[str]:
        f = self.st / "ufw_rules"
        return f.read_text(encoding="utf-8").splitlines() if f.exists() else []

    def package(self, name: str, version: str, files: list[str], conffiles: list[str] = ()) -> None:  # type: ignore[assignment]
        (self.st / f"pkg_{name}").write_text(f"ii|{version}\n", encoding="utf-8")
        (self.st / f"pkg_{name}.files").write_text("".join(f"{p}\n" for p in files), encoding="utf-8")
        (self.st / f"pkg_{name}.files.orig").write_text("".join(f"{p}\n" for p in files), encoding="utf-8")
        (self.st / f"pkg_{name}.conffiles").write_text("".join(f" {p} 0123456789abcdef\n" for p in conffiles),
                                                       encoding="utf-8")

    def write_env(self, text: str | None = None, mode: int = 0o640) -> Path:
        body = text if text is not None else "".join(f"{k}={v}\n" for k, v in self.env.items())
        return self.put("opt/vpn-service/.env", body, mode)

    def flag(self, name: str, content: str = "") -> None:
        (self.st / name).write_text(content, encoding="utf-8")

    def git_init(self, tracked: list[str]) -> None:
        repo = self.p("opt/vpn-service")
        env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
        if (repo / ".git").exists():
            return
        subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
        for rel in tracked:
            self.put(f"opt/vpn-service/{rel}", f"tracked {rel}\n")
        subprocess.run(["git", "-C", str(repo), "add", "--", *tracked], check=True, env=env)
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
                       check=True, env=env)

    # --- running ------------------------------------------------------------
    def run(self, *args: str, fail: str = "", extra_env: dict[str, str] | None = None,
            path_override: str | None = None) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": path_override or f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.tmp),
            "LANG": "C.UTF-8",
            "ST": str(self.st),
            "CALLS": str(self.calls),
            "ROOTFS": str(self.root.resolve()),
            "VPN_BOT_UNINSTALL_ROOT": str(self.root),
            "VPN_BOT_UNINSTALL_SELFTEST_BIN": str(self.bin),
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        }
        if fail:
            env["VPN_BOT_UNINSTALL_SELFTEST_FAIL"] = fail
        env.update(extra_env or {})
        return subprocess.run(["bash", str(HELPER), *args], env=env, capture_output=True, text=True,
                              check=False, timeout=110)

    def plan(self, proto: str) -> dict[str, Any]:
        proc = self.run("plan", proto)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        return json.loads(proc.stdout)

    def apply(self, proto: str, sha: str | None = None, **kw: Any) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        if sha is None:
            sha = self.plan(proto)["sha256"]
        proc = self.run("apply", proto, sha, **kw)
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:  # pragma: no cover - a debugging aid
            raise AssertionError(f"apply printed no JSON (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}") from exc
        return proc, report

    def calls_of(self, tool: str) -> list[str]:
        if not self.calls.exists():
            return []
        return [ln for ln in self.calls.read_text(encoding="utf-8").splitlines() if ln.startswith(tool + " ")]

    def mutating_calls(self) -> list[str]:
        reads = ("systemctl show", "systemctl is-enabled", "systemctl list-units", "ufw show", "ufw status",
                 "dpkg-query", "getent", "iptables-save", "pgrep", "find", "apt-get -s")
        lines = self.calls.read_text(encoding="utf-8").splitlines() if self.calls.exists() else []
        return [ln for ln in lines if not ln.startswith(reads)]

    def snapshot(self) -> dict[str, Any]:
        """Everything a rollback must put back: files (content+mode+link target),
        unit states, ufw rules, accounts, packages."""
        tree: dict[str, str] = {}
        for p in sorted(self.root.rglob("*")):
            rel = str(p.relative_to(self.root))
            if rel.startswith(("var/backups/vpn-bot", "var/log/vpn-bot-uninstall.log", "run/")):
                continue
            if p.is_symlink():
                tree[rel] = "-> " + os.readlink(p)
            elif p.is_file():
                tree[rel] = f"{oct(p.stat().st_mode & 0o777)} " + hashlib.sha256(p.read_bytes()).hexdigest()
            elif p.is_dir():
                tree[rel] = f"dir {oct(p.stat().st_mode & 0o777)}"
        units = {f.name: self.unit_state(f.name) for f in sorted((self.st / "units").iterdir())}
        pkgs = {f.name: f.read_text(encoding="utf-8") for f in sorted(self.st.glob("pkg_*")) if "." not in f.name}
        return {
            "tree": tree, "units": units, "ufw": sorted(self.ufw_rules()), "pkgs": pkgs,
            "passwd": sorted((self.st / "passwd").read_text(encoding="utf-8").splitlines()),
            "group": sorted((self.st / "group").read_text(encoding="utf-8").splitlines()),
        }


# --------------------------------------------------------------------------- #
# Fixtures: the host as measured on 2026-11-05
# --------------------------------------------------------------------------- #
XRAY_BAKS = [
    "config.json.2026-11-03T215231_0000.1793742751758508845.zeaDvN-Fbcp5WkaHFd01kA.bak",
    "config.json.2026-11-05T010100_0000.1793840460492777021.y_W0PcfP68RHru_QcycPRA.bak",
    "config.json.bak", "config.json.bak-1781130557", "config.json.bak-20260519T093908Z",
    "config.json.bak.2026-06-06-routing", "config.json.bak.20260606-214835-pre-revert",
]
AWG_FILES = [
    ".awg0.conf.lock", "awg0.conf",
    "awg0.conf.2026-06-13T111234_0000.1781349154539251877.LcNIxIPYoKiG-AVYAnfV6w.bak",
    "awg0.conf.2026-11-02T230048_0000.1793660448265103388.ilKLVb1wLmDdbBab_jsFTg.bak",
    "awg0.conf.bak.20260625T011801Z",
]


def shared_host(h: Host) -> None:
    """The parts of the host every protocol must leave alone."""
    h.put("etc/nginx/nginx.conf", "events {}\n")
    h.put("etc/nginx/conf.d/decoy.conf", "server {}\n")
    h.put("var/www/anycastedge/index.html", "<html></html>\n")
    h.put("etc/vpn-bot/tls/fullchain.pem", "chain\n")
    h.put("etc/vpn-bot/tls/privkey.pem", "key\n", 0o640)
    h.put("etc/vpn-bot/warp-split.list", "1.1.1.0/24\n")
    h.put("root/.acme.sh/acme.sh", "#!/bin/sh\n", 0o755)
    h.put("etc/amnezia/out-warp.conf", "[Interface]\n", 0o644)
    h.put("etc/amnezia/out-warp-routes.list", "x\n", 0o600)
    h.put("etc/amnezia/out-warp.conf.WORKING", "x\n", 0o600)
    h.put("etc/amnezia/out-warp.conf.bak.2026-06-24-1836", "x\n", 0o600)
    h.link("etc/amnezia/amneziawg/out-warp.conf", "/etc/amnezia/out-warp.conf")
    h.unit("nginx.service", fragment="/usr/lib/systemd/system/nginx.service")
    h.unit("awg-quick@out-warp.service", filestate="disabled", fragment="/usr/lib/systemd/system/awg-quick@.service")
    h.unit("ssh.service", fragment="/usr/lib/systemd/system/ssh.service")
    h.put("usr/local/sbin/vpn-bot-warp-routes", "#!/bin/sh\n", 0o755)
    h.unit("warp-routes.service")


def xray_host(h: Host) -> None:
    shared_host(h)
    h.env.update({"XRAY_SERVICE_NAME": "xray"})
    h.write_env()
    h.unit("xray.service")
    h.put("etc/systemd/system/xray@.service", "[Service]\nExecStart=/usr/local/bin/xray run -c %i\n")
    h.put("etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf", "# Xray-install\n")
    h.put("etc/systemd/system/xray@.service.d/10-donot_touch_single_conf.conf", "# Xray-install\n")
    h.put("usr/local/bin/xray", "ELF\n", 0o755)
    h.put("usr/local/share/xray/geoip.dat", "geoip\n")
    h.put("usr/local/share/xray/geosite.dat", "geosite\n")
    h.put("usr/local/etc/xray/config.json", '{"privateKey": "secret"}\n', 0o640)
    h.put("usr/local/etc/xray/.config.json.lock", "")
    for bak in XRAY_BAKS:
        h.put(f"usr/local/etc/xray/{bak}", '{"privateKey": "old-secret"}\n', 0o600)
    h.put("var/log/xray/access.log", "a\n", 0o600)
    h.put("var/log/xray/error.log", "e\n", 0o600)
    h.put("etc/logrotate.d/xray", "/var/log/xray/*.log {}\n")
    h.set_ufw("ufw allow 443/tcp comment 'Xray Reality HTTPS'", "ufw allow 31337/tcp", "ufw allow 443/udp",
              "ufw allow 22/tcp")


def awg_host(h: Host) -> None:
    shared_host(h)
    h.env.update({"AWG_INTERFACE": "awg0"})
    h.write_env()
    h.unit("awg-quick@awg0.service", fragment="/usr/lib/systemd/system/awg-quick@.service")
    for name in AWG_FILES:
        h.put(f"etc/amnezia/amneziawg/{name}", f"[Interface] # {name}\n", 0o600)
    h.put("etc/amnezia/amneziawg/awg1.conf", "[Interface]\n", 0o600)
    h.put("etc/amnezia/amneziawg/awg0.conf.d/keep", "not a backup\n")
    h.set_ufw("ufw allow 443/tcp comment 'Xray Reality HTTPS'", "ufw allow 22/tcp")


SOCKS_USERS = [("vpn_socks_1278023784_1c1d2360", 997), ("vpn_socks_8487207537_cfef798f", 994),
               ("vpn_socks_8487207537_f7853b7f", 993), ("vpn_socks_543375855_6f32b9b9", 988),
               ("vpn_socks_2025560328_2959abde", 987)]


def socks5_host(h: Host) -> None:
    shared_host(h)
    h.env.update({"SOCKS5_ENABLED": "true", "SOCKS5_LOGIN_PREFIX": "vpn_socks_",
                  "SOCKS5_SYSTEM_USER_SHELL": "/usr/sbin/nologin", "SOCKS5_SERVICE_NAME": "danted"})
    h.write_env()
    h.unit("danted.service", fragment="/usr/lib/systemd/system/danted.service")
    h.put("etc/systemd/system/danted.service.d/vpn-bot-warp.conf", "[Unit]\nAfter=warp-routes.service\n")
    h.put("etc/danted.conf", "logoutput: syslog\n# this host's config\n")
    h.put("usr/sbin/danted", "ELF\n", 0o755)
    h.package("dante-server", "1.4.3+dfsg-1",
              ["/usr/lib/systemd/system/danted.service", "/etc/danted.conf", "/usr/sbin/danted"], ["/etc/danted.conf"])
    for name, uid in SOCKS_USERS:
        h.user(name, uid)
    h.user("vpn_socks_operator", 980, login_shell="/bin/bash")
    h.user("other_proxy_user", 981)
    h.set_ufw("ufw allow 443/tcp comment 'Xray Reality HTTPS'", "ufw allow 31337/tcp", "ufw allow 22/tcp")


def mtproto_host(h: Host) -> None:
    """Already half removed on the host: the unit is not-found, the binary gone."""
    shared_host(h)
    h.write_env()   # no MTPROTO_* line at all on the host
    h.put("etc/systemd/system/mtproxy.service.d/vpn-bot-managed.conf", "[Service]\nExecStart=\n")
    for name in ("mtproxy.env", "proxy-multi.conf", "proxy-secret", "secret"):
        h.put(f"etc/mtproxy/{name}", "secret\n", 0o600)
    h.put("etc/mtproxy/vpn-bot/managed-secrets.json", "{}\n", 0o640)
    h.git_init(["deploy/run-mtproxy-managed", "scripts/vpnbot-hy2-warp-mark"])
    h.put("opt/vpn-service/scripts/run-mtproxy-managed", "#!/bin/sh\n", 0o700)
    h.user("mtproxy", 999)


HY2_MANGLE = (
    "*mangle\n"
    "-A OUTPUT -m owner --uid-owner 992 -p udp -m udp --sport 443 -j RETURN\n"
    "-A OUTPUT -m owner --uid-owner 992 -j MARK --set-xmark 0x3d22/0xffffffff\n"
    "COMMIT\n"
)


def hysteria2_host(h: Host, *, clear_works: bool = True) -> None:
    shared_host(h)
    h.env.update({"HYSTERIA2_ENABLED": "true", "HYSTERIA2_SERVICE_NAME": "hysteria-server",
                  "HYSTERIA2_AUTH_SERVICE_NAME": "vpnbot-hy2-auth", "HYSTERIA2_PORT": "443"})
    h.write_env()
    h.unit("vpnbot-hy2-warp-mark.service")
    h.unit("hysteria-server.service")
    h.put("etc/systemd/system/hysteria-server@.service", "[Service]\n")
    h.unit("vpnbot-hy2-auth.service")
    h.flag("mangle", HY2_MANGLE)
    clear = f': > "{h.st}/mangle"' if clear_works else "true"
    h.put("usr/local/sbin/vpnbot-hy2-warp-mark",
          "#!/bin/bash\n# fake tagger\nMARK=0x3d22; TABLE=51820; HYUID=992\n"
          f'echo "warp-mark $1" >> "{h.calls}"\n'
          f'[[ "$1" == clear ]] && {clear}\nexit 0\n', 0o755)
    # Its ExecStop runs `clear`: the stub mirrors that on `systemctl stop`.
    h.flag("hook_systemctl_stop_vpnbot-hy2-warp-mark.service",
           f'echo "warp-mark clear (ExecStop)" >> "{h.calls}"; {clear}\n')
    h.put("usr/local/bin/hysteria", "ELF\n", 0o755)
    h.put("etc/hysteria/cert.pem", "cert\n")
    h.put("etc/hysteria/key.pem", "key\n", 0o600)
    h.put("etc/hysteria/config.yaml", "listen: :443\n", 0o600)
    h.put("etc/hysteria/config.yaml.bak.1782464972", "old\n")
    h.put("etc/hysteria/masq/index.html", "<html>\n")
    h.user("hysteria", 992, login_shell="/bin/sh")
    h.git_init(["scripts/vpnbot-hy2-warp-mark", "deploy/run-mtproxy-managed"])
    h.set_ufw("ufw allow 443/tcp comment 'Xray Reality HTTPS'", "ufw allow 443/udp", "ufw allow 22/tcp")


BUILDERS = {"xray": xray_host, "awg": awg_host, "socks5": socks5_host, "mtproto": mtproto_host,
            "hysteria2": hysteria2_host}
PROTOCOLS = list(BUILDERS)


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def _shared_untouched(h: Host, before: dict[str, Any]) -> None:
    after = h.snapshot()["tree"]
    for rel, value in before["tree"].items():
        if rel.startswith(("etc/nginx", "var/www", "etc/vpn-bot/tls", "etc/vpn-bot/warp-split", "root/",
                           "etc/amnezia/out-warp", "usr/local/sbin/vpn-bot-warp-routes")) \
                or rel == "etc/amnezia/amneziawg/out-warp.conf":
            assert after.get(rel) == value, f"shared {rel} was touched"
    for unit in ("nginx.service", "awg-quick@out-warp.service", "ssh.service", "warp-routes.service"):
        assert h.unit_state(unit) == before["units"][unit], unit
    assert not [c for c in h.mutating_calls() if "out-warp" in c or "nginx" in c or "ssh.service" in c]


# --------------------------------------------------------------------------- #
# 0. The seam fences itself
# --------------------------------------------------------------------------- #
def test_the_seam_refuses_a_real_host_tool(host: Host) -> None:
    xray_host(host)
    (host.bin / "systemctl").unlink()
    proc = host.run("plan", "xray", path_override=f"{host.bin}:/usr/bin:/bin:/usr/sbin:/sbin")
    assert proc.returncode == EXIT_VALIDATION
    assert "refusing to run a real host tool" in proc.stdout
    assert json.loads(proc.stdout)["error"] == "selftest"


def test_the_seam_needs_the_stub_dir(host: Host) -> None:
    xray_host(host)
    proc = host.run("plan", "xray", extra_env={"VPN_BOT_UNINSTALL_SELFTEST_BIN": ""})
    assert proc.returncode == EXIT_VALIDATION and "SELFTEST_BIN" in proc.stdout


def test_the_helper_is_executable_bash() -> None:
    assert os.access(HELPER, os.X_OK)
    assert HELPER.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")


# --------------------------------------------------------------------------- #
# 1. Arguments
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("proto", ["", "XRAY", "wireguard", "xray;id", "../xray", "warp"])
def test_an_unknown_protocol_is_refused(host: Host, proto: str) -> None:
    xray_host(host)
    before = host.snapshot()
    proc = host.run("plan", proto)
    assert proc.returncode == EXIT_VALIDATION, proc.stdout
    assert json.loads(proc.stdout)["error"] == "unknown_protocol"
    proc = host.run("apply", proto, "0" * 64)
    assert proc.returncode == EXIT_VALIDATION
    assert host.snapshot() == before and host.mutating_calls() == []


@pytest.mark.parametrize("args", [(), ("plan",), ("apply", "xray"), ("plan", "xray", "extra"), ("rm", "xray")])
def test_bad_usage(host: Host, args: tuple[str, ...]) -> None:
    xray_host(host)
    assert host.run(*args).returncode == 2


@pytest.mark.parametrize("sha", ["", "abc", "G" * 64, "A" * 64, "0" * 63])
def test_a_malformed_sha_is_refused(host: Host, sha: str) -> None:
    xray_host(host)
    before = host.snapshot()
    proc = host.run("apply", "xray", sha)
    assert proc.returncode in (2, EXIT_VALIDATION)
    assert host.snapshot() == before


def test_a_different_sha_is_refused_with_nothing_changed(host: Host) -> None:
    xray_host(host)
    before = host.snapshot()
    proc, report = host.apply("xray", "f" * 64)
    assert proc.returncode == EXIT_PLAN_CHANGED
    assert report["error"] == "plan_changed" and report["actual"] == host.plan("xray")["sha256"]
    assert host.snapshot() == before
    assert host.mutating_calls() == []
    assert not host.p("var/backups/vpn-bot/uninstall").exists()


def test_the_host_changing_after_the_plan_changes_the_sha(host: Host) -> None:
    xray_host(host)
    sha = host.plan("xray")["sha256"]
    host.put("usr/local/bin/xray", "ELF2\n", 0o755)   # same kind: the plan is unchanged
    assert host.plan("xray")["sha256"] == sha
    host.p("usr/local/bin/xray").unlink()             # a decision changed: absent now
    assert host.plan("xray")["sha256"] != sha
    proc, _ = host.apply("xray", sha)
    assert proc.returncode == EXIT_PLAN_CHANGED


def test_backups_growing_inside_a_removed_directory_keep_the_sha(host: Host) -> None:
    """The per-client purge (step 2, before apply) writes fresh *.bak files; the plan
    the admin confirmed must survive that."""
    xray_host(host)
    sha = host.plan("xray")["sha256"]
    host.put("usr/local/etc/xray/config.json.2026-11-05T020000_0000.1.new.bak", "{}\n")
    assert host.plan("xray")["sha256"] == sha


def test_new_awg_backups_from_the_purge_keep_the_sha(host: Host) -> None:
    awg_host(host)
    sha = host.plan("awg")["sha256"]
    host.put("etc/amnezia/amneziawg/awg0.conf.2026-11-05T020000_0000.2.purge.bak", "x\n", 0o600)
    assert host.plan("awg")["sha256"] == sha
    proc, report = host.apply("awg", sha)
    assert proc.returncode == 0, report
    assert not host.p("etc/amnezia/amneziawg/awg0.conf.2026-11-05T020000_0000.2.purge.bak").exists()


def test_socks_users_deleted_by_the_purge_keep_the_sha(host: Host) -> None:
    socks5_host(host)
    sha = host.plan("socks5")["sha256"]
    host.passwd = [line for line in host.passwd if not line.startswith(SOCKS_USERS[0][0])]
    host._flush_accounts()
    assert host.plan("socks5")["sha256"] == sha


# --------------------------------------------------------------------------- #
# 2. The plan
# --------------------------------------------------------------------------- #
def test_the_plan_is_read_only(host: Host) -> None:
    for build in BUILDERS.values():
        build(host)
    before = host.snapshot()
    for proto in PROTOCOLS:
        plan = host.plan(proto)
        assert plan["ok"] is True and re.fullmatch(r"[0-9a-f]{64}", plan["sha256"])
    assert host.snapshot() == before
    assert host.mutating_calls() == []


def test_the_xray_plan_lists_units_files_sizes_rules_and_skips(host: Host) -> None:
    xray_host(host)
    plan = host.plan("xray")
    assert plan["state"] == "installed" and plan["nothing_to_do"] is False and plan["blocking"] == []
    units = {u["unit"]: u for u in plan["units"]}
    assert units["xray.service"]["actions"] == "stop disable"
    files = {f["path"]: f for f in plan["files"]}
    for p in ("/etc/systemd/system/xray.service", "/etc/systemd/system/xray@.service",
              "/etc/systemd/system/xray.service.d", "/etc/systemd/system/xray@.service.d",
              "/usr/local/bin/xray", "/usr/local/share/xray", "/usr/local/etc/xray", "/var/log/xray"):
        assert files[p]["state"] == "delete", p
    assert files["/usr/local/etc/xray"]["kind"] == "dir"
    assert files["/usr/local/etc/xray"]["entries"] == len(XRAY_BAKS) + 2
    assert files["/usr/local/share/xray"]["size"] > 0
    assert [(w["rule"], w["state"]) for w in plan["ufw"]] == [("443/tcp", "delete")]
    assert plan["users"] == [] and plan["packages"] == []
    assert plan["marker"] == {"path": "/etc/vpn-bot/uninstalled/xray", "state": "create"}
    shared = " ".join(s["what"] for s in plan["skipped_shared"])
    for what in ("nobody", "/etc/nginx", "/var/www/anycastedge", "/etc/vpn-bot/tls", "/root/.acme.sh"):
        assert what in shared
    assert plan["backup_dir"] == "/var/backups/vpn-bot/uninstall"


def test_a_package_owned_file_is_skipped_not_removed(host: Host) -> None:
    xray_host(host)
    host.flag("dpkg_owned", "xray-pkg: /usr/local/bin/xray\n")
    plan = host.plan("xray")
    entry = next(f for f in plan["files"] if f["path"] == "/usr/local/bin/xray")
    assert entry["state"] == "skip" and "xray-pkg" in entry["reason"]
    proc, _ = host.apply("xray", plan["sha256"])
    assert proc.returncode == 0
    assert host.p("usr/local/bin/xray").exists()


# --------------------------------------------------------------------------- #
# 3. A full apply per protocol
# --------------------------------------------------------------------------- #
def test_xray_apply_removes_the_manifest_and_nothing_shared(host: Host) -> None:
    xray_host(host)
    before = host.snapshot()
    proc, report = host.apply("xray")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert report["ok"] is True and report["errors"] == []
    for rel in ("etc/systemd/system/xray.service", "etc/systemd/system/xray@.service",
                "etc/systemd/system/xray.service.d", "etc/systemd/system/xray@.service.d", "usr/local/bin/xray",
                "usr/local/share/xray", "usr/local/etc/xray", "var/log/xray"):
        assert not host.p(rel).exists(), rel
    assert host.unit_state("xray.service")["load"] == "not-found"
    assert host.ufw_rules() == ["ufw allow 31337/tcp", "ufw allow 443/udp", "ufw allow 22/tcp"]
    assert "ufw delete allow 443/tcp" in host.calls_of("ufw")
    assert host.calls_of("userdel") == [] and host.calls_of("apt-get") == []
    assert any(line.startswith("nobody:") for line in (host.st / "passwd").read_text(encoding="utf-8").splitlines())
    assert host.p("etc/logrotate.d/xray").exists()
    _shared_untouched(host, before)
    marker = json.loads(host.p("etc/vpn-bot/uninstalled/xray").read_text(encoding="utf-8"))
    assert marker["sha256"] == report["sha256"] and marker["backup"] == report["backup"]
    assert oct(host.p("etc/vpn-bot/uninstalled/xray").stat().st_mode & 0o777) == "0o644"
    assert "tar -xzf" in report["rollback_command"]


def test_the_backup_holds_everything_removed_root_0600(host: Host) -> None:
    xray_host(host)
    _, report = host.apply("xray")
    archive = host.p(report["backup"])
    assert re.fullmatch(r"/var/backups/vpn-bot/uninstall/xray-\d{8}T\d{6}Z\.tar\.gz", report["backup"])
    assert oct(archive.stat().st_mode & 0o777) == "0o600"
    assert oct(archive.parent.stat().st_mode & 0o777) == "0o700"
    listing = subprocess.run(["tar", "-tzf", str(archive)], capture_output=True, text=True, check=True).stdout
    names = set(listing.splitlines())
    for member in ("usr/local/etc/xray/config.json", f"usr/local/etc/xray/{XRAY_BAKS[0]}", "usr/local/bin/xray",
                   "var/log/xray/access.log", "etc/systemd/system/xray.service",
                   "etc/systemd/system/multi-user.target.wants/xray.service", "opt/vpn-service/.env",
                   "vpn-bot-uninstall-meta/plan.json", "vpn-bot-uninstall-meta/ufw-status-numbered.txt",
                   "vpn-bot-uninstall-meta/ROLLBACK.txt"):
        assert member in names, member
    assert not any(n.startswith(("etc/nginx", "var/www")) for n in names)


def test_awg_apply_masks_the_unit_and_leaves_warp_alone(host: Host) -> None:
    awg_host(host)
    before = host.snapshot()
    plan = host.plan("awg")
    deleted = sorted(f["path"].rsplit("/", 1)[1] for f in plan["files"] if f["state"] == "delete")
    assert deleted == sorted(AWG_FILES)
    proc, report = host.apply("awg", plan["sha256"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    sc = host.calls_of("systemctl")
    order = [c for c in sc if c.split()[1] in ("stop", "disable", "mask")]
    assert order == ["systemctl stop -- awg-quick@awg0.service", "systemctl disable -- awg-quick@awg0.service",
                     "systemctl mask -- awg-quick@awg0.service"]
    assert host.unit_state("awg-quick@awg0.service")["load"] == "masked"
    for name in AWG_FILES:
        assert not host.p(f"etc/amnezia/amneziawg/{name}").exists(), name
    assert host.p("etc/amnezia/amneziawg").is_dir() and host.p("etc/amnezia").is_dir()
    assert host.p("etc/amnezia/amneziawg/awg1.conf").exists()
    assert host.p("etc/amnezia/amneziawg/awg0.conf.d/keep").exists()
    assert os.readlink(host.p("etc/amnezia/amneziawg/out-warp.conf")) == "/etc/amnezia/out-warp.conf"
    _shared_untouched(host, before)
    assert host.calls_of("apt-get") == [] and host.calls_of("userdel") == []
    assert [w["state"] for w in plan["ufw"]] == ["absent"]
    assert report["ok"] is True


def test_socks5_apply_purges_and_deletes_only_matching_users(host: Host) -> None:
    socks5_host(host)
    before = host.snapshot()
    plan = host.plan("socks5")
    states = {u["name"]: u["state"] for u in plan["users"]}
    assert states["vpn_socks_operator"] == "keep"
    assert "other_proxy_user" not in states and "nobody" not in states
    assert all(states[name] == "delete" for name, _ in SOCKS_USERS)
    proc, report = host.apply("socks5", plan["sha256"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    passwd = (host.st / "passwd").read_text(encoding="utf-8")
    for name, _ in SOCKS_USERS:
        assert f"{name}:" not in passwd
    assert "vpn_socks_operator:" in passwd and "other_proxy_user:" in passwd and "nobody:" in passwd
    assert all(c.startswith("userdel -- vpn_socks_") for c in host.calls_of("userdel"))
    assert not [c for c in host.calls_of("userdel") if "-r" in c.split()]
    assert "apt-get purge -y -q dante-server" in host.calls_of("apt-get")
    assert not (host.st / "pkg_dante-server").exists()
    assert not host.p("etc/systemd/system/danted.service.d").exists()
    assert host.ufw_rules() == ["ufw allow 443/tcp comment 'Xray Reality HTTPS'", "ufw allow 22/tcp"]
    env = host.p("opt/vpn-service/.env").read_text(encoding="utf-8")
    assert "SOCKS5_ENABLED=false\n" in env and "SOCKS5_ENABLED=true" not in env
    _shared_untouched(host, before)
    skipped = {s["item"]: s["detail"] for s in report["skipped"]}
    assert "shell /bin/bash" in skipped["vpn_socks_operator"]


def test_mtproto_half_removed_is_a_normal_input(host: Host) -> None:
    mtproto_host(host)
    plan = host.plan("mtproto")
    assert plan["state"] == "partial" and plan["blocking"] == []
    files = {f["path"]: f["state"] for f in plan["files"]}
    assert files["/usr/local/bin/mtproto-proxy"] == "absent"
    assert files["/etc/systemd/system/mtproxy.service"] == "absent"
    assert files["/etc/systemd/system/mtproxy.service.d"] == "delete"
    assert files["/etc/mtproxy"] == "delete"
    assert files["/opt/vpn-service/scripts/run-mtproxy-managed"] == "delete"
    assert plan["env"] == {"key": "MTPROTO_ENABLED", "state": "append"}
    proc, report = host.apply("mtproto", plan["sha256"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    absent = {a["item"] for a in report["already_absent"]}
    assert {"mtproxy.service", "/usr/local/bin/mtproto-proxy", "9443/tcp"} <= absent
    assert not host.p("etc/mtproxy").exists()
    assert not host.p("etc/systemd/system/mtproxy.service.d").exists()
    assert not host.p("opt/vpn-service/scripts/run-mtproxy-managed").exists()
    assert host.p("opt/vpn-service/deploy/run-mtproxy-managed").exists(), "the tracked source stays"
    assert "mtproxy:" not in (host.st / "passwd").read_text(encoding="utf-8")
    assert host.p("opt/vpn-service/.env").read_text(encoding="utf-8") == "BOT_TOKEN=x\nMTPROTO_ENABLED=false\n"
    assert host.calls_of("systemctl stop") == []


def test_a_tracked_runtime_copy_is_never_removed(host: Host) -> None:
    mtproto_host(host)
    subprocess.run(["git", "-C", str(host.p("opt/vpn-service")), "add", "-f", "scripts/run-mtproxy-managed"],
                   check=True, env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"})
    plan = host.plan("mtproto")
    entry = next(f for f in plan["files"] if f["path"] == "/opt/vpn-service/scripts/run-mtproxy-managed")
    assert entry["state"] == "skip" and entry["reason"] == "tracked in the repository"


def test_hysteria2_clears_the_marks_before_anything_else(host: Host) -> None:
    hysteria2_host(host)
    before = host.snapshot()
    proc, _ = host.apply("hysteria2")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = host.calls.read_text(encoding="utf-8").splitlines()
    i_stop_mark = calls.index("systemctl stop -- vpnbot-hy2-warp-mark.service")
    i_clear = calls.index("warp-mark clear")
    i_verify = next(i for i, c in enumerate(calls) if c.startswith("iptables-save") and i > i_clear)
    i_stop_server = calls.index("systemctl stop -- hysteria-server.service")
    assert i_stop_mark < i_clear < i_verify < i_stop_server
    assert (host.st / "mangle").read_text(encoding="utf-8") == ""
    assert not host.p("usr/local/sbin/vpnbot-hy2-warp-mark").exists()
    assert host.p("opt/vpn-service/scripts/vpnbot-hy2-warp-mark").exists(), "the tracked copy stays"
    for rel in ("etc/systemd/system/vpnbot-hy2-warp-mark.service", "etc/systemd/system/hysteria-server.service",
                "etc/systemd/system/hysteria-server@.service", "etc/systemd/system/vpnbot-hy2-auth.service",
                "usr/local/bin/hysteria", "etc/hysteria"):
        assert not host.p(rel).exists(), rel
    assert "hysteria:" not in (host.st / "passwd").read_text(encoding="utf-8")
    assert host.ufw_rules() == ["ufw allow 443/tcp comment 'Xray Reality HTTPS'", "ufw allow 22/tcp"]
    assert "HYSTERIA2_ENABLED=false\n" in host.p("opt/vpn-service/.env").read_text(encoding="utf-8")
    _shared_untouched(host, before)


def test_hysteria2_marks_still_present_roll_back(host: Host) -> None:
    hysteria2_host(host, clear_works=False)
    before = host.snapshot()
    proc, report = host.apply("hysteria2")
    assert proc.returncode == EXIT_ROLLED_BACK, proc.stdout
    assert report["failed_step"] == "units" and "mangle rules" in report["errors"][0]
    assert host.snapshot() == before
    assert host.p("usr/local/sbin/vpnbot-hy2-warp-mark").exists()


# --------------------------------------------------------------------------- #
# 4. Idempotency
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("proto", PROTOCOLS)
def test_a_second_apply_is_nothing_to_do(host: Host, proto: str) -> None:
    BUILDERS[proto](host)
    proc, _ = host.apply(proto)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    plan = host.plan(proto)
    assert plan["nothing_to_do"] is True and plan["state"] == "uninstalled", plan
    snap = host.snapshot()
    host.calls.unlink()
    proc, report = host.apply(proto, "0" * 64)
    assert proc.returncode == 0 and report["nothing_to_do"] is True
    assert host.snapshot() == snap and host.mutating_calls() == []
    assert len(list(host.p("var/backups/vpn-bot/uninstall").glob("*.tar.gz"))) == 1


# --------------------------------------------------------------------------- #
# 5. No valid backup -> nothing touched
# --------------------------------------------------------------------------- #
def test_without_a_backup_nothing_is_touched(host: Host) -> None:
    xray_host(host)
    host.put("var/backups/vpn-bot/uninstall", "a file where the directory should be\n")
    before = host.snapshot()
    proc, report = host.apply("xray")
    assert proc.returncode == EXIT_BACKUP, proc.stdout
    assert report["ok"] is False and report["failed_step"] == "backup" and report["rolled_back"] is False
    assert host.snapshot() == before
    assert host.mutating_calls() == []


def test_a_backup_missing_a_member_is_rejected(host: Host) -> None:
    """tar -tzf must list every member — a tar that silently drops one is caught."""
    xray_host(host)
    real_tar = shutil.which("tar")
    _stub(host.bin / "tar", f'if [[ "$1" == --create ]]; then args=(); skip=0\n'
                            'for a in "$@"; do [[ "$a" == usr/local/bin/xray ]] && continue; args+=("$a"); done\n'
                            f'exec {real_tar} "${{args[@]}}"; fi\nexec {real_tar} "$@"\n')
    before = host.snapshot()
    proc, report = host.apply("xray")
    assert proc.returncode == EXIT_BACKUP, proc.stdout
    assert "missing from the archive" in report["errors"][0]
    assert host.snapshot() == before and host.mutating_calls() == []


# --------------------------------------------------------------------------- #
# 6. A failure in any step 4-10 rolls everything back
# --------------------------------------------------------------------------- #
FAIL_CASES = [(proto, step) for proto in ("xray", "socks5", "hysteria2")
              for step in ("units", "files", "ufw", "packages", "users", "env", "marker")]
FAIL_CASES += [("awg", step) for step in ("units", "files", "ufw", "marker")]
FAIL_CASES += [("mtproto", step) for step in ("files", "users", "env")]


@pytest.mark.parametrize(("proto", "step"), FAIL_CASES, ids=[f"{p}-{s}" for p, s in FAIL_CASES])
def test_a_failure_after_each_step_restores_the_host(host: Host, proto: str, step: str) -> None:
    BUILDERS[proto](host)
    before = host.snapshot()
    proc, report = host.apply(proto, fail=step)
    assert proc.returncode == EXIT_ROLLED_BACK, proc.stdout + proc.stderr
    assert report["ok"] is False and report["failed_step"] == step and report["rolled_back"] is True
    assert report["rollback_errors"] == []
    after = host.snapshot()
    assert after["tree"] == before["tree"]
    assert after["units"] == before["units"]
    assert after["ufw"] == before["ufw"]
    assert after["pkgs"] == before["pkgs"]
    assert sorted(after["passwd"]) == sorted(before["passwd"])
    assert not host.p(f"etc/vpn-bot/uninstalled/{proto}").exists()
    assert host.p(report["backup"]).exists(), "the backup is kept after a rollback"


@pytest.mark.parametrize(("flag", "step"), [
    ("fail_systemctl_stop_xray.service", "units"),
    ("fail_systemctl_daemon-reload", "units"),   # one-shot: the rollback's own reload works
    ("fail_ufw_delete", "ufw"),
    ("ufw_delete_noop", "ufw"),
])
def test_real_tool_failures_roll_back_xray(host: Host, flag: str, step: str) -> None:
    xray_host(host)
    before = host.snapshot()
    host.flag(flag, "once" if flag.startswith("fail_systemctl") else "")
    proc, report = host.apply("xray")
    assert proc.returncode == EXIT_ROLLED_BACK, proc.stdout
    assert report["failed_step"] == step
    assert host.snapshot()["tree"] == before["tree"] and host.snapshot()["ufw"] == before["ufw"]
    assert host.unit_state("xray.service") == before["units"]["xray.service"]


@pytest.mark.parametrize("flag", ["fail_apt_purge", "fail_userdel"])
def test_real_tool_failures_roll_back_socks5(host: Host, flag: str) -> None:
    socks5_host(host)
    before = host.snapshot()
    host.flag(flag)
    proc, _ = host.apply("socks5")
    assert proc.returncode == EXIT_ROLLED_BACK, proc.stdout
    after = host.snapshot()
    assert after["tree"] == before["tree"] and after["pkgs"] == before["pkgs"]
    assert sorted(after["passwd"]) == sorted(before["passwd"])


def test_the_purged_package_comes_back_with_this_hosts_conffile(host: Host) -> None:
    socks5_host(host)
    conf = host.p("etc/danted.conf").read_text(encoding="utf-8")
    proc, _ = host.apply("socks5", fail="users")
    assert proc.returncode == EXIT_ROLLED_BACK
    assert "apt-get install -y -q -o Dpkg::Options::=--force-confold dante-server=1.4.3+dfsg-1" in host.calls_of("apt-get")
    assert host.p("etc/danted.conf").read_text(encoding="utf-8") == conf


def test_restored_users_get_their_password_hash_back(host: Host) -> None:
    socks5_host(host)
    shadow = (host.st / "shadow").read_text(encoding="utf-8")
    proc, _ = host.apply("socks5", fail="env")
    assert proc.returncode == EXIT_ROLLED_BACK
    restored = (host.st / "shadow").read_text(encoding="utf-8")
    for name, uid in SOCKS_USERS:
        assert f"{name}:$6$salt$hash{uid}:" in restored and f"{name}:$6$salt$hash{uid}:" in shadow
    log = host.p("var/log/vpn-bot-uninstall.log").read_text(encoding="utf-8")
    assert "$6$salt" not in log, "a password hash must never reach the log"


def test_a_rollback_that_cannot_finish_says_so(host: Host) -> None:
    xray_host(host)
    host.flag("fail_ufw_allow")
    proc, report = host.apply("xray", fail="marker")
    assert proc.returncode == 71, proc.stdout
    assert report["rolled_back"] is True and any("ufw allow 443/tcp" in e for e in report["rollback_errors"])


# --------------------------------------------------------------------------- #
# 7. Symlinks and the deny-list
# --------------------------------------------------------------------------- #
def test_a_symlinked_manifest_directory_blocks_the_apply(host: Host) -> None:
    xray_host(host)
    shutil.rmtree(host.p("usr/local/etc/xray"))
    host.link("usr/local/etc/xray", str(host.p("etc/nginx")))
    before = host.snapshot()
    plan = host.plan("xray")
    assert any("/usr/local/etc/xray" in b and "symlink" in b for b in plan["blocking"])
    proc, report = host.apply("xray", plan["sha256"])
    assert proc.returncode == EXIT_REFUSED and report["error"] == "blocked"
    assert host.snapshot() == before and host.mutating_calls() == []
    assert host.p("etc/nginx/nginx.conf").exists()


def test_a_symlinked_parent_blocks_too(host: Host) -> None:
    """/usr/local/share itself is a symlink: /usr/local/share/xray resolves outside."""
    xray_host(host)
    shutil.move(str(host.p("usr/local/share")), str(host.p("elsewhere-share")))
    host.link("usr/local/share", str(host.p("elsewhere-share")))
    plan = host.plan("xray")
    assert any(b.startswith("/usr/local/share/xray:") and "parent" in b for b in plan["blocking"]), plan["blocking"]
    proc, _ = host.apply("xray", plan["sha256"])
    assert proc.returncode == EXIT_REFUSED
    assert host.p("elsewhere-share/xray/geoip.dat").exists()


def test_a_symlink_matching_the_awg_pattern_blocks(host: Host) -> None:
    awg_host(host)
    host.link("etc/amnezia/amneziawg/awg0.conf.evil.bak", "/etc/passwd")
    plan = host.plan("awg")
    assert any("awg0.conf.evil.bak" in b for b in plan["blocking"])
    proc, _ = host.apply("awg", plan["sha256"])
    assert proc.returncode == EXIT_REFUSED


def test_a_path_swapped_for_a_symlink_mid_apply_rolls_back(host: Host) -> None:
    """Time of check = time of use: every path is re-checked right before rm."""
    xray_host(host)
    before = host.snapshot()
    host.flag("hook_systemctl_daemon-reload",
              f'rm -rf "{host.p("var/log/xray")}"; ln -s "{host.p("etc/nginx")}" "{host.p("var/log/xray")}"\n')
    proc, report = host.apply("xray")
    assert proc.returncode == EXIT_ROLLED_BACK, proc.stdout
    assert report["failed_step"] == "files" and "changed under the helper" in report["errors"][0]
    assert host.p("etc/nginx/nginx.conf").exists()
    assert host.snapshot()["units"] == before["units"]


@pytest.mark.parametrize(("var", "value"), [
    ("MTPROTO_CONFIG_DIR", "/etc"),
    ("MTPROTO_CONFIG_DIR", "/etc/nginx"),
    ("MTPROTO_CONFIG_DIR", "/etc/mtproxy/../nginx"),
    ("MTPROTO_CONFIG_DIR", "etc/mtproxy"),
    ("MTPROTO_CONFIG_DIR", "/etc/vpn-bot"),
    ("MTPROTO_BINARY_PATH", "/usr/bin/sudo"),
    ("MTPROTO_BINARY_PATH", "/usr/local/bin/../sbin/mt"),
    ("MTPROTO_SERVICE_NAME", "ssh"),
    ("MTPROTO_SERVICE_NAME", "../../ssh"),
    ("MTPROTO_SERVICE_NAME", "mt proxy"),
])
def test_env_overrides_are_validated(host: Host, var: str, value: str) -> None:
    mtproto_host(host)
    host.write_env(f"BOT_TOKEN=x\n{var}={value}\n")
    before = host.snapshot()
    proc = host.run("plan", "mtproto")
    assert proc.returncode == EXIT_VALIDATION, proc.stdout
    assert json.loads(proc.stdout)["error"] == "invalid_env"
    assert host.snapshot() == before


@pytest.mark.parametrize(("env", "message"), [
    ("AWG_INTERFACE=out-warp\n", "shared interface"),
    ("AWG_INTERFACE=awg0\nAWG_CONFIG_PATH=/etc/amnezia/out-warp.conf\n", "outside"),
    ("AWG_INTERFACE=awg0\nAWG_CONFIG_PATH=/etc/amnezia/amneziawg/awg1.conf\n", "does not belong"),
    ("SOCKS5_LOGIN_PREFIX=v\n", "too short"),
    ("SOCKS5_LOGIN_PREFIX=root_\n", "too generic"),
    ("SOCKS5_SYSTEM_USER_SHELL=/bin/bash\n", "login shell"),
    ("XRAY_SERVICE_NAME=nginx\n", "nginx"),
    ("HYSTERIA2_SERVICE_NAME=vpn-bot\n", "never touches"),
])
def test_more_env_validation(host: Host, env: str, message: str) -> None:
    for build in BUILDERS.values():
        build(host)
    host.write_env("BOT_TOKEN=x\n" + env)
    key = env.split("=", 1)[0]
    proto = {"AWG": "awg", "SOCKS5": "socks5", "XRAY": "xray", "HYSTERIA2": "hysteria2"}[key.split("_", 1)[0]]
    proc = host.run("plan", proto)
    assert proc.returncode == EXIT_VALIDATION, proc.stdout
    if message != "nginx":
        assert message in proc.stdout


def test_the_env_reader_is_tolerant_and_last_wins(host: Host) -> None:
    mtproto_host(host)
    host.write_env("BOT_TOKEN=x\nMTPROTO_CONFIG_DIR=/etc/nope\n  export MTPROTO_CONFIG_DIR = \"/etc/mtproxy\"  # host\n")
    plan = host.plan("mtproto")
    assert any(f["path"] == "/etc/mtproxy" and f["state"] == "delete" for f in plan["files"])


def test_a_socks5_user_owning_files_is_kept(host: Host) -> None:
    socks5_host(host)
    name, uid = SOCKS_USERS[1]
    host.put("srv/keep/owned-by-socks-user", "x\n")
    host.flag(f"owned_{uid}", "/srv/keep/owned-by-socks-user\n")
    plan = host.plan("socks5")
    entry = next(u for u in plan["users"] if u["name"] == name)
    assert entry["state"] == "keep" and "/srv/keep/owned-by-socks-user" in entry["reason"]
    proc, _ = host.apply("socks5", plan["sha256"])
    assert proc.returncode == 0
    assert f"{name}:" in (host.st / "passwd").read_text(encoding="utf-8")


def test_files_the_manifest_removes_do_not_keep_a_user(host: Host) -> None:
    """/etc/hysteria belongs to `hysteria`: removed in step 5, so step 8 may delete it."""
    hysteria2_host(host)
    host.flag("owned_992", "/etc/hysteria/config.yaml\n/etc/hysteria\n")
    plan = host.plan("hysteria2")
    assert next(u for u in plan["users"] if u["name"] == "hysteria")["state"] == "delete"
    proc, _ = host.apply("hysteria2", plan["sha256"])
    assert proc.returncode == 0
    assert "hysteria:" not in (host.st / "passwd").read_text(encoding="utf-8")


def test_a_user_with_running_processes_is_kept(host: Host) -> None:
    mtproto_host(host)
    host.flag("procs_999")
    plan = host.plan("mtproto")
    assert next(u for u in plan["users"] if u["name"] == "mtproxy")["state"] == "keep"


def test_a_purge_that_drags_other_packages_is_blocked(host: Host) -> None:
    socks5_host(host)
    host.flag("apt_extra", "Remv libpam-something [1.0]\n")
    plan = host.plan("socks5")
    assert any("libpam-something" in b for b in plan["blocking"])


def test_a_dpkg_rc_package_is_not_purged(host: Host) -> None:
    socks5_host(host)
    (host.st / "pkg_dante-server").write_text("rc|1.4.3+dfsg-1\n", encoding="utf-8")
    plan = host.plan("socks5")
    assert plan["packages"][0]["state"] == "skip"


def test_a_non_standard_ufw_rule_is_reported_not_removed(host: Host) -> None:
    xray_host(host)
    host.set_ufw("ufw allow 443", "ufw allow 443/udp")
    plan = host.plan("xray")
    assert [(w["state"], w["line"]) for w in plan["ufw"]] == [("skip", "ufw allow 443")]
    proc, _ = host.apply("xray", plan["sha256"])
    assert proc.returncode == 0
    assert host.ufw_rules() == ["ufw allow 443", "ufw allow 443/udp"]


# --------------------------------------------------------------------------- #
# 8. .env: exactly one line, owner and mode kept
# --------------------------------------------------------------------------- #
def test_the_env_flag_edit_changes_exactly_one_line(host: Host) -> None:
    hysteria2_host(host)
    original = ("BOT_TOKEN=x\n# HYSTERIA2_ENABLED=true is the switch\nHYSTERIA2_ENABLED=true\nHYSTERIA2_PORT=443\n"
                "export HYSTERIA2_ENABLED = \"yes\"  # last wins\nHYSTERIA2_SERVICE_NAME=hysteria-server\n"
                "HYSTERIA2_AUTH_SERVICE_NAME=vpnbot-hy2-auth\n")
    env = host.write_env(original, mode=0o640)
    proc, _ = host.apply("hysteria2")
    assert proc.returncode == 0, proc.stdout
    new = env.read_text(encoding="utf-8").splitlines()
    old = original.splitlines()
    assert len(new) == len(old)
    diff = [(a, b) for a, b in zip(old, new, strict=True) if a != b]
    assert diff == [('export HYSTERIA2_ENABLED = "yes"  # last wins', "HYSTERIA2_ENABLED=false")]
    assert oct(env.stat().st_mode & 0o777) == "0o640"


def test_the_env_append_keeps_a_file_without_a_final_newline(host: Host) -> None:
    mtproto_host(host)
    env = host.write_env("BOT_TOKEN=x", mode=0o600)
    proc, _ = host.apply("mtproto")
    assert proc.returncode == 0, proc.stdout
    assert env.read_text(encoding="utf-8") == "BOT_TOKEN=x\nMTPROTO_ENABLED=false\n"
    assert oct(env.stat().st_mode & 0o777) == "0o600"


def test_xray_and_awg_leave_the_env_alone(host: Host) -> None:
    xray_host(host)
    env = host.p("opt/vpn-service/.env").read_bytes()
    host.apply("xray")
    assert host.p("opt/vpn-service/.env").read_bytes() == env


# --------------------------------------------------------------------------- #
# 9. Static guards on the manifest
# --------------------------------------------------------------------------- #
def _manifest_block() -> list[str]:
    text = HELPER.read_text(encoding="utf-8")
    block = text.split("# >>> MANIFEST", 1)[1].split("# <<< MANIFEST", 1)[0]
    return [ln for ln in block.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_the_manifest_block_has_no_glob() -> None:
    for line in _manifest_block():
        assert not re.search(r"[*?\[]", line), f"glob-like character in the manifest: {line!r}"


def test_the_awg_regex_is_pinned() -> None:
    text = HELPER.read_text(encoding="utf-8")
    assert "readonly AWG_FILE_RE_TEMPLATE='^\\.?@IF@\\.conf(\\.lock|\\..+\\.bak|\\.bak\\..+)?$'" in text
    rx = re.compile(r"^\.?awg0\.conf(\.lock|\..+\.bak|\.bak\..+)?$")
    host_files = [
        ".awg0.conf.lock", "awg0.conf", "awg0.conf.bak.20260625T011801Z",
        "awg0.conf.2026-06-13T111234_0000.1781349154539251877.LcNIxIPYoKiG-AVYAnfV6w.bak",
        "awg0.conf.2026-11-02T230048_0000.1793660448265103388.ilKLVb1wLmDdbBab_jsFTg.bak",
    ]
    assert all(rx.fullmatch(n) for n in host_files)
    for keep in ("out-warp.conf", "awg1.conf", "awg0.conf.d", "xawg0.conf", "awg0.confx", "awg0.conf.bak",
                 "out-warp.conf.bak.2026-06-24-1836", "awg0.conf.lockx"):
        assert not rx.fullmatch(keep), keep


GLOBAL_FORBIDDEN_EXACT = {"/", "/etc", "/usr", "/usr/local", "/usr/local/bin", "/usr/local/sbin", "/var", "/var/log",
                          "/etc/systemd/system", "/etc/amnezia", "/etc/amnezia/amneziawg", "/opt/vpn-service",
                          "/opt/vpn-service/scripts"}
GLOBAL_FORBIDDEN_TREES = ("/etc/nginx", "/var/www", "/etc/vpn-bot", "/root", "/etc/ssh", "/etc/sysctl.d", "/etc/ufw",
                          "/etc/letsencrypt", "/opt/vpn-service/data", "/opt/vpn-service/.git", "/etc/sudoers.d")


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_no_manifest_path_is_globally_forbidden(host: Host, proto: str) -> None:
    for build in BUILDERS.values():
        build(host)
    proc = host.run("manifest", proto)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    man = json.loads(proc.stdout)
    for p in man["unit_files"] + man["paths"]:
        assert p.startswith("/") and ".." not in p and not re.search(r"[*?\[]", p), p
        assert p not in GLOBAL_FORBIDDEN_EXACT, p
        assert not any(p == t or p.startswith(t + "/") for t in GLOBAL_FORBIDDEN_TREES), p
        assert not any(f.startswith(p + "/") for f in (*GLOBAL_FORBIDDEN_EXACT, *GLOBAL_FORBIDDEN_TREES)), p
        assert "out-warp" not in p and "/warp-" not in p, p
        assert not p.startswith("/opt/vpn-service/") or p == "/opt/vpn-service/scripts/run-mtproxy-managed", p
    for u in (u["unit"] for u in man["units"]):
        assert u not in ("ssh.service", "nginx.service", "vpn-bot.service", "awg-quick@out-warp.service"), u
        assert not u.startswith(("warp-", "systemd-")), u
    assert not set(man["users"]) & {"root", "nobody", "vpn-bot"}
    assert man["packages"] in ([], ["dante-server"])


def test_the_expected_manifests(host: Host) -> None:
    for build in BUILDERS.values():
        build(host)
    man = {p: json.loads(host.run("manifest", p).stdout) for p in PROTOCOLS}
    assert man["xray"]["paths"] == ["/usr/local/bin/xray", "/usr/local/share/xray", "/usr/local/etc/xray",
                                    "/var/log/xray"]
    assert man["xray"]["users"] == [] and man["xray"]["ufw"] == ["443/tcp"]
    assert man["awg"]["units"] == [{"unit": "awg-quick@awg0.service", "flag": "mask"}]
    assert man["awg"]["paths"] == [] and man["awg"]["awg_dir"] == "/etc/amnezia/amneziawg"
    assert man["awg"]["ufw"] == ["11880/udp"]
    assert man["socks5"]["packages"] == ["dante-server"] and man["socks5"]["socks_rule"] is True
    assert man["socks5"]["unit_files"] == ["/etc/systemd/system/danted.service.d"]
    assert man["socks5"]["ufw"] == ["31337/tcp"]
    assert man["mtproto"]["users"] == ["mtproxy"] and man["mtproto"]["ufw"] == ["9443/tcp"]
    assert man["hysteria2"]["units"][0] == {"unit": "vpnbot-hy2-warp-mark.service", "flag": "hy2mark"}
    assert man["hysteria2"]["users"] == ["hysteria"] and man["hysteria2"]["ufw"] == ["443/udp"]
    assert "/opt/vpn-service/scripts/vpnbot-hy2-warp-mark" not in man["hysteria2"]["paths"]
    assert {u["unit"] for u in man["hysteria2"]["units"]} == {
        "vpnbot-hy2-warp-mark.service", "hysteria-server.service", "hysteria-server@.service",
        "vpnbot-hy2-auth.service"}


def test_the_helper_never_calls_userdel_with_r_or_rm_outside_remove_path() -> None:
    code = [ln for ln in HELPER.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if re.search(r"userdel\s+(-\w*r|--remove)", ln)]
    rm_lines = [ln for ln in code if re.search(r"\brm\s+-r", ln)]
    assert all("--one-file-system" in ln or "$STAGE" in ln for ln in rm_lines), rm_lines
