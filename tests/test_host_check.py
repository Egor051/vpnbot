"""scripts/vpn-bot-host-check — the EFFECTIVE host state (docs/host-state.md#effective-state).

Driven against a fake host under tmp_path (``--root``) with every command it runs
replaced by a stub on PATH: sshd -T, systemctl, sysctl, systemd-analyze, dpkg,
dpkg-query, logrotate, ss. The stubs REFUSE (exit 99) anything that is not a read —
`systemctl show` only, `sysctl -n` / `--version` / `--system --dry-run` only — so the
read-only promise is enforced, not just hoped for; and nothing outside tmp_path is
read or written. Pinned here:

1. sshd: first value wins, Include in place (glob, C order, relative to /etc/ssh),
   the main file a setter like any other, Match excluded and listed, the aliases;
   the relay case (00- no / 50- yes -> LATENT; 00- renamed 60- -> BEATEN).
2. sysctl: last value wins in the boot order (systemd-analyze cat-config), the
   `sysctl --system` order measured with --dry-run (fallback without it), the
   vendor rule (an unmodified conffile is no LATENT, a modified one is).
3. systemd *.conf: journald drop-in with a higher number -> BEATEN.
4. Units: shadowed FragmentPath, NeedDaemonReload=yes, a disabled timer, our drop-in
   missing from DropInPaths, a foreign drop-in.
5. invariants.list probes (path-regular on a symlink, unit-prop "~token", ...) and
   accepted-overrides.list (silences exactly its row; malformed lines reported).
6. WARN checks: cloud-init, logrotate ("error:" lines only, never the substring),
   NOPASSWD: ALL, login accounts — never a key or a hash in the output.
7. --pre-install: the repo files in place, retired ones gone, live values PENDING.
8. Autocover: every key of every repo sysctl/ssh/journald/resolved file of a role is
   judged — derived from the real MANAGED_HOST_FILES, so a new file is covered by
   adding it. The real invariants.list and accepted-overrides.list are well-formed.
9. The state file: atomic, 0644, valid JSON, nothing else written.
10. The .env readers and the gate evaluation are deploy.sh's.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts" / "vpn-bot-host-check"
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
INVARIANTS = ROOT / "deploy" / "host" / "invariants.list"
ACCEPTED = ROOT / "deploy" / "host" / "accepted-overrides.list"

pytestmark = pytest.mark.timeout(60)


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()  # noqa: S324 — dpkg's own digest


# --------------------------------------------------------------------------- #
# Stubs: a systemd/procps/openssh/dpkg emulation over $HC_ROOT. Reads only.
# --------------------------------------------------------------------------- #
SYSTEMD_ANALYZE = r"""
echo "systemd-analyze $*" >> "$LOGS/systemd-analyze.log"
[[ "$1" == cat-config ]] || { echo "REFUSED: systemd-analyze $*" >&2; exit 99; }
what="$2"; main=""
case "$what" in
  sysctl.d) dirs=(/etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d) ;;
  systemd/*.conf)
    x="${what#systemd/}"; x="${x%.conf}"
    dirs=("/etc/systemd/$x.conf.d" "/run/systemd/$x.conf.d" "/usr/local/lib/systemd/$x.conf.d" "/usr/lib/systemd/$x.conf.d")
    if [[ -e "$HC_ROOT/etc/systemd/$x.conf" ]]; then main="/etc/systemd/$x.conf"
    elif [[ -e "$HC_ROOT/usr/lib/systemd/$x.conf" ]]; then main="/usr/lib/systemd/$x.conf"; fi ;;
  *) exit 1 ;;
esac
declare -A byb=()
for d in "${dirs[@]}"; do
  for f in "$HC_ROOT$d"/*.conf; do
    [[ -e "$f" || -L "$f" ]] || continue
    b="${f##*/}"; [[ -n "${byb[$b]+x}" ]] && continue
    byb[$b]="${f#"$HC_ROOT"}"
  done
done
files=(); [[ -n "$main" ]] && files+=("$main")
while IFS= read -r b; do
  [[ -n "$b" ]] || continue
  f="${byb[$b]}"
  [[ "$(readlink "$HC_ROOT$f" 2>/dev/null)" == /dev/null ]] && continue
  files+=("$f")
done < <(printf '%s\n' "${!byb[@]}" | LC_ALL=C sort)
first=1
for f in "${files[@]}"; do (( first )) || echo; first=0; echo "# $f"; cat "$HC_ROOT$f"; done
"""

SYSCTL = r"""
echo "sysctl $*" >> "$LOGS/sysctl.log"
case "$1" in
  --version) cat "$SD/sysctl_version" 2>/dev/null || echo "sysctl from procps-ng 4.0.4"; exit 0 ;;
  --system)
    [[ "${2:-}" == --dry-run ]] || { echo "REFUSED: sysctl --system without --dry-run" >&2; exit 99; }
    while IFS= read -r f; do [[ "$f" == "# /"* ]] && echo "* Applying ${f#\# } ..."; done < <(systemd-analyze cat-config sysctl.d)
    [[ -e "$HC_ROOT/etc/sysctl.conf" ]] && echo "* Applying /etc/sysctl.conf ..."
    exit 0 ;;
  -n) [[ -f "$SD/live/$2" ]] || exit 255; cat "$SD/live/$2"; exit 0 ;;
esac
echo "REFUSED: sysctl $*" >&2; exit 99
"""

SSHD = r"""
echo "sshd $*" >> "$LOGS/sshd.log"
[[ "$1" == -T ]] || { echo "REFUSED: sshd $*" >&2; exit 99; }
[[ -f "$SD/sshd_T_fail" ]] && { echo "Missing privilege separation directory: /run/sshd"; exit 255; }
cat "$SD/sshd_T" 2>/dev/null; exit 0
"""

SYSTEMCTL = r"""
echo "systemctl $*" >> "$LOGS/systemctl.log"
[[ "$1" == show ]] || { echo "REFUSED: systemctl $*" >&2; exit 99; }
shift; props=(); unit=""
while (( $# )); do case "$1" in -p) props+=("$2"); shift 2 ;; --) unit="$2"; shift 2 ;; *) unit="$1"; shift ;; esac; done
f="$SD/units/$unit"
for p in "${props[@]}"; do
  if [[ -f "$f" ]]; then grep -E "^${p}=" "$f" || true
  elif [[ "$p" == LoadState ]]; then echo "LoadState=not-found"; fi
done
exit 0
"""

DPKG = r"""
echo "dpkg $*" >> "$LOGS/dpkg.log"
[[ "$1" == -S ]] || { echo "REFUSED: dpkg $*" >&2; exit 99; }
shift; rc=1
for p in "$@"; do
  l="$(grep -E ": ${p}$" "$SD/dpkg_owned" 2>/dev/null)"
  if [[ -n "$l" ]]; then echo "$l"; rc=0; else echo "dpkg-query: no path found matching pattern $p" >&2; fi
done
exit $rc
"""

DPKG_QUERY = r"""
echo "dpkg-query $*" >> "$LOGS/dpkg-query.log"
[[ "$1" == -W ]] || { echo "REFUSED: dpkg-query $*" >&2; exit 99; }
cat "$SD/conffiles" 2>/dev/null; exit 0
"""

LOGROTATE = r"""
echo "logrotate $*" >> "$LOGS/logrotate.log"
[[ "$1" == -d ]] || { echo "REFUSED: logrotate $*" >&2; exit 99; }
cat "$SD/logrotate_out" 2>/dev/null; exit 0
"""

SS = r"""
echo "ss $*" >> "$LOGS/ss.log"
cat "$SD/ss" 2>/dev/null; exit 0
"""

EMPTY_INVARIANTS = "# no invariants in this fixture\n"


@dataclass
class Result:
    rc: int
    out: str
    err: str
    rows: list[tuple[str, str, str, str, str]]
    summary: dict[str, str]

    def verdicts(self, verdict: str) -> list[tuple[str, str, str, str, str]]:
        return [r for r in self.rows if r[0] == verdict]

    def find(self, verdict: str, family: str, key: str, path: str | None = None) -> list[tuple[str, str, str, str, str]]:
        return [r for r in self.rows if r[:3] == (verdict, family, key) and (path is None or r[3] == path)]

    def keys(self, verdict: str, family: str) -> set[str]:
        return {r[2] for r in self.rows if r[0] == verdict and r[1] == family}


class HostLab:
    """A fake host (tmp/root), a fake checkout (tmp/repo) and the stubs."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.repo = tmp / "repo"
        self.stub = tmp / "stub"
        self.sd = tmp / "sd"
        self.logs = tmp / "logs"
        for d in (self.root, self.repo, self.stub, self.sd / "units", self.sd / "live", self.logs):
            d.mkdir(parents=True, exist_ok=True)
        for name, body in (("systemd-analyze", SYSTEMD_ANALYZE), ("sysctl", SYSCTL), ("sshd", SSHD),
                           ("systemctl", SYSTEMCTL), ("dpkg", DPKG), ("dpkg-query", DPKG_QUERY),
                           ("logrotate", LOGROTATE), ("ss", SS)):
            _stub(self.stub / name, body)
        self.registry: list[str] = []
        self.owned: list[str] = []
        self.conffiles: dict[str, list[str]] = {}
        self.host("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
        (self.root / "etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
        self.repo_file("deploy/host/invariants.list", EMPTY_INVARIANTS)
        self.env = self.tmp / "dot.env"
        self.env.write_text("", encoding="utf-8")

    # --- fixtures -----------------------------------------------------------
    def host(self, rel: str, content: str, mode: int = 0o644) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        p.chmod(mode)
        return p

    def link(self, rel: str, target: str) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink() or p.exists():
            p.unlink()
        p.symlink_to(target)
        return p

    def repo_file(self, rel: str, content: str) -> Path:
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def add(self, cls: str, dst: str, content: str, *, role: str = "main", installed: bool = True,
            src: str | None = None, opts: str = "") -> None:
        """A registry entry, its repo copy and (installed=True) the host copy."""
        src = src or f"deploy/host/{cls}/{Path(dst).name}"
        self.repo_file(src, content)
        if installed:
            self.host(dst.lstrip("/"), content)
        self.registry.append(f"{src}|{dst}|0644|root:root|{cls}|{role}" + (f"|{opts}" if opts else ""))

    def retire(self, dst: str, role: str = "main") -> None:
        self.registry.append(f"-|{dst}|-|-|absent|{role}")

    def sshd_t(self, **values: str) -> None:
        (self.sd / "sshd_T").write_text("".join(f"{k} {v}\n" for k, v in values.items()), encoding="utf-8")

    def live(self, key: str, value: str) -> None:
        (self.sd / "live" / key).write_text(value + "\n", encoding="utf-8")

    def unit(self, name: str, **props: str) -> None:
        lines = [f"{k}={v}" for k, v in props.items()]
        (self.sd / "units" / name).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def package_file(self, pkg: str, path: str, *, conffile: bool = True, modified: bool = False) -> None:
        """Owned by <pkg>; as a conffile its dpkg md5 is the file's (or not: modified)."""
        self.owned.append(f"{pkg}: {path}")
        if conffile:
            digest = "0" * 32 if modified else _md5(self.root / path.lstrip("/"))
            self.conffiles.setdefault(pkg, []).append(f" {path} {digest}")

    def flag(self, name: str, content: str = "") -> None:
        (self.sd / name).write_text(content, encoding="utf-8")

    # --- running ----------------------------------------------------------
    def run(self, *extra: str, role: str = "main", registry: bool = True, state: Path | None = None,
            repo: Path | None = None) -> Result:
        (self.sd / "dpkg_owned").write_text("".join(f"{x}\n" for x in self.owned), encoding="utf-8")
        (self.sd / "conffiles").write_text(
            "".join(f"{pkg}\n" + "".join(f"{c}\n" for c in cs) for pkg, cs in self.conffiles.items()),
            encoding="utf-8")
        args = ["bash", str(CHECK), "--repo", str(repo or self.repo), "--role", role,
                "--root", str(self.root), "--env", str(self.env)]
        if registry:
            reg = self.tmp / "registry"
            reg.write_text("".join(f"{e}\n" for e in self.registry), encoding="utf-8")
            args += ["--registry", str(reg)]
        args += ["--state", str(state)] if state else ["--no-state"]
        args += list(extra)
        env = {"PATH": f"{self.stub}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(self.tmp),
               "SD": str(self.sd), "LOGS": str(self.logs), "HC_ROOT": str(self.root), "LANG": "C.UTF-8"}
        proc = subprocess.run(args, cwd=str(self.tmp), env=env, capture_output=True, text=True, check=False)
        rows: list[tuple[str, str, str, str, str]] = []
        summary: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            if line.startswith("SUMMARY|"):
                summary = dict(f.split("=", 1) for f in line.split("|")[1:])
            elif "|" in line:
                v, fam, key, path, text = line.split("|", 4)
                rows.append((v, fam, key, path, text))
        return Result(proc.returncode, proc.stdout, proc.stderr, rows, summary)

    def log(self, name: str) -> list[str]:
        p = self.logs / f"{name}.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


RELAY_KEYONLY = (ROOT / "deploy/host/ssh/00-vpnrelay-keyonly.conf").read_text(encoding="utf-8")
RELAY_SSHD_T = {"pubkeyauthentication": "yes", "passwordauthentication": "no",
                "kbdinteractiveauthentication": "no", "permitrootlogin": "without-password"}


def _relay_lab(tmp_path: Path) -> HostLab:
    lab = HostLab(tmp_path)
    lab.add("ssh", "/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf", RELAY_KEYONLY, role="relay",
            src="deploy/host/ssh/00-vpnrelay-keyonly.conf")
    lab.sshd_t(**RELAY_SSHD_T)
    return lab


# --------------------------------------------------------------------------- #
# 1. sshd
# --------------------------------------------------------------------------- #
def test_relay_case_a_cloud_init_yes_behind_our_no_is_latent(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    res = lab.run(role="relay")
    assert res.rc == 0, res.out + res.err
    assert res.find("OK", "sshd", "passwordauthentication")
    latent = res.find("LATENT", "sshd", "passwordauthentication", "/etc/ssh/sshd_config.d/50-cloud-init.conf")
    assert len(latent) == 1, res.out
    text = latent[0][4]
    assert "winner /etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf:3 = no" in text
    assert "winner gone -> yes from /etc/ssh/sshd_config.d/50-cloud-init.conf" in text
    assert res.summary["beaten"] == "0" and res.summary["mismatch"] == "0"


def test_relay_case_renamed_behind_cloud_init_is_beaten(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("ssh", "/etc/ssh/sshd_config.d/60-vpnrelay-keyonly.conf", RELAY_KEYONLY, role="relay",
            src="deploy/host/ssh/00-vpnrelay-keyonly.conf")
    lab.host("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    lab.sshd_t(**{**RELAY_SSHD_T, "passwordauthentication": "yes"})
    res = lab.run(role="relay")
    assert res.rc == 1, res.out
    beaten = res.find("BEATEN", "sshd", "passwordauthentication", "/etc/ssh/sshd_config.d/50-cloud-init.conf")
    assert beaten and "wins over the repo value no of /etc/ssh/sshd_config.d/60-vpnrelay-keyonly.conf" in beaten[0][4]
    assert not res.find("MISMATCH", "sshd", "passwordauthentication"), "sshd -T agrees with the files"


def test_yes_lines_in_the_main_sshd_config_after_include_are_latent(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"
             "PasswordAuthentication yes\nPermitRootLogin yes\n")
    res = lab.run(role="relay")
    assert res.find("LATENT", "sshd", "passwordauthentication", "/etc/ssh/sshd_config")
    assert res.find("LATENT", "sshd", "permitrootlogin", "/etc/ssh/sshd_config")
    assert res.summary["beaten"] == "0"


def test_a_main_file_line_before_the_include_beats_the_dropin(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config", "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n")
    res = lab.run(role="relay")
    assert res.find("BEATEN", "sshd", "permitrootlogin", "/etc/ssh/sshd_config")


def test_match_blocks_are_excluded_and_listed(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nMatch User backup\n"
             "    PasswordAuthentication yes\n    PermitRootLogin yes\n")
    res = lab.run(role="relay")
    assert not res.verdicts("LATENT") and not res.verdicts("BEATEN"), res.out
    info = res.find("INFO", "sshd", "passwordauthentication", "/etc/ssh/sshd_config:3")
    assert info and "Match" in info[0][4]
    assert res.find("INFO", "sshd", "permitrootlogin", "/etc/ssh/sshd_config:4")


def test_a_match_inside_an_included_file_ends_with_that_file(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("ssh", "/etc/ssh/sshd_config.d/90-keyonly.conf", "PasswordAuthentication no\n",
            src="deploy/host/ssh/90-keyonly.conf")
    lab.host("etc/ssh/sshd_config.d/10-match.conf", "Match User x\n  PasswordAuthentication yes\n")
    lab.sshd_t(passwordauthentication="no")
    res = lab.run()
    assert res.find("OK", "sshd", "passwordauthentication"), "the Match of 10-match.conf does not leak into 90-"
    assert res.find("INFO", "sshd", "passwordauthentication", "/etc/ssh/sshd_config.d/10-match.conf:2")


def test_include_with_a_relative_path_is_relative_to_etc_ssh(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config", "Include sshd_config.d/*.conf\nPasswordAuthentication yes\n")
    res = lab.run(role="relay")
    assert res.find("OK", "sshd", "passwordauthentication"), res.out
    assert res.find("LATENT", "sshd", "passwordauthentication", "/etc/ssh/sshd_config")


def test_include_globs_expand_in_c_order(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("ssh", "/etc/ssh/sshd_config.d/A-ours.conf", "PasswordAuthentication no\n",
            src="deploy/host/ssh/A-ours.conf")
    # C order: upper case before lower case; a locale sort would put a- first.
    lab.host("etc/ssh/sshd_config.d/a-theirs.conf", "PasswordAuthentication yes\n")
    lab.sshd_t(passwordauthentication="no")
    res = lab.run()
    assert res.find("OK", "sshd", "passwordauthentication"), res.out
    assert res.find("LATENT", "sshd", "passwordauthentication", "/etc/ssh/sshd_config.d/a-theirs.conf")


def test_challengeresponse_is_kbdinteractive(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config", "ChallengeResponseAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n")
    res = lab.run(role="relay")
    beaten = res.find("BEATEN", "sshd", "kbdinteractiveauthentication", "/etc/ssh/sshd_config")
    assert beaten, res.out


def test_prohibit_password_is_without_password(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    # Same value under the other spelling: not a loser with another value.
    lab.host("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin without-password\n")
    res = lab.run(role="relay")
    assert res.find("OK", "sshd", "permitrootlogin")
    assert not res.find("LATENT", "sshd", "permitrootlogin"), res.out
    assert not res.find("MISMATCH", "sshd", "permitrootlogin"), "sshd -T prints without-password"


def test_multi_value_keywords_are_not_judged(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config", "Port 22\nInclude /etc/ssh/sshd_config.d/*.conf\nPort 2222\n"
             "AcceptEnv LANG\nAcceptEnv LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n")
    res = lab.run(role="relay")
    judged = {r[2] for r in res.rows if r[1] == "sshd"}
    assert not judged & {"port", "acceptenv", "subsystem"}, judged


def test_sshd_t_disagreeing_with_the_files_is_a_mismatch(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.sshd_t(**{**RELAY_SSHD_T, "passwordauthentication": "yes"})
    res = lab.run(role="relay")
    assert res.rc == 1
    mm = res.find("MISMATCH", "sshd", "passwordauthentication")
    assert mm and "sshd -T says yes, the files give no" in mm[0][4]


def test_a_failing_sshd_t_is_a_warn_not_a_verdict(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.flag("sshd_T_fail")
    res = lab.run(role="relay")
    assert res.rc == 0
    warn = [r for r in res.verdicts("WARN") if r[2] == "sshd -T"]
    assert warn and "Missing privilege separation directory" in warn[0][4]
    assert not res.verdicts("MISMATCH")


# --------------------------------------------------------------------------- #
# 2. sysctl
# --------------------------------------------------------------------------- #
BBR = (ROOT / "deploy/host/sysctl/99-bbr.conf").read_text(encoding="utf-8")


def _bbr_lab(tmp_path: Path) -> HostLab:
    lab = HostLab(tmp_path)
    lab.add("sysctl", "/etc/sysctl.d/99-bbr.conf", BBR, src="deploy/host/sysctl/99-bbr.conf")
    lab.live("net.core.default_qdisc", "fq")
    lab.live("net.ipv4.tcp_congestion_control", "bbr")
    return lab


def test_sysctl_repo_values_in_effect_are_ok(tmp_path: Path) -> None:
    res = _bbr_lab(tmp_path).run()
    assert res.rc == 0, res.out + res.err
    assert res.keys("OK", "sysctl") == {"net.core.default_qdisc", "net.ipv4.tcp_congestion_control"}


def test_a_sysctl_file_named_after_the_repo_file_beats_it(tmp_path: Path) -> None:
    lab = _bbr_lab(tmp_path)
    lab.host("etc/sysctl.d/99-zz-provider.conf", "net.ipv4.tcp_congestion_control = cubic\n")
    lab.live("net.ipv4.tcp_congestion_control", "cubic")
    res = lab.run()
    assert res.rc == 1
    beaten = res.find("BEATEN", "sysctl", "net.ipv4.tcp_congestion_control", "/etc/sysctl.d/99-zz-provider.conf")
    assert beaten and "(the last value wins)" in beaten[0][4]


def test_the_live_value_differing_from_the_files_is_a_mismatch(tmp_path: Path) -> None:
    lab = _bbr_lab(tmp_path)
    lab.live("net.core.default_qdisc", "fq_codel")
    res = lab.run()
    mm = res.find("MISMATCH", "sysctl", "net.core.default_qdisc")
    assert mm and "sysctl -n says fq_codel, the files give fq" in mm[0][4]


def test_repo_value_over_an_unmodified_conffile_is_ok(tmp_path: Path) -> None:
    """The measured case: 99-bbr.conf over procps' stock 10-bufferbloat.conf."""
    lab = _bbr_lab(tmp_path)
    lab.host("etc/sysctl.d/10-bufferbloat.conf", "net.core.default_qdisc = fq_codel\n")
    lab.package_file("procps", "/etc/sysctl.d/10-bufferbloat.conf")
    res = lab.run()
    assert not res.verdicts("LATENT"), res.out
    assert res.find("OK", "sysctl", "net.core.default_qdisc")


def test_repo_value_over_a_modified_conffile_is_latent(tmp_path: Path) -> None:
    lab = _bbr_lab(tmp_path)
    lab.host("etc/sysctl.d/10-bufferbloat.conf", "net.core.default_qdisc = fq_codel\n")
    lab.package_file("procps", "/etc/sysctl.d/10-bufferbloat.conf", modified=True)
    res = lab.run()
    latent = res.find("LATENT", "sysctl", "net.core.default_qdisc", "/etc/sysctl.d/10-bufferbloat.conf")
    assert latent and "winner gone -> fq_codel from /etc/sysctl.d/10-bufferbloat.conf" in latent[0][4]


def test_a_provider_file_over_an_unmodified_conffile_is_not_latent(tmp_path: Path) -> None:
    """The other measured case: 99-cloudimg-ipv6.conf over procps' 10-ipv6-privacy.conf."""
    lab = HostLab(tmp_path)
    lab.host("etc/sysctl.d/10-ipv6-privacy.conf", "net.ipv6.conf.all.use_tempaddr = 2\n")
    lab.host("etc/sysctl.d/99-cloudimg-ipv6.conf", "net.ipv6.conf.all.use_tempaddr = 0\n")
    lab.package_file("procps", "/etc/sysctl.d/10-ipv6-privacy.conf")
    res = lab.run()
    assert not res.verdicts("LATENT"), res.out
    assert len([ln for ln in lab.log("dpkg") if ln.startswith("dpkg -S")]) == 1, "one batched dpkg -S"


def test_a_loser_under_usr_lib_is_vendor(tmp_path: Path) -> None:
    lab = _bbr_lab(tmp_path)
    lab.host("usr/lib/sysctl.d/50-default.conf", "net.core.default_qdisc = fq_codel\n")
    res = lab.run()
    assert not res.verdicts("LATENT"), res.out


def test_a_foreign_loser_between_two_foreign_files_is_latent(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.host("etc/sysctl.d/10-mine.conf", "vm.swappiness = 60\n")
    lab.host("etc/sysctl.d/90-theirs.conf", "vm.swappiness = 1\n")
    res = lab.run()
    assert res.find("LATENT", "sysctl", "vm.swappiness", "/etc/sysctl.d/10-mine.conf")


def test_etc_sysctl_conf_winning_at_sysctl_system_is_latent(tmp_path: Path) -> None:
    """/etc/sysctl.conf is applied once more at the very end of `sysctl --system`,
    although systemd-sysctl reads it as 99-sysctl.conf in basename order at boot."""
    lab = HostLab(tmp_path)
    lab.add("sysctl", "/etc/sysctl.d/99-vpn-forwarding.conf", "net.ipv4.ip_forward=1\n",
            src="deploy/host/sysctl/99-vpn-forwarding.conf")
    lab.host("etc/sysctl.conf", "net.ipv4.ip_forward = 0\n")
    lab.link("etc/sysctl.d/99-sysctl.conf", "../sysctl.conf")
    lab.live("net.ipv4.ip_forward", "1")
    res = lab.run()
    assert res.find("OK", "sysctl", "net.ipv4.ip_forward"), res.out
    latent = res.find("LATENT", "sysctl", "net.ipv4.ip_forward", "/etc/sysctl.conf")
    assert latent, res.out
    assert "after `sysctl --system` /etc/sysctl.conf:1 = 0 wins" in latent[0][4]
    assert "measured with sysctl --system --dry-run" in latent[0][4]
    assert "sysctl --system --dry-run" in lab.log("sysctl")


def test_without_dry_run_the_system_order_is_assumed_and_said_so(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("sysctl", "/etc/sysctl.d/99-vpn-forwarding.conf", "net.ipv4.ip_forward=1\n",
            src="deploy/host/sysctl/99-vpn-forwarding.conf")
    lab.host("etc/sysctl.conf", "net.ipv4.ip_forward = 0\n")
    lab.live("net.ipv4.ip_forward", "1")
    lab.flag("sysctl_version", "sysctl from procps-ng 3.3.17\n")
    res = lab.run()
    assert not any("--system" in c for c in lab.log("sysctl")), "never sysctl --system on an old procps"
    note = res.find("INFO", "sysctl", "sysctl --system")
    assert note and "NOT measured" in note[0][4]
    latent = res.find("LATENT", "sysctl", "net.ipv4.ip_forward", "/etc/sysctl.conf")
    assert latent and "NOT measured" in latent[0][4]


@pytest.mark.parametrize(("line", "key"), [
    ("net/ipv4/ip_forward = 1", "net.ipv4.ip_forward"),
    ("-net.ipv4.ip_forward = 1", "net.ipv4.ip_forward"),
])
def test_sysctl_key_normalisation(tmp_path: Path, line: str, key: str) -> None:
    lab = HostLab(tmp_path)
    lab.add("sysctl", "/etc/sysctl.d/99-f.conf", "net.ipv4.ip_forward = 1\n", src="deploy/host/sysctl/99-f.conf")
    lab.host("etc/sysctl.d/99-zz.conf", line.replace("= 1", "= 0") + "\n")
    lab.live(key, "0")
    res = lab.run()
    assert res.find("BEATEN", "sysctl", key, "/etc/sysctl.d/99-zz.conf"), res.out


def test_value_whitespace_is_collapsed_and_glob_keys_are_not_read_live(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("sysctl", "/etc/sysctl.d/99-b.conf", "net.ipv4.tcp_rmem = 4096  1048576\t16777216\n"
            "net.ipv4.conf.*.rp_filter = 2\n", src="deploy/host/sysctl/99-b.conf")
    lab.live("net.ipv4.tcp_rmem", "4096\t1048576\t16777216")
    res = lab.run()
    assert res.find("OK", "sysctl", "net.ipv4.tcp_rmem")
    assert not res.verdicts("MISMATCH"), res.out
    glob = res.find("INFO", "sysctl", "net.ipv4.conf.*.rp_filter")
    assert glob and "glob key" in glob[0][4]
    assert not any("rp_filter" in c for c in lab.log("sysctl"))


# --------------------------------------------------------------------------- #
# 3. systemd *.conf
# --------------------------------------------------------------------------- #
JOURNALD = (ROOT / "deploy/host/journald/10-vpn-bot.conf").read_text(encoding="utf-8")
RESOLVED = (ROOT / "deploy/host/resolved/10-vpn-bot.conf").read_text(encoding="utf-8")


def test_a_journald_dropin_numbered_after_ours_beats_it(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("journald", "/etc/systemd/journald.conf.d/10-vpn-bot.conf", JOURNALD,
            src="deploy/host/journald/10-vpn-bot.conf")
    lab.host("etc/systemd/journald.conf", "[Journal]\n#SystemMaxUse=\n")
    lab.host("etc/systemd/journald.conf.d/20-provider.conf", "[Journal]\nSystemMaxUse=2G\n")
    res = lab.run()
    assert res.rc == 1
    assert res.find("BEATEN", "journald", "Journal.SystemMaxUse", "/etc/systemd/journald.conf.d/20-provider.conf")


def test_a_modified_main_conf_with_the_same_value_is_not_latent_but_reported(tmp_path: Path) -> None:
    """main today: journald.conf carries SystemMaxUse=500M by hand, duplicating the drop-in."""
    lab = HostLab(tmp_path)
    lab.add("journald", "/etc/systemd/journald.conf.d/10-vpn-bot.conf", JOURNALD,
            src="deploy/host/journald/10-vpn-bot.conf")
    lab.host("etc/systemd/journald.conf", "[Journal]\nSystemMaxUse=500M\n")
    lab.package_file("systemd", "/etc/systemd/journald.conf", modified=True)
    res = lab.run()
    assert res.find("OK", "journald", "Journal.SystemMaxUse")
    assert not res.verdicts("LATENT"), res.out
    warn = res.find("WARN", "conffile", "systemd", "/etc/systemd/journald.conf")
    assert warn and "sets: Journal.SystemMaxUse" in warn[0][4]


def test_resolved_dropin_over_the_modified_conffile(tmp_path: Path) -> None:
    """main today: DNS=/FallbackDNS= only in a modified resolved.conf; the drop-in takes them over."""
    lab = HostLab(tmp_path)
    lab.add("resolved", "/etc/systemd/resolved.conf.d/10-vpn-bot.conf", RESOLVED,
            src="deploy/host/resolved/10-vpn-bot.conf")
    lab.host("etc/systemd/resolved.conf", "[Resolve]\nDNS=1.1.1.1 8.8.8.8\nFallbackDNS=1.0.0.1 8.8.4.4\n")
    lab.package_file("systemd-resolved", "/etc/systemd/resolved.conf", modified=True)
    res = lab.run()
    assert res.keys("OK", "resolved") == {"Resolve.DNS", "Resolve.FallbackDNS"}
    assert not res.verdicts("LATENT") and res.rc == 0, res.out
    warn = res.find("WARN", "conffile", "systemd-resolved", "/etc/systemd/resolved.conf")
    assert warn and "Resolve.DNS" in warn[0][4] and "Resolve.FallbackDNS" in warn[0][4]


# --------------------------------------------------------------------------- #
# 4. Units
# --------------------------------------------------------------------------- #
TIMER = (ROOT / "deploy/host/systemd/even-day-reboot.timer").read_text(encoding="utf-8")
SERVICE = (ROOT / "deploy/host/systemd/even-day-reboot.service").read_text(encoding="utf-8")


def _unit_lab(tmp_path: Path) -> HostLab:
    lab = HostLab(tmp_path)
    lab.add("unit", "/etc/systemd/system/even-day-reboot.service", SERVICE, src="deploy/host/systemd/even-day-reboot.service")
    lab.add("unit", "/etc/systemd/system/even-day-reboot.timer", TIMER, src="deploy/host/systemd/even-day-reboot.timer")
    for name, ufs, act in (("even-day-reboot.service", "static", "inactive"), ("even-day-reboot.timer", "enabled", "active")):
        lab.unit(name, LoadState="loaded", FragmentPath=f"/etc/systemd/system/{name}", NeedDaemonReload="no",
                 DropInPaths="", UnitFileState=ufs, ActiveState=act)
    return lab


def test_units_in_effect_are_ok(tmp_path: Path) -> None:
    res = _unit_lab(tmp_path).run()
    assert res.rc == 0, res.out
    assert res.keys("OK", "unit") == {"even-day-reboot.service", "even-day-reboot.timer"}


def test_a_shadowed_fragment_is_beaten(tmp_path: Path) -> None:
    lab = _unit_lab(tmp_path)
    lab.unit("even-day-reboot.service", LoadState="loaded", FragmentPath="/run/systemd/system/even-day-reboot.service",
             NeedDaemonReload="no", DropInPaths="")
    res = lab.run()
    beaten = res.find("BEATEN", "unit", "even-day-reboot.service")
    assert beaten and "from /run/systemd/system/even-day-reboot.service" in beaten[0][4]


def test_need_daemon_reload_is_a_mismatch(tmp_path: Path) -> None:
    lab = _unit_lab(tmp_path)
    lab.unit("even-day-reboot.service", LoadState="loaded", FragmentPath="/etc/systemd/system/even-day-reboot.service",
             NeedDaemonReload="yes", DropInPaths="")
    res = lab.run()
    mm = res.find("MISMATCH", "unit", "even-day-reboot.service")
    assert mm and "NeedDaemonReload=yes" in mm[0][4]


@pytest.mark.parametrize(("ufs", "act"), [("disabled", "inactive"), ("enabled", "inactive"), ("disabled", "active")])
def test_a_timer_not_enabled_and_active_is_a_mismatch(tmp_path: Path, ufs: str, act: str) -> None:
    lab = _unit_lab(tmp_path)
    lab.unit("even-day-reboot.timer", LoadState="loaded", FragmentPath="/etc/systemd/system/even-day-reboot.timer",
             NeedDaemonReload="no", DropInPaths="", UnitFileState=ufs, ActiveState=act)
    res = lab.run()
    mm = res.find("MISMATCH", "unit", "even-day-reboot.timer")
    assert mm and f"timer is {ufs}/{act}" in mm[0][4]


def test_a_masked_unit_is_beaten(tmp_path: Path) -> None:
    lab = _unit_lab(tmp_path)
    lab.unit("even-day-reboot.timer", LoadState="masked")
    assert lab.run().find("BEATEN", "unit", "even-day-reboot.timer")


def test_our_dropin_missing_from_dropinpaths_is_beaten_a_foreign_one_latent(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("ssh", "/etc/systemd/system/ssh.socket.d/override.conf", "[Socket]\nListenStream=\nListenStream=54321\n",
            src="deploy/host/ssh/ssh.socket-override.conf")
    lab.unit("ssh.socket", LoadState="loaded", NeedDaemonReload="no",
             DropInPaths="/run/systemd/system/ssh.socket.d/override.conf /run/systemd/generator/ssh.socket.d/addresses.conf "
                         "/usr/lib/systemd/system/socket.d/10-vendor.conf")
    res = lab.run()
    beaten = res.find("BEATEN", "unit", "ssh.socket", "/etc/systemd/system/ssh.socket.d/override.conf")
    assert beaten and "a same-named drop-in elsewhere shadows it" in beaten[0][4]
    latent = {r[3] for r in res.find("LATENT", "unit", "ssh.socket")}
    assert latent == {"/run/systemd/system/ssh.socket.d/override.conf",
                      "/run/systemd/generator/ssh.socket.d/addresses.conf"}, "the /usr/lib drop-in is vendor"


def test_our_dropin_merged_is_ok(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("ssh", "/etc/systemd/system/ssh.socket.d/override.conf", "[Socket]\nListenStream=54321\n",
            src="deploy/host/ssh/ssh.socket-override.conf")
    lab.unit("ssh.socket", LoadState="loaded", NeedDaemonReload="no",
             DropInPaths="/etc/systemd/system/ssh.socket.d/override.conf")
    res = lab.run()
    assert res.find("OK", "unit", "ssh.socket", "/etc/systemd/system/ssh.socket.d/override.conf"), res.out
    assert not res.verdicts("LATENT")


def test_relay_unit_set_is_deploy_relay_and_never_an_example(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.repo_file("deploy/relay/vpn-relay.service", "[Service]\n")
    lab.repo_file("deploy/relay/x.example.service", "[Service]\n")
    lab.repo_file("deploy/vpn-bot.service", "[Service]\n")
    lab.host("etc/systemd/system/vpn-relay.service", "[Service]\n")
    lab.unit("vpn-relay.service", LoadState="loaded", FragmentPath="/etc/systemd/system/vpn-relay.service",
             NeedDaemonReload="no", DropInPaths="")
    res = lab.run(role="relay")
    assert {r[2] for r in res.rows if r[1] == "unit"} == {"vpn-relay.service"}, res.out
    shown = [ln.split()[-1] for ln in lab.log("systemctl")]
    assert "x.example.service" not in shown and "vpn-bot.service" not in shown


def test_main_unit_set_has_the_bot_unit_and_the_shipped_ones_present(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.repo_file("deploy/vpn-bot.service", "[Service]\n")
    lab.repo_file("deploy/warp-routes.service", "[Service]\n")
    lab.repo_file("deploy/not-installed.service", "[Service]\n")
    lab.repo_file("deploy/vpn-bot.nonroot.example.service", "[Service]\n")
    lab.host("etc/systemd/system/vpn-bot.service", "[Service]\n")
    lab.host("etc/systemd/system/warp-routes.service", "[Service]\n")
    for name in ("vpn-bot.service", "warp-routes.service"):
        lab.unit(name, LoadState="loaded", FragmentPath=f"/etc/systemd/system/{name}", NeedDaemonReload="no",
                 DropInPaths="")
    res = lab.run()
    assert res.keys("OK", "unit") == {"vpn-bot.service", "warp-routes.service"}, res.out
    assert not [r for r in res.rows if "not-installed" in r[2] or "example" in r[2]]


# --------------------------------------------------------------------------- #
# 5. invariants.list and accepted-overrides.list
# --------------------------------------------------------------------------- #
def test_path_regular_on_a_symlink_is_a_mismatch(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.repo_file("deploy/host/invariants.list",
                  "main|path-regular|/etc/resolv.conf|-|resolv.conf must be a plain file, not a stub symlink\n")
    lab.link("etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
    res = lab.run()
    assert res.rc == 1
    mm = res.find("MISMATCH", "invariant", "path-regular /etc/resolv.conf")
    assert mm and "expected regular, found symlink -> ../run/systemd/resolve/stub-resolv.conf" in mm[0][4]
    lab.link("etc/resolv.conf", "x")
    (lab.root / "etc/resolv.conf").unlink()
    lab.host("etc/resolv.conf", "nameserver 1.1.1.1\n")
    assert lab.run().find("OK", "invariant", "path-regular /etc/resolv.conf")


def test_unit_prop_contains_a_whole_token(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.repo_file("deploy/host/invariants.list",
                  "relay|unit-prop:ssh.socket:Listen|-|~22|the relay is managed through sshd on 22 only\n")
    lab.unit("ssh.socket", Listen="0.0.0.0:2222 (Stream)")
    assert lab.run(role="relay").find("MISMATCH", "invariant", "unit-prop:ssh.socket:Listen")
    lab.unit("ssh.socket", Listen="0.0.0.0:22 (Stream)\nListen=[::]:22 (Stream)")
    res = lab.run(role="relay")
    ok = res.find("OK", "invariant", "unit-prop:ssh.socket:Listen")
    assert ok and ok[0][4] == "0.0.0.0:22 (Stream) [::]:22 (Stream)"


def test_invariant_roles_and_the_other_probes(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("resolved", "/etc/systemd/resolved.conf.d/10-vpn-bot.conf", RESOLVED,
            src="deploy/host/resolved/10-vpn-bot.conf")
    lab.repo_file("deploy/host/invariants.list", "\n".join([
        "all|path-present|/etc/cloud/cloud-init.disabled|-|cloud-init stays off on every host",
        "relay|path-present|/etc/relay-only|-|a relay-only line must not reach a main host",
        "main|path-absent|/etc/sudoers.d/90-cloud-init-users|-|cloud-init's sudoers grant must not come back",
        "main|systemd-conf:resolved|Resolve.DNS|1.1.1.1 8.8.8.8|the main server's upstream resolvers",
        "main|tcp-listen:54321|-|-|ssh listens on 54321 on the main server",
        "main|sysctl|net.ipv4.ip_forward|1|the main server routes the VPN clients",
        "main|sshd|PermitRootLogin|prohibit-password|root logs in with a key only",
    ]) + "\n")
    lab.host("etc/cloud/cloud-init.disabled", "")
    lab.live("net.ipv4.ip_forward", "1")
    lab.sshd_t(permitrootlogin="without-password")
    lab.flag("ss", "LISTEN 0 128 0.0.0.0:54321 0.0.0.0:*\n")
    res = lab.run()
    assert not res.verdicts("MISMATCH") and not res.verdicts("WARN"), res.out
    assert len(res.verdicts("OK")) == 2 + 6, res.out
    assert not [r for r in res.rows if "relay-only" in r[2]]
    lab.flag("ss", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
    assert lab.run().find("MISMATCH", "invariant", "tcp-listen:54321")


def test_accepted_overrides_silence_exactly_their_row(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin yes\n")
    lab.repo_file("deploy/host/accepted-overrides.list",
                  "# comment\n/etc/ssh/sshd_config|permitrootlogin|the provider console needs it, ticket 42 (2026-11)\n"
                  "/etc/elsewhere.conf|vm.swappiness|another role's override, kept for that host\n")
    res = lab.run(role="relay")
    assert res.find("ACCEPTED", "sshd", "permitrootlogin", "/etc/ssh/sshd_config")
    assert "the provider console needs it" in res.find("ACCEPTED", "sshd", "permitrootlogin")[0][4]
    assert res.find("LATENT", "sshd", "passwordauthentication", "/etc/ssh/sshd_config"), "only its own row"
    assert res.summary["latent"] == "1" and res.summary["accepted"] == "1"
    assert res.find("INFO", "accepted", "vm.swappiness", "/etc/elsewhere.conf"), "an entry that matches nothing is said"


@pytest.mark.parametrize("line", [
    "relative/path|key|a reason long enough to pass",
    "/etc/x||a reason long enough to pass",
    "/etc/x|key|too short",
])
def test_a_malformed_accepted_line_is_reported_and_ignored(tmp_path: Path, line: str) -> None:
    lab = _relay_lab(tmp_path)
    lab.repo_file("deploy/host/accepted-overrides.list", line + "\n")
    res = lab.run(role="relay")
    warn = res.find("WARN", "accepted", "line 1")
    assert warn and "malformed" in warn[0][4]
    assert not res.verdicts("ACCEPTED")


@pytest.mark.parametrize("line", [
    "main|nonsense|-|-|a reason long enough to pass",
    "main|path-present|/etc/x|-|short",
    "both|path-present|/etc/x|-|a reason long enough to pass",
    "main|path-present|/etc/x|-",
    "main|exec:rm -rf /|-|-|a reason long enough to pass",
])
def test_a_malformed_invariant_line_is_reported_and_ignored(tmp_path: Path, line: str) -> None:
    lab = HostLab(tmp_path)
    lab.repo_file("deploy/host/invariants.list", line + "\n")
    res = lab.run()
    warn = res.find("WARN", "invariant", "line 1")
    assert warn and "malformed" in warn[0][4], res.out
    assert not [r for r in res.rows if r[1] == "invariant" and r[0] != "WARN"]


# --------------------------------------------------------------------------- #
# 6. WARN checks
# --------------------------------------------------------------------------- #
def test_cloud_init_alive_is_a_warn(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    (lab.root / "etc/cloud").mkdir(parents=True)
    assert lab.run().find("WARN", "cloud-init", "cloud-init")
    lab.host("etc/cloud/cloud-init.disabled", "")
    assert not lab.run().find("WARN", "cloud-init", "cloud-init")


def test_logrotate_error_log_paths_are_clean(tmp_path: Path) -> None:
    """The false positive of the 2026-11-11 sweep: "error" inside a path."""
    lab = HostLab(tmp_path)
    lab.host("etc/logrotate.conf", "include /etc/logrotate.d\n")
    lab.flag("logrotate_out", "reading config file /etc/logrotate.d/nginx\n"
                              "considering log /var/log/nginx/error.log\n  log does not need rotating\n"
                              "rotating pattern: /var/log/xray/error.log  after 1 days\n")
    res = lab.run()
    assert not res.find("WARN", "logrotate", "logrotate -d"), res.out
    assert lab.log("logrotate") == [f"logrotate -d {lab.root}/etc/logrotate.conf"]


def test_logrotate_error_lines_and_duplicates_are_warns(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.host("etc/logrotate.conf", "include /etc/logrotate.d\n")
    lab.flag("logrotate_out", "considering log /var/log/nginx/error.log\n"
                              "error: /etc/logrotate.d/xray:3 unknown option 'BROKEN' -- ignoring line\n"
                              "warning: /etc/logrotate.d/a:1 duplicate log entry for /var/log/a.log\n")
    texts = [r[4] for r in lab.run().find("WARN", "logrotate", "logrotate -d")]
    assert texts == ["error: /etc/logrotate.d/xray:3 unknown option 'BROKEN' -- ignoring line",
                     "warning: /etc/logrotate.d/a:1 duplicate log entry for /var/log/a.log"]


def test_nopasswd_all_and_login_accounts_without_secrets(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.host("etc/sudoers", "root ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n")
    lab.host("etc/sudoers.d/90-cloud-init-users", "# Created by cloud-init\nubuntu ALL=(ALL) NOPASSWD:ALL\n")
    lab.host("etc/sudoers.d/vpn-bot", "vpn-bot ALL=(root) NOPASSWD: /usr/local/sbin/vpn-bot-xray-apply\n")
    lab.host("etc/sudoers.d/README.dpkg-old", "x ALL=(ALL) NOPASSWD: ALL\n")
    lab.host("etc/passwd", "root:x:0:0::/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n"
             "vpn-bot:x:999:999::/var/lib/vpn-bot:/usr/sbin/nologin\nlocked:x:1001:1001::/home/locked:/bin/bash\n")
    lab.host("etc/shells", "/bin/sh\n/bin/bash\n")
    lab.host("etc/shadow", "root:$6$rootsecrethash:1:::::\nubuntu:$6$ubuntusecrethash:1:::::\n"
             "vpn-bot:!:1:::::\nlocked:!$6$lockedhash:1:::::\n")
    lab.host("home/ubuntu/.ssh/authorized_keys", "# a comment\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsecretkeymaterial ubuntu@x\n")
    res = lab.run()
    sudo = res.find("WARN", "sudo", "NOPASSWD: ALL")
    assert [r[3] for r in sudo] == ["/etc/sudoers.d/90-cloud-init-users"], res.out
    assert "grants NOPASSWD: ALL to ubuntu" in sudo[0][4]
    accounts = [r for r in res.rows if r[1] == "account"]
    assert {(r[2], "password" in r[4], "authorized key" in r[4]) for r in accounts} == {
        ("ubuntu", True, False), ("ubuntu", False, True)}
    everything = res.out + res.err
    for secret in ("secrethash", "secretkeymaterial", "AAAAC3", "$6$"):
        assert secret not in everything, f"{secret} leaked into the output"


# --------------------------------------------------------------------------- #
# 7. --pre-install
# --------------------------------------------------------------------------- #
def test_pre_install_judges_the_host_phase2_would_leave(tmp_path: Path) -> None:
    """The relay file is not installed yet and cloud-init's file is retired: in effect
    after Phase 2 — and the 60- name would be BEATEN before anything is installed."""
    lab = HostLab(tmp_path)
    lab.add("ssh", "/etc/ssh/sshd_config.d/00-vpnrelay-keyonly.conf", RELAY_KEYONLY, role="relay",
            src="deploy/host/ssh/00-vpnrelay-keyonly.conf", installed=False)
    lab.retire("/etc/ssh/sshd_config.d/50-cloud-init.conf", role="relay")
    lab.host("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    res = lab.run("--pre-install", role="relay")
    assert res.rc == 0, res.out
    assert res.summary["mode"] == "pre-install"
    assert res.find("OK", "sshd", "passwordauthentication")
    assert not res.verdicts("LATENT"), "the retired file is gone after Phase 2"
    pending = res.keys("PENDING", "sshd")
    assert pending == {"passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin", "pubkeyauthentication"}
    assert lab.log("sshd") == [f"sshd -T -f {lab.root}/etc/ssh/sshd_config"]

    lab.registry = [e.replace("|/etc/ssh/sshd_config.d/00-", "|/etc/ssh/sshd_config.d/60-") for e in lab.registry]
    lab.registry = [e for e in lab.registry if "absent" not in e]
    res = lab.run("--pre-install", role="relay")
    assert res.find("BEATEN", "sshd", "passwordauthentication", "/etc/ssh/sshd_config.d/50-cloud-init.conf"), res.out
    assert not (lab.root / "etc/ssh/sshd_config.d/60-vpnrelay-keyonly.conf").exists(), "nothing installed"


def test_pre_install_inserts_a_new_sysctl_file_in_basename_order(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("sysctl", "/etc/sysctl.d/50-new.conf", "vm.swappiness = 10\n", src="deploy/host/sysctl/50-new.conf",
            installed=False)
    lab.host("etc/sysctl.d/90-later.conf", "vm.swappiness = 60\n")
    lab.live("vm.swappiness", "60")
    res = lab.run("--pre-install")
    assert res.find("BEATEN", "sysctl", "vm.swappiness", "/etc/sysctl.d/90-later.conf"), res.out
    assert not res.verdicts("MISMATCH"), "the live value is the deploy's to change: PENDING"
    assert res.find("PENDING", "sysctl", "vm.swappiness")


def test_pre_install_unit_not_installed_yet_is_pending(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.add("unit", "/etc/systemd/system/vpn-bot-host-check.timer",
            (ROOT / "deploy/host/systemd/vpn-bot-host-check.timer").read_text(encoding="utf-8"),
            src="deploy/host/systemd/vpn-bot-host-check.timer", installed=False)
    res = lab.run("--pre-install")
    assert res.find("PENDING", "unit", "vpn-bot-host-check.timer"), res.out
    assert res.rc == 0
    res = lab.run()
    assert res.find("MISMATCH", "unit", "vpn-bot-host-check.timer"), "installed mode: the repo file is missing"


# --------------------------------------------------------------------------- #
# 8. Autocover + the real lists
# --------------------------------------------------------------------------- #
def _real_registry() -> list[list[str]]:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    body = text[text.index("MANAGED_HOST_FILES=(") :].split("\n)\n", 1)[0].splitlines()[1:]
    return [ln.strip().strip('"').split("|") for ln in body if ln.strip().startswith('"')]


def _expected_keys(role: str) -> set[tuple[str, str]]:
    """Every (family, key) a repo file of this role sets, read here in Python."""
    out: set[tuple[str, str]] = set()
    for e in _real_registry():
        src, dst, cls, erole = e[0], e[1], e[4], e[5]
        if erole != role or cls == "absent":
            continue
        text = (ROOT / src).read_text(encoding="utf-8")
        if dst.startswith("/etc/sysctl.d/"):
            for ln in text.splitlines():
                if "=" in ln and not ln.lstrip().startswith(("#", ";")):
                    out.add(("sysctl", ln.split("=", 1)[0].strip().lstrip("-").strip()))
        elif dst.startswith("/etc/ssh/"):
            for ln in text.splitlines():
                if ln.strip() and not ln.lstrip().startswith("#"):
                    out.add(("sshd", re.split(r"[\s=]+", ln.strip(), maxsplit=1)[0].lower()))
        elif m := re.match(r"^/etc/systemd/([a-z]+)\.conf\.d/", dst):
            section = ""
            for ln in text.splitlines():
                s = ln.strip()
                if s.startswith("[") and s.endswith("]"):
                    section = s[1:-1]
                elif "=" in s and not s.startswith(("#", ";")):
                    out.add((m.group(1), f"{section}.{s.split('=', 1)[0].strip()}"))
    return out


@pytest.mark.parametrize("role", ["main", "relay"])
def test_every_key_of_every_repo_file_is_judged(tmp_path: Path, role: str) -> None:
    """Autocover: the checker reads MANAGED_HOST_FILES out of the real deploy.sh (no
    --registry) and judges every key its sysctl/ssh/journald/resolved files set. A new
    file in the registry is covered by being added — this list is derived, not typed."""
    expected = _expected_keys(role)
    families = {f for f, _ in expected}
    assert {"sshd"} <= families
    if role == "main":
        assert {"sysctl", "sshd", "journald", "resolved"} <= families, families
    lab = HostLab(tmp_path)
    lab.host("etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
    for e in _real_registry():
        src, dst, cls, erole = e[0], e[1], e[4], e[5]
        if erole == role and cls != "absent" and (dst.startswith(("/etc/sysctl.d/", "/etc/ssh/sshd_config.d/"))
                                                  or re.match(r"^/etc/systemd/[a-z]+\.conf\.d/", dst)):
            lab.host(dst.lstrip("/"), (ROOT / src).read_text(encoding="utf-8"))
    res = lab.run(role=role, registry=False, repo=ROOT)
    judged = {(r[1], r[2]) for r in res.rows if r[0] in {"OK", "BEATEN", "MISMATCH"}}
    missing = expected - judged
    assert not missing, f"repo keys the checker did not judge: {sorted(missing)}\n{res.out}"
    assert not [r for r in res.rows if r[0] in {"BEATEN"} and r[1] in families], res.out


INV_LINE = re.compile(
    r"^(?P<role>main|relay|all)\|(?P<probe>sshd|sysctl|systemd-conf:[a-z]+|unit-prop:[A-Za-z0-9@._-]+:[A-Za-z]+"
    r"|path-present|path-absent|path-regular|tcp-listen:[0-9]+)\|(?P<key>[^|]+)\|(?P<want>[^|]+)\|(?P<why>.+)$"
)


def _entries(path: Path) -> list[str]:
    return [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_invariants_list_is_well_formed_and_seeded() -> None:
    seen = set()
    for ln in _entries(INVARIANTS):
        m = INV_LINE.match(ln)
        assert m, f"malformed invariants.list line: {ln!r}"
        assert len(m.group("why").strip()) >= 20, ln
        probe, key, want = m.group("probe"), m.group("key"), m.group("want")
        if probe.startswith(("path-", "tcp-listen")):
            assert want == "-", ln
        if probe.startswith(("unit-prop", "tcp-listen")):
            assert key == "-", ln
        if probe.startswith("path-"):
            assert key.startswith("/"), ln
        seen.add((m.group("role"), probe, key, want))
    assert seen >= {
        ("main", "unit-prop:ssh.socket:Listen", "-", "~54321"),
        ("main", "unit-prop:even-day-reboot.timer:UnitFileState", "-", "enabled"),
        ("main", "unit-prop:even-day-reboot.timer:ActiveState", "-", "active"),
        ("main", "path-regular", "/etc/resolv.conf", "-"),
        ("relay", "unit-prop:ssh.socket:Listen", "-", "~22"),
        ("all", "path-present", "/etc/cloud/cloud-init.disabled", "-"),
    }, seen


ACCEPT_LINE = re.compile(r"^(?P<path>/\S+)\|(?P<key>[^|\s]+)\|(?P<why>.+)$")


def test_accepted_overrides_list_is_well_formed_and_starts_empty() -> None:
    for ln in _entries(ACCEPTED):
        m = ACCEPT_LINE.match(ln)
        assert m and len(m.group("why").strip()) >= 20, f"malformed accepted-overrides.list line: {ln!r}"
    # Under the vendor rule neither host has a LATENT left to accept (sweep 2026-11-11).
    assert _entries(ACCEPTED) == []


def test_the_real_invariants_hold_on_a_host_that_matches_them(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    (lab.repo / "deploy/host/invariants.list").write_text(INVARIANTS.read_text(encoding="utf-8"), encoding="utf-8")
    lab.unit("ssh.socket", Listen="0.0.0.0:54321 (Stream)\nListen=[::]:54321 (Stream)")
    lab.unit("even-day-reboot.timer", UnitFileState="enabled", ActiveState="active")
    lab.host("etc/resolv.conf", "nameserver 1.1.1.1\n")
    lab.host("etc/cloud/cloud-init.disabled", "")
    res = lab.run()
    inv = [r for r in res.rows if r[1] == "invariant"]
    assert inv and all(r[0] == "OK" for r in inv), res.out
    lab.unit("ssh.socket", Listen="0.0.0.0:22 (Stream)")
    assert lab.run().find("MISMATCH", "invariant", "unit-prop:ssh.socket:Listen")


# --------------------------------------------------------------------------- #
# 9. Read-only, the state file
# --------------------------------------------------------------------------- #
def _tree(root: Path) -> dict[str, tuple[int, int, bytes | str]]:
    snap: dict[str, tuple[int, int, bytes | str]] = {}
    for p in sorted(root.rglob("*")):
        st = p.lstat()
        body: bytes | str = os.readlink(p) if p.is_symlink() else (p.read_bytes() if p.is_file() else b"")
        snap[str(p.relative_to(root))] = (st.st_mode, st.st_mtime_ns, body)
    return snap


def test_the_check_writes_nothing_but_its_state_file(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.host("etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
    lab.host("etc/sysctl.d/10-a.conf", "vm.swappiness = 1\n")
    lab.host("etc/logrotate.conf", "\n")
    lab.repo_file("deploy/host/invariants.list", INVARIANTS.read_text(encoding="utf-8"))
    before_root, before_repo = _tree(lab.root), _tree(lab.repo)
    state = tmp_path / "state" / "last.json"
    state.parent.mkdir()
    res = lab.run(role="relay", state=state)
    assert _tree(lab.root) == before_root and _tree(lab.repo) == before_repo
    assert sorted(p.name for p in state.parent.iterdir()) == ["last.json"], "no temp file left behind"
    assert stat.S_IMODE(state.stat().st_mode) == 0o644
    data = json.loads(state.read_text(encoding="utf-8"))
    assert data["role"] == "relay" and data["mode"] == "installed" and data["version"] == 1
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", data["generated_at"])
    assert data["counts"]["latent"] == int(res.summary["latent"]) >= 1
    assert [(r["verdict"], r["family"], r["key"], r["path"], r["text"]) for r in data["rows"]] == res.rows
    for name in ("systemctl", "sysctl", "sshd", "dpkg", "dpkg-query", "logrotate", "systemd-analyze"):
        assert not [ln for ln in lab.log(name) if "REFUSED" in ln]
    assert "REFUSED" not in res.err


def test_no_state_writes_nothing_and_a_failed_write_is_exit_4(tmp_path: Path) -> None:
    lab = _relay_lab(tmp_path)
    lab.run(role="relay")
    # The lab itself rewrites sd/, registry and logs/ on every run; the rest is the host.
    def host_side() -> dict[str, tuple[int, int, bytes | str]]:
        return {k: v for k, v in _tree(tmp_path).items() if not k.startswith(("logs", "sd", "registry"))}
    before = host_side()
    assert lab.run(role="relay").rc == 0
    assert host_side() == before
    blocked = tmp_path / "file-not-dir"
    blocked.write_text("", encoding="utf-8")
    res = lab.run(role="relay", state=blocked / "last.json")
    assert res.rc == 4 and "could not write" in res.err
    assert res.summary, "the rows are still printed"


def test_a_missing_checkout_cannot_run(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    res = lab.run(repo=tmp_path / "nowhere")
    assert res.rc == 3


def test_json_escaping(tmp_path: Path) -> None:
    lab = HostLab(tmp_path)
    lab.host("etc/sysctl.d/10-a.conf", 'kernel.x = "quoted" \\ back\n')
    lab.host("etc/sysctl.d/90-b.conf", "kernel.x = 2\n")
    state = tmp_path / "last.json"
    lab.run(state=state)
    data = json.loads(state.read_text(encoding="utf-8"))
    assert any('"quoted" \\ back' in r["text"] for r in data["rows"])


# --------------------------------------------------------------------------- #
# 10. The .env readers and the gates are deploy.sh's
# --------------------------------------------------------------------------- #
def _function(text: str, name: str) -> str:
    body = text[text.index(f"\n{name}() {{") + 1 :]
    return body[: body.index("\n}\n") + 3]


def test_the_env_readers_are_deploy_sh_s() -> None:
    check, deploy = CHECK.read_text(encoding="utf-8"), DEPLOY_SH.read_text(encoding="utf-8")
    assert _function(check, "env_val") == _function(deploy, "env_val")
    assert _function(check, "env_sed_val") == _function(deploy, "env_sed_val")


GATE_CASES = [
    ("MTPROTO_ENABLED=true\n", "gate=MTPROTO", [], True),
    ("MTPROTO_ENABLED=false\n", "gate=MTPROTO", [], False),
    ("MTPROTO_ENABLED=yes\n", "gate=MTPROTO", ["mtproto"], False),
    ("", "gate=SOCKS5", [], False),
    ("SOCKS5_ENABLED=ON\n", "gate=SOCKS5", [], True),
    ("HYSTERIA2_ENABLED=1\n", "gate=HYSTERIA2", [], True),
    ("", "gate=XRAY", [], True),
    ("", "gate=XRAY", ["xray"], False),
    ("", "gate=AWG", [], False),
    ("", "when=/etc/vpn-bot/tls/fullchain.pem", [], False),
    ("", "when=/etc/present", [], True),
    ("MTPROTO_ENABLED=true\n", "gate=MTPROTO;legacy=/etc/x", [], True),
    ("", "", [], True),
]


@pytest.mark.parametrize(("env", "opts", "markers", "open_"), GATE_CASES)
def test_gate_evaluation_matches_deploy_sh(tmp_path: Path, env: str, opts: str, markers: list[str], open_: bool) -> None:
    """The timer evaluates the gates itself; it must agree with deploy.sh's mh_gate_open."""
    root = tmp_path / "root"
    (root / "etc/vpn-bot/uninstalled").mkdir(parents=True)
    (root / "etc/present").write_text("", encoding="utf-8")
    for m in markers:
        (root / "etc/vpn-bot/uninstalled" / m).write_text("", encoding="utf-8")
    envf = tmp_path / "dot.env"
    envf.write_text(env, encoding="utf-8")
    deploy_opts = opts.replace("/etc/", f"{root}/etc/")
    deploy = subprocess.run(
        ["bash", "-c",
         f'export DEPLOY_SELFTEST=1; source "{DEPLOY_SH}"; ENV_FILE="{envf}"; '
         f'UNINSTALL_MARKER_DIR="{root}/etc/vpn-bot/uninstalled"; resolve_backend_units; '
         f'mh_gate_open "{deploy_opts}" && echo OPEN || echo SHUT'],
        capture_output=True, text=True, check=False)
    check_text = CHECK.read_text(encoding="utf-8")
    funcs = "".join(_function(check_text, f) for f in ("fs", "env_val", "gate_open"))
    checker = subprocess.run(
        ["bash", "-c",
         f'set -uo pipefail\n{funcs}\nROOT="{root}"; ENV_FILE="{envf}"; '
         f'UNINSTALL_MARKER_DIR=/etc/vpn-bot/uninstalled\n'
         f'gate_open "{opts}" && echo OPEN || echo SHUT'],
        capture_output=True, text=True, check=False)
    want = "OPEN" if open_ else "SHUT"
    assert deploy.stdout.strip().splitlines()[-1] == want, deploy.stdout + deploy.stderr
    assert checker.stdout.strip() == want, checker.stdout + checker.stderr


def test_the_timer_run_parses_the_registry_out_of_deploy_sh(tmp_path: Path) -> None:
    """No --registry: the role's entries come from the MANAGED_HOST_FILES literal of
    the checkout's deploy.sh — parsed, never sourced — gates evaluated from .env."""
    lab = HostLab(tmp_path)
    lab.env.write_text("NODE_ROLE=relay\n", encoding="utf-8")
    proc = subprocess.run(
        ["bash", str(CHECK), "--repo", str(ROOT), "--root", str(lab.root), "--env", str(lab.env), "--no-state"],
        env={"PATH": f"{lab.stub}:{os.environ.get('PATH', '')}", "SD": str(lab.sd), "LOGS": str(lab.logs),
             "HC_ROOT": str(lab.root)},
        capture_output=True, text=True, check=False)
    assert "SUMMARY|role=relay|" in proc.stdout, proc.stdout + proc.stderr
    relay_dsts = {e[1] for e in _real_registry() if e[5] == "relay" and e[4] != "absent"}
    assert any(d in proc.stdout for d in relay_dsts)
    main_only = {e[1] for e in _real_registry() if e[5] == "main"} - {e[1] for e in _real_registry() if e[5] == "relay"}
    assert not [d for d in main_only if d in proc.stdout], "a relay never sees a main entry"


def test_the_checker_never_evaluates_command_output() -> None:
    code = "\n".join(ln for ln in CHECK.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"\beval\b", code)
    assert not re.search(r"\|\s*head\b", code), "no `| head` (the SIGPIPE class): use awk 'NR<=N'"
    assert not re.search(r"(^|[;&|]\s*)(source|\.)\s+\S", code, re.M), "never sources anything"
