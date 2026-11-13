"""The main server's UFW is computed from the repo and .env (docs/host-state.md#the-firewall-ufw).

scripts/vpn-bot-ufw-apply (the set, plan/apply, the dead-man, the listener check,
save/restore), scripts/deploy.sh (Phase 1 «UFW», Phase 2 apply + listeners, the
rollback), scripts/vpn-bot-host-check (family ufw), the bot (apply after a protocol is
switched on or removed, «Подтвердить» of a policy change) and the uninstall helper,
which no longer touches ufw.

Every command is a stub on PATH. `ufw` is a small Python program keeping its rules in a
JSON file and writing /etc/ufw/user*.rules the way ufw 0.36 does (`### tuple ###` lines,
one file per address family: the v6 copy only with IPV6=yes and a kernel with IPv6).
VPN_BOT_UFW_SELFTEST=1 makes the helper refuse any command that does not resolve inside
the stub directory, and fences every write to the fake root: deploy.sh runs this suite
AS ROOT on the production host, where a real ufw exists.

The fixture is the main server as measured on 2026-11-12: ufw active, DROP/ACCEPT/DROP,
IPV6=yes; 443/tcp 'Xray Reality HTTPS', 31337/tcp, 54321/tcp, 443/udp, 2096/tcp
'vpn-bot all-in-one subscription (HTTPS)', 22/tcp (v4+v6), and the route rule of the
removed AWG (v4); markers awg and mtproto; listeners tcp 443/2096/31337/54321, udp 443,
udp *:32808 (out-warp's listen-port, kernel-owned) and udp 172.16.0.2:* (outgoing).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpn-bot-ufw-apply"
SSH_HELPER = ROOT / "scripts" / "vpn-bot-ssh-port"
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
HOST_CHECK = ROOT / "scripts" / "vpn-bot-host-check"
DEADMAN = "/var/lib/vpn-bot/ufw-deadman.json"

pytestmark = pytest.mark.timeout(120)


def _stub(path: Path, body: str, shebang: str = "#!/usr/bin/env bash\n") -> None:
    path.write_text(shebang + body, encoding="utf-8")
    path.chmod(0o755)


# --------------------------------------------------------------------------- #
# The ufw stub. State: $SD/ufw.json {"active": bool, "rules": [[text, comment, [fams]]]}.
# Policies live in $R/etc/default/ufw like ufw's. The tuple writer is the stub's own
# (ufw 0.36's backend_iptables format), independent of the helper's parser.
# --------------------------------------------------------------------------- #
UFW_STUB = r'''
import json, os, re, sys
SD, R, LOGS = os.environ["SD"], os.environ["R"], os.environ["LOGS"]
args = sys.argv[1:]
with open(f"{LOGS}/ufw.log", "a") as fh:
    fh.write("ufw " + " ".join(args) + "\n")
st_path = f"{SD}/ufw.json"
st = json.load(open(st_path)) if os.path.exists(st_path) else {"active": True, "rules": []}
defaults = f"{R}/etc/default/ufw"

def dflt():
    out = {}
    for line in open(defaults):
        m = re.match(r'^([A-Z_0-9]+)="?([^"]*)"?$', line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out

def save():
    json.dump(st, open(st_path, "w"))
    v4, v6 = ["### RULES ###"], ["### RULES ###"]
    for text, comment, fams in st["rules"]:
        t = tuple_of(text)
        c = f" comment={comment.encode().hex()}" if comment else ""
        if "v4" in fams:
            v4.append("### tuple ### " + t.replace("ANY", "0.0.0.0/0") + c)
        if "v6" in fams:
            v6.append("### tuple ### " + t.replace("ANY", "::/0") + c)
    os.makedirs(f"{R}/etc/ufw", exist_ok=True)
    open(f"{R}/etc/ufw/user.rules", "w").write("\n".join(v4) + "\n### END RULES ###\n")
    open(f"{R}/etc/ufw/user6.rules", "w").write("\n".join(v6) + "\n### END RULES ###\n")

def tuple_of(text):
    m = re.fullmatch(r"(allow|deny|reject|limit) (\d+)(?:/(tcp|udp))?", text)
    if m:
        return f"{m.group(1)} {m.group(3) or 'any'} {m.group(2)} ANY any ANY in"
    m = re.fullmatch(r"route allow in on (\S+) out on (\S+) from (\S+)", text)
    if m:
        return f"route:allow any any ANY any {m.group(3)} in_{m.group(1)}!out_{m.group(2)}"
    m = re.fullmatch(r"(allow|deny) from (\S+) to any port (\d+) proto (tcp|udp)", text)
    if m:
        return f"{m.group(1)} {m.group(4)} {m.group(3)} ANY any {m.group(2)} in"
    raise SystemExit(f"stub: cannot write a tuple for {text!r}")

def fams_for(text):
    d = dflt()
    v6 = d.get("IPV6") == "yes" and os.path.isdir(f"{R}/proc/sys/net/ipv6")
    if re.search(r"\b\d+\.\d+\.\d+\.\d+", text):
        return ["v4"]
    return ["v4", "v6"] if v6 else ["v4"]

def fail(what):
    return os.path.exists(f"{SD}/ufw_fail_{what}")

cmd = args[0] if args else ""
if cmd == "__save":          # the fixture: write user*.rules from the JSON state
    save(); sys.exit(0)
if cmd == "status":
    print("Status: " + ("active" if st["active"] else "inactive"))
    sys.exit(0)
if cmd == "show" and args[1:] == ["added"]:
    print("Added user rules (see 'ufw status' for running firewall):")
    seen = []
    for text, comment, fams in st["rules"]:
        line = f"ufw {text}" + (f" comment '{comment}'" if comment else "")
        if text not in seen:
            seen.append(text)
            print(line)
    sys.exit(0)
if cmd == "default":
    policy, direction = args[1], args[2]
    var = {"incoming": "DEFAULT_INPUT_POLICY", "outgoing": "DEFAULT_OUTPUT_POLICY", "routed": "DEFAULT_FORWARD_POLICY"}[direction]
    ipt = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}[policy]
    lines = [f'{var}="{ipt}"' if l.startswith(var + "=") else l for l in open(defaults).read().splitlines()]
    open(defaults, "w").write("\n".join(lines) + "\n")
    print(f"Default {direction} policy changed to '{policy}'")
    sys.exit(0)
if args[:2] == ["--force", "enable"]:
    if fail("enable"):
        print("ERROR: enable failed"); sys.exit(1)
    st["active"] = True; save(); print("Firewall is active and enabled on system startup"); sys.exit(0)
if cmd == "disable":
    if fail("disable"):
        print("ERROR: disable failed"); sys.exit(1)
    st["active"] = False; save(); print("Firewall stopped and disabled on system startup"); sys.exit(0)
if cmd == "reload":
    print("Firewall reloaded"); sys.exit(0)
if cmd == "delete" or args[:2] == ["route", "delete"]:
    if cmd == "delete" and len(args) > 1 and args[1] == "route":
        print("ERROR: Invalid syntax"); sys.exit(1)
    text = " ".join(args[1:]) if cmd == "delete" else "route " + " ".join(args[2:])
    if fail("delete"):
        print("ERROR: delete failed"); sys.exit(1)
    before = len(st["rules"])
    st["rules"] = [r for r in st["rules"] if r[0] != text]
    save()
    print("Rule deleted" if len(st["rules"]) < before else "Could not delete non-existent rule")
    sys.exit(0)
if cmd in ("allow", "deny", "reject", "limit", "route"):
    if fail("add"):
        print("ERROR: add failed"); sys.exit(1)
    comment = ""
    if "comment" in args:
        i = args.index("comment"); comment = args[i + 1]; args = args[:i]
    text = " ".join(args)
    fams = fams_for(text)
    for r in st["rules"]:
        if r[0] == text:
            r[1] = comment
            r[2] = sorted(set(r[2]) | set(fams))
            break
    else:
        st["rules"].append([text, comment, fams])
    save(); print("Rules updated"); sys.exit(0)
print(f"stub ufw: unsupported {args}"); sys.exit(2)
'''

SYSTEMCTL = r"""
echo "systemctl $*" >> "$LOGS/systemctl.log"
verb="$1"; shift
case "$verb" in
  show)
    props=(); unit=""
    while (( $# )); do case "$1" in -p) props+=("$2"); shift 2 ;; --value) shift ;; *) unit="$1"; shift ;; esac; done
    for p in "${props[@]}"; do
      case "$p" in
        ActiveState) echo "ActiveState=$(cat "$SD/$unit.active" 2>/dev/null || echo inactive)" ;;
        Listen) if [[ "$unit" == ssh.socket ]]; then
                  for port in $(cat "$SD/socket_ports" 2>/dev/null); do echo "Listen=0.0.0.0:$port (Stream)"; echo "Listen=[::]:$port (Stream)"; done
                fi ;;
      esac
    done
    exit 0 ;;
  is-active) s="$(cat "$SD/${!#}.active" 2>/dev/null || echo inactive)"; echo "$s"; [[ "$s" == active ]]; exit ;;
  stop) for u in "$@"; do echo inactive > "$SD/$u.active"; done; exit 0 ;;
  reset-failed|start|daemon-reload) exit 0 ;;
esac
exit 0
"""

SYSTEMD_RUN = r"""
echo "systemd-run $*" >> "$LOGS/systemd-run.log"
echo "ufw-call-mark $(wc -l < "$LOGS/ufw.log" 2>/dev/null || echo 0)" >> "$LOGS/systemd-run.log"
[[ -f "$SD/systemd_run_fail" ]] && { echo "Failed to start transient timer unit" >&2; exit 1; }
for a in "$@"; do case "$a" in --unit=*) echo active > "$SD/${a#--unit=}.timer.active" ;; esac; done
exit 0
"""

SS = r"""
echo "ss $*" >> "$LOGS/ss.log"
[[ -f "$SD/ss_fail" ]] && exit 1
case "$1" in *t*) cat "$SD/ss_tcp" 2>/dev/null ;; *u*) cat "$SD/ss_udp" 2>/dev/null ;; esac
exit 0
"""

SSHD = r"""
echo "sshd $*" >> "$LOGS/sshd.log"
[[ -f "$SD/sshd_fail" ]] && exit 255
for p in $(cat "$SD/sshd_ports" 2>/dev/null); do echo "port $p"; done
echo "loglevel VERBOSE"
exit 0
"""

IP = r"""
case "$*" in
  "-4 route show default") [[ -f "$SD/no_default_route" ]] || echo "default via 198.51.100.1 dev eth0 proto static" ;;
  *) echo "1: lo    inet 127.0.0.1/8 scope host lo"
     echo "2: eth0    inet 198.51.100.7/24 brd 198.51.100.255 scope global eth0" ;;
esac
exit 0
"""

AWG = r"""
[[ "$*" == "show all listen-port" ]] && cat "$SD/awg_ports" 2>/dev/null
exit 0
"""

JOURNALCTL = r"""
echo "journalctl $*" >> "$LOGS/journalctl.log"
cat "$SD/journal" 2>/dev/null; exit 0
"""

DEFAULTS = (
    'IPV6=yes\nDEFAULT_INPUT_POLICY="{inp}"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="{fwd}"\n'
    'DEFAULT_APPLICATION_POLICY="SKIP"\nMANAGE_BUILTINS=no\n'
)
MAIN_ENV = (
    "XRAY_PUBLIC_PORT=443\nSOCKS5_ENABLED=true\nSOCKS5_PORT=31337\nHYSTERIA2_ENABLED=true\nHYSTERIA2_PORT=443\n"
    "SUBSCRIPTION_ENABLED=true\nSUBSCRIPTION_PUBLIC_PORT=2096\nMTPROTO_ENABLED=false\n"
)
BOTH = ["v4", "v6"]
MEASURED_RULES: list[list[Any]] = [
    ["allow 443/tcp", "Xray Reality HTTPS", BOTH],
    ["allow 31337/tcp", "", BOTH],
    ["allow 54321/tcp", "", BOTH],
    ["allow 443/udp", "", BOTH],
    ["allow 2096/tcp", "vpn-bot all-in-one subscription (HTTPS)", BOTH],
    ["allow 22/tcp", "", BOTH],
    ["route allow in on awg0 out on eth0 from 10.0.0.0/24", "AWG clients to internet", ["v4"]],
]
TCP_MEASURED = (
    'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=700,fd=3))\n'
    'LISTEN 0 4096 [::]:443 [::]:* users:(("xray",pid=700,fd=4))\n'
    'LISTEN 0 128 0.0.0.0:2096 0.0.0.0:* users:(("python3",pid=800,fd=7))\n'
    'LISTEN 0 128 0.0.0.0:31337 0.0.0.0:* users:(("danted",pid=900,fd=5))\n'
    'LISTEN 0 4096 0.0.0.0:54321 0.0.0.0:* users:(("systemd",pid=1,fd=50))\n'
    'LISTEN 0 4096 [::]:54321 [::]:* users:(("systemd",pid=1,fd=51))\n'
    'LISTEN 0 128 127.0.0.1:8445 0.0.0.0:* users:(("python3",pid=800,fd=6))\n'
    'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=14))\n'
)
UDP_MEASURED = (
    'UNCONN 0 0 *:443 *:* users:(("hysteria",pid=1000,fd=6))\n'
    "UNCONN 0 0 *:32808 *:*\n"
    'UNCONN 0 0 172.16.0.2:41234 0.0.0.0:* users:(("hysteria",pid=1000,fd=9))\n'
    'UNCONN 0 0 172.16.0.2:443 0.0.0.0:* users:(("hysteria",pid=1000,fd=10))\n'
    'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=13))\n'
)


class Host:
    """A fake main server: root, stubs, .env, the repo's deploy/host/ufw files."""

    def __init__(self, tmp: Path, *, env: str = MAIN_ENV, rules: list[list[Any]] | None = None,
                 markers: tuple[str, ...] = ("awg", "mtproto"), active: bool = True,
                 incoming: str = "DROP", forward: str = "DROP", ssh: tuple[int, ...] = (54321,)) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.stub = tmp / "stub"
        self.sd = tmp / "sd"
        self.logs = tmp / "logs"
        self.repo = tmp / "repo"
        for d in (self.root, self.stub, self.sd, self.logs, self.repo / "deploy/host/ufw", self.repo / "scripts"):
            d.mkdir(parents=True, exist_ok=True)
        for name in ("extra.list", "policy"):
            (self.repo / "deploy/host/ufw" / name).write_bytes((ROOT / "deploy/host/ufw" / name).read_bytes())
        _stub(self.stub / "ufw", UFW_STUB, "#!/usr/bin/env python3\n")
        for name, body in (("systemctl", SYSTEMCTL), ("systemd-run", SYSTEMD_RUN), ("ss", SS), ("sshd", SSHD),
                           ("ip", IP), ("awg", AWG), ("journalctl", JOURNALCTL)):
            _stub(self.stub / name, body)
        (self.stub / "wg").symlink_to(self.stub / "awg")
        self.put("etc/default/ufw", DEFAULTS.format(inp=incoming, fwd=forward))
        (self.root / "proc/sys/net/ipv6").mkdir(parents=True)
        (self.root / "etc/ssh").mkdir(parents=True)
        self.put("etc/ssh/sshd_config", "")
        for m in markers:
            self.put(f"etc/vpn-bot/uninstalled/{m}", "{}")
        self.env_file = tmp / "dot.env"
        self.env_file.write_text(env, encoding="utf-8")
        self.set_rules(MEASURED_RULES if rules is None else rules, active=active)
        self.flag("ss_tcp", TCP_MEASURED)
        self.flag("ss_udp", UDP_MEASURED)
        self.flag("awg_ports", "out-warp\t32808\n")
        self.ssh_on(*ssh)
        self.flag("ssh.socket.active", "active")

    # --- fixtures -----------------------------------------------------------
    def h(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def put(self, path: str, content: str) -> Path:
        p = self.h(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def flag(self, name: str, content: str = "") -> None:
        (self.sd / name).write_text(content, encoding="utf-8")

    def ssh_on(self, *ports: int) -> None:
        self.flag("socket_ports", " ".join(str(p) for p in ports))
        self.flag("sshd_ports", " ".join(str(p) for p in ports))

    def set_rules(self, rules: list[list[Any]], *, active: bool = True) -> None:
        """The host's rules as [text, comment, [families]]: /etc/ufw/user*.rules follow."""
        self.flag("ufw.json", json.dumps({"active": active, "rules": rules}))
        subprocess.run([str(self.stub / "ufw"), "__save"], env=self.env_run(), check=True, capture_output=True)
        self.clear_logs()

    def clear_logs(self) -> None:
        for f in self.logs.glob("*.log"):
            f.unlink()

    def env_run(self) -> dict[str, str]:
        return {"PATH": f"{self.stub}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(self.tmp),
                "SD": str(self.sd), "LOGS": str(self.logs), "R": str(self.root), "LANG": "C.UTF-8",
                "VPN_BOT_UFW_SELFTEST": "1", "VPN_BOT_UFW_SELFTEST_BIN": str(self.stub),
                "VPN_BOT_SSH_PORT_SELFTEST": "1"}

    # --- running the helper ---------------------------------------------------
    def helper(self, *args: str, ssh_helper: str = "") -> subprocess.CompletedProcess[str]:
        argv = ["python3", "-I", str(HELPER), "--env", str(self.env_file), "--repo", str(self.repo),
                "--root", str(self.root), "--ssh-port-helper", ssh_helper, *args]
        return subprocess.run(argv, env=self.env_run(), capture_output=True, text=True, check=False, timeout=90)

    def plan(self, *extra: str) -> dict[str, list[str]]:
        proc = self.helper("plan", "--ssh-ports", "54321", *extra)
        assert proc.returncode in (0, 3), proc.stdout + proc.stderr
        out: dict[str, list[str]] = {}
        for ln in proc.stdout.splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                out.setdefault(k, []).append(v)
        return out

    def apply(self, ssh: str = "54321") -> subprocess.CompletedProcess[str]:
        return self.helper("apply", "--ssh-ports", ssh)

    def rules(self) -> dict[str, tuple[str, list[str]]]:
        st = json.loads((self.sd / "ufw.json").read_text(encoding="utf-8"))
        return {r[0]: (r[1], r[2]) for r in st["rules"]}

    def log(self, name: str) -> list[str]:
        p = self.logs / f"{name}.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def ufw_mutations(self) -> list[str]:
        return [ln for ln in self.log("ufw") if not ln.startswith(("ufw status", "ufw show"))]

    def defaults(self) -> str:
        return self.h("etc/default/ufw").read_text(encoding="utf-8")


def _rules(plan: dict[str, list[str]]) -> list[tuple[str, str, str, str]]:
    """(action, category, marked, text) of every rule= line."""
    out = []
    for v in plan.get("rule", []):
        a, b, c, d, _ = v.split("|", 4)
        out.append((a, b, c, d))
    return out


def _listeners(plan: dict[str, list[str]]) -> list[tuple[str, str, str, str]]:
    out = []
    for v in plan.get("listener", []):
        a, b, c, d, _ = v.split("|", 4)
        out.append((a, b, c, d))
    return out


# --------------------------------------------------------------------------- #
# 1. The rule text: ufw 0.36.2's own output (measured with the package, 2026-11-13)
# --------------------------------------------------------------------------- #
def _mod() -> Any:
    import importlib.machinery
    import importlib.util
    import sys
    loader = importlib.machinery.SourceFileLoader("vpn_bot_ufw_apply", str(HELPER))
    spec = importlib.util.spec_from_loader("vpn_bot_ufw_apply", loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vpn_bot_ufw_apply"] = mod
    loader.exec_module(mod)
    return mod


# (the command typed, what `ufw show added` printed, the tuple in /etc/ufw/user.rules)
MEASURED_UFW = [
    ("allow 443/tcp", "allow 443/tcp", "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in"),
    ("allow 8080", "allow 8080", "allow any 8080 0.0.0.0/0 any 0.0.0.0/0 in"),
    ("limit 2222/tcp", "limit 2222/tcp", "limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in"),
    ("allow proto tcp to any port 2096", "allow 2096/tcp", "allow tcp 2096 0.0.0.0/0 any 0.0.0.0/0 in"),
    ("route allow in on awg0 out on eth0 from 10.0.0.0/24",
     "route allow in on awg0 out on eth0 from 10.0.0.0/24",
     "route:allow any any 0.0.0.0/0 any 10.0.0.0/24 in_awg0!out_eth0"),
    ("allow from 1.2.3.4 to any port 5555 proto tcp", "allow from 1.2.3.4 to any port 5555 proto tcp",
     "allow tcp 5555 0.0.0.0/0 any 1.2.3.4 in"),
]


@pytest.mark.parametrize(("typed", "shown", "tup"), MEASURED_UFW)
def test_rule_text_and_tuple_map_to_one_key_as_ufw_prints_them(typed: str, shown: str, tup: str) -> None:
    m = _mod()
    key = m.parse_rule(shown)
    assert key is not None and m.parse_rule(typed) == key
    assert m.rule_text(key) == shown, "rule_text is ufw's get_command"
    parsed = m.parse_tuple(f"### tuple ### {tup} comment=58")
    assert parsed is not None and parsed == (key, "X")
    v6 = m.parse_tuple("### tuple ### " + tup.replace("0.0.0.0/0", "::/0"))
    if "1.2.3.4" not in tup and "10.0.0.0" not in tup:
        assert v6 is not None and v6[0] == key, "the v6 copy is the same rule"


def test_an_application_profile_or_garbage_is_never_a_table_rule() -> None:
    m = _mod()
    assert m.parse_rule("allow OpenSSH").dapp == "OpenSSH"
    assert m.parse_rule("allow 443/bogus") is None
    assert m.parse_rule("frobnicate 443") is None


def test_a_route_rule_is_deleted_with_route_delete() -> None:
    """ufw 0.36 refuses `ufw delete route allow ...` (measured: 'ERROR: Invalid syntax')."""
    m = _mod()
    assert m.delete_argv("route allow in on awg0 out on eth0 from 10.0.0.0/24") == \
        ["route", "delete", "allow", "in", "on", "awg0", "out", "on", "eth0", "from", "10.0.0.0/24"]
    assert m.delete_argv("allow 22/tcp") == ["delete", "allow", "22/tcp"]


# --------------------------------------------------------------------------- #
# 2. The measured main server
# --------------------------------------------------------------------------- #
def test_measured_main_plan(tmp_path: Path) -> None:
    host = Host(tmp_path)
    plan = host.plan()
    assert plan["result"] == ["ok"] and plan["ufw"] == ["present"] and plan["active"] == ["yes"]
    modules = dict(v.split("|", 2)[:2] for v in plan["module"])
    assert modules == {"xray": "on", "hysteria2": "on", "socks5": "on", "subscription": "on",
                       "mtproto": "off", "awg": "off"}
    assert set(_rules(plan)) == {
        ("adopt", "ssh", "no", "allow 54321/tcp"),
        ("adopt", "xray", "no", "allow 443/tcp"),
        ("adopt", "hysteria2", "no", "allow 443/udp"),
        ("adopt", "socks5", "no", "allow 31337/tcp"),
        ("adopt", "subscription", "no", "allow 2096/tcp"),
        ("delete", "ssh", "no", "allow 22/tcp"),
        ("delete", "awg", "no", "route allow in on awg0 out on eth0 from 10.0.0.0/24"),
    }
    assert "policy=routed|deny|-" in [f"policy={v}" for v in plan["policy"]], "routed is not managed"
    assert plan["listeners"] == ["ok"]
    lst = _listeners(plan)
    assert ("info", "udp", "32808", "*") in lst, "out-warp's listen-port: INFO"
    assert [x for x in lst if x[0] == "FAIL"] == []
    assert plan["deadman"] == ["none"]


def test_measured_main_apply_converges_and_is_idempotent(tmp_path: Path) -> None:
    host = Host(tmp_path)
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rules = host.rules()
    assert rules == {
        "allow 443/tcp": ("vpn-bot:xray", BOTH), "allow 31337/tcp": ("vpn-bot:socks5", BOTH),
        "allow 54321/tcp": ("vpn-bot:ssh", BOTH), "allow 443/udp": ("vpn-bot:hysteria2", BOTH),
        "allow 2096/tcp": ("vpn-bot:subscription", BOTH),
    }
    muts = host.ufw_mutations()
    assert "ufw delete allow 22/tcp" in muts
    assert "ufw route delete allow in on awg0 out on eth0 from 10.0.0.0/24" in muts
    assert not [c for c in muts if c.startswith(("ufw delete allow 443", "ufw delete allow 54321"))], \
        "an adopted rule is relabelled in place, never deleted and re-added"
    assert not [c for c in muts if c.startswith("ufw default")], "an ordinary apply changes no policy"
    assert host.log("systemd-run") == [], "and needs no dead-man"
    assert 'DEFAULT_FORWARD_POLICY="DROP"' in host.defaults()
    host.clear_logs()
    again = host.apply()
    assert again.returncode == 0 and host.ufw_mutations() == [], again.stdout


# --------------------------------------------------------------------------- #
# 3. The set follows .env and the markers
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("env", "markers", "expect"), [
    # socks5 switched off in .env: its unmarked rule goes
    (MAIN_ENV.replace("SOCKS5_ENABLED=true", "SOCKS5_ENABLED=false"), ("awg", "mtproto"),
     {"allow 31337/tcp": None}),
    # hysteria2 removed from the host: 443/udp goes, xray's 443/tcp stays
    (MAIN_ENV, ("awg", "mtproto", "hysteria2"), {"allow 443/udp": None, "allow 443/tcp": "vpn-bot:xray"}),
    # mtproto switched on and installed again (no marker): its port opens
    (MAIN_ENV.replace("MTPROTO_ENABLED=false", "MTPROTO_ENABLED=true\nMTPROTO_PORT=9443"), ("awg",),
     {"allow 9443/tcp": "vpn-bot:mtproto"}),
    # xray removed: 443/tcp goes, even though the module has no .env flag
    (MAIN_ENV, ("awg", "mtproto", "xray"), {"allow 443/tcp": None}),
])
def test_the_set_follows_env_and_markers(tmp_path: Path, env: str, markers: tuple[str, ...],
                                          expect: dict[str, str | None]) -> None:
    host = Host(tmp_path, env=env, markers=markers)
    # A listener without its rule fails the listener check — the apply alone is tested here.
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rules = host.rules()
    for text, comment in expect.items():
        if comment is None:
            assert text not in rules, text
        else:
            assert rules[text][0] == comment, text


def test_a_public_port_switched_off_goes_once_it_carries_our_comment(tmp_path: Path) -> None:
    """SUBSCRIPTION_PUBLIC_PORT=0: no port to recognise an unmarked rule by — it stays (WARN);
    the rule the first apply relabelled 'vpn-bot:subscription' is deleted."""
    env = MAIN_ENV.replace("SUBSCRIPTION_PUBLIC_PORT=2096", "SUBSCRIPTION_PUBLIC_PORT=0")
    host = Host(tmp_path, env=env)
    assert ("warn", "-", "no", "allow 2096/tcp") in _rules(host.plan())
    host.set_rules([r if r[0] != "allow 2096/tcp" else ["allow 2096/tcp", "vpn-bot:subscription", BOTH]
                    for r in MEASURED_RULES])
    assert ("delete", "subscription", "yes", "allow 2096/tcp") in _rules(host.plan())
    assert host.apply().returncode == 0
    assert "allow 2096/tcp" not in host.rules()


def test_awg_route_rule_goes_with_the_awg_marker_and_comes_with_awg(tmp_path: Path) -> None:
    host = Host(tmp_path)                              # marker awg
    assert host.apply().returncode == 0
    assert not [t for t in host.rules() if t.startswith("route ")], "the AWG route rule is gone"
    # AWG installed again: no marker, ListenPort from its config, WAN from the default route.
    host.h("etc/vpn-bot/uninstalled/awg").unlink()
    host.put("etc/amnezia/amneziawg/awg0.conf", "[Interface]\nListenPort = 11880\nPrivateKey = x\n\n[Peer]\nListenPort = 1\n")
    host.clear_logs()
    assert host.apply().returncode == 0
    rules = host.rules()
    assert rules["route allow in on awg0 out on eth0 from 10.0.0.0/24"] == ("vpn-bot:awg", ["v4"])
    assert rules["allow 11880/udp"] == ("vpn-bot:awg", BOTH)


def test_awg_without_a_default_route_leaves_its_route_rule_unmanaged(tmp_path: Path) -> None:
    host = Host(tmp_path, markers=("mtproto",))
    host.flag("no_default_route")
    plan = host.plan()
    assert any("no IPv4 default route" in n for n in plan.get("note", []))
    # AWG is on: its route rule (in on awg0, from AWG_NETWORK) stays as it is — never
    # deleted because the WAN half cannot be told, never a WARN either.
    route = "route allow in on awg0 out on eth0 from 10.0.0.0/24"
    assert [r for r in _rules(plan) if r[3] == route] == [("keep", "awg", "no", route)]
    host.set_rules([*MEASURED_RULES[:-1], [route, "vpn-bot:awg", ["v4"]]])
    assert [r for r in _rules(host.plan()) if r[3] == route] == [("keep", "awg", "yes", route)]
    assert host.apply().returncode == 0
    assert host.rules()[route] == ("vpn-bot:awg", ["v4"])


# --------------------------------------------------------------------------- #
# 4. Adopt, WARN, extra.list
# --------------------------------------------------------------------------- #
def test_an_unmarked_rule_of_the_set_is_adopted_in_place(tmp_path: Path) -> None:
    host = Host(tmp_path, rules=[["allow 443/tcp", "Xray Reality HTTPS", BOTH], ["allow 54321/tcp", "", BOTH]])
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout
    assert host.rules()["allow 443/tcp"] == ("vpn-bot:xray", BOTH)
    assert "ufw allow 443/tcp comment vpn-bot:xray" in host.ufw_mutations()
    assert not [c for c in host.ufw_mutations() if c.startswith("ufw delete")]
    assert "adopted 'allow 443/tcp' (vpn-bot:xray)" in proc.stdout


def test_an_unmarked_rule_nothing_claims_is_a_warn_and_stays(tmp_path: Path) -> None:
    rules = [*MEASURED_RULES, ["allow 9999/tcp", "hand rule", BOTH], ["allow OpenSSH", "", BOTH]]
    host = Host(tmp_path)
    st = json.loads((host.sd / "ufw.json").read_text(encoding="utf-8"))
    st["rules"] = rules[:-1]           # the stub writes no tuple for an app profile
    (host.sd / "ufw.json").write_text(json.dumps(st), encoding="utf-8")
    subprocess.run([str(host.stub / "ufw"), "__save"], env=host.env_run(), check=True)
    plan = host.plan()
    assert ("warn", "-", "no", "allow 9999/tcp") in _rules(plan)
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout
    assert host.rules()["allow 9999/tcp"] == ("hand rule", BOTH)
    assert "WARN: 'allow 9999/tcp'" in proc.stdout
    assert "ufw delete allow 9999/tcp" not in host.ufw_mutations()


def test_a_marked_rule_that_is_not_in_the_set_is_deleted(tmp_path: Path) -> None:
    host = Host(tmp_path, rules=[*MEASURED_RULES, ["allow 7000/tcp", "vpn-bot:extra", BOTH]])
    plan = host.plan()
    assert ("delete", "extra", "yes", "allow 7000/tcp") in _rules(plan)
    assert host.apply().returncode == 0
    assert "allow 7000/tcp" not in host.rules()


def test_extra_list_rules_get_the_extra_comment_and_closed_listeners_pass(tmp_path: Path) -> None:
    host = Host(tmp_path)
    (host.repo / "deploy/host/ufw/extra.list").write_text(
        "# test\nmain|allow from 203.0.113.7 to any port 9100 proto tcp|node exporter, scraped from the monitoring host only\n"
        "main|closed 8443/tcp|XRAY_XHTTP on the wildcard address, reached through the 443 fallback only\n"
        "relay|allow 1234/tcp|a relay line: a main server never reads it as its own\n", encoding="utf-8")
    host.flag("ss_tcp", TCP_MEASURED + 'LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("xray",pid=700,fd=9))\n'
              'LISTEN 0 4096 0.0.0.0:9100 0.0.0.0:* users:(("node_exporter",pid=77,fd=3))\n')
    plan = host.plan()
    assert ("add", "extra", "-", "allow from 203.0.113.7 to any port 9100 proto tcp") in _rules(plan)
    lst = {(x[0], x[2]) for x in _listeners(plan)}
    assert ("closed", "8443") in lst and ("ok", "9100") in lst and plan["listeners"] == ["ok"]
    assert host.apply().returncode == 0
    assert host.rules()["allow from 203.0.113.7 to any port 9100 proto tcp"] == ("vpn-bot:extra", ["v4"])
    assert "allow 1234/tcp" not in host.rules()


@pytest.mark.parametrize(("line", "why"), [
    ("main|allow 8080/tcp|short", "at least 20 characters"),
    ("main|allow 8080/tcp", "not 'role|rule|reason'"),
    ("main|allow OpenSSH|an application profile is not a rule we write", "no application profiles"),
    ("main|allow 8080/tcp comment 'x'|a comment is the helper's to write", "no comment"),
    ("edge|allow 8080/tcp|a role that does not exist anywhere", "is not main or relay"),
])
def test_a_bad_extra_list_refuses_the_plan(tmp_path: Path, line: str, why: str) -> None:
    host = Host(tmp_path)
    (host.repo / "deploy/host/ufw/extra.list").write_text(line + "\n", encoding="utf-8")
    proc = host.helper("plan", "--ssh-ports", "54321")
    assert proc.returncode == 3 and "result=refused" in proc.stdout and why in proc.stdout, proc.stdout
    applied = host.apply()
    assert applied.returncode == 3 and host.ufw_mutations() == []


# --------------------------------------------------------------------------- #
# 5. ssh: never locked out
# --------------------------------------------------------------------------- #
def test_22_goes_when_ssh_port_is_54321_and_sshd_t_says_54321(tmp_path: Path) -> None:
    host = Host(tmp_path, env=MAIN_ENV + "SSH_PORT=54321\n")
    assert host.apply().returncode == 0
    assert "allow 22/tcp" not in host.rules()
    assert host.rules()["allow 54321/tcp"][0] == "vpn-bot:ssh"


def test_22_stays_while_sshd_t_still_says_22(tmp_path: Path) -> None:
    """Before the Port drop-in is in place sshd -T says 22: the fallback would listen there."""
    host = Host(tmp_path, env=MAIN_ENV + "SSH_PORT=54321\n")
    host.flag("sshd_ports", "22")
    plan = host.plan()
    assert [r for r in _rules(plan) if r[3] == "allow 22/tcp"] == [("keep", "ssh", "no", "allow 22/tcp")]
    assert host.apply().returncode == 0
    assert "allow 22/tcp" in host.rules()


def test_a_marked_rule_for_the_port_sshd_listens_on_is_never_deleted(tmp_path: Path) -> None:
    host = Host(tmp_path, rules=[*MEASURED_RULES, ["allow 2222/tcp", "vpn-bot:ssh", BOTH]])
    host.flag("ss_tcp", TCP_MEASURED + 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=600,fd=3))\n')
    plan = host.plan()
    assert ("keep", "ssh", "yes", "allow 2222/tcp") in _rules(plan)
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout
    assert host.rules()["allow 2222/tcp"] == ("vpn-bot:ssh", BOTH)
    assert "sshd listens on 2222" in proc.stdout


def test_nothing_is_deleted_when_the_ssh_port_cannot_be_told(tmp_path: Path) -> None:
    host = Host(tmp_path)
    host.flag("socket_ports", "")
    host.flag("sshd_fail")
    host.flag("ss_fail")
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout   # not deleting is the safe direction, never a lockout
    assert "the port sshd listens on cannot be told" in proc.stdout
    assert "allow 22/tcp" in host.rules() and "route allow in on awg0 out on eth0 from 10.0.0.0/24" in host.rules()
    assert not [c for c in host.ufw_mutations() if "delete" in c]


def test_the_ssh_set_comes_from_the_ssh_port_plan_during_a_migration(tmp_path: Path) -> None:
    """No --ssh-ports (the bot, vpn-bot-ssh-port's firewall-open): the SSH port plan's
    listen set — both ports in phase 1 — is the ssh part of the set."""
    host = Host(tmp_path, env=MAIN_ENV + "SSH_PORT=60022\n")
    (host.repo / "deploy/host/ssh").mkdir(parents=True)
    for rel in ("deploy/host/ssh/ssh.socket-override.conf", "deploy/host/ssh/00-vpn-bot-port.conf"):
        (host.repo / rel).write_bytes((ROOT / rel).read_bytes())
    host.flag("ssh.socket.active", "active")
    proc = host.helper("apply", ssh_helper=str(SSH_HELPER))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rules = host.rules()
    assert rules["allow 60022/tcp"][0] == "vpn-bot:ssh" and rules["allow 54321/tcp"][0] == "vpn-bot:ssh"


# --------------------------------------------------------------------------- #
# 6. Listeners
# --------------------------------------------------------------------------- #
def test_udp_on_172_16_0_2_is_not_counted(tmp_path: Path) -> None:
    host = Host(tmp_path, markers=("awg", "mtproto", "hysteria2"))   # 443/udp is no module port of the set
    host.flag("ss_udp", 'UNCONN 0 0 172.16.0.2:443 0.0.0.0:* users:(("hysteria",pid=1000,fd=10))\n'
              'UNCONN 0 0 172.16.0.2:51000 0.0.0.0:* users:(("xray",pid=700,fd=11))\n'
              "UNCONN 0 0 *:32808 *:*\n")
    proc = host.helper("listeners", "--ssh-ports", "54321")
    assert proc.returncode == 0, proc.stdout
    assert "listener=info|udp|443|172.16.0.2|on a private address" in proc.stdout
    assert "listener=info|udp|32808|*|listen-port of out-warp (awg) — kernel-owned, random" in proc.stdout


def test_a_public_listener_on_a_module_udp_port_that_is_not_allowed_fails(tmp_path: Path) -> None:
    host = Host(tmp_path, markers=("awg", "mtproto", "hysteria2"))
    proc = host.helper("listeners", "--ssh-ports", "54321")
    assert proc.returncode == 4 and "listener=FAIL|udp|443|*|hysteria" in proc.stdout, proc.stdout


def test_a_public_tcp_listener_neither_allowed_nor_closed_fails(tmp_path: Path) -> None:
    host = Host(tmp_path)
    host.flag("ss_tcp", TCP_MEASURED + 'LISTEN 0 4096 [::]:8080 [::]:* users:(("nginx",pid=50,fd=6))\n'
              'LISTEN 0 4096 10.0.0.1:53 0.0.0.0:* users:(("dnsmasq",pid=51,fd=6))\n')
    proc = host.helper("listeners", "--ssh-ports", "54321")
    assert proc.returncode == 4, proc.stdout
    assert "listener=FAIL|tcp|8080|[::]|nginx listens on [::]:8080/tcp" in proc.stdout
    assert "|53|" not in proc.stdout, "a private address is not public"


# --------------------------------------------------------------------------- #
# 7. v4 and v6
# --------------------------------------------------------------------------- #
def test_a_missing_v6_copy_is_added(tmp_path: Path) -> None:
    host = Host(tmp_path, rules=[["allow 443/tcp", "vpn-bot:xray", ["v4"]], ["allow 54321/tcp", "vpn-bot:ssh", BOTH]])
    plan = host.plan()
    assert [r for r in plan["rule"] if "allow 443/tcp" in r][0].startswith("add|xray|-|allow 443/tcp|the v6 copy is missing")
    assert host.apply().returncode == 0
    assert host.rules()["allow 443/tcp"] == ("vpn-bot:xray", BOTH)


@pytest.mark.parametrize("why", ["IPV6=no", "no kernel IPv6"])
def test_no_v6_copy_is_expected_without_ipv6(tmp_path: Path, why: str) -> None:
    host = Host(tmp_path, rules=[["allow 443/tcp", "vpn-bot:xray", ["v4"]]])
    if why == "IPV6=no":
        host.put("etc/default/ufw", host.defaults().replace("IPV6=yes", "IPV6=no"))
    else:
        (host.root / "proc/sys/net/ipv6").rmdir()
    plan = host.plan()
    assert [r for r in plan["rule"] if "allow 443/tcp" in r][0].startswith("ok|xray|yes|allow 443/tcp")


# --------------------------------------------------------------------------- #
# 8. Policies and the dead-man
# --------------------------------------------------------------------------- #
def test_the_routed_policy_is_never_changed(tmp_path: Path) -> None:
    host = Host(tmp_path, forward="ACCEPT")
    assert host.apply().returncode == 0
    assert 'DEFAULT_FORWARD_POLICY="ACCEPT"' in host.defaults()
    assert not [c for c in host.ufw_mutations() if "routed" in c]
    (host.repo / "deploy/host/ufw/policy").write_text("main|routed|deny\n", encoding="utf-8")
    proc = host.helper("plan")
    assert proc.returncode == 3 and "routed policy is never managed" in proc.stdout


def test_the_policy_file_is_seeded_from_the_measurement() -> None:
    lines = [ln for ln in (ROOT / "deploy/host/ufw/policy").read_text(encoding="utf-8").splitlines()
             if ln and not ln.startswith("#")]
    assert lines == ["main|incoming|deny", "main|outgoing|allow"]


def _deadman(host: Host) -> dict[str, Any]:
    return json.loads(host.h(DEADMAN).read_text(encoding="utf-8"))


def test_a_new_incoming_policy_is_armed_with_a_deadman_first(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    runs = host.log("systemd-run")
    assert runs and "--unit=vpn-bot-ufw-deadman-watch" in runs[0] and runs[0].endswith(" deadman-check")
    calls_before_arm = int(runs[1].split()[1])
    assert not [c for c in host.log("ufw")[:calls_before_arm] if c.startswith("ufw default")], \
        "the dead-man is armed before the policy changes"
    assert "ufw default deny incoming" in host.ufw_mutations()
    st = _deadman(host)
    assert st["state"] == "pending" and st["prev_incoming"] == "allow" and st["ssh_ports"] == [54321]
    assert st["deadline"] - st["armed_at"] == 600
    assert "dead-man armed" in proc.stdout


def test_no_proof_by_the_deadline_reverts_the_policy(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    assert host.apply().returncode == 0
    waiting = host.helper("deadman-check", ssh_helper=str(SSH_HELPER))
    assert waiting.returncode == 0 and "waiting for a proof until" in waiting.stdout
    assert _deadman(host)["state"] == "pending"
    st = _deadman(host)
    st["deadline"] = int(time.time()) - 1
    host.put(DEADMAN, json.dumps(st))
    host.clear_logs()
    proc = host.helper("deadman-check", ssh_helper=str(SSH_HELPER))
    assert proc.returncode == 0 and "REVERTED" in proc.stdout, proc.stdout
    assert "ufw default allow incoming" in host.ufw_mutations()
    assert _deadman(host)["state"] == "reverted"
    assert "systemctl stop vpn-bot-ufw-deadman-watch.timer" in host.log("systemctl")


def test_a_new_ssh_connection_from_outside_confirms_the_change(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    assert host.apply().returncode == 0
    host.flag("journal", "2026-11-13T10:00:00+0000 main sshd[901]: Connection from 203.0.113.9 port 51022 "
              "on 198.51.100.7 port 54321 rdomain \"\"\n")
    proc = host.helper("deadman-check", ssh_helper=str(SSH_HELPER))
    assert proc.returncode == 0 and "confirmed (journal:" in proc.stdout, proc.stdout + proc.stderr
    st = _deadman(host)
    assert st["state"] == "confirmed" and "203.0.113.9" in st["proof"]
    assert "ufw default allow incoming" not in host.ufw_mutations()


def test_a_local_connection_proves_nothing(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    assert host.apply().returncode == 0
    host.flag("journal", "2026-11-13T10:00:00+0000 main sshd[901]: Connection from 127.0.0.1 port 51022 "
              "on 127.0.0.1 port 54321 rdomain \"\"\n")
    proc = host.helper("deadman-check", ssh_helper=str(SSH_HELPER))
    assert "waiting for a proof" in proc.stdout and _deadman(host)["state"] == "pending"


def test_the_bots_confirmation_keeps_the_change_and_a_stale_button_is_refused(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    assert host.apply().returncode == 0
    armed = _deadman(host)["armed_at"]
    stale = host.helper("confirm", "--since", str(armed - 5), "--admin", "42")
    assert stale.returncode == 3 and "stale" in stale.stderr
    ok = host.helper("confirm", "--since", str(armed), "--admin", "42")
    assert ok.returncode == 0 and "confirmed" in ok.stdout, ok.stderr
    st = _deadman(host)
    assert st["state"] == "confirmed" and st["bot_confirm"]["admin_id"] == 42


def test_an_inactive_ufw_is_enabled_under_a_deadman(tmp_path: Path) -> None:
    host = Host(tmp_path, active=False)
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout
    assert "ufw --force enable" in host.ufw_mutations()
    st = _deadman(host)
    assert st["prev_active"] is False and {"what": "ufw", "from": "inactive", "to": "active"} in st["changes"]
    st["deadline"] = int(time.time()) - 1
    host.put(DEADMAN, json.dumps(st))
    assert host.helper("deadman-check").returncode == 0
    assert "ufw disable" in host.ufw_mutations(), "no proof: ufw goes back to inactive"


def test_no_deadman_no_change(tmp_path: Path) -> None:
    host = Host(tmp_path, active=False, incoming="ACCEPT")
    host.flag("systemd_run_fail")
    proc = host.apply()
    assert proc.returncode == 9, proc.stdout
    assert not [c for c in host.ufw_mutations() if c.startswith(("ufw default", "ufw --force enable"))]
    assert not host.h(DEADMAN).exists()
    assert host.rules()["allow 54321/tcp"][0] == "vpn-bot:ssh", "the rules part still converged"


def test_after_a_reboot_the_deadman_is_rearmed_or_reverts(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    assert host.apply().returncode == 0
    host.flag("vpn-bot-ufw-deadman-watch.timer.active", "inactive")       # the reboot ended the timer
    host.clear_logs()
    proc = host.helper("deadman-check")
    assert "re-armed" in proc.stdout and host.log("systemd-run")
    unit = (ROOT / "deploy/host/systemd/vpn-bot-ufw-deadman.service").read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/sbin/vpn-bot-ufw-apply deadman-check" in unit
    assert "ConditionPathExists=/var/lib/vpn-bot/ufw-deadman.json" in unit and "[Install]" not in unit
    hc = (ROOT / "deploy/host/systemd/vpn-bot-host-check.service").read_text(encoding="utf-8")
    assert "Wants=vpn-bot-ufw-deadman.service" in hc and "After=vpn-bot-ufw-deadman.service" in hc


# --------------------------------------------------------------------------- #
# 9. save / restore, status, the test seam
# --------------------------------------------------------------------------- #
def test_save_and_restore_put_the_firewall_back(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    snap = tmp_path / "snap"
    assert host.helper("save", "--dir", str(snap)).returncode == 0
    before_rules = host.h("etc/ufw/user.rules").read_text(encoding="utf-8")
    before_defaults = host.defaults()
    assert host.apply().returncode == 0
    assert host.h(DEADMAN).exists()
    host.clear_logs()
    proc = host.helper("restore", "--dir", str(snap))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert host.h("etc/ufw/user.rules").read_text(encoding="utf-8") == before_rules
    assert host.defaults() == before_defaults
    assert not host.h(DEADMAN).exists(), "the dead-man state this run created is gone"
    assert "systemctl stop vpn-bot-ufw-deadman-watch.timer" in host.log("systemctl")
    assert "ufw reload" in host.ufw_mutations()


def test_status_is_one_line(tmp_path: Path) -> None:
    host = Host(tmp_path)
    proc = host.helper("status")
    assert proc.returncode == 0 and len(proc.stdout.strip().splitlines()) == 1
    assert proc.stdout.startswith("ufw: active; incoming deny, outgoing allow, routed deny (not managed)")


def test_the_test_seam_never_reaches_a_real_tool(tmp_path: Path) -> None:
    host = Host(tmp_path)
    (host.stub / "ufw").unlink()
    proc = host.apply()
    assert proc.returncode == 5 and "not installed" in proc.stderr
    env = host.env_run()
    env.pop("VPN_BOT_UFW_SELFTEST_BIN")
    argv = ["python3", "-I", str(HELPER), "--env", str(host.env_file), "--repo", str(host.repo),
            "--root", str(host.root), "plan"]
    out = subprocess.run(argv, env=env, capture_output=True, text=True, check=False).stdout
    assert "ufw=absent" in out, "without the stub directory every tool is refused"
    argv.remove("--root")
    argv.remove(str(host.root))
    proc = subprocess.run(argv, env=host.env_run(), capture_output=True, text=True, check=False)
    assert proc.returncode == 5 and "needs --root" in proc.stderr


def test_a_relay_has_no_ufw(tmp_path: Path) -> None:
    host = Host(tmp_path, env="NODE_ROLE=relay\n")
    proc = host.helper("plan")
    assert proc.returncode == 3 and "vpnrelay_input" in proc.stdout + proc.stderr


# --------------------------------------------------------------------------- #
# 10. vpn-bot-ssh-port: the journal proof for any port
# --------------------------------------------------------------------------- #
def test_ssh_port_helper_proof_journal(tmp_path: Path) -> None:
    host = Host(tmp_path)
    host.flag("journal", "2026-11-13T10:00:00+0000 main sshd[1]: Connection from 203.0.113.9 port 1 "
              "on 198.51.100.7 port 54321 rdomain \"\"\n")
    argv = ["python3", "-I", str(SSH_HELPER), "--env", str(host.env_file), "--repo", str(ROOT), "--role", "main",
            "--root", str(host.root), "proof-journal", "--ports", "22,54321", "--since", "1"]
    out = subprocess.run(argv, env=host.env_run(), capture_output=True, text=True, check=False)
    assert out.returncode == 0 and "proof=journal" in out.stdout and "on port 54321" in out.stdout, out.stderr
    argv[-3] = "22"
    none = subprocess.run(argv, env=host.env_run(), capture_output=True, text=True, check=False).stdout
    assert "proof=none" in none


# --------------------------------------------------------------------------- #
# 11. deploy.sh: Phase 1 «UFW», Phase 2 save -> apply -> listeners, the rollback
# --------------------------------------------------------------------------- #
class Deploy(Host):
    """The same fake main server, driven through deploy.sh's functions (DEPLOY_SELFTEST)."""

    def __init__(self, tmp: Path, **kw: Any) -> None:
        super().__init__(tmp, **kw)
        (self.repo / "scripts/vpn-bot-ufw-apply").write_bytes(HELPER.read_bytes())
        self.stage = tmp / "stage"
        self.stage.mkdir()

    def deploy(self, body: str, *, phase1_only: int = 0, ufw_root: bool = True) -> subprocess.CompletedProcess[str]:
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -uo pipefail\nexport DEPLOY_SELFTEST=1\n"
            f'source "{DEPLOY_SH}"\n'
            'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""\n'
            f'STAGE="{self.stage}"; APP_DIR="{self.repo}"; ENV_FILE="{self.env_file}"\n'
            f'UFW_ROOT="{self.root if ufw_root else ""}"; NODE_ROLE=main; PHASE1_ONLY={phase1_only}\n'
            'SSH_PLAN_LISTEN=54321; SSH_PORT_HELPER=/nonexistent/vpn-bot-ssh-port\n'
            "MANAGED_HOST_FILES=(); OUT_OF_REPO_HELPERS=()\n"
            'rollback() { set +e; echo "ROLLBACK_CALLED"; host_files_rollback; exit 42; }\n'
            + body,
            encoding="utf-8",
        )
        proc = subprocess.run(["bash", str(driver)], cwd=str(self.tmp), env=self.env_run(),
                              capture_output=True, text=True, check=False, timeout=120)
        proc.stdout = proc.stdout + "\n--STDERR--\n" + proc.stderr
        return proc


D_PHASE1 = 'ufw_phase1 "$APP_DIR"; echo PHASE1-OK; ufw_report_block\n'
D_PHASE2 = (D_PHASE1 + 'ufw_phase2_save\nufw_phase2_apply\necho PHASE2-OK\n'
            'ufw_after_deploy\necho "FINAL: ${UFW_FINAL_STATUS}"\n')


def test_deploy_phase1_reports_the_plan_and_changes_nothing(tmp_path: Path) -> None:
    host = Deploy(tmp_path)
    proc = host.deploy(D_PHASE1)
    assert proc.returncode == 0 and "PHASE1-OK" in proc.stdout, proc.stdout
    assert "UFW (scripts/vpn-bot-ufw-apply plan; docs/host-state.md#the-firewall-ufw):" in proc.stdout
    assert "delete ssh          'allow 22/tcp'" in proc.stdout
    assert "--- UFW (scripts/vpn-bot-ufw-apply — docs/host-state.md#the-firewall-ufw) ---" in proc.stdout
    assert "policy routed    deny (not managed)" in proc.stdout
    assert host.ufw_mutations() == []


def test_deploy_phase1_stops_on_a_listener_nobody_allowed(tmp_path: Path) -> None:
    host = Deploy(tmp_path)
    host.flag("ss_tcp", TCP_MEASURED + 'LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("nginx",pid=50,fd=6))\n')
    proc = host.deploy(D_PHASE1)
    assert proc.returncode == 1 and "PHASE1-OK" not in proc.stdout, proc.stdout
    assert "a public listener is neither allowed by the set nor declared closed" in proc.stdout
    assert "nothing was changed" in proc.stdout and host.ufw_mutations() == []
    inspect = host.deploy(D_PHASE1, phase1_only=1)
    assert inspect.returncode == 0 and "PHASE1-OK" in inspect.stdout and "PHASE1_ONLY=1" in inspect.stdout


@pytest.mark.parametrize("bad", ["extra", "noufw"])
def test_deploy_phase1_stops_on_a_refused_plan_or_a_missing_ufw(tmp_path: Path, bad: str) -> None:
    host = Deploy(tmp_path)
    if bad == "extra":
        (host.repo / "deploy/host/ufw/extra.list").write_text("main|allow 1/tcp|short\n", encoding="utf-8")
        want = "the UFW plan was refused"
    else:
        (host.stub / "ufw").unlink()
        want = "ufw is not installed"
    proc = host.deploy(D_PHASE1)
    assert proc.returncode == 1 and want in proc.stdout, proc.stdout


def test_deploy_phase2_applies_then_checks_the_listeners(tmp_path: Path) -> None:
    host = Deploy(tmp_path)
    proc = host.deploy(D_PHASE2)
    assert proc.returncode == 0 and "PHASE2-OK" in proc.stdout, proc.stdout
    assert "saved the UFW state (active)" in proc.stdout
    assert "ufw: every public TCP listener and every module UDP port is allowed or declared closed" in proc.stdout
    assert set(host.rules()) == {"allow 443/tcp", "allow 31337/tcp", "allow 54321/tcp", "allow 443/udp",
                                 "allow 2096/tcp"}
    assert "FINAL: ufw: active; incoming deny, outgoing allow, routed deny (not managed); 5 rule(s)" in proc.stdout


def test_deploy_a_later_failure_restores_the_saved_ufw_state(tmp_path: Path) -> None:
    host = Deploy(tmp_path)
    rules_before = host.h("etc/ufw/user.rules").read_text(encoding="utf-8")
    proc = host.deploy(D_PHASE1 + 'ufw_phase2_save\nufw_phase2_apply\nrollback_now "a later step failed"\n')
    assert proc.returncode == 42 and "ROLLBACK_CALLED" in proc.stdout, proc.stdout
    assert "ufw restored to the state saved before this deploy" in proc.stdout
    assert host.h("etc/ufw/user.rules").read_text(encoding="utf-8") == rules_before
    assert "ufw reload" in host.ufw_mutations()


def test_deploy_a_listener_failure_after_apply_rolls_back(tmp_path: Path) -> None:
    host = Deploy(tmp_path)
    rules_before = host.h("etc/ufw/user.rules").read_text(encoding="utf-8")
    # Phase 1 saw a clean host; between Phase 1 and the apply a listener appeared.
    body = (D_PHASE1 + 'ufw_phase2_save\n'
            f"printf '%s\\n' 'LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:((\"nginx\",pid=50,fd=6))' >> \"{host.sd}/ss_tcp\"\n"
            'ufw_phase2_apply\necho NOT-REACHED\n')
    proc = host.deploy(body)
    assert proc.returncode == 42 and "NOT-REACHED" not in proc.stdout, proc.stdout
    assert "tcp|8080|0.0.0.0|nginx listens" in proc.stdout
    assert host.h("etc/ufw/user.rules").read_text(encoding="utf-8") == rules_before


def test_deploy_selftest_never_reaches_the_real_firewall_without_ufw_root(tmp_path: Path) -> None:
    host = Deploy(tmp_path)
    proc = host.deploy(D_PHASE1, ufw_root=False)
    assert proc.returncode == 1 and "DEPLOY_SELFTEST: UFW_ROOT is empty" in proc.stdout, proc.stdout


def test_deploy_main_flow_order() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert 'host_invariants_phase1 "$WT"\n\n# UFW' in text and '\nufw_phase1 "$WT"\n' in text
    p2 = text[text.index("\ninstall_out_of_repo_helpers\n"):]
    order = [p2.index(x) for x in ("\nufw_phase2_save\n", "\nssh_port_phase2_pre\n", "\ninstall_managed_host_files\n",
                                   "\nssh_port_phase2_post\n", "\nufw_phase2_apply\n", '\nhost_invariants_phase2 "$APP_DIR"\n')]
    assert order == sorted(order), "save before anything touches ufw; apply after the host files and the SSH state"
    assert "\nssh_port_after_deploy\nufw_after_deploy\n" in text
    assert "${UFW_FINAL_STATUS:-ufw: not checked}" in text
    assert "  ssh_port_rollback\n  ufw_rollback\n" in text
    assert "ufw-subscription" not in text
    assert '"scripts/vpn-bot-ufw-apply|/usr/local/sbin/vpn-bot-ufw-apply|required"' in text
    assert ('"deploy/host/systemd/vpn-bot-ufw-deadman.service|/etc/systemd/system/vpn-bot-ufw-deadman.service'
            '|0644|root:root|unit|main"') in text


# --------------------------------------------------------------------------- #
# 12. The host check: family ufw
# --------------------------------------------------------------------------- #
QUIET = "exit 0\n"


def _host_check(host: Host, *extra: str) -> list[tuple[str, str, str, str, str]]:
    (host.repo / "scripts/vpn-bot-ufw-apply").write_bytes(HELPER.read_bytes())
    (host.repo / "deploy/host/invariants.list").write_text("# none\n", encoding="utf-8")
    for name in ("sysctl", "systemd-analyze", "dpkg", "dpkg-query", "logrotate"):
        if not (host.stub / name).exists():
            _stub(host.stub / name, QUIET)
    reg = host.tmp / "registry"
    reg.write_text("", encoding="utf-8")
    args = ["bash", str(HOST_CHECK), "--repo", str(host.repo), "--role", "main", "--root", str(host.root),
            "--env", str(host.env_file), "--registry", str(reg), "--no-state", *extra]
    proc = subprocess.run(args, cwd=str(host.tmp), env=host.env_run(), capture_output=True, text=True, check=False,
                          timeout=120)
    rows = [tuple(ln.split("|", 4)) for ln in proc.stdout.splitlines() if "|" in ln and not ln.startswith("SUMMARY|")]
    return [r for r in rows if r[1] == "ufw"]  # type: ignore[misc]


def test_host_check_judges_the_measured_main_server(tmp_path: Path) -> None:
    host = Host(tmp_path)
    rows = {(r[0], r[2]) for r in _host_check(host)}
    assert ("OK", "active") in rows and ("OK", "policy incoming") in rows
    assert ("INFO", "allow 443/tcp") in rows, "untagged: apply relabels it"
    assert ("LATENT", "allow 22/tcp") in rows, "an unmarked rule that is not in the set"
    assert ("LATENT", "route allow in on awg0 out on eth0 from 10.0.0.0/24") in rows
    pre = {(r[0], r[2]) for r in _host_check(host, "--pre-install")}
    assert ("PENDING", "allow 22/tcp") in pre and ("PENDING", "allow 443/tcp") in pre


def test_host_check_after_apply_is_clean(tmp_path: Path) -> None:
    host = Host(tmp_path)
    assert host.apply().returncode == 0
    rows = _host_check(host)
    assert {r[0] for r in rows} <= {"OK"}, rows


def test_host_check_mismatch_for_a_missing_or_a_marked_extra_rule_and_inactive(tmp_path: Path) -> None:
    host = Host(tmp_path, active=False,
                rules=[["allow 443/tcp", "vpn-bot:xray", ["v4"]], ["allow 7000/tcp", "vpn-bot:extra", BOTH],
                       ["allow 9999/tcp", "", BOTH]])
    rows = {(r[0], r[2]): r[4] for r in _host_check(host)}
    assert ("MISMATCH", "active") in rows
    assert ("MISMATCH", "allow 443/tcp") in rows and "v6 copy is missing" in rows["MISMATCH", "allow 443/tcp"]
    assert ("MISMATCH", "allow 31337/tcp") in rows, "a rule of the set that is missing"
    assert ("MISMATCH", "allow 7000/tcp") in rows, "a marked rule that is not in the set"
    assert ("LATENT", "allow 9999/tcp") in rows, "an unmarked one nothing claims"
    pre = {(r[0], r[2]) for r in _host_check(host, "--pre-install")}
    assert ("PENDING", "active") in pre and ("LATENT", "allow 9999/tcp") in pre


def test_host_check_mismatch_for_a_policy_and_a_missing_ufw(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT")
    rows = {(r[0], r[2]) for r in _host_check(host)}
    assert ("MISMATCH", "policy incoming") in rows
    (host.stub / "ufw").unlink()
    rows2 = {(r[0], r[2]) for r in _host_check(host)}
    assert ("MISMATCH", "ufw") in rows2


# --------------------------------------------------------------------------- #
# 13. The bot: apply after enable and after a removal; the dead-man message
# --------------------------------------------------------------------------- #
class _FakeApplier:
    def __init__(self, ok: bool = True) -> None:
        self.reasons: list[str] = []
        self.ok = ok

    async def apply(self, reason: str) -> Any:
        from services.ufw import UfwApplyResult
        self.reasons.append(reason)
        return UfwApplyResult(self.ok, "5 rule(s) in place, 0 added" if self.ok else "exit 4", 0 if self.ok else 4)


class _Runner:
    def __init__(self, rc: int = 0, stdout: str = "") -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self.rc = rc
        self.stdout = stdout

    async def run(self, helper: Path, args: Any, **_: Any) -> Any:
        from models.dto import ShellResult
        self.calls.append((str(helper), list(args)))
        return ShellResult(("x",), self.rc, self.stdout, "")


def test_the_applier_runs_the_installed_helper_with_apply_only() -> None:
    from services.ufw import HELPER_PATH, UfwApplier

    runner = _Runner(0, "vpn-bot-ufw-apply: adopted ...\nvpn-bot-ufw-apply: 5 rule(s) in place, 0 added\n")
    res = asyncio.run(UfwApplier(runner=runner).apply("enabling socks5"))  # type: ignore[arg-type]
    assert runner.calls == [(str(HELPER_PATH), ["apply"])] and str(HELPER_PATH) == "/usr/local/sbin/vpn-bot-ufw-apply"
    assert res.ok and res.summary == "5 rule(s) in place, 0 added"
    bad = asyncio.run(UfwApplier(runner=_Runner(4, "vpn-bot-ufw-apply: FAIL: x\n")).apply("t"))  # type: ignore[arg-type]
    assert not bad.ok and bad.returncode == 4


def test_enabling_a_protocol_runs_the_firewall(tmp_path: Path) -> None:
    from test_protocol_uninstall_bot import ADMIN, _world

    async def scenario() -> None:
        w = await _world(tmp_path)
        try:
            fw = _FakeApplier()
            w.modules.attach_firewall(fw)
            res = await w.modules.enable_protocol("xray", ADMIN)
            assert fw.reasons == ["enabling xray"] and res is not None and res.ok
            fw.ok = False
            bad = await w.modules.enable_protocol("xray", ADMIN)
            assert bad is not None and not bad.ok, "a failed apply is reported, the switch stands"
            assert await w.modules.is_enabled("xray")
        finally:
            await w.db.close()

    asyncio.run(scenario())


def test_removing_a_protocol_runs_the_firewall_after_the_marker(tmp_path: Path) -> None:
    from test_protocol_uninstall_bot import ADMIN, _marker, _plan, _world

    async def scenario() -> None:
        w = await _world(tmp_path)
        try:
            fw = _FakeApplier()
            w.service._firewall = fw
            backup = "/var/backups/vpn-bot/uninstall/xray-20261113T100000Z.tar.gz"
            w.runner.plans = [_plan()]
            w.runner.apply_out = {"ok": True, "protocol": "xray", "sha256": "a" * 64, "backup": backup,
                                  "removed": [], "already_absent": [], "skipped": [], "errors": []}
            w.runner.on_apply = lambda: _marker(tmp_path / "uninstalled", "xray", sha256="a" * 64, backup=backup)
            report = await w.service.apply("xray", "a" * 64, ADMIN)
            assert report.ok and fw.reasons == ["removing xray from the host"]
            assert report.firewall_ok is True and "rule(s) in place" in report.firewall
            from bot.uninstall_texts import uninstall_report_text
            assert "🧱 UFW" in uninstall_report_text(report)
            # A failed removal never runs the firewall.
            fw.reasons.clear()
            w.runner.plans = [_plan(sha="b" * 64)]
            w.runner.apply_rc = 70
            w.runner.apply_out = {"ok": False, "protocol": "xray", "failed_step": "units", "errors": ["x"],
                                  "rolled_back": True, "rollback_errors": []}
            w.runner.on_apply = None
            w.registry.refresh()
        finally:
            await w.db.close()

    asyncio.run(scenario())


def test_the_uninstall_plan_says_the_firewall_is_ufw_applys(tmp_path: Path) -> None:
    from bot.uninstall_texts import uninstall_plan_text
    from services.protocol_uninstall import UninstallPlan
    from test_protocol_uninstall_bot import _plan

    data = _plan()
    data.pop("ufw")
    text = uninstall_plan_text(UninstallPlan.from_json(data))
    assert "vpn-bot-ufw-apply" in text


class _Meta:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get_meta(self, key: str) -> str | None:
        return self.data.get(key)

    async def set_meta(self, key: str, value: str) -> None:
        self.data[key] = value


def test_the_bot_tells_a_pending_change_once_and_confirms_through_the_helper(tmp_path: Path) -> None:
    from services.ufw import UfwConfirmError, UfwDeadmanMonitor, parse_callback_data

    state = tmp_path / "ufw-deadman.json"
    armed = int(time.time())
    sent: list[tuple[str, Any]] = []

    async def send(text: str, markup: Any) -> None:
        sent.append((text, markup))

    runner = _Runner(0, "confirmed: incoming policy: allow -> deny (superadmin 42); dead-man stopped\n")
    mon = UfwDeadmanMonitor(store=_Meta(), admin_ids=frozenset({42}), path=state, runner=runner, send=send)  # type: ignore[arg-type]

    async def scenario() -> None:
        state.write_text(json.dumps({"state": "pending", "armed_at": armed, "deadline_iso": "2026-11-13T10:10:00Z",
                                     "changes": [{"what": "incoming policy", "from": "allow", "to": "deny"}],
                                     "ssh_ports": [54321]}), encoding="utf-8")
        await mon.check_once()
        await mon.check_once()
        assert len(sent) == 1 and "54321" in sent[0][0] and sent[0][1] is not None
        cb = sent[0][1].inline_keyboard[0][0].callback_data
        assert parse_callback_data(cb) == armed
        with pytest.raises(UfwConfirmError):
            await mon.confirm(42, armed - 1)
        line = await mon.confirm(42, armed)
        assert runner.calls == [("/usr/local/sbin/vpn-bot-ufw-apply",
                                 ["confirm", "--since", str(armed), "--admin", "42"])] and "confirmed" in line
        state.write_text(json.dumps({"state": "reverted", "armed_at": armed, "done_iso": "2026-11-13T10:10:05Z",
                                     "changes": [{"what": "incoming policy", "from": "allow", "to": "deny"}]}),
                         encoding="utf-8")
        await mon.check_once()
        await mon.check_once()
        assert len(sent) == 2 and sent[1][1] is None

    asyncio.run(scenario())


def test_the_sudoers_grant_is_apply_and_confirm_only() -> None:
    text = (ROOT / "deploy/sudoers.d/vpn-bot.example").read_text(encoding="utf-8")
    grants = [ln.strip().rstrip(", \\") for ln in text.splitlines() if "/usr/local/sbin/vpn-bot-ufw-apply" in ln
              and not ln.lstrip().startswith("#")]
    assert grants == ["/usr/local/sbin/vpn-bot-ufw-apply apply", "/usr/local/sbin/vpn-bot-ufw-apply confirm *"]
    assert "VPN_BOT_SSH_PORT, VPN_BOT_UFW\n" in text


# --------------------------------------------------------------------------- #
# 14. Review fixes (PR #331): live ssh ports before enabling, a failed revert, the
#     application's booleans, a marked rule of a module whose port is unknown
# --------------------------------------------------------------------------- #
def test_the_port_sshd_really_listens_on_is_opened_before_ufw_is_enabled(tmp_path: Path) -> None:
    """ufw inactive, no rules, ssh.socket inactive and sshd on 22: SSH_PORT (54321) alone
    would lock new ssh connections out — 22 is opened first."""
    host = Host(tmp_path, active=False, rules=[], ssh=(22,))
    host.flag("ssh.socket.active", "inactive")
    host.flag("socket_ports", "")
    host.flag("ss_tcp", 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=600,fd=3))\n')
    plan = host.plan()
    assert ("add", "ssh", "-", "allow 22/tcp") in _rules(plan)
    proc = host.apply()
    assert proc.returncode == 0, proc.stdout
    muts = host.ufw_mutations()
    assert muts.index("ufw allow 22/tcp comment vpn-bot:ssh") < muts.index("ufw --force enable")
    assert host.rules()["allow 22/tcp"][0] == "vpn-bot:ssh" and host.rules()["allow 54321/tcp"][0] == "vpn-bot:ssh"
    # Enabled: 22 is no longer added, only kept while sshd listens there.
    host.clear_logs()
    assert ("keep", "ssh", "yes", "allow 22/tcp") in _rules(host.plan())


def test_ufw_is_not_enabled_when_the_ssh_port_cannot_be_told(tmp_path: Path) -> None:
    host = Host(tmp_path, active=False)
    host.flag("socket_ports", "")
    host.flag("sshd_fail")
    host.flag("ss_fail")
    proc = host.apply()
    assert proc.returncode == 4 and "cannot be told" in proc.stdout, proc.stdout
    assert "ufw --force enable" not in host.ufw_mutations() and host.log("systemd-run") == []


def test_a_failed_revert_stays_pending_and_is_retried(tmp_path: Path) -> None:
    host = Host(tmp_path, active=False)
    assert host.apply().returncode == 0
    st = _deadman(host)
    st["deadline"] = int(time.time()) - 1
    host.put(DEADMAN, json.dumps(st))
    host.flag("ufw_fail_disable")
    host.clear_logs()
    proc = host.helper("deadman-check")
    assert proc.returncode == 5 and "REVERT FAILED" in proc.stdout, proc.stdout
    st = _deadman(host)
    assert st["state"] == "pending" and "revert failed" in st["last_error"]
    assert "systemctl stop vpn-bot-ufw-deadman-watch.timer" not in host.log("systemctl"), "the timer keeps retrying"
    (host.sd / "ufw_fail_disable").unlink()
    again = host.helper("deadman-check")
    assert again.returncode == 0 and "REVERTED" in again.stdout and _deadman(host)["state"] == "reverted"


@pytest.mark.parametrize("value", ["y", "Y", "yes", "on", "1", "true", " true "])
def test_the_enable_flags_read_as_the_application_reads_them(tmp_path: Path, value: str) -> None:
    host = Host(tmp_path, env=MAIN_ENV.replace("SUBSCRIPTION_ENABLED=true", f"SUBSCRIPTION_ENABLED={value}"))
    modules = dict(v.split("|", 2)[:2] for v in host.plan()["module"])
    assert modules["subscription"] == "on"
    m = _mod()
    from config import settings
    for v in ("y", "n", "yes", "no", "on", "off", "1", "0", "true", "false"):
        assert m.is_true(v) == (v in {"1", "true", "yes", "y", "on"})
    assert "{\"1\", \"true\", \"yes\", \"y\", \"on\"}" in Path(settings.__file__).read_text(encoding="utf-8")


def test_a_marked_rule_of_a_module_whose_port_is_unknown_stays(tmp_path: Path) -> None:
    """AWG on, its config unreadable and AWG_ENDPOINT_PORT unset: its marked udp rule is
    still its own — kept, never deleted on a guess."""
    host = Host(tmp_path, markers=("mtproto",),
                rules=[*MEASURED_RULES, ["allow 11880/udp", "vpn-bot:awg", BOTH]])
    plan = host.plan()
    assert ("keep", "awg", "yes", "allow 11880/udp") in _rules(plan)
    assert host.apply().returncode == 0
    assert host.rules()["allow 11880/udp"] == ("vpn-bot:awg", BOTH)


def test_no_risky_step_when_the_live_ssh_rule_could_not_be_added(tmp_path: Path) -> None:
    """The ssh allowance failed to go in: ufw stays inactive, no dead-man is armed."""
    host = Host(tmp_path, active=False, rules=[], ssh=(22,))
    host.flag("ssh.socket.active", "inactive")
    host.flag("socket_ports", "")
    host.flag("ss_tcp", 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=600,fd=3))\n')
    host.flag("ufw_fail_add")
    proc = host.apply()
    assert proc.returncode == 4, proc.stdout
    assert "ufw does not open the port(s) sshd listens on (22)" in proc.stdout
    assert "ufw --force enable" not in host.ufw_mutations() and host.log("systemd-run") == []
    assert json.loads((host.sd / "ufw.json").read_text(encoding="utf-8"))["active"] is False
    assert not host.h(DEADMAN).exists()


def test_a_missing_v6_copy_of_the_live_ssh_rule_blocks_a_new_policy(tmp_path: Path) -> None:
    host = Host(tmp_path, incoming="ACCEPT", rules=[["allow 54321/tcp", "vpn-bot:ssh", ["v4"]]])
    host.flag("ufw_fail_add")
    proc = host.apply()
    assert proc.returncode == 4 and "(54321)" in proc.stdout, proc.stdout
    assert not [c for c in host.ufw_mutations() if c.startswith("ufw default")]


@pytest.mark.parametrize("expired", [True, False])
def test_restoring_a_pending_change_runs_its_deadman_again(tmp_path: Path, expired: bool) -> None:
    """A deploy saved a host whose policy change still waited for its proof; meanwhile the
    dead-man reverted it; the rollback brings the unproven policy back — and its recovery:
    reverted at once when the deadline has passed, the timer re-armed when it has not."""
    host = Host(tmp_path, incoming="ACCEPT")
    assert host.apply().returncode == 0                       # pending: incoming deny
    st = _deadman(host)
    if expired:
        st["deadline"] = int(time.time()) - 1
    host.put(DEADMAN, json.dumps(st))
    snap = tmp_path / "snap"
    assert host.helper("save", "--dir", str(snap)).returncode == 0
    # The dead-man fires (its deadline forced past) and the timer goes.
    st2 = dict(st, deadline=int(time.time()) - 1)
    host.put(DEADMAN, json.dumps(st2))
    assert "REVERTED" in host.helper("deadman-check").stdout
    assert 'DEFAULT_INPUT_POLICY="ACCEPT"' in host.defaults()
    host.clear_logs()
    proc = host.helper("restore", "--dir", str(snap))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "its dead-man runs again" in proc.stdout
    if expired:
        assert _deadman(host)["state"] == "reverted" and 'DEFAULT_INPUT_POLICY="ACCEPT"' in host.defaults()
        assert "ufw default allow incoming" in host.ufw_mutations()
    else:
        assert _deadman(host)["state"] == "pending" and 'DEFAULT_INPUT_POLICY="DROP"' in host.defaults()
        assert host.log("systemd-run"), "the restored change has its timer again"
