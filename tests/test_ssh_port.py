"""The SSH port follows SSH_PORT on both roles, in two proven phases.

scripts/vpn-bot-ssh-port (the decision, the proofs, phase 2 outside a deploy),
scripts/deploy.sh (Phase 1 plan, the render=ssh-port host files, phase 1 / phase 2
inside a deploy, the rollback), scripts/vpn-bot-host-check (family ssh-port) and the
bot's monitor (services/ssh_port.py) — docs/host-state.md#the-ssh-port.

Every command is a stub on PATH that emulates ssh.socket from the files on a fake
host (tmp/root): `systemctl daemon-reload` loads the ListenStream ports of the
override, `systemctl restart ssh.socket` makes them listen, `ss` shows what listens,
`sshd -T` reads the Port lines, `journalctl` prints a fixture, `ufw` keeps its rules
in a file. VPN_BOT_SSH_PORT_SELFTEST=1 fences every write of the helper to that root.
deploy.sh runs this suite AS ROOT on the production host in Phase 1: nothing here may
reach a real path or a real command.

Pinned:
1. SSH_PORT: absent -> 54321; not a port, or the port of a service of the role, or a
   port another process listens on -> refused (Phase 1 stops, nothing changed).
2. Phase 1 listens on BOTH ports and opens the new one in the firewall first; the old
   port is never touched; the state file is written.
3. Without a proof there is no phase 2 — not in a deploy, not in `advance`.
4. Each proof — main's probe of the relay, a non-local connection in the sshd log, the
   bot's «Подтвердить» — leads to phase 2: the old port leaves the socket, the Port
   drop-in and the firewall.
5. A failed post-check rolls back to the previous set (deploy: rollback_now; advance:
   its own revert), the firewall rule phase 1 opened goes again.
6. main already on SSH_PORT: nothing changes but the new Port drop-in.
7. The host check: MISMATCH before a migration started, PENDING in phase 1, the
   fallback port (`sshd -T`) checked against SSH_PORT afterwards.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpn-bot-ssh-port"
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
HOST_CHECK = ROOT / "scripts" / "vpn-bot-host-check"
SOCKET_TPL = ROOT / "deploy" / "host" / "ssh" / "ssh.socket-override.conf"
PORT_TPL = ROOT / "deploy" / "host" / "ssh" / "00-vpn-bot-port.conf"

OVERRIDE = "/etc/systemd/system/ssh.socket.d/override.conf"
PORT_DROPIN = "/etc/ssh/sshd_config.d/00-vpn-bot-port.conf"
STATE = "/var/lib/vpn-bot/ssh-migration.json"
MARKER = "/etc/vpn-relay/input.confirmed"

pytestmark = pytest.mark.timeout(90)


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def render(template: Path, *ports: int) -> str:
    out: list[str] = []
    for line in template.read_text(encoding="utf-8").splitlines(keepends=True):
        if "@SSH_PORT@" in line:
            out.extend(line.replace("@SSH_PORT@", str(p)) for p in sorted(set(ports)))
        else:
            out.append(line)
    return "".join(out)


# --------------------------------------------------------------------------- #
# Stubs. $R = the fake host root, $SD = stub state, $LOGS = call logs.
# --------------------------------------------------------------------------- #
# The ports the override's ListenStream= lines leave (after the last reset), or the
# package's 22 without an override — what `daemon-reload` makes systemd "load".
SYSTEMCTL = r"""
echo "systemctl $*" >> "$LOGS/systemctl.log"
loaded_ports() {
  local f="$R/etc/systemd/system/ssh.socket.d/override.conf"
  if [[ ! -f "$f" ]]; then echo 22; return; fi
  awk '/^ListenStream=/ { v = substr($0, 14); if (v == "") { n = 0; next }; sub(/.*:/, "", v); p[++n] = v }
       END { for (i = 1; i <= n; i++) if (!s[p[i]]++) print p[i] }' "$f" | sort -n
}
verb="$1"; shift
case "$verb" in
  show)
    props=(); unit=""
    while (( $# )); do case "$1" in -p) props+=("$2"); shift 2 ;; --value) shift ;; *) unit="$1"; shift ;; esac; done
    for p in "${props[@]}"; do
      case "$p" in
        ActiveState) echo "ActiveState=$(cat "$SD/$unit.active" 2>/dev/null || echo inactive)" ;;
        LoadState)   echo "LoadState=loaded" ;;
        Listen) if [[ "$unit" == ssh.socket ]]; then
                  for port in $(cat "$SD/loaded" 2>/dev/null); do echo "Listen=0.0.0.0:$port (Stream)"; echo "Listen=[::]:$port (Stream)"; done
                fi ;;
      esac
    done
    exit 0 ;;
  is-active) s="$(cat "$SD/${!#}.active" 2>/dev/null || echo inactive)"; echo "$s"; [[ "$s" == active ]]; exit ;;
  is-enabled) echo enabled; exit 0 ;;
  cat) [[ "${!#}" == ssh.socket ]] || exit 1
       echo "[Socket]"; echo "ListenStream="
       for port in $(cat "$SD/loaded" 2>/dev/null); do echo "ListenStream=0.0.0.0:$port"; done; exit 0 ;;
esac
unit="${!#}"
[[ -f "$SD/fail_${verb}" || -f "$SD/fail_${verb}_${unit}" ]] && { echo "Job for $unit failed." >&2; exit 1; }
case "$verb" in
  daemon-reload) loaded_ports > "$SD/loaded" ;;
  restart|start|reload|try-restart)
    if [[ "$unit" == ssh.socket && ! -f "$SD/socket_stuck" ]]; then cp "$SD/loaded" "$SD/listening"; fi
    [[ " $* " == *" --no-block "* ]] || echo active > "$SD/$unit.active" ;;
  stop) echo inactive > "$SD/$unit.active" ;;
esac
exit 0
"""

# What listens: the ssh.socket ports (held by systemd, PID 1) and $SD/other ("<port> <proc>").
SS = r"""
echo "ss $*" >> "$LOGS/ss.log"
[[ "$*" == *H* ]] || echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"
for port in $(cat "$SD/listening" 2>/dev/null); do
  echo "LISTEN 0 4096 0.0.0.0:$port 0.0.0.0:* users:((\"systemd\",pid=1,fd=50))"
  echo "LISTEN 0 4096 [::]:$port [::]:* users:((\"systemd\",pid=1,fd=51))"
done
while read -r port proc; do
  [[ -n "$port" ]] && echo "LISTEN 0 511 0.0.0.0:$port 0.0.0.0:* users:((\"$proc\",pid=4242,fd=6))"
done < <(cat "$SD/other" 2>/dev/null)
exit 0
"""

# sshd -t: a BadOption anywhere fails; sshd -T: the Port lines of the config and its
# drop-ins (22 without one) and the LogLevel.
SSHD = r"""
echo "sshd $*" >> "$LOGS/sshd.log"
cfg="$R/etc/ssh/sshd_config"; mode=""
while (( $# )); do case "$1" in -t) mode=t ;; -T) mode=T ;; -f) cfg="$2"; shift ;; esac; shift; done
files=("$cfg")
while read -r inc; do for g in $inc; do [[ -f "$g" ]] && files+=("$g"); done; done < <(awk 'tolower($1)=="include"{print $2}' "$cfg")
if [[ -f "$SD/sshd_t_fail" ]] || cat "${files[@]}" | grep -q BadOption; then echo "$cfg: Bad configuration option: BadOption"; exit 255; fi
if [[ "$mode" == T ]]; then
  ports="$(cat "${files[@]}" | awk 'tolower($1)=="port"{print $2}' | sort -n -u)"
  [[ -n "$ports" ]] || ports=22
  for p in $ports; do echo "port $p"; done
  ll="$(cat "${files[@]}" | awk 'tolower($1)=="loglevel"{print toupper($2); exit}')"
  echo "loglevel ${ll:-INFO}"
fi
exit 0
"""

JOURNALCTL = r"""
echo "journalctl $*" >> "$LOGS/journalctl.log"
cat "$SD/journal" 2>/dev/null; exit 0
"""

IP = r"""
echo "1: lo    inet 127.0.0.1/8 scope host lo"
echo "2: eth0    inet 198.51.100.7/24 brd 198.51.100.255 scope global eth0"
echo "2: eth0    inet6 2001:db8::7/64 scope global"
"""

# UFW: one rule per line in $SD/ufw, "<rule>|<comment>"; `allow` of an existing rule
# updates its comment in place (as ufw 0.36 does), `delete` ignores the comment.
UFW = r"""
echo "ufw $*" >> "$LOGS/ufw.log"
f="$SD/ufw"; touch "$f"
case "$1" in
  show) echo "Added user rules (see 'ufw status' for running firewall):"
        while IFS='|' read -r r c; do [[ -n "$r" ]] || continue; if [[ -n "$c" ]]; then echo "ufw $r comment '$c'"; else echo "ufw $r"; fi; done < "$f"
        exit 0 ;;
  delete) shift; rule="$*"
          grep -q "^${rule}|" "$f" || { echo "Could not delete non-existent rule"; exit 0; }
          grep -v "^${rule}|" "$f" > "$f.new"; mv "$f.new" "$f"; echo "Rule deleted"; exit 0 ;;
  allow|limit)
    [[ -f "$SD/ufw_fail" ]] && { echo "ERROR: ufw failed"; exit 1; }
    args=("$@"); c=""; rule=""
    for (( i = 0; i < ${#args[@]}; i++ )); do
      if [[ "${args[$i]}" == comment ]]; then c="${args[$((i+1))]}"; break; fi
      rule+="${rule:+ }${args[$i]}"
    done
    if grep -q "^${rule}|" "$f"; then grep -v "^${rule}|" "$f" > "$f.new"; mv "$f.new" "$f"; fi
    echo "${rule}|${c}" >> "$f"; echo "Rules updated"; exit 0 ;;
esac
exit 0
"""

# The relay's input filter re-applied by `advance`.
RELAY_APPLY = r"""
echo "vpn-relay-apply $*" >> "$LOGS/vpn-relay-apply.log"
exit 0
"""


class Host:
    """A fake host of one role: root, stubs, .env; the helper run against it."""

    def __init__(self, tmp: Path, role: str = "main", *, listening: tuple[int, ...] = (54321,),
                 env: str = "") -> None:
        self.tmp = tmp
        self.role = role
        self.root = tmp / "root"
        self.stub = tmp / "stub"
        self.sd = tmp / "sd"
        self.logs = tmp / "logs"
        for d in (self.root, self.stub, self.sd, self.logs):
            d.mkdir(parents=True, exist_ok=True)
        for name, body in (("systemctl", SYSTEMCTL), ("ss", SS), ("sshd", SSHD), ("journalctl", JOURNALCTL),
                           ("ip", IP), ("ufw", UFW)):
            _stub(self.stub / name, body)
        self.put("etc/ssh/sshd_config", f"Include {self.root}/etc/ssh/sshd_config.d/*.conf\n")
        (self.root / "etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
        self.relay_apply = self.root / "usr/local/sbin/vpn-relay-apply"
        self.relay_apply.parent.mkdir(parents=True, exist_ok=True)
        _stub(self.relay_apply, RELAY_APPLY)
        self.env_file = tmp / "dot.env"
        self.env_file.write_text(("NODE_ROLE=relay\n" if role == "relay" else "") + env, encoding="utf-8")
        self.flag("ssh.socket.active", "active")
        self.flag("ssh.service.active", "active")
        if role == "relay":
            self.flag("vpn-relay.service.active", "active")
        self.ssh_on(*listening)

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
        """ssh listens on <ports> through the repo files (none for the package's 22)."""
        if tuple(ports) != (22,):
            self.put(OVERRIDE, render(SOCKET_TPL, *ports))
        self.flag("loaded", "".join(f"{p}\n" for p in sorted(ports)))
        self.flag("listening", "".join(f"{p}\n" for p in sorted(ports)))

    def with_port_dropin(self, *ports: int) -> None:
        self.put(PORT_DROPIN, render(PORT_TPL, *ports))

    def state(self) -> dict[str, Any] | None:
        p = self.h(STATE)
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def write_state(self, **data: Any) -> None:
        base: dict[str, Any] = {"version": 1, "role": self.role, "from": [22], "to": 54321, "phase": 1,
                                "since": int(time.time()) - 600, "proof": None, "bot_confirm": None,
                                "done_at": None, "done_iso": None, "last_error": None}
        base.update(data)
        self.put(STATE, json.dumps(base))

    def phase1(self, old: tuple[int, ...] = (22,), new: int = 54321, *, ago: int = 600) -> int:
        """A host in phase 1 of old -> new: both ports listen, the state file says so."""
        since = int(time.time()) - ago
        self.ssh_on(*old, new)
        self.with_port_dropin(*old, new)
        self.write_state(**{"from": list(old), "to": new, "since": since})
        return since

    def journal(self, *lines: str) -> None:
        self.flag("journal", "".join(f"{ln}\n" for ln in lines))

    def env_run(self) -> dict[str, str]:
        return {"PATH": f"{self.stub}:{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(self.tmp),
                "SD": str(self.sd), "LOGS": str(self.logs), "R": str(self.root), "LANG": "C.UTF-8",
                "VPN_BOT_SSH_PORT_SELFTEST": "1"}

    # --- running the helper ---------------------------------------------------
    def helper(self, *args: str) -> subprocess.CompletedProcess[str]:
        argv = ["python3", "-I", str(HELPER), "--env", str(self.env_file), "--repo", str(ROOT),
                "--role", self.role, "--root", str(self.root), *args]
        return subprocess.run(argv, env=self.env_run(), capture_output=True, text=True, check=False, timeout=60)

    def plan(self) -> dict[str, str]:
        proc = self.helper("plan")
        assert proc.returncode in (0, 3), proc.stdout + proc.stderr
        return dict(ln.split("=", 1) for ln in proc.stdout.splitlines() if "=" in ln)

    def log(self, name: str) -> list[str]:
        p = self.logs / f"{name}.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def ufw_rules(self) -> list[str]:
        p = self.sd / "ufw"
        return [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln] if p.exists() else []


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


CONN = "2026-11-12T10:00:00+0000 relay sshd[901]: Connection from {raddr} port 51022 on {laddr} port {lport} rdomain \"\""


# --------------------------------------------------------------------------- #
# 1. The templates and the registry
# --------------------------------------------------------------------------- #
def test_the_socket_template_for_54321_is_the_hosts_override_byte_for_byte() -> None:
    """main's override.conf (sha256 measured on the host, 2026-11-04) is the rendering
    for 54321: the first deploy reads it `synced` — main does not change."""
    rendered = render(SOCKET_TPL, 54321)
    assert hashlib.sha256(rendered.encode()).hexdigest() == \
        "0a66a1fd2b14fca1ece3e0f48be3cf1a6ed149de26571891d021c28933896e6b"
    proc = subprocess.run(["python3", "-I", str(HELPER), "render", "--template", str(SOCKET_TPL), "--ports", "54321"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0 and proc.stdout == rendered, proc.stderr


def test_both_ports_are_rendered_into_both_files() -> None:
    sock = render(SOCKET_TPL, 54321, 22)
    assert sock.splitlines() == ["[Socket]", "ListenStream=", "ListenStream=0.0.0.0:22", "ListenStream=0.0.0.0:54321",
                                 "ListenStream=[::]:22", "ListenStream=[::]:54321"]
    port = [ln for ln in render(PORT_TPL, 22, 54321).splitlines() if not ln.startswith("#")]
    assert port == ["Port 22", "Port 54321", "LogLevel VERBOSE"]


def _registry() -> list[list[str]]:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    block = text.split("\nMANAGED_HOST_FILES=(\n", 1)[1].split("\n)\n", 1)[0]
    return [ln.strip().strip('"').split("|") for ln in block.splitlines() if ln.strip().startswith('"')]


def test_the_helpers_templates_are_the_registrys_render_entries_of_both_roles() -> None:
    import re
    helper = HELPER.read_text(encoding="utf-8")
    pairs = set(re.findall(r'\("(deploy/host/ssh/[^"]+)", "(/etc/[^"]+)"\)', helper))
    for role in ("main", "relay"):
        rendered = {(e[0], e[1]) for e in _registry() if e[5] == role and len(e) > 6 and "render=ssh-port" in e[6]}
        assert rendered == pairs, role
        units = {e[1] for e in _registry() if e[5] == role}
        assert "/etc/systemd/system/vpn-bot-ssh-port.service" in units, role
        assert all(e[4] == "ssh" for e in _registry() if len(e) > 6 and "render=ssh-port" in e[6])


def test_the_helper_is_installed_on_both_roles_and_the_host_check_pulls_the_unit_in() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert '"scripts/vpn-bot-ssh-port|/usr/local/sbin/vpn-bot-ssh-port|required"' in text
    assert '"scripts/vpn-bot-ssh-port|/usr/local/sbin/vpn-bot-ssh-port|required|relay"' in text
    hc = (ROOT / "deploy/host/systemd/vpn-bot-host-check.service").read_text(encoding="utf-8")
    assert "Wants=vpn-bot-ssh-port.service" in hc and "After=vpn-bot-ssh-port.service" in hc
    unit = (ROOT / "deploy/host/systemd/vpn-bot-ssh-port.service").read_text(encoding="utf-8")
    assert "ExecStart=/usr/local/sbin/vpn-bot-ssh-port advance" in unit
    assert "[Install]" not in unit, "pulled in by the host check, never enabled on its own"


# --------------------------------------------------------------------------- #
# 2. SSH_PORT
# --------------------------------------------------------------------------- #
def test_ssh_port_absent_means_54321(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay", listening=(22,))
    plan = host.plan()
    assert plan["ssh_port"] == "54321" and plan["ssh_port_source"] == "default"
    assert plan["action"] == "start" and plan["from"] == "22" and plan["listen"] == "22,54321"


def test_main_already_on_ssh_port_is_steady(tmp_path: Path) -> None:
    host = Host(tmp_path, "main", listening=(54321,))
    plan = host.plan()
    assert plan["action"] == "steady" and plan["listen"] == "54321", plan
    assert plan["status"] == "ssh port: 54321 (SSH_PORT, default)"


@pytest.mark.parametrize(("role", "env", "why"), [
    ("main", "SSH_PORT=443\n", "XRAY_PUBLIC_PORT"),
    ("main", "SSH_PORT=2096\nSUBSCRIPTION_PUBLIC_PORT=2096\n", "SUBSCRIPTION_PUBLIC_PORT"),
    ("main", "SSH_PORT=31337\nSOCKS5_PORT=31337\n", "SOCKS5_PORT"),
    ("main", "SSH_PORT=8443\n", "XRAY_XHTTP_PORT"),
    ("relay", "SSH_PORT=443\n", "RELAY_FORWARD_TCP_PORTS"),
    ("relay", "SSH_PORT=8080\nRELAY_INPUT_EXTRA_TCP=80,8080\n", "RELAY_INPUT_EXTRA_TCP"),
    ("main", "SSH_PORT=70000\n", "is not a TCP port"),
    ("main", "SSH_PORT=022\n", "is not a TCP port"),
    ("main", "SSH_PORT=ssh\n", "is not a TCP port"),
])
def test_ssh_port_that_is_no_port_or_a_services_port_is_refused(tmp_path: Path, role: str, env: str, why: str) -> None:
    host = Host(tmp_path, role, listening=(22,), env=env)
    proc = host.helper("plan")
    assert proc.returncode == 3, proc.stdout
    assert "action=refused" in proc.stdout and why in proc.stdout


def test_a_port_another_process_listens_on_is_refused(tmp_path: Path) -> None:
    host = Host(tmp_path, "main", listening=(22,), env="SSH_PORT=2222\n")
    host.flag("other", "2222 nginx\n")
    proc = host.helper("plan")
    assert proc.returncode == 3 and "in use by nginx" in proc.stdout, proc.stdout


def test_ssh_socket_not_active_is_refused(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay", listening=(22,))
    host.flag("ssh.socket.active", "inactive")
    proc = host.helper("plan")
    assert proc.returncode == 3 and "ssh.socket is inactive" in proc.stdout, proc.stdout


# --------------------------------------------------------------------------- #
# 3. Proofs: without one there is no phase 2
# --------------------------------------------------------------------------- #
def test_phase1_without_a_proof_waits(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay")
    host.phase1()
    host.journal(CONN.format(raddr="127.0.0.1", laddr="127.0.0.1", lport=54321),          # loopback
                 CONN.format(raddr="198.51.100.7", laddr="198.51.100.7", lport=54321),    # the host itself
                 CONN.format(raddr="203.0.113.9", laddr="198.51.100.7", lport=22))        # the OLD port
    host.put(MARKER, f"sha256={'a' * 64}\ntcp=22,54321\nconfirmed_at={_iso(time.time())}\nconfirmed_by=ssh-session\n")
    plan = host.plan()
    assert plan["action"] == "wait" and plan["listen"] == "22,54321" and plan["proof"] == "none", plan
    assert plan["status"].startswith("ssh port: migrating 22 -> 54321 (waiting for proof: main's probe of tcp 54321")


def test_main_probe_of_the_relay_is_a_proof(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay")
    since = host.phase1()
    host.put(MARKER, f"sha256={'a' * 64}\ntcp=22,54321\nconfirmed_at={_iso(since + 5)}\nconfirmed_by=main-probe\n")
    plan = host.plan()
    assert plan["action"] == "finish" and plan["listen"] == "54321" and plan["proof"] == "relay-probe", plan


def test_a_main_probe_from_before_phase1_proves_nothing(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay")
    since = host.phase1()
    host.put(MARKER, f"sha256={'a' * 64}\ntcp=22,54321\nconfirmed_at={_iso(since - 60)}\nconfirmed_by=main-probe\n")
    assert host.plan()["action"] == "wait"


@pytest.mark.parametrize("role", ["main", "relay"])
def test_a_connection_from_outside_on_the_new_port_in_the_sshd_log_is_a_proof(tmp_path: Path, role: str) -> None:
    host = Host(tmp_path, role, listening=(22,) if role == "relay" else (54321,),
                env="" if role == "relay" else "SSH_PORT=60022\n")
    old = (22,) if role == "relay" else (54321,)
    new = 54321 if role == "relay" else 60022
    host.phase1(old, new)
    host.journal(CONN.format(raddr="203.0.113.9", laddr="198.51.100.7", lport=new))
    plan = host.plan()
    assert plan["action"] == "finish" and plan["proof"] == "journal", plan
    assert "203.0.113.9" in plan["proof_detail"]
    # Read since the start of phase 1, from ssh.service.
    assert any("-u ssh.service" in ln and "--since @" in ln for ln in host.log("journalctl"))


def test_the_bots_confirmation_is_a_proof_and_a_stale_button_is_refused(tmp_path: Path) -> None:
    host = Host(tmp_path, "main", env="SSH_PORT=60022\n")
    since = host.phase1((54321,), 60022)
    stale = host.helper("confirm", "--port", "60022", "--since", str(since - 1), "--admin", "77")
    assert stale.returncode == 3 and "stale" in stale.stderr
    assert host.plan()["action"] == "wait"
    ok = host.helper("confirm", "--port", "60022", "--since", str(since), "--admin", "77")
    assert ok.returncode == 0, ok.stderr
    assert "systemctl start --no-block vpn-bot-ssh-port.service" in host.log("systemctl")
    state = host.state()
    assert state is not None and state["bot_confirm"]["admin_id"] == 77
    plan = host.plan()
    assert plan["action"] == "finish" and plan["proof"] == "bot", plan


# --------------------------------------------------------------------------- #
# 4. advance: phase 2 outside a deploy
# --------------------------------------------------------------------------- #
def test_advance_without_a_proof_changes_nothing(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay")
    host.phase1()
    before = host.h(OVERRIDE).read_text(encoding="utf-8")
    proc = host.helper("advance", "--listen-wait", "0")
    assert proc.returncode == 0, proc.stderr
    assert "waiting for proof" in proc.stdout
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == before
    assert not [ln for ln in host.log("systemctl") if "restart" in ln or "daemon-reload" in ln]
    assert host.state()["phase"] == 1  # type: ignore[index]


def test_advance_with_the_relay_probe_closes_the_old_port(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay")
    since = host.phase1()
    host.put(MARKER, f"tcp=22,54321\nconfirmed_at={_iso(since + 5)}\nconfirmed_by=main-probe\n")
    proc = host.helper("advance", "--listen-wait", "0")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 54321)
    assert host.h(PORT_DROPIN).read_text(encoding="utf-8") == render(PORT_TPL, 54321)
    assert (host.sd / "listening").read_text(encoding="utf-8").split() == ["54321"]
    sc = [ln for ln in host.log("systemctl") if ln.split()[1] not in ("show", "is-active")]
    assert sc == ["systemctl daemon-reload", "systemctl restart ssh.socket", "systemctl restart ssh.service"]
    assert host.log("vpn-relay-apply") == ["vpn-relay-apply apply"], "the input filter follows the ports"
    assert host.log("ufw") == [], "a relay never touches ufw"
    state = host.state()
    assert state is not None and state["phase"] == 2 and state["proof"]["kind"] == "relay-probe"
    assert host.plan()["status"].startswith("ssh port: 54321 (SSH_PORT, default); migrated from 22 at ")


def test_advance_on_main_closes_the_old_port_in_ufw_and_keeps_the_new_one(tmp_path: Path) -> None:
    host = Host(tmp_path, "main", env="SSH_PORT=60022\n")
    host.phase1((54321,), 60022)
    host.flag("ufw", "allow 22/tcp|\nallow 54321/tcp|ssh\nallow 443|\nallow 60022/tcp|vpn-bot:ssh-migration\n")
    host.journal(CONN.format(raddr="203.0.113.9", laddr="198.51.100.7", lport=60022))
    proc = host.helper("advance", "--listen-wait", "0")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert host.ufw_rules() == ["allow 22/tcp|", "allow 443|", "allow 60022/tcp|vpn-bot:ssh"], \
        "54321 closed, the migration rule kept (relabelled in place), 22 and 443 untouched"
    assert host.state()["phase"] == 2  # type: ignore[index]


def test_advance_reverts_when_the_new_set_does_not_come_up(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay")
    since = host.phase1()
    host.put(MARKER, f"tcp=22,54321\nconfirmed_at={_iso(since + 5)}\nconfirmed_by=main-probe\n")
    host.flag("socket_stuck")            # restart does not apply the new set: 22 still listens
    proc = host.helper("advance", "--listen-wait", "0")
    assert proc.returncode == 4, proc.stdout + proc.stderr
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 22, 54321), "reverted"
    assert host.h(PORT_DROPIN).read_text(encoding="utf-8") == render(PORT_TPL, 22, 54321)
    state = host.state()
    assert state is not None and state["phase"] == 1 and "reverted to 22,54321" in state["last_error"]
    assert host.log("vpn-relay-apply") == []


def test_advance_leaves_a_hand_edited_file_to_a_deploy(tmp_path: Path) -> None:
    host = Host(tmp_path, "relay")
    since = host.phase1()
    host.put(MARKER, f"tcp=22,54321\nconfirmed_at={_iso(since + 5)}\nconfirmed_by=main-probe\n")
    host.put(PORT_DROPIN, "Port 22\nPort 54321\nPort 2200\n")
    proc = host.helper("advance", "--listen-wait", "0")
    assert proc.returncode == 3 and "a deploy decides" in proc.stderr
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 22, 54321)


def test_advance_never_runs_next_to_a_deploy(tmp_path: Path) -> None:
    import fcntl
    host = Host(tmp_path, "relay")
    since = host.phase1()
    host.put(MARKER, f"tcp=22,54321\nconfirmed_at={_iso(since + 5)}\nconfirmed_by=main-probe\n")
    lock = host.h("/run/vpn-bot-deploy.lock")
    lock.parent.mkdir(parents=True, exist_ok=True)
    with lock.open("w") as fh:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        proc = host.helper("advance", "--listen-wait", "0")
    assert proc.returncode == 0 and "a deploy holds the lock" in proc.stdout
    assert host.state()["phase"] == 1  # type: ignore[index]


def test_firewall_open_adds_a_migration_rule_and_undo_removes_only_that(tmp_path: Path) -> None:
    host = Host(tmp_path, "main", env="SSH_PORT=60022\n")
    host.flag("ufw", "allow 54321/tcp|\n")
    assert host.helper("firewall-open", "--port", "60022").returncode == 0
    assert host.ufw_rules() == ["allow 54321/tcp|", "allow 60022/tcp|vpn-bot:ssh-migration"]
    assert host.helper("firewall-undo", "--port", "60022").returncode == 0
    assert host.ufw_rules() == ["allow 54321/tcp|"]
    # Already open by the operator: nothing added, so nothing to undo either.
    host.flag("ufw", "allow 60022/tcp|mine\n")
    out = host.helper("firewall-open", "--port", "60022").stdout
    assert "already allows 60022/tcp" in out
    host.helper("firewall-undo", "--port", "60022")
    assert host.ufw_rules() == ["allow 60022/tcp|mine"]


def test_env_reader_is_deploy_shs(tmp_path: Path) -> None:
    """The helper reads SSH_PORT/NODE_ROLE with deploy.sh's env_sed_val semantics."""
    matrix = ["K=7\n", 'K="7"\n', "K='7'\n", " export K = 7 # c\n", "K=1\nK=7\n", "K=7\nK=\n", "# K=7\n",
              "KX=7\n", "K=7\r\n", 'K="7"\r\n', "K=7#c\n", ""]
    for text in matrix:
        env = tmp_path / "e.env"
        env.write_text(text, encoding="utf-8")
        drv = (f'set -uo pipefail\nexport DEPLOY_SELFTEST=1\nsource "{DEPLOY_SH}"\n'
               f'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\nENV_FILE="{env}"\n'
               'printf "[%s]" "$(env_sed_val K)"\n')
        want = subprocess.run(["bash", "-c", drv], capture_output=True, text=True, check=False).stdout
        code = ("import importlib.machinery, importlib.util, sys\n"
                f"l = importlib.machinery.SourceFileLoader('h', {str(HELPER)!r})\n"
                "s = importlib.util.spec_from_loader('h', l); m = importlib.util.module_from_spec(s)\n"
                "sys.modules['h'] = m; l.exec_module(m)\n"
                f"print('[' + m.env_sed_val(open({str(env)!r}, newline='').read(), 'K') + ']', end='')\n")
        got = subprocess.run(["python3", "-I", "-c", code], capture_output=True, text=True, check=False)
        assert got.stdout == want, (text, got.stdout, want, got.stderr)


# --------------------------------------------------------------------------- #
# 5. deploy.sh: Phase 1 plan, the render=ssh-port files, phase 1 / phase 2, rollback
# --------------------------------------------------------------------------- #
PHASE1 = 'ssh_port_phase1 "$APP_DIR"; host_state_phase1 "$APP_DIR"; echo PHASE1-OK\n'
PHASE2 = (
    'readarray -t _p < <(managed_host_stage_paths); stage_host_paths "${_p[@]}" "$(ssh_port_state_path)"\n'
    "ssh_port_phase2_pre\ninstall_managed_host_files\nssh_port_phase2_post\necho PHASE2-OK\n"
    "ssh_port_after_deploy\necho \"FINAL: ${SSH_FINAL_STATUS}\"\n"
)
FAIL_LATER = (
    'readarray -t _p < <(managed_host_stage_paths); stage_host_paths "${_p[@]}" "$(ssh_port_state_path)"\n'
    "ssh_port_phase2_pre\ninstall_managed_host_files\nssh_port_phase2_post\n"
    'rollback_now "a later step failed"\n'
)


class Deploy(Host):
    """The same fake host, deployed by scripts/deploy.sh (DEPLOY_SELFTEST seam)."""

    def __init__(self, tmp: Path, role: str = "main", **kw: Any) -> None:
        super().__init__(tmp, role, **kw)
        self.repo = tmp / "repo"
        for rel in ("scripts/vpn-bot-ssh-port", "deploy/host/ssh/ssh.socket-override.conf",
                    "deploy/host/ssh/00-vpn-bot-port.conf"):
            dst = self.repo / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes((ROOT / rel).read_bytes())
        self.stage = tmp / "stage"
        self.stage.mkdir()
        self.unitdir = self.h("/etc/systemd/system")
        self.unitdir.mkdir(parents=True, exist_ok=True)
        # deploy.sh creates a missing drop-in directory with `install -d -o root -g root`:
        # the suite also runs unprivileged (CI), so `install` is the same stub as in
        # tests/test_deploy_host_state.py — it copies and sets the mode, never the owner.
        from test_deploy_host_state import INSTALL
        _stub(self.stub / "install", INSTALL)

    def entries(self) -> list[str]:
        import grp
        import pwd
        owner = f"{pwd.getpwuid(os.getuid()).pw_name}:{grp.getgrgid(os.getgid()).gr_name}"
        return [
            f"deploy/host/ssh/ssh.socket-override.conf|{self.h(OVERRIDE)}|0644|{owner}|ssh|{self.role}|render=ssh-port",
            f"deploy/host/ssh/00-vpn-bot-port.conf|{self.h(PORT_DROPIN)}|0644|{owner}|ssh|{self.role}|render=ssh-port",
        ]

    def deploy(self, body: str, **knobs: str) -> subprocess.CompletedProcess[str]:
        entries = "\n".join(f'  "{e}"' for e in self.entries())
        knob_lines = "".join(f'{k}="{v}"\n' for k, v in knobs.items())
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -uo pipefail\nexport DEPLOY_SELFTEST=1\n"
            f'source "{DEPLOY_SH}"\n'
            'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""\n'
            f'STAGE="{self.stage}"; APP_DIR="{self.repo}"; ENV_FILE="{self.env_file}"\n'
            f'MH_SELFTEST_ROOT="{self.tmp}"; SSH_PORT_ROOT="{self.root}"\n'
            f'SYSTEMD_UNIT_DIR="{self.unitdir}"; SSHD_CONFIG="{self.h("/etc/ssh/sshd_config")}"\n'
            "SSH_LISTEN_WAIT=1; ABSENT_REF_PATHS=(); UNMANAGED_SCAN_DIRS=(); CONFFILE_REPORT_PATHS=()\n"
            f"ALLOW_SSH_CHANGE=0; ALLOW_UNIT_DRIFT=0; PHASE1_ONLY=0; NODE_ROLE={self.role}\n"
            f"MANAGED_HOST_FILES=(\n{entries}\n)\nOUT_OF_REPO_HELPERS=()\n"
            'ssh_banner_ok() { [[ ! -f "$SD/no_banner_$1" ]]; }\n'
            'rollback() { set +e; echo "ROLLBACK_CALLED"; host_files_rollback; exit 42; }\n'
            'relay_rollback() { set +e; echo "RELAY_ROLLBACK_CALLED"; host_files_rollback; exit 43; }\n'
            + knob_lines + body,
            encoding="utf-8",
        )
        proc = subprocess.run(["bash", str(driver)], cwd=str(self.tmp), env=self.env_run(),
                              capture_output=True, text=True, check=False, timeout=120)
        proc.stdout = proc.stdout + "\n--STDERR--\n" + proc.stderr
        return proc

    def mutating(self) -> list[str]:
        reads = {"show", "is-active", "is-enabled", "cat"}
        return [ln for ln in self.log("systemctl") if ln.split()[1] not in reads]


def test_deploy_relay_phase1_listens_on_both_ports_without_the_knob(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "relay", listening=(22,))
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 0, proc.stdout
    assert "ssh port: migrating 22 -> 54321 (phase 1 starts now: ssh.socket listens on both" in proc.stdout
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 22, 54321)
    assert host.h(PORT_DROPIN).read_text(encoding="utf-8") == render(PORT_TPL, 22, 54321)
    assert any(" -d " in f" {ln} " and "ssh.socket.d" in ln for ln in host.log("install")), \
        "the relay had no ssh.socket.d: the deploy creates it"
    assert (host.sd / "listening").read_text(encoding="utf-8").split() == ["22", "54321"], "22 never stops"
    assert "ssh port: ssh.socket holds exactly 22 54321" in proc.stdout
    state = host.state()
    assert state is not None and state["phase"] == 1 and state["from"] == [22] and state["to"] == 54321
    assert "FINAL: ssh port: migrating 22 -> 54321 (waiting for proof: main's probe of tcp 54321" in proc.stdout
    assert "systemctl start vpn-bot-ssh-port.service" in host.log("systemctl"), "the proof is looked for at once"
    assert host.log("ufw") == []


def test_deploy_main_phase1_opens_the_new_port_in_ufw_first(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "main", listening=(54321,), env="SSH_PORT=60022\n")
    host.flag("ufw", "allow 22/tcp|\nallow 54321/tcp|\n")
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 0, proc.stdout
    # override.conf differs from the repo rendering, but it IS the rendering of what
    # listens now: a migration step — no ALLOW_SSH_CHANGE.
    assert "a migration step from 54321" in proc.stdout
    assert "allow 60022/tcp|vpn-bot:ssh-migration" in host.ufw_rules()
    assert "allow 54321/tcp|" in host.ufw_rules(), "the old port is not touched in phase 1"
    ufw_at = (host.logs / "ufw.log").stat().st_mtime_ns
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 54321, 60022)
    assert ufw_at <= host.h(OVERRIDE).stat().st_mtime_ns, "the firewall opens before the socket listens"
    assert (host.sd / "listening").read_text(encoding="utf-8").split() == ["54321", "60022"]
    assert host.state()["phase"] == 1  # type: ignore[index]


def test_deploy_phase1_failure_rolls_back_files_state_and_the_ufw_rule(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "main", listening=(54321,), env="SSH_PORT=60022\n")
    host.flag("ufw", "allow 54321/tcp|\n")
    host.flag("socket_stuck")                 # the new set never comes up
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 42, proc.stdout
    assert "NOT listening on :60022" in proc.stdout
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 54321)
    assert not host.h(PORT_DROPIN).exists()
    assert host.state() is None
    assert host.ufw_rules() == ["allow 54321/tcp|"], "the rule phase 1 opened is gone again"
    assert host.mutating()[-2:] == ["systemctl restart ssh.socket", "systemctl restart ssh.service"]


def test_deploy_a_later_failure_rolls_phase1_back_too(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "relay", listening=(22,))
    proc = host.deploy(PHASE1 + FAIL_LATER)
    assert proc.returncode == 43, proc.stdout
    # Phase 1 got all the way through before the later step failed.
    assert "ssh port: phase 1 — ssh.socket listens on 22,54321" in proc.stdout
    assert "a later step failed" in proc.stdout
    assert not host.h(OVERRIDE).exists() and not host.h(PORT_DROPIN).exists()
    assert host.state() is None, "the state file Phase 2 wrote is removed again"
    assert host.mutating()[-1] == "systemctl restart ssh.service"


def test_deploy_main_already_on_ssh_port_changes_nothing_but_the_port_dropin(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "main", listening=(54321,))
    host.flag("ufw", "allow 22/tcp|\nallow 54321/tcp|\n")
    before = host.h(OVERRIDE).read_text(encoding="utf-8")
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 0, proc.stdout
    assert "ssh port: 54321 (SSH_PORT, default)" in proc.stdout
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == before
    assert host.h(PORT_DROPIN).read_text(encoding="utf-8") == render(PORT_TPL, 54321)
    assert host.mutating() == ["systemctl reload ssh.service"], "no socket restart, no new port"
    assert [ln for ln in host.log("ufw") if not ln.startswith("ufw show")] == []
    assert host.state() is None
    # And the next deploy finds everything in sync.
    for f in ("systemctl.log", "ufw.log"):
        (host.logs / f).unlink(missing_ok=True)
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 0 and host.mutating() == [], proc.stdout


def test_deploy_without_a_proof_leaves_phase1_as_it_is(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "relay")
    host.phase1()
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 0, proc.stdout
    assert "ssh port: migrating 22 -> 54321 (waiting for proof:" in proc.stdout
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 22, 54321)
    assert host.mutating() == ["systemctl start vpn-bot-ssh-port.service"]
    assert host.state()["phase"] == 1  # type: ignore[index]


def _prove(host: Deploy, kind: str, since: int, new: int) -> None:
    if kind == "relay-probe":
        host.put(MARKER, f"tcp=22,{new}\nconfirmed_at={_iso(since + 5)}\nconfirmed_by=main-probe\n")
    elif kind == "journal":
        host.journal(CONN.format(raddr="203.0.113.9", laddr="198.51.100.7", lport=new))
    else:
        state = host.state()
        assert state is not None
        state["bot_confirm"] = {"port": new, "admin_id": 5, "at": since + 30}
        host.put(STATE, json.dumps(state))


@pytest.mark.parametrize(("role", "kind"), [("relay", "relay-probe"), ("relay", "journal"),
                                            ("main", "journal"), ("main", "bot")])
def test_deploy_each_proof_leads_to_phase2(tmp_path: Path, role: str, kind: str) -> None:
    old, new = ((22,), 54321) if role == "relay" else ((54321,), 60022)
    host = Deploy(tmp_path, role, listening=old, env="" if role == "relay" else "SSH_PORT=60022\n")
    since = host.phase1(old, new)
    if role == "main":
        host.flag("ufw", f"allow 22/tcp|\nallow {old[0]}/tcp|\nallow {new}/tcp|vpn-bot:ssh-migration\n")
    _prove(host, kind, since, new)
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 0, proc.stdout
    assert f"— proven ({kind}:" in proc.stdout
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, new)
    assert host.h(PORT_DROPIN).read_text(encoding="utf-8") == render(PORT_TPL, new)
    assert (host.sd / "listening").read_text(encoding="utf-8").split() == [str(new)]
    assert f"ssh.socket holds exactly {new}; {old[0]} no longer listens" in proc.stdout
    state = host.state()
    assert state is not None and state["phase"] == 2 and state["proof"]["kind"] == kind
    assert f"FINAL: ssh port: {new} (SSH_PORT" in proc.stdout
    if role == "main":
        assert host.ufw_rules() == ["allow 22/tcp|", f"allow {new}/tcp|vpn-bot:ssh"], "the old port closed after DEPLOY OK"


def test_deploy_phase2_failure_rolls_back_to_both_ports(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "relay")
    since = host.phase1()
    _prove(host, "relay-probe", since, 54321)
    host.flag("socket_stuck")                 # 22 keeps listening: not the planned set
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 43, proc.stdout
    assert "ssh port check failed after the change" in proc.stdout
    assert "port 22 still listens" in proc.stdout
    assert host.h(OVERRIDE).read_text(encoding="utf-8") == render(SOCKET_TPL, 22, 54321)
    assert host.h(PORT_DROPIN).read_text(encoding="utf-8") == render(PORT_TPL, 22, 54321)
    assert host.state()["phase"] == 1  # type: ignore[index]


def test_a_hand_edited_ssh_port_file_still_needs_the_knob(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "main", listening=(54321,))
    host.put(OVERRIDE, render(SOCKET_TPL, 54321) + "Backlog=4096\n")
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 1, proc.stdout
    assert "refusing to deploy without ALLOW_SSH_CHANGE=1; nothing was changed" in proc.stdout
    assert host.mutating() == [] and host.log("ufw") == []


def test_deploy_refuses_a_service_port_in_phase1_before_any_change(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "main", listening=(54321,), env="SSH_PORT=443\n")
    proc = host.deploy(PHASE1 + PHASE2)
    assert proc.returncode == 1, proc.stdout
    assert "ssh port: REFUSED — SSH_PORT=443 is the port of XRAY_PUBLIC_PORT" in proc.stdout
    assert "nothing was changed" in proc.stdout and "PHASE1-OK" not in proc.stdout
    assert host.mutating() == [] and host.log("ufw") == [] and not host.h(PORT_DROPIN).exists()


def test_inspection_mode_reports_a_refusal(tmp_path: Path) -> None:
    host = Deploy(tmp_path, "relay", listening=(22,), env="SSH_PORT=443\n")
    proc = host.deploy(PHASE1 + "ssh_port_report_block\n", PHASE1_ONLY="1")
    assert proc.returncode == 0, proc.stdout
    assert "a real deploy stops here (PHASE1_ONLY=1: not fatal)" in proc.stdout
    assert "cannot-render" in proc.stdout and "PHASE1-OK" in proc.stdout


def test_ssh_port_phase1_runs_before_the_host_file_scan_in_both_roles() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert 'ssh_port_phase1 "$WT"\nhost_state_phase1 "$WT"' in text
    assert '  ssh_port_phase1 "$WT"\n  host_state_phase1 "$WT"' in text
    assert "ssh_port_phase2_pre\ninstall_managed_host_files\nssh_port_phase2_post" in text
    assert "  ssh_port_phase2_pre\n  install_managed_host_files\n" in text


# --------------------------------------------------------------------------- #
# 6. The host check: family ssh-port
# --------------------------------------------------------------------------- #
def _hc_lab(tmp_path: Path, role: str, *, listen: tuple[int, ...], sshd_ports: tuple[int, ...], env: str = "") -> Any:
    from test_host_check import HostLab, _stub as hc_stub
    lab = HostLab(tmp_path)
    for rel in ("scripts/vpn-bot-ssh-port", "deploy/host/ssh/ssh.socket-override.conf",
                "deploy/host/ssh/00-vpn-bot-port.conf"):
        lab.repo_file(rel, (ROOT / rel).read_text(encoding="utf-8"))
    hc_stub(lab.stub / "journalctl", 'cat "$SD/journal" 2>/dev/null; exit 0\n')
    hc_stub(lab.stub / "ip", IP)
    lab.env.write_text(("NODE_ROLE=relay\n" if role == "relay" else "") + env, encoding="utf-8")
    lab.unit("ssh.socket", ActiveState="active",
             Listen="\nListen=".join(f"0.0.0.0:{p} (Stream)" for p in listen))
    lab.flag("ss", "".join(f'LISTEN 0 4096 0.0.0.0:{p} 0.0.0.0:* users:(("systemd",pid=1,fd=50))\n' for p in listen))
    (lab.sd / "sshd_T").write_text("".join(f"port {p}\n" for p in sshd_ports), encoding="utf-8")
    return lab


def _ssh_rows(res: Any) -> list[tuple[str, str, str, str, str]]:
    return [r for r in res.rows if r[1] == "ssh-port"]


def test_host_check_mismatch_when_ssh_port_is_not_where_ssh_listens(tmp_path: Path) -> None:
    lab = _hc_lab(tmp_path, "relay", listen=(22,), sshd_ports=(22,))
    res = lab.run(role="relay")
    rows = _ssh_rows(res)
    assert [r[0] for r in rows] == ["MISMATCH"], res.out
    assert "SSH_PORT=54321, but ssh.socket listens on 22 and no migration has started" in rows[0][4]
    assert res.rc == 1
    # Phase 1 of a deploy: the deploy starts it now.
    pre = _ssh_rows(lab.run("--pre-install", role="relay"))
    assert [r[0] for r in pre] == ["PENDING"] and "phase 1 starts now" in pre[0][4]


def test_host_check_phase1_is_pending_with_its_reason(tmp_path: Path) -> None:
    lab = _hc_lab(tmp_path, "relay", listen=(22, 54321), sshd_ports=(22, 54321))
    lab.host(STATE.lstrip("/"), json.dumps({"version": 1, "from": [22], "to": 54321, "phase": 1,
                                            "since": int(time.time()) - 60}))
    res = lab.run(role="relay")
    rows = _ssh_rows(res)
    assert [r[0] for r in rows] == ["PENDING"], res.out
    assert rows[0][4].startswith("ssh port: migrating 22 -> 54321 (waiting for proof:")
    assert res.rc == 0


def test_host_check_after_phase2_checks_the_fallback_port(tmp_path: Path) -> None:
    lab = _hc_lab(tmp_path, "main", listen=(54321,), sshd_ports=(54321,))
    res = lab.run()
    assert {(r[0], r[2]) for r in _ssh_rows(res)} == {("OK", "ssh.socket"), ("OK", "fallback")}, res.out
    (lab.sd / "sshd_T").write_text("port 22\n", encoding="utf-8")     # the Port drop-in not in effect
    res = lab.run()
    bad = [r for r in _ssh_rows(res) if r[0] == "MISMATCH"]
    assert bad and bad[0][2] == "fallback" and "sshd -T would listen on 22, not on SSH_PORT=54321" in bad[0][4]


def test_host_check_refused_ssh_port_is_a_mismatch(tmp_path: Path) -> None:
    lab = _hc_lab(tmp_path, "main", listen=(54321,), sshd_ports=(54321,), env="SSH_PORT=443\n")
    rows = _ssh_rows(lab.run())
    assert [r[0] for r in rows] == ["MISMATCH"] and "XRAY_PUBLIC_PORT" in rows[0][4]


# --------------------------------------------------------------------------- #
# 7. The bot: one message per step, «Подтвердить» runs the helper
# --------------------------------------------------------------------------- #
class _Meta:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get_meta(self, key: str) -> str | None:
        return self.data.get(key)

    async def set_meta(self, key: str, value: str) -> None:
        self.data[key] = value


class _Runner:
    def __init__(self, rc: int = 0) -> None:
        self.calls: list[tuple[str, list[str]]] = []
        self.rc = rc

    async def run(self, helper: Path, args: Any, **_: Any) -> Any:
        from models.dto import ShellResult
        self.calls.append((str(helper), list(args)))
        return ShellResult(args=(str(helper), *args), returncode=self.rc, stdout="confirmed: 60022\n", stderr="")


def test_bot_tells_each_step_once_and_confirms_through_the_helper(tmp_path: Path) -> None:
    from services.ssh_port import SshPortConfirmError, SshPortMonitor, parse_callback_data

    state = tmp_path / "ssh-migration.json"
    sent: list[tuple[str, Any]] = []

    async def send(text: str, markup: Any) -> None:
        sent.append((text, markup))

    meta, runner = _Meta(), _Runner()
    mon = SshPortMonitor(store=meta, admin_ids=frozenset({5}), path=state, runner=runner,  # type: ignore[arg-type]
                         send=send)

    async def scenario() -> None:
        await mon.check_once()
        assert sent == [], "no migration, no message"
        state.write_text(json.dumps({"from": [54321], "to": 60022, "phase": 1, "since": 1700000000}))
        await mon.check_once()
        await mon.check_once()
        assert len(sent) == 1, "phase 1 is told once"
        text, markup = sent[0]
        assert "54321 → 60022" in text and "60022" in text
        data = markup.inline_keyboard[0][0].callback_data
        assert parse_callback_data(data) == (60022, 1700000000)
        # A restart (a new monitor on the same database) does not repeat it.
        again = SshPortMonitor(store=meta, admin_ids=frozenset({5}), path=state, send=send)
        await again.check_once()
        assert len(sent) == 1
        with pytest.raises(SshPortConfirmError):
            await mon.confirm(5, 60022, 1699999999)          # a button of another migration
        assert await mon.confirm(5, 60022, 1700000000) == "confirmed: 60022"
        assert runner.calls == [("/usr/local/sbin/vpn-bot-ssh-port",
                                 ["confirm", "--port", "60022", "--since", "1700000000", "--admin", "5"])]
        state.write_text(json.dumps({"from": [54321], "to": 60022, "phase": 2, "since": 1700000000,
                                     "done_iso": "2026-11-12T10:00:00Z",
                                     "proof": {"kind": "bot", "detail": "superadmin 5 pressed it"}}))
        await mon.check_once()
        await mon.check_once()
        assert len(sent) == 2 and "superadmin 5 pressed it" in sent[1][0] and sent[1][1] is None
        with pytest.raises(SshPortConfirmError):
            await mon.confirm(5, 60022, 1700000000)          # done: nothing waits any more

    asyncio.run(scenario())


def test_the_sudoers_grant_is_the_confirm_verb_only() -> None:
    text = (ROOT / "deploy/sudoers.d/vpn-bot.example").read_text(encoding="utf-8")
    grants = [ln.strip().rstrip(",\\").strip() for ln in text.splitlines() if "vpn-bot-ssh-port" in ln and not ln.lstrip().startswith("#")]
    assert grants == ["/usr/local/sbin/vpn-bot-ssh-port confirm *"]
    assert "VPN_BOT_SSH_PORT" in text.split("vpn-bot ALL=(root) NOPASSWD:", 1)[1]
