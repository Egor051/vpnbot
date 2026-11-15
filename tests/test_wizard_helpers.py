"""The setup wizard's root helpers (scripts/wizard/, docs/wizard.md).

* The launcher refuses anything outside its fixed mode table — an unknown mode, a bad
  run id, an unknown or out-of-range parameter — before it runs a thing, refuses
  while another wizard unit is active, and starts the phase ONLY through
  `systemd-run --unit=vpn-bot-wizard-<id> --collect`.
* The runner drives the contract plan → apply → verify → rollback and always ends
  the status file with one `finished` line; the global lock refuses a second run.
* Each mode helper: selfcheck (green/yellow/red items), dump (redacted artifact, the
  last ERROR judged by its timestamp, verify refuses a secret), update (CHECK=1
  redeploy for the plan, DEPLOY OK / ROLLBACK REPORT for the outcome).
* The library: the redaction patterns and the mode table match the bot's copies;
  the dead-man is a `systemd-run --on-active` timer; backups restore.

VPN_BOT_WIZARD_SELFTEST=1 re-roots every path under a temporary directory and refuses
any command that is not a stub here: deploy.sh runs this suite AS ROOT on the
production host, and nothing here may touch it.
"""

from __future__ import annotations

import fcntl
import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import utils.redact as bot_redact
from services.wizard_modes import MODES as BOT_MODES

ROOT = Path(__file__).resolve().parents[1]
WIZ = ROOT / "scripts" / "wizard"
LAUNCHER = WIZ / "vpn-bot-wizard"

pytestmark = pytest.mark.timeout(120)


class Host:
    """A fake root, a stub directory and the call log."""

    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.calls = tmp / "calls.log"
        self.root.mkdir()
        self.bin.mkdir()
        self.calls.write_text("", encoding="utf-8")
        app = self.root / "opt" / "vpn-service"
        (app / "data").mkdir(parents=True)
        (app / "data").chmod(0o700)
        (app / "logs").mkdir()
        (app / "scripts").mkdir()
        (app / "db").mkdir()
        env = app / ".env"
        env.write_text("BOT_TOKEN=123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", encoding="utf-8")
        env.chmod(0o600)
        db = app / "data" / "vpn.db"
        import sqlite3

        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO schema_meta VALUES ('schema_version', '41')")
        conn.commit()
        conn.close()
        db.chmod(0o600)
        (app / "db" / "database.py").write_text("CURRENT_SCHEMA_VERSION = 41\n", encoding="utf-8")
        # one registered helper, in sync
        (app / "scripts" / "helper-a").write_text("#!/bin/sh\necho a\n", encoding="utf-8")
        sbin = self.root / "usr" / "local" / "sbin"
        sbin.mkdir(parents=True)
        (sbin / "helper-a").write_text("#!/bin/sh\necho a\n", encoding="utf-8")
        (app / "scripts" / "deploy.sh").write_text(
            'OUT_OF_REPO_HELPERS=(\n  "scripts/helper-a|/usr/local/sbin/helper-a|required"\n'
            '  "scripts/relay-only|/usr/local/sbin/relay-only|required|relay"\n)\n',
            encoding="utf-8",
        )
        # The default stubs: a quiet, healthy host.
        self.stub("systemctl", r'''
case "$*" in
  "list-units"*) cat "$SD/units" 2>/dev/null || true ;;
  "is-enabled warp-routes.service") echo disabled; exit 1 ;;
  "--failed"*) cat "$SD/failed" 2>/dev/null || true ;;
  "is-active vpn-bot.service") cat "$SD/bot-state" 2>/dev/null || echo active ;;
  *) : ;;
esac
''')
        self.stub("systemd-run", 'exit "$(cat "$SD/systemd-run-rc" 2>/dev/null || echo 0)"\n')
        self.stub("vpn-bot-ufw-apply", 'echo "listener=ok|tcp|443|*|xray: allowed"; echo "listeners=ok"\n')
        self.stub("openssl", 'echo "notAfter=Jan  1 00:00:00 2099 GMT"\n')

    def stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(
            '#!/bin/bash\nprintf "%s\\n" "$(basename "$0") $*" >> "$CALLS"\n' + body,
            encoding="utf-8",
        )
        path.chmod(0o755)

    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "VPN_BOT_WIZARD_SELFTEST": "1",
            "VPN_BOT_WIZARD_ROOT": str(self.root),
            "VPN_BOT_WIZARD_SELFTEST_BIN": str(self.bin),
            "CALLS": str(self.calls),
            "SD": str(self.bin.parent),
            "TZ": "UTC",
            **extra,
        }

    def run(self, argv: list[str], **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", *argv], capture_output=True, text=True, env=self.env(**extra), timeout=90, check=False
        )

    def launcher(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.run([str(LAUNCHER), *args])

    def helper(self, name: str, *args: str) -> subprocess.CompletedProcess[str]:
        return self.run([str(WIZ / name), *args])

    def events(self, run_id: int) -> list[dict[str, Any]]:
        path = self.root / "var" / "lib" / "vpn-bot-wizard" / f"{run_id}.status"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def calls_of(self, name: str) -> list[str]:
        return [line for line in self.calls.read_text(encoding="utf-8").splitlines() if line.split(" ", 1)[0] == name]

    def file(self, rel: str) -> Path:
        return self.root / rel.lstrip("/")


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def finished(events: list[dict[str, Any]]) -> dict[str, Any]:
    done = [e for e in events if e["event"] == "finished"]
    assert len(done) == 1, events
    return done[0]


# --------------------------------------------------------------------------- #
# The launcher
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "args",
    [
        ["launch", "--mode", "shell", "--run", "1", "--phase", "plan"],
        ["launch", "--mode", "update", "--run", "0", "--phase", "plan"],
        ["launch", "--mode", "update", "--run", "1;id", "--phase", "plan"],
        ["launch", "--mode", "update", "--run", "1", "--phase", "apply"],
        ["launch", "--mode", "dump", "--run", "1", "--phase", "execute", "--param", "lines=5"],
        ["launch", "--mode", "dump", "--run", "1", "--phase", "execute", "--param", "lines=abc"],
        ["launch", "--mode", "update", "--run", "1", "--phase", "plan", "--param", "force=yes"],
        ["launch", "--mode", "update", "--run", "1", "--phase", "plan", "--param", "cmd=rm"],
        ["launch", "--mode", "update", "--run", "1", "--phase", "plan", "--param", "force=1", "--param", "force=0"],
        ["launch", "--mode", "selfcheck", "--run", "1", "--phase", "execute", "--shell", "x"],
        ["exec", "--mode", "selfcheck"],
        [],
    ],
)
def test_launcher_refuses_anything_outside_the_table(host: Host, args: list[str]) -> None:
    result = host.launcher(*args)
    assert result.returncode == 2, result.stderr
    assert host.calls_of("systemd-run") == []
    assert host.calls_of("systemctl") == []


def test_launch_starts_the_phase_only_through_systemd_run(host: Host) -> None:
    result = host.launcher("launch", "--mode", "dump", "--run", "17", "--phase", "execute", "--param", "lines=50")
    assert result.returncode == 0, result.stderr
    (call,) = host.calls_of("systemd-run")
    argv = call.split(" ")
    assert argv[1:4] == ["--unit=vpn-bot-wizard-17", "--collect", "--quiet"]
    tail = argv[argv.index(str(LAUNCHER)) :]
    assert tail == [str(LAUNCHER), "run", "--mode", "dump", "--run", "17", "--phase", "execute", "--param", "lines=50"]
    events = host.events(17)
    assert events[0]["event"] == "launched" and events[0]["phase"] == "execute"
    assert (host.file("/var/lib/vpn-bot-wizard").stat().st_mode & 0o777) == 0o755
    assert (host.file("/var/log/vpn-bot-wizard").stat().st_mode & 0o777) == 0o750


def test_launch_fills_in_parameter_defaults(host: Host) -> None:
    assert host.launcher("launch", "--mode", "update", "--run", "3", "--phase", "plan").returncode == 0
    (call,) = host.calls_of("systemd-run")
    assert call.endswith("--phase plan --param force=0")


@pytest.mark.parametrize(
    "line",
    [
        "vpn-bot-wizard-9.service loaded active running vpn-bot setup wizard",
        "● vpn-bot-wizard-9.service loaded activating start vpn-bot setup wizard",
        "vpn-bot-wizard-9-deadman.timer loaded active waiting vpn-bot wizard run 9: dead-man rollback",
    ],
)
def test_launch_refuses_while_another_wizard_unit_runs(host: Host, line: str) -> None:
    (host.bin.parent / "units").write_text(
        "vpn-bot-wizard-2.service loaded inactive dead old run\n" + line + "\n", encoding="utf-8"
    )
    result = host.launcher("launch", "--mode", "selfcheck", "--run", "10", "--phase", "execute")
    assert result.returncode == 3
    assert "vpn-bot-wizard-9" in result.stderr
    assert host.calls_of("systemd-run") == []


def test_launch_refuses_while_the_lock_is_held(host: Host) -> None:
    lock = host.file("/run/vpn-bot-wizard.lock")
    lock.parent.mkdir(parents=True)
    with lock.open("w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        result = host.launcher("launch", "--mode", "selfcheck", "--run", "10", "--phase", "execute")
    assert result.returncode == 3
    assert host.calls_of("systemd-run") == []


def test_a_failed_systemd_run_is_a_failed_run(host: Host) -> None:
    (host.bin.parent / "systemd-run-rc").write_text("1", encoding="utf-8")
    result = host.launcher("launch", "--mode", "selfcheck", "--run", "4", "--phase", "execute")
    assert result.returncode == 3
    assert finished(host.events(4))["outcome"] == "failed"


# --------------------------------------------------------------------------- #
# The runner and the contract
# --------------------------------------------------------------------------- #
def test_runner_refuses_a_second_run_while_the_lock_is_held(host: Host) -> None:
    lock = host.file("/run/vpn-bot-wizard.lock")
    lock.parent.mkdir(parents=True)
    with lock.open("w") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        result = host.launcher("run", "--mode", "selfcheck", "--run", "8", "--phase", "execute")
    assert result.returncode == 3
    assert finished(host.events(8))["outcome"] == "failed"


@pytest.mark.parametrize("helper", ["vpn-bot-wizard-selfcheck", "vpn-bot-wizard-dump", "vpn-bot-wizard-update"])
def test_every_mode_helper_speaks_the_contract(host: Host, helper: str) -> None:
    assert host.helper(helper, "shell", "--run", "1").returncode == 2
    assert host.helper(helper, "plan").returncode == 2
    assert host.helper(helper, "plan", "--run", "1", "--param", "nope=1").returncode == 2
    assert host.helper(helper, "apply", "--run", "1", "--deadman").returncode == 2  # only rollback takes it


def test_selfcheck_on_a_healthy_host_is_all_green(host: Host) -> None:
    result = host.launcher("run", "--mode", "selfcheck", "--run", "5", "--phase", "execute")
    assert result.returncode == 0, result.stderr
    events = host.events(5)
    assert finished(events)["outcome"] == "succeeded"
    items = {e["key"]: e["level"] for e in events if e["event"] == "item"}
    for key in ("listeners", "warp", "failed_units", "certs", "helpers", "perms", "reboot"):
        assert items[key] == "green", (key, events)
    assert "disk" in items
    steps = [(e["step"], e["state"]) for e in events if e["event"] == "step"]
    assert steps == [("apply", "start"), ("apply", "ok"), ("verify", "start"), ("verify", "ok")]
    assert host.calls_of("systemd-run") == []  # a read-only mode arms no dead-man


def test_selfcheck_reports_deviations(host: Host) -> None:
    (host.bin.parent / "failed").write_text("xray.service loaded failed failed Xray\n", encoding="utf-8")
    host.file("/var/run").mkdir(parents=True)
    host.file("/var/run/reboot-required").write_text("*** System restart required ***\n", encoding="utf-8")
    host.file("/var/run/reboot-required.pkgs").write_text("linux-image-6.8\n", encoding="utf-8")
    host.file("/opt/vpn-service/.env").chmod(0o644)
    host.file("/usr/local/sbin/helper-a").write_text("#!/bin/sh\necho stale\n", encoding="utf-8")
    host.stub("vpn-bot-ufw-apply", 'echo "listener=FAIL|tcp|8080|0.0.0.0|python3: not allowed"; echo "listeners=fail"\n')
    host.stub("openssl", 'echo "notAfter=Jan  1 00:00:00 2000 GMT"\n')
    acme = host.file("/root/.acme.sh/example.org_ecc")
    acme.mkdir(parents=True)
    (acme / "example.org.conf").write_text("Le_Domain='example.org'\nLe_ReloadCmd=''\n", encoding="utf-8")
    (acme / "example.org.cer").write_text("cert", encoding="utf-8")
    assert host.launcher("run", "--mode", "selfcheck", "--run", "6", "--phase", "execute").returncode == 0
    items = {e["key"]: (e["level"], e["text"]) for e in host.events(6) if e["event"] == "item"}
    assert items["failed_units"][0] == "red" and "xray.service" in items["failed_units"][1]
    assert items["reboot"][0] == "yellow" and "linux-image-6.8" in items["reboot"][1]
    assert items["perms"][0] == "red" and "world-accessible" in items["perms"][1]
    assert items["helpers"][0] == "yellow" and "helper-a" in items["helpers"][1]
    assert items["listeners"][0] == "red" and "8080" in items["listeners"][1]
    assert items["cert:example.org:reload"][0] == "yellow"
    assert items["cert:example.org"][0] == "red"
    summary = [e for e in host.events(6) if e["event"] == "summary"][0]
    assert summary["red"] >= 4


# --------------------------------------------------------------------------- #
# Self-check: WARP — intent (what the bot keeps) against fact (what the kernel routes)
# --------------------------------------------------------------------------- #
GW = "203.0.113.1"
ANTI_LOOP = f"162.159.195.1 via {GW} dev eth0"
# The production host as measured on 2026-11-15: WARP_PROXY_EGRESS=true, xray's only
# outbound a freedom with sendThrough 172.16.0.2, danted `external: 172.16.0.2`, split
# OFF (marker), table 51820 = the anti-loop route only, AWG uninstalled.
PROD_NAT = (
    "-P POSTROUTING ACCEPT\n"
    "-A POSTROUTING -o out-warp -j MASQUERADE\n"
    "-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE\n"
    "-A POSTROUTING -s 172.16.0.2/32 -o eth0 -j MASQUERADE\n"
)
PROD_ADDR = "lo               UNKNOWN        127.0.0.1/8 \neth0             UP             198.18.0.10/24 \nout-warp         UNKNOWN        172.16.0.2/32 \n"
_WARP_STUBS = {
    "awg": r"""
case "$*" in
  "show out-warp fwmark") cat "$SD/fwmark" 2>/dev/null || { echo "Unable to access interface: No such device" >&2; exit 1; } ;;
  *) exit 1 ;;
esac
""",
    "ip": r"""
case "$1 $2 $3" in
  "-4 rule show") cat "$SD/ip-rule" 2>/dev/null ;;
  "-4 route show")
    if [ "$4" = default ]; then cat "$SD/ip-default" 2>/dev/null
    else cat "$SD/ip-table" 2>/dev/null || { echo "Error: ipv4: FIB table does not exist." >&2; exit 2; }; fi ;;
  "-4 -br addr") cat "$SD/ip-addr" 2>/dev/null ;;
  "-4 route get")
    f="$SD/route-get.$4"; [ -f "$f" ] || f="$SD/route-get"
    [ -f "$f" ] || { echo "RTNETLINK answers: Network is unreachable" >&2; exit 2; }
    echo "$4 from $6 $(cat "$f") uid 0"; echo "    cache" ;;
  *) echo "ip stub: unexpected $*" >&2; exit 9 ;;
esac
""",
    "iptables": r"""
case "$*" in
  "-t nat -S POSTROUTING") cat "$SD/nat" 2>/dev/null ;;
  *) echo "iptables stub: unexpected $*" >&2; exit 9 ;;
esac
""",
    # The real helper's status verb: n_table is ITS awk filter over the same table.
    "vpn-bot-warp-split-state": r"""
[ "$1" = status ] || exit 2
if [ -f "$SD/fwmark" ]; then
  echo tunnel_up=1
  echo "n_table=$(awk -v dev="${WARP_IFACE:-out-warp}" '$1!="default" && $2=="dev" && $3==dev' "$SD/ip-table" 2>/dev/null | wc -l | tr -d ' ')"
else
  echo tunnel_up=0; echo n_table=0
fi
if [ -e "$VPN_BOT_WIZARD_ROOT/etc/vpn-bot/warp-split.disabled" ]; then echo marker=off; else echo marker=on; fi
""",
}


def warp_host(
    host: Host,
    *,
    enabled: int | None = 1,
    fwmark: str | None = "0xca6c",
    marker: bool = True,
    split_list: list[str] | None = None,
    table: str | None = ANTI_LOOP,
    rules: str = "999: from 172.16.0.2 lookup 51820\n1000: from 10.0.0.0/24 lookup 51820\n",
    awg_removed: bool = True,
    env: str = "WARP_PROXY_EGRESS=true\n",
    tunnel_ip: str = "172.16.0.2",
    send_through: str | None = "172.16.0.2",
    dante_external: str | None = "172.16.0.2",
    addr: str = PROD_ADDR,
    default: str = f"default via {GW} dev eth0 proto static",
    route_get: str | None = f"via {GW} dev eth0",
    route_get_by_probe: dict[str, str] | None = None,
    nat: str = PROD_NAT,
) -> None:
    """A WARP host: every fact a knob; the defaults are the production host above."""
    sd = host.bin.parent
    for name, body in _WARP_STUBS.items():
        host.stub(name, body)
    for name, value in (("fwmark", fwmark), ("ip-table", table), ("ip-default", default), ("route-get", route_get)):
        if value is None:
            (sd / name).unlink(missing_ok=True)
        else:
            (sd / name).write_text(value + "\n", encoding="utf-8")
    (sd / "ip-rule").write_text(rules, encoding="utf-8")
    (sd / "ip-addr").write_text(addr, encoding="utf-8")
    (sd / "nat").write_text(nat, encoding="utf-8")
    for old in sd.glob("route-get.*"):
        old.unlink()
    for probe, tail in (route_get_by_probe or {}).items():
        (sd / f"route-get.{probe}").write_text(tail + "\n", encoding="utf-8")
    import sqlite3

    conn = sqlite3.connect(host.file("/opt/vpn-service/data/vpn.db"))
    conn.execute("DROP TABLE IF EXISTS warp_settings")
    if enabled is not None:
        conn.execute("CREATE TABLE warp_settings (id INTEGER PRIMARY KEY DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 0)")
        conn.execute("INSERT INTO warp_settings (id, enabled) VALUES (1, ?)", (enabled,))
    conn.commit()
    conn.close()
    host.file("/opt/vpn-service/.env").write_text(
        "BOT_TOKEN=123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n" + env, encoding="utf-8"
    )
    files: dict[str, str | None] = {
        "/etc/amnezia/out-warp.conf": f"[Interface]\nAddress = {tunnel_ip}/32\n\n[Peer]\nEndpoint = 162.159.195.1:500\n",
        "/etc/vpn-bot/warp-split.disabled": "disabled\n" if marker else None,
        "/etc/vpn-bot/warp-split.list": "".join(f"{p}\n" for p in split_list) if split_list is not None else None,
        "/etc/vpn-bot/uninstalled/awg": '{"ts": 1}\n' if awg_removed else None,
        "/usr/local/etc/xray/config.json": json.dumps(
            {"outbounds": [{"protocol": "freedom", "tag": "direct", **({"sendThrough": send_through} if send_through else {})}]}
        ),
        "/etc/danted.conf": f"logoutput: syslog\ninternal: eth0 port = 1080\nexternal: {dante_external}\n" if dante_external else None,
    }
    for rel, content in files.items():
        path = host.file(rel)
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")


_RUN_IDS = iter(range(700, 10**6))


def warp_items(host: Host) -> list[dict[str, Any]]:
    run_id = next(_RUN_IDS)
    result = host.launcher("run", "--mode", "selfcheck", "--run", str(run_id), "--phase", "execute")
    assert result.returncode == 0, result.stderr
    return [e for e in host.events(run_id) if e["event"] == "item" and e["key"].startswith("warp")]


def only(items: list[dict[str, Any]], key: str) -> dict[str, Any]:
    found = [i for i in items if i["key"] == key]
    assert len(found) == 1, items
    return found[0]


def verdict(items: list[dict[str, Any]], key: str) -> tuple[str, str]:
    item = only(items, key)
    return item["level"], item["msg"]


def test_selfcheck_warp_not_deployed_has_nothing_to_check(host: Host) -> None:
    items = warp_items(host)
    assert [(i["key"], i["level"], i["msg"]) for i in items] == [("warp", "green", "warp_not_deployed")]


@pytest.mark.parametrize("enabled", [1, 0])
@pytest.mark.parametrize("flag", ["WARP_PROXY_EGRESS=true", "WARP_PROXY_EGRESS_ENABLED=true"])
def test_selfcheck_warp_production_host_is_all_green(host: Host, enabled: int, flag: str) -> None:
    """THE regression: split OFF by marker, table 51820 = anti-loop only, AWG uninstalled,
    VLESS/SOCKS5 sending from 172.16.0.2 straight out of eth0 with its own MASQUERADE.
    Not one red or yellow, and no word of "WARP clients" where there are none."""
    warp_host(host, enabled=enabled, env=flag + "\n")
    items = warp_items(host)
    assert {i["level"] for i in items} == {"green"}, items
    # AWG is gone: no client rule and no client SNAT to want.
    assert not {"warp:rule", "warp:clients_nat"} & {i["key"] for i in items}
    egress = only(items, "warp:egress")
    assert egress["msg"] == "warp_egress_direct_ok"
    assert egress["args"]["addr"] == "172.16.0.2" and egress["args"]["wan"] == "eth0"
    assert egress["args"]["protos"] == "VLESS/SOCKS5"
    assert only(items, "warp")["msg"] == ("warp_direct_ok" if enabled else "warp_disabled_up")
    assert not any("clients have no way out" in i["text"] for i in items)


def test_selfcheck_warp_stays_read_only(host: Host) -> None:
    warp_host(host)
    warp_items(host)
    for line in host.calls_of("ip"):
        assert line.split()[1:4] in (["-4", "rule", "show"], ["-4", "route", "show"], ["-4", "-br", "addr"], ["-4", "route", "get"]), line
    assert host.calls_of("iptables") and all(line == "iptables -t nat -S POSTROUTING" for line in host.calls_of("iptables"))
    assert all(line.split()[1:] in (["show", "out-warp", "fwmark"],) for line in host.calls_of("awg"))
    assert host.calls_of("vpn-bot-warp-split-state") == ["vpn-bot-warp-split-state status"]


def test_selfcheck_warp_turned_off_by_the_administrator_is_green(host: Host) -> None:
    warp_host(host, enabled=0, fwmark=None, send_through=None, dante_external=None, env="")
    assert [(i["key"], i["level"], i["msg"]) for i in warp_items(host)] == [("warp", "green", "warp_disabled")]
    warp_host(host, enabled=0, send_through=None, dante_external=None, env="")
    items = warp_items(host)
    assert [(i["key"], i["level"], i["msg"]) for i in items] == [("warp", "green", "warp_disabled_up")]
    assert items[0]["args"]["iface"] == "out-warp"


def test_selfcheck_warp_turned_on_without_an_interface_is_red(host: Host) -> None:
    warp_host(host, fwmark=None, send_through=None, dante_external=None, env="")
    assert verdict(warp_items(host), "warp") == ("red", "warp_down")
    warp_host(host, enabled=None, fwmark=None, send_through=None, dante_external=None, env="")
    assert verdict(warp_items(host), "warp") == ("red", "warp_down_unknown")  # vpn.db had no warp_settings


@pytest.mark.parametrize(
    ("table", "level", "msg"),
    [
        (ANTI_LOOP, "green", "warp_direct_ok"),
        (f"{ANTI_LOOP}\n1.2.3.0/24 dev out-warp scope link\n5.6.0.0/16 dev out-warp scope link", "yellow", "warp_direct_drift"),
        # The PR #274 class: at boot «off» became a full tunnel.
        (f"default dev out-warp scope link\n{ANTI_LOOP}", "yellow", "warp_direct_default"),
        (None, "green", "warp_direct_ok"),  # "FIB table does not exist" = empty
    ],
)
def test_selfcheck_warp_split_off_wants_no_route_via_out_warp(host: Host, table: str | None, level: str, msg: str) -> None:
    warp_host(host, table=table)
    item = only(warp_items(host), "warp")
    assert (item["level"], item["msg"]) == (level, msg)
    if msg == "warp_direct_drift":
        assert item["args"]["count"] == "2"


@pytest.mark.parametrize(
    ("table", "level", "msg"),
    [
        (f"1.2.3.0/24 dev out-warp scope link\n5.6.0.0/16 dev out-warp scope link\n{ANTI_LOOP}", "green", "warp_selective_ok"),
        (f"1.2.3.0/24 dev out-warp scope link\n{ANTI_LOOP}", "yellow", "warp_selective_drift"),
        ("default dev out-warp scope link\n1.2.3.0/24 dev out-warp scope link\n5.6.0.0/16 dev out-warp scope link", "yellow", "warp_selective_default"),
    ],
)
def test_selfcheck_warp_selective_split_matches_the_list(host: Host, table: str, level: str, msg: str) -> None:
    # A comment, a duplicate in another spelling and an IPv6 line route nothing extra.
    warp_host(host, marker=False, split_list=["# feed", "1.2.3.0/24", "1.2.3.7/24", "5.6.0.0/16", "2001:db8::/32"], table=table,
              send_through=None, dante_external=None, env="")
    item = only(warp_items(host), "warp")
    assert (item["level"], item["msg"]) == (level, msg)
    assert item["args"].get("want", "2") == "2"
    if msg == "warp_selective_drift":
        assert item["args"]["count"] == "1"


@pytest.mark.parametrize(("table", "level", "msg"), [
    (f"default dev out-warp scope link\n{ANTI_LOOP}", "green", "warp_full_ok"),
    (ANTI_LOOP, "red", "warp_full_missing"),
])
def test_selfcheck_warp_full_tunnel_needs_its_default(host: Host, table: str, level: str, msg: str) -> None:
    warp_host(host, marker=False, split_list=None, table=table, send_through=None, dante_external=None, env="")
    assert verdict(warp_items(host), "warp") == (level, msg)


@pytest.mark.parametrize(
    ("marker", "rules", "level", "msg"),
    [
        (False, "1000: from 10.0.0.0/24 lookup 51820\n", "green", "warp_rule_ok"),
        (False, "999: from 172.16.0.2 lookup 51820\n", "red", "warp_rule_missing"),  # the proxy rule is not the client's
        (True, "0: from all lookup local\n", "yellow", "warp_rule_missing_direct"),
    ],
)
def test_selfcheck_warp_client_rule_only_while_awg_is_installed(host: Host, marker: bool, rules: str, level: str, msg: str) -> None:
    table = ANTI_LOOP if marker else f"default dev out-warp scope link\n{ANTI_LOOP}"
    warp_host(host, marker=marker, table=table, rules=rules, awg_removed=False, send_through=None, dante_external=None, env="")
    items = warp_items(host)
    item = only(items, "warp:rule")
    assert (item["level"], item["msg"]) == (level, msg)
    assert item["args"] == {"subnet": "10.0.0.0/24", "table": "51820"}
    if marker:  # split off: no client enters WARP, nothing to masquerade there
        assert "warp:clients_nat" not in {i["key"] for i in items}
    else:
        assert verdict(items, "warp:clients_nat") == ("green", "warp_clients_nat_ok")


def test_selfcheck_warp_egress_without_the_masquerade_for_its_address_is_red(host: Host) -> None:
    warp_host(host, nat=PROD_NAT.replace("-A POSTROUTING -s 172.16.0.2/32 -o eth0 -j MASQUERADE\n", ""))
    item = only(warp_items(host), "warp:egress")
    assert (item["level"], item["msg"]) == ("red", "warp_egress_no_snat")
    assert "without" not in item["text"] and "no SNAT" in item["text"] and "hy2 may still work" in item["text"]
    # A MASQUERADE that is not for this source (a mark match) does not count either.
    warp_host(host, nat=PROD_NAT.replace("-s 172.16.0.2/32 -o eth0", "-o eth0 -m mark --mark 0x2"))
    assert verdict(warp_items(host), "warp:egress") == ("red", "warp_egress_no_snat")
    # A plain MASQUERADE on the WAN with no source covers it.
    warp_host(host, nat="-A POSTROUTING -o eth0 -j MASQUERADE\n")
    assert verdict(warp_items(host), "warp:egress") == ("green", "warp_egress_direct_ok")


def test_selfcheck_warp_egress_address_gone_from_out_warp_is_red_even_with_split_off(host: Host) -> None:
    warp_host(host, addr="eth0             UP             198.18.0.10/24 \n")
    items = warp_items(host)
    egress = only(items, "warp:egress")
    assert (egress["level"], egress["msg"]) == ("red", "warp_egress_addr_missing")
    assert egress["args"] == {"who": "xray/danted", "addr": "172.16.0.2", "iface": "out-warp"}
    assert only(items, "warp")["level"] == "green"  # the split itself is as intended
    warp_host(host, addr=PROD_ADDR.replace("out-warp         UNKNOWN", "out-warp         DOWN   "))
    assert verdict(warp_items(host), "warp:egress") == ("red", "warp_egress_iface_down")


def test_selfcheck_warp_egress_unreadable_addresses_are_no_red(host: Host) -> None:
    warp_host(host)
    host.stub("ip", _WARP_STUBS["ip"].replace('"-4 -br addr") cat "$SD/ip-addr" 2>/dev/null ;;', '"-4 -br addr") exit 1 ;;'))
    assert verdict(warp_items(host), "warp:egress") == ("yellow", "warp_egress_addrs_unreadable")


def test_selfcheck_warp_egress_split_off_but_still_through_warp_is_yellow(host: Host) -> None:
    warp_host(host, route_get="dev out-warp table 51820")
    assert verdict(warp_items(host), "warp:egress") == ("yellow", "warp_egress_direct_via_warp")
    warp_host(host, route_get=None)  # no route at all
    item = only(warp_items(host), "warp:egress")
    assert (item["level"], item["msg"], item["args"]["got"]) == ("red", "warp_egress_route", "—")


def test_selfcheck_warp_egress_selective_needs_both_paths(host: Host) -> None:
    listed = {"1.2.3.1": "dev out-warp table 51820"}
    table = f"1.2.3.0/24 dev out-warp scope link\n{ANTI_LOOP}"
    warp_host(host, marker=False, split_list=["1.2.3.0/24"], table=table, route_get_by_probe=listed)
    item = only(warp_items(host), "warp:egress")
    assert (item["level"], item["msg"]) == ("green", "warp_egress_selective_ok")
    assert item["args"]["probe_in"] == "1.2.3.1" and item["args"]["probe"] == "192.0.2.1"
    # The listed prefix leaves through the WAN: the split is not doing its job.
    warp_host(host, marker=False, split_list=["1.2.3.0/24"], table=table)
    item = only(warp_items(host), "warp:egress")
    assert (item["level"], item["msg"], item["args"]["want"], item["args"]["got"]) == ("red", "warp_egress_route", "out-warp", "eth0")
    # The rest goes out of the WAN without a MASQUERADE for the address.
    warp_host(host, marker=False, split_list=["1.2.3.0/24"], table=table, route_get_by_probe=listed,
              nat="-A POSTROUTING -o out-warp -j MASQUERADE\n")
    assert verdict(warp_items(host), "warp:egress") == ("red", "warp_egress_no_snat")
    # The probe outside the list is never one the list covers.
    warp_host(host, marker=False, split_list=["192.0.2.0/24", "1.2.3.0/24"], table=table,
              route_get_by_probe={"192.0.2.1": "dev out-warp table 51820"})
    item = only(warp_items(host), "warp:egress")
    assert item["msg"] == "warp_egress_selective_ok" and item["args"]["probe"] == "198.51.100.1"


NO_WARP_MASQ = PROD_NAT.replace("-A POSTROUTING -o out-warp -j MASQUERADE\n", "")


def test_selfcheck_warp_tunnel_address_needs_no_masquerade_on_out_warp(host: Host) -> None:
    """The production facts (A = 172.16.0.2 = the out-warp address, AWG uninstalled)
    without `-o out-warp -j MASQUERADE`: the proxies are fine — the tunnel address is the
    source WARP accepts — and with no AWG clients there is no client SNAT item at all."""
    listed = {"1.2.3.1": "dev out-warp table 51820"}
    table = f"1.2.3.0/24 dev out-warp scope link\n{ANTI_LOOP}"
    warp_host(host, marker=False, split_list=["1.2.3.0/24"], table=table, route_get_by_probe=listed, nat=NO_WARP_MASQ)
    items = warp_items(host)
    assert {i["level"] for i in items} == {"green"}, items
    assert only(items, "warp:egress")["msg"] == "warp_egress_selective_ok"
    assert "warp:clients_nat" not in {i["key"] for i in items}
    warp_host(host, marker=False, table=f"default dev out-warp scope link\n{ANTI_LOOP}",
              route_get="dev out-warp table 51820", nat=NO_WARP_MASQ)
    assert verdict(warp_items(host), "warp:egress") == ("green", "warp_egress_full_ok")


def test_selfcheck_warp_awg_clients_without_masquerade_on_out_warp_are_red_on_their_own(host: Host) -> None:
    listed = {"1.2.3.1": "dev out-warp table 51820"}
    table = f"1.2.3.0/24 dev out-warp scope link\n{ANTI_LOOP}"
    warp_host(host, marker=False, split_list=["1.2.3.0/24"], table=table, route_get_by_probe=listed, nat=NO_WARP_MASQ,
              awg_removed=False)
    items = warp_items(host)
    assert [(i["key"], i["msg"]) for i in items if i["level"] != "green"] == [("warp:clients_nat", "warp_clients_nat_missing")]
    clients = only(items, "warp:clients_nat")
    assert clients["args"] == {"subnet": "10.0.0.0/24", "iface": "out-warp"}
    assert "without SNAT" in clients["text"]
    assert verdict(items, "warp:egress") == ("green", "warp_egress_selective_ok")  # the proxies are not the clients


def test_selfcheck_warp_another_address_through_out_warp_needs_its_masquerade(host: Host) -> None:
    """A is on out-warp but is not the tunnel address WARP assigned: through the tunnel
    it must be masqueraded, or WARP drops it."""
    addr = PROD_ADDR.replace("172.16.0.2/32", "172.16.0.2/32 172.16.0.9/32")
    table = f"default dev out-warp scope link\n{ANTI_LOOP}"
    common: dict[str, Any] = {"marker": False, "table": table, "addr": addr, "send_through": "172.16.0.9",
                              "dante_external": None, "route_get": "dev out-warp table 51820"}
    warp_host(host, nat=NO_WARP_MASQ, **common)
    item = only(warp_items(host), "warp:egress")
    assert (item["level"], item["msg"]) == ("red", "warp_egress_warp_no_nat")
    assert item["args"]["addr"] == "172.16.0.9" and item["args"]["tunnel"] == "172.16.0.2"
    warp_host(host, nat=PROD_NAT, **common)
    assert verdict(warp_items(host), "warp:egress") == ("green", "warp_egress_full_ok")


def test_selfcheck_warp_egress_full_tunnel_goes_through_out_warp(host: Host) -> None:
    table = f"default dev out-warp scope link\n{ANTI_LOOP}"
    warp_host(host, marker=False, table=table, route_get="dev out-warp table 51820")
    assert verdict(warp_items(host), "warp:egress") == ("green", "warp_egress_full_ok")
    warp_host(host, marker=False, table=table)
    assert verdict(warp_items(host), "warp:egress") == ("red", "warp_egress_route")


def test_selfcheck_warp_egress_reads_the_address_and_the_wan_from_the_host(host: Host) -> None:
    """Nothing hardcoded: the address comes from xray/danted, the WAN from the default route."""
    addr = "lo UNKNOWN 127.0.0.1/8\nens3 UP 198.18.0.10/24\nout-warp UNKNOWN 172.16.0.9/32\n"
    warp_host(host, tunnel_ip="172.16.0.9", send_through="172.16.0.9", dante_external="172.16.0.9", addr=addr,
              default=f"default via {GW} dev ens3 proto dhcp", route_get=f"via {GW} dev ens3",
              nat="-A POSTROUTING -s 172.16.0.9/32 -o ens3 -j MASQUERADE\n")
    item = only(warp_items(host), "warp:egress")
    assert (item["level"], item["msg"]) == ("green", "warp_egress_direct_ok")
    assert item["args"]["addr"] == "172.16.0.9" and item["args"]["wan"] == "ens3"
    # The MASQUERADE of the production host names eth0: on an ens3 host it is no NAT at all.
    warp_host(host, tunnel_ip="172.16.0.9", send_through="172.16.0.9", dante_external="172.16.0.9", addr=addr,
              default=f"default via {GW} dev ens3 proto dhcp", route_get=f"via {GW} dev ens3",
              nat="-A POSTROUTING -s 172.16.0.9/32 -o eth0 -j MASQUERADE\n")
    assert verdict(warp_items(host), "warp:egress") == ("red", "warp_egress_no_snat")


def test_selfcheck_warp_egress_only_judges_proxies_bound_to_warp(host: Host) -> None:
    # sendThrough a second public IP of eth0, danted on the interface name: not WARP's business.
    warp_host(host, send_through="198.18.0.10", dante_external="eth0", env="")
    assert "warp:egress" not in {i["key"] for i in warp_items(host)}
    # Only danted bound to the tunnel address: SOCKS5 alone is named.
    warp_host(host, send_through=None)
    assert only(warp_items(host), "warp:egress")["args"]["protos"] == "SOCKS5"
    # WARP_PROXY_EGRESS on, xray read, nobody bound to the tunnel address.
    warp_host(host, send_through=None, dante_external=None)
    item = only(warp_items(host), "warp:egress")
    assert (item["level"], item["msg"], item["args"]["addr"]) == ("yellow", "warp_egress_unused", "172.16.0.2")
    # A protocol uninstalled by the bot is no consumer, whatever its leftover config says.
    warp_host(host, dante_external=None, env="")
    host.file("/etc/vpn-bot/uninstalled/xray").write_text("{}\n", encoding="utf-8")
    assert "warp:egress" not in {i["key"] for i in warp_items(host)}


@pytest.fixture
def selfcheck(host: Host, lib: ModuleType) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("vpn_bot_wizard_selfcheck_under_test", str(WIZ / "vpn-bot-wizard-selfcheck"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    try:
        loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop("vpn_bot_wizard_lib", None)


def test_selfcheck_item_messages_match_the_bots_english(selfcheck: ModuleType) -> None:
    from i18n import en, ru

    for msg, text in selfcheck.MESSAGES.items():
        assert en.STRINGS[f"wizard_item_{msg}"] == text, msg
        assert f"wizard_item_{msg}" in ru.STRINGS, msg


@pytest.mark.parametrize(
    ("rule", "dev", "covers"),
    [
        ("-A POSTROUTING -s 172.16.0.2/32 -o eth0 -j MASQUERADE", "eth0", True),
        ("-A POSTROUTING -s 172.16.0.0/12 -o eth0 -j SNAT --to-source 198.18.0.10", "eth0", True),
        ("-A POSTROUTING -o eth+ -m comment --comment \"wan nat\" -j MASQUERADE --random-fully", "eth0", True),
        ("-A POSTROUTING -o out-warp -j MASQUERADE", "out-warp", True),
        ("-A POSTROUTING -o out-warp -j MASQUERADE", "eth0", False),
        ("-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE", "eth0", False),
        ("-A POSTROUTING -o out-warp -m mark --mark 0x2 -j SNAT --to-source 172.16.0.2", "out-warp", False),
        ("-A POSTROUTING ! -s 10.0.0.0/24 -o eth0 -j MASQUERADE", "eth0", False),
        ("-A POSTROUTING -s 172.16.0.2/32 -d 1.1.1.1/32 -o eth0 -j MASQUERADE", "eth0", False),
        ("-A POSTROUTING -s 172.16.0.2/32 -o eth0 -j ACCEPT", "eth0", False),
        ("-A ufw-before-output -s 172.16.0.2/32 -o eth0 -j MASQUERADE", "eth0", False),
    ],
)
def test_snat_covers_only_plain_rules_for_the_source(selfcheck: ModuleType, rule: str, dev: str, covers: bool) -> None:
    assert selfcheck.snat_covers(rule, "172.16.0.2", dev) is covers


def test_tunnel_address_is_read_as_the_bot_reads_it(selfcheck: ModuleType, tmp_path: Path) -> None:
    from warp.proxy_egress import read_tunnel_address

    for body in ("[Interface]\nAddress = 172.16.0.2/32\n", "[Interface]\naddress=fd00::2/128, 172.16.0.3/32\n",
                 "[Interface]\nPrivateKey = x\n", "  Address =  10.9.0.1 \n"):
        conf = tmp_path / "out-warp.conf"
        conf.write_text(body, encoding="utf-8")
        assert selfcheck.read_tunnel_address(conf) == read_tunnel_address(conf), body


def test_dump_is_redacted_and_judges_errors_by_timestamp(host: Host) -> None:
    token = "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    logs = host.file("/opt/vpn-service/logs")
    (logs / "bot.log").write_text(
        "2026-11-13T10:00:00+0000 INFO [x] started\n"
        f"2026-11-13T10:05:00+0000 ERROR [x] failed with bot_token={token}\n"
        "2026-11-13T10:06:00+0000 INFO [x] password=hunter2 ok\n",
        encoding="utf-8",
    )
    host.file("/var/log/xray").mkdir(parents=True)
    host.file("/var/log/xray/error.log").write_text(
        "2026/11/13 09:00:00 [Error] old failure\n2026/11/13 11:30:00 [Warning] noise\n", encoding="utf-8"
    )
    host.stub("git", 'case "$*" in *rev-parse*) echo deadbeef ;; *log*) echo "deadbee 2026 msg" ;; esac\n')
    result = host.launcher("run", "--mode", "dump", "--run", "11", "--phase", "execute", "--param", "lines=20")
    assert result.returncode == 0, result.stderr
    events = host.events(11)
    assert finished(events)["outcome"] == "succeeded"
    artifact = [e for e in events if e["event"] == "artifact"][0]
    dump = host.file("/var/lib/vpn-bot-wizard/11.dump.txt")
    assert artifact["name"] == "dump.txt" and dump.exists()
    assert (dump.stat().st_mode & 0o777) == 0o640
    text = dump.read_text(encoding="utf-8")
    assert token not in text and "hunter2" not in text
    assert "last ERROR at 2026-11-13T10:05:00 UTC" in text
    assert "last ERROR at 2026-11-13T09:00:00 UTC" in text  # host time (TZ=UTC here), shown in UTC
    assert "live schema_version: 41" in text
    log = host.file("/var/log/vpn-bot-wizard/11.log").read_text(encoding="utf-8")
    assert token not in log


def test_dump_verify_refuses_an_artifact_with_a_secret(host: Host) -> None:
    path = host.file("/var/lib/vpn-bot-wizard/12.dump.txt")
    path.parent.mkdir(parents=True)
    path.write_text("leak: 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", encoding="utf-8")
    assert host.helper("vpn-bot-wizard-dump", "verify", "--run", "12").returncode == 1
    assert host.helper("vpn-bot-wizard-dump", "rollback", "--run", "12").returncode == 0
    assert not path.exists()


# --------------------------------------------------------------------------- #
# update
# --------------------------------------------------------------------------- #
TIP = "b" * 40


def _git_stub(host: Host, *, commits: int = 2, head: str = "a" * 40, ahead: int = 0) -> None:
    """origin/main is TIP unless $SD/tip says otherwise (a push after the plan)."""
    host.stub("git", rf'''
case "$*" in
  *"fetch origin main"*) : ;;
  *"rev-parse --short HEAD"*) echo aaaaaaa ;;
  *"rev-parse --short origin/main"*) echo bbbbbbb ;;
  *"rev-parse origin/main"*) cat "$SD/tip" 2>/dev/null || echo {TIP} ;;
  *"rev-parse HEAD"*) echo {head} ;;
  *"rev-list --count HEAD..origin/main"*) echo {commits} ;;
  *"rev-list --count origin/main..HEAD"*) echo {ahead} ;;
  *"log --oneline"*) [ {commits} -gt 0 ] && printf 'bbbbbbb feat: two\ncccccc1 fix: one\n' ;;
  *"show HEAD:db/database.py"*) echo "CURRENT_SCHEMA_VERSION = 41" ;;
  *"show origin/main:db/database.py"*) echo "CURRENT_SCHEMA_VERSION = 42" ;;
esac
''')


def _planned(host: Host, run_id: int, target: str = TIP) -> None:
    """What step_plan leaves behind: the revision the superadmin was shown."""
    path = host.file(f"/var/lib/vpn-bot-wizard/{run_id}.update-plan.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"target": target}), encoding="utf-8")


def _redeploy_stub(host: Host, outcome: str) -> None:
    host.stub("bash", rf'''
echo "env: CHECK=${{CHECK:-}} FORCE=${{FORCE:-}} ATTACH=${{REDEPLOY_ATTACH:-}}" >> "$CALLS"
if [ "${{CHECK:-}}" = 1 ]; then
  echo "===== PHASE 1 REPORT (PHASE1_ONLY=1 — no mutations performed) ====="; exit 0
fi
case "{outcome}" in
  ok) printf '===== DEPLOY OK =====\n  deployed         : aaaaaaa -> bbbbbbb\n  schema_version   : 41 -> 42 (target 42)\n=====================\n' ;;
  rollback) printf '===== ROLLBACK REPORT =====\n  - start vpn-bot: rc=0\n===========================\n'; exit 1 ;;
  die) echo "[deploy] FATAL: unit drift detected"; exit 1 ;;
esac
''')


def test_update_plan_shows_commits_and_the_migration_and_runs_check(host: Host) -> None:
    _git_stub(host)
    _redeploy_stub(host, "ok")
    assert host.launcher("run", "--mode", "update", "--run", "20", "--phase", "plan", "--param", "force=0").returncode == 0
    events = host.events(20)
    assert finished(events)["outcome"] == "planned"
    plan = [e for e in events if e["event"] == "plan"][0]
    assert "aaaaaaa → origin/main bbbbbbb: 2 commit(s)" in plan["text"]
    assert "schema migration: 41 → 42" in plan["text"]
    assert plan["check_ok"] is True and plan["noop"] is False
    redeploys = [c for c in host.calls.read_text().splitlines() if c.startswith("env:")]
    assert redeploys == ["env: CHECK=1 FORCE= ATTACH=pipe"]
    (bash_call,) = host.calls_of("bash")
    assert bash_call.endswith("/opt/vpn-service/scripts/redeploy.sh")


def test_update_plan_is_a_noop_when_already_at_origin_main(host: Host) -> None:
    _git_stub(host, commits=0, head=TIP)
    _redeploy_stub(host, "ok")
    assert host.launcher("run", "--mode", "update", "--run", "21", "--phase", "plan").returncode == 0
    plan = [e for e in host.events(21) if e["event"] == "plan"][0]
    assert plan["noop"] is True
    assert host.calls_of("bash") == []  # the CHECK is skipped


def test_update_deploy_ok_succeeds(host: Host) -> None:
    _redeploy_stub(host, "ok")
    _git_stub(host)
    _planned(host, 22)
    assert host.launcher("run", "--mode", "update", "--run", "22", "--phase", "execute").returncode == 0
    events = host.events(22)
    assert finished(events)["outcome"] == "succeeded"
    result = [e for e in events if e["event"] == "result"][0]
    assert result["verdict"] == "deploy_ok" and "41 -> 42" in result["text"]
    assert [c for c in host.calls.read_text().splitlines() if c.startswith("env:")] == ["env: CHECK= FORCE= ATTACH=pipe"]


def test_update_force_is_forwarded(host: Host) -> None:
    _redeploy_stub(host, "ok")
    _git_stub(host)
    _planned(host, 23)
    host.launcher("run", "--mode", "update", "--run", "23", "--phase", "execute", "--param", "force=1")
    assert [c for c in host.calls.read_text().splitlines() if c.startswith("env:")] == ["env: CHECK= FORCE=1 ATTACH=pipe"]


def test_update_rollback_report_is_rolled_back(host: Host) -> None:
    _redeploy_stub(host, "rollback")
    _git_stub(host)
    _planned(host, 24)
    assert host.launcher("run", "--mode", "update", "--run", "24", "--phase", "execute").returncode == 1
    events = host.events(24)
    assert finished(events)["outcome"] == "rolled_back"
    steps = [(e["step"], e["state"]) for e in events if e["event"] == "step"]
    assert ("apply", "fail") in steps and ("rollback", "ok") in steps and ("verify", "start") not in steps
    result = [e for e in events if e["event"] == "result"][0]
    assert result["verdict"] == "rolled_back" and "ROLLBACK REPORT" in result["text"]


def test_update_rollback_with_the_bot_down_is_failed(host: Host) -> None:
    _redeploy_stub(host, "rollback")
    _git_stub(host)
    _planned(host, 25)
    (host.bin.parent / "bot-state").write_text("failed\n", encoding="utf-8")
    host.launcher("run", "--mode", "update", "--run", "25", "--phase", "execute")
    assert finished(host.events(25))["outcome"] == "failed"


def test_update_without_a_report_is_failed_not_rolled_back(host: Host) -> None:
    _redeploy_stub(host, "die")
    _git_stub(host)
    _planned(host, 26)
    host.launcher("run", "--mode", "update", "--run", "26", "--phase", "execute")
    events = host.events(26)
    assert finished(events)["outcome"] == "failed"
    assert [e for e in events if e["event"] == "result"][0]["verdict"] == "no_report"


def test_update_verify_needs_the_bot_running(host: Host) -> None:
    _redeploy_stub(host, "ok")
    _git_stub(host)
    _planned(host, 27)
    (host.bin.parent / "bot-state").write_text("activating\n", encoding="utf-8")
    host.launcher("run", "--mode", "update", "--run", "27", "--phase", "execute")
    steps = [(e["step"], e["state"]) for e in host.events(27) if e["event"] == "step"]
    assert ("verify", "fail") in steps


# --------------------------------------------------------------------------- #
# The library, in process
# --------------------------------------------------------------------------- #
@pytest.fixture
def lib(host: Host, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    for key, value in host.env().items():
        monkeypatch.setenv(key, value)
    loader = importlib.machinery.SourceFileLoader("vpn_bot_wizard_lib_under_test", str(WIZ / "vpn-bot-wizard-lib"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    try:
        loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(loader.name, None)


def test_redaction_patterns_match_utils_redact(lib: ModuleType) -> None:
    names = [n for n in dir(bot_redact) if n.endswith("_RE") and isinstance(getattr(bot_redact, n), re.Pattern)]
    assert names
    for name in names:
        ours, theirs = getattr(lib, name), getattr(bot_redact, name)
        assert (ours.pattern, ours.flags) == (theirs.pattern, theirs.flags), name
    sample = "token=abc secret=x https://u:p@h/ Bearer abcdefghijklmnopqrstu " + "f" * 40
    assert lib.redact_text(sample) == bot_redact.redact_text(sample)


def test_mode_table_matches_the_bots(lib: ModuleType) -> None:
    assert set(lib.MODES) == set(BOT_MODES)
    for key, mode in BOT_MODES.items():
        ours = lib.MODES[key]
        assert ours.helper == mode.helper and ours.read_only == mode.read_only, key
        assert set(ours.params) == set(mode.params), key
        for name, spec in mode.params.items():
            p = ours.params[name]
            assert (p.kind, p.default, p.minimum, p.maximum, p.choices) == (
                spec.kind,
                spec.default,
                spec.minimum,
                spec.maximum,
                spec.choices,
            ), (key, name)
        assert (WIZ / mode.helper).is_file() and os.access(WIZ / mode.helper, os.X_OK)


def test_deadman_is_a_systemd_run_timer_that_rolls_back(host: Host, lib: ModuleType) -> None:
    lib.ensure_dirs()
    with pytest.raises(lib.WizardError):
        lib.deadman_arm(5, 5, "vpn-bot-wizard-update", {})
    lib.deadman_arm(5, 120, "vpn-bot-wizard-update", {"force": "0"})
    (call,) = host.calls_of("systemd-run")
    argv = call.split(" ")
    assert "--unit=vpn-bot-wizard-5-deadman" in argv and "--on-active=120" in argv and "--collect" in argv
    assert argv[-7:] == [str(WIZ / "vpn-bot-wizard-update"), "rollback", "--run", "5", "--deadman", "--param", "force=0"]
    assert lib.deadman_disarm(5) is True
    assert "systemctl stop vpn-bot-wizard-5-deadman.timer" in host.calls_of("systemctl")
    states = [e["state"] for e in host.events(5) if e["event"] == "deadman"]
    assert states == ["armed", "disarmed"]


def test_backup_before_a_change_restores(host: Host, lib: ModuleType) -> None:
    lib.ensure_dirs()
    target = host.file("/etc/example.conf")
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    target.chmod(0o640)
    archive = lib.backup_paths(9, ["/etc/example.conf", "/etc/absent.conf"])
    assert archive.is_file() and (archive.stat().st_mode & 0o777) == 0o600
    target.write_text("after\n", encoding="utf-8")
    assert lib.restore_backup(archive) == ["/etc/example.conf"]
    assert target.read_text(encoding="utf-8") == "before\n"
    assert (target.stat().st_mode & 0o777) == 0o640


def test_selftest_refuses_commands_and_writes_outside_the_fence(lib: ModuleType) -> None:
    rc, out = lib.run_cmd(["rm", "-rf", "/nonexistent-wizard-test"])
    assert rc == 127 and "refused" in out
    with pytest.raises(lib.WizardError):
        lib.fence(Path("/etc/passwd"))


def test_validate_params_types(lib: ModuleType) -> None:
    assert lib.validate_params("dump", []) == {"lines": "200"}
    assert lib.validate_params("dump", ["lines=020"]) == {"lines": "20"}
    for bad in (["lines=1001"], ["lines=-1"], ["lines"], ["x=1"]):
        with pytest.raises(lib.WizardError):
            lib.validate_params("dump", bad)
    assert lib.validate_params("update", ["force=1"]) == {"force": "1"}
    assert lib.validate_params("selfcheck", []) == {}


def test_update_plan_records_the_revision_it_shows(host: Host) -> None:
    _git_stub(host)
    _redeploy_stub(host, "ok")
    host.launcher("run", "--mode", "update", "--run", "30", "--phase", "plan")
    plan = json.loads(host.file("/var/lib/vpn-bot-wizard/30.update-plan.json").read_text(encoding="utf-8"))
    assert plan == {"target": TIP}


def test_update_refuses_when_origin_main_moved_after_the_plan(host: Host) -> None:
    _git_stub(host)
    _redeploy_stub(host, "ok")
    _planned(host, 31)
    (host.bin.parent / "tip").write_text("c" * 40 + "\n", encoding="utf-8")
    assert host.launcher("run", "--mode", "update", "--run", "31", "--phase", "execute").returncode == 1
    events = host.events(31)
    assert finished(events)["outcome"] == "failed"
    results = [e for e in events if e["event"] == "result"]
    assert [r["verdict"] for r in results] == ["target_moved"]
    assert "bbbbbbb → ccccccc" in results[0]["text"]
    assert host.calls_of("bash") == []  # nothing was deployed


def test_update_without_a_plan_deploys_nothing(host: Host) -> None:
    _git_stub(host)
    _redeploy_stub(host, "ok")
    host.launcher("run", "--mode", "update", "--run", "32", "--phase", "execute")
    events = host.events(32)
    assert finished(events)["outcome"] == "failed"
    assert [e["verdict"] for e in events if e["event"] == "result"] == ["no_plan"]
    assert host.calls_of("bash") == []


def test_update_verify_tells_when_another_revision_was_deployed(host: Host) -> None:
    _git_stub(host)
    _redeploy_stub(host, "ok")  # reports "aaaaaaa -> bbbbbbb"
    _planned(host, 33, "d" * 40)
    (host.bin.parent / "tip").write_text("d" * 40 + "\n", encoding="utf-8")
    host.launcher("run", "--mode", "update", "--run", "33", "--phase", "execute")
    result = [e for e in host.events(33) if e["event"] == "result"][0]
    assert "deployed bbbbbbb, the plan was for ddddddd" in result["text"]


def test_dump_dates_errors_with_the_logs_own_offset(host: Host) -> None:
    """utils/logging.py writes local time WITH %z: an error two hours old, logged at
    +0300 on a Moscow host, is two hours old — not "0 min" from a misread offset."""
    import datetime as dt

    two_hours_ago = dt.datetime.now(dt.timezone(dt.timedelta(hours=3))) - dt.timedelta(hours=2)
    stamp = two_hours_ago.strftime("%Y-%m-%dT%H:%M:%S%z")
    host.file("/opt/vpn-service/logs/bot.log").write_text(f"{stamp} ERROR [x] boom\n", encoding="utf-8")
    host.launcher("run", "--mode", "dump", "--run", "34", "--phase", "execute")
    text = host.file("/var/lib/vpn-bot-wizard/34.dump.txt").read_text(encoding="utf-8")
    utc = two_hours_ago.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    assert f"last ERROR at {utc} UTC (" in text
    assert re.search(r"last ERROR at \S+ UTC \((1\.9|2\.0|2\.1) h ago\)", text), text


def test_launch_reenters_the_host_mount_namespace(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under the non-root bot's ProtectSystem=strict, sudo keeps the bot's mount namespace:
    /run, /var/lib and /var/log are read-only there. `launch` re-executes itself in PID 1's."""
    for key in ("VPN_BOT_WIZARD_SELFTEST", "VPN_BOT_WIZARD_HOSTNS"):
        monkeypatch.delenv(key, raising=False)
    loader = importlib.machinery.SourceFileLoader("vpn_bot_wizard_launcher_under_test", str(LAUNCHER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    launcher = importlib.util.module_from_spec(spec)
    loader.exec_module(launcher)
    namespaces = {"/proc/self/ns/mnt": "mnt:[1]", "/proc/1/ns/mnt": "mnt:[2]"}
    monkeypatch.setattr(launcher.os, "geteuid", lambda: 0)
    monkeypatch.setattr(launcher.os, "readlink", lambda path: namespaces[path])
    argv = ["launch", "--mode", "selfcheck", "--run", "1", "--phase", "execute"]
    reexec = launcher.host_mount_namespace_argv(argv)
    assert reexec[:3] == ["nsenter", "--mount=/proc/1/ns/mnt", "--"]
    assert reexec[-len(argv):] == argv and reexec[-len(argv) - 1] == str(LAUNCHER)
    assert launcher.host_mount_namespace_argv(["active"]) is None  # only launch writes
    monkeypatch.setenv("VPN_BOT_WIZARD_HOSTNS", "1")
    assert launcher.host_mount_namespace_argv(argv) is None  # already re-executed
    monkeypatch.delenv("VPN_BOT_WIZARD_HOSTNS")
    namespaces["/proc/1/ns/mnt"] = "mnt:[1]"
    assert launcher.host_mount_namespace_argv(argv) is None  # already in the host's


def test_update_plan_is_not_a_noop_when_the_checkout_is_ahead(host: Host) -> None:
    """A local hotfix commit: nothing incoming (HEAD..origin/main is empty), yet HEAD is
    not origin/main — the deploy would reset it. That is a plan, with a warning."""
    _git_stub(host, commits=0, head="e" * 40, ahead=1)
    _redeploy_stub(host, "ok")
    assert host.launcher("run", "--mode", "update", "--run", "35", "--phase", "plan").returncode == 0
    plan = [e for e in host.events(35) if e["event"] == "plan"][0]
    assert plan["noop"] is False
    assert "1 commit(s) that are NOT on origin/main" in plan["text"]
    assert host.calls_of("bash")  # the CHECK ran
