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


def test_selfcheck_checks_the_warp_table_when_warp_is_deployed(host: Host) -> None:
    host.file("/etc/amnezia").mkdir(parents=True)
    host.file("/etc/amnezia/out-warp.conf").write_text("[Interface]\n", encoding="utf-8")
    host.stub("awg", 'echo 0xca6c\n')
    host.stub("ip", r'''
case "$*" in
  "rule show") echo "1000: from 10.8.0.0/24 lookup 51820" ;;
  "route show table 51820") echo "default dev out-warp scope link" ;;
esac
''')
    assert host.launcher("run", "--mode", "selfcheck", "--run", "7", "--phase", "execute").returncode == 0
    warp = [e for e in host.events(7) if e["event"] == "item" and e["key"] == "warp"][0]
    assert warp["level"] == "green" and "51820" in warp["text"]
    host.stub("ip", 'case "$*" in "rule show") echo "0: from all lookup local" ;; esac\n')
    assert host.launcher("run", "--mode", "selfcheck", "--run", "70", "--phase", "execute").returncode == 0
    warp = [e for e in host.events(70) if e["event"] == "item" and e["key"] == "warp"][0]
    assert warp["level"] == "red"


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
    assert "last ERROR at 2026/11/13 09:00:00 UTC" in text
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
def _git_stub(host: Host, *, commits: int = 2) -> None:
    host.stub("git", rf'''
case "$*" in
  *"fetch origin main"*) : ;;
  *"rev-parse --short HEAD"*) echo aaaaaaa ;;
  *"rev-parse --short origin/main"*) echo bbbbbbb ;;
  *"rev-list --count"*) echo {commits} ;;
  *"log --oneline"*) [ {commits} -gt 0 ] && printf 'bbbbbbb feat: two\ncccccc1 fix: one\n' ;;
  *"show HEAD:db/database.py"*) echo "CURRENT_SCHEMA_VERSION = 41" ;;
  *"show origin/main:db/database.py"*) echo "CURRENT_SCHEMA_VERSION = 42" ;;
esac
''')


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
    _git_stub(host, commits=0)
    _redeploy_stub(host, "ok")
    assert host.launcher("run", "--mode", "update", "--run", "21", "--phase", "plan").returncode == 0
    plan = [e for e in host.events(21) if e["event"] == "plan"][0]
    assert plan["noop"] is True
    assert host.calls_of("bash") == []  # the CHECK is skipped


def test_update_deploy_ok_succeeds(host: Host) -> None:
    _redeploy_stub(host, "ok")
    assert host.launcher("run", "--mode", "update", "--run", "22", "--phase", "execute").returncode == 0
    events = host.events(22)
    assert finished(events)["outcome"] == "succeeded"
    result = [e for e in events if e["event"] == "result"][0]
    assert result["verdict"] == "deploy_ok" and "41 -> 42" in result["text"]
    assert [c for c in host.calls.read_text().splitlines() if c.startswith("env:")] == ["env: CHECK= FORCE= ATTACH=pipe"]


def test_update_force_is_forwarded(host: Host) -> None:
    _redeploy_stub(host, "ok")
    host.launcher("run", "--mode", "update", "--run", "23", "--phase", "execute", "--param", "force=1")
    assert [c for c in host.calls.read_text().splitlines() if c.startswith("env:")] == ["env: CHECK= FORCE=1 ATTACH=pipe"]


def test_update_rollback_report_is_rolled_back(host: Host) -> None:
    _redeploy_stub(host, "rollback")
    assert host.launcher("run", "--mode", "update", "--run", "24", "--phase", "execute").returncode == 1
    events = host.events(24)
    assert finished(events)["outcome"] == "rolled_back"
    steps = [(e["step"], e["state"]) for e in events if e["event"] == "step"]
    assert ("apply", "fail") in steps and ("rollback", "ok") in steps and ("verify", "start") not in steps
    result = [e for e in events if e["event"] == "result"][0]
    assert result["verdict"] == "rolled_back" and "ROLLBACK REPORT" in result["text"]


def test_update_rollback_with_the_bot_down_is_failed(host: Host) -> None:
    _redeploy_stub(host, "rollback")
    (host.bin.parent / "bot-state").write_text("failed\n", encoding="utf-8")
    host.launcher("run", "--mode", "update", "--run", "25", "--phase", "execute")
    assert finished(host.events(25))["outcome"] == "failed"


def test_update_without_a_report_is_failed_not_rolled_back(host: Host) -> None:
    _redeploy_stub(host, "die")
    host.launcher("run", "--mode", "update", "--run", "26", "--phase", "execute")
    events = host.events(26)
    assert finished(events)["outcome"] == "failed"
    assert [e for e in events if e["event"] == "result"][0]["verdict"] == "no_report"


def test_update_verify_needs_the_bot_running(host: Host) -> None:
    _redeploy_stub(host, "ok")
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
