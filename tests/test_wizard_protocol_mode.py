"""The wizard's «protocol» mode (scripts/wizard/vpn-bot-wizard-protocol) end to end on a fake host.

The launcher runs the mode helper through the contract (plan → apply → verify →
rollback); the mode helper calls the REAL scripts/vpn-bot-protocol-install (a wrapper in
the stub directory), which drives the stubs of tests/install_fakes.py on the same root.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from install_fakes import DOMAIN, ROOT, InstallHost

pytestmark = [pytest.mark.timeout(240)]

LAUNCHER = ROOT / "scripts" / "wizard" / "vpn-bot-wizard"
WIZARD_STATE = ("/var/lib/vpn-bot-wizard", "/var/log/vpn-bot-wizard")


class WizardHost(InstallHost):
    def wizard(self, run_id: int, phase: str, **params: str) -> subprocess.CompletedProcess[str]:
        args = [sys.executable, "-I", str(LAUNCHER), "run", "--mode", "protocol", "--run", str(run_id), "--phase", phase]
        for key, value in {"proto": "xray", **params}.items():
            args += ["--param", f"{key}={value}"]
        env = self.base_env(VPN_BOT_WIZARD_SELFTEST="1", VPN_BOT_WIZARD_ROOT=str(self.root),
                            VPN_BOT_WIZARD_SELFTEST_BIN=str(self.bin))
        return subprocess.run(args, capture_output=True, text=True, env=env, timeout=220, check=False)

    def events(self, run_id: int) -> list[dict[str, Any]]:
        path = self.file(f"/var/lib/vpn-bot-wizard/{run_id}.status")
        return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()] if path.exists() else []

    def outcome(self, run_id: int) -> str:
        done = [e for e in self.events(run_id) if e["event"] == "finished"]
        assert done, self.events(run_id)
        return str(done[-1]["outcome"])


@pytest.fixture
def host(tmp_path: Path) -> WizardHost:
    return WizardHost(tmp_path)


def test_plan_then_execute_installs_verifies_and_restarts_the_bot(host: WizardHost) -> None:
    assert host.wizard(1, "plan").returncode == 0
    assert host.outcome(1) == "planned"
    plan = next(e for e in host.events(1) if e["event"] == "plan")
    assert not plan.get("noop")
    assert "+ package nginx" in plan["text"] and f"XRAY_SNI: (unset) → {DOMAIN}" in plan["text"]
    assert "privateKey" not in plan["text"]
    assert not host.file("/usr/local/bin/xray").exists(), "the plan changes nothing"
    steps = [e for e in host.events(1) if e["event"] == "steps"]
    assert steps and set(steps[-1]["steps"].values()) == {"wait"}

    proc = host.wizard(1, "execute")
    assert proc.returncode == 0, proc.stderr
    assert host.outcome(1) == "succeeded"
    events = host.events(1)
    last_steps = [e for e in events if e["event"] == "steps"][-1]["steps"]
    assert last_steps["xray_config"] == "ok" and last_steps["marker"] == "skip"
    items = [e for e in events if e["event"] == "item"]
    assert items and all(i["level"] == "green" for i in items)
    assert any(c.startswith("systemctl try-restart --no-block vpn-bot.service") for c in host.calls())
    journal = json.loads(host.file("/var/lib/vpn-bot-protocol-install/xray.journal.json").read_text())
    assert journal["state"] == "committed"


def test_a_failed_verify_is_rolled_back_by_the_runner(host: WizardHost) -> None:
    before = host.snapshot(skip=WIZARD_STATE)
    assert host.wizard(2, "plan").returncode == 0
    host.fail("openssl")
    host.wizard(2, "execute")
    assert host.outcome(2) == "rolled_back"
    after = host.snapshot(skip=(*WIZARD_STATE, "/etc/vpn-bot/tls"))
    assert after["files"] == {k: v for k, v in before["files"].items() if not k.startswith("/etc/vpn-bot/tls")}
    assert after["packages"] == before["packages"] and after["units"] == before["units"]
    assert not any("try-restart" in c for c in host.calls()), "no restart of the bot for a rolled-back install"


def test_a_plan_without_a_certificate_fails_with_the_reason(host: WizardHost) -> None:
    host.cert(adopted=False)
    host.wizard(3, "plan")
    assert host.outcome(3) == "failed"
    plan = next(e for e in host.events(3) if e["event"] == "plan")
    assert "no certificate" in plan["text"]


def test_an_installed_protocol_is_a_noop_plan(host: WizardHost) -> None:
    assert host.install()[0] == 0
    assert host.wizard(4, "plan").returncode == 0
    plan = next(e for e in host.events(4) if e["event"] == "plan")
    assert plan["noop"] is True


def test_the_host_changing_between_plan_and_apply_installs_nothing(host: WizardHost) -> None:
    assert host.wizard(5, "plan").returncode == 0
    host.file("/usr/local/bin/xray").write_text("someone else's xray")
    host.wizard(5, "execute")
    assert host.outcome(5) in ("failed", "rolled_back")
    result = [e for e in host.events(5) if e["event"] == "result"]
    assert any("changed since the plan" in r["text"] for r in result)
    assert not host.file("/usr/local/etc/xray/config.json").exists()
