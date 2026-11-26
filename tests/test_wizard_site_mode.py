"""The wizard's «site» mode (scripts/wizard/vpn-bot-wizard-site) end to end on a fake host.

The launcher runs the mode helper through the contract (plan → apply → verify → rollback);
the mode helper calls the REAL scripts/vpn-bot-site (a wrapper in the stub directory), which
drives the stubs of tests/site_fakes.py on the same root.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from site_fakes import HELPER, ROOT, SITE_V1, SITE_V2, SiteHost, tar_gz_bytes, zip_bytes

pytestmark = [pytest.mark.timeout(240)]

MODE_HELPER = ROOT / "scripts" / "wizard" / "vpn-bot-wizard-site"


@pytest.fixture
def host(tmp_path: Path) -> SiteHost:
    return SiteHost(tmp_path)


def _restarts(host: SiteHost) -> list[str]:
    return [c for c in host.calls() if c.startswith("systemctl try-restart")]


def test_plan_then_execute_deploys_verifies_commits_and_restarts(host: SiteHost) -> None:
    digest = host.upload(zip_bytes(SITE_V2))
    assert host.wizard(1, "plan", action="deploy", digest=digest).returncode == 0
    assert host.outcome(1) == "planned"
    plan = next(e for e in host.events(1) if e["event"] == "plan")
    assert not plan.get("noop")
    text = plan["text"]
    assert "Files: +4 −3 ~2" in text and "− /about.html" in text and "+ /docs/api.html" in text
    assert "spiderX pool (XRAY_SPIDER_X_POOL, .env backed up first): 3 → 4 path(s)" in text
    assert "2 of 3 key(s)" in text and "one atomic exchange" in text
    assert "***" not in text, "no whole sha256 in the plan (it would be redacted)"
    assert host.tree() == SITE_V1, "the plan changes nothing"
    steps = [e for e in host.events(1) if e["event"] == "steps"]
    assert steps and set(steps[-1]["steps"].values()) == {"wait"}

    proc = host.wizard(1, "execute", action="deploy", digest=digest)
    assert proc.returncode == 0, proc.stderr
    assert host.outcome(1) == "succeeded"
    assert host.tree() == SITE_V2
    events = host.events(1)
    last_steps = [e for e in events if e["event"] == "steps"][-1]["steps"]
    assert last_steps == {"site_stage": "ok", "site_swap": "ok", "site_env": "ok"}
    items = {e["key"]: e for e in events if e["event"] == "item"}
    assert all(i["level"] == "green" for i in items.values())
    assert items["pages"]["text"] == "all 4 page(s) answer 200 over HTTP/2"
    assert _restarts(host) == ["systemctl try-restart vpn-bot-subscription.service",
                               "systemctl try-restart --no-block vpn-bot.service"]
    result = [e for e in events if e["event"] == "result"][-1]
    assert "the replaced version kept" in result["text"] and "XRAY_SPIDER_X_POOL: 4 path(s)" in result["text"]
    assert host.journal()["state"] == "committed"


def test_a_failed_verify_is_rolled_back_by_the_runner(host: SiteHost) -> None:
    env = host.env()
    digest = host.upload(zip_bytes(SITE_V2))
    assert host.wizard(2, "plan", action="deploy", digest=digest).returncode == 0
    (host.st / "fail_curl_path").write_text("/status.html")
    host.wizard(2, "execute", action="deploy", digest=digest)
    assert host.outcome(2) == "rolled_back"
    assert host.tree() == SITE_V1 and host.env() == env
    items = [e for e in host.events(2) if e["event"] == "item" and e["level"] == "red"]
    assert [i["key"] for i in items] == ["pages"] and "/status.html → 404" in items[0]["text"]
    assert _restarts(host) == [], "no restart for a rolled-back deploy"


def test_an_evil_archive_fails_the_plan_with_its_reason(host: SiteHost) -> None:
    digest = host.upload(zip_bytes({"index.html": b"x", "../../etc/cron.d/x.txt": b"x"}))
    host.wizard(3, "plan", action="deploy", digest=digest)
    assert host.outcome(3) == "failed"
    plan = next(e for e in host.events(3) if e["event"] == "plan")
    assert "plan failed" in plan["text"] and "`..`" in plan["text"]
    assert host.tree() == SITE_V1


def test_a_deploy_without_its_digest_is_refused(host: SiteHost) -> None:
    host.upload(zip_bytes(SITE_V2))
    host.wizard(4, "plan", action="deploy")
    assert host.outcome(4) == "failed"
    assert "digest" in next(e for e in host.events(4) if e["event"] == "plan")["text"]


def test_the_plan_rolls_back_an_apply_whose_unit_was_killed(host: SiteHost) -> None:
    digest = host.upload(zip_bytes(SITE_V2))
    _, plan, _ = host.helper("plan", "deploy", "--run", "5", "--digest", digest)
    assert host.helper("apply", "--run", "5", "--expect-plan", plan["sha256"])[0] == 0
    assert host.tree() == SITE_V2  # …and the unit died here: no verify, no rollback
    digest = host.upload(tar_gz_bytes({**SITE_V1, "new.html": b"x"}))
    assert host.wizard(6, "plan", action="deploy", digest=digest).returncode == 0
    text = next(e for e in host.events(6) if e["event"] == "plan")["text"]
    assert text.startswith("⚠ run #5 had left its change of the site unfinished: rolled back first")
    assert "Files: +1 −0 ~0" in text, "the plan is against the site as it was before run #5"
    assert host.tree() == SITE_V1


def test_a_revert_through_the_wizard(host: SiteHost) -> None:
    assert host.deploy(zip_bytes(SITE_V2), 7)[0] == 0
    assert host.wizard(8, "plan", action="revert").returncode == 0
    text = next(e for e in host.events(8) if e["event"] == "plan")["text"]
    assert text.startswith("back to the kept version") and "Pages: 4 → 3" in text
    assert host.wizard(8, "execute", action="revert").returncode == 0
    assert host.outcome(8) == "succeeded" and host.tree() == SITE_V1
    assert host.pool() == ["/", "/about.html", "/blog/"]


def test_the_same_pages_restart_nothing(host: SiteHost) -> None:
    digest = host.upload(zip_bytes({**SITE_V1, "css/style.css": b"body{}"}))
    assert host.wizard(9, "plan", action="deploy", digest=digest).returncode == 0
    assert "all on the new site — unchanged" in next(e for e in host.events(9) if e["event"] == "plan")["text"]
    assert host.wizard(9, "execute", action="deploy", digest=digest).returncode == 0
    assert host.outcome(9) == "succeeded" and _restarts(host) == []


def test_the_same_archive_is_a_noop_plan(host: SiteHost) -> None:
    digest = host.upload(zip_bytes(SITE_V1))
    assert host.wizard(10, "plan", action="deploy", digest=digest).returncode == 0
    plan = next(e for e in host.events(10) if e["event"] == "plan")
    assert plan["noop"] is True and "Nothing to do" in plan["text"]


def test_the_modes_steps_are_the_helpers() -> None:
    """vpn-bot-wizard-site's STEPS == vpn-bot-site's APPLY_STEPS (⚪ before apply, labelled)."""

    def steps_of(path: Path, name: str) -> tuple[str, ...]:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                value = ast.literal_eval(node.value)
                assert isinstance(value, tuple)
                return value
        raise AssertionError(name)

    assert steps_of(MODE_HELPER, "STEPS") == steps_of(HELPER, "APPLY_STEPS")
    from i18n import en, ru

    for step in steps_of(HELPER, "APPLY_STEPS"):
        assert f"install_step_{step}" in ru.STRINGS and f"install_step_{step}" in en.STRINGS


def test_no_dead_man_and_no_network_step() -> None:
    """The site mode touches no network configuration: no dead-man is armed (docs/site.md)."""
    text = MODE_HELPER.read_text(encoding="utf-8")
    assert "deadman_arm" not in text
    helper = HELPER.read_text(encoding="utf-8")
    assert not re.search(r"\"(ufw|iptables|ip|nft|nginx)\"\s*,", helper), "vpn-bot-site runs no network or nginx command"
