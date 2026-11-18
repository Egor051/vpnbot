"""Why a deploy ended — ONE rule from deploy.sh's markers to the bot's message (A4).

scripts/deploy.sh prints machine-readable markers (docs/deployment.md «Step and result
markers»); scripts/vpn-relay-agent (`update`) and scripts/wizard/vpn-bot-wizard-update
(«Обновить бота») read them with ONE classifier, the DEPLOY VERDICT block they carry
verbatim; services/deploy_result.py validates what reaches the bot and bot/deploy_views.py
renders it. Pinned here:

1. **One block.** The DEPLOY VERDICT blocks of the two readers are byte-identical.
2. **One vocabulary.** The reasons and steps of deploy.sh, of the block and of the bot
   are the same lists, and the bot has a message for each, in both locales.
3. **The classifier**: deploy.sh's result line decides; without one (a target whose
   deploy.sh predates the markers) the text does; the excerpt carries the lines that
   tell the cause; a waiter's timeout is "timeout".
4. **deploy.sh's markers**: a step line per step, a result line on every way out —
   die, errexit, the rollbacks — with the reason of that way.
"""

from __future__ import annotations

import re
import subprocess
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType

import pytest

from bot.deploy_views import deploy_failure_text, deploy_warnings_text
from i18n import t
from services.deploy_result import (
    DEPLOY_REASONS,
    DEPLOY_STEPS,
    DeployWarning,
    deploy_failure_from,
    deploy_warnings_from,
)

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
AGENT = ROOT / "scripts" / "vpn-relay-agent"
WIZARD_UPDATE = ROOT / "scripts" / "wizard" / "vpn-bot-wizard-update"
BEGIN = "# DEPLOY VERDICT — one rule"
END = "# --- DEPLOY VERDICT (end) ---"

pytestmark = pytest.mark.timeout(60)


def _block(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    start = text.index(BEGIN)
    start = text.rindex("\n# ----", 0, start) + 1
    return text[start : text.index(END) + len(END)]


def _load(path: Path, name: str) -> ModuleType:
    loader = SourceFileLoader(name, str(path))
    spec = spec_from_loader(name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


agent = _load(AGENT, "vpn_relay_agent_verdict")


def _bash_array(name: str) -> tuple[str, ...]:
    m = re.search(rf"^{name}=\(([^)]*)\)$", DEPLOY_SH.read_text(encoding="utf-8"), re.MULTILINE)
    assert m, name
    return tuple(m.group(1).split())


# --------------------------------------------------------------------------- #
# 1-2. One block, one vocabulary
# --------------------------------------------------------------------------- #
def test_both_readers_carry_the_same_block() -> None:
    assert _block(AGENT) == _block(WIZARD_UPDATE)


def test_reasons_and_steps_are_one_list_everywhere() -> None:
    assert (*_bash_array("DEPLOY_FAIL_REASONS"), "timeout") == agent.DEPLOY_REASONS == DEPLOY_REASONS
    assert _bash_array("DEPLOY_STEPS") == DEPLOY_STEPS


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_the_bot_has_a_message_for_every_reason_and_step(locale: str) -> None:
    from i18n import _CATALOGS

    catalog = _CATALOGS[locale]
    keys = [f"deploy_reason_{r}" for r in DEPLOY_REASONS] + [f"deploy_step_{s}" for s in DEPLOY_STEPS]
    missing = [k for k in [*keys, "deploy_warn_upstream_preexisting"] if k not in catalog]
    assert missing == []


# --------------------------------------------------------------------------- #
# 3. The classifier
# --------------------------------------------------------------------------- #
LOG_LINE = "redeploy: launching vpn-bot-deploy (log: /root/deploy-20261118T120000Z.log)"


def test_the_result_line_decides() -> None:
    out = "\n".join([
        LOG_LINE, "[deploy:step 1/8 preflight]", "[deploy:step 2/8 fetch]", "[deploy:step 3/8 tests]",
        "FAILED tests/test_a.py::test_b - AssertionError", "=== 1 failed, 10 passed in 3.21s ===",
        "[deploy][FAIL] Phase 1 gate: pytest failed on origin/main (above) — nothing was changed",
        "[deploy:result failed step=tests reason=tests]",
    ])
    v = agent.deploy_verdict(out, 1)
    assert (v["reason"], v["step"], v["log"]) == ("tests", "tests", "/root/deploy-20261118T120000Z.log")
    assert v["excerpt"] == [
        "FAILED tests/test_a.py::test_b - AssertionError", "=== 1 failed, 10 passed in 3.21s ===",
        "[deploy][FAIL] Phase 1 gate: pytest failed on origin/main (above) — nothing was changed",
    ]


@pytest.mark.parametrize(
    ("tail", "rc", "reason"),
    [
        ("[deploy:result ok]", 0, ""),
        ("[deploy:result noop]", 0, ""),
        ("[deploy:result failed step=checks reason=bogus]", 1, "failed"),
        ("[deploy:result failed step=fetch reason=fetch]", 1, "fetch"),
        ("[deploy:result failed step=verify reason=upstream]", 1, "upstream"),
        ("[deploy:result failed step=tests reason=tests]", 124, "timeout"),
    ],
)
def test_result_lines(tail: str, rc: int, reason: str) -> None:
    assert agent.deploy_verdict(f"{LOG_LINE}\n{tail}\n", rc)["reason"] == reason


@pytest.mark.parametrize(
    ("lines", "rc", "reason"),
    [
        (["[deploy][FAIL] another deploy already holds /run/vpn-bot-deploy.lock"], 1, "busy"),
        (["The virtual environment was not created successfully because ensurepip is not",
          "    apt install python3.12-venv"], 1, "no_venv"),
        (["[deploy][WARN] vpn-relay-apply check failed after the restart (exit 13: the upstream does not answer)",
          "[deploy][WARN] ROLLBACK (relay): restoring PREV_SHA=abc", "===== ROLLBACK REPORT (relay) ====="], 1, "upstream"),
        (["[deploy][WARN] vpn-relay-apply check failed after the restart (exit 11: differs)",
          "[deploy][WARN] ROLLBACK (relay): restoring PREV_SHA=abc", "===== ROLLBACK REPORT (relay) ====="], 1, "rolled_back"),
        (["FAILED tests/test_a.py::test_b - boom", "==== 1 failed, 2 passed in 1.00s ===="], 1, "tests"),
        (["[deploy][FAIL] relay: git fetch failed (above) — nothing was changed"], 1, "fetch"),
        (["[deploy][FAIL] unit drift detected (set ALLOW_UNIT_DRIFT=1 ...)"], 1, "checks"),
        (["something else entirely"], 2, "failed"),
        (["anything"], 124, "timeout"),
        (["[deploy] DEPLOY OK"], 0, ""),
    ],
)
def test_without_markers_the_text_decides(lines: list[str], rc: int, reason: str) -> None:
    assert agent.deploy_verdict("\n".join(lines), rc)["reason"] == reason


def test_the_excerpt_names_the_rollbacks_reason_and_stays_short() -> None:
    out = "\n".join([
        *[f"[deploy] line {i}" for i in range(50)],
        *[f"vpn-relay-apply: FAIL: TCP connect 203.0.113.{i}:443 failed: timed out" for i in range(20)],
        "[deploy][WARN] vpn-relay-apply check failed after the restart (exit 13: x)",
        "[deploy][WARN] ROLLBACK (relay): restoring PREV_SHA=abc",
        "x" * 1000,
        "[deploy:result failed step=verify reason=upstream]",
    ])
    v = agent.deploy_verdict(out, 1)
    assert len(v["excerpt"]) == agent.DV_EXCERPT_LINES
    assert v["excerpt"][-1] == "[deploy][WARN] vpn-relay-apply check failed after the restart (exit 13: x)"
    assert all(len(line) <= agent.DV_EXCERPT_CHARS for line in v["excerpt"])


def test_warnings_of_a_successful_deploy() -> None:
    v = agent.deploy_verdict("[deploy:warn upstream_preexisting] upstream unreachable: TCP connect 1.2.3.4:443\n[deploy:result ok]\n", 0)
    assert v["reason"] == "" and v["warnings"] == [
        {"code": "upstream_preexisting", "text": "upstream unreachable: TCP connect 1.2.3.4:443"}
    ]


# --------------------------------------------------------------------------- #
# The bot's side: validation and rendering
# --------------------------------------------------------------------------- #
def test_the_bot_validates_what_arrives() -> None:
    f = deploy_failure_from({
        "reason": "tests", "step": "tests", "excerpt": ["<b>x</b>", 5, None, ""], "log": "/root/deploy-x.log",
    })
    assert (f.reason, f.step, f.excerpt, f.log) == ("tests", "tests", ("<b>x</b>", "5"), "/root/deploy-x.log")
    junk = deploy_failure_from({"reason": "rm -rf", "step": "nope", "excerpt": "str", "log": "rel/path"}, message="m")
    assert (junk.reason, junk.step, junk.excerpt, junk.log, junk.message) == ("failed", "", (), "", "m")
    assert deploy_failure_from(None, default="rolled_back").reason == "rolled_back"
    # The wizard's field names.
    assert deploy_failure_from({"reason": "checks", "fail_step": "checks", "deploy_log": "/root/d.log"}).log == "/root/d.log"
    assert deploy_warnings_from([{"code": "upstream_preexisting", "text": "t"}, {"code": "BAD CODE"}, "x"]) == (
        DeployWarning("upstream_preexisting", "t"),
    )


def test_the_failure_block_escapes_and_names_cause_step_lines_and_log() -> None:
    text = deploy_failure_text(deploy_failure_from({
        "reason": "upstream", "step": "verify", "excerpt": ["FAIL: <TCP> & co"], "log": "/root/deploy-1.log",
    }))
    assert t("deploy_reason_upstream") in text and t("deploy_step_verify") in text
    assert "FAIL: &lt;TCP&gt; &amp; co" in text and "<pre>" in text and "/root/deploy-1.log" in text
    assert "⚠️" in deploy_warnings_text((DeployWarning("upstream_preexisting", "a<b"),))
    assert "a&lt;b" in deploy_warnings_text((DeployWarning("unknown_code", "a<b"),))


# --------------------------------------------------------------------------- #
# 4. deploy.sh's markers
# --------------------------------------------------------------------------- #
def _deploy(tmp_path: Path, body: str, **env: str) -> subprocess.CompletedProcess[str]:
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -euo pipefail\nexport DEPLOY_SELFTEST=1\n"
        + "".join(f"export {k}={v}\n" for k, v in env.items())
        + f'source "{DEPLOY_SH}"\nVENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n' + body,
        encoding="utf-8",
    )
    return subprocess.run(["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True, check=False)


def test_step_lines_number_the_steps(tmp_path: Path) -> None:
    proc = _deploy(tmp_path, "step preflight\nstep tests\nstep verify\n")
    assert proc.stdout.splitlines() == ["[deploy:step 1/8 preflight]", "[deploy:step 3/8 tests]", "[deploy:step 8/8 verify]"]
    proc = _deploy(tmp_path, "step fetch\nstep checks\n", PHASE1_ONLY="1")
    assert proc.stdout.splitlines() == ["[deploy:step 2/4 fetch]", "[deploy:step 4/4 checks]"]


@pytest.mark.parametrize(
    ("body", "line"),
    [
        ("step fetch\ndie boom\n", "[deploy:result failed step=fetch reason=preflight]"),
        ("step tests\ndie boom\n", "[deploy:result failed step=tests reason=tests]"),
        ("step checks\ndie boom\n", "[deploy:result failed step=checks reason=checks]"),
        ("step fetch\nDEPLOY_FAIL_REASON=fetch\ndie boom\n", "[deploy:result failed step=fetch reason=fetch]"),
        ("step install\nPHASE=armed\ndie boom\n", "[deploy:result failed step=install reason=rolled_back]"),
        ("step restart\ndie boom\n", "[deploy:result failed step=restart reason=failed]"),
        # errexit without a die: the EXIT trap still says why.
        ("step tests\nfalse\n", "[deploy:result failed step=tests reason=tests]"),
    ],
)
def test_every_way_out_prints_one_result_line(tmp_path: Path, body: str, line: str) -> None:
    proc = _deploy(tmp_path, body)
    assert proc.returncode != 0
    results = [ln for ln in proc.stderr.splitlines() if ln.startswith("[deploy:result")]
    assert results == [line], proc.stderr


def test_a_green_run_prints_no_failure(tmp_path: Path) -> None:
    proc = _deploy(tmp_path, "step verify\ndeploy_result_ok\n")
    assert proc.returncode == 0
    assert "[deploy:result ok]" in proc.stdout and "failed" not in proc.stdout + proc.stderr


def test_every_reason_deploy_sh_sets_is_in_its_list() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    reasons = set(_bash_array("DEPLOY_FAIL_REASONS"))
    set_ones = set(re.findall(r"DEPLOY_FAIL_REASON=([a-z_]+)", text))
    assert set_ones and set_ones <= reasons, set_ones - reasons


# --------------------------------------------------------------------------- #
# 5. The progress of a running deploy (D) — the same block
# --------------------------------------------------------------------------- #
def test_progress_of_a_running_deploy() -> None:
    out = "\n".join([
        "[deploy:step 1/8 preflight]", "[deploy:step 2/8 fetch]",
        # A relay's handover: the target's own copy starts over.
        "[deploy:step 1/8 preflight]", "[deploy:step 2/8 fetch]", "[deploy:step 3/8 tests]",
        "[deploy:tests total=200]", "." * 72 + " [ 36%]", "." * 28,
    ])
    p = agent.deploy_progress(out)
    assert p["step"] == "tests"
    assert p["steps"] == {"preflight": "ok", "fetch": "ok", "tests": "run", "checks": "wait", "backup": "wait",
                          "install": "wait", "restart": "wait", "verify": "wait"}
    assert p["tests"] == {"done": 100, "total": 200}


def test_progress_skip_fail_and_done() -> None:
    skipped = agent.deploy_progress("[deploy:step 3/8 tests]\n[deploy:skip tests] stamp\n[deploy:step 4/8 checks]\n")
    assert skipped["steps"]["tests"] == "skip" and skipped["steps"]["checks"] == "run"
    failed = agent.deploy_progress("[deploy:step 7/8 restart]\n[deploy:result failed step=restart reason=rolled_back]\n")
    assert failed["steps"]["restart"] == "fail" and failed["steps"]["install"] == "ok"
    done = agent.deploy_progress("[deploy:step 8/8 verify]\n[deploy:result ok]\n")
    assert set(done["steps"].values()) == {"ok"}
    assert agent.deploy_progress("nothing yet") == {"step": "", "steps": dict.fromkeys(DEPLOY_STEPS, "wait"), "tests": {}}
