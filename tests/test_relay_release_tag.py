"""Which revision a relay deploys — ONE engine, ONE release rule (docs/relay.md).

A relay is updated by scripts/deploy.sh in the relay role, whether an operator runs
``redeploy.sh`` or the bot sends the agent's ``update``. Pinned here:

* **One release rule.** deploy.sh's ``relay_latest_release`` and the agent's
  ``latest_release`` pick the same tag from the same listing — fixed edge cases
  (``v.3.1.0``, pre-releases, leading zeros, ties, huge numbers, non-ASCII digits) and a
  seeded fuzz — and both read the listing with the same ``git tag`` command.
* **The target** (``relay_resolve_target``, real git): default = the newest release;
  ``DEPLOY_REF=main`` = origin/main; a tag; a commit sha; anything else refused.
* **Forward only** (``relay_fetch_target``): at the target → nothing to deploy (FORCE
  redeploys, PHASE1_ONLY inspects); ahead → INFO no-op "ahead of latest release; DEPLOY_REF=main to
  follow main"; sideways → refused before any mutation; no WARN about a detached tree.
* **Detached** Phase 2 checkout and rollback (``pin_tree_detached`` /
  ``restore_tree_detached``).
* **The handover**: the target's own deploy.sh runs the deploy; a target whose deploy.sh
  predates release-based relay deploys is refused.
* **redeploy.sh** forwards DEPLOY_REF; the main server refuses any DEPLOY_REF but main.
* **install.json**'s ref is the install's: nothing but install.sh writes it.

Driven through the ``DEPLOY_SELFTEST=1`` seam against REAL git repositories under
tmp_path; the git environment is hermetic (own HOME, no system config).
"""

from __future__ import annotations

import os
import random
import re
import subprocess
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
AGENT = ROOT / "scripts" / "vpn-relay-agent"
REDEPLOY_SH = ROOT / "scripts" / "redeploy.sh"
INSTALL_SH = ROOT / "scripts" / "install.sh"

pytestmark = pytest.mark.timeout(120)


def _load_agent() -> ModuleType:
    loader = SourceFileLoader("vpn_relay_agent_release", str(AGENT))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


agent = _load_agent()


def _deploy_pick(listings: list[list[str]], tmp: Path) -> list[str | None]:
    """relay_latest_release of deploy.sh on each listing, in ONE bash process."""
    sets = tmp / "sets"
    sets.mkdir(exist_ok=True)
    for i, tags in enumerate(listings):
        (sets / f"{i:05d}").write_bytes(("".join(f"{t}\n" for t in tags)).encode("utf-8"))
    driver = (
        "export DEPLOY_SELFTEST=1\n"
        f'source "{DEPLOY_SH}"\n'
        f'for f in "{sets}"/*; do relay_latest_release < "$f"; echo "--END--"; done\n'
    )
    proc = subprocess.run(["bash", "-c", driver], capture_output=True, text=True, check=True,
                          env={**os.environ, "LC_ALL": "C.UTF-8"})
    out: list[str | None] = []
    for chunk in proc.stdout.split("--END--\n")[:-1]:
        lines = chunk.splitlines()
        assert len(lines) <= 1, chunk
        out.append(lines[0] if lines else None)
    assert len(out) == len(listings)
    return out


def _agent_pick(tags: list[str]) -> str | None:
    return agent.latest_release("".join(f"{t}\n" for t in tags))


# --------------------------------------------------------------------------- #
# 1. One release rule
# --------------------------------------------------------------------------- #
FIXED: list[tuple[list[str], str | None]] = [
    # The real repository: v.3.1.0 is a typo tag on the commit of v3.1.0.
    (["v.3.1.0", "v1.0.0", "v1.0.1", "v1.0.2", "v1.1.0", "v1.2.0", "v1.3.0", "v2.0.0", "v2.1.0",
      "v3.0.0", "v3.1.0"], "v3.1.0"),
    (["v.3.1.0"], None),
    ([], None),
    (["v3.2.0-rc1", "v3.1.0", "v3.2.0rc2", "v3.2.0.beta"], "v3.1.0"),
    (["v3", "v10", "v2.0"], "v2.0"),
    (["v1.9.0", "v1.10.0"], "v1.10.0"),
    (["v9.0", "v10.0"], "v10.0"),
    (["v1.2", "v1.2.0"], "v1.2.0"),
    (["v1.2.0", "v1.2"], "v1.2.0"),
    (["v1.02.0", "v1.2.0"], "v1.02.0"),            # equal keys: the first (max) wins
    (["v1.2.0", "v1.02.0"], "v1.2.0"),
    (["v08.09", "v8.9"], "v08.09"),                  # leading zeros, no octal
    (["v0.0", "v00.00.00"], "v00.00.00"),
    (["v1.2.3.4", "v1.2.3.4.5", "v1.2.3"], "v1.2.3.4"),
    (["v99999999999999999999.0", "v9223372036854775807.1"], "v99999999999999999999.0"),
    (["v1.٣.0", "v1.2.0"], "v1.2.0"),          # an Arabic-Indic digit is not [0-9]
    (["v1.2.0 v9.9.9", "v1.1.0"], "v1.1.0"),   # one name, never split on Unicode space
    (["v1.2.0\x85v9.9.9", "v1.1.0"], "v1.1.0"),
    (["V1.2.0", "v1.1.0", " v9.0.0", "v9.0.0 "], "v1.1.0"),
    (["v1..2", "v1.2.", "v.1", "v1.1.0"], "v1.1.0"),
]


def test_the_fixed_cases_pick_the_same_release(tmp_path: Path) -> None:
    deploy = _deploy_pick([tags for tags, _ in FIXED], tmp_path)
    for (tags, expected), got in zip(FIXED, deploy, strict=True):
        assert _agent_pick(tags) == expected, tags
        assert got == expected, (tags, got)


def _fuzz_tag(rng: random.Random) -> str:
    if rng.random() < 0.1:
        return rng.choice(["v.3.1.0", "v3.1.0-rc1", "vv1.0", "v1", "release-1.0", "v1.0.0.0.0", "v1.0.٣"])
    parts = [
        rng.choice(["0", "00", "1", "01", "2", "9", "10", "11", "007", str(rng.randint(0, 40))])
        for _ in range(rng.choice([1, 2, 2, 3, 3, 4, 5]))
    ]
    return "v" + ".".join(parts) + rng.choice(["", "", "", "", "-rc1", "a"])


def test_a_seeded_fuzz_picks_the_same_release(tmp_path: Path) -> None:
    rng = random.Random(20261116)  # noqa: S311 — a reproducible fuzz, not a secret
    listings = [sorted(_fuzz_tag(rng) for _ in range(rng.randint(0, 12))) for _ in range(400)]
    for tags, got in zip(listings, _deploy_pick(listings, tmp_path), strict=True):
        assert got == _agent_pick(tags), tags


def test_both_read_the_same_tag_listing() -> None:
    deploy = DEPLOY_SH.read_text(encoding="utf-8")
    assert "git tag -l --sort=refname 'v*' | relay_latest_release" in deploy
    assert agent.TAG_LIST == ("tag", "-l", "--sort=refname", "v*")
    text = AGENT.read_text(encoding="utf-8")
    assert "latest_release(run([*git, *TAG_LIST]" in text
    # The same pattern on both sides.
    assert agent.RELEASE_TAG_RE.pattern == r"v[0-9]+(?:\.[0-9]+){1,3}"
    assert r'[[ "$t" =~ ^v[0-9]+(\.[0-9]+){1,3}$ ]]' in deploy


# --------------------------------------------------------------------------- #
# 2-4. The target, forward only, detached — real git
# --------------------------------------------------------------------------- #
def _env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "DEPLOY_", "FORCE", "PHASE1_ONLY"))}
    env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    return env


class Relay:
    """origin: main = A(v1.0.0, v.1.0.0) - B(v1.1.0, v1.2.0-rc1) - C; side = A - S.
    The live relay clone sits on local main at A, as a relay deployed by hand did."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.home = tmp / "home"
        self.home.mkdir()
        self.env = _env(self.home)
        self.origin = tmp / "origin.git"
        self.seed = tmp / "seed"
        self.live = tmp / "live"
        self.git(tmp, "-c", "init.defaultBranch=main", "init", "-q", "--bare", str(self.origin))
        self.git(tmp, "-c", "init.defaultBranch=main", "init", "-q", str(self.seed))
        self.git(self.seed, "config", "commit.gpgsign", "false")
        self.a = self.commit("A", "v1.0.0", "v.1.0.0")
        self.git(self.seed, "push", "-q", str(self.origin), "main", "--tags")
        self.git(tmp, "clone", "-q", str(self.origin), str(self.live))
        self.b = self.commit("B", "v1.1.0", "v1.2.0-rc1")
        self.c = self.commit("C")
        self.git(self.seed, "push", "-q", str(self.origin), "main", "--tags")

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=str(cwd), env=self.env, capture_output=True, text=True,
                              check=True).stdout.strip()

    def commit(self, content: str, *tags: str) -> str:
        (self.seed / "app.txt").write_text(content + "\n", encoding="utf-8")
        scripts = self.seed / "scripts"
        scripts.mkdir(exist_ok=True)
        # The target's deploy.sh: by default one that knows release-based relay deploys.
        (scripts / "deploy.sh").write_text(self.target_deploy_sh(content), encoding="utf-8")
        self.git(self.seed, "add", "-A")
        self.git(self.seed, "commit", "-q", "-m", content)
        for tag in tags:
            self.git(self.seed, "tag", tag)
        return self.git(self.seed, "rev-parse", "HEAD")

    @staticmethod
    def target_deploy_sh(name: str, *, protocol: bool = True) -> str:
        return (
            "#!/usr/bin/env bash\n"
            + ("RELAY_REF_PROTOCOL=1\n" if protocol else "")
            + f'echo "HANDED-OVER-TO {name} sha=$DEPLOY_HANDOVER_SHA ref=${{DEPLOY_REF:-}} force=${{FORCE:-}}"\n'
        )

    def side(self, tag: str) -> str:
        self.git(self.seed, "checkout", "-q", "-b", "side", self.a)
        sha = self.commit("S", tag)
        self.git(self.seed, "push", "-q", str(self.origin), "side", "--tags")
        self.git(self.seed, "checkout", "-q", "main")
        return sha

    def head(self) -> str:
        return self.git(self.live, "rev-parse", "HEAD")

    def branch(self) -> str:
        return subprocess.run(["git", "symbolic-ref", "-q", "--short", "HEAD"], cwd=str(self.live), env=self.env,
                              capture_output=True, text=True).stdout.strip()

    def run(self, body: str, **knobs: str) -> subprocess.CompletedProcess[str]:
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -euo pipefail\n"
            "export DEPLOY_SELFTEST=1\n"
            + "".join(f"export {k}={v!r}\n" for k, v in knobs.items())
            + f'source "{DEPLOY_SH}"\n'
            'WT=""; STAGE=""; VENV=/nonexistent; VENV_PREV=/nonexistent; NODE_ROLE=relay\n'
            f'HANDOVER_DIR="{self.tmp}/handover"\n'
            f"{body}\n",
            encoding="utf-8",
        )
        return subprocess.run(["bash", str(driver)], cwd=str(self.live), env=self.env, capture_output=True,
                              text=True)


@pytest.fixture
def relay(tmp_path: Path) -> Relay:
    return Relay(tmp_path)


RESOLVE = 'relay_fetch_target\necho "TARGET=$RELAY_TARGET_SHA KIND=$RELAY_TARGET_KIND NAME=$RELAY_TARGET_NAME TAG=$TAG"\necho "LABEL=$DEPLOY_TARGET_LABEL WT_TARGET=$DEPLOY_TARGET"\n'


def test_default_target_is_the_newest_release(relay: Relay) -> None:
    proc = relay.run(RESOLVE)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"TARGET={relay.b} KIND=release NAME=v1.1.0" in proc.stdout, "v.1.0.0 and v1.2.0-rc1 are not releases"
    assert f"LABEL=latest release v1.1.0 WT_TARGET={relay.b}" in proc.stdout, "Phase 1 tests the target"
    assert "[WARN]" not in proc.stderr, "a relay is not WARNed about its branch or a detached tree"
    assert relay.head() == relay.a and relay.branch() == "main", "Phase 1 moves nothing"


def test_deploy_ref_main_follows_origin_main(relay: Relay) -> None:
    proc = relay.run(RESOLVE, DEPLOY_REF="main")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"TARGET={relay.c} KIND=main NAME=origin/main" in proc.stdout
    assert "LABEL=origin/main" in proc.stdout


def test_deploy_ref_names_a_tag_or_a_commit(relay: Relay) -> None:
    proc = relay.run(RESOLVE, DEPLOY_REF="v1.1.0")
    assert f"TARGET={relay.b} KIND=tag NAME=v1.1.0" in proc.stdout, proc.stderr
    proc = relay.run(RESOLVE, DEPLOY_REF=relay.c[:12])
    assert f"TARGET={relay.c} KIND=commit NAME={relay.c[:12]}" in proc.stdout, proc.stderr
    proc = relay.run(RESOLVE, DEPLOY_REF="v1.2.0-rc1")
    assert "KIND=tag NAME=v1.2.0-rc1" in proc.stdout, "an explicit tag is the operator's choice"


@pytest.mark.parametrize("ref", ["v9.9.9", "deadbeefdeadbeef", "origin/main", "-x", "a..b", "main;id", "HEAD~1"])
def test_a_ref_that_is_no_tag_main_or_commit_is_refused(relay: Relay, ref: str) -> None:
    proc = relay.run(RESOLVE, DEPLOY_REF=ref)
    assert proc.returncode == 1 and "TARGET=" not in proc.stdout
    assert "nothing was changed" in proc.stderr
    assert relay.head() == relay.a


def test_no_release_at_all_is_refused_with_the_way_out(relay: Relay) -> None:
    """Only v.1.0.0 and v1.2.0-rc1 are left: neither is a release."""
    for tag in ("v1.0.0", "v1.1.0"):
        relay.git(relay.seed, "push", "-q", str(relay.origin), f":refs/tags/{tag}")
    relay.git(relay.live, "tag", "-d", "v1.0.0")
    proc = relay.run(RESOLVE)
    assert proc.returncode == 1
    assert "no release tag (vX.Y[.Z[.W]]) in the repository — DEPLOY_REF=main to follow main" in proc.stderr


def test_at_the_target_there_is_nothing_to_deploy(relay: Relay) -> None:
    relay.git(relay.live, "fetch", "-q", "--tags", "origin")
    relay.git(relay.live, "checkout", "-q", "--detach", "v1.1.0")
    proc = relay.run(RESOLVE + "echo NOT-REACHED\n")
    assert proc.returncode == 0, proc.stderr
    assert "NOT-REACHED" not in proc.stdout
    assert "HEAD already at latest release v1.1.0" in proc.stdout and "nothing to deploy" in proc.stdout
    forced = relay.run(RESOLVE + "echo GOES-ON\n", FORCE="1")
    assert "GOES-ON" in forced.stdout and "FORCE=1: redeploying" in forced.stderr
    inspect = relay.run(RESOLVE + "echo GOES-ON\n", PHASE1_ONLY="1")
    assert "GOES-ON" in inspect.stdout


def test_ahead_of_the_release_is_an_info_noop_never_a_move_back(relay: Relay) -> None:
    """ru1 on 2026-11-16: deployed from main (1a87f67) while the newest release (v3.1.0)
    is older — the deploy must not take it back."""
    relay.git(relay.live, "pull", "-q", "--ff-only", "origin", "main")
    assert relay.head() == relay.c
    for knobs in ({}, {"FORCE": "1"}, {"PHASE1_ONLY": "1"}):
        proc = relay.run(RESOLVE + "echo NOT-REACHED\n", **knobs)
        assert proc.returncode == 0, proc.stderr
        assert "NOT-REACHED" not in proc.stdout, knobs
        assert (f"INFO: the checkout ({relay.c[:12]}) is ahead of latest release v1.1.0 "
                f"({relay.b[:7]}) — a relay never goes backwards: nothing to deploy; "
                "DEPLOY_REF=main to follow main") in proc.stdout
        assert relay.head() == relay.c and relay.branch() == "main"
    explicit = relay.run(RESOLVE, DEPLOY_REF="v1.0.0")
    assert "is ahead of tag v1.0.0" in explicit.stdout and "DEPLOY_REF=main to follow main" in explicit.stdout
    assert relay.head() == relay.c


def test_sideways_is_refused_before_any_mutation(relay: Relay) -> None:
    relay.side("v2.0.0")
    relay.git(relay.live, "pull", "-q", "--ff-only", "origin", "main")
    for knobs in ({}, {"PHASE1_ONLY": "1"}, {"FORCE": "1"}):
        proc = relay.run(RESOLVE + "echo NOT-REACHED\n", **knobs)
        assert proc.returncode == 1 and "NOT-REACHED" not in proc.stdout
        assert "are on different lines of history — a relay never moves sideways; nothing was changed" in proc.stderr
        assert relay.head() == relay.c


def test_a_dirty_tree_is_refused(relay: Relay) -> None:
    (relay.live / "app.txt").write_text("hand edit\n", encoding="utf-8")
    proc = relay.run(RESOLVE)
    assert proc.returncode == 1 and "working tree is not clean" in proc.stderr
    assert (relay.live / "app.txt").read_text(encoding="utf-8") == "hand edit\n"


def test_phase2_goes_to_the_target_detached_and_the_rollback_comes_back_detached(relay: Relay) -> None:
    proc = relay.run(
        RESOLVE
        + 'PREV_SHA="$(git rev-parse HEAD)"\n'
        'pin_tree_detached "$RELAY_TARGET_SHA"\n'
        'echo "AFTER-PIN=$(git rev-parse HEAD) BRANCH=$(current_branch)"\n'
        'restore_tree_detached "$PREV_SHA"; echo\n'
        'echo "AFTER-ROLLBACK=$(git rev-parse HEAD) BRANCH=$(current_branch)"\n'
        "relay_ref_report_line; echo\n"
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"AFTER-PIN={relay.b} BRANCH=\n" in proc.stdout, "detached at the release"
    assert f"git checkout -f --detach {relay.a}: rc=0 (code restored, HEAD detached)" in proc.stdout
    assert f"AFTER-ROLLBACK={relay.a} BRANCH=\n" in proc.stdout, "PREV_SHA back, detached"
    assert relay.git(relay.live, "rev-parse", "main") == relay.a, "the old local main stays where it was"
    assert (f"tree              : branch main at {relay.a[:12]} -> latest release v1.1.0 ({relay.b[:7]}), detached"
            in proc.stdout)
    assert "[WARN]" not in proc.stderr


def test_phase1_on_a_relay_detached_at_a_release_is_not_a_warning(relay: Relay) -> None:
    relay.git(relay.live, "fetch", "-q", "--tags", "origin")
    relay.git(relay.live, "checkout", "-q", "--detach", "v1.0.0")
    proc = relay.run(RESOLVE + "relay_ref_report_line; echo\n")
    assert proc.returncode == 0, proc.stderr
    assert "[WARN]" not in proc.stderr and "WARN" not in proc.stdout
    assert f"tree              : a detached HEAD at {relay.a[:12]} -> latest release v1.1.0" in proc.stdout


# --------------------------------------------------------------------------- #
# 5. The handover: the target's own deploy.sh deploys it
# --------------------------------------------------------------------------- #
HANDOVER = RESOLVE + 'LOCK_FD=""\nrelay_handover\necho NO-HANDOVER\n'


def test_the_targets_own_deploy_sh_takes_over(relay: Relay) -> None:
    proc = relay.run(HANDOVER, DEPLOY_REF="v1.1.0", FORCE="0")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "NO-HANDOVER" not in proc.stdout, "exec: nothing after the handover runs here"
    assert f"HANDED-OVER-TO B sha={relay.b} ref=v1.1.0 force=0" in proc.stdout, "the env goes with it"
    assert "handing over to the deploy.sh of tag v1.1.0" in proc.stdout
    again = relay.run(HANDOVER, DEPLOY_REF="v1.1.0")
    assert again.returncode == 0 and "HANDED-OVER-TO B" in again.stdout
    files = sorted((relay.tmp / "handover").iterdir())
    assert len(files) == 2, "a file per run: bash reads a running script, nobody may rewrite it"
    assert all(f.name.startswith(f"deploy-{relay.b[:7]}.") and f.name.endswith(".sh") for f in files)


def test_no_handover_when_this_copy_is_the_targets(relay: Relay) -> None:
    """The handed-over copy (DEPLOY_HANDOVER_SHA set) and a copy equal to the target's
    one run the deploy themselves."""
    proc = relay.run(HANDOVER, DEPLOY_HANDOVER_SHA=relay.b)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "NO-HANDOVER" in proc.stdout and "HANDED-OVER" not in proc.stdout
    (relay.seed / "scripts" / "deploy.sh").write_text(DEPLOY_SH.read_text(encoding="utf-8"), encoding="utf-8")
    relay.git(relay.seed, "commit", "-qam", "D: the real deploy.sh")
    relay.git(relay.seed, "tag", "v1.3.0")
    relay.git(relay.seed, "push", "-q", str(relay.origin), "main", "--tags")
    same = relay.run(HANDOVER)
    assert same.returncode == 0, same.stdout + same.stderr
    assert "NAME=v1.3.0" in same.stdout and "NO-HANDOVER" in same.stdout


def test_a_handed_over_copy_refuses_a_target_that_moved(relay: Relay) -> None:
    proc = relay.run(HANDOVER, DEPLOY_HANDOVER_SHA=relay.a)
    assert proc.returncode == 1 and "moved during the handover" in proc.stderr
    assert "NO-HANDOVER" not in proc.stdout


def test_a_target_from_before_release_deploys_is_refused(relay: Relay) -> None:
    """Its deploy.sh would deploy origin/main whatever DEPLOY_REF says."""
    (relay.seed / "scripts" / "deploy.sh").write_text(Relay.target_deploy_sh("OLD", protocol=False), encoding="utf-8")
    relay.git(relay.seed, "commit", "-qam", "old deploy.sh")
    relay.git(relay.seed, "tag", "v1.4.0")
    relay.git(relay.seed, "push", "-q", str(relay.origin), "main", "--tags")
    proc = relay.run(HANDOVER)
    assert proc.returncode == 1
    assert "predates release-based relay deploys (it would deploy origin/main instead) — DEPLOY_REF=main" in proc.stderr
    assert "HANDED-OVER" not in proc.stdout and relay.head() == relay.a


def test_the_handover_comes_before_tests_and_mutations() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    body = text[text.index("\nrelay_deploy() {"):]
    body = body[: body.index("\n}\n")]
    order = [body.index(s) for s in ("flock -n", "relay_fetch_target", "relay_handover", "run_checkout_tests",
                                     "relay_phase1", "relay_phase2")]
    assert order == sorted(order)
    assert "fetch_origin_main" not in body, "a relay fetches its target, not origin/main alone"


# --------------------------------------------------------------------------- #
# 6. redeploy.sh, the main server, install.json
# --------------------------------------------------------------------------- #
def test_redeploy_forwards_deploy_ref() -> None:
    text = REDEPLOY_SH.read_text(encoding="utf-8")
    allow = text[text.index("DEPLOY_ENV_PASSTHROUGH=("):]
    assert "\n  DEPLOY_REF\n" in allow[: allow.index(")")]
    assert 'DEPLOY_REF="${DEPLOY_REF:-}"' in DEPLOY_SH.read_text(encoding="utf-8")


def _main_guard() -> str:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    start = text.index("# DEPLOY_REF picks a relay's release;")
    return text[start : text.index("\n", text.index("|| die", start)) + 1]


def test_the_main_server_refuses_a_deploy_ref_other_than_main() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    seam = text.index('if [[ "${DEPLOY_SELFTEST:-0}" == "1" ]]; then return 0')
    guard = text.index("# DEPLOY_REF picks a relay's release;")
    assert seam < text.index("  relay_deploy\n  exit 0\nfi\n", seam) < guard < text.index("require_tools git sqlite3", seam)
    for ref, ok in (("", True), ("main", True), ("v3.1.0", False), ("1a87f67", False), ("origin/main", False)):
        proc = subprocess.run(
            ["bash", "-c", 'die() { echo "DIE: $*" >&2; exit 1; }\nDEPLOY_REF="$1"\n' + _main_guard() + "echo PASSED\n",
             "x", ref],
            capture_output=True, text=True,
        )
        assert ("PASSED" in proc.stdout) is ok, (ref, proc.stderr)
        if not ok:
            assert "applies to a relay only — the main server always deploys origin/main" in proc.stderr


def test_install_json_ref_is_written_by_the_installer_only() -> None:
    """The ref in /etc/vpn-relay/install.json is the INSTALL's ref (documented in
    install.sh and docs/relay.md); deploy.sh and the agent's update never rewrite it."""
    assert "install.json" not in DEPLOY_SH.read_text(encoding="utf-8")
    agent_text = AGENT.read_text(encoding="utf-8")
    assert agent_text.count("INSTALL_FILE") == 2, "defined, and read by installer_relay — never written"
    assert re.search(r"write_\w+\(INSTALL_FILE", agent_text) is None
    install = INSTALL_SH.read_text(encoding="utf-8")
    assert '"ref": ref' in install and "the ref of the installation, never kept current" in install
    for doc in ("docs/relay.md", "docs/relay.ru.md"):
        assert "install.json" in (ROOT / doc).read_text(encoding="utf-8") and "`ref`" in (ROOT / doc).read_text(
            encoding="utf-8"), doc


def test_relay_update_of_install_sh_is_retired_with_the_way_onto_deploy() -> None:
    proc = subprocess.run(["bash", str(INSTALL_SH), "--relay-update"], capture_output=True, text=True,
                          env={"PATH": os.environ["PATH"], "INSTALL_SELFTEST": "0"})
    assert proc.returncode == 1
    assert "scripts/deploy.sh" in proc.stderr and "sudo bash /opt/vpn-service/scripts/redeploy.sh" in proc.stderr
    assert "DEPLOY_REF=main" in proc.stderr
