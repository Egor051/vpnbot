"""The live tree is always on local `main`, whatever branch it was found on.

Phase 2 advanced the tree with ``git reset --hard origin/main``, which moves whatever
branch is checked out. Production had been left on ``feat/offsite-system-bundle``, so
every deploy rewrote that feature branch to the tip of main and ``git status`` named a
branch the host was not running. Now:

* Phase 2 (the main server): ``git checkout -f -B main origin/main``;
* rollback (the main server): ``git checkout -f -B main PREV_SHA``, falling back to
  ``git reset --hard PREV_SHA`` should git refuse the branch — the code comes back
  regardless;
* the no-op guard (HEAD == origin/main, no FORCE): ``git checkout -B main origin/main``
  only — the same commit, so no file changes, a local edit survives, nothing restarts;
* Phase 1 WARNs when the tree is not on main, and a real deploy stops before any
  mutation when another worktree has main checked out (git would refuse ``-B``).

A relay follows releases, detached — tests/test_relay_release_tag.py.

Driven through the ``DEPLOY_SELFTEST=1`` seam against REAL git repositories under
tmp_path (a bare origin and a clone) — never the repository running this suite. The
git environment is hermetic (own HOME, no system config).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

pytestmark = pytest.mark.timeout(60)

FEATURE = "feat/offsite-system-bundle"


def _env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        HOME=str(home),
        GIT_CONFIG_NOSYSTEM="1",
        GIT_AUTHOR_NAME="t",
        GIT_AUTHOR_EMAIL="t@example.invalid",
        GIT_COMMITTER_NAME="t",
        GIT_COMMITTER_EMAIL="t@example.invalid",
    )
    return env


class Repo:
    """A bare origin with main at A then B, and a live clone like production's."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.home = tmp / "home"
        self.home.mkdir()
        self.env = _env(self.home)
        self.origin = tmp / "origin.git"
        self.seed = tmp / "seed"
        self.live = tmp / "live"
        self.git(tmp, "init", "-q", "--bare", str(self.origin))
        self.git(tmp, "-c", "init.defaultBranch=main", "init", "-q", str(self.seed))
        self.git(self.seed, "config", "commit.gpgsign", "false")
        (self.seed / "app.txt").write_text("A\n", encoding="utf-8")
        self.git(self.seed, "add", "app.txt")
        self.git(self.seed, "commit", "-q", "-m", "A")
        self.a = self.rev(self.seed, "HEAD")
        self.git(self.seed, "push", "-q", str(self.origin), "main", f"main:refs/heads/{FEATURE}")
        self.git(tmp, "clone", "-q", str(self.origin), str(self.live))
        # Production: the checkout sits on the feature branch.
        self.git(self.live, "checkout", "-q", FEATURE)
        (self.seed / "app.txt").write_text("B\n", encoding="utf-8")
        self.git(self.seed, "commit", "-q", "-am", "B")
        self.b = self.rev(self.seed, "HEAD")
        self.git(self.seed, "push", "-q", str(self.origin), "main")

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=str(cwd), env=self.env, capture_output=True, text=True, check=True
        ).stdout.strip()

    def rev(self, cwd: Path, ref: str) -> str:
        return self.git(cwd, "rev-parse", ref)

    def branch(self) -> str:
        return subprocess.run(
            ["git", "symbolic-ref", "-q", "--short", "HEAD"],
            cwd=str(self.live), env=self.env, capture_output=True, text=True,
        ).stdout.strip()

    def run(self, body: str, **knobs: str) -> subprocess.CompletedProcess[str]:
        stub = self.tmp / "stub"
        stub.mkdir(exist_ok=True)
        calls = self.tmp / "systemctl.log"
        sc = stub / "systemctl"
        sc.write_text(f'#!/usr/bin/env bash\necho "$*" >> "{calls}"\nexit 0\n', encoding="utf-8")
        sc.chmod(0o755)
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -uo pipefail\n"
            "export DEPLOY_SELFTEST=1\n"
            f'export PATH="{stub}:$PATH"\n'
            + "".join(f"export {k}={v}\n" for k, v in knobs.items())
            + f'source "{DEPLOY_SH}"\n'
            'WT=""; STAGE=""; VENV=/nonexistent; VENV_PREV=/nonexistent\n'
            f"{body}\n",
            encoding="utf-8",
        )
        return subprocess.run(
            ["bash", str(driver)], cwd=str(self.live), env=self.env, capture_output=True, text=True
        )

    def systemctl_calls(self) -> str:
        f = self.tmp / "systemctl.log"
        return f.read_text(encoding="utf-8") if f.exists() else ""


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path)


# --------------------------------------------------------------------------- #
# Phase 1: the WARN, read-only
# --------------------------------------------------------------------------- #
def test_phase1_warns_when_not_on_main_and_changes_nothing(repo: Repo) -> None:
    proc = repo.run("fetch_origin_main\necho TAG=$TAG\nbranch_report_line\n", PHASE1_ONLY="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"[WARN] the live checkout is on branch {FEATURE}, not on local main" in proc.stderr
    assert f"branch {FEATURE} itself is left where it is" in proc.stderr
    assert f"branch            : WARN branch {FEATURE} — the deploy moves the tree to local main" in proc.stdout
    assert repo.branch() == FEATURE
    assert repo.rev(repo.live, "HEAD") == repo.a


def test_phase1_is_silent_on_main(repo: Repo) -> None:
    repo.git(repo.live, "checkout", "-q", "-B", "main", repo.a)
    proc = repo.run("fetch_origin_main\nbranch_report_line\n", PHASE1_ONLY="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "not on local main" not in proc.stderr
    assert "branch            : main (the deploy keeps the tree on it)" in proc.stdout


def test_phase1_names_a_detached_head(repo: Repo) -> None:
    repo.git(repo.live, "checkout", "-q", "--detach", repo.a)
    proc = repo.run("fetch_origin_main\n", PHASE1_ONLY="1")
    assert "the live checkout is on a detached HEAD, not on local main" in proc.stderr


# --------------------------------------------------------------------------- #
# Phase 2 and the rollback
# --------------------------------------------------------------------------- #
def test_phase2_puts_the_tree_on_main_and_leaves_the_feature_branch_alone(repo: Repo) -> None:
    proc = repo.run("fetch_origin_main\npin_tree_to_main origin/main\necho PINNED\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PINNED" in proc.stdout
    assert repo.branch() == "main"
    assert repo.rev(repo.live, "HEAD") == repo.b
    assert (repo.live / "app.txt").read_text(encoding="utf-8") == "B\n"
    # reset --hard used to drag the feature branch to origin/main; now it stays put.
    assert repo.rev(repo.live, FEATURE) == repo.a


def test_rollback_restores_prev_sha_on_main(repo: Repo) -> None:
    proc = repo.run(
        'PREV_SHA="$(git rev-parse HEAD)"\n'
        "pin_tree_to_main origin/main\n"
        'restore_tree_to "$PREV_SHA"\n'
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"git checkout -f -B main {repo.a}: rc=0" in proc.stdout
    assert repo.branch() == "main"
    assert repo.rev(repo.live, "HEAD") == repo.a
    assert (repo.live / "app.txt").read_text(encoding="utf-8") == "A\n"


def test_rollback_falls_back_to_a_detached_checkout_when_git_refuses_the_branch(repo: Repo) -> None:
    """The code must come back even when `checkout -B main` cannot write main.

    A stale refs/heads/main.lock (a git process that died) makes every write of main
    fail — `reset --hard` on main included. The detached checkout writes no branch.
    """
    proc = repo.run(
        'PREV_SHA="$(git rev-parse HEAD)"\n'
        "pin_tree_to_main origin/main\n"
        ': > "$(git rev-parse --git-path refs/heads/main.lock)"\n'
        'restore_tree_to "$PREV_SHA"\n'
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"FELL BACK to git checkout -f --detach {repo.a}: rc=0 (code restored, HEAD detached)" in proc.stdout
    assert repo.branch() == ""
    assert repo.rev(repo.live, "HEAD") == repo.a
    assert (repo.live / "app.txt").read_text(encoding="utf-8") == "A\n"


# --------------------------------------------------------------------------- #
# The no-op guard: normalize the branch, restart nothing
# --------------------------------------------------------------------------- #
def _feature_at_tip(repo: Repo) -> None:
    """Production after the last deploy: the feature branch was reset to origin/main."""
    repo.git(repo.live, "fetch", "-q", "origin", "main")
    repo.git(repo.live, "reset", "-q", "--hard", "origin/main")
    assert repo.branch() == FEATURE and repo.rev(repo.live, "HEAD") == repo.b


def test_noop_guard_moves_the_branch_without_a_restart(repo: Repo) -> None:
    _feature_at_tip(repo)
    # A local edit must survive: the no-op path never discards anything.
    (repo.live / "app.txt").write_text("hand edit\n", encoding="utf-8")
    proc = repo.run("fetch_origin_main\necho NOT-REACHED\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "NOT-REACHED" not in proc.stdout, "the no-op guard still exits"
    assert "nothing to deploy" in proc.stdout
    assert f"moved the checkout from branch {FEATURE} to local main" in proc.stdout
    assert "no file changed, vpn-bot not restarted" in proc.stdout
    assert repo.branch() == "main"
    assert repo.rev(repo.live, "HEAD") == repo.b
    assert (repo.live / "app.txt").read_text(encoding="utf-8") == "hand edit\n"
    assert repo.systemctl_calls() == "", "the no-op path touched systemd"


def test_noop_guard_on_main_is_a_plain_noop(repo: Repo) -> None:
    _feature_at_tip(repo)
    repo.git(repo.live, "checkout", "-q", "-B", "main")
    proc = repo.run("fetch_origin_main\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "moved the checkout" not in proc.stdout
    assert repo.branch() == "main"


def test_phase1_only_never_moves_the_branch(repo: Repo) -> None:
    _feature_at_tip(repo)
    proc = repo.run("fetch_origin_main\necho PHASE1-GOES-ON\n", PHASE1_ONLY="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PHASE1-GOES-ON" in proc.stdout
    assert repo.branch() == FEATURE, "PHASE1_ONLY mutates nothing, the branch included"


def test_force_leaves_the_branch_to_phase2(repo: Repo) -> None:
    _feature_at_tip(repo)
    proc = repo.run("fetch_origin_main\necho GOES-ON\n", FORCE="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "GOES-ON" in proc.stdout
    assert repo.branch() == FEATURE, "Phase 1 is read-only; Phase 2's checkout -B moves it"


# --------------------------------------------------------------------------- #
# main checked out in another worktree
# --------------------------------------------------------------------------- #
def _main_elsewhere(repo: Repo) -> Path:
    other = repo.tmp / "other"
    repo.git(repo.live, "worktree", "add", "-q", str(other), "-b", "main", "origin/main")
    return other


def test_real_deploy_stops_before_any_mutation_when_main_is_taken(repo: Repo) -> None:
    other = _main_elsewhere(repo)
    proc = repo.run("fetch_origin_main\necho NOT-REACHED\n")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "NOT-REACHED" not in proc.stdout
    assert f"local main is checked out in another worktree ({other})" in proc.stderr
    assert repo.branch() == FEATURE and repo.rev(repo.live, "HEAD") == repo.a


def test_phase1_only_reports_the_taken_main(repo: Repo) -> None:
    _main_elsewhere(repo)
    proc = repo.run("fetch_origin_main\nbranch_report_line\n", PHASE1_ONLY="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "BLOCKED: main is checked out in" in proc.stdout


def test_noop_guard_with_main_taken_warns_and_exits_clean(repo: Repo) -> None:
    _feature_at_tip(repo)
    _main_elsewhere(repo)
    proc = repo.run("fetch_origin_main\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"left on branch {FEATURE}: local main is checked out in" in proc.stderr
    assert repo.branch() == FEATURE


# --------------------------------------------------------------------------- #
# Shape: no bare `reset --hard origin/main` is left in either role
# --------------------------------------------------------------------------- #
def _code_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


def test_no_role_advances_the_tree_with_reset_hard_any_more() -> None:
    """main: local main at origin/main; a relay: its target, detached (its own suite,
    tests/test_relay_release_tag.py) — neither by reset --hard."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    code = "\n".join(_code_lines(text))
    assert "git reset --hard" not in code
    assert code.count("pin_tree_to_main origin/main") == 1, "main Phase 2 only"
    assert code.count('pin_tree_detached "$RELAY_TARGET_SHA"') == 1, "relay_phase2"
    for header, restore in (("\nrollback() {", "restore_tree_to"), ("\nrelay_rollback() {", "restore_tree_detached")):
        start = text.index(header)
        body = text[start : text.index("\n}\n", start)]
        assert f'report+=("$({restore} "$PREV_SHA")")' in body, header
        assert "git reset --hard" not in "\n".join(_code_lines(body)), header


def test_each_phase1_report_carries_its_tree_line() -> None:
    """main: the branch line (WARN off main); a relay: where the tree goes, no WARN."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    for header, line in (("\nphase1_report() {", "branch_report_line"), ("\nrelay_phase1_report() {", "relay_ref_report_line")):
        start = text.index(header)
        assert line in text[start : text.index("\n}\n", start)], header
