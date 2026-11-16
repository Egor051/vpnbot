"""Local branches already merged into origin/main are deleted after a successful deploy.

The main server's checkout carried 15 such branches on 2026-11-16. After DEPLOY OK is
certain (disarmed — it can never roll a deploy back), both roles run
``delete_merged_branches``: every branch ``git branch --merged origin/main`` lists, except
the current one and main, goes with ``git branch -d`` — NEVER ``-D``. A refusal (git's own
safety: unmerged into its upstream/HEAD, checked out in another worktree) is a WARN, never
a failure; every deletion is logged with its sha; DEPLOY OK carries one counter line.

Real git repositories under tmp_path, driven through the DEPLOY_SELFTEST=1 seam; WT stays
empty (the EXIT trap runs `git worktree remove --force "$WT"`).
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

pytestmark = pytest.mark.timeout(60)


def _env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    return env


class Repo:
    """origin: main A - B - C. The live clone on local main at C with branches:
    feat/a (at A) and feat/b (at B) — merged; feat/wt (at B) — merged but checked out in
    another worktree; feat/unmerged — a commit origin/main does not have."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        (tmp / "home").mkdir()
        self.env = _env(tmp / "home")
        self.origin = tmp / "origin.git"
        self.live = tmp / "live"
        self.git(tmp, "-c", "init.defaultBranch=main", "init", "-q", "--bare", str(self.origin))
        self.git(tmp, "-c", "init.defaultBranch=main", "init", "-q", str(self.live))
        self.git(self.live, "remote", "add", "origin", str(self.origin))
        self.sha = {name: self.commit(name) for name in ("A", "B", "C")}
        self.git(self.live, "push", "-q", "origin", "main")
        self.git(self.live, "fetch", "-q", "origin")
        self.git(self.live, "branch", "feat/a", self.sha["A"])
        self.git(self.live, "branch", "feat/b", self.sha["B"])
        self.git(self.live, "branch", "feat/wt", self.sha["B"])
        self.git(self.live, "worktree", "add", "-q", str(tmp / "other"), "feat/wt")
        self.git(self.live, "checkout", "-q", "-b", "feat/unmerged")
        self.unmerged = self.commit("U")
        self.git(self.live, "checkout", "-q", "main")

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=str(cwd), env=self.env, capture_output=True, text=True,
                              check=True).stdout.strip()

    def commit(self, name: str) -> str:
        (self.live / "f").write_text(name + "\n", encoding="utf-8")
        self.git(self.live, "add", "f")
        self.git(self.live, "-c", "commit.gpgsign=false", "commit", "-q", "-m", name)
        return self.git(self.live, "rev-parse", "HEAD")

    def branches(self) -> set[str]:
        return set(self.git(self.live, "branch", "--format=%(refname:short)").split())

    def run(self, body: str = 'delete_merged_branches\necho "SUMMARY=$(merged_branches_summary)"\n'
            ) -> subprocess.CompletedProcess[str]:
        driver = self.tmp / "driver.sh"
        driver.write_text(
            "set -euo pipefail\nexport DEPLOY_SELFTEST=1\n"
            f'source "{DEPLOY_SH}"\n'
            'WT=""; STAGE=""; VENV=/nonexistent; VENV_PREV=/nonexistent\n'
            f"{body}\n",
            encoding="utf-8",
        )
        return subprocess.run(["bash", str(driver)], cwd=str(self.live), env=self.env, capture_output=True,
                              text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path)


def test_merged_branches_go_with_branch_d_and_a_refusal_is_a_warning(repo: Repo) -> None:
    proc = repo.run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert repo.branches() == {"main", "feat/wt", "feat/unmerged"}
    for name in ("feat/a", "feat/b"):
        assert re.search(rf"\[deploy\] merged branch: Deleted branch {re.escape(name)} \(was [0-9a-f]{{7,}}\)\.",
                         proc.stdout), (name, proc.stdout)
    assert "merged branch feat/wt kept — git branch -d refused:" in proc.stderr, "another worktree has it"
    assert "SUMMARY=2 deleted (git branch -d; each with its sha in the log above), 1 kept" in proc.stdout
    assert "feat/unmerged" not in proc.stdout + proc.stderr, "not merged: never even tried"
    assert repo.git(repo.live, "rev-parse", "feat/unmerged") == repo.unmerged


def test_the_current_branch_and_main_are_never_deleted(repo: Repo) -> None:
    """On feat/a (at A) neither it nor main goes; and feat/b (at B, merged into origin/main
    but not into this HEAD) is refused by git's own -d check — kept, with a WARN, which is
    exactly why the deploy never uses -D."""
    repo.git(repo.live, "checkout", "-q", "feat/a")
    proc = repo.run()
    assert proc.returncode == 0, proc.stderr
    assert {"main", "feat/a", "feat/b"} <= repo.branches()
    assert "Deleted branch feat/a" not in proc.stdout and "Deleted branch main" not in proc.stdout
    assert "merged branch feat/b kept — git branch -d refused:" in proc.stderr
    assert "not fully merged" in proc.stderr


def test_nothing_to_delete_says_so(repo: Repo) -> None:
    repo.git(repo.live, "worktree", "remove", "--force", str(repo.tmp / "other"))
    for name in ("feat/a", "feat/b", "feat/wt"):
        repo.git(repo.live, "branch", "-d", name)
    proc = repo.run()
    assert proc.returncode == 0, proc.stderr
    assert "SUMMARY=none merged into origin/main besides main" in proc.stdout
    assert repo.branches() == {"main", "feat/unmerged"}


def test_a_git_failure_never_fails_the_caller(repo: Repo) -> None:
    """No origin/main to compare with: nothing listed, nothing deleted, rc 0."""
    repo.git(repo.live, "update-ref", "-d", "refs/remotes/origin/main")
    proc = repo.run('delete_merged_branches\necho "SUMMARY=$(merged_branches_summary)"\necho GOES-ON\n')
    assert proc.returncode == 0 and "GOES-ON" in proc.stdout, proc.stderr
    assert {"feat/a", "feat/b"} <= repo.branches()


# --------------------------------------------------------------------------- #
# Where it runs
# --------------------------------------------------------------------------- #
def _code(text: str) -> str:
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def test_never_branch_capital_d() -> None:
    code = _code(DEPLOY_SH.read_text(encoding="utf-8"))
    assert "branch -D" not in code and "branch --delete --force" not in code
    assert 'git branch -d -- "$b"' in code


def test_both_roles_delete_after_disarm_and_report_it() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    top = text[text.index('if [[ "${DEPLOY_SELFTEST:-0}" == "1" ]]; then return 0'):]
    main = [top.index(s) for s in ("\ndisarm\n", "\ndelete_merged_branches\n", "===== DEPLOY OK =====",
                                   "merged branches  : $(merged_branches_summary)")]
    assert main == sorted(main), "main: after disarm, before the report"
    relay = text[text.index("\nrelay_phase2() {"):]
    relay = relay[: relay.index("\n}\n")]
    order = [relay.index(s) for s in ("  disarm\n", "  delete_merged_branches\n", "===== DEPLOY OK (relay) =====",
                                      "merged branches  : $(merged_branches_summary)")]
    assert order == sorted(order), "relay: after disarm, before the report"
