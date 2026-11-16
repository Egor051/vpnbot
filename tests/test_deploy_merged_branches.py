"""Local branches already merged into origin/main are deleted after a successful deploy.

The main server's checkout carried 15 such branches on 2026-11-16. After DEPLOY OK is
certain (disarmed — it can never roll a deploy back), both roles run
``delete_merged_branches``: every branch ``git for-each-ref --merged origin/main refs/heads/``
lists, except the current one and main, goes when its sha is an ancestor of origin/main
(re-checked right before) — by ``git update-ref -d <ref> <sha>``, so a branch that moved
since the listing is refused. NOT ``git branch -d``: it judges a branch by its stale
upstream (10 of 13 refused on the main server), and ``git branch --merged`` printed a
"(HEAD detached at …)" pseudo-branch on every relay deploy. A refusal (moved, no longer an
ancestor, checked out in another worktree) is a WARN, never a failure; every deletion is
logged with its sha; DEPLOY OK carries one counter line.

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
        return set(self.git(self.live, "for-each-ref", "--format=%(refname:lstrip=2)", "refs/heads/").split())

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


SUMMARY_RE = r"SUMMARY={d} deleted \(ancestors of origin/main; each with its sha in the log above\), {k} kept"


def _deleted(proc: subprocess.CompletedProcess[str], name: str, sha: str) -> bool:
    return f"[deploy] merged branch: Deleted branch {name} (was {sha})." in proc.stdout


def _race_hook(trigger_sha: str, action: str) -> str:
    """A `git` wrapper that runs <action> once, when the deletion re-checks <trigger_sha> —
    i.e. AFTER the listing and BEFORE update-ref: the window a concurrent change hits."""
    return (
        "git() {\n"
        f'  if [[ "$1" == merge-base && "$2" == --is-ancestor && "$3" == {trigger_sha} && -z "${{HOOKED:-}}" ]]; then\n'
        f"    HOOKED=1; command git {action}\n"
        "  fi\n"
        '  command git "$@"\n'
        "}\n"
    )


def test_merged_branches_go_and_a_refusal_is_a_warning(repo: Repo) -> None:
    proc = repo.run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert repo.branches() == {"main", "feat/wt", "feat/unmerged"}
    assert _deleted(proc, "feat/a", repo.sha["A"]), proc.stdout
    assert _deleted(proc, "feat/b", repo.sha["B"]), proc.stdout
    assert f"merged branch feat/wt kept — checked out in another worktree ({repo.tmp / 'other'})" in proc.stderr
    assert repo.git(repo.tmp / "other", "symbolic-ref", "HEAD") == "refs/heads/feat/wt"
    assert re.search(SUMMARY_RE.format(d=2, k=1), proc.stdout), proc.stdout
    assert "feat/unmerged" not in proc.stdout + proc.stderr, "not merged: never even tried"
    assert repo.git(repo.live, "rev-parse", "feat/unmerged") == repo.unmerged


def test_a_detached_head_lists_no_pseudo_branch(repo: Repo) -> None:
    """A relay is always detached. `git branch --merged origin/main` printed
    "(HEAD detached at <sha>)" there and the deploy tried to delete it — a WARN on every
    relay deploy. for-each-ref over refs/heads/ lists branches only."""
    repo.git(repo.live, "checkout", "-q", "--detach", repo.sha["C"])
    assert "(HEAD detached at" in repo.git(repo.live, "branch", "--merged", "origin/main"), "the old source"
    proc = repo.run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "HEAD detached" not in proc.stdout + proc.stderr and "(HEAD" not in proc.stdout + proc.stderr
    assert repo.branches() == {"main", "feat/wt", "feat/unmerged"}
    warns = [ln for ln in proc.stderr.splitlines() if "[WARN]" in ln]
    assert len(warns) == 1 and "feat/wt kept — checked out in another worktree" in warns[0], warns
    assert re.search(SUMMARY_RE.format(d=2, k=1), proc.stdout), proc.stdout
    assert repo.git(repo.live, "rev-parse", "HEAD") == repo.sha["C"]


def test_a_branch_ahead_of_its_stale_upstream_goes_with_its_config(repo: Repo) -> None:
    """Measured on the main server: the deploy fetches only main, so origin/<b> is a stale
    remote-tracking ref, and the local branch (moved by an old reset --hard) is ahead of it.
    `git branch -d` refuses that ("not yet merged to refs/remotes/origin/<b>, even though it
    is merged to HEAD"); it is still contained in origin/main, so it goes — and its
    [branch "<b>"] config section with it."""
    repo.git(repo.live, "update-ref", "refs/remotes/origin/feat/stale", repo.sha["A"])
    repo.git(repo.live, "branch", "feat/stale", repo.sha["B"])
    repo.git(repo.live, "config", "branch.feat/stale.remote", "origin")
    repo.git(repo.live, "config", "branch.feat/stale.merge", "refs/heads/feat/stale")
    repo.git(repo.live, "config", "branch.feat/stale.x.remote", "origin")  # another branch's section
    old = subprocess.run(["git", "branch", "-d", "feat/stale"], cwd=str(repo.live), env=repo.env,
                         capture_output=True, text=True)
    assert old.returncode != 0, old.stderr
    assert "not yet merged to 'refs/remotes/origin/feat/stale'" in " ".join(old.stderr.split()), old.stderr

    proc = repo.run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "feat/stale" not in repo.branches()
    assert _deleted(proc, "feat/stale", repo.sha["B"]), proc.stdout
    assert "feat/stale" not in proc.stderr, proc.stderr
    names = repo.git(repo.live, "config", "--local", "--name-only", "--get-regexp", r"^branch\.").split()
    assert not [n for n in names if n.startswith("branch.feat/stale.") and n.count(".") == 2], names
    assert "branch.feat/stale.x.remote" in names, "a section of another name stays"
    repo.git(repo.live, "branch", "feat/stale", repo.sha["B"])  # the log line is enough to bring it back


def test_a_branch_with_a_commit_origin_main_lacks_stays(repo: Repo) -> None:
    """feat/unmerged has U, which origin/main does not: never listed, never touched — even
    with an upstream it is "merged" into."""
    repo.git(repo.live, "update-ref", "refs/remotes/origin/feat/unmerged", repo.unmerged)
    repo.git(repo.live, "config", "branch.feat/unmerged.remote", "origin")
    repo.git(repo.live, "config", "branch.feat/unmerged.merge", "refs/heads/feat/unmerged")
    proc = repo.run()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert repo.git(repo.live, "rev-parse", "feat/unmerged") == repo.unmerged
    assert repo.git(repo.live, "config", "branch.feat/unmerged.remote") == "origin"
    assert "feat/unmerged" not in proc.stdout + proc.stderr


def test_a_branch_that_moved_after_the_listing_is_refused_by_update_ref(repo: Repo) -> None:
    """The race: feat/race (at C, listed as merged) moves to U between the listing and the
    deletion. update-ref -d with the listed sha as the old value refuses; the branch stays
    at U with its config; a WARN, rc 0, the rest goes on."""
    repo.git(repo.live, "branch", "feat/race", repo.sha["C"])
    repo.git(repo.live, "config", "branch.feat/race.remote", "origin")
    hook = _race_hook(repo.sha["C"], f"update-ref refs/heads/feat/race {repo.unmerged}")
    proc = repo.run(hook + 'delete_merged_branches\necho "SUMMARY=$(merged_branches_summary)"\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert repo.git(repo.live, "rev-parse", "feat/race") == repo.unmerged
    assert repo.git(repo.live, "config", "branch.feat/race.remote") == "origin", "kept branch keeps its config"
    assert f"merged branch feat/race kept — git update-ref -d refs/heads/feat/race {repo.sha['C']} refused:" \
        in proc.stderr, proc.stderr
    assert "Deleted branch feat/race" not in proc.stdout
    assert "feat/a" not in repo.branches() and "feat/b" not in repo.branches()
    assert re.search(SUMMARY_RE.format(d=2, k=2), proc.stdout), proc.stdout


def test_a_sha_no_longer_in_origin_main_is_kept(repo: Repo) -> None:
    """The ancestor re-check right before the deletion: origin/main rewound to A after the
    listing — B is no longer contained, so feat/b stays (WARN); feat/a still goes."""
    hook = _race_hook(repo.sha["B"], f"update-ref refs/remotes/origin/main {repo.sha['A']}")
    proc = repo.run(hook + 'delete_merged_branches\necho "SUMMARY=$(merged_branches_summary)"\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert repo.git(repo.live, "rev-parse", "feat/b") == repo.sha["B"]
    assert f"merged branch feat/b kept — {repo.sha['B']} is not an ancestor of origin/main" in proc.stderr
    assert _deleted(proc, "feat/a", repo.sha["A"]), proc.stdout


def test_the_current_branch_and_main_are_never_deleted(repo: Repo) -> None:
    """On feat/a (at A) neither it nor main goes. feat/b (at B) is not merged into this HEAD
    but is contained in origin/main — the rule is origin/main, so it goes."""
    repo.git(repo.live, "checkout", "-q", "feat/a")
    proc = repo.run()
    assert proc.returncode == 0, proc.stderr
    assert {"main", "feat/a"} <= repo.branches()
    assert "feat/b" not in repo.branches()
    assert "Deleted branch feat/a" not in proc.stdout and "Deleted branch main" not in proc.stdout
    assert _deleted(proc, "feat/b", repo.sha["B"]), proc.stdout


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


def test_never_branch_d_and_never_an_unchecked_update_ref() -> None:
    code = _code(DEPLOY_SH.read_text(encoding="utf-8"))
    assert "branch -D" not in code and "branch --delete --force" not in code
    assert "git branch -d" not in code, "branch -d judges by the stale upstream"
    assert "git branch --merged" not in code and "branch --format" not in code, "the detached-HEAD pseudo-line"
    body = code[code.index("\ndelete_merged_branches() {"):]
    body = body[: body.index("\n}\n")]
    assert "git for-each-ref --format='%(refname) %(objectname)' --merged origin/main refs/heads/" in body
    assert 'git merge-base --is-ancestor "$sha" origin/main' in body
    calls = re.findall(r'git update-ref -d "\$ref"( "\$sha")?', body)
    assert calls == [' "$sha"'], "update-ref -d always with the old value"
    assert 'git config --remove-section "branch.${b}"' in body


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
