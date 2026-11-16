"""scripts/redeploy.sh runs as origin/main's copy, whatever copy the checkout holds.

Measured on a relay on 2026-11-16: its checkout sat at 1a87f67, and
`sudo DEPLOY_REF=main bash scripts/redeploy.sh` printed `deploy.sh env: <none>`,
while CHECK=1 got through in the same run (PHASE1_ONLY=1). deploy.sh was
origin/main's (the wrapper takes it from there), but the wrapper itself was the
checkout's older copy, whose DEPLOY_ENV_PASSTHROUGH had no DEPLOY_REF, and a name
that does not start with ALLOW_* is not even refused by that list.

Now, right after the fetch, the wrapper compares its own bytes with
`git show origin/main:scripts/redeploy.sh`. When they differ, it execs origin/main's
copy from a private temp file with the same arguments and environment, plus
REDEPLOY_REEXEC=1, so it never does that twice. Asserted here:

1. A stale copy re-executes and DEPLOY_REF reaches the systemd-run argv. With the
   re-exec suppressed, the same copy loses it, exactly as on the relay.
2. A copy identical to origin/main's does not re-execute. The comparison is byte
   for byte: a trailing newline counts as a difference.
3. The loop guard: with REDEPLOY_REEXEC=1 the wrapper never re-executes, and the
   temp copy deletes itself and nothing else.
4. When origin/main's copy cannot be used (path missing, empty, does not parse, no
   origin/main), the wrapper prints a WARN on stderr and goes on with the current
   copy.
5. The mechanism: the same argv and environment, and a 0700 temp file holding
   origin/main's exact bytes.

The repositories are real git repositories under tmp_path (origin.git is cloned
from a seed; the checkout is a clone of origin.git). systemd-run, systemctl and
date are stubbed on PATH. The end-to-end runs execute redeploy.sh with its root
guard replaced by `:`, because CI runs this suite unprivileged; the rest of the
file is exactly as committed. Every subprocess gets a minimal environment, as in
tests/test_redeploy_env_passthrough.py: deploy.sh runs this suite as a Phase 1
gate, where the operator's own ALLOW_* or DEPLOY_REF may well be exported.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REDEPLOY_SH = ROOT / "scripts" / "redeploy.sh"

# Nothing here waits on anything; a test near this ceiling is a hang (a re-exec loop).
pytestmark = pytest.mark.timeout(60)

ROOT_GUARD = '[[ "${EUID}" -eq 0 ]] || { echo "redeploy: run as root (sudo bash scripts/redeploy.sh)" >&2; exit 1; }\n'
TS = "20261116T000000Z"

# Records every call to the stubbed host commands; systemd-run also writes its
# argv one element per line so a test can compare it exactly. git is NOT stubbed.
CALL_LOGGER = 'printf "%s\\n" "$(basename "$0") $*" >> "$CALLS"\n'


def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _current() -> str:
    """redeploy.sh as committed, minus the root guard (CI runs unprivileged)."""
    text = REDEPLOY_SH.read_text(encoding="utf-8")
    assert text.count(ROOT_GUARD) == 1, "the root guard line changed: update ROOT_GUARD in this test"
    return text.replace(ROOT_GUARD, ": # root guard removed for the test\n")


def _stale() -> str:
    """The same copy without DEPLOY_REF in DEPLOY_ENV_PASSTHROUGH: what the relay ran.

    It keeps the re-exec, which the relay's copy did not have yet. It stands for
    any checkout copy older than origin/main's that has the re-exec."""
    text = _current()
    line = "  DEPLOY_REF\n"
    assert text.count(line) == 1, "DEPLOY_REF is no longer a line of DEPLOY_ENV_PASSTHROUGH"
    return text.replace(line, "")


def _base_env(tmp: Path) -> dict[str, str]:
    stub = tmp / "stub"
    stub.mkdir(exist_ok=True)
    _make_stub(stub / "systemd-run", CALL_LOGGER + 'printf "%s\\n" "$@" > "$ARGV_LOG"\n')
    _make_stub(stub / "systemctl", CALL_LOGGER)
    _make_stub(stub / "date", CALL_LOGGER + f"echo {TS}\n")
    (tmp / "home").mkdir(exist_ok=True)
    (tmp / "tmpdir").mkdir(exist_ok=True)
    return {
        "PATH": f"{stub}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(tmp / "home"),
        "LC_ALL": "C",
        "TMPDIR": str(tmp / "tmpdir"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "CALLS": str(tmp / "calls"),
        "ARGV_LOG": str(tmp / "argv"),
    }


class Host:
    """origin.git has main at A (the checkout's commit), then B (origin/main).

    The checkout is a clone of origin.git, detached at A, which is where a relay on
    a release tag (or any host that lags behind) sits. Its working tree holds A's
    scripts/redeploy.sh; origin/main holds B's. `None` means B deletes the file.
    """

    def __init__(self, tmp: Path, *, checkout_copy: str, origin_copy: str | None) -> None:
        self.tmp = tmp
        self.env = _base_env(tmp)
        self.tmpdir = tmp / "tmpdir"
        self.logs = tmp / "logs"
        self.logs.mkdir()
        self.tmp_deploy = tmp / "deploy.sh"
        seed = tmp / "seed"
        self.git(tmp, "-c", "init.defaultBranch=main", "init", "-q", str(seed))
        self.commit(seed, "A", checkout_copy)
        self.commit(seed, "B", origin_copy)
        self.git(tmp, "clone", "-q", "--bare", str(seed), str(tmp / "origin.git"))
        self.app = tmp / "app"
        self.git(tmp, "clone", "-q", str(tmp / "origin.git"), str(self.app))
        self.a = self.git(self.app, "rev-parse", "--short", "origin/main~1")
        self.b = self.git(self.app, "rev-parse", "--short", "origin/main")
        self.git(self.app, "checkout", "-q", "--detach", self.a)
        self.env.update(
            APP_DIR=str(self.app),
            TMP_DEPLOY=str(self.tmp_deploy),
            REDEPLOY_LOG_DIR=str(self.logs),
        )

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=str(cwd), env=self.env, capture_output=True, text=True,
                              check=True).stdout.strip()

    def commit(self, seed: Path, name: str, redeploy: str | None) -> None:
        scripts = seed / "scripts"
        scripts.mkdir(exist_ok=True)
        (scripts / "deploy.sh").write_text(f"echo deploy.sh at {name}\n", encoding="utf-8")
        target = scripts / "redeploy.sh"
        if redeploy is None:
            target.unlink(missing_ok=True)
        else:
            target.write_text(redeploy, encoding="utf-8")
        self.git(seed, "add", "-A")
        self.git(seed, "-c", "commit.gpgsign=false", "commit", "-q", "-m", name)

    def run(self, **extra: str) -> subprocess.CompletedProcess[str]:
        """`cd /opt/vpn-service && bash scripts/redeploy.sh`, as an operator types it."""
        return subprocess.run(["bash", "scripts/redeploy.sh"], cwd=str(self.app), env={**self.env, **extra},
                              capture_output=True, text=True, encoding="utf-8")

    def calls(self) -> list[str]:
        log = self.tmp / "calls"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def argv(self) -> list[str]:
        return (self.tmp / "argv").read_text(encoding="utf-8").splitlines()

    def leftovers(self) -> list[str]:
        return sorted(p.name for p in self.tmpdir.iterdir())

    def launch_lines(self, env_line: str) -> list[str]:
        """The tail every run that reaches the launch prints."""
        return [
            f"redeploy: host HEAD={self.a}  origin/main={self.b}",
            f"redeploy: extracting deploy.sh from origin/main -> {self.tmp_deploy}",
            f"redeploy: launching vpn-bot-deploy (log: {self.logs}/deploy-{TS}.log)",
            f"redeploy:   deploy.sh env: {env_line}",
        ]

    def expected_argv(self, *deploy_env: str, attach: str = "pty") -> list[str]:
        command = f"bash {self.tmp_deploy} 2>&1 | tee {self.logs}/deploy-{TS}.log"
        if attach == "pipe":
            return ["--unit=vpn-bot-deploy", "--collect", "--wait", "--pipe", "--quiet",
                    "env", *deploy_env, "bash", "-c", f"set -o pipefail; {command}"]
        return ["--unit=vpn-bot-deploy", "--collect", "--pty", "env", *deploy_env, "bash", "-c", command]


# --------------------------------------------------------------------------- #
# 1. A stale copy re-executes as origin/main's, and the knob gets through
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("extra", "deploy_env", "attach"),
    [
        # The operator's command on the relay.
        ({"CHECK": "1", "DEPLOY_REF": "main"}, ["PHASE1_ONLY=1", "DEPLOY_REF=main"], "pty"),
        # The relay agent's `update` (scripts/vpn-relay-agent): no terminal, a release tag.
        ({"DEPLOY_REF": "v9.9.9", "REDEPLOY_ATTACH": "pipe"}, ["DEPLOY_REF=v9.9.9"], "pipe"),
    ],
    ids=["operator", "relay-agent"],
)
def test_stale_copy_reexecs_from_origin_main_and_forwards_deploy_ref(
    tmp_path: Path, extra: dict[str, str], deploy_env: list[str], attach: str
) -> None:
    host = Host(tmp_path, checkout_copy=_stale(), origin_copy=_current())
    proc = host.run(**extra)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # One re-exec line, then origin/main's copy runs the whole flow, its own fetch
    # included. Without the loop guard this would never end: the re-executed copy
    # runs from a temp file it has already deleted, so it would always "differ".
    assert proc.stdout.splitlines() == [
        "redeploy: fetching origin/main",
        f"redeploy: re-exec from origin/main ({host.b})",
        "redeploy: fetching origin/main",
        *host.launch_lines(" ".join(deploy_env)),
    ]
    assert "WARN" not in proc.stderr
    assert host.argv() == host.expected_argv(*deploy_env, attach=attach)
    assert [c.split()[0] for c in host.calls()] == ["systemctl", "date", "systemd-run"], "one launch"
    assert host.tmp_deploy.read_text(encoding="utf-8") == "echo deploy.sh at B\n"
    assert host.leftovers() == [], "the re-executed copy deletes its temp file"


def test_without_the_reexec_the_stale_copy_loses_deploy_ref(tmp_path: Path) -> None:
    """The relay incident, reproduced: REDEPLOY_REEXEC=1 suppresses the re-exec, and
    CHECK=1 gets through while DEPLOY_REF is dropped."""
    host = Host(tmp_path, checkout_copy=_stale(), origin_copy=_current())
    proc = host.run(CHECK="1", DEPLOY_REF="main", REDEPLOY_REEXEC="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.splitlines() == ["redeploy: fetching origin/main", *host.launch_lines("PHASE1_ONLY=1")]
    assert host.argv() == host.expected_argv("PHASE1_ONLY=1")
    assert host.leftovers() == []


# --------------------------------------------------------------------------- #
# 2. A copy identical to origin/main's runs as it is
# --------------------------------------------------------------------------- #
def test_matching_copy_does_not_reexec(tmp_path: Path) -> None:
    """A and B differ (deploy.sh), their redeploy.sh does not: no re-exec, one fetch."""
    host = Host(tmp_path, checkout_copy=_current(), origin_copy=_current())
    proc = host.run(DEPLOY_REF="main")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.splitlines() == ["redeploy: fetching origin/main", *host.launch_lines("DEPLOY_REF=main")]
    assert "WARN" not in proc.stderr
    assert host.argv() == host.expected_argv("DEPLOY_REF=main")
    assert host.leftovers() == [], "the temp copy made for the comparison is removed"


ORIGIN_STUB = 'echo "origin copy ran:" "$@"\n'


def _drive(tmp: Path, host: Host, self_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Source the real redeploy.sh and call reexec_from_origin_main in the checkout.

    REDEPLOY_SELFTEST is set but NOT exported, so a copy the call execs runs as a
    script, not through the seam."""
    quoted = " ".join(f"'{a}'" for a in args)
    driver = tmp / "driver.sh"
    driver.write_text(
        "REDEPLOY_SELFTEST=1\n"
        f'source "{REDEPLOY_SH}"\n'
        "unset REDEPLOY_SELFTEST\n"
        f'cd "{host.app}"\n'
        "env -0 > \"$BEFORE\"\n"
        f'reexec_from_origin_main "{self_path}" {quoted}\n'
        'echo "continued with this copy"\n',
        encoding="utf-8",
    )
    env = {**host.env, "BEFORE": str(tmp / "env.before"), "AFTER": str(tmp / "env.after")}
    return subprocess.run(["bash", str(driver)], cwd=str(tmp), env=env, capture_output=True, text=True,
                          encoding="utf-8")


@pytest.mark.parametrize(
    ("self_bytes", "reexecs"),
    [(ORIGIN_STUB, False), (ORIGIN_STUB + "\n", True), (ORIGIN_STUB.rstrip("\n"), True)],
    ids=["identical", "extra-trailing-newline", "missing-trailing-newline"],
)
def test_comparison_is_byte_for_byte(tmp_path: Path, self_bytes: str, reexecs: bool) -> None:
    host = Host(tmp_path, checkout_copy=_current(), origin_copy=ORIGIN_STUB)
    self_path = tmp_path / "self.sh"
    self_path.write_text(self_bytes, encoding="utf-8")
    proc = _drive(tmp_path, host, self_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    if reexecs:
        assert proc.stdout == f"redeploy: re-exec from origin/main ({host.b})\norigin copy ran:\n"
    else:
        assert proc.stdout == "continued with this copy\n"
        assert host.leftovers() == []
    assert proc.stderr == ""


# --------------------------------------------------------------------------- #
# 3. The loop guard, and the temp file deleting itself (and only itself)
# --------------------------------------------------------------------------- #
def test_loop_guard_never_reexecs_a_second_time(tmp_path: Path) -> None:
    """REDEPLOY_REEXEC=1: no git show, no comparison, no re-exec, even though the copies differ."""
    host = Host(tmp_path, checkout_copy=_current(), origin_copy=ORIGIN_STUB)
    self_path = tmp_path / "self.sh"
    self_path.write_text("something else\n", encoding="utf-8")
    host.env["REDEPLOY_REEXEC"] = "1"
    proc = _drive(tmp_path, host, self_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "continued with this copy\n"
    assert proc.stderr == ""
    assert host.leftovers() == []


def _copy_of_redeploy(tmp: Path) -> Path:
    copy = tmp / "copy" / "redeploy.sh"
    copy.parent.mkdir()
    copy.write_bytes(REDEPLOY_SH.read_bytes())
    return copy


@pytest.mark.parametrize(
    ("reexec", "point_at_self", "deleted"),
    [("1", True, True), ("", True, False), ("0", True, False), ("1", False, False)],
    ids=["reexec-run-deletes-itself", "no-marker", "marker-0", "marker-but-other-file"],
)
def test_temp_copy_deletes_itself_and_nothing_else(
    tmp_path: Path, reexec: str, point_at_self: bool, deleted: bool
) -> None:
    """The run stops at REDEPLOY_ATTACH's refusal, which comes after the deletion: a
    message from it proves bash reads on from the descriptor of the deleted file."""
    copy = _copy_of_redeploy(tmp_path)
    decoy = tmp_path / "decoy.sh"
    decoy.write_text("keep me\n", encoding="utf-8")
    env = _base_env(tmp_path)
    env.update(REDEPLOY_ATTACH="bogus", REDEPLOY_REEXEC_FILE=str(copy if point_at_self else decoy))
    if reexec:
        env["REDEPLOY_REEXEC"] = reexec
    proc = subprocess.run(["bash", str(copy)], cwd=str(tmp_path), env=env, capture_output=True, text=True,
                          encoding="utf-8")
    assert proc.returncode == 1
    assert "REDEPLOY_ATTACH must be pty or pipe, got 'bogus'" in proc.stderr
    assert copy.exists() is not deleted
    assert decoy.exists(), "only the exact file this run executes is ever deleted"
    assert not (tmp_path / "calls").exists(), "nothing ran past the refusal"


# --------------------------------------------------------------------------- #
# 4. origin/main's copy unusable: WARN, and the current copy carries on
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("origin_copy", "why"),
    [
        # git words the rest by what is on disk ("does not exist in" / "exists on disk, but not in").
        (None, "git show {b}:scripts/redeploy.sh failed: fatal: path 'scripts/redeploy.sh' "),
        ("", "origin/main's scripts/redeploy.sh ({b}) is empty"),
        ("fi\n", "origin/main's scripts/redeploy.sh ({b}) does not parse (bash -n)"),
    ],
    ids=["missing-in-origin-main", "empty", "does-not-parse"],
)
def test_unusable_origin_copy_warns_and_the_current_copy_carries_on(
    tmp_path: Path, origin_copy: str | None, why: str
) -> None:
    host = Host(tmp_path, checkout_copy=_current(), origin_copy=origin_copy)
    proc = host.run(DEPLOY_REF="main")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    first, second = proc.stderr.splitlines()[-2:]
    assert first.startswith(f"redeploy: WARN: cannot run origin/main's copy of this wrapper — {why.format(b=host.b)}")
    assert second == (
        f"redeploy: WARN:   continuing with THIS copy ({host.app.resolve()}/scripts/redeploy.sh): "
        "a name added to DEPLOY_ENV_PASSTHROUGH after it was written is NOT forwarded — "
        "check the 'deploy.sh env:' line below"
    )
    assert proc.stdout.splitlines() == ["redeploy: fetching origin/main", *host.launch_lines("DEPLOY_REF=main")]
    assert host.argv() == host.expected_argv("DEPLOY_REF=main")
    assert host.leftovers() == []


def test_no_origin_main_warns_and_returns(tmp_path: Path) -> None:
    """Called where origin/main does not resolve: WARN, back to the caller."""
    host = Host(tmp_path, checkout_copy=_current(), origin_copy=_current())
    host.git(host.app, "update-ref", "-d", "refs/remotes/origin/main")
    proc = _drive(tmp_path, host, REDEPLOY_SH)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "continued with this copy\n"
    assert proc.stderr.startswith(
        "redeploy: WARN: cannot run origin/main's copy of this wrapper — origin/main does not resolve\n"
    )
    assert host.leftovers() == []


# --------------------------------------------------------------------------- #
# 5. The mechanism: same argv, same environment, origin/main's bytes in a 0700 file
# --------------------------------------------------------------------------- #
DUMPER = """\
printf 'argc=%s\\n' "$#"
printf 'arg=[%s]\\n' "$@"
printf 'self=%s\\n' "$0"
env -0 > "$AFTER"
"""


def test_reexec_keeps_argv_and_environment(tmp_path: Path) -> None:
    host = Host(tmp_path, checkout_copy=_current(), origin_copy=DUMPER)
    host.env.update(DEPLOY_REF="main", CHECK="1")
    proc = _drive(tmp_path, host, REDEPLOY_SH, "two words", "", "-x")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    assert lines[0] == f"redeploy: re-exec from origin/main ({host.b})"
    assert lines[1:5] == ["argc=3", "arg=[two words]", "arg=[]", "arg=[-x]"]
    assert "continued with this copy" not in proc.stdout, "exec does not come back"

    temp = Path(lines[5].removeprefix("self="))
    assert temp.parent == host.tmpdir
    assert temp.read_text(encoding="utf-8") == DUMPER, "origin/main's exact bytes"
    assert temp.stat().st_mode & 0o777 == 0o700

    def environ(name: str) -> dict[str, str]:
        raw = (tmp_path / name).read_text(encoding="utf-8")
        pairs = (item.split("=", 1) for item in raw.split("\0") if item)
        return {k: v for k, v in pairs if k not in ("_", "SHLVL")}

    before, after = environ("env.before"), environ("env.after")
    assert after == {**before, "REDEPLOY_REEXEC": "1", "REDEPLOY_REEXEC_FILE": str(temp)}
    assert before["DEPLOY_REF"] == "main" and "REDEPLOY_SELFTEST" not in after
