"""Refusal branches of the root helpers — the privilege boundary.

deploy/helpers/vpn-bot-{awg,xray,mtproxy}-apply and vpn-bot-socks5-user run
as root via sudo with arguments the (unprivileged) bot controls. Every way they
can say "no" — argument, path and name validation, malformed inputs, failed
tools, rollback — is pinned here, together with the exit code the bot relies
on (64 = validation, 70 = command failed).

Hermetic by construction:
* every path constant is pointed into tmp_path;
* the module's ``subprocess`` is replaced by a scripted recorder, so
  systemctl/awg/xray/ss/nsenter/useradd never run;
* ``os.chown`` is recorded instead of executed (CI is not root), and the
  ``grp``/``pwd`` lookups are faked, so the host's user database is never read;
* the MTProxy port poll uses a fake clock — no sleeping.
"""

from __future__ import annotations

import grp
import io
import json
import os
import pwd
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

EXIT_VALIDATION = 64
EXIT_COMMAND_FAILED = 70
SECRET_HEX = "0123456789abcdef0123456789abcdef"
SS_HEADER = "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"


class FakeRun:
    """Stands in for subprocess.run: records argv, answers by argv prefix."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.rules: list[tuple[tuple[str, ...], int, str, str, BaseException | None]] = []

    def on(self, *prefix: str, rc: int = 0, stdout: str = "", stderr: str = "", exc: BaseException | None = None) -> None:
        # Later rules win, so a test can override a fixture default.
        self.rules.insert(0, (prefix, rc, stdout, stderr, exc))

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert isinstance(args, list) and kwargs.get("shell") is None
        self.calls.append(list(args))
        for prefix, rc, out, err, exc in self.rules:
            if tuple(args[: len(prefix)]) == prefix:
                if exc is not None:
                    raise exc
                return subprocess.CompletedProcess(args, rc, out, err)
        return subprocess.CompletedProcess(args, 0, "", "")

    def argv0s(self) -> list[str]:
        return [" ".join(call[:2]) for call in self.calls]


class OsProxy:
    """The real os module, except chown is recorded (CI runs unprivileged)."""

    def __init__(self) -> None:
        self.chowns: list[tuple[Path, int, int]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(os, name)

    def chown(self, path: Any, uid: int, gid: int) -> None:
        self.chowns.append((Path(path), uid, gid))


def _fake_getgrnam(name: str) -> Any:
    if name == "vpn-bot":
        return SimpleNamespace(gr_gid=4242)
    raise KeyError(name)


def _fake_getpwnam(name: str) -> Any:
    if name == "nobody":
        return SimpleNamespace(pw_uid=65534)
    raise KeyError(name)


def _hermetic(monkeypatch: pytest.MonkeyPatch, helper: ModuleType) -> tuple[FakeRun, OsProxy]:
    run = FakeRun()
    proxy = OsProxy()
    monkeypatch.setattr(
        helper,
        "subprocess",
        SimpleNamespace(
            run=run, PIPE=subprocess.PIPE, DEVNULL=subprocess.DEVNULL, CompletedProcess=subprocess.CompletedProcess
        ),
    )
    if hasattr(helper, "os"):  # vpn-bot-socks5-user never touches the filesystem
        monkeypatch.setattr(helper, "os", proxy)
    monkeypatch.setattr(grp, "getgrnam", _fake_getgrnam)
    monkeypatch.setattr(pwd, "getpwnam", _fake_getpwnam)
    return run, proxy


def _code(helper: ModuleType, fn: Callable[[], object]) -> tuple[int, str]:
    with pytest.raises(helper.HelperError) as excinfo:
        fn()
    return excinfo.value.code, str(excinfo.value)


# ── file-apply helpers (awg / xray): shared fixture ──────────────────────────


@pytest.fixture(params=["vpn-bot-awg-apply", "vpn-bot-xray-apply"])
def file_helper(request: pytest.FixtureRequest, load_helper: Callable[[str], ModuleType], tmp_path: Path,
                monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    helper = load_helper(request.param)
    run, proxy = _hermetic(monkeypatch, helper)
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setattr(helper, "STAGING_ROOT", staging)
    monkeypatch.setattr(helper, "CANONICAL_CONFIG", tmp_path / "etc" / "svc" / "config")
    run.on("systemctl", "is-active", stdout="active\n")
    return SimpleNamespace(h=helper, run=run, os=proxy, staging=staging, tmp=tmp_path, name=request.param)


@pytest.fixture
def awg(load_helper: Callable[[str], ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    helper = load_helper("vpn-bot-awg-apply")
    run, proxy = _hermetic(monkeypatch, helper)
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setattr(helper, "STAGING_ROOT", staging)
    monkeypatch.setattr(helper, "CANONICAL_CONFIG", tmp_path / "etc" / "amnezia" / "awg0.conf")
    run.on("systemctl", "is-active", stdout="active\n")
    run.on("awg-quick", "strip", stdout="[Interface]\nPrivateKey = stripped\n")
    candidate = staging / "candidate.conf"
    candidate.write_text("[Interface]\nPrivateKey = NEW\n", encoding="utf-8")
    return SimpleNamespace(h=helper, run=run, os=proxy, staging=staging, candidate=candidate, tmp=tmp_path)


@pytest.fixture
def xray(load_helper: Callable[[str], ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    helper = load_helper("vpn-bot-xray-apply")
    run, proxy = _hermetic(monkeypatch, helper)
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setattr(helper, "STAGING_ROOT", staging)
    monkeypatch.setattr(helper, "CANONICAL_CONFIG", tmp_path / "usr" / "local" / "etc" / "xray" / "config.json")
    run.on("systemctl", "is-active", stdout="active\n")
    candidate = staging / "candidate.json"
    candidate.write_text('{"inbounds": []}', encoding="utf-8")
    return SimpleNamespace(h=helper, run=run, os=proxy, staging=staging, candidate=candidate, tmp=tmp_path)


# ── candidate path validation (awg + xray, identical contract) ───────────────


# Invariant: a relative candidate path is refused (exit 64) before the
# filesystem is consulted.
def test_candidate_relative_path_refused(file_helper: SimpleNamespace) -> None:
    # Arrange
    h = file_helper.h

    # Act
    code, message = _code(h, lambda: h.validate_candidate_path("staging/candidate"))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "candidate path must be absolute")


# Invariant: a candidate that is itself a symlink is refused (exit 64), even
# when it points inside the staging root.
def test_candidate_symlink_refused(file_helper: SimpleNamespace) -> None:
    # Arrange
    real = file_helper.staging / "real"
    real.write_text("{}", encoding="utf-8")
    link = file_helper.staging / "link"
    link.symlink_to(real)

    # Act
    code, message = _code(file_helper.h, lambda: file_helper.h.validate_candidate_path(str(link)))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "candidate path must not be a symlink")


# Invariant: a candidate that does not exist is refused (exit 64).
def test_candidate_missing_refused(file_helper: SimpleNamespace) -> None:
    # Arrange
    missing = file_helper.staging / "nope"

    # Act
    code, message = _code(file_helper.h, lambda: file_helper.h.validate_candidate_path(str(missing)))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "candidate path does not exist")


# Invariant: a staging root that is a symlink (planted by the bot user to
# retarget the allowed prefix) refuses every candidate (exit 64).
def test_symlinked_staging_root_refused(file_helper: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    target = file_helper.tmp / "elsewhere"
    target.mkdir()
    (target / "candidate").write_text("{}", encoding="utf-8")
    link_root = file_helper.tmp / "staging-link"
    link_root.symlink_to(target)
    monkeypatch.setattr(file_helper.h, "STAGING_ROOT", link_root)

    # Act
    code, message = _code(file_helper.h, lambda: file_helper.h.validate_candidate_path(str(target / "candidate")))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "staging root must not be a symlink")


# Invariant: any candidate resolving outside the staging root is refused (exit
# 64) — a plain outside path, a `..` traversal, and a path through a symlinked
# subdirectory alike.
@pytest.mark.parametrize("shape", ["outside", "dotdot", "symlinked-parent"])
def test_candidate_outside_staging_refused(file_helper: SimpleNamespace, shape: str) -> None:
    # Arrange
    outside_dir = file_helper.tmp / "outside"
    outside_dir.mkdir()
    (outside_dir / "candidate").write_text("{}", encoding="utf-8")
    if shape == "outside":
        raw = str(outside_dir / "candidate")
    elif shape == "dotdot":
        raw = str(file_helper.staging / ".." / "outside" / "candidate")
    else:
        (file_helper.staging / "sub").symlink_to(outside_dir)
        raw = str(file_helper.staging / "sub" / "candidate")

    # Act
    code, message = _code(file_helper.h, lambda: file_helper.h.validate_candidate_path(raw))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "candidate path outside staging root")


# Invariant: a directory inside the staging root is not a candidate (exit 64).
def test_candidate_directory_refused(file_helper: SimpleNamespace) -> None:
    # Arrange
    directory = file_helper.staging / "dir"
    directory.mkdir()

    # Act
    code, message = _code(file_helper.h, lambda: file_helper.h.validate_candidate_path(str(directory)))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "candidate path must be a file")


# Invariant: a regular file inside the staging root is accepted and returned
# resolved.
def test_candidate_inside_staging_accepted(file_helper: SimpleNamespace) -> None:
    # Arrange
    candidate = file_helper.staging / "ok"
    candidate.write_text("{}", encoding="utf-8")

    # Act
    resolved = file_helper.h.validate_candidate_path(str(candidate))

    # Assert
    assert resolved == candidate.resolve()


# Invariant: the CLI refuses a missing candidate argument and an unknown action
# at argparse level (exit 2) — nothing runs.
@pytest.mark.parametrize("argv", [["apply"], ["validate"], ["frobnicate"], []])
def test_cli_rejects_malformed_arguments(file_helper: SimpleNamespace, argv: list[str]) -> None:
    # Arrange
    h = file_helper.h

    # Act
    with pytest.raises(SystemExit) as excinfo:
        h.main(argv, stdout=io.StringIO(), stderr=io.StringIO())

    # Assert
    assert excinfo.value.code == 2
    assert file_helper.run.calls == []


# Invariant: a refused candidate surfaces through main() as "error: <reason>"
# on stderr with exit 64, and never touches the canonical config.
def test_cli_reports_refusal_with_validation_code(file_helper: SimpleNamespace) -> None:
    # Arrange
    stderr = io.StringIO()

    # Act
    rc = file_helper.h.main(["apply", "relative/path"], stdout=io.StringIO(), stderr=stderr)

    # Assert
    assert rc == EXIT_VALIDATION
    assert stderr.getvalue() == "error: candidate path must be absolute\n"
    assert not file_helper.h.CANONICAL_CONFIG.exists()


# Invariant: the final-owner lookup refuses (exit 64) when the required group
# (or, for xray, user) is missing, instead of chowning to a wrong id.
def test_missing_final_group_refused(file_helper: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(file_helper.h, "FINAL_GROUP", "no-such-group")
    lookup = getattr(file_helper.h, "_lookup_final_gid", None) or file_helper.h._lookup_final_ids

    # Act
    code, message = _code(file_helper.h, lookup)

    # Assert
    assert code == EXIT_VALIDATION
    assert "missing" in message


# Invariant: a candidate swapped for a symlink between validation and install
# is refused by O_NOFOLLOW (exit 64) and leaves no temp file behind.
def test_install_refuses_symlink_swapped_candidate(file_helper: SimpleNamespace) -> None:
    # Arrange
    real = file_helper.tmp / "secret-target"
    real.write_text("root-only", encoding="utf-8")
    swapped = file_helper.staging / "swapped"
    swapped.symlink_to(real)

    # Act
    code, message = _code(file_helper.h, lambda: file_helper.h.install_candidate(swapped))

    # Assert
    assert code == EXIT_VALIDATION and message.startswith("cannot open candidate")
    leftovers = [p.name for p in file_helper.h.CANONICAL_CONFIG.parent.iterdir()]
    assert leftovers == []


# Invariant: `validate` on a good candidate succeeds WITHOUT installing it or
# touching the service — it is a dry run.
@pytest.mark.parametrize("helper_fixture", ["awg", "xray"])
def test_validate_is_a_dry_run(request: pytest.FixtureRequest, helper_fixture: str) -> None:
    # Arrange
    world = request.getfixturevalue(helper_fixture)

    # Act
    rc = world.h.main(["validate", str(world.candidate)], stdout=io.StringIO(), stderr=io.StringIO())

    # Assert
    assert rc == 0
    assert not world.h.CANONICAL_CONFIG.exists()
    assert not [c for c in world.run.calls if c[0] == "systemctl"]


# ── awg-apply specifics ──────────────────────────────────────────────────────


# Invariant: a config that awg-quick strip rejects fails validation (exit 70),
# and the root-owned strip copy is always removed.
def test_awg_strip_rejection(awg: SimpleNamespace) -> None:
    # Arrange
    awg.run.on("awg-quick", "strip", rc=1, stderr="Line unrecognized")

    # Act
    code, message = _code(awg.h, lambda: awg.h.action_validate(str(awg.candidate)))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "AWG config validation failed")
    assert list(awg.h.CANONICAL_CONFIG.parent.glob("*.strip")) == []


# Invariant: when awg-quick is absent (127) the strip falls back to wg-quick.
def test_awg_strip_falls_back_to_wg_quick(awg: SimpleNamespace) -> None:
    # Arrange
    awg.run.on("awg-quick", exc=FileNotFoundError("awg-quick"))
    awg.run.on("wg-quick", "strip", stdout="ok")

    # Act
    stripped = awg.h.quick_strip(awg.candidate)

    # Assert
    assert stripped == "ok"
    assert [c[0] for c in awg.run.calls] == ["awg-quick", "wg-quick"]


# Invariant: a candidate swapped for a symlink before strip is refused by
# O_NOFOLLOW (exit 64).
def test_awg_strip_refuses_symlink(awg: SimpleNamespace) -> None:
    # Arrange
    real = awg.tmp / "shadow"
    real.write_text("x", encoding="utf-8")
    link = awg.staging / "link.conf"
    link.symlink_to(real)

    # Act
    code, message = _code(awg.h, lambda: awg.h.quick_strip(link))

    # Assert
    assert code == EXIT_VALIDATION and message.startswith("cannot open candidate")


# Invariant: awg/wg missing entirely is reported as rc 127 (never an uncaught
# FileNotFoundError), and `awg` falls back to `wg`.
def test_awg_tool_fallback_and_missing(awg: SimpleNamespace) -> None:
    # Arrange
    awg.run.on("awg", exc=FileNotFoundError("awg"))
    awg.run.on("wg", exc=FileNotFoundError("wg"))

    # Act
    result = awg.h.run_awg_or_wg(["show", "awg0"])

    # Assert
    assert result.returncode == 127
    assert [c[0] for c in awg.run.calls] == ["awg", "wg"]


# Invariant: a failed syncconf fails the runtime sync (exit 70) and the
# root-only stripped copy is removed.
def test_awg_syncconf_failure(awg: SimpleNamespace) -> None:
    # Arrange
    awg.run.on("awg", "syncconf", rc=1)
    awg.h.CANONICAL_CONFIG.parent.mkdir(parents=True)

    # Act
    code, message = _code(awg.h, lambda: awg.h.sync_runtime("[Interface]\n"))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "AWG syncconf failed")
    assert list(awg.h.CANONICAL_CONFIG.parent.glob("*.stripped")) == []


# Invariant: a sync whose service is not active afterwards is a failure.
def test_awg_service_inactive_after_sync(awg: SimpleNamespace) -> None:
    # Arrange
    awg.run.on("systemctl", "is-active", rc=3, stdout="failed\n")
    awg.h.CANONICAL_CONFIG.parent.mkdir(parents=True)

    # Act
    code, message = _code(awg.h, lambda: awg.h.sync_runtime("[Interface]\n"))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "AWG service is not active")


# Invariant: a failed apply restores the previous config byte-for-byte and
# reports "previous config restored" (exit 70).
def test_awg_apply_failure_restores_previous(awg: SimpleNamespace) -> None:
    # Arrange
    awg.h.CANONICAL_CONFIG.parent.mkdir(parents=True)
    awg.h.CANONICAL_CONFIG.write_text("[Interface]\nPrivateKey = OLD\n", encoding="utf-8")
    syncs = {"n": 0}
    real_run = awg.run

    def first_sync_fails(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["awg", "syncconf"]:
            syncs["n"] += 1
            if syncs["n"] == 1:
                real_run.calls.append(list(args))
                return subprocess.CompletedProcess(args, 1, "", "bad peer")
        return real_run(args, **kwargs)

    awg.h.subprocess.run = first_sync_fails

    # Act
    code, message = _code(awg.h, lambda: awg.h.action_apply(str(awg.candidate)))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "AWG apply failed; previous config restored")
    assert awg.h.CANONICAL_CONFIG.read_text(encoding="utf-8") == "[Interface]\nPrivateKey = OLD\n"
    assert syncs["n"] == 2


# Invariant: when the rollback ALSO fails the helper says so explicitly
# ("rollback failed", exit 70) — never claims the old config is back.
def test_awg_apply_rollback_failure(awg: SimpleNamespace) -> None:
    # Arrange
    awg.h.CANONICAL_CONFIG.parent.mkdir(parents=True)
    awg.h.CANONICAL_CONFIG.write_text("OLD", encoding="utf-8")
    awg.run.on("awg", "syncconf", rc=1)

    # Act
    code, message = _code(awg.h, lambda: awg.h.action_apply(str(awg.candidate)))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "AWG apply failed and rollback failed")


# Invariant: with no previous config, a failed apply removes the half-installed
# one instead of leaving the new (unsynced) config in place.
def test_awg_apply_failure_without_backup_removes_config(awg: SimpleNamespace) -> None:
    # Arrange
    awg.run.on("awg", "syncconf", rc=1)

    # Act
    code, _ = _code(awg.h, lambda: awg.h.action_apply(str(awg.candidate)))

    # Assert
    assert code == EXIT_COMMAND_FAILED
    assert not awg.h.CANONICAL_CONFIG.exists()


# Invariant: a successful apply installs the candidate with the final owner
# (root:vpn-bot) and mode 0640.
def test_awg_apply_success_sets_final_stat(awg: SimpleNamespace) -> None:
    # Arrange — fixture candidate, everything succeeds

    # Act
    rc = awg.h.main(["apply", str(awg.candidate)], stdout=io.StringIO(), stderr=io.StringIO())

    # Assert
    assert rc == 0
    assert awg.h.CANONICAL_CONFIG.read_text(encoding="utf-8") == "[Interface]\nPrivateKey = NEW\n"
    assert oct(awg.h.CANONICAL_CONFIG.stat().st_mode & 0o777) == "0o640"
    # The owner is set on the temp file BEFORE the atomic rename onto the canonical path.
    assert any(path.name.endswith('.tmp') and (uid, gid) == (0, 4242) for path, uid, gid in awg.os.chowns)


# Invariant: the read-only actions print only on success and return the tool's
# exit code unchanged.
@pytest.mark.parametrize(
    ("action", "prefix", "rc", "stdout", "printed"),
    [
        ("status", ("systemctl", "is-active"), 3, "inactive\n", "inactive\n"),
        ("show-peers", ("awg", "show"), 0, "peer: X\n", "peer: X\n"),
        ("show-peers", ("awg", "show"), 1, "partial", ""),
        ("show-transfer", ("awg", "show"), 0, "X\t1\t2\n", "X\t1\t2\n"),
    ],
)
def test_awg_read_only_actions(awg: SimpleNamespace, action: str, prefix: tuple[str, ...], rc: int, stdout: str,
                               printed: str) -> None:
    # Arrange
    awg.run.on(*prefix, rc=rc, stdout=stdout)
    out = io.StringIO()

    # Act
    result = awg.h.main([action], stdout=out, stderr=io.StringIO())

    # Assert
    assert result == rc
    assert out.getvalue() == printed


# ── xray-apply specifics ─────────────────────────────────────────────────────


# Invariant: the candidate must be a JSON object — invalid JSON, a non-object
# and a symlink-swapped file are all refused (exit 64) before xray runs.
@pytest.mark.parametrize(
    ("content", "message"),
    [("{not json", "candidate JSON is invalid"), ("[1, 2]", "candidate JSON must be an object")],
)
def test_xray_json_refusals(xray: SimpleNamespace, content: str, message: str) -> None:
    # Arrange
    xray.candidate.write_text(content, encoding="utf-8")

    # Act
    code, got = _code(xray.h, lambda: xray.h.action_validate(str(xray.candidate)))

    # Assert
    assert (code, got) == (EXIT_VALIDATION, message)
    assert xray.run.calls == []


# Invariant: a symlink-swapped candidate is refused by O_NOFOLLOW at JSON
# validation.
def test_xray_json_refuses_symlink(xray: SimpleNamespace) -> None:
    # Arrange
    real = xray.tmp / "other.json"
    real.write_text("{}", encoding="utf-8")
    link = xray.staging / "link.json"
    link.symlink_to(real)

    # Act
    code, message = _code(xray.h, lambda: xray.h.validate_json(link))

    # Assert
    assert code == EXIT_VALIDATION and message.startswith("cannot open candidate")


# Invariant: `xray run -test` rejecting the config fails validation (exit 70).
def test_xray_test_config_rejection(xray: SimpleNamespace) -> None:
    # Arrange
    xray.run.on(xray.h.XRAY_BIN, rc=23)

    # Act
    code, message = _code(xray.h, lambda: xray.h.action_validate(str(xray.candidate)))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "Xray config validation failed")


# Invariant: a missing binary is a clean HelperError (exit 70), not a crash.
def test_xray_missing_binary(xray: SimpleNamespace) -> None:
    # Arrange
    xray.run.on(xray.h.XRAY_BIN, exc=FileNotFoundError("xray"))

    # Act
    code, message = _code(xray.h, lambda: xray.h.xray_test_config(xray.candidate))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "required command not found")


# Invariant: a failed restart, or a service not active after restart, fails
# verification (exit 70).
@pytest.mark.parametrize(
    ("rule", "message"),
    [
        ((("systemctl", "restart"), 1, ""), "Xray restart failed"),
        ((("systemctl", "is-active"), 3, "failed\n"), "Xray service is not active"),
    ],
)
def test_xray_restart_verification(xray: SimpleNamespace, rule: tuple[tuple[str, ...], int, str], message: str) -> None:
    # Arrange
    prefix, rc, stdout = rule
    xray.run.on(*prefix, rc=rc, stdout=stdout)

    # Act
    code, got = _code(xray.h, xray.h.restart_and_verify)

    # Assert
    assert (code, got) == (EXIT_COMMAND_FAILED, message)


# Invariant: the final owner lookup refuses a missing user as well as a missing
# group (exit 64).
def test_xray_missing_final_user(xray: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(xray.h, "FINAL_USER", "no-such-user")

    # Act
    code, message = _code(xray.h, xray.h._lookup_final_ids)

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "required final owner/group is missing")


# Invariant: a failed apply restores the previous config and re-verifies the
# service ("previous config restored"); if the re-verification fails too, it
# says "rollback failed".
@pytest.mark.parametrize("rollback_ok", [True, False])
def test_xray_apply_failure_and_rollback(xray: SimpleNamespace, rollback_ok: bool) -> None:
    # Arrange
    xray.h.CANONICAL_CONFIG.parent.mkdir(parents=True)
    xray.h.CANONICAL_CONFIG.write_text('{"old": true}', encoding="utf-8")
    restarts = {"n": 0}
    real_run = xray.run

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["systemctl", "restart"]:
            restarts["n"] += 1
            ok = restarts["n"] > 1 and rollback_ok
            return subprocess.CompletedProcess(args, 0 if ok else 1, "", "")
        return real_run(args, **kwargs)

    xray.h.subprocess.run = run

    # Act
    code, message = _code(xray.h, lambda: xray.h.action_apply(str(xray.candidate)))

    # Assert
    assert code == EXIT_COMMAND_FAILED
    if rollback_ok:
        assert message == "Xray apply failed; previous config restored"
    else:
        assert message == "Xray apply failed and rollback failed"
    assert xray.h.CANONICAL_CONFIG.read_text(encoding="utf-8") == '{"old": true}'


# Invariant: with no previous config, a failed apply removes the new one.
def test_xray_apply_failure_without_backup_removes_config(xray: SimpleNamespace) -> None:
    # Arrange
    restarts = {"n": 0}
    real_run = xray.run

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["systemctl", "restart"]:
            restarts["n"] += 1
            return subprocess.CompletedProcess(args, 1 if restarts["n"] == 1 else 0, "", "")
        return real_run(args, **kwargs)

    xray.h.subprocess.run = run

    # Act
    _, message = _code(xray.h, lambda: xray.h.action_apply(str(xray.candidate)))

    # Assert
    assert message == "Xray apply failed; previous config restored"
    assert not xray.h.CANONICAL_CONFIG.exists()


# Invariant: a successful apply installs nobody:vpn-bot 0640, and a config
# directory the helper had to create is widened to 0755 (traversable by the
# service user) while one that already existed is left alone.
@pytest.mark.parametrize("dir_preexists", [False, True])
def test_xray_apply_success_dir_mode(xray: SimpleNamespace, dir_preexists: bool) -> None:
    # Arrange
    if dir_preexists:
        xray.h.CANONICAL_CONFIG.parent.mkdir(parents=True, mode=0o700)
        os.chmod(xray.h.CANONICAL_CONFIG.parent, 0o700)

    # Act
    rc = xray.h.main(["apply", str(xray.candidate)], stdout=io.StringIO(), stderr=io.StringIO())

    # Assert
    assert rc == 0
    assert any(path.name.endswith('.tmp') and (uid, gid) == (65534, 4242) for path, uid, gid in xray.os.chowns)
    dir_mode = oct(xray.h.CANONICAL_CONFIG.parent.stat().st_mode & 0o777)
    assert dir_mode == ("0o700" if dir_preexists else "0o755")


# Invariant: status prints the service state and returns systemctl's rc.
def test_xray_status(xray: SimpleNamespace) -> None:
    # Arrange
    out = io.StringIO()

    # Act
    rc = xray.h.main(["status"], stdout=out, stderr=io.StringIO())

    # Assert
    assert (rc, out.getvalue()) == (0, "active\n")


# ── mtproxy-apply ────────────────────────────────────────────────────────────


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _secrets(**overrides: Any) -> str:
    data: dict[str, Any] = {
        "version": 1,
        "generation": 3,
        "secrets": [{"secret": SECRET_HEX, "fingerprint": "fp", "owner_user_id": 1, "access_id": 2}],
        "runtime_secrets": [],
    }
    data.update(overrides)
    return json.dumps(data)


VALID_ENV = "MTPROTO_BINARY_PATH=/usr/local/bin/mtproto-proxy\nMTPROTO_PORT=8443\n"


@pytest.fixture
def mtp(load_helper: Callable[[str], ModuleType], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    helper = load_helper("vpn-bot-mtproxy-apply")
    run, proxy = _hermetic(monkeypatch, helper)
    staging = tmp_path / "staging"
    candidate = staging / "c1"
    candidate.mkdir(parents=True)
    target = tmp_path / "etc" / "mtproxy" / "vpn-bot"
    monkeypatch.setattr(helper, "STAGING_ROOT", staging)
    monkeypatch.setattr(helper, "TARGET_DIR", target)
    monkeypatch.setattr(helper, "TARGET_SECRETS", target / "managed-secrets.json")
    monkeypatch.setattr(helper, "TARGET_ENV", target / "mtproxy.env")
    clock = FakeClock()
    monkeypatch.setattr(helper, "time", SimpleNamespace(time_ns=time.time_ns, monotonic=clock.monotonic, sleep=clock.sleep))
    run.on("systemctl", "is-active", stdout="active\n")
    run.on("ss", "-tln", stdout=SS_HEADER + "LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:*\n")
    (candidate / "managed-secrets.json").write_text(_secrets(), encoding="utf-8")
    (candidate / "mtproxy.env").write_text(VALID_ENV, encoding="utf-8")
    return SimpleNamespace(h=helper, run=run, os=proxy, staging=staging, candidate=candidate, target=target,
                           clock=clock, tmp=tmp_path)


# Invariant: the candidate DIRECTORY gets the same path checks as a file
# candidate — relative, symlink, missing, symlinked root, outside root and
# not-a-directory are all refused (exit 64).
@pytest.mark.parametrize("shape", ["relative", "symlink", "missing", "root-symlink", "outside", "file"])
def test_mtproxy_candidate_dir_refusals(mtp: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
    # Arrange
    h = mtp.h
    expected = {
        "relative": "candidate path must be absolute",
        "symlink": "candidate path must not be a symlink",
        "missing": "candidate path does not exist",
        "root-symlink": "staging root must not be a symlink",
        "outside": "candidate path outside staging root",
        "file": "candidate path must be a directory",
    }[shape]
    if shape == "relative":
        raw = "staging/c1"
    elif shape == "symlink":
        link = mtp.staging / "link"
        link.symlink_to(mtp.candidate)
        raw = str(link)
    elif shape == "missing":
        raw = str(mtp.staging / "nope")
    elif shape == "root-symlink":
        link_root = mtp.tmp / "root-link"
        link_root.symlink_to(mtp.staging)
        monkeypatch.setattr(h, "STAGING_ROOT", link_root)
        raw = str(mtp.candidate)
    elif shape == "outside":
        other = mtp.tmp / "other"
        other.mkdir()
        raw = str(other)
    else:
        raw = str(mtp.candidate / "mtproxy.env")

    # Act
    code, message = _code(h, lambda: h.validate_candidate_dir(raw))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, expected)


# Invariant: each candidate FILE must be a regular, non-symlinked file that
# resolves inside the (resolved) candidate directory.
@pytest.mark.parametrize("shape", ["symlink", "missing", "directory", "outside"])
def test_mtproxy_candidate_file_refusals(mtp: SimpleNamespace, shape: str) -> None:
    # Arrange
    h = mtp.h
    name = "managed-secrets.json"
    candidate_dir = mtp.candidate
    (mtp.candidate / name).unlink()
    if shape == "symlink":
        real = mtp.tmp / "real.json"
        real.write_text("{}", encoding="utf-8")
        (mtp.candidate / name).symlink_to(real)
        expected = "candidate file must not be a symlink"
    elif shape == "missing":
        expected = "candidate file missing"
    elif shape == "directory":
        (mtp.candidate / name).mkdir()
        expected = "candidate file must be a regular file"
    else:
        # A caller passing an UNRESOLVED directory (defence in depth): the file
        # resolves through the symlinked dir to somewhere else.
        (mtp.candidate / name).write_text("{}", encoding="utf-8")
        candidate_dir = mtp.tmp / "dir-link"
        candidate_dir.symlink_to(mtp.candidate)
        expected = "candidate file outside candidate directory"

    # Act
    code, message = _code(h, lambda: h.candidate_file(candidate_dir, name))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, expected)


# Invariant: every malformed managed-secrets document is refused (exit 64):
# not JSON, not an object, wrong version, non-int generation, missing/non-list
# lists, and each malformed item field.
@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{oops", "managed secrets JSON is invalid"),
        ("[]", "managed secrets JSON must be an object"),
        (_secrets(version=2), "managed secrets JSON has unsupported version"),
        (_secrets(generation="3"), "managed secrets JSON has invalid generation"),
        (_secrets(secrets={"a": 1}), "managed secrets JSON has invalid list"),
        (json.dumps({"version": 1, "secrets": []}), "managed secrets JSON has invalid list"),
        (_secrets(secrets=["x"]), "managed secrets item must be an object"),
        (_secrets(secrets=[{"secret": "zz" * 16}]), "managed secrets JSON contains an invalid secret"),
        (_secrets(secrets=[{"secret": SECRET_HEX[:-2]}]), "managed secrets JSON contains an invalid secret"),
        (_secrets(secrets=[{"secret": 12345}]), "managed secrets JSON contains an invalid secret"),
        (_secrets(runtime_secrets=[{"fingerprint": 7}]), "managed secrets JSON contains an invalid fingerprint"),
        (_secrets(secrets=[{"owner_user_id": "1"}]), "managed secrets JSON contains an invalid integer"),
        (_secrets(secrets=[{"access_id": 1.5}]), "managed secrets JSON contains an invalid integer"),
    ],
)
def test_mtproxy_managed_secrets_refusals(mtp: SimpleNamespace, content: str, message: str) -> None:
    # Arrange
    path = mtp.candidate / "managed-secrets.json"
    path.write_text(content, encoding="utf-8")

    # Act
    code, got = _code(mtp.h, lambda: mtp.h.validate_managed_secrets(path))

    # Assert
    assert (code, got) == (EXIT_VALIDATION, message)


# Invariant: a well-formed document (nullable item fields included) passes.
def test_mtproxy_managed_secrets_accepts_valid(mtp: SimpleNamespace) -> None:
    # Arrange
    path = mtp.candidate / "managed-secrets.json"
    path.write_text(_secrets(runtime_secrets=[{"secret": None, "fingerprint": None, "owner_user_id": None}]),
                    encoding="utf-8")

    # Act
    result = mtp.h.validate_managed_secrets(path)

    # Assert
    assert result is None


# Invariant: the env file is an allowlist — bad lines, unknown keys, NUL bytes,
# a non-allowlisted binary and relative path values are all refused (exit 64).
@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("JUSTTEXT\n", "MTProxy env file has invalid line"),
        ("LD_PRELOAD=/tmp/x.so\n", "MTProxy env file has unsupported key"),
        ("MTPROTO_RUN_USER=no\x00body\n", "MTProxy env file has invalid value"),
        ("MTPROTO_BINARY_PATH=/bin/sh\n", "MTPROTO_BINARY_PATH is not in the allowlist"),
        ("MTPROTO_PROXY_SECRET_PATH=relative/secret\n", "MTProxy env path value must be absolute"),
    ],
)
def test_mtproxy_env_refusals(mtp: SimpleNamespace, content: str, message: str) -> None:
    # Arrange
    path = mtp.candidate / "mtproxy.env"
    path.write_text(content, encoding="utf-8")

    # Act
    code, got = _code(mtp.h, lambda: mtp.h.parse_env(path))

    # Assert
    assert (code, got) == (EXIT_VALIDATION, message)


# Invariant: blank lines are skipped and allowlisted keys are returned as-is.
def test_mtproxy_env_parses_valid(mtp: SimpleNamespace) -> None:
    # Arrange
    path = mtp.candidate / "mtproxy.env"
    path.write_text("\nMTPROTO_PORT=9443\n\nMTPROTO_WORKERS=2\n", encoding="utf-8")

    # Act
    values = mtp.h.parse_env(path)

    # Assert
    assert values == {"MTPROTO_PORT": "9443", "MTPROTO_WORKERS": "2"}


# Invariant: symlinked secrets/env files are refused by O_NOFOLLOW (exit 64).
@pytest.mark.parametrize("fn", ["validate_managed_secrets", "parse_env"])
def test_mtproxy_open_refuses_symlink(mtp: SimpleNamespace, fn: str) -> None:
    # Arrange
    real = mtp.tmp / "real"
    real.write_text("x", encoding="utf-8")
    link = mtp.candidate / "link"
    link.symlink_to(real)

    # Act
    code, message = _code(mtp.h, lambda: getattr(mtp.h, fn)(link))

    # Assert
    assert code == EXIT_VALIDATION and message.startswith("cannot open")


# Invariant: the port must be an integer in 1..65535; absent means 8443.
@pytest.mark.parametrize(("values", "expected"), [({}, 8443), ({"MTPROTO_PORT": "65535"}, 65535)])
def test_mtproxy_port_accepts(mtp: SimpleNamespace, values: dict[str, str], expected: int) -> None:
    # Arrange — parametrised

    # Act
    port = mtp.h.port_from_env(values)

    # Assert
    assert port == expected


# Invariant: a non-numeric or out-of-range port is refused (exit 64).
@pytest.mark.parametrize("raw", ["http", "0", "65536", "-1"])
def test_mtproxy_port_refusals(mtp: SimpleNamespace, raw: str) -> None:
    # Arrange
    values = {"MTPROTO_PORT": raw}

    # Act
    code, message = _code(mtp.h, lambda: mtp.h.port_from_env(values))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "MTProxy port is invalid")


# Invariant: port detection matches the LOCAL port at a field boundary only —
# ":84430", a peer-column port, non-LISTEN rows, malformed rows and a failed ss
# never count as "listening".
@pytest.mark.parametrize(
    ("rc", "output", "listening"),
    [
        (1, "", False),
        (0, SS_HEADER + "LISTEN 0 4096 0.0.0.0:84430 0.0.0.0:*\n", False),
        (0, SS_HEADER + "ESTAB 0 0 10.0.0.1:5555 1.2.3.4:8443\n", False),
        (0, SS_HEADER + "LISTEN 0\n", False),
        (0, SS_HEADER + "LISTEN 0 4096 nocolon 0.0.0.0:*\n", False),
        (0, SS_HEADER + "LISTEN 0 4096 0.0.0.0:http 0.0.0.0:*\n", False),
        (0, SS_HEADER + "LISTEN 0 4096 [::]:8443 [::]:*\n", True),
    ],
)
def test_mtproxy_port_listening(mtp: SimpleNamespace, rc: int, output: str, listening: bool) -> None:
    # Arrange
    mtp.run.on("ss", "-tln", rc=rc, stdout=output)

    # Act
    result = mtp.h.port_listening(8443)

    # Assert
    assert result is listening


# Invariant: restart verification fails (exit 70) on a failed restart, an
# inactive service, or a port that never starts listening within the timeout.
@pytest.mark.parametrize("failure", ["restart", "inactive", "never-listens"])
def test_mtproxy_restart_verification_failures(mtp: SimpleNamespace, failure: str) -> None:
    # Arrange
    expected = {
        "restart": "MTProxy restart failed",
        "inactive": "MTProxy service is not active",
        "never-listens": "MTProxy port is not listening",
    }[failure]
    if failure == "restart":
        mtp.run.on("systemctl", "restart", rc=1)
    elif failure == "inactive":
        mtp.run.on("systemctl", "is-active", rc=3, stdout="failed\n")
    else:
        mtp.run.on("ss", "-tln", stdout=SS_HEADER)

    # Act
    code, message = _code(mtp.h, lambda: mtp.h.restart_and_verify(8443, timeout=1.0, interval=0.25))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, expected)
    if failure == "never-listens":
        assert mtp.clock.sleeps == [0.25, 0.25, 0.25, 0.25]


# Invariant: the previous port comes from the installed env; a missing or
# corrupt env falls back to the default rather than failing the rollback.
@pytest.mark.parametrize(("env", "expected"), [(None, 8443), ("garbage\n", 8443), ("MTPROTO_PORT=9000\n", 9000)])
def test_mtproxy_existing_port(mtp: SimpleNamespace, env: str | None, expected: int) -> None:
    # Arrange
    if env is not None:
        mtp.target.mkdir(parents=True)
        mtp.h.TARGET_ENV.write_text(env, encoding="utf-8")

    # Act
    port = mtp.h.existing_port()

    # Assert
    assert port == expected


# Invariant: a failed apply restores BOTH previous files and re-verifies on the
# OLD port ("previous files restored"); a failure of that too is reported as
# "rollback failed".
@pytest.mark.parametrize("rollback_ok", [True, False])
def test_mtproxy_apply_failure_and_rollback(mtp: SimpleNamespace, rollback_ok: bool) -> None:
    # Arrange
    mtp.target.mkdir(parents=True)
    mtp.h.TARGET_SECRETS.write_text("OLD-SECRETS", encoding="utf-8")
    mtp.h.TARGET_ENV.write_text("MTPROTO_PORT=9000\n", encoding="utf-8")
    (mtp.candidate / "mtproxy.env").write_text("MTPROTO_PORT=9443\n", encoding="utf-8")
    listening_on = "9000" if rollback_ok else "1"
    mtp.run.on("ss", "-tln", stdout=SS_HEADER + f"LISTEN 0 4096 0.0.0.0:{listening_on} 0.0.0.0:*\n")

    # Act
    code, message = _code(mtp.h, lambda: mtp.h.action_apply(str(mtp.candidate)))

    # Assert
    assert code == EXIT_COMMAND_FAILED
    if rollback_ok:
        assert message == "MTProxy apply failed; previous files restored"
    else:
        assert message == "MTProxy apply failed and rollback failed"
    assert mtp.h.TARGET_SECRETS.read_text(encoding="utf-8") == "OLD-SECRETS"
    assert mtp.h.TARGET_ENV.read_text(encoding="utf-8") == "MTPROTO_PORT=9000\n"


# Invariant: with no previous files, a failed apply removes the new ones.
def test_mtproxy_apply_failure_without_backup(mtp: SimpleNamespace) -> None:
    # Arrange
    restarts = {"n": 0}
    real_run = mtp.run

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if args[:2] == ["systemctl", "restart"]:
            restarts["n"] += 1
            return subprocess.CompletedProcess(args, 1 if restarts["n"] == 1 else 0, "", "")
        return real_run(args, **kwargs)

    mtp.h.subprocess.run = run

    # Act
    _, message = _code(mtp.h, lambda: mtp.h.action_apply(str(mtp.candidate)))

    # Assert
    assert message == "MTProxy apply failed; previous files restored"
    assert not mtp.h.TARGET_SECRETS.exists() and not mtp.h.TARGET_ENV.exists()


# Invariant: a source swapped for a symlink before install is refused by
# O_NOFOLLOW (exit 64) and leaves no temp file.
def test_mtproxy_install_refuses_symlink(mtp: SimpleNamespace) -> None:
    # Arrange
    real = mtp.tmp / "real"
    real.write_text("x", encoding="utf-8")
    link = mtp.candidate / "link"
    link.symlink_to(real)

    # Act
    code, message = _code(mtp.h, lambda: mtp.h.install_file(link, mtp.h.TARGET_SECRETS))

    # Assert
    assert code == EXIT_VALIDATION and message.startswith("cannot open source file")
    assert list(mtp.target.iterdir()) == []


# Invariant: a successful apply installs both files root:vpn-bot 0640 inside a
# root:vpn-bot 0750 directory.
def test_mtproxy_apply_success(mtp: SimpleNamespace) -> None:
    # Arrange — fixture candidate

    # Act
    rc = mtp.h.main(["apply", str(mtp.candidate)], stdout=io.StringIO(), stderr=io.StringIO())

    # Assert
    assert rc == 0
    assert json.loads(mtp.h.TARGET_SECRETS.read_text(encoding="utf-8"))["generation"] == 3
    assert oct(mtp.h.TARGET_ENV.stat().st_mode & 0o777) == "0o640"
    assert oct(mtp.target.stat().st_mode & 0o777) == "0o750"
    assert (mtp.target, 0, 4242) in mtp.os.chowns


# Invariant: status is 0 only when the service is active AND the port listens.
@pytest.mark.parametrize(
    ("active", "listening", "rc", "printed"),
    [(True, True, 0, "active\nlistening\n"), (True, False, 1, "active\n"), (False, True, 1, "listening\n")],
)
def test_mtproxy_status(mtp: SimpleNamespace, active: bool, listening: bool, rc: int, printed: str) -> None:
    # Arrange
    if not active:
        mtp.run.on("systemctl", "is-active", rc=3, stdout="inactive\n")
    if not listening:
        mtp.run.on("ss", "-tln", stdout=SS_HEADER)
    out = io.StringIO()

    # Act
    result = mtp.h.main(["status"], stdout=out, stderr=io.StringIO())

    # Assert
    assert (result, out.getvalue()) == (rc, printed)


# Invariant: a refusal surfaces through main() on stderr with its exit code,
# and argparse rejects a missing candidate (exit 2).
def test_mtproxy_cli_refusals(mtp: SimpleNamespace) -> None:
    # Arrange
    stderr = io.StringIO()

    # Act
    rc = mtp.h.main(["apply", "relative"], stdout=io.StringIO(), stderr=stderr)

    # Assert
    assert (rc, stderr.getvalue()) == (EXIT_VALIDATION, "error: candidate path must be absolute\n")
    with pytest.raises(SystemExit) as excinfo:
        mtp.h.main(["apply"], stdout=io.StringIO(), stderr=io.StringIO())
    assert excinfo.value.code == 2


# Invariant: a missing system tool is a clean HelperError (exit 70).
def test_mtproxy_missing_tool(mtp: SimpleNamespace) -> None:
    # Arrange
    mtp.run.on("ss", exc=FileNotFoundError("ss"))

    # Act
    code, message = _code(mtp.h, lambda: mtp.h.port_listening(8443))

    # Assert
    assert (code, message) == (EXIT_COMMAND_FAILED, "required command not found")


# Invariant: the final group must exist (exit 64) before any directory is
# chowned.
def test_mtproxy_missing_final_group(mtp: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    # Arrange
    monkeypatch.setattr(mtp.h, "FINAL_GROUP", "nope")

    # Act
    code, message = _code(mtp.h, mtp.h._prepare_target_dir)

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "required final group is missing")
    assert mtp.os.chowns == []


# ── socks5-user ──────────────────────────────────────────────────────────────


@pytest.fixture
def socks(load_helper: Callable[[str], ModuleType], monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    helper = load_helper("vpn-bot-socks5-user")
    run, _ = _hermetic(monkeypatch, helper)
    return SimpleNamespace(h=helper, run=run)


LOGIN = "vpn_socks_100_abcd"


# Invariant: a login outside the managed prefix is refused with its own message
# (exit 64) — the helper never acts on system accounts.
@pytest.mark.parametrize("login", ["root", "nobody", "vpn_sock_100", "Vpn_socks_100"])
def test_socks5_login_outside_prefix(socks: SimpleNamespace, login: str) -> None:
    # Arrange
    h = socks.h

    # Act
    code, message = _code(h, lambda: h.validate_login(login))

    # Assert
    assert (code, message) == (EXIT_VALIDATION, "login outside managed prefix")


# Invariant: every mutating action validates the login BEFORE running any
# tool, and reports the refusal through main() with exit 64.
@pytest.mark.parametrize("action", ["exists", "create", "set-password", "lock", "delete"])
def test_socks5_actions_refuse_bad_login_without_running_tools(socks: SimpleNamespace, action: str) -> None:
    # Arrange
    stderr = io.StringIO()

    # Act
    rc = socks.h.main([action, "--", "-rf"], stdin=io.StringIO("pw\n"), stderr=stderr)

    # Assert
    assert rc == EXIT_VALIDATION
    assert stderr.getvalue() == "error: invalid managed login\n"
    assert socks.run.calls == []


# Invariant: `exists` maps getent rc 0 → 0 and rc 2 → 2 (not found); any other
# rc is a lookup failure (exit 70).
@pytest.mark.parametrize(("getent_rc", "expected"), [(0, 0), (2, 2), (1, EXIT_COMMAND_FAILED)])
def test_socks5_exists_mapping(socks: SimpleNamespace, getent_rc: int, expected: int) -> None:
    # Arrange
    socks.run.on("getent", rc=getent_rc)
    stderr = io.StringIO()

    # Act
    rc = socks.h.main(["exists", LOGIN], stderr=stderr)

    # Assert
    assert rc == expected
    assert socks.run.calls == [["getent", "passwd", LOGIN]]
    if expected == EXIT_COMMAND_FAILED:
        assert stderr.getvalue() == "error: account lookup failed\n"


# Invariant: create/lock/delete run their tool inside the host mount namespace
# with a fixed argv, and a non-zero rc maps to exit 70 with a generic message.
@pytest.mark.parametrize(
    ("action", "tool_argv", "message"),
    [
        ("create", ["useradd", "-r", "-s", "/usr/sbin/nologin", LOGIN], "account create failed"),
        ("lock", ["passwd", "-l", LOGIN], "account lock failed"),
        ("delete", ["userdel", LOGIN], "account delete failed"),
    ],
)
@pytest.mark.parametrize("tool_rc", [0, 1])
def test_socks5_mutating_actions(socks: SimpleNamespace, action: str, tool_argv: list[str], message: str,
                                 tool_rc: int) -> None:
    # Arrange
    socks.run.on("nsenter", rc=tool_rc, stderr="tool said something")
    stderr = io.StringIO()

    # Act
    rc = socks.h.main([action, LOGIN], stderr=stderr)

    # Assert
    assert socks.run.calls == [["nsenter", "--mount=/proc/1/ns/mnt", "--", *tool_argv]]
    if tool_rc == 0:
        assert (rc, stderr.getvalue()) == (0, "")
    else:
        assert (rc, stderr.getvalue()) == (EXIT_COMMAND_FAILED, f"error: {message}\n")


# Invariant: set-password refuses an empty password and any character that
# could inject an extra chpasswd record or corrupt the line (exit 64), without
# running chpasswd.
@pytest.mark.parametrize(
    ("stdin", "message"),
    [
        ("", "password input is empty"),
        ("\n", "password input is empty"),
        ("a:b\n", "invalid password characters"),
        ("a\rb\n", "invalid password characters"),
        ("a\x00b\n", "invalid password characters"),
        ("a\nroot:x\n", "invalid password characters"),
    ],
)
def test_socks5_set_password_refusals(socks: SimpleNamespace, stdin: str, message: str) -> None:
    # Arrange
    stderr = io.StringIO()

    # Act
    rc = socks.h.main(["set-password", LOGIN], stdin=io.StringIO(stdin), stderr=stderr)

    # Assert
    assert (rc, stderr.getvalue()) == (EXIT_VALIDATION, f"error: {message}\n")
    assert socks.run.calls == []


# Invariant: a failing chpasswd maps to exit 70 with a message that carries no
# part of the password.
def test_socks5_set_password_tool_failure(socks: SimpleNamespace) -> None:
    # Arrange
    socks.run.on("nsenter", rc=1, stderr="chpasswd: line 1: S3cret-Pass")
    stderr = io.StringIO()

    # Act
    rc = socks.h.main(["set-password", LOGIN], stdin=io.StringIO("S3cret-Pass\n"), stderr=stderr)

    # Assert
    assert (rc, stderr.getvalue()) == (EXIT_COMMAND_FAILED, "error: password update failed\n")


# Invariant: `status` is a no-op health probe that runs nothing.
def test_socks5_status(socks: SimpleNamespace) -> None:
    # Arrange — nothing

    # Act
    rc = socks.h.main(["status"])

    # Assert
    assert rc == 0
    assert socks.run.calls == []


# Invariant: argparse refuses a missing login and unknown actions (exit 2).
@pytest.mark.parametrize("argv", [["create"], ["passwd", LOGIN], []])
def test_socks5_cli_malformed(socks: SimpleNamespace, argv: list[str]) -> None:
    # Arrange
    h = socks.h

    # Act
    with pytest.raises(SystemExit) as excinfo:
        h.main(argv, stderr=io.StringIO())

    # Assert
    assert excinfo.value.code == 2
