"""Behavioural + structural coverage for deploy/hysteria/install-config.sh.

The tracked deploy/hysteria/config.yaml carries a placeholder
`secret: "<random-secret>"` in its trafficStats block. A bare
`cp deploy/hysteria/config.yaml /etc/hysteria/config.yaml` overwrites the live
Traffic Stats secret with that placeholder, so hysteria-server starts
rejecting the bot's stats/online/kick calls with 401 — silently, since the
data plane itself still starts fine. install-config.sh is the only supported
way to (re)install the file: it copies the repo config AND injects
HYSTERIA2_STATS_SECRET from .env, so the placeholder never reaches disk.

These tests drive the REAL shipped script via subprocess, using the
INSTALL_CONFIG_REQUIRE_ROOT=0 / INSTALL_CONFIG_OWNER / INSTALL_CONFIG_GROUP
test seam documented in the script itself, so the full
transform -> backup -> install path runs without root or the `hysteria`
system user — the same reason tests/test_hy2_warp_mark_helper.py drives
scripts/vpnbot-hy2-warp-mark under a stubbed PATH instead of the real network
tools.

The script also refuses to install unless the hysteria binary reports
v2.8.0 or newer (the repo config sets `congestion.bbrProfile`). Every run here
points HYSTERIA_BIN at a mock written into tmp_path — never at the host's
/usr/local/bin/hysteria — so the result cannot depend on what happens to be
installed on the machine running the suite (cf. the host-leak class of
#239/#246/#249: green in clean CI, red on the box, or the other way round).
"""

import grp
import json
import os
import pwd
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SCRIPT = ROOT / "deploy" / "hysteria" / "install-config.sh"
REPO_CONFIG = ROOT / "deploy" / "hysteria" / "config.yaml"

_CURRENT_USER = pwd.getpwuid(os.getuid()).pw_name
_CURRENT_GROUP = grp.getgrgid(os.getgid()).gr_name


# What the real `hysteria version` prints before its `Key: value` lines: an
# ASCII-art banner made of non-ASCII box characters.
_BANNER = (
    "░█░█░█░█░█▀▀░▀█▀░█▀▀░█▀▄░▀█▀░█▀█░░░▀▀▄\n"
    "░█▀█░░█░░▀▀█░░█░░█▀▀░█▀▄░░█░░█▀█░░░▄▀░\n"
    "░▀░▀░░▀░░▀▀▀░░▀░░▀▀▀░▀░▀░▀▀▀░▀░▀░░░▀▀▀\n"
    "a powerful, lightning fast and censorship resistant proxy\n"
    "\n"
)
_DEFAULT_VERSION_LINE = "Version:\tv2.8.0"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_mock_hysteria(path: Path, version_line: str | None) -> Path:
    """An executable stand-in for `hysteria` that logs each call next to itself.

    On `version` it prints the banner, then `version_line` (left out when None),
    then a couple of the other tab-separated keys the real binary prints.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    body = _BANNER + (f"{version_line}\n" if version_line is not None else "")
    body += "BuildType:\trelease\nPlatform:\tlinux\n"
    calls = path.with_name(path.name + ".calls")
    path.write_text(
        "#!/bin/sh\n"
        f'echo "$*" >> "{calls}"\n'
        '[ "$1" = version ] || exit 2\n'
        "cat <<'BANNER'\n"
        f"{body}"
        "BANNER\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _mock_calls(path: Path) -> list[str]:
    calls = path.with_name(path.name + ".calls")
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


def _base_env(hysteria_bin: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["INSTALL_CONFIG_REQUIRE_ROOT"] = "0"
    env["INSTALL_CONFIG_OWNER"] = _CURRENT_USER
    env["INSTALL_CONFIG_GROUP"] = _CURRENT_GROUP
    # Always a path under tmp_path, whatever the caller's environment says.
    env["HYSTERIA_BIN"] = str(hysteria_bin)
    # The retention knob never leaks in from the environment running the suite.
    env.pop("HYSTERIA_CONFIG_BACKUP_KEEP", None)
    return env


def _run_install(
    tmp_path: Path,
    env_content: str,
    target_initial: str | None = None,
    *,
    version_line: str | None = _DEFAULT_VERSION_LINE,
    hysteria_bin: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real install-config.sh against a temp .env/target, unprivileged.

    HYSTERIA_BIN points at a mock in tmp_path printing `version_line` (v2.8.0 by
    default). Pass `hysteria_bin` to point it somewhere else under tmp_path
    instead — e.g. at a path that does not exist.
    """
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")
    target = tmp_path / "config.yaml"
    if target_initial is not None:
        target.write_text(target_initial, encoding="utf-8")

    if hysteria_bin is None:
        hysteria_bin = _write_mock_hysteria(tmp_path / "bin" / "hysteria", version_line)
    assert tmp_path in hysteria_bin.parents, "HYSTERIA_BIN must stay inside tmp_path"
    env = _base_env(hysteria_bin)
    env.update(extra_env or {})

    return subprocess.run(
        ["bash", str(INSTALL_SCRIPT), "--env", str(env_file), "--target", str(target)],
        env=env,
        capture_output=True,
        text=True,
    )


def _secret_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if re.match(r"^[ \t]+secret:", line)]


# --------------------------------------------------------------------------- #
# structural
# --------------------------------------------------------------------------- #
def test_install_config_script_exists_and_is_executable() -> None:
    assert INSTALL_SCRIPT.exists()
    assert os.access(INSTALL_SCRIPT, os.X_OK), "install-config.sh must be executable (git mode 0755)"


def test_repo_config_still_has_placeholder_for_install_config_to_fill() -> None:
    # If the placeholder ever disappears from the tracked file, install-config.sh
    # has nothing left to inject and its reason to exist evaporates.
    text = _read(REPO_CONFIG)
    assert "<random-secret>" in text
    assert len(_secret_lines(text)) == 1


def test_install_config_selftest_passes(tmp_path: Path) -> None:
    # HYSTERIA_BIN points at nothing: the selftest brings its own mock binaries
    # and must pass without consulting the host's hysteria at all.
    env = dict(os.environ)
    env["HYSTERIA_BIN"] = str(tmp_path / "no-such-hysteria")
    proc = subprocess.run(
        ["bash", str(INSTALL_SCRIPT), "--selftest"], capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0, proc.stderr
    assert "all checks passed" in proc.stderr
    # The version guard is part of the selftest, not only of this suite.
    for case in ("v2.7.1 -> fail", "v2.8.0 -> ok", "v2.10.0 -> ok", "missing binary fails closed"):
        assert f"version guard: {case}" in proc.stderr, proc.stderr


def test_install_config_defaults_hysteria_bin_to_usr_local_bin() -> None:
    # Static on purpose: executing the default would read the host's binary.
    text = _read(INSTALL_SCRIPT)
    assert 'HYSTERIA_BIN="${HYSTERIA_BIN:-/usr/local/bin/hysteria}"' in text


# --------------------------------------------------------------------------- #
# behavioural: real install against a temp .env / temp target
# --------------------------------------------------------------------------- #
def test_install_config_injects_secret_and_removes_placeholder(tmp_path: Path) -> None:
    secret = "known-test-secret-abc123"
    proc = _run_install(tmp_path, f"HYSTERIA2_STATS_SECRET={secret}\n")
    assert proc.returncode == 0, proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert "<random-secret>" not in installed

    lines = _secret_lines(installed)
    assert len(lines) == 1, f"expected exactly one secret: line, got {lines!r}"
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == secret


def test_install_config_backs_up_existing_target_before_overwrite(tmp_path: Path) -> None:
    proc = _run_install(
        tmp_path,
        "HYSTERIA2_STATS_SECRET=fresh-secret\n",
        target_initial="stale placeholder content\n",
    )
    assert proc.returncode == 0, proc.stderr

    backups = list(tmp_path.glob("config.yaml.bak.*"))
    assert len(backups) == 1, f"expected exactly one backup file, got {backups!r}"
    assert backups[0].read_text(encoding="utf-8") == "stale placeholder content\n"


def test_install_config_never_invokes_systemctl(tmp_path: Path) -> None:
    # install-config.sh must never restart hysteria-server itself — the
    # operator runs preflight-udp443.sh and restarts by hand. Stub systemctl on
    # PATH so an accidental restart call would be caught, not silently succeed.
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    systemctl_log = tmp_path / "systemctl.log"
    stub = stub_dir / "systemctl"
    stub.write_text(f'#!/bin/bash\necho "$*" >> "{systemctl_log}"\nexit 0\n', encoding="utf-8")
    stub.chmod(0o755)

    env_file = tmp_path / ".env"
    env_file.write_text("HYSTERIA2_STATS_SECRET=some-secret\n", encoding="utf-8")
    target = tmp_path / "config.yaml"

    env = _base_env(_write_mock_hysteria(tmp_path / "mock" / "hysteria", _DEFAULT_VERSION_LINE))
    env["PATH"] = f"{stub_dir}:{env['PATH']}"

    proc = subprocess.run(
        ["bash", str(INSTALL_SCRIPT), "--env", str(env_file), "--target", str(target)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert not systemctl_log.exists(), "install-config.sh must never invoke systemctl itself"
    # It must still tell the operator to do so by hand.
    assert "systemctl restart hysteria-server" in proc.stderr


# --------------------------------------------------------------------------- #
# fail-closed
# --------------------------------------------------------------------------- #
def test_install_config_fails_closed_without_secret_in_env(tmp_path: Path) -> None:
    proc = _run_install(tmp_path, "SOME_OTHER_VAR=1\n")
    assert proc.returncode != 0
    assert "HYSTERIA2_STATS_SECRET" in proc.stderr
    assert not (tmp_path / "config.yaml").exists()


def test_install_config_warns_but_proceeds_on_empty_secret(tmp_path: Path) -> None:
    proc = _run_install(tmp_path, "HYSTERIA2_STATS_SECRET=\n")
    assert proc.returncode == 0, proc.stderr
    assert "WARNING" in proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    lines = _secret_lines(installed)
    assert len(lines) == 1
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == ""


def test_install_config_last_assignment_wins(tmp_path: Path) -> None:
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=first\nHYSTERIA2_STATS_SECRET=second\n"
    )
    assert proc.returncode == 0, proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    lines = _secret_lines(installed)
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == "second"


# --------------------------------------------------------------------------- #
# quoting: special characters must round-trip through json.dumps() exactly
# --------------------------------------------------------------------------- #
def test_install_config_injects_secret_with_quotes_backslash_and_hash(tmp_path: Path) -> None:
    # Unquoted values are taken verbatim to end of line (see install-config.sh's
    # dequote()) specifically so a secret containing '#' is not silently
    # truncated as an inline comment. This also covers embedded double/single
    # quotes and a literal backslash — all of which must survive intact and be
    # re-quoted correctly by json.dumps() in the installed YAML.
    secret = "ab\"cd\\ef#gh'ij"
    proc = _run_install(tmp_path, f"HYSTERIA2_STATS_SECRET={secret}\n")
    assert proc.returncode == 0, proc.stderr

    installed = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    assert "<random-secret>" not in installed

    lines = _secret_lines(installed)
    assert len(lines) == 1
    m = re.match(r"^[ \t]+secret:[ \t]*(.*)$", lines[0])
    assert m is not None
    assert json.loads(m.group(1)) == secret


# --------------------------------------------------------------------------- #
# hysteria version guard (repo config needs >= v2.8.0 for congestion.bbrProfile)
# --------------------------------------------------------------------------- #
_LIVE_TARGET = "live config that must survive a refused install\n"


def _assert_target_untouched(tmp_path: Path) -> None:
    target = tmp_path / "config.yaml"
    assert target.read_text(encoding="utf-8") == _LIVE_TARGET
    assert not list(tmp_path.glob("config.yaml.bak.*")), "a refused install must not even back up"


@pytest.mark.parametrize("version", ["v2.8.0", "v2.10.0", "2.9.0", "v3.0.0"])
def test_install_config_accepts_hysteria_at_or_above_2_8_0(tmp_path: Path, version: str) -> None:
    proc = _run_install(
        tmp_path,
        "HYSTERIA2_STATS_SECRET=s3cret\n",
        target_initial=_LIVE_TARGET,
        version_line=f"Version:\t{version}",
    )
    assert proc.returncode == 0, proc.stderr
    installed = _read(tmp_path / "config.yaml")
    assert "bbrProfile: conservative" in installed
    # The guard ran, and against the mock — not some other hysteria on the box.
    assert _mock_calls(tmp_path / "bin" / "hysteria") == ["version"]


@pytest.mark.parametrize("version", ["v2.7.1", "v2.7.99", "v1.99.99", "v0.8.0"])
def test_install_config_refuses_hysteria_below_2_8_0(tmp_path: Path, version: str) -> None:
    proc = _run_install(
        tmp_path,
        "HYSTERIA2_STATS_SECRET=s3cret\n",
        target_initial=_LIVE_TARGET,
        version_line=f"Version:\t{version}",
    )
    assert proc.returncode != 0
    assert "v2.8.0" in proc.stderr, proc.stderr
    assert version.lstrip("v") in proc.stderr, "the error must say which version it found"
    _assert_target_untouched(tmp_path)


@pytest.mark.parametrize(
    "version_line",
    [
        pytest.param(None, id="banner-only-no-version-line"),
        pytest.param("Version:\tbanana", id="garbage-version"),
        pytest.param("Version:\tv2.8", id="two-component-version"),
        pytest.param("  Version: v2.8.0", id="not-at-line-start"),
    ],
)
def test_install_config_fails_closed_on_unparseable_version(
    tmp_path: Path, version_line: str | None
) -> None:
    proc = _run_install(
        tmp_path,
        "HYSTERIA2_STATS_SECRET=s3cret\n",
        target_initial=_LIVE_TARGET,
        version_line=version_line,
    )
    assert proc.returncode != 0
    assert "Version: vX.Y.Z" in proc.stderr, proc.stderr
    _assert_target_untouched(tmp_path)


def test_install_config_fails_closed_without_hysteria_binary(tmp_path: Path) -> None:
    proc = _run_install(
        tmp_path,
        "HYSTERIA2_STATS_SECRET=s3cret\n",
        target_initial=_LIVE_TARGET,
        hysteria_bin=tmp_path / "bin" / "no-such-hysteria",
    )
    assert proc.returncode != 0
    assert "not found" in proc.stderr, proc.stderr
    _assert_target_untouched(tmp_path)


def test_install_config_fails_closed_when_version_command_fails(tmp_path: Path) -> None:
    broken = tmp_path / "bin" / "hysteria"
    broken.parent.mkdir()
    broken.write_text("#!/bin/sh\necho 'Version:\tv2.8.0'\nexit 1\n", encoding="utf-8")
    broken.chmod(0o755)
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial=_LIVE_TARGET, hysteria_bin=broken
    )
    assert proc.returncode != 0
    assert "version' failed" in proc.stderr, proc.stderr
    _assert_target_untouched(tmp_path)


def test_install_config_refused_install_creates_no_target(tmp_path: Path) -> None:
    proc = _run_install(tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", version_line="Version:\tv2.7.1")
    assert proc.returncode != 0
    assert not (tmp_path / "config.yaml").exists()


# --------------------------------------------------------------------------- #
# Backup retention: HYSTERIA_CONFIG_BACKUP_KEEP (default 3), own names only
# --------------------------------------------------------------------------- #
# Names a careless glob would take for this script's backups — never deleted.
_FOREIGN_BACKUPS = (
    "config.yaml.bak443",                    # a hand-made copy (operations.md lists it)
    "config.yaml.bak",
    "config.yaml.bak.2026-11-01",
    "config.yaml.bak.20261101T000000.orig",
    "config.yaml.bak.20261101T0000",
    "other.yaml.bak.20261101T000000",
    "cert.pem.selfsigned.bak",
)


def _plant_old_backups(tmp_path: Path, n: int) -> list[Path]:
    """n backups in this script's own name, oldest first (2020-01-01 .. 2020-01-n)."""
    out = []
    for i in range(1, n + 1):
        p = tmp_path / f"config.yaml.bak.202001{i:02d}T000000"
        p.write_text(f"old {i}\n", encoding="utf-8")
        out.append(p)
    for name in _FOREIGN_BACKUPS:
        (tmp_path / name).write_text("foreign\n", encoding="utf-8")
    return out


def _own_backups(tmp_path: Path) -> list[str]:
    rx = re.compile(r"config\.yaml\.bak\.[0-9]{8}T[0-9]{6}")
    return sorted(p.name for p in tmp_path.iterdir() if rx.fullmatch(p.name))


def _assert_foreign_backups_intact(tmp_path: Path) -> None:
    for name in _FOREIGN_BACKUPS:
        assert (tmp_path / name).read_text(encoding="utf-8") == "foreign\n", name


def test_install_keeps_the_newest_three_backups_by_default(tmp_path: Path) -> None:
    _plant_old_backups(tmp_path, 5)
    proc = _run_install(tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial="live\n")
    assert proc.returncode == 0, proc.stderr
    own = _own_backups(tmp_path)
    # The one this run wrote (today) plus the two newest planted ones.
    assert len(own) == 3, own
    assert own[:2] == ["config.yaml.bak.20200104T000000", "config.yaml.bak.20200105T000000"]
    assert (tmp_path / own[2]).read_text(encoding="utf-8") == "live\n"
    assert proc.stderr.count("removed old backup") == 3
    _assert_foreign_backups_intact(tmp_path)


def test_install_honours_hysteria_config_backup_keep(tmp_path: Path) -> None:
    _plant_old_backups(tmp_path, 4)
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial="live\n",
        extra_env={"HYSTERIA_CONFIG_BACKUP_KEEP": "1"},
    )
    assert proc.returncode == 0, proc.stderr
    own = _own_backups(tmp_path)
    assert len(own) == 1 and (tmp_path / own[0]).read_text(encoding="utf-8") == "live\n"
    _assert_foreign_backups_intact(tmp_path)


def test_install_with_few_backups_deletes_nothing(tmp_path: Path) -> None:
    _plant_old_backups(tmp_path, 1)
    proc = _run_install(tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial="live\n")
    assert proc.returncode == 0, proc.stderr
    assert len(_own_backups(tmp_path)) == 2
    assert "removed old backup" not in proc.stderr


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1001", "07"])
def test_bad_keep_value_warns_and_uses_the_default(tmp_path: Path, bad: str) -> None:
    _plant_old_backups(tmp_path, 5)
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial="live\n",
        extra_env={"HYSTERIA_CONFIG_BACKUP_KEEP": bad},
    )
    assert proc.returncode == 0, proc.stderr
    assert f"HYSTERIA_CONFIG_BACKUP_KEEP='{bad}' is not a whole number" in proc.stderr
    assert len(_own_backups(tmp_path)) == 3


def test_a_symlink_with_the_backup_name_is_never_followed_or_deleted(tmp_path: Path) -> None:
    _plant_old_backups(tmp_path, 4)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me\n", encoding="utf-8")
    link = tmp_path / "config.yaml.bak.20190101T000000"
    link.symlink_to(victim)
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial="live\n",
        extra_env={"HYSTERIA_CONFIG_BACKUP_KEEP": "1"},
    )
    assert proc.returncode == 0, proc.stderr
    assert link.is_symlink() and victim.read_text(encoding="utf-8") == "keep me\n"


def test_cleanup_failure_warns_and_the_install_still_succeeds(tmp_path: Path) -> None:
    _plant_old_backups(tmp_path, 5)
    # An `rm` that refuses this script's backups (root ignores file modes, so a stub
    # on PATH is the portable way to make the deletion fail); anything else goes to
    # the real rm (the EXIT trap removes its temp file through it).
    stub = tmp_path / "stub"
    stub.mkdir()
    (stub / "rm").write_text(
        '#!/bin/sh\nfor a in "$@"; do case "$a" in *.bak.*) echo "rm: denied" >&2; exit 1 ;; esac; done\n'
        'exec /bin/rm "$@"\n',
        encoding="utf-8",
    )
    (stub / "rm").chmod(0o755)
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial="live\n",
        extra_env={"PATH": f"{stub}:{os.environ['PATH']}"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "WARNING: could not remove every old" in proc.stderr
    assert '"s3cret"' in _read(tmp_path / "config.yaml"), "the new config is installed all the same"
    assert len(_own_backups(tmp_path)) == 6


def test_refused_install_prunes_nothing(tmp_path: Path) -> None:
    _plant_old_backups(tmp_path, 5)
    proc = _run_install(
        tmp_path, "HYSTERIA2_STATS_SECRET=s3cret\n", target_initial="live\n", version_line="Version:\tv2.7.1"
    )
    assert proc.returncode != 0
    assert len(_own_backups(tmp_path)) == 5
