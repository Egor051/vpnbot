"""Coverage for the shared-WAL DB ownership helper `scripts/vpn-bot-db-perms`.

WHY THE HELPER EXISTS
    vpn-bot.service runs as root while vpnbot-hy2-auth.service and
    vpn-bot-subscription.service run as vpn-bot; all three open the same
    /opt/vpn-service/data/vpn.db in journal_mode=WAL. SQLite's robustFchown()
    gives the -wal/-shm sidecars the owner of the MAIN DB FILE, so the only way
    left to break the two readers is vpn.db itself becoming root-owned (a root
    restore from a backup tar, a manual cp, a DB created under root) — the
    sidecars then come out root:root and both readers die with
    "unable to open database file". The helper re-asserts the ownership as
    ExecStartPre of vpn-bot.service, before the bot reopens the DB.

WHAT IS PINNED HERE
  (a) structural guards — the ExecStartPre line in deploy/vpn-bot.service, the
      OUT_OF_REPO_HELPERS registration (with the `required` policy, so a clean
      host gets the helper instead of a 203/EXEC unit), the helper-install step
      running BEFORE the unit install/start, the post-deploy + post-restore
      ownership assertions, and the empty-path / "/" precondition guard inside
      the helper. None of these may be silently dropped by a later edit.
  (b) behaviour — driven through the helper's DB_PERMS_SELFTEST seam (mirrors
      DEPLOY_SELFTEST in scripts/deploy.sh: define every function, return before
      doing any work) and through full runs under stubbed `id`/`chown`/`chmod`,
      so nothing here performs a real chown: the non-root no-op, DB-path
      resolution precedence, the guard tripping on an empty path and on "/",
      idempotent silence, first-run tolerance of a missing vpn.db, and the
      absent-target-user no-op.
"""

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpn-bot-db-perms"
BOT_UNIT = ROOT / "deploy" / "vpn-bot.service"
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
INSTALLED_PATH = "/usr/local/sbin/vpn-bot-db-perms"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# (a) structural guards: the helper file itself
# --------------------------------------------------------------------------- #
def test_helper_exists_and_is_executable() -> None:
    assert HELPER.exists()
    assert os.access(HELPER, os.X_OK), "the tracked helper must be executable (git mode 0755)"


def test_helper_parses() -> None:
    subprocess.run(["bash", "-n", str(HELPER)], check=True)


def test_helper_resolves_the_real_settings_name_with_a_fallback_constant() -> None:
    """The DB location comes from DB_PATH — the same setting name
    config/settings.py reads (DB_PATH -> Settings.db_path) — with the project's
    own default as the fallback constant."""
    text = _read(HELPER)
    assert "DB_PATH" in text
    assert "/opt/vpn-service/data/vpn.db" in text or "${DB_PERMS_DATA_ROOT}/vpn.db" in text
    assert "resolve_db_path()" in text
    # config/settings.py must still spell the setting the same way.
    settings = _read(ROOT / "config" / "settings.py")
    assert '_optional("DB_PATH"' in settings, "helper resolves DB_PATH; settings must still read it"


def test_helper_guards_empty_path_and_filesystem_root() -> None:
    """The mandatory precondition guard. An empty variable expanding into
    `chmod 0600 ""` / `chown ... /` is the class of bug that took the host down on
    2026-07-29 — this helper must not become a second instance of it, so the guard
    must stay present and stay fail-closed."""
    text = _read(HELPER)
    assert "guard_target()" in text
    lowered = text.lower()
    # Empty-path refusal.
    assert "empty" in lowered and "refusing" in lowered
    # Filesystem-root refusal.
    assert '"/"' in text
    assert "filesystem root" in lowered
    # Confinement to the project data dir.
    assert "DB_PERMS_DATA_ROOT" in text
    assert "outside the project data dir" in text


def test_helper_is_a_no_op_for_non_root_and_never_creates_the_db() -> None:
    text = _read(HELPER)
    assert 'id -u' in text, "the privilege check must use id -u"
    # Documented as a no-op in the non-root privilege model.
    assert "no-op" in text.lower() or "No-op" in text
    # A missing vpn.db is a valid first-run state, never created here.
    lowered = text.lower()
    assert "first-run" in lowered or "first run" in lowered
    assert "must not create" in lowered or "not create it here" in lowered


def test_helper_uses_owner_only_modes_and_no_group_scheme() -> None:
    """robustFchown() works on this host, so 0600/0700 owned by the reader user is
    enough — and is the tightest thing that works. No setgid/group-read/UMask
    scheme may creep in."""
    text = _read(HELPER)
    assert 'DIR_MODE="700"' in text
    assert 'FILE_MODE="600"' in text
    assert "g+r" not in text and "chmod 0640" not in text and "chmod 2" not in text


# --------------------------------------------------------------------------- #
# (a) structural guards: deploy/vpn-bot.service
# --------------------------------------------------------------------------- #
def test_bot_unit_runs_the_helper_as_execstartpre_before_execstart() -> None:
    """The ExecStartPre line is the whole delivery mechanism — pin it so a future
    edit cannot quietly drop it, and pin that it precedes ExecStart."""
    text = _read(BOT_UNIT)
    line = f"ExecStartPre={INSTALLED_PATH}"
    assert line in text, f"deploy/vpn-bot.service must run {INSTALLED_PATH} as ExecStartPre"
    assert text.index(line) < text.index("ExecStart=/opt/vpn-service/.venv/bin/python")


def test_bot_unit_privilege_model_and_umask_untouched() -> None:
    """This change adds ONLY the ExecStartPre line: the run user, UMask and
    ProtectSystem stay exactly as they were (robustFchown() removes any need for a
    UMask/group scheme)."""
    text = _read(BOT_UNIT)
    assert "User=root" in text and "Group=root" in text
    assert "UMask=0077" in text
    assert "ProtectSystem=false" in text


# --------------------------------------------------------------------------- #
# (a) structural guards: scripts/deploy.sh wiring
# --------------------------------------------------------------------------- #
def test_deploy_sh_registers_the_helper_as_required() -> None:
    text = _read(DEPLOY_SH)
    assert f"scripts/vpn-bot-db-perms|{INSTALLED_PATH}|required" in text, (
        "the helper must be in OUT_OF_REPO_HELPERS with the `required` policy, so an "
        "absent copy is INSTALLED (a unit's ExecStartPre names it) instead of tolerated"
    )
    # The absent+required branch actually installs, and the post-install gate
    # refuses to leave a required helper absent.
    assert '"$policy" == "required"' in text
    assert "still absent" in text


def test_deploy_sh_installs_helpers_before_the_unit_install_and_start() -> None:
    """On a clean host an ExecStartPre pointing at a not-yet-installed helper fails
    the unit with 203/EXEC, so the helper-install phase MUST precede both the unit
    install and the bot start."""
    text = _read(DEPLOY_SH)
    helper_call = text.index("\ninstall_out_of_repo_helpers\n")
    unit_install = text.index('install -m0644 "deploy/vpn-bot.service"')
    bot_start = text.index('systemctl start "$BOT_UNIT"\ndeadline=')
    assert helper_call < unit_install < bot_start
    # And the ordering constraint is written down where it can be seen.
    assert "203/EXEC" in text


def test_deploy_sh_asserts_db_ownership_post_deploy_through_rollback() -> None:
    text = _read(DEPLOY_SH)
    assert "assert_db_ownership()" in text
    assert 'DB_OWNER_USER="${DB_OWNER_USER:-vpn-bot}"' in text
    # Post-deploy the failure routes through the existing rollback path.
    idx = text.index("asserting shared-WAL DB ownership")
    window = text[idx : idx + 1200]
    assert "rollback_now" in window
    # The message names the file(s), the expectation and the consequence.
    assert "unable to open database file" in window
    assert "-wal/-shm" in window


def test_deploy_sh_asserts_db_ownership_after_the_restore_in_rollback() -> None:
    """The rollback/restore branch is THE hole: `tar -xzf -C /` as root restores a
    root-owned vpn.db. The assertion must run after the extraction.

    The extraction itself lives behind restore_archive_into_root (the single
    --no-overwrite-dir choke point — see tests/test_deploy_restore_permissions.py),
    so the ordering is pinned on that call site."""
    text = _read(DEPLOY_SH)
    extract = text.index('restore_archive_into_root "$ARCHIVE"')
    assert_call = text.index('db_own_msg="$(assert_db_ownership)"')
    assert extract < assert_call, "the ownership assertion must run AFTER the backup is unpacked"
    # The failing branch is loud and tells the operator how to fix it by hand.
    window = text[assert_call : assert_call + 900]
    assert "MANUAL ACTION REQUIRED" in window
    assert "chown -R" in window


def test_deploy_sh_fix_db_perms_targets_the_reader_user_and_the_sidecars() -> None:
    """fix_db_perms must hand the DB to the reader user (not to the bot's run user)
    and cover the data dir + both sidecars, otherwise the rollback re-creates the
    exact breakage this PR closes."""
    text = _read(DEPLOY_SH)
    idx = text.index("fix_db_perms() {")
    window = text[idx : idx + 1400]
    # The reader-user rule lives in db_target_owner() — one definition, shared with
    # the backup staging and the restore canary.
    assert "db_target_owner" in window
    owner_fn = text[text.index("db_target_owner() {") :][:600]
    assert 'id -u "$DB_OWNER_USER"' in owner_fn
    assert '${DB_PATH}-wal' in window and '${DB_PATH}-shm' in window
    assert 'chmod "$DB_DIR_MODE"' in window and 'chmod "$DB_FILE_MODE"' in window
    assert 'DB_DIR_MODE="0700"' in text and 'DB_FILE_MODE="0600"' in text
    # Same empty/"/" guard as the helper — deploy.sh must not chown "/" either.
    assert "db_path_is_sane" in window
    assert "db_path_is_sane()" in text


def test_deploy_sh_parses() -> None:
    subprocess.run(["bash", "-n", str(DEPLOY_SH)], check=True)


def test_operations_runbook_documents_the_ownership_contract() -> None:
    """An operator hitting "unable to open database file" must be able to find the
    one rule (vpn.db belongs to the reader user) and the one-line fix."""
    text = _read(ROOT / "docs" / "operations.md")
    assert "vpn-bot-db-perms" in text
    assert "robustFchown" in text
    assert "unable to open database file" in text
    assert INSTALLED_PATH in text
    # The escape hatch for a DB kept outside the project data dir.
    assert "DB_PERMS_DATA_ROOT" in text


# --------------------------------------------------------------------------- #
# (b) behavioural harness — stubbed id/chown/chmod, never a real chown
# --------------------------------------------------------------------------- #
def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _stub_dir(tmp_path: Path, *, uid: str = "0", user_exists: bool = True) -> tuple[Path, Path]:
    """Build a stub bin dir. Returns (stub_dir, mutation_log).

    `id -u`            -> uid          (drives the non-root no-op branch)
    `id -u <user>`     -> 0 / 1        (target-user existence)
    `chown` / `chmod`  -> log the call and exit 0 (no real ownership change)
    """
    stub = tmp_path / "bin"
    stub.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "mutations.log"
    _make_stub(stub / "id", (
        f'if [[ "$1" == "-u" && $# -eq 1 ]]; then echo "{uid}"; exit 0; fi\n'
        f'if [[ "$1" == "-u" && $# -eq 2 ]]; then exit {0 if user_exists else 1}; fi\n'
        "exit 1\n"
    ))
    for tool in ("chown", "chmod"):
        _make_stub(stub / tool, f'echo "{tool} $*" >> "{log}"\nexit 0\n')
    return stub, log


def _run_helper(
    tmp_path: Path,
    *,
    app_dir: Path,
    uid: str = "0",
    user_exists: bool = True,
    env: dict[str, str] | None = None,
) -> tuple[int, str, list[str]]:
    """Run the shipped helper end-to-end under stubs. Returns (rc, stderr, mutations)."""
    stub, log = _stub_dir(tmp_path, uid=uid, user_exists=user_exists)
    run_env = dict(os.environ)
    run_env["PATH"] = f"{stub}:{run_env['PATH']}"
    run_env["APP_DIR"] = str(app_dir)
    run_env.pop("DB_PATH", None)
    run_env.update(env or {})
    proc = subprocess.run(
        ["bash", str(HELPER)], env=run_env, capture_output=True, text=True,
    )
    mutations = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return proc.returncode, proc.stderr, mutations


def _call_function(
    tmp_path: Path,
    snippet: str,
    *,
    uid: str = "0",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Source the helper through its DB_PERMS_SELFTEST seam and call one function.

    Mirrors the DEPLOY_SELFTEST harness in tests/test_deploy_helper_install.py: the
    seam defines every function and returns before doing any work, so a single
    function can be driven in isolation.
    """
    stub, _ = _stub_dir(tmp_path, uid=uid)
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DB_PERMS_SELFTEST=1\n"
        f'export PATH="{stub}:$PATH"\n'
        f'source "{HELPER}"\n'
        f"{snippet}\n",
        encoding="utf-8",
    )
    run_env = dict(os.environ)
    run_env.pop("DB_PATH", None)
    run_env.update(env or {})
    return subprocess.run(
        ["bash", str(driver)], env=run_env, capture_output=True, text=True,
    )


def _app(tmp_path: Path, *, with_db: bool = True, with_sidecars: bool = True) -> Path:
    app_dir = tmp_path / "opt"
    data = app_dir / "data"
    data.mkdir(parents=True, exist_ok=True)
    if with_db:
        (data / "vpn.db").write_bytes(b"")
        if with_sidecars:
            (data / "vpn.db-wal").write_bytes(b"")
            (data / "vpn.db-shm").write_bytes(b"")
    return app_dir


# --------------------------------------------------------------------------- #
# (b1) non-root no-op
# --------------------------------------------------------------------------- #
def test_non_root_is_a_silent_no_op(tmp_path: Path) -> None:
    """In the non-root privilege model the bot runs as vpn-bot itself, so ownership
    cannot drift to root: exit 0, mutate nothing, say nothing."""
    app_dir = _app(tmp_path)
    rc, stderr, mutations = _run_helper(tmp_path, app_dir=app_dir, uid="1000")
    assert rc == 0
    assert mutations == [], f"a non-root run must not chown/chmod anything: {mutations}"
    assert stderr == ""


# --------------------------------------------------------------------------- #
# (b2) DB path resolution
# --------------------------------------------------------------------------- #
def test_resolve_prefers_the_environment(tmp_path: Path) -> None:
    """vpn-bot.service pulls .env in via EnvironmentFile, so under systemd DB_PATH
    is already in the environment — it wins."""
    app_dir = _app(tmp_path)
    env_file = tmp_path / "env"
    env_file.write_text("DB_PATH=/from/the/file/vpn.db\n", encoding="utf-8")
    proc = _call_function(
        tmp_path, "resolve_db_path",
        env={
            "APP_DIR": str(app_dir),
            "DB_PERMS_ENV_FILE": str(env_file),
            "DB_PATH": "/from/the/environment/vpn.db",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "/from/the/environment/vpn.db"


def test_resolve_falls_back_to_the_env_file(tmp_path: Path) -> None:
    app_dir = _app(tmp_path)
    env_file = tmp_path / "env"
    # Quoted, with an inline comment, an `export` prefix, a decoy prefix-sharing
    # key, and an earlier value that the last assignment overrides.
    env_file.write_text(
        "IP2ASN_DB_PATH=/wrong/ip2asn.tsv\n"
        "DB_PATH=/early/vpn.db\n"
        'export DB_PATH="/opt/custom/data/vpn.db"   # the real one\n',
        encoding="utf-8",
    )
    proc = _call_function(
        tmp_path, "resolve_db_path",
        env={"APP_DIR": str(app_dir), "DB_PERMS_ENV_FILE": str(env_file)},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "/opt/custom/data/vpn.db"


def test_resolve_falls_back_to_the_constant_when_nothing_is_set(tmp_path: Path) -> None:
    proc = _call_function(
        tmp_path, "resolve_db_path",
        env={"APP_DIR": "/opt/vpn-service", "DB_PERMS_ENV_FILE": str(tmp_path / "absent")},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "/opt/vpn-service/data/vpn.db"


# --------------------------------------------------------------------------- #
# (b3) the precondition guard
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("", "EMPTY"),
        ("/", "filesystem root"),
        ("relative/vpn.db", "not absolute"),
        ("/opt/vpn-service/data/", "trailing slash"),
        ("/opt/vpn-service/data/../../etc/shadow", ".."),
        ("/etc/shadow", "outside the project data dir"),
    ],
)
def test_guard_refuses_unsafe_targets(tmp_path: Path, target: str, expected: str) -> None:
    """The guard fails closed (exit 2) and mutates nothing. The empty-path and "/"
    cases are the 2026-07-29 breakage; the rest keep the helper from wandering
    outside the project data dir."""
    proc = _call_function(
        tmp_path, f'guard_target "{target}"',
        env={"APP_DIR": "/opt/vpn-service"},
    )
    assert proc.returncode == 2, f"guard must fail closed on {target!r}: {proc.stdout}{proc.stderr}"
    assert expected in proc.stderr


def test_guard_refuses_an_empty_data_root(tmp_path: Path) -> None:
    """Emptied in the driver AFTER sourcing: `${VAR:-default}` already turns an
    empty environment variable back into the default, so this exercises the guard
    itself — the last line of defence if a future edit ever lets an empty root
    through to chown/chmod."""
    proc = _call_function(
        tmp_path,
        'DB_PERMS_DATA_ROOT=""\nguard_target "/opt/vpn-service/data/vpn.db"',
    )
    assert proc.returncode == 2
    assert "EMPTY" in proc.stderr


def test_empty_db_path_in_the_environment_falls_back_to_the_default(tmp_path: Path) -> None:
    """`DB_PATH=` (set but empty, e.g. a blank line in .env) must NOT resolve to an
    empty target — it falls back to the .env value and then to the constant."""
    proc = _call_function(
        tmp_path, "resolve_db_path",
        env={
            "APP_DIR": "/opt/vpn-service",
            "DB_PATH": "",
            "DB_PERMS_ENV_FILE": str(tmp_path / "absent"),
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "/opt/vpn-service/data/vpn.db"


def test_guard_refuses_a_data_root_of_slash(tmp_path: Path) -> None:
    proc = _call_function(
        tmp_path, 'guard_target "/vpn.db"',
        env={"DB_PERMS_DATA_ROOT": "/"},
    )
    assert proc.returncode == 2
    assert "filesystem root" in proc.stderr


def test_guard_accepts_the_project_db_path(tmp_path: Path) -> None:
    proc = _call_function(
        tmp_path, 'guard_target "/opt/vpn-service/data/vpn.db" && echo ACCEPTED',
        env={"APP_DIR": "/opt/vpn-service"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "ACCEPTED" in proc.stdout
    assert proc.stderr == ""


def test_a_run_with_an_unsafe_db_path_never_reaches_chown(tmp_path: Path) -> None:
    """End-to-end: the guard sits in front of every mutation, so an unsafe resolved
    path exits 2 with an empty mutation log."""
    app_dir = _app(tmp_path)
    rc, stderr, mutations = _run_helper(
        tmp_path, app_dir=app_dir, env={"DB_PATH": "/"},
    )
    assert rc == 2
    assert mutations == []
    assert "filesystem root" in stderr


# --------------------------------------------------------------------------- #
# (b4) the applying path
# --------------------------------------------------------------------------- #
def test_root_run_fixes_dir_db_and_both_sidecars(tmp_path: Path) -> None:
    app_dir = _app(tmp_path)
    data = app_dir / "data"
    # A wrong-mode, wrong-owner starting state (the owner mismatch is expressed by
    # asking for an owner the tmp files cannot already have).
    data.chmod(0o755)
    for name in ("vpn.db", "vpn.db-wal", "vpn.db-shm"):
        (data / name).chmod(0o644)
    rc, stderr, mutations = _run_helper(
        tmp_path, app_dir=app_dir, env={"DB_PERMS_OWNER": "vpn-bot:vpn-bot"},
    )
    assert rc == 0, stderr
    joined = "\n".join(mutations)
    for path in (data, data / "vpn.db", data / "vpn.db-wal", data / "vpn.db-shm"):
        assert f"chown vpn-bot:vpn-bot {path}" in joined
    assert f"chmod 0700 {data}" in joined
    for name in ("vpn.db", "vpn.db-wal", "vpn.db-shm"):
        assert f"chmod 0600 {data / name}" in joined
    # Only real changes are reported, and every reported line names the path.
    assert "chown" in stderr and str(data / "vpn.db") in stderr


def test_already_correct_state_is_silent(tmp_path: Path) -> None:
    """Idempotent: when owner and mode already match, nothing is called and nothing
    is logged. Silence in the journal means 'the host was already right'."""
    app_dir = _app(tmp_path)
    data = app_dir / "data"
    data.chmod(0o700)
    for name in ("vpn.db", "vpn.db-wal", "vpn.db-shm"):
        (data / name).chmod(0o600)
    # Ask for the owner the tmp tree already has, so only the modes could differ.
    owner = subprocess.run(
        ["stat", "-c", "%U:%G", str(data)], capture_output=True, text=True, check=True,
    ).stdout.strip()
    rc, stderr, mutations = _run_helper(
        tmp_path, app_dir=app_dir, env={"DB_PERMS_OWNER": owner},
    )
    assert rc == 0, stderr
    assert mutations == [], f"nothing should have been called: {mutations}"
    assert stderr == "", f"a correct host must stay silent: {stderr!r}"


def test_missing_db_is_a_valid_first_run_and_is_not_created(tmp_path: Path) -> None:
    app_dir = _app(tmp_path, with_db=False)
    data = app_dir / "data"
    data.chmod(0o755)
    rc, stderr, mutations = _run_helper(
        tmp_path, app_dir=app_dir, env={"DB_PERMS_OWNER": "vpn-bot:vpn-bot"},
    )
    assert rc == 0, stderr
    assert not (data / "vpn.db").exists(), "the helper must never create the DB"
    joined = "\n".join(mutations)
    # The data dir is still fixed; the absent DB is simply skipped.
    assert f"chmod 0700 {data}" in joined
    assert "vpn.db" not in joined


def test_absent_sidecars_are_skipped_not_reported(tmp_path: Path) -> None:
    """A cleanly-closed DB has no -wal/-shm; that is normal, not a fault."""
    app_dir = _app(tmp_path, with_sidecars=False)
    data = app_dir / "data"
    rc, stderr, mutations = _run_helper(
        tmp_path, app_dir=app_dir, env={"DB_PERMS_OWNER": "vpn-bot:vpn-bot"},
    )
    assert rc == 0, stderr
    joined = "\n".join(mutations)
    assert "vpn.db-wal" not in joined and "vpn.db-shm" not in joined
    assert f"chown vpn-bot:vpn-bot {data / 'vpn.db'}" in joined


def test_absent_target_user_is_a_no_op_and_never_fails_the_start(tmp_path: Path) -> None:
    """On a host without the reader user there are no non-root readers to hand the
    DB to. ExecStartPre must not fail the bot over it — warn, exit 0."""
    app_dir = _app(tmp_path)
    rc, stderr, mutations = _run_helper(
        tmp_path, app_dir=app_dir, user_exists=False,
        env={"DB_PERMS_OWNER": "vpn-bot:vpn-bot"},
    )
    assert rc == 0, stderr
    assert mutations == []
    assert "does not exist on this host" in stderr


# --------------------------------------------------------------------------- #
# (c) behavioural: the deploy.sh side, via the DEPLOY_SELFTEST seam
# --------------------------------------------------------------------------- #
def _deploy_driver(
    tmp_path: Path,
    snippet: str,
    *,
    stub_reader_user: bool | None = True,
    env: dict[str, str] | None = None,
) -> tuple[int, str, list[str]]:
    """Source deploy.sh through DEPLOY_SELFTEST=1 and run `snippet`.

    stub_reader_user: True  -> stub `id -u <user>` as existing
                      False -> stub it as missing
                      None  -> no `id` stub (use the real one)
    Returns (rc, stdout+stderr, chown/chmod calls) — never a real chown.
    """
    stub = tmp_path / "deploybin"
    stub.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "deploy-mutations.log"
    if stub_reader_user is not None:
        _make_stub(stub / "id", (
            'if [[ "$1" == "-u" && $# -eq 1 ]]; then echo 0; exit 0; fi\n'
            f'if [[ "$1" == "-u" && $# -eq 2 ]]; then exit {0 if stub_reader_user else 1}; fi\n'
            "exit 1\n"
        ))
    for tool in ("chown", "chmod"):
        _make_stub(stub / tool, f'echo "{tool} $*" >> "{log}"\nexit 0\n')
    _make_stub(stub / "systemctl", "exit 0\n")
    _make_stub(stub / "install", (
        'args=()\n'
        'while [[ $# -gt 0 ]]; do case "$1" in\n'
        '  -o|-g|-m) shift 2 ;;\n'
        '  -d) shift ;;\n'
        '  *) args+=("$1"); shift ;;\n'
        'esac; done\n'
        'cp "${args[0]}" "${args[1]}"\n'
    ))
    driver = tmp_path / "deploy-driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub}:$PATH"\n'
        f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic for the test environment.
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        f"{snippet}\n",
        encoding="utf-8",
    )
    run_env = dict(os.environ)
    run_env.update(env or {})
    proc = subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path), env=run_env,
        capture_output=True, text=True,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return proc.returncode, proc.stdout + proc.stderr, calls


def test_scan_emits_the_policy_field_and_defaults_it(tmp_path: Path) -> None:
    """The policy field is optional (two-field entries stay valid) and surfaces in
    the scan output so the installer can act on absent+required."""
    checkout = tmp_path / "repo" / "scripts"
    checkout.mkdir(parents=True)
    (checkout / "vpn-bot-db-perms").write_text("SRC\n", encoding="utf-8")
    (checkout / "legacy-helper").write_text("SRC\n", encoding="utf-8")
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    rc, out, _ = _deploy_driver(
        tmp_path,
        f'APP_DIR="{tmp_path / "repo"}"\n'
        "OUT_OF_REPO_HELPERS=(\n"
        f'  "scripts/vpn-bot-db-perms|{sbin}/vpn-bot-db-perms|required"\n'
        f'  "scripts/legacy-helper|{sbin}/legacy-helper"\n'
        ")\n"
        'scan_out_of_repo_helpers "$APP_DIR"\n',
    )
    assert rc == 0, out
    assert "|absent|required" in out
    assert "|absent|absent-ok" in out, "a two-field entry must default to absent-ok"


def test_install_installs_an_absent_required_helper(tmp_path: Path) -> None:
    """The clean-host case: vpn-bot.service names the helper in ExecStartPre, so an
    absent copy must be installed, not tolerated as 'subsystem not deployed'."""
    checkout = tmp_path / "repo" / "scripts"
    checkout.mkdir(parents=True)
    (checkout / "vpn-bot-db-perms").write_text("FRESH\n", encoding="utf-8")
    (checkout / "vpn-bot-warp-routes").write_text("FRESH\n", encoding="utf-8")
    sbin = tmp_path / "sbin"
    sbin.mkdir()
    rc, out, _ = _deploy_driver(
        tmp_path,
        f'APP_DIR="{tmp_path / "repo"}"\n'
        "OUT_OF_REPO_HELPERS=(\n"
        f'  "scripts/vpn-bot-db-perms|{sbin}/vpn-bot-db-perms|required"\n'
        f'  "scripts/vpn-bot-warp-routes|{sbin}/vpn-bot-warp-routes|absent-ok"\n'
        ")\n"
        f'WARP_ROUTES_HELPER="{sbin}/vpn-bot-warp-routes"\n'
        'U_PRE_ACTIVE["warp-routes.service"]="inactive"\n'
        'rollback_now() { echo "ROLLBACK_CALLED: $*"; exit 42; }\n'
        "install_out_of_repo_helpers\n",
    )
    assert rc == 0, out
    assert (sbin / "vpn-bot-db-perms").read_text() == "FRESH\n", (
        "the required helper must be installed on a host that lacks it"
    )
    # The absent-ok helper is still left absent (WARP not deployed here).
    assert not (sbin / "vpn-bot-warp-routes").exists()
    assert "required helper missing" in out


def _db_tree(tmp_path: Path, *, with_sidecars: bool = True) -> Path:
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "vpn.db").write_bytes(b"")
    if with_sidecars:
        (data / "vpn.db-wal").write_bytes(b"")
        (data / "vpn.db-shm").write_bytes(b"")
    return data


def test_assert_db_ownership_flags_every_wrong_owner(tmp_path: Path) -> None:
    """The post-deploy / post-restore gate: each offending path is reported with its
    actual and expected owner, and the function returns non-zero so the caller can
    route it through rollback."""
    data = _db_tree(tmp_path)
    rc, out, _ = _deploy_driver(
        tmp_path,
        f'DB_PATH="{data / "vpn.db"}"\n'
        'DB_OWNER_USER="a-user-that-owns-nothing"\n'
        'assert_db_ownership && echo UNEXPECTED_PASS || echo REPORTED\n',
    )
    assert rc == 0, out          # the driver itself exits 0; the message is the signal
    assert "UNEXPECTED_PASS" not in out and "REPORTED" in out
    for name in ("vpn.db", "vpn.db-wal", "vpn.db-shm"):
        assert f"{data / name} is owned by" in out
    assert f"{data} is owned by" in out, "the data dir is part of the contract too"
    assert "expected a-user-that-owns-nothing:a-user-that-owns-nothing" in out


def test_assert_db_ownership_passes_on_a_correct_tree(tmp_path: Path) -> None:
    data = _db_tree(tmp_path)
    owner = subprocess.run(
        ["stat", "-c", "%U", str(data)], capture_output=True, text=True, check=True,
    ).stdout.strip()
    rc, out, _ = _deploy_driver(
        tmp_path,
        f'DB_PATH="{data / "vpn.db"}"\n'
        f'DB_OWNER_USER="{owner}"\n'
        'assert_db_ownership || echo UNEXPECTED_FAIL\n',
    )
    assert rc == 0, out
    assert "UNEXPECTED_FAIL" not in out
    assert "is owned by" not in out, "no mismatch line may be printed for a correct tree"


def test_assert_db_ownership_tolerates_absent_sidecars_and_db(tmp_path: Path) -> None:
    """A cleanly-closed DB has no -wal/-shm, and a first-run host has no vpn.db —
    neither may be reported as a mismatch."""
    data = tmp_path / "data"
    data.mkdir()
    owner = subprocess.run(
        ["stat", "-c", "%U", str(data)], capture_output=True, text=True, check=True,
    ).stdout.strip()
    rc, out, _ = _deploy_driver(
        tmp_path,
        f'DB_PATH="{data / "vpn.db"}"\n'
        f'DB_OWNER_USER="{owner}"\n'
        'assert_db_ownership || echo UNEXPECTED_FAIL\n',
    )
    assert rc == 0, out
    assert "UNEXPECTED_FAIL" not in out


def test_assert_db_ownership_skips_when_the_reader_user_does_not_exist(tmp_path: Path) -> None:
    """A host without the reader user has no non-root readers — nothing to assert,
    and never a reason to roll a deploy back."""
    data = _db_tree(tmp_path)
    rc, out, _ = _deploy_driver(
        tmp_path,
        f'DB_PATH="{data / "vpn.db"}"\n'
        'DB_OWNER_USER="vpn-bot"\n'
        'assert_db_ownership || echo UNEXPECTED_FAIL\n',
        stub_reader_user=False,
    )
    assert rc == 0, out
    assert "UNEXPECTED_FAIL" not in out
    assert "ownership check skipped" in out


def test_assert_db_ownership_refuses_an_insane_db_path(tmp_path: Path) -> None:
    """Same rake-guard as the helper: deploy.sh must never stat/chown '/' either."""
    for bad in ("", "/", "relative/vpn.db"):
        rc, out, _ = _deploy_driver(
            tmp_path,
            f'DB_PATH="{bad}"\n'
            'DB_OWNER_USER="vpn-bot"\n'
            'assert_db_ownership && echo UNEXPECTED_PASS || echo REFUSED\n',
        )
        assert rc == 0, out
        assert "REFUSED" in out and "UNEXPECTED_PASS" not in out, f"DB_PATH={bad!r} must not pass the gate"
        assert "not a sane absolute DB path" in out


def test_fix_db_perms_hands_the_tree_to_the_reader_user(tmp_path: Path) -> None:
    """The rollback's repair step must target the READER user (vpn-bot) — not the
    bot's run user — and cover the data dir plus both sidecars. Targeting root:root
    (the old behaviour when the restored unit ran as root) is exactly what killed
    the readers after a restore."""
    data = _db_tree(tmp_path)
    rc, out, calls = _deploy_driver(
        tmp_path,
        f'DB_PATH="{data / "vpn.db"}"\n'
        'DB_OWNER_USER="vpn-bot"\n'
        'INSTALLED_USER="root"\n'
        "fix_db_perms\n",
    )
    assert rc == 0, out
    joined = "\n".join(calls)
    assert f"chown vpn-bot:vpn-bot {data}" in joined
    for name in ("vpn.db", "vpn.db-wal", "vpn.db-shm"):
        assert f"chown vpn-bot:vpn-bot {data / name}" in joined
    assert "root:root" not in joined
    assert f"chmod 0700 {data}" in joined
    assert f"chmod 0600 {data / 'vpn.db'}" in joined


def test_fix_db_perms_refuses_an_insane_db_path(tmp_path: Path) -> None:
    rc, out, calls = _deploy_driver(
        tmp_path,
        'DB_PATH="/"\n'
        'DB_OWNER_USER="vpn-bot"\n'
        'INSTALLED_USER="root"\n'
        "fix_db_perms || echo REFUSED\n",
    )
    assert rc == 0, out
    assert "REFUSED" in out
    assert calls == [], f"nothing may be chowned when DB_PATH is '/': {calls}"
