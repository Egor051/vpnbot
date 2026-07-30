"""Coverage for the restore/backup permission contract in `scripts/deploy.sh`.

CONFIRMED ROOT CAUSE (2026-07-29 outage)
    The backup archive written by an earlier deploy carried its own staging root
    as a member:

        drwx------ root/root       0  ./
        drwxr-xr-x root/root       0  ./opt/vpn-service/data/
        -rw-r--r-- root/root  602112  ./opt/vpn-service/data/vpn.db

    `mktemp -d` creates the staging root 0700, and `tar -czf … -C "$STAGE" .`
    records that mode on the archive's own "./" member. Unpacking such an archive
    with `tar -p -xzf … -C /` as root applies the "./" member's metadata to the
    extraction target itself — i.e. `chmod 700 /` — and every non-root unit then
    dies with status=200/CHDIR. The same extraction restored vpn.db as
    root:root 0644: world-readable secrets, plus root-owned -wal/-shm on the next
    open, which is what breaks the two vpn-bot WAL readers.

WHAT IS PINNED HERE — the three independent defences
  1. SOURCE: the archive is built harmless. The staging root is created
     explicitly 0755 (never inherited from `mktemp -d`), the staged data dir
     carries ${DB_DIR_MODE}, and the sqlite `.backup` snapshot is chowned to the
     reader user and chmod ${DB_FILE_MODE} BEFORE it is archived. Proven on a real
     archive built in a tmpdir.
  2. EXTRACTION: every tar-extract-into-/ carries --no-overwrite-dir, which
     preserves the metadata of already-existing directories (/, /opt, /usr, /etc).
     A static gate scans the shipped shell and the operator runbooks so the flag
     cannot be lost again.
  3. CANARY: assert_restore_permissions() re-checks, after any restore, that
     others can still traverse / and that the DB tree has the expected
     modes+owner — the last rubezh if 1 and 2 both fail (a stale archive unpacked
     by a future deploy.sh that dropped the flag).

Everything behavioural is driven through the existing DEPLOY_SELFTEST seam under
stubbed `id`/`chown`/`chmod`/`sqlite3`/`stat`. No test extracts anything into /,
and no test performs a real chown.
"""

import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
HELPER = ROOT / "scripts" / "vpn-bot-db-perms"
NO_OVERWRITE_DIR = "--no-overwrite-dir"

# Files an operator (or this script) can run as root to unpack a backup: the
# shipped shell plus the runbooks whose command blocks are meant to be pasted.
TAR_SOURCES = (
    ROOT / "scripts" / "deploy.sh",
    ROOT / "scripts" / "redeploy.sh",
    ROOT / "docs" / "operations.md",
    ROOT / "docs" / "operations.ru.md",
)

# `-C /` as the extraction target: "/" followed by whitespace or end of line, so
# `-C /root/vpn-service-backups/...` (a plain destination path) does not match.
INTO_ROOT = re.compile(r"-C\s+/(?:\s|$)")
# An extract: a short-option cluster containing `x` (-x, -xf, -xzf) or --extract.
# Deliberately does not match `--xattrs`, `-czf` or `-tzf`.
EXTRACTS = re.compile(r"(?<![-\w])-[A-Za-z]*x[A-Za-z]*(?![-\w])|--extract\b")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _tar_extract_into_root_lines(path: Path) -> list[str]:
    """Every line in `path` that unpacks a tar into /.

    Whole-line shell comments are skipped: the deploy script explains the outage
    by quoting the offending command, and prose about a bug is not a call site.
    """
    lines = []
    for raw in _read(path).splitlines():
        line = raw.strip()
        if path.suffix == ".sh" and line.startswith("#"):
            continue
        if "tar" in line and INTO_ROOT.search(line) and EXTRACTS.search(line):
            lines.append(line)
    return lines


# --------------------------------------------------------------------------- #
# (2) static gate — the flag cannot be lost
# --------------------------------------------------------------------------- #
def test_every_tar_extract_into_root_uses_no_overwrite_dir() -> None:
    """Regression gate for the root cause. Any command that unpacks an archive
    into / must preserve the metadata of the directories that are already there —
    otherwise one 0700 "./" member in a stale archive re-runs the outage."""
    offenders = []
    for path in TAR_SOURCES:
        if not path.exists():
            continue
        for line in _tar_extract_into_root_lines(path):
            if NO_OVERWRITE_DIR not in line:
                offenders.append(f"{path.relative_to(ROOT)}: {line}")
    assert not offenders, (
        "every tar-extract-into-/ must carry --no-overwrite-dir (a 0700 './' member "
        "would otherwise chmod / itself — the 2026-07-29 200/CHDIR outage):\n"
        + "\n".join(offenders)
    )


def test_the_gate_actually_sees_the_deploy_extraction() -> None:
    """Guard for the guard: if a refactor renames the extraction so the scanner
    stops matching it, the test above would pass vacuously."""
    found = _tar_extract_into_root_lines(DEPLOY_SH)
    assert len(found) == 1, f"expected exactly one extraction call site, found: {found}"
    assert NO_OVERWRITE_DIR in found[0]


def test_extraction_has_a_single_choke_point_called_by_rollback() -> None:
    text = _read(DEPLOY_SH)
    assert "restore_archive_into_root()" in text
    # rollback() must go through it rather than calling tar itself. Anchored on the
    # newline so `arm_rollback() {` cannot match instead.
    rb = text.index("\nrollback() {")
    window = text[rb : text.index("\n# ", rb + 100)]
    assert 'restore_archive_into_root "$ARCHIVE"' in window
    assert "tar " not in window.replace("`tar -xzf ... -C /`", ""), (
        "rollback() must unpack through restore_archive_into_root, not its own tar"
    )
    # The flag is documented as load-bearing so a cleanup pass does not drop it.
    idx = text.index("restore_archive_into_root() {")
    rationale = text[max(0, idx - 1500) : idx]
    assert "LOAD-BEARING" in rationale and "Do not remove it." in rationale


def test_root_cause_listing_is_recorded_next_to_the_extraction() -> None:
    """The archive listing that explains the outage stays in the file that has to
    keep defending against it."""
    text = _read(DEPLOY_SH)
    assert "2026-07-29" in text
    assert "drwx------ root/root" in text, "keep the proving listing next to the fix"
    assert "200/CHDIR" in text


# --------------------------------------------------------------------------- #
# (3) static gate — the canary runs after the restore
# --------------------------------------------------------------------------- #
def test_canary_is_defined_and_runs_after_the_extraction() -> None:
    text = _read(DEPLOY_SH)
    assert "assert_restore_permissions() {" in text
    extract = text.index('restore_archive_into_root "$ARCHIVE"')
    canary = text.index('canary_msg="$(assert_restore_permissions)"')
    assert extract < canary, "the canary must run AFTER the archive is unpacked"
    window = text[canary : canary + 700]
    assert "MANUAL ACTION REQUIRED" in window
    # It reports; repairing / by chmod is the class of bug that caused the outage.
    idx = text.index("assert_restore_permissions() {")
    rationale = text[max(0, idx - 900) : idx]
    assert "never repairs /" in rationale


def test_owner_resolution_is_not_duplicated() -> None:
    """The reader-user rule lives in db_target_owner() only: fix_db_perms, the
    staged snapshot and the canary all call it, so a future change to the owner
    cannot fix one call site and miss the other two."""
    text = _read(DEPLOY_SH)
    assert text.count("db_target_owner() {") == 1
    # The fallback chain exists exactly once — nobody re-derives the owner.
    assert text.count('"$INSTALLED_USER" != "root"') == 1
    for func in ("fix_db_perms() {", "stage_db_snapshot() {", "assert_restore_permissions() {"):
        idx = text.index(func)
        window = text[idx : idx + 1500]
        assert "db_target_owner" in window, f"{func} must resolve the owner via db_target_owner"


def test_deploy_modes_match_the_helper_constants() -> None:
    """deploy.sh and scripts/vpn-bot-db-perms must not disagree about the modes;
    the canary asserts what the helper applies."""
    deploy = _read(DEPLOY_SH)
    helper = _read(HELPER)
    assert 'DB_DIR_MODE="0700"' in deploy and 'DIR_MODE="700"' in helper
    assert 'DB_FILE_MODE="0600"' in deploy and 'FILE_MODE="600"' in helper


def test_deploy_sh_parses() -> None:
    subprocess.run(["bash", "-n", str(DEPLOY_SH)], check=True)


# --------------------------------------------------------------------------- #
# behavioural harness — DEPLOY_SELFTEST seam, stubbed id/chown/chmod/sqlite3/stat
# --------------------------------------------------------------------------- #
def _make_stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _stubs(tmp_path: Path, *, reader_exists: bool = True) -> tuple[Path, Path]:
    """Stub bin dir + mutation log. `chown` never really runs (the reader user does
    not exist in CI, and a test must not chown anything anyway)."""
    stub = tmp_path / "bin"
    stub.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "mutations.log"
    _make_stub(stub / "id", (
        'if [[ "$1" == "-u" && $# -eq 1 ]]; then echo 0; exit 0; fi\n'
        f'if [[ "$1" == "-u" && $# -eq 2 ]]; then exit {0 if reader_exists else 1}; fi\n'
        "exit 1\n"
    ))
    _make_stub(stub / "chown", f'echo "chown $*" >> "{log}"\nexit 0\n')
    return stub, log


def _run_driver(tmp_path: Path, stub: Path, body: str) -> subprocess.CompletedProcess[str]:
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export PATH="{stub}:$PATH"\n'
        f'source "{DEPLOY_SH}"\n'
        # deploy.sh sets `set -e` for the whole shell; the harness drives functions
        # whose non-zero return IS the result under test, so relax it here only.
        "set +e\n"
        # Neutralise the EXIT trap's venv/worktree/stage logic for the harness.
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        f"{body}\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env.pop("DB_PATH", None)
    env["TMPDIR"] = str(tmp_path)      # keep mktemp -d inside the test's tmpdir
    return subprocess.run(
        ["bash", str(driver)], env=env, cwd=str(tmp_path), capture_output=True, text=True,
    )


# --------------------------------------------------------------------------- #
# (1) the archive is correct at the source
# --------------------------------------------------------------------------- #
def test_stage_dir_is_created_0755_and_never_inherits_mktemp_0700(tmp_path: Path) -> None:
    """The staging root becomes the archive's "./" member. `mktemp -d` gives 0700,
    which is what chmod'd / to 0700 on 2026-07-29 — it must be set explicitly."""
    stub, _ = _stubs(tmp_path)
    proc = _run_driver(tmp_path, stub, 'd="$(make_stage_dir)"; stat -c "%a" "$d"; echo "DIR=$d"')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines()[0] == "755", proc.stdout
    # And it really is a fresh private dir, not a fixed name.
    created = [ln[4:] for ln in proc.stdout.splitlines() if ln.startswith("DIR=")][0]
    assert Path(created).is_dir()
    assert str(tmp_path) in created


def test_staged_sqlite_snapshot_is_handed_to_the_reader_at_0600(tmp_path: Path) -> None:
    """The snapshot is chowned to the reader user and tightened to 0600 BEFORE it
    is archived, so a restore cannot resurrect a root:root 0644 vpn.db."""
    stub, log = _stubs(tmp_path)
    live = tmp_path / "live" / "opt" / "vpn-service" / "data"
    live.mkdir(parents=True)
    (live / "vpn.db").write_bytes(b"SQLite format 3\0")
    _make_stub(stub / "sqlite3", (
        # Mimic `sqlite3 <db> ".backup '<dest>'"` running as root: 0644 output.
        'dest="${2#*\\\'}"; dest="${dest%\\\'*}"\n'
        'printf "SQLite format 3\\0" > "$dest"\nchmod 0644 "$dest"\nexit 0\n'
    ))
    proc = _run_driver(tmp_path, stub, (
        f'DB_PATH="{live}/vpn.db"\n'
        'STAGE="$(make_stage_dir)"\n'
        "manifest=()\n"
        "stage_db_snapshot\n"
        'echo "STAGED_DB_MODE=$(stat -c "%a" "${STAGE}${DB_PATH}")"\n'
        'echo "STAGED_DIR_MODE=$(stat -c "%a" "${STAGE}$(dirname "$DB_PATH")")"\n'
        'echo "STAGED_PARENT_MODE=$(stat -c "%a" "${STAGE}$(dirname "$(dirname "$DB_PATH")")")"\n'
        'echo "STAGED_DB=${STAGE}${DB_PATH}"\n'
    ))
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "STAGED_DB_MODE=600" in out, out
    assert "STAGED_DIR_MODE=700" in out, out
    # The dirs ABOVE the data dir must stay traversable: a 0700 /opt member is the
    # same outage one level down.
    assert "STAGED_PARENT_MODE=755" in out, out
    staged_db = [ln.split("=", 1)[1] for ln in out.splitlines() if ln.startswith("STAGED_DB=")][0]
    mutations = log.read_text(encoding="utf-8").splitlines()
    # Exactly one chown, on the STAGED copy — the live DB is never touched here.
    assert mutations == [f"chown vpn-bot:vpn-bot {staged_db}"], mutations


def test_built_archive_carries_no_hostile_directory_member(tmp_path: Path) -> None:
    """The end-to-end shape check, on a real archive built in a tmpdir: the "./"
    member must not be 0700 (the 2026-07-29 listing), the data dir must be 0700
    and vpn.db must be 0600."""
    stub, _ = _stubs(tmp_path)
    live = tmp_path / "live" / "opt" / "vpn-service" / "data"
    live.mkdir(parents=True)
    (live / "vpn.db").write_bytes(b"SQLite format 3\0")
    _make_stub(stub / "sqlite3", (
        'dest="${2#*\\\'}"; dest="${dest%\\\'*}"\n'
        'printf "SQLite format 3\\0" > "$dest"\nchmod 0644 "$dest"\nexit 0\n'
    ))
    archive = tmp_path / "backup.tar.gz"
    proc = _run_driver(tmp_path, stub, (
        f'DB_PATH="{live}/vpn.db"\n'
        'STAGE="$(make_stage_dir)"\n'
        "manifest=()\n"
        "stage_db_snapshot\n"
        f'create_backup_archive "{archive}"\n'
    ))
    assert proc.returncode == 0, proc.stderr
    with tarfile.open(archive) as tf:
        members = {m.name: m for m in tf.getmembers()}
    # tar writes the staging root as "./"; tarfile reports the normalised ".".
    assert "." in members, sorted(members)
    root_mode = members["."].mode
    assert root_mode != 0o700, "the './' member is what a root extraction applies to / itself"
    assert root_mode == 0o755, f"expected 0755 on './', got {root_mode:04o}"
    data_member = members["." + str(live)]
    assert data_member.mode == 0o700, f"data dir must stay owner-only, got {data_member.mode:04o}"
    db_member = members["." + str(live / "vpn.db")]
    assert db_member.mode == 0o600, f"vpn.db must be 0600 in the archive, got {db_member.mode:04o}"
    # No directory member anywhere may be owner-only except the data dir itself:
    # every one of them is a chmod applied to a real host directory on restore.
    owner_only = [
        m.name for m in members.values()
        if m.isdir() and (m.mode & 0o001) == 0 and m.name != "." + str(live)
    ]
    assert not owner_only, f"directory members that would strip the traverse bit: {owner_only}"


# --------------------------------------------------------------------------- #
# (3) the canary
# --------------------------------------------------------------------------- #
def _canary(
    tmp_path: Path,
    *,
    overrides: dict[str, tuple[str, str]] | None = None,
    with_db: bool = True,
    with_sidecars: bool = True,
    db_path: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Drive assert_restore_permissions() with a stubbed `stat`.

    The tree is real (the function tests existence with -d/-e), the METADATA is
    stubbed: `overrides` maps a path to (mode, owner), everything else answers
    0755 root:root — including the real ancestors up to /, which no test may
    depend on or modify. Defaults describe a correct host, so each test only
    states the one thing it breaks.
    """
    stub, _ = _stubs(tmp_path)
    fsroot = tmp_path / "fsroot"
    shutil.rmtree(fsroot, ignore_errors=True)   # a test may drive the canary twice
    data = fsroot / "opt" / "vpn-service" / "data"
    data.mkdir(parents=True)
    db = data / "vpn.db"
    if with_db:
        db.write_bytes(b"")
        if with_sidecars:
            (data / "vpn.db-wal").write_bytes(b"")
            (data / "vpn.db-shm").write_bytes(b"")

    table = {str(data): ("700", "vpn-bot:vpn-bot")}
    for name in ("vpn.db", "vpn.db-wal", "vpn.db-shm"):
        table[str(data / name)] = ("600", "vpn-bot:vpn-bot")
    table.update(overrides or {})

    table_file = tmp_path / "stat.table"
    table_file.write_text(
        "".join(f"{p}\t{mode}\t{owner}\n" for p, (mode, owner) in table.items()),
        encoding="utf-8",
    )
    _make_stub(stub / "stat", (
        'fmt="$1"; path="$2"\n'
        'if [[ "$1" == "-c" ]]; then fmt="$2"; path="$3"; fi\n'
        'mode="755"; owner="root:root"\n'
        'while IFS=$\'\\t\' read -r p m o; do\n'
        '  [[ "$p" == "$path" ]] || continue\n'
        '  mode="$m"; owner="$o"\n'
        f'done < "{table_file}"\n'
        'case "$fmt" in\n'
        "  '%a') printf '%s\\n' \"$mode\" ;;\n"
        "  '%U:%G') printf '%s\\n' \"$owner\" ;;\n"
        '  *) exit 1 ;;\n'
        "esac\n"
    ))
    return _run_driver(tmp_path, stub, (
        f'DB_PATH="{db_path if db_path is not None else db}"\n'
        'msg="$(assert_restore_permissions)"; rc=$?\n'
        'printf "RC=%s\\n" "$rc"\n'
        'printf "%s\\n" "$msg"\n'
    ))


def test_canary_passes_on_a_correctly_restored_tree(tmp_path: Path) -> None:
    proc = _canary(tmp_path)
    assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
    assert "traversable" in proc.stdout


def test_canary_catches_the_traverse_bit_stripped_from_filesystem_root(tmp_path: Path) -> None:
    """THE outage. A 0700 "/" is invisible to this deploy (it runs as root) and
    fatal to every non-root unit, so the canary has to say so out loud."""
    proc = _canary(tmp_path, overrides={"/": ("700", "root:root")})
    assert "RC=1" in proc.stdout, proc.stdout + proc.stderr
    assert "/ is mode 0700" in proc.stdout
    assert "200/CHDIR" in proc.stdout
    assert "chmod o+rx /" in proc.stdout, "the operator needs the exact repair command"


def test_canary_catches_an_intermediate_directory_losing_the_traverse_bit(tmp_path: Path) -> None:
    """Same failure one level down: a 0700 /opt is equally fatal to the readers."""
    opt = str((tmp_path / "fsroot" / "opt").resolve())
    proc = _canary(tmp_path, overrides={opt: ("700", "root:root")})
    assert "RC=1" in proc.stdout, proc.stdout + proc.stderr
    assert f"{opt} is mode 0700" in proc.stdout


def test_canary_catches_the_root_owned_world_readable_db_from_the_outage(tmp_path: Path) -> None:
    """`-rw-r--r-- root/root ./opt/vpn-service/data/vpn.db` — the second half of
    the 2026-07-29 restore: world-readable secrets and root-owned WAL sidecars."""
    db = str((tmp_path / "fsroot" / "opt" / "vpn-service" / "data" / "vpn.db").resolve())
    proc = _canary(tmp_path, overrides={db: ("644", "root:root")})
    assert "RC=1" in proc.stdout, proc.stdout + proc.stderr
    assert f"{db} is mode 0644, expected 0600" in proc.stdout
    assert f"{db} is owned by root:root, expected vpn-bot:vpn-bot" in proc.stdout


def test_canary_catches_a_loosened_data_dir(tmp_path: Path) -> None:
    data = str((tmp_path / "fsroot" / "opt" / "vpn-service" / "data").resolve())
    proc = _canary(tmp_path, overrides={data: ("755", "vpn-bot:vpn-bot")})
    assert "RC=1" in proc.stdout, proc.stdout + proc.stderr
    assert f"{data} is mode 0755, expected 0700" in proc.stdout


def test_canary_tolerates_a_closed_db_and_a_first_run_host(tmp_path: Path) -> None:
    """Absent -wal/-shm (cleanly closed) and an absent vpn.db (first run) are valid
    states, not findings — the canary must not invent failures after a restore."""
    closed = _canary(tmp_path, with_sidecars=False)
    assert "RC=0" in closed.stdout, closed.stdout + closed.stderr
    first_run = _canary(tmp_path, with_db=False)
    assert "RC=0" in first_run.stdout, first_run.stdout + first_run.stderr


def test_canary_refuses_an_insane_db_path(tmp_path: Path) -> None:
    """Same fail-closed guard as fix_db_perms: never reason about "/" or an empty
    path — that is the bug class that took the host down in the first place."""
    for bad in ("/", "", "relative/vpn.db"):
        proc = _canary(tmp_path, db_path=bad)
        assert "RC=1" in proc.stdout, f"{bad!r}: {proc.stdout}{proc.stderr}"
        assert "not a sane absolute DB path" in proc.stdout


def test_canary_expectation_follows_the_reader_user(tmp_path: Path) -> None:
    """With no reader user on the host, db_target_owner falls back to root:root and
    the canary must expect THAT — not fail a host that has no non-root readers."""
    stub, _ = _stubs(tmp_path, reader_exists=False)
    fsroot = tmp_path / "fsroot"
    data = fsroot / "opt" / "vpn-service" / "data"
    data.mkdir(parents=True)
    (data / "vpn.db").write_bytes(b"")
    table_file = tmp_path / "stat.table"
    table_file.write_text(
        f"{data}\t700\troot:root\n{data / 'vpn.db'}\t600\troot:root\n", encoding="utf-8"
    )
    _make_stub(stub / "stat", (
        'fmt="$1"; path="$2"\n'
        'if [[ "$1" == "-c" ]]; then fmt="$2"; path="$3"; fi\n'
        'mode="755"; owner="root:root"\n'
        'while IFS=$\'\\t\' read -r p m o; do\n'
        '  [[ "$p" == "$path" ]] || continue\n'
        '  mode="$m"; owner="$o"\n'
        f'done < "{table_file}"\n'
        'case "$fmt" in\n'
        "  '%a') printf '%s\\n' \"$mode\" ;;\n"
        "  '%U:%G') printf '%s\\n' \"$owner\" ;;\n"
        '  *) exit 1 ;;\n'
        "esac\n"
    ))
    proc = _run_driver(tmp_path, stub, (
        f'DB_PATH="{data / "vpn.db"}"\n'
        'INSTALLED_USER="root"\n'
        'msg="$(assert_restore_permissions)"; rc=$?\n'
        'printf "RC=%s\\n" "$rc"\nprintf "%s\\n" "$msg"\n'
    ))
    assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
    assert "root:root" in proc.stdout
