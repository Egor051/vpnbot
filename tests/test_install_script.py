"""Behavioural coverage for scripts/install.sh through its INSTALL_SELFTEST seam.

The whole installer runs end to end only on a real systemd VM — that is the
``installer-e2e`` CI job (tests/e2e/). Here the individual functions are driven
against stubbed host tools, so the rules that make the installer safe are pinned
on every pytest run, deploy Phase 1 included:

* the bot token never reaches an argv, the log or the terminal;
* rollback follows the manifest in reverse and never deletes outside its paths;
* claim.json holds only sha256(code) and an expiry, root-only, in exactly the
  format the bot's reader (services/superadmin_claim.py) accepts;
* readiness is the "Run polling" marker after the start offset, with no
  ERROR/CRITICAL/Traceback in that range;
* the superadmin check opens the database read-only.

Hermeticity: every host command these functions reach is stubbed on PATH
(systemctl, journalctl, curl where used); chown and the -o/-g of install are
neutralised so the suite also runs unprivileged in CI.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "scripts" / "install.sh"
TOKEN = "123456789:AAH" + "x" * 32

pytestmark = pytest.mark.timeout(60)

_PRELUDE = r"""
set -Eeuo pipefail
INSTALL_SELFTEST=1 source "$INSTALL_SH"
# Unprivileged runs: ownership is not what these tests check.
chown() { :; }
install() {
  local args=()
  while (($#)); do
    case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
  done
  command install "${args[@]}"
}
APP_DIR="$T/opt/vpn-service"
ENV_FILE="$APP_DIR/.env"
UNIT_PATH="$T/etc/systemd/system/vpn-bot.service"
DB_PERMS_HELPER="$T/usr/local/sbin/vpn-bot-db-perms"
SBIN_DIR="$T/usr/local/sbin"
CLAIM_DIR="$T/etc/vpn-bot"
CLAIM_FILE="$CLAIM_DIR/claim.json"
INSTALL_LOG_DIR="$T/var/log"
mkdir -p "$INSTALL_LOG_DIR" "$(dirname "$UNIT_PATH")" "$(dirname "$DB_PERMS_HELPER")"
"""


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(
    tmp_path: Path,
    body: str,
    *,
    stdin: str = "",
    systemctl: str = 'case "$*" in *NRestarts*) echo 0;; *ActiveState*) echo active;; esac\nexit 0\n',
    curl: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    stubs = tmp_path / "stub"
    stubs.mkdir(exist_ok=True)
    _stub(stubs, "systemctl", f'printf "%s\\n" "$*" >> "{tmp_path}/systemctl.args"\n' + systemctl)
    _stub(stubs, "journalctl", "exit 0\n")
    if curl is not None:
        _stub(stubs, "curl", curl)
    env = {
        "PATH": f"{stubs}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "T": str(tmp_path),
        "INSTALL_SH": str(INSTALL_SH),
        "LC_ALL": "C.UTF-8",
        **(extra_env or {}),
    }
    return subprocess.run(
        ["bash", "-c", _PRELUDE + body],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=50,
        check=False,
    )


def _ok(result: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    assert result.returncode == 0, f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
    return result


def test_script_parses() -> None:
    subprocess.run(["bash", "-n", str(INSTALL_SH)], check=True)


def test_selftest_seam_does_nothing(tmp_path: Path) -> None:
    result = _ok(_run(tmp_path, "echo seam-returned"))
    assert result.stdout.strip() == "seam-returned"
    assert not (tmp_path / "systemctl.args").exists()


# ── the token ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("token", "valid"),
    [
        (TOKEN, True),
        ("123456:" + "A" * 30, True),
        ("12345:" + "A" * 35, False),  # id too short
        ("1234567890123:" + "A" * 35, False),  # id too long
        ("123456789:" + "A" * 29, False),  # secret too short
        ("123456789:" + "A" * 30 + "!", False),
        ("123456789 " + "A" * 35, False),
        ("", False),
    ],
)
def test_token_format(tmp_path: Path, token: str, valid: bool) -> None:
    result = _ok(_run(tmp_path, 'valid_token_format "$TOK" && echo yes || echo no', extra_env={"TOK": token}))
    assert result.stdout.strip() == ("yes" if valid else "no")


def test_get_me_sends_the_token_on_stdin_never_in_argv(tmp_path: Path) -> None:
    curl = f"""
printf '%s\\n' "$@" > "{tmp_path}/curl.argv"
cat > "{tmp_path}/curl.stdin"
echo '{{"ok": true, "result": {{"id": 1, "is_bot": true, "first_name": "B", "username": "my_vpn_bot"}}}}'
"""
    result = _ok(
        _run(
            tmp_path,
            f'TG_API_BASE=http://127.0.0.1:1; telegram_get_me "{TOKEN}"',
            curl=curl,
        )
    )
    assert result.stdout.strip() == "my_vpn_bot"
    argv = (tmp_path / "curl.argv").read_text()
    assert TOKEN not in argv
    assert "-K" in argv.split()
    assert (tmp_path / "curl.stdin").read_text().strip() == f'url = "http://127.0.0.1:1/bot{TOKEN}/getMe"'


@pytest.mark.parametrize(
    "reply",
    [
        '{"ok": false, "error_code": 401, "description": "Unauthorized"}',
        '{"ok": true, "result": {"is_bot": false, "username": "a_person"}}',
        '{"ok": true, "result": {"is_bot": true, "username": "bad name!"}}',
        "not json",
    ],
)
def test_get_me_rejects_anything_but_a_bot(tmp_path: Path, reply: str) -> None:
    curl = f"cat >/dev/null; echo '{reply}'\n"
    result = _run(tmp_path, f'telegram_get_me "{TOKEN}" && echo accepted || echo rejected', curl=curl)
    assert result.stdout.strip().splitlines()[-1] == "rejected"


def test_read_token_retries_and_never_echoes_it(tmp_path: Path) -> None:
    curl = (
        'grep -q "AAHgood" && echo \'{"ok": true, "result": {"is_bot": true, "username": "good_bot"}}\''
        " || echo '{\"ok\": false}'\n"
    )
    good = "123456789:AAHgood" + "y" * 30
    result = _ok(
        _run(
            tmp_path,
            'open_log; read_token; echo "user=$BOT_USERNAME"; [[ "$BOT_TOKEN" == "' + good + '" ]] && echo token-kept',
            stdin=f"not-a-token\n{TOKEN}\n{good}\n",
            curl=curl,
        )
    )
    assert "user=good_bot" in result.stdout and "token-kept" in result.stdout
    assert TOKEN not in result.stderr and good not in result.stderr
    log = next((tmp_path / "var/log").glob("vpn-bot-install.*.log")).read_text()
    assert TOKEN not in log and good not in log


def test_redact_hides_tokens_and_claim_codes(tmp_path: Path) -> None:
    result = _ok(_run(tmp_path, f'printf "%s\\n" "t={TOKEN} l=https://t.me/b?start=claim_AbCdEfGh12345678" | redact'))
    assert TOKEN not in result.stdout and "AbCdEfGh12345678" not in result.stdout
    assert "<redacted-bot-token>" in result.stdout and "claim_<redacted>" in result.stdout


@pytest.mark.parametrize(
    ("base", "ok"),
    [
        ("https://api.telegram.org", True),
        ("https://bot-api.example.com:8443/x", True),
        ("http://127.0.0.1:8081", True),
        ("http://localhost:8081", True),
        ("http://[::1]:8081", True),
        ("http://bot-api.example.com", False),  # the token would travel in clear text
        ("http://127.0.0.1.evil.example", False),
        ("ftp://127.0.0.1", False),
        ("https://user:pw@example.com", False),
        ("https://example.com/?q=1", False),
    ],
)
def test_api_base_rule_matches_the_bots(tmp_path: Path, base: str, ok: bool) -> None:
    result = _ok(_run(tmp_path, 'valid_api_base "$B" && echo yes || echo no', extra_env={"B": base}))
    assert result.stdout.strip() == ("yes" if ok else "no")


# ── questions ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(("answer", "mode"), [("1", "main"), ("2", "relay"), ("x\n 2 ", "relay")])
def test_ask_mode(tmp_path: Path, answer: str, mode: str) -> None:
    result = _ok(_run(tmp_path, 'ask_mode; echo "mode=$MODE"', stdin=answer + "\n"))
    assert result.stdout.strip() == f"mode={mode}"


def test_ask_mode_without_an_answer_fails(tmp_path: Path) -> None:
    result = _run(tmp_path, "ask_mode", stdin="")
    assert result.returncode == 1


# ── .env ──────────────────────────────────────────────────────────────────────


def _checkout(tmp_path: Path) -> Path:
    app = tmp_path / "opt/vpn-service"
    app.mkdir(parents=True)
    (app / ".env.example").write_text((ROOT / ".env.example").read_text(encoding="utf-8"), encoding="utf-8")
    return app


@pytest.mark.parametrize("api_base", ["https://api.telegram.org", "http://127.0.0.1:8081"])
def test_write_env_from_example(tmp_path: Path, api_base: str) -> None:
    app = _checkout(tmp_path)
    _ok(_run(tmp_path, f'open_log; BOT_TOKEN="{TOKEN}"; TG_API_BASE="{api_base}"; write_env'))

    env_file = app / ".env"
    assert env_file.stat().st_mode & 0o777 == 0o600
    values = dict(
        line.split("=", 1) for line in env_file.read_text().splitlines() if re.match(r"^[A-Z][A-Z0-9_]*=", line)
    )
    assert values["BOT_TOKEN"] == TOKEN
    assert values["ADMIN_IDS"] == ""
    enabled = {k: v for k, v in values.items() if k.endswith("_ENABLED")}
    assert enabled and set(enabled.values()) == {"false"}
    assert not [v for v in values.values() if v.startswith("<") and v.endswith(">")]
    if api_base.startswith("http://"):
        assert values["TELEGRAM_API_BASE"] == api_base
    else:
        assert "TELEGRAM_API_BASE" not in values
    assert (app / "data").stat().st_mode & 0o777 == 0o700
    assert (app / "logs").stat().st_mode & 0o777 == 0o700
    assert not list(app.glob(".env.*[!e]")), "no temp file left behind"
    log = next((tmp_path / "var/log").glob("vpn-bot-install.*.log")).read_text()
    assert TOKEN not in log


def test_generated_env_loads_with_the_bot_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The .env the installer writes must start the bot: ADMIN_IDS empty, protocols off."""
    from config.settings import load_settings

    app = _checkout(tmp_path)
    _ok(_run(tmp_path, f'open_log; BOT_TOKEN="{TOKEN}"; TG_API_BASE="http://127.0.0.1:8081"; write_env'))
    for key in list(os.environ):
        if key in {"BOT_TOKEN", "ADMIN_IDS", "TELEGRAM_API_BASE"}:
            monkeypatch.delenv(key)
    settings = load_settings(app / ".env")
    assert settings.admin_ids == frozenset()
    assert settings.telegram_api_base == "http://127.0.0.1:8081"
    assert not (settings.socks5_enabled or settings.mtproto_enabled or settings.hysteria2_enabled)
    assert not (settings.subscription_enabled or settings.xray_xhttp_enabled)


# ── the claim ─────────────────────────────────────────────────────────────────


def test_issue_claim_stores_only_the_hash_in_the_bots_format(tmp_path: Path) -> None:
    from services.superadmin_claim import claim_payload, read_pending_claim

    result = _ok(
        _run(tmp_path, 'open_log; BOT_USERNAME=my_vpn_bot; issue_claim; printf "%s\\n" "$CLAIM_LINK"')
    )
    link = result.stdout.strip()
    match = re.fullmatch(r"https://t\.me/my_vpn_bot\?start=(claim_[A-Za-z0-9_-]+)", link)
    assert match is not None
    payload = match.group(1)
    assert len(payload) <= 64
    code = claim_payload(payload)
    assert code is not None and len(code) == 22  # 128 bits

    claim_file = tmp_path / "etc/vpn-bot/claim.json"
    assert claim_file.stat().st_mode & 0o777 == 0o600
    raw = claim_file.read_text()
    assert code not in raw
    data = json.loads(raw)
    assert set(data) == {"version", "code_sha256", "expires_at"}
    pending = read_pending_claim(claim_file)
    assert pending.code_sha256 == hashlib.sha256(code.encode()).hexdigest()
    assert abs(pending.expires_at - (time.time() + 1800)) < 60
    log = next((tmp_path / "var/log").glob("vpn-bot-install.*.log")).read_text()
    assert code not in log
    assert [p.name for p in claim_file.parent.iterdir()] == ["claim.json"]


def test_two_claims_never_share_a_code(tmp_path: Path) -> None:
    result = _ok(
        _run(tmp_path, 'open_log; BOT_USERNAME=my_vpn_bot; issue_claim; a=$CLAIM_LINK; issue_claim; [[ "$a" != "$CLAIM_LINK" ]] && echo distinct')
    )
    assert result.stdout.strip() == "distinct"


def test_print_claim_keeps_the_link_out_of_the_log(tmp_path: Path) -> None:
    result = _ok(
        _run(tmp_path, 'open_log; BOT_USERNAME=my_vpn_bot; issue_claim; print_claim 2>/dev/null')
    )
    assert "start=claim_" in result.stdout
    log = next((tmp_path / "var/log").glob("vpn-bot-install.*.log")).read_text()
    assert "start=claim_" not in log


# ── manifest and rollback ─────────────────────────────────────────────────────


def test_rollback_follows_the_manifest_in_reverse(tmp_path: Path) -> None:
    body = r"""
open_log
manifest_add dir "$APP_DIR"
mkdir -p "$APP_DIR/sub"; echo x > "$APP_DIR/sub/f"
echo original > "$UNIT_PATH"
manifest_add replaced "$UNIT_PATH" "$UNIT_PATH.vpn-bot-install.T.bak"
cp "$UNIT_PATH" "$UNIT_PATH.vpn-bot-install.T.bak"; echo new > "$UNIT_PATH"
manifest_add file "$DB_PERMS_HELPER"; echo helper > "$DB_PERMS_HELPER"
manifest_add enabled vpn-bot.service
manifest_add dir "$CLAIM_DIR"; mkdir -p "$CLAIM_DIR"
manifest_add file "$CLAIM_FILE"; echo '{}' > "$CLAIM_FILE"
manifest_add apt qrencode
rollback
for p in "$APP_DIR" "$DB_PERMS_HELPER" "$CLAIM_DIR" "$UNIT_PATH.vpn-bot-install.T.bak"; do
  [[ -e "$p" ]] && echo "LEFT $p"
done
cat "$UNIT_PATH"
tail -n1 "$MANIFEST"
"""
    result = _ok(_run(tmp_path, body))
    assert "LEFT" not in result.stdout
    lines = result.stdout.strip().splitlines()
    assert lines[0] == "original", "the replaced unit is restored"
    assert lines[1].startswith("# rolled back")
    calls = (tmp_path / "systemctl.args").read_text().splitlines()
    assert calls[0] == "disable --now vpn-bot.service"
    assert "daemon-reload" in calls
    log = next((tmp_path / "var/log").glob("vpn-bot-install.*.log")).read_text()
    assert "package qrencode stays installed" in log


def test_rollback_restarts_a_unit_it_restarted_after_restoring_files(tmp_path: Path) -> None:
    body = r"""
open_log
echo old > "$UNIT_PATH"
manifest_add replaced "$UNIT_PATH" "$UNIT_PATH.vpn-bot-install.T.bak"
cp "$UNIT_PATH" "$UNIT_PATH.vpn-bot-install.T.bak"; echo new > "$UNIT_PATH"
manifest_add restart vpn-bot.service
rollback
cat "$UNIT_PATH"
"""
    result = _ok(_run(tmp_path, body))
    assert result.stdout.strip() == "old"
    calls = (tmp_path / "systemctl.args").read_text().splitlines()
    assert calls.index("daemon-reload") < calls.index("restart vpn-bot.service")


@pytest.mark.parametrize("path", ["/", "", "relative/x", "/etc/passwd", "/opt/other", "/opt/vpn-service/../etc"])
def test_rollback_refuses_paths_that_are_not_ours(tmp_path: Path, path: str) -> None:
    result = _ok(_run(tmp_path, f'path_is_ours "{path}" && echo ours || echo refused'))
    assert result.stdout.strip() == "refused"


def test_rollback_does_not_delete_a_foreign_path_in_the_manifest(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("keep")
    _ok(_run(tmp_path, f'open_log; manifest_add file "{victim}"; manifest_add dir "{tmp_path}"; rollback'))
    assert victim.read_text() == "keep"


def test_error_after_arming_rolls_back_and_exits_1(tmp_path: Path) -> None:
    body = r"""
open_log
arm_rollback
manifest_add dir "$APP_DIR"
mkdir -p "$APP_DIR"
false
echo not-reached
"""
    result = _run(tmp_path, body)
    assert result.returncode == 1
    assert "not-reached" not in result.stdout
    assert not (tmp_path / "opt/vpn-service").exists()


def test_die_after_arming_rolls_back(tmp_path: Path) -> None:
    """`exit` does not fire the ERR trap: a deliberate refusal must roll back itself."""
    body = r"""
open_log
arm_rollback
manifest_add dir "$APP_DIR"
mkdir -p "$APP_DIR"
die "refused half-way"
"""
    result = _run(tmp_path, body)
    assert result.returncode == 1
    assert not (tmp_path / "opt/vpn-service").exists()
    manifest = next((tmp_path / "var/log").glob("vpn-bot-install.*.manifest")).read_text()
    assert manifest.rstrip().splitlines()[-1].startswith("# rolled back")


def test_die_before_arming_touches_nothing(tmp_path: Path) -> None:
    keep = tmp_path / "opt/vpn-service"
    keep.mkdir(parents=True)
    result = _run(tmp_path, 'open_log; manifest_add dir "$APP_DIR"; die "precondition"')
    assert result.returncode == 1
    assert keep.is_dir(), "nothing was armed, so nothing may be rolled back"


def test_ref_without_claim_support_leaves_no_checkout(tmp_path: Path) -> None:
    """A release that predates the claim (v3.0.0): refused, and the clone is gone."""
    repo = tmp_path / "old-release"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "README.md").write_text("old\n")
    subprocess.run([*git, "add", "README.md"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "old"], check=True)
    sha = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()

    result = _run(
        tmp_path,
        f'open_log; arm_rollback; INSTALL_REPO="file://{repo}"; INSTALL_REF_RESOLVED="{sha}"; clone_checkout',
    )

    assert result.returncode == 1
    assert "не поддерживает установку через claim" in result.stderr
    assert not (tmp_path / "opt/vpn-service").exists()


def test_injected_failure_point(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        'open_log; arm_rollback; manifest_add dir "$APP_DIR"; mkdir -p "$APP_DIR"; '
        "INSTALL_INJECT_FAILURE=after_start; fail_point after_env; echo passed-other; fail_point after_start; echo not-reached",
    )
    assert result.returncode == 1
    assert "passed-other" in result.stdout and "not-reached" not in result.stdout
    assert not (tmp_path / "opt/vpn-service").exists()


def test_commit_disarms_rollback_and_drops_backups(tmp_path: Path) -> None:
    body = r"""
open_log
arm_rollback
echo old > "$UNIT_PATH"
manifest_add replaced "$UNIT_PATH" "$UNIT_PATH.vpn-bot-install.T.bak"
cp "$UNIT_PATH" "$UNIT_PATH.vpn-bot-install.T.bak"
commit
[[ -e "$UNIT_PATH.vpn-bot-install.T.bak" ]] && echo backup-left
tail -n1 "$MANIFEST"
"""
    result = _ok(_run(tmp_path, body))
    assert "backup-left" not in result.stdout
    assert result.stdout.strip().startswith("# committed")


def test_install_file_is_idempotent_and_records_what_it_did(tmp_path: Path) -> None:
    body = r"""
open_log
mkdir -p "$APP_DIR/deploy"; echo unit-v1 > "$APP_DIR/deploy/u"
install_file "$APP_DIR/deploy/u" "$UNIT_PATH" 0644
install_file "$APP_DIR/deploy/u" "$UNIT_PATH" 0644
echo unit-v2 > "$APP_DIR/deploy/u"
install_file "$APP_DIR/deploy/u" "$UNIT_PATH" 0644
cut -f1 "$MANIFEST" | grep -v '^#' | tr '\n' ' '
echo; cat "$UNIT_PATH"
"""
    result = _ok(_run(tmp_path, body))
    records, content = result.stdout.strip().splitlines()
    assert records.split() == ["file", "file", "replaced", "file"]
    assert content == "unit-v2"
    assert oct((tmp_path / "etc/systemd/system/vpn-bot.service").stat().st_mode & 0o777) == "0o644"


# ── readiness ─────────────────────────────────────────────────────────────────


def _bot_log(tmp_path: Path, before: str, after: str) -> tuple[Path, int]:
    log = tmp_path / "bot.log"
    log.write_text(before)
    offset = log.stat().st_size
    log.write_text(before + after)
    return log, offset


POLLING = "2026-01-01T00:00:00+0000 INFO [aiogram.dispatcher] Run polling for bot @my_vpn_bot id=1 - 'B'\n"


def test_ready_on_the_marker_after_the_offset(tmp_path: Path) -> None:
    old_error = "2026-01-01T00:00:00+0000 ERROR [x] from the previous run\n"
    log, offset = _bot_log(tmp_path, POLLING + old_error, "2026-01-01 INFO [main] VPN bot started\n" + POLLING)
    _ok(_run(tmp_path, f'open_log; READY_TIMEOUT=5; wait_ready "{log}" {offset} 0'))


@pytest.mark.parametrize(
    "bad",
    [
        "2026-01-01T00:00:00+0000 ERROR [services.x] boom\n",
        "2026-01-01T00:00:00+0000 CRITICAL [services.xray] degraded\n",
        "Traceback (most recent call last):\n  File x\n",
    ],
)
def test_not_ready_with_errors_since_the_offset(tmp_path: Path, bad: str) -> None:
    log, offset = _bot_log(tmp_path, "", bad + POLLING)
    result = _run(tmp_path, f'open_log; READY_TIMEOUT=5; wait_ready "{log}" {offset} 0')
    assert result.returncode == 1


def test_a_message_that_merely_mentions_error_is_not_an_error(tmp_path: Path) -> None:
    log, offset = _bot_log(tmp_path, "", "2026-01-01T00:00:00+0000 INFO [x] ERROR budget fine\n" + POLLING)
    _ok(_run(tmp_path, f'open_log; READY_TIMEOUT=5; wait_ready "{log}" {offset} 0'))


def test_old_marker_before_the_offset_does_not_count(tmp_path: Path) -> None:
    log, offset = _bot_log(tmp_path, POLLING, "")
    started = time.monotonic()
    result = _run(tmp_path, f'open_log; READY_TIMEOUT=1; wait_ready "{log}" {offset} 0')
    assert result.returncode == 1
    assert time.monotonic() - started < 10


def test_failed_unit_ends_the_wait_at_once(tmp_path: Path) -> None:
    log, offset = _bot_log(tmp_path, "", "")
    started = time.monotonic()
    result = _run(
        tmp_path,
        f'open_log; READY_TIMEOUT=60; wait_ready "{log}" {offset} 0',
        systemctl='case "$*" in *NRestarts*) echo 0;; *ActiveState*) echo failed;; esac\nexit 0\n',
    )
    assert result.returncode == 1
    assert time.monotonic() - started < 10


def test_a_restart_during_the_wait_is_a_crash(tmp_path: Path) -> None:
    log, offset = _bot_log(tmp_path, "", "")
    result = _run(
        tmp_path,
        f'open_log; READY_TIMEOUT=60; wait_ready "{log}" {offset} 0',
        systemctl='case "$*" in *NRestarts*) echo 1;; *ActiveState*) echo activating;; esac\nexit 0\n',
    )
    assert result.returncode == 1


def test_rotated_log_is_read_from_its_start(tmp_path: Path) -> None:
    log = tmp_path / "bot.log"
    log.write_text(POLLING)
    _ok(_run(tmp_path, f'open_log; READY_TIMEOUT=5; wait_ready "{log}" 999999 0'))


# ── the superadmin check reads the database read-only ─────────────────────────


def _db(path: Path, *, claimed: bool = False, superadmin_role: bool = False) -> None:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("CREATE TABLE users (telegram_user_id INTEGER PRIMARY KEY, role TEXT NOT NULL)")
    conn.execute("CREATE TABLE claimed_superadmins (telegram_user_id INTEGER PRIMARY KEY, claimed_at TEXT)")
    conn.execute("INSERT INTO users VALUES (5, 'PENDING_USER')")
    if claimed:
        conn.execute("INSERT INTO claimed_superadmins VALUES (7, 'now')")
    if superadmin_role:
        conn.execute("INSERT INTO users VALUES (8, 'SUPERADMIN')")
    conn.commit()
    conn.close()


@pytest.mark.parametrize(
    ("admin_ids", "claimed", "role", "expected"),
    [
        ("", False, False, "none"),
        ("123", False, False, "exists"),
        ("", True, False, "exists"),
        ("", False, True, "exists"),
    ],
)
def test_has_superadmin(tmp_path: Path, admin_ids: str, claimed: bool, role: bool, expected: str) -> None:
    app = tmp_path / "opt/vpn-service"
    (app / "data").mkdir(parents=True)
    db = app / "data/vpn.db"
    _db(db, claimed=claimed, superadmin_role=role)
    (app / ".env").write_text(f"BOT_TOKEN={TOKEN}\nADMIN_IDS={admin_ids}\nDB_PATH={db}\n")
    before = hashlib.sha256(db.read_bytes()).hexdigest()

    result = _ok(_run(tmp_path, "has_superadmin && echo exists || echo none"))

    assert result.stdout.strip() == expected
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before


def test_has_superadmin_without_a_database(tmp_path: Path) -> None:
    app = tmp_path / "opt/vpn-service"
    app.mkdir(parents=True)
    (app / ".env").write_text("ADMIN_IDS=\n")
    result = _ok(_run(tmp_path, "has_superadmin && echo exists || echo none"))
    assert result.stdout.strip() == "none"


# ── host state ────────────────────────────────────────────────────────────────


def test_detect_state(tmp_path: Path) -> None:
    body = r"""
detect_state; echo "$STATE"
mkdir -p "$APP_DIR"; detect_state; echo "$STATE"
mkdir -p "$APP_DIR/.git"; touch "$ENV_FILE"; detect_state; echo "$STATE"
rm -rf "$APP_DIR"; touch "$UNIT_PATH"; detect_state; echo "$STATE"
"""
    assert _ok(_run(tmp_path, body)).stdout.split() == ["fresh", "conflict", "repair", "conflict"]


def test_env_value_reader(tmp_path: Path) -> None:
    env = tmp_path / "e"
    env.write_text("A=1\nexport B = \"two\"  # c\nA=3\nDB_PATH_X=no\nDB_PATH='/x/y.db'\n")
    result = _ok(_run(tmp_path, f'env_value "{env}" A; env_value "{env}" B; env_value "{env}" DB_PATH'))
    assert result.stdout.split() == ["3", "two", "/x/y.db"]


# ── contracts with the rest of the repository ─────────────────────────────────


def _script_var(name: str) -> str:
    match = re.search(rf'^{name}="([^"]+)"', INSTALL_SH.read_text(), re.M)
    assert match is not None, name
    return match.group(1)


def test_paths_agree_with_the_unit_and_the_bot() -> None:
    unit = (ROOT / "deploy/vpn-bot.service").read_text()
    assert f"WorkingDirectory={_script_var('APP_DIR')}" in unit
    assert "ExecStartPre=/usr/local/sbin/vpn-bot-db-perms" in unit
    assert _script_var("DB_PERMS_HELPER") == "/usr/local/sbin/vpn-bot-db-perms"
    settings_src = (ROOT / "config/settings.py").read_text()
    assert f'SUPERADMIN_CLAIM_PATH = Path("{_script_var("CLAIM_DIR")}/claim.json")' in settings_src
    assert (ROOT / _script_var("CLAIM_SUPPORT_MARKER")).is_file()


def test_token_regex_matches_the_documented_one() -> None:
    assert "TOKEN_RE='^[0-9]{6,12}:[A-Za-z0-9_-]{30,}$'" in INSTALL_SH.read_text()


def test_no_curl_pipe_bash_and_no_xtrace() -> None:
    text = INSTALL_SH.read_text()
    assert "set -x" not in text
    assert not re.search(r"curl[^\n|]*\|\s*(sudo\s+)?bash", text)


# --------------------------------------------------------------------------- #
# The setup wizard's helpers and the TOTP reset come with a fresh install
# --------------------------------------------------------------------------- #
WIZARD_HELPERS = [
    "vpn-bot-wizard",
    "vpn-bot-wizard-lib",
    "vpn-bot-wizard-selfcheck",
    "vpn-bot-wizard-dump",
    "vpn-bot-wizard-update",
    "vpn-bot-totp-reset",
]


def _install_helpers() -> list[str]:
    text = INSTALL_SH.read_text(encoding="utf-8")
    body = text[text.index("INSTALL_HELPERS=(") :].split("\n)", 1)[0].splitlines()[1:]
    return [line.strip() for line in body if line.strip() and not line.strip().startswith("#")]


def test_install_helpers_are_the_registered_main_helpers() -> None:
    """The installer's list == deploy.sh's OUT_OF_REPO_HELPERS entries for these helpers
    (same source, /usr/local/sbin/<name>, required, main): a deploy and a fresh install
    put the same files in the same place."""
    deploy = (ROOT / "scripts/deploy.sh").read_text(encoding="utf-8")
    listed = _install_helpers()
    assert sorted(src.rsplit("/", 1)[-1] for src in listed) == sorted(WIZARD_HELPERS)
    for src in listed:
        assert (ROOT / src).is_file(), src
        name = src.rsplit("/", 1)[-1]
        assert f'"{src}|/usr/local/sbin/{name}|required"' in deploy, src


def _checkout_with_helpers(tmp_path: Path) -> str:
    """A fake checkout with every helper the installer installs."""
    lines = ['mkdir -p "$APP_DIR/scripts/wizard" "$APP_DIR/deploy"', 'echo db > "$APP_DIR/scripts/vpn-bot-db-perms"',
             'echo unit > "$APP_DIR/deploy/vpn-bot.service"']
    for src in _install_helpers():
        lines.append(f'echo "{src}" > "$APP_DIR/{src}"')
    return "\n".join(lines) + "\n"


def test_install_unit_installs_the_wizard_helpers_and_rolls_them_back(tmp_path: Path) -> None:
    body = _checkout_with_helpers(tmp_path) + """
open_log
install_unit
for name in vpn-bot-wizard vpn-bot-wizard-lib vpn-bot-wizard-selfcheck vpn-bot-wizard-dump vpn-bot-wizard-update vpn-bot-totp-reset; do
  [[ -f "$SBIN_DIR/$name" ]] || { echo "missing $name"; exit 1; }
  stat -c '%a' "$SBIN_DIR/$name"
done
rollback
for name in vpn-bot-wizard vpn-bot-totp-reset; do
  [[ -e "$SBIN_DIR/$name" ]] && { echo "left behind: $name"; exit 1; }
done
echo rolled-back
"""
    result = _ok(_run(tmp_path, body))
    lines = result.stdout.split()
    assert lines[:6] == ["755"] * 6
    assert lines[-1] == "rolled-back"


def test_install_unit_skips_helpers_a_checkout_does_not_have(tmp_path: Path) -> None:
    body = """
mkdir -p "$APP_DIR/scripts" "$APP_DIR/deploy"
echo db > "$APP_DIR/scripts/vpn-bot-db-perms"; echo unit > "$APP_DIR/deploy/vpn-bot.service"
open_log
install_unit
[[ -e "$SBIN_DIR/vpn-bot-wizard" ]] && echo installed || echo skipped
"""
    assert _ok(_run(tmp_path, body)).stdout.strip().splitlines()[-1] == "skipped"


def test_path_is_ours_covers_the_installed_helpers_only(tmp_path: Path) -> None:
    body = """
for p in "$SBIN_DIR/vpn-bot-wizard" "$SBIN_DIR/vpn-bot-totp-reset.vpn-bot-install.T.bak" "$SBIN_DIR/vpn-bot-ufw-apply" "$SBIN_DIR/vpn-bot-wizardx"; do
  path_is_ours "$p" && echo ours || echo refused
done
"""
    assert _ok(_run(tmp_path, body)).stdout.split() == ["ours", "ours", "refused", "refused"]
