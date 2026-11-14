"""scripts/install.sh, relay mode — the functions, through the INSTALL_SELFTEST seam.

The whole relay install (adoption of a hand-made relay, the rollback that puts it
back, the agent over a real ssh, the resolve timer) runs on a real ubuntu-24.04 VM:
the ``relay-installer-e2e`` CI job (tests/e2e/run_relay_install_e2e.sh). Pinned here
on every pytest run:

* the pairing code: what the bot encodes (services/relay_pairing.py) the installer
  decodes; the token never leaves python (only its sha256), expiry and every field
  are checked, anything else is refused;
* `sshd -T` decides whether root may log in with a key, and where authorized_keys
  is; sshd_config is never written;
* the authorized_keys line is `restrict,command="/usr/local/sbin/vpn-relay-agent"`,
  other lines stay byte-identical, an unrestricted copy of the same key goes;
* the relay .env carries the target NAME, the ports and NODE_ROLE=relay and loads in
  vpn-relay-apply;
* the relay manifest records (adopted, nft, sysctl) roll back in reverse and the
  adoption backup survives both a rollback and a commit;
* the verification wants exactly ONE DNAT rule per forwarded port.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from services.relay_pairing import PairingCode, decode_pairing_code, encode_pairing_code, new_token

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "scripts" / "install.sh"
# A real ed25519 public key blob (the fixed bytes of the wire format + 32 zero bytes).
BLOB = base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
PUBKEY = f"ssh-ed25519 {BLOB}"

pytestmark = pytest.mark.timeout(60)

_PRELUDE = r"""
set -Eeuo pipefail
INSTALL_SELFTEST=1 source "$INSTALL_SH"
chown() { :; }
install() {
  local args=()
  while (($#)); do
    case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
  done
  command install "${args[@]}"
}
MODE=relay
APP_DIR="$T/opt/vpn-service"
ENV_FILE="$APP_DIR/.env"
UNIT_PATH="$T/etc/systemd/system/vpn-bot.service"
SBIN_DIR="$T/usr/local/sbin"
SYSTEMD_DIR="$T/etc/systemd/system"
RELAY_STATE_DIR="$T/etc/vpn-relay"
RELAY_VAR_DIR="$T/var/lib/vpn-relay"
RELAY_SYSCTL_FILE="$T/etc/sysctl.d/90-vpn-relay.conf"
RELAY_LEGACY_NFT="$T/etc/vpn-relay.nft"
RELAY_BACKUP_ROOT="$T/var/backups/vpn-relay"
INSTALL_LOG_DIR="$T/var/log"
mkdir -p "$INSTALL_LOG_DIR" "$SYSTEMD_DIR" "$SBIN_DIR" "$T/etc/sysctl.d"
"""


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/bin/bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _run(
    tmp_path: Path, body: str, *, stdin: str = "", stubs: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    bin_dir = tmp_path / "stub"
    bin_dir.mkdir(exist_ok=True)
    defaults = {
        "systemctl": f'printf "%s\\n" "$*" >> "{tmp_path}/systemctl.args"\nexit 0\n',
        "nft": f'printf "%s\\n" "$*" >> "{tmp_path}/nft.args"\n[[ "$1" == "-f" ]] && cat >> "{tmp_path}/nft.stdin"\nexit 0\n',
        "sysctl": f'printf "%s\\n" "$*" >> "{tmp_path}/sysctl.args"\nexit 0\n',
    }
    for name, text in {**defaults, **(stubs or {})}.items():
        _stub(bin_dir, name, text)
    env = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "T": str(tmp_path),
        "INSTALL_SH": str(INSTALL_SH),
        "LC_ALL": "C.UTF-8",
    }
    return subprocess.run(
        ["bash", "-c", _PRELUDE + body], input=stdin, capture_output=True, text=True, env=env, timeout=50, check=False
    )


def _ok(result: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    assert result.returncode == 0, f"rc={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}"
    return result


def _code(**overrides: object) -> tuple[str, str]:
    token = new_token()
    fields: dict[str, object] = {
        "target_host": "vpn.example.com",
        "tcp_ports": (443,),
        "udp_ports": (443,),
        "main_pubkey": PUBKEY + " vpn-bot-relay@main",
        "token": token,
        "exp": int(time.time()) + 1800,
    }
    fields.update(overrides)
    return encode_pairing_code(PairingCode(**fields)), token  # type: ignore[arg-type]


def _raw_code(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "v": 1,
        "target_host": "vpn.example.com",
        "ports": ["443/tcp", "443/udp"],
        "main_pubkey": PUBKEY,
        "one_time_token": "A" * 43,
        "exp": int(time.time()) + 1800,
    }
    payload.update(overrides)
    return payload


# ── the pairing code ─────────────────────────────────────────────────────────


def test_the_bots_code_decodes_in_the_installer(tmp_path: Path) -> None:
    code, token = _code(tcp_ports=(443, 8443))
    result = _ok(_run(tmp_path, 'read_pairing_code; declare -p PAIR_TARGET PAIR_TCP PAIR_UDP PAIR_KEY_BLOB PAIR_TOKEN_SHA256 PAIR_EXP', stdin=code + "\n"))
    out = result.stdout
    assert 'PAIR_TARGET="vpn.example.com"' in out
    assert 'PAIR_TCP="443,8443"' in out and 'PAIR_UDP="443"' in out
    assert f'PAIR_KEY_BLOB="{BLOB}"' in out
    assert f'PAIR_TOKEN_SHA256="{hashlib.sha256(token.encode()).hexdigest()}"' in out
    assert token not in result.stdout + result.stderr, "the token itself never reaches bash"
    assert code not in result.stdout + result.stderr
    assert decode_pairing_code(code, now=int(time.time())).token == token


@pytest.mark.parametrize(
    "payload",
    [
        _payload(v=2),
        _payload(target_host="203.0.113.5"),
        _payload(target_host="localhost"),
        _payload(target_host="vpn.example.com;id"),
        _payload(ports=["443/tcp"]),
        _payload(ports=["443/udp"]),
        _payload(ports=["443/tcp", "443/udp", "443/tcp"]),
        _payload(ports=["0/tcp", "443/udp"]),
        _payload(ports=["70000/tcp", "443/udp"]),
        _payload(ports=["443/sctp", "443/udp"]),
        _payload(ports="443/tcp,443/udp"),
        _payload(main_pubkey="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"),
        _payload(main_pubkey="ssh-ed25519 " + "A" * 68),
        _payload(main_pubkey=PUBKEY + "\nssh-ed25519 " + BLOB),
        _payload(one_time_token="short"),
        _payload(one_time_token="A" * 42 + "$"),
        _payload(exp=int(time.time()) - 400),
        _payload(exp=int(time.time()) + 3 * 3600),
        _payload(exp="soon"),
        _payload(exp=True),
        {**_payload(), "extra": 1},
        {k: v for k, v in _payload().items() if k != "exp"},
    ],
)
def test_bad_codes_are_refused(tmp_path: Path, payload: dict[str, object]) -> None:
    result = _run(tmp_path, "read_pairing_code; echo READ", stdin=_raw_code(payload) + "\n")
    assert result.returncode == 1
    assert "READ" not in result.stdout
    assert not list((tmp_path / "var/log").glob("vpn-bot-install.*")), "nothing written before the code is valid"


@pytest.mark.parametrize("garbage", ["", "not a code", "x" * 30, "!" * 60, "QUJD" * 20])
def test_garbage_is_refused(tmp_path: Path, garbage: str) -> None:
    assert _run(tmp_path, "read_pairing_code", stdin=garbage + "\n").returncode == 1


def test_a_code_within_the_clock_skew_is_accepted(tmp_path: Path) -> None:
    code, _ = _code(exp=int(time.time()) - 200)
    _ok(_run(tmp_path, "read_pairing_code", stdin=code + "\n"))


def test_whitespace_around_the_pasted_code_is_ignored(tmp_path: Path) -> None:
    code, _ = _code()
    _ok(_run(tmp_path, "read_pairing_code", stdin=f"  {code[:50]}\t{code[50:]} \n"))


def test_redact_hides_a_pairing_code(tmp_path: Path) -> None:
    code, _ = _code()
    result = _ok(_run(tmp_path, f'printf "%s\\n" "x {code} y" | redact'))
    assert code not in result.stdout and "<redacted-pairing-code>" in result.stdout


# ── sshd -T ──────────────────────────────────────────────────────────────────

UBUNTU_SSHD_T = (
    "port 22\npubkeyauthentication yes\npermitrootlogin without-password\n"
    "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nusepam yes\n"
)


@pytest.mark.parametrize(
    ("extra", "groups", "expected"),
    [
        ("", "root", "/root/.ssh/authorized_keys"),
        ("allowusers root@10.* alice\n", "root", "/root/.ssh/authorized_keys"),
        ("allowusers *\n", "root", "/root/.ssh/authorized_keys"),
        ("allowgroups wheel root\n", "root", "/root/.ssh/authorized_keys"),
    ],
)
def test_ssh_login_allowed(tmp_path: Path, extra: str, groups: str, expected: str) -> None:
    result = _ok(_run(tmp_path, f'ssh_login_verdict "{groups}"', stdin=UBUNTU_SSHD_T + extra))
    assert result.stdout.strip() == expected


@pytest.mark.parametrize(
    ("sshd_t", "why"),
    [
        (UBUNTU_SSHD_T.replace("pubkeyauthentication yes", "pubkeyauthentication no"), "PubkeyAuthentication"),
        (UBUNTU_SSHD_T.replace("without-password", "no"), "PermitRootLogin"),
        (UBUNTU_SSHD_T + "denyusers root\n", "DenyUsers"),
        (UBUNTU_SSHD_T + "denyusers ro*\n", "DenyUsers"),
        (UBUNTU_SSHD_T + "allowusers alice bob\n", "AllowUsers"),
        (UBUNTU_SSHD_T + "allowgroups admins\n", "AllowGroups"),
        (UBUNTU_SSHD_T + "denygroups root\n", "DenyGroups"),
        (UBUNTU_SSHD_T.replace(".ssh/authorized_keys .ssh/authorized_keys2", "none"), "AuthorizedKeysFile"),
        (UBUNTU_SSHD_T.replace(".ssh/authorized_keys .ssh/authorized_keys2", "%h/../etc/x"), "AuthorizedKeysFile"),
    ],
)
def test_ssh_login_refused(tmp_path: Path, sshd_t: str, why: str) -> None:
    result = _run(tmp_path, 'ssh_login_verdict root', stdin=sshd_t)
    assert result.returncode == 1
    assert why in result.stdout


@pytest.mark.parametrize(
    ("value", "path"),
    [("/etc/ssh/keys/%u", "/etc/ssh/keys/root"), ("%h/.ssh/keys", "/root/.ssh/keys"), (".ssh/ak2", "/root/.ssh/ak2")],
)
def test_authorized_keys_file_expansion(tmp_path: Path, value: str, path: str) -> None:
    sshd_t = UBUNTU_SSHD_T.replace(".ssh/authorized_keys .ssh/authorized_keys2", value)
    assert _ok(_run(tmp_path, "ssh_login_verdict root", stdin=sshd_t)).stdout.strip() == path


def test_the_installer_never_writes_sshd_config() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    assert "sshd_config" not in text.replace("sshd_config is never", "").replace("sshd_config is NEVER", "").replace(
        "sshd_config itself is never", ""
    )


# ── authorized_keys ──────────────────────────────────────────────────────────

OPERATOR = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPERATOR operator@laptop\n"


def test_authorize_key_adds_one_restricted_line(tmp_path: Path) -> None:
    keys = tmp_path / "root/.ssh/authorized_keys"
    keys.parent.mkdir(parents=True)
    keys.write_text(
        OPERATOR
        + f"{PUBKEY} copied-by-hand\n"
        + 'restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 OLDKEY vpn-relay-agent\n'
        + "# comment",
        encoding="utf-8",
    )
    _ok(_run(tmp_path, f'AUTH_KEYS="{keys}"; PAIR_KEY_BLOB="{BLOB}"; open_log; arm_rollback; relay_authorize_key; commit'))
    lines = keys.read_text(encoding="utf-8").splitlines(keepends=True)
    assert lines == [
        OPERATOR,
        "# comment\n",
        f'restrict,command="/usr/local/sbin/vpn-relay-agent" ssh-ed25519 {BLOB} vpn-relay-agent\n',
    ]
    assert oct(keys.stat().st_mode & 0o777) == "0o600"
    assert not list(keys.parent.glob("*.bak")), "commit drops the backup of a replaced file"


def test_authorize_key_rolls_back_byte_for_byte(tmp_path: Path) -> None:
    keys = tmp_path / "root/.ssh/authorized_keys"
    keys.parent.mkdir(parents=True)
    keys.write_text(OPERATOR, encoding="utf-8")
    _ok(_run(tmp_path, f'AUTH_KEYS="{keys}"; PAIR_KEY_BLOB="{BLOB}"; open_log; arm_rollback; relay_authorize_key; rollback'))
    assert keys.read_text(encoding="utf-8") == OPERATOR
    assert sorted(p.name for p in keys.parent.iterdir()) == ["authorized_keys"]


def test_authorize_key_creates_the_ssh_dir_and_rolls_it_back(tmp_path: Path) -> None:
    keys = tmp_path / "root/.ssh/authorized_keys"
    (tmp_path / "root").mkdir()
    _ok(_run(tmp_path, f'AUTH_KEYS="{keys}"; PAIR_KEY_BLOB="{BLOB}"; open_log; arm_rollback; relay_authorize_key; ls -ld "{keys.parent}"; rollback'))
    assert not keys.parent.exists()


# ── the relay .env ───────────────────────────────────────────────────────────


def test_relay_env_from_the_template(tmp_path: Path) -> None:
    app = tmp_path / "opt/vpn-service"
    (app / "deploy/relay").mkdir(parents=True)
    (app / "deploy/relay/relay.env.example").write_text(
        (ROOT / "deploy/relay/relay.env.example").read_text(encoding="utf-8"), encoding="utf-8"
    )
    stubs = {
        "ss": "echo 'LISTEN 0 4096 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=7,fd=3))'\n",
        "systemctl": "exit 0\n",
    }
    _ok(_run(
        tmp_path,
        'PAIR_TARGET=vpn.example.com; PAIR_TCP=443; PAIR_UDP=443,8443; open_log; arm_rollback; relay_write_env; commit',
        stubs=stubs,
    ))
    env = (app / ".env").read_text(encoding="utf-8")
    assert oct((app / ".env").stat().st_mode & 0o777) == "0o600"
    values = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in env.splitlines() if "=" in line and not line.startswith("#")}
    assert values["NODE_ROLE"] == "relay"
    assert values["RELAY_UPSTREAM_HOST"] == "vpn.example.com"
    assert "RELAY_UPSTREAM_IPV4" not in values
    assert values["RELAY_FORWARD_TCP_PORTS"] == "443" and values["RELAY_FORWARD_UDP_PORTS"] == "443,8443"
    assert values["RELAY_INPUT_FILTER"] == "off"
    assert values["SSH_PORT"] == "2222", "a later redeploy must not move ssh away from the bot"
    assert "BOT_TOKEN" not in env


# ── manifest records of the relay mode ───────────────────────────────────────


def test_adopted_nft_and_sysctl_records_roll_back(tmp_path: Path) -> None:
    legacy = tmp_path / "etc/vpn-relay.nft"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text("table ip vpnrelay { }\n", encoding="utf-8")
    stubs = {
        "nft": (
            f'printf "%s\\n" "$*" >> "{tmp_path}/nft.args"\n'
            f'if [[ "$1" == list ]]; then [[ "$3 $4" == "ip vpnrelay" ]] && echo "table ip vpnrelay {{ old }}" && exit 0; exit 1; fi\n'
            f'[[ "$1" == "-f" ]] && cat >> "{tmp_path}/nft.stdin"\nexit 0\n'
        ),
    }
    _ok(_run(
        tmp_path,
        "STATE=adopt; open_log; arm_rollback; relay_backup_existing; manifest_add sysctl net.ipv4.ip_forward 0; "
        'echo new > "$RELAY_LEGACY_NFT"; rollback',
        stubs=stubs,
    ))
    assert legacy.read_text(encoding="utf-8") == "table ip vpnrelay { }\n", "the hand-made file is put back"
    restored = (tmp_path / "nft.stdin").read_text(encoding="utf-8")
    assert restored.startswith("table ip vpnrelay\ndelete table ip vpnrelay\ntable ip vpnrelay { old }")
    nft_args = (tmp_path / "nft.args").read_text(encoding="utf-8")
    assert "delete table inet vpnrelay_input" not in nft_args, "list said it was absent: nothing to delete"
    assert "-q -w net.ipv4.ip_forward=0" in (tmp_path / "sysctl.args").read_text(encoding="utf-8")
    backups = list((tmp_path / "var/backups/vpn-relay").glob("adopt-*/files/**/vpn-relay.nft"))
    assert backups, "the adoption backup stays after a rollback"


def test_adoption_moves_the_hand_made_file_away_and_commit_keeps_the_backup(tmp_path: Path) -> None:
    legacy = tmp_path / "etc/vpn-relay.nft"
    legacy.parent.mkdir(parents=True, exist_ok=True)
    legacy.write_text("hand made\n", encoding="utf-8")
    _ok(_run(tmp_path, "STATE=adopt; open_log; arm_rollback; relay_backup_existing; commit"))
    assert not legacy.exists()
    kept = list((tmp_path / "var/backups/vpn-relay").glob("adopt-*/files/**/vpn-relay.nft"))
    assert len(kept) == 1 and kept[0].read_text(encoding="utf-8") == "hand made\n"


def test_fresh_install_records_absent_tables_and_deletes_them_on_rollback(tmp_path: Path) -> None:
    # No table before; the "apply" (touch applied) creates them; the rollback deletes them.
    stubs = {
        "nft": (
            f'printf "%s\\n" "$*" >> "{tmp_path}/nft.args"\n'
            f'if [[ "$1" == list ]]; then [[ -e "{tmp_path}/applied" ]]; exit; fi\nexit 0\n'
        ),
    }
    _ok(_run(tmp_path, f'STATE=fresh; open_log; arm_rollback; relay_backup_existing; touch "{tmp_path}/applied"; rollback', stubs=stubs))
    args = (tmp_path / "nft.args").read_text(encoding="utf-8")
    assert "delete table ip vpnrelay" in args and "delete table inet vpnrelay_input" in args
    assert not (tmp_path / "var/backups").exists(), "a fresh relay has nothing to back up"


@pytest.mark.parametrize("record", ["nft\tip\tfilter\t-", "nft\tinet\tvpnrelay\t/etc/passwd", "sysctl\tkernel.x\t1", "gitref\t/etc\t" + "a" * 40])
def test_foreign_relay_records_are_refused(tmp_path: Path, record: str) -> None:
    _ok(_run(tmp_path, f"open_log; arm_rollback; printf '%s\\n' $'{record}' >> \"$MANIFEST\"; rollback"))
    for name in ("nft.args", "sysctl.args"):
        path = tmp_path / name
        if path.exists():
            assert "filter" not in path.read_text() and "kernel.x" not in path.read_text()


def test_relay_paths_are_ours_only_in_relay_mode(tmp_path: Path) -> None:
    body = (
        'p="$SBIN_DIR/vpn-relay-agent"; path_is_ours "$p" && echo relay-yes; '
        'MODE=main; path_is_ours "$p" || echo main-no; '
        'MODE=relay; path_is_ours "$T/etc/shadow" || echo shadow-no'
    )
    out = _ok(_run(tmp_path, body)).stdout
    assert "relay-yes" in out and "main-no" in out and "shadow-no" in out


# ── verification: exactly one DNAT per port ──────────────────────────────────


def _verify(tmp_path: Path, *, check_rc: int, ruleset: str, timer: int = 0) -> subprocess.CompletedProcess[str]:
    helper = tmp_path / "usr/local/sbin/vpn-relay-apply"
    helper.parent.mkdir(parents=True, exist_ok=True)
    helper.write_text(f"#!/bin/bash\necho checked\nexit {check_rc}\n", encoding="utf-8")
    helper.chmod(0o755)
    (tmp_path / "ruleset.txt").write_text(ruleset, encoding="utf-8")
    stubs = {
        "nft": f'cat "{tmp_path}/ruleset.txt"\n',
        "systemctl": f"exit {timer}\n",
    }
    return _run(tmp_path, "PAIR_TCP=443; PAIR_UDP=443; PAIR_TARGET=vpn.example.com; open_log; relay_verify", stubs=stubs)


ONE = (
    'table ip vpnrelay {\n chain pre {\n  iifname "eth0" tcp dport 443 counter packets 0 bytes 0 dnat to 203.0.113.10:443\n'
    '  iifname "eth0" udp dport 443 counter packets 0 bytes 0 dnat to 203.0.113.10:443\n }\n}\n'
)


def test_verify_passes_with_one_dnat_per_port(tmp_path: Path) -> None:
    _ok(_verify(tmp_path, check_rc=0, ruleset=ONE))


def test_verify_fails_on_a_double_dnat(tmp_path: Path) -> None:
    double = ONE + 'table ip nat {\n chain PREROUTING {\n  tcp dport 443 counter dnat to 10.0.0.5:443\n }\n}\n'
    result = _verify(tmp_path, check_rc=0, ruleset=double)
    assert result.returncode != 0
    assert "TCP 443: 2" in result.stderr


@pytest.mark.parametrize(("rc", "ok"), [(13, True), (14, True), (11, False), (6, False), (20, False)])
def test_verify_check_codes(tmp_path: Path, rc: int, ok: bool) -> None:
    assert (_verify(tmp_path, check_rc=rc, ruleset=ONE).returncode == 0) is ok


def test_verify_needs_the_timer(tmp_path: Path) -> None:
    assert _verify(tmp_path, check_rc=0, ruleset=ONE, timer=3).returncode != 0


# ── the dispatch ─────────────────────────────────────────────────────────────


def test_unknown_argument_is_a_usage_error(tmp_path: Path) -> None:
    result = subprocess.run(["bash", str(INSTALL_SH), "--bogus"], capture_output=True, text=True, check=False, timeout=30)
    assert result.returncode == 2


def test_relay_mode_never_reaches_the_bot_api() -> None:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start = text.index("preflight_relay() {")
    end = text.index("usage() {")
    relay = text[start:end]
    for needle in ("TG_API_BASE", "telegram_get_me", "BOT_TOKEN", "api.telegram.org"):
        assert needle not in relay, needle


def test_files_the_helper_writes_are_removed_by_a_rollback(tmp_path: Path) -> None:
    """vpn-relay-apply writes the sysctl file and upstream.resolved itself: a rollback
    of a relay that had neither leaves neither."""
    sysctl = tmp_path / "etc/sysctl.d/90-vpn-relay.conf"
    state = tmp_path / "etc/vpn-relay/upstream.resolved"
    stubs = {"nft": "[[ \"$1\" == list ]] && exit 1\nexit 0\n"}
    _ok(_run(
        tmp_path,
        f'STATE=adopt; RELAY_EXISTING_CHECKOUT=0; open_log; arm_rollback; relay_backup_existing; '
        f'mkdir -p "{state.parent}"; echo x > "{sysctl}"; echo y > "{state}"; rollback',
        stubs=stubs,
    ))
    assert not sysctl.exists() and not state.exists()


def test_a_repair_rollback_puts_back_the_old_upstream_cache(tmp_path: Path) -> None:
    """Re-pair with another target, then a failure: the old target's last-known address
    must come back (a cache of the new name would be refused at a DNS-less boot)."""
    state = tmp_path / "etc/vpn-relay/upstream.resolved"
    state.parent.mkdir(parents=True)
    state.write_text("host=old.example.com\nipv4=203.0.113.10\nat=1\n", encoding="utf-8")
    stubs = {"nft": "[[ \"$1\" == list ]] && exit 1\nexit 0\n"}
    _ok(_run(
        tmp_path,
        f'STATE=repair; RELAY_EXISTING_CHECKOUT=0; open_log; arm_rollback; relay_backup_existing; '
        f'printf "host=new.example.com\\nipv4=198.51.100.20\\nat=2\\n" > "{state}"; rollback',
        stubs=stubs,
    ))
    assert state.read_text(encoding="utf-8").startswith("host=old.example.com")

