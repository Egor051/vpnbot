"""TOTP second factor (utils/totp.py, services/totp.py, scripts/vpn-bot-totp-reset).

* RFC 4226 Appendix D (HOTP) and RFC 6238 Appendix B (TOTP, SHA1/SHA256/SHA512,
  8 digits) test vectors drive the very functions the bot uses.
* The window is ±1 step; a step at or below the last accepted one is refused
  (replay), also through the service and across a restart.
* Five wrong codes in a row lock the user for 15 minutes and alert; the lock lives
  in the database, so a "restart" (a new service object) does not lift it.
* Backup codes: shown once, stored as scrypt only, each redeemable once; reissuing
  needs a TOTP code, not a backup code.
* The Fernet key file: created 0600 on the first enrollment, never replaced while
  credentials exist, refused when it is not private.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from adapters.clock import ClockProvider
from db.database import Database
from repositories.audit_log import AuditLogRepository
from repositories.totp import TotpRepository
from repositories.users import UserRepository
from services.audit import AuditService
from services.totp import (
    ELEVATION_SECONDS,
    LOCK_SECONDS,
    MAX_FAILURES,
    TotpError,
    TotpKeyFile,
    TotpKeyUnavailable,
    TotpLocked,
    TotpService,
)
from utils import totp as otp

ROOT = Path(__file__).resolve().parents[1]
RESET = ROOT / "scripts" / "vpn-bot-totp-reset"

pytestmark = pytest.mark.timeout(120)

# --------------------------------------------------------------------------- #
# RFC vectors
# --------------------------------------------------------------------------- #
RFC4226_SECRET = b"12345678901234567890"
RFC4226_HOTP = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]

SEED_SHA1 = b"12345678901234567890"
SEED_SHA256 = b"12345678901234567890123456789012"
SEED_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"
RFC6238 = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("counter,expected", list(enumerate(RFC4226_HOTP)))
def test_rfc4226_hotp_vectors(counter: int, expected: str) -> None:
    assert otp.hotp(RFC4226_SECRET, counter) == expected


@pytest.mark.parametrize("at,sha1,sha256,sha512", RFC6238)
def test_rfc6238_totp_vectors(at: int, sha1: str, sha256: str, sha512: str) -> None:
    assert otp.totp(SEED_SHA1, at, digits=8, digest="sha1") == sha1
    assert otp.totp(SEED_SHA256, at, digits=8, digest="sha256") == sha256
    assert otp.totp(SEED_SHA512, at, digits=8, digest="sha512") == sha512


def test_six_digit_default_is_the_low_digits_of_the_rfc_value() -> None:
    # Same truncation, modulo 10**6: what every authenticator app shows.
    assert otp.totp(SEED_SHA1, 59) == "287082"
    assert otp.totp(SEED_SHA1, 1111111109) == "081804"


def test_time_step_and_bad_arguments() -> None:
    assert otp.time_step(59) == 1
    assert otp.time_step(60) == 2
    with pytest.raises(ValueError):
        otp.hotp(SEED_SHA1, -1)
    with pytest.raises(ValueError):
        otp.hotp(SEED_SHA1, 0, digits=5)
    with pytest.raises(ValueError):
        otp.hotp(SEED_SHA1, 0, digest="md5")


def test_verify_window_is_plus_minus_one_step() -> None:
    now = 1_700_000_000
    step = otp.time_step(now)
    for delta in (-1, 0, 1):
        code = otp.hotp(SEED_SHA1, step + delta)
        assert otp.verify(SEED_SHA1, code, now) == step + delta
    for delta in (-2, 2):
        assert otp.verify(SEED_SHA1, otp.hotp(SEED_SHA1, step + delta), now) is None


def test_verify_refuses_replay_and_older_steps() -> None:
    now = 1_700_000_000
    step = otp.time_step(now)
    code = otp.hotp(SEED_SHA1, step)
    assert otp.verify(SEED_SHA1, code, now, last_step=step - 1) == step
    assert otp.verify(SEED_SHA1, code, now, last_step=step) is None
    older = otp.hotp(SEED_SHA1, step - 1)
    assert otp.verify(SEED_SHA1, older, now, last_step=step) is None


@pytest.mark.parametrize("typed", ["123 456", "123-456", " 123456 "])
def test_normalize_code_accepts_spacing(typed: str) -> None:
    assert otp.normalize_code(typed) == "123456"


@pytest.mark.parametrize("typed", ["", "12345", "1234567", "abcdef", "12345a"])
def test_normalize_code_rejects_junk(typed: str) -> None:
    assert otp.normalize_code(typed) is None
    assert otp.verify(SEED_SHA1, typed, 59) is None


def test_secret_encoding_and_otpauth_uri() -> None:
    key = otp.generate_secret()
    assert len(key) == otp.SECRET_BYTES
    b32 = otp.encode_secret(key)
    assert "=" not in b32
    assert otp.decode_secret(b32.lower()) == key
    assert otp.decode_secret(otp.grouped_secret(b32)) == key
    with pytest.raises(otp.TotpFormatError):
        otp.decode_secret("not base32!")
    uri = otp.otpauth_uri(b32, account="alice", issuer="vpnbot")
    assert uri.startswith("otpauth://totp/vpnbot:alice?")
    for part in (f"secret={b32}", "issuer=vpnbot", "algorithm=SHA1", "digits=6", "period=30"):
        assert part in uri


def test_backup_codes_are_distinct_and_hash_only_their_normalized_form() -> None:
    codes = otp.generate_backup_codes()
    assert len(codes) == otp.BACKUP_CODE_COUNT == len(set(codes))
    for code in codes:
        assert len(code) == 11 and code[5] == "-"
        assert otp.normalize_backup_code(code) == code.replace("-", "")
    salt = otp.new_salt()
    digest = otp.hash_backup_code(codes[0], salt)
    assert otp.backup_code_matches(codes[0].upper().replace("-", " "), salt, digest)
    assert not otp.backup_code_matches(codes[1], salt, digest)
    assert not otp.backup_code_matches("garbage", salt, digest)
    assert otp.normalize_backup_code("0000000000") is None  # 0 is not in the alphabet


# --------------------------------------------------------------------------- #
# The service, on a real database
# --------------------------------------------------------------------------- #
USER = 4242


class Clock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.t = start
        self.mono = 1000.0

    def now(self) -> float:
        return self.t

    def monotonic(self) -> float:
        return self.mono


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[tuple[Database, Path]]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, role, created_at, updated_at) VALUES (?, 'SUPERADMIN', ?, ?)",
        (USER, "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
    )
    await db.commit()
    try:
        yield db, tmp_path / "etc" / "totp.key"
    finally:
        await db.close()


def make_service(db: Database, key: Path, clock: Clock, alerts: list[str] | None = None) -> TotpService:
    async def alert(text: str) -> None:
        if alerts is not None:
            alerts.append(text)

    return TotpService(
        repo=TotpRepository(db),
        audit=AuditService(AuditLogRepository(db), ClockProvider(), UserRepository(db)),
        clock=ClockProvider(),
        key_file=TotpKeyFile(key),
        now=clock.now,
        monotonic=clock.monotonic,
        alert=alert,
    )


async def enroll(svc: TotpService, clock: Clock) -> tuple[bytes, list[str]]:
    enrollment = await svc.begin_enrollment(USER, "alice")
    key = otp.decode_secret(enrollment.secret_b32)
    codes = await svc.confirm_enrollment(USER, otp.totp(key, clock.t))
    return key, codes


async def audit_actions(db: Database) -> list[str]:
    rows = await db.conn.execute_fetchall("SELECT action FROM audit_log ORDER BY id")
    return [str(r["action"]) for r in rows]


async def test_enrollment_creates_a_private_key_and_stores_only_ciphertext(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    assert not key_path.exists()
    enrollment = await svc.begin_enrollment(USER, "alice")
    assert key_path.is_file() and (key_path.stat().st_mode & 0o777) == 0o600
    row = await db.conn.execute_fetchone("SELECT secret_enc, enabled FROM totp_credentials WHERE telegram_user_id = ?", (USER,))
    assert row is not None and int(row["enabled"]) == 0
    secret = otp.decode_secret(enrollment.secret_b32)
    assert enrollment.secret_b32 not in str(row["secret_enc"])
    assert secret.hex() not in str(row["secret_enc"])
    # a wrong first code does not enable it
    with pytest.raises(TotpError) as exc:
        await svc.confirm_enrollment(USER, "000000" if otp.totp(secret, clock.t) != "000000" else "111111")
    assert exc.value.key == "totp_invalid_code"
    assert not await svc.is_enabled(USER)
    codes = await svc.confirm_enrollment(USER, otp.totp(secret, clock.t))
    assert len(codes) == 10
    status = await svc.status(USER)
    assert status.enabled and status.backup_left == 10
    stored = await db.conn.execute_fetchall("SELECT salt_hex, hash_hex FROM totp_backup_codes")
    plain = {c.replace("-", "") for c in codes}
    assert all(str(r["hash_hex"]) not in plain and len(str(r["hash_hex"])) == 64 for r in stored)
    assert svc.is_elevated(USER)  # the confirming code counts as a fresh check
    assert "totp_enabled" in await audit_actions(db)


async def test_verify_and_replay_through_the_service_and_across_a_restart(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    key, _ = await enroll(svc, clock)
    # the enrollment code's step is used: the same code again is a replay
    with pytest.raises(TotpError):
        await svc.verify(USER, otp.totp(key, clock.t), purpose="test")
    clock.t += 30
    code = otp.totp(key, clock.t)
    assert (await svc.verify(USER, code, purpose="test")).method == "totp"
    restarted = make_service(db, key_path, clock)
    with pytest.raises(TotpError):
        await restarted.verify(USER, code, purpose="test")
    # the previous step is inside the window but older than the last used one
    with pytest.raises(TotpError):
        await restarted.verify(USER, otp.totp(key, clock.t - 30), purpose="test")
    clock.t += 30
    assert (await restarted.verify(USER, otp.totp(key, clock.t), purpose="test")).method == "totp"


async def test_five_wrong_codes_lock_for_15_minutes_and_alert(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    alerts: list[str] = []
    svc = make_service(db, key_path, clock, alerts)
    key, _ = await enroll(svc, clock)
    clock.t += 30
    wrong = "000000" if otp.totp(key, clock.t) != "000000" else "111111"
    for _ in range(MAX_FAILURES - 1):
        with pytest.raises(TotpError) as exc:
            await svc.verify(USER, wrong, purpose="test")
        assert not isinstance(exc.value, TotpLocked)
    with pytest.raises(TotpError):
        await svc.verify(USER, wrong, purpose="test")
    assert len(alerts) == 1 and str(USER) in alerts[0]
    assert "totp_locked" in await audit_actions(db)
    # even the right code is refused during the lock — and a restart does not lift it
    restarted = make_service(db, key_path, clock, alerts)
    with pytest.raises(TotpLocked) as locked:
        await restarted.verify(USER, otp.totp(key, clock.t), purpose="test")
    assert locked.value.params["minutes"] == LOCK_SECONDS // 60
    clock.t += LOCK_SECONDS + 1
    assert (await restarted.verify(USER, otp.totp(key, clock.t), purpose="test")).method == "totp"


async def test_success_resets_the_failure_series(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    key, _ = await enroll(svc, clock)
    clock.t += 30
    wrong = "000000" if otp.totp(key, clock.t) != "000000" else "111111"
    for _ in range(MAX_FAILURES - 1):
        with pytest.raises(TotpError):
            await svc.verify(USER, wrong, purpose="test")
    await svc.verify(USER, otp.totp(key, clock.t), purpose="test")
    for _ in range(MAX_FAILURES - 1):
        with pytest.raises(TotpError) as exc:
            await svc.verify(USER, wrong, purpose="test")
        assert not isinstance(exc.value, TotpLocked)


async def test_backup_codes_redeem_once_and_count_down(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    _, codes = await enroll(svc, clock)
    result = await svc.verify(USER, codes[3], purpose="test")
    assert result.method == "backup" and result.backup_left == 9
    with pytest.raises(TotpError):
        await svc.verify(USER, codes[3], purpose="test")
    assert (await svc.status(USER)).backup_left == 9
    assert "totp_backup_code_used" in await audit_actions(db)


async def test_reissue_needs_a_totp_code_and_kills_the_old_codes(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    key, codes = await enroll(svc, clock)
    with pytest.raises(TotpError):
        await svc.reissue_backup_codes(USER, codes[0])  # a backup code is not enough
    clock.t += 30
    fresh = await svc.reissue_backup_codes(USER, otp.totp(key, clock.t))
    assert len(fresh) == 10 and not set(fresh) & set(codes)
    with pytest.raises(TotpError):
        await svc.verify(USER, codes[1], purpose="test")
    assert (await svc.verify(USER, fresh[0], purpose="test")).method == "backup"


async def test_disable_needs_a_code_and_removes_everything(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    _, codes = await enroll(svc, clock)
    with pytest.raises(TotpError):
        await svc.disable(USER, "not-a-code")
    assert await svc.is_enabled(USER)
    await svc.disable(USER, codes[0])
    assert not await svc.is_enabled(USER)
    assert not svc.is_elevated(USER)
    left = await db.conn.execute_fetchone("SELECT COUNT(*) AS n FROM totp_backup_codes")
    assert left is not None and int(left["n"]) == 0
    assert "totp_disabled" in await audit_actions(db)


async def test_elevation_lasts_five_minutes_and_dies_with_the_process(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    await enroll(svc, clock)
    assert svc.is_elevated(USER)
    clock.mono += ELEVATION_SECONDS - 1
    assert svc.is_elevated(USER)
    clock.mono += 2
    assert not svc.is_elevated(USER)
    svc.elevate(USER)
    assert not make_service(db, key_path, clock).is_elevated(USER)  # a restart drops it


async def test_a_wrong_code_drops_an_elevation(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    await enroll(svc, clock)
    with pytest.raises(TotpError):
        await svc.verify(USER, "zzzzz-zzzzz", purpose="test")
    assert not svc.is_elevated(USER)


async def test_missing_key_with_live_credentials_is_never_silently_replaced(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    key, _ = await enroll(svc, clock)
    key_path.unlink()
    clock.t += 30
    with pytest.raises(TotpKeyUnavailable):
        await svc.verify(USER, otp.totp(key, clock.t), purpose="test")
    with pytest.raises(TotpError):
        await svc.begin_enrollment(USER, "alice")  # already enabled
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, role, created_at, updated_at) VALUES (77, 'SUPERADMIN', 'x', 'x')"
    )
    await db.commit()
    with pytest.raises(TotpKeyUnavailable) as exc:
        await svc.begin_enrollment(77, "bob")
    assert exc.value.key == "totp_key_missing"
    assert not key_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
async def test_a_key_file_others_can_read_is_refused(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    key, _ = await enroll(svc, clock)
    key_path.chmod(0o644)
    clock.t += 30
    with pytest.raises(TotpKeyUnavailable) as exc:
        await svc.verify(USER, otp.totp(key, clock.t), purpose="test")
    assert exc.value.key == "totp_key_unusable"


async def test_secret_enc_and_backup_hashes_never_reach_a_repr(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    await enroll(svc, clock)
    cred = await svc.repo.get(USER)
    assert cred is not None and cred.secret_enc not in repr(cred)
    code = (await svc.repo.unused_backup_codes(USER))[0]
    assert code.hash_hex not in repr(code)


# --------------------------------------------------------------------------- #
# The emergency reset (root CLI)
# --------------------------------------------------------------------------- #
def _reset(*args: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "VPN_BOT_TOTP_RESET_SELFTEST": "1"}
    return subprocess.run([sys.executable, "-I", str(RESET), *args], capture_output=True, text=True, env=env, timeout=30, check=False)


async def test_totp_reset_cli_removes_the_factor_and_audits(world: tuple[Database, Path]) -> None:
    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    await enroll(svc, clock)
    db_file = str(db.path)
    # Every call names the test's own database: deploy.sh runs this suite as root on
    # the production host, where the default DB_PATH is the live one.
    assert _reset(str(USER), "--db", db_file).returncode == 2  # no terminal and no --yes
    assert _reset("abc", "--yes", "--db", db_file).returncode == 2
    done = _reset(str(USER), "--yes", "--db", db_file)
    assert done.returncode == 0, done.stderr
    assert "removed" in done.stdout
    assert not await svc.is_enabled(USER)
    conn = sqlite3.connect(db_file)
    try:
        row = conn.execute("SELECT actor_user_id, entity_type, entity_id FROM audit_log WHERE action = 'totp_reset_cli'").fetchone()
        codes = conn.execute("SELECT COUNT(*) FROM totp_backup_codes").fetchone()
    finally:
        conn.close()
    assert row == (None, "security", str(USER))
    assert codes == (0,)
    again = _reset(str(USER), "--yes", "--db", db_file)
    assert again.returncode == 0 and "nothing to reset" in again.stdout


async def test_a_restarted_enrollment_waits_for_the_running_confirmation(world: tuple[Database, Path]) -> None:
    """«Enable TOTP» pressed while the first code is being checked must not swap the
    secret under it: the confirmation enables exactly the secret it verified."""
    import asyncio

    db, key_path = world
    clock = Clock()
    svc = make_service(db, key_path, clock)
    enrollment = await svc.begin_enrollment(USER, "alice")
    key = otp.decode_secret(enrollment.secret_b32)
    confirm = asyncio.create_task(svc.confirm_enrollment(USER, otp.totp(key, clock.t)))
    await asyncio.sleep(0)  # the confirmation holds the user's lock now
    restart = asyncio.create_task(svc.begin_enrollment(USER, "alice"))
    codes = await confirm
    with pytest.raises(TotpError) as exc:
        await restart
    assert exc.value.key == "totp_already_enabled"
    assert len(codes) == 10
    clock.t += 30
    assert (await svc.verify(USER, otp.totp(key, clock.t), purpose="test")).method == "totp"


async def test_enable_matches_the_verified_ciphertext(world: tuple[Database, Path]) -> None:
    db, key_path = world
    svc = make_service(db, key_path, Clock())
    await svc.begin_enrollment(USER, "alice")
    assert not await svc.repo.enable(USER, secret_enc="not-the-one", step=1, codes=[], now="t")
    assert not await svc.is_enabled(USER)
    cred = await svc.repo.get(USER)
    assert cred is not None
    assert await svc.repo.enable(USER, secret_enc=cred.secret_enc, step=1, codes=[], now="t")
    await svc.cancel_enrollment(USER)  # never removes an enabled credential
    assert await svc.is_enabled(USER)
