"""TOTP (RFC 6238) on top of HOTP (RFC 4226), standard library only.

Nothing here touches storage, Telegram or the clock implicitly: every function takes
the key and the instant it works on, so the RFC test vectors in tests/test_totp.py
drive exactly the code the bot runs. The service layer (services/totp.py) adds the
encrypted storage, the replay guard's memory, the rate limit and the elevation.

Choices, each one on purpose:

* SHA-1, 6 digits, 30-second step, T0 = 0 — the defaults every authenticator app
  (Google Authenticator, Aegis, 1Password, ...) assumes when the ``otpauth://`` URI
  carries no ``algorithm``/``digits``/``period``. SHA-256/512 and 8 digits are
  implemented only so the RFC 6238 vectors can be checked in full.
* A 160-bit secret (RFC 4226 §4 recommends at least 128, and 160 is the SHA-1 block
  output the apps are tuned for), from :mod:`secrets`.
* Codes are compared with :func:`hmac.compare_digest`.
* :func:`verify` returns the time-step that matched, never a bare bool: the caller
  remembers it and passes it back as ``last_step``, and a step at or below it is
  refused — that is the replay guard (RFC 6238 §5.2: "the verifier MUST NOT accept
  the second attempt of the OTP after the successful validation").
* Backup codes are hashed with :func:`hashlib.scrypt` and a per-code random salt; the
  plain code exists only in the one message that shows it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
from urllib.parse import quote, urlencode

DEFAULT_STEP_SECONDS = 30
DEFAULT_DIGITS = 6
DEFAULT_DIGEST = "sha1"
# ±1 step: a code typed in the last seconds of its window, or on a phone whose clock
# is a few seconds off, still counts. Wider windows only widen what a shoulder-surfed
# code is worth.
DEFAULT_WINDOW = 1
SECRET_BYTES = 20

_DIGESTS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}
_CODE_RE = re.compile(r"^[0-9]{6}$")

# Backup codes: 10 characters from an alphabet without look-alikes (no 0/o, 1/l/i),
# shown as two groups of five. 31 symbols ** 10 ≈ 2**49.5 — far beyond what a rate
# limit of 5 tries per 15 minutes lets anyone search.
BACKUP_CODE_COUNT = 10
BACKUP_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
BACKUP_CODE_LENGTH = 10
_BACKUP_RE = re.compile(rf"^[{BACKUP_ALPHABET}]{{{BACKUP_CODE_LENGTH}}}$")
# scrypt cost: N=2**14, r=8, p=1 — the parameters RFC 7914 §2 cites for interactive
# logins (16 MiB, tens of milliseconds). Ten codes are checked at most once per typed
# attempt, in a worker thread.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16


class TotpFormatError(ValueError):
    """A secret or code that is not in the format this module produces."""


def hotp(key: bytes, counter: int, *, digits: int = DEFAULT_DIGITS, digest: str = DEFAULT_DIGEST) -> str:
    """RFC 4226 §5.3: HMAC, dynamic truncation, modulo 10**digits."""
    if counter < 0:
        raise ValueError("counter must not be negative")
    if digits not in (6, 7, 8):
        raise ValueError("digits must be 6, 7 or 8")
    try:
        algorithm = _DIGESTS[digest]
    except KeyError:
        raise ValueError(f"unsupported digest {digest!r}") from None
    mac = hmac.new(key, struct.pack(">Q", counter), algorithm).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def time_step(at: float, *, step: int = DEFAULT_STEP_SECONDS, t0: int = 0) -> int:
    """RFC 6238 §4.2: T = floor((Unix time - T0) / X)."""
    if step <= 0:
        raise ValueError("step must be positive")
    return int((int(at) - t0) // step)


def totp(
    key: bytes,
    at: float,
    *,
    step: int = DEFAULT_STEP_SECONDS,
    digits: int = DEFAULT_DIGITS,
    digest: str = DEFAULT_DIGEST,
    t0: int = 0,
) -> str:
    """The code valid at *at* (Unix seconds)."""
    return hotp(key, time_step(at, step=step, t0=t0), digits=digits, digest=digest)


def normalize_code(text: str) -> str | None:
    """A typed TOTP code without spaces/dashes, or None when it is not six digits."""
    cleaned = re.sub(r"[\s-]", "", text or "")
    return cleaned if _CODE_RE.match(cleaned) else None


def verify(
    key: bytes,
    code: str,
    at: float,
    *,
    last_step: int | None = None,
    window: int = DEFAULT_WINDOW,
    step: int = DEFAULT_STEP_SECONDS,
) -> int | None:
    """The time-step *code* belongs to, within ±window of *at*, or None.

    A step at or below *last_step* never matches (replay guard). Every candidate is
    computed and compared, so the time taken does not depend on which one matched.
    """
    normalized = normalize_code(code)
    if normalized is None:
        return None
    current = time_step(at, step=step)
    matched: int | None = None
    for candidate in range(current - window, current + window + 1):
        if candidate < 0:
            continue
        ok = hmac.compare_digest(hotp(key, candidate), normalized)
        if ok and (last_step is None or candidate > last_step) and matched is None:
            matched = candidate
    return matched


def generate_secret(nbytes: int = SECRET_BYTES) -> bytes:
    return secrets.token_bytes(nbytes)


def encode_secret(key: bytes) -> str:
    """Base32 without padding — what authenticator apps accept for manual entry."""
    return base64.b32encode(key).decode("ascii").rstrip("=")


def decode_secret(text: str) -> bytes:
    cleaned = re.sub(r"\s", "", text or "").upper()
    if not cleaned or not re.fullmatch(r"[A-Z2-7]+", cleaned):
        raise TotpFormatError("not a base32 secret")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(padded)
    except (ValueError, TypeError) as exc:
        raise TotpFormatError("not a base32 secret") from exc


def grouped_secret(secret_b32: str) -> str:
    """The base32 secret in groups of four, easier to type by hand."""
    return " ".join(secret_b32[i : i + 4] for i in range(0, len(secret_b32), 4))


def otpauth_uri(secret_b32: str, *, account: str, issuer: str) -> str:
    """Key Uri Format (Google Authenticator wiki): ``otpauth://totp/Issuer:account?...``.

    The defaults (SHA1, 6 digits, 30 s) are spelled out anyway, so an app that does
    not assume them still lands on the same codes.
    """
    label = quote(f"{issuer}:{account}", safe=":@")
    query = urlencode(
        {
            "secret": secret_b32,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": str(DEFAULT_DIGITS),
            "period": str(DEFAULT_STEP_SECONDS),
        }
    )
    return f"otpauth://totp/{label}?{query}"


# --------------------------------------------------------------------------- #
# Backup codes
# --------------------------------------------------------------------------- #
def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
    """``count`` distinct codes, each ``xxxxx-xxxxx``."""
    codes: set[str] = set()
    while len(codes) < count:
        raw = "".join(secrets.choice(BACKUP_ALPHABET) for _ in range(BACKUP_CODE_LENGTH))
        codes.add(raw)
    return [format_backup_code(code) for code in sorted(codes)]


def format_backup_code(raw: str) -> str:
    half = BACKUP_CODE_LENGTH // 2
    return f"{raw[:half]}-{raw[half:]}"


def normalize_backup_code(text: str) -> str | None:
    """The ten code characters of a typed backup code, or None."""
    cleaned = re.sub(r"[\s-]", "", (text or "").lower())
    return cleaned if _BACKUP_RE.match(cleaned) else None


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_BYTES)


def hash_backup_code(code: str, salt: bytes) -> bytes:
    """scrypt of the normalized code. Raises TotpFormatError on a malformed code."""
    normalized = normalize_backup_code(code)
    if normalized is None:
        raise TotpFormatError("not a backup code")
    return hashlib.scrypt(
        normalized.encode("ascii"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )


def backup_code_matches(code: str, salt: bytes, digest: bytes) -> bool:
    try:
        candidate = hash_backup_code(code, salt)
    except TotpFormatError:
        return False
    return hmac.compare_digest(candidate, digest)
