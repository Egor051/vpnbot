"""The first superadmin claims a fresh install with a one-time deep link.

scripts/install.sh leaves ADMIN_IDS empty. Instead it draws a 128-bit code, prints
``https://t.me/<bot>?start=claim_<code>`` (and a QR) to the operator's terminal,
and stores ONLY ``sha256(code)`` and an expiry in ``/etc/vpn-bot/claim.json``
(root, 0600). The operator opens the link; Telegram sends ``/start claim_<code>``;
this service makes the sender the superadmin.

Rules (each one is a test in tests/test_superadmin_claim.py):

* Private chat only.
* Only while there is NO superadmin at all — none in ADMIN_IDS, none claimed, no
  user with the SUPERADMIN role. With one, the claim is completely inert: the file
  is not even opened, so a production host (ADMIN_IDS set) ignores a claim.json
  whatever it says.
* The code is compared as ``sha256`` with :func:`hmac.compare_digest`; the expiry
  is checked; the file must be a regular file owned by this process's user with
  no group/other permission bits.
* Rate limited: 5 attempts per user per hour and 20 per hour in total, counted
  only while a claim is possible.
* Success, atomically: the file is renamed away first (so it is consumed exactly
  once, whatever else is running), then one transaction records the claim, gives
  the user the SUPERADMIN role and writes the audit row. If that transaction
  fails the file is renamed back, so the operator can retry the same link.
* Failure: one result, ``rejected``. The handler answers one generic message;
  the reason goes to the bot log only.
* The code itself is never logged, stored or echoed.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from adapters.clock import ClockProvider
from bot.rate_limit import RateLimiter, RateLimitExceeded
from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import AuditEntityType, UserRole
from repositories.claimed_superadmins import ClaimedSuperadminRepository
from repositories.users import UserRepository
from services.audit import AuditService
from services.superadmins import SuperadminSet

logger = logging.getLogger(__name__)

# The deep-link payload is "claim_<code>". Telegram allows 64 characters of
# [A-Za-z0-9_-] in a start parameter, so the code is at most 58 of them. The
# installer issues 22 (128 bits, url-safe base64 without padding).
CLAIM_PREFIX = "claim_"
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{16,58}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
# claim.json is a few dozen bytes; anything much larger is not ours.
_MAX_CLAIM_FILE_BYTES = 4096
CLAIM_FILE_VERSION = 1

PER_USER_ATTEMPTS = 5
GLOBAL_ATTEMPTS = 20
ATTEMPT_WINDOW_SECONDS = 3600
# Telegram user ids are positive, so 0 can never collide with a real user's
# rate-limit window.
_GLOBAL_LIMIT_KEY = 0


class ClaimOutcome(enum.Enum):
    CLAIMED = "claimed"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class PendingClaim:
    code_sha256: str
    expires_at: int


class _Rejected(Exception):
    """Internal: why a claim was refused. Logged, never shown to the user."""


def claim_payload(start_args: str | None) -> str | None:
    """The code from a ``/start`` payload, or None when it is not a claim."""
    if not start_args:
        return None
    args = start_args.strip()
    if not args.startswith(CLAIM_PREFIX):
        return None
    return args[len(CLAIM_PREFIX):]


def read_pending_claim(path: Path) -> PendingClaim:
    """Read and validate claim.json. Raises _Rejected on anything unexpected.

    Opened with O_NOFOLLOW and checked through the open descriptor: a symlink, a
    non-regular file, another owner or any group/other permission bit means the
    file is not the one the installer wrote, and it is refused.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise _Rejected("no pending claim") from None
    except OSError as exc:
        raise _Rejected(f"claim file unreadable ({type(exc).__name__})") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise _Rejected("claim file is not a regular file")
        if info.st_uid != os.geteuid():
            raise _Rejected("claim file has an unexpected owner")
        if info.st_mode & 0o077:
            raise _Rejected("claim file is readable by group/others")
        raw = os.read(fd, _MAX_CLAIM_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > _MAX_CLAIM_FILE_BYTES:
        raise _Rejected("claim file too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _Rejected("claim file is not valid JSON") from None
    if not isinstance(data, dict) or data.get("version") != CLAIM_FILE_VERSION:
        raise _Rejected("claim file has an unknown format")
    digest = data.get("code_sha256")
    expires_at = data.get("expires_at")
    if not isinstance(digest, str) or _SHA256_HEX_RE.fullmatch(digest) is None:
        raise _Rejected("claim file has no valid code_sha256")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
        raise _Rejected("claim file has no valid expires_at")
    return PendingClaim(code_sha256=digest, expires_at=expires_at)


def claim_status(path: Path, now: float) -> str:
    """'pending', 'expired', 'invalid' or 'absent' — for the startup log line only."""
    try:
        claim = read_pending_claim(path)
    except _Rejected as exc:
        return "absent" if str(exc) == "no pending claim" else "invalid"
    return "pending" if now < claim.expires_at else "expired"


class SuperadminClaimService:
    def __init__(
        self,
        *,
        db: Database,
        claims: ClaimedSuperadminRepository,
        users: UserRepository,
        audit: AuditService,
        superadmins: SuperadminSet,
        claim_path: Path,
        clock: ClockProvider,
        wall_clock: Callable[[], float] = time.time,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._db = db
        self._claims = claims
        self._users = users
        self._audit = audit
        self._superadmins = superadmins
        self._claim_path = claim_path
        self._clock = clock
        self._wall_clock = wall_clock
        self._rate_limiter = rate_limiter or RateLimiter()
        # One claim at a time: the second of two simultaneous valid attempts must
        # see the superadmin the first one created.
        self._lock = asyncio.Lock()

    async def has_superadmin(self) -> bool:
        """Whether any superadmin exists: ADMIN_IDS, a claim, or a SUPERADMIN role."""
        if len(self._superadmins) > 0:
            return True
        return await self._claims.any_superadmin()

    async def claim(self, profile: TelegramUserProfile, code: str, *, private_chat: bool) -> ClaimOutcome:
        user_id = profile.telegram_user_id
        async with self._lock:
            try:
                await self._claim_locked(profile, code, private_chat=private_chat)
            except _Rejected as exc:
                logger.warning("Superadmin claim by user %d rejected: %s", user_id, exc)
                return ClaimOutcome.REJECTED
        logger.warning("Superadmin claimed by user %d — the install claim is consumed", user_id)
        return ClaimOutcome.CLAIMED

    async def _claim_locked(self, profile: TelegramUserProfile, code: str, *, private_chat: bool) -> None:
        user_id = profile.telegram_user_id
        if not private_chat:
            raise _Rejected("not a private chat")
        # Inert first: with a superadmin in place nothing below runs — no rate-limit
        # bookkeeping, and claim.json is never opened.
        if await self.has_superadmin():
            raise _Rejected("a superadmin already exists; claim is inert")
        try:
            self._rate_limiter.check(user_id, "superadmin-claim", ATTEMPT_WINDOW_SECONDS, burst=PER_USER_ATTEMPTS)
            self._rate_limiter.check(
                _GLOBAL_LIMIT_KEY, "superadmin-claim", ATTEMPT_WINDOW_SECONDS, burst=GLOBAL_ATTEMPTS
            )
        except RateLimitExceeded:
            raise _Rejected("rate limited") from None
        if _CODE_RE.fullmatch(code) is None:
            raise _Rejected("malformed code")
        pending = read_pending_claim(self._claim_path)
        if self._wall_clock() >= pending.expires_at:
            raise _Rejected("claim expired")
        offered = hashlib.sha256(code.encode("ascii")).hexdigest()
        if not hmac.compare_digest(offered, pending.code_sha256):
            raise _Rejected("code does not match")
        consumed = self._consume_file()
        try:
            await self._record(profile)
        except _Rejected:
            self._restore_file(consumed)
            raise
        except Exception as exc:
            self._restore_file(consumed)
            logger.error("Superadmin claim by user %d could not be recorded (%s)", user_id, type(exc).__name__)
            raise _Rejected("database write failed") from None
        self._superadmins.add_claimed(user_id)
        self._discard(consumed)

    def _consume_file(self) -> Path:
        """Rename claim.json away — the atomic "taken" step. Raises if it is gone."""
        consumed = self._claim_path.with_name(f".{self._claim_path.name}.consumed-{secrets.token_hex(8)}")
        try:
            os.rename(self._claim_path, consumed)
        except FileNotFoundError:
            raise _Rejected("claim was consumed concurrently") from None
        except OSError as exc:
            raise _Rejected(f"claim file could not be consumed ({type(exc).__name__})") from None
        self._fsync_dir()
        return consumed

    def _restore_file(self, consumed: Path) -> None:
        try:
            os.rename(consumed, self._claim_path)
            self._fsync_dir()
        except OSError:
            logger.error("Could not restore the install claim after a failed claim; run install.sh --reclaim")

    def _discard(self, consumed: Path) -> None:
        try:
            consumed.unlink()
            self._fsync_dir()
        except OSError:
            logger.warning("Consumed install claim %s could not be removed", consumed.name)

    def _fsync_dir(self) -> None:
        try:
            fd = os.open(self._claim_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    async def _record(self, profile: TelegramUserProfile) -> None:
        user_id = profile.telegram_user_id
        now = self._clock.now()
        async with self._db.transaction():
            # Re-checked inside the write transaction: the in-process lock covers
            # this process, the IMMEDIATE transaction covers everything else.
            if await self._claims.any_superadmin():
                raise _Rejected("a superadmin appeared during the claim")
            await self._claims.add(user_id, now)
            await self._users.upsert_profile(profile, UserRole.SUPERADMIN, now)
            await self._users.set_role(user_id, UserRole.SUPERADMIN, now, blocked_at=None)
            await self._audit.write(
                actor_user_id=user_id,
                action="superadmin_claimed",
                entity_type=AuditEntityType.USER,
                entity_id=user_id,
                details={"source": "install_claim"},
            )
