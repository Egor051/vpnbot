"""The superadmins' TOTP second factor (docs/wizard.md#totp).

Storage
    The secret lives in ``totp_credentials.secret_enc`` only as a Fernet token; the
    Fernet key is ``/etc/vpn-bot/totp.key`` (0600, owned by the bot's user), created on
    the first enrollment and never written to the database. A key file that is missing
    while credentials exist is never silently replaced — that would make every secret
    undecryptable; :class:`TotpKeyUnavailable` points at ``vpn-bot-totp-reset``.
    Backup codes are stored as ``scrypt(code, salt)`` only.

Checks
    ±1 time-step; a step at or below ``last_used_step`` is refused (replay); five
    wrong codes in a row lock the user out for 15 minutes and alert every superadmin;
    the counter and the lock are in the database, so a restart does not lift them.
    A backup code is redeemed once (``used_at``).

Elevation
    A successful check elevates the user for :data:`ELEVATION_SECONDS`: the dangerous
    actions (services/dangerous.py) do not ask again inside that window. Held in this
    process only — a restart drops every elevation, on purpose.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from adapters.clock import ClockProvider
from models.enums import AuditEntityType
from repositories.totp import TotpRepository
from services.audit import AuditService
from services.errors import InvalidOperation
from utils import totp as otp

logger = logging.getLogger(__name__)

TOTP_KEY_PATH = Path("/etc/vpn-bot/totp.key")
ISSUER = "vpnbot"
MAX_FAILURES = 5
LOCK_SECONDS = 15 * 60
ELEVATION_SECONDS = 5 * 60
_MAX_KEY_FILE_BYTES = 256

AlertSender = Callable[[str], Awaitable[None]]


class TotpError(InvalidOperation):
    """A refused TOTP operation; ``key`` is the i18n message."""


class TotpKeyUnavailable(TotpError):
    """The key file is missing, unreadable or not private."""


class TotpLocked(TotpError):
    def __init__(self, locked_until: int, now: float) -> None:
        minutes = max(1, (locked_until - int(now) + 59) // 60)
        super().__init__("TOTP заблокирован", key="totp_locked", params={"minutes": minutes})
        self.locked_until = locked_until


@dataclass(frozen=True, slots=True)
class TotpStatus:
    enabled: bool
    pending: bool
    backup_left: int
    locked_until: int


@dataclass(frozen=True, slots=True)
class Enrollment:
    secret_b32: str
    uri: str


@dataclass(frozen=True, slots=True)
class VerifyResult:
    method: str  # "totp" | "backup"
    backup_left: int


class TotpKeyFile:
    """The Fernet key at ``path``: read with the same checks as claim.json."""

    def __init__(self, path: Path = TOTP_KEY_PATH) -> None:
        self.path = path

    def exists(self) -> bool:
        return os.path.lexists(self.path)

    def load(self) -> Fernet:
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            raise TotpKeyUnavailable("нет файла ключа TOTP", key="totp_key_missing") from None
        except OSError as exc:
            logger.warning("TOTP key %s cannot be opened: %s", self.path, exc)
            raise TotpKeyUnavailable("файл ключа TOTP недоступен", key="totp_key_unusable") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_KEY_FILE_BYTES:
                raise TotpKeyUnavailable("файл ключа TOTP не обычный файл", key="totp_key_unusable")
            if os.name == "posix" and (st.st_uid != os.geteuid() or st.st_mode & 0o077):
                logger.warning("TOTP key %s: owner %s mode %o is not private to uid %s", self.path, st.st_uid, st.st_mode & 0o777, os.geteuid())
                raise TotpKeyUnavailable("файл ключа TOTP не приватный", key="totp_key_unusable")
            raw = os.read(fd, _MAX_KEY_FILE_BYTES + 1).strip()
        finally:
            os.close(fd)
        try:
            return Fernet(raw)
        except (ValueError, TypeError) as exc:
            raise TotpKeyUnavailable("файл ключа TOTP повреждён", key="totp_key_unusable") from exc

    def create(self) -> Fernet:
        """Write a new key (O_EXCL: never over an existing file) and return it."""
        key = Fernet.generate_key()
        parent = self.path.parent
        try:
            if not parent.exists():
                parent.mkdir(mode=0o755, parents=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            return self.load()
        except OSError as exc:
            logger.warning("TOTP key %s cannot be created: %s", self.path, exc)
            raise TotpKeyUnavailable("не удалось создать ключ TOTP", key="totp_key_create_failed") from exc
        try:
            os.write(fd, key + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        logger.info("TOTP key created at %s", self.path)
        return Fernet(key)


class TotpService:
    def __init__(
        self,
        *,
        repo: TotpRepository,
        audit: AuditService,
        clock: ClockProvider,
        key_file: TotpKeyFile | None = None,
        issuer: str = ISSUER,
        now: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        alert: AlertSender | None = None,
    ) -> None:
        self.repo = repo
        self.audit = audit
        self.clock = clock
        self.key_file = key_file or TotpKeyFile()
        self.issuer = issuer
        self._now = now
        self._monotonic = monotonic
        self.alert = alert
        self._elevated: dict[int, float] = {}
        self._locks: dict[int, asyncio.Lock] = {}

    def _lock(self, user_id: int) -> asyncio.Lock:
        lock = self._locks.get(user_id)
        if lock is None:
            lock = self._locks[user_id] = asyncio.Lock()
        return lock

    # ------------------------------------------------------------------ status
    async def status(self, user_id: int) -> TotpStatus:
        cred = await self.repo.get(user_id)
        if cred is None:
            return TotpStatus(enabled=False, pending=False, backup_left=0, locked_until=0)
        left = await self.repo.count_unused_backup_codes(user_id) if cred.enabled else 0
        return TotpStatus(
            enabled=cred.enabled,
            pending=not cred.enabled,
            backup_left=left,
            locked_until=cred.locked_until if cred.locked_until > int(self._now()) else 0,
        )

    async def is_enabled(self, user_id: int) -> bool:
        cred = await self.repo.get(user_id)
        return cred is not None and cred.enabled

    # --------------------------------------------------------------- elevation
    def is_elevated(self, user_id: int) -> bool:
        until = self._elevated.get(user_id)
        if until is None:
            return False
        if self._monotonic() >= until:
            self._elevated.pop(user_id, None)
            return False
        return True

    def elevate(self, user_id: int) -> None:
        self._elevated[user_id] = self._monotonic() + ELEVATION_SECONDS

    def drop_elevation(self, user_id: int) -> None:
        self._elevated.pop(user_id, None)

    # -------------------------------------------------------------- enrollment
    async def _fernet_for_enrollment(self) -> Fernet:
        if self.key_file.exists():
            return await asyncio.to_thread(self.key_file.load)
        if await self.repo.count_credentials() > 0:
            # Enabled secrets exist that were encrypted with a key that is gone. A new
            # key would not bring them back; it would only hide the loss.
            raise TotpKeyUnavailable("ключ TOTP пропал при живых секретах", key="totp_key_missing")
        return await asyncio.to_thread(self.key_file.create)

    async def begin_enrollment(self, user_id: int, account: str) -> Enrollment:
        """A new secret, stored encrypted as not-yet-enabled. Refused while enabled."""
        cred = await self.repo.get(user_id)
        if cred is not None and cred.enabled:
            raise TotpError("TOTP уже включён", key="totp_already_enabled")
        fernet = await self._fernet_for_enrollment()
        key = otp.generate_secret()
        secret_b32 = otp.encode_secret(key)
        token = fernet.encrypt(key).decode("ascii")
        await self.repo.save_pending(user_id, token, self.clock.now())
        await self.audit.write(
            actor_user_id=user_id,
            action="totp_enrollment_started",
            entity_type=AuditEntityType.SECURITY,
            entity_id=user_id,
        )
        return Enrollment(secret_b32=secret_b32, uri=otp.otpauth_uri(secret_b32, account=account, issuer=self.issuer))

    async def confirm_enrollment(self, user_id: int, code: str) -> list[str]:
        """Check the first code; on success enable TOTP and return the backup codes.

        The plain codes exist only in the return value: the caller shows them once.
        """
        async with self._lock(user_id):
            cred = await self.repo.get(user_id)
            if cred is None or cred.enabled:
                raise TotpError("нет начатого подключения TOTP", key="totp_no_enrollment")
            self._raise_if_locked(cred.locked_until)
            key = await self._decrypt(cred.secret_enc)
            step = otp.verify(key, code, self._now(), last_step=None)
            if step is None:
                await self._failure(user_id, "enroll")
                raise TotpError("неверный код", key="totp_invalid_code")
            codes = otp.generate_backup_codes()
            hashed = await asyncio.to_thread(_hash_codes, codes)
            await self.repo.enable(user_id, step=step, codes=hashed, now=self.clock.now())
        self.elevate(user_id)
        await self.audit.write(
            actor_user_id=user_id,
            action="totp_enabled",
            entity_type=AuditEntityType.SECURITY,
            entity_id=user_id,
            details={"backup_codes": len(codes)},
        )
        return codes

    async def cancel_enrollment(self, user_id: int) -> None:
        cred = await self.repo.get(user_id)
        if cred is not None and not cred.enabled:
            await self.repo.delete(user_id)

    # ------------------------------------------------------------- verification
    async def verify(self, user_id: int, code: str, *, purpose: str, allow_backup: bool = True) -> VerifyResult:
        """Check a TOTP code (or, when allowed, a backup code). Elevates on success.

        Raises :class:`TotpLocked` during a lockout (the code is not even looked at),
        :class:`TotpError` ``totp_invalid_code`` on a wrong one (counted).
        """
        async with self._lock(user_id):
            cred = await self.repo.get(user_id)
            if cred is None or not cred.enabled:
                raise TotpError("TOTP не включён", key="totp_not_enabled")
            self._raise_if_locked(cred.locked_until)
            if otp.normalize_code(code) is not None:
                key = await self._decrypt(cred.secret_enc)
                step = otp.verify(key, code, self._now(), last_step=cred.last_used_step)
                if step is not None:
                    await self.repo.record_success(user_id, step)
                    result = VerifyResult("totp", await self.repo.count_unused_backup_codes(user_id))
                    await self._succeeded(user_id, purpose, result)
                    return result
            elif allow_backup and otp.normalize_backup_code(code) is not None:
                code_id = await self._match_backup_code(user_id, code)
                if code_id is not None and await self.repo.redeem_backup_code(code_id, self.clock.now()):
                    await self.repo.record_success(user_id, None)
                    result = VerifyResult("backup", await self.repo.count_unused_backup_codes(user_id))
                    await self._succeeded(user_id, purpose, result)
                    return result
            await self._failure(user_id, purpose)
        raise TotpError("неверный код", key="totp_invalid_code")

    async def _match_backup_code(self, user_id: int, code: str) -> int | None:
        rows = await self.repo.unused_backup_codes(user_id)
        candidates = [(row.id, bytes.fromhex(row.salt_hex), bytes.fromhex(row.hash_hex)) for row in rows]
        return await asyncio.to_thread(_first_match, code, candidates)

    async def _succeeded(self, user_id: int, purpose: str, result: VerifyResult) -> None:
        self.elevate(user_id)
        await self.audit.write(
            actor_user_id=user_id,
            action="totp_backup_code_used" if result.method == "backup" else "totp_verified",
            entity_type=AuditEntityType.SECURITY,
            entity_id=user_id,
            details={"purpose": purpose, "backup_left": result.backup_left},
        )

    async def _failure(self, user_id: int, purpose: str) -> None:
        lock_until = int(self._now()) + LOCK_SECONDS
        failures, locked = await self.repo.record_failure(user_id, max_failures=MAX_FAILURES, lock_until=lock_until)
        self.drop_elevation(user_id)
        await self.audit.write(
            actor_user_id=user_id,
            action="totp_locked" if locked else "totp_verify_failed",
            entity_type=AuditEntityType.SECURITY,
            entity_id=user_id,
            details={"purpose": purpose, "failures": failures, **({"locked_until": lock_until} if locked else {})},
        )
        if locked:
            logger.warning("TOTP: %d wrong codes in a row for user %d — locked for %ds", failures, user_id, LOCK_SECONDS)
            if self.alert is not None:
                try:
                    await self.alert(_lock_alert_text(user_id, lock_until))
                except Exception:
                    logger.warning("TOTP lockout alert could not be sent", exc_info=True)

    def _raise_if_locked(self, locked_until: int) -> None:
        if locked_until > int(self._now()):
            raise TotpLocked(locked_until, self._now())

    async def _decrypt(self, token: str) -> bytes:
        fernet = await asyncio.to_thread(self.key_file.load)
        try:
            return fernet.decrypt(token.encode("ascii"))
        except InvalidToken as exc:
            logger.warning("TOTP secret does not decrypt with %s (key replaced?)", self.key_file.path)
            raise TotpKeyUnavailable("секрет TOTP не расшифровывается", key="totp_key_unusable") from exc

    # ----------------------------------------------------- disable / reissue
    async def disable(self, user_id: int, code: str) -> None:
        """Needs a TOTP or a backup code."""
        await self.verify(user_id, code, purpose="disable", allow_backup=True)
        await self.repo.delete(user_id)
        self.drop_elevation(user_id)
        await self.audit.write(
            actor_user_id=user_id,
            action="totp_disabled",
            entity_type=AuditEntityType.SECURITY,
            entity_id=user_id,
        )

    async def reissue_backup_codes(self, user_id: int, code: str) -> list[str]:
        """New backup codes; the old ones stop working. Needs a TOTP code, not a backup one."""
        await self.verify(user_id, code, purpose="reissue_backup_codes", allow_backup=False)
        codes = otp.generate_backup_codes()
        hashed = await asyncio.to_thread(_hash_codes, codes)
        await self.repo.replace_backup_codes(user_id, hashed, self.clock.now())
        await self.audit.write(
            actor_user_id=user_id,
            action="totp_backup_codes_reissued",
            entity_type=AuditEntityType.SECURITY,
            entity_id=user_id,
            details={"backup_codes": len(codes)},
        )
        return codes


def _hash_codes(codes: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for code in codes:
        salt = otp.new_salt()
        out.append((salt.hex(), otp.hash_backup_code(code, salt).hex()))
    return out


def _first_match(code: str, candidates: list[tuple[int, bytes, bytes]]) -> int | None:
    found: int | None = None
    for code_id, salt, digest in candidates:
        if otp.backup_code_matches(code, salt, digest) and found is None:
            found = code_id
    return found


def _lock_alert_text(user_id: int, lock_until: int) -> str:
    from i18n import t

    until = time.strftime("%H:%M UTC", time.gmtime(lock_until))
    return t("totp_lock_alert", user_id=user_id, failures=MAX_FAILURES, until=until)
