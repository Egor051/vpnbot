"""«🌐 Сайт» — the decoy site seen from the bot (docs/site.md).

The site is the static tree nginx serves on 127.0.0.1:8443 — the REALITY self-steal target
and, through Hysteria2's masquerade proxy, the same site on UDP. It is root's:
/usr/local/sbin/vpn-bot-site (scripts/vpn-bot-site). The bot

* READS it: ``vpn-bot-site status --json`` — through sudo in the helper model (the exact
  grant ``/usr/local/sbin/vpn-bot-site status --json``), directly as root otherwise;
* STAGES an archive the superadmin sent as a document: written atomically (0600) to
  ``<HELPER_STAGING_ROOT>/site/upload.bin`` — the bot's RuntimeDirectory, the fixed path
  the helper reads with O_NOFOLLOW (so HELPER_STAGING_ROOT stays /run/vpn-bot, as for the
  xray staging). Its sha256's first 16 hex is the run's ``digest``: the helper's plan takes
  the upload only when it IS that archive, and then removes it;
* CHANGES the site only through a run of the setup wizard's ``site`` mode
  (services/wizard.py): the plan with the diff, the superadmin's confirmation and TOTP,
  apply → verify → rollback, in its own systemd unit;
* after a run that succeeded, re-lays the xray keys whose STORED spiderX is no longer in
  XRAY_SPIDER_X_POOL (the pool the helper wrote, read back from its status): the same
  deterministic pick a fresh key gets (``utils.spider_x.pick_spider_x``). The database is
  the bot's — the helper only counts those keys for the plan. The every-start backfill is
  not that step: it fills NULLs only and never overwrites an assigned value.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from adapters.clock import ClockProvider
from adapters.privileged_helpers import PrivilegedHelperRunner
from models.dto import WizardRun
from models.enums import AuditEntityType
from services.audit import AuditService
from services.errors import InvalidOperation, ServiceError
from services.wizard import WizardService

logger = logging.getLogger(__name__)

MODE = "site"
SITE_HELPER = Path("/usr/local/sbin/vpn-bot-site")
UPLOAD_NAME = "upload.bin"
STATUS_TIMEOUT = 120.0
# vpn-bot-site's MAX_ARCHIVE_BYTES (a test keeps the two equal): the Bot API downloads at
# most 20 MB, so a bigger document is refused before it is fetched.
MAX_ARCHIVE_BYTES = 20 << 20
ACTIONS = ("deploy", "revert")


class SiteError(InvalidOperation):
    """A refused site operation the admin must see (``key`` is the i18n message)."""


@dataclass(frozen=True, slots=True)
class SiteStatus:
    """``vpn-bot-site status --json``, as the screen reads it (the raw report kept)."""

    raw: dict[str, Any] = field(default_factory=dict)

    def _dict(self, key: str) -> dict[str, Any]:
        value = self.raw.get(key)
        return value if isinstance(value, dict) else {}

    @property
    def docroot(self) -> str | None:
        value = self.raw.get("docroot")
        return str(value) if value else None

    @property
    def domain(self) -> str | None:
        value = self.raw.get("domain")
        return str(value) if value else None

    @property
    def current(self) -> dict[str, Any]:
        return self._dict("current")

    @property
    def pages(self) -> list[str]:
        return [str(p) for p in self.raw.get("pages") or [] if isinstance(p, str)]

    @property
    def pages_total(self) -> int:
        value = self.raw.get("pages_total")
        return int(value) if isinstance(value, int) else len(self.pages)

    @property
    def releases(self) -> list[dict[str, Any]]:
        return [r for r in self.raw.get("releases") or [] if isinstance(r, dict)]

    @property
    def revert_to(self) -> str | None:
        value = self.raw.get("revert_to")
        return str(value) if value else None

    @property
    def spx(self) -> dict[str, Any]:
        return self._dict("spx")

    @property
    def pool(self) -> tuple[str, ...]:
        return tuple(str(p) for p in self.spx.get("pool") or [] if isinstance(p, str) and p.startswith("/"))

    @property
    def hy2(self) -> dict[str, Any]:
        return self._dict("hy2")

    @property
    def problems(self) -> list[str]:
        return [str(p) for p in self.raw.get("problems") or []]

    @property
    def limits(self) -> dict[str, Any]:
        return self._dict("limits")

    @property
    def ok(self) -> bool:
        return bool(self.raw.get("ok"))

    @property
    def unfinished(self) -> bool:
        """An apply that never finished (the next run's plan rolls it back first)."""
        journal = self._dict("journal")
        return journal.get("state") in ("applying", "applied", "committing", "rollback_failed")


class _Users(Protocol):
    async def require_superadmin(self, user_id: int) -> object: ...


class _Keys(Protocol):
    async def relayout_spider_x(self, pool: tuple[str, ...], now: str) -> int: ...


def archive_kind(data: bytes) -> str | None:
    """zip / tar.gz by the first bytes (the helper decides the same way), else None."""
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "tar.gz"
    return None


class SiteService:
    def __init__(
        self,
        *,
        runner: PrivilegedHelperRunner | None,
        wizard: WizardService | None,
        users: _Users,
        keys: _Keys,
        audit: AuditService | None,
        clock: ClockProvider,
        staging_dir: Path,
        helper: Path = SITE_HELPER,
    ) -> None:
        self.runner = runner
        self.wizard = wizard
        self.users = users
        self.keys = keys
        self.audit = audit
        self.clock = clock
        self.staging_dir = staging_dir
        self.helper = helper
        if wizard is not None:
            wizard.register_after_success(MODE, self.after_success)
            wizard.add_finish_listener(self._on_finished)

    def installed(self) -> bool:
        return self.helper.is_file()

    async def _raw_status(self) -> dict[str, Any]:
        if self.runner is None or not self.installed():
            raise ServiceError("vpn-bot-site не установлен", key="site_err_not_installed", params={"path": str(self.helper)})
        try:
            result = await self.runner.run(self.helper, ["status", "--json"], timeout=STATUS_TIMEOUT, max_output_chars=200_000)
        except Exception as exc:
            logger.warning("vpn-bot-site status could not run: %s", type(exc).__name__)
            raise ServiceError("vpn-bot-site не запустился", key="site_err_status", params={"error": type(exc).__name__}) from None
        raw: dict[str, Any] | None = None
        for line in (result.stdout or "").splitlines():
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                except ValueError:
                    continue
                if isinstance(parsed, dict):
                    raw = parsed
        # exit 3 with a report: the helper found the site but not one it can change (the
        # report says why) — still a status the screen shows.
        if raw is None or "limits" not in raw:
            tail = ((result.stderr or "") + (result.stdout or "")).strip().splitlines()
            raise ServiceError("vpn-bot-site status", key="site_err_status",
                               params={"error": (tail[-1] if tail else f"exit {result.returncode}")[:300]})
        return raw

    async def status(self, actor_user_id: int) -> SiteStatus:
        await self.users.require_superadmin(actor_user_id)
        return SiteStatus(await self._raw_status())

    # ── the upload ────────────────────────────────────────────────────────────

    @property
    def upload_path(self) -> Path:
        return self.staging_dir / UPLOAD_NAME

    def stage(self, data: bytes) -> str:
        """The archive where the helper reads it (atomic, 0600, the staging directory
        0700 and not a symlink); its digest — the first 16 hex of its sha256."""
        if not data:
            raise SiteError("пустой файл", key="site_err_empty")
        if len(data) > MAX_ARCHIVE_BYTES:
            raise SiteError("слишком большой архив", key="site_err_too_large", params={"max": MAX_ARCHIVE_BYTES // (1 << 20)})
        if archive_kind(data) is None:
            raise SiteError("не zip и не tar.gz", key="site_err_not_archive")
        directory = self.staging_dir
        if directory.is_symlink():
            raise SiteError("каталог загрузки — симлинк", key="site_err_staging", params={"path": str(directory)})
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".upload.")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.upload_path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return hashlib.sha256(data).hexdigest()[:16]

    def discard_upload(self) -> None:
        try:
            self.upload_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("site upload %s could not be removed: %s", self.upload_path, type(exc).__name__)

    # ── the runs ──────────────────────────────────────────────────────────────

    async def start(
        self,
        actor_user_id: int,
        action: str,
        *,
        digest: str = "",
        chat_id: int | None = None,
        message_id: int | None = None,
    ) -> WizardRun:
        """A run of the ``site`` mode: its plan first. SUPERADMIN; the TOTP is the
        handler's; the caller holds the wizard's ``exclusive()``."""
        await self.users.require_superadmin(actor_user_id)
        if action not in ACTIONS:
            raise ValueError(action)
        if self.wizard is None:
            raise ServiceError("мастер не подключён", key="wizard_unavailable")
        if action == "deploy" and not digest:
            raise SiteError("нет архива", key="site_err_no_upload")
        return await self.wizard.start(
            actor_user_id, MODE, {"action": action, "digest": digest if action == "deploy" else ""},
            chat_id=chat_id, message_id=message_id,
        )

    async def _on_finished(self, run: WizardRun) -> None:
        """Whatever a site run ended with, the bot's copy of the archive goes (the plan
        removes it once it took it; a plan that refused it did not)."""
        if run.mode == MODE:
            self.discard_upload()

    async def after_success(self, run: WizardRun) -> str | None:
        """The keys follow the pool: every xray key whose stored spiderX the new site no
        longer has gets one of its paths (idempotent — run again by every report attempt)."""
        try:
            status = SiteStatus(await self._raw_status())
        except ServiceError as exc:
            logger.warning("site run %d: status for the spiderX re-layout failed (%s)", run.id, exc.key)
            return "spiderX: the keys were not re-laid (vpn-bot-site status did not answer) — they will be at the next site run"
        pool = status.pool
        if not pool:
            return None
        moved = await self.keys.relayout_spider_x(pool, self.clock.now())
        if moved and self.audit is not None:
            await self.audit.write_best_effort(
                actor_user_id=run.started_by,
                action="site_spider_x_relayout",
                entity_type=AuditEntityType.WIZARD,
                entity_id=run.id,
                details={"keys": moved, "pool": len(pool)},
            )
        return f"spiderX: {moved} key(s) moved to paths of the new site" if moved else None
