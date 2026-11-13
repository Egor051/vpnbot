"""The main server's UFW as the bot sees it (docs/host-state.md#the-firewall-ufw).

``scripts/vpn-bot-ufw-apply`` (installed by deploy.sh, ``OUT_OF_REPO_HELPERS``) owns
the firewall: it computes the rule set from ``.env``, its module table and the
uninstall markers, and converges the host on it. Nobody types ``ufw allow``. The bot
has two parts in it:

* :class:`UfwApplier` runs ``vpn-bot-ufw-apply apply`` after a protocol is switched on
  in «Модули протоколов» and after one is removed from the host — its marker takes the
  module out of the set, and that is how its rules leave the firewall (the uninstall
  helper no longer touches ufw: one owner of the rules). Through sudo in the helper
  model (exact-path grant in deploy/sudoers.d/vpn-bot.example), directly as root
  otherwise. A failure is reported, never raised: the protocol change stands and the
  next deploy converges the firewall anyway.
* :class:`UfwDeadmanMonitor`: a change of the incoming policy, or enabling an inactive
  ufw, stays only with a proof that ssh still answers from outside. The helper keeps
  that state in ``/var/lib/vpn-bot/ufw-deadman.json`` (root, 0644); the monitor reads
  it every :data:`POLL_SECONDS` and tells the superadmins once when a change waits for
  its proof — with «Подтвердить», which runs ``vpn-bot-ufw-apply confirm --since S
  --admin ID`` — and once when it was confirmed or reverted. What was told is kept in
  ``schema_meta``, so a restart (every deploy is one) does not repeat it.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aiogram import Bot
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from adapters.privileged_helpers import PrivilegedHelperRunner
from i18n import t
from services.errors import InvalidOperation
from utils.formatting import h

logger = logging.getLogger(__name__)

# Installed from scripts/vpn-bot-ufw-apply by deploy.sh (OUT_OF_REPO_HELPERS, required).
HELPER_PATH = Path("/usr/local/sbin/vpn-bot-ufw-apply")
# Written by the helper (root, 0644) while a policy change waits for its proof.
DEADMAN_STATE_PATH = Path("/var/lib/vpn-bot/ufw-deadman.json")
# schema_meta key: what was told, as JSON {"pending": <armed_at>, "done": <armed_at>}.
META_KEY = "ufw_deadman_alerted"
CALLBACK_PREFIX = "ufw:ok:"
APPLY_TIMEOUT_SECONDS = 300.0
CONFIRM_TIMEOUT_SECONDS = 60.0
# The dead-man reverts after 10 minutes: the message must come well before that.
POLL_SECONDS = 30
_PREFIX = "vpn-bot-ufw-apply: "


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class UfwApplyResult:
    ok: bool
    summary: str
    returncode: int


def _last_line(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return ""
    last = lines[-1]
    return last[len(_PREFIX):] if last.startswith(_PREFIX) else last


class UfwApplier:
    """Runs ``vpn-bot-ufw-apply apply``; never raises."""

    def __init__(self, *, runner: PrivilegedHelperRunner | None, helper: Path = HELPER_PATH) -> None:
        self._runner = runner
        self._helper = helper

    async def apply(self, reason: str) -> UfwApplyResult:
        if self._runner is None:
            return UfwApplyResult(False, "no runner for vpn-bot-ufw-apply", -1)
        try:
            result = await self._runner.run(
                self._helper, ["apply"], timeout=APPLY_TIMEOUT_SECONDS, max_output_chars=8000
            )
        except Exception as exc:
            logger.warning("UFW apply after %s could not run", reason, exc_info=True)
            return UfwApplyResult(False, f"vpn-bot-ufw-apply could not run: {exc}", -1)
        text = (result.stdout or "") + (result.stderr or "")
        summary = _last_line(text) or f"exit {result.returncode}"
        if result.returncode == 0:
            logger.info("UFW applied after %s: %s", reason, summary)
            return UfwApplyResult(True, summary, 0)
        logger.warning("UFW apply after %s failed (rc %s): %s", reason, result.returncode, text.strip())
        return UfwApplyResult(False, summary, result.returncode)


# --------------------------------------------------------------------------- #
# The dead-man of a policy change
# --------------------------------------------------------------------------- #
class UfwStateError(ValueError):
    """The state file is not one the helper writes."""


class UfwConfirmError(InvalidOperation):
    """The confirmation was refused (a stale button, or the helper failed)."""


@dataclass(frozen=True, slots=True)
class DeadmanState:
    state: str            # pending | confirmed | reverted
    armed_at: int
    deadline_iso: str
    changes: str          # "incoming policy: allow -> deny; ufw: inactive -> active"
    ssh_ports: str
    done_iso: str
    proof: str


def parse_state(raw: str) -> DeadmanState:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UfwStateError(f"not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise UfwStateError("not a JSON object")
    state, armed = data.get("state"), data.get("armed_at")
    if state not in ("pending", "confirmed", "reverted"):
        raise UfwStateError(f"state {state!r}")
    if not isinstance(armed, int) or isinstance(armed, bool) or armed <= 0:
        raise UfwStateError(f"armed_at {armed!r}")
    changes = []
    for c in data.get("changes") or []:
        if isinstance(c, dict):
            changes.append(f"{c.get('what')}: {c.get('from')} → {c.get('to')}")
    ports = data.get("ssh_ports") or []
    return DeadmanState(
        state=str(state),
        armed_at=armed,
        deadline_iso=str(data.get("deadline_iso") or "?"),
        changes="; ".join(changes) or "?",
        ssh_ports=",".join(str(p) for p in ports if isinstance(p, int)),
        done_iso=str(data.get("done_iso") or "?"),
        proof=str(data.get("proof") or ""),
    )


def confirm_callback_data(s: DeadmanState) -> str:
    return f"{CALLBACK_PREFIX}{s.armed_at}"


def parse_callback_data(data: str) -> int | None:
    """The armed_at of a «Подтвердить» button, or None."""
    if not data.startswith(CALLBACK_PREFIX):
        return None
    tail = data[len(CALLBACK_PREFIX):]
    return int(tail) if tail.isdigit() and int(tail) > 0 else None


def confirm_keyboard(s: DeadmanState) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_ufw_confirm"), callback_data=confirm_callback_data(s))]]
    )


def render_pending(s: DeadmanState) -> str:
    return t("ufw_deadman_pending", changes=h(s.changes), ports=h(s.ssh_ports or "?"), deadline=h(s.deadline_iso))


def render_done(s: DeadmanState) -> str:
    if s.state == "confirmed":
        return t("ufw_deadman_confirmed", changes=h(s.changes), proof=h(s.proof or "?"), at=h(s.done_iso))
    return t("ufw_deadman_reverted", changes=h(s.changes), at=h(s.done_iso))


class MetaStore(Protocol):
    async def get_meta(self, key: str) -> str | None: ...

    async def set_meta(self, key: str, value: str) -> None: ...


Sender = Callable[[str, InlineKeyboardMarkup | None], Awaitable[None]]


class UfwDeadmanMonitor:
    """Reads the dead-man state, tells the superadmins once per step, confirms."""

    def __init__(
        self,
        *,
        store: MetaStore,
        admin_ids: AbstractSet[int],
        path: Path = DEADMAN_STATE_PATH,
        helper: Path = HELPER_PATH,
        runner: PrivilegedHelperRunner | None = None,
        bot: Bot | None = None,
        send: Sender | None = None,
    ) -> None:
        self._store = store
        self._admin_ids = admin_ids
        self._path = path
        self._helper = helper
        self._runner = runner
        self.bot = bot
        self._send_override = send
        self._last_problem: str | None = None

    async def _send(self, text: str, markup: InlineKeyboardMarkup | None) -> None:
        if self._send_override is not None:
            await self._send_override(text, markup)
            return
        if self.bot is None:
            return
        for admin_id in self._admin_ids:
            try:
                await self.bot.send_message(admin_id, text, reply_markup=markup)
            except Exception:
                logger.warning("Failed to send the UFW dead-man message to admin %d", admin_id, exc_info=True)

    def _note(self, problem: str | None) -> None:
        if problem is not None and problem != self._last_problem:
            logger.warning("UFW dead-man: %s", problem)
        self._last_problem = problem

    async def read(self) -> DeadmanState | None:
        try:
            raw = await asyncio.to_thread(self._path.read_text, encoding="utf-8")
        except FileNotFoundError:
            self._note(None)
            return None
        except OSError as exc:
            self._note(f"cannot read {self._path}: {exc}")
            return None
        try:
            s = parse_state(raw)
        except UfwStateError as exc:
            self._note(f"{self._path} is not a dead-man state: {exc}")
            return None
        self._note(None)
        return s

    async def _told(self) -> dict[str, int]:
        raw = await self._store.get_meta(META_KEY)
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, int)}

    async def check_once(self) -> None:
        """One pass. Nothing is sent and nothing remembered while no bot is attached."""
        if self.bot is None and self._send_override is None:
            return
        s = await self.read()
        if s is None:
            return
        told = await self._told()
        now = dict(told)
        if s.state == "pending" and told.get("pending") != s.armed_at:
            await self._send(render_pending(s), confirm_keyboard(s))
            now["pending"] = s.armed_at
        elif s.state in ("confirmed", "reverted") and told.get("done") != s.armed_at:
            # A change confirmed before the first pass (the journal proof can come
            # within a minute) was never announced: say once what happened anyway.
            await self._send(render_done(s), None)
            now["pending"] = now["done"] = s.armed_at
        if now != told:
            await self._store.set_meta(META_KEY, json.dumps(now, sort_keys=True))

    async def confirm(self, admin_id: int, armed_at: int) -> str:
        """The superadmin's proof that ssh still answers. Returns the helper's line."""
        s = await self.read()
        if s is None or s.state != "pending" or s.armed_at != armed_at:
            raise UfwConfirmError(
                "Эта смена политики UFW уже не ждёт подтверждения.", key="ufw_confirm_stale"
            )
        if self._runner is None:
            raise UfwConfirmError("Нет исполнителя для vpn-bot-ufw-apply.", key="ufw_confirm_failed")
        result = await self._runner.run(
            self._helper,
            ["confirm", "--since", str(armed_at), "--admin", str(admin_id)],
            timeout=CONFIRM_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            logger.warning("UFW confirm refused (rc %s): %s", result.returncode, (result.stderr or result.stdout).strip())
            raise UfwConfirmError("vpn-bot-ufw-apply не принял подтверждение.", key="ufw_confirm_failed")
        return result.stdout.strip()


async def ufw_deadman_loop(monitor: UfwDeadmanMonitor, interval: int = POLL_SECONDS) -> None:
    """Read the state file every *interval* seconds; a failing pass is logged."""
    while True:
        try:
            await monitor.check_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("UFW dead-man pass failed", exc_info=True)
        await asyncio.sleep(interval)
