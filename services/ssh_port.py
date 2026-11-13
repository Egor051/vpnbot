"""The SSH port migration as the superadmins see it (docs/host-state.md#the-ssh-port).

``SSH_PORT`` in ``.env`` is the port ssh listens on. When it is not the port ssh
listens on now, the deploy moves ssh in two phases (scripts/vpn-bot-ssh-port):
phase 1 listens on BOTH ports, phase 2 closes the old one — and only once the new
one is PROVEN to work from outside. The state is
``/var/lib/vpn-bot/ssh-migration.json`` (root, 0644), written by the helper.

This module is the bot's part of it, on the main server:

* :class:`SshPortMonitor` reads that file on the host check's interval and tells the
  superadmins (``ADMIN_IDS``) once when phase 1 starts — with the «Подтвердить»
  button, proof (c): "SSH is on port N too — connect there and press Подтвердить" —
  once when the migration is done, and once when it was called off. What was told is
  kept in ``schema_meta``, so a restart (every deploy is one) does not repeat it.
* :meth:`SshPortMonitor.confirm` is that button: it runs
  ``vpn-bot-ssh-port confirm --port N --since S --admin ID`` — through sudo in the
  helper model (exact-path grant in deploy/sudoers.d/vpn-bot.example), directly as
  root otherwise. The helper writes the proof into the state file and starts
  vpn-bot-ssh-port.service, which closes the old port. The port and the start time
  travel in the button, so a button of an older migration is refused by the helper.

A relay runs no bot: its migration is proven by main's probe or by its sshd log, and
its state is in its own deploy report and journal.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from aiogram import Bot
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from adapters.privileged_helpers import PrivilegedHelperRunner
from i18n import t
from services.errors import InvalidOperation
from utils.formatting import h

logger = logging.getLogger(__name__)

# Written by scripts/vpn-bot-ssh-port (root, 0644).
STATE_PATH = Path("/var/lib/vpn-bot/ssh-migration.json")
# Installed from scripts/vpn-bot-ssh-port by deploy.sh (OUT_OF_REPO_HELPERS, required).
HELPER_PATH = Path("/usr/local/sbin/vpn-bot-ssh-port")
# schema_meta key: what was told, as JSON {"started": <since>, "done": <since>, ...}.
META_KEY = "ssh_port_alerted"
CALLBACK_PREFIX = "sshport:ok:"
CONFIRM_TIMEOUT_SECONDS = 60.0


class SshPortStateError(ValueError):
    """The state file is not one the helper writes."""


class SshPortConfirmError(InvalidOperation):
    """The confirmation was refused (a stale button, or the helper failed)."""


@dataclass(frozen=True, slots=True)
class Migration:
    from_ports: tuple[int, ...]
    to: int
    phase: int          # 1 = both ports, 2 = done, 0 = called off
    since: int
    done_iso: str
    proof_kind: str
    proof_detail: str

    @property
    def old(self) -> str:
        return ",".join(str(p) for p in self.from_ports)

    @property
    def since_text(self) -> str:
        return datetime.fromtimestamp(self.since, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise SshPortStateError(f"not a port: {value!r}")
    return value


def parse_state(raw: str) -> Migration:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SshPortStateError(f"not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SshPortStateError("not a JSON object")
    from_raw, phase, since = data.get("from"), data.get("phase"), data.get("since")
    if not isinstance(from_raw, list) or not from_raw:
        raise SshPortStateError("from is not a list of ports")
    if phase not in (0, 1, 2) or isinstance(phase, bool):
        raise SshPortStateError(f"phase {phase!r}")
    if not isinstance(since, int) or isinstance(since, bool) or since <= 0:
        raise SshPortStateError(f"since {since!r}")
    proof = data.get("proof")
    kind = detail = ""
    if isinstance(proof, dict):
        kind = str(proof.get("kind") or "")
        detail = str(proof.get("detail") or "")
    return Migration(
        from_ports=tuple(_port(p) for p in from_raw),
        to=_port(data.get("to")),
        phase=int(phase),
        since=since,
        done_iso=str(data.get("done_iso") or ""),
        proof_kind=kind,
        proof_detail=detail,
    )


def confirm_callback_data(m: Migration) -> str:
    return f"{CALLBACK_PREFIX}{m.to}:{m.since}"


def parse_callback_data(data: str) -> tuple[int, int] | None:
    """(port, since) of a «Подтвердить» button, or None."""
    if not data.startswith(CALLBACK_PREFIX):
        return None
    port_s, _, since_s = data[len(CALLBACK_PREFIX):].partition(":")
    if not port_s.isdigit() or not since_s.isdigit() or not 1 <= int(port_s) <= 65535:
        return None
    return int(port_s), int(since_s)


def confirm_keyboard(m: Migration) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_ssh_port_confirm", port=m.to),
                                               callback_data=confirm_callback_data(m))]]
    )


def render_started(m: Migration) -> str:
    return t("ssh_port_started", old=h(m.old), new=m.to, since=h(m.since_text))


def render_done(m: Migration) -> str:
    return t("ssh_port_done", old=h(m.old), new=m.to, at=h(m.done_iso or "?"),
             proof=h(m.proof_detail or m.proof_kind or "?"))


def render_cancelled(m: Migration) -> str:
    return t("ssh_port_cancelled", old=h(m.old), new=m.to)


class MetaStore(Protocol):
    async def get_meta(self, key: str) -> str | None: ...

    async def set_meta(self, key: str, value: str) -> None: ...


Sender = Callable[[str, InlineKeyboardMarkup | None], Awaitable[None]]


class SshPortMonitor:
    """Reads the migration state, tells the superadmins once per step, confirms."""

    def __init__(
        self,
        *,
        store: MetaStore,
        admin_ids: AbstractSet[int],
        path: Path = STATE_PATH,
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
                logger.warning("Failed to send the SSH port message to admin %d", admin_id, exc_info=True)

    def _note(self, problem: str | None) -> None:
        if problem is not None and problem != self._last_problem:
            logger.warning("SSH port: %s", problem)
        self._last_problem = problem

    async def read(self) -> Migration | None:
        try:
            raw = await asyncio.to_thread(self._path.read_text, encoding="utf-8")
        except FileNotFoundError:
            self._note(None)
            return None
        except OSError as exc:
            self._note(f"cannot read {self._path}: {exc}")
            return None
        try:
            m = parse_state(raw)
        except SshPortStateError as exc:
            self._note(f"{self._path} is not a migration state: {exc}")
            return None
        self._note(None)
        return m

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
        m = await self.read()
        if m is None:
            return
        told = await self._told()
        now = dict(told)
        if m.phase == 1 and told.get("started") != m.since:
            await self._send(render_started(m), confirm_keyboard(m))
            now["started"] = m.since
        elif m.phase == 2 and told.get("done") != m.since:
            await self._send(render_done(m), None)
            now["started"] = now["done"] = m.since
        elif m.phase == 0 and told.get("cancelled") != m.since:
            if told.get("started") == m.since:
                await self._send(render_cancelled(m), None)
            now["cancelled"] = m.since
        if now != told:
            await self._store.set_meta(META_KEY, json.dumps(now, sort_keys=True))

    async def confirm(self, admin_id: int, port: int, since: int) -> str:
        """Proof (c): the superadmin connected on the new port. Returns the helper's line."""
        m = await self.read()
        if m is None or m.phase != 1 or m.to != port or m.since != since:
            raise SshPortConfirmError(
                "Эта миграция SSH-порта уже не ждёт подтверждения.", key="ssh_port_confirm_stale"
            )
        if self._runner is None:
            raise SshPortConfirmError("Нет исполнителя для vpn-bot-ssh-port.", key="ssh_port_confirm_failed")
        result = await self._runner.run(
            self._helper,
            ["confirm", "--port", str(port), "--since", str(since), "--admin", str(admin_id)],
            timeout=CONFIRM_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            logger.warning("SSH port confirm refused (rc %s): %s", result.returncode, (result.stderr or result.stdout).strip())
            raise SshPortConfirmError(
                "vpn-bot-ssh-port не принял подтверждение.", key="ssh_port_confirm_failed"
            )
        return result.stdout.strip()


async def ssh_port_loop(monitor: SshPortMonitor, interval: int) -> None:
    """Read the state file every *interval* seconds; a failing pass is logged."""
    while True:
        try:
            await monitor.check_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("SSH port pass failed", exc_info=True)
        await asyncio.sleep(interval)
