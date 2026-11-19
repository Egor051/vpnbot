"""A foreign sshd override on a relay, as the superadmins see it (docs/relay.md «Чужой sshd-override»).

WHAT. A hoster's panel that «resets the root password» drops a file into
/etc/ssh/sshd_config.d (he2, 2026-11-18: ``00-password-login.conf`` with
PasswordAuthentication yes / PermitRootLogin yes). Sorted before the repo's
``00-vpnrelay-keyonly.conf`` it wins — sshd takes the first value — and the relay takes
passwords again; vpn-bot-host-check reports it BEATEN and every deploy of the relay stops
in Phase 1 (rightly). The agent (5+) moves such a file to /root/attic on request
(``sshd-override-off``, :meth:`services.relays.RelayService.remove_sshd_override`).

THIS MODULE tells the superadmins (``ADMIN_IDS``) when a relay has one, with the button
that removes it, from every status the bot keeps (a listener of RelayService):

* the status names it (``sshd_overrides`` — the host check's last.json: its daily timer,
  the last deploy, the last ``sshd-check``);
* or only the auth keys drift (``sshd_drift`` — ``sshd -T`` against the repo, cheap, every
  status) while last.json does not name the file yet: the monitor asks ``sshd-check`` (a
  fresh host check) at most once an hour per relay.

Told ONCE per file and its mtime (``schema_meta``, so a restart does not repeat it): the
same file again says nothing, a file that COMES BACK — a repeated «password reset» in the
panel — is a new mtime and is told again. A second reset must never silently re-open
password login on the hub.

THE BUTTON carries a short hash of the path (callback data is 64 bytes); the paths the
bot learned for a relay — from a status, an ``sshd-check`` or the findings of a failed
update — are kept in ``schema_meta`` too (:meth:`SshdOverrideMonitor.remember`), so the
button still resolves after a restart.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from collections.abc import Set as AbstractSet
from typing import Protocol

from aiogram import Bot
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import Relay
from services.relays import (
    AGENT_SSHD_OVERRIDE,
    SshdCheck,
    SshdOverride,
    agent_older_than,
    agent_uninstalled,
    sshd_drift_of,
    sshd_overrides_of,
)
from utils.formatting import code, h

logger = logging.getLogger(__name__)

# schema_meta: {"<relay id>|<path>": "<mtime>"} — told; {"<relay id>": [paths]} — known.
TOLD_META_KEY = "relay_sshd_override_told"
KNOWN_META_KEY = "relay_sshd_override_paths"
# Buttons: rsov:go:<relay id>:<hash> (the plan), rsov:ok:<relay id>:<hash> (the run).
CALLBACK_PREFIX = "rsov:"
# A drift with no file named yet: a fresh host check at most this often per relay.
RECHECK_SECONDS = 3600.0
MAX_KNOWN = 8


class MetaStore(Protocol):
    async def get_meta(self, key: str) -> str | None: ...

    async def set_meta(self, key: str, value: str) -> None: ...


Sender = Callable[[str, InlineKeyboardMarkup | None], Awaitable[None]]
Checker = Callable[[int], Awaitable[SshdCheck]]


def path_tag(path: str) -> str:
    """The short, stable tag of a path in callback data."""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()[:10]


def parse_callback(data: str) -> tuple[str, int, str] | None:
    """(verb, relay id, path tag) of a button, or None."""
    if not data.startswith(CALLBACK_PREFIX):
        return None
    parts = data[len(CALLBACK_PREFIX):].split(":")
    if len(parts) != 3 or parts[0] not in ("go", "ok") or not parts[1].isdigit() or len(parts[1]) > 12:
        return None
    if len(parts[2]) != 10 or any(c not in "0123456789abcdef" for c in parts[2]):
        return None
    return parts[0], int(parts[1]), parts[2]


def remove_button(relay_id: int, path: str) -> list[InlineKeyboardButton]:
    name = path.rsplit("/", 1)[-1]
    return [InlineKeyboardButton(text=t("btn_relay_sshd_override", name=name[:40]),
                                 callback_data=f"{CALLBACK_PREFIX}go:{relay_id}:{path_tag(path)}")]


def keys_text(keys: Iterable[str]) -> str:
    return ", ".join(code(key) for key in keys)


def render_alert(relay: Relay, override: SshdOverride) -> str:
    lines = [t("relay_sshd_override_alert", name=h(relay.name), path=code(override.path), keys=keys_text(override.keys))]
    lines += [f"• {h(text)}" for text in override.texts[:4]]
    lines.append(t("relay_sshd_override_alert_hint"))
    return "\n".join(lines)


def alert_keyboard(relay_id: int, path: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        remove_button(relay_id, path),
        [InlineKeyboardButton(text=t("btn_relay_harden_to_card"), callback_data=f"admin:relay:{relay_id}")],
    ])


class SshdOverrideMonitor:
    """Tells the superadmins about a foreign sshd override, once per file and mtime."""

    def __init__(
        self,
        *,
        store: MetaStore,
        admin_ids: AbstractSet[int],
        bot: Bot | None = None,
        send: Sender | None = None,
        check: Checker | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._admin_ids = admin_ids
        self.bot = bot
        self._send_override = send
        self.check = check
        self._clock = clock
        self._rechecked: dict[int, float] = {}

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
                logger.warning("Failed to send the sshd override alert to admin %d", admin_id, exc_info=True)

    async def _meta(self, key: str) -> dict[str, object]:
        raw = await self._store.get_meta(key)
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    async def known_paths(self, relay_id: int) -> list[str]:
        """The override paths the bot learned for this relay (status, check, update)."""
        value = (await self._meta(KNOWN_META_KEY)).get(str(relay_id))
        return [p for p in value if isinstance(p, str)] if isinstance(value, list) else []

    async def remember(self, relay_id: int, paths: Iterable[str]) -> None:
        """Keep the paths a button may name (newest last, at most MAX_KNOWN)."""
        new = [p for p in paths if p]
        if not new:
            return
        data = await self._meta(KNOWN_META_KEY)
        current = await self.known_paths(relay_id)
        merged = [p for p in current if p not in new] + list(dict.fromkeys(new))
        data[str(relay_id)] = merged[-MAX_KNOWN:]
        await self._store.set_meta(KNOWN_META_KEY, json.dumps(data, sort_keys=True))

    async def resolve(self, relay: Relay, tag: str) -> str | None:
        """The path a button's tag names: one the bot learned, or one the relay's last
        status names."""
        status: Mapping[str, object] = (relay.agent.last_status or {}) if relay.agent is not None else {}
        candidates = [*await self.known_paths(relay.id), *(o.path for o in sshd_overrides_of(status.get("sshd_overrides")))]
        for path in candidates:
            if path_tag(path) == tag:
                return path
        return None

    async def _tell(self, relay: Relay, overrides: Iterable[SshdOverride]) -> int:
        told = await self._meta(TOLD_META_KEY)
        count = 0
        fresh = list(overrides)
        await self.remember(relay.id, (o.path for o in fresh))
        for override in fresh:
            mark = f"{relay.id}|{override.path}"
            stamp = str(override.mtime if override.mtime is not None else "?")
            if told.get(mark) == stamp:
                continue
            await self._send(render_alert(relay, override), alert_keyboard(relay.id, override.path))
            told[mark] = stamp
            count += 1
        if count:
            await self._store.set_meta(TOLD_META_KEY, json.dumps(told, sort_keys=True))
        return count

    async def relay_status(self, relay: Relay, payload: Mapping[str, object]) -> None:
        """A kept status (a listener of services/relays.py)."""
        if relay.agent is None or agent_uninstalled(relay.agent):
            return
        if self.bot is None and self._send_override is None:
            return
        overrides = sshd_overrides_of(payload.get("sshd_overrides"))
        if overrides:
            await self._tell(relay, overrides)
            return
        drift = sshd_drift_of(payload.get("sshd_drift"))
        if not drift or self.check is None or agent_older_than(relay.agent, AGENT_SSHD_OVERRIDE):
            return
        now = self._clock()
        last = self._rechecked.get(relay.id)
        if last is not None and now - last < RECHECK_SECONDS:
            return
        self._rechecked[relay.id] = now
        try:
            result = await self.check(relay.id)
        except Exception as exc:
            logger.info("Relay %s: sshd-check after a drift failed: %s: %s", relay.name, type(exc).__name__, exc)
            return
        await self._tell(relay, result.overrides)
