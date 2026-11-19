"""«Довести relay до нормы» as the superadmins see it (docs/relay.md#bringing-a-relay-to-the-defaults).

scripts/install.sh writes a NEW relay ``SSH_PORT=<the port sshd listens on>`` and
``RELAY_INPUT_FILTER=off`` — on purpose, so its first deploy cannot cut the bot off —
and nothing moved them on afterwards: he2, the hub all traffic goes through, ran SSH on
22 with no input filter. :func:`services.relays.hardening_of` reads what is left from
the agent's last status; :meth:`services.relays.RelayService.harden` does it.

:class:`RelayHardeningMonitor` tells the superadmins (``ADMIN_IDS``) ONCE per pairing, in
bold — «relay X: SSH на 22, входной фильтр выключен — довести до нормы?» with «🛡 Довести»
and «Позже» — from every status the bot keeps (a listener of RelayService: the pairing's
``hello``, the health loop, a check) and when the relay's card is opened
(:meth:`RelayHardeningMonitor.observe`). «Позже» is remembered: nothing asks again until
the relay is paired anew. The way back is always there: the wizard's «🔑 SSH-порт relay»
and «🛡 Входной фильтр relay», and the line on the relay's card. What was told and
postponed lives in ``schema_meta`` (keyed by the relay id and its pairing time), so a
restart — every deploy is one — does not repeat it.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from collections.abc import Set as AbstractSet
from typing import Protocol

from aiogram import Bot
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import Relay
from services.relays import HARDEN_SSH_PORT, RelayHardening, agent_uninstalled, hardening_of, hardening_of_status
from utils.formatting import h

logger = logging.getLogger(__name__)

# schema_meta: {"<relay id>": "<paired_at>"} — told once / postponed («Позже»).
TOLD_META_KEY = "relay_hardening_told"
LATER_META_KEY = "relay_hardening_later"
# Buttons: rhard:go:<id> («Довести»: the plan), rhard:ok:<id> (the run), rhard:later:<id>.
CALLBACK_PREFIX = "rhard:"


class MetaStore(Protocol):
    async def get_meta(self, key: str) -> str | None: ...

    async def set_meta(self, key: str, value: str) -> None: ...


Sender = Callable[[str, InlineKeyboardMarkup | None], Awaitable[None]]


def what_text(hardening: RelayHardening) -> str:
    """«SSH на 22, входной фильтр выключен» — or one of the two."""
    parts = []
    if hardening.overrides:
        parts.append(t("relay_harden_what_sshd", count=len(hardening.overrides)))
    if hardening.ssh_on_22:
        parts.append(t("relay_harden_what_ssh"))
    if hardening.filter_off:
        parts.append(t("relay_harden_what_filter"))
    return ", ".join(parts)


def warning_line(relay: Relay) -> str | None:
    """The card's line while the relay is not brought to the defaults."""
    hardening = hardening_of(relay)
    if hardening is None or not hardening.needed:
        return None
    return t("relay_harden_card_line", what=what_text(hardening))


def alert_keyboard(relay_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=t("btn_relay_harden"), callback_data=f"{CALLBACK_PREFIX}go:{relay_id}")],
        [InlineKeyboardButton(text=t("btn_relay_harden_later"), callback_data=f"{CALLBACK_PREFIX}later:{relay_id}")],
    ])


def render_alert(name: str, hardening: RelayHardening) -> str:
    return t("relay_harden_alert", name=h(name), what=what_text(hardening), port=HARDEN_SSH_PORT)


def parse_callback(data: str) -> tuple[str, int] | None:
    """(verb, relay id) of a «Довести» / «Позже» button, or None."""
    if not data.startswith(CALLBACK_PREFIX):
        return None
    verb, _, raw = data[len(CALLBACK_PREFIX):].partition(":")
    if verb not in ("go", "ok", "later") or not raw.isdigit() or len(raw) > 12:
        return None
    return verb, int(raw)


class RelayHardeningMonitor:
    """Tells the superadmins once per pairing; remembers «Позже»."""

    def __init__(
        self,
        *,
        store: MetaStore,
        admin_ids: AbstractSet[int],
        bot: Bot | None = None,
        send: Sender | None = None,
    ) -> None:
        self._store = store
        self._admin_ids = admin_ids
        self.bot = bot
        self._send_override = send

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
                logger.warning("Failed to send the relay hardening message to admin %d", admin_id, exc_info=True)

    async def _meta(self, key: str) -> dict[str, str]:
        raw = await self._store.get_meta(key)
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}

    async def _remember(self, key: str, relay_id: int, mark: str) -> None:
        data = await self._meta(key)
        data[str(relay_id)] = mark
        await self._store.set_meta(key, json.dumps(data, sort_keys=True))

    @staticmethod
    def _mark(relay: Relay) -> str:
        return relay.agent.paired_at if relay.agent is not None else ""

    async def postponed(self, relay: Relay) -> bool:
        """«Позже» was pressed for this pairing of the relay."""
        return (await self._meta(LATER_META_KEY)).get(str(relay.id)) == self._mark(relay)

    async def later(self, relay: Relay) -> None:
        """«Позже»: not asked again for this pairing (told counts as done too)."""
        await self._remember(LATER_META_KEY, relay.id, self._mark(relay))
        await self._remember(TOLD_META_KEY, relay.id, self._mark(relay))

    async def _maybe_tell(self, relay: Relay, hardening: RelayHardening | None) -> bool:
        if self.bot is None and self._send_override is None:
            return False
        # A foreign sshd override has its own alert (services/relay_sshd_override.py).
        if (hardening is None or not (hardening.ssh_on_22 or hardening.filter_off) or relay.agent is None
                or agent_uninstalled(relay.agent)):
            return False
        mark = self._mark(relay)
        if (await self._meta(TOLD_META_KEY)).get(str(relay.id)) == mark or await self.postponed(relay):
            return False
        await self._send(render_alert(relay.name, hardening), alert_keyboard(relay.id))
        await self._remember(TOLD_META_KEY, relay.id, mark)
        return True

    async def relay_status(self, relay: Relay, payload: Mapping[str, object]) -> None:
        """A kept status / the pairing's hello (a listener of services/relays.py)."""
        if relay.agent is None:
            return
        await self._maybe_tell(relay, hardening_of_status(payload, relay.agent.ssh_port))

    async def observe(self, relay: Relay) -> bool:
        """The relay's card was opened: tell now, unless told / postponed already."""
        return await self._maybe_tell(relay, hardening_of(relay))
