"""The fallback mode's automatic switch — and its suggestion (docs/relay.md «Автоматика»).

The health loop (services/relay_health.py) already sees the RU (edge) relays from the
main server — directly, and through the hub (the hairpin, the agent called through the
hub). When the TSPU cuts the main server at the border, every edge relay looks the
same: its own ``vpn-relay-apply check`` says the upstream does not answer (exit 13/14),
or the main server reaches neither its traffic port nor its agent. This module watches
the passes (:meth:`FallbackAutoSwitch.observe`, a pass listener of the supervisor) and,
when that holds **stably**, acts:

* «Автопереключение» OFF (the default): every superadmin gets ONE message with ONE
  button «🛟 Включить режим фолбэка» — the screen's own confirmation, behind TOTP as
  always.
* ON: the bot switches by itself (:meth:`services.fallback.FallbackService._switch`
  with ``actor_user_id=None`` — the full preflight, the hub chosen by ``select_hub``,
  the seam a balancer will use) and ALWAYS tells the superadmins, with the report.

STABLY = hysteresis: every enabled edge relay with an agent is cut in
:data:`PASSES` passes in a row AND for at least :data:`MIN_SECONDS`, while the hub
itself is reachable from here (the main server works; only the path from Russia is
cut — otherwise switching would not help). One message per incident: the incident ends
only when a pass sees an edge relay reachable again. After a switch (by hand or by
this) nothing automatic happens for :data:`COOLDOWN_SECONDS`. Together: no flapping.

BACK to normal: by hand only. Once the mode is on, the RU relays forward to the hub,
so the signal that switched it on — the relays cannot reach the main server — is no
longer observable the same way (their check now probes the hub and passes); a
"recovery" read from it would be false and would send every client back into the
blocked path. A switch-off that comes a little late costs the hub's traffic; one that
comes too early costs the outage the mode exists to prevent.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.dto import Relay
from services.errors import ServiceError
from services.fallback import FAILOVER, FallbackService
from services.relay_health import ProbeResult
from services.relays import agent_uninstalled
from utils.formatting import h

logger = logging.getLogger(__name__)

PASSES = 3
MIN_SECONDS = 600.0
COOLDOWN_SECONDS = 3600.0
# `vpn-relay-apply check`: the upstream (main) does not answer on TCP / TLS.
UPSTREAM_CODES = frozenset({13, 14})

Notify = Callable[[str, InlineKeyboardMarkup | None], Awaitable[None]]


def relay_cut(probe: ProbeResult | None) -> bool:
    """This edge relay and the main server do not reach each other in this pass: its
    own check says the upstream does not answer, or the main server reaches neither
    its traffic nor its agent."""
    if probe is None:
        return False
    agent = probe.agent
    if agent is not None and not agent.ok and agent.rc in UPSTREAM_CODES:
        return True
    return not probe.tcp and agent is not None and not agent.ok and bool(agent.error_key)


def suggest_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t("btn_fb_auto_enable"), callback_data="admin:fb:on")
    ]])


class FallbackAutoSwitch:
    def __init__(
        self,
        fallback: FallbackService,
        *,
        notify: Notify | None = None,
        clock: Callable[[], float] = time.monotonic,
        passes: int = PASSES,
        min_seconds: float = MIN_SECONDS,
        cooldown_seconds: float = COOLDOWN_SECONDS,
    ) -> None:
        self.fallback = fallback
        self.notify = notify
        self._clock = clock
        self._passes = passes
        self._min_seconds = min_seconds
        self._cooldown = cooldown_seconds
        self._streak = 0
        self._since: float | None = None
        self._handled = False
        self._mode_was_on: bool | None = None
        self._switched_at: float | None = None

    def _reset(self) -> None:
        self._streak = 0
        self._since = None
        self._handled = False

    async def observe(self, relays: Sequence[Relay], last: Mapping[int, ProbeResult]) -> None:
        """One health pass (a pass listener of the supervisor)."""
        now = self._clock()
        mode_on = self.fallback.mode_on
        if self._mode_was_on is not None and mode_on != self._mode_was_on:
            self._switched_at = now  # switched since the last pass (by hand, or by us)
        self._mode_was_on = mode_on
        if mode_on:
            self._reset()
            return
        edges = [r for r in relays if r.enabled and not r.is_hub and r.agent is not None
                 and not agent_uninstalled(r.agent)]
        hubs = [r for r in relays if r.enabled and r.is_hub]
        hub_probe = last.get(hubs[0].id) if hubs else None
        cut = bool(edges) and all(relay_cut(last.get(r.id)) for r in edges)
        if not cut or hub_probe is None or not hub_probe.tcp:
            self._reset()
            return
        self._streak += 1
        if self._since is None:
            self._since = now
        if self._handled or self._streak < self._passes or now - self._since < self._min_seconds:
            return
        if self._switched_at is not None and now - self._switched_at < self._cooldown:
            return
        if not await self.fallback.configured():
            return
        self._handled = True
        names = ", ".join(r.name for r in edges)
        minutes = int((now - self._since) // 60)
        if not await self.fallback.auto_switch():
            await self._tell(t("fb_auto_suggest", relays=h(names), passes=self._streak, minutes=minutes),
                             suggest_keyboard())
            return
        try:
            report = await self.fallback._switch(FAILOVER, None)
        except ServiceError as exc:
            await self._tell(t("fb_auto_failed", relays=h(names), error=h(str(exc))), suggest_keyboard())
            return
        self._switched_at = now
        self._mode_was_on = self.fallback.mode_on
        if report.started:
            key = "fb_auto_switched" if report.complete else "fb_auto_switched_partial"
            await self._tell(t(key, relays=h(names), passes=self._streak, minutes=minutes,
                               failed=h(", ".join(report.failed_names))), None)
        else:
            await self._tell(t("fb_auto_blocked", relays=h(names)), suggest_keyboard())

    async def _tell(self, text: str, markup: InlineKeyboardMarkup | None) -> None:
        if self.notify is None:
            logger.warning("Fallback auto: %s (no one to tell)", text)
            return
        try:
            await self.notify(text, markup)
        except Exception as exc:
            logger.warning("Fallback auto: the message failed: %s: %s", type(exc).__name__, exc)
