"""Superadmin alerts from the host invariants check (scripts/vpn-bot-host-check).

The check judges whether the host's EFFECTIVE state is what the repo says — a repo
sshd/sysctl/systemd value another file outranks, a live value nobody applied, a
shadowed unit (docs/host-state.md#effective-state). It runs from
vpn-bot-host-check.timer five minutes after every boot and then daily, and once more
at the end of every deploy; each run atomically rewrites
``/var/lib/vpn-bot-host-check/last.json``.

This module reads that file on a loop and tells the superadmins (``ADMIN_IDS``,
through the same :func:`services.relay_health.broadcast_to_admins` the relay alerts
use) when the state CHANGES — never on every pass:

* a row turns BEATEN or MISMATCH that was not so before (fatal: the repo's host
  state is not in effect);
* a LATENT appears that was not there before (right now, but one removal away from
  silently flipping);
* once, when the last BEATEN/MISMATCH is gone.

What was reported is kept in ``schema_meta`` (:meth:`db.database.Database.set_meta`),
so a bot restart — every deploy is one — does not report the same rows again.

The relay runs no bot. The bot has no channel to it either: relays are rows in the
database (:mod:`services.relay_management`) probed from outside by a TLS handshake
(:mod:`services.relay_health`), and no new channel is built for this. A relay's
verdict is in its own journal (``journalctl -u vpn-bot-host-check``, exit 1 = a
failed unit on BEATEN/MISMATCH) and in Phase 1 of every relay deploy.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aiogram import Bot

from i18n import t
from services.relay_health import broadcast_to_admins
from utils.formatting import h

logger = logging.getLogger(__name__)

# Written by scripts/vpn-bot-host-check (root, 0644).
STATE_PATH = Path("/var/lib/vpn-bot-host-check/last.json")
# schema_meta key: the rows already reported, as JSON {"fatal": [...], "latent": [...]}.
META_KEY = "host_check_alerted"
FATAL_VERDICTS = frozenset({"BEATEN", "MISMATCH"})
# Rows listed in one Telegram message; the rest is counted.
MAX_LISTED = 15
# A row's text is cut to this many characters in the message (the full row is in
# last.json and in the journal of vpn-bot-host-check.service).
MAX_TEXT = 300


class HostCheckStateError(ValueError):
    """last.json is not a state file the check writes."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One row of the check: verdict, family, key, the file it is about, the text."""

    verdict: str
    family: str
    key: str
    path: str
    text: str

    @property
    def ident(self) -> str:
        """Stable identity across runs: the text may change, the row is the same."""
        return "|".join((self.verdict, self.family, self.key, self.path))


@dataclass(frozen=True, slots=True)
class HostCheckReport:
    generated_at: str
    role: str
    findings: tuple[Finding, ...]

    def with_verdicts(self, verdicts: frozenset[str]) -> dict[str, Finding]:
        return {f.ident: f for f in self.findings if f.verdict in verdicts}


def _text_field(row: dict[str, object], name: str) -> str:
    value = row.get(name)
    if not isinstance(value, str):
        raise HostCheckStateError(f"row field {name!r} is not a string")
    return value


def parse_report(raw: str) -> HostCheckReport:
    """Parse last.json; raises :class:`HostCheckStateError` on anything else."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HostCheckStateError(f"not JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise HostCheckStateError("not a JSON object")
    generated_at = data.get("generated_at")
    role = data.get("role")
    rows = data.get("rows")
    if not isinstance(generated_at, str) or not isinstance(role, str) or not isinstance(rows, list):
        raise HostCheckStateError("generated_at, role or rows missing")
    findings: list[Finding] = []
    for row in rows:
        if not isinstance(row, dict):
            raise HostCheckStateError("a row is not an object")
        findings.append(
            Finding(
                verdict=_text_field(row, "verdict"),
                family=_text_field(row, "family"),
                key=_text_field(row, "key"),
                path=_text_field(row, "path"),
                text=_text_field(row, "text"),
            )
        )
    return HostCheckReport(generated_at=generated_at, role=role, findings=tuple(findings))


@dataclass(frozen=True, slots=True)
class Reported:
    """The rows already told to the superadmins."""

    fatal: frozenset[str]
    latent: frozenset[str]

    def dump(self) -> str:
        return json.dumps({"fatal": sorted(self.fatal), "latent": sorted(self.latent)})

    @classmethod
    def load(cls, raw: str | None) -> Reported:
        if not raw:
            return cls(frozenset(), frozenset())
        try:
            data = json.loads(raw)
            fatal = frozenset(str(x) for x in data.get("fatal", []))
            latent = frozenset(str(x) for x in data.get("latent", []))
        except (json.JSONDecodeError, AttributeError, TypeError):
            logger.warning("Host check: unreadable %s in schema_meta — starting from nothing reported", META_KEY)
            return cls(frozenset(), frozenset())
        return cls(fatal, latent)


class MetaStore(Protocol):
    async def get_meta(self, key: str) -> str | None: ...

    async def set_meta(self, key: str, value: str) -> None: ...


def _line(finding: Finding) -> str:
    text = finding.text if len(finding.text) <= MAX_TEXT else finding.text[: MAX_TEXT - 1] + "…"
    return t(
        "host_check_alert_line",
        verdict=h(finding.verdict),
        family=h(finding.family),
        setting=h(finding.key),
        text=h(text),
    )


def render_alert(report: HostCheckReport, new: list[Finding]) -> str:
    """The message for rows that just turned BEATEN/MISMATCH or LATENT."""
    lines = [_line(f) for f in new[:MAX_LISTED]]
    if len(new) > MAX_LISTED:
        lines.append(t("host_check_alert_more", count=len(new) - MAX_LISTED))
    fatal = sum(1 for f in report.findings if f.verdict in FATAL_VERDICTS)
    latent = sum(1 for f in report.findings if f.verdict == "LATENT")
    return t(
        "host_check_alert",
        role=h(report.role),
        at=h(report.generated_at),
        fatal=fatal,
        latent=latent,
        lines="\n".join(lines),
    )


def render_cleared(report: HostCheckReport) -> str:
    return t("host_check_cleared", role=h(report.role), at=h(report.generated_at))


class HostCheckMonitor:
    """Reads last.json, alerts on a change, remembers what it reported."""

    def __init__(
        self,
        *,
        store: MetaStore,
        admin_ids: frozenset[int],
        path: Path = STATE_PATH,
        bot: Bot | None = None,
        send: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._store = store
        self._admin_ids = admin_ids
        self._path = path
        self.bot = bot
        self._send_override = send
        # The last problem with the file that was logged, so it is logged once.
        self._last_problem: str | None = None

    async def _send(self, text: str) -> None:
        if self._send_override is not None:
            await self._send_override(text)
        elif self.bot is not None:
            await broadcast_to_admins(self.bot, self._admin_ids, text)

    def _note(self, problem: str | None) -> None:
        if problem is not None and problem != self._last_problem:
            logger.warning("Host check: %s", problem)
        self._last_problem = problem

    async def _read(self) -> HostCheckReport | None:
        try:
            raw = await asyncio.to_thread(self._path.read_text, encoding="utf-8")
        except FileNotFoundError:
            self._note(f"{self._path} not found — vpn-bot-host-check has not run on this host yet")
            return None
        except OSError as exc:
            self._note(f"cannot read {self._path}: {exc}")
            return None
        try:
            report = parse_report(raw)
        except HostCheckStateError as exc:
            self._note(f"{self._path} is not a host check state file: {exc}")
            return None
        self._note(None)
        return report

    async def check_once(self) -> None:
        """One pass: alert on what changed since the last report, then remember it.

        Nothing is sent and nothing is remembered while no bot is attached, so an
        early pass cannot swallow an alert.
        """
        if self.bot is None and self._send_override is None:
            return
        report = await self._read()
        if report is None:
            return
        reported = Reported.load(await self._store.get_meta(META_KEY))
        fatal = report.with_verdicts(FATAL_VERDICTS)
        latent = report.with_verdicts(frozenset({"LATENT"}))
        new = [f for ident, f in fatal.items() if ident not in reported.fatal]
        new += [f for ident, f in latent.items() if ident not in reported.latent]
        if new:
            await self._send(render_alert(report, new))
        elif reported.fatal and not fatal:
            await self._send(render_cleared(report))
        now = Reported(frozenset(fatal), frozenset(latent))
        if now != reported:
            await self._store.set_meta(META_KEY, now.dump())


async def host_check_loop(monitor: HostCheckMonitor, interval: int) -> None:
    """Read the state file every *interval* seconds; a failing pass is logged."""
    while True:
        try:
            await monitor.check_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Host check alert pass failed", exc_info=True)
        await asyncio.sleep(interval)
