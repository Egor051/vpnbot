"""«🔐 Сертификат и DNS» — the bot's TLS certificate seen from the bot (docs/certificate.md).

The certificate itself is root's: /usr/local/sbin/vpn-bot-cert (the registry of its
readers, deploy with a rollback per group, acme.sh). The bot

* READS its status: ``vpn-bot-cert status --json`` — through sudo in the helper model
  (the exact grant ``/usr/local/sbin/vpn-bot-cert status --json``), directly as root
  otherwise; nothing else of the helper is granted to the bot;
* CHANGES it only through a run of the setup wizard's ``cert`` mode (services/wizard.py):
  a plan with the diff, the superadmin's confirmation and TOTP, apply → verify →
  rollback, in its own systemd unit. This service works out the run's parameters: the
  names (the certificate's SAN today, else HYSTERIA2_SNI), and the Cloudflare zone the
  bot's ONE token was checked against (services/dns.py) — the zone's NAME: its id
  would be masked as a secret in the run's record, and root asks it with the token.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adapters.privileged_helpers import PrivilegedHelperRunner
from config.settings import Settings
from models.dto import WizardRun
from services.dns import DnsService
from services.errors import InvalidOperation, ServiceError
from services.relay_pairing import valid_dns_name
from services.users import UserService
from services.wizard import WizardService
from services.wizard_modes import MAX_NAMES

logger = logging.getLogger(__name__)

CERT_HELPER = Path("/usr/local/sbin/vpn-bot-cert")
STATUS_TIMEOUT = 90.0
ACTIONS = ("issue", "renew", "adopt", "deploy")


@dataclass(frozen=True, slots=True)
class CertStatus:
    """``vpn-bot-cert status --json``, as the screen reads it (the raw report kept)."""

    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def domain_name(self) -> str | None:
        name = self.raw.get("domain") or self.raw.get("candidate")
        return str(name) if name else None

    @property
    def adopted(self) -> bool:
        return bool(self.raw.get("adopted"))

    @property
    def candidate(self) -> str | None:
        value = self.raw.get("candidate")
        return str(value) if value else None

    @property
    def candidates(self) -> list[str]:
        """Every acme.sh domain that could be the bot's (several: the superadmin picks one)."""
        value = self.raw.get("candidates")
        return [str(v) for v in value] if isinstance(value, list) else ([self.candidate] if self.candidate else [])

    @property
    def domain(self) -> dict[str, Any] | None:
        name = self.domain_name
        return next((d for d in self.raw.get("domains", []) if d.get("name") == name), None) if name else None

    @property
    def consumers(self) -> list[dict[str, Any]]:
        return [c for c in self.raw.get("consumers", []) if isinstance(c, dict)]

    @property
    def problems(self) -> list[dict[str, Any]]:
        return [p for p in self.raw.get("problems", []) if isinstance(p, dict)]

    @property
    def acme(self) -> dict[str, Any]:
        value = self.raw.get("acme")
        return value if isinstance(value, dict) else {}

    @property
    def token(self) -> dict[str, Any]:
        value = self.raw.get("token")
        return value if isinstance(value, dict) else {}

    @property
    def out_of_sync(self) -> bool:
        return any(c.get("installed") and (c.get("in_sync") is False or c.get("took_current") is False)
                   for c in self.consumers)

    @property
    def names(self) -> list[str]:
        dom = self.domain
        if dom is None:
            return []
        return [str(n) for n in dom.get("names") or []]


class CertService:
    def __init__(
        self,
        *,
        runner: PrivilegedHelperRunner | None,
        wizard: WizardService | None,
        dns: DnsService,
        users: UserService,
        settings: Settings,
        helper: Path = CERT_HELPER,
    ) -> None:
        self.runner = runner
        self.wizard = wizard
        self.dns = dns
        self.users = users
        self.settings = settings
        self.helper = helper
        # The names a superadmin typed for «Выпустить» (process memory: a restart, or
        # «⬅️ Назад», falls back to the defaults).
        self._names: dict[int, list[str]] = {}

    def installed(self) -> bool:
        return self.helper.is_file()

    async def status(self, actor_user_id: int) -> CertStatus:
        await self.users.require_superadmin(actor_user_id)
        if self.runner is None or not self.installed():
            raise ServiceError("vpn-bot-cert не установлен", key="cert_err_not_installed", params={"path": str(self.helper)})
        try:
            result = await self.runner.run(self.helper, ["status", "--json"], timeout=STATUS_TIMEOUT, max_output_chars=200_000)
        except Exception as exc:
            logger.warning("vpn-bot-cert status could not run: %s", type(exc).__name__)
            raise ServiceError("vpn-bot-cert не запустился", key="cert_err_status", params={"error": type(exc).__name__}) from None
        raw: dict[str, Any] | None = None
        for line in (result.stdout or "").splitlines():
            if line.startswith("{"):
                try:
                    parsed = json.loads(line)
                except ValueError:
                    continue
                if isinstance(parsed, dict):
                    raw = parsed
        if result.returncode != 0 or raw is None or "consumers" not in raw:
            tail = ((result.stderr or "") + (result.stdout or "")).strip().splitlines()
            raise ServiceError("vpn-bot-cert status", key="cert_err_status",
                               params={"error": (tail[-1] if tail else f"exit {result.returncode}")[:300]})
        return CertStatus(raw)

    # ── the names of «Выпустить» ──────────────────────────────────────────────

    def default_names(self, status: CertStatus | None) -> list[str]:
        if status is not None and status.names:
            return status.names
        sni = (self.settings.hysteria2_sni or "").strip().lower()
        return [sni] if valid_dns_name(sni) else []

    def chosen_names(self, actor_user_id: int, status: CertStatus | None) -> list[str]:
        return list(self._names.get(actor_user_id) or self.default_names(status))

    def set_names(self, actor_user_id: int, raw: str) -> list[str]:
        names: list[str] = []
        for part in (raw or "").replace(";", ",").replace(" ", ",").split(","):
            name = part.strip().lower().rstrip(".")
            if not name:
                continue
            bare = name[2:] if name.startswith("*.") else name
            if not valid_dns_name(bare):
                raise InvalidOperation("не DNS-имя", key="cert_err_bad_name", params={"value": name[:80]})
            if name not in names:
                names.append(name)
        if not names or len(names) > MAX_NAMES:
            raise InvalidOperation("1..10 имён", key="cert_err_names_count", params={"max": MAX_NAMES})
        self._names[actor_user_id] = names
        return names

    def forget_names(self, actor_user_id: int) -> None:
        self._names.pop(actor_user_id, None)

    def token_check_name(self, status: CertStatus | None) -> str:
        """The name whose zone a new token must manage: the certificate's, else HYSTERIA2_SNI."""
        names = self.default_names(status)
        if not names:
            raise InvalidOperation("нет имени для проверки зоны", key="cert_err_no_name")
        return names[0].removeprefix("*.")

    # ── the runs ──────────────────────────────────────────────────────────────

    async def start(
        self,
        actor_user_id: int,
        action: str,
        *,
        names: Sequence[str] = (),
        chat_id: int | None = None,
        message_id: int | None = None,
    ) -> WizardRun:
        """A run of the wizard's ``cert`` mode (its plan first). The caller holds the
        wizard's ``exclusive()`` and has checked the superadmin and the TOTP."""
        await self.users.require_superadmin(actor_user_id)
        if action not in ACTIONS:
            raise ValueError(action)
        if self.wizard is None:
            raise ServiceError("мастер не подключён", key="wizard_unavailable")
        params: dict[str, object] = {"action": action}
        if action == "issue":
            chosen = [n.lower() for n in names]
            if not chosen:
                raise InvalidOperation("нет имён", key="cert_err_no_name")
            zone = await self.dns.zone(chosen[0].removeprefix("*."))
            outside = [n for n in chosen if n.removeprefix("*.") != zone.name and not n.endswith("." + zone.name)]
            if outside:
                raise InvalidOperation("имена из разных зон", key="cert_err_other_zone",
                                       params={"zone": zone.name, "names": ", ".join(outside)})
            params.update(names=",".join(chosen), zone=zone.name)
        elif action == "renew" and self.dns.token_set() and names:
            # vpn-bot-cert hands acme.sh ONE zone (CF_Zone_ID): every name must be in it —
            # refused here, before a plan is shown, not after the confirmation.
            chosen = [n.lower() for n in names]
            zone = await self.dns.zone(chosen[0].removeprefix("*."))
            outside = [n for n in chosen if n.removeprefix("*.") != zone.name and not n.endswith("." + zone.name)]
            if outside:
                raise InvalidOperation("имена из разных зон", key="cert_err_other_zone",
                                       params={"zone": zone.name, "names": ", ".join(outside)})
            params["zone"] = zone.name
        elif action == "adopt" and names:
            # One of several domains that could be the bot's: the screen names it.
            domain = names[0].lower()
            if not valid_dns_name(domain.removeprefix("*.")):
                raise InvalidOperation("не DNS-имя", key="cert_err_bad_name", params={"value": domain[:80]})
            params["names"] = domain
        run = await self.wizard.start(actor_user_id, "cert", params, chat_id=chat_id, message_id=message_id)
        if action == "issue":
            self.forget_names(actor_user_id)
        return run
