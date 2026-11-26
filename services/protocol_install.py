"""Installing a protocol on the HOST from the bot («📦 Установить», docs/protocol-install.md).

The mirror of services/protocol_uninstall.py. The work is root's: the helper
``scripts/vpn-bot-protocol-install`` (OUT_OF_REPO_HELPERS) installs exactly what the
uninstall's manifest removes, plus what the protocol shares with the host (nginx, the
decoy site, the certificate's registry). The bot

* READS whether a protocol is on the host — the paths the helper's ``status`` probes
  (:data:`HOST_PROBES`; a test keeps the two equal), and the uninstall marker;
* CHANGES the host only through a run of the setup wizard's ``protocol`` mode
  (services/wizard.py): the helper's plan with the diff, the superadmin's confirmation and
  TOTP, apply → verify → rollback, in its own systemd unit — the run survives the restart
  of the bot its verify asks for (the new XRAY_* of .env are read at start);
* converges the firewall once a run succeeded (``vpn-bot-ufw-apply apply``, the one owner
  of the rules — the same as after an uninstall), and says so in the report.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from models.dto import WizardRun
from services.errors import InvalidOperation, ServiceError
from services.ufw import UfwApplier
from services.wizard import WizardService
from services.wizard_modes import MODES

logger = logging.getLogger(__name__)

MODE = "protocol"
# The protocols the helper installs (its PROTOCOLS == the mode's `proto` choices).
INSTALLABLE: tuple[str, ...] = MODES[MODE].params["proto"].choices
# A protocol is "installed" when ALL its probes exist, "partial" when some do
# (vpn-bot-protocol-install installed_probes — tests/test_protocol_install_helper.py).
HOST_PROBES: Mapping[str, tuple[str, ...]] = {
    "xray": ("/usr/local/bin/xray", "/etc/systemd/system/xray.service", "/usr/local/etc/xray/config.json"),
    "hysteria2": ("/usr/local/bin/hysteria", "/etc/systemd/system/hysteria-server.service", "/etc/hysteria/config.yaml"),
    "socks5": ("/usr/sbin/danted", "/etc/danted.conf"),
}
HOST_STATES = ("installed", "partial", "absent", "uninstalled", "unknown")


class _Registry(Protocol):
    def is_uninstalled(self, name: str) -> bool: ...


class _Modules(Protocol):
    async def is_enabled(self, name: str) -> bool: ...

    async def enable_protocol(self, name: str, actor_id: int) -> object: ...


class _Users(Protocol):
    async def require_superadmin(self, user_id: int) -> object: ...


class ProtocolInstallError(InvalidOperation):
    """A refused install the admin must see (``key`` is the i18n message)."""


class ProtocolInstallService:
    def __init__(
        self,
        *,
        wizard: WizardService | None,
        users: _Users,
        registry: _Registry,
        firewall: UfwApplier | None = None,
        root: Path | None = None,
        modules: _Modules | None = None,
    ) -> None:
        self.wizard = wizard
        self.users = users
        self.registry = registry
        self.firewall = firewall
        # services.protocol_modules.ProtocolModulesService: a reinstall switches the module
        # back on (the superadmin pressed «Включить» on a removed protocol to get here).
        self.modules = modules
        # None (every Settings a test builds by hand): nothing on the real host is read,
        # every state is "unknown" and no install is offered.
        self.root = root
        if wizard is not None:
            wizard.register_after_success(MODE, self.after_success)

    def host_state(self, name: str) -> str:
        if self.registry.is_uninstalled(name):
            return "uninstalled"
        probes = HOST_PROBES.get(name)
        if self.root is None or not probes:
            return "unknown"
        present = [p for p in probes if (self.root / p.lstrip("/")).exists()]
        if len(present) == len(probes):
            return "installed"
        return "partial" if present else "absent"

    def installable(self, name: str) -> bool:
        """«📦 Установить» / «♻️ Переустановить» is offered: the helper installs it and it is
        not on the host — all of it, a part (the helper puts back what is missing and keeps
        the rest), or removed by an uninstall (its marker: the same install, the marker goes
        as its last step)."""
        return name in INSTALLABLE and self.host_state(name) in ("absent", "partial", "uninstalled")

    def reinstallable(self, name: str) -> bool:
        return name in INSTALLABLE and self.host_state(name) == "uninstalled"

    def missing(self) -> frozenset[str]:
        """Every installable protocol that is not on the host — the panel offers them."""
        return frozenset(name for name in INSTALLABLE if self.installable(name))

    async def start(self, actor: int, name: str, *, chat_id: int | None, message_id: int | None) -> WizardRun:
        """A run of the ``protocol`` mode: its plan first. SUPERADMIN; TOTP is the handler's."""
        await self.users.require_superadmin(actor)
        if self.wizard is None:
            raise ServiceError("мастер не подключён", key="wizard_unavailable")
        if not self.installable(name):
            raise ProtocolInstallError("протокол уже на сервере", key="install_not_offered", params={"name": name})
        # domain "": the helper takes the name of the bot's certificate (vpn-bot-cert
        # status), so the plan shows the very name the protocol will serve.
        return await self.wizard.start(actor, MODE, {"proto": name, "domain": ""}, chat_id=chat_id, message_id=message_id)

    async def after_success(self, run: WizardRun) -> str | None:
        """A module switched off (a reinstall after an uninstall) is switched on again — that
        converges the firewall too; otherwise the firewall alone follows the module set (the
        protocol is in it again): `vpn-bot-ufw-apply apply`."""
        proto = run.params.get("proto", "?")
        refresh = getattr(self.registry, "refresh", None)
        if callable(refresh):
            refresh()  # the marker the run removed
        if self.modules is not None and run.started_by is not None and not await self.modules.is_enabled(proto):
            try:
                result = await self.modules.enable_protocol(proto, run.started_by)
            except Exception as exc:  # the report says what is left to do
                logger.warning("protocol install run %d: enabling %s failed (%s: %s)", run.id, proto,
                               type(exc).__name__, exc)
                return f"module {proto}: not switched on ({type(exc).__name__}) — switch it on in «⚙️ Модули протоколов»"
            summary = getattr(result, "summary", None)
            return f"module {proto}: switched on" + (f"; UFW: {summary}" if summary else "")
        if self.firewall is None:
            return None
        result_fw = await self.firewall.apply(f"installing {proto}")
        prefix = "UFW: " if result_fw.ok else "UFW (failed): "
        return prefix + result_fw.summary
