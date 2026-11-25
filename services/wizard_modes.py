"""The setup wizard's modes as the bot sees them (docs/wizard.md).

Each mode is a FIXED set of root helpers in scripts/wizard/ (installed to
/usr/local/sbin, OUT_OF_REPO_HELPERS). This table is what the bot offers and how it
types the parameters BEFORE anything is launched; the launcher checks them again
against its own table (scripts/wizard/vpn-bot-wizard-lib, MODES) —
tests/test_wizard_helpers.py fails when the two disagree.

``dangerous`` modes ask the superadmin's TOTP (services/totp.py) before they start
and again before a plan is applied, unless the user is elevated.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from services.errors import InvalidOperation


class WizardParamError(InvalidOperation):
    """A parameter that does not fit its declared type."""


# The text kinds of scripts/wizard/vpn-bot-wizard-lib, typed identically: a comma list of
# lowercase DNS names (at most MAX_NAMES, distinct) and a Cloudflare zone's NAME (not its id:
# 32 hex look like a secret to utils/redact and would be masked in the run's params); "" = not given.
_DNS_NAME_RE = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_ZONE_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
MAX_NAMES = 10


@dataclass(frozen=True, slots=True)
class ParamSpec:
    kind: str  # "int" | "bool" | "enum" | "names" | "zone"
    default: str
    minimum: int = 0
    maximum: int = 0
    choices: tuple[str, ...] = ()

    def coerce(self, name: str, value: object) -> str:
        if self.kind == "int":
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise WizardParamError(f"{name}: не число", key="wizard_param_invalid", params={"name": name})
            text = str(value).strip()
            if not re.fullmatch(r"-?[0-9]{1,9}", text) or not self.minimum <= int(text) <= self.maximum:
                raise WizardParamError(f"{name}: вне диапазона", key="wizard_param_invalid", params={"name": name})
            return str(int(text))
        if self.kind == "bool":
            if isinstance(value, bool):
                return "1" if value else "0"
            if value in ("0", "1", 0, 1):
                return str(int(value))
            raise WizardParamError(f"{name}: не 0/1", key="wizard_param_invalid", params={"name": name})
        if self.kind == "enum":
            if value not in self.choices:
                raise WizardParamError(f"{name}: не из списка", key="wizard_param_invalid", params={"name": name})
            return str(value)
        if self.kind == "names":
            raw = value if isinstance(value, str) else ",".join(value) if isinstance(value, (list, tuple)) else None
            names = [n.strip() for n in raw.split(",") if n.strip()] if raw is not None else None
            if (names is None or len(names) > MAX_NAMES or len(set(names)) != len(names)
                    or not all(_DNS_NAME_RE.match(n) for n in names)):
                raise WizardParamError(f"{name}: не DNS-имена", key="wizard_param_invalid", params={"name": name})
            return ",".join(names)
        if self.kind == "zone":
            if not isinstance(value, str) or (value and not _ZONE_RE.match(value)):
                raise WizardParamError(f"{name}: не имя зоны", key="wizard_param_invalid", params={"name": name})
            return value
        raise WizardParamError(f"{name}: неизвестный тип", key="wizard_param_invalid", params={"name": name})


@dataclass(frozen=True, slots=True)
class WizardMode:
    key: str
    helper: str
    read_only: bool
    dangerous: bool
    # A plan the superadmin confirms before anything changes. A read-only mode has
    # nothing to confirm: its execute phase starts right away.
    needs_confirmation: bool
    params: Mapping[str, ParamSpec] = field(default_factory=dict)
    # A button of its own in «🧙 Мастер настройки». False: started from its own screen
    # with the parameters that screen works out («🔐 Сертификат и DNS»).
    menu: bool = True

    def validate(self, raw: Mapping[str, object]) -> dict[str, str]:
        unknown = set(raw) - set(self.params)
        if unknown:
            name = sorted(unknown)[0]
            raise WizardParamError(f"нет параметра {name}", key="wizard_param_invalid", params={"name": name})
        out: dict[str, str] = {}
        for name, spec in self.params.items():
            out[name] = spec.coerce(name, raw[name]) if name in raw else spec.default
        return out


MODES: dict[str, WizardMode] = {
    "selfcheck": WizardMode(
        key="selfcheck",
        helper="vpn-bot-wizard-selfcheck",
        read_only=True,
        dangerous=False,
        needs_confirmation=False,
    ),
    "dump": WizardMode(
        key="dump",
        helper="vpn-bot-wizard-dump",
        read_only=True,
        # The dump carries the host's topology off the box (redacted, but still).
        dangerous=True,
        needs_confirmation=False,
        params={"lines": ParamSpec("int", "200", minimum=20, maximum=1000)},
    ),
    "update": WizardMode(
        key="update",
        helper="vpn-bot-wizard-update",
        read_only=False,
        dangerous=True,
        needs_confirmation=True,
        params={"force": ParamSpec("bool", "0")},
    ),
    # «🔐 Сертификат и DNS» (docs/certificate.md): issue / renew / adopt / deploy through the
    # root helper vpn-bot-cert — a plan with the diff first, TOTP, then apply → verify.
    "cert": WizardMode(
        key="cert",
        helper="vpn-bot-wizard-cert",
        read_only=False,
        dangerous=True,
        needs_confirmation=True,
        params={
            "action": ParamSpec("enum", "deploy", choices=("issue", "renew", "adopt", "deploy")),
            "names": ParamSpec("names", ""),
            "zone": ParamSpec("zone", ""),
        },
        menu=False,
    ),
    # «📦 Установить протокол» (docs/protocol-install.md): the root helper
    # vpn-bot-protocol-install of one protocol — a plan with the diff first, TOTP, then
    # apply → verify (→ rollback). Started from «Модули протоколов», not from the menu.
    "protocol": WizardMode(
        key="protocol",
        helper="vpn-bot-wizard-protocol",
        read_only=False,
        dangerous=True,
        needs_confirmation=True,
        params={
            "proto": ParamSpec("enum", "xray", choices=("xray",)),
            "domain": ParamSpec("names", ""),
        },
        menu=False,
    ),
}


def get_mode(key: str) -> WizardMode:
    mode = MODES.get(key)
    if mode is None:
        raise WizardParamError(f"нет режима {key}", key="wizard_unknown_mode")
    return mode
