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


@dataclass(frozen=True, slots=True)
class ParamSpec:
    kind: str  # "int" | "bool" | "enum"
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
}


def get_mode(key: str) -> WizardMode:
    mode = MODES.get(key)
    if mode is None:
        raise WizardParamError(f"нет режима {key}", key="wizard_unknown_mode")
    return mode
