"""How a deploy's cause reads in the bot — the relay's «Обновить агент» and the main
server's «Обновить бота» (setup wizard) show the same block (services/deploy_result.py).

A failure: the cause in plain words (one of deploy.sh's reasons), the step it stopped
in («шаг неизвестен» when neither the marker nor the text tells it), the lines that tell it (as received, escaped, in <pre>) and where the full log is
on that host. A success with findings: one line per ``[deploy:warn]``.
"""

from __future__ import annotations

from collections.abc import Sequence

from i18n import t
from services.deploy_result import DEPLOY_STEPS, DeployFailure, DeployWarning
from utils.formatting import code, h


def step_title(step: str) -> str:
    return t(f"deploy_step_{step}") if step in DEPLOY_STEPS else step


def deploy_failure_text(failure: DeployFailure) -> str:
    lines = [t("deploy_fail_cause", cause=t(f"deploy_reason_{failure.reason}"))]
    if failure.step:
        lines.append(t("deploy_fail_step", step=h(step_title(failure.step))))
    else:
        # Neither deploy.sh's marker nor the result's text tells it: never a guess.
        lines.append(t("deploy_fail_step_unknown"))
    if failure.excerpt:
        lines.append(t("deploy_fail_lines"))
        lines.append("<pre>" + h("\n".join(failure.excerpt)) + "</pre>")
    elif failure.message:
        lines.append("<pre>" + h(failure.message) + "</pre>")
    if failure.log:
        lines.append(t("deploy_fail_log", path=code(failure.log)))
    return "\n".join(lines)


def deploy_warnings_text(warnings: Sequence[DeployWarning]) -> str:
    """One line per finding; a code this bot does not know shows its text."""
    out: list[str] = []
    for warning in warnings:
        key = f"deploy_warn_{warning.code}"
        known = t(key)
        out.append("⚠️ " + (known if known != key else h(warning.code)) + (f": {h(warning.text)}" if warning.text else ""))
    return "\n".join(out)
