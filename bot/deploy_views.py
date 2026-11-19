"""How a deploy's cause reads in the bot — the relay's «Обновить агент» and the main
server's «Обновить бота» (setup wizard) show the same block (services/deploy_result.py).

A failure: the cause in plain words (one of deploy.sh's reasons), the step it stopped
in («шаг неизвестен» when neither the marker nor the text tells it), the host check's
findings that stopped it (the key, file:line, what beat what), the lines that tell it
(as received, escaped, in <pre>) and where the full log is on that host. A success
with findings: one line per ``[deploy:warn]``.
"""

from __future__ import annotations

from collections.abc import Sequence

from i18n import t
from services.deploy_result import DEPLOY_STEPS, DeployFailure, DeployWarning, HostFinding
from utils.formatting import code, h


def step_title(step: str) -> str:
    return t(f"deploy_step_{step}") if step in DEPLOY_STEPS else step


def finding_line(finding: HostFinding) -> str:
    """One finding: the key, the file and line, what beat what — or the check's text."""
    beaten = finding.beaten
    if beaten is not None:
        return t(
            "deploy_finding_beaten", setting=code(finding.key), file=code(beaten["file"]), line=h(beaten["line"]),
            value=code(beaten["value"] or '""'), repo_value=code(beaten["repo_value"] or '""'),
            repo_file=code(beaten["repo_file"]),
        )
    where = f" [{code(finding.path)}]" if finding.path and finding.path not in finding.text else ""
    return t("deploy_finding_other", verdict=h(finding.verdict), family=h(finding.family), setting=code(finding.key),
             text=h(finding.text)) + where


def findings_text(findings: Sequence[HostFinding]) -> str:
    return "\n".join([t("deploy_fail_findings"), *(finding_line(f) for f in findings)])


def deploy_failure_text(failure: DeployFailure) -> str:
    lines = [t("deploy_fail_cause", cause=t(f"deploy_reason_{failure.reason}"))]
    if failure.step:
        lines.append(t("deploy_fail_step", step=h(step_title(failure.step))))
    else:
        # Neither deploy.sh's marker nor the result's text tells it: never a guess.
        lines.append(t("deploy_fail_step_unknown"))
    if failure.findings:
        # What the host check found — the key, file:line, what beat what — not only
        # «2 fatal finding(s)».
        lines.append(findings_text(failure.findings))
    if failure.excerpt:
        lines.append(t("deploy_fail_lines"))
        lines.append("<pre>" + h("\n".join(failure.excerpt)) + "</pre>")
    elif failure.message:
        # The findings an older agent carried inside its message are listed above.
        message = failure.message.split(". Fatal: ", 1)[0] if failure.findings else failure.message
        lines.append("<pre>" + h(message) + "</pre>")
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
