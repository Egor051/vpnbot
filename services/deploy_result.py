"""Why a deploy ended as it did — the bot's side of deploy.sh's result line.

scripts/deploy.sh prints ``[deploy:result failed step=<step> reason=<class>]`` when it
stops, and ``[deploy:warn <code>] <text>`` for a finding of a deploy that succeeded
(docs/deployment.md «Step and result markers»). The two callers that run a deploy for
the bot read them with ONE classifier (``deploy_verdict``, carried verbatim by
scripts/vpn-relay-agent and scripts/wizard/vpn-bot-wizard-update) and hand the bot its
fields: ``reason``, ``step``, ``excerpt`` (the lines that tell the cause), ``log`` (the
deploy log on that host) and ``warnings``.

This module only VALIDATES what arrives — it comes from another host (a relay's agent)
or a root helper's status file — into :class:`DeployFailure` /
:class:`DeployWarning`, which the bot renders (bot/deploy_views.py). Anything unknown
falls back to a generic reason; nothing is ever trusted as markup.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

# deploy.sh's DEPLOY_FAIL_REASONS plus the waiter's "timeout" — the same tuple as
# DEPLOY_REASONS of the DEPLOY VERDICT block (tests/test_deploy_verdict.py pins all three).
DEPLOY_REASONS: tuple[str, ...] = (
    "busy", "fetch", "preflight", "no_venv", "tests", "checks", "upstream", "rolled_back", "failed", "timeout",
)
# deploy.sh's DEPLOY_STEPS, in order.
DEPLOY_STEPS: tuple[str, ...] = ("preflight", "fetch", "tests", "checks", "backup", "install", "restart", "verify")
MAX_EXCERPT_LINES = 8
MAX_LINE_CHARS = 300
MAX_MESSAGE_CHARS = 600
_LOG_PATH = re.compile(r"/[A-Za-z0-9._/-]{1,200}")
_WARN_CODE = re.compile(r"[a-z_]{1,48}")


@dataclass(frozen=True, slots=True)
class DeployFailure:
    reason: str
    step: str = ""
    excerpt: tuple[str, ...] = ()
    log: str = ""
    message: str = ""


@dataclass(frozen=True, slots=True)
class DeployWarning:
    code: str
    text: str


def _lines(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        return ()
    out = [str(line).strip()[:MAX_LINE_CHARS] for line in raw if isinstance(line, str | int) and str(line).strip()]
    return tuple(out[-MAX_EXCERPT_LINES:])


def deploy_failure_from(
    data: Mapping[str, object] | None, *, message: str = "", default: str = "failed"
) -> DeployFailure:
    """A failure from a caller's fields (``reason``, ``step``/``fail_step``, ``excerpt``,
    ``log``/``deploy_log``); a reason it does not know becomes *default*."""
    data = data or {}
    reason = data.get("reason")
    step = data.get("step") or data.get("fail_step")
    log = data.get("log") or data.get("deploy_log")
    return DeployFailure(
        reason=reason if isinstance(reason, str) and reason in DEPLOY_REASONS else default,
        step=step if isinstance(step, str) and step in DEPLOY_STEPS else "",
        excerpt=_lines(data.get("excerpt")),
        log=log if isinstance(log, str) and _LOG_PATH.fullmatch(log) else "",
        message=(message or str(data.get("message") or ""))[:MAX_MESSAGE_CHARS],
    )


def deploy_warnings_from(raw: object) -> tuple[DeployWarning, ...]:
    """``[{"code": ..., "text": ...}, ...]`` → validated warnings (junk dropped)."""
    if not isinstance(raw, list):
        return ()
    found: list[DeployWarning] = []
    for item in raw[:8]:
        if not isinstance(item, Mapping):
            continue
        code, text = item.get("code"), item.get("text")
        if isinstance(code, str) and _WARN_CODE.fullmatch(code):
            found.append(DeployWarning(code=code, text=str(text or "")[:MAX_LINE_CHARS]))
    return tuple(found)
