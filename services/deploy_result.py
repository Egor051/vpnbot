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

THE STEP of a failure. A caller older than the markers (a relay agent before v3.2.1:
only its one-line ``message``, e.g. «the deploy of v3.2.1 stopped before any change
(exit 1): Phase 1 gate: pytest failed on tag v3.2.1 …») hands no ``step``. Then the
step is read, in this order: from a ``[deploy:result failed step=… reason=…]`` line
among the texts; else from the reason — the caller's, or the one the text tells
(:data:`TEXT_REASONS`) — through :data:`REASON_STEPS`, the inverse of deploy.sh's
``deploy_fail_reason`` (tests/test_deploy_verdict.py runs that function for every step
against it); else it stays "" and the bot says «шаг неизвестен». Never a guess onto
the first step.
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
# reason → the step deploy.sh stops in with it: deploy_fail_reason maps preflight/fetch →
# preflight, tests → tests, checks → checks, an armed Phase 2 → rolled_back; the explicit
# reasons are set in the step named here (busy: the lock, before `step fetch`; no_venv:
# the test venv of the tests step; upstream: the relay's verify after the restart). A
# rollback without its step is read as the verify after the restart, where a relay's
# rollbacks happen. "failed" and "timeout" say nothing about the step.
REASON_STEPS: dict[str, str] = {
    "busy": "preflight", "preflight": "preflight", "fetch": "fetch", "no_venv": "tests", "tests": "tests",
    "checks": "checks", "upstream": "verify", "rolled_back": "verify",
}
# What a result's TEXT says the reason is (a caller older than the markers), first match
# wins: the same readings as the DEPLOY VERDICT block's _dv_guess, on deploy.sh's own
# words as an older agent forwards them (its one line drops the «[deploy][FAIL]» prefix).
TEXT_REASONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"did not finish within"), "timeout"),
    (re.compile(r"another deploy already holds"), "busy"),
    (re.compile(r"ensurepip is not available|\bpython3\.[0-9]+-venv\b|the test venv"), "no_venv"),
    (re.compile(r"vpn-relay-apply check failed after the restart \(exit 1[34]\b"), "upstream"),
    (re.compile(r"ROLLBACK|rolled back"), "rolled_back"),
    (re.compile(r"Phase 1 gate: (?:ruff check|compileall|pytest) failed|^(?:FAILED|ERROR) tests/"
                r"|^=+ .*\b[0-9]+ (?:failed|errors?)\b.* in [0-9.]+s", re.MULTILINE), "tests"),
    (re.compile(r"git fetch"), "fetch"),
    (re.compile(r"Phase 1 gate:|^\[deploy\]\[FAIL\] ", re.MULTILINE), "checks"),
)
_RESULT_LINE = re.compile(r"\[deploy:result failed step=(?P<step>[a-z_]{1,32}) reason=(?P<reason>[a-z_]{1,32})\]")
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


def reason_from_text(text: str) -> str:
    """The reason a result's text tells (:data:`TEXT_REASONS`), "" when it tells none."""
    for pattern, reason in TEXT_REASONS:
        if pattern.search(text):
            return reason
    return ""


def deploy_failure_from(
    data: Mapping[str, object] | None, *, message: str = "", default: str = "failed"
) -> DeployFailure:
    """A failure from a caller's fields (``reason``, ``step``/``fail_step``, ``excerpt``,
    ``log``/``deploy_log``); a reason it does not know becomes the one its text tells,
    else *default*. A missing step is read as the module docstring says («THE STEP»)."""
    data = data or {}
    raw_reason = data.get("reason")
    raw_step = data.get("step") or data.get("fail_step")
    log = data.get("log") or data.get("deploy_log")
    excerpt = _lines(data.get("excerpt"))
    text_message = (message or str(data.get("message") or ""))[:MAX_MESSAGE_CHARS]
    reason = raw_reason if isinstance(raw_reason, str) and raw_reason in DEPLOY_REASONS else ""
    step = raw_step if isinstance(raw_step, str) and raw_step in DEPLOY_STEPS else ""
    text = "\n".join((text_message, str(data.get("message") or "")[:MAX_MESSAGE_CHARS], *excerpt))
    markers = list(_RESULT_LINE.finditer(text))
    marker = markers[-1] if markers else None  # the last result line counts
    if marker is not None:
        if not step and marker.group("step") in DEPLOY_STEPS:
            step = marker.group("step")
        if not reason and marker.group("reason") in DEPLOY_REASONS:
            reason = marker.group("reason")
    if not reason:
        reason = reason_from_text(text) or default
    if not step:
        step = REASON_STEPS.get(reason, "")
    return DeployFailure(
        reason=reason,
        step=step,
        excerpt=excerpt,
        log=log if isinstance(log, str) and _LOG_PATH.fullmatch(log) else "",
        message=text_message,
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
