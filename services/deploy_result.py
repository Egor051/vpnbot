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
among the texts; else, for a deploy that stopped before any change, from deploy.sh's
own words (:data:`TEXT_STEPS` — every «… nothing was changed» of deploy.sh with the
step and the reason it dies with; tests/test_deploy_verdict.py walks all of them);
else from the reason — the caller's, or the one the text tells (:data:`TEXT_REASONS`)
— through :data:`REASON_STEPS`, the inverse of deploy.sh's ``deploy_fail_reason``
(tests/test_deploy_verdict.py runs that function for every step against it); else it
stays "" and the bot says «шаг неизвестен». Never a guess onto the first step.
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
# The text → step table for a deploy that STOPPED BEFORE ANY CHANGE (its text says
# «nothing was changed»: deploy.sh's die, forwarded by an agent older than the markers
# — he2's v3.2.0 handed only «… (exit 1): host invariants: 2 fatal finding(s) — nothing
# was changed»). Each entry: deploy.sh's own words, the reason deploy_fail_reason gives
# there and the step it dies in. First match wins. tests/test_deploy_verdict.py takes
# EVERY «nothing was changed» message of scripts/deploy.sh and pins it to its step here.
_NOTHING_CHANGED = re.compile(r"nothing was changed", re.IGNORECASE)
TEXT_STEPS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # preflight: the host role and DEPLOY_REF (before the lock and the fetch)
    (re.compile(r"\bNODE_ROLE\b|DEPLOY_REF=\S* applies to a relay only"), "preflight", "preflight"),
    # fetch: the fetch itself, then a relay's target and its handover
    (re.compile(r"git fetch origin main failed|relay: git fetch failed"), "fetch", "fetch"),
    (re.compile(
        r"relay: (?:no release tag|release tag \S* ?does not name|origin/main does not resolve|DEPLOY_REF='"
        r"|git merge-base failed|the checkout \(\S+\) and .* are on different lines|cannot create a file under"
        r"|cannot read scripts/deploy\.sh|the deploy\.sh of )|moved during the handover"
    ), "preflight", "fetch"),
    # tests: the test venv, then the gate itself
    (re.compile(
        r"ensurepip is not available|python3 -m ensurepip still fails|the test venv cannot be built"
        r"|the test venv's pip|into the test venv failed"
    ), "no_venv", "tests"),
    (re.compile(r"Phase 1 gate: (?:ruff check|compileall|pytest) failed"), "tests", "tests"),
    # checks: the Phase 1 gates of both roles
    (re.compile(
        r"host invariants: |host files: Phase 1 refused|ssh configuration drift|\bssh port: |\bufw: "
        r"|cannot copy \S+/scripts/vpn-bot-(?:ssh-port|ufw-apply) into|cannot create a temporary file"
        r"|hy2-auth unit|relay: the ruleset does not render|relay: the checkout has no |relay: the unit set is not known"
    ), "checks", "checks"),
    # backup: a relay's Phase 2 backup, before the rollback is armed
    (re.compile(r"was present in Phase 1 but cannot be listed now|backup archive"), "failed", "backup"),
)
_RESULT_LINE = re.compile(r"\[deploy:result failed step=(?P<step>[a-z_]{1,32}) reason=(?P<reason>[a-z_]{1,32})\]")
MAX_EXCERPT_LINES = 8
MAX_LINE_CHARS = 300
# An agent's message carries deploy.sh's last FAIL line (it caps that at 600) after its
# own «the deploy of … stopped before any change (exit 1): ».
MAX_MESSAGE_CHARS = 900
MAX_FINDINGS = 8
_LOG_PATH = re.compile(r"/[A-Za-z0-9._/-]{1,200}")
_WARN_CODE = re.compile(r"[a-z_]{1,48}")
# The host invariants' findings (scripts/vpn-bot-host-check rows that stopped the deploy).
FINDING_VERDICTS = ("BEATEN", "MISMATCH", "LATENT")
_FAMILY = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_FINDING_KEY = re.compile(r"[A-Za-z0-9_.@:/|-]{1,128}")
_FINDING_PATH = re.compile(r"/[A-Za-z0-9._/@:+-]{1,300}")
# deploy.sh's die of the host invariants (hc_fatal_brief): «… — nothing was changed.
# Fatal: BEATEN sshd passwordauthentication: <text>; BEATEN sshd permitrootlogin: …».
_BRIEF_START = re.compile(r"\. Fatal: ")
_BRIEF_SPLIT = re.compile(r"; (?=(?:BEATEN|MISMATCH|LATENT) )")
_BRIEF_ITEM = re.compile(
    r"^(?P<verdict>BEATEN|MISMATCH|LATENT) (?P<family>[a-z][a-z0-9_-]{0,31}) (?P<key>\S{1,128}): "
    r"(?P<text>.*?)(?: \[(?P<path>/[^\]\s]{1,300})\])?$"
)
_AT_PATH = re.compile(r"^(/\S{1,300}?):(?P<line>[0-9]{1,6}) = ")
# BEATEN's text (vpn-bot-host-check's ANALYZER): «<file>:<line> = <value> wins over the
# repo value <repo value> of <repo file> (<rule>)».
_BEATEN_TEXT = re.compile(
    r"^(?P<file>/\S{1,300}?):(?P<line>[0-9]{1,6}) = (?P<value>.*?) wins over the repo value "
    r"(?P<repo_value>.*?) of (?P<repo_file>/\S{1,300})(?: \((?P<rule>[^)]*)\))?$"
)
# A FOREIGN SSHD OVERRIDE: a file directly in sshd_config.d (the agent's whitelist,
# scripts/vpn-relay-agent _SSHD_DROPIN) that beats one of these keys (deploy.sh's
# HOST_CHECK_SSHD_AUTH_KEYS) and that the repo does not install (deploy/host/ssh/*.conf).
SSHD_DROPIN = re.compile(r"/etc/ssh/sshd_config\.d/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\.conf")
SSHD_AUTH_KEYS: tuple[str, ...] = (
    "passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin",
    "permitemptypasswords", "pubkeyauthentication", "authenticationmethods",
)
REPO_SSHD_DROPINS: frozenset[str] = frozenset({
    "00-root-key-only.conf", "00-vpn-bot-port.conf", "00-vpnrelay-forwarding.conf", "00-vpnrelay-keyonly.conf",
})


@dataclass(frozen=True, slots=True)
class HostFinding:
    """One row of the host invariants that stopped a deploy: the verdict, the family
    and key, the file it is about, the check's own text (English, as received)."""

    verdict: str
    family: str
    key: str
    path: str = ""
    text: str = ""

    @property
    def beaten(self) -> dict[str, str] | None:
        """BEATEN's parts — file, line, value, repo_value, repo_file — or None."""
        if self.verdict != "BEATEN":
            return None
        m = _BEATEN_TEXT.match(self.text)
        return {k: v for k, v in m.groupdict().items() if v is not None} if m else None

    @property
    def foreign_sshd_override(self) -> bool:
        """A file in sshd_config.d the repo does not install beats a repo auth key."""
        return (
            self.verdict == "BEATEN" and self.family == "sshd" and self.key in SSHD_AUTH_KEYS
            and SSHD_DROPIN.fullmatch(self.path) is not None
            and self.path.rsplit("/", 1)[-1] not in REPO_SSHD_DROPINS
        )


@dataclass(frozen=True, slots=True)
class DeployFailure:
    reason: str
    step: str = ""
    excerpt: tuple[str, ...] = ()
    log: str = ""
    message: str = ""
    findings: tuple[HostFinding, ...] = ()

    @property
    def sshd_overrides(self) -> tuple[str, ...]:
        """The foreign sshd overrides among the findings, one path each."""
        return tuple(dict.fromkeys(f.path for f in self.findings if f.foreign_sshd_override))


def _finding(verdict: object, family: object, key: object, path: object, text: object) -> HostFinding | None:
    """A validated finding; the path from the text («<file>:<line> = …») when none is given."""
    if not (isinstance(verdict, str) and verdict in FINDING_VERDICTS and isinstance(family, str)
            and _FAMILY.fullmatch(family) and isinstance(key, str) and _FINDING_KEY.fullmatch(key)):
        return None
    body = str(text or "").strip()[:MAX_LINE_CHARS]
    where = str(path or "")
    if not where:
        at = _AT_PATH.match(body)
        where = at.group(1) if at else ""
    return HostFinding(verdict, family, key, where if _FINDING_PATH.fullmatch(where) else "", body)


def findings_from(raw: object) -> tuple[HostFinding, ...]:
    """``[{"verdict", "family", "key", "path", "text"}, ...]`` → validated findings."""
    if not isinstance(raw, list):
        return ()
    found: list[HostFinding] = []
    for item in raw[:MAX_FINDINGS]:
        if isinstance(item, Mapping):
            finding = _finding(item.get("verdict"), item.get("family"), item.get("key"), item.get("path"),
                               item.get("text"))
            if finding is not None and finding not in found:
                found.append(finding)
    return tuple(found)


def findings_from_text(text: str) -> tuple[HostFinding, ...]:
    """The findings deploy.sh put into its die message (hc_fatal_brief) — what an agent
    older than the structured ``findings`` forwards. A truncated last item keeps its
    truncated text (a path cut short does not validate)."""
    start = _BRIEF_START.search(text)
    if start is None:
        return ()
    found: list[HostFinding] = []
    for part in _BRIEF_SPLIT.split(text[start.end():])[:MAX_FINDINGS]:
        m = _BRIEF_ITEM.match(part.strip())
        if m is None:
            continue
        finding = _finding(m.group("verdict"), m.group("family"), m.group("key"), m.group("path"), m.group("text"))
        if finding is not None and finding not in found:
            found.append(finding)
    return tuple(found)


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


def step_from_text(text: str) -> tuple[str, str]:
    """(reason, step) a deploy that stopped before any change tells by its words
    (:data:`TEXT_STEPS`); ("", "") for any other text."""
    if not _NOTHING_CHANGED.search(text):
        return "", ""
    for pattern, reason, step in TEXT_STEPS:
        if pattern.search(text):
            return reason, step
    return "", ""


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
    if not step:
        text_reason, step = step_from_text(text)
        reason = reason or text_reason
    if not reason:
        reason = reason_from_text(text) or default
    if not step:
        step = REASON_STEPS.get(reason, "")
    findings = findings_from(data.get("findings")) or findings_from_text(text)
    return DeployFailure(
        reason=reason,
        step=step,
        excerpt=excerpt,
        log=log if isinstance(log, str) and _LOG_PATH.fullmatch(log) else "",
        message=text_message,
        findings=findings,
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
