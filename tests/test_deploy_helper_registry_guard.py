"""Registration-completeness guard for `OUT_OF_REPO_HELPERS` in scripts/deploy.sh.

Background
----------
Privileged helpers live in `scripts/` (tracked source) but RUN from
`/usr/local/sbin` (installed copy). `git reset --hard origin/main` advances the
source and never the installed copy, so deploy.sh Phase 2
(`install_out_of_repo_helpers`) closes that drift — but only for the helpers
listed in the `OUT_OF_REPO_HELPERS` array.

A helper that is installed on the host but MISSING from that array is invisible
to the gate, and the gate then prints

    out-of-repo helpers already matched the checkout (no drift to close)

while the installed copy stays stale. A green report over an unclosed drift is
strictly worse than no gate: it actively tells the operator the thing it did not
check is fine. That is not hypothetical — on 2026-08-01, PR #274 changed
`scripts/vpn-bot-warp-split`, the deploy reported exactly that line, and
`/usr/local/sbin/vpn-bot-warp-split` never moved, because the three split helpers
had no entry in the array.

The guards
----------
Two independent scans, deliberately anchored at opposite ends, because each one is
blind exactly where the other looks:

1. SOURCE-ANCHORED. Any `scripts/` file whose installed path
   `/usr/local/sbin/<name>` is referenced by the machine-consumed deploy surface
   (an `install` line in `deploy/setup-nonroot-helper-mode.sh`, an `Exec*=` in a
   shipped unit, a sudoers grant, one helper calling another by absolute path) or
   by the deploy docs is, by that reference, a helper that MUST exist at that path
   on a deployed host — so it needs an `OUT_OF_REPO_HELPERS` entry.

2. INSTALL-SITE-ANCHORED. Every `/usr/local/sbin/<name>` a shipped `deploy/*.service`
   or `deploy/*.timer` actually EXECUTES (`ExecStart=`, `ExecStop=`, and the rest of
   the `Exec*=` family), plus — as a second source — every one a `deploy/sudoers.d/*`
   grant names, must be registered or carry an explicit, justified exemption.

Scan 1 starts from the `scripts/` listing, so it only ever asks about names that
exist there: a unit executing `/usr/local/sbin/<name>` with no `scripts/<name>`
file is invisible to it and it reports green — the same shape of blindness as the
original bug, one level up. Scan 2 starts from the install site instead, so the
unit itself is the evidence and no file listing can filter it away. The 2026-08-01
miss is caught by both; the split-`state`/`apply` helpers appear in no unit at all
and are caught through the sudoers source.

Everything here reads repo files only — no host paths, no systemctl, no network.
"""

import re
from collections.abc import Iterable, Mapping
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
SCRIPTS_DIR = ROOT / "scripts"
DEPLOY_DIR = ROOT / "deploy"

# Shipped systemd units, the mandatory source of scan 2. Globbed recursively, not
# read from a hardcoded list: a unit added under deploy/<subsystem>/ must be scanned
# too, or the guard goes blind exactly where a new subsystem lands.
UNIT_GLOBS = ("*.service", "*.timer")
# Second source of scan 2: a sudoers grant naming /usr/local/sbin/<name> asserts the
# helper is installed there just as firmly as an Exec*= does. It carries the two
# split helpers (`-state`, `-apply`) that no unit executes, so without it scan 2
# would see only one third of the helpers the 2026-08-01 bug was about.
SUDOERS_GLOB = "sudoers.d/*"

# Directories whose files are scanned for "<helper> is installed at
# /usr/local/sbin/<helper>" evidence. deploy/ and scripts/ are the machine-consumed
# surface (install commands, unit Exec*=, sudoers grants, helper-to-helper calls);
# docs/ is included because a runbook that tells an operator to run
# /usr/local/sbin/<name> is making the same claim.
EVIDENCE_DIRS = ("deploy", "scripts", "docs")

# Per-test wall-clock ceiling (pytest-timeout). Every test here reads repo files and
# finishes in milliseconds, so anything near this limit is a hang, not slow work.
# Belt-and-braces on top of the real rule, because deploy.sh runs this suite as a
# Phase 1 gate on the production host, where a wedged test blocks the deploy.
pytestmark = pytest.mark.timeout(60)

# Deliberate non-registrations: a `scripts/` file that IS referenced under
# /usr/local/sbin but must NOT be managed by deploy.sh, mapped to the reason why.
# Empty on purpose — every installed helper today is registered. Adding a name here
# is a conscious decision to leave that helper's installed copy un-refreshed by the
# deploy, i.e. to accept the stale-copy drift for it; say why in the value.
UNMANAGED_SBIN_HELPERS: Mapping[str, str] = {}


def _backend_helper_reason(name: str) -> str:
    """The one legitimate reason a unit/sudoers-referenced helper is not registered."""
    return (
        f"Backend helper: its tracked source is deploy/helpers/{name}, not scripts/{name}. "
        "deploy/setup-nonroot-helper-mode.sh installs and refreshes the deploy/helpers/ "
        "layer, and OUT_OF_REPO_HELPERS is scoped to scripts/ files by construction "
        "(scripts/deploy.sh: 'the backend helpers under deploy/helpers/ are installed by "
        "deploy/setup-nonroot-helper-mode.sh and are out of scope here'). Registering it "
        "would make every deploy install the backend-helper layer — a scope change this "
        "guard must not smuggle in as a side effect of a test. Its refresh path is a "
        "rerun of that setup script."
    )


# Explicit allowlist for scan 2 (unit Exec*= + sudoers grants): a helper that IS
# referenced at an install site but must NOT be in OUT_OF_REPO_HELPERS, mapped to the
# justification. An entry here is a decision, not a formality — every one is checked
# by test_sbin_exemptions_are_well_formed, which fails on a stub justification, on a
# name that is ALSO registered (contradictory), and on a name nothing references any
# more (a stale entry that would hide a future re-introduction).
EXEC_SBIN_EXEMPTIONS: Mapping[str, str] = {
    "vpn-bot-socks5-user": _backend_helper_reason("vpn-bot-socks5-user"),
    "vpn-bot-xray-apply": _backend_helper_reason("vpn-bot-xray-apply"),
    "vpn-bot-awg-apply": _backend_helper_reason("vpn-bot-awg-apply"),
    "vpn-bot-mtproxy-apply": _backend_helper_reason("vpn-bot-mtproxy-apply"),
}

# Shortest justification that can be a reason rather than a shrug ("n/a", "later",
# "not needed"). A rule, not a style preference: the allowlist is the one place where
# a helper is knowingly left out of the drift gate, so the next reader has to be able
# to see WHY without a git archaeology session.
MIN_JUSTIFICATION_CHARS = 60

# The install path prefix + a helper basename. Kept deliberately narrow (no `/`) so
# `/usr/local/sbin/foo/bar` cannot be read as a helper called "foo/bar".
SBIN_REF_RE = re.compile(r"/usr/local/sbin/([A-Za-z0-9][A-Za-z0-9._-]*)")

# One `Exec*=` directive line in a unit file: ExecStart, ExecStop, ExecStartPre,
# ExecStartPost, ExecStopPost, ExecReload, ExecCondition — every systemd verb that
# RUNS a command. ExecStart=/ExecStop= are the two the requirement names; the rest
# are the same claim ("this path is executed on a deployed host") in another verb,
# and vpn-bot.service's ExecStartPre=/usr/local/sbin/vpn-bot-db-perms is exactly
# that case, so the family is matched whole rather than two verbs of it.
EXEC_DIRECTIVE_RE = re.compile(r"^\s*Exec[A-Za-z]*\s*=\s*(.+)$")
# systemd's Exec* prefix characters — "-" (ignore failure), "@" (argv[0] override),
# "+" / "!" / "!!" (privilege modifiers), ":" (no variable expansion) — legal in any
# combination before the executable path.
EXEC_PREFIX_CHARS = "-@+!:"
# The executed binary itself, anchored end to end: a registry destination is always
# /usr/local/sbin/<name>, so /usr/local/sbin/sub/dir is not a helper name and is not
# read as one.
SBIN_COMMAND_RE = re.compile(r"^/usr/local/sbin/([A-Za-z0-9][A-Za-z0-9._-]*)$")

# A systemctl call in deploy.sh: verb plus its first argument, if any. Used to read
# what a shell function actually re-applies instead of grepping for unit names —
# `systemctl restart "$SOME_NEW_UNIT"` must be as visible as a literal.
SYSTEMCTL_CALL_RE = re.compile(r"\bsystemctl\s+([a-z][a-z-]*)(?:\s+(\S+))?")
# One OUT_OF_REPO_HELPERS entry: "<src>|<dst>[|<policy>]", the policy field optional.
REGISTRY_ENTRY_RE = re.compile(r'^\s*"([^"|]+)\|([^"|]+?)(?:\|([^"|]+))?"\s*$')

VALID_POLICIES = frozenset({"absent-ok", "required"})

# The failure text the main guard carries: it must name the bug CLASS and the FIX,
# not just report an unregistered name.
REMEDY = (
    "This helper is installed to /usr/local/sbin but has no OUT_OF_REPO_HELPERS entry in "
    "scripts/deploy.sh, so the Phase 2 drift gate never looks at it: a deploy that changes "
    "the tracked source leaves the installed copy stale AND prints 'out-of-repo helpers "
    "already matched the checkout (no drift to close)' — a green report over an unclosed "
    "drift (PR #274 / 2026-08-01).\n"
    'FIX: add "scripts/<name>|/usr/local/sbin/<name>|absent-ok" to OUT_OF_REPO_HELPERS '
    "(use `required` instead when a unit names the helper in Exec*= on EVERY host, so an "
    "absent copy would fail 203/EXEC). If the helper genuinely must not be deploy-managed, "
    "record it in UNMANAGED_SBIN_HELPERS in this module with the reason."
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested on synthetic input further down)
# --------------------------------------------------------------------------- #
def parse_registry(deploy_text: str) -> dict[str, tuple[str, str, str]]:
    """Parse the OUT_OF_REPO_HELPERS array.

    Returns {installed basename: (checkout-relative source, installed path, policy)}.
    Comment lines inside the array are ignored; a two-field entry defaults to the
    `absent-ok` policy, exactly like scan_out_of_repo_helpers does in bash.
    """
    start = deploy_text.index("OUT_OF_REPO_HELPERS=(")
    body = deploy_text[start:].splitlines()[1:]
    out: dict[str, tuple[str, str, str]] = {}
    for line in body:
        if line.rstrip() == ")":
            break
        if line.lstrip().startswith("#") or not line.strip():
            continue
        m = REGISTRY_ENTRY_RE.match(line)
        if m is None:
            raise AssertionError(f"unparseable OUT_OF_REPO_HELPERS entry: {line!r}")
        src, dst, policy = m.group(1), m.group(2), m.group(3) or "absent-ok"
        out[dst.rsplit("/", 1)[-1]] = (src, dst, policy)
    return out


def collect_sbin_evidence(
    sources: Iterable[tuple[str, str]], scripts_files: Iterable[str]
) -> dict[str, list[str]]:
    """Map each scripts/ file referenced as /usr/local/sbin/<name> to where.

    `sources` is (label, text) pairs; the returned values are "<label>:<lineno>"
    citations, so a failure names the exact install site.
    """
    known = set(scripts_files)
    evidence: dict[str, list[str]] = {}
    for label, text in sources:
        for lineno, line in enumerate(text.splitlines(), start=1):
            for name in SBIN_REF_RE.findall(line):
                if name in known:
                    evidence.setdefault(name, []).append(f"{label}:{lineno}")
    return evidence


def unregistered_helpers(
    evidence: Mapping[str, list[str]],
    registered: Iterable[str],
    exempt: Mapping[str, str] = UNMANAGED_SBIN_HELPERS,
) -> list[str]:
    """Installed-but-unregistered helper names, sorted. This is THE detector."""
    known = set(registered)
    return sorted(n for n in evidence if n not in known and n not in exempt)


def exec_command(directive_value: str) -> str:
    """The executable path out of an `Exec*=` value: prefixes and quoting removed.

    `ExecStart=-@"/usr/local/sbin/foo" bar` -> `/usr/local/sbin/foo`. Quotes are
    stripped on both sides of the prefix chars because systemd accepts either order.
    Arguments are dropped: only the binary is an install-path claim.
    """
    first = directive_value.split()[0]
    return first.strip("\"'").lstrip(EXEC_PREFIX_CHARS).strip("\"'")


def unit_exec_sbin_refs(units: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    """Map each /usr/local/sbin helper a unit EXECUTES to its "<file>:<lineno>" sites.

    `units` is (label, text) pairs. Only `Exec*=` directives count: a path inside a
    comment (warp-routes.service documents its own install command in one) or inside
    `Environment=`/`Documentation=` is not something the unit runs. Comment lines are
    skipped for both systemd comment characters, `#` and `;`.

    A continuation line (`\\` at the end of an Exec*= value) carries arguments, never
    the binary, so reading only the directive line is enough.
    """
    refs: dict[str, list[str]] = {}
    for label, text in units:
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith(("#", ";")):
                continue
            directive = EXEC_DIRECTIVE_RE.match(line)
            if directive is None:
                continue
            command = SBIN_COMMAND_RE.match(exec_command(directive.group(1)))
            if command is not None:
                refs.setdefault(command.group(1), []).append(f"{label}:{lineno}")
    return refs


def sudoers_sbin_refs(files: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    """Map each /usr/local/sbin helper a sudoers grant NAMES to its sites.

    Same claim as an Exec*=, made by the other machine-consumed file the deploy
    ships: `vpn-bot ALL=(root) NOPASSWD: /usr/local/sbin/<name> <args>` only makes
    sense if <name> is installed there. Comment lines are skipped — the header of
    deploy/sudoers.d/vpn-bot.example spells out the `install` commands for helpers
    it does NOT grant, and documentation is not a grant.
    """
    refs: dict[str, list[str]] = {}
    for label, text in files:
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            for name in SBIN_REF_RE.findall(line):
                refs.setdefault(name, []).append(f"{label}:{lineno}")
    return refs


def shell_function_body(script: str, name: str) -> str:
    """The body of `name() { ... }`, up to the closing brace in column 0."""
    opener = f"{name}() {{"
    lines = script[script.index(opener) :].splitlines()[1:]
    end = next((i for i, line in enumerate(lines) if line.rstrip() == "}"), None)
    assert end is not None, f"{name}(): no closing brace in column 0 — is it still a function?"
    return "\n".join(lines[:end])


def shell_loop_body(script: str, opener: str) -> list[str]:
    """The lines of a `for ...; do` loop, up to its `done` at the opener's indent."""
    start = script.index(opener)
    indent = " " * (start - script.rfind("\n", 0, start) - 1)
    lines = script[start:].splitlines()[1:]
    end = next((i for i, line in enumerate(lines) if line == f"{indent}done"), None)
    assert end is not None, f"no `done` closing {opener!r} at its own indent"
    return lines[:end]


def systemctl_calls(body: str) -> list[tuple[str, str]]:
    """(verb, argument) for every systemctl call in a shell snippet, comments aside.

    The argument keeps its `$VAR` form with quotes stripped, so a restart written
    through a variable is caught as readily as a literal unit name.
    """
    calls: list[tuple[str, str]] = []
    for line in body.splitlines():
        if line.lstrip().startswith("#"):
            continue
        calls.extend((verb, arg.strip("\"'")) for verb, arg in SYSTEMCTL_CALL_RE.findall(line))
    return calls


def exemption_defects(
    exempt: Mapping[str, str], registered: Iterable[str], referenced: Iterable[str]
) -> list[str]:
    """Problems with the allowlist itself, sorted. An allowlist nobody checks rots."""
    known, seen = set(registered), set(referenced)
    defects: list[str] = []
    for name, reason in sorted(exempt.items()):
        if len(reason.strip()) < MIN_JUSTIFICATION_CHARS:
            defects.append(
                f"{name}: exemption carries no real justification ({reason.strip()!r}) — "
                f"state WHY this helper must not be deploy-managed, in at least "
                f"{MIN_JUSTIFICATION_CHARS} characters"
            )
        if name in known:
            defects.append(
                f"{name}: exempted AND registered in OUT_OF_REPO_HELPERS — contradictory; "
                "the registry wins, so drop the exemption"
            )
        if name not in seen:
            defects.append(
                f"{name}: exempted but no unit Exec*= or sudoers grant references it any "
                "more — delete the stale entry, or it will silently exempt the name again "
                "the day someone reintroduces it"
            )
    return defects


# --------------------------------------------------------------------------- #
# Repo facts
# --------------------------------------------------------------------------- #
def _scripts_files() -> set[str]:
    return {p.name for p in SCRIPTS_DIR.iterdir() if p.is_file()}


def _evidence_sources() -> list[tuple[str, str]]:
    """(repo-relative path, text) for every readable file in the evidence dirs.

    scripts/deploy.sh itself is excluded: it CONTAINS the registry, so counting its
    own entries as evidence would make the guard trivially self-satisfying.
    """
    sources: list[tuple[str, str]] = []
    for directory in EVIDENCE_DIRS:
        for path in sorted((ROOT / directory).rglob("*")):
            if not path.is_file() or path == DEPLOY_SH:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # binary or unreadable: carries no install command
            sources.append((str(path.relative_to(ROOT)), text))
    return sources


def _repo_evidence() -> dict[str, list[str]]:
    return collect_sbin_evidence(_evidence_sources(), _scripts_files())


def _unit_files() -> list[tuple[str, str]]:
    """(repo-relative path, text) for every shipped systemd unit under deploy/."""
    units: list[tuple[str, str]] = []
    for pattern in UNIT_GLOBS:
        for path in sorted(DEPLOY_DIR.rglob(pattern)):
            units.append((str(path.relative_to(ROOT)), _read(path)))
    return sorted(units)


def _sudoers_files() -> list[tuple[str, str]]:
    """(repo-relative path, text) for every shipped sudoers fragment under deploy/."""
    return [
        (str(path.relative_to(ROOT)), _read(path))
        for path in sorted(DEPLOY_DIR.glob(SUDOERS_GLOB))
        if path.is_file()
    ]


def _install_site_refs() -> dict[str, list[str]]:
    """Scan 2's evidence: unit Exec*= sites merged with sudoers grant sites."""
    merged = {name: list(sites) for name, sites in unit_exec_sbin_refs(_unit_files()).items()}
    for name, sites in sudoers_sbin_refs(_sudoers_files()).items():
        merged.setdefault(name, []).extend(sites)
    return merged


# --------------------------------------------------------------------------- #
# THE guard: every installed scripts/ helper is registered
# --------------------------------------------------------------------------- #
def test_every_installed_scripts_helper_is_registered() -> None:
    evidence = _repo_evidence()
    assert evidence, "no /usr/local/sbin references found at all — the scanner is broken"
    missing = unregistered_helpers(evidence, parse_registry(_read(DEPLOY_SH)))
    if missing:
        detail = "\n".join(
            f"  scripts/{name}  installed per: " + ", ".join(evidence[name][:4])
            for name in missing
        )
        pytest.fail(
            f"{len(missing)} scripts/ helper(s) installed to /usr/local/sbin without an "
            f"OUT_OF_REPO_HELPERS entry:\n{detail}\n\n{REMEDY}"
        )


def test_split_helpers_are_registered() -> None:
    """The exact 2026-08-01 miss: PR #274 changed scripts/vpn-bot-warp-split, the
    deploy printed "no drift to close", and the installed copy stayed stale."""
    registry = parse_registry(_read(DEPLOY_SH))
    for name in ("vpn-bot-warp-split", "vpn-bot-warp-split-state", "vpn-bot-warp-split-apply"):
        assert name in registry, f"{name} must be in OUT_OF_REPO_HELPERS"
        src, dst, policy = registry[name]
        assert src == f"scripts/{name}"
        assert dst == f"/usr/local/sbin/{name}"
        assert policy == "absent-ok", "the split layer is not deployed on every host"


def test_warp_failsafe_is_registered() -> None:
    """Same class as the split helpers: installed from scripts/ by
    deploy/setup-nonroot-helper-mode.sh and executed by warp-failsafe.service."""
    registry = parse_registry(_read(DEPLOY_SH))
    assert "warp-failsafe" in registry
    assert registry["warp-failsafe"][:2] == ("scripts/warp-failsafe", "/usr/local/sbin/warp-failsafe")


def test_registry_sources_exist_in_the_checkout() -> None:
    """A typo'd source path would scan as permanent drift, then fail the `install`
    in Phase 2 and roll the whole deploy back."""
    for name, (src, _dst, _policy) in parse_registry(_read(DEPLOY_SH)).items():
        assert (ROOT / src).is_file(), f"{name}: OUT_OF_REPO_HELPERS source {src} does not exist"


def test_registry_entries_are_well_formed() -> None:
    registry = parse_registry(_read(DEPLOY_SH))
    for name, (src, dst, policy) in registry.items():
        assert dst.startswith("/usr/local/sbin/"), f"{name}: unexpected install dir {dst}"
        assert src.rsplit("/", 1)[-1] == name, (
            f"{name}: source basename {src} differs from the installed name — "
            "scan_out_of_repo_helpers keys drift reports on the installed basename"
        )
        assert policy in VALID_POLICIES, f"{name}: unknown policy {policy!r}"


def test_registry_has_no_duplicate_entries() -> None:
    """parse_registry() keys by install path, so a duplicated destination would be
    silently collapsed here — count the raw entries instead."""
    text = _read(DEPLOY_SH)
    body = text[text.index("OUT_OF_REPO_HELPERS=(") :].split("\n)", 1)[0]
    raw = [m.group(2) for m in (REGISTRY_ENTRY_RE.match(ln) for ln in body.splitlines()) if m]
    assert len(raw) == len(set(raw)), f"duplicate OUT_OF_REPO_HELPERS destinations: {raw}"


# --------------------------------------------------------------------------- #
# THE SECOND guard: everything a shipped unit EXECUTES from /usr/local/sbin — plus
# everything a sudoers fragment grants there — is registered or explicitly exempt.
#
# Anchored at the install site, not at the scripts/ listing, so it cannot be filtered
# into silence: `ExecStart=/usr/local/sbin/<name>` in a shipped unit IS the claim that
# <name> runs from that path on a deployed host, whatever the checkout does or does
# not contain under scripts/.
# --------------------------------------------------------------------------- #
INSTALL_SITE_REMEDY = (
    "A shipped systemd unit executes this path (or a shipped sudoers fragment grants it), "
    "so on a deployed host it IS an installed helper — but it has no OUT_OF_REPO_HELPERS "
    "entry, so the Phase 2 drift gate never compares it with the checkout: a PR can change "
    "the tracked source while the installed copy keeps running the old code, and the deploy "
    "still prints 'out-of-repo helpers already matched the checkout (no drift to close)' "
    "(PR #274 / 2026-08-01).\n"
    'FIX: add "scripts/<name>|/usr/local/sbin/<name>|absent-ok" to OUT_OF_REPO_HELPERS in '
    "scripts/deploy.sh (use `required` when a unit names it in Exec*= on EVERY host, so an "
    "absent copy would fail 203/EXEC). If the helper genuinely must not be deploy-managed — "
    "the deploy/helpers/ backend layer is the standing example, owned by "
    "deploy/setup-nonroot-helper-mode.sh — add it to EXEC_SBIN_EXEMPTIONS in this module "
    "WITH the reason why."
)


def test_every_unit_executed_sbin_helper_is_registered() -> None:
    """The mandatory scan: deploy/*.service + deploy/*.timer Exec*= paths."""
    units = _unit_files()
    assert units, "no shipped unit files found under deploy/ — the scanner is broken"
    refs = unit_exec_sbin_refs(units)
    assert refs, "no Exec*=/usr/local/sbin/... found in any unit — the parser is broken"
    missing = unregistered_helpers(
        refs, parse_registry(_read(DEPLOY_SH)), exempt=EXEC_SBIN_EXEMPTIONS
    )
    if missing:
        detail = "\n".join(
            f"  /usr/local/sbin/{name}  executed by: " + ", ".join(refs[name][:4])
            for name in missing
        )
        pytest.fail(
            f"{len(missing)} helper(s) executed by a shipped unit without an "
            f"OUT_OF_REPO_HELPERS entry:\n{detail}\n\n{INSTALL_SITE_REMEDY}"
        )


def test_every_sudoers_granted_sbin_helper_is_registered() -> None:
    """The second source: a grant is the same install-path claim as an Exec*=."""
    files = _sudoers_files()
    assert files, "no sudoers fragments found under deploy/ — the scanner is broken"
    refs = sudoers_sbin_refs(files)
    assert refs, "no /usr/local/sbin grants found in any fragment — the parser is broken"
    missing = unregistered_helpers(
        refs, parse_registry(_read(DEPLOY_SH)), exempt=EXEC_SBIN_EXEMPTIONS
    )
    if missing:
        detail = "\n".join(
            f"  /usr/local/sbin/{name}  granted by: " + ", ".join(refs[name][:4])
            for name in missing
        )
        pytest.fail(
            f"{len(missing)} helper(s) granted in sudoers without an OUT_OF_REPO_HELPERS "
            f"entry:\n{detail}\n\n{INSTALL_SITE_REMEDY}"
        )


def test_install_site_scan_sees_the_helpers_the_2026_08_01_bug_was_about() -> None:
    """Non-vacuity, pinned to the real files: the scan must actually find the split
    layer. A parser that quietly stopped matching would leave both guards above
    passing over an empty set — the failure mode this whole module exists to deny."""
    unit_refs = unit_exec_sbin_refs(_unit_files())
    sudo_refs = sudoers_sbin_refs(_sudoers_files())

    split_sites = unit_refs["vpn-bot-warp-split"]
    assert len(split_sites) == 2, f"expected ExecStart + ExecStop, got {split_sites}"
    assert all(s.startswith("deploy/vpn-bot-warp-split.service:") for s in split_sites)
    # The helper the drift gate must never lose again, and its two neighbours.
    assert "warp-failsafe" in unit_refs
    assert "vpn-bot-warp-routes" in unit_refs
    # ExecStartPre, not ExecStart/ExecStop: the `required` helper is in scope too.
    assert "vpn-bot-db-perms" in unit_refs

    # WHY sudoers is scanned as a second source: two of the three helpers named in the
    # 2026-08-01 report are executed by NO unit at all, only by the bot through sudo.
    # With units as the only source, scan 2 would cover one third of that bug.
    assert "vpn-bot-warp-split-state" not in unit_refs
    assert "vpn-bot-warp-split-apply" not in unit_refs
    assert "vpn-bot-warp-split-state" in sudo_refs
    assert "vpn-bot-warp-split-apply" in sudo_refs


def test_sbin_exemptions_are_well_formed() -> None:
    """The allowlist is checked like any other input: a stub reason, a name that is
    also registered, or a name nothing references any more all fail here."""
    defects = exemption_defects(
        EXEC_SBIN_EXEMPTIONS,
        parse_registry(_read(DEPLOY_SH)),
        _install_site_refs(),
    )
    assert not defects, "EXEC_SBIN_EXEMPTIONS is not in order:\n  " + "\n  ".join(defects)


# --------------------------------------------------------------------------- #
# Guard-the-guard for the install-site scan: prove the detector catches the real
# 2026-08-01 miss on the REAL files, that the parser reads what it claims to read,
# and that the allowlist checks are not decorative.
# --------------------------------------------------------------------------- #
def test_install_site_guard_flags_the_split_helper_when_it_is_deregistered() -> None:
    """The 2026-08-01 state, replayed against the shipped units: take the real
    registry, remove `vpn-bot-warp-split` (exactly what the array looked like when
    PR #274 shipped) and the detector must name it. This is the guard-the-guard case
    that the passing state above is a fact about deploy.sh, not about an empty scan."""
    registry = parse_registry(_read(DEPLOY_SH))
    assert "vpn-bot-warp-split" in registry, "precondition: the helper is registered today"
    faked = {name: entry for name, entry in registry.items() if name != "vpn-bot-warp-split"}
    missing = unregistered_helpers(
        unit_exec_sbin_refs(_unit_files()), faked, exempt=EXEC_SBIN_EXEMPTIONS
    )
    assert missing == ["vpn-bot-warp-split"]


def test_install_site_guard_flags_the_state_helpers_when_they_are_deregistered() -> None:
    """The other two thirds of the same miss, through the sudoers source."""
    registry = parse_registry(_read(DEPLOY_SH))
    dropped = ("vpn-bot-warp-split-state", "vpn-bot-warp-split-apply")
    assert all(name in registry for name in dropped), "precondition: both registered today"
    faked = {name: entry for name, entry in registry.items() if name not in dropped}
    missing = unregistered_helpers(
        sudoers_sbin_refs(_sudoers_files()), faked, exempt=EXEC_SBIN_EXEMPTIONS
    )
    assert missing == ["vpn-bot-warp-split-apply", "vpn-bot-warp-split-state"]


def test_install_site_guard_flags_a_helper_with_no_scripts_file_at_all() -> None:
    """The blind spot scan 1 cannot cover, and the reason scan 2 exists: scan 1 asks
    "is this scripts/ file installed?", so a unit executing a path with no scripts/
    counterpart is filtered out of its evidence entirely and it reports green."""
    unit = ("deploy/new-thing.service", "ExecStart=/usr/local/sbin/vpn-bot-new-thing run\n")
    registry = parse_registry(_read(DEPLOY_SH))
    assert collect_sbin_evidence([unit], _scripts_files()) == {}, "scan 1 is blind here"
    assert unregistered_helpers(
        unit_exec_sbin_refs([unit]), registry, exempt=EXEC_SBIN_EXEMPTIONS
    ) == ["vpn-bot-new-thing"]


def test_install_site_guard_passes_once_the_helper_is_registered() -> None:
    unit = ("deploy/x.service", "ExecStart=/usr/local/sbin/vpn-bot-new-thing run\n")
    refs = unit_exec_sbin_refs([unit])
    assert unregistered_helpers(refs, ["vpn-bot-new-thing"], exempt={}) == []


def test_install_site_guard_honours_the_exemption() -> None:
    unit = ("deploy/x.service", "ExecStart=/usr/local/sbin/vpn-bot-xray-apply status\n")
    refs = unit_exec_sbin_refs([unit])
    exempt = {"vpn-bot-xray-apply": _backend_helper_reason("vpn-bot-xray-apply")}
    assert unregistered_helpers(refs, [], exempt=exempt) == []


def test_unit_parser_reads_execstart_execstop_and_the_rest_of_the_family() -> None:
    unit = (
        "deploy/x.service",
        "[Service]\n"
        "ExecStartPre=/usr/local/sbin/pre\n"
        "ExecStart=/usr/local/sbin/start apply\n"
        "ExecStop=/usr/local/sbin/stop revert\n"
        "ExecReload=/usr/local/sbin/reload\n",
    )
    assert unit_exec_sbin_refs([unit]) == {
        "pre": ["deploy/x.service:2"],
        "start": ["deploy/x.service:3"],
        "stop": ["deploy/x.service:4"],
        "reload": ["deploy/x.service:5"],
    }


def test_unit_parser_strips_systemd_exec_prefixes_and_quotes() -> None:
    for value in ('-/usr/local/sbin/h', '+/usr/local/sbin/h', '@/usr/local/sbin/h x',
                  '!!/usr/local/sbin/h', ':-/usr/local/sbin/h', '"/usr/local/sbin/h" a',
                  '-"/usr/local/sbin/h"'):
        refs = unit_exec_sbin_refs([("u", f"ExecStart={value}\n")])
        assert refs == {"h": ["u:1"]}, value


def test_unit_parser_ignores_comments_and_non_exec_directives() -> None:
    """warp-routes.service documents its own `install ... /usr/local/sbin/...` command
    in a comment, and a unit may name a helper in Environment= or Documentation=;
    neither is the unit executing it."""
    unit = (
        "deploy/x.service",
        "# install -m 0755 scripts/h /usr/local/sbin/h\n"
        "; ExecStart=/usr/local/sbin/semicolon-comment\n"
        "Environment=HELPER=/usr/local/sbin/env-only\n"
        "Documentation=file:///usr/local/sbin/doc-only\n",
    )
    assert unit_exec_sbin_refs([unit]) == {}


def test_unit_parser_ignores_commands_outside_usr_local_sbin() -> None:
    """Every non-helper ExecStart the repo actually ships (a venv python, a repo
    script) must be silently ignored, or the guard would demand registry entries for
    things that are not out-of-repo helpers at all."""
    unit = (
        "deploy/x.service",
        "ExecStart=/opt/vpn-service/.venv/bin/python -m hy2_auth\n"
        "ExecStart=/opt/vpn-service/deploy/update-ip2asn.sh\n"
        "ExecStart=/usr/bin/env true\n",
    )
    assert unit_exec_sbin_refs([unit]) == {}


def test_unit_parser_ignores_a_deeper_sbin_path() -> None:
    """A registry destination is /usr/local/sbin/<name>; /usr/local/sbin/sub/dir is
    not one, so it must not be reported as a helper called "sub"."""
    assert unit_exec_sbin_refs([("u", "ExecStart=/usr/local/sbin/sub/dir\n")]) == {}


def test_unit_parser_cites_every_execution_site() -> None:
    unit = (
        "deploy/x.service",
        "ExecStart=/usr/local/sbin/h apply\nRemainAfterExit=yes\nExecStop=/usr/local/sbin/h revert\n",
    )
    assert unit_exec_sbin_refs([unit]) == {"h": ["deploy/x.service:1", "deploy/x.service:3"]}


def test_sudoers_parser_reads_grants_and_skips_the_documentation_header() -> None:
    fragment = (
        "deploy/sudoers.d/x",
        "#   install -m 0755 deploy/helpers/documented /usr/local/sbin/documented\n"
        'Defaults:vpn-bot secure_path="/usr/local/sbin:/usr/sbin:/usr/bin"\n'
        "vpn-bot ALL=(root) NOPASSWD: \\\n"
        "    /usr/local/sbin/granted status\n",
    )
    assert sudoers_sbin_refs([fragment]) == {"granted": ["deploy/sudoers.d/x:4"]}


def test_exemption_defects_rejects_a_stub_justification() -> None:
    defects = exemption_defects({"h": "   "}, registered=[], referenced=["h"])
    assert len(defects) == 1 and "no real justification" in defects[0]


def test_exemption_defects_rejects_an_exemption_that_is_also_registered() -> None:
    defects = exemption_defects(
        {"h": _backend_helper_reason("h")}, registered=["h"], referenced=["h"]
    )
    assert len(defects) == 1 and "contradictory" in defects[0]


def test_exemption_defects_rejects_a_stale_exemption() -> None:
    """An exemption for a name nothing references any more is not harmless: it sits
    there ready to exempt the helper again the day someone reintroduces it."""
    defects = exemption_defects({"h": _backend_helper_reason("h")}, registered=[], referenced=[])
    assert len(defects) == 1 and "stale entry" in defects[0]


def test_exemption_defects_accepts_a_justified_live_exemption() -> None:
    assert exemption_defects(
        {"h": _backend_helper_reason("h")}, registered=[], referenced=["h"]
    ) == []


# --------------------------------------------------------------------------- #
# Deploy-side intent: the split layer is refreshed on disk but never re-applied
# --------------------------------------------------------------------------- #
def test_deploy_sh_does_not_reapply_the_split_layer() -> None:
    """Registering the split helpers must not drag a restart along "for symmetry"
    with warp-routes / vpnbot-hy2-warp-mark: the split ON/OFF state is the
    operator's, carried by the root-owned marker file, not by git. The rationale
    comment must survive so this is not "completed" later."""
    text = _read(DEPLOY_SH)
    assert "systemctl restart vpn-bot-warp-split" not in text
    assert 'systemctl restart "$SPLIT_UNIT"' not in text
    assert "systemctl restart warp-failsafe" not in text
    lowered = text.lower()
    assert "explicit exception" in lowered
    assert "warp-split.disabled" in lowered, "the marker must be named as the intent signal"
    assert "operator" in lowered and "symmetry" in lowered


def test_helper_refresh_reapplies_only_the_two_git_derived_units() -> None:
    """The invariant behind the rationale comment, checked on what the code DOES.

    Registering a helper must never grow a re-apply for it. `install_out_of_repo_helpers`
    may restart exactly two units, and both are re-applied because their effective input
    is git-derived and their intent signal is a was-active pre-state:

      * warp-routes.service — executes the refreshed helper, gated on `changed`;
      * vpnbot-hy2-warp-mark.service — re-derives its --sport exemption from .env.

    The split layer's state is NOT git-derived: it lives in the root-owned marker
    /etc/vpn-bot/warp-split.disabled and the saved list, both the operator's. Restarting
    vpn-bot-warp-split.service from here would reconcile table T on the deploy's schedule
    instead of the operator's, and warp-failsafe would burn its ~75s sleep in the deploy's
    critical path and could revert live WARP routing. A string check would miss a restart
    written through a new variable; this reads every systemctl call in the function.
    """
    body = shell_function_body(_read(DEPLOY_SH), "install_out_of_repo_helpers")
    restarted = {arg for verb, arg in systemctl_calls(body) if verb in ("restart", "start", "stop")}
    assert restarted == {"$WARP_ROUTES_UNIT", "$HY2_MARK_UNIT"}, (
        "install_out_of_repo_helpers may only re-apply the two units whose input is "
        f"git-derived, but it acts on {sorted(restarted)}. If a split/failsafe restart was "
        "added here 'for symmetry', remove it: their state belongs to the operator "
        "(/etc/vpn-bot/warp-split.disabled), and a refreshed helper takes effect on the "
        "next boot or the next `vpn-bot-warp-split-state on|off|restart`."
    )


def test_the_only_split_restart_path_left_stays_gated_on_the_pre_deploy_state() -> None:
    """The one place a deploy may touch vpn-bot-warp-split.service, kept honest.

    An AWG config change runs `awg-quick down/up`, which recreates the interface and
    silently drops what the RemainAfterExit WARP oneshots had installed — so that path
    re-applies WARP_ONESHOTS (the split unit among them) to restore what was there. That
    is not the deploy MOVING the split state: it is gated on the Phase 1 pre-state
    snapshot, so a unit the operator had stopped stays stopped. If that gate is ever
    dropped, a deploy would start re-activating a split the operator turned off — the
    exact outcome the registration work was required not to cause.
    """
    text = _read(DEPLOY_SH)
    assert "vpn-bot-warp-split.service" in text[text.index("WARP_ONESHOTS=(") :].split("\n", 1)[0]
    body = shell_loop_body(text, 'for w in "${WARP_ONESHOTS[@]}"; do')
    restarts = [i for i, line in enumerate(body) if 'systemctl restart "$w"' in line]
    gate = [i for i, line in enumerate(body) if '[[ "$pre" == "active" ]]' in line]
    assert len(restarts) == 1, f"expected exactly one reapply call, found {len(restarts)}"
    assert gate and gate[0] < restarts[0], (
        "the WARP oneshot reapply must stay inside the `pre == active` branch — "
        "reapplying an oneshot the operator deliberately stopped restarts what they "
        "took down (and for vpn-bot-warp-split.service that means a deploy moving the "
        "split state)"
    )
    assert any("U_PRE_ACTIVE[$w]" in line for line in body), "the pre-state snapshot must feed it"
    assert any("skip reapply" in line for line in body), "an inactive oneshot must be reported"


# --------------------------------------------------------------------------- #
# Guard-the-guard for the two intent checks above: the shell readers must see a
# re-apply that a future PR adds "for symmetry", and must not stop reading early
# (a truncated body is an empty call list, i.e. a check that passes on nothing).
# --------------------------------------------------------------------------- #
SYNTHETIC_REAPPLY = (
    "f() {\n"
    '  # systemctl restart "$COMMENTED_OUT_UNIT"\n'
    '  systemctl restart "$WARP_ROUTES_UNIT" \\\n'
    '    || rollback_now "boom"\n'
    "  systemctl daemon-reload\n"
    '  systemctl restart "$SPLIT_UNIT"\n'
    "}\n"
    "not_the_function() {\n"
    "  systemctl restart other.service\n"
    "}\n"
)


def test_systemctl_reader_catches_a_restart_added_for_symmetry() -> None:
    """The exact regression the intent check must catch: a split re-apply written
    through a fresh variable, which no `systemctl restart vpn-bot-warp-split` string
    search would ever see."""
    body = shell_function_body(SYNTHETIC_REAPPLY, "f")
    calls = systemctl_calls(body)
    assert ("restart", "$SPLIT_UNIT") in calls
    assert ("restart", "$WARP_ROUTES_UNIT") in calls
    assert ("daemon-reload", "") in calls
    # A commented-out call is documentation, and a call in the NEXT function is not
    # this function's behaviour: neither may count.
    assert ("restart", "$COMMENTED_OUT_UNIT") not in calls
    assert ("restart", "other.service") not in calls


def test_shell_function_body_reader_is_not_vacuous() -> None:
    body = shell_function_body(SYNTHETIC_REAPPLY, "f")
    assert body.splitlines()[0].strip().startswith("#")
    assert "not_the_function" not in body
    assert systemctl_calls(body), "an empty body would make the intent check pass on nothing"


def test_shell_loop_body_reader_stops_at_its_own_done() -> None:
    """A `done` nested deeper must not end the loop early, or the reader would return
    a stub the gate check then 'passes' over."""
    script = (
        "  for w in x; do\n"
        "    while read -r l; do\n"
        '      systemctl restart "$w"\n'
        "    done < <(gen)\n"
        "    echo tail\n"
        "  done\n"
        "  echo after\n"
    )
    body = shell_loop_body(script, "for w in x; do")
    assert [line.strip() for line in body] == [
        "while read -r l; do",
        'systemctl restart "$w"',
        "done < <(gen)",
        "echo tail",
    ]


# --------------------------------------------------------------------------- #
# Guard-the-guard: prove the detector catches the real bug and honours its
# exemption, so a future regression cannot pass by silently breaking the scan.
# --------------------------------------------------------------------------- #
SYNTHETIC_INSTALL = (
    "setup.sh",
    'install -o root -g root -m 0755 "${DIR}/vpn-bot-warp-split" /usr/local/sbin/vpn-bot-warp-split\n',
)
SYNTHETIC_UNIT = ("some.service", "ExecStart=/usr/local/sbin/warp-failsafe\n")


def test_guard_flags_an_unregistered_installed_helper() -> None:
    """The PR #274 scenario in miniature: the helper is installed, the registry
    lists only the other one, the detector must name it."""
    evidence = collect_sbin_evidence(
        [SYNTHETIC_INSTALL, SYNTHETIC_UNIT], ["vpn-bot-warp-split", "warp-failsafe"]
    )
    assert unregistered_helpers(evidence, ["warp-failsafe"], exempt={}) == ["vpn-bot-warp-split"]


def test_guard_passes_once_the_helper_is_registered() -> None:
    evidence = collect_sbin_evidence(
        [SYNTHETIC_INSTALL, SYNTHETIC_UNIT], ["vpn-bot-warp-split", "warp-failsafe"]
    )
    assert unregistered_helpers(evidence, ["vpn-bot-warp-split", "warp-failsafe"], exempt={}) == []


def test_guard_honours_the_unmanaged_exemption() -> None:
    evidence = collect_sbin_evidence([SYNTHETIC_INSTALL], ["vpn-bot-warp-split"])
    exempt = {"vpn-bot-warp-split": "installed by another mechanism"}
    assert unregistered_helpers(evidence, [], exempt=exempt) == []


def test_guard_ignores_sbin_paths_that_are_not_scripts_files() -> None:
    """deploy/helpers/* helpers also live in /usr/local/sbin but are installed by
    setup-nonroot-helper-mode.sh and are out of scope for this registry."""
    src = ("sudoers", "    /usr/local/sbin/vpn-bot-xray-apply status,\n")
    assert collect_sbin_evidence([src], ["vpn-bot-warp-split"]) == {}


def test_guard_cites_every_reference_site() -> None:
    src = (
        "docs/warp.md",
        "run /usr/local/sbin/vpn-bot-warp-split\n"
        "nothing here\n"
        "then /usr/local/sbin/vpn-bot-warp-split again\n",
    )
    assert collect_sbin_evidence([src], ["vpn-bot-warp-split"]) == {
        "vpn-bot-warp-split": ["docs/warp.md:1", "docs/warp.md:3"]
    }


def test_reference_regex_does_not_swallow_a_deeper_path() -> None:
    assert collect_sbin_evidence([("x", "/usr/local/sbin/sub/dir\n")], ["sub"]) == {
        "sub": ["x:1"]
    }
    assert collect_sbin_evidence([("x", "/usr/local/sbin/sub/dir\n")], ["sub/dir"]) == {}


def test_registry_parser_defaults_the_optional_policy_field() -> None:
    parsed = parse_registry(
        'OUT_OF_REPO_HELPERS=(\n'
        '  # a comment inside the array\n'
        '  "scripts/two-field|/usr/local/sbin/two-field"\n'
        '  "scripts/three-field|/usr/local/sbin/three-field|required"\n'
        ')\n'
    )
    assert parsed["two-field"] == ("scripts/two-field", "/usr/local/sbin/two-field", "absent-ok")
    assert parsed["three-field"] == (
        "scripts/three-field",
        "/usr/local/sbin/three-field",
        "required",
    )


def test_registry_parser_rejects_a_malformed_entry() -> None:
    with pytest.raises(AssertionError):
        parse_registry('OUT_OF_REPO_HELPERS=(\n  "scripts/no-destination"\n)\n')


def test_registry_parser_reads_the_real_array_whole() -> None:
    """Pin the parser against the shipped file: if the array is ever reformatted in
    a way the parser reads only partially, that must fail here rather than silently
    shrink the registry (which would make the main guard flag the rest of it)."""
    text = _read(DEPLOY_SH)
    registry = parse_registry(text)
    body = text[text.index("OUT_OF_REPO_HELPERS=(") :].split("\n)", 1)[0]
    quoted = [ln for ln in body.splitlines() if ln.strip().startswith('"')]
    assert quoted, "the array has no entries at all"
    assert len(registry) == len(quoted), "parse_registry dropped entries the array declares"
    assert registry["vpn-bot-db-perms"][2] == "required"
