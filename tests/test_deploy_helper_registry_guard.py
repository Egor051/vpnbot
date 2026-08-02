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

The guard
---------
Any `scripts/` file whose installed path `/usr/local/sbin/<name>` is referenced by
the machine-consumed deploy surface (an `install` line in
`deploy/setup-nonroot-helper-mode.sh`, an `Exec*=` in a shipped unit, a sudoers
grant, one helper calling another by absolute path) or by the deploy docs is, by
that reference, a helper that MUST exist at that path on a deployed host. Every
such file therefore needs an `OUT_OF_REPO_HELPERS` entry. This module fails when
one does not.

Everything here reads repo files only — no host paths, no systemctl, no network.
"""

import re
from collections.abc import Iterable, Mapping
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
SCRIPTS_DIR = ROOT / "scripts"

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

# The install path prefix + a helper basename. Kept deliberately narrow (no `/`) so
# `/usr/local/sbin/foo/bar` cannot be read as a helper called "foo/bar".
SBIN_REF_RE = re.compile(r"/usr/local/sbin/([A-Za-z0-9][A-Za-z0-9._-]*)")
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
