"""Guard the per-client bandwidth ceiling in deploy/hysteria/config.yaml.

The tracked template is the source of truth for /etc/hysteria/config.yaml (see
deploy/hysteria/install-config.sh): whatever is missing here is silently dropped
from the host the next time the installer runs. That is exactly how
``ignoreClientBandwidth`` was lost once already — it lived in a hand-edited
/etc/hysteria/config.yaml and never made it into the repo, so the move of
Hysteria2 to UDP/443 reinstalled the file without it.

The ``bandwidth`` block bounds Hysteria2's Brutal congestion controller. Brutal
does not measure the path — it sends at the rate it was told and holds that rate
through loss — so a client declaring a fantasy figure would otherwise pin this
1-vCPU box at whatever it asked for. Server-side values are a limit PER CLIENT
and the effective rate is min(client, server), so removing the block does not
fall back to something conservative: it removes the ceiling entirely.

These tests read ONLY the repo file. Nothing here touches /etc, systemd or the
network — the same reason tests/conftest.py's autouse fixture blocks dotenv
auto-discovery of the production .env (cf. #239/#241/#242: green in clean CI,
red on the box, because live host state bleeds in).

PyYAML is deliberately not imported unconditionally: it is not a project
dependency, and CI installs strictly from the hashed constraints, which do not
carry it — the same reason install-config.sh hand-rolls its secret substitution
instead of round-tripping the file through a YAML library. The block-mapping
parser below covers the subset this config is written in and rejects anything
outside it, and the one test that does use PyYAML skips when it is absent.
"""

import re
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
REPO_CONFIG = ROOT / "deploy" / "hysteria" / "config.yaml"

EXPECTED_CEILING = "95 mbps"

# `key:` (nested mapping) or `key: value` (scalar), at any indentation.
_ENTRY_RE = re.compile(r"^(?P<indent>[ ]*)(?P<key>[A-Za-z_][A-Za-z0-9_.-]*):(?:[ ]+(?P<value>.*))?$")
# A `#` starts a comment only at line start or after whitespace (YAML's own rule),
# so a `#` inside a value — e.g. a Traffic Stats secret — is not cut off.
_COMMENT_RE = re.compile(r"(?:^|(?<=\s))#.*$")


def _strip_comment(line: str) -> str:
    return _COMMENT_RE.sub("", line).rstrip()


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_block_mapping(text: str) -> dict[str, Any]:
    """Parse the block-mapping subset of YAML this config is written in.

    Supports nested mappings and plain/quoted scalars, which is everything the
    file uses. Anything outside that subset — tabs, sequences, flow collections,
    an indentation level that matches no open mapping, a duplicate key — raises,
    so a structurally broken template fails loudly here rather than being read as
    an empty mapping and quietly passing the assertions below.
    """
    root: dict[str, Any] = {}
    # (indent of the keys inside it, mapping) — innermost last.
    stack: list[tuple[int, dict[str, Any]]] = [(0, root)]

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_comment(raw)
        if not line.strip():
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            raise ValueError(f"line {lineno}: tab in indentation")
        if line.lstrip().startswith("- "):
            raise ValueError(f"line {lineno}: sequences are not part of the supported subset")

        match = _ENTRY_RE.match(line)
        if match is None:
            raise ValueError(f"line {lineno}: not a `key:` / `key: value` entry: {line!r}")

        indent = len(match.group("indent"))
        # A mapping opened by a bare `key:` has its indent fixed by its first
        # entry (pushed as the -1 sentinel below); a line that does not indent
        # past the parent means it had no entries at all.
        if stack[-1][0] == -1:
            if indent > stack[-2][0]:
                stack[-1] = (indent, stack[-1][1])
            else:
                stack.pop()
        while len(stack) > 1 and indent < stack[-1][0]:
            stack.pop()
        if indent != stack[-1][0]:
            raise ValueError(f"line {lineno}: indentation {indent} opens no known mapping level")

        mapping = stack[-1][1]
        key = match.group("key")
        if key in mapping:
            raise ValueError(f"line {lineno}: duplicate key {key!r} at the same level")

        value = match.group("value")
        if value is None or value == "":
            child: dict[str, Any] = {}
            mapping[key] = child
            # The child's own indent is fixed by its first entry; push a sentinel
            # that the next deeper line resolves.
            stack.append((-1, child))
            continue
        if value[0] in "[{":
            raise ValueError(f"line {lineno}: flow collections are not part of the supported subset")
        mapping[key] = _unquote(value)

    return root


def parse_config() -> dict[str, Any]:
    return parse_block_mapping(REPO_CONFIG.read_text(encoding="utf-8"))


def _normalise_bool(value: object) -> object:
    """Fold the YAML spellings of false the subset parser returns as strings."""
    if isinstance(value, str) and value.strip().lower() in ("false", "no", "off"):
        return False
    return value


# --------------------------------------------------------------------------- #
# the template still parses
# --------------------------------------------------------------------------- #
def test_repo_config_parses_and_keeps_its_top_level_blocks() -> None:
    config = parse_config()

    # Every block the data plane depends on, so a mangled edit that happens to
    # leave `bandwidth` intact still fails here.
    for key in ("listen", "tls", "auth", "trafficStats", "masquerade", "bandwidth"):
        assert key in config, f"{key} missing from {REPO_CONFIG}"


def test_repo_config_parses_under_real_yaml_when_available() -> None:
    # Cross-check the subset parser above against a real YAML implementation
    # wherever one happens to be installed. Skipped in CI (PyYAML is not in the
    # hashed constraints), so it can only ever add confidence, never gate.
    yaml = pytest.importorskip("yaml")

    loaded = yaml.safe_load(REPO_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    assert loaded["bandwidth"] == {"up": EXPECTED_CEILING, "down": EXPECTED_CEILING}
    assert loaded.get("ignoreClientBandwidth") in (None, False)


# --------------------------------------------------------------------------- #
# the ceiling itself
# --------------------------------------------------------------------------- #
def test_bandwidth_block_caps_both_directions_at_95_mbps() -> None:
    bandwidth = parse_config()["bandwidth"]
    assert isinstance(bandwidth, dict), "bandwidth must be a mapping with up/down"

    # Server-side: `up` is the client's download ceiling, `down` its upload one.
    # Both must be present — an omitted direction means "no limit" for it, not
    # "inherit the other".
    assert bandwidth.get("up") == EXPECTED_CEILING
    assert bandwidth.get("down") == EXPECTED_CEILING


def test_ignore_client_bandwidth_is_absent_or_disabled() -> None:
    # `ignoreClientBandwidth: true` discards the client's declared bandwidth and
    # forces the non-Brutal controller, which makes the ceiling above dead weight
    # — the two are mutually exclusive by meaning. Adding it is a deliberate
    # decision that has to come with re-reading the block above, not a quiet edit.
    config = parse_config()
    assert _normalise_bool(config.get("ignoreClientBandwidth", False)) is False
