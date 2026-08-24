"""Guards on deploy/backend-config-sync.py — the reconciler for the three data-plane
backend configs (Xray's config.json, AmneziaWG's awg0.conf, Hysteria2's config.yaml).

WHY THIS SUITE MATTERS MORE THAN A USUAL SCRIPT TEST

For the two CO-OWNED files the whole design rests on ONE definition — which regions
belong to the bot and must therefore be excluded from a structural comparison. Get
that definition wrong in either direction and the tool is worse than nothing:

  * too NARROW — the checker calls the bot's own runtime state "drift", so every
    issued key turns Phase 1 red and the operator learns to pass the bypass knob;
  * too WIDE — the checker stops looking at operator structure that actually moved,
    and `install-xray` overwrites live keys instead of preserving them.

So the pins below are not string comparisons against a copy of the definition. They
drive the REAL writers (adapters/xray_config.py, adapters/awg_config.py), then assert
the checker classifies what those writers produced. If a writer ever moves a client
list, renames a peer marker or binds egress somewhere new, these fail.

Hysteria2's config has no such split — it is operator-owned end to end, so section 2b
asserts the opposite property: that nothing is excluded, and that the differences the
comparison must still ignore (comments, key order, the placeholder secret) do not
become findings on every host.

Everything here works on tmp_path copies and injected paths: no live host config is
read, no service is touched, and the `xray -test` validation is exercised through
the xray_bin seam rather than by finding a binary. That matters because this suite
runs as a Phase 1 gate ON the production host (see the note in
tests/test_deploy_unit_nofile_limits.py) — tests that peeked at the live host have
failed here before.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from adapters.awg_config import AwgConfigAdapter
from adapters.xray_config import (
    FREEDOM_OUTBOUND_PROTOCOL,
    XrayConfigAdapter,
    apply_warp_send_through,
)

# The YAML subset the tracked hysteria config is written in, already parsed and
# pinned by that suite. Reused rather than re-implemented so there is exactly one
# definition of what this repo considers a parseable hysteria config.
from tests.test_hysteria_config_bandwidth import parse_block_mapping


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "backend-config-sync.py"
SKELETON = ROOT / "deploy" / "xray" / "config.skeleton.json"
AWG_EXAMPLE = ROOT / "deploy" / "awg" / "awg0.conf.example"
HY2_CONFIG = ROOT / "deploy" / "hysteria" / "config.yaml"
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"

# Per-test ceiling (pytest-timeout). Everything here is small file I/O in tmp_path.
pytestmark = pytest.mark.timeout(60)

# Exit codes the script documents in its own header, restated so a change to either
# side has to be conscious.
EXIT_OK = 0
EXIT_FAIL_CLOSED = 1
EXIT_DRIFT = 3


@pytest.fixture
def sync() -> ModuleType:
    """Load backend-config-sync.py (hyphenated, so not importable) per test."""
    loader = importlib.machinery.SourceFileLoader("backend_config_sync", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _skeleton() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


def _live_from_skeleton() -> dict:
    """A plausible live config: the skeleton with every placeholder given a value.

    Placeholders match any value by design, so `check` sees no drift against this —
    which is what makes it a usable baseline for injecting one difference at a time.
    """
    live = _skeleton()
    live["inbounds"][0]["settings"]["fallbacks"][0]["dest"] = 8001
    reality = live["inbounds"][0]["streamSettings"]["realitySettings"]
    reality["serverNames"] = ["decoy.example.invalid"]
    reality["privateKey"] = "live-private-key-placeholder"
    live["inbounds"][2]["port"] = 8001
    live["inbounds"][2]["streamSettings"]["xhttpSettings"]["path"] = "/v1/messages/stream"
    return live


def _write(path: Path, config: dict) -> Path:
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return path


def _live_awg() -> str:
    """A live awg0.conf whose [Interface] satisfies the tracked example."""
    return (
        "[Interface]\n"
        "PrivateKey = server-private-key\n"
        "Address = 10.0.0.1/24\n"
        "ListenPort = 443\n"
        "H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
        "S1 = 15\nS2 = 60\nS3 = 0\nS4 = 0\n"
        "Jc = 4\nJmin = 40\nJmax = 70\n"
        "I1 = <b 0xaa>\nI2 = <b 0xbb>\nI3 = <b 0xcc>\nI4 = <b 0xdd>\nI5 = <b 0xee>\n"
        "PostUp = sysctl -w net.ipv4.ip_forward=1; iptables -t nat -A POSTROUTING "
        "-s 10.0.0.0/24 -o eth0 -j MASQUERADE\n"
        "PostDown = iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE\n"
    )


def _dump_block_mapping(mapping: dict[str, Any], indent: int = 0) -> list[str]:
    """Re-emit a parsed block mapping as YAML — no comments, whatever key order it
    was handed. The inverse of parse_block_mapping over the same subset, used to
    build a live-config fixture that differs from the tracked file in every way the
    comparison must ignore.
    """
    out: list[str] = []
    pad = " " * indent
    for key, value in mapping.items():
        if isinstance(value, dict):
            out.append(f"{pad}{key}:")
            out.extend(_dump_block_mapping(value, indent + 2))
        else:
            out.append(f"{pad}{key}: {value}")
    return out


# --------------------------------------------------------------------------- #
# 1. The pins: the checker's region definition vs what the writers really write
# --------------------------------------------------------------------------- #
def test_clients_path_the_writer_uses_is_excluded_by_the_checker(sync) -> None:
    """XrayConfigAdapter._clients() decides where a client is stored. Whatever it
    returns must be a region the checker ignores — otherwise every issued key is
    reported as drift.

    _clients() only touches *self* to raise, so an unbound call is a faithful read
    of the path without standing up an adapter (which needs a full Settings)."""
    live = _live_from_skeleton()
    inbound = live["inbounds"][0]
    clients = XrayConfigAdapter._clients(None, inbound)  # type: ignore[arg-type]
    clients.append({"id": "uuid-1", "email": "key-1", "flow": "xtls-rprx-vision"})
    clients.append({"id": "uuid-2", "email": "key-2"})

    stripped = sync.strip_xray_bot_owned(live)
    assert stripped["inbounds"][0]["settings"]["clients"] == []
    # ...and the source config is untouched: strip must deep-copy, or `check`
    # would corrupt the very dict it later reports a census from.
    assert len(live["inbounds"][0]["settings"]["clients"]) == 2


def test_short_ids_path_the_writer_uses_is_excluded_by_the_checker(sync) -> None:
    live = _live_from_skeleton()
    inbound = live["inbounds"][0]
    reality = XrayConfigAdapter._reality_settings(None, inbound)  # type: ignore[arg-type]
    reality.setdefault("shortIds", []).append("ab12cd34")

    stripped = sync.strip_xray_bot_owned(live)
    assert stripped["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"] == []


def test_send_through_the_warp_writer_asserts_is_excluded_by_the_checker(sync) -> None:
    """apply_warp_send_through() is the real writer, re-run on EVERY config write.
    The skeleton deliberately ships no sendThrough, so if the checker did not strip
    it, a host with WARP deployed would report drift forever."""
    live = _live_from_skeleton()
    changed = apply_warp_send_through(live, "172.16.0.2")
    assert changed, "apply_warp_send_through did not bind the skeleton's freedom outbound"
    assert live["outbounds"][0]["sendThrough"] == "172.16.0.2"
    assert live["outbounds"][0]["protocol"] == FREEDOM_OUTBOUND_PROTOCOL

    stripped = sync.strip_xray_bot_owned(live)
    assert "sendThrough" not in stripped["outbounds"][0]


def test_checker_freedom_protocol_matches_the_adapter(sync) -> None:
    assert sync.FREEDOM_OUTBOUND_PROTOCOL == FREEDOM_OUTBOUND_PROTOCOL


def test_send_through_is_only_excluded_on_freedom_outbounds(sync, tmp_path: Path) -> None:
    """The exclusion must be no wider than the writer's region. apply_warp_send_through
    touches sendThrough ONLY where protocol == freedom, so the same key on any other
    outbound is operator structure and has to stay visible as drift."""
    config = _live_from_skeleton()
    config["outbounds"].append(
        {"tag": "extra", "protocol": "socks", "sendThrough": "203.0.113.7", "settings": {}}
    )
    live = _write(tmp_path / "config.json", config)
    count, lines = sync.check_xray(SKELETON, live)
    joined = "\n".join(lines)
    assert count >= 1, lines
    assert "outbounds[extra]" in joined, joined


def test_peer_block_the_writer_emits_is_counted_as_bot_managed(sync) -> None:
    """AwgConfigAdapter._peer_block() is the only thing that writes a peer. Its
    markers are what the checker keys on, so generate one with the real method and
    assert the checker recognises it — a renamed marker fails here, not in prod."""
    fake_self = SimpleNamespace(_validate_label=lambda label: None)
    block = AwgConfigAdapter._peer_block(  # type: ignore[arg-type]
        fake_self, 7, 42, "client-public-key", "psk", "10.0.0.5", "phone"
    )
    text = _live_awg() + "\n" + block
    total, managed = sync.count_awg_peers(text)
    assert (total, managed) == (1, 1), (total, managed, block)
    assert sync.AWG_MANAGED_START_PREFIX in block
    assert sync.AWG_MANAGED_END_PREFIX in block


def test_interface_keys_the_writer_carries_through_are_all_in_the_example() -> None:
    """The obfuscation fingerprint must be declared in the tracked example.

    services/awg.py copies these [Interface] values verbatim into every client
    config (`client_interface_options`), and AmneziaWG completes no handshake unless
    server and client agree on them byte for byte — so a key the writer carries but
    the example omits is invisible to `check`, and a host missing it issues keys that
    silently never connect.

    The set is pinned as CLIENT ∩ CRITICAL rather than all of _CLIENT_INTERFACE_KEYS
    because DNS and MTU are deliberately NOT sourced from awg0.conf: the builder
    writes `DNS = settings.awg_client_dns` and skips the server's own DNS outright,
    and MTU comes from the key payload or settings.awg_mtu. Their home is .env
    (AWG_CLIENT_DNS / AWG_MTU), and the live host carries neither in [Interface].
    The second assertion is the guard on that reasoning: a NEW client-carried key
    has to be classified here consciously instead of quietly slipping past."""
    example = AWG_EXAMPLE.read_text(encoding="utf-8")
    declared = {
        line.split("=", 1)[0].strip()
        for line in example.splitlines()
        if "=" in line and not line.lstrip().startswith("#")
    }
    client_keys = AwgConfigAdapter._CLIENT_INTERFACE_KEYS
    critical_keys = AwgConfigAdapter._CRITICAL_INTERFACE_KEYS
    for key in client_keys & critical_keys:
        assert key in declared, f"{key} is carried into client configs but absent from the example"
    assert client_keys - critical_keys == {"DNS", "MTU"}, (
        "a client-carried [Interface] key appeared that is neither critical on the server "
        "nor one of the two .env-sourced values — decide where it belongs and update the "
        "example plus this guard"
    )


# --------------------------------------------------------------------------- #
# 2. check: clean baseline, absent-ok, and one injected difference at a time
# --------------------------------------------------------------------------- #
def test_clean_live_config_reports_no_drift(sync, tmp_path: Path) -> None:
    live = _write(tmp_path / "config.json", _live_from_skeleton())
    count, lines = sync.check_xray(SKELETON, live)
    assert count == 0, lines


def test_bot_owned_state_on_top_of_a_clean_config_is_still_no_drift(sync, tmp_path: Path) -> None:
    config = _live_from_skeleton()
    XrayConfigAdapter._clients(None, config["inbounds"][0]).append({"id": "u", "email": "k"})  # type: ignore[arg-type]
    XrayConfigAdapter._reality_settings(None, config["inbounds"][0])["shortIds"].append("ab12")  # type: ignore[arg-type]
    apply_warp_send_through(config, "172.16.0.2")
    live = _write(tmp_path / "config.json", config)

    count, lines = sync.check_xray(SKELETON, live)
    assert count == 0, lines
    # The census still reports the real client count — excluded from comparison is
    # not the same as unreported.
    assert "vless-in=1" in "\n".join(lines)


def test_absent_backend_is_not_drift(sync, tmp_path: Path) -> None:
    """A host running only Hysteria2 has no xray/awg config. Phase 1 must not fail
    there — same absent-ok policy as deploy.sh's OUT_OF_REPO_HELPERS."""
    x_count, x_lines = sync.check_xray(SKELETON, tmp_path / "nope.json")
    a_count, a_lines = sync.check_awg(AWG_EXAMPLE, tmp_path / "nope.conf")
    assert (x_count, a_count) == (0, 0)
    assert "absent" in x_lines[0] and "not drift" in x_lines[0]
    assert "absent" in a_lines[0] and "not drift" in a_lines[0]


def test_inbounds_are_matched_by_tag_not_position(sync, tmp_path: Path) -> None:
    """Xray does not care about inbound order and neither may the checker: a host
    whose inbounds sit in another order is not drift."""
    config = _live_from_skeleton()
    config["inbounds"] = list(reversed(config["inbounds"]))
    live = _write(tmp_path / "config.json", config)
    count, lines = sync.check_xray(SKELETON, live)
    assert count == 0, lines


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        pytest.param(
            lambda c: c["log"].__setitem__("loglevel", "warning"),
            "log.loglevel",
            id="operator-value-changed",
        ),
        pytest.param(
            lambda c: c.__setitem__("unexpectedKey", {"a": 1}),
            "EXTRA on host",
            id="extra-top-level-key",
        ),
        pytest.param(
            lambda c: c.pop("dns"),
            "MISSING on host",
            id="missing-top-level-key",
        ),
        pytest.param(
            lambda c: c["inbounds"].pop(1),
            "inbounds[tag=api]",
            id="whole-inbound-gone",
        ),
        pytest.param(
            lambda c: c["inbounds"][0]["streamSettings"]["realitySettings"].__setitem__(
                "target", "127.0.0.1:9443"
            ),
            "target",
            id="reality-decoy-moved",
        ),
        pytest.param(
            lambda c: c["inbounds"][0]["sniffing"].__setitem__("routeOnly", 1),
            "routeOnly",
            id="json-true-vs-1",
        ),
    ],
)
def test_operator_owned_drift_is_reported(sync, tmp_path: Path, mutate, expected: str) -> None:
    config = _live_from_skeleton()
    mutate(config)
    live = _write(tmp_path / "config.json", config)
    count, lines = sync.check_xray(SKELETON, live)
    assert count >= 1, lines
    assert expected in "\n".join(lines), lines


def test_clean_awg_reports_no_drift(sync, tmp_path: Path) -> None:
    live = tmp_path / "awg0.conf"
    live.write_text(_live_awg(), encoding="utf-8")
    count, lines = sync.check_awg(AWG_EXAMPLE, live)
    assert count == 0, lines


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        pytest.param(
            lambda t: t.replace("Jc = 4\n", ""),
            "MISSING on host   [Interface].Jc",
            id="obfuscation-param-dropped",
        ),
        pytest.param(
            lambda t: t.replace("[Interface]\n", "[Interface]\nFwMark = 51820\n"),
            "EXTRA on host     [Interface].FwMark",
            id="undocumented-key-added",
        ),
        pytest.param(
            lambda t: t.replace("-j MASQUERADE", "-j SNAT --to-source 203.0.113.5"),
            "[Interface].PostUp",
            id="nat-rule-reshaped",
        ),
    ],
)
def test_awg_interface_drift_is_reported(sync, tmp_path: Path, mutate, expected: str) -> None:
    live = tmp_path / "awg0.conf"
    live.write_text(mutate(_live_awg()), encoding="utf-8")
    count, lines = sync.check_awg(AWG_EXAMPLE, live)
    assert count >= 1, lines
    assert expected in "\n".join(lines), lines


def test_unmarked_peer_is_reported_as_info_but_not_drift(sync, tmp_path: Path) -> None:
    """A hand-added peer is not a config error, but it is invisible to the bot while
    still holding an address out of AWG_NETWORK. It must never pass silently."""
    live = tmp_path / "awg0.conf"
    live.write_text(
        _live_awg() + "\n[Peer]\nPublicKey = hand-added\nAllowedIPs = 10.0.0.9/32\n",
        encoding="utf-8",
    )
    count, lines = sync.check_awg(AWG_EXAMPLE, live)
    assert count == 0, lines
    joined = "\n".join(lines)
    assert "1 hand-added" in joined
    assert "INFO" in joined and "no vpn-bot marker" in joined


# --------------------------------------------------------------------------- #
# 2b. check_hysteria: the one config that is operator-owned END TO END
#
# No region is excluded here, because none of it is runtime state — the bot
# manages Hysteria2 users over the HTTP auth service and never edits this file.
# So the comparison is the whole document, and the interesting cases are the ones
# that must NOT be drift: comments, key order, and the placeholder secret.
#
# PyYAML is not a project dependency (see the guarded import in the script), so
# these drive the checker through a stub parser built on the YAML subset the
# tracked config is written in. That keeps them running in CI, where PyYAML is
# absent; test_hysteria_parses_the_same_under_real_pyyaml cross-checks against the
# real library wherever one is installed.
# --------------------------------------------------------------------------- #
class _StubYAMLError(Exception):
    pass


class _StubYAML:
    """The `_yaml` surface check_hysteria uses: safe_load + YAMLError."""

    YAMLError = _StubYAMLError

    @staticmethod
    def safe_load(text: str) -> Any:
        try:
            return parse_block_mapping(text)
        except ValueError as exc:  # what a real parser raises on malformed input
            raise _StubYAMLError(str(exc)) from exc


@pytest.fixture
def hy2(sync, monkeypatch) -> ModuleType:
    """`sync` with YAML parsing forced through the subset stub."""
    monkeypatch.setattr(sync, "_yaml", _StubYAML)
    return sync


def _live_hy2() -> str:
    """A plausible live config: the tracked one with the placeholder secret filled
    in, exactly as install-config.sh leaves it on disk."""
    return HY2_CONFIG.read_text(encoding="utf-8").replace(
        '"<random-secret>"', "d34dbe3fd34dbe3fd34dbe3fd34dbe3f"
    )


def test_clean_hysteria_reports_no_drift(hy2, tmp_path: Path) -> None:
    live = tmp_path / "config.yaml"
    live.write_text(_live_hy2(), encoding="utf-8")
    count, lines = hy2.check_hysteria(HY2_CONFIG, live)
    assert count == 0, lines
    # The census reports the live layout without it affecting the verdict — that is
    # how an operator sees a `file` host is still a `file` host.
    assert "masquerade type: 'proxy'" in "\n".join(lines), lines


def test_hysteria_placeholder_secret_matches_any_live_value(hy2, tmp_path: Path) -> None:
    """`secret: "<random-secret>"` is the one placeholder in this file, and its
    lowercase-hyphen spelling is pinned by install-config.sh and its tests. If the
    checker's placeholder pattern stopped covering it, every host with a real stats
    secret — i.e. every host — would report drift on this key forever."""
    live = tmp_path / "config.yaml"
    live.write_text(
        HY2_CONFIG.read_text(encoding="utf-8").replace('"<random-secret>"', "zzz"),
        encoding="utf-8",
    )
    count, lines = hy2.check_hysteria(HY2_CONFIG, live)
    assert count == 0, lines


def test_hysteria_comments_and_key_order_are_invisible(hy2, tmp_path: Path) -> None:
    """The tracked file carries a long rationale in comments that the host does not,
    and install-config.sh does not preserve key order. Comparing parsed data rather
    than text is what keeps both from being reported on every host."""
    parsed = parse_block_mapping(_live_hy2())
    reordered = "\n".join(_dump_block_mapping(dict(reversed(list(parsed.items())))))
    live = tmp_path / "config.yaml"
    live.write_text(reordered + "\n", encoding="utf-8")
    assert "#" not in reordered, "the reshuffled fixture must carry no comments at all"

    count, lines = hy2.check_hysteria(HY2_CONFIG, live)
    assert count == 0, lines


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        pytest.param(
            lambda t: t.replace("type: proxy", "type: file"),
            "hy2.masquerade.type",
            id="masquerade-layout-reverted-to-file",
        ),
        pytest.param(
            lambda t: t.replace("up: 95 mbps", "up: 500 mbps"),
            "hy2.bandwidth.up",
            id="brutal-ceiling-raised-on-the-host",
        ),
        pytest.param(
            lambda t: t.replace("url: http://127.0.0.1:8444/auth", "url: http://127.0.0.1:9444/auth"),
            "hy2.auth.http.url",
            id="auth-endpoint-moved-away-from-hy2_auth",
        ),
        pytest.param(
            lambda t: t.replace("listen: 127.0.0.1:9999", "listen: 0.0.0.0:9999"),
            "hy2.trafficStats.listen",
            id="stats-api-exposed-off-loopback",
        ),
        pytest.param(
            lambda t: t.replace("    insecure: true\n", "    insecure: true\n    something: else\n"),
            "EXTRA on host",
            id="undocumented-key-added",
        ),
        pytest.param(
            lambda t: t.replace("    rewriteHost: false\n", ""),
            "MISSING on host",
            id="key-dropped-on-the-host",
        ),
    ],
)
def test_hysteria_operator_drift_is_reported(hy2, tmp_path: Path, mutate, expected: str) -> None:
    """Every key in this file is operator structure, so any difference is a finding.
    That is the point: /etc/hysteria/config.yaml had no gate at all before, and
    install-config.sh will happily install over whatever the host had."""
    live = tmp_path / "config.yaml"
    live.write_text(mutate(_live_hy2()), encoding="utf-8")
    count, lines = hy2.check_hysteria(HY2_CONFIG, live)
    assert count >= 1, lines
    assert expected in "\n".join(lines), lines


def test_absent_hysteria_is_not_drift(sync, tmp_path: Path) -> None:
    """An Xray-only host has no /etc/hysteria/config.yaml. Checked without the stub
    on purpose: absent-ok must resolve before anything needs a YAML parser."""
    count, lines = sync.check_hysteria(HY2_CONFIG, tmp_path / "nope.yaml")
    assert count == 0
    assert "absent" in lines[0] and "not drift" in lines[0]


def test_missing_pyyaml_skips_loudly_instead_of_failing_the_deploy(sync, monkeypatch, tmp_path: Path) -> None:
    """PyYAML is not a project dependency and Phase 1 runs this script under the
    system python3. Without it this one backend must degrade to a visible SKIPPED
    line and exit 0 — turning a missing optional module into a failed deploy would
    be a regression on a file that had no gate at all before."""
    monkeypatch.setattr(sync, "_yaml", None)
    live = tmp_path / "config.yaml"
    live.write_text(_live_hy2(), encoding="utf-8")

    count, lines = sync.check_hysteria(HY2_CONFIG, live)
    assert count == 0
    joined = "\n".join(lines)
    assert "SKIPPED" in joined, joined
    assert "python3-yaml" in joined, "the skip must name the fix, not just the symptom"


def test_unparseable_hysteria_config_fails_closed(hy2, tmp_path: Path) -> None:
    """Same policy as unparseable JSON: no verdict was reachable, so exit 1 — which
    ALLOW_BACKEND_CONFIG_DRIFT deliberately does not waive."""
    live = tmp_path / "config.yaml"
    live.write_text("masquerade:\n\t\ttype: proxy\n", encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        hy2.check_hysteria(HY2_CONFIG, live)
    assert excinfo.value.code == EXIT_FAIL_CLOSED


def test_missing_tracked_hysteria_config_fails_closed(hy2, tmp_path: Path) -> None:
    live = tmp_path / "config.yaml"
    live.write_text(_live_hy2(), encoding="utf-8")
    with pytest.raises(SystemExit) as excinfo:
        hy2.check_hysteria(tmp_path / "nope.yaml", live)
    assert excinfo.value.code == EXIT_FAIL_CLOSED


def test_hysteria_parses_the_same_under_real_pyyaml(sync, tmp_path: Path) -> None:
    """Cross-check the stub above against a real YAML implementation wherever one is
    installed — the deploy host has python3-yaml, CI does not. Confidence only: it
    can never gate."""
    pytest.importorskip("yaml")
    assert sync._yaml is not None, "PyYAML is importable, so the script must have it too"

    live = tmp_path / "config.yaml"
    live.write_text(_live_hy2(), encoding="utf-8")
    assert sync.check_hysteria(HY2_CONFIG, live)[0] == 0

    live.write_text(_live_hy2().replace("type: proxy", "type: file"), encoding="utf-8")
    count, lines = sync.check_hysteria(HY2_CONFIG, live)
    assert count >= 1
    assert "hy2.masquerade.type" in "\n".join(lines), lines


# --------------------------------------------------------------------------- #
# 3. install-xray: every path that must refuse before touching anything
# --------------------------------------------------------------------------- #
def test_install_refuses_when_live_config_is_absent(sync, tmp_path: Path) -> None:
    """No bootstrap: the REALITY private key exists ONLY in the live file, so a
    merge with nothing to merge into would write `<REALITY_PRIVATE_KEY>` into a
    load-bearing config."""
    with pytest.raises(SystemExit) as exc:
        sync.install_xray(
            SKELETON, tmp_path / "nope.json", tmp_path / ".env",
            dry_run=False, xray_bin="/bin/true",
        )
    assert exc.value.code == EXIT_FAIL_CLOSED


def test_install_refuses_a_config_with_no_clients_list(sync, tmp_path: Path) -> None:
    config = _live_from_skeleton()
    for inbound in config["inbounds"]:
        inbound.get("settings", {}).pop("clients", None)
    live = _write(tmp_path / "config.json", config)
    with pytest.raises(SystemExit) as exc:
        sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=False, xray_bin="/bin/true")
    assert exc.value.code == EXIT_FAIL_CLOSED


def test_install_refuses_on_an_unresolvable_placeholder(sync, tmp_path: Path) -> None:
    """A placeholder with neither an .env mapping nor a live value to preserve. The
    live config here has clients (so the earlier guard passes) but no privateKey."""
    config = _live_from_skeleton()
    config["inbounds"][0]["settings"]["clients"] = [{"id": "u", "email": "k"}]
    config["inbounds"][0]["streamSettings"]["realitySettings"].pop("privateKey")
    live = _write(tmp_path / "config.json", config)
    with pytest.raises(SystemExit) as exc:
        sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=False, xray_bin="/bin/true")
    assert exc.value.code == EXIT_FAIL_CLOSED


def test_install_refuses_when_a_skeleton_tag_does_not_match_the_host(sync, tmp_path: Path) -> None:
    """The tag is how clients are put back. If the skeleton names an inbound the
    host does not have, the merge would silently drop that inbound's keys — so the
    client-count assertion has to catch it before anything is written."""
    config = _live_from_skeleton()
    config["inbounds"][0]["tag"] = "vless-in-renamed"
    config["inbounds"][0]["settings"]["clients"] = [{"id": "u", "email": "k"}]
    live = _write(tmp_path / "config.json", config)
    with pytest.raises(SystemExit) as exc:
        sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=False, xray_bin="/bin/true")
    assert exc.value.code == EXIT_FAIL_CLOSED


def test_install_refuses_without_the_xray_binary(sync, tmp_path: Path) -> None:
    """An unvalidated config over a live one would take :443 down on the next
    restart — and the bot's own writes would then fail on a file it cannot parse."""
    config = _live_from_skeleton()
    config["inbounds"][0]["settings"]["clients"] = [{"id": "u", "email": "k"}]
    live = _write(tmp_path / "config.json", config)
    before = live.read_text(encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=False, xray_bin=None)
    assert exc.value.code == EXIT_FAIL_CLOSED
    assert live.read_text(encoding="utf-8") == before, "refused but wrote anyway"
    assert not list(tmp_path.glob(".backend-config-sync.*")), "left a temp file behind"


def test_install_refuses_when_xray_rejects_the_merged_config(sync, tmp_path: Path) -> None:
    config = _live_from_skeleton()
    config["inbounds"][0]["settings"]["clients"] = [{"id": "u", "email": "k"}]
    live = _write(tmp_path / "config.json", config)
    before = live.read_text(encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=False, xray_bin="/bin/false")
    assert exc.value.code == EXIT_FAIL_CLOSED
    assert live.read_text(encoding="utf-8") == before
    assert not live.with_suffix(".json.pre-sync").exists(), "backed up a config it never replaced"


def test_install_writes_preserves_mode_and_keeps_a_backup(sync, tmp_path: Path) -> None:
    """The only path with side effects. xray_bin is a stub that accepts anything, so
    this exercises the write itself: mode preserved (the file is read by the xray
    service, not by us), previous copy kept, temp file gone, keys intact."""
    config = _live_from_skeleton()
    clients = [{"id": f"uuid-{n}", "email": f"key-{n}"} for n in range(3)]
    config["inbounds"][0]["settings"]["clients"] = list(clients)
    config["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"] = ["ab12", "cd34"]
    live = _write(tmp_path / "config.json", config)
    live.chmod(0o640)
    before = live.read_text(encoding="utf-8")

    rc = sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=False, xray_bin="/bin/true")
    assert rc == EXIT_OK

    written = json.loads(live.read_text(encoding="utf-8"))
    by_tag = {ib["tag"]: ib for ib in written["inbounds"]}
    assert by_tag["vless-in"]["settings"]["clients"] == clients
    assert by_tag["vless-in"]["streamSettings"]["realitySettings"]["shortIds"] == ["ab12", "cd34"]
    assert live.stat().st_mode & 0o777 == 0o640, "mode not preserved"

    backup = live.with_suffix(".json.pre-sync")
    assert backup.read_text(encoding="utf-8") == before, "previous config not kept"
    assert not list(tmp_path.glob(".backend-config-sync.*")), "left a temp file behind"


def test_dry_run_writes_nothing_and_preserves_every_client(sync, tmp_path: Path, capsys) -> None:
    config = _live_from_skeleton()
    clients = [{"id": f"uuid-{n}", "email": f"key-{n}"} for n in range(5)]
    config["inbounds"][0]["settings"]["clients"] = list(clients)
    config["inbounds"][2]["settings"]["clients"] = list(clients[:2])
    apply_warp_send_through(config, "172.16.0.2")
    live = _write(tmp_path / "config.json", config)
    before = live.read_text(encoding="utf-8")

    rc = sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=True, xray_bin=None)
    assert rc == EXIT_OK
    assert live.read_text(encoding="utf-8") == before

    merged = json.loads(capsys.readouterr().out)
    by_tag = {ib["tag"]: ib for ib in merged["inbounds"]}
    assert by_tag["vless-in"]["settings"]["clients"] == clients
    assert by_tag["vless-xhttp-reality"]["settings"]["clients"] == clients[:2]
    assert merged["outbounds"][0]["sendThrough"] == "172.16.0.2"
    assert "<" not in json.dumps(merged), "an unresolved placeholder survived into the merge"


def test_dry_run_on_a_clean_host_is_semantically_a_noop(sync, tmp_path: Path, capsys) -> None:
    """The property that makes the installer safe to reach for: at zero drift it
    changes nothing but formatting."""
    config = _live_from_skeleton()
    config["inbounds"][0]["settings"]["clients"] = [{"id": "u", "email": "k"}]
    live = _write(tmp_path / "config.json", config)
    sync.install_xray(SKELETON, live, tmp_path / ".env", dry_run=True, xray_bin=None)
    assert json.loads(capsys.readouterr().out) == config


def test_env_mapping_wins_over_the_live_value(sync, tmp_path: Path, capsys) -> None:
    """XRAY_SNI is how the operator changes the decoy: .env is the intent, the live
    file only the current state, so the mapping must take precedence."""
    config = _live_from_skeleton()
    config["inbounds"][0]["settings"]["clients"] = [{"id": "u", "email": "k"}]
    live = _write(tmp_path / "config.json", config)
    env = tmp_path / ".env"
    env.write_text("XRAY_SNI=new-decoy.example.invalid\n", encoding="utf-8")

    sync.install_xray(SKELETON, live, env, dry_run=True, xray_bin=None)
    merged = json.loads(capsys.readouterr().out)
    reality = merged["inbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["serverNames"] == ["new-decoy.example.invalid"]
    # ...while the secret with no .env source is still preserved from the host.
    assert reality["privateKey"] == "live-private-key-placeholder"


def test_commented_out_env_line_is_not_a_value(sync, tmp_path: Path) -> None:
    assert sync.read_env(_env(tmp_path, "# XRAY_SNI=commented\nXRAY_SNI=real\n")) == {
        "XRAY_SNI": "real"
    }


def _env(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# 4. The script's own selftest and CLI contract
# --------------------------------------------------------------------------- #
def test_selftest_passes(sync) -> None:
    assert sync.selftest() == EXIT_OK


def test_check_exits_3_on_drift_and_0_when_clean(hy2, tmp_path: Path) -> None:
    """The exit codes are the gate's contract with deploy.sh: 3 means drift, and
    nothing else may.

    Every live path is injected into tmp_path, including the hysteria one. Left at
    its default this would read /etc/hysteria/config.yaml — and this suite runs on
    the production host as a Phase 1 gate. YAML goes through the subset stub so the
    verdict is the same in CI, where PyYAML is absent, as on the host.
    """
    repo = tmp_path / "repo"
    (repo / "deploy" / "xray").mkdir(parents=True)
    (repo / "deploy" / "awg").mkdir(parents=True)
    (repo / "deploy" / "hysteria").mkdir(parents=True)
    (repo / "deploy" / "xray" / "config.skeleton.json").write_text(
        SKELETON.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (repo / "deploy" / "awg" / "awg0.conf.example").write_text(
        AWG_EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (repo / "deploy" / "hysteria" / "config.yaml").write_text(
        HY2_CONFIG.read_text(encoding="utf-8"), encoding="utf-8"
    )
    live = _write(tmp_path / "config.json", _live_from_skeleton())
    awg = tmp_path / "awg0.conf"
    awg.write_text(_live_awg(), encoding="utf-8")
    hy2_live = tmp_path / "hysteria.yaml"
    hy2_live.write_text(_live_hy2(), encoding="utf-8")
    argv = [
        "check",
        "--repo-root", str(repo),
        "--xray-config", str(live),
        "--awg-config", str(awg),
        "--hysteria-config", str(hy2_live),
    ]

    assert hy2.main(argv) == EXIT_OK

    drifted = _live_from_skeleton()
    drifted["log"]["loglevel"] = "warning"
    _write(live, drifted)
    assert hy2.main(argv) == EXIT_DRIFT

    # ...and a hysteria-only difference reaches the same exit code, so the third
    # backend is really summed into the verdict rather than only reported.
    _write(live, _live_from_skeleton())
    assert hy2.main(argv) == EXIT_OK
    hy2_live.write_text(_live_hy2().replace("type: proxy", "type: file"), encoding="utf-8")
    assert hy2.main(argv) == EXIT_DRIFT


def test_no_subcommand_is_a_usage_error(sync) -> None:
    assert sync.main([]) == 2


def test_skeleton_ships_no_bot_state_and_no_secrets() -> None:
    """The skeleton is committed, so it must hold structure only: empty bot-owned
    lists, and a placeholder wherever a real deployment has a secret."""
    skeleton = _skeleton()
    for inbound in skeleton["inbounds"]:
        clients = inbound.get("settings", {}).get("clients")
        if clients is not None:
            assert clients == [], f"{inbound['tag']} ships clients"
        reality = inbound.get("streamSettings", {}).get("realitySettings")
        if reality is not None:
            assert reality.get("shortIds") == [], f"{inbound['tag']} ships shortIds"
            assert reality["privateKey"] == "<REALITY_PRIVATE_KEY>"
            assert reality["serverNames"] == ["<REALITY_SERVER_NAME>"]
    for outbound in skeleton["outbounds"]:
        assert "sendThrough" not in outbound, "the skeleton must not pin WARP egress"
    # The example must ship no peer — checked over its DIRECTIVES only, since the
    # header prose necessarily names [Peer] to explain who owns it.
    directives = [
        line for line in AWG_EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert "[Peer]" not in directives, "the example ships a peer"
    assert directives[0] == "[Interface]", directives[:3]


# --------------------------------------------------------------------------- #
# 5. deploy.sh wiring — the gate exists, is documented, and is bypassable exactly
#    the way the other drift gates are
# --------------------------------------------------------------------------- #
def test_deploy_sh_runs_the_checker_against_the_origin_main_worktree() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert '"$WT/deploy/backend-config-sync.py" check' in text, "checker not wired into Phase 1"
    assert '--repo-root "$WT"' in text, "must compare against origin/main, not the live checkout"
    assert '--xray-config "$XRAY_CONF"' in text
    assert '--awg-config "$AWG_CONF"' in text
    # The live path is overridable like the other two, and defaults to where the
    # hysteria package puts it — a host that moved the file overrides the variable
    # instead of the gate reporting a phantom absent backend.
    assert '--hysteria-config "$HYSTERIA_CONF"' in text
    assert 'HYSTERIA_CONF="${HYSTERIA_CONF:-/etc/hysteria/config.yaml}"' in text


def test_deploy_sh_prints_the_hysteria_repair_route_too() -> None:
    """The checker cannot know which side is wrong, so the drift report names the
    repair route for each backend. Hysteria2's is a whole-file install, not a merge
    — an operator handed only `install-xray` would reach for a tool that cannot
    touch this file."""
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert "deploy/hysteria/install-config.sh" in text, "no hy2 repair route in the report"
    assert "deploy/hysteria/config.yaml" in text, "no route for when the REPO is the wrong side"


def test_deploy_sh_gate_is_documented_and_defaults_to_enforcing() -> None:
    text = DEPLOY_SH.read_text(encoding="utf-8")
    assert 'ALLOW_BACKEND_CONFIG_DRIFT="${ALLOW_BACKEND_CONFIG_DRIFT:-0}"' in text
    assert "#   ALLOW_BACKEND_CONFIG_DRIFT=1" in text, "undocumented bypass knob"
    # Same three-way as ALLOW_UNIT_DRIFT: bypass, inspection mode, otherwise die.
    assert 'if [[ "$ALLOW_BACKEND_CONFIG_DRIFT" == "1" ]]' in text
    assert 'die "backend config drift detected' in text
    assert 'die "backend-config-sync.py check could not run' in text, (
        "exit 1 (no verdict reachable) must not be waivable by the drift knob"
    )
