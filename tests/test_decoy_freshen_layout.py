"""Guard the two halves of ONE contract: the masquerade layout the tracked hysteria
config declares, and the mirror step deploy/vpn-bot-decoy-freshen.sh runs because of it.

WHY THIS IS A SUITE AND NOT A COMMENT

Two data planes on this host answer an unauthenticated probe with a real website
instead of a reset — Xray REALITY over TCP/443 (self-steal `target`) and Hysteria2
over UDP/443 (masquerade) — and they must answer with the SAME one. A probe that
gets two different sites, or a site from one plane and a bare 404 from the other, is
precisely the fingerprint the decoy exists to remove.

How Hysteria2 gets that site is a single key, `masquerade.type`, and the two values
are not interchangeable:

  * `type: proxy` (what deploy/hysteria/config.yaml ships) reverse-proxies the same
    local HTTPS listener REALITY targets. One docroot, one source of truth, nothing
    to mirror — and nothing that can go stale.
  * `type: file` (legacy) makes Hysteria2 read MASQ_DIR itself, as an unprivileged
    daemon that cannot read the nginx docroot. Now there are two trees, and the
    mirror in vpn-bot-decoy-freshen.sh is the only thing keeping them equal.

So a silent revert of that key is not a formatting change: it takes the mirror from
"correctly does nothing" to "load-bearing", or the other way round leaves a stale
second copy on disk that looks authoritative to whoever finds it next. This suite
pins the declared layout, and drives the REAL hook to assert it branches on the
LIVE value rather than on an assumption.

Everything runs in tmp_path against injected paths — HYSTERIA_CONF, DECOY_ROOT and
MASQ_DIR are all environment knobs precisely so this is possible. Nothing here reads
/etc/hysteria, and the one non-dry run is on the proxy layout, where the hook's only
side effect is calling the freshener.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_hysteria_config_bandwidth import parse_block_mapping


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "deploy" / "vpn-bot-decoy-freshen.sh"
REPO_CONFIG = ROOT / "deploy" / "hysteria" / "config.yaml"

pytestmark = pytest.mark.timeout(60)


def _config() -> dict:
    return parse_block_mapping(REPO_CONFIG.read_text(encoding="utf-8"))


def _normalise_bool(value: object) -> object:
    """The subset parser returns scalars as text; fold YAML's boolean spellings."""
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "on"):
            return True
        if lowered in ("false", "no", "off"):
            return False
    return value


# --------------------------------------------------------------------------- #
# 1. The layout the tracked config declares
# --------------------------------------------------------------------------- #
def test_tracked_config_declares_the_proxy_masquerade() -> None:
    """`install-config.sh` installs this file wholesale, so whatever it says here is
    what the host serves after the next install. Reverting to `type: file` would put
    the second, mirror-fed tree back — the exact drift risk the proxy layout removed."""
    masquerade = _config()["masquerade"]
    assert isinstance(masquerade, dict), "masquerade must be a mapping"
    assert masquerade.get("type") == "proxy", masquerade
    assert "file" not in masquerade, "a proxy masquerade must not also carry a file dir"

    proxy = masquerade.get("proxy")
    assert isinstance(proxy, dict), "type: proxy needs a proxy block"
    # Loopback only: the point is to reuse the listener REALITY already falls back
    # to, not to reach off-box. https, because that listener speaks TLS.
    assert proxy.get("url", "").startswith("https://127.0.0.1:"), proxy
    # Keep the client's Host header so the local server picks the same vhost it
    # would over TCP — rewriting it can select a different one, i.e. a different site.
    assert _normalise_bool(proxy.get("rewriteHost")) is False, proxy
    # The peer is an address literal, so no certificate name can ever match it.
    assert _normalise_bool(proxy.get("insecure")) is True, proxy


def test_tracked_config_declares_no_plaintext_listeners() -> None:
    """listenHTTP/listenHTTPS would open separate plaintext TCP :80/:443 listeners.
    TCP/443 here is Xray REALITY, so that is a port collision, not an alternative —
    the decoy rides the existing UDP/443 QUIC path instead."""
    config = _config()
    assert "listenHTTP" not in config
    assert "listenHTTPS" not in config


# --------------------------------------------------------------------------- #
# 2. The hook branches on the LIVE layout
# --------------------------------------------------------------------------- #
def _sandbox(tmp_path: Path, masq_type: str | None) -> tuple[Path, Path, dict[str, str]]:
    """A decoy source, an absent MASQ_DIR under an existing parent, and the env that
    points the hook at both. `masq_type=None` writes no hysteria config at all."""
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / "index.html").write_text("<html>site</html>\n", encoding="utf-8")

    masq_parent = tmp_path / "masq-parent"
    masq_parent.mkdir()
    masq_dir = masq_parent / "masq"

    env = dict(os.environ)
    # Every knob the hook reads is popped first: an inherited MASQ_OWNER or
    # DECOY_FRESHEN_HOOK from the operator's shell would quietly change what these
    # tests assert, and the owner/group defaults are themselves pinned below.
    for knob in ("MASQ_OWNER", "MASQ_GROUP", "DECOY_FRESHEN_HOOK", "INDEX_NAME"):
        env.pop(knob, None)
    env["DECOY_ROOT"] = str(decoy)
    env["MASQ_DIR"] = str(masq_dir)
    if masq_type is None:
        env["HYSTERIA_CONF"] = str(tmp_path / "no-such-config.yaml")
    else:
        conf = tmp_path / "config.yaml"
        conf.write_text(
            # Ordered as the real file is: `auth.type` comes BEFORE `masquerade`, so a
            # reader that matched `type:` anywhere would pick up `http` instead.
            "listen: :443\n"
            "auth:\n  type: http\n  http:\n    url: http://127.0.0.1:8444/auth\n"
            "trafficStats:\n  listen: 127.0.0.1:9999\n  secret: \"x\"\n"
            f"masquerade:\n  type: {masq_type}\n",
            encoding="utf-8",
        )
        env["HYSTERIA_CONF"] = str(conf)
    return decoy, masq_dir, env


def _run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    if shutil.which("bash") is None:
        pytest.skip("bash is not available")
    return subprocess.run(
        ["bash", str(HOOK), *args],
        env=env,
        capture_output=True,
        text=True,
    )


@pytest.fixture(autouse=True)
def _needs_rsync() -> None:
    # The hook fails closed without rsync, by design — that refusal is its own
    # guard, not something to assert around here.
    if shutil.which("rsync") is None:
        pytest.skip("rsync is not installed")


def test_proxy_layout_skips_the_mirror_and_says_why(tmp_path: Path) -> None:
    _decoy, masq_dir, env = _sandbox(tmp_path, "proxy")

    result = _run(env, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "skipping the Hysteria2 mirror" in result.stdout, result.stdout
    assert "masquerade.type: proxy" in result.stdout, result.stdout
    assert "single source of truth" in result.stdout, result.stdout
    # Not merely unmentioned — never even proposed.
    assert "rsync" not in result.stdout, result.stdout
    assert not masq_dir.exists(), "the proxy layout must leave MASQ_DIR alone"


def test_legacy_file_layout_still_mirrors(tmp_path: Path) -> None:
    """The guard must not turn into "never mirror": on a `type: file` host the mirror
    IS the mechanism, and skipping it leaves Hysteria2 answering probes with a 404
    while nginx answers with a site."""
    decoy, masq_dir, env = _sandbox(tmp_path, "file")

    result = _run(env, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "skipping the Hysteria2 mirror" not in result.stdout, result.stdout
    assert f"rsync -a --delete {decoy}/ {masq_dir}/" in result.stdout, result.stdout
    # Re-asserted every pass, not once at install: rsync preserves the nginx-side
    # ownership and the daemon reads this tree as an unprivileged user.
    assert f"chown -R hysteria:hysteria {masq_dir}" in result.stdout, result.stdout
    assert not masq_dir.exists(), "--dry-run must not create anything"


def test_unreadable_layout_skips_rather_than_guessing(tmp_path: Path) -> None:
    """An Xray-only host, or a config this reader cannot see, must not be treated as
    either layout: mirroring on a guess is what writes the stale second copy."""
    _decoy, masq_dir, env = _sandbox(tmp_path, None)

    result = _run(env, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "could not read masquerade.type" in result.stdout, result.stdout
    assert "rsync" not in result.stdout, result.stdout
    assert not masq_dir.exists()


def test_masquerade_without_a_type_is_not_read_as_the_auth_type(tmp_path: Path) -> None:
    """`auth.type: http` sits above `masquerade:` in the real file. A reader that
    matched `type:` outside the block would see `http`, fall through to the else
    branch and mirror on a host that never reads MASQ_DIR."""
    _decoy, _masq_dir, env = _sandbox(tmp_path, "proxy")
    conf = Path(env["HYSTERIA_CONF"])
    conf.write_text(
        conf.read_text(encoding="utf-8").replace("  type: proxy\n", "  proxy:\n    url: x\n"),
        encoding="utf-8",
    )

    result = _run(env, "--dry-run")

    assert result.returncode == 0, result.stderr
    assert "could not read masquerade.type" in result.stdout, result.stdout
    assert "rsync" not in result.stdout, result.stdout


def test_the_freshness_pass_is_layout_independent(tmp_path: Path) -> None:
    """The freshener advances the decoy's rolling timestamps, which both planes serve
    — so it runs on every layout, including the one where nothing is mirrored. This
    is the half an operator migrating off an untracked predecessor keeps, so it must
    not quietly become conditional on the mirror.

    Run for real, not --dry-run: under the proxy layout the hook's only side effect
    is this call.
    """
    _decoy, masq_dir, env = _sandbox(tmp_path, "proxy")
    marker = tmp_path / "freshened"
    freshener = tmp_path / "rewrite-timestamps.sh"
    freshener.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    freshener.chmod(0o755)
    env["DECOY_FRESHEN_HOOK"] = str(freshener)

    result = _run(env)

    assert result.returncode == 0, result.stderr
    assert marker.exists(), result.stdout
    assert "skipping the Hysteria2 mirror" in result.stdout, result.stdout
    assert not masq_dir.exists(), "still nothing mirrored"


def test_non_executable_freshener_fails_closed(tmp_path: Path) -> None:
    """A rewriter only ever invoked as `python3 rewrite.py` is typically mode 0644.
    Guessing an interpreter would run the wrong thing; a half-run freshener would
    publish inconsistent dates. So this refuses, loudly, before touching anything."""
    _decoy, _masq_dir, env = _sandbox(tmp_path, "proxy")
    freshener = tmp_path / "rewrite-timestamps.py"
    freshener.write_text("print('nope')\n", encoding="utf-8")
    freshener.chmod(0o644)
    env["DECOY_FRESHEN_HOOK"] = str(freshener)

    result = _run(env, "--dry-run")

    assert result.returncode == 1
    assert "not executable" in result.stdout, result.stdout


def test_missing_decoy_root_refuses_before_touching_anything(tmp_path: Path) -> None:
    """`rsync --delete` pointed at an empty source faithfully empties the target. The
    refusal has to come before step 1, not as an rsync error afterwards."""
    _decoy, masq_dir, env = _sandbox(tmp_path, "file")
    env["DECOY_ROOT"] = str(tmp_path / "gone")

    result = _run(env, "--dry-run")

    assert result.returncode == 1
    assert "FATAL" in result.stdout, result.stdout
    assert not masq_dir.exists()
