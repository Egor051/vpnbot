"""Integrity checks for the WARP sudo helper scripts."""
from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
WARP_HELPERS = (
    "vpnbot-warp-install",
    "vpnbot-warp-iface",
    "vpnbot-warp-routes",
    "vpnbot-warp-status",
)


@pytest.mark.parametrize("name", WARP_HELPERS)
def test_helper_exists_with_bash_shebang(name: str) -> None:
    path = SCRIPTS / name
    assert path.exists(), f"missing helper: {name}"
    assert path.read_text(encoding="utf-8").startswith("#!/bin/bash")


@pytest.mark.parametrize("name", WARP_HELPERS)
def test_helper_is_executable(name: str) -> None:
    mode = (SCRIPTS / name).stat().st_mode
    assert mode & stat.S_IXUSR


def test_uses_awg_quick_not_wg_quick() -> None:
    """The module must drive AmneziaWG (awg-quick/awg), never plain wg-quick."""
    for name in ("vpnbot-warp-iface", "vpnbot-warp-status"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert "awg-quick" in text or "awg show" in text
        # "wg-quick"/"wg show" must not appear except as part of "awg-quick"/"awg show".
        assert re.search(r"(?<![a-z])wg-quick", text) is None
        assert re.search(r"(?<![a-z])wg show", text) is None


def test_routes_helper_reads_list_and_has_no_hardcoded_cidrs() -> None:
    text = (SCRIPTS / "vpnbot-warp-routes").read_text(encoding="utf-8")
    assert "tg-warp-routes.list" in text
    # No literal CIDR should be baked into the routes helper.
    assert re.search(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", text) is None


def test_install_helper_preprocessing_rules() -> None:
    text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    # Validates AmneziaWG markers.
    for marker in ("Jc", "S1", "S2", "AllowedIPs"):
        assert marker in text
    # Strips DNS, adds Table=off and PersistentKeepalive, writes routes.list.
    assert "DNS" in text
    assert "Table = off" in text
    assert "PersistentKeepalive = 25" in text
    assert "tg-warp-routes.list" in text


def test_no_helper_uses_shell_injection_patterns() -> None:
    for name in WARP_HELPERS:
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert "eval " not in text

    # The install helper must use a quoted here-doc delimiter so the shell does
    # not interpolate $SOURCE/$DEST/$ROUTES_LIST into the Python source code.
    install_text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    assert "<<'PYEOF'" in install_text or "<< 'PYEOF'" in install_text


def test_install_helper_validates_source_path() -> None:
    text = (SCRIPTS / "vpnbot-warp-install").read_text(encoding="utf-8")
    assert "ALLOWED_DIR" in text or "realpath" in text
