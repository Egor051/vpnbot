"""Unit tests for the AmneziaWG config validator used by the WARP module."""
from __future__ import annotations

import pytest

from warp.config_validator import (
    WarpConfig,
    WarpConfigError,
    extract_allowed_ips,
    validate_amnezia_config,
)

VALID_AMNEZIA = """\
[Interface]
PrivateKey = aGVsbG8gd29ybGQgcHJpdmF0ZSBrZXkgYmFzZTY0AA=
Address = 10.0.0.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 50
S2 = 100
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = cHVibGljIGtleSBiYXNlNjQgZW5jb2RlZCB2YWx1ZQA=
PresharedKey = cHJlc2hhcmVkIGtleSBiYXNlNjQgZW5jb2RlZCBhYQA=
AllowedIPs = 149.154.160.0/20, 91.108.4.0/22, 8.8.8.8/32
Endpoint = 198.51.100.10:51820
"""

PLAIN_WIREGUARD = """\
[Interface]
PrivateKey = aGVsbG8gd29ybGQgcHJpdmF0ZSBrZXkgYmFzZTY0AA=
Address = 10.0.0.2/32

[Peer]
PublicKey = cHVibGljIGtleSBiYXNlNjQgZW5jb2RlZCB2YWx1ZQA=
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.10:51820
"""


def test_valid_amnezia_config_returns_allowed_ips() -> None:
    result = validate_amnezia_config(VALID_AMNEZIA)
    assert isinstance(result, WarpConfig)
    assert result.allowed_ips == ("149.154.160.0/20", "91.108.4.0/22", "8.8.8.8/32")


def test_allowed_ips_not_modified() -> None:
    """The CIDR list must be extracted verbatim, never normalised or replaced."""
    original = "AllowedIPs = 149.154.160.0/20,91.108.4.0/22 , 2001:db8::/32"
    config = VALID_AMNEZIA.replace(
        "AllowedIPs = 149.154.160.0/20, 91.108.4.0/22, 8.8.8.8/32", original
    )
    result = validate_amnezia_config(config)
    assert result.allowed_ips == ("149.154.160.0/20", "91.108.4.0/22", "2001:db8::/32")
    # The single AllowedIPs line in the source config is untouched.
    assert original in config


def test_extract_allowed_ips_preserves_tokens() -> None:
    assert extract_allowed_ips("AllowedIPs = 10.0.0.0/8") == ("10.0.0.0/8",)
    assert extract_allowed_ips("AllowedIPs = a, b ,c,") == ("a", "b", "c")


def test_missing_interface_section_rejected() -> None:
    config = VALID_AMNEZIA.replace("[Interface]", "[Iface]")
    with pytest.raises(WarpConfigError, match="Interface"):
        validate_amnezia_config(config)


def test_missing_peer_section_rejected() -> None:
    config = VALID_AMNEZIA.replace("[Peer]", "[Friend]")
    with pytest.raises(WarpConfigError, match="Peer"):
        validate_amnezia_config(config)


@pytest.mark.parametrize("field", ["PrivateKey", "PublicKey", "Endpoint"])
def test_missing_required_field_rejected(field: str) -> None:
    config = "\n".join(line for line in VALID_AMNEZIA.splitlines() if not line.startswith(field))
    with pytest.raises(WarpConfigError, match=field):
        validate_amnezia_config(config)


def test_plain_wireguard_rejected() -> None:
    with pytest.raises(WarpConfigError, match="WireGuard"):
        validate_amnezia_config(PLAIN_WIREGUARD)


@pytest.mark.parametrize("marker", ["Jc", "S1", "S2"])
def test_missing_amnezia_marker_rejected(marker: str) -> None:
    config = "\n".join(
        line for line in VALID_AMNEZIA.splitlines() if not line.startswith(f"{marker} ")
    )
    with pytest.raises(WarpConfigError, match="WireGuard"):
        validate_amnezia_config(config)


def test_empty_allowed_ips_rejected() -> None:
    config = VALID_AMNEZIA.replace(
        "AllowedIPs = 149.154.160.0/20, 91.108.4.0/22, 8.8.8.8/32", "AllowedIPs = "
    )
    with pytest.raises(WarpConfigError, match="AllowedIPs"):
        validate_amnezia_config(config)


def test_missing_allowed_ips_line_rejected() -> None:
    config = "\n".join(
        line for line in VALID_AMNEZIA.splitlines() if not line.startswith("AllowedIPs")
    )
    with pytest.raises(WarpConfigError, match="AllowedIPs"):
        validate_amnezia_config(config)


def test_invalid_cidr_rejected() -> None:
    config = VALID_AMNEZIA.replace(
        "AllowedIPs = 149.154.160.0/20, 91.108.4.0/22, 8.8.8.8/32",
        "AllowedIPs = 10.0.0.0/8, not-a-cidr, also-bad",
    )
    with pytest.raises(WarpConfigError, match="некорректные CIDR"):
        validate_amnezia_config(config)
