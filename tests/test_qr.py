"""Unit coverage for :mod:`utils.qr`.

The round-trip assertions decode the rendered PNG with :mod:`tests.qr_decode`, a
from-the-spec decoder that reads the module grid out of the image — so "it
decodes back to the original content" means a scanner would read the same string,
not merely that ``qrcode`` agrees with itself.
"""

import pytest
from qrcode.constants import ERROR_CORRECT_M

from tests.qr_decode import decode_qr
from utils.qr import QrPayloadTooLarge, render_config_qr

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

# Real payload shapes, one per delivery path the «Конфиг» button drives.
_VLESS_XHTTP = (
    "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
    "?type=xhttp&path=%2Fxhttp-multi&mode=auto&security=reality"
    "&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&fp=chrome"
    "&sni=www.microsoft.com&sid=a1b2c3d4&spx=%2F&encryption=none#awg_A7kQz"
)
_VLESS_TCP = (
    "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
    "?type=tcp&security=reality&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
    "&fp=chrome&sni=www.microsoft.com&sid=a1b2c3d4&spx=%2F&encryption=none#awg_A7kQz"
)
_HYSTERIA2 = "hysteria2://c2VjcmV0dG9rZW4@vpn.example.com:443?sni=vpn.example.com#hy2_A7kQz"
_SUB_URL = "https://vpn.example.com:2096/sub/s3cr3t-subscription-token-value"
_AWG_CONF = """[Interface]
PrivateKey = aGVsbG93b3JsZHRoaXNpc2Fmb3J0eXRocmVlY2hhcmtleQ=
Address = 10.8.1.37/32
DNS = 1.1.1.1, 1.0.0.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 78
S2 = 129
H1 = 1234567891
H2 = 2345678912
H3 = 3456789123
H4 = 4567891234
MTU = 1280

[Peer]
PublicKey = c2VydmVycHVibGlja2V5YmFzZTY0Zm9ydHl0aHJlZWNoYXI=
PresharedKey = cHJlc2hhcmVka2V5YmFzZTY0Zm9ydHl0aHJlZWNoYXJzaGE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"""


def test_render_config_qr_returns_a_valid_png() -> None:
    png = render_config_qr(_SUB_URL)
    assert png.startswith(_PNG_MAGIC)
    # IEND terminates every PNG; a truncated buffer would not carry it.
    assert png.endswith(b"IEND\xaeB`\x82")


@pytest.mark.parametrize(
    "content",
    [_VLESS_XHTTP, _VLESS_TCP, _HYSTERIA2, _SUB_URL, _AWG_CONF],
    ids=["vless-xhttp", "vless-tcp", "hysteria2", "bundle-sub-url", "awg-conf"],
)
def test_render_config_qr_decodes_back_to_the_original_content(content: str) -> None:
    assert decode_qr(render_config_qr(content), error_correction=ERROR_CORRECT_M) == content


def test_render_config_qr_survives_non_ascii_labels() -> None:
    """A key note/label can be Cyrillic, which pushes the payload into UTF-8 bytes."""
    content = "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443#Ключ-Тест"
    assert decode_qr(render_config_qr(content), error_correction=ERROR_CORRECT_M) == content


def test_render_config_qr_rejects_empty_content() -> None:
    with pytest.raises(ValueError, match="empty content"):
        render_config_qr("")


def test_render_config_qr_refuses_to_truncate_an_oversized_payload() -> None:
    """Overflow must raise, never silently encode a partial credential.

    ``qrcode`` reports overflow two different ways — ``DataOverflowError`` from the
    encoder, a bare ``ValueError`` from ``best_fit`` running off the version table —
    and this payload takes the second path. Both have to surface as
    :class:`QrPayloadTooLarge`, or the caller cannot tell overflow from a bug.
    """
    # Two bytes per character in UTF-8, so this is ~2.4 KB — past the 2331-byte
    # byte-mode ceiling of version 40 at error correction M.
    content = "é" * 1200
    with pytest.raises(QrPayloadTooLarge) as excinfo:
        render_config_qr(content)
    assert excinfo.value.byte_length == 2400


def test_the_largest_payload_that_still_fits_round_trips() -> None:
    """The ceiling is real and just below it still works — no off-by-one at v40."""
    content = "é" * 1165  # 2330 bytes
    assert decode_qr(render_config_qr(content), error_correction=ERROR_CORRECT_M) == content


def test_the_awg_conf_sits_far_below_the_qr_ceiling() -> None:
    """Guard the capacity headroom the design relies on.

    The AWG ``.conf`` is the longest thing this bot ever encodes. If a future field
    pushes it near the ceiling, this fails while there is still room to react —
    rather than a user getting no QR in production.
    """
    assert len(_AWG_CONF.encode("utf-8")) < 1000
