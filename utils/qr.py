"""QR rendering for the connection configs the bot hands to a user.

One helper, :func:`render_config_qr`, turns whatever text a user would paste into
a client (an AmneziaWG ``.conf``, a ``vless://``/``hysteria2://`` URI, a bundle
sub-URL) into PNG bytes. It renders in memory — no temp file ever holds a
credential, which matters because every payload here IS the credential.

Capacity is checked, never worked around: :func:`render_config_qr` raises
:class:`QrPayloadTooLarge` rather than encoding a truncated config, because a QR
that scans into a half config is worse than no QR at all — the user would import
it, fail to connect, and have nothing pointing at why.
"""

from __future__ import annotations

import io

import qrcode
from qrcode.constants import ERROR_CORRECT_M

# Medium error correction (~15% recoverable). L would fit more bytes per version,
# but these codes are photographed off a phone screen at an angle, often through
# a chat client's image compression, so the redundancy is worth more than the
# headroom: even the largest payload here (an AWG .conf, ~460 bytes) lands around
# version 17 of 40, leaving the ceiling far away.
_ERROR_CORRECTION = ERROR_CORRECT_M

# Pixels per module and the quiet-zone width in modules. 8 keeps a version-17
# code near ~800px — big enough to scan off a phone screen without Telegram's
# image pipeline resampling the modules into mush. 4 is the spec-mandated minimum
# quiet zone; scanners rely on it to find the code's edges.
_BOX_SIZE = 8
_BORDER = 4

# Version 40 is the largest QR the standard defines. With ERROR_CORRECT_M in byte
# mode that is 2331 bytes; ``qrcode`` refuses once a payload cannot be fitted, and
# we translate that into our own error below. For reference, at that ceiling the
# real payloads sit far below it: an AWG .conf ~460 bytes (version 17), a VLESS
# xhttp URI ~250 (version 11), hysteria2 ~90 (version 6), a bundle sub-URL ~75
# (version 5).
_MAX_VERSION = 40


class QrPayloadTooLarge(ValueError):
    """Raised when a config does not fit in a QR code at all.

    Carries the payload's byte length so the caller can log/report the real size
    without re-deriving it. Never raised for anything this bot issues today; it
    exists so that a future config format that outgrows the standard fails loudly
    instead of shipping a QR that scans into a partial credential.
    """

    def __init__(self, byte_length: int) -> None:
        super().__init__(
            f"config of {byte_length} bytes does not fit a QR code "
            f"(max version {_MAX_VERSION}, error correction M)"
        )
        self.byte_length = byte_length


def render_config_qr(content: str) -> bytes:
    """Render ``content`` as a PNG QR code and return its bytes.

    ``content`` must be exactly what the user needs to connect — this function is
    deliberately dumb about protocols so the QR and the text/file delivered
    alongside it can never disagree about what was encoded.
    """
    if not content:
        raise ValueError("refusing to render a QR code for empty content")
    code = qrcode.QRCode(error_correction=_ERROR_CORRECTION, box_size=_BOX_SIZE, border=_BORDER)
    code.add_data(content)
    try:
        # fit=True picks the smallest version that holds the payload. Overflow
        # surfaces two different ways depending on where ``qrcode`` notices it:
        # ``DataOverflowError`` from the encoder, but a bare
        # ``ValueError("Invalid version (was 41, ...)")`` from ``best_fit`` when the
        # search for a version runs off the end of the table — which is the path a
        # too-large payload actually takes. Both mean the same thing here, and the
        # only inputs to ``make`` are the payload and the EC level, so neither can
        # be some other kind of ValueError.
        code.make(fit=True)
    except (qrcode.exceptions.DataOverflowError, ValueError) as exc:
        raise QrPayloadTooLarge(len(content.encode("utf-8"))) from exc
    buffer = io.BytesIO()
    code.make_image().save(buffer, format="PNG")
    return buffer.getvalue()
