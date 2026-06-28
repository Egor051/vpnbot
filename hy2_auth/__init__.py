"""Standalone Hysteria2 HTTP-auth endpoint (apernet v2 ``auth: type: http``).

This is an INDEPENDENT data-plane process, deliberately decoupled from the bot:
it must keep authenticating handshakes even when the bot is down. Therefore it
never imports ``bot`` or ``aiogram``, opens vpn.db strictly read-only, and binds
loopback only. Run it with ``python -m hy2_auth``.
"""

from hy2_auth.server import build_app
from hy2_auth.store import ReadOnlyKeyStore

__all__ = ["ReadOnlyKeyStore", "build_app"]
