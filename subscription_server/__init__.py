"""Standalone all-in-one subscription endpoint (``GET /sub/{token}``).

An INDEPENDENT process, built to the same pattern as :mod:`hy2_auth`: it opens
``vpn.db`` strictly read-only, re-reads it on every request (no cache, so a
revoke takes effect immediately and without a restart), fails closed on any
internal fault, and keeps serving while the bot is down. Run it with
``python -m subscription_server``.

Two deliberate differences from :mod:`hy2_auth`:

* it reads the database **through the ordinary repositories** rather than raw
  SQL, so the sub-URL sees exactly the rows the rest of the codebase sees; and
* it imports the bot's link renderers (``bot.formatters``, the VLESS link
  builder in :mod:`services.xray`) instead of duplicating the link formats.
  A second copy of a client link format would drift from the single-key path
  silently, which is a worse failure than the extra import.

It never writes: the connection is opened with ``mode=ro`` and every repository
method it calls is a SELECT.
"""

from subscription_server.server import build_app
from subscription_server.store import ReadOnlyBundleStore

__all__ = ["ReadOnlyBundleStore", "build_app"]
