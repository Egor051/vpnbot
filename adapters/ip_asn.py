"""IPv4 → ASN / subnet normalization backed by the iptoasn database.

The anomaly detector counts *distinct networks* per key rather than distinct raw
IPs, so that a single mobile client whose carrier rotates its address (many IPs
inside one ASN) or who switches between mobile data and home Wi-Fi does not look
like key sharing. Each IP is collapsed to ``AS<asn>`` when the ASN is known, or
to its ``/24`` otherwise.

The ASN table is the iptoasn ``ip2asn-v4.tsv`` dump (tab-separated
``range_start range_end asn country description``), refreshed out-of-process by a
systemd timer (see ``deploy/update-ip2asn.sh``). It is loaded lazily and cached
in memory; lookups are a local ``bisect`` over the sorted ranges, so the
detector's hot path makes no network or blocking calls. The cache reloads
automatically when the file's ``(mtime, size)`` changes, so the daily refresh is
picked up without restarting the bot.

The deployment is IPv4-only: IPv6 literals — and any unparseable junk that leaks
in from logs — are passed through unchanged rather than raising.
"""

from __future__ import annotations

import bisect
import ipaddress
import logging
import os
import threading
from typing import Final

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH: Final = "/opt/vpn-service/data/ip2asn-v4.tsv"
_DB_PATH_ENV: Final = "IP2ASN_DB_PATH"

# Cached table of (range_start_int, range_end_int, asn) sorted by range start,
# with a parallel list of just the starts for bisect. Guarded by _LOCK, and
# reloaded when the source file's (mtime_ns, size) signature changes.
_LOCK = threading.Lock()
_TABLE: list[tuple[int, int, int]] | None = None
_STARTS: list[int] = []
_SIGNATURE: tuple[int, int] | None = None
_MISSING_LOGGED = False


def _db_path() -> str:
    return os.environ.get(_DB_PATH_ENV, DEFAULT_DB_PATH)


def _load_table(path: str) -> list[tuple[int, int, int]]:
    """Parse the iptoasn TSV into a list of ``(start_int, end_int, asn)`` ranges.

    Malformed lines (wrong field count, unparseable IP/ASN, inverted range) are
    skipped defensively so a single bad row never breaks normalization.
    """
    table: list[tuple[int, int, int]] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            try:
                start = int(ipaddress.IPv4Address(parts[0]))
                end = int(ipaddress.IPv4Address(parts[1]))
                asn = int(parts[2])
            except ValueError:
                continue
            if end < start:
                continue
            table.append((start, end, asn))
    table.sort(key=lambda row: row[0])
    return table


def _get_table() -> tuple[list[tuple[int, int, int]], list[int]]:
    """Return the cached ``(table, starts)``, (re)loading it if the file changed."""
    global _TABLE, _STARTS, _SIGNATURE, _MISSING_LOGGED
    path = _db_path()
    with _LOCK:
        try:
            stat = os.stat(path)
        except OSError:
            if not _MISSING_LOGGED:
                logger.warning(
                    "IP-to-ASN database not found at %s; falling back to /24 "
                    "networks for anomaly normalization",
                    path,
                )
                _MISSING_LOGGED = True
            _TABLE = None
            _STARTS = []
            _SIGNATURE = None
            return [], []
        signature = (stat.st_mtime_ns, stat.st_size)
        if _TABLE is not None and _SIGNATURE == signature:
            return _TABLE, _STARTS
        table = _load_table(path)
        _TABLE = table
        _STARTS = [row[0] for row in table]
        _SIGNATURE = signature
        _MISSING_LOGGED = False
        logger.info("Loaded %d IP-to-ASN ranges from %s", len(table), path)
        return _TABLE, _STARTS


def lookup_asn(ip: str) -> int | None:
    """Return the ASN announcing ``ip``, or ``None`` when it cannot be resolved.

    ``None`` is returned for non-IPv4 or unparseable input, for an IP not covered
    by the database, or when the covering range is unrouted (iptoasn ASN 0).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    ip_int = int(addr)
    table, starts = _get_table()
    if not table:
        return None
    idx = bisect.bisect_right(starts, ip_int) - 1
    if idx < 0:
        return None
    start, end, asn = table[idx]
    if start <= ip_int <= end and asn != 0:
        return asn
    return None


def normalize_ip(ip: str) -> str:
    """Collapse an IPv4 address to ``AS<asn>`` or, failing that, its ``/24``.

    Unparseable input or an IPv6 literal (which should not occur in this
    IPv4-only deployment but may leak in from logs) is returned unchanged.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version != 4:
        return ip
    asn = lookup_asn(ip)
    if asn is not None:
        return f"AS{asn}"
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def reset_cache() -> None:
    """Drop the in-memory ASN table so the next lookup reloads from disk.

    Primarily a test hook (to switch between fixture databases); also usable to
    force a reload after an out-of-band database swap.
    """
    global _TABLE, _STARTS, _SIGNATURE, _MISSING_LOGGED
    with _LOCK:
        _TABLE = None
        _STARTS = []
        _SIGNATURE = None
        _MISSING_LOGGED = False
