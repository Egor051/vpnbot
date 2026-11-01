
"""Per-key REALITY spiderX (spx) helpers.

spiderX is a purely *client-side* REALITY parameter: it is emitted into the
VLESS client link only and is NEVER written to the server inbound — the xray
config on the host is untouched and no restart is required. XTLS recommends a
value unique per client, so instead of a single global constant the value is
picked deterministically from an operator-provided pool by hashing the key's
UUID: the same UUID always maps to the same pool entry, so the value is stable
across restarts and reproducible by the backfill migration.

:func:`rotating_spider_x` is the opt-in alternative for the children of an
all-in-one bundle (``XRAY_SPIDER_X_ROTATION_HOURS``): the value walks the pool
over time instead of staying put. It is computed at render time and never stored.

Kept dependency-free (stdlib only) so it can be imported from the db, service
and config layers alike without creating an import cycle.
"""

import hashlib
from collections.abc import Sequence


def parse_spider_x_pool(raw: str | None) -> tuple[str, ...]:
    """Parse a comma-separated XRAY_SPIDER_X_POOL value into a tuple of paths.

    Whitespace around entries is stripped and blank entries are dropped. An
    empty or unset value yields an empty tuple (meaning: do not emit spx). No
    leading-slash validation is done here — the settings layer raises on an
    invalid entry, and the migration filters defensively — so this stays a pure
    string split usable by every caller.
    """
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def pick_spider_x(uuid_value: str, pool: Sequence[str]) -> str | None:
    """Deterministically pick a spiderX value for *uuid_value* from *pool*.

    Returns None when the pool is empty (spx not emitted). The choice is a
    stable hash of the UUID (SHA-256, not Python's per-process salted hash), so
    it never drifts between restarts and the backfill migration reproduces the
    exact value a fresh create would have assigned.
    """
    if not pool:
        return None
    digest = hashlib.sha256(uuid_value.encode("utf-8")).digest()
    return pool[int.from_bytes(digest, "big") % len(pool)]


def _sha256_int(text: str) -> int:
    """SHA-256 of *text* as a big-endian integer — identical in every process."""
    return int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest(), "big")


def rotating_spider_x(uuid_value: str, pool: Sequence[str], period_seconds: int, now_unix: int) -> str:
    """The spiderX a bundle child's link carries at *now_unix* under rotation.

    The pool is walked in a per-UUID order, one entry per epoch of
    *period_seconds*. Every input to the walk is a SHA-256 of the UUID — never the
    built-in ``hash()`` (salted per process by PYTHONHASHSEED) and never
    ``random`` — because the bot and the subscription endpoint are separate
    processes and must render the same value for the same key at the same second:

    * ``order`` — the pool sorted by ``sha256(f"{uuid}|{path}")``, so each key walks
      the entries in its own sequence;
    * ``phase`` — ``sha256(f"{uuid}|phase") % period``, so keys switch at different
      seconds of the period instead of all flipping together;
    * ``start`` — ``sha256(f"{uuid}|start") % len(pool)``, the key's offset in that
      walk;
    * ``epoch = (now_unix + phase) // period`` and the value is
      ``order[(start + epoch) % len(pool)]``.

    Consecutive epochs therefore land on consecutive positions of ``order``: two
    adjacent epochs never repeat a value (for a pool of two or more) and any
    ``len(pool)`` consecutive epochs visit the whole pool. Duplicate entries are
    dropped first (keeping their first position) so an operator's repeated path
    cannot produce two identical values in a row; a pool without duplicates is
    walked exactly as described above. A one-entry pool is that entry, always.

    Raises ``ValueError`` on an empty pool or a non-positive period: rotation has
    nothing to rotate through, and the caller decides what "off" means.
    """
    distinct = tuple(dict.fromkeys(pool))
    if not distinct:
        raise ValueError("rotating_spider_x needs a non-empty pool")
    if period_seconds <= 0:
        raise ValueError("rotating_spider_x needs a positive period")
    if len(distinct) == 1:
        return distinct[0]
    order = sorted(distinct, key=lambda path: _sha256_int(f"{uuid_value}|{path}"))
    phase = _sha256_int(f"{uuid_value}|phase") % period_seconds
    epoch = (now_unix + phase) // period_seconds
    start = _sha256_int(f"{uuid_value}|start") % len(distinct)
    return order[(start + epoch) % len(distinct)]
