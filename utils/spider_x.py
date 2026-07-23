
"""Per-key REALITY spiderX (spx) helpers.

spiderX is a purely *client-side* REALITY parameter: it is emitted into the
VLESS client link only and is NEVER written to the server inbound — the xray
config on the host is untouched and no restart is required. XTLS recommends a
value unique per client, so instead of a single global constant the value is
picked deterministically from an operator-provided pool by hashing the key's
UUID: the same UUID always maps to the same pool entry, so the value is stable
across restarts and reproducible by the backfill migration.

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
