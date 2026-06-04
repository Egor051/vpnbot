#!/usr/bin/env python3
"""Derive constraints.txt (the un-hashed pip-audit set) from constraints-hashed.txt.

constraints-hashed.txt is the source of truth for what CI installs (with
``--require-hashes``). pip-audit, however, runs against constraints.txt. If the
two drift, the audited dependency set no longer matches the installed one, which
both hides real CVEs and reports phantom ones.

This script rewrites constraints.txt as the exact ``name==version`` mirror of
constraints-hashed.txt (same direct + transitive set, hashes stripped), so the
two can never disagree. It is invoked by ``make update-hashes`` / ``make
sync-constraints``.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HASHED = ROOT / "constraints-hashed.txt"
OUT = ROOT / "constraints.txt"

HEADER = """\
# Production constraints for Python 3.12 on Ubuntu 24.04 x86_64.
#
# This is the un-hashed mirror of constraints-hashed.txt: the same fully
# pinned set (direct + transitive), without the --hash lines. It is what
# `pip-audit` consumes in CI, so it MUST stay byte-for-byte version-aligned
# with constraints-hashed.txt — otherwise the audited set drifts from the
# installed set. Regenerate both together with `make update-hashes`.
#
# Install runtime deps with:
#   pip install -r requirements.txt -c constraints.txt
#
# cryptography pin must match requirements.txt and constraints-hashed.txt.
"""

_PIN = re.compile(r"^([A-Za-z0-9._-]+)==([^\s\\]+)")


def parse_pins(text: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in text.splitlines():
        m = _PIN.match(line)
        if m:
            pins[m.group(1)] = m.group(2)
    return pins


def render(pins: dict[str, str]) -> str:
    body = "\n".join(f"{name}=={pins[name]}" for name in sorted(pins, key=str.lower))
    return f"{HEADER}\n{body}\n"


def main() -> int:
    if not HASHED.exists():
        print(f"error: {HASHED} not found", file=sys.stderr)
        return 1
    pins = parse_pins(HASHED.read_text())
    if not pins:
        print(f"error: no pinned requirements found in {HASHED}", file=sys.stderr)
        return 1
    new = render(pins)
    if OUT.exists() and OUT.read_text() == new:
        print(f"constraints.txt already in sync ({len(pins)} packages)")
        return 0
    OUT.write_text(new)
    print(f"constraints.txt synced from constraints-hashed.txt ({len(pins)} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
