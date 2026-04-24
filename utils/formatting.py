from __future__ import annotations

from html import escape


def h(value: object) -> str:
    return escape(str(value), quote=False)


def code(value: object) -> str:
    return f"<code>{h(value)}</code>"


def pre(value: object) -> str:
    return f"<pre>{h(value)}</pre>"
