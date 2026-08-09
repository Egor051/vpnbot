"""/warp_split_list must survive a list longer than a Telegram message.

The command rendered every prefix into one ``message.answer``. Telegram caps a
message at 4096 characters; 269 prefixes render to 8115, so the call came back
as ``TelegramBadRequest("message is too long")`` and the admin got an error
instead of the list. The data was never at fault — the file and the
warp_split_prefixes/_sources tables agree byte for byte — only the delivery was.

Above the threshold the list now goes out as a plain-text document; below it,
nothing changes. Both sides of the boundary are pinned here, because a fix that
only ever takes the document branch would quietly turn every two-prefix list
into a file download.
"""
from __future__ import annotations

import asyncio
import ipaddress
from types import SimpleNamespace

import bot.handlers.admin_warp_split as mod
from bot.handlers.admin_warp_split import (
    WARP_SPLIT_LIST_FILENAME,
    WARP_SPLIT_LIST_MESSAGE_LIMIT,
    warp_split_list_cmd,
)
from i18n import t
from utils.formatting import code


class _Message:
    def __init__(self) -> None:
        self.from_user = SimpleNamespace(id=1, username="admin", first_name="Admin")
        self.chat = SimpleNamespace(id=1, type="private")
        self.text = "/warp_split_list"
        self.answers: list[str] = []
        self.documents: list[tuple[object, str | None]] = []

    async def answer(self, text: str, reply_markup: object = None, **kwargs: object) -> None:
        self.answers.append(text)

    async def answer_document(self, document: object, caption: str | None = None, **kwargs: object) -> None:
        self.documents.append((document, caption))


def _services() -> SimpleNamespace:
    class Users:
        async def require_superadmin(self, user_id: int) -> object:
            return SimpleNamespace(telegram_user_id=user_id)

    return SimpleNamespace(users=Users())


def _prefixes(count: int) -> list[str]:
    """`count` distinct /24s, formatted exactly as the manager returns them."""
    return [str(ipaddress.ip_network((f"10.{i // 256}.{i % 256}.0", 24))) for i in range(count)]


def _rendered_message(entries: list[str]) -> str:
    """The exact message form the handler builds, so the boundary is not guessed."""
    return "\n".join([t("warp_split_list_header", count=len(entries)), *(f"  {code(e)}" for e in entries)])


def _run(entries: list[str], monkeypatch) -> _Message:  # type: ignore[no-untyped-def]
    async def ok(message: object, text: str | None = None) -> bool:
        return True

    monkeypatch.setattr(mod, "ensure_private_message", ok, raising=False)
    message = _Message()
    services = _services()
    services.warp_split = SimpleNamespace(read_list=lambda: list(entries))
    asyncio.run(warp_split_list_cmd(message, services))  # type: ignore[arg-type]
    return message


def test_a_long_list_is_delivered_as_a_document(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    entries = _prefixes(269)
    message = _run(entries, monkeypatch)

    assert message.answers == [], "the overflowing list must not go out as a message"
    assert len(message.documents) == 1
    document, caption = message.documents[0]
    assert document.filename == WARP_SPLIT_LIST_FILENAME
    # Plain text, one prefix per line, no markup — greppable and pasteable back
    # into /warp_split_add.
    body = document.data.decode("utf-8")
    assert body.splitlines() == entries
    assert "<code>" not in body
    # The count is printed exactly once, in the caption, and the caption itself
    # stays well inside Telegram's 1024-character limit.
    assert caption is not None
    assert "269" in caption
    assert len(caption) <= 1024


def test_a_short_list_is_still_an_ordinary_message(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    entries = _prefixes(3)
    message = _run(entries, monkeypatch)

    assert message.documents == []
    assert len(message.answers) == 1
    text = message.answers[0]
    assert "3" in text
    for entry in entries:
        assert entry in text


def test_the_threshold_is_honoured_on_both_sides(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Walk the boundary: the last message-sized list, and the first file-sized one."""
    below: list[str] | None = None
    above: list[str] | None = None
    for count in range(1, 400):
        entries = _prefixes(count)
        if len(_rendered_message(entries)) <= WARP_SPLIT_LIST_MESSAGE_LIMIT:
            below = entries
        elif above is None:
            above = entries
            break
    assert below is not None and above is not None
    assert len(above) == len(below) + 1

    assert _run(below, monkeypatch).documents == []
    assert _run(above, monkeypatch).answers == []


def test_the_threshold_leaves_room_under_the_telegram_cap() -> None:
    """A margin, not a coincidence: the header and per-line markup ride on top."""
    assert WARP_SPLIT_LIST_MESSAGE_LIMIT < 4096
