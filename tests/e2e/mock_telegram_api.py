"""A minimal stand-in for api.telegram.org, for the installer end-to-end job.

Not a test module (pytest collects only ``test_*.py``): the CI job runs it as a
process next to the bot, points both ``scripts/install.sh`` and the bot at it
through ``TELEGRAM_API_BASE`` and drives it through the ``/_control`` endpoints.

What it speaks
--------------
``/bot<token>/<method>``, form-encoded or JSON, the way aiogram and curl call it:

* ``getMe`` — the bot, but only for the one token it was started with
  (``MOCK_BOT_TOKEN``); any other token gets Telegram's own 401, which is how the
  installer's getMe check is exercised for a wrong token.
* ``getUpdates`` — long poll over the queue filled by ``/_control/inject``,
  honouring ``offset`` and ``timeout`` (capped so a stopping bot never waits long).
* ``sendMessage`` — recorded, answered with a Message.
* everything else (deleteWebhook, setMyCommands, …) — ``{"ok": true, "result": true}``.

Control
-------
* ``POST /_control/inject`` ``{"user_id": 1, "text": "/start …", "chat_type": "private"}``
  queues one message update; answers ``{"update_id": N}``.
* ``GET /_control/sent`` — every sendMessage so far: ``[{"chat_id", "text"}, …]``.
* ``GET /_control/delivered`` — the highest update_id the bot has confirmed
  (the offset it polled with, minus one): an injected update is HANDLED once
  this reaches it.
* ``GET /_control/health`` — 200 once listening.

The token never appears in its output: the bot's requests are logged by method
name only.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import time
from typing import Any

from aiohttp import web

logger = logging.getLogger("mock-telegram")

BOT_ID = 7_000_000_001
BOT_USERNAME = os.environ.get("MOCK_BOT_USERNAME", "vpnbot_ci_bot")
MAX_POLL_SECONDS = 2.0


class MockTelegram:
    def __init__(self, token: str) -> None:
        self.token = token
        self.updates: list[dict[str, Any]] = []
        self.sent: list[dict[str, Any]] = []
        self.next_update_id = 1
        self.next_message_id = 1
        self.confirmed = 0
        self.new_update = asyncio.Event()

    async def _params(self, request: web.Request) -> dict[str, Any]:
        params: dict[str, Any] = dict(request.query)
        if request.method == "POST" and request.can_read_body:
            if request.content_type == "application/json":
                body = await request.json()
                if isinstance(body, dict):
                    params.update(body)
            else:
                form = await request.post()
                for key, value in form.items():
                    params[key] = value if isinstance(value, str) else str(value)
        return params

    async def api(self, request: web.Request) -> web.Response:
        token = request.match_info["token"]
        method = request.match_info["method"]
        params = await self._params(request)
        if token != self.token:
            logger.info("call %s with a wrong token -> 401", method)
            return web.json_response(
                {"ok": False, "error_code": 401, "description": "Unauthorized"}, status=401
            )
        handler = getattr(self, "m_" + method.lower(), None)
        if handler is None:
            return web.json_response({"ok": True, "result": True})
        result = await handler(params)
        return web.json_response({"ok": True, "result": result})

    async def m_getme(self, _params: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": BOT_ID,
            "is_bot": True,
            "first_name": "VPN bot CI",
            "username": BOT_USERNAME,
            "can_join_groups": True,
            "can_read_all_group_messages": False,
            "supports_inline_queries": False,
        }

    async def m_getupdates(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        offset = int(params.get("offset") or 0)
        timeout = min(float(params.get("timeout") or 0), MAX_POLL_SECONDS)
        if offset > 0:
            # Like Telegram: an offset confirms every update below it, and a
            # confirmed update is never delivered again — not even to a bot that
            # restarted and polls without an offset.
            self.confirmed = max(self.confirmed, offset - 1)
            self.updates = [u for u in self.updates if u["update_id"] >= offset]
        deadline = time.monotonic() + timeout
        while True:
            pending = [u for u in self.updates if u["update_id"] >= offset]
            if pending:
                return pending
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return []
            self.new_update.clear()
            try:
                await asyncio.wait_for(self.new_update.wait(), timeout=remaining)
            except TimeoutError:
                return []

    async def m_sendmessage(self, params: dict[str, Any]) -> dict[str, Any]:
        chat_id = int(params["chat_id"])
        text = str(params.get("text", ""))
        self.sent.append({"chat_id": chat_id, "text": text})
        message_id = self.next_message_id
        self.next_message_id += 1
        logger.info("sendMessage to chat %d (%d chars)", chat_id, len(text))
        return {
            "message_id": message_id,
            "date": int(time.time()),
            "chat": {"id": chat_id, "type": "private"},
            "from": {"id": BOT_ID, "is_bot": True, "first_name": "VPN bot CI", "username": BOT_USERNAME},
            "text": text,
        }

    async def control_inject(self, request: web.Request) -> web.Response:
        body = await request.json()
        user_id = int(body["user_id"])
        text = str(body["text"])
        chat_type = str(body.get("chat_type", "private"))
        chat_id = user_id if chat_type == "private" else -1_000_000_000_000 - user_id
        update_id = self.next_update_id
        self.next_update_id += 1
        entities = []
        if text.startswith("/"):
            command = text.split(maxsplit=1)[0]
            entities.append({"type": "bot_command", "offset": 0, "length": len(command)})
        chat: dict[str, Any] = {"id": chat_id, "type": chat_type}
        if chat_type == "private":
            chat["first_name"] = "Operator"
        else:
            chat["title"] = "Some group"
        self.updates.append(
            {
                "update_id": update_id,
                "message": {
                    "message_id": 10_000 + update_id,
                    "date": int(time.time()),
                    "chat": chat,
                    "from": {
                        "id": user_id,
                        "is_bot": False,
                        "first_name": "Operator",
                        "username": f"op{user_id}",
                        "language_code": "en",
                    },
                    "text": text,
                    "entities": entities,
                },
            }
        )
        self.new_update.set()
        return web.json_response({"update_id": update_id})

    async def control_sent(self, _request: web.Request) -> web.Response:
        return web.json_response(self.sent)

    async def control_delivered(self, _request: web.Request) -> web.Response:
        return web.json_response({"confirmed": self.confirmed, "queued": self.next_update_id - 1})

    async def control_health(self, _request: web.Request) -> web.Response:
        return web.json_response({"ok": True})


def build_app(token: str) -> web.Application:
    mock = MockTelegram(token)
    app = web.Application()
    app.router.add_post("/_control/inject", mock.control_inject)
    app.router.add_get("/_control/sent", mock.control_sent)
    app.router.add_get("/_control/delivered", mock.control_delivered)
    app.router.add_get("/_control/health", mock.control_health)
    app.router.add_route("*", "/bot{token}/{method}", mock.api)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    token = os.environ.get("MOCK_BOT_TOKEN", "")
    if not token:
        raise SystemExit("MOCK_BOT_TOKEN must be set")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    web.run_app(build_app(token), host=args.host, port=args.port, print=None, access_log=None)


if __name__ == "__main__":
    main()
