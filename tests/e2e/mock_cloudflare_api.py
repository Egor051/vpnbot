"""A minimal stand-in for api.cloudflare.com/client/v4, for the first setup's end-to-end job.

Not a test module: tests/e2e/run_setup_e2e.sh runs it next to the bot and points the bot at
it (CLOUDFLARE_API_BASE, http on loopback only — config/settings.py). It speaks what
adapters/cloudflare_dns.py calls, for ONE token (MOCK_CF_TOKEN) and ONE zone (MOCK_CF_ZONE):

* ``GET /user/tokens/verify`` — ``{"status": "active"}`` for the token, 401 for any other;
* ``GET /zones?name=`` — the zone when the name is it;
* ``GET /zones/<id>/dns_records?type=&name=``, ``POST``, ``PATCH``/``DELETE`` ``…/<rid>`` —
  an in-memory record set.

``GET /_control/records`` lists the records (the job checks the token probe left none
behind). The token is never logged.
"""

from __future__ import annotations

import argparse
import itertools
import logging
import os
from typing import Any

from aiohttp import web

logger = logging.getLogger("mock-cloudflare")
ZONE_ID = "0123456789abcdef0123456789abcdef"


class MockCloudflare:
    def __init__(self, token: str, zone: str) -> None:
        self.token = token
        self.zone = zone
        self.records: dict[str, dict[str, Any]] = {}
        self.ids = itertools.count(1)

    def _authorized(self, request: web.Request) -> bool:
        return request.headers.get("Authorization", "") == f"Bearer {self.token}"

    @staticmethod
    def ok(result: Any) -> web.Response:
        return web.json_response({"success": True, "errors": [], "messages": [], "result": result})

    @staticmethod
    def error(status: int, message: str) -> web.Response:
        return web.json_response({"success": False, "errors": [{"code": status, "message": message}], "result": None},
                                 status=status)

    async def handle(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            logger.info("%s %s with a wrong token -> 401", request.method, request.path)
            return self.error(401, "Invalid API Token")
        path = request.path.removeprefix("/client/v4")
        logger.info("%s %s", request.method, path)
        if path == "/user/tokens/verify":
            return self.ok({"id": "t1", "status": "active"})
        if path == "/zones":
            name = request.query.get("name", "")
            return self.ok([{"id": ZONE_ID, "name": self.zone}] if name == self.zone else [])
        prefix = f"/zones/{ZONE_ID}/dns_records"
        if path == prefix and request.method == "GET":
            rtype, name = request.query.get("type"), request.query.get("name")
            return self.ok([r for r in self.records.values()
                            if (not rtype or r["type"] == rtype) and (not name or r["name"] == name)])
        if path == prefix and request.method == "POST":
            body = await request.json()
            rid = f"r{next(self.ids)}"
            record = {"id": rid, "type": body.get("type"), "name": body.get("name"), "content": body.get("content"),
                      "ttl": body.get("ttl", 1), "proxied": bool(body.get("proxied", False))}
            self.records[rid] = record
            return self.ok(record)
        if path.startswith(prefix + "/"):
            rid = path.rsplit("/", 1)[-1]
            if rid not in self.records:
                return self.error(404, "Record not found")
            if request.method == "DELETE":
                self.records.pop(rid)
                return self.ok({"id": rid})
            if request.method in ("PATCH", "PUT"):
                body = await request.json()
                self.records[rid].update({k: v for k, v in body.items() if k in ("content", "ttl", "proxied")})
                return self.ok(self.records[rid])
        return self.error(404, f"no route {request.method} {path}")

    async def control_records(self, _request: web.Request) -> web.Response:
        return web.json_response(list(self.records.values()))


def build_app(token: str, zone: str) -> web.Application:
    mock = MockCloudflare(token, zone)
    app = web.Application()
    app.router.add_get("/_control/records", mock.control_records)
    app.router.add_get("/_control/health", lambda _r: web.json_response({"ok": True}))
    app.router.add_route("*", "/client/v4/{tail:.*}", mock.handle)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()
    token, zone = os.environ.get("MOCK_CF_TOKEN", ""), os.environ.get("MOCK_CF_ZONE", "")
    if not token or not zone:
        raise SystemExit("MOCK_CF_TOKEN and MOCK_CF_ZONE must be set")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    web.run_app(build_app(token, zone), host=args.host, port=args.port, print=None, access_log=None)


if __name__ == "__main__":
    main()
