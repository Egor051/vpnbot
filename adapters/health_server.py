from __future__ import annotations

import json
from datetime import datetime, timezone

from aiohttp import web

from services.backend_health import BackendHealth


def create_health_app(backend_health: BackendHealth) -> web.Application:
    """Create an aiohttp app with a single GET /health endpoint."""
    app = web.Application()

    async def handle_health(request: web.Request) -> web.Response:
        statuses = backend_health.snapshot()
        backends = {
            s.backend_type.value: {"degraded": s.degraded, "reason": s.reason}
            for s in statuses
        }
        all_healthy = all(not s.degraded for s in statuses)
        body = {
            "status": "healthy" if all_healthy else "degraded",
            "backends": backends,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return web.Response(
            text=json.dumps(body, ensure_ascii=False),
            content_type="application/json",
            status=200 if all_healthy else 503,
        )

    app.router.add_get("/health", handle_health)
    return app
