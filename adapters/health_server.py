
import json
from datetime import datetime, timezone

from aiohttp import web

from services.backend_health import BackendHealth
from utils.redact import redact


def create_health_app(backend_health: BackendHealth) -> web.Application:
    """Create an aiohttp app with a single GET /health endpoint."""
    app = web.Application()

    async def handle_health(request: web.Request) -> web.Response:
        statuses = backend_health.snapshot()
        # The endpoint is unauthenticated (and may be bound beyond localhost): redact the
        # backend reason so secret-like detail can never leak, matching the bot's own
        # check_backends() handling.
        backends = {
            s.backend_type.value: {"degraded": s.degraded, "reason": redact(s.reason) if s.reason else None}
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
