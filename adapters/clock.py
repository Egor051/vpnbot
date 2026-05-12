
from datetime import datetime, timezone


class ClockProvider:
    def now(self) -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
