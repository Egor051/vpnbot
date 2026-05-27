
from datetime import datetime, timezone


class ClockProvider:
    def now(self) -> str:
        """Return the current UTC time as an ISO 8601 string without microseconds."""
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
