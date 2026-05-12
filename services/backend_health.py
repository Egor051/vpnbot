from __future__ import annotations

from dataclasses import dataclass

from models.enums import ProxyAccessType, VpnKeyType
from services.errors import InvalidOperation

BackendType = VpnKeyType | ProxyAccessType


@dataclass(frozen=True, slots=True)
class BackendHealthStatus:
    backend_type: BackendType
    label: str
    degraded: bool
    reason: str | None


class BackendHealth:
    """Tracks which backends are degraded and blocks mutations on them."""

    def __init__(self) -> None:
        self._degraded: dict[BackendType, str] = {}

    def mark_degraded(self, backend_type: BackendType, reason: str) -> None:
        """Record a backend as degraded with a human-readable reason."""
        self._degraded[backend_type] = reason

    def mark_healthy(self, backend_type: BackendType) -> None:
        """Clear degraded status for a backend."""
        self._degraded.pop(backend_type, None)

    def snapshot(self) -> tuple[BackendHealthStatus, ...]:
        """Return current health status for all known backends."""
        return tuple(
            BackendHealthStatus(
                backend_type=backend_type,
                label=label,
                degraded=backend_type in self._degraded,
                reason=self._degraded.get(backend_type),
            )
            for backend_type, label in _BACKEND_LABELS.items()
        )

    def require_mutation_allowed(self, backend_type: BackendType) -> None:
        """Raise InvalidOperation if the backend is currently degraded."""
        reason = self._degraded.get(backend_type)
        if reason is None:
            return
        label = _BACKEND_LABELS.get(backend_type, str(backend_type))
        raise InvalidOperation(
            f"{label}-операции временно заблокированы: backend degraded ({reason}). "
            "Проверьте конфиг/runtime на сервере и перезапустите бота после восстановления."
        )


_BACKEND_LABELS: dict[BackendType, str] = {
    VpnKeyType.XRAY: "Xray",
    VpnKeyType.AWG: "AWG",
    ProxyAccessType.SOCKS5: "SOCKS5",
    ProxyAccessType.MTPROTO: "MTProto",
}
