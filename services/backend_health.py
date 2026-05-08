from __future__ import annotations

from models.enums import ProxyAccessType, VpnKeyType
from services.errors import InvalidOperation

BackendType = VpnKeyType | ProxyAccessType


class BackendHealth:
    def __init__(self) -> None:
        self._degraded: dict[BackendType, str] = {}

    def mark_degraded(self, backend_type: BackendType, reason: str) -> None:
        self._degraded[backend_type] = reason

    def mark_healthy(self, backend_type: BackendType) -> None:
        self._degraded.pop(backend_type, None)

    def require_mutation_allowed(self, backend_type: BackendType) -> None:
        reason = self._degraded.get(backend_type)
        if reason is None:
            return
        label = {
            VpnKeyType.XRAY: "Xray",
            VpnKeyType.AWG: "AWG",
            ProxyAccessType.SOCKS5: "SOCKS5",
            ProxyAccessType.MTPROTO: "MTProto",
        }.get(backend_type, str(backend_type))
        raise InvalidOperation(
            f"{label}-операции временно заблокированы: backend degraded ({reason}). "
            "Проверьте конфиг/runtime на сервере и перезапустите бота после восстановления."
        )
