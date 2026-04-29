from __future__ import annotations

from models.enums import VpnKeyType
from services.errors import InvalidOperation


class BackendHealth:
    def __init__(self) -> None:
        self._degraded: dict[VpnKeyType, str] = {}

    def mark_degraded(self, key_type: VpnKeyType, reason: str) -> None:
        self._degraded[key_type] = reason

    def mark_healthy(self, key_type: VpnKeyType) -> None:
        self._degraded.pop(key_type, None)

    def require_mutation_allowed(self, key_type: VpnKeyType) -> None:
        reason = self._degraded.get(key_type)
        if reason is None:
            return
        label = "Xray" if key_type == VpnKeyType.XRAY else "AWG"
        raise InvalidOperation(
            f"{label}-операции временно заблокированы: startup reconciliation завершился с ошибкой. "
            "Проверьте конфиг/runtime на сервере и перезапустите бота после восстановления."
        )
