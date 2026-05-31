"""In-memory representation of the WARP module state.

``WarpState`` mirrors the single ``warp_settings`` row one-to-one. Persisted
fields (``enabled``, ``config_path``, ``interface_name``, ``routes_count``) and
runtime fields (everything else, reset on bot restart) are kept together so the
admin panel can render the whole picture from one object without issuing any new
probes.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WarpState:
    enabled: bool = False
    config_path: str = "/etc/amnezia/tg-warp.conf"
    interface_name: str = "tg-warp"
    routes_count: int = 0
    # runtime state (reset on bot restart)
    tunnel_up: bool = False
    routes_active: bool = False
    fail_streak: int = 0
    success_streak: int = 0
    last_handshake: int = 0
    last_check_ts: int = 0
    updated_at: int = 0

    @property
    def config_present(self) -> bool:
        """A config is considered installed once it produced at least one route."""
        return self.routes_count > 0
