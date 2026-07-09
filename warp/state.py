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
    config_path: str = "/etc/amnezia/out-warp.conf"
    interface_name: str = "out-warp"
    routes_count: int = 0
    # ``config_installed`` is the authoritative "a config was installed" flag,
    # persisted independently of ``routes_count``: a full-tunnel AllowedIPs
    # (0.0.0.0/0) is stripped by the routes helper and yields zero routes, yet the
    # config is present and the module must be startable.
    config_installed: bool = False
    # Operator opt-in kill-switch. When enabled, the legacy (non-observer) health
    # monitor keeps the tunnel routes on a tunnel-down instead of removing them, so
    # masked traffic blackholes on the down interface rather than leaking out the
    # real server IP. Off by default (preserves fallback-to-direct behaviour).
    kill_switch: bool = False
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
        """Whether a config is installed.

        True when the persisted ``config_installed`` flag is set OR at least one
        route was produced. The ``routes_count > 0`` fallback keeps legacy rows
        (and unit fixtures) that predate the flag working unchanged.
        """
        return self.config_installed or self.routes_count > 0
