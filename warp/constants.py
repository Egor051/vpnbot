"""Static constants for the WARP routing module.

Only values that never change per deployment live here. Helper script paths,
the config path and the interface name are configurable and therefore belong to
``config.settings`` / the ``warp_settings`` table, not this file.
"""

# Telegram MTProto IP used as the tunnel liveness probe target. Such configs
# always route this address, so it is a reliable ping target for the tunnel.
PING_TARGET = "149.154.167.50"

# Interface created by awg-quick for the WARP tunnel.
PING_INTERFACE = "tg-warp"

# File the install helper writes (one CIDR per line, extracted from AllowedIPs)
# and the routes helper reads. Never hardcode the CIDRs themselves.
ROUTES_LIST = "/etc/amnezia/tg-warp-routes.list"

# Health monitor thresholds.
CHECK_INTERVAL = 10     # seconds between tunnel liveness probes
FAIL_THRESHOLD = 2      # consecutive failures before routes are removed (fallback)
RECOVER_THRESHOLD = 3   # consecutive successes before routes are restored
