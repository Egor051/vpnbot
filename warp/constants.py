"""Static constants for the WARP routing module.

Only values that never change per deployment live here. Helper script paths,
the config path and the interface name are configurable and therefore belong to
``config.settings`` / the ``warp_settings`` table, not this file.
"""

# Cloudflare anycast — стабильно отвечает на ICMP, присутствует в типовых WARP AllowedIPs.
PING_TARGET = "162.159.140.245"

# Interface created by awg-quick for the WARP tunnel.
PING_INTERFACE = "out-warp"

# File the install helper writes (one CIDR per line, extracted from AllowedIPs)
# and the routes helper reads. Never hardcode the CIDRs themselves.
ROUTES_LIST = "/etc/amnezia/out-warp-routes.list"

# Health monitor thresholds.
CHECK_INTERVAL = 10     # seconds between tunnel liveness probes
FAIL_THRESHOLD = 2      # consecutive failures before routes are removed (fallback)
RECOVER_THRESHOLD = 3   # consecutive successes before routes are restored

# A WireGuard handshake newer than this is treated as tunnel liveness when the
# fixed ICMP probe target is unreachable (e.g. it is not inside the user's
# AllowedIPs or it filters ICMP), preventing a permanent false "tunnel down".
HANDSHAKE_FRESH_SECONDS = 180
