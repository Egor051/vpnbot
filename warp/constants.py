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

# Health monitor cadence and switch windows. These are the built-in defaults;
# production reads the effective values from ``config.settings``
# (``WARP_MONITOR_*`` env vars). The switch decision is time-based: the tunnel is
# declared down only after ``FAIL_WINDOW_SECONDS`` of *continuous* no-response, and
# back up only after ``RECOVER_WINDOW_SECONDS`` of *continuous* success — so a single
# dropped (or single recovered) ICMP probe never flaps the routing. The probe cadence
# is adaptive: ``CHECK_INTERVAL`` while the last probe answered, dropping to the faster
# ``FAST_CHECK_INTERVAL`` the moment a probe gets no response so an outage (and the
# start of recovery) is detected quickly.
CHECK_INTERVAL = 10        # seconds between probes during normal operation
FAST_CHECK_INTERVAL = 3    # seconds between probes while the last probe failed
FAIL_WINDOW_SECONDS = 60   # continuous no-response before the tunnel is declared down
RECOVER_WINDOW_SECONDS = 60  # continuous success before the tunnel is declared back up

# A WireGuard handshake newer than this is treated as tunnel liveness when the
# fixed ICMP probe target is unreachable (e.g. it is not inside the user's
# AllowedIPs or it filters ICMP), preventing a permanent false "tunnel down".
HANDSHAKE_FRESH_SECONDS = 180

# Sustained-degradation detector (observability only — NEVER removes routes). The
# continuous-fail latch above requires an *uninterrupted* run of failures, so a
# tunnel dropping (say) half its probes can stay "up" indefinitely while badly
# degraded. This sliding window flags that case for an admin alert without ever
# touching routing. The MIN_SAMPLES floor guarantees a single (or a couple of)
# isolated failures can never raise the alert. Hysteresis: raise at LOSS, clear at
# the lower CLEAR threshold.
DEGRADED_WINDOW_SECONDS = 120   # trailing window over which loss is measured
DEGRADED_MIN_SAMPLES = 10       # need at least this many probes in-window to judge
DEGRADED_LOSS_THRESHOLD = 0.5   # failure ratio at/above which the tunnel is degraded
DEGRADED_CLEAR_THRESHOLD = 0.2  # failure ratio below which the degraded flag clears
