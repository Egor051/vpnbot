"""Server-side WARP (AmneziaWG) module for masking the server's outbound IP.

It routes the traffic of selected applications (e.g. data-harvesting "spy" apps)
through an AmneziaWG tunnel so their outbound connections leave from the tunnel
endpoint instead of the real server IP. Which traffic is masked is decided purely
by the uploaded config's ``AllowedIPs``.

The module is disabled by default. Until an administrator uploads a config and
explicitly enables it from the admin panel, nothing is brought up and no routes
are touched. All privileged operations (awg-quick, ip route) go through fixed
sudo helpers; the bot process itself runs unprivileged.

Importing submodules directly (``from warp.manager import WarpManager``) keeps
``warp/__init__`` free of side effects and avoids import cycles with the
``repositories`` package.
"""
