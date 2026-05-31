"""Server-side WARP (AmneziaWG) routing module for Telegram traffic.

The module is disabled by default. Until an administrator uploads a config and
explicitly enables it from the admin panel, nothing is brought up and no routes
are touched. All privileged operations (awg-quick, ip route) go through fixed
sudo helpers; the bot process itself runs unprivileged.

Importing submodules directly (``from warp.manager import WarpManager``) keeps
``warp/__init__`` free of side effects and avoids import cycles with the
``repositories`` package.
"""
