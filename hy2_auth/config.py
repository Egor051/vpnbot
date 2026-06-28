
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# Mirrors config.settings defaults, kept local so this process never imports the
# bot's settings module (which requires BOT_TOKEN/ADMIN_IDS and pulls in the bot).
DEFAULT_DB_PATH = "/opt/vpn-service/data/vpn.db"
DEFAULT_AUTH_LISTEN = "127.0.0.1:8444"


class Hy2AuthConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Hy2AuthConfig:
    db_path: Path
    host: str
    port: int


def parse_loopback_listen(listen: str) -> tuple[str, int]:
    """Parse a ``host:port`` string, enforcing a loopback bind host.

    The endpoint must never be reachable off the box, so a non-loopback host is
    rejected outright rather than silently bound. ``localhost`` is normalised to
    ``127.0.0.1`` so the actual bind address is always an explicit loopback IP.
    """
    host, sep, port_raw = listen.strip().rpartition(":")
    if not sep or not host:
        raise Hy2AuthConfigError(f"HYSTERIA2_AUTH_LISTEN must be host:port, got {listen!r}")
    host = host.strip("[]")  # tolerate bracketed IPv6 loopback ([::1]:8444)
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise Hy2AuthConfigError(f"HYSTERIA2_AUTH_LISTEN port must be an integer, got {port_raw!r}") from exc
    if not 1 <= port <= 65535:
        raise Hy2AuthConfigError("HYSTERIA2_AUTH_LISTEN port must be in 1–65535")
    if host == "localhost":
        return "127.0.0.1", port
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise Hy2AuthConfigError(f"HYSTERIA2_AUTH_LISTEN host must be a loopback address, got {host!r}") from exc
    if not address.is_loopback:
        raise Hy2AuthConfigError(f"HYSTERIA2_AUTH_LISTEN must bind loopback only, got {host!r}")
    return host, port


def load_config(environ: dict[str, str] | None = None) -> Hy2AuthConfig:
    """Load DB path and loopback listen address from the environment (and .env)."""
    load_dotenv()
    env = environ if environ is not None else dict(os.environ)
    db_path = (env.get("DB_PATH") or "").strip() or DEFAULT_DB_PATH
    listen = (env.get("HYSTERIA2_AUTH_LISTEN") or "").strip() or DEFAULT_AUTH_LISTEN
    host, port = parse_loopback_listen(listen)
    return Hy2AuthConfig(db_path=Path(db_path), host=host, port=port)
