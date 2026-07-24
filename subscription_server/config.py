
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path

from config.settings import Settings, SettingsError, load_settings

logger = logging.getLogger(__name__)


class SubscriptionConfigError(RuntimeError):
    """The endpoint cannot start with the configuration it was given."""


@dataclass(frozen=True, slots=True)
class SubscriptionConfig:
    """Everything the endpoint process needs to bind and answer.

    ``settings`` is carried whole because the renderers need the very same
    Xray/Hysteria2 values the bot uses to build single-key links — reading them
    from one place is what keeps the subscription links and the per-key links
    byte-identical.
    """

    settings: Settings
    db_path: Path
    bind_host: str
    bind_port: int
    public_port: int
    tls_cert: Path | None
    tls_key: Path | None
    lock_path: Path

    @property
    def enabled(self) -> bool:
        return self.settings.subscription_enabled

    @property
    def tls_configured(self) -> bool:
        return self.public_port > 0 and self.tls_cert is not None and self.tls_key is not None


def load_config(settings: Settings | None = None) -> SubscriptionConfig:
    """Build the process config from the shared ``.env`` (via ``Settings``).

    Unlike ``hy2_auth.config`` this process does NOT re-implement its own env
    parsing: it needs the full Xray/Hysteria2 link settings anyway, so parsing
    them a second time would be a source of drift rather than of isolation.
    """
    resolved = settings if settings is not None else load_settings()
    try:
        resolved.validate_subscription_ready()
    except SettingsError as exc:
        # Fail closed at startup rather than binding a cleartext public port.
        raise SubscriptionConfigError(str(exc)) from exc
    return SubscriptionConfig(
        settings=resolved,
        db_path=resolved.db_path,
        bind_host=resolved.subscription_bind_host,
        bind_port=resolved.subscription_bind_port,
        public_port=resolved.subscription_public_port,
        tls_cert=resolved.subscription_tls_cert,
        tls_key=resolved.subscription_tls_key,
        lock_path=resolved.subscription_lock_path,
    )


def build_ssl_context(config: SubscriptionConfig) -> ssl.SSLContext | None:
    """Load the TLS material for the public listener, or None when it is off.

    The certificate and key are read HERE, once, at startup and as the
    unprivileged service user — the process never needs root and never re-reads
    them, so a renewal is picked up by restarting the unit (acme.sh reloadcmd).
    A missing/unreadable key is a startup failure, never a silently plaintext
    public port.
    """
    if not config.tls_configured:
        return None
    assert config.tls_cert is not None and config.tls_key is not None  # tls_configured
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(certfile=str(config.tls_cert), keyfile=str(config.tls_key))
    except (OSError, ssl.SSLError) as exc:
        raise SubscriptionConfigError(
            f"Не удалось прочитать TLS-материал подписки ({config.tls_cert}): {exc}"
        ) from exc
    return context
