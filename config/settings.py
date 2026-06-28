
import base64
import binascii
import os
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import find_dotenv, load_dotenv


class SettingsError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SettingsError(f"Не задана обязательная переменная окружения {name}")
    return value


def _optional(name: str, default: str = "") -> str:
    # NOTE: an explicitly empty value (``VAR=``) intentionally yields "" rather
    # than *default* — several call sites rely on that to fail closed (e.g. the
    # managed MTProto paths reject a blanked value via _non_empty()). Values that
    # must keep a safe fallback when blanked apply ``or default`` at the call site.
    return os.getenv(name, default).strip()


def _int(name: str, default: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        if default is None:
            raise SettingsError(f"Не задана обязательная переменная окружения {name}")
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise SettingsError(f"Переменная {name} должна быть целым числом") from exc


def _int_range(name: str, default: int | None, min_value: int, max_value: int) -> int:
    value = _int(name, default)
    if not min_value <= value <= max_value:
        raise SettingsError(f"Переменная {name} должна быть в диапазоне {min_value}–{max_value}")
    return value


def _optional_int_range(name: str, min_value: int, max_value: int) -> int | None:
    raw = _optional(name)
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError as exc:
        raise SettingsError(f"Переменная {name} должна быть целым числом") from exc
    if not min_value <= value <= max_value:
        raise SettingsError(f"Переменная {name} должна быть в диапазоне {min_value}–{max_value}")
    return value


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "y", "on"}:
        return True
    if value in {"0", "false", "no", "n", "off"}:
        return False
    raise SettingsError(f"Переменная {name} должна быть явным boolean: true/false, yes/no, on/off или 1/0")


def _choice(name: str, default: str, allowed: set[str]) -> str:
    value = _optional(name, default).lower()
    if value not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise SettingsError(f"Переменная {name} должна быть одним из значений: {allowed_values}")
    return value


def _non_empty(name: str, value: str) -> str:
    if not value:
        raise SettingsError(f"Не задана обязательная переменная окружения {name}")
    return value


def _no_control_chars(name: str, value: str) -> str:
    """Reject control characters in values that flow into generated configs/links.

    A newline injected into e.g. XRAY_SNI or AWG_ENDPOINT_HOST could break the
    Xray config.json / WireGuard config or the generated client URI.
    """
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise SettingsError(f"{name} содержит недопустимые управляющие символы")
    return value


_SOCKS5_FORBIDDEN_PREFIXES = frozenset({"", "root", "admin", "user", "test", "ubuntu", "www", "daemon"})


def _socks5_login_prefix(value: str) -> str:
    if not value:
        raise SettingsError("SOCKS5_LOGIN_PREFIX не должен быть пустым")
    if re.fullmatch(r"[A-Za-z0-9_]+", value) is None:
        raise SettingsError("SOCKS5_LOGIN_PREFIX должен содержать только A-Z, a-z, 0-9 и _")
    if value[0].isdigit():
        raise SettingsError("SOCKS5_LOGIN_PREFIX должен начинаться с буквы или _")
    normalized = value.strip("_").lower()
    if normalized in _SOCKS5_FORBIDDEN_PREFIXES:
        raise SettingsError("SOCKS5_LOGIN_PREFIX слишком общий или опасный")
    return value


def _int_list_positive(name: str, default: tuple[int, ...]) -> tuple[int, ...]:
    raw = _optional(name)
    if not raw:
        return default
    result: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            v = int(item)
        except ValueError as exc:
            raise SettingsError(f"Переменная {name} должна быть списком целых чисел через запятую") from exc
        if v <= 0:
            raise SettingsError(f"Переменная {name}: все значения должны быть положительными числами")
        result.append(v)
    return tuple(sorted(set(result), reverse=True))


def _fernet_key(name: str) -> str:
    value = _optional(name)
    if not value:
        return ""
    error = SettingsError(
        f"{name} должен быть корректным Fernet-ключом "
        "(44-символьный URL-safe base64, сгенерируйте командой: "
        'python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")'
    )
    if len(value) != 44 or re.fullmatch(r"[A-Za-z0-9_\-=]+", value) is None:
        raise error
    # A real Fernet key is 32 raw bytes encoded as URL-safe base64; verify the
    # bytes decode and have the right length instead of trusting the charset only.
    try:
        if len(base64.urlsafe_b64decode(value)) != 32:
            raise error
    except (ValueError, binascii.Error) as exc:
        raise error from exc
    return value


def _loopback_host_port(name: str, value: str) -> str:
    """Validate a ``host:port`` whose host must be loopback.

    The hy2_auth endpoint must never be reachable off the box, so the bind host
    is constrained to a loopback address here (defence-in-depth alongside the
    hy2_auth process enforcing the same invariant).
    """
    value = _no_control_chars(name, value).strip()
    host, sep, port_raw = value.rpartition(":")
    if not sep or not host:
        raise SettingsError(f"{name} должен быть в формате host:port")
    host = host.strip("[]")  # tolerate bracketed IPv6 loopback ([::1]:8444)
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise SettingsError(f"{name}: порт должен быть целым числом") from exc
    if not 1 <= port <= 65535:
        raise SettingsError(f"{name}: порт должен быть в диапазоне 1–65535")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        if host == "localhost":
            return value
        raise SettingsError(f"{name}: host должен быть loopback (127.0.0.1, ::1 или localhost)") from exc
    if not address.is_loopback:
        raise SettingsError(f"{name}: host должен быть loopback (127.0.0.1, ::1 или localhost)")
    return value


def _admin_ids(raw: str) -> frozenset[int]:
    values: set[int] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            parsed = int(item)
        except ValueError as exc:
            raise SettingsError("ADMIN_IDS должен быть списком Telegram ID через запятую") from exc
        if parsed <= 0:
            raise SettingsError("ADMIN_IDS: все Telegram ID должны быть положительными числами")
        values.add(parsed)
    if not values:
        raise SettingsError("ADMIN_IDS не должен быть пустым")
    return frozenset(values)


def _xray_short_id(value: str, *, required: bool) -> str:
    if not value:
        if required:
            raise SettingsError("XRAY_SHORT_ID должен быть задан, если XRAY_MANAGE_SHORT_IDS=false")
        return ""
    if len(value) > 16 or len(value) % 2 != 0 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise SettingsError("XRAY_SHORT_ID должен быть hex-строкой чётной длины до 16 символов")
    return value.lower()


def _ipv4_network(name: str, value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SettingsError(f"{name} должен быть корректной IPv4-сетью") from exc
    if network.version != 4:
        raise SettingsError(f"{name} сейчас поддерживает только IPv4")
    return value


def _ipv4_address_in_network(name: str, value: str, network_value: str) -> str:
    try:
        network = ipaddress.ip_network(network_value, strict=False)
        address = ipaddress.ip_address(value.split("/", 1)[0])
    except ValueError as exc:
        raise SettingsError(f"{name} должен быть корректным IPv4-адресом внутри AWG_NETWORK") from exc
    if address.version != 4:
        raise SettingsError(f"{name} сейчас поддерживает только IPv4")
    if address not in network:
        raise SettingsError(f"{name} должен входить в AWG_NETWORK")
    if address == network.network_address or address == network.broadcast_address:
        raise SettingsError(f"{name} не должен быть network или broadcast address")
    return str(address)


@dataclass(frozen=True, slots=True)
class Settings:
    bot_token: str = field(repr=False)
    admin_ids: frozenset[int]

    db_path: Path
    log_dir: Path
    bot_lock_path: Path
    bot_drop_pending_updates: bool

    xray_config_path: Path
    xray_service_name: str
    xray_apply_mode: str
    xray_inbound_tag: str
    xray_public_host: str
    xray_public_port: int
    xray_reality_public_key: str
    xray_sni: str
    xray_flow: str
    xray_fingerprint: str
    xray_network_type: str
    xray_short_id: str
    xray_manage_short_ids: bool
    xray_allow_restart_on_rollback: bool
    xray_stats_server: str

    awg_config_path: Path
    awg_interface: str
    awg_network: str
    awg_server_address: str
    awg_endpoint_host: str
    awg_endpoint_port: int
    awg_server_public_key: str
    awg_client_dns: str
    awg_mtu: int | None
    awg_allowed_ips: str
    awg_persistent_keepalive: int
    awg_use_preshared_key: bool

    default_proxy_type: str
    default_proxy_host: str
    default_proxy_port: int | None
    default_proxy_login: str
    default_proxy_password: str = field(repr=False)
    default_proxy_note: str
    audit_retention_days: int
    config_backup_keep_last: int
    sqlite_synchronous: str = "FULL"
    awg_stats_interval: int = 60
    xray_stats_interval: int = 60
    socks5_enabled: bool = False
    socks5_host: str = ""
    socks5_port: int | None = None
    socks5_login_prefix: str = "vpn_socks_"
    socks5_system_user_shell: str = "/usr/sbin/nologin"
    socks5_service_name: str = "danted"
    socks5_public_name: str = "SOCKS5 Proxy"
    socks5_note: str = "SOCKS5 Dante proxy on VDS"
    mtproto_enabled: bool = False
    mtproto_mode: str = "static"
    mtproto_host: str = ""
    mtproto_port: int = 8443
    mtproto_secret: str = field(default="", repr=False)
    mtproto_public_name: str = "Telegram MTProto Proxy"
    mtproto_note: str = "MTProto proxy for Telegram"
    mtproto_stats_url: str = ""
    mtproto_service_name: str = "mtproxy"
    mtproto_binary_path: Path = Path("/usr/local/bin/mtproto-proxy")
    mtproto_run_user: str = "mtproxy"
    mtproto_run_group: str = "mtproxy"
    mtproto_config_dir: Path = Path("/etc/mtproxy")
    mtproto_proxy_secret_path: Path = Path("/etc/mtproxy/proxy-secret")
    mtproto_proxy_multi_conf_path: Path = Path("/etc/mtproxy/proxy-multi.conf")
    mtproto_managed_dir: Path = Path("/etc/mtproxy/vpnbot")
    mtproto_managed_secrets_path: Path = Path("/etc/mtproxy/vpnbot/managed-secrets.json")
    mtproto_managed_env_path: Path = Path("/etc/mtproxy/vpnbot/mtproxy.env")
    mtproto_managed_wrapper_path: Path = Path("/opt/vpn-service/scripts/run-mtproxy-managed")
    mtproto_backup_dir: Path = Path("/etc/mtproxy/vpnbot/backups")
    mtproto_internal_stats_port: int | None = 8888
    mtproto_workers: int = 1
    mtproto_apply_timeout_seconds: int = 10
    mtproto_rollback_on_apply_failure: bool = True
    mtproto_keep_last_backups: int = 10
    privilege_helpers_enabled: bool = False
    helper_staging_root: Path = Path("/run/vpn-bot")
    socks5_user_helper_path: Path = Path("/usr/local/sbin/vpnbot-socks5-user")
    xray_apply_helper_path: Path = Path("/usr/local/sbin/vpnbot-xray-apply")
    awg_apply_helper_path: Path = Path("/usr/local/sbin/vpnbot-awg-apply")
    mtproto_apply_helper_path: Path = Path("/usr/local/sbin/vpnbot-mtproxy-apply")
    xray_helper_staging_dir: Path = Path("/run/vpn-bot/xray")
    awg_helper_staging_dir: Path = Path("/run/vpn-bot/awg")
    mtproto_helper_staging_dir: Path = Path("/run/vpn-bot/mtproxy")
    warp_config_path: Path = Path("/etc/amnezia/out-warp.conf")
    warp_interface: str = "out-warp"
    warp_ping_target: str = "162.159.140.245"
    warp_install_helper_path: Path = Path("/usr/local/sbin/vpnbot-warp-install")
    warp_iface_helper_path: Path = Path("/usr/local/sbin/vpnbot-warp-iface")
    warp_routes_helper_path: Path = Path("/usr/local/sbin/vpnbot-warp-routes")
    warp_status_helper_path: Path = Path("/usr/local/sbin/vpnbot-warp-status")
    warp_helper_staging_dir: Path = Path("/run/vpn-bot/warp")
    # Observer mode (default): the bot's health monitor only watches the tunnel
    # (probes, DB state, admin notifications) and NEVER touches the interface or
    # routes — those are owned by systemd (``awg-quick@out-warp`` +
    # ``warp-routes.service``). Set to False only to restore the legacy model where
    # the bot itself brings the interface up/down and adds/removes the routes.
    warp_monitor_observer_mode: bool = True
    # Time-based switch windows: the monitor declares the tunnel down only after
    # ``fail_window`` seconds of continuous no-response, and back up only after
    # ``recover_window`` seconds of continuous success — so a single dropped (or single
    # recovered) probe never flaps the routing. The probe cadence is adaptive:
    # ``interval`` seconds while the last probe answered, dropping to ``fast_interval``
    # the moment a probe gets no response.
    warp_monitor_fail_window_seconds: int = 60
    warp_monitor_recover_window_seconds: int = 60
    warp_monitor_interval_seconds: int = 10
    warp_monitor_fast_interval_seconds: int = 3
    # Selective-split list and its privileged apply helper.
    # The bot reads the list file directly (0644); writes go exclusively through
    # the helper which validates, writes atomically, and restarts the service.
    warp_split_list_path: Path = Path("/etc/vpnbot/warp-split.list")
    warp_split_apply_helper_path: Path = Path("/usr/local/sbin/vpnbot-warp-split-apply")
    # Privileged on/off/restart/status helper for split ROUTING (table T) plus the
    # root-owned intent marker it manages. Toggling these buttons operates on the
    # selective-split routes only — never the awg-quick@out-warp interface/process.
    # The bot reads the marker directly (root:root 0644) but mutates routing solely
    # through this helper.
    warp_split_state_helper_path: Path = Path("/usr/local/sbin/vpnbot-warp-split-state")
    warp_split_disabled_marker_path: Path = Path("/etc/vpnbot/warp-split.disabled")
    # Route LOCAL proxy egress (Dante/Xray/MTProto) through the WARP tunnel too.
    # When true the Xray config writer binds the freedom outbound's egress source to
    # the tunnel IP (``sendThrough``) so its traffic is diverted into the tunnel by
    # ``vpnbot-warp-routes``. Off by default; flipped on as part of the manual WARP
    # proxy-egress activation runbook. Independent of the tunnel-up monitor above.
    warp_proxy_egress_enabled: bool = False
    health_port: int | None = None
    health_host: str = "127.0.0.1"
    key_expiry_check_interval: int = 1800
    key_expiry_notify_days: tuple[int, ...] = ()
    key_max_trial_days: int = 365
    offsite_backup_encryption_key: str = field(default="", repr=False)
    offsite_backup_interval: int = 604800
    # When enabled, each offsite backup run also sends a second encrypted archive
    # (the "recovery bundle") with .env + service configs needed to rebuild the
    # service on a clean server. The DB backup itself is unchanged.
    offsite_backup_include_configs: bool = True
    # Path to the .env file included in the recovery bundle. None disables only the
    # .env entry (configs are still bundled). Resolved at load time.
    offsite_backup_env_path: Path | None = None
    anomaly_check_interval: int = 300
    anomaly_window_seconds: int = 3600
    anomaly_min_unique_ips: int = 3
    anomaly_auto_revoke: bool = False
    anomaly_cooldown_seconds: int = 7200
    anomaly_concurrent_window_seconds: int = 600
    xray_access_log_path: str = ""
    bot_language: str = "ru"
    # Second VLESS transport (XHTTP+REALITY) as a separate inbound. Inert while
    # disabled: when xray_xhttp_enabled is False the bot behaves exactly as before
    # and never touches the vless-xhttp-reality inbound. Defaulted so existing
    # Settings(...) call sites keep working unchanged.
    xray_xhttp_enabled: bool = False
    xray_xhttp_inbound_tag: str = "vless-xhttp-reality"
    # xray_xhttp_port is retained for back-compat but no longer used to build VLESS
    # (HTTP) links: in the fallback topology http rides vless-in's public :443
    # (xray_public_port), and the XHTTP inbound listens only on loopback.
    xray_xhttp_port: int = 8443
    xray_xhttp_path: str = "/v1/messages/stream"
    # Client-side XHTTP mode written into VLESS (HTTP) links. Default stream-one: a single
    # full-duplex HTTP/2 session, the cleanest fit for direct REALITY and confirmed working
    # through the catch-all fallback. packet-up is a switchable option for request
    # throttling on long sessions or CDN passthrough (xmux rotates connections there);
    # stream-up (two-request) is only for environments without single-request full-duplex
    # and is not needed on direct REALITY.
    xray_xhttp_mode: str = "stream-one"
    # Hysteria2 (apernet v2) integration. The data plane (a standalone hysteria
    # server + the hy2_auth endpoint) runs independently of the bot; these settings
    # only let the bot build client links and gate issuance. HOST/PORT/SNI/OBFS are
    # global (one server, shared by every issued key). OBFS_PASSWORD is the
    # salamander obfuscation password and MUST match /etc/hysteria/config.yaml — a
    # mismatch is a silent client timeout, not an error. AUTH_LISTEN is the
    # loopback host:port the separate hy2_auth process binds (used by the operator
    # to point hysteria's auth url at it); the bot never binds it.
    hysteria2_enabled: bool = False
    hysteria2_host: str = ""
    hysteria2_port: int = 15650
    hysteria2_sni: str = ""
    hysteria2_obfs_password: str = field(default="", repr=False)
    hysteria2_insecure: bool = True
    hysteria2_auth_listen: str = "127.0.0.1:8444"

    def validate_xray_ready(self) -> None:
        if self.xray_apply_mode == "api":
            if not self.xray_inbound_tag:
                raise SettingsError("XRAY_APPLY_MODE=api требует XRAY_INBOUND_TAG")
            if not self.xray_stats_server:
                raise SettingsError("XRAY_APPLY_MODE=api требует XRAY_STATS_SERVER")
        if self.xray_xhttp_enabled:
            if not self.xray_xhttp_inbound_tag:
                raise SettingsError("XRAY_XHTTP_ENABLED=true требует XRAY_XHTTP_INBOUND_TAG")
            if self.xray_xhttp_inbound_tag == self.xray_inbound_tag:
                raise SettingsError("XRAY_XHTTP_INBOUND_TAG не должен совпадать с XRAY_INBOUND_TAG")
            if not self.xray_xhttp_path.startswith("/"):
                raise SettingsError("XRAY_XHTTP_PATH должен начинаться с '/'")
        required = {
            "XRAY_PUBLIC_HOST/XRAY_SERVER_ADDRESS": self.xray_public_host,
            "XRAY_REALITY_PUBLIC_KEY/XRAY_PUBLIC_KEY": self.xray_reality_public_key,
            "XRAY_SNI/XRAY_SERVER_NAME": self.xray_sni,
        }
        if not self.xray_manage_short_ids:
            required["XRAY_SHORT_ID"] = self.xray_short_id
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise SettingsError("Для создания Xray-ключа не заданы: " + ", ".join(missing))
        _xray_short_id(self.xray_short_id, required=not self.xray_manage_short_ids)
        if self.xray_network_type not in {"tcp", "raw"}:
            raise SettingsError("XRAY_NETWORK_TYPE должен быть tcp или raw")
        if self.xray_fingerprint not in {
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
            "randomizedalpn",
            "randomizednoalpn",
        }:
            raise SettingsError("XRAY_FINGERPRINT содержит неподдерживаемое значение")
        if re.fullmatch(r"[A-Za-z0-9_-]+", self.xray_reality_public_key) is None:
            raise SettingsError("XRAY_REALITY_PUBLIC_KEY должен быть base64url-совместимой строкой")

    def validate_hysteria2_ready(self) -> None:
        missing = [
            name
            for name, value in {
                "HYSTERIA2_HOST": self.hysteria2_host,
                "HYSTERIA2_SNI": self.hysteria2_sni,
                "HYSTERIA2_OBFS_PASSWORD": self.hysteria2_obfs_password,
            }.items()
            if not value
        ]
        if missing:
            raise SettingsError("Для создания Hysteria2-ключа не заданы: " + ", ".join(missing))
        if not 1 <= self.hysteria2_port <= 65535:
            raise SettingsError("Для создания Hysteria2-ключа HYSTERIA2_PORT должен быть в диапазоне 1–65535")

    def is_hysteria2_ready(self) -> bool:
        """Non-raising form of validate_hysteria2_ready() for gating UI affordances.

        Used to hide the Hysteria2 create button when HOST/SNI/OBFS are not yet
        configured, so the user never sees an option that would fail on issuance.
        Reuses validate_hysteria2_ready() so the two cannot drift.
        """
        try:
            self.validate_hysteria2_ready()
        except SettingsError:
            return False
        return True

    def validate_awg_ready(self) -> None:
        missing = [
            name
            for name, value in {
                "AWG_ENDPOINT_HOST": self.awg_endpoint_host,
                "AWG_SERVER_PUBLIC_KEY": self.awg_server_public_key,
            }.items()
            if not value
        ]
        if missing:
            raise SettingsError("Для создания AWG-ключа не заданы: " + ", ".join(missing))
        if not 1 <= self.awg_endpoint_port <= 65535:
            raise SettingsError("Для создания AWG-ключа AWG_ENDPOINT_PORT должен быть в диапазоне 1–65535")


def _offsite_env_path(env_path: str | Path | None) -> Path | None:
    """Resolve which .env file to bundle into the offsite recovery archive.

    Precedence: explicit OFFSITE_BACKUP_ENV_PATH, then the path passed to
    load_settings(), then dotenv's own discovery (find_dotenv, same search
    load_dotenv(None) uses). Returns None when no .env can be located.
    """
    explicit = _optional("OFFSITE_BACKUP_ENV_PATH")
    if explicit:
        return Path(explicit)
    if env_path:
        return Path(env_path)
    found = find_dotenv(usecwd=True)
    return Path(found) if found else None


def load_settings(env_path: str | Path | None = None) -> Settings:
    load_dotenv(env_path)
    helper_staging_root = Path(_optional("HELPER_STAGING_ROOT", "/run/vpn-bot"))
    awg_dns = _optional("AWG_DNS") or _optional("AWG_CLIENT_DNS", "1.1.1.1")
    xray_manage_short_ids = _bool("XRAY_MANAGE_SHORT_IDS", False)
    xray_short_id = _xray_short_id(_optional("XRAY_SHORT_ID"), required=False)
    xray_port = _optional("XRAY_PUBLIC_PORT") or _optional("XRAY_SERVER_PORT")
    socks5_enabled = _bool("SOCKS5_ENABLED", False)
    socks5_login_prefix = _socks5_login_prefix(_optional("SOCKS5_LOGIN_PREFIX", "vpn_socks_"))
    socks5_host = _required("SOCKS5_HOST") if socks5_enabled else _optional("SOCKS5_HOST")
    socks5_port = (
        _int_range("SOCKS5_PORT", None, 1, 65535)
        if socks5_enabled
        else _optional_int_range("SOCKS5_PORT", 1, 65535)
    )
    mtproto_enabled = _bool("MTPROTO_ENABLED", False)
    mtproto_mode = _choice("MTPROTO_MODE", "static", {"static", "managed"})
    mtproto_host = _required("MTPROTO_HOST") if mtproto_enabled else _optional("MTPROTO_HOST")
    mtproto_secret = (
        _required("MTPROTO_SECRET")
        if mtproto_enabled and mtproto_mode == "static"
        else _optional("MTPROTO_SECRET")
    )
    mtproto_service_name = _optional("MTPROTO_SERVICE_NAME", "mtproxy")
    mtproto_binary_path = _optional("MTPROTO_BINARY_PATH", "/usr/local/bin/mtproto-proxy")
    mtproto_run_user = _optional("MTPROTO_RUN_USER", "mtproxy")
    mtproto_run_group = _optional("MTPROTO_RUN_GROUP", "mtproxy")
    mtproto_config_dir = _optional("MTPROTO_CONFIG_DIR", "/etc/mtproxy")
    mtproto_proxy_secret_path = _optional("MTPROTO_PROXY_SECRET_PATH", "/etc/mtproxy/proxy-secret")
    mtproto_proxy_multi_conf_path = _optional("MTPROTO_PROXY_MULTI_CONF_PATH", "/etc/mtproxy/proxy-multi.conf")
    mtproto_managed_dir = _optional("MTPROTO_MANAGED_DIR", "/etc/mtproxy/vpnbot")
    mtproto_managed_secrets_path = _optional(
        "MTPROTO_MANAGED_SECRETS_PATH",
        str(Path(mtproto_managed_dir) / "managed-secrets.json"),
    )
    mtproto_managed_env_path = _optional("MTPROTO_MANAGED_ENV_PATH", str(Path(mtproto_managed_dir) / "mtproxy.env"))
    mtproto_managed_wrapper_path = _optional(
        "MTPROTO_MANAGED_WRAPPER_PATH",
        "/opt/vpn-service/scripts/run-mtproxy-managed",
    )
    mtproto_backup_dir = _optional("MTPROTO_BACKUP_DIR", str(Path(mtproto_managed_dir) / "backups"))
    if mtproto_enabled and mtproto_mode == "managed":
        _non_empty("MTPROTO_SERVICE_NAME", mtproto_service_name)
        _non_empty("MTPROTO_BINARY_PATH", mtproto_binary_path)
        _non_empty("MTPROTO_PROXY_SECRET_PATH", mtproto_proxy_secret_path)
        _non_empty("MTPROTO_PROXY_MULTI_CONF_PATH", mtproto_proxy_multi_conf_path)
        _non_empty("MTPROTO_MANAGED_DIR", mtproto_managed_dir)
        _non_empty("MTPROTO_MANAGED_SECRETS_PATH", mtproto_managed_secrets_path)
        _non_empty("MTPROTO_MANAGED_ENV_PATH", mtproto_managed_env_path)
        _non_empty("MTPROTO_MANAGED_WRAPPER_PATH", mtproto_managed_wrapper_path)
        _non_empty("MTPROTO_BACKUP_DIR", mtproto_backup_dir)
    awg_network = _ipv4_network("AWG_NETWORK", _optional("AWG_NETWORK", "10.0.0.0/24"))
    awg_server_address = _ipv4_address_in_network(
        "AWG_SERVER_ADDRESS",
        _optional("AWG_SERVER_ADDRESS", "10.0.0.1"),
        awg_network,
    )
    xray_xhttp_enabled = _bool("XRAY_XHTTP_ENABLED", False)
    xray_inbound_tag = _optional("XRAY_INBOUND_TAG")
    xray_xhttp_inbound_tag = _optional("XRAY_XHTTP_INBOUND_TAG", "vless-xhttp-reality")
    if xray_xhttp_enabled:
        # Catch XHTTP misconfig at startup rather than lazily on the first key
        # issuance (validate_xray_ready). A blank tag, or one colliding with the
        # primary inbound, would otherwise route both transports into one inbound.
        if not xray_xhttp_inbound_tag:
            raise SettingsError("XRAY_XHTTP_ENABLED=true требует непустой XRAY_XHTTP_INBOUND_TAG")
        if xray_xhttp_inbound_tag == xray_inbound_tag:
            raise SettingsError("XRAY_XHTTP_INBOUND_TAG не должен совпадать с XRAY_INBOUND_TAG")
    return Settings(
        bot_token=_required("BOT_TOKEN"),
        admin_ids=_admin_ids(_required("ADMIN_IDS")),
        db_path=Path(_optional("DB_PATH", "/opt/vpn-service/data/vpn.db")),
        sqlite_synchronous=_choice("SQLITE_SYNCHRONOUS", "FULL", {"full", "normal", "extra"}).upper(),
        log_dir=Path(_optional("LOG_DIR", "/opt/vpn-service/logs")),
        bot_lock_path=Path(_optional("BOT_LOCK_PATH", "/run/vpn-bot/vpn-bot.lock")),
        bot_drop_pending_updates=_bool("BOT_DROP_PENDING_UPDATES", False),
        xray_config_path=Path(_optional("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json")),
        xray_service_name=_optional("XRAY_SERVICE_NAME", "xray"),
        xray_apply_mode=_choice("XRAY_APPLY_MODE", "api", {"reload", "restart", "api"}),
        xray_inbound_tag=xray_inbound_tag,
        xray_public_host=_no_control_chars(
            "XRAY_PUBLIC_HOST", _optional("XRAY_PUBLIC_HOST") or _optional("XRAY_SERVER_ADDRESS")
        ),
        xray_public_port=(
            _int_range("XRAY_PUBLIC_PORT" if _optional("XRAY_PUBLIC_PORT") else "XRAY_SERVER_PORT", 443, 1, 65535)
            if xray_port
            else 443
        ),
        xray_reality_public_key=_optional("XRAY_REALITY_PUBLIC_KEY") or _optional("XRAY_PUBLIC_KEY"),
        xray_sni=_no_control_chars("XRAY_SNI", _optional("XRAY_SNI") or _optional("XRAY_SERVER_NAME")),
        xray_flow=_no_control_chars("XRAY_FLOW", _optional("XRAY_FLOW", "xtls-rprx-vision")),
        xray_fingerprint=_choice(
            "XRAY_FINGERPRINT",
            "chrome",
            {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizedalpn", "randomizednoalpn"},
        ),
        xray_network_type=_choice("XRAY_NETWORK_TYPE", "tcp", {"tcp", "raw"}),
        xray_short_id=xray_short_id,
        xray_manage_short_ids=xray_manage_short_ids,
        xray_allow_restart_on_rollback=_bool("XRAY_ALLOW_RESTART_ON_ROLLBACK", False),
        xray_stats_server=_optional("XRAY_STATS_SERVER"),
        xray_xhttp_enabled=xray_xhttp_enabled,
        xray_xhttp_inbound_tag=xray_xhttp_inbound_tag,
        xray_xhttp_port=_int_range("XRAY_XHTTP_PORT", 8443, 1, 65535),
        xray_xhttp_path=_no_control_chars("XRAY_XHTTP_PATH", _optional("XRAY_XHTTP_PATH", "/v1/messages/stream")),
        xray_xhttp_mode=_choice(
            "XRAY_XHTTP_MODE",
            "stream-one",
            {"auto", "packet-up", "stream-up", "stream-one"},
        ),
        awg_config_path=Path(_optional("AWG_CONFIG_PATH", "/etc/amnezia/amneziawg/awg0.conf")),
        awg_interface=_optional("AWG_INTERFACE", "awg0"),
        awg_network=awg_network,
        awg_server_address=awg_server_address,
        awg_endpoint_host=_no_control_chars("AWG_ENDPOINT_HOST", _optional("AWG_ENDPOINT_HOST")),
        awg_endpoint_port=_int_range("AWG_ENDPOINT_PORT", 0, 0, 65535),
        awg_server_public_key=_optional("AWG_SERVER_PUBLIC_KEY"),
        awg_client_dns=_no_control_chars("AWG_DNS", awg_dns),
        awg_mtu=_optional_int_range("AWG_MTU", 576, 1500),
        awg_allowed_ips=_no_control_chars("AWG_ALLOWED_IPS", _optional("AWG_ALLOWED_IPS", "0.0.0.0/0, ::/0")),
        awg_persistent_keepalive=_int_range("AWG_PERSISTENT_KEEPALIVE", 25, 0, 86400),
        awg_use_preshared_key=_bool("AWG_USE_PRESHARED_KEY", True),
        awg_stats_interval=_int_range("AWG_STATS_INTERVAL", 60, 0, 3600),
        xray_stats_interval=_int_range("XRAY_STATS_INTERVAL", 60, 0, 3600),
        default_proxy_type=_optional("DEFAULT_PROXY_TYPE"),
        default_proxy_host=_optional("DEFAULT_PROXY_HOST"),
        default_proxy_port=_optional_int_range("DEFAULT_PROXY_PORT", 1, 65535),
        default_proxy_login=_optional("DEFAULT_PROXY_LOGIN"),
        default_proxy_password=_optional("DEFAULT_PROXY_PASSWORD"),
        default_proxy_note=_optional("DEFAULT_PROXY_NOTE"),
        audit_retention_days=_int_range("AUDIT_RETENTION_DAYS", 180, 0, 3650),
        config_backup_keep_last=_int_range("CONFIG_BACKUP_KEEP_LAST", 20, 1, 500),
        socks5_enabled=socks5_enabled,
        socks5_host=_no_control_chars("SOCKS5_HOST", socks5_host),
        socks5_port=socks5_port,
        socks5_login_prefix=socks5_login_prefix,
        socks5_system_user_shell=_optional("SOCKS5_SYSTEM_USER_SHELL", "/usr/sbin/nologin"),
        socks5_service_name=_optional("SOCKS5_SERVICE_NAME", "danted"),
        socks5_public_name=_optional("SOCKS5_PUBLIC_NAME", "SOCKS5 Proxy"),
        socks5_note=_optional("SOCKS5_NOTE", "SOCKS5 Dante proxy on VDS"),
        mtproto_enabled=mtproto_enabled,
        mtproto_mode=mtproto_mode,
        mtproto_host=_no_control_chars("MTPROTO_HOST", mtproto_host),
        mtproto_port=_int_range("MTPROTO_PORT", 8443, 1, 65535),
        mtproto_secret=mtproto_secret,
        mtproto_public_name=_optional("MTPROTO_PUBLIC_NAME", "Telegram MTProto Proxy"),
        mtproto_note=_optional("MTPROTO_NOTE", "MTProto proxy for Telegram"),
        mtproto_stats_url=_optional("MTPROTO_STATS_URL"),
        mtproto_service_name=mtproto_service_name,
        mtproto_binary_path=Path(mtproto_binary_path),
        mtproto_run_user=_non_empty("MTPROTO_RUN_USER", mtproto_run_user)
        if mtproto_enabled and mtproto_mode == "managed"
        else mtproto_run_user,
        mtproto_run_group=_non_empty("MTPROTO_RUN_GROUP", mtproto_run_group)
        if mtproto_enabled and mtproto_mode == "managed"
        else mtproto_run_group,
        mtproto_config_dir=Path(_non_empty("MTPROTO_CONFIG_DIR", mtproto_config_dir))
        if mtproto_enabled and mtproto_mode == "managed"
        else Path(mtproto_config_dir),
        mtproto_proxy_secret_path=Path(mtproto_proxy_secret_path),
        mtproto_proxy_multi_conf_path=Path(mtproto_proxy_multi_conf_path),
        mtproto_managed_dir=Path(mtproto_managed_dir),
        mtproto_managed_secrets_path=Path(mtproto_managed_secrets_path),
        mtproto_managed_env_path=Path(mtproto_managed_env_path),
        mtproto_managed_wrapper_path=Path(mtproto_managed_wrapper_path),
        mtproto_backup_dir=Path(mtproto_backup_dir),
        mtproto_internal_stats_port=_optional_int_range("MTPROTO_INTERNAL_STATS_PORT", 1, 65535) or 8888,
        mtproto_workers=_int_range("MTPROTO_WORKERS", 1, 1, 1024),
        mtproto_apply_timeout_seconds=_int_range("MTPROTO_APPLY_TIMEOUT_SECONDS", 10, 1, 3600),
        mtproto_rollback_on_apply_failure=_bool("MTPROTO_ROLLBACK_ON_APPLY_FAILURE", True),
        mtproto_keep_last_backups=_int_range("MTPROTO_KEEP_LAST_BACKUPS", 10, 0, 1000),
        health_port=_optional_int_range("HEALTH_PORT", 1, 65535),
        health_host=_optional("HEALTH_HOST", "127.0.0.1") or "127.0.0.1",
        key_expiry_check_interval=_int_range("KEY_EXPIRY_CHECK_INTERVAL", 1800, 0, 86400),
        key_expiry_notify_days=_int_list_positive("KEY_EXPIRY_NOTIFY_DAYS", ()),
        key_max_trial_days=_int_range("KEY_MAX_TRIAL_DAYS", 365, 1, 3650),
        privilege_helpers_enabled=_bool("PRIVILEGE_HELPERS_ENABLED", False),
        helper_staging_root=helper_staging_root,
        offsite_backup_encryption_key=_fernet_key("OFFSITE_BACKUP_ENCRYPTION_KEY"),
        offsite_backup_interval=_int_range("OFFSITE_BACKUP_INTERVAL", 604800, 0, 365 * 24 * 3600),
        offsite_backup_include_configs=_bool("OFFSITE_BACKUP_INCLUDE_CONFIGS", True),
        offsite_backup_env_path=_offsite_env_path(env_path),
        anomaly_check_interval=_int_range("ANOMALY_CHECK_INTERVAL", 300, 0, 86400),
        anomaly_window_seconds=_int_range("ANOMALY_WINDOW_SECONDS", 3600, 60, 86400),
        anomaly_min_unique_ips=_int_range("ANOMALY_MIN_UNIQUE_IPS", 3, 1, 1000),
        anomaly_auto_revoke=_bool("ANOMALY_AUTO_REVOKE", False),
        anomaly_cooldown_seconds=_int_range("ANOMALY_COOLDOWN_SECONDS", 7200, 0, 86400),
        anomaly_concurrent_window_seconds=_int_range("ANOMALY_CONCURRENT_WINDOW_SECONDS", 600, 0, 86400),
        xray_access_log_path=_optional("XRAY_ACCESS_LOG_PATH"),
        socks5_user_helper_path=Path(_optional("SOCKS5_USER_HELPER_PATH", "/usr/local/sbin/vpnbot-socks5-user")),
        xray_apply_helper_path=Path(_optional("XRAY_APPLY_HELPER_PATH", "/usr/local/sbin/vpnbot-xray-apply")),
        awg_apply_helper_path=Path(_optional("AWG_APPLY_HELPER_PATH", "/usr/local/sbin/vpnbot-awg-apply")),
        mtproto_apply_helper_path=Path(_optional("MTPROTO_APPLY_HELPER_PATH", "/usr/local/sbin/vpnbot-mtproxy-apply")),
        xray_helper_staging_dir=Path(_optional("XRAY_HELPER_STAGING_DIR", str(helper_staging_root / "xray"))),
        awg_helper_staging_dir=Path(_optional("AWG_HELPER_STAGING_DIR", str(helper_staging_root / "awg"))),
        mtproto_helper_staging_dir=Path(_optional("MTPROTO_HELPER_STAGING_DIR", str(helper_staging_root / "mtproxy"))),
        warp_config_path=Path(_optional("WARP_CONFIG_PATH", "/etc/amnezia/out-warp.conf")),
        warp_interface=_optional("WARP_INTERFACE", "out-warp"),
        warp_ping_target=_optional("WARP_PING_TARGET", "162.159.140.245"),
        warp_install_helper_path=Path(_optional("WARP_INSTALL_HELPER_PATH", "/usr/local/sbin/vpnbot-warp-install")),
        warp_iface_helper_path=Path(_optional("WARP_IFACE_HELPER_PATH", "/usr/local/sbin/vpnbot-warp-iface")),
        warp_routes_helper_path=Path(_optional("WARP_ROUTES_HELPER_PATH", "/usr/local/sbin/vpnbot-warp-routes")),
        warp_status_helper_path=Path(_optional("WARP_STATUS_HELPER_PATH", "/usr/local/sbin/vpnbot-warp-status")),
        warp_helper_staging_dir=Path(_optional("WARP_HELPER_STAGING_DIR", str(helper_staging_root / "warp"))),
        warp_monitor_observer_mode=_bool("WARP_MONITOR_OBSERVER_MODE", True),
        warp_monitor_fail_window_seconds=_int_range("WARP_MONITOR_FAIL_WINDOW_SECONDS", 60, 1, 3600),
        warp_monitor_recover_window_seconds=_int_range("WARP_MONITOR_RECOVER_WINDOW_SECONDS", 60, 1, 3600),
        warp_monitor_interval_seconds=_int_range("WARP_MONITOR_INTERVAL_SECONDS", 10, 1, 3600),
        warp_monitor_fast_interval_seconds=_int_range("WARP_MONITOR_FAST_INTERVAL_SECONDS", 3, 1, 3600),
        warp_split_list_path=Path(
            _optional("WARP_SPLIT_LIST_PATH", "/etc/vpnbot/warp-split.list")
        ),
        warp_split_apply_helper_path=Path(
            _optional("WARP_SPLIT_APPLY_HELPER_PATH", "/usr/local/sbin/vpnbot-warp-split-apply")
        ),
        warp_split_state_helper_path=Path(
            _optional("WARP_SPLIT_STATE_HELPER_PATH", "/usr/local/sbin/vpnbot-warp-split-state")
        ),
        warp_split_disabled_marker_path=Path(
            _optional("WARP_SPLIT_DISABLED_MARKER_PATH", "/etc/vpnbot/warp-split.disabled")
        ),
        warp_proxy_egress_enabled=_bool("WARP_PROXY_EGRESS", False),
        bot_language=_choice("BOT_LANGUAGE", "ru", {"ru", "en"}),
        hysteria2_enabled=_bool("HYSTERIA2_ENABLED", False),
        hysteria2_host=_no_control_chars("HYSTERIA2_HOST", _optional("HYSTERIA2_HOST")),
        hysteria2_port=_int_range("HYSTERIA2_PORT", 15650, 1, 65535),
        hysteria2_sni=_no_control_chars("HYSTERIA2_SNI", _optional("HYSTERIA2_SNI")),
        hysteria2_obfs_password=_no_control_chars("HYSTERIA2_OBFS_PASSWORD", _optional("HYSTERIA2_OBFS_PASSWORD")),
        hysteria2_insecure=_bool("HYSTERIA2_INSECURE", True),
        hysteria2_auth_listen=_loopback_host_port(
            "HYSTERIA2_AUTH_LISTEN", _optional("HYSTERIA2_AUTH_LISTEN", "127.0.0.1:8444")
        ),
    )
