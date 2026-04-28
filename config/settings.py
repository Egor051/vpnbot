from __future__ import annotations

import os
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


class SettingsError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SettingsError(f"Не задана обязательная переменная окружения {name}")
    return value


def _optional(name: str, default: str = "") -> str:
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
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _admin_ids(raw: str) -> frozenset[int]:
    values: set[int] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            values.add(int(item))
        except ValueError as exc:
            raise SettingsError("ADMIN_IDS должен быть списком Telegram ID через запятую") from exc
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


@dataclass(frozen=True, slots=True)
class Settings:
    bot_token: str
    admin_ids: frozenset[int]

    db_path: Path
    log_dir: Path
    bot_lock_path: Path
    bot_drop_pending_updates: bool

    xray_config_path: Path
    xray_service_name: str
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
    default_proxy_password: str
    default_proxy_note: str
    audit_retention_days: int
    config_backup_keep_last: int

    def validate_xray_ready(self) -> None:
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

    def validate_awg_ready(self) -> None:
        missing = [
            name
            for name, value in {
                "AWG_ENDPOINT_HOST": self.awg_endpoint_host,
            }.items()
            if not value
        ]
        if missing:
            raise SettingsError("Для создания AWG-ключа не заданы: " + ", ".join(missing))


def load_settings(env_path: str | Path | None = None) -> Settings:
    load_dotenv(env_path)
    awg_dns = _optional("AWG_DNS") or _optional("AWG_CLIENT_DNS", "1.1.1.1")
    xray_manage_short_ids = _bool("XRAY_MANAGE_SHORT_IDS", False)
    xray_short_id = _xray_short_id(_optional("XRAY_SHORT_ID"), required=False)
    xray_port = _optional("XRAY_PUBLIC_PORT") or _optional("XRAY_SERVER_PORT")
    awg_network = _ipv4_network("AWG_NETWORK", _optional("AWG_NETWORK", "10.0.0.0/24"))
    return Settings(
        bot_token=_required("BOT_TOKEN"),
        admin_ids=_admin_ids(_required("ADMIN_IDS")),
        db_path=Path(_optional("DB_PATH", "/opt/vpn-service/data/vpn.db")),
        log_dir=Path(_optional("LOG_DIR", "/opt/vpn-service/logs")),
        bot_lock_path=Path(_optional("BOT_LOCK_PATH", "/run/vpn-bot.lock")),
        bot_drop_pending_updates=_bool("BOT_DROP_PENDING_UPDATES", False),
        xray_config_path=Path(_optional("XRAY_CONFIG_PATH", "/usr/local/etc/xray/config.json")),
        xray_service_name=_optional("XRAY_SERVICE_NAME", "xray"),
        xray_inbound_tag=_optional("XRAY_INBOUND_TAG"),
        xray_public_host=_optional("XRAY_PUBLIC_HOST") or _optional("XRAY_SERVER_ADDRESS"),
        xray_public_port=(
            _int_range("XRAY_PUBLIC_PORT" if _optional("XRAY_PUBLIC_PORT") else "XRAY_SERVER_PORT", 443, 1, 65535)
            if xray_port
            else 443
        ),
        xray_reality_public_key=_optional("XRAY_REALITY_PUBLIC_KEY") or _optional("XRAY_PUBLIC_KEY"),
        xray_sni=_optional("XRAY_SNI") or _optional("XRAY_SERVER_NAME"),
        xray_flow=_optional("XRAY_FLOW", "xtls-rprx-vision"),
        xray_fingerprint=_optional("XRAY_FINGERPRINT", "chrome"),
        xray_network_type=_optional("XRAY_NETWORK_TYPE", "tcp"),
        xray_short_id=xray_short_id,
        xray_manage_short_ids=xray_manage_short_ids,
        xray_allow_restart_on_rollback=_bool("XRAY_ALLOW_RESTART_ON_ROLLBACK", False),
        xray_stats_server=_optional("XRAY_STATS_SERVER"),
        awg_config_path=Path(_optional("AWG_CONFIG_PATH", "/etc/amnezia/amneziawg/awg0.conf")),
        awg_interface=_optional("AWG_INTERFACE", "awg0"),
        awg_network=awg_network,
        awg_server_address=_optional("AWG_SERVER_ADDRESS", "10.0.0.1"),
        awg_endpoint_host=_optional("AWG_ENDPOINT_HOST"),
        awg_endpoint_port=_int_range("AWG_ENDPOINT_PORT", 0, 0, 65535),
        awg_server_public_key=_optional("AWG_SERVER_PUBLIC_KEY"),
        awg_client_dns=awg_dns,
        awg_mtu=_optional_int_range("AWG_MTU", 576, 1500),
        awg_allowed_ips=_optional("AWG_ALLOWED_IPS", "0.0.0.0/0, ::/0"),
        awg_persistent_keepalive=_int_range("AWG_PERSISTENT_KEEPALIVE", 25, 0, 86400),
        awg_use_preshared_key=_bool("AWG_USE_PRESHARED_KEY", True),
        default_proxy_type=_optional("DEFAULT_PROXY_TYPE"),
        default_proxy_host=_optional("DEFAULT_PROXY_HOST"),
        default_proxy_port=_optional_int_range("DEFAULT_PROXY_PORT", 1, 65535),
        default_proxy_login=_optional("DEFAULT_PROXY_LOGIN"),
        default_proxy_password=_optional("DEFAULT_PROXY_PASSWORD"),
        default_proxy_note=_optional("DEFAULT_PROXY_NOTE"),
        audit_retention_days=_int_range("AUDIT_RETENTION_DAYS", 180, 0, 3650),
        config_backup_keep_last=_int_range("CONFIG_BACKUP_KEEP_LAST", 20, 1, 500),
    )
