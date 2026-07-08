
from datetime import datetime, timezone
from urllib.parse import quote

from aiogram.types import User as TgUser

from i18n import t
from models.dto import (
    AccessRequest,
    KeyTrafficStatsView,
    ProxyAccessStatsItem,
    ProxyAdminStats,
    ProxyAccess,
    ProxyEntry,
    ProxyLifecycleStats,
    ProxyServiceStatus,
    ProxyUserStats,
    TrafficStats,
    UnblockUserWarning,
    User,
    VpnKey,
)
from repositories.protocol_modules import PROTOCOL_DISPLAY, ProtocolModule
from models.enums import ProxyAccessStatus, ProxyAccessType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.announcements import AnnouncementBatch
from services.backend_health import BackendHealthStatus
from services.dashboard import DashboardSnapshot
from services.health import HealthCheckResult
from services.online_clients import OnlineClients
from services.server_status import ServerStatus
from utils.formatting import (
    code,
    format_bytes,
    format_expiry_date,
    format_greeting_name,
    format_msk_datetime,
    format_user_display,
    h,
)
from utils.redact import redact as _redact


def short_note(note: str | None, limit: int = 42) -> str:
    if not note:
        return t("none")
    value = note.strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def role_text(role: UserRole) -> str:
    return {
        UserRole.SUPERADMIN: t("role_superadmin"),
        UserRole.APPROVED_USER: t("role_approved"),
        UserRole.PENDING_USER: t("role_pending"),
        UserRole.BLOCKED_USER: t("role_blocked"),
    }.get(role, role.value)


def status_text(status: VpnKeyStatus) -> str:
    return {
        VpnKeyStatus.PENDING_APPLY: t("key_status_pending_apply"),
        VpnKeyStatus.ACTIVE: t("key_status_active"),
        VpnKeyStatus.APPLY_FAILED: t("key_status_apply_failed"),
        VpnKeyStatus.PENDING_REVOKE: t("key_status_pending_revoke"),
        VpnKeyStatus.REVOKED: t("key_status_revoked"),
        VpnKeyStatus.PENDING_DELETE: t("key_status_pending_delete"),
        VpnKeyStatus.DELETE_FAILED: t("key_status_delete_failed"),
        VpnKeyStatus.DELETED: t("key_status_deleted"),
        VpnKeyStatus.FAILED: t("key_status_failed"),
    }.get(status, status.value)


def key_type_label(key: VpnKey) -> str:
    """Human label for a key by protocol + transport.

    "VLESS (TCP)" / "VLESS (HTTP)" for Xray keys, "AmneziaWG" for AWG keys.
    Legacy Xray keys (no/unknown transport) read as "VLESS (TCP)".
    """
    if key.key_type == VpnKeyType.AWG:
        return "AmneziaWG"
    if key.key_type == VpnKeyType.HYSTERIA2:
        return "Hysteria2"
    transport = str(getattr(key, "transport", "tcp") or "tcp").lower()
    return "VLESS (HTTP)" if transport == "http" else "VLESS (TCP)"


def key_title(key: VpnKey) -> str:
    return f"{key_type_label(key)} #{key.id}"


def key_note_for_viewer(key: VpnKey, viewer_user_id: int) -> str | None:
    if not key.note:
        return None
    note_owner_id = getattr(key, "note_owner_id", None) or key.owner_user_id
    return key.note if int(note_owner_id) == int(viewer_user_id) else None


def key_display_label(key: VpnKey, viewer_user_id: int | None = None) -> str:
    if key.email_label:
        return key.email_label
    note = key_note_for_viewer(key, viewer_user_id) if viewer_user_id is not None else None
    if note:
        return note
    if key.public_key:
        return key.public_key[:12] + "..."
    return key_title(key)


def main_menu_text(user: TgUser) -> str:
    name = format_greeting_name(user.id, user.first_name, user.username)
    return t("main_menu_text", name=name, rules=t("usage_rules"), warning=t("server_restart_warning"))


def settings_intro_text() -> str:
    """Build the settings panel text: explanations of each button shown above them."""
    return f"{t('settings_title')}\n\n{t('settings_intro')}"


def personal_cabinet_text(
    user: User,
    *,
    active_xray: int,
    active_awg: int,
    active_hysteria2: int,
    downloaded_bytes: int,
    uploaded_bytes: int,
    proxy_count: int,
) -> str:
    """Build the personal cabinet card: profile fields plus a personal summary."""
    username = f"@{user.username}" if user.username else t("not_specified")
    lines = [
        t("cabinet_title"),
        f"{t('field_tg_id')}: {code(user.telegram_user_id)}",
        f"{t('field_name')}: {h(user.first_name or t('not_specified'))}",
        f"{t('field_username')}: {h(username)}",
        f"{t('field_role')}: {h(role_text(user.role))}",
        f"{t('field_registered')}: {h(format_msk_datetime(user.created_at))}",
        "",
        t(
            "cabinet_active_keys",
            total=active_xray + active_awg + active_hysteria2,
            xray=active_xray,
            awg=active_awg,
            hysteria2=active_hysteria2,
        ),
        t("cabinet_traffic", down=format_bytes(downloaded_bytes), up=format_bytes(uploaded_bytes)),
        t("cabinet_proxy_count", count=proxy_count),
    ]
    return "\n".join(lines)


def key_list_card(key: VpnKey, *, viewer_user_id: int) -> str:
    note = key_note_for_viewer(key, viewer_user_id)
    label = key_display_label(key, viewer_user_id=viewer_user_id)
    parts = [
        f"<b>{key_title(key)}</b>",
        f"{t('field_status')}: {h(status_text(key.status))}",
        f"{t('field_label')}: {code(label)}",
        f"{t('field_created')}: {h(format_msk_datetime(key.created_at))}",
    ]
    if key.expires_at:
        parts.append(f"{t('field_expires')}: {h(format_expiry_date(key.expires_at))}")
    if not note or label != note:
        parts.append(f"{t('field_note')}: {h(short_note(note))}")
    if key.client_ip and key.key_type != VpnKeyType.AWG:
        parts.append(f"{t('field_ip')}: {code(key.client_ip)}")
    return "\n".join(parts)


def keys_page_text(keys: list[VpnKey], page: int, *, viewer_user_id: int, owner_user_id: int | None = None) -> str:
    title = t("keys_user_title") if owner_user_id else t("keys_my_title")
    if not keys:
        return f"{title}\n\n{t('one_key_one_device')}\n\n{t('keys_page_empty')}"
    xray = [key for key in keys if key.key_type == VpnKeyType.XRAY]
    awg = [key for key in keys if key.key_type == VpnKeyType.AWG]
    hysteria2 = [key for key in keys if key.key_type == VpnKeyType.HYSTERIA2]
    sections = [t("keys_page_title", title=title, page=page + 1), t("one_key_one_device")]
    if xray:
        sections.append("<b>VLESS</b>\n" + "\n\n".join(key_list_card(key, viewer_user_id=viewer_user_id) for key in xray))
    if awg:
        sections.append("<b>AmneziaWG</b>\n" + "\n\n".join(key_list_card(key, viewer_user_id=viewer_user_id) for key in awg))
    if hysteria2:
        sections.append("<b>Hysteria2</b>\n" + "\n\n".join(key_list_card(key, viewer_user_id=viewer_user_id) for key in hysteria2))
    return "\n\n".join(sections)


def key_detail_text(key: VpnKey, *, viewer_user_id: int) -> str:
    note = key_note_for_viewer(key, viewer_user_id)
    label = key_display_label(key, viewer_user_id=viewer_user_id)
    lines = [
        f"<b>{key_title(key)}</b>",
        f"{t('field_status')}: {h(status_text(key.status))}",
        f"{t('field_label')}: {code(label)}",
        f"{t('field_created')}: {h(format_msk_datetime(key.created_at))}",
        f"{t('field_updated')}: {h(format_msk_datetime(key.updated_at))}",
    ]
    if key.expires_at:
        lines.append(f"{t('field_expires')}: {h(format_expiry_date(key.expires_at))}")
    if not note or label != note:
        lines.append(f"{t('field_note')}: {h(note or t('none'))}")
    if key.key_type == VpnKeyType.AWG:
        mtu = key.payload.get("mtu")
        if mtu is not None:
            lines.append(f"MTU: {h(str(int(str(mtu))))}")
    else:
        fp = key.payload.get("fingerprint")
        if fp:
            lines.append(f"Fingerprint: {h(str(fp))}")
        if key.client_ip:
            lines.append(f"{t('field_ip')}: {code(key.client_ip)}")
        if key.public_key:
            lines.append(f"{t('field_pubkey')}: {code(key.public_key)}")
    return "\n".join(lines)


def traffic_stats_text(view: KeyTrafficStatsView, *, viewer_user_id: int) -> str:
    key = view.key
    owner = view.owner
    owner_text = (
        format_user_display(owner.telegram_user_id, owner.username)
        if owner is not None
        else format_user_display(key.owner_user_id, key.username)
    )
    label = key_display_label(key, viewer_user_id=viewer_user_id)
    lines = [
        t("stats_title", key_title=key_title(key)),
        f"{t('field_type')}: {h(key_type_label(key))}",
        f"{t('field_label')}: {code(label)}",
        f"{t('field_owner')}: {owner_text}",
    ]
    note = key_note_for_viewer(key, viewer_user_id)
    if note and label != note:
        lines.append(f"{t('field_note')}: {h(note)}")
    stats = view.stats
    if stats is None or not stats.available:
        lines.append("")
        if stats and stats.last_success_at:
            lines.append(t("stats_unavailable_now"))
            lines.append(f"{t('field_downloaded')}: {h(format_bytes(stats.downloaded_bytes))}")
            lines.append(f"{t('field_uploaded')}: {h(format_bytes(stats.uploaded_bytes))}")
            lines.append(f"{t('field_updated_at')}: {h(format_msk_datetime(stats.last_success_at))}")
        else:
            lines.append(t("stats_not_available_yet"))
        if stats and stats.unavailable_reason:
            lines.append(f"{t('field_reason')}: {h(stats.unavailable_reason)}")
        return "\n".join(lines)
    lines.extend(
        [
            f"{t('field_downloaded')}: {h(format_bytes(stats.downloaded_bytes))}",
            f"{t('field_uploaded')}: {h(format_bytes(stats.uploaded_bytes))}",
            f"{t('field_updated_at')}: {h(format_msk_datetime(stats.last_success_at))}",
        ]
    )
    return "\n".join(lines)


def admin_stats_page_text(views: list[KeyTrafficStatsView], page: int, *, viewer_user_id: int) -> str:
    if not views:
        return t("stats_keys_empty")
    lines = [f"{t('stats_keys_title')} · page {page + 1}"]
    for view in views:
        stats = view.stats
        owner = view.owner
        owner_text = (
            format_user_display(owner.telegram_user_id, owner.username)
            if owner is not None
            else format_user_display(view.key.owner_user_id, view.key.username)
        )
        if stats is None or not stats.available:
            if stats and stats.last_success_at:
                traffic = f"{t('stats_last_prefix')}: ↓ {format_bytes(stats.downloaded_bytes)} · ↑ {format_bytes(stats.uploaded_bytes)}"
            else:
                traffic = t("stats_unavailable_short")
        else:
            traffic = f"↓ {format_bytes(stats.downloaded_bytes)} · ↑ {format_bytes(stats.uploaded_bytes)}"
        updated = ""
        if stats and stats.last_success_at:
            updated = t("stats_updated_fmt", at=format_msk_datetime(stats.last_success_at))
        elif stats and stats.last_attempt_at:
            updated = t("stats_attempt_fmt", at=format_msk_datetime(stats.last_attempt_at))
        label = key_display_label(view.key, viewer_user_id=viewer_user_id)
        line = (
            f"{h(key_type_label(view.key))} · {code(label)} · "
            f"{owner_text} · {h(traffic + updated)}"
        )
        note = key_note_for_viewer(view.key, viewer_user_id)
        if note and label != note:
            line += f" · {t('stats_note')}: {h(short_note(note))}"
        lines.append(line)
    return "\n".join(lines)


# XHTTP transport profiles offered for VLESS (HTTP) keys (callback suffixes).
XHTTP_PROFILE_CHOICES: tuple[str, ...] = ("base", "antisib", "multi")


def xhttp_profile_prompt() -> str:
    """Header plus each profile's name + description, from single-source i18n keys."""
    blocks = "\n\n".join(
        f"{t(f'xhttp_profile_{profile}_name')}\n{t(f'xhttp_profile_{profile}_desc')}"
        for profile in XHTTP_PROFILE_CHOICES
    )
    return f"{t('choose_xhttp_profile')}\n\n{blocks}"


def create_type_label(key_type: str, transport: str | None = None, profile: str | None = None) -> str:
    """Human label for a key type + transport (+ xhttp profile) for the confirm screen."""
    if key_type == VpnKeyType.AWG.value:
        return "AmneziaWG"
    if key_type == VpnKeyType.HYSTERIA2.value:
        return "Hysteria2"
    if key_type == VpnKeyType.XRAY.value:
        if str(transport or "tcp").lower() != "http":
            return "VLESS (TCP)"
        prof = str(profile or "base").lower()
        # base stays plain "VLESS (HTTP)" (regression-identical); the tuned
        # profiles append their short name so the user can tell them apart.
        if prof in ("antisib", "multi"):
            return f"VLESS (HTTP) · {t(f'xhttp_profile_{prof}_name')}"
        return "VLESS (HTTP)"
    return key_type.upper()


def create_confirm_text(
    key_type: str,
    note: str | None,
    owner: User | None = None,
    expires_at: str | None = None,
    mtu: int | None = None,
    fingerprint: str | None = None,
    transport: str | None = None,
    profile: str | None = None,
) -> str:
    lines = [
        t("create_confirm_title"),
        f"{t('field_type')}: {h(create_type_label(key_type, transport, profile))}",
        f"{t('field_note')}: {h(note or t('none'))}",
        f"{t('field_expires_at')}: {h(format_expiry_date(expires_at))}",
    ]
    if mtu is not None:
        lines.append(f"MTU: {h(str(mtu))}")
    if fingerprint is not None:
        lines.append(f"Fingerprint: {h(fingerprint)}")
    if owner is not None:
        lines.append(f"{t('field_owner')}: {format_user_display(owner.telegram_user_id, owner.username)}")
    return "\n".join(lines)


def note_confirm_text(key: VpnKey, note: str | None) -> str:
    return (
        f"{t('note_confirm_title')}\n"
        f"{t('note_confirm_key')}: {h(key_title(key))}\n"
        f"{t('note_confirm_new_note')}: {h(note or t('none'))}"
    )


def xray_config_text(config_text: str) -> str:
    return f"{config_text}\n\n{t('xray_config_hint')}"


def awg_config_text(config_text: str) -> str:
    return f"{config_text}\n\n{t('awg_config_hint')}"


def hysteria2_config_text(config_text: str) -> str:
    return f"{config_text}\n\n{t('hy2_config_hint')}"


def format_hysteria2_link(
    label: str,
    secret: str,
    *,
    host: str,
    port: int,
    sni: str,
    obfs_password: str,
    insecure: bool = True,
) -> str:
    """Build a ``hysteria2://`` client URI for a single issued key.

    The userinfo component is the single auth token (our per-key secret) — NOT a
    ``user:pass`` pair. Every interpolated value is percent-encoded via
    ``urllib.parse.quote`` so an obfs password (or label) containing URL
    metacharacters cannot break the link. ``host``/``port``/``sni``/
    ``obfs_password`` are the global server settings shared by every key.
    """
    user = quote(secret, safe="")
    sni_q = quote(sni, safe="")
    obfs_q = quote(obfs_password, safe="")
    label_q = quote(label, safe="")
    insecure_flag = 1 if insecure else 0
    return (
        f"hysteria2://{user}@{host}:{port}/"
        f"?sni={sni_q}&obfs=salamander&obfs-password={obfs_q}&insecure={insecure_flag}"
        f"#{label_q}"
    )


def proxy_section_separator() -> str:
    return "\n\n<b>━━━━━━━━━━━━━━━━</b>\n\n"


def socks5_proxy_text(payload: dict[str, object]) -> str:
    return "\n".join(
        [
            "<b>SOCKS5</b>",
            f"Host: {code(payload.get('host') or '')}",
            f"Port: {code(payload.get('port') or '')}",
            f"Login: {code(payload.get('login') or '')}",
            f"Password: {code(payload.get('password') or '')}",
            f"URL: {code(payload.get('url') or '')}",
        ]
    )


def mtproto_proxy_text(payload: dict[str, object]) -> str:
    mode = str(payload.get("mode") or "static")
    mode_note = (
        t("mtproto_managed_note")
        if mode == "managed"
        else t("mtproto_static_note")
    )
    return "\n".join(
        [
            "<b>Telegram MTProto Proxy</b>",
            "",
            t("mtproto_variant1"),
            code(payload.get("link") or ""),
            "",
            t("mtproto_variant2"),
            code(payload.get("link_dd") or ""),
            "",
            f"Server: {code(payload.get('host') or '')}",
            f"Port: {code(payload.get('port') or '')}",
            "",
            t("mtproto_try_note"),
            mode_note,
        ]
    )


def proxy_access_text(accesses: list[ProxyAccess]) -> str:
    socks5 = next((access for access in accesses if access.access_type == ProxyAccessType.SOCKS5), None)
    mtproto = next((access for access in accesses if access.access_type == ProxyAccessType.MTPROTO), None)
    parts: list[str] = []
    if socks5 is not None:
        parts.append(socks5_proxy_text(socks5.payload))
    if mtproto is not None:
        parts.append(mtproto_proxy_text(mtproto.payload))
    if not parts:
        return t("proxy_no_accesses")
    return proxy_section_separator().join(parts)


def user_proxy_stats_text(stats: ProxyUserStats) -> str:
    lines = [t("proxy_user_stats_title")]
    if not stats.accesses:
        return "\n\n".join([lines[0], t("proxy_no_issued")])

    active_accesses = [access for access in stats.accesses if access.status == ProxyAccessStatus.ACTIVE]
    active_accesses.sort(key=lambda item: (_proxy_type_order(item.access_type), item.id))
    failed_accesses = [access for access in stats.accesses if access.status == ProxyAccessStatus.APPLY_FAILED]
    failed_accesses.sort(key=lambda item: (item.updated_at, item.created_at, item.id), reverse=True)
    recent_failed = failed_accesses[:3]
    hidden_failed = max(len(failed_accesses) - len(recent_failed), 0)

    lines.extend(["", t("proxy_active_header")])
    if active_accesses:
        for access in active_accesses:
            lines.append("")
            lines.extend(_proxy_stats_access_lines(access, include_id=True))
    else:
        lines.append("")
        lines.append(t("proxy_no_active"))

    if recent_failed:
        lines.append("")
        lines.append(t("proxy_recent_errors_header"))
        for access in recent_failed:
            lines.append(_proxy_stats_error_line(access))
    if hidden_failed > 0:
        lines.append("")
        lines.append(t("proxy_hidden_old", n=hidden_failed))
    lines.extend(
        [
            "",
            t("proxy_traffic_header"),
            t("proxy_traffic_unavailable"),
        ]
    )
    return "\n".join(lines)


def admin_proxy_stats_text(stats: ProxyAdminStats) -> str:
    lines = [
        t("proxy_user_stats_title"),
        "",
        "<b>Aggregate summary</b>",
        f"• total proxy accesses: {h(stats.total_accesses)}",
        f"• active total: {h(stats.active_total)}",
        f"• active SOCKS5: {h(stats.active_socks5)}",
        f"• active MTProto: {h(stats.active_mtproto)}",
        f"• apply_failed: {h(stats.apply_failed)}",
        f"• failed total: {h(_admin_failed_total(stats))}",
        f"• revoked/inactive: {h(stats.revoked)}",
        f"• deleted: {h(stats.deleted)}",
        f"• pending: {h(stats.pending)}",
        f"• users with active proxies: {h(stats.users_with_active_proxies)}",
        f"• last issued: {h(_format_proxy_datetime(stats.last_issued_at))}",
        f"• last failed: {h(_format_proxy_datetime(stats.last_failed_at))}",
        "",
        "<b>By type/status</b>",
    ]
    for access_type in (ProxyAccessType.SOCKS5, ProxyAccessType.MTPROTO):
        lines.append(f"{h(_proxy_type_title(access_type))}:")
        status_counts = stats.type_status_counts.get(access_type, {})
        for status in _status_display_order():
            value = status_counts.get(status, 0)
            if value or status in {
                ProxyAccessStatus.ACTIVE,
                ProxyAccessStatus.APPLY_FAILED,
                ProxyAccessStatus.REVOKED,
                ProxyAccessStatus.DELETED,
            }:
                lines.append(f"• {h(status.value)}: {h(value)}")
    if stats.mtproto_mode_counts:
        lines.append("MTProto modes:")
        managed = stats.mtproto_mode_counts.get("managed", 0)
        static_shared = sum(
            value
            for mode, value in stats.mtproto_mode_counts.items()
            if mode != "managed"
        )
        lines.append(f"• managed: {h(managed)}")
        lines.append(f"• static/shared: {h(static_shared)}")

    lines.extend(["", "<b>Runtime status</b>"])
    runtime = stats.runtime
    if runtime is None:
        lines.append(t("proxy_runtime_unavailable"))
    else:
        lines.extend(
            [
                "<b>SOCKS5 / Dante</b>",
                f"• enabled: {h(_yes_no(runtime.socks5_enabled))}",
                f"• service active: {h(_runtime_value(runtime.socks5_systemd_active))}",
                f"• listening: {h(_runtime_value(runtime.socks5_port_listening))}",
                f"• host: {code(runtime.socks5_host or t('not_set'))}",
                f"• port: {code(runtime.socks5_port if runtime.socks5_port is not None else t('not_set'))}",
                "<b>MTProto</b>",
                f"• enabled: {h(_yes_no(runtime.mtproto_enabled))}",
                f"• service active: {h(_runtime_value(runtime.mtproto_systemd_active))}",
                f"• listening: {h(_runtime_value(runtime.mtproto_port_listening))}",
                f"• host: {code(runtime.mtproto_host or t('not_set'))}",
                f"• port: {code(runtime.mtproto_port if runtime.mtproto_port is not None else t('not_set'))}",
                f"• mode: {h(runtime.mtproto_mode)}",
                f"• runtime managed secrets: {h(_count_or_unavailable(runtime.mtproto_runtime_secret_count))}",
            ]
        )

    lines.extend(["", "<b>Users</b>"])
    if not stats.users:
        lines.append(t("proxy_stats_no_users"))
    for row in stats.users:
        username = format_user_display(row.telegram_user_id, row.username)
        active = ", ".join(
            f"{_proxy_type_title(ref.access_type)} #{ref.id}"
            for ref in row.active_accesses
        ) or t("none")
        lines.extend(
            [
                f"👤 {code(row.telegram_user_id)} {username}",
                f"• active: {h(active)}",
                f"• failed: {h(row.failed_count)}",
                f"• last issued: {h(_format_proxy_datetime(row.last_proxy_issued_at))}",
            ]
        )
    if stats.hidden_users > 0:
        lines.append(t("proxy_stats_hidden_users", n=stats.hidden_users))
    lines.extend(["", t("proxy_stats_traffic_note")])
    return "\n".join(lines)


def _proxy_stats_access_lines(access: ProxyAccessStatsItem, *, include_id: bool) -> list[str]:
    title = _proxy_type_title(access.access_type)
    if include_id:
        title = f"{title} #{access.id}"
    lines = [
        f"<b>{h(title)}</b>",
        f"• {t('proxy_stat_status')}: {h(access.status.value)}",
        f"• {t('proxy_stat_issued')}: {h(_format_proxy_datetime(access.created_at))}",
    ]
    if access.activated_at:
        lines.append(f"• {t('proxy_stat_activated')}: {h(_format_proxy_datetime(access.activated_at))}")
    if access.last_shown_at:
        lines.append(f"• {t('proxy_stat_last_shown')}: {h(_format_proxy_datetime(access.last_shown_at))}")
    if access.revoked_at:
        lines.append(f"• {t('proxy_stat_revoked')}: {h(_format_proxy_datetime(access.revoked_at))}")
    if access.deleted_at:
        lines.append(f"• {t('proxy_stat_deleted')}: {h(_format_proxy_datetime(access.deleted_at))}")
    if access.access_type == ProxyAccessType.SOCKS5:
        if access.host:
            lines.append(f"• Host: {code(access.host)}")
        if access.port is not None:
            lines.append(f"• Port: {code(access.port)}")
        if access.login:
            lines.append(f"• Login: {code(access.login)}")
        return lines
    mode = access.mtproto_mode or "static"
    lines.append(f"• {t('proxy_stat_type')}: {h(mode)}")
    if access.mtproto_source:
        lines.append(f"• Source: {h(access.mtproto_source)}")
    if access.secret_fingerprint:
        lines.append(f"• Fingerprint: {code(access.secret_fingerprint)}")
    if access.host:
        lines.append(f"• Host: {code(access.host)}")
    if access.port is not None:
        lines.append(f"• Port: {code(access.port)}")
    return lines


def _proxy_stats_error_line(access: ProxyAccessStatsItem) -> str:
    time_value = access.updated_at or access.created_at
    return (
        f"• {h(_proxy_type_title(access.access_type))} #{h(access.id)} — "
        f"{h(access.status.value)}, {h(_format_proxy_datetime(time_value))}"
    )


def _admin_failed_total(stats: ProxyAdminStats) -> int:
    failed_statuses = {
        ProxyAccessStatus.APPLY_FAILED,
        ProxyAccessStatus.REVOKE_FAILED,
        ProxyAccessStatus.DELETE_FAILED,
    }
    return sum(
        value
        for status_counts in stats.type_status_counts.values()
        for status, value in status_counts.items()
        if status in failed_statuses
    )


def _format_proxy_datetime(value: str | None) -> str:
    if not value:
        return t("no_data")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _proxy_type_title(access_type: ProxyAccessType) -> str:
    if access_type == ProxyAccessType.SOCKS5:
        return "SOCKS5"
    return "MTProto"


def _proxy_type_order(access_type: ProxyAccessType) -> int:
    if access_type == ProxyAccessType.SOCKS5:
        return 0
    if access_type == ProxyAccessType.MTPROTO:
        return 1
    return 2


def _runtime_value(value: bool | None) -> str:
    if value is None:
        return t("unavailable")
    return "yes" if value else "no"


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _count_or_unavailable(value: int | None) -> str:
    return str(value) if value is not None else t("unavailable")


def _status_display_order() -> tuple[ProxyAccessStatus, ...]:
    return (
        ProxyAccessStatus.PENDING_APPLY,
        ProxyAccessStatus.ACTIVE,
        ProxyAccessStatus.APPLY_FAILED,
        ProxyAccessStatus.PENDING_REVOKE,
        ProxyAccessStatus.REVOKED,
        ProxyAccessStatus.REVOKE_FAILED,
        ProxyAccessStatus.INACTIVE,
        ProxyAccessStatus.PENDING_DELETE,
        ProxyAccessStatus.DELETE_FAILED,
        ProxyAccessStatus.DELETED,
    )


def proxy_admin_combined_text(lifecycle: ProxyLifecycleStats, stats: ProxyAdminStats) -> str:
    lines = ["<b>Прокси — статус и статистика</b>"]
    runtime = stats.runtime

    lines.extend(["", "<b>SOCKS5 / Dante</b>"])
    if runtime is not None:
        lines.append(f"• enabled: {h(_yes_no(runtime.socks5_enabled))}")
        if runtime.socks5_enabled:
            lines.append(
                f"• host: {code(runtime.socks5_host or t('not_set'))}"
                f" | port: {code(runtime.socks5_port if runtime.socks5_port is not None else t('not_set'))}"
            )
            lines.append(
                f"• service: {h(_runtime_value(runtime.socks5_systemd_active))}"
                f" | listening: {h(_runtime_value(runtime.socks5_port_listening))}"
            )
    lines.append(
        f"• issued: {h(lifecycle.socks5_issued)}"
        f" | active: {h(lifecycle.socks5_active)}"
        f" | revoked: {h(lifecycle.socks5_revoked)}"
    )
    pending_statuses = frozenset({ProxyAccessStatus.PENDING_APPLY, ProxyAccessStatus.PENDING_REVOKE, ProxyAccessStatus.PENDING_DELETE})
    failed_statuses = frozenset({ProxyAccessStatus.APPLY_FAILED, ProxyAccessStatus.REVOKE_FAILED, ProxyAccessStatus.DELETE_FAILED})
    socks5_counts = stats.type_status_counts.get(ProxyAccessType.SOCKS5, {})
    socks5_pending = sum(v for s, v in socks5_counts.items() if s in pending_statuses)
    socks5_failed = sum(v for s, v in socks5_counts.items() if s in failed_statuses)
    socks5_deleted = socks5_counts.get(ProxyAccessStatus.DELETED, 0)
    if socks5_pending:
        lines.append(f"• pending: {h(socks5_pending)}")
    if socks5_deleted:
        lines.append(f"• deleted: {h(socks5_deleted)}")
    if socks5_failed:
        lines.append(f"• failed: {h(socks5_failed)}")

    lines.extend(["", "<b>MTProto</b>"])
    if runtime is not None:
        lines.append(f"• enabled: {h(_yes_no(runtime.mtproto_enabled))}")
        if runtime.mtproto_enabled:
            lines.append(f"• mode: {h(runtime.mtproto_mode)}")
            lines.append(
                f"• host: {code(runtime.mtproto_host or t('not_set'))}"
                f" | port: {code(runtime.mtproto_port if runtime.mtproto_port is not None else t('not_set'))}"
            )
            lines.append(
                f"• service: {h(_runtime_value(runtime.mtproto_systemd_active))}"
                f" | listening: {h(_runtime_value(runtime.mtproto_port_listening))}"
            )
    lines.append(
        f"• issued: {h(lifecycle.mtproto_issued)}"
        f" | active: {h(lifecycle.mtproto_active)}"
        f" | deactivated: {h(lifecycle.mtproto_deactivated)}"
    )
    if lifecycle.mtproto_managed_issued:
        managed_str = (
            f"managed: {h(lifecycle.mtproto_managed_issued)} issued,"
            f" {h(lifecycle.mtproto_managed_active)} active"
        )
        if lifecycle.mtproto_managed_revoked:
            managed_str += f", {h(lifecycle.mtproto_managed_revoked)} revoked"
        lines.append(f"• {managed_str}")
    if lifecycle.mtproto_legacy_static:
        lines.append(f"• legacy/static records: {h(lifecycle.mtproto_legacy_static)}")
    if runtime is not None and runtime.mtproto_runtime_secret_count is not None:
        lines.append(f"• runtime secrets: {h(runtime.mtproto_runtime_secret_count)}")
    mtproto_counts = stats.type_status_counts.get(ProxyAccessType.MTPROTO, {})
    mtproto_pending = sum(v for s, v in mtproto_counts.items() if s in pending_statuses)
    mtproto_failed = sum(v for s, v in mtproto_counts.items() if s in failed_statuses)
    mtproto_deleted = mtproto_counts.get(ProxyAccessStatus.DELETED, 0)
    if mtproto_pending:
        lines.append(f"• pending: {h(mtproto_pending)}")
    if mtproto_deleted:
        lines.append(f"• deleted: {h(mtproto_deleted)}")
    if mtproto_failed:
        lines.append(f"• failed: {h(mtproto_failed)}")

    lines.extend(["", "<b>Пользователи</b>"])
    if stats.last_issued_at:
        lines.append(f"• last issued: {h(_format_proxy_datetime(stats.last_issued_at))}")
    if not stats.users:
        lines.append(t("proxy_stats_no_users"))
    for row in stats.users:
        username = format_user_display(row.telegram_user_id, row.username)
        active = ", ".join(
            f"{_proxy_type_title(ref.access_type)} #{ref.id}"
            for ref in row.active_accesses
        ) or t("none")
        lines.append(f"👤 {code(row.telegram_user_id)} {username}")
        lines.append(f"  active: {h(active)}")
        if row.failed_count:
            lines.append(f"  failed: {h(row.failed_count)}")
    if stats.hidden_users > 0:
        lines.append(t("proxy_stats_hidden_users", n=stats.hidden_users))
    lines.extend(["", t("proxy_stats_traffic_note")])
    return "\n".join(lines)


def proxy_admin_status_text(status: ProxyServiceStatus, stats: ProxyLifecycleStats) -> str:
    socks5_port = status.socks5_port if status.socks5_port is not None else t("not_set")
    mtproto_active = "unknown" if status.mtproto_systemd_active is None else ("yes" if status.mtproto_systemd_active else "no")
    mtproto_listening = "unknown" if status.mtproto_port_listening is None else ("yes" if status.mtproto_port_listening else "no")
    mtproto_traffic_text = (
        "Traffic: per-user stats for MTProto not available without reliable server-side accounting by secret."
    )
    mtproto_revoke_note = (
        "Managed mode: individual server-side revoke by removing secret from active MTProxy list."
        if status.mtproto_mode == "managed"
        else "Static mode: shared secret in use, individual server-side revoke impossible without secret rotation."
    )
    lines = [
        t("proxy_title").replace("<b>", "").replace("</b>", "") + " " + "status",
        "",
        "<b>SOCKS5 / Dante</b>",
        f"Enabled: {h('yes' if status.socks5_enabled else 'no')}",
        f"Host: {code(status.socks5_host or t('not_set'))}",
        f"Port: {code(socks5_port)}",
        f"Public name: {h(status.socks5_public_name)}",
        f"Service: {code(status.socks5_service_name)}",
        f"Issued: {h(stats.socks5_issued)}",
        f"Active: {h(stats.socks5_active)}",
        f"Revoked/blocked: {h(stats.socks5_revoked)}",
        t("proxy_socks5_traffic_note"),
        "",
        "<b>MTProto</b>",
        f"Enabled: {h('yes' if status.mtproto_enabled else 'no')}",
        f"Mode: {h(status.mtproto_mode)}",
        f"Host: {code(status.mtproto_host or t('not_set'))}",
        f"Port: {code(status.mtproto_port)}",
        f"Public name: {h(status.mtproto_public_name)}",
        f"Service: {code(status.mtproto_service_name)}",
        f"Systemd active: {h(mtproto_active)}",
        f"Port listening: {h(mtproto_listening)}",
        f"Stats URL configured: {h('yes' if status.mtproto_stats_url_configured else 'no')}",
        f"Issued: {h(stats.mtproto_issued)}",
        f"Active: {h(stats.mtproto_active)}",
        f"Deactivated/blocked: {h(stats.mtproto_deactivated)}",
        f"Managed issued: {h(stats.mtproto_managed_issued)}",
        f"Managed active secrets: {h(stats.mtproto_managed_active)}",
        f"Managed revoked: {h(stats.mtproto_managed_revoked)}",
        f"Legacy/static records: {h(stats.mtproto_legacy_static)}",
        f"Apply failed: {h(stats.mtproto_apply_failed)}",
        f"Revoke failed: {h(stats.mtproto_revoke_failed)}",
        mtproto_traffic_text,
        "",
        mtproto_revoke_note,
    ]
    return "\n".join(lines)


def backend_diagnostics_text(
    statuses: tuple[BackendHealthStatus, ...],
    *,
    mtproto_mode: str = "static",
    skipped_revocation_count: int = 0,
) -> str:
    lines = [
        "<b>Backend diagnostics</b>",
        "",
        "DEGRADED blocks only the affected backend create/revoke/delete/reconcile operations.",
        "Other backends continue working unless they are also degraded.",
        "",
    ]
    for status in statuses:
        state = "DEGRADED" if status.degraded else "OK"
        lines.append(f"{h(status.label)}: <b>{state}</b>")
        if status.reason:
            lines.append(f"• reason: {h(_redact_diagnostic_reason(status.reason))}")
    lines.append("")
    if skipped_revocation_count:
        lines.append(
            f"⚠️ Skipped revocations (degraded backend, since last restart): {skipped_revocation_count}"
        )
        lines.append("")
    if mtproto_mode == "managed":
        lines.append("MTProto mode: managed, per-user server-side revoke removes only that user's secret.")
    else:
        lines.append("MTProto mode: static/shared, per-user server-side revoke is impossible until the shared secret is rotated.")
    return "\n".join(lines)


_STATUS_ICONS: dict[str, str] = {
    "ok": "✓",
    "warning": "⚠",
    "degraded": "✗",
    "failed": "✗",
}


def system_diagnostics_text(
    result: HealthCheckResult,
    *,
    disabled_modules: list[ProtocolModule] | None = None,
) -> str:
    overall = result.overall.upper()
    ts = result.timestamp[:19].replace("T", " ") + " UTC"
    lines = [
        f"<b>Diagnostics</b>  <b>{h(overall)}</b>",
        f"<i>{h(ts)}</i>",
        "",
    ]
    for item in result.checks:
        icon = _STATUS_ICONS.get(item.status, "?")
        lines.append(f"{icon} {h(item.message)}")
        if item.details:
            lines.append(f"  └ {h(item.details)}")
    if disabled_modules:
        lines.append("")
        lines.append("<b>Отключённые модули:</b>")
        for m in disabled_modules:
            label = PROTOCOL_DISPLAY.get(m.name, m.name)
            ts_part = f" (отключён {m.disabled_at[:10]})" if m.disabled_at else ""
            lines.append(f"✗ {h(label)}: DISABLED{h(ts_part)}")
    return "\n".join(lines)


def announcement_batches_text(batches: list[AnnouncementBatch]) -> str:
    if not batches:
        return t("announce_batches_empty")
    lines = [t("announce_batches_title")]
    for batch in batches:
        pending = max(batch.total_count - batch.success_count - batch.failed_count - batch.skipped_count, 0)
        entry = [
            "",
            f"<b>Batch #{h(batch.id)}</b>",
            f"Status: {h(batch.status)}",
            f"Total: {h(batch.total_count)}",
            f"Sent: {h(batch.success_count)}",
            f"Failed: {h(batch.failed_count)}",
            f"Skipped: {h(batch.skipped_count)}",
            f"Pending: {h(pending)}",
            f"Created: {h(format_msk_datetime(batch.created_at))}",
            f"Updated: {h(format_msk_datetime(batch.updated_at))}",
        ]
        if batch.scheduled_at:
            entry.append(f"Scheduled: {h(format_msk_datetime(batch.scheduled_at))}")
        lines.extend(entry)
    return "\n".join(lines)


def proxy_entry_text(entry: ProxyEntry) -> str:
    lines = [
        f"<b>{h(entry.proxy_type)}</b>",
        f"{t('field_host')}: {code(entry.host)}",
        f"{t('field_port')}: {code(entry.port)}",
    ]
    if entry.login:
        lines.append(f"{t('field_login')}: {code(entry.login)}")
    if entry.password:
        lines.append(f"{t('field_password')}: {code(entry.password)}")
    if entry.note:
        lines.append(f"{t('field_description')}: {h(entry.note)}")
    lines.append(f"{t('field_status')}: {h(entry.status.value)}")
    return "\n".join(lines)


def _redact_diagnostic_reason(value: str, limit: int = 180) -> str:
    return _redact(value, limit)


def proxy_page_text(entries: list[ProxyEntry], page: int) -> str:
    if not entries:
        return f"{t('proxy_title')}\n\n{t('proxy_not_configured')}"
    return f"{t('proxy_title')} · page {page + 1}\n\n" + "\n\n".join(proxy_entry_text(entry) for entry in entries)


def access_request_text(request: AccessRequest) -> str:
    username = f"@{request.username}" if request.username else t("not_specified")
    return (
        f"{t('request_title', id=request.id)}\n"
        f"{t('field_tg_id')}: {code(request.telegram_user_id)}\n"
        f"{t('field_username')}: {h(username)}\n"
        f"{t('field_status')}: {h(request.status.value)}\n"
        f"{t('field_created')}: {h(format_msk_datetime(request.requested_at))}"
    )


def access_request_decision_confirm_text(request: AccessRequest, action: str) -> str:
    action_text = t("decision_confirm_approve") if action == "approve" else t("decision_confirm_reject")
    username = f"@{request.username}" if request.username else t("not_specified")
    return (
        f"{t('decision_confirm_title', action=action_text)}\n"
        f"{t('field_tg_id')}: {code(request.telegram_user_id)}\n"
        f"{t('field_username')}: {h(username)}\n"
        f"{t('field_status')}: {h(request.status.value)}\n"
        f"{t('field_created')}: {h(format_msk_datetime(request.requested_at))}"
    )


def access_requests_page_text(requests: list[AccessRequest], page: int) -> str:
    if not requests:
        return t("requests_page_empty")
    return t("requests_page_title", page=page + 1) + "\n\n" + "\n\n".join(access_request_text(req) for req in requests)


def user_card_text(
    user: User,
    keys: list[VpnKey] | None = None,
    stats_by_key_id: dict[int, TrafficStats] | None = None,
    *,
    viewer_user_id: int | None = None,
) -> str:
    username = f"@{user.username}" if user.username else t("not_specified")
    lines = [
        t("user_card_title"),
        f"{t('field_tg_id')}: {code(user.telegram_user_id)}",
        f"{t('field_username')}: {h(username)}",
        f"{t('field_role')}: {h(role_text(user.role))}",
        f"{t('field_updated')}: {h(format_msk_datetime(user.updated_at))}",
    ]
    if user.note:
        lines.append(f"{t('field_note')}: {h(user.note)}")
    if keys is not None:
        lines.append("")
        lines.append(t("user_keys_title"))
        if not keys:
            lines.append(t("user_no_keys"))
        else:
            stats_by_key_id = stats_by_key_id or {}
            for key in keys:
                stats = stats_by_key_id.get(key.id)
                traffic = ""
                if stats and stats.available:
                    traffic = f" · ↓ {format_bytes(stats.downloaded_bytes)} · ↑ {format_bytes(stats.uploaded_bytes)}"
                elif stats:
                    traffic = f" · {t('user_stats_unavailable')}"
                lines.append(f"{h(key_type_label(key))} · {code(key_display_label(key, viewer_user_id=viewer_user_id))}{traffic}")
    return "\n".join(lines)


def block_user_confirm_text(user: User, key_count: int) -> str:
    username = f"@{user.username}" if user.username else t("not_specified")
    return (
        f"{t('block_confirm_title')}\n"
        f"{t('field_tg_id')}: {code(user.telegram_user_id)}\n"
        f"{t('field_username')}: {h(username)}\n"
        f"{t('field_name')}: {h(user.first_name or t('not_specified'))}\n"
        f"{t('field_current_role')}: {h(role_text(user.role))}\n"
        f"{t('block_keys_to_check', count=key_count)}\n\n"
        f"{t('block_action_warning')}"
    )


def unblock_user_confirm_text(warning: UnblockUserWarning) -> str:
    user = warning.user
    username = f"@{user.username}" if user.username else t("not_specified")
    lines = [
        t("unblock_confirm_title"),
        f"{t('field_tg_id')}: {code(user.telegram_user_id)}",
        f"{t('field_username')}: {h(username)}",
        f"{t('field_name')}: {h(user.first_name or t('not_specified'))}",
        f"{t('field_current_role')}: {h(role_text(user.role))}",
    ]
    if warning.has_warning:
        lines.extend(
            [
                "",
                t("unblock_manual_check"),
                t("unblock_manual_check_desc"),
            ]
        )
        for reason in warning.reasons:
            lines.append(f"• {h(reason)}")
        if warning.last_block_error_at:
            lines.append(t("unblock_warning_last_error", at=format_msk_datetime(warning.last_block_error_at)))
        lines.append(t("unblock_no_auto_fix"))
    else:
        lines.extend(["", t("unblock_confirm_success")])
    return "\n".join(lines)


def unblock_user_success_text(warning: UnblockUserWarning) -> str:
    text = t("unblock_success")
    if not warning.has_warning:
        return text
    return text + "\n\n" + t("unblock_vpn_check_warning")


def users_page_text(users: list[User], page: int, key_counts: dict[int, int] | None = None) -> str:
    if not users:
        return f"{t('users_title')}\n\n{t('users_empty')}"
    lines = [t("users_page_title", page=page + 1)]
    key_counts = key_counts or {}
    for user in users:
        username = format_user_display(user.telegram_user_id, user.username)
        key_count = key_counts.get(user.telegram_user_id, 0)
        lines.append(
            f"{code(user.telegram_user_id)} · {username} · {h(role_text(user.role))} · {t('users_key_count')}: {key_count}"
        )
    return "\n".join(lines)


def audit_page_text(items: list[dict[str, object]], page: int, users: dict[int, User] | None = None) -> str:
    if not items:
        return f"{t('audit_title')}\n\n{t('audit_empty')}"
    lines = [t("audit_page_title", page=page + 1)]
    users = users or {}
    for item in items:
        lines.append(_human_audit_line(item, users))
    return "\n".join(lines)


def _human_audit_line(item: dict[str, object], users: dict[int, User]) -> str:
    actor_id = item.get("actor_user_id")
    actor: User | None = users.get(int(actor_id)) if actor_id is not None else None  # type: ignore[call-overload]
    actor_text = (
        format_user_display(actor.telegram_user_id, actor.username)
        if actor is not None
        else format_user_display(int(actor_id), None) if actor_id is not None else t("audit_system")  # type: ignore[call-overload]
    )
    action = str(item.get("action") or "")
    details = item.get("details")
    details_dict = details if isinstance(details, dict) else {}
    label = h(str(details_dict.get("label") or details_dict.get("email_label") or details_dict.get("key_label") or ""))
    owner_user_id = details_dict.get("owner_user_id")
    owner_username = details_dict.get("owner_username")
    owner_text = format_user_display(
        int(owner_user_id) if owner_user_id is not None else None,
        str(owner_username) if owner_username else None,
    )
    owner_suffix = ""
    if owner_user_id is not None and actor_id is not None and int(owner_user_id) != int(actor_id):  # type: ignore[call-overload]
        owner_suffix = t("audit_owner_suffix", owner=owner_text)
    time_text = h(format_msk_datetime(str(item.get("created_at") or "")))
    if action == "xray_key_created":
        suffix = (t("audit_created_xray", label=label) if label else t("audit_created_xray_nolabel")) + owner_suffix
    elif action == "awg_key_created":
        suffix = (t("audit_created_awg", label=label) if label else t("audit_created_awg_nolabel")) + owner_suffix
    elif action == "stats_viewed":
        target_user_id = details_dict.get("target_user_id")
        target_username = details_dict.get("target_username")
        target_text = format_user_display(
            int(target_user_id) if target_user_id is not None else None,
            str(target_username) if target_username else None,
        )
        suffix = t("audit_viewed_user_stats", user=target_text)
    elif action == "user_role_changed":
        suffix = t("audit_changed_role")
    elif action == "user_blocked":
        suffix = t("audit_blocked_user")
    elif action == "user_unblocked":
        suffix = t("audit_unblocked_user")
    elif action == "access_requested":
        if details_dict.get("repeat_after_block"):
            suffix = t("audit_access_request_repeat")
        else:
            suffix = t("audit_access_request")
    elif action == "access_approved":
        suffix = t("audit_access_approved")
    elif action == "access_rejected":
        suffix = t("audit_access_rejected")
    else:
        suffix = t("audit_action_generic", action=h(action))
    return f"{time_text} — {actor_text}{suffix}"


def dashboard_text(snap: DashboardSnapshot) -> str:
    lines: list[str] = [f"<b>📊 Дашборд</b>  <i>обновлено {h(snap.refreshed_at)}</i>", ""]

    # Users
    approved = snap.users_by_role.get("APPROVED_USER", 0)
    pending = snap.users_by_role.get("PENDING_USER", 0)
    blocked = snap.users_by_role.get("BLOCKED_USER", 0)
    moderators = snap.users_by_role.get("MODERATOR", 0)
    superadmins = snap.users_by_role.get("SUPERADMIN", 0)
    total_users = sum(snap.users_by_role.values())
    lines += [
        "<b>👥 Пользователи</b>",
        f"  Всего: <b>{h(total_users)}</b>  (одобрено: {h(approved)} | ожидают: {h(pending)} | заблок.: {h(blocked)})",
    ]
    if moderators or superadmins:
        lines.append(f"  Модераторов: {h(moderators)} | Админов: {h(superadmins)}")
    lines.append(f"  Новых за 7д: {h(snap.new_users_7d)} | за 30д: {h(snap.new_users_30d)}")
    lines.append(f"  С активными ключами: {h(snap.users_with_active_keys)}")
    attention_parts = []
    if snap.pending_access_requests:
        attention_parts.append(f"⏳ Заявок: {snap.pending_access_requests}")
    if snap.pending_trial_requests:
        attention_parts.append(f"⏳ Пробных: {snap.pending_trial_requests}")
    if attention_parts:
        lines.append("  " + " | ".join(attention_parts))
    lines.append("")

    # Keys
    k = snap.keys
    lines += [
        "<b>🔑 VPN-ключи</b>",
        f"  Активных: <b>{h(k.active)}</b>  (Xray: {h(k.xray_active)} | AWG: {h(k.awg_active)} | Hy2: {h(k.hysteria2_active)})  · всего: {h(k.total)}",
        f"  Истекают 7д: {h(k.expiring_7d)} | 30д: {h(k.expiring_30d)}",
        f"  Зависших: {'⚠️ ' + str(k.stuck) if k.stuck else '0'} | Ср. на пользователя: {h(f'{k.avg_per_user:.1f}')}",
        "",
    ]

    # Traffic
    t_ = snap.traffic
    top_parts = []
    for entry in snap.top_users:
        name = f"@{entry.username}" if entry.username else f"id{entry.user_id}"
        top_parts.append(f"{h(name)} {h(format_bytes(entry.total_bytes))}")
    lines += [
        "<b>📊 Трафик</b>",
        f"  Итого: <b>{h(format_bytes(t_.total_bytes))}</b>  (Xray: {h(format_bytes(t_.xray_bytes))} | AWG: {h(format_bytes(t_.awg_bytes))} | Hy2: {h(format_bytes(t_.hysteria2_bytes))})",
        f"  Среднее на ключ: {h(format_bytes(t_.avg_per_key_bytes))}",
    ]
    if top_parts:
        lines.append("  Топ-5:")
        for part in top_parts:
            lines.append(f"    {part}")
    lines.append("")

    # Proxy
    stuck_proxy_str = f"  ⚠️ Зависших: {snap.stuck_proxies}" if snap.stuck_proxies else ""
    lines += [
        "<b>🌐 Прокси</b>",
        f"  SOCKS5: {h(snap.active_socks5)} | MTProto: {h(snap.active_mtproto)}",
    ]
    if stuck_proxy_str:
        lines.append(stuck_proxy_str)
    lines.append("")

    # System
    health_parts = []
    for s in snap.backend_health:
        icon = "✅" if not s.degraded else "⚠️"
        health_parts.append(f"{icon} {h(s.label)}")
    w = snap.warp
    warp_str = "вкл" if w.enabled else "выкл"
    if w.enabled:
        warp_str += f" · тоннель: {'↑' if w.tunnel_up else '↓'}"
        if w.fail_streak:
            warp_str += f" · ошибок: {w.fail_streak}"
    lines += [
        "<b>⚙️ Система</b>",
        "  " + " | ".join(health_parts),
        f"  WARP: {h(warp_str)} | БД: {h(format_bytes(snap.db_size_bytes))}",
    ]
    if snap.last_backup_at is not None:
        from datetime import timezone as _tz
        now_dt = datetime.now(_tz.utc)
        delta = now_dt - snap.last_backup_at.replace(tzinfo=_tz.utc) if snap.last_backup_at.tzinfo is None else now_dt - snap.last_backup_at
        hours = int(delta.total_seconds() // 3600)
        if hours < 1:
            backup_age = f"{int(delta.total_seconds() // 60)} мин назад"
        elif hours < 24:
            backup_age = f"{hours} ч назад"
        else:
            backup_age = f"{hours // 24} д назад"
        lines.append(f"  Последний бэкап: {h(backup_age)}")
    else:
        lines.append("  Последний бэкап: нет данных")
    lines.append("")

    # Activity
    recent_actions = []
    for audit_entry in snap.recent_audit_entries[:3]:
        action = str(audit_entry.get("action") or "")
        recent_actions.append(h(action))
    lines += [
        "<b>📋 Активность</b>",
        f"  Аудит 24ч: {h(snap.audit_count_24h)} | 7д: {h(snap.audit_count_7d)}",
        f"  Объявлений за 30д: {h(snap.announcements_30d)}",
    ]
    if recent_actions:
        lines.append("  Последние:")
        for action in recent_actions:
            lines.append(f"    {action}")

    return "\n".join(lines)


_BAR_WIDTH = 10
_SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"


def _usage_bar(percent: float, width: int = _BAR_WIDTH) -> str:
    """Render a 10-cell usage bar: white squares filled, red at ≥90 %, black empty."""
    percent = max(0.0, min(100.0, percent))
    filled = round(percent / 100 * width)
    glyph = "🟥" if percent >= 90 else "⬜"
    return glyph * filled + "⬛" * (width - filled)


def _sparkline(values: tuple[float, ...]) -> str:
    """Render a series as Unicode block glyphs scaled to the window's own peak."""
    if not values:
        return ""
    peak = max(values)
    if peak <= 0:
        return _SPARKLINE_CHARS[0] * len(values)
    last = len(_SPARKLINE_CHARS) - 1
    return "".join(_SPARKLINE_CHARS[min(last, int(value / peak * last))] for value in values)


def _format_uptime(seconds: float) -> str:
    """Render an uptime duration as ``Xд Yч Zм`` (omitting zero leading units)."""
    total = int(seconds)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts: list[str] = []
    if days:
        parts.append(f"{days}д")
    if hours or days:
        parts.append(f"{hours}ч")
    parts.append(f"{minutes}м")
    return " ".join(parts)


_TREND_ARROW = {"up": "↑", "down": "↓", "flat": "→"}


def _online_clients_line(online: OnlineClients) -> str:
    no_data = t("no_data")
    if not online.available:
        return f"🔗 {t('server_status_online_label')}: {h(t('server_status_online_collecting'))}"
    total = no_data if online.total is None else str(online.total)
    wg = no_data if online.wg is None else str(online.wg)
    xray = no_data if online.xray is None else str(online.xray)
    parts = f"WG: {h(wg)} · Xray: {h(xray)}"
    # Only surface the Hysteria2 leg when the Traffic Stats API is configured
    # (otherwise online.hysteria2 is None and a count would be misleading).
    if online.hysteria2 is not None:
        parts += f" · Hy2: {h(str(online.hysteria2))}"
    return (
        f"🔗 {t('server_status_online_label')}: <b>{h(total)}</b>"
        f"  ({parts})"
    )


def _detailed_lines(status: ServerStatus) -> list[str]:
    """Build the extra detailed-metrics block (uptime, load average, net trends).

    Order within the block: uptime first, then the load average, then the
    network avg/peak/trend figures and the sparkline.
    """
    lines: list[str] = [""]
    if status.uptime_seconds is not None:
        lines.append(f"⏱ {t('server_status_uptime_label')}: {h(_format_uptime(status.uptime_seconds))}")
    if status.load1 is not None and status.load5 is not None and status.load15 is not None:
        if status.cpu_count and status.cpu_count > 0:
            # Normalise each load average by the CPU count so all three read as a
            # percentage of total CPU capacity (100% == every core fully busy).
            load = " / ".join(
                f"{val / status.cpu_count * 100:.0f}%"
                for val in (status.load1, status.load5, status.load15)
            )
        else:
            # No CPU count to normalise against — fall back to the raw figures.
            load = f"{status.load1:.2f} / {status.load5:.2f} / {status.load15:.2f}"
        lines.append(f"📈 {t('server_status_loadavg_label')}: {h(load)}")
    if status.net_in_avg is not None and status.net_out_avg is not None:
        in_arrow = _TREND_ARROW.get(status.net_in_trend or "flat", "→")
        out_arrow = _TREND_ARROW.get(status.net_out_trend or "flat", "→")
        avg_label = t("server_status_net_avg")
        peak_label = t("server_status_net_peak")
        lines.append(
            f"📥 {avg_label} {status.net_in_avg:.2f} {in_arrow}"
            f"  {peak_label} {status.net_in_peak or 0.0:.2f} Mbps"
        )
        lines.append(
            f"📤 {avg_label} {status.net_out_avg:.2f} {out_arrow}"
            f"  {peak_label} {status.net_out_peak or 0.0:.2f} Mbps"
        )
    if status.net_sparkline:
        lines.append(_sparkline(status.net_sparkline))
    return lines


def server_status_text(status: ServerStatus, online: OnlineClients) -> str:
    """Render the real-time server status panel (CPU, RAM, disk, network)."""
    no_data = t("no_data")

    cpu = f"{status.cpu_percent:.1f}%" if status.cpu_available else no_data
    cpu_bar = _usage_bar(status.cpu_percent) if status.cpu_available else ""
    if status.ram_total_gb > 0:
        ram = f"{status.ram_used_gb:.2f} GB / {status.ram_total_gb:.2f} GB"
        ram_bar = _usage_bar(status.ram_used_gb / status.ram_total_gb * 100)
    else:
        ram = no_data
        ram_bar = ""
    if status.disk_total_gb > 0:
        disk = t("server_status_disk_value", used=f"{status.disk_used_gb:.2f}", total=f"{status.disk_total_gb:.2f}")
    else:
        disk = no_data
    if status.swap_total_gb > 0:
        swap = f"{status.swap_used_gb:.2f} GB / {status.swap_total_gb:.2f} GB"
    else:
        swap = t("server_status_swap_off")
    net_in = f"{status.net_in_mbps:.2f} Mbps" if status.net_available else no_data
    net_out = f"{status.net_out_mbps:.2f} Mbps" if status.net_available else no_data

    # Timestamp of the snapshot itself (set by the background sampler), so the
    # mark freezes when the sampler stalls instead of tracking render time. A
    # cold cache or a status built without a time renders no mark at all.
    title = f"<b>📊 {t('server_status_title')}</b>"
    if status.sampled_at is not None:
        updated = t("server_status_updated_at", time=h(status.sampled_at.strftime("%H:%M:%S")))
        title = f"{title}  <i>{updated}</i>"

    cpu_line = f"⚙️ CPU: {h(cpu)}"
    if status.cpu_available:
        # After the plain CPU%, show in parentheses the share consumed by the
        # hypervisor (the /proc/stat "steal" counter). Shown only here.
        cpu_line += f" ({t('server_status_cpu_hypervisor')}: {status.cpu_steal_percent:.1f}%)"
    lines = [
        title,
        "",
        cpu_line,
    ]
    if cpu_bar:
        lines.append(cpu_bar)
    lines.append(f"🧠 RAM: {h(ram)}")
    if ram_bar:
        lines.append(ram_bar)
    lines.append(f"💾 {t('server_status_disk_label')}: {h(disk)}")
    lines.append(f"🔁 {t('server_status_swap_label')}: {h(swap)}")
    lines.append("")
    lines.append(_online_clients_line(online))
    lines.append("")
    lines.append(f"🌐 {t('server_status_network_label')}:")
    lines.append(f"📥 {t('server_status_net_in')}: {h(net_in)}")
    lines.append(f"📤 {t('server_status_net_out')}: {h(net_out)}")
    if status.detailed_enabled:
        lines.extend(_detailed_lines(status))
    return "\n".join(lines)
