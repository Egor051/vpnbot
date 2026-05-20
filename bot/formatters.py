
from datetime import datetime, timezone

from aiogram.types import User as TgUser

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
from models.enums import ProxyAccessStatus, ProxyAccessType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.announcements import AnnouncementBatch
from services.backend_health import BackendHealthStatus
from services.health import HealthCheckResult
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


ONE_KEY_ONE_DEVICE_WARNING = "<b>⚠️ 1 КЛЮЧ = 1 УСТРОЙСТВО</b>"
NOTE_CREATE_WARNING = "<b>Рекомендуем не оставлять поле пустым, чтобы не запутаться в ключах.</b>"
SERVER_RESTART_WARNING = (
    "<b>⚠️ Сервер перезагружается по чётным числам в 04:00 по МСК. "
    "Перезагрузка занимает несколько минут, в это время соединение может кратковременно прерваться.</b>"
)


def short_note(note: str | None, limit: int = 42) -> str:
    if not note:
        return "нет"
    value = note.strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def role_text(role: UserRole) -> str:
    return {
        UserRole.SUPERADMIN: "superadmin",
        UserRole.APPROVED_USER: "одобрен",
        UserRole.PENDING_USER: "ожидает",
        UserRole.BLOCKED_USER: "заблокирован",
    }.get(role, role.value)


def status_text(status: VpnKeyStatus) -> str:
    return {
        VpnKeyStatus.PENDING_APPLY: "применяется",
        VpnKeyStatus.ACTIVE: "активен",
        VpnKeyStatus.APPLY_FAILED: "ошибка применения",
        VpnKeyStatus.PENDING_REVOKE: "отзывается",
        VpnKeyStatus.REVOKED: "отозван",
        VpnKeyStatus.PENDING_DELETE: "удаляется",
        VpnKeyStatus.DELETE_FAILED: "ошибка удаления",
        VpnKeyStatus.DELETED: "удалён",
        VpnKeyStatus.FAILED: "ошибка",
    }.get(status, status.value)


def key_title(key: VpnKey) -> str:
    prefix = "Xray" if key.key_type == VpnKeyType.XRAY else "AWG"
    return f"{prefix} #{key.id}"


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
    return f"Доброго времени суток, {name}\n\n{SERVER_RESTART_WARNING}\n\nВыберите действие."


def key_list_card(key: VpnKey, *, viewer_user_id: int) -> str:
    note = key_note_for_viewer(key, viewer_user_id)
    label = key_display_label(key, viewer_user_id=viewer_user_id)
    parts = [
        f"<b>{key_title(key)}</b>",
        f"Статус: {h(status_text(key.status))}",
        f"Метка: {code(label)}",
        f"Создан: {h(format_msk_datetime(key.created_at))}",
    ]
    if key.expires_at:
        parts.append(f"Действует до: {h(format_expiry_date(key.expires_at))}")
    if not note or label != note:
        parts.append(f"Заметка: {h(short_note(note))}")
    if key.client_ip:
        parts.append(f"IP: {code(key.client_ip)}")
    return "\n".join(parts)


def keys_page_text(keys: list[VpnKey], page: int, *, viewer_user_id: int, owner_user_id: int | None = None) -> str:
    title = "<b>Ключи пользователя</b>" if owner_user_id else "<b>Мои ключи</b>"
    if not keys:
        return f"{title}\n\n{ONE_KEY_ONE_DEVICE_WARNING}\n\nНа этой странице ключей нет."
    xray = [key for key in keys if key.key_type == VpnKeyType.XRAY]
    awg = [key for key in keys if key.key_type == VpnKeyType.AWG]
    sections = [f"{title} · страница {page + 1}", ONE_KEY_ONE_DEVICE_WARNING]
    if xray:
        sections.append("<b>Xray</b>\n" + "\n\n".join(key_list_card(key, viewer_user_id=viewer_user_id) for key in xray))
    if awg:
        sections.append("<b>AWG</b>\n" + "\n\n".join(key_list_card(key, viewer_user_id=viewer_user_id) for key in awg))
    return "\n\n".join(sections)


def key_detail_text(key: VpnKey, *, viewer_user_id: int) -> str:
    note = key_note_for_viewer(key, viewer_user_id)
    label = key_display_label(key, viewer_user_id=viewer_user_id)
    lines = [
        f"<b>{key_title(key)}</b>",
        f"Статус: {h(status_text(key.status))}",
        f"Метка: {code(label)}",
        f"Создан: {h(format_msk_datetime(key.created_at))}",
        f"Обновлён: {h(format_msk_datetime(key.updated_at))}",
    ]
    if key.expires_at:
        lines.append(f"Действует до: {h(format_expiry_date(key.expires_at))}")
    if not note or label != note:
        lines.append(f"Заметка: {h(note or 'нет')}")
    if key.client_ip:
        lines.append(f"IP: {code(key.client_ip)}")
    if key.public_key:
        lines.append(f"Публичный ключ: {code(key.public_key)}")
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
        f"<b>Статистика {h(key_title(key))}</b>",
        f"Тип: {h(key.key_type.value.upper())}",
        f"Метка: {code(label)}",
        f"Владелец: {owner_text}",
    ]
    note = key_note_for_viewer(key, viewer_user_id)
    if note and label != note:
        lines.append(f"Заметка: {h(note)}")
    stats = view.stats
    if stats is None or not stats.available:
        lines.append("")
        if stats and stats.last_success_at:
            lines.append("Статистика сейчас недоступна. Последний успешный снимок:")
            lines.append(f"Скачано: {h(format_bytes(stats.downloaded_bytes))}")
            lines.append(f"Отправлено: {h(format_bytes(stats.uploaded_bytes))}")
            lines.append(f"Обновлено: {h(format_msk_datetime(stats.last_success_at))}")
        else:
            lines.append("Статистика пока недоступна.")
        if stats and stats.unavailable_reason:
            lines.append(f"Причина: {h(stats.unavailable_reason)}")
        return "\n".join(lines)
    lines.extend(
        [
            f"Скачано: {h(format_bytes(stats.downloaded_bytes))}",
            f"Отправлено: {h(format_bytes(stats.uploaded_bytes))}",
            f"Обновлено: {h(format_msk_datetime(stats.last_success_at))}",
        ]
    )
    return "\n".join(lines)


def admin_stats_page_text(views: list[KeyTrafficStatsView], page: int, *, viewer_user_id: int) -> str:
    if not views:
        return "<b>Статистика ключей</b>\n\nНа этой странице ключей нет."
    lines = [f"<b>Статистика ключей</b> · страница {page + 1}"]
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
                traffic = f"последнее: ↓ {format_bytes(stats.downloaded_bytes)} · ↑ {format_bytes(stats.uploaded_bytes)}"
            else:
                traffic = "статистика пока недоступна"
        else:
            traffic = f"↓ {format_bytes(stats.downloaded_bytes)} · ↑ {format_bytes(stats.uploaded_bytes)}"
        updated = ""
        if stats and stats.last_success_at:
            updated = f" · обновлено {format_msk_datetime(stats.last_success_at)}"
        elif stats and stats.last_attempt_at:
            updated = f" · попытка {format_msk_datetime(stats.last_attempt_at)}"
        label = key_display_label(view.key, viewer_user_id=viewer_user_id)
        line = (
            f"{h(view.key.key_type.value.upper())} · {code(label)} · "
            f"{owner_text} · {h(traffic + updated)}"
        )
        note = key_note_for_viewer(view.key, viewer_user_id)
        if note and label != note:
            line += f" · Заметка: {h(short_note(note))}"
        lines.append(line)
    return "\n".join(lines)


def create_confirm_text(
    key_type: str,
    note: str | None,
    owner: User | None = None,
    expires_at: str | None = None,
    mtu: int | None = None,
) -> str:
    lines = [
        "<b>Подтверждение создания ключа</b>",
        f"Тип: {h(key_type.upper())}",
        f"Заметка: {h(note or 'нет')}",
        f"Срок действия: {h(format_expiry_date(expires_at))}",
    ]
    if mtu is not None:
        lines.append(f"MTU: {h(str(mtu))}")
    if owner is not None:
        lines.append(f"Владелец: {format_user_display(owner.telegram_user_id, owner.username)}")
    return "\n".join(lines)


def note_confirm_text(key: VpnKey, note: str | None) -> str:
    return (
        "<b>Подтверждение заметки</b>\n"
        f"Ключ: {h(key_title(key))}\n"
        f"Новая заметка: {h(note or 'нет')}"
    )


def xray_config_text(config_text: str) -> str:
    return f"{config_text}\n\nДобавьте ссылку в клиент с поддержкой VLESS/REALITY."


def awg_config_text(config_text: str) -> str:
    return f"{config_text}\n\nДобавьте ссылку в клиент AmneziaWG или используйте файл конфигурации."


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
        "Это индивидуальный MTProto-доступ. При блокировке пользователя этот MTProto secret будет отозван."
        if mode == "managed"
        else "Это общий MTProto-доступ. Индивидуальный серверный отзыв в static mode невозможен."
    )
    return "\n".join(
        [
            "<b>Telegram MTProto Proxy</b>",
            "",
            "Вариант 1 — обычный, попробуйте сначала:",
            code(payload.get("link") or ""),
            "",
            "Вариант 2 — с random padding dd, если первый не работает:",
            code(payload.get("link_dd") or ""),
            "",
            f"Server: {code(payload.get('host') or '')}",
            f"Port: {code(payload.get('port') or '')}",
            "",
            "Сначала попробуйте первый вариант. Если он не работает или плохо грузит медиа — попробуйте второй вариант с dd.",
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
        return "<b>Прокси</b>\n\nУ вас пока нет прокси-доступов."
    return proxy_section_separator().join(parts)


def user_proxy_stats_text(stats: ProxyUserStats) -> str:
    lines = ["<b>📊 Статистика прокси</b>"]
    if not stats.accesses:
        return "\n\n".join([lines[0], "У вас пока нет выданных прокси."])

    active_accesses = [access for access in stats.accesses if access.status == ProxyAccessStatus.ACTIVE]
    active_accesses.sort(key=lambda item: (_proxy_type_order(item.access_type), item.id))
    failed_accesses = [access for access in stats.accesses if access.status == ProxyAccessStatus.APPLY_FAILED]
    failed_accesses.sort(key=lambda item: (item.updated_at, item.created_at, item.id), reverse=True)
    recent_failed = failed_accesses[:3]
    hidden_failed = max(len(failed_accesses) - len(recent_failed), 0)

    lines.extend(["", "<b>Активные прокси:</b>"])
    if active_accesses:
        for access in active_accesses:
            lines.append("")
            lines.extend(_proxy_stats_access_lines(access, include_id=True))
    else:
        lines.append("")
        lines.append("Активных прокси нет.")

    if recent_failed:
        lines.append("")
        lines.append("<b>Последние ошибки выдачи:</b>")
        for access in recent_failed:
            lines.append(_proxy_stats_error_line(access))
    if hidden_failed > 0:
        lines.append("")
        lines.append(f"Старые неудачные попытки скрыты: {h(hidden_failed)}.")
    lines.extend(
        [
            "",
            "<b>Трафик:</b>",
            "Per-user traffic accounting для SOCKS5/MTProto сейчас недоступен и не фейкуется.",
        ]
    )
    return "\n".join(lines)


def admin_proxy_stats_text(stats: ProxyAdminStats) -> str:
    lines = [
        "<b>📊 Статистика прокси</b>",
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
        lines.append("Runtime status: недоступно")
    else:
        lines.extend(
            [
                "<b>SOCKS5 / Dante</b>",
                f"• enabled: {h(_yes_no(runtime.socks5_enabled))}",
                f"• service active: {h(_runtime_value(runtime.socks5_systemd_active))}",
                f"• listening: {h(_runtime_value(runtime.socks5_port_listening))}",
                f"• host: {code(runtime.socks5_host or 'не задан')}",
                f"• port: {code(runtime.socks5_port if runtime.socks5_port is not None else 'не задан')}",
                "<b>MTProto</b>",
                f"• enabled: {h(_yes_no(runtime.mtproto_enabled))}",
                f"• service active: {h(_runtime_value(runtime.mtproto_systemd_active))}",
                f"• listening: {h(_runtime_value(runtime.mtproto_port_listening))}",
                f"• host: {code(runtime.mtproto_host or 'не задан')}",
                f"• port: {code(runtime.mtproto_port if runtime.mtproto_port is not None else 'не задан')}",
                f"• mode: {h(runtime.mtproto_mode)}",
                f"• runtime managed secrets: {h(_count_or_unavailable(runtime.mtproto_runtime_secret_count))}",
            ]
        )

    lines.extend(["", "<b>Users</b>"])
    if not stats.users:
        lines.append("Пользователей с proxy_accesses нет.")
    for row in stats.users:
        username = format_user_display(row.telegram_user_id, row.username)
        active = ", ".join(
            f"{_proxy_type_title(ref.access_type)} #{ref.id}"
            for ref in row.active_accesses
        ) or "нет"
        lines.extend(
            [
                f"👤 {code(row.telegram_user_id)} {username}",
                f"• active: {h(active)}",
                f"• failed: {h(row.failed_count)}",
                f"• last issued: {h(_format_proxy_datetime(row.last_proxy_issued_at))}",
            ]
        )
    if stats.hidden_users > 0:
        lines.append(f"Ещё {h(stats.hidden_users)} пользователей скрыто.")
    lines.extend(["", "Traffic: per-user traffic accounting для SOCKS5/MTProto сейчас недоступен и не фейкуется."])
    return "\n".join(lines)


def _proxy_stats_access_lines(access: ProxyAccessStatsItem, *, include_id: bool) -> list[str]:
    title = _proxy_type_title(access.access_type)
    if include_id:
        title = f"{title} #{access.id}"
    lines = [
        f"<b>{h(title)}</b>",
        f"• Статус: {h(access.status.value)}",
        f"• Выдан: {h(_format_proxy_datetime(access.created_at))}",
    ]
    if access.activated_at:
        lines.append(f"• Активирован: {h(_format_proxy_datetime(access.activated_at))}")
    if access.last_shown_at:
        lines.append(f"• Последний показ: {h(_format_proxy_datetime(access.last_shown_at))}")
    if access.revoked_at:
        lines.append(f"• Отозван: {h(_format_proxy_datetime(access.revoked_at))}")
    if access.deleted_at:
        lines.append(f"• Удалён: {h(_format_proxy_datetime(access.deleted_at))}")
    if access.access_type == ProxyAccessType.SOCKS5:
        if access.host:
            lines.append(f"• Host: {code(access.host)}")
        if access.port is not None:
            lines.append(f"• Port: {code(access.port)}")
        if access.login:
            lines.append(f"• Login: {code(access.login)}")
        return lines
    mode = access.mtproto_mode or "static"
    lines.append(f"• Тип: {h(mode)}")
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
        return "нет данных"
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
        return "недоступно"
    return "yes" if value else "no"


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def _count_or_unavailable(value: int | None) -> str:
    return str(value) if value is not None else "недоступно"


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


def proxy_admin_status_text(status: ProxyServiceStatus, stats: ProxyLifecycleStats) -> str:
    socks5_port = status.socks5_port if status.socks5_port is not None else "не задан"
    mtproto_active = "unknown" if status.mtproto_systemd_active is None else ("yes" if status.mtproto_systemd_active else "no")
    mtproto_listening = "unknown" if status.mtproto_port_listening is None else ("yes" if status.mtproto_port_listening else "no")
    mtproto_traffic_text = (
        "Traffic: per-user статистика недоступна для MTProto без надёжного server-side accounting по secret."
    )
    mtproto_revoke_note = (
        "Managed mode: индивидуальный server-side revoke выполняется удалением secret из active list MTProxy."
        if status.mtproto_mode == "managed"
        else "Static mode: используется общий secret, индивидуальный server-side revoke невозможен без ротации secret."
    )
    lines = [
        "<b>Статус прокси</b>",
        "",
        "<b>SOCKS5 / Dante</b>",
        f"Enabled: {h('yes' if status.socks5_enabled else 'no')}",
        f"Host: {code(status.socks5_host or 'не задан')}",
        f"Port: {code(socks5_port)}",
        f"Public name: {h(status.socks5_public_name)}",
        f"Service: {code(status.socks5_service_name)}",
        f"Issued: {h(stats.socks5_issued)}",
        f"Active: {h(stats.socks5_active)}",
        f"Revoked/blocked: {h(stats.socks5_revoked)}",
        "Traffic: статистика трафика недоступна для этого типа прокси без per-login accounting Dante.",
        "",
        "<b>MTProto</b>",
        f"Enabled: {h('yes' if status.mtproto_enabled else 'no')}",
        f"Mode: {h(status.mtproto_mode)}",
        f"Host: {code(status.mtproto_host or 'не задан')}",
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


def backend_diagnostics_text(statuses: tuple[BackendHealthStatus, ...], *, mtproto_mode: str = "static") -> str:
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


def system_diagnostics_text(result: HealthCheckResult) -> str:
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
    return "\n".join(lines)


def announcement_batches_text(batches: list[AnnouncementBatch]) -> str:
    if not batches:
        return "<b>Незавершённые объявления</b>\n\nНезавершённых batch-записей нет."
    lines = ["<b>Незавершённые объявления</b>"]
    for batch in batches:
        pending = max(batch.total_count - batch.success_count - batch.failed_count - batch.skipped_count, 0)
        lines.extend(
            [
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
        )
    return "\n".join(lines)


def proxy_entry_text(entry: ProxyEntry) -> str:
    lines = [
        f"<b>{h(entry.proxy_type)}</b>",
        f"Хост: {code(entry.host)}",
        f"Порт: {code(entry.port)}",
    ]
    if entry.login:
        lines.append(f"Логин: {code(entry.login)}")
    if entry.password:
        lines.append(f"Пароль: {code(entry.password)}")
    if entry.note:
        lines.append(f"Описание: {h(entry.note)}")
    lines.append(f"Статус: {h(entry.status.value)}")
    return "\n".join(lines)


def _redact_diagnostic_reason(value: str, limit: int = 180) -> str:
    return _redact(value, limit)


def proxy_page_text(entries: list[ProxyEntry], page: int) -> str:
    if not entries:
        return "<b>Прокси</b>\n\nДоступные прокси не настроены."
    return f"<b>Прокси</b> · страница {page + 1}\n\n" + "\n\n".join(proxy_entry_text(entry) for entry in entries)


def access_request_text(request: AccessRequest) -> str:
    username = f"@{request.username}" if request.username else "не указан"
    return (
        f"<b>Заявка #{request.id}</b>\n"
        f"Telegram ID: {code(request.telegram_user_id)}\n"
        f"Username: {h(username)}\n"
        f"Статус: {h(request.status.value)}\n"
        f"Создана: {h(format_msk_datetime(request.requested_at))}"
    )


def access_request_decision_confirm_text(request: AccessRequest, action: str) -> str:
    action_text = "одобрить" if action == "approve" else "отклонить"
    username = f"@{request.username}" if request.username else "не указан"
    return (
        f"<b>Подтвердите действие: {h(action_text)}</b>\n"
        f"Заявка: #{request.id}\n"
        f"Telegram ID: {code(request.telegram_user_id)}\n"
        f"Username: {h(username)}\n"
        f"Статус: {h(request.status.value)}\n"
        f"Создана: {h(format_msk_datetime(request.requested_at))}"
    )


def access_requests_page_text(requests: list[AccessRequest], page: int) -> str:
    if not requests:
        return "<b>Заявки на доступ</b>\n\nНовых заявок нет."
    return f"<b>Заявки на доступ</b> · страница {page + 1}\n\n" + "\n\n".join(access_request_text(req) for req in requests)


def user_card_text(
    user: User,
    keys: list[VpnKey] | None = None,
    stats_by_key_id: dict[int, TrafficStats] | None = None,
    *,
    viewer_user_id: int | None = None,
) -> str:
    username = f"@{user.username}" if user.username else "не указан"
    lines = [
        "<b>Пользователь</b>",
        f"Telegram ID: {code(user.telegram_user_id)}",
        f"Username: {h(username)}",
        f"Роль: {h(role_text(user.role))}",
        f"Обновлён: {h(format_msk_datetime(user.updated_at))}",
    ]
    if user.note:
        lines.append(f"Заметка: {h(user.note)}")
    if keys is not None:
        lines.append("")
        lines.append("<b>Ключи</b>")
        if not keys:
            lines.append("Ключей нет.")
        else:
            stats_by_key_id = stats_by_key_id or {}
            for key in keys:
                stats = stats_by_key_id.get(key.id)
                traffic = ""
                if stats and stats.available:
                    traffic = f" · ↓ {format_bytes(stats.downloaded_bytes)} · ↑ {format_bytes(stats.uploaded_bytes)}"
                elif stats:
                    traffic = " · статистика пока недоступна"
                lines.append(f"{h(key.key_type.value.upper())} · {code(key_display_label(key, viewer_user_id=viewer_user_id))}{traffic}")
    return "\n".join(lines)


def block_user_confirm_text(user: User, key_count: int) -> str:
    username = f"@{user.username}" if user.username else "не указан"
    return (
        "<b>Подтвердите блокировку пользователя</b>\n"
        f"Telegram ID: {code(user.telegram_user_id)}\n"
        f"Username: {h(username)}\n"
        f"Имя: {h(user.first_name or 'не указано')}\n"
        f"Текущая роль: {h(role_text(user.role))}\n"
        f"Ключей к проверке/отзыву: {key_count}\n\n"
        "Действие заблокирует доступ к боту и попытается отозвать VPN-ключи. "
        "Если часть VPN-ключей не получится отключить автоматически, потребуется ручная проверка на сервере."
    )


def unblock_user_confirm_text(warning: UnblockUserWarning) -> str:
    user = warning.user
    username = f"@{user.username}" if user.username else "не указан"
    lines = [
        "<b>Подтвердите разблокировку пользователя</b>",
        f"Telegram ID: {code(user.telegram_user_id)}",
        f"Username: {h(username)}",
        f"Имя: {h(user.first_name or 'не указано')}",
        f"Текущая роль: {h(role_text(user.role))}",
    ]
    if warning.has_warning:
        lines.extend(
            [
                "",
                "<b>Требуется ручная проверка VPN</b>",
                "Ранее могли остаться активные или проблемные VPN-ключи.",
            ]
        )
        for reason in warning.reasons:
            lines.append(f"• {h(reason)}")
        if warning.last_block_error_at:
            lines.append(f"Последняя ошибка блокировки: {h(format_msk_datetime(warning.last_block_error_at))}")
        lines.append("Разблокировка восстановит доступ к боту, но не исправит Xray/AWG runtime автоматически.")
    else:
        lines.extend(["", "После подтверждения пользователь снова получит доступ к боту."])
    return "\n".join(lines)


def unblock_user_success_text(warning: UnblockUserWarning) -> str:
    text = "Пользователь разблокирован. FSM-состояние очищено, сценарии начнутся заново."
    if not warning.has_warning:
        return text
    return (
        text
        + "\n\n"
        + "Внимание: перед разблокировкой были признаки неполного отзыва VPN-доступа. "
        + "Проверьте Xray/AWG runtime и config вручную."
    )


def users_page_text(users: list[User], page: int, key_counts: dict[int, int] | None = None) -> str:
    if not users:
        return "<b>Пользователи</b>\n\nНа этой странице пользователей нет."
    lines = [f"<b>Пользователи</b> · страница {page + 1}"]
    key_counts = key_counts or {}
    for user in users:
        username = format_user_display(user.telegram_user_id, user.username)
        key_count = key_counts.get(user.telegram_user_id, 0)
        lines.append(
            f"{code(user.telegram_user_id)} · {username} · {h(role_text(user.role))} · ключей: {key_count}"
        )
    return "\n".join(lines)


def audit_page_text(items: list[dict[str, object]], page: int, users: dict[int, User] | None = None) -> str:
    if not items:
        return "<b>Логи действий</b>\n\nНа этой странице записей нет."
    lines = [f"<b>Логи действий</b> · страница {page + 1}"]
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
        else format_user_display(int(actor_id), None) if actor_id is not None else "система"  # type: ignore[call-overload]
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
        owner_suffix = f" для {owner_text}"
    time_text = h(format_msk_datetime(str(item.get("created_at") or "")))
    if action == "xray_key_created":
        suffix = (f" создал Xray-ключ {label}" if label else " создал Xray-ключ") + owner_suffix
    elif action == "awg_key_created":
        suffix = (f" создал AWG-ключ {label}" if label else " создал AWG-ключ") + owner_suffix
    elif action == "stats_viewed":
        target_user_id = details_dict.get("target_user_id")
        target_username = details_dict.get("target_username")
        target_text = format_user_display(
            int(target_user_id) if target_user_id is not None else None,
            str(target_username) if target_username else None,
        )
        suffix = f" открыл статистику пользователя {target_text}"
    elif action == "user_role_changed":
        suffix = " изменил роль пользователя"
    elif action == "user_blocked":
        suffix = " заблокировал пользователя"
    elif action == "user_unblocked":
        suffix = " разблокировал пользователя"
    elif action == "access_requested":
        if details_dict.get("repeat_after_block"):
            suffix = " отправил повторную заявку на доступ"
        else:
            suffix = " отправил заявку на доступ"
    elif action == "access_approved":
        suffix = " одобрил заявку на доступ"
    elif action == "access_rejected":
        suffix = " отклонил заявку на доступ"
    else:
        suffix = f" выполнил действие {h(action)}"
    return f"{time_text} — {actor_text}{suffix}"
