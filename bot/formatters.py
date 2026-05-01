from __future__ import annotations

from aiogram.types import User as TgUser

from models.dto import AccessRequest, KeyTrafficStatsView, ProxyEntry, TrafficStats, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from utils.formatting import (
    code,
    format_bytes,
    format_greeting_name,
    format_msk_datetime,
    format_user_display,
    h,
)


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
    return f"Доброго времени суток, {h(name)}\n\n{SERVER_RESTART_WARNING}\n\nВыберите действие."


def key_list_card(key: VpnKey, *, viewer_user_id: int) -> str:
    note = key_note_for_viewer(key, viewer_user_id)
    label = key_display_label(key, viewer_user_id=viewer_user_id)
    parts = [
        f"<b>{key_title(key)}</b>",
        f"Статус: {h(status_text(key.status))}",
        f"Метка: {code(label)}",
        f"Создан: {h(format_msk_datetime(key.created_at))}",
    ]
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
        f"Владелец: {h(owner_text)}",
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
            f"{h(owner_text)} · {h(traffic + updated)}"
        )
        note = key_note_for_viewer(view.key, viewer_user_id)
        if note and label != note:
            line += f" · Заметка: {h(short_note(note))}"
        lines.append(line)
    return "\n".join(lines)


def create_confirm_text(key_type: str, note: str | None, owner: User | None = None) -> str:
    lines = [
        "<b>Подтверждение создания ключа</b>",
        f"Тип: {h(key_type.upper())}",
        f"Заметка: {h(note or 'нет')}",
    ]
    if owner is not None:
        lines.append(f"Владелец: {h(format_user_display(owner.telegram_user_id, owner.username))}")
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
    return f"{config_text}\n\nСкопируйте конфиг в клиент AmneziaWG."


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


def users_page_text(users: list[User], page: int, key_counts: dict[int, int] | None = None) -> str:
    if not users:
        return "<b>Пользователи</b>\n\nНа этой странице пользователей нет."
    lines = [f"<b>Пользователи</b> · страница {page + 1}"]
    key_counts = key_counts or {}
    for user in users:
        username = format_user_display(user.telegram_user_id, user.username)
        key_count = key_counts.get(user.telegram_user_id, 0)
        lines.append(
            f"{code(user.telegram_user_id)} · {h(username)} · {h(role_text(user.role))} · ключей: {key_count}"
        )
    return "\n".join(lines)


def audit_page_text(items: list[dict[str, object]], page: int, users: dict[int, User] | None = None) -> str:
    if not items:
        return "<b>Логи действий</b>\n\nНа этой странице записей нет."
    lines = [f"<b>Логи действий</b> · страница {page + 1}"]
    users = users or {}
    for item in items:
        lines.append(h(_human_audit_line(item, users)))
    return "\n".join(lines)


def _human_audit_line(item: dict[str, object], users: dict[int, User]) -> str:
    actor_id = item.get("actor_user_id")
    actor: User | None = users.get(int(actor_id)) if actor_id is not None else None
    actor_text = (
        format_user_display(actor.telegram_user_id, actor.username)
        if actor is not None
        else format_user_display(int(actor_id), None) if actor_id is not None else "система"
    )
    action = str(item.get("action") or "")
    details = item.get("details")
    details_dict = details if isinstance(details, dict) else {}
    label = str(details_dict.get("label") or details_dict.get("email_label") or details_dict.get("key_label") or "")
    owner_user_id = details_dict.get("owner_user_id")
    owner_username = details_dict.get("owner_username")
    owner_text = format_user_display(
        int(owner_user_id) if owner_user_id is not None else None,
        str(owner_username) if owner_username else None,
    )
    owner_suffix = ""
    if owner_user_id is not None and actor_id is not None and int(owner_user_id) != int(actor_id):
        owner_suffix = f" для {owner_text}"
    time_text = format_msk_datetime(str(item.get("created_at") or ""))
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
        suffix = f" выполнил действие {action}"
    return f"{time_text} — {actor_text}{suffix}"
