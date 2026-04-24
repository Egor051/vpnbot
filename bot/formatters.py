from __future__ import annotations

from models.dto import AccessRequest, ProxyEntry, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType
from utils.formatting import code, h


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


def key_list_card(key: VpnKey) -> str:
    parts = [
        f"<b>{key_title(key)}</b>",
        f"Статус: {h(status_text(key.status))}",
        f"Создан: {h(key.created_at)}",
        f"Заметка: {h(short_note(key.note))}",
    ]
    if key.client_ip:
        parts.append(f"IP: {code(key.client_ip)}")
    return "\n".join(parts)


def keys_page_text(keys: list[VpnKey], page: int, owner_user_id: int | None = None) -> str:
    title = "<b>Ключи пользователя</b>" if owner_user_id else "<b>Мои ключи</b>"
    if not keys:
        return f"{title}\n\nНа этой странице ключей нет."
    xray = [key for key in keys if key.key_type == VpnKeyType.XRAY]
    awg = [key for key in keys if key.key_type == VpnKeyType.AWG]
    sections = [f"{title} · страница {page + 1}"]
    if xray:
        sections.append("<b>Xray</b>\n" + "\n\n".join(key_list_card(key) for key in xray))
    if awg:
        sections.append("<b>AWG</b>\n" + "\n\n".join(key_list_card(key) for key in awg))
    return "\n\n".join(sections)


def key_detail_text(key: VpnKey) -> str:
    lines = [
        f"<b>{key_title(key)}</b>",
        f"Статус: {h(status_text(key.status))}",
        f"Создан: {h(key.created_at)}",
        f"Обновлён: {h(key.updated_at)}",
        f"Заметка: {h(key.note or 'нет')}",
    ]
    if key.client_ip:
        lines.append(f"IP: {code(key.client_ip)}")
    if key.email_label:
        lines.append(f"Label: {code(key.email_label)}")
    if key.public_key:
        lines.append(f"Public key: {code(key.public_key)}")
    return "\n".join(lines)


def create_confirm_text(key_type: str, note: str | None, owner: User | None = None) -> str:
    lines = [
        "<b>Подтверждение создания ключа</b>",
        f"Тип: {h(key_type.upper())}",
        f"Заметка: {h(note or 'нет')}",
    ]
    if owner is not None:
        username = f"@{owner.username}" if owner.username else str(owner.telegram_user_id)
        lines.append(f"Владелец: {h(username)}")
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
        f"Host: {code(entry.host)}",
        f"Port: {code(entry.port)}",
    ]
    if entry.login:
        lines.append(f"Login: {code(entry.login)}")
    if entry.password:
        lines.append(f"Password: {code(entry.password)}")
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
        f"User ID: {code(request.telegram_user_id)}\n"
        f"Username: {h(username)}\n"
        f"Статус: {h(request.status.value)}\n"
        f"Создана: {h(request.requested_at)}"
    )


def access_requests_page_text(requests: list[AccessRequest], page: int) -> str:
    if not requests:
        return "<b>Заявки на доступ</b>\n\nНовых заявок нет."
    return f"<b>Заявки на доступ</b> · страница {page + 1}\n\n" + "\n\n".join(access_request_text(req) for req in requests)


def user_card_text(user: User) -> str:
    username = f"@{user.username}" if user.username else "не указан"
    return (
        "<b>Пользователь</b>\n"
        f"ID: {code(user.telegram_user_id)}\n"
        f"Username: {h(username)}\n"
        f"Роль: {h(role_text(user.role))}\n"
        f"Обновлён: {h(user.updated_at)}"
    )


def users_page_text(users: list[User], page: int) -> str:
    if not users:
        return "<b>Пользователи</b>\n\nНа этой странице пользователей нет."
    lines = [f"<b>Пользователи</b> · страница {page + 1}"]
    for user in users:
        username = f"@{user.username}" if user.username else str(user.telegram_user_id)
        lines.append(f"{code(user.telegram_user_id)} · {h(username)} · {h(role_text(user.role))}")
    return "\n".join(lines)


def audit_page_text(items: list[dict[str, object]], page: int) -> str:
    if not items:
        return "<b>Логи действий</b>\n\nНа этой странице записей нет."
    lines = [f"<b>Логи действий</b> · страница {page + 1}"]
    for item in items:
        lines.append(
            f"#{item['id']} · {h(item['created_at'])} · {h(item['action'])} · "
            f"{h(item['entity_type'])}:{h(item['entity_id'] or '-')}"
        )
    return "\n".join(lines)
