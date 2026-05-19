
from datetime import datetime
from html import escape
from zoneinfo import ZoneInfo


MSK_TZ = ZoneInfo("Europe/Moscow")


def h(value: object) -> str:
    return escape(str(value), quote=False)


def code(value: object) -> str:
    return f"<code>{h(value)}</code>"


def pre(value: object) -> str:
    return f"<pre>{h(value)}</pre>"


def format_bytes(value: int | None) -> str:
    if value is None:
        return "нет данных"
    try:
        size = max(int(value), 0)
    except (TypeError, ValueError, OverflowError):
        return "нет данных"
    units = ("B", "KB", "MB", "GB", "TB")
    amount = float(size)
    unit = units[0]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            break
        amount /= 1024
    if unit == "B":
        return f"{size} B"
    return f"{amount:.2f} {unit}"


_MONTHS_RU = [
    "января", "февраля", "марта", "апреля", "мая", "июня",
    "июля", "августа", "сентября", "октября", "ноября", "декабря",
]


def format_expiry_date(value: str | None) -> str:
    if not value:
        return "бессрочный"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return str(value)
    if dt.tzinfo is None:
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    dt_msk = dt.astimezone(MSK_TZ)
    month = _MONTHS_RU[dt_msk.month - 1]
    return f"{dt_msk.day} {month} {dt_msk.year}"


def format_msk_datetime(value: str | None) -> str:
    if not value:
        return "нет данных"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=MSK_TZ)
    return dt.astimezone(MSK_TZ).strftime("%d.%m.%Y %H:%M:%S МСК")


def format_user_display(telegram_user_id: int | None, username: str | None) -> str:
    if username:
        clean = username.lstrip("@")
        if clean:
            return f"@{h(clean)}"
    if telegram_user_id is None:
        return "неизвестный пользователь"
    return f"tg{telegram_user_id}"


def format_greeting_name(telegram_user_id: int, first_name: str | None, username: str | None) -> str:
    if first_name:
        return h(str(first_name))
    if username:
        return h(username.lstrip("@"))
    return str(telegram_user_id)
