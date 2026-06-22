
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup

from i18n import t

FAQ_TOPICS: list[tuple[str, str]] = [
    ("connect",        "btn_faq_connect"),
    ("trouble",        "btn_faq_trouble"),
    ("key_statuses",   "btn_faq_key_statuses"),
    ("revoke_delete",  "btn_faq_revoke_delete"),
    ("expired",        "btn_faq_expired"),
    ("device",         "btn_faq_device"),
    ("stats",          "btn_faq_stats"),
    ("choice",         "btn_faq_choice"),
    ("fingerprint",    "btn_faq_fingerprint"),
    ("mtu",            "btn_faq_mtu"),
    ("note_why",       "btn_faq_note_why"),
    ("proxy",          "btn_faq_proxy"),
    ("settings",       "btn_faq_settings"),
    ("server_restart", "btn_faq_server_restart"),
    ("security",       "btn_faq_security"),
    ("support",        "btn_faq_support"),
]
FAQ_PER_PAGE = 5


def main_menu(is_admin: bool = False) -> InlineKeyboardMarkup:
    """Build the main menu inline keyboard, optionally with the admin panel entry."""
    rows = [
        [InlineKeyboardButton(text=t("btn_my_keys"), callback_data="keys:list")],
        [InlineKeyboardButton(text=t("btn_create_key"), callback_data="keys:create")],
        [InlineKeyboardButton(text=t("btn_proxy"), callback_data="proxy:show")],
        [InlineKeyboardButton(text=t("btn_settings"), callback_data="settings:open")],
        [InlineKeyboardButton(text=t("btn_help"), callback_data="help")],
    ]
    if is_admin:
        rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def main_reply_keyboard(is_admin: bool = False) -> ReplyKeyboardMarkup:
    """Build the main menu reply keyboard, optionally with the admin panel button."""
    rows = [
        [KeyboardButton(text=t("btn_my_keys")), KeyboardButton(text=t("btn_create_key"))],
        [KeyboardButton(text=t("btn_proxy")), KeyboardButton(text=t("btn_help"))],
    ]
    if is_admin:
        rows.append([KeyboardButton(text=t("btn_admin_panel"))])
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, input_field_placeholder=t("btn_keyboard_placeholder"))


def back_to_menu() -> InlineKeyboardMarkup:
    """Build a keyboard with a single back-to-menu button."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")]]
    )


def faq_keyboard(page: int = 1) -> InlineKeyboardMarkup:
    """Build the paginated FAQ topics inline keyboard."""
    total = (len(FAQ_TOPICS) + FAQ_PER_PAGE - 1) // FAQ_PER_PAGE
    page = max(1, min(page, total))
    start = (page - 1) * FAQ_PER_PAGE
    page_topics = FAQ_TOPICS[start : start + FAQ_PER_PAGE]

    rows: list[list[InlineKeyboardButton]] = []
    for topic_key, btn_key in page_topics:
        rows.append([InlineKeyboardButton(text=t(btn_key), callback_data=f"faq:{topic_key}:{page}")])

    nav: list[InlineKeyboardButton] = []
    if page > 1:
        nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=f"faq_page:{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"{page} / {total}", callback_data="noop"))
    if page < total:
        nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=f"faq_page:{page + 1}"))
    rows.append(nav)

    rows.append([InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def faq_answer_keyboard(page: int = 1) -> InlineKeyboardMarkup:
    """Build the keyboard shown beneath an FAQ answer."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_back_to_faq"), callback_data=f"faq_page:{page}")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


def cancel_keyboard() -> InlineKeyboardMarkup:
    """Build a keyboard with a single cancel button."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")]]
    )


def confirm_cancel_keyboard(confirm_data: str, cancel_data: str = "cancel") -> InlineKeyboardMarkup:
    """Build a confirm/cancel keyboard with the given callback data."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=confirm_data)],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=cancel_data)],
        ]
    )


def pagination_keyboard(
    *,
    prev_data: str | None,
    next_data: str | None,
    back_data: str,
) -> InlineKeyboardMarkup:
    """Build a generic prev/next pagination keyboard with a back button."""
    rows: list[list[InlineKeyboardButton]] = []
    nav: list[InlineKeyboardButton] = []
    if prev_data:
        nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=prev_data))
    if next_data:
        nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=next_data))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)
