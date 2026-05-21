
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from bot.formatters import status_text
from i18n import t
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType


def create_key_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Xray", callback_data="keys:create:xray")],
            [InlineKeyboardButton(text="AWG", callback_data="keys:create:awg")],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="menu:main")],
        ]
    )


def keys_list_keyboard(
    keys: list[VpnKey],
    page: int = 0,
    has_next: bool = False,
    owner_user_id: int | None = None,
    total_pages: int = 1,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for key in keys:
        prefix = "Xray" if key.key_type == VpnKeyType.XRAY else "AWG"
        open_data = f"key:open:{key.id}"
        if owner_user_id is not None:
            open_data = f"key:open:{key.id}:{owner_user_id}:{page}"
        rows.append([InlineKeyboardButton(text=f"{prefix} #{key.id} · {status_text(key.status)}", callback_data=open_data)])
        if key.status == VpnKeyStatus.ACTIVE:
            buttons = [
                InlineKeyboardButton(text=t("btn_config"), callback_data=f"key:show:{key.id}"),
                InlineKeyboardButton(text=t("btn_stats"), callback_data=f"key:stats:{key.id}"),
            ]
            revoke_data = f"key:revoke:{key.id}" if owner_user_id is None else f"key:revoke:{key.id}:{owner_user_id}:{page}"
            buttons.append(InlineKeyboardButton(text=t("btn_revoke"), callback_data=revoke_data))
            rows.append(buttons)
        else:
            rows.append([InlineKeyboardButton(text=t("btn_stats"), callback_data=f"key:stats:{key.id}")])
        if key.status != VpnKeyStatus.DELETED:
            note_buttons: list[InlineKeyboardButton] = []
            if owner_user_id is None:
                note_buttons.append(InlineKeyboardButton(text=t("btn_note"), callback_data=f"key:note:{key.id}"))
            delete_data = f"key:delete:{key.id}" if owner_user_id is None else f"key:delete:{key.id}:{owner_user_id}:{page}"
            note_buttons.append(InlineKeyboardButton(text=t("btn_delete"), callback_data=delete_data))
            rows.append(note_buttons)

    prev_page = page - 1
    next_page = page + 1
    page_prefix = f"admin:ukeys:{owner_user_id}" if owner_user_id is not None else "keys:list"
    if page > 0 or has_next:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=f"{page_prefix}:{prev_page}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1} / {total_pages}", callback_data="noop"))
        if has_next:
            nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=f"{page_prefix}:{next_page}"))
        rows.append(nav)

    create_callback = f"admin:issue:{owner_user_id}" if owner_user_id is not None else "keys:create"
    rows.append([InlineKeyboardButton(text=t("btn_create_key"), callback_data=create_callback)])
    rows.append([InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def key_actions_keyboard(key: VpnKey, owner_user_id: int | None = None, page: int = 0) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if key.status == VpnKeyStatus.ACTIVE:
        rows.append([InlineKeyboardButton(text=t("btn_show_config"), callback_data=f"key:show:{key.id}")])
        revoke_data = f"key:revoke:{key.id}" if owner_user_id is None else f"key:revoke:{key.id}:{owner_user_id}:{page}"
        rows.append([InlineKeyboardButton(text=t("btn_revoke"), callback_data=revoke_data)])
    rows.append([InlineKeyboardButton(text=t("btn_stats"), callback_data=f"key:stats:{key.id}")])
    if key.status != VpnKeyStatus.DELETED:
        if owner_user_id is None:
            rows.append([InlineKeyboardButton(text=t("btn_edit_note_key"), callback_data=f"key:note:{key.id}")])
        delete_data = f"key:delete:{key.id}" if owner_user_id is None else f"key:delete:{key.id}:{owner_user_id}:{page}"
        rows.append([InlineKeyboardButton(text=t("btn_delete"), callback_data=delete_data)])
    back_data = f"admin:ukeys:{owner_user_id}:{page}" if owner_user_id is not None else "keys:list"
    rows.append([InlineKeyboardButton(text=t("btn_to_list"), callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def confirm_keyboard(action: str, key_id: int, owner_user_id: int | None = None, page: int = 0) -> InlineKeyboardMarkup:
    confirm_data = f"confirm:{action}:{key_id}"
    cancel_data = f"key:open:{key_id}"
    if owner_user_id is not None:
        confirm_data = f"{confirm_data}:{owner_user_id}:{page}"
        cancel_data = f"{cancel_data}:{owner_user_id}:{page}"
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=confirm_data)],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=cancel_data)],
        ]
    )


def mtu_choice_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_mtu_recommended"), callback_data="mtu:1360")],
            [InlineKeyboardButton(text="1280", callback_data="mtu:1280")],
            [InlineKeyboardButton(text="1420", callback_data="mtu:1420")],
            [InlineKeyboardButton(text="1500", callback_data="mtu:1500")],
            [InlineKeyboardButton(text=t("btn_enter_manually"), callback_data="mtu:custom")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")],
        ]
    )


def after_key_created_keyboard(key: VpnKey) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_open_key"), callback_data=f"key:open:{key.id}")],
            [InlineKeyboardButton(text=t("btn_my_keys"), callback_data="keys:list")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


def expiry_choice_keyboard(is_admin: bool = False) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text=t("btn_permanent"), callback_data="expiry:permanent")],
        [InlineKeyboardButton(text=t("btn_7_days"), callback_data="expiry:7")],
        [InlineKeyboardButton(text=t("btn_30_days"), callback_data="expiry:30")],
        [InlineKeyboardButton(text=t("btn_enter_days"), callback_data="expiry:custom")],
        [InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def trial_key_show_keyboard(key_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_get_config"), callback_data=f"trial:show:{key_id}")],
        ]
    )


def request_trial_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_request_trial"), callback_data="trial:request")],
        ]
    )


def trial_protocol_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Xray", callback_data="trial:proto:xray")],
            [InlineKeyboardButton(text="AWG", callback_data="trial:proto:awg")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")],
        ]
    )


def after_key_deleted_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_my_keys"), callback_data="keys:list")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )
