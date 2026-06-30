
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from bot.formatters import key_type_label, status_text
from i18n import t
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType

VALID_FINGERPRINTS = [
    "firefox", "chrome", "safari", "ios", "android", "edge",
    "360", "qq", "random", "randomized",
]


def create_key_keyboard(
    *,
    xray_enabled: bool = True,
    awg_enabled: bool = True,
    xhttp_enabled: bool = False,
    hysteria2_enabled: bool = False,
    back_data: str = "keys:list",
) -> InlineKeyboardMarkup:
    """Build the protocol selection keyboard for creating a new key (step 1).

    With XHTTP disabled there is only one VLESS transport, so the VLESS button
    goes straight to TCP key creation (no redundant single-option transport
    step). The transport step is offered only when XHTTP is enabled.

    ``back_data`` controls where the «back» button returns to so the flow can
    honour its entry point (the main menu vs. the «My keys» list).
    """
    rows: list[list[InlineKeyboardButton]] = []
    if xray_enabled:
        vless_data = "keys:proto:vless" if xhttp_enabled else "keys:create:xray"
        rows.append([InlineKeyboardButton(text="VLESS", callback_data=vless_data)])
    if awg_enabled:
        rows.append([InlineKeyboardButton(text="AmneziaWG 2.0", callback_data="keys:create:awg")])
    if hysteria2_enabled:
        rows.append([InlineKeyboardButton(text="Hysteria2", callback_data="keys:create:hy2")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def vless_transport_keyboard(*, xhttp_enabled: bool = False) -> InlineKeyboardMarkup:
    """Build the VLESS transport selection keyboard (step 2, VLESS only)."""
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text="VLESS (TCP)", callback_data="keys:create:xray")],
    ]
    if xhttp_enabled:
        rows.append([InlineKeyboardButton(text="VLESS (HTTP)", callback_data="keys:create:xhttp")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="keys:create")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def xhttp_profile_keyboard() -> InlineKeyboardMarkup:
    """Build the XHTTP transport-profile selection keyboard (step 3, VLESS HTTP).

    Descriptions are shown in the prompt text; each button carries the profile's
    short name. Back returns to the VLESS transport step.
    """
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text=t("xhttp_profile_base_name"), callback_data="keys:xhttp:profile:base")],
        [InlineKeyboardButton(text=t("xhttp_profile_antisib_name"), callback_data="keys:xhttp:profile:antisib")],
        [InlineKeyboardButton(text=t("xhttp_profile_multi_name"), callback_data="keys:xhttp:profile:multi")],
        [InlineKeyboardButton(text=t("btn_back"), callback_data="keys:proto:vless")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def keys_list_keyboard(
    keys: list[VpnKey],
    page: int = 0,
    has_next: bool = False,
    owner_user_id: int | None = None,
    total_pages: int = 1,
    back_data: str = "menu:main",
) -> InlineKeyboardMarkup:
    """Build the paginated keyboard listing keys with per-key actions."""
    rows: list[list[InlineKeyboardButton]] = []
    for key in keys:
        prefix = key_type_label(key)
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
    rows.append([InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data=back_data)])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def key_actions_keyboard(key: VpnKey, owner_user_id: int | None = None, page: int = 0) -> InlineKeyboardMarkup:
    """Build the actions keyboard for a single key based on its status."""
    rows: list[list[InlineKeyboardButton]] = []
    if key.status == VpnKeyStatus.ACTIVE:
        rows.append([InlineKeyboardButton(text=t("btn_show_config"), callback_data=f"key:show:{key.id}")])
        revoke_data = f"key:revoke:{key.id}" if owner_user_id is None else f"key:revoke:{key.id}:{owner_user_id}:{page}"
        rows.append([InlineKeyboardButton(text=t("btn_revoke"), callback_data=revoke_data)])
        if key.key_type == VpnKeyType.XRAY and owner_user_id is None:
            rows.append([InlineKeyboardButton(text=t("btn_change_fp"), callback_data=f"key:fp:{key.id}")])
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
    """Build a confirm/cancel keyboard for an action on a key."""
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


def fp_choice_keyboard() -> InlineKeyboardMarkup:
    """Build the fingerprint selection keyboard for Xray key creation."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_fp_firefox"),    callback_data="fp:firefox")],
            [InlineKeyboardButton(text="Chrome",               callback_data="fp:chrome")],
            [InlineKeyboardButton(text="Safari",               callback_data="fp:safari")],
            [InlineKeyboardButton(text="iOS",                  callback_data="fp:ios")],
            [InlineKeyboardButton(text="Android",              callback_data="fp:android")],
            [InlineKeyboardButton(text="Edge",                 callback_data="fp:edge")],
            [InlineKeyboardButton(text="360",                  callback_data="fp:360")],
            [InlineKeyboardButton(text="QQ",                   callback_data="fp:qq")],
            [InlineKeyboardButton(text=t("btn_fp_random"),     callback_data="fp:random")],
            [InlineKeyboardButton(text=t("btn_fp_randomized"), callback_data="fp:randomized")],
            [InlineKeyboardButton(text=t("btn_cancel"),        callback_data="cancel")],
        ]
    )


def mtu_choice_keyboard() -> InlineKeyboardMarkup:
    """Build the MTU value selection keyboard."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_mtu_recommended"), callback_data="mtu:1280")],
            [InlineKeyboardButton(text="1370", callback_data="mtu:1370")],
            [InlineKeyboardButton(text="1420", callback_data="mtu:1420")],
            [InlineKeyboardButton(text=t("btn_enter_manually"), callback_data="mtu:custom")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")],
        ]
    )


def after_key_created_keyboard(key: VpnKey) -> InlineKeyboardMarkup:
    """Build the keyboard shown after a key is created."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_open_key"), callback_data=f"key:open:{key.id}")],
            [InlineKeyboardButton(text=t("btn_my_keys"), callback_data="keys:list")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


def expiry_choice_keyboard(is_admin: bool = False) -> InlineKeyboardMarkup:
    """Build the key expiry duration selection keyboard."""
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text=t("btn_permanent"), callback_data="expiry:permanent")],
        [InlineKeyboardButton(text=t("btn_7_days"), callback_data="expiry:7")],
        [InlineKeyboardButton(text=t("btn_30_days"), callback_data="expiry:30")],
        [InlineKeyboardButton(text=t("btn_enter_days"), callback_data="expiry:custom")],
        [InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def trial_key_show_keyboard(key_id: int) -> InlineKeyboardMarkup:
    """Build the keyboard to reveal a trial key's config."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_get_config"), callback_data=f"trial:show:{key_id}")],
        ]
    )


def request_trial_keyboard() -> InlineKeyboardMarkup:
    """Build the keyboard to request a trial access."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_request_trial"), callback_data="trial:request")],
        ]
    )


def trial_protocol_keyboard(
    *, xray_enabled: bool = True, awg_enabled: bool = True, hysteria2_enabled: bool = False
) -> InlineKeyboardMarkup:
    """Build the protocol selection keyboard for a trial key."""
    rows: list[list[InlineKeyboardButton]] = []
    if xray_enabled:
        rows.append([InlineKeyboardButton(text="Xray(VLESS+XReality)", callback_data="trial:proto:xray")])
    if awg_enabled:
        rows.append([InlineKeyboardButton(text="AmneziaWG 2.0", callback_data="trial:proto:awg")])
    if hysteria2_enabled:
        rows.append([InlineKeyboardButton(text="Hysteria2", callback_data="trial:proto:hy2")])
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def after_key_deleted_keyboard() -> InlineKeyboardMarkup:
    """Build the keyboard shown after a key is deleted."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_my_keys"), callback_data="keys:list")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )
