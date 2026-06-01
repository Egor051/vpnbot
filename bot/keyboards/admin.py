
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.access import is_blocked_user
from models.dto import AccessRequest, User
from models.enums import UserRole
from repositories.announcements import AnnouncementBatch
from utils.formatting import format_user_display


def access_request_keyboard(request_id: int) -> InlineKeyboardMarkup:
    """Build the approve/reject inline keyboard for an access request."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text=t("btn_approve"), callback_data=f"admin:approve:{request_id}"),
                InlineKeyboardButton(text=t("btn_reject"), callback_data=f"admin:reject:{request_id}"),
            ]
        ]
    )


def access_request_decision_confirm_keyboard(request_id: int, action: str) -> InlineKeyboardMarkup:
    """Build the confirm/cancel keyboard for an access request decision."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=f"admin:{action}:confirm:{request_id}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"admin:req:{request_id}")],
        ]
    )


def moderator_panel_keyboard() -> InlineKeyboardMarkup:
    """Build the moderator panel inline keyboard."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_access_requests"), callback_data="admin:reqs")],
            [InlineKeyboardButton(text=t("btn_users"), callback_data="admin:users")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


def dashboard_keyboard() -> InlineKeyboardMarkup:
    """Build the refresh/back inline keyboard for the admin dashboard."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔄 Обновить", callback_data="admin:dashboard:refresh")],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="admin:panel")],
        ]
    )


def admin_panel_keyboard() -> InlineKeyboardMarkup:
    """Build the full admin panel inline keyboard."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="📊 Дашборд", callback_data="admin:dashboard")],
            [InlineKeyboardButton(text=t("btn_access_requests"), callback_data="admin:reqs")],
            [InlineKeyboardButton(text=t("btn_users"), callback_data="admin:users")],
            [InlineKeyboardButton(text=t("btn_issue_key_to_user"), callback_data="admin:issue")],
            [InlineKeyboardButton(text=t("btn_trial_accesses"), callback_data="admin:trial")],
            [InlineKeyboardButton(text=t("btn_key_stats"), callback_data="admin:stats")],
            [InlineKeyboardButton(text=t("btn_proxy_status"), callback_data="admin:proxy")],
            [InlineKeyboardButton(text=t("btn_announcement"), callback_data="admin:announce")],
            [InlineKeyboardButton(text=t("btn_warp"), callback_data="admin:warp")],
            [InlineKeyboardButton(text=t("btn_modules"), callback_data="admin:modules")],
            [InlineKeyboardButton(text=t("btn_backend_diagnostics"), callback_data="admin:diagnostics")],
            [InlineKeyboardButton(text=t("btn_action_logs"), callback_data="admin:audit")],
            [InlineKeyboardButton(text=t("btn_announcement_recovery"), callback_data="admin:announce_batches")],
            [InlineKeyboardButton(text=t("btn_db_backup"), callback_data="admin:backup")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


def announcement_confirm_keyboard() -> InlineKeyboardMarkup:
    """Build the send/schedule/cancel keyboard for an announcement."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_send_now"), callback_data="admin:announce:send")],
            [InlineKeyboardButton(text=t("btn_schedule"), callback_data="admin:announce:schedule")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:announce:cancel")],
        ]
    )


def announcement_batches_keyboard(batches: list[AnnouncementBatch]) -> InlineKeyboardMarkup:
    """Build the keyboard listing announcement batches with status-based actions."""
    rows: list[list[InlineKeyboardButton]] = []
    for batch in batches:
        actions: list[InlineKeyboardButton] = []
        if batch.status == "scheduled":
            actions.append(InlineKeyboardButton(text=f"{t('btn_send_now')} #{batch.id}", callback_data=f"admin:announce:resume:{batch.id}"))
        if batch.status in {"pending", "sending"}:
            actions.append(InlineKeyboardButton(text=f"Continue #{batch.id}", callback_data=f"admin:announce:resume:{batch.id}"))
        if batch.status == "failed":
            actions.append(InlineKeyboardButton(text=f"Retry errors #{batch.id}", callback_data=f"admin:announce:retry:{batch.id}"))
        if actions:
            rows.append(actions)
        rows.append([InlineKeyboardButton(text=f"Cancel #{batch.id}", callback_data=f"admin:announce:cancelbatch:{batch.id}")])
    rows.append([InlineKeyboardButton(text=t("btn_refresh"), callback_data="admin:announce_batches")])
    rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def pending_requests_keyboard(requests: list[AccessRequest], page: int = 0, has_next: bool = False, total_pages: int = 1) -> InlineKeyboardMarkup:
    """Build the paginated keyboard listing pending access requests."""
    rows: list[list[InlineKeyboardButton]] = []
    for request in requests:
        title = request.username or str(request.telegram_user_id)
        rows.append([InlineKeyboardButton(text=f"{title} · #{request.id}", callback_data=f"admin:req:{request.id}")])
        rows.append(
            [
                InlineKeyboardButton(text=t("btn_approve"), callback_data=f"admin:approve:{request.id}"),
                InlineKeyboardButton(text=t("btn_reject"), callback_data=f"admin:reject:{request.id}"),
            ]
        )
    if page > 0 or has_next:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=f"admin:reqs:{page - 1}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1} / {total_pages}", callback_data="noop"))
        if has_next:
            nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=f"admin:reqs:{page + 1}"))
        rows.append(nav)
    rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def users_keyboard(
    users: list[User],
    page: int = 0,
    has_next: bool = False,
    prefix: str = "admin:user",
    nav_prefix: str = "admin:users",
    total_pages: int = 1,
) -> InlineKeyboardMarkup:
    """Build the paginated keyboard listing users."""
    rows: list[list[InlineKeyboardButton]] = []
    for user in users:
        title = format_user_display(user.telegram_user_id, user.username)
        rows.append(
            [
                InlineKeyboardButton(
                    text=title,
                    callback_data=f"{prefix}:{user.telegram_user_id}",
                )
            ]
        )
    if page > 0 or has_next:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=f"{nav_prefix}:{page - 1}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1} / {total_pages}", callback_data="noop"))
        if has_next:
            nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=f"{nav_prefix}:{page + 1}"))
        rows.append(nav)
    rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def user_actions_keyboard(
    user: User,
    *,
    has_used_trial: bool = False,
    actor_role: UserRole = UserRole.SUPERADMIN,
) -> InlineKeyboardMarkup:
    """Build the user management actions keyboard scoped to the actor's role."""
    rows: list[list[InlineKeyboardButton]] = []
    blocked = is_blocked_user(user)
    is_moderator_actor = actor_role == UserRole.MODERATOR

    if not is_moderator_actor and user.role not in {UserRole.APPROVED_USER, UserRole.MODERATOR} and not blocked:
        rows.append([InlineKeyboardButton(text=t("btn_approve_user"), callback_data=f"admin:userapprove:{user.telegram_user_id}")])
    if not blocked:
        rows.append([InlineKeyboardButton(text=t("btn_block"), callback_data=f"admin:block:{user.telegram_user_id}")])
    if blocked:
        rows.append([InlineKeyboardButton(text=t("btn_unblock"), callback_data=f"admin:unblock:{user.telegram_user_id}")])
    if not is_moderator_actor:
        if user.role in {UserRole.APPROVED_USER, UserRole.MODERATOR, UserRole.SUPERADMIN, UserRole.PENDING_USER} and not blocked:
            rows.append([InlineKeyboardButton(text=t("btn_issue_key"), callback_data=f"admin:issue:{user.telegram_user_id}")])
        if has_used_trial:
            rows.append([InlineKeyboardButton(text=t("btn_reset_trial"), callback_data=f"admin:trial:reset:{user.telegram_user_id}")])
        rows.append([InlineKeyboardButton(text=t("btn_user_keys"), callback_data=f"admin:ukeys:{user.telegram_user_id}:0")])
        rows.append([InlineKeyboardButton(text=t("btn_edit_note_user"), callback_data=f"admin:unote:{user.telegram_user_id}")])
    if not is_moderator_actor and not blocked and user.role == UserRole.APPROVED_USER:
        rows.append([InlineKeyboardButton(text=t("btn_set_moderator"), callback_data=f"admin:setmoderator:{user.telegram_user_id}")])
    if not is_moderator_actor and user.role == UserRole.MODERATOR:
        rows.append([InlineKeyboardButton(text=t("btn_remove_moderator"), callback_data=f"admin:setmoderator:{user.telegram_user_id}")])
    rows.append([InlineKeyboardButton(text=t("btn_to_users"), callback_data="admin:users")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def block_user_confirm_keyboard(user: User) -> InlineKeyboardMarkup:
    """Build the confirm/cancel keyboard for blocking a user."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_block_confirm"), callback_data=f"admin:block:confirm:{user.telegram_user_id}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"admin:user:{user.telegram_user_id}")],
        ]
    )


def unblock_user_confirm_keyboard(user: User) -> InlineKeyboardMarkup:
    """Build the confirm/cancel keyboard for unblocking a user."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_unblock_confirm"), callback_data=f"admin:unblock:confirm:{user.telegram_user_id}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"admin:user:{user.telegram_user_id}")],
        ]
    )


def admin_key_type_keyboard(
    user_id: int,
    *,
    xray_enabled: bool = True,
    awg_enabled: bool = True,
) -> InlineKeyboardMarkup:
    """Build the key type selection keyboard for issuing a key to a user."""
    rows: list[list[InlineKeyboardButton]] = []
    if xray_enabled:
        rows.append([InlineKeyboardButton(text="Xray(VLESS+XReality)", callback_data=f"admin:ctype:xray:{user_id}")])
    if awg_enabled:
        rows.append([InlineKeyboardButton(text="AmneziaWG 2.0", callback_data=f"admin:ctype:awg:{user_id}")])
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def trial_request_keyboard(request_id: int) -> InlineKeyboardMarkup:
    """Build the approve/reject keyboard for a trial access request."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text=t("btn_approve"), callback_data=f"admin:trial:approve:{request_id}"),
                InlineKeyboardButton(text=t("btn_reject"), callback_data=f"admin:trial:reject:{request_id}"),
            ]
        ]
    )


def admin_issue_users_keyboard(users: list[User], page: int = 0, has_next: bool = False, total_pages: int = 1) -> InlineKeyboardMarkup:
    """Build the paginated keyboard for selecting a user to issue a key to."""
    rows: list[list[InlineKeyboardButton]] = []
    for user in users:
        title = format_user_display(user.telegram_user_id, user.username)
        rows.append([InlineKeyboardButton(text=title, callback_data=f"admin:issue:{user.telegram_user_id}")])
    if page > 0 or has_next:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton(text=t("btn_prev"), callback_data=f"admin:issuepage:{page - 1}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1} / {total_pages}", callback_data="noop"))
        if has_next:
            nav.append(InlineKeyboardButton(text=t("btn_next"), callback_data=f"admin:issuepage:{page + 1}"))
        rows.append(nav)
    rows.append([InlineKeyboardButton(text=t("btn_admin_panel"), callback_data="admin:panel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
