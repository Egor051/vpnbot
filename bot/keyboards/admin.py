
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from models.access import is_blocked_user
from models.dto import AccessRequest, Relay, User
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


def access_request_detail_keyboard(request: AccessRequest | None) -> InlineKeyboardMarkup:
    """One request's screen, and the screen after a decision.

    A pending request gets approve/reject; every variant leads back to the list
    (the «to requests» button) — the detail used to reuse the list keyboard, whose only way
    out was the admin panel, so a moderator had no way back at all.
    """
    rows: list[list[InlineKeyboardButton]] = []
    if request is not None:
        rows.append(
            [
                InlineKeyboardButton(text=t("btn_approve"), callback_data=f"admin:approve:{request.id}"),
                InlineKeyboardButton(text=t("btn_reject"), callback_data=f"admin:reject:{request.id}"),
            ]
        )
    rows.append([InlineKeyboardButton(text=t("btn_to_requests"), callback_data="admin:reqs")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def moderator_panel_keyboard() -> InlineKeyboardMarkup:
    """Build the moderator panel inline keyboard."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_access_requests"), callback_data="admin:reqs")],
            [InlineKeyboardButton(text=t("btn_users"), callback_data="admin:users")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )


# The groups of the admin panel. Every leaf screen keeps its old callback, so a
# keyboard still sitting in a chat's history opens the same screen as before;
# only the panel itself gained this one level. ``people`` is also the moderator's
# section — its handler renders the moderator panel for a moderator.
ADMIN_GROUPS: tuple[str, ...] = ("people", "mon", "comms", "infra", "ops")


def admin_group_keyboard(group: str, *, subscription_enabled: bool = False) -> InlineKeyboardMarkup:
    """One section of the admin panel (``admin:grp:<group>``)."""
    def row(key: str, data: str) -> list[InlineKeyboardButton]:
        return [InlineKeyboardButton(text=t(key), callback_data=data)]

    rows: list[list[InlineKeyboardButton]]
    if group == "people":
        rows = [
            row("btn_access_requests", "admin:reqs"),
            row("btn_trial_accesses", "admin:trial"),
            row("btn_users", "admin:users"),
        ]
    elif group == "mon":
        rows = [
            row("btn_dashboard", "admin:dashboard"),
            row("btn_server_status", "admin:server_status"),
            row("btn_key_stats", "admin:stats"),
            row("btn_proxy_status", "admin:proxy"),
            row("btn_backend_diagnostics", "admin:diagnostics"),
            row("btn_action_logs", "admin:audit"),
        ]
    elif group == "comms":
        rows = [
            row("btn_announcement", "admin:announce"),
            row("btn_announcement_recovery", "admin:announce_batches"),
        ]
    elif group == "infra":
        rows = [
            row("btn_modules", "admin:modules"),
            row("btn_relays", "admin:relays"),
            *([row("btn_admin_bundles", "admin:aio")] if subscription_enabled else []),
            row("btn_warp", "admin:warp"),
        ]
    elif group == "ops":
        rows = [
            row("btn_maintenance", "admin:maintenance"),
            row("btn_db_backup", "admin:backup"),
        ]
    else:
        rows = []
    rows.append(row("btn_admin_panel", "admin:panel"))
    return InlineKeyboardMarkup(inline_keyboard=rows)


def dashboard_keyboard() -> InlineKeyboardMarkup:
    """The dashboard: refresh, a way into the screens its figures summarise, back.

    The dashboard repeats the counters of other screens (requests, trials,
    diagnostics, the audit log); it used to offer no way to act on them.
    """
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_dashboard_refresh"), callback_data="admin:dashboard:refresh")],
            [
                InlineKeyboardButton(text=t("btn_access_requests"), callback_data="admin:reqs"),
                InlineKeyboardButton(text=t("btn_trial_accesses"), callback_data="admin:trial"),
            ],
            [
                InlineKeyboardButton(text=t("btn_backend_diagnostics"), callback_data="admin:diagnostics"),
                InlineKeyboardButton(text=t("btn_action_logs"), callback_data="admin:audit"),
            ],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:mon")],
        ]
    )


def server_status_keyboard(detailed_enabled: bool = False) -> InlineKeyboardMarkup:
    """Build the inline keyboard for the server status panel.

    A toggle row controls the detailed-metrics mode (load average, uptime,
    network smoothing); its label reflects the current state. No manual refresh
    button is needed because the panel auto-refreshes.
    """
    toggle_text = t("btn_server_status_detailed_on" if detailed_enabled else "btn_server_status_detailed_off")
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=toggle_text, callback_data="admin:server_status:toggle_detailed")],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:mon")],
        ]
    )


def maintenance_panel_keyboard(enabled: bool) -> InlineKeyboardMarkup:
    """Build the maintenance panel: an enable/disable toggle plus a back button."""
    if enabled:
        toggle = InlineKeyboardButton(text=t("btn_maintenance_disable"), callback_data="admin:maintenance:disable")
    else:
        toggle = InlineKeyboardButton(text=t("btn_maintenance_enable"), callback_data="admin:maintenance:enable")
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [toggle],
            [InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:ops")],
        ]
    )


def maintenance_disable_confirm_keyboard() -> InlineKeyboardMarkup:
    """Ending maintenance messages every user, so it is one more tap, not one."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_maintenance_disable_confirm"), callback_data="admin:maintenance:disable:ok")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:maintenance")],
        ]
    )


def backup_confirm_keyboard() -> InlineKeyboardMarkup:
    """The backup sends the database to every admin: confirm first."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_backup_confirm"), callback_data="admin:backup:ok")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:grp:ops")],
        ]
    )


def maintenance_enable_skip_keyboard() -> InlineKeyboardMarkup:
    """Keyboard shown while asking for the banner text: skip (use default) or cancel."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_maintenance_skip_text"), callback_data="admin:maintenance:enable:default")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:maintenance")],
        ]
    )


def admin_panel_keyboard(
    *,
    subscription_enabled: bool = False,
    pending_requests: int = 0,
    pending_trials: int = 0,
) -> InlineKeyboardMarkup:
    """The admin panel: five sections, plus a shortcut row while there is a queue.

    The panel used to be eighteen buttons in one column with no order — monitoring,
    people, broadcasts and infrastructure interleaved. Each section now holds at
    most six screens (:func:`admin_group_keyboard`); every screen kept its old
    callback. The shortcut row points at the same handlers as the «Люди» section,
    so the most frequent action (answer a request) stays one tap away.

    ``subscription_enabled`` is accepted for the callers that pass it; the
    «All-in-One» row lives in the «Протоколы» section now.
    """
    del subscription_enabled
    rows: list[list[InlineKeyboardButton]] = []
    shortcuts: list[InlineKeyboardButton] = []
    if pending_requests > 0:
        shortcuts.append(InlineKeyboardButton(text=t("btn_pending_requests", count=pending_requests), callback_data="admin:reqs"))
    if pending_trials > 0:
        shortcuts.append(InlineKeyboardButton(text=t("btn_pending_trials", count=pending_trials), callback_data="admin:trial"))
    if shortcuts:
        rows.append(shortcuts)
    rows.extend(
        [
            [InlineKeyboardButton(text=t("btn_group_people"), callback_data="admin:grp:people")],
            [InlineKeyboardButton(text=t("btn_group_mon"), callback_data="admin:grp:mon")],
            [InlineKeyboardButton(text=t("btn_group_comms"), callback_data="admin:grp:comms")],
            [InlineKeyboardButton(text=t("btn_group_infra"), callback_data="admin:grp:infra")],
            [InlineKeyboardButton(text=t("btn_group_ops"), callback_data="admin:grp:ops")],
            [InlineKeyboardButton(text=t("btn_back_to_menu"), callback_data="menu:main")],
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def announcement_confirm_keyboard() -> InlineKeyboardMarkup:
    """Build the send/schedule/cancel keyboard for an announcement."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_send_now"), callback_data="admin:announce:send")],
            [InlineKeyboardButton(text=t("btn_schedule"), callback_data="admin:announce:schedule")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:announce:cancel")],
        ]
    )


# Segmentation options for targeted announcements. Roles carry an i18n label key
# (translated at render time); protocols/transports use universal literal labels.
ANNOUNCEMENT_ROLE_OPTIONS: tuple[tuple[str, str], ...] = (
    (UserRole.APPROVED_USER.value, "seg_role_approved"),
    (UserRole.MODERATOR.value, "seg_role_moderator"),
    (UserRole.PENDING_USER.value, "seg_role_pending"),
    (UserRole.SUPERADMIN.value, "seg_role_superadmin"),
)
ANNOUNCEMENT_PROTOCOL_OPTIONS: tuple[tuple[str, str], ...] = (
    ("xray", "VLESS"),
    ("awg", "AmneziaWG"),
    ("hysteria2", "Hysteria2"),
    ("socks5", "SOCKS5"),
    ("mtproto", "MTProto"),
)
ANNOUNCEMENT_TRANSPORT_OPTIONS: tuple[tuple[str, str], ...] = (
    ("tcp", "TCP"),
    ("http", "HTTP"),
)


def _segment_option_button(label: str, selected: bool, callback_data: str) -> InlineKeyboardButton:
    """Build a toggle button prefixed with a checkbox reflecting its selected state."""
    mark = "✅" if selected else "▫️"
    return InlineKeyboardButton(text=f"{mark} {label}", callback_data=callback_data)


def announcement_roles_keyboard(selected: set[str]) -> InlineKeyboardMarkup:
    """Build the role-selection (stage 1) keyboard for a segmented announcement."""
    rows: list[list[InlineKeyboardButton]] = [
        [_segment_option_button(t(label_key), value in selected, f"admin:announce:role:{value}")]
        for value, label_key in ANNOUNCEMENT_ROLE_OPTIONS
    ]
    rows.append([InlineKeyboardButton(text=t("btn_seg_all"), callback_data="admin:announce:role:all")])
    if selected:
        rows.append([InlineKeyboardButton(text=t("btn_seg_next"), callback_data="admin:announce:roles:done")])
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:announce:cancel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def announcement_protocols_keyboard(
    selected: set[str], *, unavailable: frozenset[str] = frozenset()
) -> InlineKeyboardMarkup:
    """Build the protocol-selection (stage 2) keyboard for a segmented announcement.

    A protocol that is switched off right now stays selectable — its users may
    still hold keys and be the very audience of the message — but carries a
    «выкл.» mark, so the choice is not made blind.
    """
    rows: list[list[InlineKeyboardButton]] = [
        [
            _segment_option_button(
                f"{label} · {t('seg_protocol_off')}" if value in unavailable else label,
                value in selected,
                f"admin:announce:proto:{value}",
            )
        ]
        for value, label in ANNOUNCEMENT_PROTOCOL_OPTIONS
    ]
    rows.append([InlineKeyboardButton(text=t("btn_seg_all"), callback_data="admin:announce:proto:all")])
    if selected:
        rows.append([InlineKeyboardButton(text=t("btn_seg_next"), callback_data="admin:announce:protos:done")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:announce:back:roles")])
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:announce:cancel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def announcement_transports_keyboard(selected: set[str]) -> InlineKeyboardMarkup:
    """Build the VLESS transport-selection (stage 3) keyboard for a segmented announcement."""
    rows: list[list[InlineKeyboardButton]] = [
        [_segment_option_button(label, value in selected, f"admin:announce:tr:{value}")]
        for value, label in ANNOUNCEMENT_TRANSPORT_OPTIONS
    ]
    rows.append([InlineKeyboardButton(text=t("btn_seg_all"), callback_data="admin:announce:tr:all")])
    if selected:
        rows.append([InlineKeyboardButton(text=t("btn_seg_next"), callback_data="admin:announce:trs:done")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:announce:back:protos")])
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:announce:cancel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def announcement_cancel_keyboard() -> InlineKeyboardMarkup:
    """Single «Отмена» for the text-input steps of the announcement wizard.

    Every step of that wizard cancels through ``admin:announce:cancel`` now; the
    choice steps used the generic ``cancel`` and the confirm step this callback,
    two mechanisms for one action.
    """
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:announce:cancel")]]
    )


def announcement_batches_keyboard(batches: list[AnnouncementBatch]) -> InlineKeyboardMarkup:
    """Build the keyboard listing announcement batches with status-based actions.

    One row per batch (its action next to its cancel) instead of two, so ten
    batches fit in twelve rows. Each button opens a confirmation
    (:func:`announcement_batch_confirm_keyboard`): every action here sends a
    broadcast or stops one.
    """
    rows: list[list[InlineKeyboardButton]] = []
    for batch in batches:
        row: list[InlineKeyboardButton] = []
        if batch.status == "scheduled":
            row.append(InlineKeyboardButton(text=f"{t('btn_send_now')} #{batch.id}", callback_data=f"admin:announce:resume:{batch.id}"))
        if batch.status in {"pending", "sending"}:
            row.append(InlineKeyboardButton(text=t("btn_batch_continue", id=batch.id), callback_data=f"admin:announce:resume:{batch.id}"))
        if batch.status == "failed":
            row.append(InlineKeyboardButton(text=t("btn_batch_retry", id=batch.id), callback_data=f"admin:announce:retry:{batch.id}"))
        row.append(InlineKeyboardButton(text=t("btn_batch_cancel", id=batch.id), callback_data=f"admin:announce:cancelbatch:{batch.id}"))
        rows.append(row)
    rows.append([InlineKeyboardButton(text=t("btn_refresh"), callback_data="admin:announce_batches")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:comms")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def announcement_batch_confirm_keyboard(action: str, batch_id: int) -> InlineKeyboardMarkup:
    """Confirm a batch action (``admin:announce:<action>:<id>:ok``)."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=f"admin:announce:{action}:{batch_id}:ok")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:announce_batches")],
        ]
    )


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
    # admin:grp:people is role-aware: a moderator lands on their own panel.
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:people")])
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
    rows.append([InlineKeyboardButton(text=t("btn_user_search"), callback_data="admin:users:find")])
    # admin:grp:people is role-aware: a moderator lands on their own panel.
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:people")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def user_search_keyboard() -> InlineKeyboardMarkup:
    """While waiting for the search query: back to the list."""
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:users")]]
    )


def user_actions_keyboard(
    user: User,
    *,
    has_used_trial: bool = False,
    actor_role: UserRole = UserRole.MODERATOR,
    actor_user_id: int | None = None,
) -> InlineKeyboardMarkup:
    """Build the user management actions keyboard for this actor and this target.

    The ``actor_role`` default is intentionally the least-privileged role that
    still has a user card (MODERATOR): if a caller forgets to pass the real
    actor role, the keyboard fails closed and hides superadmin-only actions
    instead of exposing them.

    Only actions the service would carry out are shown. The card used to offer
    «Одобрить» and «Заблокировать» on a superadmin, and «Заблокировать» to a
    moderator on another moderator — buttons whose only outcome, after a
    confirmation screen, was a refusal (services/users.py: set_role, block_user).
    """
    rows: list[list[InlineKeyboardButton]] = []
    uid = user.telegram_user_id
    blocked = is_blocked_user(user)
    is_moderator_actor = actor_role == UserRole.MODERATOR
    is_self = actor_user_id is not None and actor_user_id == uid
    target_is_staff = user.role in {UserRole.SUPERADMIN, UserRole.MODERATOR}

    if not is_moderator_actor and user.role == UserRole.PENDING_USER and not blocked:
        rows.append([InlineKeyboardButton(text=t("btn_approve_user"), callback_data=f"admin:userapprove:{uid}")])
    can_block = not blocked and not is_self and user.role != UserRole.SUPERADMIN
    if is_moderator_actor and target_is_staff:
        can_block = False
    if can_block:
        rows.append([InlineKeyboardButton(text=t("btn_block"), callback_data=f"admin:block:{uid}")])
    if blocked:
        rows.append([InlineKeyboardButton(text=t("btn_unblock"), callback_data=f"admin:unblock:{uid}")])
    if not is_moderator_actor:
        if user.role in {UserRole.APPROVED_USER, UserRole.MODERATOR, UserRole.SUPERADMIN, UserRole.PENDING_USER} and not blocked:
            rows.append([InlineKeyboardButton(text=t("btn_issue_key"), callback_data=f"admin:issue:{uid}")])
        if has_used_trial:
            rows.append([InlineKeyboardButton(text=t("btn_reset_trial"), callback_data=f"admin:trial:reset:{uid}")])
        rows.append([InlineKeyboardButton(text=t("btn_user_keys"), callback_data=f"admin:ukeys:{uid}:0")])
        rows.append([InlineKeyboardButton(text=t("btn_edit_note_user"), callback_data=f"admin:unote:{uid}")])
        if not blocked and user.role == UserRole.APPROVED_USER:
            rows.append([InlineKeyboardButton(text=t("btn_set_moderator"), callback_data=f"admin:setmoderator:{uid}")])
        if user.role == UserRole.MODERATOR:
            rows.append([InlineKeyboardButton(text=t("btn_remove_moderator"), callback_data=f"admin:setmoderator:{uid}")])
    rows.append([InlineKeyboardButton(text=t("btn_to_users"), callback_data="admin:users")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def user_action_confirm_keyboard(confirm_data: str, user_id: int) -> InlineKeyboardMarkup:
    """Confirm a role change or a trial reset; «Отмена» returns to the card."""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_confirm"), callback_data=confirm_data)],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data=f"admin:user:{user_id}")],
        ]
    )


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
    xhttp_enabled: bool = False,
    hysteria2_enabled: bool = False,
) -> InlineKeyboardMarkup:
    """Build the protocol selection keyboard for issuing a key to a user (step 1).

    With XHTTP disabled the VLESS button goes straight to TCP key creation,
    skipping the redundant single-option transport step; the transport step is
    offered only when XHTTP is enabled.
    """
    rows: list[list[InlineKeyboardButton]] = []
    if xray_enabled:
        vless_data = f"admin:proto:vless:{user_id}" if xhttp_enabled else f"admin:ctype:xray:{user_id}"
        rows.append([InlineKeyboardButton(text="VLESS", callback_data=vless_data)])
    if awg_enabled:
        rows.append([InlineKeyboardButton(text="AmneziaWG 2.0", callback_data=f"admin:ctype:awg:{user_id}")])
    if hysteria2_enabled:
        rows.append([InlineKeyboardButton(text="Hysteria2", callback_data=f"admin:ctype:hy2:{user_id}")])
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="cancel")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def admin_vless_transport_keyboard(user_id: int, *, xhttp_enabled: bool = False) -> InlineKeyboardMarkup:
    """Build the VLESS transport selection keyboard for issuing a key (step 2)."""
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text=t("btn_vless_tcp"), callback_data=f"admin:ctype:xray:{user_id}")],
    ]
    if xhttp_enabled:
        rows.append([InlineKeyboardButton(text=t("btn_vless_http"), callback_data=f"admin:ctype:xhttp:{user_id}")])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data=f"admin:issue:{user_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def admin_xhttp_profile_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Build the XHTTP transport-profile selection keyboard for issuing a key (step 3)."""
    rows: list[list[InlineKeyboardButton]] = [
        [InlineKeyboardButton(text=t("xhttp_profile_base_name"), callback_data=f"admin:cxprof:base:{user_id}")],
        [InlineKeyboardButton(text=t("xhttp_profile_multi_name"), callback_data=f"admin:cxprof:multi:{user_id}")],
        [InlineKeyboardButton(text=t("xhttp_profile_antisib_name"), callback_data=f"admin:cxprof:antisib:{user_id}")],
        [InlineKeyboardButton(text=t("btn_back"), callback_data=f"admin:proto:vless:{user_id}")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def admin_relay_route_keyboard(user_id: int, relays: list[Relay]) -> InlineKeyboardMarkup:
    """The «Подключение» step of issuing a key: direct plus one button per enabled relay.

    ``admin:croute:direct:<user>`` / ``admin:croute:<relay id>:<user>``.
    """
    rows = [[InlineKeyboardButton(text=t("btn_route_direct"), callback_data=f"admin:croute:direct:{user_id}")]]
    rows.extend(
        [
            InlineKeyboardButton(
                text=t("btn_route_via", label=relay.label), callback_data=f"admin:croute:{relay.id}:{user_id}"
            )
        ]
        for relay in relays
    )
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
