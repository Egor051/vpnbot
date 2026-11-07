
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from i18n import t
from repositories.protocol_modules import PROTOCOL_DISPLAY, PROTOCOL_NAMES, ProtocolModule


def modules_panel_keyboard(
    modules: list[ProtocolModule],
    uninstalled: frozenset[str] = frozenset(),
    env_off: frozenset[str] = frozenset(),
) -> InlineKeyboardMarkup:
    """One row per protocol: its state and the action it allows.

    ✅ enabled → «Disable» · ❌ disabled → «Enable», plus a row «🗑 Remove from the
    server» (a module switched off earlier may still have everything on the host) ·
    🗑 removed from the server → «🔒 Enable», which only explains that it needs a
    reinstall · ⛔ switched off in ``.env`` (``env_off``) → an info button «.env», which says
    which flag, instead of «Enable» (disabling and removal stay offered). A protocol is offered only when ``.env`` AND the toggle allow it
    (services/protocol_availability.py); the panel used to show «✅ Выключить» for
    a protocol ``.env`` had switched off, i.e. claim it was on.
    """
    rows: list[list[InlineKeyboardButton]] = []
    by_name = {m.name: m for m in modules}
    for name in PROTOCOL_NAMES:
        module = by_name.get(name)
        enabled = module.enabled if module else True
        label = PROTOCOL_DISPLAY.get(name, name)
        if name in env_off and name not in uninstalled:
            # Off in .env: the toggle cannot turn it on, so «Enable» gives way to
            # the .env note. Switching the module off and removing the protocol
            # from the server stay available — the host may still carry it.
            row = [
                InlineKeyboardButton(text=f"⛔ {label}", callback_data="noop"),
                InlineKeyboardButton(text=t("btn_module_env_off"), callback_data=f"admin:module:envoff:{name}"),
            ]
            if enabled:
                row.append(InlineKeyboardButton(text=t("btn_module_disable"), callback_data=f"admin:module:disable:{name}"))
            rows.append(row)
            if not enabled:
                rows.append([
                    InlineKeyboardButton(
                        text=t("btn_module_uninstall", label=label), callback_data=f"admin:module:uninst:{name}"
                    )
                ])
            continue
        if name in uninstalled:
            rows.append([
                InlineKeyboardButton(text=f"🗑 {label}", callback_data="noop"),
                InlineKeyboardButton(text=t("btn_module_enable_locked"), callback_data=f"admin:module:enable:{name}"),
            ])
            continue
        icon = "✅" if enabled else "❌"
        action = "disable" if enabled else "enable"
        action_label = t("btn_module_disable") if enabled else t("btn_module_enable")
        rows.append([
            InlineKeyboardButton(text=f"{icon} {label}", callback_data="noop"),
            InlineKeyboardButton(text=action_label, callback_data=f"admin:module:{action}:{name}"),
        ])
        if not enabled:
            rows.append([
                InlineKeyboardButton(
                    text=t("btn_module_uninstall", label=label), callback_data=f"admin:module:uninst:{name}"
                )
            ])
    rows.append([InlineKeyboardButton(text=t("btn_back"), callback_data="admin:grp:infra")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def module_disable_confirm1_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_module_disable_only"), callback_data=f"admin:module:disable:{name}:2")],
            [InlineKeyboardButton(text=t("btn_module_disable_uninstall"), callback_data=f"admin:module:uninst:{name}")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:modules")],
        ]
    )


def module_disable_confirm2_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_module_disable_step2"), callback_data=f"admin:module:disable:{name}:exec")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:modules")],
        ]
    )


def module_enable_confirm_keyboard(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=t("btn_module_enable_confirm"), callback_data=f"admin:module:enable:{name}:exec")],
            [InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:modules")],
        ]
    )


def module_uninstall_plan_keyboard(name: str, sha_prefix: str | None) -> InlineKeyboardMarkup:
    """Under a plan: confirm it (only when it can be applied), re-plan, or leave.

    The confirm button carries the first characters of the plan's sha256, so a
    button under an OLD plan message can never apply a newer, unseen plan.
    """
    rows: list[list[InlineKeyboardButton]] = []
    if sha_prefix:
        rows.append([
            InlineKeyboardButton(
                text=t("btn_module_uninstall_confirm"), callback_data=f"admin:module:uninst:{name}:x:{sha_prefix}"
            )
        ])
    rows.append([InlineKeyboardButton(text=t("btn_module_uninstall_refresh"), callback_data=f"admin:module:uninst:{name}")])
    rows.append([InlineKeyboardButton(text=t("btn_cancel"), callback_data="admin:modules")])
    return InlineKeyboardMarkup(inline_keyboard=rows)
