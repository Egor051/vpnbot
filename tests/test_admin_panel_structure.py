"""Structural guarantees of the admin panel.

These pin properties of the panel as a whole rather than of one screen:

* every button of every admin keyboard reaches a real handler (not the
  stale-callback catch-all) in the FSM state the keyboard is shown in — resolved
  through the routers' own aiogram filters, in the include order of ``bot/app.py``;
* every admin handler checks the actor's role itself;
* «Назад»/«Отмена» of each screen leads to its parent;
* no handler reacts to the label of a reply keyboard the bot never sends;
* the admin screens rendered in English contain no Cyrillic.

The audit that introduced them found a «Назад» that led nowhere (the XHTTP
profile step of «Выдать ключ»), lists whose only exit refused a moderator, and
screens hard-coded in Russian — each of which one of these tests now catches.
"""
from __future__ import annotations

import ast
import asyncio
import re
from collections.abc import Callable, Iterator
from ipaddress import IPv4Network
from pathlib import Path

import pytest
from aiogram.types import CallbackQuery, InlineKeyboardMarkup
from aiogram.types import User as TgUser

from bot.fsm.states import (
    AdminAnnouncementStates,
    AdminCreateKeyStates,
    AdminRelayStates,
    AdminUserSearchStates,
    MaintenanceStates,
    WarpConfigStates,
    WarpSplitStates,
)
from bot.handlers import (
    admin,
    admin_bundles,
    admin_dashboard,
    admin_maintenance,
    admin_modules,
    admin_relays,
    admin_warp,
    admin_warp_split,
    admin_warp_split_sources,
    admin_warp_split_ui,
    admin_wizard,
    callbacks,
    common,
    key_bundles,
    keys,
    proxy,
    security,
    ssh_port,
    start,
    ufw,
)
from bot.handlers import settings as settings_handler
from bot.keyboards import admin as kb
from bot.keyboards import admin_bundles as kb_aio
from bot.keyboards import admin_modules as kb_mod
from bot.keyboards import admin_relays as kb_rel
from bot.keyboards import common as kb_common
from bot.keyboards import keys as kb_keys
from bot.keyboards import warp_keyboard as kb_warp
from bot.keyboards import warp_split_keyboard as kb_split
from bot.keyboards import warp_split_sources_keyboard as kb_src
from bot import totp_gate, wizard_views as wv
from models.dto import WizardRun
from i18n import use_locale
from models.dto import AccessRequest, Relay, User, VpnKey
from models.enums import AccessRequestStatus, UserRole, VpnKeyStatus, VpnKeyType
from repositories.announcements import AnnouncementBatch
from repositories.protocol_modules import ProtocolModule
from services.relay_management import RelayOverview
from warp.feed_state import SplitSource
from warp.split_manager import SplitStatus
from warp.state import WarpState

REPO = Path(__file__).resolve().parent.parent

# Same order as bot/app.py (pinned by test_router_order_matches_app below).
ROUTERS = [
    start, security, common, settings_handler, admin, admin_dashboard, admin_warp, admin_warp_split, admin_warp_split_ui,
    admin_warp_split_sources, admin_modules, admin_relays, admin_maintenance, ssh_port, ufw, admin_wizard, admin_bundles,
    keys, key_bundles, proxy, callbacks,
]


def _resolve(data: str, state: str | None) -> str:
    """The first handler aiogram would run for *data* in FSM *state*."""
    cb = CallbackQuery(id="1", from_user=TgUser(id=1, is_bot=False, first_name="a"), chat_instance="x", data=data)

    async def run() -> str:
        for module in ROUTERS:
            for handler in module.router.callback_query.handlers:
                ok, _ = await handler.check(cb, raw_state=state, event_from_user=cb.from_user)
                if ok:
                    return f"{module.__name__.rsplit('.', 1)[-1]}.{handler.callback.__name__}"
        return "<none>"

    return asyncio.run(run())


# ── fixtures for rendering ─────────────────────────────────────────────────────

NOW = "2026-11-06T00:00:00+00:00"


def _user(role: UserRole, uid: int = 123, blocked: bool = False) -> User:
    return User(uid, "u", "U", UserRole.BLOCKED_USER if blocked else role, NOW, NOW, NOW if blocked else None)


def _request() -> AccessRequest:
    return AccessRequest(11, 123, "u", AccessRequestStatus.PENDING, NOW, None, None, None)


def _relay(enabled: bool = True) -> Relay:
    return Relay(7, "r1", "EU", "203.0.113.5", (IPv4Network("203.0.113.0/24"),), enabled, True, None, NOW, NOW, None, None)


def _batch(status: str, bid: int) -> AnnouncementBatch:
    return AnnouncementBatch(bid, 1, 1, 1, status, 10, 0, 0, 0, NOW, NOW, None)


def _key(owner: int = 123) -> VpnKey:
    fields = {name: None for name in VpnKey.__dataclass_fields__}
    fields.update(
        id=42, owner_user_id=owner, key_type=VpnKeyType.XRAY, status=VpnKeyStatus.ACTIVE, created_at=NOW, updated_at=NOW
    )
    return VpnKey(**fields)  # type: ignore[arg-type]


def _split(intended: str) -> SplitStatus:
    return SplitStatus(tunnel_up=True, intended_state=intended, n_list=2, n_table=2, in_sync=True)


def _source(enabled: bool) -> SplitSource:
    return SplitSource(1, "goog", "Google", "https://example.com/goog.json", "json", "add", None, enabled, True, 86400)


_S = AdminCreateKeyStates
_A = AdminAnnouncementStates

# (case name, keyboard factory, FSM state while the keyboard is on screen)
CASES: list[tuple[str, Callable[[], InlineKeyboardMarkup], str | None]] = [
    ("admin_panel", lambda: kb.admin_panel_keyboard(pending_requests=2, pending_trials=1), None),
    *[
        (f"group:{group}", lambda group=group: kb.admin_group_keyboard(group, subscription_enabled=True), None)
        for group in kb.ADMIN_GROUPS
    ],
    ("moderator_panel", kb.moderator_panel_keyboard, None),
    ("main_menu_admin", lambda: kb_common.main_menu(True), None),
    ("main_menu_moderator", lambda: kb_common.main_menu(is_moderator=True), None),
    ("dashboard", kb.dashboard_keyboard, None),
    ("server_status", lambda: kb.server_status_keyboard(True), None),
    ("maintenance_on", lambda: kb.maintenance_panel_keyboard(True), None),
    ("maintenance_off", lambda: kb.maintenance_panel_keyboard(False), None),
    ("maintenance_disable_confirm", kb.maintenance_disable_confirm_keyboard, None),
    ("maintenance_enable_skip", kb.maintenance_enable_skip_keyboard, MaintenanceStates.waiting_message.state),
    ("backup_confirm", kb.backup_confirm_keyboard, None),
    ("requests", lambda: kb.pending_requests_keyboard([_request()], page=1, has_next=True, total_pages=3), None),
    ("request_detail", lambda: kb.access_request_detail_keyboard(_request()), None),
    ("request_done", lambda: kb.access_request_detail_keyboard(None), None),
    ("request_notification", lambda: kb.access_request_keyboard(11), None),
    ("request_confirm", lambda: kb.access_request_decision_confirm_keyboard(11, "approve"), None),
    ("users", lambda: kb.users_keyboard([_user(UserRole.APPROVED_USER)], page=1, has_next=True, total_pages=3), None),
    ("user_search", kb.user_search_keyboard, AdminUserSearchStates.waiting_query.state),
    *[
        (
            f"user_card:{actor.value}->{target.value}{'(blocked)' if blocked else ''}",
            lambda actor=actor, target=target, blocked=blocked: kb.user_actions_keyboard(
                _user(target, blocked=blocked), has_used_trial=True, actor_role=actor, actor_user_id=1
            ),
            None,
        )
        for actor in (UserRole.SUPERADMIN, UserRole.MODERATOR)
        for target in (UserRole.PENDING_USER, UserRole.APPROVED_USER, UserRole.MODERATOR, UserRole.SUPERADMIN)
        for blocked in (False, True)
    ],
    ("user_action_confirm", lambda: kb.user_action_confirm_keyboard("admin:setmoderator:123:ok", 123), None),
    ("block_confirm", lambda: kb.block_user_confirm_keyboard(_user(UserRole.APPROVED_USER)), None),
    ("unblock_confirm", lambda: kb.unblock_user_confirm_keyboard(_user(UserRole.APPROVED_USER)), None),
    ("user_keys", lambda: kb_keys.keys_list_keyboard([_key()], page=1, has_next=True, owner_user_id=123, total_pages=3, back_data="admin:user:123"), None),
    ("user_key_card", lambda: kb_keys.key_actions_keyboard(_key(), owner_user_id=123, page=1), None),
    ("user_key_confirm", lambda: kb_keys.confirm_keyboard("revoke", 42, owner_user_id=123, page=1), None),
    ("issue_type", lambda: kb.admin_key_type_keyboard(123, xhttp_enabled=True, hysteria2_enabled=True), _S.choosing_type.state),
    ("issue_type_no_xhttp", lambda: kb.admin_key_type_keyboard(123), _S.choosing_type.state),
    ("issue_transport", lambda: kb.admin_vless_transport_keyboard(123, xhttp_enabled=True), _S.choosing_type.state),
    ("issue_xhttp_profile", lambda: kb.admin_xhttp_profile_keyboard(123), _S.waiting_xhttp_profile.state),
    ("issue_route", lambda: kb.admin_relay_route_keyboard(123, [_relay()]), _S.waiting_route.state),
    ("issue_fp", kb_keys.fp_choice_keyboard, _S.waiting_fp.state),
    ("issue_mtu", kb_keys.mtu_choice_keyboard, _S.waiting_mtu.state),
    ("issue_expiry", kb_keys.expiry_choice_keyboard, _S.waiting_expiry.state),
    ("trial_notification", lambda: kb.trial_request_keyboard(3), None),
    ("announce_roles", lambda: kb.announcement_roles_keyboard({"APPROVED_USER"}), _A.choosing_roles.state),
    ("announce_protocols", lambda: kb.announcement_protocols_keyboard({"xray"}, unavailable=frozenset({"awg"})), _A.choosing_protocols.state),
    ("announce_transports", lambda: kb.announcement_transports_keyboard({"tcp"}), _A.choosing_transports.state),
    ("announce_message", kb.announcement_cancel_keyboard, _A.waiting_message.state),
    ("announce_confirm", kb.announcement_confirm_keyboard, _A.confirming.state),
    ("announce_batches", lambda: kb.announcement_batches_keyboard([_batch("scheduled", 1), _batch("pending", 2), _batch("failed", 3)]), None),
    ("announce_batch_confirm", lambda: kb.announcement_batch_confirm_keyboard("resume", 1), None),
    ("warp_on", lambda: kb_warp.warp_main_keyboard(WarpState(enabled=True, routes_count=2), _split("on")), None),
    ("warp_off", lambda: kb_warp.warp_main_keyboard(WarpState(enabled=True, routes_count=2), _split("off")), None),
    ("warp_no_config", lambda: kb_warp.warp_main_keyboard(WarpState(routes_count=0), _split("on")), None),
    ("warp_settings", lambda: kb_warp.warp_settings_keyboard(WarpState(routes_count=2)), None),
    ("warp_upload", kb_warp.warp_upload_keyboard, WarpConfigStates.waiting_config.state),
    ("warp_replace", lambda: kb_warp.warp_upload_keyboard("admin:warp:settings"), WarpConfigStates.waiting_config.state),
    ("warp_delete_confirm", kb_warp.warp_delete_confirm_keyboard, None),
    *[
        (f"warp_confirm:{action}", lambda action=action: kb_warp.warp_action_confirm_keyboard(action), None)
        for action in ("disable", "restart", "killswitch:toggle")
    ],
    ("split_panel", lambda: kb_split.warp_split_panel_keyboard(["1.2.3.0/24", "5.6.7.0/24"], 0, {"5.6.7.0/24": ("goog",)}), None),
    ("split_add", kb_split.warp_split_add_keyboard, WarpSplitStates.waiting_cidrs.state),
    ("split_del_confirm", lambda: kb_split.warp_split_del_confirm_keyboard("1.2.3.0/24"), None),
    ("split_sources", lambda: kb_src.warp_split_sources_keyboard([_source(True), _source(False)], has_migratable=True), None),
    ("split_source_add", kb_src.warp_split_source_add_keyboard, WarpSplitStates.waiting_source.state),
    ("split_history", kb_src.warp_split_back_keyboard, None),
    ("split_confirm", lambda: kb_src.warp_split_confirm_keyboard("wsplit:srcapply"), None),
    ("split_pending", kb_src.warp_split_pending_keyboard, None),
    (
        "modules",
        lambda: kb_mod.modules_panel_keyboard(
            [ProtocolModule("xray", True), ProtocolModule("awg", False), ProtocolModule("hysteria2", True)],
            frozenset({"socks5"}),
            frozenset({"mtproto"}),
        ),
        None,
    ),
    ("module_disable_1", lambda: kb_mod.module_disable_confirm1_keyboard("xray"), None),
    ("module_disable_2", lambda: kb_mod.module_disable_confirm2_keyboard("xray"), None),
    ("module_enable", lambda: kb_mod.module_enable_confirm_keyboard("awg"), None),
    ("module_uninstall_plan", lambda: kb_mod.module_uninstall_plan_keyboard("xray", "0123456789ab"), None),
    ("relays", lambda: kb_rel.relays_list_keyboard([RelayOverview(_relay(), 3)]), None),
    ("relay_card", lambda: kb_rel.relay_card_keyboard(_relay(), suggest_source_ip="203.0.113.5"), None),
    ("relay_toggle_confirm", lambda: kb_rel.relay_toggle_confirm_keyboard(7, "enabled"), None),
    ("relay_delete_confirm", lambda: kb_rel.relay_delete_confirm_keyboard(7), None),
    ("relay_delete_impact", lambda: kb_rel.relay_delete_impact_keyboard(7), None),
    ("relay_edit", lambda: kb_rel.relay_cancel_keyboard("admin:relay:7"), AdminRelayStates.edit_host.state),
    ("relay_add_src", lambda: kb_rel.relay_source_step_keyboard("203.0.113.5"), AdminRelayStates.add_source_ips.state),
    ("relay_add_label", lambda: kb_rel.relay_label_step_keyboard(True), AdminRelayStates.add_label.state),
    ("relay_add_confirm", kb_rel.relay_add_confirm_keyboard, AdminRelayStates.add_confirm.state),
    ("aio_panel", kb_aio.admin_bundles_panel_keyboard, None),
    ("aio_confirm", lambda: kb_aio.admin_bundles_confirm_keyboard("basic"), None),
    ("aio_back", kb_aio.admin_bundles_back_keyboard, None),
    ("wizard_menu", lambda: wv.menu_keyboard(active=_wrun(), daily=True), None),
    ("wizard_menu_idle", lambda: wv.menu_keyboard(active=None, daily=False), None),
    ("wizard_progress", lambda: wv.progress_keyboard(_wrun()), None),
    ("wizard_plan", lambda: wv.plan_keyboard(_wrun()), None),
    ("wizard_final", lambda: wv.final_keyboard(_wrun(), artifact=True), None),
    ("wizard_history", lambda: wv.history_keyboard([_wrun()], 1, True), None),
    ("totp_gate_cancel", totp_gate.gate_cancel_keyboard, None),
    ("totp_gate_resume", lambda: totp_gate.resume_keyboard("admin:module:uninst:xray:x:0123456789ab"), None),
    ("totp_claim_offer", security.claim_offer_keyboard, None),
    ("totp_codes", security.codes_keyboard, None),
]


def _wrun() -> WizardRun:
    return WizardRun(
        id=7, mode="update", state="planned", phase="plan", current_step="plan", params={"force": "0"},
        started_by=1, origin="manual", chat_id=1, message_id=2, log_path="", summary="", plan_ready=True,
        active=True, created_at=NOW, updated_at=NOW, finished_at=None, reported_at=None,
    )


def _buttons(markup: InlineKeyboardMarkup) -> Iterator[tuple[str, str]]:
    for row in markup.inline_keyboard:
        for button in row:
            assert button.callback_data is not None
            yield button.text, button.callback_data


@pytest.mark.parametrize(("name", "factory", "state"), CASES, ids=[case[0] for case in CASES])
def test_every_admin_button_reaches_a_handler_in_its_state(
    name: str, factory: Callable[[], InlineKeyboardMarkup], state: str | None
) -> None:
    dead = [
        (text, data) for text, data in _buttons(factory()) if _resolve(data, state) == "callbacks.unknown_callback"
    ]
    assert dead == [], f"{name}: buttons that only hit the stale-callback catch-all: {dead}"


def test_xhttp_profile_back_reaches_the_vless_step() -> None:
    """The dead end the audit found: «Назад» on the XHTTP profile step."""
    assert _resolve("admin:proto:vless:123", _S.waiting_xhttp_profile.state) == "admin.admin_issue_proto_vless"


def test_router_order_matches_app() -> None:
    tree = ast.parse((REPO / "bot" / "app.py").read_text(encoding="utf-8"))
    calls = sorted(
        (node.lineno, node.args[0].value.id)  # type: ignore[attr-defined]
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "include_router"
    )
    names = ["settings" if name == "settings_handler" else name for _, name in calls]
    assert names == [module.__name__.rsplit(".", 1)[-1] for module in ROUTERS]


# ── «Назад» leads to the parent ────────────────────────────────────────────────

BACK_TEXT_KEYS = {"btn_back", "btn_admin_panel", "btn_to_users", "btn_relays_back", "btn_back_to_settings",
                  "btn_to_requests", "btn_to_list", "btn_back_to_user", "btn_aio_back"}

# (case, factory, the callback its «Назад» must carry)
PARENTS: list[tuple[str, Callable[[], InlineKeyboardMarkup], str]] = [
    *[(f"group:{group}", lambda group=group: kb.admin_group_keyboard(group), "admin:panel") for group in kb.ADMIN_GROUPS],
    ("requests", lambda: kb.pending_requests_keyboard([_request()]), "admin:grp:people"),
    ("request_detail", lambda: kb.access_request_detail_keyboard(_request()), "admin:reqs"),
    ("request_done", lambda: kb.access_request_detail_keyboard(None), "admin:reqs"),
    ("users", lambda: kb.users_keyboard([_user(UserRole.APPROVED_USER)]), "admin:grp:people"),
    ("user_card", lambda: kb.user_actions_keyboard(_user(UserRole.APPROVED_USER), actor_role=UserRole.SUPERADMIN), "admin:users"),
    ("user_keys", lambda: kb_keys.keys_list_keyboard([_key()], owner_user_id=123, back_data="admin:user:123"), "admin:user:123"),
    ("dashboard", kb.dashboard_keyboard, "admin:grp:mon"),
    ("server_status", kb.server_status_keyboard, "admin:grp:mon"),
    ("announce_batches", lambda: kb.announcement_batches_keyboard([]), "admin:grp:comms"),
    ("maintenance", lambda: kb.maintenance_panel_keyboard(False), "admin:grp:ops"),
    ("modules", lambda: kb_mod.modules_panel_keyboard([]), "admin:grp:infra"),
    ("relays", lambda: kb_rel.relays_list_keyboard([]), "admin:grp:infra"),
    ("relay_card", lambda: kb_rel.relay_card_keyboard(_relay()), "admin:relays"),
    ("aio_panel", kb_aio.admin_bundles_panel_keyboard, "admin:grp:infra"),
    ("warp", lambda: kb_warp.warp_main_keyboard(WarpState(routes_count=2), _split("on")), "admin:grp:infra"),
    ("warp_settings", lambda: kb_warp.warp_settings_keyboard(WarpState(routes_count=2)), "admin:warp"),
    ("warp_replace", lambda: kb_warp.warp_upload_keyboard("admin:warp:settings"), "admin:warp:settings"),
    ("split_panel", lambda: kb_split.warp_split_panel_keyboard([], 0), "admin:warp:settings"),
    ("split_sources", lambda: kb_src.warp_split_sources_keyboard([]), "wsplit:p:0"),
    ("issue_transport", lambda: kb.admin_vless_transport_keyboard(123), "admin:issue:123"),
    ("issue_xhttp_profile", lambda: kb.admin_xhttp_profile_keyboard(123), "admin:proto:vless:123"),
]


@pytest.mark.parametrize(("name", "factory", "parent"), PARENTS, ids=[case[0] for case in PARENTS])
def test_back_leads_to_the_parent(name: str, factory: Callable[[], InlineKeyboardMarkup], parent: str) -> None:
    from i18n import t

    labels = {t(key) for key in BACK_TEXT_KEYS}
    backs = [data for text, data in _buttons(factory()) if text in labels]
    assert backs, f"{name}: no back button"
    assert backs[-1] == parent, f"{name}: «Назад» leads to {backs[-1]}, not to {parent}"


# ── every admin handler checks the role ────────────────────────────────────────

ADMIN_MODULES = [admin, admin_dashboard, admin_warp, admin_warp_split, admin_warp_split_ui,
                 admin_warp_split_sources, admin_modules, admin_relays, admin_maintenance, admin_bundles]
GUARDS = {"require_superadmin", "require_moderator_or_admin"}
# Handlers that need no role: they only delete the alert message they sit under.
NO_ROLE_NEEDED = {"anomaly_alert_dismiss", "warp_alert_dismiss"}


def _calls_a_guard(fn: ast.AST, helpers: dict[str, ast.AST], depth: int = 0) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
        if name in GUARDS:
            return True
        if depth < 2 and isinstance(node.func, ast.Name) and name in helpers and _calls_a_guard(helpers[name], helpers, depth + 1):
            return True
    return False


def _handlers(module: object) -> Iterator[ast.AsyncFunctionDef]:
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    for node in tree.body:
        if isinstance(node, ast.AsyncFunctionDef) and any(
            isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and getattr(dec.func.value, "id", "") == "router"
            for dec in node.decorator_list
        ):
            yield node


def test_every_admin_handler_checks_the_role() -> None:
    missing = []
    for module in ADMIN_MODULES:
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))  # type: ignore[arg-type]
        helpers = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for handler in _handlers(module):
            if handler.name in NO_ROLE_NEEDED:
                continue
            if not _calls_a_guard(handler, helpers):
                missing.append(f"{module.__name__}.{handler.name}")
    assert missing == []


def test_no_handler_reacts_to_a_reply_keyboard_label() -> None:
    """The bot sends no reply keyboard; a text trigger on a button label is dead code
    that reacts to whoever types the label («Панель модератора:»)."""
    offenders = []
    for path in (REPO / "bot" / "handlers").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "F.text.in_(" in text or "all_variants(" in text:
            offenders.append(path.name)
    assert offenders == []
    assert not re.search(r"ReplyKeyboard(Markup|Builder)", "".join(p.read_text(encoding="utf-8") for p in (REPO / "bot").rglob("*.py")))


# ── the admin screens are localized ────────────────────────────────────────────

_CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def _admin_screens() -> dict[str, str]:
    from bot.formatters import dashboard_text, proxy_admin_combined_text, system_diagnostics_text
    from models.dto import ProxyAdminStats, ProxyLifecycleStats, ProxyRuntimeStats
    from repositories.dashboard import KeysSummary, TopUserTraffic, TrafficTotals, TrafficWindows
    from services.dashboard import DashboardSnapshot
    from services.health import HealthCheckItem, build_result

    snapshot = DashboardSnapshot(
        refreshed_at="12:34:56",
        users_by_role={"APPROVED_USER": 3, "PENDING_USER": 1, "MODERATOR": 1, "SUPERADMIN": 1},
        new_users_7d=1, new_users_30d=2, users_with_active_keys=2,
        pending_access_requests=1, pending_trial_requests=1,
        keys=KeysSummary(total=3, active=2, xray_active=1, awg_active=1, hysteria2_active=0,
                         expiring_7d=1, expiring_30d=1, stuck=1, avg_per_user=1.5),
        traffic=TrafficTotals(total_bytes=1024, xray_bytes=512, awg_bytes=512, hysteria2_bytes=0, avg_per_key_bytes=341),
        traffic_windows=TrafficWindows(current_hour_utc=500000, bytes_by_days={1: 1, 7: 2, 30: 3, 90: 4, 180: 5, 365: 6}, first_hour_utc=None),
        top_users=[TopUserTraffic(user_id=100, username="user", total_bytes=1024)],
        active_socks5=1, active_mtproto=1, stuck_proxies=1,
        backend_health=(), warp=WarpState(enabled=True, routes_count=2), active_modules=[], last_backup_at=None, db_size_bytes=0,
        audit_count_24h=1, audit_count_7d=2, recent_audit_entries=[{"action": "user_blocked"}], announcements_30d=1,
    )
    lifecycle = ProxyLifecycleStats(1, 1, 0, 1, 1, 0)
    stats = ProxyAdminStats(
        total_accesses=2, active_total=2, active_socks5=1, active_mtproto=1, apply_failed=0, revoked=0, deleted=0,
        pending=0, users_with_active_proxies=1, last_issued_at=None, last_failed_at=None, type_status_counts={},
        mtproto_mode_counts={}, users=(), total_users=0, runtime=ProxyRuntimeStats(socks5_enabled=True, mtproto_enabled=True),
    )
    health = build_result([HealthCheckItem(name="x", status="ok", severity="info", message="Non-root OK")])
    return {
        "dashboard": dashboard_text(snapshot),
        "proxy": proxy_admin_combined_text(lifecycle, stats, module_off=frozenset({"socks5"})),
        "diagnostics": system_diagnostics_text(
            health, disabled_modules=[ProtocolModule("awg", False, disabled_at=NOW)]
        ),
    }


def test_admin_screens_in_english_have_no_cyrillic() -> None:
    with use_locale("en"):
        screens = _admin_screens()
    leaks = {name: _CYRILLIC.findall(text) for name, text in screens.items() if _CYRILLIC.search(text)}
    assert leaks == {}


def test_admin_screens_in_russian_are_unchanged_where_they_were_russian() -> None:
    with use_locale("ru"):
        screens = _admin_screens()
    assert screens["dashboard"].startswith("<b>📊 Дашборд</b>  <i>обновлено 12:34:56</i>")
    assert "<b>👥 Пользователи</b>" in screens["dashboard"]
    assert screens["proxy"].startswith("<b>Прокси — статус и статистика</b>")
    assert "<b>Отключённые модули:</b>" in screens["diagnostics"]
