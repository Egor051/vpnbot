"""Regressions found by the admin-panel audit (2026-11), one test per defect.

Each test fails on the code before the fix:

* ``/warp_split_add|del|reload`` bypassed the feed database / the forced re-apply;
* a moderator's ``/start`` filed an access request nobody could resolve, and the
  lists a moderator sees had no exit a moderator could use;
* the user card offered actions the service always refused;
* keys could be issued on a module that was switched off;
* «Перезапустить» re-enabled switched-off WARP routes, and one-tap actions that
  broadcast to everyone or change routing ran without a confirmation;
* the modules panel claimed a protocol switched off in ``.env`` was on.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import bot.handlers.admin as admin_mod
import bot.handlers.admin_maintenance as maint_mod
import bot.handlers.admin_modules as modules_mod
import bot.handlers.admin_warp as warp_mod
import bot.handlers.admin_warp_split as split_cmds
import bot.handlers.common as common_mod
from adapters.clock import ClockProvider
from bot.fsm.states import AdminCreateKeyStates
from bot.keyboards.admin import user_actions_keyboard
from db.database import Database
from i18n import t
from models.dto import TelegramUserProfile, User
from models.enums import AccessRequestStatus, UserRole
from repositories.access_requests import AccessRequestRepository
from repositories.audit_log import AuditLogRepository
from repositories.protocol_modules import ProtocolModule
from repositories.users import UserRepository
from services.access_approval import AccessApprovalService
from services.audit import AuditService
from services.awg import AwgService
from services.errors import InvalidOperation
from services.users import UserService
from services.xray import XrayService
from tests.test_telegram_rbac import _settings
from tests.test_warp_split_feeds import _make
from warp.split_manager import SplitStatus
from warp.state import WarpState

NOW = "2026-11-06T00:00:00+00:00"


async def _allow(*args: object, **kwargs: object) -> bool:
    return True


class _Callback:
    def __init__(self, data: str, user_id: int = 1) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="u", first_name="U")
        self.message = SimpleNamespace(message_id=1, chat=SimpleNamespace(id=user_id))
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _State:
    def __init__(self, data: dict[str, object] | None = None, state: object | None = None) -> None:
        self.data = dict(data or {})
        self.state = state

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def get_state(self) -> str | None:
        return getattr(self.state, "state", self.state)  # type: ignore[return-value]

    async def set_state(self, state: object) -> None:
        self.state = state

    async def update_data(self, **kwargs: object) -> None:
        self.data.update(kwargs)

    async def clear(self) -> None:
        self.data.clear()
        self.state = None


class _Message:
    def __init__(self, text: str, user_id: int = 1) -> None:
        self.text = text
        self.from_user = SimpleNamespace(id=user_id, username="u", first_name="U")
        self.chat = SimpleNamespace(id=user_id, type="private")
        self.answers: list[tuple[str, object]] = []

    async def answer(self, text: str, reply_markup: object = None, **kwargs: object) -> None:
        self.answers.append((text, reply_markup))


def _user(uid: int, role: UserRole) -> User:
    return User(uid, f"u{uid}", "U", role, NOW, NOW, None)


def _callbacks(markup: Any) -> list[str]:
    return [button.callback_data for row in markup.inline_keyboard for button in row]


@pytest.fixture
def edits(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    """Capture every screen edit of the admin handler modules."""
    captured: list[tuple[str, Any]] = []

    async def fake_edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> None:
        captured.append((text, reply_markup))

    for module in (admin_mod, maint_mod, modules_mod, warp_mod):
        monkeypatch.setattr(module, "safe_edit_message_text", fake_edit)
        monkeypatch.setattr(module, "ensure_private_callback", _allow)
    monkeypatch.setattr(admin_mod, "ensure_private_message", _allow)
    return captured


# ── /warp_split_* commands go the panel's way ───────────────────────────────────


async def _split_world(tmp_path: Path) -> tuple[Any, ...]:
    db, shell, manager, _f, repo, service = await _make(tmp_path)
    for slug in ("telegram-cidr", "google-goog", "google-cloud"):
        await repo.set_enabled(slug, False)
    manager.list_path.write_text("1.2.3.0/24\n", encoding="utf-8")
    await service.ensure_manual_adopted()

    class Users:
        async def require_superadmin(self, user_id: int) -> object:
            return SimpleNamespace(role=UserRole.SUPERADMIN)

    services = SimpleNamespace(users=Users(), warp_split=manager, warp_split_feeds=service)
    return db, shell, manager, repo, service, services


@pytest.fixture
def split_private(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(split_cmds, "ensure_private_message", _allow)


@pytest.mark.usefixtures("split_private")
async def test_a_prefix_added_by_command_survives_the_next_merge(tmp_path: Path) -> None:
    db, _shell, manager, repo, service, services = await _split_world(tmp_path)
    try:
        await split_cmds.warp_split_add_cmd(_Message("/warp_split_add 9.9.9.0/24"), services)  # type: ignore[arg-type]
        assert "9.9.9.0/24" in await repo.manual_prefixes()
        await service.add_manual(["8.8.8.0/24"], actor_user_id=1)  # the panel's «Добавить»
        assert "9.9.9.0/24" in manager.read_list()
    finally:
        await db.close()


@pytest.mark.usefixtures("split_private")
async def test_a_prefix_deleted_by_command_stays_deleted(tmp_path: Path) -> None:
    db, _shell, manager, repo, service, services = await _split_world(tmp_path)
    try:
        await service.add_manual(["8.8.8.0/24"], actor_user_id=1)
        await split_cmds.warp_split_del_cmd(_Message("/warp_split_del 1.2.3.0/24"), services)  # type: ignore[arg-type]
        assert "1.2.3.0/24" not in await repo.manual_prefixes()
        await service.add_manual(["7.7.7.0/24"], actor_user_id=1)
        assert "1.2.3.0/24" not in manager.read_list()
    finally:
        await db.close()


@pytest.mark.usefixtures("split_private")
async def test_a_feed_prefix_is_not_deleted_by_command(tmp_path: Path) -> None:
    db, _shell, _manager, repo, service, services = await _split_world(tmp_path)
    try:
        await repo.replace_prefixes("google-goog", ["8.8.8.0/24"])  # supplied by an enabled feed
        await repo.set_enabled("google-goog", True)
        await service.add_manual(["8.8.8.0/24"], actor_user_id=1)
        message = _Message("/warp_split_del 8.8.8.0/24")
        await split_cmds.warp_split_del_cmd(message, services)  # type: ignore[arg-type]
        assert "8.8.8.0/24" in await repo.manual_prefixes()
        assert t("warp_split_report_unchanged") in message.answers[-1][0]
        assert "google-goog" in message.answers[-1][0]
    finally:
        await db.close()


@pytest.mark.usefixtures("split_private")
async def test_deleting_a_collapsed_prefix_drops_its_manual_contributors(tmp_path: Path) -> None:
    """The routed list is collapsed: two manual /25s are routed as one /24, which
    matches no stored row. Deleting the /24 must drop both (Codex review)."""
    db, _shell, manager, repo, service, services = await _split_world(tmp_path)
    try:
        await service.add_manual(["8.8.8.0/25", "8.8.8.128/25"], actor_user_id=1)
        assert "8.8.8.0/24" in manager.read_list()
        await split_cmds.warp_split_del_cmd(_Message("/warp_split_del 8.8.8.0/24"), services)  # type: ignore[arg-type]
        assert "8.8.8.0/24" not in manager.read_list()
        assert not {"8.8.8.0/25", "8.8.8.128/25"} & set(await repo.manual_prefixes())
    finally:
        await db.close()


@pytest.mark.usefixtures("split_private")
async def test_a_collapsed_prefix_with_a_feed_part_is_not_deleted(tmp_path: Path) -> None:
    db, _shell, manager, repo, service, services = await _split_world(tmp_path)
    try:
        await repo.replace_prefixes("google-goog", ["8.8.8.128/25"])
        await repo.set_enabled("google-goog", True)
        await service.add_manual(["8.8.8.0/25"], actor_user_id=1)
        assert "8.8.8.0/24" in manager.read_list()  # collapsed: half manual, half feed
        message = _Message("/warp_split_del 8.8.8.0/24")
        await split_cmds.warp_split_del_cmd(message, services)  # type: ignore[arg-type]
        assert "8.8.8.0/25" in await repo.manual_prefixes()
        assert "google-goog" in message.answers[-1][0]
    finally:
        await db.close()


@pytest.mark.usefixtures("split_private")
async def test_a_prefix_of_a_disabled_feed_can_be_deleted(tmp_path: Path) -> None:
    db, _shell, manager, repo, service, services = await _split_world(tmp_path)
    try:
        await service.add_manual(["8.8.8.0/24"], actor_user_id=1)
        await repo.replace_prefixes("google-goog", ["8.8.8.0/24"])  # cached, but the source is off
        await split_cmds.warp_split_del_cmd(_Message("/warp_split_del 8.8.8.0/24"), services)  # type: ignore[arg-type]
        assert "8.8.8.0/24" not in manager.read_list()
    finally:
        await db.close()


@pytest.mark.usefixtures("split_private")
async def test_a_feed_range_carved_out_by_a_scoped_subtraction_does_not_block_a_delete(tmp_path: Path) -> None:
    """The feed caches 8.8.8.0/24 but its scoped subtraction removes it: the route
    is the manual row's alone, so the delete goes through (Codex review)."""
    db, _shell, manager, repo, service, services = await _split_world(tmp_path)
    try:
        await repo.replace_prefixes("google-goog", ["8.8.8.0/24", "9.9.0.0/16"])
        await repo.replace_prefixes("google-cloud", ["8.8.8.0/24"])  # subtract, scoped to google-goog
        await repo.set_enabled("google-goog", True)
        await repo.set_enabled("google-cloud", True)
        await service.add_manual(["8.8.8.0/24"], actor_user_id=1)
        assert "8.8.8.0/24" in manager.read_list()
        assert await service.feed_origins("8.8.8.0/24") == []
        await split_cmds.warp_split_del_cmd(_Message("/warp_split_del 8.8.8.0/24"), services)  # type: ignore[arg-type]
        assert "8.8.8.0/24" not in manager.read_list()
    finally:
        await db.close()


def test_removing_a_range_splits_a_wider_manual_row() -> None:
    import ipaddress

    from services.warp_split_feeds import _manual_rows_without

    drop, add = _manual_rows_without(["8.8.0.0/16", "1.1.1.0/24", "8.8.8.0/25"], ["8.8.0.0/21"])
    assert set(drop) == {"8.8.0.0/16"}
    remaining = [ipaddress.IPv4Network(item) for item in add]
    assert sum(net.num_addresses for net in remaining) == 2**16 - 2**11
    assert not any(net.overlaps(ipaddress.IPv4Network("8.8.0.0/21")) for net in remaining)


def test_back_from_replace_config_leaves_the_upload(edits: list[tuple[str, Any]]) -> None:
    """«Назад» of «Заменить конфиг» goes to the WARP settings, which must end the
    upload: otherwise the next document still replaced the live config (Codex review)."""
    from bot.fsm.states import WarpConfigStates

    state = _State({"cancel_target": "admin:warp:settings"}, WarpConfigStates.waiting_config)
    services = SimpleNamespace(users=_RoleUsers(UserRole.SUPERADMIN), warp=_Warp())
    asyncio.run(warp_mod.warp_settings(_Callback("admin:warp:settings"), state, services))  # type: ignore[arg-type]
    assert state.state is None


@pytest.mark.usefixtures("split_private")
async def test_reload_command_runs_the_helper_on_an_unchanged_file(tmp_path: Path) -> None:
    db, shell, _manager, _repo, _service, services = await _split_world(tmp_path)
    try:
        before = len(shell.apply_calls)
        await split_cmds.warp_split_reload_cmd(_Message("/warp_split_reload"), services)  # type: ignore[arg-type]
        assert len(shell.apply_calls) == before + 1
    finally:
        await db.close()


# ── moderators ──────────────────────────────────────────────────────────────────


async def _access_world(tmp_path: Path) -> tuple[Database, UserRepository, AccessRequestRepository, AccessApprovalService]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users_repo = UserRepository(db)
    requests_repo = AccessRequestRepository(db)
    audit = AuditService(AuditLogRepository(db), ClockProvider())
    users = UserService(users=users_repo, settings=_settings(tmp_path), clock=ClockProvider(), audit=audit)
    await users.bootstrap_admins()
    await users_repo.upsert_profile(TelegramUserProfile(200, "mod", "Mod"), UserRole.MODERATOR, NOW)
    return db, users_repo, requests_repo, AccessApprovalService(requests=requests_repo, users=users, clock=ClockProvider(), audit=audit)


async def test_moderator_start_files_no_access_request(tmp_path: Path) -> None:
    db, _users, _requests, access = await _access_world(tmp_path)
    try:
        result = await access.create_or_get_request(TelegramUserProfile(200, "mod", "Mod"))
        assert result.request is None and result.created is False
        assert await access.count_pending(1) == 0
    finally:
        await db.close()


@pytest.mark.parametrize("decision", ["approve", "reject"])
async def test_an_old_moderator_request_can_be_closed_without_a_role_change(tmp_path: Path, decision: str) -> None:
    db, users_repo, requests_repo, access = await _access_world(tmp_path)
    try:
        request = await requests_repo.create(200, "mod", NOW)  # filed by an older build
        _request, changed = await getattr(access, decision)(1, request.id)
        assert changed is True
        stored = await requests_repo.get_by_id(request.id)
        assert stored is not None and stored.status != AccessRequestStatus.PENDING
        moderator = await users_repo.get_by_id(200)
        assert moderator is not None and moderator.role == UserRole.MODERATOR
    finally:
        await db.close()


def test_the_main_menu_has_a_moderator_entry() -> None:
    from bot.keyboards.common import main_menu

    assert "admin:moderator_panel" in _callbacks(main_menu(is_moderator=True))
    assert "admin:moderator_panel" not in _callbacks(main_menu(True))
    assert "admin:panel" not in _callbacks(main_menu(is_moderator=True))


class _RoleUsers:
    def __init__(self, role: UserRole) -> None:
        self.role = role

    async def get_user(self, user_id: int) -> User:
        return _user(user_id, self.role)

    async def require_moderator_or_admin(self, user_id: int) -> User:
        if self.role not in {UserRole.SUPERADMIN, UserRole.MODERATOR}:
            raise admin_mod.AccessDenied("no", key="err_insufficient_rights")
        return _user(user_id, self.role)

    async def require_superadmin(self, user_id: int) -> User:
        if self.role != UserRole.SUPERADMIN:
            raise admin_mod.AccessDenied("no", key="err_insufficient_rights")
        return _user(user_id, self.role)


@pytest.mark.parametrize("data", ["admin:panel", "admin:grp:people"])
def test_back_from_a_moderator_list_opens_the_moderator_panel(data: str, edits: list[tuple[str, Any]]) -> None:
    services = SimpleNamespace(users=_RoleUsers(UserRole.MODERATOR), auto_refresh=SimpleNamespace(cancel=lambda key: None))
    callback = _Callback(data)
    handler = admin_mod.admin_panel if data == "admin:panel" else admin_mod.admin_group
    asyncio.run(handler(callback, _State(), services))  # type: ignore[arg-type]
    assert edits and edits[-1][0] == t("moderator_panel_title")
    assert all(not alert for _text, alert in callback.answers)


def test_other_sections_stay_superadmin_only(edits: list[tuple[str, Any]]) -> None:
    services = SimpleNamespace(users=_RoleUsers(UserRole.MODERATOR), auto_refresh=SimpleNamespace(cancel=lambda key: None))
    callback = _Callback("admin:grp:infra")
    asyncio.run(admin_mod.admin_group(callback, _State(), services))  # type: ignore[arg-type]
    assert edits == []
    assert callback.answers[-1] == (t("err_insufficient_rights"), True)


def test_moderator_start_shows_the_main_menu(monkeypatch: pytest.MonkeyPatch) -> None:
    import bot.handlers.start as start_mod

    monkeypatch.setattr(start_mod, "ensure_private_message", _allow)

    class Access:
        async def create_or_get_request(self, profile: object) -> object:
            return SimpleNamespace(user=_user(200, UserRole.MODERATOR), request=None, created=False)

    message = _Message("/start", user_id=200)
    services = SimpleNamespace(access=Access(), users=_RoleUsers(UserRole.MODERATOR))
    asyncio.run(start_mod.start_command(message, services, SimpleNamespace()))  # type: ignore[arg-type]
    assert "admin:moderator_panel" in _callbacks(message.answers[-1][1])


# ── the user card offers only what the service carries out ──────────────────────


@pytest.mark.parametrize(
    ("actor", "target", "absent"),
    [
        (UserRole.SUPERADMIN, UserRole.SUPERADMIN, {"admin:userapprove:2", "admin:block:2"}),
        (UserRole.MODERATOR, UserRole.MODERATOR, {"admin:block:2"}),
        (UserRole.MODERATOR, UserRole.SUPERADMIN, {"admin:block:2"}),
    ],
)
def test_the_card_hides_actions_the_service_refuses(actor: UserRole, target: UserRole, absent: set[str]) -> None:
    datas = set(_callbacks(user_actions_keyboard(_user(2, target), actor_role=actor, actor_user_id=1)))
    assert not datas & absent


def test_nobody_is_offered_to_block_themselves() -> None:
    datas = _callbacks(user_actions_keyboard(_user(1, UserRole.APPROVED_USER), actor_role=UserRole.MODERATOR, actor_user_id=1))
    assert "admin:block:1" not in datas


def test_a_moderator_can_still_block_an_ordinary_user() -> None:
    datas = _callbacks(user_actions_keyboard(_user(2, UserRole.APPROVED_USER), actor_role=UserRole.MODERATOR, actor_user_id=1))
    assert "admin:block:2" in datas


# ── no key on a switched-off module ─────────────────────────────────────────────


class _Off:
    async def is_enabled(self, name: str) -> bool:
        return False


def _profile() -> TelegramUserProfile:
    return TelegramUserProfile(100, "u", "U")


def test_xray_service_refuses_a_key_on_a_disabled_module() -> None:
    service = XrayService(
        vpn_keys=None, users=None, adapter=None, settings=None, clock=None, ids=None, audit=None, modules=_Off()  # type: ignore[arg-type]
    )
    with pytest.raises(InvalidOperation) as err:
        asyncio.run(service.create_xray_key(1, _profile(), None))
    assert err.value.key == "protocol_unavailable"


def test_awg_service_refuses_a_key_on_a_disabled_module() -> None:
    service = AwgService(
        vpn_keys=None, users=None, adapter=None, ip_allocator=None, settings=None, clock=None, ids=None, audit=None, modules=_Off()  # type: ignore[arg-type]
    )
    with pytest.raises(InvalidOperation) as err:
        asyncio.run(service.create_awg_key(1, _profile(), None))
    assert err.value.key == "protocol_unavailable"


def test_admin_wizard_refuses_a_disabled_protocol(edits: list[tuple[str, Any]]) -> None:
    state = _State({"owner_user_id": 200}, AdminCreateKeyStates.choosing_type)
    callback = _Callback("admin:ctype:awg:200")
    services = SimpleNamespace(users=_RoleUsers(UserRole.SUPERADMIN), modules=_Off())
    asyncio.run(admin_mod.admin_issue_type_selected(callback, state, services))  # type: ignore[arg-type]
    assert callback.answers[-1] == (t("protocol_unavailable"), True)
    assert state.state is AdminCreateKeyStates.choosing_type


# ── WARP ────────────────────────────────────────────────────────────────────────


class _Split:
    def __init__(self, intended: str) -> None:
        self.intended = intended
        self.calls: list[str] = []

    async def status(self) -> SplitStatus:
        return SplitStatus(tunnel_up=True, intended_state=self.intended, n_list=1, n_table=1, in_sync=True)

    async def restart_routes(self) -> None:
        self.calls.append("restart_routes")

    async def disable(self) -> None:
        self.calls.append("disable")


class _Warp:
    last_error = None

    async def get_state(self) -> WarpState:
        return WarpState(enabled=True, routes_count=1)


def _warp_services(split: _Split) -> SimpleNamespace:
    return SimpleNamespace(users=_RoleUsers(UserRole.SUPERADMIN), warp=_Warp(), warp_split=split)


def test_restart_does_not_switch_off_routes_back_on(edits: list[tuple[str, Any]]) -> None:
    split = _Split("off")
    callback = _Callback("admin:warp:restart:ok")
    asyncio.run(warp_mod.warp_restart(callback, _warp_services(split)))  # type: ignore[arg-type]
    assert split.calls == []
    assert callback.answers[-1] == (t("warp_restart_routes_off"), True)


@pytest.mark.parametrize("data", ["admin:warp:disable", "admin:warp:restart", "admin:warp:killswitch:toggle"])
def test_routing_actions_ask_first(data: str, edits: list[tuple[str, Any]]) -> None:
    split = _Split("on")
    asyncio.run(warp_mod.warp_action_confirm(_Callback(data), _warp_services(split)))  # type: ignore[arg-type]
    assert split.calls == []
    assert f"{data}:ok" in _callbacks(edits[-1][1])


# ── broadcasts and maintenance ask first ────────────────────────────────────────


def test_ending_maintenance_asks_first(edits: list[tuple[str, Any]]) -> None:
    disabled: list[int] = []
    services = SimpleNamespace(
        users=_RoleUsers(UserRole.SUPERADMIN), maintenance=SimpleNamespace(disable=lambda actor: disabled.append(actor))
    )
    asyncio.run(maint_mod.admin_maintenance_disable_confirm(_Callback("admin:maintenance:disable"), _State(), services))  # type: ignore[arg-type]
    assert disabled == []
    assert "admin:maintenance:disable:ok" in _callbacks(edits[-1][1])


@pytest.mark.parametrize("action", ["resume", "retry", "cancelbatch"])
def test_batch_actions_ask_first(action: str, edits: list[tuple[str, Any]]) -> None:
    services = SimpleNamespace(users=_RoleUsers(UserRole.SUPERADMIN), announcements=SimpleNamespace())
    asyncio.run(admin_mod.admin_announcement_batch_confirm(_Callback(f"admin:announce:{action}:5"), services))  # type: ignore[arg-type]
    assert f"admin:announce:{action}:5:ok" in _callbacks(edits[-1][1])


# ── the modules panel and .env ──────────────────────────────────────────────────


def _env_settings(**flags: bool) -> SimpleNamespace:
    return SimpleNamespace(
        hysteria2_enabled=flags.get("hy2", True),
        is_hysteria2_ready=lambda: True,
        socks5_enabled=flags.get("socks5", True),
        mtproto_enabled=flags.get("mtproto", True),
    )


def test_the_modules_panel_marks_a_protocol_switched_off_in_env(edits: list[tuple[str, Any]]) -> None:
    class Modules:
        async def get_all(self) -> list[ProtocolModule]:
            return [ProtocolModule(name, True) for name in ("xray", "awg", "socks5", "mtproto", "hysteria2")]

    services = SimpleNamespace(users=_RoleUsers(UserRole.SUPERADMIN), modules=Modules(), settings=_env_settings(socks5=False))
    asyncio.run(modules_mod.admin_modules_panel(_Callback("admin:modules"), services))  # type: ignore[arg-type]
    datas = _callbacks(edits[-1][1])
    assert "admin:module:envoff:socks5" in datas
    assert "admin:module:enable:socks5" not in datas
    # Switching it off stays possible (Codex review): the host may still carry it.
    assert "admin:module:disable:socks5" in datas
    assert "admin:module:disable:mtproto" in datas


def test_a_protocol_off_in_env_can_still_be_removed_from_the_server() -> None:
    from bot.keyboards.admin_modules import modules_panel_keyboard

    datas = _callbacks(modules_panel_keyboard([ProtocolModule("socks5", False)], env_off=frozenset({"socks5"})))
    assert "admin:module:envoff:socks5" in datas
    assert "admin:module:uninst:socks5" in datas
    assert "admin:module:enable:socks5" not in datas


def test_enabling_a_protocol_switched_off_in_env_is_refused(edits: list[tuple[str, Any]]) -> None:
    services = SimpleNamespace(users=_RoleUsers(UserRole.SUPERADMIN), settings=_env_settings(mtproto=False))
    callback = _Callback("admin:module:enable:mtproto")
    asyncio.run(modules_mod.admin_module_enable_confirm(callback, services))  # type: ignore[arg-type]
    assert edits == []
    assert callback.answers[-1][1] is True and "MTPROTO_ENABLED" in callback.answers[-1][0]


# ── user search ─────────────────────────────────────────────────────────────────


async def test_user_search_by_id_and_username(tmp_path: Path) -> None:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    try:
        await db.bootstrap()
        repo = UserRepository(db)
        await repo.upsert_profile(TelegramUserProfile(555, "Alice_Smith", "A"), UserRole.APPROVED_USER, NOW)
        await repo.upsert_profile(TelegramUserProfile(556, "alicex", "A"), UserRole.APPROVED_USER, NOW)
        await repo.upsert_profile(TelegramUserProfile(557, "bob", "B"), UserRole.APPROVED_USER, NOW)
        assert [u.telegram_user_id for u in await repo.search_users("555")] == [555]
        assert {u.telegram_user_id for u in await repo.search_users("@alice")} == {555, 556}
        assert [u.telegram_user_id for u in await repo.search_users("ce_s")] == [555]  # «_» is literal
        assert await repo.search_users("%") == []
        assert await repo.search_users("9" * 30) == []
    finally:
        await db.close()


# ── /cancel returns where the wizard started ────────────────────────────────────


def test_cancel_command_returns_to_the_wizard_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    import bot.handlers.callbacks as callbacks_mod

    monkeypatch.setattr(common_mod, "ensure_private_message", _allow)

    async def fake_view(services: object, user_id: int, target: str) -> tuple[str, Any]:
        return f"screen:{target}", None

    monkeypatch.setattr(callbacks_mod, "admin_cancel_view", fake_view)
    message = _Message("/cancel")
    state = _State({"cancel_target": "admin:user:200"})
    asyncio.run(common_mod.cancel_command(message, state, SimpleNamespace()))  # type: ignore[arg-type]
    assert message.answers[-1][0].endswith("screen:admin:user:200")
    assert state.data == {}
