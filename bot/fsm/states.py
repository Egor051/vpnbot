
from aiogram.fsm.state import State, StatesGroup


class CreateKeyStates(StatesGroup):
    waiting_xhttp_profile = State()
    # «Подключение: напрямую / через <relay>» — only while a relay is enabled.
    waiting_route = State()
    # All-in-one: basic or extended.
    waiting_bundle_kind = State()
    waiting_note = State()
    waiting_fp = State()
    waiting_mtu = State()
    waiting_mtu_custom = State()
    waiting_expiry = State()
    waiting_custom_days = State()
    confirming = State()


class EditNoteStates(StatesGroup):
    waiting_note = State()
    confirming = State()


class EditFpStates(StatesGroup):
    waiting_fp = State()


class ProxyStates(StatesGroup):
    confirming = State()


class AdminCreateKeyStates(StatesGroup):
    choosing_type = State()
    waiting_xhttp_profile = State()
    # «Подключение: напрямую / через <relay>» — only while a relay is enabled.
    waiting_route = State()
    waiting_note = State()
    waiting_fp = State()
    waiting_mtu = State()
    waiting_mtu_custom = State()
    waiting_expiry = State()
    waiting_custom_days = State()
    confirming = State()


class AdminEditUserNoteStates(StatesGroup):
    waiting_note = State()


class AdminUserSearchStates(StatesGroup):
    """«🔎 Найти» in the users list: waiting for a Telegram id or a username."""

    waiting_query = State()


class AdminAnnouncementStates(StatesGroup):
    choosing_roles = State()
    choosing_protocols = State()
    choosing_transports = State()
    waiting_message = State()
    confirming = State()
    waiting_schedule_time = State()


class MaintenanceStates(StatesGroup):
    waiting_message = State()


class TrialRequestStates(StatesGroup):
    choosing_protocol = State()
    confirming = State()


class WarpConfigStates(StatesGroup):
    waiting_config = State()


class WarpSplitStates(StatesGroup):
    waiting_cidrs = State()
    # New prefix source: slug / title / URL / format, one per line.
    waiting_source = State()


class AdminRelayStates(StatesGroup):
    """The relay panel's wizards: «Добавить relay» and the per-field edits."""

    add_name = State()
    add_host = State()
    add_source_ips = State()
    add_label = State()
    add_confirm = State()
    edit_host = State()
    edit_source_ips = State()
    edit_label = State()
    edit_note = State()
