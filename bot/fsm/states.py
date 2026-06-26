
from aiogram.fsm.state import State, StatesGroup


class CreateKeyStates(StatesGroup):
    waiting_xhttp_profile = State()
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
    waiting_note = State()
    waiting_fp = State()
    waiting_mtu = State()
    waiting_mtu_custom = State()
    waiting_expiry = State()
    waiting_custom_days = State()
    confirming = State()


class AdminEditUserNoteStates(StatesGroup):
    waiting_note = State()


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
