
from aiogram.fsm.state import State, StatesGroup


class CreateKeyStates(StatesGroup):
    waiting_note = State()
    waiting_mtu = State()
    waiting_mtu_custom = State()
    waiting_expiry = State()
    waiting_custom_days = State()
    confirming = State()


class EditNoteStates(StatesGroup):
    waiting_note = State()
    confirming = State()


class ProxyStates(StatesGroup):
    confirming = State()


class AdminCreateKeyStates(StatesGroup):
    choosing_type = State()
    waiting_note = State()
    waiting_mtu = State()
    waiting_mtu_custom = State()
    waiting_expiry = State()
    waiting_custom_days = State()
    confirming = State()


class AdminAnnouncementStates(StatesGroup):
    waiting_message = State()
    confirming = State()


class TrialRequestStates(StatesGroup):
    choosing_protocol = State()
    confirming = State()
