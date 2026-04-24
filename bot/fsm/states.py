from __future__ import annotations

from aiogram.fsm.state import State, StatesGroup


class CreateKeyStates(StatesGroup):
    waiting_note = State()
    confirming = State()


class EditNoteStates(StatesGroup):
    waiting_note = State()
    confirming = State()


class AdminCreateKeyStates(StatesGroup):
    choosing_type = State()
    waiting_note = State()
    confirming = State()
