from __future__ import annotations

import secrets
import uuid


class IdGenerator:
    def uuid4(self) -> str:
        return str(uuid.uuid4())

    def xray_short_id(self) -> str:
        return secrets.token_hex(8)

    def email_label(self, telegram_user_id: int) -> str:
        return f"tg{telegram_user_id}_{secrets.token_hex(4)}"
