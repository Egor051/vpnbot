from __future__ import annotations

import re
import secrets
import uuid


class IdGenerator:
    def uuid4(self) -> str:
        return str(uuid.uuid4())

    def xray_short_id(self) -> str:
        return secrets.token_hex(8)

    def key_label(self, telegram_user_id: int, username: str | None = None) -> str:
        base = self._label_base(telegram_user_id, username)
        return f"{base}_{secrets.token_hex(3)}"

    def email_label(self, telegram_user_id: int, username: str | None = None) -> str:
        return self.key_label(telegram_user_id, username)

    def _label_base(self, telegram_user_id: int, username: str | None) -> str:
        if username:
            value = username.lstrip("@").strip().lower()
            value = re.sub(r"[^a-z0-9_]+", "_", value)
            value = re.sub(r"_+", "_", value).strip("_")
            if value:
                return value[:32]
        return f"tg{telegram_user_id}"
