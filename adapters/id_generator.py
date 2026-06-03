
import re
import secrets
import uuid


KEY_NAME_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_LABEL_NON_WORD_RE = re.compile(r"[^a-z0-9_]+")
_LABEL_UNDERSCORE_RUN_RE = re.compile(r"_+")


class IdGenerator:
    def uuid4(self) -> str:
        """Generate a random UUID4 string."""
        return str(uuid.uuid4())

    def xray_short_id(self) -> str:
        """Generate a random Xray REALITY short id."""
        return secrets.token_hex(8)

    def key_label(self, telegram_user_id: int, username: str | None = None) -> str:
        """Generate a unique key label derived from the user id or username."""
        base = self._label_base(telegram_user_id, username)
        return f"{base}_{secrets.token_hex(4)}"

    def email_label(self, telegram_user_id: int, username: str | None = None) -> str:
        """Generate a unique email label derived from the user id or username."""
        return self.key_label(telegram_user_id, username)

    def generated_key_name(self, prefix: str) -> str:
        """Generate a key name from the prefix plus a random suffix."""
        return f"{prefix}_{''.join(secrets.choice(KEY_NAME_ALPHABET) for _ in range(5))}"

    def _label_base(self, telegram_user_id: int, username: str | None) -> str:
        if username:
            value = username.lstrip("@").strip().lower()
            value = _LABEL_NON_WORD_RE.sub("_", value)
            value = _LABEL_UNDERSCORE_RUN_RE.sub("_", value).strip("_")
            if value:
                return value[:32]
        return f"tg{telegram_user_id}"
