
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

    def hysteria2_label(self) -> str:
        """Generate a Hysteria2 stats/log label: ``hy2_`` + the standard suffix.

        Deliberately the same shape as every other key label (``xray_tcp_*``,
        ``awg_*``, ``bundle_*``): the label is what the user reads under «Метка», so
        one protocol printing a 16-hex-char suffix while the rest print five just
        looked like a bug. It is a stats identifier returned to Hysteria's
        traffic-stats API — NOT the auth secret, which is generated separately in
        ``HysteriaService.issue`` and keeps its full entropy. Uniqueness comes from
        the same retry-and-check loop the other protocols use
        (``HysteriaService._generate_unique_label``), not from the suffix width.

        Existing keys keep their old ``hy2_<16 hex>`` labels: the label is the
        connection identity ``hy2_auth`` hands to the server and the key into the
        traffic-stats/kick APIs, so renaming a live key would orphan its stats.
        """
        return self.generated_key_name("hy2")

    def _label_base(self, telegram_user_id: int, username: str | None) -> str:
        if username:
            value = username.lstrip("@").strip().lower()
            value = _LABEL_NON_WORD_RE.sub("_", value)
            value = _LABEL_UNDERSCORE_RUN_RE.sub("_", value).strip("_")
            if value:
                return value[:32]
        return f"tg{telegram_user_id}"
