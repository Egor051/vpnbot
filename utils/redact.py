
import re

_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(bot_token|token|password|passwd|secret|mtproto_secret|private_key|preshared_key)\s*([:=])\s*[^,\s;]+",
    re.IGNORECASE,
)
_SECRET_QUERY_RE = re.compile(r"(?i)(secret=)[^&\s]+")
_HEX_SECRET_RE = re.compile(r"\b(?:dd)?[0-9a-fA-F]{32,}\b")


def redact(value: str, limit: int = 180) -> str:
    """Redact secret-like patterns from diagnostic text and truncate to limit."""
    text = value.replace("\r", " ").replace("\n", " ").strip()
    text = _SECRET_QUERY_RE.sub(r"\1***", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    text = _HEX_SECRET_RE.sub("***", text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."
