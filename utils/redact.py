
import re

_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(bot_token|token|password|passwd|secret|mtproto_secret|private_key|preshared_key)\s*([:=])\s*[^,\s;]+",
    re.IGNORECASE,
)
_SECRET_QUERY_RE = re.compile(r"(?i)(secret=)[^&\s]+")
_HEX_SECRET_RE = re.compile(r"\b(?:dd)?[0-9a-fA-F]{32,}\b")
_TG_BOT_TOKEN_RE = re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{35}\b")
_BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_.~+/=-]{16,}\b")
_URL_CREDENTIALS_RE = re.compile(r"(?i)([a-z][a-z0-9+\-.]*://)([^:@/\s]+:[^@/\s]+@)")
_WG_PRIVATE_KEY_RE = re.compile(r"\b[A-Za-z0-9+/]{43}={1,2}(?=[^A-Za-z0-9+/=]|$)")


def redact(value: str, limit: int = 180) -> str:
    """Redact secret-like patterns from diagnostic text and truncate to limit."""
    text = value.replace("\r", " ").replace("\n", " ").strip()
    text = _SECRET_QUERY_RE.sub(r"\1***", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    text = _HEX_SECRET_RE.sub("***", text)
    text = _TG_BOT_TOKEN_RE.sub("***", text)
    text = _BEARER_TOKEN_RE.sub("Bearer ***", text)
    text = _URL_CREDENTIALS_RE.sub(r"\1***@", text)
    text = _WG_PRIVATE_KEY_RE.sub("***", text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def redact_value(value: str) -> str:
    """Redact secret-like patterns without truncation, for individual field values."""
    text = value.replace("\r", " ").replace("\n", " ").strip()
    text = _SECRET_QUERY_RE.sub(r"\1***", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}***", text)
    text = _HEX_SECRET_RE.sub("***", text)
    text = _TG_BOT_TOKEN_RE.sub("***", text)
    text = _BEARER_TOKEN_RE.sub("Bearer ***", text)
    text = _URL_CREDENTIALS_RE.sub(r"\1***@", text)
    text = _WG_PRIVATE_KEY_RE.sub("***", text)
    return text
