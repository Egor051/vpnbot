
import json
import logging
from enum import Enum
from typing import TypeVar

logger = logging.getLogger(__name__)

EnumT = TypeVar("EnumT", bound=Enum)


def _clamp_limit(limit: int, max_: int = 500) -> int:
    """Clamp limit to [0, max_] to prevent unbounded full-table scans."""
    return max(0, min(limit, max_))


def _clamp_offset(offset: int) -> int:
    """Clamp offset to >= 0."""
    return max(0, offset)


def json_loads_dict(value: str, source: str) -> dict[str, object]:
    """Parse a JSON object string, returning a sentinel dict on corruption."""
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        logger.warning("Некорректный JSON в %s", source)
        return {"_corrupted": True}
    return data if isinstance(data, dict) else {}


def enum_value(enum_cls: type[EnumT], value: str, field: str) -> EnumT:
    """Convert a stored string into an enum member, raising on invalid values."""
    try:
        return enum_cls(value)
    except ValueError as exc:
        raise RuntimeError(
            f"Некорректное значение {field} в SQLite: {value!r}. "
            "Сделайте backup DB и исправьте повреждённую запись вручную."
        ) from exc
