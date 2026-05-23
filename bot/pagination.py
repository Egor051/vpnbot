
from typing import TypeVar

T = TypeVar("T")

MAX_PAGE = 10_000


def page_offset(page: int, page_size: int) -> int:
    return max(min(page, MAX_PAGE), 0) * page_size


def split_page(items: list[T], page_size: int) -> tuple[list[T], bool]:
    return items[:page_size], len(items) > page_size
