from __future__ import annotations

from bot.pagination import page_offset, split_page


def test_page_offset_first_page() -> None:
    # page is 0-indexed: page=0 is the first page
    assert page_offset(0, 10) == 0


def test_page_offset_second_page() -> None:
    assert page_offset(1, 10) == 10


def test_page_offset_third_page() -> None:
    assert page_offset(2, 5) == 10


def test_page_offset_zero_page() -> None:
    assert page_offset(0, 10) == 0


def test_page_offset_negative_page_clamps_to_zero() -> None:
    assert page_offset(-5, 10) == 0


def test_split_page_empty_list() -> None:
    items, has_next = split_page([], 10)
    assert items == []
    assert has_next is False


def test_split_page_fewer_than_page_size() -> None:
    items, has_next = split_page([1, 2, 3], 10)
    assert items == [1, 2, 3]
    assert has_next is False


def test_split_page_exactly_page_size() -> None:
    items, has_next = split_page(list(range(10)), 10)
    assert items == list(range(10))
    assert has_next is False


def test_split_page_one_more_than_page_size() -> None:
    items, has_next = split_page(list(range(11)), 10)
    assert items == list(range(10))
    assert has_next is True


def test_split_page_much_larger_than_page_size() -> None:
    items, has_next = split_page(list(range(100)), 10)
    assert items == list(range(10))
    assert has_next is True


def test_split_page_page_size_one() -> None:
    items, has_next = split_page(["a", "b"], 1)
    assert items == ["a"]
    assert has_next is True


def test_split_page_preserves_item_types() -> None:
    data = [{"id": 1}, {"id": 2}]
    items, has_next = split_page(data, 10)
    assert items == data
    assert has_next is False
