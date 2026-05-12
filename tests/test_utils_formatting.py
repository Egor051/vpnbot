from __future__ import annotations

from datetime import datetime, timezone

from utils.formatting import (
    code,
    format_bytes,
    format_greeting_name,
    format_msk_datetime,
    format_user_display,
    h,
    pre,
)


def test_h_escapes_html_special_chars() -> None:
    assert h("<script>alert('xss')</script>") == "&lt;script&gt;alert('xss')&lt;/script&gt;"


def test_h_leaves_plain_text_unchanged() -> None:
    assert h("hello world") == "hello world"


def test_h_converts_non_string_to_str() -> None:
    assert h(42) == "42"
    assert h(None) == "None"


def test_code_wraps_in_code_tag() -> None:
    assert code("hello") == "<code>hello</code>"


def test_code_escapes_content() -> None:
    assert code("<b>") == "<code>&lt;b&gt;</code>"


def test_pre_wraps_in_pre_tag() -> None:
    assert pre("hello") == "<pre>hello</pre>"


def test_pre_escapes_content() -> None:
    assert pre("<b>") == "<pre>&lt;b&gt;</pre>"


def test_format_bytes_none_returns_no_data() -> None:
    assert format_bytes(None) == "нет данных"


def test_format_bytes_zero() -> None:
    assert format_bytes(0) == "0 B"


def test_format_bytes_bytes_range() -> None:
    assert format_bytes(500) == "500 B"
    assert format_bytes(1023) == "1023 B"


def test_format_bytes_kilobytes() -> None:
    assert format_bytes(1024) == "1.00 KB"
    assert format_bytes(2048) == "2.00 KB"


def test_format_bytes_megabytes() -> None:
    assert format_bytes(1024 * 1024) == "1.00 MB"


def test_format_bytes_gigabytes() -> None:
    assert format_bytes(1024 ** 3) == "1.00 GB"


def test_format_bytes_terabytes() -> None:
    assert format_bytes(1024 ** 4) == "1.00 TB"


def test_format_bytes_negative_treated_as_zero() -> None:
    assert format_bytes(-100) == "0 B"


def test_format_msk_datetime_none_returns_no_data() -> None:
    assert format_msk_datetime(None) == "нет данных"


def test_format_msk_datetime_empty_string_returns_no_data() -> None:
    assert format_msk_datetime("") == "нет данных"


def test_format_msk_datetime_invalid_returns_raw() -> None:
    assert format_msk_datetime("not-a-date") == "not-a-date"


def test_format_msk_datetime_naive_iso() -> None:
    result = format_msk_datetime("2026-01-15T10:00:00")
    assert "15.01.2026" in result
    assert "МСК" in result


def test_format_msk_datetime_utc_converts_to_msk() -> None:
    # UTC+3 = MSK; 07:00 UTC → 10:00 MSK
    result = format_msk_datetime("2026-01-15T07:00:00+00:00")
    assert "15.01.2026" in result
    assert "10:00:00" in result
    assert "МСК" in result


def test_format_user_display_both_none() -> None:
    assert format_user_display(None, None) == "неизвестный пользователь"


def test_format_user_display_id_only() -> None:
    assert format_user_display(123456, None) == "tg123456"


def test_format_user_display_username_without_at() -> None:
    assert format_user_display(123, "testuser") == "@testuser"


def test_format_user_display_username_with_at_stripped() -> None:
    assert format_user_display(123, "@testuser") == "@testuser"


def test_format_user_display_username_takes_priority_over_id() -> None:
    assert format_user_display(999, "alice") == "@alice"


def test_format_user_display_empty_username_falls_back_to_id() -> None:
    assert format_user_display(123, "") == "tg123"


def test_format_user_display_at_only_falls_back_to_id() -> None:
    # "@" stripped → empty string → fall back to id
    assert format_user_display(123, "@") == "tg123"


def test_format_greeting_name_first_name_preferred() -> None:
    assert format_greeting_name(1, "Alice", "bob") == "Alice"


def test_format_greeting_name_username_when_no_first_name() -> None:
    assert format_greeting_name(1, None, "@bob") == "bob"


def test_format_greeting_name_username_without_at() -> None:
    assert format_greeting_name(1, None, "charlie") == "charlie"


def test_format_greeting_name_id_fallback() -> None:
    assert format_greeting_name(42, None, None) == "42"


def test_format_greeting_name_empty_first_name_falls_through() -> None:
    # Empty string is falsy → falls through to username
    assert format_greeting_name(1, "", "@bob") == "bob"
