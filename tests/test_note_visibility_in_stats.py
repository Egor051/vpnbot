
from types import SimpleNamespace

from bot.formatters import (
    admin_stats_page_text,
    key_detail_text,
    key_display_label,
    key_note_for_viewer,
    keys_page_text,
    traffic_stats_text,
    user_card_text,
)
from models.dto import KeyTrafficStatsView, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType


def _key(
    *,
    key_id: int = 10,
    owner_user_id: int = 100,
    note: str | None = "owner private note",
    email_label: str | None = None,
    public_key: str | None = None,
) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=owner_user_id,
        username="owner",
        key_type=VpnKeyType.AWG,
        status=VpnKeyStatus.ACTIVE,
        note=note,
        uuid=None,
        email_label=email_label,
        public_key=public_key,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="2026-04-28T12:00:00+00:00",
        updated_at="2026-04-28T12:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        created_by=owner_user_id,
        revoked_by=None,
        deleted_by=None,
    )


def _view(key: VpnKey) -> KeyTrafficStatsView:
    return KeyTrafficStatsView(key=key, owner=None, stats=None)


def test_owner_sees_own_key_note_in_key_list() -> None:
    text = keys_page_text([_key(email_label="key-label")], page=0, viewer_user_id=100)

    assert "owner private note" in text
    assert "Заметка: owner private note" in text


def test_owner_sees_own_key_note_in_key_details() -> None:
    text = key_detail_text(_key(email_label="key-label"), viewer_user_id=100)

    assert "owner private note" in text
    assert "Заметка: owner private note" in text


def test_foreign_viewer_does_not_see_note_in_key_list_or_details() -> None:
    key = _key(note="foreign note", email_label="key-label")

    list_text = keys_page_text([key], page=0, viewer_user_id=1, owner_user_id=100)
    detail_text = key_detail_text(key, viewer_user_id=1)

    assert "foreign note" not in list_text
    assert "foreign note" not in detail_text
    assert "Заметка: нет" in list_text
    assert "Заметка: нет" in detail_text


def test_superadmin_does_not_see_foreign_note_in_key_list_or_details() -> None:
    key = _key(note="foreign note", email_label="key-label")

    list_text = keys_page_text([key], page=0, viewer_user_id=1, owner_user_id=100)
    detail_text = key_detail_text(key, viewer_user_id=1)

    assert "foreign note" not in list_text
    assert "foreign note" not in detail_text


def test_key_display_label_does_not_use_foreign_note_as_fallback() -> None:
    key = _key(note="fallback note", email_label=None, public_key=None)

    assert key_display_label(key, viewer_user_id=1) == "AWG #10"
    assert key_display_label(key, viewer_user_id=100) == "fallback note"
    assert key_display_label(key) == "AWG #10"


def test_note_used_as_fallback_label_is_not_duplicated_in_key_list_or_details() -> None:
    key = _key()

    list_text = keys_page_text([key], page=0, viewer_user_id=100)
    detail_text = key_detail_text(key, viewer_user_id=100)

    assert list_text.count("owner private note") == 1
    assert detail_text.count("owner private note") == 1
    assert "Заметка: owner private note" not in list_text
    assert "Заметка: owner private note" not in detail_text


def test_admin_user_card_hides_foreign_note_fallback_label() -> None:
    text = user_card_text(
        SimpleNamespace(telegram_user_id=100, username="owner", role=UserRole.APPROVED_USER, updated_at="now"),
        keys=[_key(note="foreign note", email_label=None, public_key=None)],
        viewer_user_id=1,
    )

    assert "foreign note" not in text
    assert "<code>AWG #10</code>" in text


def test_owner_sees_own_key_note_in_stats() -> None:
    text = traffic_stats_text(_view(_key(email_label="key-label")), viewer_user_id=100)

    assert "owner private note" in text
    assert "Заметка: owner private note" in text


def test_foreign_viewer_does_not_see_note_or_note_fallback_label_in_stats() -> None:
    text = traffic_stats_text(_view(_key()), viewer_user_id=1)

    assert "owner private note" not in text
    assert "<code>AWG #10</code>" in text


def test_owner_note_used_as_fallback_label_is_not_duplicated_in_stats() -> None:
    text = traffic_stats_text(_view(_key()), viewer_user_id=100)

    assert text.count("owner private note") == 1
    assert "Заметка: owner private note" not in text


def test_empty_note_is_not_rendered_in_stats() -> None:
    text = traffic_stats_text(_view(_key(note=None, email_label="key-label")), viewer_user_id=100)

    assert "Заметка:" not in text


def test_explicit_note_owner_id_takes_precedence_over_key_owner_id() -> None:
    key = SimpleNamespace(note="delegated note", note_owner_id=200, owner_user_id=100)

    assert key_note_for_viewer(key, 200) == "delegated note"  # type: ignore[arg-type]
    assert key_note_for_viewer(key, 100) is None  # type: ignore[arg-type]


def test_missing_note_owner_id_falls_back_to_key_owner_id() -> None:
    key = SimpleNamespace(note="owner note", owner_user_id=100)

    assert key_note_for_viewer(key, 100) == "owner note"  # type: ignore[arg-type]
    assert key_note_for_viewer(key, 1) is None  # type: ignore[arg-type]


def test_admin_monitoring_hides_foreign_notes_and_shows_own_notes() -> None:
    foreign_key = _key(key_id=10, owner_user_id=100, note="foreign note")
    own_key = _key(key_id=11, owner_user_id=1, note="own note", email_label="own-label")

    text = admin_stats_page_text([_view(foreign_key), _view(own_key)], page=0, viewer_user_id=1)

    assert "foreign note" not in text
    assert "own note" in text


def test_superadmin_monitoring_hides_foreign_note() -> None:
    text = admin_stats_page_text([_view(_key(owner_user_id=100, note="foreign note"))], page=0, viewer_user_id=1)

    assert "foreign note" not in text
