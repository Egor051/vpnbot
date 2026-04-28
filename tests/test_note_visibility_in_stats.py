from __future__ import annotations

from bot.formatters import admin_stats_page_text, traffic_stats_text
from models.dto import KeyTrafficStatsView, VpnKey
from models.enums import VpnKeyStatus, VpnKeyType


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


def test_owner_sees_own_key_note_in_stats() -> None:
    text = traffic_stats_text(_view(_key(email_label="key-label")), viewer_user_id=100)

    assert "owner private note" in text
    assert "Заметка: owner private note" in text


def test_foreign_viewer_does_not_see_note_or_note_fallback_label_in_stats() -> None:
    text = traffic_stats_text(_view(_key()), viewer_user_id=1)

    assert "owner private note" not in text
    assert "<code>AWG #10</code>" in text


def test_empty_note_is_not_rendered_in_stats() -> None:
    text = traffic_stats_text(_view(_key(note=None, email_label="key-label")), viewer_user_id=100)

    assert "Заметка:" not in text


def test_admin_monitoring_hides_foreign_notes_and_shows_own_notes() -> None:
    foreign_key = _key(key_id=10, owner_user_id=100, note="foreign note")
    own_key = _key(key_id=11, owner_user_id=1, note="own note", email_label="own-label")

    text = admin_stats_page_text([_view(foreign_key), _view(own_key)], page=0, viewer_user_id=1)

    assert "foreign note" not in text
    assert "own note" in text
