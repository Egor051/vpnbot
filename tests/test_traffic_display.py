"""Every screen that shows traffic must show the same number for the same key.

Four renderers read ``TrafficStats.available`` and each drew its own conclusion:
the key card printed the accumulated totals and marked them stale, the bundle
card hid them and summed a 0 into the subscription total, the admin list and the
user card had two more variants. So a subscription read «0 B» while the key
listed inside it, one tap away, read the real figure.

They all go through ``bot.formatters.traffic_figures`` now. The rule it encodes:
the numbers ALWAYS come from the accumulated totals, and ``available`` decides
only whether they carry a staleness mark. A zero appears only when the total
really is zero.
"""
from __future__ import annotations

from bot.bundles import bundle_stats_block
from bot.formatters import (
    admin_stats_page_text,
    sum_traffic_figures,
    traffic_figures,
    traffic_stats_block,
    user_card_text,
)
from i18n import t
from models.dto import KeyTrafficStatsView, TrafficStats, User, VpnKey
from models.enums import UserRole, VpnKeyStatus, VpnKeyType

STALE_SNAPSHOT = "2026-08-09T09:00:00+00:00"


def _key(key_id: int = 1, key_type: VpnKeyType = VpnKeyType.XRAY) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=100,
        username="user",
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid="00000000-0000-4000-8000-000000000001",
        email_label=f"label-{key_id}",
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        created_by=100,
        revoked_by=None,
        deleted_by=None,
    )


def _stale_stats(key_id: int = 1, downloaded: int = 3_221_225_472, uploaded: int = 1_073_741_824) -> TrafficStats:
    """Real accumulated totals whose latest poll did not land: 3 GB down / 1 GB up."""
    return TrafficStats(
        key_id=key_id,
        downloaded_bytes=downloaded,
        uploaded_bytes=uploaded,
        last_raw_downloaded_bytes=downloaded,
        last_raw_uploaded_bytes=uploaded,
        last_success_at=STALE_SNAPSHOT,
        last_attempt_at="2026-08-09T10:00:00+00:00",
        available=False,
        unavailable_reason="Не удалось получить данные от backend",
        source="xray statsquery",
    )


def _user() -> User:
    return User(
        telegram_user_id=100,
        username="user",
        first_name="User",
        role=UserRole.APPROVED_USER,
        created_at="2026-08-01T00:00:00+00:00",
        updated_at="2026-08-01T00:00:00+00:00",
        note=None,
        blocked_at=None,
    )


def _has_figures(text: str) -> bool:
    """The 3 GB / 1 GB pair, as format_bytes renders it."""
    return "3.00 GB" in text and "1.00 GB" in text


def test_key_card_prints_stale_figures_with_a_mark() -> None:
    text = "\n".join(traffic_stats_block(_stale_stats()))
    assert _has_figures(text)
    assert t("stats_unavailable_now") in text


def test_bundle_card_prints_stale_figures_instead_of_hiding_them() -> None:
    """The headline bug: a subscription showed «недоступно» and 0 B for real traffic."""
    views = [KeyTrafficStatsView(key=_key(1), owner=None, stats=_stale_stats(1))]
    text = "\n".join(bundle_stats_block(views))
    assert _has_figures(text)
    assert t("bundle_stats_unavailable") not in text
    assert t("stats_stale_mark", at="").split("(")[0].strip() in text


def test_admin_stats_page_prints_stale_figures_with_a_mark() -> None:
    views = [KeyTrafficStatsView(key=_key(1), owner=None, stats=_stale_stats(1))]
    text = admin_stats_page_text(views, page=0, viewer_user_id=100)
    assert _has_figures(text)
    assert t("stats_unavailable_short") not in text


def test_user_card_prints_stale_figures_with_a_mark() -> None:
    text = user_card_text(_user(), [_key(1)], {1: _stale_stats(1)}, viewer_user_id=100)
    assert _has_figures(text)


def test_a_bundle_total_is_the_sum_of_the_keys_listed_under_it() -> None:
    """One stale child used to drop out of the total; now nothing is dropped."""
    fresh = TrafficStats(
        key_id=2,
        downloaded_bytes=1_073_741_824,
        uploaded_bytes=0,
        last_raw_downloaded_bytes=1_073_741_824,
        last_raw_uploaded_bytes=0,
        last_success_at="2026-08-09T10:00:00+00:00",
        last_attempt_at="2026-08-09T10:00:00+00:00",
        available=True,
        unavailable_reason=None,
        source="hysteria2 trafficStats",
    )
    views = [
        KeyTrafficStatsView(key=_key(1, VpnKeyType.XRAY), owner=None, stats=_stale_stats(1)),
        KeyTrafficStatsView(key=_key(2, VpnKeyType.HYSTERIA2), owner=None, stats=fresh),
    ]
    text = "\n".join(bundle_stats_block(views))
    # 3 GB (stale VLESS) + 1 GB (fresh hy2) down, 1 GB up.
    assert "4.00 GB" in text
    total = sum_traffic_figures(view.stats for view in views)
    assert total.downloaded_bytes == 3_221_225_472 + 1_073_741_824
    assert total.uploaded_bytes == 1_073_741_824
    # The group is stale because a part of it is, and the mark names the oldest
    # confirmation — the point past which the sum stopped being complete.
    assert total.stale is True
    assert total.last_success_at == STALE_SNAPSHOT


def test_a_real_zero_is_still_printed_as_zero() -> None:
    """A key that has moved nothing shows 0, not "no data" — that is the hy2 fix."""
    measured_zero = TrafficStats(
        key_id=1,
        downloaded_bytes=0,
        uploaded_bytes=0,
        last_raw_downloaded_bytes=None,
        last_raw_uploaded_bytes=None,
        last_success_at=None,
        last_attempt_at="2026-08-09T10:00:00+00:00",
        available=True,
        unavailable_reason=None,
        source="xray statsquery",
    )
    figures = traffic_figures(measured_zero)
    assert figures.known is True
    assert figures.total_bytes == 0
    assert "0" in "\n".join(traffic_stats_block(measured_zero))


def test_a_key_that_was_never_measured_says_so_instead_of_printing_zero() -> None:
    never = TrafficStats(
        key_id=1,
        downloaded_bytes=0,
        uploaded_bytes=0,
        last_raw_downloaded_bytes=None,
        last_raw_uploaded_bytes=None,
        last_success_at=None,
        last_attempt_at="2026-08-09T10:00:00+00:00",
        available=False,
        unavailable_reason="Не удалось получить данные от backend",
        source="xray statsquery",
    )
    assert traffic_figures(never).known is False
    assert t("stats_not_available_yet") in "\n".join(traffic_stats_block(never))
    assert traffic_figures(None).known is False
