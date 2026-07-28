"""Anomaly alerts roll up onto the all-in-one bundle a key belongs to.

Detection is unchanged: the Xray access-log tail still matches child email
labels (``xray_tcp_*`` / ``xray_http_*`` / ``hy2_*``) and the AWG peer sampler
still matches public keys. What changed is the OUTPUT — how the triggered keys
are turned into messages:

* a child of a bundle is reported as the **bundle** (id + display label), never
  as the child's internal label, which the user has never seen;
* several children of the SAME bundle crossing in one window collapse into
  **one** alert with merged IP evidence — a shared subscription URL lights up
  every protocol at once with the same IPs, so five alerts buried the signal
  that one alert sharpens;
* a standalone key (``bundle_id`` NULL) is reported exactly as before.

These tests drive the real service with mocked repositories, and assert on the
message text that actually reaches admins.
"""

import asyncio
import time as time_module
from unittest.mock import AsyncMock

import i18n
from models.dto import KeyBundle, VpnKey
from models.enums import KeyBundleStatus, VpnKeyStatus, VpnKeyType
from services.anomaly_detection import AnomalyDetectionService

# Three IPs in three distinct /24s => 3 unique networks with no IP2ASN DB set
# (normalize_ip degrades to /24 grouping). Matches tests/test_anomaly_detection.py.
IP_A, IP_B, IP_C = "10.0.0.1", "10.1.0.2", "10.2.0.3"
IP_D = "10.3.0.4"


# ------------------------------------------------------------------ fixtures


def _key(
    key_id: int,
    *,
    key_type: VpnKeyType = VpnKeyType.XRAY,
    email_label: str = "xray_tcp_aaaa",
    transport: str = "tcp",
    username: str | None = "alice",
    owner: int = 100,
) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=owner,
        username=username,
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=f"uuid-{key_id}",
        email_label=email_label,
        public_key=None,
        client_ip=None,
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=1,
        revoked_by=None,
        deleted_by=None,
        transport=transport,
    )


def _bundle(bundle_id: int = 7, *, user_id: int = 100, label: str = "bundle_00007") -> KeyBundle:
    return KeyBundle(
        id=bundle_id,
        user_id=user_id,
        label=label,
        note=None,
        status=KeyBundleStatus.ACTIVE,
        # A real, secret-looking token: the assertions below check it never leaks.
        token="s3cr3t-subscription-token-value",
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
    )


class _FakeBundleRepo:
    """Minimal stand-in for KeyBundleRepository with the two methods used here."""

    def __init__(self, *, by_key: dict[int, KeyBundle], children: dict[int, list[VpnKey]]) -> None:
        self._by_key = by_key
        self._children = children
        self.raise_on_lookup = False

    async def get_bundle_of_key(self, key_id: int) -> KeyBundle | None:
        if self.raise_on_lookup:
            raise RuntimeError("bundle lookup exploded")
        return self._by_key.get(key_id)

    async def list_keys_of_bundle(self, bundle_id: int) -> list[VpnKey]:
        return self._children.get(bundle_id, [])


def _service(keys: list[VpnKey], bundles: object | None, **kwargs: object) -> AnomalyDetectionService:
    by_id = {key.id: key for key in keys}
    vpn_keys = AsyncMock()
    # A plain (non-async) side_effect: AsyncMock uses its return value as the
    # awaited result, so this stays a simple id -> key lookup.
    vpn_keys.get_by_id.side_effect = by_id.get
    vpn_keys.list_by_type_statuses.return_value = []
    defaults: dict[str, object] = dict(
        vpn_keys=vpn_keys,
        awg=AsyncMock(),
        xray_service=AsyncMock(),
        awg_service=AsyncMock(),
        admin_ids=frozenset([999]),
        window_seconds=3600,
        unique_nets=3,
        auto_revoke=False,
        cooldown_seconds=7200,
        xray_access_log_path="",
        concurrent_window_seconds=0,
        bundles=bundles,
    )
    defaults.update(kwargs)
    svc = AnomalyDetectionService(**defaults)  # type: ignore[arg-type]
    svc.bot = AsyncMock()
    return svc


def _sent(svc: AnomalyDetectionService) -> list[str]:
    """Every alert body sent to admins, in order."""
    return [call.args[1] for call in svc.bot.send_message.call_args_list]  # type: ignore[union-attr]


# ------------------------------------------------------ a child names its bundle


def test_bundle_child_alert_names_the_bundle_not_the_child() -> None:
    """The alert must speak about the subscription the user holds."""
    child = _key(11, email_label="xray_http_zzzz", transport="http")
    bundle = _bundle()
    svc = _service(
        [child],
        _FakeBundleRepo(by_key={11: bundle}, children={7: [child]}),
        cooldown_seconds=0,
    )

    now = time_module.time()
    for ip in (IP_A, IP_B, IP_C):
        svc._record_ip(11, now - 60, ip)
    asyncio.run(svc._check_thresholds(now))

    (text,) = _sent(svc)
    assert "бандл #7" in text
    assert "bundle_00007" in text
    # The child's internal handles must not appear: the user has never seen them.
    assert "xray_http_zzzz" not in text
    assert "ключ #11" not in text
    # And the sub-URL credential is never anywhere near an alert.
    assert "s3cr3t-subscription-token-value" not in text


def test_bundle_child_alert_still_carries_the_ip_evidence() -> None:
    """Naming the bundle must not cost the detail an admin acts on."""
    child = _key(11)
    svc = _service(
        [child],
        _FakeBundleRepo(by_key={11: _bundle()}, children={7: [child]}),
        cooldown_seconds=0,
    )

    now = time_module.time()
    for ip in (IP_A, IP_B, IP_C):
        svc._record_ip(11, now - 60, ip)
    asyncio.run(svc._check_thresholds(now))

    (text,) = _sent(svc)
    assert "3 уник. сетей" in text
    assert "(3 IP)" in text
    assert "@alice" in text
    assert "10.0.0.0/24" in text


# ------------------------------------------------------------- N children -> ONE


def test_three_children_of_one_bundle_produce_a_single_aggregated_alert() -> None:
    """The shared-URL case: several protocols light up with the same IP set.

    That is the sharing signal, and one rolled-up alert states it more clearly
    than three alerts that each look like an isolated incident.
    """
    tcp = _key(11, email_label="xray_tcp_aaaa", transport="tcp")
    http = _key(12, email_label="xray_http_bbbb", transport="http")
    hy2 = _key(13, key_type=VpnKeyType.HYSTERIA2, email_label="hy2_cccc")
    children = [tcp, http, hy2]
    svc = _service(
        children,
        _FakeBundleRepo(by_key={11: _bundle(), 12: _bundle(), 13: _bundle()}, children={7: children}),
        cooldown_seconds=0,
    )

    now = time_module.time()
    # Same three IPs on every child (one client set, three protocols) plus a
    # fourth seen only on the Hysteria2 child — the union is what gets reported.
    for key_id in (11, 12, 13):
        for ip in (IP_A, IP_B, IP_C):
            svc._record_ip(key_id, now - 60, ip)
    svc._record_ip(13, now - 30, IP_D)

    asyncio.run(svc._check_thresholds(now))

    texts = _sent(svc)
    assert len(texts) == 1, f"expected ONE rolled-up alert, got {len(texts)}: {texts}"
    text = texts[0]
    assert "бандл #7" in text
    # 3 children affected, named by protocol (the two Xray transports stay
    # distinguishable, which is the part worth reading).
    assert "Ключей бандла затронуто: <b>3</b>" in text
    assert "VLESS TCP" in text and "VLESS HTTP" in text and "HYSTERIA2" in text
    # Merged evidence: 4 distinct IPs across 4 distinct /24s, counted once.
    assert "4 уник. сетей" in text
    assert "(4 IP)" in text


def test_rollup_puts_the_whole_bundle_on_cooldown() -> None:
    """A sibling crossing later in the window must not re-alert for the same event.

    Without this the rollup would only defer the duplicates: the sibling is a
    different key_id, so it would pass its own cooldown check.
    """
    tcp = _key(11, email_label="xray_tcp_aaaa", transport="tcp")
    http = _key(12, email_label="xray_http_bbbb", transport="http")
    children = [tcp, http]
    svc = _service(
        children,
        _FakeBundleRepo(by_key={11: _bundle(), 12: _bundle()}, children={7: children}),
        cooldown_seconds=7200,
    )

    now = time_module.time()
    for ip in (IP_A, IP_B, IP_C):
        svc._record_ip(11, now - 600, ip)
    asyncio.run(svc._check_thresholds(now))
    assert len(_sent(svc)) == 1

    # The second child crosses a minute later, well inside the cooldown.
    for ip in (IP_A, IP_B, IP_C):
        svc._record_ip(12, now - 30, ip)
    asyncio.run(svc._check_thresholds(now + 60))
    assert len(_sent(svc)) == 1, "the bundle re-alerted inside its cooldown"


def test_two_different_bundles_are_not_merged() -> None:
    """Aggregation is per bundle — unrelated subscriptions stay separate alerts."""
    first = _key(11)
    second = _key(21, owner=200, username="bob")
    svc = _service(
        [first, second],
        _FakeBundleRepo(
            by_key={11: _bundle(7), 21: _bundle(8, user_id=200, label="bundle_00008")},
            children={7: [first], 8: [second]},
        ),
        cooldown_seconds=0,
    )

    now = time_module.time()
    for key_id in (11, 21):
        for ip in (IP_A, IP_B, IP_C):
            svc._record_ip(key_id, now - 60, ip)
    asyncio.run(svc._check_thresholds(now))

    texts = _sent(svc)
    assert len(texts) == 2
    assert {"бандл #7" in t for t in texts} == {True, False}
    assert {"бандл #8" in t for t in texts} == {True, False}


# ------------------------------------------------------- standalone regress guard


def test_standalone_key_alert_is_unchanged() -> None:
    """The pre-bundle message, byte for byte — no bundle wording anywhere."""
    key = _key(5, email_label="xray_tcp_solo")
    svc = _service([key], _FakeBundleRepo(by_key={}, children={}), cooldown_seconds=0)

    now = time_module.time()
    for ip in (IP_A, IP_B, IP_C):
        svc._record_ip(5, now - 60, ip)
    asyncio.run(svc._check_thresholds(now))

    (text,) = _sent(svc)
    assert text.startswith("⚠️ <b>Аномалия: ключ #5 (XRAY)</b>\n")
    assert "За последние 60 мин: <b>3 уник. сетей</b> (3 IP)" in text
    assert "Владелец: @alice" in text
    assert "бандл" not in text
    assert "Ключей бандла затронуто" not in text


def test_service_without_a_bundle_repository_behaves_exactly_as_before() -> None:
    """`bundles=None` is the constructor default and must be the old behaviour."""
    key = _key(5)
    svc = _service([key], None, cooldown_seconds=0)

    now = time_module.time()
    for ip in (IP_A, IP_B, IP_C):
        svc._record_ip(5, now - 60, ip)
    asyncio.run(svc._check_thresholds(now))

    (text,) = _sent(svc)
    assert text.startswith("⚠️ <b>Аномалия: ключ #5 (XRAY)</b>")


def test_bundle_lookup_failure_falls_back_to_the_per_key_alert() -> None:
    """A repository fault must degrade the alert, never swallow it."""
    key = _key(5)
    repo = _FakeBundleRepo(by_key={5: _bundle()}, children={7: [key]})
    repo.raise_on_lookup = True
    svc = _service([key], repo, cooldown_seconds=0)

    now = time_module.time()
    for ip in (IP_A, IP_B, IP_C):
        svc._record_ip(5, now - 60, ip)
    asyncio.run(svc._check_thresholds(now))

    (text,) = _sent(svc)
    assert text.startswith("⚠️ <b>Аномалия: ключ #5 (XRAY)</b>")


# ------------------------------------------------- Hysteria2 connection-count path


def test_hysteria_conn_count_alert_names_the_bundle() -> None:
    """The other alert kind is addressed to the bundle too (nothing to aggregate:
    a bundle has at most one Hysteria2 child)."""
    child = _key(13, key_type=VpnKeyType.HYSTERIA2, email_label="hy2_cccc")
    vpn_keys = AsyncMock()
    vpn_keys.list_by_type_statuses.side_effect = [[child], []]
    stats = AsyncMock()
    stats.query_online.return_value = {"hy2_cccc": 9}

    svc = _service(
        [child],
        _FakeBundleRepo(by_key={13: _bundle()}, children={7: [child]}),
        vpn_keys=vpn_keys,
        hysteria_stats=stats,
        hysteria2_max_conn=5,
        cooldown_seconds=0,
    )

    asyncio.run(svc._check_hysteria_online(time_module.time()))

    (text,) = _sent(svc)
    assert "бандл #7" in text
    assert "<b>9</b>" in text and "порог: 5" in text
    assert "ключ #13" not in text
    assert "hy2_cccc" not in text


def test_standalone_hysteria_conn_count_alert_is_unchanged() -> None:
    child = _key(13, key_type=VpnKeyType.HYSTERIA2, email_label="hy2_solo")
    vpn_keys = AsyncMock()
    vpn_keys.list_by_type_statuses.side_effect = [[child], []]
    stats = AsyncMock()
    stats.query_online.return_value = {"hy2_solo": 9}

    svc = _service(
        [child],
        _FakeBundleRepo(by_key={}, children={}),
        vpn_keys=vpn_keys,
        hysteria_stats=stats,
        hysteria2_max_conn=5,
        cooldown_seconds=0,
    )

    asyncio.run(svc._check_hysteria_online(time_module.time()))

    (text,) = _sent(svc)
    assert text.startswith("⚠️ <b>Аномалия: ключ #13 (HYSTERIA2)</b>\n")
    assert "Одновременных соединений: <b>9</b> (порог: 5)" in text
    assert "бандл" not in text


# ------------------------------------------------------------------------- i18n


def test_rolled_up_alert_renders_in_both_locales() -> None:
    """Every new string exists in ru and en, and the whole message is one language.

    Structural ru/en parity (key sets, placeholders, tag balance) is enforced for
    the catalogues as a whole by tests/test_i18n_parity.py; this checks that the
    rolled-up alert actually composes in each locale rather than falling back.
    """
    child = _key(11)
    rendered: dict[str, str] = {}
    for locale in ("ru", "en"):
        svc = _service(
            [child],
            _FakeBundleRepo(by_key={11: _bundle()}, children={7: [child]}),
            cooldown_seconds=0,
        )
        now = time_module.time()
        for ip in (IP_A, IP_B, IP_C):
            svc._record_ip(11, now - 60, ip)
        with i18n.use_locale(locale):
            asyncio.run(svc._check_thresholds(now))
        (rendered[locale],) = _sent(svc)

    assert "Аномалия: бандл #7" in rendered["ru"]
    assert "Ключей бандла затронуто" in rendered["ru"]
    assert "За последние 60 мин" in rendered["ru"]

    assert "Anomaly: bundle #7" in rendered["en"]
    assert "Bundle keys affected" in rendered["en"]
    assert "In the last 60 min" in rendered["en"]
    # No leaked identifiers (the i18n fallback returns the raw key on a miss) and
    # no half-translated message.
    assert "anomaly_bundle" not in rendered["en"]
    assert "уник" not in rendered["en"]


def test_new_alert_keys_exist_in_both_catalogues() -> None:
    from i18n import en as en_mod
    from i18n import ru as ru_mod

    expected = {
        "anomaly_bundle_title",
        "anomaly_bundle_protocols",
        "anomaly_bundle_counts",
        "anomaly_bundle_counts_concurrent",
        "anomaly_bundle_owner",
        "anomaly_bundle_networks",
        "anomaly_bundle_networks_window",
        "anomaly_bundle_auto_revoked",
        "anomaly_bundle_revoke_failed",
        "anomaly_bundle_hysteria_conns",
        "anomaly_window_minutes",
        "anomaly_window_seconds",
    }
    assert expected <= set(ru_mod.STRINGS)
    assert expected <= set(en_mod.STRINGS)
