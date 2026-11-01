"""Opt-in spiderX rotation for the VLESS children of an all-in-one bundle.

``XRAY_SPIDER_X_ROTATION_HOURS`` > 0 makes a bundle child's ``spx`` walk the pool
over time. Covered here, without a database:

* the pure walk (:func:`utils.spider_x.rotating_spider_x`): the specified formula,
  stability inside an epoch, a change exactly at its boundary, no repeat between
  adjacent epochs, full coverage of the pool, per-key switch moments;
* cross-process determinism — the bot and the subscription endpoint are separate
  processes, so the value must not depend on ``PYTHONHASHSEED``;
* the setting's validation;
* the seam on ``XrayService`` (``link_spider_x`` / ``connection_link``): off means
  byte-for-byte the stored-spx link, standalone keys never rotate.

The endpoint-versus-bot agreement on a real bundle lives in
``test_subscription_server.py``, next to the harness that provisions one.
"""

import ast
import asyncio
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import quote

import pytest

from adapters.clock import ClockProvider
from config.settings import Settings, SettingsError, load_settings
from models.dto import VpnKey
from models.enums import VpnKeyStatus, VpnKeyType
from services.xray import XrayService
from utils.spider_x import pick_spider_x, rotating_spider_x

ROOT = Path(__file__).resolve().parents[1]

UUID_A = "11111111-2222-4333-8444-555555555555"
UUID_B = "66666666-7777-4888-9999-000000000000"
HOUR = 3600
DAY = 24 * HOUR
# 2027-01-15T08:00:00Z — an arbitrary, fixed instant; every test is relative to it.
T0 = 1_800_000_000


def _uuids(count: int) -> list[str]:
    return [f"{i:08x}-0000-4000-8000-{i:012x}" for i in range(1, count + 1)]


def _pool(size: int) -> tuple[str, ...]:
    return tuple(f"/p{i}" for i in range(size))


def _reference(uuid_value: str, pool: Sequence[str], period: int, now: int) -> str:
    """The formula exactly as specified, transcribed independently of the code
    under test (hexdigest → int instead of from_bytes, plain sort)."""

    def h(text: str) -> int:
        return int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16)

    order = sorted(pool, key=lambda path: h(f"{uuid_value}|{path}"))
    phase = h(f"{uuid_value}|phase") % period
    epoch = (now + phase) // period
    start = h(f"{uuid_value}|start") % len(pool)
    return order[(start + epoch) % len(pool)]


def _switch_seconds(uuid_value: str, pool: Sequence[str], period: int, start: int, span: int) -> list[int]:
    """Every second ``t`` in ``(start, start + span]`` where the value differs from ``t - 1``.

    Found by scanning the public function — it does not peek at ``phase``.
    """
    previous = rotating_spider_x(uuid_value, pool, period, start)
    switches: list[int] = []
    for t in range(start + 1, start + span + 1):
        current = rotating_spider_x(uuid_value, pool, period, t)
        if current != previous:
            switches.append(t)
        previous = current
    return switches


# ── the pure walk ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("size", [2, 3, 5, 7, 11])
@pytest.mark.parametrize("period", [1, HOUR, DAY, 720 * HOUR])
def test_walk_is_exactly_the_specified_formula(size: int, period: int) -> None:
    pool = _pool(size)
    for uuid_value in _uuids(6):
        for offset in (0, 1, period // 3, period - 1, period, 7 * period + 13, 400 * period):
            now = T0 + offset
            assert rotating_spider_x(uuid_value, pool, period, now) == _reference(uuid_value, pool, period, now)


def test_walk_is_pinned_to_known_values() -> None:
    """Golden values: a change to the walk re-shuffles every client's spx at once,
    so it must be a deliberate, visible edit of this test — never a side effect."""
    pool = ("/", "/api", "/blog/", "/static/app.js")
    assert [rotating_spider_x(UUID_A, pool, DAY, T0 + day * DAY) for day in range(6)] == [
        "/",
        "/api",
        "/static/app.js",
        "/blog/",
        "/",
        "/api",
    ]
    assert [rotating_spider_x(UUID_B, pool, DAY, T0 + day * DAY) for day in range(4)] == [
        "/blog/",
        "/api",
        "/static/app.js",
        "/",
    ]


def test_single_entry_pool_is_a_constant() -> None:
    for uuid_value in _uuids(5):
        for offset in range(0, 50 * DAY, 7 * HOUR + 11):
            assert rotating_spider_x(uuid_value, ("/only",), DAY, T0 + offset) == "/only"


@pytest.mark.parametrize("size", [2, 3, 7, 11])
def test_adjacent_epochs_never_repeat_and_any_n_epochs_cover_the_pool(size: int) -> None:
    pool = _pool(size)
    epochs = 240
    for uuid_value in _uuids(8):
        # T0 + k*period lands in k consecutive epochs, whatever the key's phase is.
        values = [rotating_spider_x(uuid_value, pool, DAY, T0 + k * DAY) for k in range(epochs)]
        assert set(values) <= set(pool)
        for k in range(epochs - 1):
            assert values[k] != values[k + 1], (uuid_value, k)
        for k in range(epochs - size + 1):
            assert set(values[k : k + size]) == set(pool), (uuid_value, k)


def test_value_is_stable_inside_an_epoch_and_changes_exactly_at_its_boundary() -> None:
    pool = _pool(5)
    period = HOUR
    for uuid_value in _uuids(4):
        switches = _switch_seconds(uuid_value, pool, period, T0, 3 * period)
        # Exactly one switch per period, exactly one period apart.
        assert len(switches) == 3, (uuid_value, switches)
        assert switches[1] - switches[0] == period
        assert switches[2] - switches[1] == period
        boundary = switches[0]
        inside = rotating_spider_x(uuid_value, pool, period, boundary)
        for t in (boundary, boundary + 1, boundary + period // 2, boundary + period - 1):
            assert rotating_spider_x(uuid_value, pool, period, t) == inside
        assert rotating_spider_x(uuid_value, pool, period, boundary - 1) != inside
        assert rotating_spider_x(uuid_value, pool, period, boundary + period) != inside


def test_keys_switch_at_their_own_moment() -> None:
    """``phase`` spreads the switches over the period: a subscription's keys (and
    every user's) must not all flip at the same second."""
    pool = _pool(4)
    period = HOUR
    uuids = _uuids(20)
    offsets: list[int] = []
    for uuid_value in uuids:
        switches = _switch_seconds(uuid_value, pool, period, T0, period)
        assert len(switches) == 1
        offset = switches[0] % period
        # It is exactly the specified phase: the epoch starts where now + phase ≡ 0.
        phase = int(hashlib.sha256(f"{uuid_value}|phase".encode()).hexdigest(), 16) % period
        assert offset == (-phase) % period
        offsets.append(offset)
    assert len(set(offsets)) == len(offsets), "two keys share a switch second"
    # And two specific keys, on the daily period the feature is meant for.
    day_a = int(hashlib.sha256(f"{UUID_A}|phase".encode()).hexdigest(), 16) % DAY
    day_b = int(hashlib.sha256(f"{UUID_B}|phase".encode()).hexdigest(), 16) % DAY
    assert day_a != day_b


def test_duplicate_pool_entries_cannot_repeat_a_value_in_adjacent_epochs() -> None:
    pool = ("/a", "/a", "/b", "/b", "/c")
    for uuid_value in _uuids(5):
        values = [rotating_spider_x(uuid_value, pool, DAY, T0 + k * DAY) for k in range(60)]
        assert set(values) == {"/a", "/b", "/c"}
        assert all(values[k] != values[k + 1] for k in range(len(values) - 1))
    # A pool that is one path repeated is that path.
    assert rotating_spider_x(UUID_A, ("/x", "/x"), DAY, T0) == "/x"


def test_walk_refuses_nothing_to_rotate() -> None:
    with pytest.raises(ValueError):
        rotating_spider_x(UUID_A, (), DAY, T0)
    for period in (0, -1):
        with pytest.raises(ValueError):
            rotating_spider_x(UUID_A, ("/a", "/b"), period, T0)


def test_pick_spider_x_is_unchanged() -> None:
    """The stored per-key value (what standalone keys and rotation-off use) is still
    the plain UUID hash it always was."""
    pool = ("/", "/api", "/blog/", "/static/app.js")
    digest = hashlib.sha256(UUID_A.encode("utf-8")).digest()
    assert pick_spider_x(UUID_A, pool) == pool[int.from_bytes(digest, "big") % len(pool)]
    assert pick_spider_x(UUID_A, ()) is None


# ── cross-process determinism ─────────────────────────────────────────────────


_PROBE = """
import json
from utils.spider_x import rotating_spider_x
pool = ("/", "/api", "/blog/", "/static/app.js", "/v2/feed", "/img/a.png", "/x")
values = [
    rotating_spider_x(f"{i:08x}-0000-4000-8000-{i:012x}", pool, period, start + k * period)
    for i in range(1, 9)
    for period in (3600, 86400, 720 * 3600)
    for start in (1800000000, 1800000017)
    for k in range(30)
]
print(json.dumps({"values": values, "salted_hash": hash("spider-x-probe")}))
"""


def _probe(seed: str) -> dict[str, object]:
    env = {**os.environ, "PYTHONHASHSEED": seed}
    completed = subprocess.run(  # noqa: S603 - fixed argv, our own interpreter
        [sys.executable, "-c", _PROBE],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    result: dict[str, object] = json.loads(completed.stdout)
    return result


def test_value_does_not_depend_on_the_process_hash_seed() -> None:
    """The bot and the subscription endpoint are two processes, each with its own
    hash salt. If the walk used ``hash()`` the two would serve different values for
    the same key at the same second."""
    runs = {seed: _probe(seed) for seed in ("0", "1", "4242", "random")}
    # The probe is not vacuous: the seeds really do change the salted hash.
    assert runs["0"]["salted_hash"] != runs["1"]["salted_hash"]
    reference = runs["0"]["values"]
    for seed, run in runs.items():
        assert run["values"] == reference, f"PYTHONHASHSEED={seed} changed the walk"
    # …and the subprocesses agree with this process too.
    pool = ("/", "/api", "/blog/", "/static/app.js", "/v2/feed", "/img/a.png", "/x")
    here = [
        rotating_spider_x(f"{i:08x}-0000-4000-8000-{i:012x}", pool, period, start + k * period)
        for i in range(1, 9)
        for period in (3600, 86400, 720 * 3600)
        for start in (1800000000, 1800000017)
        for k in range(30)
    ]
    assert here == reference


def test_spider_x_module_uses_neither_builtin_hash_nor_random() -> None:
    tree = ast.parse((ROOT / "utils" / "spider_x.py").read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "hash", "built-in hash() is salted per process"
    assert imported <= {"hashlib", "collections"}, imported


# ── the setting ───────────────────────────────────────────────────────────────


def _base_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("BOT_TOKEN", "token")
    monkeypatch.setenv("ADMIN_IDS", "1")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("XRAY_PUBLIC_HOST", "vpn.example.com")
    monkeypatch.setenv("XRAY_REALITY_PUBLIC_KEY", "public")
    monkeypatch.setenv("XRAY_SNI", "example.com")
    monkeypatch.setenv("XRAY_SHORT_ID", "abcd")


def test_rotation_defaults_to_off(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    assert load_settings().xray_spider_x_rotation_hours == 0
    monkeypatch.setenv("XRAY_SPIDER_X_ROTATION_HOURS", "")
    assert load_settings().xray_spider_x_rotation_hours == 0


@pytest.mark.parametrize(("raw", "expected"), [("0", 0), ("1", 1), ("24", 24), (" 168 ", 168), ("720", 720)])
def test_rotation_accepts_its_range(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: str, expected: int
) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XRAY_SPIDER_X_POOL", "/,/api")
    monkeypatch.setenv("XRAY_SPIDER_X_ROTATION_HOURS", raw)
    assert load_settings().xray_spider_x_rotation_hours == expected


@pytest.mark.parametrize("raw", ["721", "-1", "100000", "abc", "1.5", "24h"])
def test_rotation_outside_its_range_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: str
) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XRAY_SPIDER_X_POOL", "/,/api")
    monkeypatch.setenv("XRAY_SPIDER_X_ROTATION_HOURS", raw)
    with pytest.raises(SettingsError, match="XRAY_SPIDER_X_ROTATION_HOURS"):
        load_settings()


def test_rotation_without_a_pool_loads_and_is_inert(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("XRAY_SPIDER_X_ROTATION_HOURS", "24")
    settings = load_settings()
    assert settings.xray_spider_x_rotation_hours == 24
    assert settings.xray_spider_x_pool == ()
    service = _service(settings)
    key = _key(spider_x=None)
    assert service.link_spider_x(key, bundle_member=True, now_unix=T0) is None
    assert "spx" not in service.connection_link(key, bundle_member=True, now_unix=T0)


# ── the seam on XrayService ───────────────────────────────────────────────────


_POOL = ("/", "/api", "/blog/", "/static/app.js", "/v2/feed")


def _settings(tmp_path: Path, *, pool: tuple[str, ...] = _POOL, hours: int = 0) -> Settings:
    return Settings(
        bot_token="token",
        admin_ids=frozenset({1}),
        db_path=tmp_path / "vpn.db",
        log_dir=tmp_path / "logs",
        bot_lock_path=tmp_path / "vpn.lock",
        bot_drop_pending_updates=False,
        xray_config_path=tmp_path / "xray.json",
        xray_service_name="xray",
        xray_apply_mode="reload",
        xray_inbound_tag="vless-in",
        xray_public_host="vpn.example.com",
        xray_public_port=443,
        xray_reality_public_key="public",
        xray_sni="example.com",
        xray_flow="xtls-rprx-vision",
        xray_fingerprint="chrome",
        xray_network_type="tcp",
        xray_short_id="abcd",
        xray_manage_short_ids=False,
        xray_allow_restart_on_rollback=False,
        xray_stats_server="",
        awg_config_path=tmp_path / "awg.conf",
        awg_interface="awg0",
        awg_network="10.0.0.0/24",
        awg_server_address="10.0.0.1",
        awg_endpoint_host="vpn.example.com",
        awg_endpoint_port=443,
        awg_server_public_key="server-public",
        awg_client_dns="1.1.1.1",
        awg_mtu=None,
        awg_allowed_ips="0.0.0.0/0, ::/0",
        awg_persistent_keepalive=25,
        awg_use_preshared_key=True,
        default_proxy_type="",
        default_proxy_host="",
        default_proxy_port=None,
        default_proxy_login="",
        default_proxy_password="",
        default_proxy_note="",
        audit_retention_days=180,
        config_backup_keep_last=20,
        xray_xhttp_enabled=True,
        xray_xhttp_inbound_tag="vless-xhttp-reality",
        xray_xhttp_port=8443,
        xray_xhttp_path="/v1/messages/stream",
        xray_xhttp_mode="stream-one",
        xray_spider_x_pool=pool,
        xray_spider_x_rotation_hours=hours,
    )


class _ForbiddenRepo:
    """A repository the code under test must not touch."""

    async def is_bundle_member(self, key_id: int) -> bool:
        raise AssertionError("the bundle-membership query ran although rotation is off")


class _MembershipRepo:
    def __init__(self, members: set[int]) -> None:
        self.members = members
        self.asked: list[int] = []

    async def is_bundle_member(self, key_id: int) -> bool:
        self.asked.append(key_id)
        return key_id in self.members


def _forbidden_clock() -> float:
    raise AssertionError("the clock was read although nothing rotates")


def _service(settings: Settings, *, repo: object | None = None, unix_clock: object = None) -> XrayService:
    return XrayService(
        vpn_keys=repo if repo is not None else _ForbiddenRepo(),  # type: ignore[arg-type]
        users=object(),  # type: ignore[arg-type]
        adapter=object(),  # type: ignore[arg-type]
        settings=settings,
        clock=ClockProvider(),
        ids=object(),  # type: ignore[arg-type]
        audit=object(),  # type: ignore[arg-type]
        unix_clock=unix_clock if unix_clock is not None else _forbidden_clock,  # type: ignore[arg-type]
    )


def _key(
    key_id: int = 7,
    *,
    uuid_value: str = UUID_A,
    spider_x: str | None = "/api",
    transport: str = "tcp",
    profile: str = "base",
) -> VpnKey:
    label = "xray_tcp_A0001" if transport == "tcp" else f"xray_http_{profile}_A0001"
    return VpnKey(
        id=key_id,
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.XRAY,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=uuid_value,
        email_label=label,
        public_key=None,
        client_ip=None,
        payload={"uuid": uuid_value, "email_label": label, "short_id": "abcd", "spider_x": spider_x},
        public_payload={"short_id": "abcd"},
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
        revoked_at=None,
        deleted_at=None,
        created_by=1,
        revoked_by=None,
        deleted_by=None,
        transport=transport,
        xhttp_profile=profile,
        spider_x=spider_x,
    )


_FAMILIES = [("tcp", "base"), ("http", "base"), ("http", "multi"), ("http", "antisib")]


def _spx(link: str) -> str:
    """The encoded ``spx`` value: always the last query parameter, before ``#``."""
    head = link.split("#", 1)[0]
    assert "&spx=" in head
    return head.rsplit("&spx=", 1)[1]


def _without_spx(link: str) -> str:
    head, fragment = link.split("#", 1)
    return f"{head.rsplit('&spx=', 1)[0]}#{fragment}"


@pytest.mark.parametrize(("transport", "profile"), _FAMILIES)
def test_rotation_off_renders_the_stored_link_byte_for_byte(tmp_path: Path, transport: str, profile: str) -> None:
    """hours=0: a bundle member and a standalone key render the same, stored-spx link
    — without reading the clock and without asking the database anything."""
    service = _service(_settings(tmp_path, hours=0))
    key = _key(transport=transport, profile=profile)
    standalone = service.connection_link(key)
    assert service.connection_link(key, bundle_member=True) == standalone
    assert service.connection_link(key, bundle_member=True, now_unix=T0 + 99 * DAY) == standalone
    assert f"&spx={quote('/api', safe='')}" in standalone
    assert service.link_spider_x(key, bundle_member=True) == "/api"
    assert asyncio.run(service.is_rotating_bundle_member(key)) is False
    assert asyncio.run(service.delivery_link(key)) == standalone


def test_standalone_key_never_rotates(tmp_path: Path) -> None:
    service = _service(_settings(tmp_path, hours=24))
    key = _key(spider_x="/blog/")
    for offset in range(0, 30 * DAY, 5 * HOUR):
        assert service.link_spider_x(key, bundle_member=False, now_unix=T0 + offset) == "/blog/"
    # A standalone key does not read the clock either (the forbidden clock is wired).
    assert "&spx=%2Fblog%2F" in service.connection_link(key)


@pytest.mark.parametrize(("transport", "profile"), _FAMILIES)
def test_bundle_member_carries_the_rotating_value(tmp_path: Path, transport: str, profile: str) -> None:
    hours = 24
    now = [T0]
    service = _service(_settings(tmp_path, hours=hours), unix_clock=lambda: now[0])
    key = _key(transport=transport, profile=profile, spider_x="/api")
    for offset in range(0, 12 * DAY, 9 * HOUR):
        now[0] = T0 + offset
        expected = rotating_spider_x(UUID_A, _POOL, hours * HOUR, T0 + offset)
        assert service.link_spider_x(key, bundle_member=True) == expected
        link = service.connection_link(key, bundle_member=True)
        assert _spx(link) == quote(expected, safe="")
        # Every other byte is the stored-spx link's.
        assert _without_spx(link) == _without_spx(service.connection_link(key))
    # An explicit instant wins over the clock (the bot pins one per screen).
    now[0] = T0
    pinned = T0 + 40 * DAY
    assert service.link_spider_x(key, bundle_member=True, now_unix=pinned) == rotating_spider_x(
        UUID_A, _POOL, hours * HOUR, pinned
    )


def test_bundle_member_without_a_stored_value_still_rotates(tmp_path: Path) -> None:
    """A child issued before the pool existed has spider_x NULL; with rotation on it
    is a bundle child all the same and gets the walk."""
    service = _service(_settings(tmp_path, hours=24), unix_clock=lambda: float(T0))
    key = _key(spider_x=None)
    assert "spx" not in service.connection_link(key)
    assert service.link_spider_x(key, bundle_member=True) == rotating_spider_x(UUID_A, _POOL, DAY, T0)


def test_rotation_reads_a_fractional_clock_as_whole_seconds(tmp_path: Path) -> None:
    service = _service(_settings(tmp_path, hours=1), unix_clock=lambda: T0 + 0.999)
    assert service.link_instant() == T0
    assert service.link_spider_x(_key(), bundle_member=True) == rotating_spider_x(UUID_A, _POOL, HOUR, T0)


def test_membership_is_asked_of_the_database_only_while_rotation_is_on(tmp_path: Path) -> None:
    repo = _MembershipRepo(members={7})
    service = _service(_settings(tmp_path, hours=24), repo=repo, unix_clock=lambda: float(T0))
    member, standalone = _key(7, spider_x="/api"), _key(8, uuid_value=UUID_B, spider_x="/api")
    assert asyncio.run(service.is_rotating_bundle_member(member)) is True
    assert asyncio.run(service.is_rotating_bundle_member(standalone)) is False
    assert repo.asked == [7, 8]
    assert asyncio.run(service.delivery_link(member)) == service.connection_link(member, bundle_member=True)
    assert asyncio.run(service.delivery_link(standalone)) == service.connection_link(standalone)
    # An empty pool switches rotation off as surely as hours=0 does: no query.
    inert = _service(_settings(tmp_path, pool=(), hours=24))
    assert asyncio.run(inert.is_rotating_bundle_member(member)) is False


def test_a_key_without_a_uuid_keeps_its_stored_value(tmp_path: Path) -> None:
    """Nothing to hash means nothing to walk: the stored value stands (and the
    subscription renderer refuses such a row before it gets here anyway)."""
    service = _service(_settings(tmp_path, hours=24))
    assert service.link_spider_x(_key(uuid_value="", spider_x="/api"), bundle_member=True) == "/api"
