"""Endpoint tests for the standalone all-in-one subscription server.

These drive the REAL ``KeyBundleService`` (which drives the real
``XrayService``/``HysteriaService``) against a real SQLite database, then point
the read-only endpoint at that same file — so every assertion covers the actual
path a client takes: bundle rows written by the bot, read live by a separate
read-only process, rendered by the same link builders the single-key view uses.
"""

import base64
import html
import logging
import re
import socket
import ssl
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer

from adapters.clock import ClockProvider
from config.settings import Settings, SettingsError, load_settings
from db.database import Database
from models.dto import TelegramUserProfile, User, VpnKey
from models.enums import KeyBundleStatus, UserRole, VpnKeyStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from repositories.traffic_stats import TrafficStatsRepository
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository
from services.hysteria import HysteriaService
from services.key_bundles import KeyBundleService
from services.xray import XrayService
from subscription_server import render as render_module
from subscription_server.config import SubscriptionConfig, SubscriptionConfigError, build_ssl_context, load_config
from subscription_server.render import SubscriptionRenderError, render_subscription
from subscription_server.server import build_app, token_fingerprint
from subscription_server.store import BundleStoreUnavailable, ReadOnlyBundleStore

ROOT = Path(__file__).resolve().parents[1]
UNIT_PATH = ROOT / "deploy" / "vpn-bot-subscription.service"

OWNER = 100
ADMIN = 1
EXPIRES_AT = "2030-01-01T00:00:00+00:00"
EXPIRES_AT_UNIX = 1893456000


# ── harness ───────────────────────────────────────────────────────────────────


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    values: dict[str, object] = dict(
        bot_token="token",
        admin_ids=frozenset({ADMIN}),
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
        hysteria2_enabled=True,
        hysteria2_host="vpn.example.com",
        hysteria2_port=443,
        hysteria2_sni="anycastedge.duckdns.org",
        hysteria2_insecure=False,
        subscription_enabled=True,
        # Off by default in the harness: the limiter is keyed by client address
        # and every test client is 127.0.0.1, so a shared cooldown would throttle
        # unrelated assertions. The limiter has its own test below.
        subscription_rate_limit_seconds=0,
    )
    values.update(overrides)
    return Settings(**values)


class _Users:
    async def require_approved_or_admin(self, user_id: int) -> User:
        role = UserRole.SUPERADMIN if user_id == ADMIN else UserRole.APPROVED_USER
        return User(user_id, f"user{user_id}", "User", role, "now", "now", None)

    async def get_user(self, user_id: int) -> User:
        return await self.require_approved_or_admin(user_id)


class _Audit:
    async def write_best_effort(self, **kwargs: object) -> None:
        return None

    async def write(self, **kwargs: object) -> None:
        return None


class _Modules:
    async def is_enabled(self, name: str) -> bool:
        return True


class _Ids:
    def __init__(self) -> None:
        self._n = 0

    def _next(self) -> int:
        self._n += 1
        return self._n

    def uuid4(self) -> str:
        return f"00000000-0000-4000-8000-{self._next():012d}"

    def generated_key_name(self, prefix: str) -> str:
        return f"{prefix}_{self._next():05d}"

    def xray_short_id(self) -> str:
        return "ff69b6f523de0d17"

    def hysteria2_label(self) -> str:
        return f"hy2_{self._next():016x}"


class _RecordingAdapter:
    """Stand-in for one Xray inbound (the bundle create path applies to it)."""

    def __init__(self) -> None:
        self.clients: list[dict[str, str]] = []

    async def add_client(self, **kwargs: object) -> object:
        self.clients.append({"id": str(kwargs["uuid_value"]), "email": str(kwargs["email_label"])})
        return SimpleNamespace(short_id_inserted=False)

    async def remove_client(self, **kwargs: object) -> None:
        return None

    def find_client(self, *, uuid_value: str | None = None, email_label: str | None = None) -> dict[str, str] | None:
        return None

    def list_clients(self) -> list[dict[str, str]]:
        return [dict(client) for client in self.clients]

    def list_short_ids(self) -> set[str]:
        return set()


class _Harness:
    def __init__(self, db: Database, settings: Settings, token: str, bundle_id: int) -> None:
        self.db = db
        self.settings = settings
        self.token = token
        self.bundle_id = bundle_id
        self.bundles = KeyBundleRepository(db)
        self.vpn_keys = VpnKeyRepository(db)
        self.traffic = TrafficStatsRepository(db)


async def _seed(tmp_path: Path, **settings_overrides: object) -> _Harness:
    """Create a real all-in-one bundle (VLESS TCP + 3 XHTTP profiles + hy2)."""
    settings = _settings(tmp_path, **settings_overrides)
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users_repo = UserRepository(db)
    for uid in (ADMIN, OWNER):
        await users_repo.upsert_profile(
            TelegramUserProfile(uid, f"user{uid}", "User"), UserRole.APPROVED_USER, "now"
        )
    vpn_keys = VpnKeyRepository(db)
    clock = ClockProvider()
    ids = _Ids()
    audit = _Audit()
    xray = XrayService(
        vpn_keys=vpn_keys,
        users=_Users(),  # type: ignore[arg-type]
        adapter=_RecordingAdapter(),  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=ids,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        xhttp_adapter=_RecordingAdapter(),  # type: ignore[arg-type]
    )
    hysteria = HysteriaService(
        vpn_keys=vpn_keys,
        users=_Users(),  # type: ignore[arg-type]
        settings=settings,
        clock=clock,
        ids=ids,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
        modules=_Modules(),  # type: ignore[arg-type]
    )
    service = KeyBundleService(
        bundles=KeyBundleRepository(db),
        users=_Users(),  # type: ignore[arg-type]
        xray=xray,
        hysteria=hysteria,
        modules=_Modules(),  # type: ignore[arg-type]
        settings=_settings(tmp_path, subscription_enabled=True),
        clock=clock,
        ids=ids,  # type: ignore[arg-type]
        audit=audit,  # type: ignore[arg-type]
    )
    result = await service.create_bundle(
        ADMIN, TelegramUserProfile(OWNER, f"user{OWNER}", "User"), None, expires_at=EXPIRES_AT
    )
    return _Harness(db, settings, result.bundle.token, result.bundle.id)


async def _client(harness: _Harness) -> tuple[TestClient, ReadOnlyBundleStore]:
    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    config = load_config(harness.settings)
    client = TestClient(TestServer(build_app(store, config)))
    await client.start_server()
    return client, store


def _decode(body: str) -> list[str]:
    return base64.b64decode(body.encode("ascii")).decode("utf-8").splitlines()


# ── the happy path ────────────────────────────────────────────────────────────


async def test_active_token_serves_exactly_the_bundle_children(tmp_path: Path) -> None:
    """200 + valid base64 carrying one link per child of bundle_composition():
    VLESS TCP, the three XHTTP profiles and Hysteria2 — and nothing else."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 200
        body = await resp.text()
        links = _decode(body)

        assert len(links) == 5
        assert sum(1 for link in links if link.startswith("vless://")) == 4
        assert sum(1 for link in links if link.startswith("hysteria2://")) == 1
        # One VLESS (TCP) plus one link per XHTTP profile, identified by the
        # email label the create path assigned (labels ride the #fragment).
        assert sum(1 for link in links if "%23xray_tcp_" in link or "#xray_tcp_" in link) == 1
        for profile in ("base", "antisib", "multi"):
            assert sum(1 for link in links if f"xray_http_{profile}_" in link) == 1, profile
        # Nothing that cannot ride a v2ray subscription.
        for forbidden in ("awg", "wireguard", "socks", "mtproto", "PrivateKey"):
            assert forbidden not in body.lower() and forbidden.lower() not in "\n".join(links).lower()
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_body_is_standard_base64_of_newline_joined_links(tmp_path: Path) -> None:
    """The body must be plain standard-alphabet base64 (what every client decodes),
    not raw links and not a JSON envelope."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        resp = await client.get(f"/sub/{harness.token}")
        body = await resp.text()
        assert re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", body), "body must be standard base64"
        assert base64.b64encode(base64.b64decode(body)).decode() == body
        assert "vless://" not in body  # never the plaintext links on the wire
        assert resp.headers["Content-Type"].startswith("text/plain")
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_subscription_links_match_the_single_key_view(tmp_path: Path) -> None:
    """Drift guard: the endpoint must render byte-identical links to the per-key
    config view. A subscription link that differs by one REALITY/xhttp parameter
    is a key that works from the bot's message and fails from the sub-URL."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        resp = await client.get(f"/sub/{harness.token}")
        links = _decode(await resp.text())

        reference = XrayService(
            vpn_keys=harness.vpn_keys,
            users=_Users(),  # type: ignore[arg-type]
            adapter=_RecordingAdapter(),  # type: ignore[arg-type]
            settings=harness.settings,
            clock=ClockProvider(),
            ids=_Ids(),  # type: ignore[arg-type]
            audit=_Audit(),  # type: ignore[arg-type]
            xhttp_adapter=_RecordingAdapter(),  # type: ignore[arg-type]
        )
        for key in await harness.bundles.list_keys_of_bundle(harness.bundle_id):
            if key.key_type is not VpnKeyType.XRAY:
                continue
            # _format_config wraps the link in an HTML-escaped <code>…</code> for
            # Telegram; unwrap and unescape it to compare the link itself.
            rendered = reference._format_config(key)
            expected = html.unescape(rendered.split("<code>")[1].split("</code>")[0])
            assert expected in links, f"key {key.id}: endpoint link differs from the single-key view"
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


# ── the single negative answer ────────────────────────────────────────────────


async def test_unknown_token_is_404(tmp_path: Path) -> None:
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        resp = await client.get("/sub/" + "z" * 43)
        assert resp.status == 404
        assert await resp.text() == ""
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


@pytest.mark.parametrize(
    "status", [KeyBundleStatus.REVOKED, KeyBundleStatus.PENDING_REVOKE, KeyBundleStatus.DELETE_FAILED]
)
async def test_non_active_bundle_is_indistinguishable_from_unknown(
    tmp_path: Path, status: KeyBundleStatus
) -> None:
    """A revoked/deleted bundle must answer EXACTLY like a token that never
    existed — same status, same (empty) body, same headers — so the endpoint
    cannot be used to confirm that a token exists."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        unknown = await client.get("/sub/" + "z" * 43)
        unknown_headers = {k: v for k, v in unknown.headers.items() if k.lower() != "date"}
        unknown_body = await unknown.text()

        await harness.bundles.set_status(harness.bundle_id, status, "now")
        resp = await client.get(f"/sub/{harness.token}")

        assert resp.status == unknown.status == 404
        assert await resp.text() == unknown_body == ""
        assert {k: v for k, v in resp.headers.items() if k.lower() != "date"} == unknown_headers
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_deleted_bundle_row_is_404(tmp_path: Path) -> None:
    """A hard-deleted bundle (row gone) is the same 404, with no server error."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        for key in await harness.bundles.list_keys_of_bundle(harness.bundle_id):
            await harness.vpn_keys.clear_bundle_id(key.id, "now") if hasattr(
                harness.vpn_keys, "clear_bundle_id"
            ) else await harness.db.conn.execute(
                "UPDATE vpn_keys SET bundle_id = NULL WHERE id = ?", (key.id,)
            )
        await harness.db.commit()
        await harness.bundles.delete(harness.bundle_id)

        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 404
        assert await resp.text() == ""
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_revoked_children_leave_nothing_to_serve(tmp_path: Path) -> None:
    """An ACTIVE bundle whose children are all revoked serves 404, never an empty
    (but successful) subscription a client would happily install."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        for key in await harness.bundles.list_keys_of_bundle(harness.bundle_id):
            await harness.vpn_keys.mark_revoked(key.id, ADMIN, "now")
        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 404
        assert await resp.text() == ""
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_one_revoked_child_disappears_live_without_a_restart(tmp_path: Path) -> None:
    """The read is live: revoking a single child drops exactly that link on the
    very next fetch, with no cache to invalidate and no process to restart."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        assert len(_decode(await (await client.get(f"/sub/{harness.token}")).text())) == 5
        keys = await harness.bundles.list_keys_of_bundle(harness.bundle_id)
        hy2 = next(key for key in keys if key.key_type is VpnKeyType.HYSTERIA2)
        await harness.vpn_keys.mark_revoked(hy2.id, ADMIN, "now")

        links = _decode(await (await client.get(f"/sub/{harness.token}")).text())
        assert len(links) == 4
        assert not any(link.startswith("hysteria2://") for link in links)
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


@pytest.mark.parametrize(
    "token",
    ["  ", "short", "a" * 200, "tok en", "'; DROP TABLE key_bundles;--", "%2e%2e%2fetc%2fpasswd"],
)
async def test_malformed_tokens_never_reach_the_database(
    tmp_path: Path, token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Anything that cannot be a token we issued is rejected on shape alone,
    before the database is touched — a public endpoint must not turn junk paths
    into queries."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    reads = 0
    original = store.load_active_bundle

    async def _counting(value: str) -> object:
        nonlocal reads
        reads += 1
        return await original(value)

    monkeypatch.setattr(store, "load_active_bundle", _counting)
    try:
        resp = await client.get(f"/sub/{token}")
        assert resp.status == 404
        assert await resp.text() == ""
        assert reads == 0
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_only_the_sub_route_exists(tmp_path: Path) -> None:
    """One route, one method. No health endpoint, no listing, no writes."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        assert (await client.get("/healthz")).status == 404
        assert (await client.get("/")).status == 404
        assert (await client.get("/sub/")).status == 404
        assert (await client.post(f"/sub/{harness.token}")).status == 405
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


# ── the feature flag ──────────────────────────────────────────────────────────


async def test_disabled_flag_answers_404_and_never_reads_the_database(tmp_path: Path) -> None:
    """SUBSCRIPTION_ENABLED=false has teeth at the endpoint too: the valid token
    of a live bundle gets the same empty 404, and no DB read happens at all."""
    harness = await _seed(tmp_path, subscription_enabled=False)
    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    reads = 0
    original = store.load_active_bundle

    async def _counting(token: str) -> object:
        nonlocal reads
        reads += 1
        return await original(token)

    store.load_active_bundle = _counting  # type: ignore[method-assign]
    client = TestClient(TestServer(build_app(store, load_config(harness.settings))))
    await client.start_server()
    try:
        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 404
        assert await resp.text() == ""
        assert reads == 0, "a disabled endpoint must not touch the database"
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


# ── fail-closed ───────────────────────────────────────────────────────────────


async def test_render_failure_is_404_not_500_and_never_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If ANY child fails to render, the whole response is an empty 404 — never a
    500 with a traceback, never the subset of links that did render."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    real = render_module.format_hysteria2_link

    def _boom(*args: object, **kwargs: object) -> str:
        raise RuntimeError("link renderer exploded")

    monkeypatch.setattr(render_module, "format_hysteria2_link", _boom)
    try:
        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 404
        assert await resp.text() == ""
        assert "Traceback" not in await resp.text()
        # ... and the endpoint recovers once the fault clears (no poisoned state).
        monkeypatch.setattr(render_module, "format_hysteria2_link", real)
        assert (await client.get(f"/sub/{harness.token}")).status == 200
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_malformed_child_row_fails_the_whole_render(tmp_path: Path) -> None:
    """A child whose payload lost its uuid must not be silently dropped: a
    subscription quietly missing one protocol is worse than no subscription."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        keys = await harness.bundles.list_keys_of_bundle(harness.bundle_id)
        victim = next(key for key in keys if key.key_type is VpnKeyType.XRAY)
        await harness.db.conn.execute(
            "UPDATE vpn_keys SET payload_json = '{}', uuid = NULL WHERE id = ?", (victim.id,)
        )
        await harness.db.commit()

        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 404
        assert await resp.text() == ""
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_unreadable_database_is_404_not_500(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        async def _boom(token: str) -> object:
            raise BundleStoreUnavailable("database is locked")

        monkeypatch.setattr(store, "load_active_bundle", _boom)
        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 404
        assert await resp.text() == ""
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_unexpected_error_never_surfaces_a_500(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The last safety net: even an error nobody anticipated leaves as a 404."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        async def _boom(token: str) -> object:
            raise ZeroDivisionError("something nobody planned for")

        monkeypatch.setattr(store, "load_active_bundle", _boom)
        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 404
        assert await resp.text() == ""
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


# ── headers ───────────────────────────────────────────────────────────────────


async def test_subscription_headers_are_present_and_truthful(tmp_path: Path) -> None:
    """Profile-Title is the bundle's own label, the update interval comes from
    settings, expire is the children's shared expiry as unix seconds, and total
    is absent because this deployment has no quota to report."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        resp = await client.get(f"/sub/{harness.token}")
        bundle = await harness.bundles.get_by_id(harness.bundle_id)
        assert bundle is not None

        assert resp.headers["Profile-Title"] == bundle.label
        assert resp.headers["Profile-Update-Interval"] == "12"
        assert resp.headers["Cache-Control"] == "no-store"
        userinfo = resp.headers["Subscription-Userinfo"]
        assert f"expire={EXPIRES_AT_UNIX}" in userinfo
        assert "total=" not in userinfo
        # No traffic was ever collected for these keys, so no counters are claimed.
        assert "upload=" not in userinfo and "download=" not in userinfo
        # The token never travels in a header.
        assert harness.token not in "".join(f"{k}{v}" for k, v in resp.headers.items())
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_measured_traffic_is_summed_across_children(tmp_path: Path) -> None:
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        keys = await harness.bundles.list_keys_of_bundle(harness.bundle_id)
        for index, key in enumerate(keys[:2]):
            await harness.traffic.upsert_success(
                key_id=key.id,
                downloaded_bytes=1000 * (index + 1),
                uploaded_bytes=10 * (index + 1),
                raw_downloaded_bytes=None,
                raw_uploaded_bytes=None,
                now="2026-01-01T00:00:00+00:00",
                source="test",
            )
        userinfo = (await client.get(f"/sub/{harness.token}")).headers["Subscription-Userinfo"]
        assert "upload=30" in userinfo
        assert "download=3000" in userinfo
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_no_expiry_omits_expire_rather_than_inventing_one(tmp_path: Path) -> None:
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        await harness.db.conn.execute("UPDATE vpn_keys SET expires_at = NULL")
        await harness.db.commit()
        resp = await client.get(f"/sub/{harness.token}")
        assert resp.status == 200
        assert "Subscription-Userinfo" not in resp.headers
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


def test_expire_uses_the_earliest_child_expiry() -> None:
    """Children share one expires_at by construction; if that ever stops holding,
    the truthful answer is the earliest one — that is when the subscription starts
    losing protocols."""
    from subscription_server.store import BundleView

    def _key(key_id: int, expires_at: str | None) -> VpnKey:
        return VpnKey(
            id=key_id,
            owner_user_id=OWNER,
            username=None,
            key_type=VpnKeyType.XRAY,
            status=VpnKeyStatus.ACTIVE,
            note=None,
            uuid=None,
            email_label=None,
            public_key=None,
            client_ip=None,
            payload={},
            public_payload={},
            created_at="now",
            updated_at="now",
            revoked_at=None,
            deleted_at=None,
            created_by=ADMIN,
            revoked_by=None,
            deleted_by=None,
            expires_at=expires_at,
        )

    view = BundleView(
        bundle=None,  # type: ignore[arg-type]
        keys=(_key(1, "2031-01-01T00:00:00+00:00"), _key(2, EXPIRES_AT), _key(3, None)),
        traffic=(),
    )
    assert view.expires_at == EXPIRES_AT


# ── rate limiting ─────────────────────────────────────────────────────────────


async def test_rate_limit_throttles_a_hot_client(tmp_path: Path) -> None:
    """The second request inside the cooldown is refused with 429 + Retry-After,
    and the refusal happens before the database is read."""
    harness = await _seed(tmp_path, subscription_rate_limit_seconds=30)
    client, store = await _client(harness)
    try:
        first = await client.get(f"/sub/{harness.token}")
        assert first.status == 200
        second = await client.get(f"/sub/{harness.token}")
        assert second.status == 429
        assert int(second.headers["Retry-After"]) >= 1
        assert await second.text() == ""
        # An unknown token is throttled the same way — the limiter is keyed by
        # client, so it cannot be used to probe which tokens exist.
        assert (await client.get("/sub/" + "z" * 43)).status == 429
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_rate_limit_disabled_by_zero(tmp_path: Path) -> None:
    harness = await _seed(tmp_path, subscription_rate_limit_seconds=0)
    client, store = await _client(harness)
    try:
        for _ in range(3):
            assert (await client.get(f"/sub/{harness.token}")).status == 200
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


# ── the token never reaches a log ─────────────────────────────────────────────


async def test_token_never_appears_in_logs(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """Not on the success path, not on the reject path, not in the access log —
    the token is a working credential and a log file is not a place for it."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        with caplog.at_level(logging.DEBUG):
            caplog.clear()
            await client.get(f"/sub/{harness.token}")
            await client.get("/sub/" + "y" * 43)
            await harness.bundles.set_status(harness.bundle_id, KeyBundleStatus.REVOKED, "now")
            await client.get(f"/sub/{harness.token}")

        logged = "\n".join(record.getMessage() for record in caplog.records)
        assert harness.token not in logged
        assert "y" * 43 not in logged
        # ... but the request is still diagnosable by a stable fingerprint.
        assert token_fingerprint(harness.token) in logged
        assert len(token_fingerprint(harness.token)) == 12
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


async def test_access_log_line_is_redacted_even_if_it_is_switched_on(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """aiohttp's access log prints the request line — which contains the token.
    The runner disables that log; this asserts the second line of defence, the
    filter the app installs, so a re-enabled access log still cannot leak."""
    harness = await _seed(tmp_path)
    client, store = await _client(harness)
    try:
        with caplog.at_level(logging.INFO):
            caplog.clear()
            await client.get(f"/sub/{harness.token}")
        access = [
            record.getMessage() for record in caplog.records if record.name == "aiohttp.access"
        ]
        assert access, "the test server must have logged an access line to assert on"
        for line in access:
            assert harness.token not in line
            assert f"/sub/<redacted:{token_fingerprint(harness.token)}>" in line
    finally:
        await client.close()
        await store.close()
        await harness.db.close()


def test_log_guards_are_idempotent_and_pin_aiosqlite() -> None:
    """aiosqlite logs every statement WITH its bound parameters at DEBUG, and the
    token is a bound parameter of the bundle lookup."""
    from subscription_server.server import _TokenRedactingFilter, install_log_guards

    install_log_guards()
    install_log_guards()
    access = logging.getLogger("aiohttp.access")
    assert sum(isinstance(f, _TokenRedactingFilter) for f in access.filters) == 1
    assert logging.getLogger("aiosqlite").level >= logging.INFO


def test_token_fingerprint_is_not_reversible() -> None:
    token = "s3cr3t-token-value-that-must-never-be-logged"
    fingerprint = token_fingerprint(token)
    assert token not in fingerprint
    assert fingerprint != token_fingerprint(token + "x")
    assert fingerprint == token_fingerprint(token)


# ── the store: read-only, live ────────────────────────────────────────────────


async def test_store_connection_is_read_only(tmp_path: Path) -> None:
    """The endpoint physically cannot write: the connection is opened mode=ro, so
    even a repository method that tried would raise."""
    harness = await _seed(tmp_path)
    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    try:
        assert "mode=ro" in store.uri
        with pytest.raises(Exception) as exc:  # sqlite3.OperationalError: readonly
            await store._db.conn.execute("UPDATE key_bundles SET note = 'x' WHERE id = -1")
        assert "readonly" in str(exc.value).lower()
    finally:
        await store.close()
        await harness.db.close()


async def test_store_reads_through_the_repositories(tmp_path: Path) -> None:
    """Rows come back as the ordinary DTOs (decoded enums, parsed payloads), which
    is the whole point of going through the repositories rather than raw SQL."""
    harness = await _seed(tmp_path)
    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    try:
        view = await store.load_active_bundle(harness.token)
        assert view is not None
        assert view.bundle.status is KeyBundleStatus.ACTIVE
        assert view.bundle.id == harness.bundle_id
        assert len(view.keys) == 5
        assert all(key.status is VpnKeyStatus.ACTIVE for key in view.keys)
        assert view.expires_at == EXPIRES_AT
        assert await store.healthcheck() is True
    finally:
        await store.close()
        await harness.db.close()


async def test_store_infra_failure_is_counted_and_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A broken DB is loud (error + counter) and fails closed; it never looks like
    a token that simply does not exist."""
    import aiosqlite

    harness = await _seed(tmp_path)
    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    try:
        async def _boom(*args: object, **kwargs: object) -> object:
            raise aiosqlite.OperationalError("database disk image is malformed")

        monkeypatch.setattr(store._db._conn, "execute", _boom)
        with caplog.at_level(logging.ERROR), pytest.raises(BundleStoreUnavailable):
            await store.load_active_bundle(harness.token)
        assert store.infra_failures == 1
        assert [record for record in caplog.records if record.levelno >= logging.ERROR]
        assert await store.healthcheck() is False
    finally:
        await store.close()
        await harness.db.close()


async def test_store_reopens_after_the_db_file_is_swapped(tmp_path: Path) -> None:
    """A restore that atomically replaces vpn.db must be visible on the next read:
    the connection pins an inode, so the store has to detect the swap and reopen —
    otherwise a bundle revoked in the restored file would keep being served."""
    import os

    harness = await _seed(tmp_path)
    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    try:
        assert await store.load_active_bundle(harness.token) is not None

        replacement = await _seed(tmp_path / "replacement")
        await replacement.bundles.set_status(replacement.bundle_id, KeyBundleStatus.REVOKED, "now")
        await replacement.db.close()  # checkpoints the WAL into the main file
        await harness.db.close()
        os.replace(replacement.db.path, harness.db.path)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{harness.db.path}{suffix}")
            if sidecar.exists():
                sidecar.unlink()

        # The swapped-in file has a different token entirely, so the old one is gone.
        assert await store.load_active_bundle(harness.token) is None
    finally:
        await store.close()


# ── config ────────────────────────────────────────────────────────────────────


def test_public_port_without_tls_refuses_to_start(tmp_path: Path) -> None:
    """Cleartext off-loopback must be unreachable by configuration, not by
    convention: the process refuses to start rather than binding it."""
    settings = _settings(tmp_path, subscription_public_port=2096)
    with pytest.raises(SettingsError):
        settings.validate_subscription_ready()
    with pytest.raises(SubscriptionConfigError):
        load_config(settings)


def test_loopback_only_bind_host_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """The plain-HTTP bind must never leave the box."""
    monkeypatch.setenv("BOT_TOKEN", "1234567890:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    monkeypatch.setenv("ADMIN_IDS", "1")
    for host in ("0.0.0.0", "10.0.0.5", "example.com"):  # noqa: S104 - the point is that these are refused
        monkeypatch.setenv("SUBSCRIPTION_BIND_HOST", host)
        with pytest.raises(SettingsError):
            load_settings()
    for host in ("127.0.0.1", "::1", "localhost"):
        monkeypatch.setenv("SUBSCRIPTION_BIND_HOST", host)
        assert load_settings().subscription_bind_host in {"127.0.0.1", "::1", "localhost"}


def test_default_bind_port_avoids_the_ports_this_host_already_uses(monkeypatch: pytest.MonkeyPatch) -> None:
    """8443 is taken twice on this host (XRAY_XHTTP_PORT on loopback, MTPROTO_PORT
    publicly), so the endpoint must not default to it."""
    monkeypatch.setenv("BOT_TOKEN", "1234567890:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    monkeypatch.setenv("ADMIN_IDS", "1")
    settings = load_settings()
    assert settings.subscription_bind_port == 8445
    assert settings.subscription_bind_port != settings.xray_xhttp_port
    assert settings.subscription_public_port == 0  # public listener off by default
    assert settings.subscription_enabled is False


def test_ssl_context_is_none_while_the_public_port_is_off(tmp_path: Path) -> None:
    config = load_config(_settings(tmp_path))
    assert config.tls_configured is False
    assert build_ssl_context(config) is None


def test_unreadable_tls_material_is_a_startup_failure(tmp_path: Path) -> None:
    """A missing/unreadable key must stop the process, never silently downgrade
    the public listener to plaintext."""
    config = SubscriptionConfig(
        settings=_settings(tmp_path),
        db_path=tmp_path / "vpn.db",
        bind_host="127.0.0.1",
        bind_port=8445,
        public_port=2096,
        tls_cert=tmp_path / "missing-cert.pem",
        tls_key=tmp_path / "missing-key.pem",
        lock_path=tmp_path / "sub.lock",
    )
    with pytest.raises(SubscriptionConfigError):
        build_ssl_context(config)


def test_tls_context_loads_a_real_certificate(tmp_path: Path) -> None:
    """The public listener really does terminate TLS in-process (option (a)) —
    exercised here with a self-signed pair so the wiring is covered, not mocked."""
    pytest.importorskip("cryptography")
    cert_path, key_path = _self_signed_pair(tmp_path)
    config = SubscriptionConfig(
        settings=_settings(tmp_path),
        db_path=tmp_path / "vpn.db",
        bind_host="127.0.0.1",
        bind_port=8445,
        public_port=2096,
        tls_cert=cert_path,
        tls_key=key_path,
        lock_path=tmp_path / "sub.lock",
    )
    context = build_ssl_context(config)
    assert context is not None
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def _self_signed_pair(tmp_path: Path) -> tuple[Path, Path]:
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sub.test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


# ── the runner: which sockets actually come up ────────────────────────────────


async def _run_sites(harness: _Harness, config: SubscriptionConfig) -> tuple[object, ReadOnlyBundleStore, list[int]]:
    from aiohttp import web

    from subscription_server.__main__ import _start_sites

    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    runner = web.AppRunner(build_app(store, config), access_log=None)
    await runner.setup()
    await _start_sites(runner, config)
    ports = [sock[1] for sock in runner.addresses]
    return runner, store, ports


def _config(harness: _Harness, tmp_path: Path, **overrides: object) -> SubscriptionConfig:
    values: dict[str, object] = dict(
        settings=harness.settings,
        db_path=harness.db.path,
        bind_host="127.0.0.1",
        bind_port=0,  # ephemeral: never collide with a real service on the runner
        public_port=0,
        tls_cert=None,
        tls_key=None,
        lock_path=tmp_path / "sub.lock",
    )
    values.update(overrides)
    return SubscriptionConfig(**values)  # type: ignore[arg-type]


async def test_runner_binds_loopback_only_while_tls_is_off(tmp_path: Path) -> None:
    """Without TLS material the process exposes exactly one socket, on loopback —
    there is no configuration in which it serves cleartext off the box."""
    harness = await _seed(tmp_path)
    runner, store, ports = await _run_sites(harness, _config(harness, tmp_path))
    try:
        assert len(runner.addresses) == 1  # type: ignore[attr-defined]
        assert runner.addresses[0][0] == "127.0.0.1"  # type: ignore[attr-defined]
        assert len(ports) == 1
    finally:
        await runner.cleanup()  # type: ignore[attr-defined]
        await store.close()
        await harness.db.close()


async def test_public_listener_terminates_tls_in_process(tmp_path: Path) -> None:
    """End-to-end proof of the chosen TLS design (option (a)): the endpoint itself
    speaks HTTPS on the public port — no reverse proxy anywhere — and serves the
    very same base64 body the loopback socket does."""
    pytest.importorskip("cryptography")
    import aiohttp

    harness = await _seed(tmp_path)
    cert_path, key_path = _self_signed_pair(tmp_path)
    # public_port=0 means "disabled", so pick a concrete free port for this one.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = int(probe.getsockname()[1])
    config = _config(harness, tmp_path, public_port=free_port, tls_cert=cert_path, tls_key=key_path)

    runner, store, _ = await _run_sites(harness, config)
    try:
        assert len(runner.addresses) == 2, "loopback plain site + public TLS site"  # type: ignore[attr-defined]
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://127.0.0.1:{free_port}/sub/{harness.token}", ssl=False
            ) as resp:
                assert resp.status == 200
                assert len(_decode(await resp.text())) == 5
                assert resp.headers["Profile-Update-Interval"] == "12"
    finally:
        await runner.cleanup()  # type: ignore[attr-defined]
        await store.close()
        await harness.db.close()


async def test_disabled_feature_holds_no_public_socket(tmp_path: Path) -> None:
    """With SUBSCRIPTION_ENABLED=false the public listener is not started at all:
    a port that could only ever answer 404 is attack surface with no function."""
    pytest.importorskip("cryptography")
    harness = await _seed(tmp_path, subscription_enabled=False)
    cert_path, key_path = _self_signed_pair(tmp_path)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = int(probe.getsockname()[1])
    config = _config(harness, tmp_path, public_port=free_port, tls_cert=cert_path, tls_key=key_path)

    runner, store, _ = await _run_sites(harness, config)
    try:
        assert len(runner.addresses) == 1, "only the loopback site may be up"  # type: ignore[attr-defined]
        assert runner.addresses[0][0] == "127.0.0.1"  # type: ignore[attr-defined]
    finally:
        await runner.cleanup()  # type: ignore[attr-defined]
        await store.close()
        await harness.db.close()


def test_main_exits_instead_of_starting_misconfigured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A configuration the endpoint refuses stops the process at startup rather
    than running it in a weaker posture."""
    import subscription_server.__main__ as main_module

    def _boom() -> SubscriptionConfig:
        raise SubscriptionConfigError("SUBSCRIPTION_PUBLIC_PORT требует TLS")

    monkeypatch.setattr(main_module, "load_config", _boom)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 1


# ── render unit-level guards ──────────────────────────────────────────────────


async def test_render_refuses_a_protocol_that_cannot_ride_a_subscription(tmp_path: Path) -> None:
    """AWG never belongs in a bundle; if a row ever claims otherwise the render
    fails closed instead of emitting a link no client can use."""
    harness = await _seed(tmp_path)
    store = ReadOnlyBundleStore(harness.db.path)
    await store.connect()
    try:
        keys = await harness.bundles.list_keys_of_bundle(harness.bundle_id)
        await harness.db.conn.execute(
            "UPDATE vpn_keys SET key_type = 'awg' WHERE id = ?", (keys[0].id,)
        )
        await harness.db.commit()
        view = await store.load_active_bundle(harness.token)
        assert view is not None
        with pytest.raises(SubscriptionRenderError):
            render_subscription(view, harness.settings)
    finally:
        await store.close()
        await harness.db.close()


def test_profile_title_wraps_only_non_ascii_labels() -> None:
    assert render_module._profile_title("bundle_ab12x") == "bundle_ab12x"
    wrapped = render_module._profile_title("подписка")
    assert wrapped.startswith("base64:")
    assert base64.b64decode(wrapped.removeprefix("base64:")).decode("utf-8") == "подписка"


def test_unparseable_expiry_omits_expire() -> None:
    assert render_module._expire_timestamp("not-a-date") is None
    assert render_module._expire_timestamp(None) is None
    # A naive stamp is read as UTC (that is what the clock provider writes).
    assert render_module._expire_timestamp("2030-01-01T00:00:00") == EXPIRES_AT_UNIX


# ── the systemd unit ──────────────────────────────────────────────────────────


def test_subscription_unit_is_a_hardened_simple_service() -> None:
    """Structural guard on the shipped unit: a long-running simple service, run
    unprivileged, with the full sandbox — an accidental weakening fails CI."""
    text = UNIT_PATH.read_text(encoding="utf-8")
    assert "Type=simple" in text
    assert "ExecStart=/opt/vpn-service/.venv/bin/python -m subscription_server" in text
    assert "Restart=on-failure" in text
    assert "User=vpn-bot" in text and "Group=vpn-bot" in text
    assert "User=root" not in text
    for hardening in (
        "NoNewPrivileges=yes",
        "PrivateTmp=true",
        "ProtectHome=true",
        "ProtectSystem=strict",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectControlGroups=true",
        "RestrictRealtime=true",
        "RestrictSUIDSGID=true",
        "RestrictNamespaces=true",
        "LockPersonality=true",
        "MemoryDenyWriteExecute=true",
        "RestrictAddressFamilies=AF_INET AF_INET6",
        "SystemCallFilter=@system-service",
        "UMask=0077",
    ):
        assert hardening in text, hardening
    assert "RuntimeDirectory=vpn-bot-subscription" in text
    assert "RuntimeDirectoryMode=0700" in text


def test_subscription_unit_grants_write_only_to_the_wal_sidecars() -> None:
    """The data directory is the ONLY writable path (WAL readers must write the
    -shm/-wal sidecars); the database itself stays read-only via `mode=ro`, and
    nothing else on the box is writable to this unit."""
    text = UNIT_PATH.read_text(encoding="utf-8")
    read_write = [line.strip() for line in text.splitlines() if line.strip().startswith("ReadWritePaths=")]
    assert read_write == ["ReadWritePaths=/opt/vpn-service/data"]
    for forbidden in ("/etc/systemd/system", "/usr/local/etc/xray", "/etc/hysteria", "/etc/passwd"):
        assert forbidden not in "\n".join(read_write)
    # The unit does not install itself: it documents the manual (drift) install.
    assert "systemctl enable --now vpn-bot-subscription" in text


def test_phase1_sees_the_unit_through_the_shipped_service_glob() -> None:
    """deploy.sh assembles UNIT_SET from every deploy/*.service basename (source
    (c)), so a repo-shipped unit needs no managed-units.list entry — that file is
    explicitly for units with no .env variable that ship no unit file."""
    assert UNIT_PATH.name.endswith(".service")
    assert not UNIT_PATH.name.endswith(".example.service")
    deploy_sh = (ROOT / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    assert 'for f in "$WT"/deploy/*.service; do' in deploy_sh
    managed = (ROOT / "deploy" / "managed-units.list").read_text(encoding="utf-8")
    assert "vpn-bot-subscription" not in managed


def test_deploy_sh_checks_the_endpoint_informationally() -> None:
    """Phase 1 reports the unit + listening state and NEVER dies over it."""
    text = (ROOT / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    assert "subscription_endpoint_status()" in text
    assert "SUBSCRIPTION_UNIT=" in text
    assert "SUBSCRIPTION_ENABLED" in text
    index = text.index("subscription_endpoint_status()")
    body = text[index : index + 2000]
    assert "die " not in body, "the subscription check must never be fatal"
    # Wired into both the live path (warn) and the PHASE1_ONLY report.
    assert 'warn "subscription endpoint:' in text
    assert "Subscription endpoint (%s — drift-installed by hand)" in text


def _run_endpoint_check(env_lines: str, *, unit_loaded: bool, listening_ports: list[str], tmp_path: Path) -> tuple[int, str]:
    """Drive the real `subscription_endpoint_status` through deploy.sh's documented
    DEPLOY_SELFTEST=1 source seam, with `systemctl`/`ss` shadowed by bash
    functions. Nothing here runs a real systemctl or reads a production .env."""
    env_file = tmp_path / ".env"
    env_file.write_text(env_lines, encoding="utf-8")
    load_state = "loaded" if unit_loaded else "not-found"
    active_state = "active" if unit_loaded else "inactive"
    ss_output = "\n".join(f"LISTEN 0 128 {port} 0.0.0.0:*" for port in listening_ports)
    driver = (
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        f'export ENV_FILE="{env_file}"\n'
        f'source "{ROOT / "scripts" / "deploy.sh"}"\n'
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        "set +e\n"
        "systemctl() {\n"
        '  if [[ "${1:-}" == "show" ]]; then\n'
        f'    case "$3" in LoadState) echo "{load_state}";; ActiveState) echo "{active_state}";; esac\n'
        "  fi\n"
        "  return 0\n"
        "}\n"
        f'ss() {{ printf "%s\\n" "{ss_output}"; }}\n'
        "subscription_endpoint_status\n"
        "exit $?\n"
    )
    result = subprocess.run(["bash", "-c", driver], capture_output=True, text=True, timeout=120)
    return result.returncode, result.stdout.strip()


def test_deploy_check_reports_a_healthy_endpoint(tmp_path: Path) -> None:
    rc, message = _run_endpoint_check(
        "SUBSCRIPTION_ENABLED=true\nSUBSCRIPTION_BIND_PORT=8445\nSUBSCRIPTION_PUBLIC_PORT=2096\n",
        unit_loaded=True,
        listening_ports=["127.0.0.1:8445", "*:2096"],
        tmp_path=tmp_path,
    )
    assert rc == 0, message
    assert "loaded/active" in message
    assert "8445" in message and "2096" in message


def test_deploy_check_flags_a_missing_unit_and_a_dead_port(tmp_path: Path) -> None:
    """Both failure modes are reported (never fatally): the unit was never
    installed, and the unit is installed but nothing is listening."""
    rc, message = _run_endpoint_check(
        "SUBSCRIPTION_ENABLED=true\nSUBSCRIPTION_BIND_PORT=8445\n",
        unit_loaded=False,
        listening_ports=[],
        tmp_path=tmp_path,
    )
    assert rc == 1
    assert "not installed" in message

    rc, message = _run_endpoint_check(
        "SUBSCRIPTION_ENABLED=true\nSUBSCRIPTION_BIND_PORT=8445\nSUBSCRIPTION_PUBLIC_PORT=2096\n",
        unit_loaded=True,
        listening_ports=["127.0.0.1:8445"],
        tmp_path=tmp_path,
    )
    assert rc == 1
    assert "NOT listening" in message and "2096" in message


def test_deploy_check_is_silent_while_the_feature_is_off(tmp_path: Path) -> None:
    """A host that has not enabled the subscription is a normal state, not a flag."""
    rc, message = _run_endpoint_check(
        "SUBSCRIPTION_ENABLED=false\n", unit_loaded=False, listening_ports=[], tmp_path=tmp_path
    )
    assert rc == 0
    assert "intentionally inert" in message


def test_ufw_rule_is_a_tracked_artifact_reading_the_port_from_env() -> None:
    """The firewall rule ships as a re-runnable script, not as a command someone
    typed once: a `ufw reset` or a rebuilt host would otherwise lose it silently."""
    script = ROOT / "deploy" / "ufw-subscription.sh"
    text = script.read_text(encoding="utf-8")
    assert script.stat().st_mode & 0o111, "script must be executable"
    assert "SUBSCRIPTION_PUBLIC_PORT" in text
    assert "ufw allow" in text and "ufw delete allow" in text
    assert "comment" in text
    # The port is never hardcoded, and .env is parsed rather than sourced (it
    # holds the bot token and every backend secret).
    assert "source " not in text and ". /opt" not in text
    assert re.search(r"ufw allow \"\$\{?PORT", text)


def test_ufw_script_refuses_to_open_a_port_for_a_disabled_feature(tmp_path: Path) -> None:
    """Driven for real against a stub `ufw`: no rule is added while
    SUBSCRIPTION_ENABLED is false, and the port comes from .env when it is true."""
    env_file = tmp_path / ".env"
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    calls = tmp_path / "ufw-calls.log"
    (stub_bin / "ufw").write_text(
        f'#!/usr/bin/env bash\necho "$@" >> {calls}\nexit 0\n', encoding="utf-8"
    )
    (stub_bin / "ufw").chmod(0o755)
    script = ROOT / "deploy" / "ufw-subscription.sh"

    def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(script), *args],
            capture_output=True,
            text=True,
            env={
                "PATH": f"{stub_bin}:/usr/bin:/bin",
                "ENV_FILE": str(env_file),
                "HOME": str(tmp_path),
            },
            timeout=60,
        )

    env_file.write_text("SUBSCRIPTION_ENABLED=false\nSUBSCRIPTION_PUBLIC_PORT=2096\n", encoding="utf-8")
    disabled = _run([])
    assert disabled.returncode != 0
    assert not calls.exists(), "no ufw rule may be added while the feature is off"

    env_file.write_text("SUBSCRIPTION_ENABLED=true\nSUBSCRIPTION_PUBLIC_PORT=2096\n", encoding="utf-8")
    enabled = _run([])
    assert enabled.returncode == 0, enabled.stderr
    assert "allow 2096/tcp" in calls.read_text(encoding="utf-8")

    calls.unlink()
    removed = _run(["--delete"])
    assert removed.returncode == 0, removed.stderr
    assert "delete allow 2096/tcp" in calls.read_text(encoding="utf-8")


def test_ufw_script_rejects_a_missing_or_bogus_port(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    (stub_bin / "ufw").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (stub_bin / "ufw").chmod(0o755)
    script = ROOT / "deploy" / "ufw-subscription.sh"

    for content in ("SUBSCRIPTION_ENABLED=true\n", "SUBSCRIPTION_ENABLED=true\nSUBSCRIPTION_PUBLIC_PORT=nope\n"):
        env_file.write_text(content, encoding="utf-8")
        result = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            env={"PATH": f"{stub_bin}:/usr/bin:/bin", "ENV_FILE": str(env_file), "HOME": str(tmp_path)},
            timeout=60,
        )
        assert result.returncode != 0
        assert "ufw-subscription:" in result.stderr


def test_docs_document_the_tls_decision_and_the_reading_user() -> None:
    """The runbook must state HOW TLS is terminated and UNDER WHICH USER the key
    is read — the two facts an operator cannot infer from the unit alone."""
    for doc in (ROOT / "docs" / "subscription.md", ROOT / "docs" / "subscription.ru.md"):
        text = doc.read_text(encoding="utf-8")
        assert "ssl_context" in text
        assert "vpn-bot" in text
        assert "acme.sh" in text
        assert "0640" in text
        assert "ufw-subscription.sh" in text
