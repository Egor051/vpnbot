import subprocess
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

import hy2_auth.store as store_mod
from db.database import Database
from hy2_auth.config import Hy2AuthConfigError, load_config, parse_loopback_listen
from hy2_auth.server import build_app
from hy2_auth.store import ReadOnlyKeyStore
from models.dto import TelegramUserProfile
from models.enums import UserRole, VpnKeyType
from repositories.users import UserRepository
from repositories.vpn_keys import VpnKeyRepository

ROOT = Path(__file__).resolve().parents[1]

ACTIVE_LABEL = "hy2_aaaaaaaaaaaaaaaa"
ACTIVE_SECRET = "a" * 48
REVOKED_LABEL = "hy2_bbbbbbbbbbbbbbbb"
REVOKED_SECRET = "b" * 48


async def _seed_db(tmp_path: Path) -> Database:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    users = UserRepository(db)
    await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.APPROVED_USER, "now")
    repo = VpnKeyRepository(db)
    active = await repo.create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.HYSTERIA2,
        note=None,
        payload={"secret": ACTIVE_SECRET, "email_label": ACTIVE_LABEL},
        public_payload={"email_label": ACTIVE_LABEL},
        created_by=100,
        now="now",
        email_label=ACTIVE_LABEL,
    )
    await repo.mark_active(active.id, "now")
    revoked = await repo.create_pending(
        owner_user_id=100,
        username="user",
        key_type=VpnKeyType.HYSTERIA2,
        note=None,
        payload={"secret": REVOKED_SECRET, "email_label": REVOKED_LABEL},
        public_payload={"email_label": REVOKED_LABEL},
        created_by=100,
        now="now",
        email_label=REVOKED_LABEL,
    )
    await repo.mark_active(revoked.id, "now")
    await repo.mark_revoked(revoked.id, 100, "now")
    return db


# ── config: loopback-only bind ───────────────────────────────────────────────

def test_parse_loopback_listen_default_is_127() -> None:
    assert parse_loopback_listen("127.0.0.1:8444") == ("127.0.0.1", 8444)
    assert parse_loopback_listen("localhost:9000") == ("127.0.0.1", 9000)
    assert parse_loopback_listen("[::1]:8444") == ("::1", 8444)


def test_load_config_defaults_to_loopback() -> None:
    cfg = load_config({})
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 8444


@pytest.mark.parametrize("listen", ["0.0.0.0:8444", "10.0.0.5:8444", "8.8.8.8:80"])
def test_parse_loopback_listen_rejects_non_loopback(listen: str) -> None:
    with pytest.raises(Hy2AuthConfigError):
        parse_loopback_listen(listen)


def test_parse_loopback_listen_rejects_bad_format() -> None:
    with pytest.raises(Hy2AuthConfigError):
        parse_loopback_listen("127.0.0.1")
    with pytest.raises(Hy2AuthConfigError):
        parse_loopback_listen("127.0.0.1:notaport")


# ── store: read-only, live, constant-time ────────────────────────────────────

async def test_store_matches_only_active_secret(tmp_path: Path) -> None:
    db = await _seed_db(tmp_path)
    store = ReadOnlyKeyStore(db.path)
    await store.connect()
    try:
        assert await store.match(ACTIVE_SECRET) == ACTIVE_LABEL
        assert await store.match(REVOKED_SECRET) is None  # revoked: not matched
        assert await store.match("c" * 48) is None  # unknown
        assert await store.match("") is None
    finally:
        await store.close()
        await db.close()


async def test_store_connection_is_read_only(tmp_path: Path) -> None:
    db = await _seed_db(tmp_path)
    store = ReadOnlyKeyStore(db.path)
    await store.connect()
    try:
        assert "mode=ro" in store.uri
        with pytest.raises(Exception) as exc:  # sqlite3.OperationalError: readonly
            await store._conn.execute("UPDATE vpn_keys SET note = 'x' WHERE id = -1")  # type: ignore[union-attr]
        assert "readonly" in str(exc.value).lower()
    finally:
        await store.close()
        await db.close()


async def test_store_reads_revoke_live_without_cache(tmp_path: Path) -> None:
    db = await _seed_db(tmp_path)
    store = ReadOnlyKeyStore(db.path)
    await store.connect()
    try:
        assert await store.match(ACTIVE_SECRET) == ACTIVE_LABEL
        # Revoke through the writer; the next read must reflect it (no cache).
        repo = VpnKeyRepository(db)
        active = next(k for k in await repo.list_active_hysteria2() if k.email_label == ACTIVE_LABEL)
        await repo.mark_revoked(active.id, 100, "now")
        assert await store.match(ACTIVE_SECRET) is None
    finally:
        await store.close()
        await db.close()


async def test_store_uses_compare_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = await _seed_db(tmp_path)
    store = ReadOnlyKeyStore(db.path)
    await store.connect()
    calls: list[tuple[object, object]] = []
    real = store_mod.hmac.compare_digest

    def _spy(a: object, b: object) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(store_mod.hmac, "compare_digest", _spy)
    try:
        await store.match(ACTIVE_SECRET)
        assert calls, "match() must compare via hmac.compare_digest, not =="
    finally:
        await store.close()
        await db.close()


# ── endpoint: always 200, {ok,id} ────────────────────────────────────────────

async def _client(tmp_path: Path) -> tuple[TestClient, Database, ReadOnlyKeyStore]:
    db = await _seed_db(tmp_path)
    store = ReadOnlyKeyStore(db.path)
    await store.connect()
    client = TestClient(TestServer(build_app(store)))
    await client.start_server()
    return client, db, store


async def test_endpoint_active_secret_authenticates(tmp_path: Path) -> None:
    client, db, store = await _client(tmp_path)
    try:
        resp = await client.post("/auth", json={"addr": "1.2.3.4:5555", "auth": ACTIVE_SECRET, "tx": 100})
        assert resp.status == 200
        assert await resp.json() == {"ok": True, "id": ACTIVE_LABEL}
    finally:
        await client.close()
        await store.close()
        await db.close()


async def test_endpoint_revoked_and_unknown_rejected(tmp_path: Path) -> None:
    client, db, store = await _client(tmp_path)
    try:
        for token in (REVOKED_SECRET, "z" * 48, ""):
            resp = await client.post("/auth", json={"addr": "1.2.3.4:5", "auth": token, "tx": 0})
            assert resp.status == 200
            assert await resp.json() == {"ok": False}
    finally:
        await client.close()
        await store.close()
        await db.close()


async def test_endpoint_malformed_body_returns_200_not_500(tmp_path: Path) -> None:
    client, db, store = await _client(tmp_path)
    try:
        # Not JSON at all.
        resp = await client.post("/auth", data=b"this is not json", headers={"Content-Type": "application/json"})
        assert resp.status == 200
        assert await resp.json() == {"ok": False}
        # Valid JSON but missing/!str auth.
        for body in ({"addr": "x", "tx": 1}, {"auth": 123}, {"auth": None}, []):
            resp = await client.post("/auth", json=body)
            assert resp.status == 200
            assert await resp.json() == {"ok": False}
    finally:
        await client.close()
        await store.close()
        await db.close()


# ── data-plane isolation ─────────────────────────────────────────────────────

def test_hy2_auth_imports_without_bot_or_aiogram() -> None:
    code = (
        "import hy2_auth, sys; "
        "bad=[m for m in sys.modules "
        "if m=='aiogram' or m.startswith('aiogram.') or m=='bot' or m.startswith('bot.')]; "
        "print(bad); sys.exit(1 if bad else 0)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, f"bot/aiogram leaked into hy2_auth import: {result.stdout}{result.stderr}"
