"""Tests for the off-site recovery bundle (.env + service configs).

The recovery bundle is a second encrypted artifact sent alongside the existing
``*.db.enc`` DB backup. These tests cover the in-memory tar build, the manifest,
best-effort skipping of unreadable/missing sources, the shared Fernet TTL, and
the delivery glue (send method + scheduler loop).
"""
from __future__ import annotations

import asyncio
import io
import json
import tarfile
import time
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from adapters.clock import ClockProvider
from services.offsite_backup import OffsiteBackupService, offsite_backup_loop


def _make_service(
    *,
    sources,
    include_recovery: bool = True,
    encryption_key: str | None = None,
) -> OffsiteBackupService:
    key = encryption_key if encryption_key is not None else Fernet.generate_key().decode()
    return OffsiteBackupService(
        db=object(),  # type: ignore[arg-type]  # recovery path never touches the DB
        db_path=Path("/nonexistent/vpn.db"),
        encryption_key=key,
        clock=ClockProvider(),
        recovery_sources=sources,
        include_recovery=include_recovery,
    )


def _extract(service: OffsiteBackupService, encrypted: bytes) -> tuple[dict, dict[str, bytes]]:
    raw = service.decrypt_backup(encrypted)
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for member in tar.getmembers():
            extracted = tar.extractfile(member)
            members[member.name] = extracted.read() if extracted is not None else b""
    manifest = json.loads(members["MANIFEST.json"])
    return manifest, members


class FakeBot:
    def __init__(self, fail_for: frozenset[int] = frozenset()) -> None:
        self.documents: list[tuple[int, bytes, str]] = []
        self._fail_for = fail_for

    async def send_document(self, chat_id, *, document, caption=None):  # noqa: ANN001
        if chat_id in self._fail_for:
            raise RuntimeError("send failed")
        self.documents.append((chat_id, document.data, document.filename))


@pytest.mark.asyncio
async def test_recovery_bundle_roundtrips_files_and_manifest(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("BOT_TOKEN=secret\nOFFSITE_BACKUP_ENCRYPTION_KEY=k\n", encoding="utf-8")
    xray = tmp_path / "xray" / "config.json"
    xray.parent.mkdir()
    xray.write_text('{"inbounds": []}', encoding="utf-8")

    service = _make_service(sources=[env_file, xray])
    built = await service.create_recovery_bundle()
    assert built is not None
    encrypted, filename = built
    assert filename.startswith("vpnbot_recovery_")
    assert filename.endswith(".tar.gz.enc")

    manifest, members = _extract(service, encrypted)
    assert "MANIFEST.json" in members
    included = {entry["path"]: entry for entry in manifest["files"]}
    assert included[str(env_file)]["included"] is True
    assert included[str(xray)]["included"] is True

    # Every included member is stored under files/ with no path escape, and its
    # bytes round-trip exactly.
    for entry in manifest["files"]:
        if not entry["included"]:
            continue
        member = entry["member"]
        assert member.startswith("files/")
        assert ".." not in member
        assert members[member] == Path(entry["path"]).read_bytes()


@pytest.mark.asyncio
async def test_recovery_bundle_skips_missing_sources(tmp_path: Path) -> None:
    present = tmp_path / "present.conf"
    present.write_text("data", encoding="utf-8")
    missing = tmp_path / "missing.conf"

    service = _make_service(sources=[present, missing])
    built = await service.create_recovery_bundle()
    assert built is not None
    encrypted, _ = built

    manifest, members = _extract(service, encrypted)
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    assert by_path[str(present)]["included"] is True
    assert by_path[str(missing)]["included"] is False
    assert "reason" in by_path[str(missing)]
    # The missing file contributes no tar member.
    assert all(not name.endswith("missing.conf") for name in members)


@pytest.mark.asyncio
async def test_recovery_bundle_none_when_no_readable_sources(tmp_path: Path) -> None:
    service = _make_service(sources=[tmp_path / "a.conf", tmp_path / "b.conf"])
    assert await service.create_recovery_bundle() is None


@pytest.mark.asyncio
async def test_recovery_disabled_when_flag_off(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")
    service = _make_service(sources=[present], include_recovery=False)
    assert service.recovery_enabled is False
    assert await service.send_recovery_to_admins(FakeBot(), frozenset({1})) is None  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_recovery_disabled_without_key(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")
    service = _make_service(sources=[present], encryption_key="")
    assert service.recovery_enabled is False
    with pytest.raises(RuntimeError, match="OFFSITE_BACKUP_ENCRYPTION_KEY"):
        await service.create_recovery_bundle()


@pytest.mark.asyncio
async def test_recovery_bundle_ttl_enforced(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")
    key = Fernet.generate_key().decode()
    service = _make_service(sources=[present], encryption_key=key)

    # A token older than the TTL must be rejected by the shared decrypt path.
    fernet = Fernet(key.encode())
    stale = fernet.encrypt_at_time(b"payload", int(time.time()) - 40 * 86400)
    with pytest.raises(RuntimeError, match="устарел"):
        service.decrypt_backup(stale)


@pytest.mark.asyncio
async def test_send_recovery_to_admins_delivers_per_admin(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")
    service = _make_service(sources=[present])
    bot = FakeBot(fail_for=frozenset({2}))

    result = await service.send_recovery_to_admins(bot, frozenset({1, 2}))  # type: ignore[arg-type]
    assert result == {"success": 1, "failed": 1, "total": 2}
    # The delivered document decrypts back to a valid tar bundle.
    assert len(bot.documents) == 1
    _, data, filename = bot.documents[0]
    assert filename.endswith(".tar.gz.enc")
    raw = service.decrypt_backup(data)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        assert "MANIFEST.json" in tar.getnames()


@pytest.mark.asyncio
async def test_encrypted_db_backup_roundtrips_and_verifies_integrity(tmp_path: Path) -> None:
    # P5-006: a real DB snapshot round-trips through create -> decrypt and opens as
    # a consistent SQLite image. P5-005: the filename carries seconds resolution.
    import sqlite3

    from db.database import Database

    db_path = tmp_path / "vpn.db"
    db = Database(db_path)
    await db.connect()
    try:
        await db.bootstrap()
    finally:
        await db.close()

    service = OffsiteBackupService(
        db=object(),  # type: ignore[arg-type]
        db_path=db_path,
        encryption_key=Fernet.generate_key().decode(),
        clock=ClockProvider(),
    )

    encrypted, filename = await service.create_encrypted_backup()
    assert filename.startswith("vpnbot_backup_") and filename.endswith(".db.enc")
    # Stamp keeps seconds: YYYYMMDDThhmmss -> "T" at index 8, 15-char stamp.
    stamp = filename[len("vpnbot_backup_") : -len(".db.enc")]
    assert len(stamp) == 15 and stamp[8] == "T"

    raw = service.decrypt_backup(encrypted)
    restored = tmp_path / "restored.db"
    restored.write_bytes(raw)
    conn = sqlite3.connect(str(restored))
    try:
        assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone() is not None
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_dedupes_recovery_sources(tmp_path: Path) -> None:
    present = tmp_path / "x.conf"
    present.write_text("data", encoding="utf-8")
    service = _make_service(sources=[present, present])
    built = await service.create_recovery_bundle()
    assert built is not None
    manifest, _ = _extract(service, built[0])
    assert sum(1 for e in manifest["files"] if e["path"] == str(present)) == 1


class _FakeService:
    """Minimal stand-in for OffsiteBackupService to drive offsite_backup_loop."""

    def __init__(self, recovery_enabled: bool) -> None:
        self.recovery_enabled = recovery_enabled
        self.backup_sent = 0
        self.recovery_sent = 0
        self.recorded = 0

    async def get_last_backup_time(self):
        return None

    async def send_to_admins(self, bot, admin_ids):  # noqa: ANN001
        self.backup_sent += 1
        return {"success": 1, "failed": 0, "total": len(admin_ids)}

    async def record_backup_sent(self) -> None:
        self.recorded += 1

    async def send_recovery_to_admins(self, bot, admin_ids):  # noqa: ANN001
        self.recovery_sent += 1
        return {"success": 1, "failed": 0, "total": len(admin_ids)}


@pytest.mark.asyncio
async def test_loop_sends_both_artifacts(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeService(recovery_enabled=True)
    calls = {"n": 0}

    async def fake_sleep(_delay: float) -> None:
        calls["n"] += 1
        # First sleep is the startup delay; the second is the trailing
        # sleep(interval) after one full iteration — stop there.
        if calls["n"] >= 2:
            raise asyncio.CancelledError

    monkeypatch.setattr("services.offsite_backup.asyncio.sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await offsite_backup_loop(service, FakeBot(), frozenset({1}), interval=10)  # type: ignore[arg-type]

    assert service.backup_sent == 1
    assert service.recorded == 1
    assert service.recovery_sent == 1


@pytest.mark.asyncio
async def test_loop_skips_recovery_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeService(recovery_enabled=False)
    calls = {"n": 0}

    async def fake_sleep(_delay: float) -> None:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise asyncio.CancelledError

    monkeypatch.setattr("services.offsite_backup.asyncio.sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await offsite_backup_loop(service, FakeBot(), frozenset({1}), interval=10)  # type: ignore[arg-type]

    assert service.backup_sent == 1
    assert service.recovery_sent == 0
