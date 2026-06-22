import asyncio
from pathlib import Path

import pytest

from db.database import Database
from i18n import t
from repositories.maintenance_settings import MaintenanceSettingsRepository
from services.errors import AccessDenied
from services.maintenance import MaintenanceService


class _FakeUsers:
    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.calls: list[int] = []

    async def require_superadmin(self, actor_id: int):
        self.calls.append(actor_id)
        if not self.allow:
            raise AccessDenied("nope")
        return None


class _FakeAudit:
    def __init__(self) -> None:
        self.records: list[dict] = []

    async def write_best_effort(self, **kwargs) -> None:
        self.records.append(kwargs)


def _build(tmp_path: Path, *, allow: bool = True):
    db = Database(tmp_path / "vpn.db")
    users = _FakeUsers(allow=allow)
    audit = _FakeAudit()
    return db, users, audit


def test_enable_disable_roundtrip_and_audit(tmp_path: Path) -> None:
    async def run() -> None:
        db, users, audit = _build(tmp_path)
        await db.connect()
        try:
            await db.bootstrap()
            service = MaintenanceService(MaintenanceSettingsRepository(db), users, audit)
            await service.load()
            assert service.is_enabled() is False

            await service.enable(1, "custom banner")
            assert service.is_enabled() is True
            assert service.banner_text() == "custom banner"
            assert service.snapshot().started_by == 1

            await service.disable(1)
            assert service.is_enabled() is False

            actions = [r["action"] for r in audit.records]
            assert actions == ["maintenance_enabled", "maintenance_disabled"]
        finally:
            await db.close()

    asyncio.run(run())


def test_banner_falls_back_to_default(tmp_path: Path) -> None:
    async def run() -> None:
        db, users, audit = _build(tmp_path)
        await db.connect()
        try:
            await db.bootstrap()
            service = MaintenanceService(MaintenanceSettingsRepository(db), users, audit)
            await service.load()
            # Empty/whitespace message → default banner from i18n.
            await service.enable(1, "   ")
            assert service.snapshot().message is None
            assert service.banner_text() == t("maintenance_default_banner")
        finally:
            await db.close()

    asyncio.run(run())


def test_banner_escapes_html_in_custom_message(tmp_path: Path) -> None:
    async def run() -> None:
        db, users, audit = _build(tmp_path)
        await db.connect()
        try:
            await db.bootstrap()
            service = MaintenanceService(MaintenanceSettingsRepository(db), users, audit)
            await service.load()
            await service.enable(1, "down until 5 < 6 & back")
            # Raw text is stored; banner_text() returns an HTML-safe rendering.
            assert service.snapshot().message == "down until 5 < 6 & back"
            assert service.banner_text() == "down until 5 &lt; 6 &amp; back"
        finally:
            await db.close()

    asyncio.run(run())


def test_enable_requires_superadmin(tmp_path: Path) -> None:
    async def run() -> None:
        db, users, audit = _build(tmp_path, allow=False)
        await db.connect()
        try:
            await db.bootstrap()
            service = MaintenanceService(MaintenanceSettingsRepository(db), users, audit)
            await service.load()
            with pytest.raises(AccessDenied):
                await service.enable(999, "x")
            # State unchanged, nothing audited.
            assert service.is_enabled() is False
            assert audit.records == []
        finally:
            await db.close()

    asyncio.run(run())


def test_load_restores_persisted_state(tmp_path: Path) -> None:
    async def run() -> None:
        db_path = tmp_path / "vpn.db"
        db = Database(db_path)
        await db.connect()
        try:
            await db.bootstrap()
            await MaintenanceSettingsRepository(db).set_state(enabled=True, message="brb", started_by=5)
        finally:
            await db.close()

        db2 = Database(db_path)
        users = _FakeUsers()
        audit = _FakeAudit()
        await db2.connect()
        try:
            await db2.bootstrap()
            service = MaintenanceService(MaintenanceSettingsRepository(db2), users, audit)
            await service.load()
            assert service.is_enabled() is True
            assert service.banner_text() == "brb"
        finally:
            await db2.close()

    asyncio.run(run())
