
import asyncio
from pathlib import Path

import pytest

from adapters.dante_users import DanteUserAdapter
from adapters.errors import DanteUserError
from db.database import Database
from models.dto import TelegramUserProfile
from models.enums import AuditEntityType, UserRole
from repositories.audit_log import AuditLogRepository
from repositories.users import UserRepository
from services.notes import normalize_note


class _NullShell:
    async def run(self, args: list[str], **kwargs: object) -> object:
        raise AssertionError("shell should not be called in these tests")


def _adapter() -> DanteUserAdapter:
    return DanteUserAdapter(
        shell=_NullShell(),  # type: ignore[arg-type]
        login_prefix="vpn_socks_",
        system_user_shell="/usr/sbin/nologin",
    )


# ---------------------------------------------------------------------------
# G5 — chpasswd newline injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "login",
    [
        "vpn_socks_good\nbad",
        "vpn_socks_ok\nroot:injected",
        "vpn_socks_\n",
        "vpn_socks_multi\nline\ninjection",
    ],
)
def test_chpasswd_newline_injection(login: str) -> None:
    """DanteUserAdapter rejects logins containing newlines, blocking chpasswd injection."""
    adapter = _adapter()
    with pytest.raises(DanteUserError):
        adapter._ensure_managed_login(login)


def test_chpasswd_newline_injection_valid_login_passes() -> None:
    """A well-formed managed login is accepted without error."""
    adapter = _adapter()
    adapter._ensure_managed_login("vpn_socks_100_abcd")


# ---------------------------------------------------------------------------
# G5 — AWG config note newline injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "note",
    [
        "hello\nworld",
        "safe text\r\ninjected",
        "line1\rline2",
        "note with \n embedded newline",
    ],
)
def test_awg_config_note_newline_injection(note: str) -> None:
    """normalize_note rejects notes containing newlines to prevent config corruption."""
    with pytest.raises(ValueError, match="переводы строк"):
        normalize_note(note)


def test_awg_config_note_clean_note_passes() -> None:
    """A clean note without newlines is accepted by normalize_note."""
    result = normalize_note("This is a safe note")
    assert result == "This is a safe note"


def test_awg_config_note_none_returns_none() -> None:
    """normalize_note returns None for None input."""
    assert normalize_note(None) is None


# ---------------------------------------------------------------------------
# SQL parameterization — values with SQL metacharacters must be stored
# verbatim and never interpreted (verifies the S608 suppression in practice).
# ---------------------------------------------------------------------------

_SQL_INJECTION_PAYLOADS = [
    "'); DROP TABLE users;--",
    "' OR '1'='1",
    'Robert"); DROP TABLE vpn_keys;--',
    "x'; DELETE FROM users WHERE ''='",
]


@pytest.mark.parametrize("payload", _SQL_INJECTION_PAYLOADS)
def test_user_note_sql_injection_is_stored_verbatim(tmp_path: Path, payload: str) -> None:
    """A note containing SQL metacharacters is stored as data, not executed."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            users = UserRepository(db)
            await users.upsert_profile(TelegramUserProfile(100, "user", "User"), UserRole.PENDING_USER, "now")
            await users.update_note(100, payload, "now")

            # The users table still exists and the value round-trips verbatim.
            stored = await users.get_by_id(100)
            assert stored is not None
            assert stored.note == payload
            count = await users.count_users()
            assert count == 1
        finally:
            await db.close()

    asyncio.run(run())


@pytest.mark.parametrize("payload", _SQL_INJECTION_PAYLOADS)
def test_audit_entity_id_filter_sql_injection_is_inert(tmp_path: Path, payload: str) -> None:
    """A crafted entity_id / action filter is parameterized, not interpreted."""

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        try:
            await db.bootstrap()
            audit = AuditLogRepository(db)
            await audit.create(
                actor_user_id=None,
                action=payload,
                entity_type=AuditEntityType.SYSTEM,
                entity_id=payload,
                details={"note": payload},
                now="2026-01-01T00:00:00+00:00",
            )
            # Dynamic action IN-list + entity_id filter must match the literal row,
            # not trigger injection, and the audit_log table must survive.
            rows = await audit.list_recent_for_entity(
                entity_type=AuditEntityType.SYSTEM,
                entity_id=payload,
                actions={payload, "' OR 1=1 --"},
            )
            assert len(rows) == 1
            assert rows[0]["entity_id"] == payload
            assert await audit.count_all() == 1
        finally:
            await db.close()

    asyncio.run(run())
