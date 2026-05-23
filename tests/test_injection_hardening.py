
import pytest

from adapters.dante_users import DanteUserAdapter
from adapters.errors import DanteUserError
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
