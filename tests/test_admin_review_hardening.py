"""Regression tests for the P6 admin-interface review fixes.

Covers:
  P6-001  server-status reset gated behind the superadmin check
  P6-004  key-issue confirm serialised against a double-tap
  P6-007  split report escapes the raw (admin-typed) token
  P6-008  split panel drops the delete button for an unsafe entry
  P6-009  reply-keyboard filters match every locale variant
"""
import asyncio
from types import SimpleNamespace

from bot.handlers.admin import admin_issue_confirm
from bot.handlers.admin_dashboard import admin_server_status
from bot.handlers.admin_warp_split import _format_add_report
from bot.keyboards.warp_split_keyboard import _deletable, warp_split_panel_keyboard
from i18n import _CATALOGS, all_variants
from models.dto import User
from models.enums import UserRole, VpnKeyType
from services.errors import AccessDenied


class _Callback:
    def __init__(self, data: str, user_id: int = 1) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="user", first_name="User")
        self.message = SimpleNamespace(message_id=1)
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _State:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self.data = data or {}
        self.state: object | None = None

    async def get_data(self) -> dict[str, object]:
        return dict(self.data)

    async def set_state(self, state: object) -> None:
        self.state = state

    async def update_data(self, **kwargs: object) -> None:
        self.data.update(kwargs)

    async def clear(self) -> None:
        self.data.clear()
        self.state = None


async def _allow_private(*args: object, **kwargs: object) -> bool:
    return True


# ── P6-009: locale-independent reply-keyboard filters ────────────────────────


def test_all_variants_covers_every_locale() -> None:
    variants = all_variants("btn_admin_panel")
    assert _CATALOGS["ru"]["btn_admin_panel"] in variants
    assert _CATALOGS["en"]["btn_admin_panel"] in variants
    # Distinct wording per locale, so both must be present (this is the whole point).
    assert len(variants) >= 2
    # An unknown key yields an empty set rather than {key} or a crash.
    assert all_variants("__no_such_key__") == frozenset()


# ── P6-008: split panel button length/validity guard ─────────────────────────


def test_deletable_accepts_ipv4_rejects_others() -> None:
    assert _deletable("10.0.0.0/8") is True
    assert _deletable("255.255.255.255/32") is True
    assert _deletable("2001:db8::/32") is False  # IPv6 unsupported
    assert _deletable("garbage-line") is False


def test_split_panel_omits_delete_for_unsafe_entries() -> None:
    entries = ["10.0.0.0/8", "2001:db8::/32", "garbage-line"]
    markup = warp_split_panel_keyboard(entries, 0)
    callbacks = [b.callback_data for row in markup.inline_keyboard for b in row]
    # Valid IPv4 keeps its delete button; the unsafe rows are shown read-only.
    assert "wsplit:del:10.0.0.0/8" in callbacks
    assert "wsplit:del:2001:db8::/32" not in callbacks
    assert "wsplit:del:garbage-line" not in callbacks
    # No button may exceed Telegram's 64-byte callback_data limit.
    assert all(len(c.encode("utf-8")) <= 64 for c in callbacks)


# ── P6-007: split report escapes the raw admin-typed token ───────────────────


def test_split_add_report_escapes_rejected_raw_token() -> None:
    rejected = SimpleNamespace(status="rejected", raw="<b>x</b>", canonical="", note="bad & ugly")
    out = _format_add_report([rejected], changed=False)
    assert "<b>x</b>" not in out                 # not injected as live HTML
    assert "&lt;b&gt;x&lt;/b&gt;" in out         # escaped instead
    assert "bad &amp; ugly" in out               # note escaped too


# ── P6-001: server-status reset gated behind the superadmin check ────────────


def test_server_status_non_admin_does_not_touch_shared_state(monkeypatch) -> None:
    reset_calls: list[int] = []
    started: list[int] = []
    errors: list[Exception] = []

    async def deny(services: object, uid: int) -> None:
        raise AccessDenied("no")

    async def record_error(cb: object, exc: Exception) -> None:
        errors.append(exc)

    monkeypatch.setattr("bot.handlers.admin_dashboard.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin_dashboard.require_superadmin", deny)
    monkeypatch.setattr("bot.handlers.admin_dashboard.answer_callback_error", record_error)

    services = SimpleNamespace(
        server_status=SimpleNamespace(reset_network_history=lambda: reset_calls.append(1), detailed=False),
        auto_refresh=SimpleNamespace(start=lambda *a, **k: started.append(1)),
    )

    async def run() -> None:
        callback = _Callback("admin:server_status", user_id=999)
        await admin_server_status(callback, services)  # type: ignore[arg-type]

    asyncio.run(run())
    assert reset_calls == []       # shared sampler window untouched
    assert started == []           # no auto-refresh loop spun up
    assert errors and isinstance(errors[0], AccessDenied)


# ── P6-004: key-issue confirm serialised against a double-tap ────────────────


def test_key_issue_confirm_double_tap_creates_one_key(monkeypatch) -> None:
    create_calls: list[int] = []
    answers: list[tuple[str, bool | None]] = []

    async def fake_require(services: object, uid: int) -> User:
        return User(uid, "admin", "Admin", UserRole.SUPERADMIN, "now", "now", None)

    async def fake_get_user(uid: int) -> User:
        return User(uid, "owner", "Owner", UserRole.APPROVED_USER, "now", "now", None)

    async def fake_create_xray_key(*args: object, **kwargs: object) -> object:
        create_calls.append(1)
        await asyncio.sleep(0)  # yield so a second tap could interleave without the lock
        return SimpleNamespace(
            key=SimpleNamespace(key_type=VpnKeyType.XRAY, owner_user_id=200, id=70),
            config_text="cfg",
        )

    async def fake_answer(cb: object, text: str | None = None, show_alert: bool | None = None, **k: object) -> None:
        answers.append((text or "", show_alert))

    async def fake_noop(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr("bot.handlers.admin.ensure_private_callback", _allow_private)
    monkeypatch.setattr("bot.handlers.admin.require_superadmin", fake_require)
    monkeypatch.setattr("bot.handlers.admin.safe_callback_answer", fake_answer)
    monkeypatch.setattr("bot.handlers.admin.safe_edit_message_text", fake_noop)
    monkeypatch.setattr("bot.handlers.admin.key_actions_keyboard", lambda *a, **k: None)

    services = SimpleNamespace(
        users=SimpleNamespace(get_user=fake_get_user),
        xray=SimpleNamespace(create_xray_key=fake_create_xray_key),
    )
    rate_limiter = SimpleNamespace(check=lambda *a, **k: None)
    state = _State({"owner_user_id": 200, "key_type": VpnKeyType.XRAY.value})

    async def run() -> None:
        c1 = _Callback("admin:cconfirm", user_id=5)
        c2 = _Callback("admin:cconfirm", user_id=5)
        await asyncio.gather(
            admin_issue_confirm(c1, state, services, rate_limiter, SimpleNamespace()),  # type: ignore[arg-type]
            admin_issue_confirm(c2, state, services, rate_limiter, SimpleNamespace()),  # type: ignore[arg-type]
        )
        # Exactly one creation despite two concurrent confirms; the loser is told it's stale.
        assert create_calls == [1]
        stale = [a for a in answers if a[1]]  # answers sent with show_alert=True
        assert stale, "second tap should surface an action-stale alert"

    asyncio.run(run())
