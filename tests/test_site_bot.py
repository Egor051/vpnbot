"""«🌐 Сайт» from the bot: services/site.py, bot/handlers/admin_site.py, the spiderX re-layout.

* The archive is staged where root reads it (0600, its digest), refused early when it is
  empty, too big or not a zip / tar.gz; the screen reads ``vpn-bot-site status --json``.
* The buttons start runs of the wizard's ``site`` mode (TOTP first), the document handler
  stages the archive and starts the deploy with its digest.
* After a run that succeeded, the keys whose STORED spiderX the new site no longer has get
  the pick a fresh key would get from the new pool — the explicit step, never the
  every-start backfill (which fills NULLs only) — on a database upgraded from the newest
  production snapshot too.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import InlineKeyboardMarkup
from site_fakes import HELPER, SITE_V2, tar_gz_bytes, zip_bytes
from test_admin_fallback_ui import FakeCallback, FakeMessage
from test_admin_wizard_handlers import FakeTotp, FakeWizard, wizard_run
from test_relay import ADMIN

from bot.fsm.states import SiteStates, TotpStates
from bot.handlers import admin_site
from bot.site_views import screen_keyboard, screen_text
from bot.wizard_views import final_text, menu_keyboard
from db.database import Database
from models.dto import ShellResult
from models.enums import UserRole, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.errors import ServiceError
from services.site import MAX_ARCHIVE_BYTES, SiteError, SiteService, SiteStatus
from services.wizard import Item, StatusSnapshot
from utils.spider_x import pick_spider_x

pytestmark = pytest.mark.timeout(60)
POOL_AFTER = ["/", "/docs/", "/docs/api.html", "/status.html"]


def report(**over: Any) -> dict[str, Any]:
    """What vpn-bot-site status says about the production host after one deploy."""
    base: dict[str, Any] = {
        "version": 1, "ok": True, "problems": [], "docroot": "/var/www/anycastedge", "domain": "site.example.com",
        "vhost": "/etc/nginx/conf.d/anycastedge.conf", "exists": True,
        "current": {"tree": "b0b36c6f88b8" + "0" * 52, "files": 6, "bytes": 165, "pages": 4, "symlinks": 0,
                    "complete": True, "deployed_at": "2026-11-26T11:38:26Z", "run": 7, "source": "upload",
                    "archive": "472285b41cbf" + "0" * 52, "modified": False, "newest_mtime": "2026-11-26T11:38:26Z"},
        "pages": POOL_AFTER, "pages_total": 4,
        "releases": [{"id": "20261126T113826Z-fba40f8635ee", "tree": "fba40f8635ee", "pages": 3, "files": 5,
                      "bytes": 125, "kind": "previous", "stored_at": "2026-11-26T11:38:26Z", "deployed_at": None,
                      "source": "host"}],
        "revert_to": "20261126T113826Z-fba40f8635ee",
        "spx": {"enabled": True, "pool": POOL_AFTER, "missing": [], "in_sync": True},
        "hy2": {"layout": "proxy", "detail": "https://127.0.0.1:8443"},
        "limits": {"archive": MAX_ARCHIVE_BYTES, "files": 1000, "bytes": 64 << 20, "file": 16 << 20, "depth": 12,
                   "ext": [".css", ".html", ".js"], "keep": 5},
        "journal": {"run": 7, "state": "committed"},
    }
    base.update(over)
    return base


class Runner:
    def __init__(self, data: dict[str, Any] | None, rc: int = 0) -> None:
        self.data = data
        self.rc = rc
        self.calls: list[tuple[str, list[str]]] = []

    async def run(self, helper: Path, args: list[str], **_: Any) -> ShellResult:
        self.calls.append((str(helper), list(args)))
        out = json.dumps(self.data) + "\n" if self.data is not None else "garbage\n"
        return ShellResult(args=tuple(args), returncode=self.rc, stdout=out, stderr="")


class Users:
    async def require_superadmin(self, user_id: int) -> object:
        return object()


class Keys:
    def __init__(self, moved: int = 2) -> None:
        self.moved = moved
        self.calls: list[tuple[str, ...]] = []

    async def relayout_spider_x(self, pool: tuple[str, ...], now: str) -> int:
        self.calls.append(pool)
        return self.moved


class Audit:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    async def write_best_effort(self, **kw: Any) -> None:
        self.rows.append(kw)


class Clock:
    def now(self) -> str:
        return "2026-11-26T12:00:00+00:00"


class Wizard(FakeWizard):
    def __init__(self) -> None:
        super().__init__()
        self.after: dict[str, Any] = {}
        self.listeners: list[Any] = []
        self.raw: list[Any] = []

    def register_after_success(self, mode: str, hook: Any) -> None:
        self.after[mode] = hook

    def add_finish_listener(self, listener: Any) -> None:
        self.listeners.append(listener)

    async def start(self, actor: int, mode: str, raw: Any = None, **kw: Any) -> Any:
        self.raw.append(raw)
        return await super().start(actor, mode, raw, **kw)


def make_site(tmp_path: Path, data: dict[str, Any] | None = None, *, keys: Keys | None = None) -> tuple[SiteService, Runner, Wizard, Audit]:
    helper = tmp_path / "vpn-bot-site"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    runner = Runner(report() if data is None else data)
    wizard = Wizard()
    audit = Audit()
    site = SiteService(runner=runner, wizard=wizard, users=Users(), keys=keys or Keys(), audit=audit,  # type: ignore[arg-type]
                       clock=Clock(), staging_dir=tmp_path / "run" / "site", helper=helper)  # type: ignore[arg-type]
    return site, runner, wizard, audit


def _fsm() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=ADMIN, user_id=ADMIN))


def _callbacks(markup: InlineKeyboardMarkup) -> list[str]:
    return [str(button.callback_data) for row in markup.inline_keyboard for button in row]


@pytest.fixture(autouse=True)
def _private_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    async def yes(*_: Any) -> bool:
        return True

    monkeypatch.setattr(admin_site, "ensure_private_callback", yes)
    monkeypatch.setattr(admin_site, "ensure_private_message", yes)


# --------------------------------------------------------------------------- #
# The service
# --------------------------------------------------------------------------- #
def test_the_bots_archive_limit_is_the_helpers() -> None:
    assert "MAX_ARCHIVE_BYTES = 20 << 20" in HELPER.read_text(encoding="utf-8")
    assert MAX_ARCHIVE_BYTES == 20 << 20


def test_the_sudoers_grant_is_status_only() -> None:
    """The bot only READS the site; every change is a wizard run (VPN_BOT_WIZARD)."""
    text = (HELPER.parents[1] / "deploy/sudoers.d/vpn-bot.example").read_text(encoding="utf-8")
    grants = [ln.strip().rstrip(", \\") for ln in text.splitlines() if "/usr/local/sbin/vpn-bot-site" in ln
              and not ln.lstrip().startswith("#")]
    assert grants == ["/usr/local/sbin/vpn-bot-site status --json"]
    user_line = next(ln for ln in text.splitlines() if ln.startswith("vpn-bot ALL=(root) NOPASSWD:"))
    assert user_line.rstrip().endswith(", VPN_BOT_SITE")


def test_stage_writes_the_archive_privately_and_returns_its_digest(tmp_path: Path) -> None:
    import hashlib

    site, *_ = make_site(tmp_path)
    data = zip_bytes(SITE_V2)
    digest = site.stage(data)
    assert digest == hashlib.sha256(data).hexdigest()[:16] and len(digest) == 16
    assert site.upload_path.read_bytes() == data
    assert stat.S_IMODE(site.upload_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(site.upload_path.parent.stat().st_mode) == 0o700
    assert site.stage(tar_gz_bytes(SITE_V2)) != digest, "a second upload replaces the first"
    site.discard_upload()
    assert not site.upload_path.exists()


@pytest.mark.parametrize(("data", "key"), [
    (b"", "site_err_empty"),
    (b"PK\x03\x04" + b"\0" * MAX_ARCHIVE_BYTES, "site_err_too_large"),
    (b"<html>not an archive</html>", "site_err_not_archive"),
])
def test_stage_refuses_what_is_no_archive(tmp_path: Path, data: bytes, key: str) -> None:
    site, *_ = make_site(tmp_path)
    with pytest.raises(SiteError) as exc:
        site.stage(data)
    assert exc.value.key == key
    assert not site.upload_path.exists()


def test_stage_does_not_write_through_a_symlinked_directory(tmp_path: Path) -> None:
    site, *_ = make_site(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    site.staging_dir.parent.mkdir(parents=True)
    site.staging_dir.symlink_to(elsewhere)
    with pytest.raises(SiteError) as exc:
        site.stage(zip_bytes(SITE_V2))
    assert exc.value.key == "site_err_staging" and not any(elsewhere.iterdir())


async def test_status_reads_the_helper_and_survives_a_refusal_report(tmp_path: Path) -> None:
    site, runner, *_ = make_site(tmp_path)
    status = await site.status(ADMIN)
    assert status.docroot == "/var/www/anycastedge" and status.pool == tuple(POOL_AFTER) and status.ok
    assert runner.calls == [(str(site.helper), ["status", "--json"])]
    runner.data, runner.rc = report(ok=False, problems=["no nginx vhost listens on 127.0.0.1:8443"]), 3
    status = await site.status(ADMIN)
    assert not status.ok and status.problems
    runner.data = None
    with pytest.raises(ServiceError) as exc:
        await site.status(ADMIN)
    assert exc.value.key == "site_err_status"


async def test_start_runs_the_site_mode_with_the_digest(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    await site.start(ADMIN, "deploy", digest="0123456789abcdef", chat_id=1, message_id=2)
    await site.start(ADMIN, "revert", digest="ignored", chat_id=1, message_id=3)
    assert wizard.raw == [{"action": "deploy", "digest": "0123456789abcdef"}, {"action": "revert", "digest": ""}]
    assert [m for m, _ in wizard.started] == ["site", "site"]
    with pytest.raises(SiteError):
        await site.start(ADMIN, "deploy")


async def test_after_success_relays_the_keys_to_the_new_pool(tmp_path: Path) -> None:
    keys = Keys(moved=2)
    site, _, wizard, audit = make_site(tmp_path, keys=keys)
    assert wizard.after["site"] == site.after_success
    note = await site.after_success(wizard_run(mode="site", state="succeeded", id=9))
    assert keys.calls == [tuple(POOL_AFTER)]
    assert note == "spiderX: 2 key(s) moved to paths of the new site"
    assert audit.rows[0]["action"] == "site_spider_x_relayout" and audit.rows[0]["details"] == {"keys": 2, "pool": 4}
    keys.moved = 0
    assert await site.after_success(wizard_run(mode="site", state="succeeded")) is None


async def test_after_success_with_spx_off_or_no_status(tmp_path: Path) -> None:
    keys = Keys()
    site, runner, *_ = make_site(tmp_path, report(spx={"enabled": False, "pool": [], "missing": [], "in_sync": False}), keys=keys)
    assert await site.after_success(wizard_run(mode="site", state="succeeded")) is None
    runner.data = None
    note = await site.after_success(wizard_run(mode="site", state="succeeded"))
    assert note is not None and "not re-laid" in note
    assert keys.calls == []


async def test_a_finished_site_run_drops_the_bots_copy_of_the_archive(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    site.stage(zip_bytes(SITE_V2))
    (listener,) = wizard.listeners
    await listener(wizard_run(mode="cert", state="failed"))
    assert site.upload_path.exists()
    await listener(wizard_run(mode="site", state="failed"))
    assert not site.upload_path.exists()


# --------------------------------------------------------------------------- #
# The re-layout of the stored spiderX (repositories/vpn_keys.py)
# --------------------------------------------------------------------------- #
async def _keys_db(tmp_path: Path) -> tuple[Database, VpnKeyRepository, dict[str, int]]:
    db = Database(tmp_path / "vpn.db")
    await db.connect()
    await db.bootstrap()
    await db.conn.execute(
        "INSERT INTO users (telegram_user_id, username, first_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (100, "user", "User", UserRole.APPROVED_USER.value, "now", "now"),
    )
    await db.commit()
    repo = VpnKeyRepository(db)
    ids: dict[str, int] = {}
    for uuid_value, spx in (("aaaa0001-0000-4000-8000-000000000001", "/"),
                            ("aaaa0002-0000-4000-8000-000000000002", "/about.html"),
                            ("aaaa0003-0000-4000-8000-000000000003", "/blog/"),
                            ("aaaa0004-0000-4000-8000-000000000004", None)):
        key = await repo.create_pending(owner_user_id=100, username="user", key_type=VpnKeyType.XRAY, note=None,
                                        payload={"uuid": uuid_value}, public_payload={}, created_by=100, now="now",
                                        uuid=uuid_value, spider_x=spx)
        ids[uuid_value] = key.id
    awg = await repo.create_pending(owner_user_id=100, username="user", key_type=VpnKeyType.AWG, note=None,
                                    payload={}, public_payload={}, created_by=100, now="now", public_key="wg-pub")
    ids["awg"] = awg.id
    return db, repo, ids


async def test_relayout_moves_only_the_keys_whose_path_left_the_pool(tmp_path: Path) -> None:
    db, repo, ids = await _keys_db(tmp_path)
    try:
        pool = tuple(POOL_AFTER)
        moved = await repo.relayout_spider_x(pool, "later")
        assert moved == 2
        got = {u: (await repo.get_by_id(i)).spider_x for u, i in ids.items()}  # type: ignore[union-attr]
        assert got["aaaa0001-0000-4000-8000-000000000001"] == "/", "a path still on the site is kept"
        for u in ("aaaa0002-0000-4000-8000-000000000002", "aaaa0003-0000-4000-8000-000000000003"):
            assert got[u] == pick_spider_x(u, pool), "the pick a fresh key would get"
        assert got["aaaa0004-0000-4000-8000-000000000004"] is None, "a NULL is the backfill's"
        assert got["awg"] is None
        assert await repo.relayout_spider_x(pool, "again") == 0, "idempotent"
        assert await repo.relayout_spider_x((), "off") == 0
    finally:
        await db.close()


async def test_the_every_start_backfill_still_never_overwrites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The re-layout is the site run's step only: a bootstrap with a new pool fills the
    NULL key and leaves every assigned value (also one the pool no longer has)."""
    db, repo, ids = await _keys_db(tmp_path)
    try:
        monkeypatch.setenv("XRAY_SPIDER_X_POOL", ",".join(POOL_AFTER))
        await db._ensure_spider_x_backfill()
        await db.commit()
        assert (await repo.get_by_id(ids["aaaa0002-0000-4000-8000-000000000002"])).spider_x == "/about.html"  # type: ignore[union-attr]
        filled = (await repo.get_by_id(ids["aaaa0004-0000-4000-8000-000000000004"])).spider_x  # type: ignore[union-attr]
        assert filled in POOL_AFTER
    finally:
        await db.close()


async def test_relayout_on_a_database_upgraded_from_the_production_snapshot(tmp_path: Path) -> None:
    """The newest schema snapshot (+ the fidelity dataset), upgraded by bootstrap(): the
    row-level step works on what production has."""
    from test_schema_upgrade_path import _snapshot_versions
    from test_schema_upgrade_row_fidelity import _bootstrap, _prepare

    newest = max(v for v in _snapshot_versions())
    db_path, _, _ = await _prepare(tmp_path, newest)
    await _bootstrap(db_path)
    db = Database(db_path)
    await db.connect()
    try:
        repo = VpnKeyRepository(db)
        pool = ("/", "/docs/")
        assert await repo.relayout_spider_x(pool, "2026-11-26T12:00:00+00:00") == 1
        key = await repo.get_by_id(5101)
        assert key is not None and key.spider_x == pick_spider_x("5101aaaa-0000-4000-8000-000000005101", pool)
        assert (await repo.get_by_id(5102)).spider_x is None  # type: ignore[union-attr]
    finally:
        await db.close()


# --------------------------------------------------------------------------- #
# The screen and its buttons
# --------------------------------------------------------------------------- #
def _services(site: SiteService, wizard: Wizard, totp: Any = None) -> Any:
    return SimpleNamespace(site=site, wizard=wizard, users=Users(), totp=totp)


async def test_the_screen_shows_the_version_the_kept_ones_and_the_pool(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    cb = FakeCallback("site:menu")
    await admin_site.site_menu(cb, _fsm(), _services(site, wizard))  # type: ignore[arg-type]
    text, markup = cb.message.edits[-1]
    assert "/var/www/anycastedge" in text and "site.example.com" in text and "b0b36c6f88b8" in text
    assert "#7" in text and "20261126T113826Z-fba40f8635ee" in text and "4" in text
    assert "***" not in text
    assert _callbacks(markup) == ["site:upload", "site:revert", "site:pages:0", "site:menu", "wiz:menu"]


def test_a_hand_made_site_without_kept_versions_offers_no_revert() -> None:
    status = SiteStatus(report(revert_to=None, releases=[], current={**report()["current"], "deployed_at": None, "run": None,
                                                                     "source": "host"}))
    text = screen_text(status)
    assert "2026-11-26 11:38 UTC" in text
    assert "site:revert" not in _callbacks(screen_keyboard(status))
    refused = SiteStatus(report(ok=False, problems=["no nginx vhost listens on 127.0.0.1:8443"]))
    assert "site:upload" not in _callbacks(screen_keyboard(refused)) and "no nginx vhost" in screen_text(refused)


async def test_upload_asks_the_totp_first(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    state = _fsm()
    cb = FakeCallback("site:upload")
    await admin_site.site_upload(cb, state, _services(site, wizard, FakeTotp(enabled=True)))  # type: ignore[arg-type]
    assert await state.get_state() == TotpStates.gate_code.state
    assert not cb.message.edits


async def test_upload_then_a_document_stages_it_and_starts_the_deploy(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    services = _services(site, wizard)
    state = _fsm()
    cb = FakeCallback("site:upload")
    await admin_site.site_upload(cb, state, services)  # type: ignore[arg-type]
    assert await state.get_state() == SiteStates.archive.state
    assert "zip" in cb.message.edits[-1][0] and "20" in cb.message.edits[-1][0]

    data = zip_bytes(SITE_V2)
    msg = FakeMessage()
    msg.document = SimpleNamespace(file_size=len(data), file_name="site.zip")  # type: ignore[attr-defined]

    class Bot:
        async def download(self, document: Any, destination: Any) -> None:
            destination.write(data)

    await admin_site.site_archive_input(msg, state, services, Bot())  # type: ignore[arg-type]
    assert await state.get_state() is None
    import hashlib

    assert wizard.raw == [{"action": "deploy", "digest": hashlib.sha256(data).hexdigest()[:16]}]
    assert site.upload_path.read_bytes() == data
    holder = msg.children[0]
    assert "site.zip" in msg.answers[0][0] and holder.edits, "the run is rendered on a message of its own"
    assert wizard.started[0][1]["message_id"] == holder.message_id


async def test_a_document_that_is_not_an_archive_or_too_big_is_refused(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    services = _services(site, wizard)
    state = _fsm()
    await state.set_state(SiteStates.archive)

    class Bot:
        downloads = 0

        async def download(self, document: Any, destination: Any) -> None:
            Bot.downloads += 1
            destination.write(b"plain text")

    msg = FakeMessage("hello")
    msg.document = None  # type: ignore[attr-defined]
    await admin_site.site_archive_input(msg, state, services, Bot())  # type: ignore[arg-type]
    big = FakeMessage()
    big.document = SimpleNamespace(file_size=MAX_ARCHIVE_BYTES + 1, file_name="big.zip")  # type: ignore[attr-defined]
    await admin_site.site_archive_input(big, state, services, Bot())  # type: ignore[arg-type]
    assert Bot.downloads == 0, "a too big document is not even downloaded"
    text = FakeMessage()
    text.document = SimpleNamespace(file_size=10, file_name="x.zip")  # type: ignore[attr-defined]
    await admin_site.site_archive_input(text, state, services, Bot())  # type: ignore[arg-type]
    assert wizard.started == [] and not site.upload_path.exists()
    assert await state.get_state() == SiteStates.archive.state, "the prompt stays for another try"


async def test_revert_starts_the_revert_run_on_this_message(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    cb = FakeCallback("site:revert")
    await admin_site.site_revert(cb, _fsm(), _services(site, wizard))  # type: ignore[arg-type]
    assert wizard.raw == [{"action": "revert", "digest": ""}]
    assert wizard.started[0][1] == {"chat_id": ADMIN, "message_id": 10}


async def test_a_press_while_a_run_is_active_changes_nothing(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path)
    wizard.running = wizard_run(id=3, mode="cert")
    for data, handler in (("site:upload", admin_site.site_upload), ("site:revert", admin_site.site_revert)):
        cb = FakeCallback(data)
        await handler(cb, _fsm(), _services(site, wizard))  # type: ignore[operator]
        assert cb.alerts and "#3" in str(cb.alerts[-1][0]) and not cb.message.edits
    assert wizard.started == []


async def test_the_page_list(tmp_path: Path) -> None:
    site, _, wizard, _ = make_site(tmp_path, report(pages=[f"/p{i}.html" for i in range(50)], pages_total=50))
    cb = FakeCallback("site:pages:1")
    await admin_site.site_pages(cb, _services(site, wizard))  # type: ignore[arg-type]
    text, markup = cb.message.edits[-1]
    assert "/p49.html" in text and "/p0.html" not in text and "50" in text
    assert _callbacks(markup) == ["site:pages:0", "site:menu"]


# --------------------------------------------------------------------------- #
# The wizard's views know the mode
# --------------------------------------------------------------------------- #
def test_the_wizard_menu_opens_the_site_screen() -> None:
    assert "site:menu" in _callbacks(menu_keyboard(active=None, daily=False))
    assert "wiz:start:site" not in _callbacks(menu_keyboard(active=None, daily=False)), "started from its screen"


def test_the_final_report_shows_the_steps_the_checks_and_the_note() -> None:
    run = wizard_run(mode="site", state="succeeded", active=False, phase="execute")
    snap = StatusSnapshot(
        helper_steps={"site_stage": "ok", "site_swap": "ok", "site_env": "skip"},
        items=[Item("green", "pages", "all 4 page(s) answer 200 over HTTP/2")],
        result_text="the new site answers: 4 page(s) 200 over HTTP/2",
        notes=["spiderX: 2 key(s) moved to paths of the new site"],
    )
    text = final_text(run, snap)
    assert "атомарная подмена каталога" in text or "atomic swap of the directory" in text
    assert "all 4 page(s) answer 200" in text and "2 key(s) moved" in text
