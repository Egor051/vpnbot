
import asyncio
import logging
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.base import StorageKey
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BufferedInputFile, CallbackQuery, Chat, Message, User as TgUser
from qrcode.constants import ERROR_CORRECT_M

from bot.handlers.key_bundles import show_bundle_config
from bot.handlers.keys import show_key_config
from bot.messages import (
    CONFIG_DOC_KIND_BUNDLE,
    config_document_present,
    discard_config_document,
    remember_config_document,
    send_config_with_qr,
)
from bot.middlewares.config_cleanup import ConfigDocumentCleanupMiddleware
from models.dto import KeyBundle, VpnKey
from models.enums import KeyBundleStatus, VpnKeyStatus, VpnKeyType
from tests.qr_decode import decode_qr
from utils.qr import QrPayloadTooLarge

_TOKEN = "123456789:AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQRS"

# What each protocol hands the user, and therefore what its QR must decode to.
_VLESS_LINK = (
    "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
    "?type=xhttp&path=%2Fxhttp-multi&mode=auto&security=reality"
    "&pbk=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&fp=chrome"
    "&sni=www.microsoft.com&sid=a1b2c3d4&spx=%2F&encryption=none#awg_A7kQz"
)
_HY2_LINK = "hysteria2://c2VjcmV0dG9rZW4@vpn.example.com:443?sni=vpn.example.com#hy2_A7kQz"
_AWG_CONF = """[Interface]
PrivateKey = aGVsbG93b3JsZHRoaXNpc2Fmb3J0eXRocmVlY2hhcmtleQ=
Address = 10.8.1.37/32
DNS = 1.1.1.1, 1.0.0.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 78
S2 = 129
H1 = 1234567891
H2 = 2345678912
H3 = 3456789123
H4 = 4567891234
MTU = 1280

[Peer]
PublicKey = c2VydmVycHVibGlja2V5YmFzZTY0Zm9ydHl0aHJlZWNoYXI=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"""
_SUB_URL = "https://vpn.example.com:2096/sub/s3cr3t-subscription-token-value"


def _key(key_id: int = 10, owner_user_id: int = 100, key_type: VpnKeyType = VpnKeyType.AWG) -> VpnKey:
    return VpnKey(
        id=key_id,
        owner_user_id=owner_user_id,
        username="user",
        key_type=key_type,
        status=VpnKeyStatus.ACTIVE,
        note=None,
        uuid=None,
        email_label="awg_A7kQz",
        public_key="public",
        client_ip="10.0.0.2",
        payload={},
        public_payload={},
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        created_by=owner_user_id,
        revoked_by=None,
        deleted_by=None,
    )


def _awg_key(key_id: int = 10, owner_user_id: int = 100) -> VpnKey:
    return _key(key_id, owner_user_id, VpnKeyType.AWG)


def _bundle(bundle_id: int = 7, owner_user_id: int = 100) -> KeyBundle:
    return KeyBundle(
        id=bundle_id,
        user_id=owner_user_id,
        label="All-in-One",
        note=None,
        status=KeyBundleStatus.ACTIVE,
        token="s3cr3t-subscription-token-value",
        created_at="now",
        updated_at="now",
        revoked_at=None,
        deleted_at=None,
        display_no=bundle_id,
    )


class _Message:
    def __init__(self) -> None:
        self.chat = SimpleNamespace(id=100)
        self.documents: list[object] = []
        self.photos: list[object] = []
        self._next_id = 555

    def _take_id(self) -> int:
        sent = SimpleNamespace(message_id=self._next_id)
        self._next_id += 1
        return sent  # type: ignore[return-value]

    async def answer_document(self, document: object, **kwargs: object) -> SimpleNamespace:
        self.documents.append(document)
        return self._take_id()  # type: ignore[return-value]

    async def answer_photo(self, photo: object, **kwargs: object) -> SimpleNamespace:
        self.photos.append(photo)
        return self._take_id()  # type: ignore[return-value]


class _Callback:
    def __init__(self, data: str, user_id: int = 100) -> None:
        self.from_user = SimpleNamespace(id=user_id, username="user", first_name="User")
        self.message = _Message()
        self.data = data
        self.answers: list[tuple[str, bool | None]] = []

    async def answer(self, text: str | None = None, show_alert: bool | None = None, **kwargs: object) -> None:
        self.answers.append((text or "", show_alert))


class _RateLimiter:
    def check(self, *args: object) -> None:
        return None


class _Bot:
    """Just enough Bot for :func:`discard_config_document`."""

    def __init__(self) -> None:
        self.deleted: list[int] = []

    async def delete_message(self, chat_id: int, message_id: int) -> None:
        self.deleted.append(message_id)


def _make_state() -> FSMContext:
    return FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=1, chat_id=100, user_id=100))


def _sent_qr_payload(message: _Message) -> str:
    """Decode the single QR photo the handler put on screen."""
    assert len(message.photos) == 1
    photo = message.photos[0]
    # The QR goes out with no caption and no text of any kind — image only.
    assert photo.filename == "config-qr.png"  # type: ignore[attr-defined]
    return decode_qr(photo.data, error_correction=ERROR_CORRECT_M)  # type: ignore[attr-defined]


# ── helper-level coverage ─────────────────────────────────────────────────────


def test_remember_and_discard_config_document() -> None:
    async def run() -> None:
        state = _make_state()
        bot = _Bot()
        assert await config_document_present(state, 10) is False

        await remember_config_document(state, key_id=10, message_ids=[777])
        assert await config_document_present(state, 10) is True
        # A different key must not match the tracked file.
        assert await config_document_present(state, 11) is False

        await discard_config_document(state, bot, chat_id=100)  # type: ignore[arg-type]
        assert bot.deleted == [777]
        assert await config_document_present(state, 10) is False

        # Discarding again is a no-op (nothing tracked).
        await discard_config_document(state, bot, chat_id=100)  # type: ignore[arg-type]
        assert bot.deleted == [777]

    asyncio.run(run())


def test_a_config_and_its_qr_are_tracked_and_deleted_as_one_unit() -> None:
    """The whole reason the tracked id became a list: no half-deleted pair."""

    async def run() -> None:
        state = _make_state()
        bot = _Bot()
        await remember_config_document(state, key_id=10, message_ids=[777, 778])
        assert await config_document_present(state, 10) is True

        await discard_config_document(state, bot, chat_id=100)  # type: ignore[arg-type]
        assert bot.deleted == [777, 778]
        assert await config_document_present(state, 10) is False

    asyncio.run(run())


def test_keys_and_bundles_do_not_share_the_tracking_slot() -> None:
    """Key #10 and bundle #10 both exist; the kind keeps them apart."""

    async def run() -> None:
        state = _make_state()
        await remember_config_document(state, key_id=10, message_ids=[777])
        assert await config_document_present(state, 10) is True
        assert await config_document_present(state, 10, CONFIG_DOC_KIND_BUNDLE) is False

        await remember_config_document(state, key_id=10, message_ids=[888], kind=CONFIG_DOC_KIND_BUNDLE)
        assert await config_document_present(state, 10, CONFIG_DOC_KIND_BUNDLE) is True
        assert await config_document_present(state, 10) is False

    asyncio.run(run())


def test_a_legacy_single_message_id_is_still_understood() -> None:
    """FSM data written before the id became a list must still clean up.

    Storage is in-memory (``TTLMemoryStorage``), so this cannot survive a restart —
    but it can survive a code reload within one process' lifetime.
    """

    async def run() -> None:
        state = _make_state()
        bot = _Bot()
        await state.update_data({"config_doc_msg_id": 777, "config_doc_key_id": 10})
        assert await config_document_present(state, 10) is True

        await discard_config_document(state, bot, chat_id=100)  # type: ignore[arg-type]
        assert bot.deleted == [777]

    asyncio.run(run())


def test_unusable_tracking_data_is_treated_as_nothing_tracked() -> None:
    async def run() -> None:
        state = _make_state()
        bot = _Bot()
        await state.update_data({"config_doc_msg_id": "not-an-id", "config_doc_key_id": 10})
        assert await config_document_present(state, 10) is False

        await discard_config_document(state, bot, chat_id=100)  # type: ignore[arg-type]
        assert bot.deleted == []

    asyncio.run(run())


def test_an_unrenderable_qr_is_skipped_without_losing_the_config(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A QR that cannot be encoded is dropped; the config it accompanies is not.

    And the payload never reaches the log — the whole reason the warning reports a
    byte count instead of the string is that every payload here is a credential.
    """
    secret = "vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443#secret"

    def explode(content: str) -> bytes:
        raise QrPayloadTooLarge(len(content.encode("utf-8")))

    monkeypatch.setattr("bot.messages.render_config_qr", explode)

    async def run() -> None:
        state = _make_state()
        message = _Message()
        document = BufferedInputFile(b"config-body", filename="awg.conf")

        with caplog.at_level(logging.DEBUG):
            sent = await send_config_with_qr(
                message,  # type: ignore[arg-type]
                state,
                entity_id=10,
                qr_content=secret,
                document=document,
            )

        # The .conf still went out, and is still tracked for cleanup.
        assert len(message.documents) == 1
        assert message.photos == []
        assert sent == [555]
        assert await config_document_present(state, 10) is True
        assert any("Skipping config QR" in record.getMessage() for record in caplog.records)
        assert all(secret not in record.getMessage() for record in caplog.records)

    asyncio.run(run())


def test_nothing_is_tracked_when_a_uri_protocol_loses_its_only_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No document and no QR means nothing on screen — so nothing to remember."""

    def explode(content: str) -> bytes:
        raise QrPayloadTooLarge(len(content.encode("utf-8")))

    monkeypatch.setattr("bot.messages.render_config_qr", explode)

    async def run() -> None:
        state = _make_state()
        message = _Message()
        sent = await send_config_with_qr(message, state, entity_id=10, qr_content=_VLESS_LINK)  # type: ignore[arg-type]
        assert sent == []
        assert await config_document_present(state, 10) is False

    asyncio.run(run())


def test_nothing_is_sent_when_the_card_is_no_longer_accessible() -> None:
    """An unreachable card means there is nowhere to reply — and nothing to track."""

    async def run() -> None:
        state = _make_state()
        sent = await send_config_with_qr(None, state, entity_id=10, qr_content=_VLESS_LINK)
        assert sent == []
        assert await config_document_present(state, 10) is False

    asyncio.run(run())


# ── show_key_config: one QR per type, no duplicate delivery ───────────────────


def _patch_keys_handler(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    async def allow_private(callback: object) -> bool:
        return True

    edits: list[str] = []

    async def fake_edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.keys.ensure_private_callback", allow_private)
    monkeypatch.setattr("bot.handlers.keys.safe_edit_message_text", fake_edit)
    monkeypatch.setattr("bot.handlers.keys.awg_config_text", lambda cfg: "awg config text")
    monkeypatch.setattr("bot.handlers.keys.xray_config_text", lambda cfg: "xray config text")
    monkeypatch.setattr("bot.handlers.keys.hysteria2_config_text", lambda cfg: "hysteria2 config text")
    return edits


class _Awg:
    def __init__(self) -> None:
        self.plain_calls = 0

    async def get_awg_client_config(self, actor_user_id: int, key_id: int) -> str:
        return "formatted"

    async def get_awg_client_config_plain(self, actor_user_id: int, key_id: int, audit: bool = True) -> str:
        self.plain_calls += 1
        return _AWG_CONF


class _Xray:
    async def get_xray_key_config(self, actor_user_id: int, key_id: int) -> str:
        return "formatted"

    def connection_link(self, key: VpnKey) -> str:
        return _VLESS_LINK


class _Hysteria:
    async def get_config(self, actor_user_id: int, key_id: int) -> str:
        return "formatted"

    def connection_link(self, key: VpnKey) -> str:
        return _HY2_LINK


def _services_for(key_type: VpnKeyType, awg: _Awg | None = None) -> SimpleNamespace:
    class VpnKeys:
        async def get_for_actor(self, actor_user_id: int, key_id: int) -> VpnKey:
            return _key(key_id, key_type=key_type)

    return SimpleNamespace(vpn_keys=VpnKeys(), awg=awg or _Awg(), xray=_Xray(), hysteria=_Hysteria())


def test_show_config_sends_once_then_skips_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_keys_handler(monkeypatch)

    async def run() -> None:
        awg = _Awg()
        services = _services_for(VpnKeyType.AWG, awg)
        state = _make_state()
        callback = _Callback("key:show:10")

        # First press: file and QR are delivered and tracked together.
        await show_key_config(callback, state, services, _RateLimiter(), _Bot())  # type: ignore[arg-type]
        assert len(callback.message.documents) == 1
        assert len(callback.message.photos) == 1
        assert awg.plain_calls == 1
        assert await config_document_present(state, 10) is True

        # Second press on the same key: no duplicate file/QR, user gets a toast.
        await show_key_config(callback, state, services, _RateLimiter(), _Bot())  # type: ignore[arg-type]
        assert len(callback.message.documents) == 1
        assert len(callback.message.photos) == 1
        assert awg.plain_calls == 1
        assert callback.answers[-1][0] == "Файл конфигурации уже отправлен."

    asyncio.run(run())


@pytest.mark.parametrize(
    ("key_type", "expected_payload", "expected_documents"),
    [
        (VpnKeyType.XRAY, _VLESS_LINK, 0),
        (VpnKeyType.HYSTERIA2, _HY2_LINK, 0),
        (VpnKeyType.AWG, _AWG_CONF, 1),
    ],
    ids=["vless", "hysteria2", "awg"],
)
def test_config_button_sends_a_qr_of_the_real_payload_for_every_key_type(
    monkeypatch: pytest.MonkeyPatch,
    key_type: VpnKeyType,
    expected_payload: str,
    expected_documents: int,
) -> None:
    """Every type gets a QR, and it decodes back to exactly what the user connects with."""
    edits = _patch_keys_handler(monkeypatch)

    async def run() -> None:
        state = _make_state()
        callback = _Callback("key:show:10")

        await show_key_config(callback, state, _services_for(key_type), _RateLimiter(), _Bot())  # type: ignore[arg-type]

        # The card is still edited in place with the config text, as before.
        assert len(edits) == 1
        # AWG additionally gets its .conf file; the URI protocols do not.
        assert len(callback.message.documents) == expected_documents
        assert _sent_qr_payload(callback.message) == expected_payload
        assert await config_document_present(state, 10) is True

    asyncio.run(run())


@pytest.mark.parametrize(
    ("key_type", "expected_deletes"),
    [(VpnKeyType.XRAY, 1), (VpnKeyType.HYSTERIA2, 1), (VpnKeyType.AWG, 2)],
    ids=["vless", "hysteria2", "awg"],
)
def test_the_awg_cleanup_mechanism_removes_the_qr_for_every_key_type(
    monkeypatch: pytest.MonkeyPatch, key_type: VpnKeyType, expected_deletes: int
) -> None:
    """Tap «Конфиг», then tap anything else: everything that tap sent is gone.

    This is the exact mechanism the AWG ``.conf`` file has always used —
    ``ConfigDocumentCleanupMiddleware`` calling ``discard_config_document`` on the
    next callback — driven here by each protocol in turn.
    """
    _patch_keys_handler(monkeypatch)

    async def run() -> None:
        bot = Bot(_TOKEN)
        try:
            deleted: list[int] = []

            async def fake_delete(chat_id: int, message_id: int, **kwargs: object) -> bool:
                deleted.append(message_id)
                return True

            monkeypatch.setattr(bot, "delete_message", fake_delete)
            state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=bot.id, chat_id=100, user_id=100))
            callback = _Callback("key:show:10")

            await show_key_config(callback, state, _services_for(key_type), _RateLimiter(), bot)  # type: ignore[arg-type]
            sent = len(callback.message.documents) + len(callback.message.photos)
            assert sent == expected_deletes

            async def handler(event: object, data: dict[str, object]) -> str:
                return "ok"

            await ConfigDocumentCleanupMiddleware()(
                handler, _callback_query("key:stats:10"), {"state": state, "bot": bot}
            )
            assert deleted == list(range(555, 555 + expected_deletes))
            assert await config_document_present(state, 10) is False
        finally:
            await bot.session.close()

    asyncio.run(run())


# ── bundle subscription: the same QR, the same cleanup ────────────────────────


def _patch_bundle_handler(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    async def allow_private(callback: object) -> bool:
        return True

    edits: list[str] = []

    async def fake_edit(message: object, text: str, reply_markup: object = None, **kwargs: object) -> None:
        edits.append(text)

    monkeypatch.setattr("bot.handlers.key_bundles.ensure_private_callback", allow_private)
    monkeypatch.setattr("bot.handlers.key_bundles.safe_edit_message_text", fake_edit)
    monkeypatch.setattr("bot.handlers.key_bundles.require_subscription_ui", lambda services: None)
    monkeypatch.setattr("bot.handlers.key_bundles.bundle_config_text", lambda b, s: "bundle config text")
    monkeypatch.setattr("bot.handlers.key_bundles.bundle_actions_keyboard", lambda b, has_vless=False: None)
    monkeypatch.setattr("bot.handlers.key_bundles.bundle_has_vless", lambda keys: True)
    monkeypatch.setattr("bot.handlers.key_bundles.subscription_url", lambda settings, token: _SUB_URL)
    return edits


def _bundle_services() -> SimpleNamespace:
    class Views:
        async def get_for_actor(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
            return _bundle(bundle_id)

        async def list_keys_for_actor(self, actor_user_id: int, bundle_id: int) -> list[VpnKey]:
            return [_key(1, key_type=VpnKeyType.XRAY), _key(2, key_type=VpnKeyType.AWG)]

    return SimpleNamespace(key_bundle_views=Views(), settings=SimpleNamespace())


def test_bundle_config_button_sends_a_qr_of_the_subscription_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """The all-in-one subscription gets a QR of its sub-URL — not of the aggregated body."""
    edits = _patch_bundle_handler(monkeypatch)

    async def run() -> None:
        state = _make_state()
        callback = _Callback("bundle:show:7")

        await show_bundle_config(callback, state, _bundle_services(), _RateLimiter(), _Bot())  # type: ignore[arg-type]

        assert len(edits) == 1
        assert callback.message.documents == []
        assert _sent_qr_payload(callback.message) == _SUB_URL
        assert await config_document_present(state, 7, CONFIG_DOC_KIND_BUNDLE) is True

        # Second press: no duplicate QR, and the user is told why.
        await show_bundle_config(callback, state, _bundle_services(), _RateLimiter(), _Bot())  # type: ignore[arg-type]
        assert len(callback.message.photos) == 1
        assert callback.answers[-1][0] == "Файл конфигурации уже отправлен."

    asyncio.run(run())


def test_the_awg_cleanup_mechanism_removes_the_bundle_qr(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_bundle_handler(monkeypatch)

    async def run() -> None:
        bot = Bot(_TOKEN)
        try:
            deleted: list[int] = []

            async def fake_delete(chat_id: int, message_id: int, **kwargs: object) -> bool:
                deleted.append(message_id)
                return True

            monkeypatch.setattr(bot, "delete_message", fake_delete)
            state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=bot.id, chat_id=100, user_id=100))
            callback = _Callback("bundle:show:7")

            await show_bundle_config(callback, state, _bundle_services(), _RateLimiter(), bot)  # type: ignore[arg-type]
            assert len(callback.message.photos) == 1

            async def handler(event: object, data: dict[str, object]) -> str:
                return "ok"

            await ConfigDocumentCleanupMiddleware()(
                handler, _callback_query("bundle:open:7"), {"state": state, "bot": bot}
            )
            assert deleted == [555]
            assert await config_document_present(state, 7, CONFIG_DOC_KIND_BUNDLE) is False
        finally:
            await bot.session.close()

    asyncio.run(run())


# ── feature 2: cleanup middleware ─────────────────────────────────────────────


def _callback_query(data: str) -> CallbackQuery:
    chat = Chat(id=100, type="private")
    message = Message(message_id=1, date=datetime.now(timezone.utc), chat=chat)
    return CallbackQuery(
        id="cq",
        from_user=TgUser(id=100, is_bot=False, first_name="User"),
        chat_instance="instance",
        message=message,
        data=data,
    )


def test_cleanup_middleware_deletes_file_on_other_button(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        bot = Bot(_TOKEN)
        try:
            deleted: list[int] = []

            async def fake_delete(chat_id: int, message_id: int, **kwargs: object) -> bool:
                deleted.append(message_id)
                return True

            monkeypatch.setattr(bot, "delete_message", fake_delete)
            state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=bot.id, chat_id=100, user_id=100))
            await remember_config_document(state, key_id=10, message_ids=[999])

            middleware = ConfigDocumentCleanupMiddleware()
            handled: list[str] = []

            async def handler(event: object, data: dict[str, object]) -> str:
                handled.append("ran")
                return "ok"

            # A non-"show config" button deletes the tracked file before handling.
            result = await middleware(handler, _callback_query("key:stats:10"), {"state": state, "bot": bot})
            assert result == "ok"
            assert handled == ["ran"]
            assert deleted == [999]
            assert await config_document_present(state, 10) is False
        finally:
            await bot.session.close()

    asyncio.run(run())


def test_cleanup_middleware_keeps_file_on_show_config(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> None:
        bot = Bot(_TOKEN)
        try:
            deleted: list[int] = []

            async def fake_delete(chat_id: int, message_id: int, **kwargs: object) -> bool:
                deleted.append(message_id)
                return True

            monkeypatch.setattr(bot, "delete_message", fake_delete)
            state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=bot.id, chat_id=100, user_id=100))
            await remember_config_document(state, key_id=10, message_ids=[999])

            middleware = ConfigDocumentCleanupMiddleware()

            async def handler(event: object, data: dict[str, object]) -> str:
                return "ok"

            # Tapping "show config" must NOT delete the file it may reuse.
            await middleware(handler, _callback_query("key:show:10"), {"state": state, "bot": bot})
            assert deleted == []
            assert await config_document_present(state, 10) is True
        finally:
            await bot.session.close()

    asyncio.run(run())


def test_cleanup_middleware_keeps_the_bundle_qr_on_show_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """``bundle:show:`` is exempt from cleanup for the same reason ``key:show:`` is."""

    async def run() -> None:
        bot = Bot(_TOKEN)
        try:
            deleted: list[int] = []

            async def fake_delete(chat_id: int, message_id: int, **kwargs: object) -> bool:
                deleted.append(message_id)
                return True

            monkeypatch.setattr(bot, "delete_message", fake_delete)
            state = FSMContext(storage=MemoryStorage(), key=StorageKey(bot_id=bot.id, chat_id=100, user_id=100))
            await remember_config_document(state, key_id=7, message_ids=[999], kind=CONFIG_DOC_KIND_BUNDLE)

            async def handler(event: object, data: dict[str, object]) -> str:
                return "ok"

            await ConfigDocumentCleanupMiddleware()(
                handler, _callback_query("bundle:show:7"), {"state": state, "bot": bot}
            )
            assert deleted == []
            assert await config_document_present(state, 7, CONFIG_DOC_KIND_BUNDLE) is True
        finally:
            await bot.session.close()

    asyncio.run(run())
