
import asyncio
import logging
import secrets

from adapters.clock import ClockProvider
from adapters.hysteria_stats import HysteriaStatsAdapter
from adapters.id_generator import IdGenerator
from bot.formatters import format_hysteria2_link, key_note_for_viewer, status_text
from config.settings import Settings
from models.dto import TelegramUserProfile, VpnKey, VpnKeyCreateResult
from models.enums import AuditEntityType, UserRole, VpnKeyStatus, VpnKeyType
from repositories.vpn_keys import VpnKeyRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.notes import normalize_note
from services.protocol_modules import ProtocolModulesService
from services.user_locks import UserLockManager
from services.users import UserService
from utils.formatting import code, h

logger = logging.getLogger(__name__)

# A Hysteria2 key whose access may still need revoking. There is no apply step
# (the hy2_auth endpoint reads the live DB), so in practice a key is ACTIVE
# almost immediately; PENDING_APPLY only exists in the tiny window of issue().
HYSTERIA2_REVOCABLE_STATUSES: set[VpnKeyStatus] = {
    VpnKeyStatus.ACTIVE,
    VpnKeyStatus.PENDING_APPLY,
    VpnKeyStatus.APPLY_FAILED,
}


class HysteriaService:
    """Issue/revoke Hysteria2 (apernet v2) keys with NO data-plane apply step.

    Hysteria authenticates each handshake against the hy2_auth endpoint, which
    live-reads vpn.db. So issuance is a pure DB write (flip a row to ACTIVE) and
    revocation is a pure DB write (flip it to REVOKED) — there is no config file
    to mutate and no service to restart. The vpn_key secret lives only in
    payload_json; public_payload_json never carries it.
    """

    def __init__(
        self,
        *,
        vpn_keys: VpnKeyRepository,
        users: UserService,
        settings: Settings,
        clock: ClockProvider,
        ids: IdGenerator,
        audit: AuditService,
        modules: ProtocolModulesService,
        user_locks: UserLockManager | None = None,
        stats: HysteriaStatsAdapter | None = None,
    ) -> None:
        self.vpn_keys = vpn_keys
        self.users = users
        self.settings = settings
        self.clock = clock
        self.ids = ids
        self.audit = audit
        self.modules = modules
        # Traffic Stats API client; when configured, revoke/delete/expiry/block
        # kick any live session so the flip to REVOKED takes effect immediately
        # instead of surviving until the client reconnects. None => no kick.
        self.stats = stats
        self.user_locks: UserLockManager = (
            user_locks if user_locks is not None else getattr(users, "user_locks", UserLockManager())
        )
        self._lock = asyncio.Lock()

    async def create_key(self, actor_user_id: int, owner: TelegramUserProfile, note: str | None) -> VpnKeyCreateResult:
        """Create a new Hysteria2 key for the owner."""
        return await self.issue(actor_user_id, owner, note)

    async def issue(
        self,
        actor_user_id: int,
        owner: TelegramUserProfile,
        note: str | None,
        expires_at: str | None = None,
        allow_pending_owner: bool = False,
    ) -> VpnKeyCreateResult:
        """Generate a label + secret, persist the key as ACTIVE, and return its link.

        There is no apply phase: the hy2_auth endpoint reads the live DB, so a row
        flipped to ACTIVE is authenticatable on the very next handshake.
        """
        await self._ensure_module_enabled()
        self.settings.validate_hysteria2_ready()
        clean_note = normalize_note(note)

        async with self.user_locks.lock(owner.telegram_user_id):
            await self._ensure_can_create(actor_user_id, owner.telegram_user_id, allow_pending_owner=allow_pending_owner)
            async with self._lock:
                await self._ensure_can_create(
                    actor_user_id, owner.telegram_user_id, allow_pending_owner=allow_pending_owner
                )
                label = await self._generate_unique_label()
                # token_hex is deliberate: hex has no '+', '/', '=' or ':' so the
                # secret drops cleanly into the URI userinfo without escaping.
                secret = secrets.token_hex(24)
                payload: dict[str, object] = {"secret": secret, "email_label": label}
                # public_payload_json must never carry the secret (it is not redacted
                # in VpnKey.__repr__); the link is rebuilt on demand from settings.
                public_payload: dict[str, object] = {"email_label": label}
                key = await self.vpn_keys.create_pending(
                    owner_user_id=owner.telegram_user_id,
                    username=owner.username,
                    key_type=VpnKeyType.HYSTERIA2,
                    note=clean_note,
                    payload=payload,
                    public_payload=public_payload,
                    created_by=actor_user_id,
                    now=self.clock.now(),
                    email_label=label,
                    expires_at=expires_at,
                )
                # Flip straight to ACTIVE: mark_active transitions PENDING_APPLY ->
                # ACTIVE, so the status guard stays intact even though there is no
                # backend apply between the two writes.
                await self.vpn_keys.mark_active(
                    key.id, self.clock.now(), payload=payload, public_payload=public_payload
                )
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="hysteria2_key_created",
                    entity_id=key.id,
                    details={
                        "owner_user_id": owner.telegram_user_id,
                        "owner_username": owner.username,
                        "label": label,
                        "expires_at": expires_at,
                    },
                )
                active_key = await self._get_key(key.id)
                return VpnKeyCreateResult(
                    key=active_key, config_text=self._format_config(active_key, viewer_user_id=actor_user_id)
                )

    async def revoke(self, actor_user_id: int, key_id: int) -> VpnKey:
        """Revoke a Hysteria2 key by id, enforcing ownership (IDOR-safe).

        Semantics: flipping the row to REVOKED blocks every NEW handshake
        immediately (the endpoint matches only ACTIVE rows on its live read). An
        already-established session is then terminated by a best-effort ``/kick``
        against the Traffic Stats API when it is configured; without that API the
        live session survives until the client reconnects (the original
        no-data-plane behaviour).
        """
        async with self._lock:
            key = await self._get_key_for_manage(actor_user_id, key_id)
            if key.status in {VpnKeyStatus.REVOKED, VpnKeyStatus.DELETED}:
                return key
            if key.status not in HYSTERIA2_REVOCABLE_STATUSES:
                raise InvalidOperation("Отозвать можно только активный Hysteria2-ключ")
            await self.vpn_keys.mark_revoked(key_id, actor_user_id, self.clock.now())
            await self._kick_best_effort(key.email_label)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="hysteria2_key_revoked",
                entity_id=key_id,
                details={"owner_user_id": key.owner_user_id, "label": key.email_label},
            )
            return await self._get_key(key_id)

    async def revoke_hysteria2_key_system(
        self,
        key_id: int,
        *,
        actor_user_id: int | None = None,
        action: str = "hysteria2_key_revoked",
    ) -> VpnKey:
        """Revoke without an interactive role check — for trusted callers.

        Used by the expiry job and the block-user flow, both of which authorise
        the operation themselves. When *actor_user_id* is given it is recorded as
        the revoker; otherwise the key's creator is recorded.
        """
        async with self._lock:
            key = await self._get_key(key_id)
            if key.key_type != VpnKeyType.HYSTERIA2:
                raise InvalidOperation("Это не Hysteria2-ключ")
            if key.status in {VpnKeyStatus.REVOKED, VpnKeyStatus.DELETED}:
                return key
            if key.status not in HYSTERIA2_REVOCABLE_STATUSES:
                raise InvalidOperation("Отозвать можно только активный Hysteria2-ключ")
            revoked_by = actor_user_id if actor_user_id is not None else key.created_by
            await self.vpn_keys.mark_revoked(key_id, revoked_by, self.clock.now())
            await self._kick_best_effort(key.email_label)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action=action,
                entity_id=key_id,
                details={"owner_user_id": key.owner_user_id, "expires_at": key.expires_at, "label": key.email_label},
            )
            return await self._get_key(key_id)

    async def delete_hysteria2_key(self, actor_user_id: int, key_id: int) -> None:
        """Hard-delete a Hysteria2 key (used by the UI and by protocol-disable).

        There is no backend artefact to remove — dropping the DB row is what
        stops the endpoint from authenticating the secret — so this is the
        purger contract for the hysteria2 protocol module.
        """
        async with self._lock:
            key = await self._get_key_for_manage(actor_user_id, key_id)
            previous_status = key.status
            await self.vpn_keys.hard_delete_with_stats(key_id, self.clock.now())
            await self._kick_best_effort(key.email_label)
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="hysteria2_key_hard_deleted",
                entity_id=key_id,
                details={
                    "owner_user_id": key.owner_user_id,
                    "previous_status": previous_status.value,
                    "label": key.email_label,
                },
            )

    async def get_config(self, actor_user_id: int, key_id: int) -> str:
        """Return the formatted Hysteria2 link for an active key owned/managed by the actor."""
        async with self._lock:
            key = await self._get_key_for_manage(actor_user_id, key_id, allow_read=True)
            if key.status != VpnKeyStatus.ACTIVE:
                raise InvalidOperation("Конфигурация доступна только для активного ключа")
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="hysteria2_config_shown",
                entity_id=key_id,
                details={"owner_user_id": key.owner_user_id, "label": key.email_label},
            )
            return self._format_config(key, viewer_user_id=actor_user_id)

    async def list_user_keys(
        self,
        actor_user_id: int,
        owner_user_id: int | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[VpnKey]:
        """Return a paginated list of a user's Hysteria2 keys, enforcing ownership."""
        actor = await self.users.require_approved_or_admin(actor_user_id)
        target = owner_user_id or actor_user_id
        if actor.role != UserRole.SUPERADMIN and target != actor_user_id:
            raise AccessDenied("Нельзя смотреть чужие ключи")
        return await self.vpn_keys.list_by_owner_and_type(target, VpnKeyType.HYSTERIA2, limit=limit, offset=offset)

    async def _ensure_module_enabled(self) -> None:
        if not self.settings.hysteria2_enabled:
            raise InvalidOperation("Hysteria2 сейчас отключён")
        if not await self.modules.is_enabled("hysteria2"):
            raise InvalidOperation("Hysteria2 сейчас отключён")

    async def _ensure_can_create(
        self, actor_user_id: int, owner_user_id: int, *, allow_pending_owner: bool = False
    ) -> None:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        if actor.role != UserRole.SUPERADMIN and actor_user_id != owner_user_id:
            raise AccessDenied("Нельзя создавать ключи для другого пользователя")
        if allow_pending_owner:
            if actor.role != UserRole.SUPERADMIN:
                raise AccessDenied("Только администратор может выдавать ключи гостям")
            owner = await self.users.get_user(owner_user_id)
            from models.access import is_blocked_user

            if is_blocked_user(owner):
                raise AccessDenied("Нельзя выдать ключ заблокированному пользователю")
        else:
            owner = await self.users.require_approved_or_admin(owner_user_id)
            if owner.role not in {UserRole.SUPERADMIN, UserRole.APPROVED_USER}:
                raise AccessDenied("Владелец ключа не имеет доступа")

    async def _get_key_for_manage(self, actor_user_id: int, key_id: int, allow_read: bool = False) -> VpnKey:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        key = await self._get_key(key_id)
        if key.key_type != VpnKeyType.HYSTERIA2:
            raise InvalidOperation("Это не Hysteria2-ключ")
        if actor.role != UserRole.SUPERADMIN and key.owner_user_id != actor_user_id:
            raise AccessDenied("Нельзя управлять чужим ключом")
        return key

    async def _get_key(self, key_id: int) -> VpnKey:
        key = await self.vpn_keys.get_by_id(key_id)
        if key is None:
            raise NotFound("Ключ не найден")
        return key

    async def _kick_best_effort(self, label: str | None) -> None:
        """Terminate any live session for *label* via the Traffic Stats API.

        No-op when the API is not configured. Never raises: the DB flip already
        blocks new handshakes, so a kick failure must not fail the revoke/delete.
        """
        if self.stats is None or not label:
            return
        try:
            await self.stats.kick([label])
        except Exception:
            logger.warning("Hysteria2 kick failed for label=%s (revoke still applied)", label, exc_info=True)

    async def _generate_unique_label(self) -> str:
        for _ in range(5):
            label = self.ids.hysteria2_label()
            if await self.vpn_keys.find_by_email_label(label) is None:
                return label
        raise InvalidOperation("Не удалось сгенерировать уникальную метку для Hysteria2-ключа")

    def _format_config(self, key: VpnKey, *, viewer_user_id: int | None = None) -> str:
        label = key.email_label or ""
        secret = str(key.payload.get("secret") or "")
        link = format_hysteria2_link(
            label,
            secret,
            host=self.settings.hysteria2_host,
            port=self.settings.hysteria2_port,
            sni=self.settings.hysteria2_sni,
            obfs_password=self.settings.hysteria2_obfs_password,
            insecure=self.settings.hysteria2_insecure,
        )
        visible_note = key_note_for_viewer(key, viewer_user_id) if viewer_user_id is not None else None
        note = f"\nЗаметка: {h(visible_note)}" if visible_note else ""
        label_line = f"\nМетка: {h(label)}" if label else ""
        return (
            f"<b>Hysteria2-ключ #{key.id}</b>\n"
            f"Статус: {status_text(key.status)}{label_line}{note}\n\n"
            f"{code(link)}"
        )

    async def _write_audit_best_effort(
        self,
        *,
        actor_user_id: int | None,
        action: str,
        entity_id: str | int | None,
        details: dict[str, object] | None = None,
    ) -> None:
        writer = getattr(self.audit, "write_best_effort", None)
        if writer is not None:
            await writer(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=entity_id,
                details=details,
            )
            return
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=AuditEntityType.VPN_KEY,
                entity_id=entity_id,
                details=details,
            )
        except Exception:
            logger.warning(
                "Audit write failed after Hysteria2 operation: action=%s entity_id=%s", action, entity_id, exc_info=True
            )
