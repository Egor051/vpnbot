"""Read side of the all-in-one subscription bundles (plus the display-only note).

:class:`services.key_bundles.KeyBundleService` owns the *lifecycle* — create,
revoke, delete — and is deliberately left untouched by the UI PR. Everything the
bot needs in order to *show* a bundle lives here instead, mirroring how
:class:`services.vpn_keys.VpnKeyQueryService` sits next to the per-protocol key
services: listing, single-bundle lookup, the bundle's children, and the note
(metadata on the parent row, not a backend operation).

``SUBSCRIPTION_ENABLED`` gates every method exactly as it gates every mutation on
the lifecycle service. The bot layer already refuses bundle callbacks while the
flag is off; this is the second lock on the same door, so a future handler that
forgets the guard still cannot read a bundle out of the database.
"""

import logging

from config.settings import Settings
from models.dto import KeyBundle, VpnKey
from models.enums import AuditEntityType, UserRole
from repositories.key_bundles import KeyBundleRepository
from services.audit import AuditService
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.notes import normalize_note
from services.users import UserService

logger = logging.getLogger(__name__)


class KeyBundleViewService:
    """Actor-checked reads of all-in-one bundles, plus their note."""

    def __init__(
        self,
        *,
        bundles: KeyBundleRepository,
        users: UserService,
        settings: Settings,
        audit: AuditService,
    ) -> None:
        self.bundles = bundles
        self.users = users
        self.settings = settings
        self.audit = audit

    @property
    def enabled(self) -> bool:
        """Whether the all-in-one subscription feature is switched on."""
        return self.settings.subscription_enabled

    async def list_for_actor(self, actor_user_id: int, *, limit: int = 20, offset: int = 0) -> list[KeyBundle]:
        """Return the actor's own bundles, oldest first."""
        self._require_enabled()
        await self.users.require_approved_or_admin(actor_user_id)
        return await self.bundles.list_by_user(actor_user_id, limit=limit, offset=offset)

    async def count_for_actor(self, actor_user_id: int) -> int:
        """Return how many bundles the actor owns."""
        self._require_enabled()
        await self.users.require_approved_or_admin(actor_user_id)
        return await self.bundles.count_by_user(actor_user_id)

    async def get_for_actor(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
        """Return one bundle if the actor may see it (own bundle, or superadmin)."""
        self._require_enabled()
        actor = await self.users.require_approved_or_admin(actor_user_id)
        bundle = await self.bundles.get_by_id(bundle_id)
        if bundle is None:
            raise NotFound("Подписка не найдена", key="err_bundle_not_found")
        if bundle.user_id != actor_user_id and actor.role != UserRole.SUPERADMIN:
            raise AccessDenied("Нельзя смотреть чужую подписку", key="err_foreign_bundle_view")
        return bundle

    async def list_keys_for_actor(self, actor_user_id: int, bundle_id: int) -> list[VpnKey]:
        """Return the child keys of a bundle the actor may see."""
        bundle = await self.get_for_actor(actor_user_id, bundle_id)
        return await self.bundles.list_keys_of_bundle(bundle.id)

    async def update_note(self, actor_user_id: int, bundle_id: int, note: str | None) -> None:
        """Update the note on the actor's own bundle.

        Deliberately owner-only (not superadmin-wide), exactly like
        :meth:`services.notes.NotesService.update_key_note`: the note is the
        owner's private label for their own subscription.
        """
        self._require_enabled()
        # Authorize before the lookup so a caller cannot tell a real bundle id from
        # one they may not touch — the same ordering NotesService uses.
        await self.users.require_approved_or_admin(actor_user_id)
        bundle = await self.bundles.get_by_id(bundle_id)
        if bundle is None:
            raise NotFound("Подписка не найдена", key="err_bundle_not_found")
        if bundle.user_id != actor_user_id:
            raise AccessDenied("Можно менять заметку только своих подписок", key="err_note_own_only")
        clean_note = normalize_note(note)
        await self.bundles.update_note(bundle_id, clean_note, self.users.clock.now())
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="bundle_note_updated",
            entity_id=bundle_id,
            details={},
        )

    def _require_enabled(self) -> None:
        if not self.settings.subscription_enabled:
            raise InvalidOperation("All-in-one подписка сейчас отключена", key="err_subscription_disabled")

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
                entity_type=AuditEntityType.KEY_BUNDLE,
                entity_id=entity_id,
                details=details,
            )
            return
        try:
            await self.audit.write(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=AuditEntityType.KEY_BUNDLE,
                entity_id=entity_id,
                details=details,
            )
        except Exception:
            logger.warning(
                "Audit write failed after key bundle view operation: action=%s entity_id=%s",
                action,
                entity_id,
                exc_info=True,
            )
