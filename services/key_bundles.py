"""All-in-one subscription bundles — service layer.

A bundle is a parent row in ``key_bundles`` that owns several ordinary VPN keys
(its *children*), so one subscription URL can hand a client every protocol at
once. The bundle has NO backend of its own: every child is provisioned, revoked
and deleted through **the same per-protocol service path a standalone key uses**
(:class:`services.xray.XrayService`, :class:`services.hysteria.HysteriaService`).
That is deliberate — the children keep the existing ``xray_tcp_*`` /
``xray_http_*`` / ``hy2_*`` email-label scheme, so ``reconcile_email_labels``,
startup drift reconciliation and anomaly detection keep working with no changes.
The bundle's own ``bundle_*`` label is display-only.

This module only orchestrates those paths and keeps the parent row consistent
with them. Nothing here is reachable from the UI yet and there is no HTTP
endpoint yet; ``SUBSCRIPTION_ENABLED`` gates every mutation so the flag has teeth
from the moment it exists.
"""

import asyncio
import logging
import sqlite3
from dataclasses import dataclass

from adapters.clock import ClockProvider
from adapters.id_generator import IdGenerator
from config.settings import Settings
from models.dto import KeyBundle, TelegramUserProfile, VpnKey
from models.enums import AuditEntityType, KeyBundleStatus, UserRole, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.hysteria import HysteriaService
from services.notes import normalize_note
from services.protocol_modules import ProtocolModulesService
from services.users import UserService
from services.xray import XHTTP_PROFILES, XrayService

logger = logging.getLogger(__name__)

# Bundle statuses a revoke may start from. PENDING_REVOKE is included so a revoke
# that failed partway (bundle left pending) can simply be retried.
BUNDLE_REVOCABLE_STATUSES: tuple[KeyBundleStatus, ...] = (
    KeyBundleStatus.ACTIVE,
    KeyBundleStatus.PENDING_REVOKE,
)
# Bundle statuses a delete may start from — everything except DELETED (whose row
# is already gone). DELETE_FAILED is included so a failed delete is retryable.
BUNDLE_DELETABLE_STATUSES: tuple[KeyBundleStatus, ...] = (
    KeyBundleStatus.ACTIVE,
    KeyBundleStatus.PENDING_REVOKE,
    KeyBundleStatus.REVOKED,
    KeyBundleStatus.PENDING_DELETE,
    KeyBundleStatus.DELETE_FAILED,
)


@dataclass(frozen=True, slots=True)
class BundleMember:
    """One child key an all-in-one bundle provisions.

    ``transport``/``xhttp_profile`` are meaningful only for :attr:`VpnKeyType.XRAY`
    and are passed straight through to the existing Xray create path, which
    derives the email-label prefix from them.
    """

    key_type: VpnKeyType
    transport: str = "tcp"
    xhttp_profile: str = "base"

    @property
    def protocol_module(self) -> str:
        """Name of this member's protocol module in ``protocol_modules``."""
        return self.key_type.value


def bundle_composition() -> tuple[BundleMember, ...]:
    """THE seam: every child key an all-in-one bundle may contain.

    This is the single point where the bundle's composition is decided. Today it
    returns the full permissible set — VLESS (TCP) plus every VLESS (HTTP)
    profile, plus Hysteria2 — and availability (a backend switched off in ``.env``
    or via the protocol-module toggle) is filtered on top of it by
    :meth:`KeyBundleService._resolve_composition`. Any future divergence (e.g. a
    client that cannot parse one of the XHTTP profiles, so its bundle carries a
    smaller set) belongs HERE and nowhere else — never as scattered ``if``s along
    the provisioning path.

    Deliberately excluded:

    * **AWG** — WireGuard configs do not ride a base64 v2ray subscription at all.
    * **SOCKS5 / MTProto** — a different entity (``ProxyAccess``), and MTProto is
      not even a v2ray link format.
    """
    return (
        BundleMember(VpnKeyType.XRAY, transport="tcp", xhttp_profile="base"),
        *(
            BundleMember(VpnKeyType.XRAY, transport="http", xhttp_profile=profile)
            for profile in XHTTP_PROFILES
        ),
        BundleMember(VpnKeyType.HYSTERIA2),
    )


@dataclass(frozen=True, slots=True)
class KeyBundleCreateResult:
    """Outcome of a successful bundle creation.

    ``included``/``skipped`` record the composition actually provisioned versus
    the members whose backend was switched off, so the caller (and the audit
    trail) can see exactly what went into the bundle.
    """

    bundle: KeyBundle
    keys: tuple[VpnKey, ...]
    included: tuple[BundleMember, ...]
    skipped: tuple[BundleMember, ...]


class KeyBundleService:
    """Create / revoke / delete all-in-one subscription bundles.

    Partial-provisioning policy (see the PR description):

    * a backend switched **off** (``.env`` flag or protocol-module toggle) is
      skipped silently — a missing protocol is a normal, expected state here;
    * a backend that is **on but degraded** aborts the whole creation. A bundle
      that silently lacks Hysteria2 because of a thirty-second blip is defective
      forever (nobody tops it up later), whereas an aborted creation is something
      the user simply retries.
    """

    def __init__(
        self,
        *,
        bundles: KeyBundleRepository,
        users: UserService,
        xray: XrayService,
        hysteria: HysteriaService,
        modules: ProtocolModulesService,
        settings: Settings,
        clock: ClockProvider,
        ids: IdGenerator,
        audit: AuditService,
        backend_health: BackendHealth | None = None,
    ) -> None:
        self.bundles = bundles
        self.users = users
        self.xray = xray
        self.hysteria = hysteria
        self.modules = modules
        self.settings = settings
        self.clock = clock
        self.ids = ids
        self.audit = audit
        self.backend_health = backend_health or BackendHealth()
        # Serialises whole-bundle operations. Always the OUTERMOST lock: the child
        # services take their own per-user and per-backend locks underneath, and
        # nothing else ever takes this one, so no cycle is possible.
        self._lock = asyncio.Lock()

    # ── creation ──────────────────────────────────────────────────────

    async def create_bundle(
        self,
        actor_user_id: int,
        owner: TelegramUserProfile,
        note: str | None = None,
        *,
        expires_at: str | None = None,
        allow_pending_owner: bool = False,
    ) -> KeyBundleCreateResult:
        """Provision one child key per available protocol under a single bundle.

        Atomic from the caller's point of view: either every included child is
        live and attached, or nothing is left behind on the backends or in the DB.
        All children share the same *expires_at* so they expire together and the
        key-expiry job needs no bundle awareness at all.
        """
        self._require_enabled()
        clean_note = normalize_note(note)
        async with self._lock:
            included, skipped = await self._resolve_composition()
            if not included:
                raise InvalidOperation(
                    "Нет включённых протоколов для all-in-one подписки",
                    key="err_bundle_no_backends",
                )
            # Degraded check BEFORE anything is written: an enabled-but-degraded
            # backend aborts the whole creation rather than silently shrinking the
            # bundle. dict.fromkeys keeps the order stable and de-duplicates the
            # four Xray members down to one check.
            for backend in dict.fromkeys(member.key_type for member in included):
                self.backend_health.require_mutation_allowed(backend)
            await self._ensure_can_create(
                actor_user_id, owner.telegram_user_id, allow_pending_owner=allow_pending_owner
            )

            bundle = await self._create_bundle_row(owner.telegram_user_id, clean_note)
            created: list[VpnKey] = []
            try:
                for member in included:
                    key = await self._provision_child(
                        actor_user_id,
                        owner,
                        member,
                        note=clean_note,
                        expires_at=expires_at,
                        allow_pending_owner=allow_pending_owner,
                    )
                    await self.bundles.attach_key_to_bundle(key.id, bundle.id, self.clock.now())
                    created.append(key)
            except Exception as exc:
                await self._rollback_partial_bundle(actor_user_id, bundle, created, exc)
                raise

            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="key_bundle_created",
                entity_id=bundle.id,
                details={
                    "owner_user_id": owner.telegram_user_id,
                    "label": bundle.label,
                    "expires_at": expires_at,
                    "key_ids": [key.id for key in created],
                    "included": [_member_name(member) for member in included],
                    "skipped": [_member_name(member) for member in skipped],
                },
            )
            return KeyBundleCreateResult(
                bundle=await self._get_bundle(bundle.id),
                keys=tuple(created),
                included=included,
                skipped=skipped,
            )

    # ── revocation ────────────────────────────────────────────────────

    async def revoke_bundle(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
        """Revoke every child through its normal path, then retire the bundle.

        The subscription token is rotated as well. That is defence in depth: even
        if a later subscription-endpoint change mis-reads the bundle status, the
        sub-URL the user already holds is dead because its token no longer
        resolves. The rotation happens even when a child revoke failed — the URL
        must die regardless.
        """
        self._require_enabled()
        async with self._lock:
            bundle = await self._get_bundle_for_manage(actor_user_id, bundle_id)
            if bundle.status in {KeyBundleStatus.REVOKED, KeyBundleStatus.DELETED}:
                return bundle
            if bundle.status not in BUNDLE_REVOCABLE_STATUSES:
                raise InvalidOperation(
                    "Отозвать можно только активную подписку", key="err_bundle_revoke_active_only"
                )
            await self.bundles.set_status(
                bundle_id,
                KeyBundleStatus.PENDING_REVOKE,
                self.clock.now(),
                allowed_from_statuses=BUNDLE_REVOCABLE_STATUSES,
            )

            revoked_ids: list[int] = []
            errors: list[tuple[int, Exception]] = []
            for key in await self.bundles.list_keys_of_bundle(bundle_id):
                try:
                    await self._revoke_child(actor_user_id, key)
                    revoked_ids.append(key.id)
                except Exception as exc:
                    errors.append((key.id, exc))
                    logger.warning(
                        "Не удалось отозвать ключ key_id=%s бандла bundle_id=%s", key.id, bundle_id, exc_info=True
                    )
            rotated = await self._rotate_token_best_effort(bundle_id)

            if errors:
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="key_bundle_revoke_failed",
                    entity_id=bundle_id,
                    details={
                        "revoked_key_ids": revoked_ids,
                        "failed_key_ids": [key_id for key_id, _ in errors],
                        "token_rotated": rotated,
                    },
                )
                # The bundle stays PENDING_REVOKE so a retry is possible; the token
                # is already dead, so no live sub-URL survives this state.
                raise InvalidOperation(
                    f"Не удалось отозвать все ключи подписки: {len(errors)} из {len(revoked_ids) + len(errors)}",
                    key="err_bundle_revoke_partial",
                ) from errors[0][1]

            await self.bundles.set_status(bundle_id, KeyBundleStatus.REVOKED, self.clock.now())
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="key_bundle_revoked",
                entity_id=bundle_id,
                details={"revoked_key_ids": revoked_ids, "token_rotated": rotated},
            )
            return await self._get_bundle(bundle_id)

    # ── deletion ──────────────────────────────────────────────────────

    async def delete_bundle(self, actor_user_id: int, bundle_id: int) -> None:
        """Remove every child (backend, then DB row) and only then the bundle row.

        ``vpn_keys.bundle_id`` is ON DELETE RESTRICT, so this order is not a
        convention that can be forgotten — the database refuses the other one. The
        RESTRICT is a backstop, never a routine path: it should never actually
        fire here, and if it does the bundle is left DELETE_FAILED with a clear
        error rather than half-removed.
        """
        self._require_enabled()
        async with self._lock:
            bundle = await self._get_bundle_for_manage(actor_user_id, bundle_id)
            if bundle.status not in BUNDLE_DELETABLE_STATUSES:
                raise InvalidOperation("Эту подписку нельзя удалить", key="err_bundle_delete_forbidden")
            await self.bundles.set_status(
                bundle_id,
                KeyBundleStatus.PENDING_DELETE,
                self.clock.now(),
                allowed_from_statuses=BUNDLE_DELETABLE_STATUSES,
            )

            deleted_ids: list[int] = []
            for key in await self.bundles.list_keys_of_bundle(bundle_id):
                try:
                    await self._delete_child(actor_user_id, key)
                except Exception as exc:
                    await self._mark_bundle_failed(bundle_id)
                    await self._write_audit_best_effort(
                        actor_user_id=actor_user_id,
                        action="key_bundle_delete_failed",
                        entity_id=bundle_id,
                        details={
                            "deleted_key_ids": deleted_ids,
                            "failed_key_id": key.id,
                            "error_type": type(exc).__name__,
                        },
                    )
                    raise
                deleted_ids.append(key.id)

            try:
                await self.bundles.delete(bundle_id)
            except sqlite3.IntegrityError as exc:
                # ON DELETE RESTRICT fired: a key still points at the bundle even
                # though we just cleared every child we could see (e.g. one was
                # attached concurrently). Fail loudly instead of orphaning.
                await self._mark_bundle_failed(bundle_id)
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="key_bundle_delete_restricted",
                    entity_id=bundle_id,
                    details={"deleted_key_ids": deleted_ids},
                )
                raise InvalidOperation(
                    "Нельзя удалить подписку: к ней всё ещё привязаны ключи",
                    key="err_bundle_has_keys",
                ) from exc

            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="key_bundle_deleted",
                entity_id=bundle_id,
                details={"owner_user_id": bundle.user_id, "deleted_key_ids": deleted_ids},
            )

    # ── composition / availability ────────────────────────────────────

    async def _resolve_composition(self) -> tuple[tuple[BundleMember, ...], tuple[BundleMember, ...]]:
        """Split the composition seam into (included, skipped-because-disabled)."""
        included: list[BundleMember] = []
        skipped: list[BundleMember] = []
        for member in bundle_composition():
            if await self._member_enabled(member):
                included.append(member)
            else:
                skipped.append(member)
        return tuple(included), tuple(skipped)

    async def _member_enabled(self, member: BundleMember) -> bool:
        """Whether *member*'s backend is switched on right now.

        Mirrors exactly what gates the single-key create path for that protocol:
        the protocol-module toggle plus the protocol's own ``.env`` flags. A
        disabled backend is a normal state, never an error.
        """
        if not await self.modules.is_enabled(member.protocol_module):
            return False
        if member.key_type is VpnKeyType.XRAY:
            if member.transport == "http":
                return self.settings.xray_xhttp_enabled
            return True
        if member.key_type is VpnKeyType.HYSTERIA2:
            return self.settings.hysteria2_enabled and self.settings.is_hysteria2_ready()
        # Unreachable while bundle_composition() is the only producer of members.
        return False

    # ── child provisioning through the existing per-protocol paths ────

    async def _provision_child(
        self,
        actor_user_id: int,
        owner: TelegramUserProfile,
        member: BundleMember,
        *,
        note: str | None,
        expires_at: str | None,
        allow_pending_owner: bool,
    ) -> VpnKey:
        if member.key_type is VpnKeyType.XRAY:
            result = await self.xray.create_xray_key(
                actor_user_id,
                owner,
                note,
                expires_at=expires_at,
                allow_pending_owner=allow_pending_owner,
                transport=member.transport,
                xhttp_profile=member.xhttp_profile,
            )
            return result.key
        if member.key_type is VpnKeyType.HYSTERIA2:
            result = await self.hysteria.issue(
                actor_user_id,
                owner,
                note,
                expires_at,
                allow_pending_owner,
            )
            return result.key
        raise InvalidOperation(f"Протокол {member.key_type.value} не входит в all-in-one подписку")

    async def _revoke_child(self, actor_user_id: int, key: VpnKey) -> None:
        if key.key_type is VpnKeyType.XRAY:
            await self.xray.revoke_xray_key(actor_user_id, key.id)
            return
        if key.key_type is VpnKeyType.HYSTERIA2:
            await self.hysteria.revoke(actor_user_id, key.id)
            return
        raise InvalidOperation(f"Протокол {key.key_type.value} не входит в all-in-one подписку")

    async def _delete_child(self, actor_user_id: int, key: VpnKey) -> None:
        if key.key_type is VpnKeyType.XRAY:
            await self.xray.delete_xray_key(actor_user_id, key.id)
            return
        if key.key_type is VpnKeyType.HYSTERIA2:
            await self.hysteria.delete_hysteria2_key(actor_user_id, key.id)
            return
        raise InvalidOperation(f"Протокол {key.key_type.value} не входит в all-in-one подписку")

    # ── rollback ──────────────────────────────────────────────────────

    async def _rollback_partial_bundle(
        self,
        actor_user_id: int,
        bundle: KeyBundle,
        created: list[VpnKey],
        original_error: Exception,
    ) -> None:
        """Unwind a half-built bundle on both the backends and in the DB.

        Children are removed newest-first through their normal delete path, so
        each one clears its own backend artefact before its row goes. If ANY part
        of the unwind fails the bundle is marked ``delete_failed`` and kept — it
        must never be left looking like a success — and the original error is
        re-raised by the caller.
        """
        logger.warning(
            "Откат частично созданного бандла bundle_id=%s: %d дочерних ключей (%s)",
            bundle.id,
            len(created),
            type(original_error).__name__,
        )
        failed_ids: list[int] = []
        for key in reversed(created):
            try:
                await self._delete_child(actor_user_id, key)
            except Exception:
                failed_ids.append(key.id)
                logger.critical(
                    "Откат бандла bundle_id=%s не смог снять дочерний ключ key_id=%s",
                    bundle.id,
                    key.id,
                    exc_info=True,
                )

        if not failed_ids:
            try:
                await self.bundles.delete(bundle.id)
            except Exception:
                failed_ids.append(0)
                logger.critical(
                    "Откат бандла bundle_id=%s снял всех детей, но не смог удалить строку бандла",
                    bundle.id,
                    exc_info=True,
                )

        if failed_ids:
            await self._mark_bundle_failed(bundle.id)
        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="key_bundle_create_rolled_back" if not failed_ids else "key_bundle_rollback_failed",
            entity_id=bundle.id,
            details={
                "owner_user_id": bundle.user_id,
                "created_key_ids": [key.id for key in created],
                "rollback_failed_key_ids": [key_id for key_id in failed_ids if key_id],
                "original_error_type": type(original_error).__name__,
            },
        )

    # ── helpers ───────────────────────────────────────────────────────

    def _require_enabled(self) -> None:
        if not self.settings.subscription_enabled:
            raise InvalidOperation("All-in-one подписка сейчас отключена", key="err_subscription_disabled")

    async def _create_bundle_row(self, user_id: int, note: str | None) -> KeyBundle:
        """Insert the parent row with a unique ``bundle_*`` display label.

        The label is UNIQUE, so uniqueness is settled by the database rather than
        by a read-then-write check that could race. The secret subscription token
        is generated inside the repository with ``secrets.token_urlsafe`` (256
        bits, URL-safe).
        """
        for _ in range(5):
            label = self.ids.generated_key_name("bundle")
            try:
                return await self.bundles.create(
                    user_id=user_id, label=label, now=self.clock.now(), note=note
                )
            except sqlite3.IntegrityError:
                logger.warning("Коллизия метки бандла %s, повтор", label)
        raise InvalidOperation("Не удалось сгенерировать уникальную метку подписки")

    async def _rotate_token_best_effort(self, bundle_id: int) -> bool:
        try:
            await self.bundles.rotate_token(bundle_id, self.clock.now())
        except Exception:
            logger.warning("Не удалось прокрутить токен бандла bundle_id=%s", bundle_id, exc_info=True)
            return False
        return True

    async def _mark_bundle_failed(self, bundle_id: int) -> None:
        """Best-effort flip to ``delete_failed`` — never let a bundle look successful."""
        try:
            await self.bundles.set_status(bundle_id, KeyBundleStatus.DELETE_FAILED, self.clock.now())
        except Exception:
            logger.critical(
                "Не удалось пометить бандл bundle_id=%s как delete_failed", bundle_id, exc_info=True
            )

    async def _ensure_can_create(
        self, actor_user_id: int, owner_user_id: int, *, allow_pending_owner: bool = False
    ) -> None:
        """Thin pre-check so no bundle row is written for an unauthorised actor.

        The full owner-side checks (approved/blocked/guest) stay where they always
        were — inside each per-protocol create path, which every child goes
        through anyway.
        """
        actor = await self.users.require_approved_or_admin(actor_user_id)
        if actor.role != UserRole.SUPERADMIN and actor_user_id != owner_user_id:
            raise AccessDenied("Нельзя создавать ключи для другого пользователя", key="err_create_for_other")
        if allow_pending_owner and actor.role != UserRole.SUPERADMIN:
            raise AccessDenied("Только администратор может выдавать ключи гостям", key="err_guest_admin_only")

    async def _get_bundle(self, bundle_id: int) -> KeyBundle:
        bundle = await self.bundles.get_by_id(bundle_id)
        if bundle is None:
            raise NotFound("Подписка не найдена", key="err_bundle_not_found")
        return bundle

    async def _get_bundle_for_manage(self, actor_user_id: int, bundle_id: int) -> KeyBundle:
        actor = await self.users.require_approved_or_admin(actor_user_id)
        bundle = await self._get_bundle(bundle_id)
        if actor.role != UserRole.SUPERADMIN and bundle.user_id != actor_user_id:
            raise AccessDenied("Нельзя управлять чужой подпиской", key="err_foreign_bundle_manage")
        return bundle

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
                "Audit write failed after key bundle operation: action=%s entity_id=%s",
                action,
                entity_id,
                exc_info=True,
            )


def _member_name(member: BundleMember) -> str:
    """Stable, human-readable member identifier for audit details."""
    if member.key_type is VpnKeyType.XRAY:
        if member.transport == "http":
            return f"xray_http_{member.xhttp_profile}"
        return "xray_tcp"
    return member.key_type.value
