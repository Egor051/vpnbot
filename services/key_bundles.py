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
with them. ``SUBSCRIPTION_ENABLED`` gates every mutation so the flag has teeth
from the moment it exists.
"""

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Collection, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum

from adapters.clock import ClockProvider
from adapters.id_generator import IdGenerator
from config.settings import Settings
from models.dto import KeyBundle, TelegramUserProfile, VpnKey
from models.enums import AuditEntityType, KeyBundleKind, KeyBundleStatus, UserRole, VpnKeyStatus, VpnKeyType
from repositories.key_bundles import KeyBundleRepository
from services.audit import AuditService
from services.backend_health import BackendHealth
from services.errors import AccessDenied, InvalidOperation, NotFound
from services.hysteria import HysteriaService
from services.key_naming import XHTTP_PROFILES, key_member_name
from services.notes import normalize_note
from services.protocol_availability import Protocol
from services.protocol_modules import ProtocolModulesService
from services.relay import RelayCatalog, RelaySnapshot, relay_available
from services.users import UserService
from services.xray import XrayService

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

    ``relay`` names the L4 relay a member's link points at (``None`` = direct).
    A relay member is the same protocol member as its direct twin — same create
    path, same label prefix, same preference circle — provisioned with the
    relay attribute set.
    """

    key_type: VpnKeyType
    transport: str = "tcp"
    xhttp_profile: str = "base"
    relay: str | None = None

    @property
    def protocol_module(self) -> str:
        """Name of this member's protocol module in ``protocol_modules``."""
        return self.key_type.value


def _direct_members(kind: KeyBundleKind) -> tuple[BundleMember, ...]:
    """The direct members of a bundle of *kind*, in serving order."""
    if kind is KeyBundleKind.BASIC:
        return (
            BundleMember(VpnKeyType.XRAY, transport="tcp", xhttp_profile="base"),
            BundleMember(VpnKeyType.HYSTERIA2),
        )
    return (
        BundleMember(VpnKeyType.XRAY, transport="tcp", xhttp_profile="base"),
        BundleMember(VpnKeyType.HYSTERIA2),
        *(
            BundleMember(VpnKeyType.XRAY, transport="http", xhttp_profile=profile)
            for profile in XHTTP_PROFILES
        ),
    )


def bundle_composition(
    kind: KeyBundleKind = KeyBundleKind.EXTENDED, *, relays: Sequence[str] = ()
) -> tuple[BundleMember, ...]:
    """THE seam: every child key an all-in-one bundle may contain, in order.

    This is the single point where the bundle's composition — and the order the
    subscription presents it in — is decided:

    * **extended** — VLESS (TCP) and Hysteria2 first, then the VLESS (HTTP)
      profiles from the fastest (``base``) to the slowest (``antisib``): sorted by
      how good a connection the member usually gives;
    * **basic** — VLESS (TCP), then Hysteria2.

    *relays* names the relays new bundles get members through, in relay order
    (``relays.id``) — the caller passes the relays that are enabled AND marked
    «в подписках». For each of them the same members follow once more as relay
    members, in groups: every direct member first, then every member through
    relay #1, then through relay #2, and so on, each group in the order above
    (basic: 2 per group, extended: 5). Availability (a backend switched off in
    ``.env`` or via the protocol-module toggle) is filtered on top of it by
    :meth:`KeyBundleService._resolve_composition`. Any future divergence belongs
    HERE and nowhere else — never as scattered ``if``s along the provisioning path.

    Deliberately excluded:

    * **AWG** — WireGuard configs do not ride a base64 v2ray subscription at all.
    * **SOCKS5 / MTProto** — a different entity (``ProxyAccess``), and MTProto is
      not even a v2ray link format.
    """
    direct = _direct_members(kind)
    return (
        *direct,
        *(
            BundleMember(member.key_type, member.transport, member.xhttp_profile, relay=relay)
            for relay in relays
            for member in direct
        ),
    )


def member_protocol(member: BundleMember) -> Protocol:
    """The availability switch a composition member depends on.

    The same mapping :meth:`KeyBundleService._member_enabled` applies on the
    provisioning path (a VLESS (HTTP) member needs XHTTP on top of Xray), stated as
    a :class:`~services.protocol_availability.Protocol` so the texts describing a
    bundle can filter the composition exactly the way creating one does.
    """
    if member.key_type is VpnKeyType.XRAY:
        return Protocol.XHTTP if member.transport == "http" else Protocol.XRAY
    if member.key_type is VpnKeyType.HYSTERIA2:
        return Protocol.HYSTERIA2
    raise ValueError(f"not a bundle member type: {member.key_type}")


def available_composition(
    kind: KeyBundleKind, available: Collection[Protocol]
) -> tuple[BundleMember, ...]:
    """The direct members of a *kind* bundle whose protocol is available right now.

    :func:`bundle_composition` filtered by availability — what describing a bundle
    (the kind screen, the help text, whether to offer All-in-One at all) is built
    from, so no text keeps a hard-coded member list of its own. Relay members are
    left out: they repeat the direct ones and add no protocol.
    """
    return tuple(member for member in bundle_composition(kind) if member_protocol(member) in available)


def member_name(member: BundleMember) -> str:
    """Stable, human-readable identifier of one composition member.

    The same vocabulary the audit trail records (``xray_tcp`` / ``xray_http_base``
    / ``hysteria2``), and the join key between the composition seam above and the
    per-member presentation the subscription renderer applies.
    """
    if member.key_type is VpnKeyType.XRAY:
        if member.transport == "http":
            return f"xray_http_{member.xhttp_profile}"
        return "xray_tcp"
    return member.key_type.value


def member_audit_name(member: BundleMember) -> str:
    """:func:`member_name` plus ``_relay`` (and the relay's name) for a relay member.

    What the audit trail records in ``included``/``skipped``: with relay members a
    bare member name would list ``xray_tcp`` several times and lose which one was
    which — and with several relays, through which relay.
    """
    name = member_name(member)
    return f"{name}_relay_{member.relay}" if member.relay is not None else name


def subscription_member_order() -> tuple[str, ...]:
    """Member names in the order a subscription must list them (within a group).

    Derived from :func:`bundle_composition` rather than restated, so the order a
    bundle is *provisioned* in and the order its subscription is *served* in cannot
    drift apart. The renderer sorts by this instead of trusting child ``id`` order,
    which would leave bundles created before an order change stuck on the old one.
    The basic composition is a prefix-ordered subset of the extended one, so this
    one list ranks both kinds.
    """
    return tuple(member_name(member) for member in bundle_composition(KeyBundleKind.EXTENDED))


def subscription_sort_key(key: VpnKey, relays: RelaySnapshot) -> tuple[int, int, int]:
    """Sort key placing a provisioned child where the subscription serves it.

    Direct children first, then the children of relay #1, relay #2, … in relay
    order (``relays.id``, via :meth:`RelaySnapshot.group_of`); inside each group
    the composition order (:func:`subscription_member_order`), ties broken by id.
    An unknown member (a protocol a future migration added before this list
    learned about it) sorts to the end of its group instead of being dropped, and
    a child of a relay *relays* does not know sorts after every known relay.
    Shared by the subscription renderer and the bot's «Состав» preview, so the two
    cannot disagree.
    """
    order = subscription_member_order()
    name = key_member_name(key)
    rank = order.index(name) if name in order else len(order)
    return (relays.group_of(key.relay), rank, key.id)


def child_audit_name(key: VpnKey) -> str:
    """:func:`member_audit_name` of a provisioned child — the same vocabulary.

    Lets a reconcile plan name the children it removes exactly as it names the
    members it adds, so «create xray_tcp_relay_ru1 / delete xray_http_base» reads
    as one list.
    """
    name = key_member_name(key)
    return f"{name}_relay_{key.relay}" if key.relay is not None else name


def _member_slot(member: BundleMember) -> tuple[str, str | None]:
    """The (member name, relay) pair a composition member occupies."""
    return member_name(member), member.relay


def _child_slot(key: VpnKey) -> tuple[str, str | None]:
    """The (member name, relay) pair a provisioned child occupies."""
    return key_member_name(key), key.relay


# Key types a bundle may hold — the ones _provision_child/_delete_child handle.
_BUNDLE_CHILD_TYPES = frozenset({VpnKeyType.XRAY, VpnKeyType.HYSTERIA2})
# A child in one of these was being removed and the removal did not finish (a
# failed delete, or a failed reconcile rollback): it was meant to go, so a
# reconcile finishes the removal wherever it sits instead of skipping the bundle.
_REMOVAL_STATUSES = frozenset({VpnKeyStatus.PENDING_DELETE, VpnKeyStatus.DELETE_FAILED})


class ReconcileOutcome(StrEnum):
    """What :meth:`KeyBundleService.reconcile_composition` did to one bundle."""

    # Already the target composition and kind; nothing written.
    NOOP = "noop"
    # dry_run: the plan has changes; nothing written.
    PLANNED = "planned"
    # Every create, delete and the kind update went through.
    APPLIED = "applied"
    # Not touched at all; ``skip_reason`` says why.
    SKIPPED = "skipped"
    # A create failed; what this call created was rolled back, the bundle is as
    # it was (``rollback_failed_key_ids`` lists anything the unwind could not
    # remove).
    FAILED = "failed"
    # Every create went through, then a delete failed; the kind was not changed.
    # A re-run finishes the job.
    PARTIAL = "partial"


class ReconcileSkipReason(StrEnum):
    """Why a bundle was left untouched by a reconcile."""

    NOT_ACTIVE = "not_active"
    # The target composition is empty: every member's backend is switched off.
    NO_MEMBERS = "no_members"
    # A child of a protocol a bundle cannot hold (only VLESS / Hysteria2 can).
    UNSUPPORTED_CHILD = "unsupported_child"
    # No active child at all (e.g. every child expired) — nothing to take the
    # expiry and fingerprint from.
    NO_ACTIVE_CHILDREN = "no_active_children"
    # Two active children occupy the same member slot.
    DUPLICATE_MEMBER = "duplicate_member"
    # The active children do not share one expires_at.
    MIXED_EXPIRY = "mixed_expiry"
    # The shared expires_at has already passed.
    EXPIRED = "expired"
    # A child of a target member is not active and not being removed (revoked,
    # failed to apply, …).
    INACTIVE_CHILD = "inactive_child"
    BACKEND_DEGRADED = "backend_degraded"


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    """The plan for — or the outcome of — reconciling one bundle.

    ``to_create`` / ``to_delete`` are :func:`member_audit_name` values: the
    members missing from the bundle and the children outside the target. With
    ``dry_run`` they are the plan; otherwise what was attempted. ``created_key_ids``
    / ``deleted_key_ids`` are what actually happened. ``kind_after`` is the kind
    the bundle has after the call (for a dry run: would have).
    """

    bundle_id: int
    display_no: int
    outcome: ReconcileOutcome
    kind_before: KeyBundleKind | None = None
    kind_after: KeyBundleKind | None = None
    to_create: tuple[str, ...] = ()
    to_delete: tuple[str, ...] = ()
    created_key_ids: tuple[int, ...] = ()
    deleted_key_ids: tuple[int, ...] = ()
    rollback_failed_key_ids: tuple[int, ...] = ()
    skip_reason: ReconcileSkipReason | None = None
    anomalies: tuple[str, ...] = ()
    error: Exception | None = field(default=None, compare=False)

    @property
    def kind_changes(self) -> bool:
        return self.kind_before is not None and self.kind_after is not None and self.kind_before != self.kind_after


@dataclass(frozen=True, slots=True)
class ReconcileSummary:
    """Results of reconciling every active bundle, in bundle id order."""

    results: tuple[ReconcileResult, ...]
    # Active bundles the run did not reach because it was asked to stop.
    remaining: int = 0

    def with_outcome(self, *outcomes: ReconcileOutcome) -> tuple[ReconcileResult, ...]:
        return tuple(result for result in self.results if result.outcome in outcomes)

    @property
    def keys_to_create(self) -> int:
        return sum(len(result.to_create) for result in self.with_outcome(ReconcileOutcome.PLANNED))

    @property
    def keys_to_delete(self) -> int:
        return sum(len(result.to_delete) for result in self.with_outcome(ReconcileOutcome.PLANNED))

    @property
    def kind_changes(self) -> int:
        return sum(1 for result in self.with_outcome(ReconcileOutcome.PLANNED) if result.kind_changes)

    @property
    def keys_created(self) -> int:
        return sum(len(result.created_key_ids) for result in self.results if result.outcome is not ReconcileOutcome.FAILED)

    @property
    def keys_deleted(self) -> int:
        return sum(len(result.deleted_key_ids) for result in self.results)


def _bundle_fingerprint(active: list[VpnKey], relays: RelaySnapshot) -> str | None:
    """The TLS fingerprint a new VLESS child of this bundle should get.

    Taken from the existing VLESS children in serving order (the direct TCP one
    first): :meth:`KeyBundleService.change_fingerprint` stamps them all with one
    value, and creation does too. ``None`` — no VLESS child, or one that never
    had a fingerprint — keeps the global ``XRAY_FINGERPRINT`` default.
    """
    for key in sorted(active, key=lambda key: subscription_sort_key(key, relays)):
        if key.key_type is VpnKeyType.XRAY and key.payload.get("fingerprint"):
            return str(key.payload["fingerprint"])
    return None


@dataclass(frozen=True, slots=True)
class _ReconcilePlan:
    kind_after: KeyBundleKind
    create: tuple[BundleMember, ...]
    delete: tuple[VpnKey, ...]
    expires_at: str | None
    fingerprint: str | None


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
        relays: RelayCatalog | None = None,
    ) -> None:
        self.bundles = bundles
        # Which relays new bundles get members through (enabled + «в подписках»).
        self.relays = relays if relays is not None else RelayCatalog()
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
        fingerprint: str | None = None,
        kind: KeyBundleKind = KeyBundleKind.EXTENDED,
    ) -> KeyBundleCreateResult:
        """Provision one child key per available protocol under a single bundle.

        *kind* picks the composition (:func:`bundle_composition`) and is stored on
        the bundle row, where the subscription renderer reads it to choose the
        naming rule. Only the admin reconcile (:meth:`reconcile_composition`) may
        change it later.

        Atomic from the caller's point of view: either every included child is
        live and attached, or nothing is left behind on the backends or in the DB.
        All children share the same *expires_at* so they expire together and the
        key-expiry job needs no bundle awareness at all.

        *fingerprint* is applied to every Xray child (Hysteria2 has no such
        setting), so one subscription speaks with one TLS fingerprint instead of
        four children silently taking the global ``XRAY_FINGERPRINT`` default.
        ``None`` keeps exactly that old behaviour. The value is validated by the
        caller against ``VALID_FINGERPRINTS``, the same contract the single-key
        create path uses.
        """
        self._require_enabled()
        kind = KeyBundleKind(kind)
        clean_note = normalize_note(note)
        async with self._lock:
            included, skipped = await self._resolve_composition(kind)
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

            bundle = await self._create_bundle_row(owner.telegram_user_id, clean_note, kind)
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
                        fingerprint=fingerprint,
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
                    "kind": kind.value,
                    "expires_at": expires_at,
                    "fingerprint": fingerprint,
                    "key_ids": [key.id for key in created],
                    "included": [member_audit_name(member) for member in included],
                    "skipped": [member_audit_name(member) for member in skipped],
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

    # ── fingerprint ───────────────────────────────────────────────────

    async def change_fingerprint(
        self, actor_user_id: int, bundle_id: int, fingerprint: str
    ) -> tuple[KeyBundle, int]:
        """Re-stamp every VLESS child of a bundle with one TLS fingerprint.

        The single-key screen has been able to change a fingerprint since the
        setting existed; a subscription could only choose one at creation time and
        was then stuck with it. This closes that gap through the very same
        per-key path (:meth:`services.xray.XrayService.change_fingerprint`), so a
        child re-stamped here is indistinguishable from one re-stamped on its own
        screen — including the per-key audit entry each one writes.

        Hysteria2 has no TLS fingerprint knob and is skipped, exactly as it is on
        the create path. Returns the refreshed bundle and how many children were
        actually re-stamped.

        Not atomic, and deliberately so: the change is a pure payload/link rewrite
        with nothing applied to a backend, so a failure part-way leaves some
        children on the new fingerprint and the rest on the old — every one of them
        still a working key. Rolling the successful ones back would mean a second
        write that can fail in exactly the same way. The error names how many were
        changed instead, and a retry is idempotent.
        """
        self._require_enabled()
        async with self._lock:
            bundle = await self._get_bundle_for_manage(actor_user_id, bundle_id)
            if bundle.status is not KeyBundleStatus.ACTIVE:
                raise InvalidOperation(
                    "Fingerprint можно изменить только у активной подписки",
                    key="err_bundle_fp_active_only",
                )
            targets = [
                key
                for key in await self.bundles.list_keys_of_bundle(bundle_id)
                if key.key_type is VpnKeyType.XRAY and key.status is VpnKeyStatus.ACTIVE
            ]
            if not targets:
                raise InvalidOperation(
                    "В подписке нет активных VLESS-ключей", key="err_bundle_no_vless"
                )

            changed: list[int] = []
            for key in targets:
                try:
                    await self.xray.change_fingerprint(actor_user_id, key.id, fingerprint)
                except Exception as exc:
                    await self._write_audit_best_effort(
                        actor_user_id=actor_user_id,
                        action="key_bundle_fingerprint_failed",
                        entity_id=bundle_id,
                        details={
                            "fingerprint": fingerprint,
                            "changed_key_ids": changed,
                            "failed_key_id": key.id,
                            "error_type": type(exc).__name__,
                        },
                    )
                    raise InvalidOperation(
                        f"Fingerprint изменён только у {len(changed)} из {len(targets)} ключей подписки",
                        key="err_bundle_fp_partial",
                    ) from exc
                changed.append(key.id)

            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="key_bundle_fingerprint_changed",
                entity_id=bundle_id,
                details={"fingerprint": fingerprint, "key_ids": changed},
            )
            return await self._get_bundle(bundle_id), len(changed)

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

    # ── composition reconcile (admin) ─────────────────────────────────

    async def reconcile_composition(
        self,
        bundle_id: int,
        *,
        actor_user_id: int,
        target_kind: KeyBundleKind | None = None,
        dry_run: bool = False,
    ) -> ReconcileResult:
        """Bring an existing bundle to the composition a new one would get now.

        The target is exactly what :meth:`create_bundle` would provision —
        :meth:`_resolve_composition` of *target_kind* (or the bundle's own kind),
        relay members included for every relay that is enabled and marked «в
        подписках» — so «switch to basic» and «top up with relay members» are the
        same operation. Active children are
        matched to it by (member name, relay):

        * a missing member is created through :meth:`_provision_child` for the
          bundle's owner, with the bundle's note, the children's shared
          ``expires_at`` and the existing VLESS fingerprint, and attached;
        * a child outside the target — and any non-active child outside it, such
          as one a previous run failed to delete — is removed through
          :meth:`_delete_child`, the very path :meth:`delete_bundle` uses.

        Order: every create first; if one fails, what this call created is rolled
        back and the bundle is left as it was (``FAILED``). Then the deletes; if
        one fails the call stops (``PARTIAL``) and a re-run finishes the job. Then
        the kind. The subscription token never changes. A bundle already in shape
        is a no-op.

        Anything unusual — two children in one slot, children with different
        expiries, a non-active child holding a target member, a degraded backend
        the plan touches — skips the bundle untouched, with the reason in the
        result. Superadmin only.
        """
        self._require_enabled()
        target = KeyBundleKind(target_kind) if target_kind is not None else None
        await self.users.require_superadmin(actor_user_id)
        async with self._lock:
            bundle = await self._get_bundle(bundle_id)
            plan = await self._plan_reconcile(bundle, target)
            if isinstance(plan, ReconcileResult):
                return plan
            if dry_run:
                return ReconcileResult(
                    bundle_id=bundle.id,
                    display_no=bundle.display_no,
                    outcome=ReconcileOutcome.PLANNED,
                    kind_before=bundle.kind,
                    kind_after=plan.kind_after,
                    to_create=tuple(member_audit_name(member) for member in plan.create),
                    to_delete=tuple(child_audit_name(key) for key in plan.delete),
                )
            return await self._apply_reconcile(actor_user_id, bundle, plan)

    async def reconcile_all(
        self,
        *,
        actor_user_id: int,
        target_kind: KeyBundleKind | None = None,
        dry_run: bool = False,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ) -> ReconcileSummary:
        """:meth:`reconcile_composition` for every active bundle, one at a time.

        One bundle's error never stops the rest: it becomes a ``FAILED`` result.
        *on_progress* gets (done, total) after each bundle; its own errors are
        logged and ignored. The lock is taken per bundle, not for the whole run,
        so ordinary bundle operations keep working while it runs.

        *should_stop* is asked before each bundle — never in the middle of one, so
        a stop (bot shutdown) never leaves a bundle half-provisioned; the bundles
        not reached are counted in ``remaining`` and a re-run picks them up.
        """
        self._require_enabled()
        await self.users.require_superadmin(actor_user_id)
        bundle_ids = await self.bundles.list_ids_by_status(KeyBundleStatus.ACTIVE)
        results: list[ReconcileResult] = []
        for done, bundle_id in enumerate(bundle_ids, start=1):
            if should_stop is not None and should_stop():
                remaining = len(bundle_ids) - done + 1
                logger.warning("Приведение состава бандлов остановлено: не обработано %d", remaining)
                return ReconcileSummary(tuple(results), remaining=remaining)
            try:
                result = await self.reconcile_composition(
                    bundle_id, actor_user_id=actor_user_id, target_kind=target_kind, dry_run=dry_run
                )
            except Exception as exc:
                logger.warning("Не удалось привести состав бандла bundle_id=%s", bundle_id, exc_info=True)
                result = ReconcileResult(
                    bundle_id=bundle_id,
                    display_no=await self._display_no_best_effort(bundle_id),
                    outcome=ReconcileOutcome.FAILED,
                    error=exc,
                )
            results.append(result)
            if on_progress is not None:
                try:
                    await on_progress(done, len(bundle_ids))
                except Exception:
                    logger.warning("Reconcile progress callback failed", exc_info=True)
        return ReconcileSummary(tuple(results))

    async def _plan_reconcile(
        self, bundle: KeyBundle, target_kind: KeyBundleKind | None
    ) -> _ReconcilePlan | ReconcileResult:
        """The plan for *bundle*, or a NOOP/SKIPPED result. Reads only."""

        def skip(reason: ReconcileSkipReason, anomalies: tuple[str, ...] = ()) -> ReconcileResult:
            return ReconcileResult(
                bundle_id=bundle.id,
                display_no=bundle.display_no,
                outcome=ReconcileOutcome.SKIPPED,
                kind_before=bundle.kind,
                kind_after=bundle.kind,
                skip_reason=reason,
                anomalies=anomalies,
            )

        if bundle.status is not KeyBundleStatus.ACTIVE:
            return skip(ReconcileSkipReason.NOT_ACTIVE, (bundle.status.value,))
        kind = target_kind or bundle.kind
        included, _skipped = await self._resolve_composition(kind)
        if not included:
            return skip(ReconcileSkipReason.NO_MEMBERS)

        children = await self.bundles.list_keys_of_bundle(bundle.id)
        unsupported = [key for key in children if key.key_type not in _BUNDLE_CHILD_TYPES]
        if unsupported:
            return skip(
                ReconcileSkipReason.UNSUPPORTED_CHILD,
                tuple(f"{key.key_type.value}#{key.id}" for key in unsupported),
            )
        active = [key for key in children if key.status is VpnKeyStatus.ACTIVE]
        inactive = [key for key in children if key.status is not VpnKeyStatus.ACTIVE]
        if not active:
            return skip(ReconcileSkipReason.NO_ACTIVE_CHILDREN)

        by_slot: dict[tuple[str, str | None], list[VpnKey]] = {}
        for key in active:
            by_slot.setdefault(_child_slot(key), []).append(key)
        duplicates = {slot: keys for slot, keys in by_slot.items() if len(keys) > 1}
        if duplicates:
            return skip(
                ReconcileSkipReason.DUPLICATE_MEMBER,
                tuple(
                    f"{child_audit_name(keys[0])}: " + ", ".join(f"#{key.id}" for key in keys)
                    for keys in duplicates.values()
                ),
            )

        expiries = {key.expires_at for key in active}
        if len(expiries) > 1:
            return skip(
                ReconcileSkipReason.MIXED_EXPIRY,
                tuple(sorted(value or "-" for value in expiries)),
            )
        expires_at = next(iter(expiries))
        # The same comparison the key-expiry job revokes by.
        if expires_at is not None and expires_at <= self.clock.now():
            return skip(ReconcileSkipReason.EXPIRED, (expires_at,))

        target_slots = {_member_slot(member) for member in included}
        stale = [
            key for key in inactive if key.status not in _REMOVAL_STATUSES and _child_slot(key) in target_slots
        ]
        if stale:
            return skip(
                ReconcileSkipReason.INACTIVE_CHILD,
                tuple(f"{child_audit_name(key)}#{key.id}: {key.status.value}" for key in stale),
            )

        create = tuple(member for member in included if _member_slot(member) not in by_slot)
        # Every inactive child left is either outside the target or one whose
        # removal did not finish (checked above), so all of them go — that is what
        # lets a re-run finish a failed delete or a failed rollback. The slot of
        # the latter counts as empty and is filled by a fresh create first.
        delete = tuple(
            sorted(
                [key for key in active if _child_slot(key) not in target_slots] + inactive,
                key=lambda key: key.id,
            )
        )
        if not create and not delete and kind == bundle.kind:
            return ReconcileResult(
                bundle_id=bundle.id,
                display_no=bundle.display_no,
                outcome=ReconcileOutcome.NOOP,
                kind_before=bundle.kind,
                kind_after=bundle.kind,
            )

        affected = dict.fromkeys([member.key_type for member in create] + [key.key_type for key in delete])
        for backend in affected:
            try:
                self.backend_health.require_mutation_allowed(backend)
            except InvalidOperation:
                return skip(ReconcileSkipReason.BACKEND_DEGRADED, (backend.value,))

        return _ReconcilePlan(
            kind_after=kind,
            create=create,
            delete=delete,
            expires_at=expires_at,
            fingerprint=_bundle_fingerprint(active, self.relays.snapshot),
        )

    async def _apply_reconcile(
        self, actor_user_id: int, bundle: KeyBundle, plan: _ReconcilePlan
    ) -> ReconcileResult:
        to_create = tuple(member_audit_name(member) for member in plan.create)
        to_delete = tuple(child_audit_name(key) for key in plan.delete)

        base = ReconcileResult(
            bundle_id=bundle.id,
            display_no=bundle.display_no,
            outcome=ReconcileOutcome.FAILED,
            kind_before=bundle.kind,
            kind_after=bundle.kind,
            to_create=to_create,
            to_delete=to_delete,
        )

        created: list[VpnKey] = []
        if plan.create:
            try:
                owner, allow_pending_owner = await self._bundle_owner(bundle.user_id)
                for member in plan.create:
                    key = await self._provision_child(
                        actor_user_id,
                        owner,
                        member,
                        note=bundle.note,
                        expires_at=plan.expires_at,
                        allow_pending_owner=allow_pending_owner,
                        fingerprint=plan.fingerprint,
                    )
                    # Recorded before the attach, so a failed attach is unwound too.
                    created.append(key)
                    await self.bundles.attach_key_to_bundle(key.id, bundle.id, self.clock.now())
            except Exception as exc:
                rollback_failed = await self._rollback_reconcile_creates(actor_user_id, bundle, created)
                await self._write_audit_best_effort(
                    actor_user_id=actor_user_id,
                    action="key_bundle_reconcile_rolled_back"
                    if not rollback_failed
                    else "key_bundle_reconcile_rollback_failed",
                    entity_id=bundle.id,
                    details={
                        "kind_before": bundle.kind.value,
                        "kind_after": bundle.kind.value,
                        "created_key_ids": [key.id for key in created],
                        "rollback_failed_key_ids": rollback_failed,
                        "deleted_key_ids": [],
                        "planned_create": list(to_create),
                        "planned_delete": list(to_delete),
                        "error_type": type(exc).__name__,
                    },
                )
                return replace(
                    base,
                    created_key_ids=tuple(key.id for key in created),
                    rollback_failed_key_ids=tuple(rollback_failed),
                    error=exc,
                )

        created_ids = tuple(key.id for key in created)
        deleted: list[int] = []
        try:
            for key in plan.delete:
                await self._delete_child(actor_user_id, key)
                deleted.append(key.id)
            if plan.kind_after != bundle.kind:
                await self.bundles.set_kind(bundle.id, plan.kind_after, now=self.clock.now())
        except Exception as exc:
            logger.warning(
                "Приведение состава бандла bundle_id=%s остановилось: удалено %d из %d",
                bundle.id,
                len(deleted),
                len(plan.delete),
                exc_info=True,
            )
            await self._write_audit_best_effort(
                actor_user_id=actor_user_id,
                action="key_bundle_reconcile_partial",
                entity_id=bundle.id,
                details={
                    "kind_before": bundle.kind.value,
                    "kind_after": bundle.kind.value,
                    "created_key_ids": list(created_ids),
                    "deleted_key_ids": deleted,
                    "planned_delete": list(to_delete),
                    "error_type": type(exc).__name__,
                },
            )
            return replace(
                base,
                outcome=ReconcileOutcome.PARTIAL,
                created_key_ids=created_ids,
                deleted_key_ids=tuple(deleted),
                error=exc,
            )

        await self._write_audit_best_effort(
            actor_user_id=actor_user_id,
            action="key_bundle_composition_reconciled",
            entity_id=bundle.id,
            details={
                "kind_before": bundle.kind.value,
                "kind_after": plan.kind_after.value,
                "created_key_ids": list(created_ids),
                "deleted_key_ids": deleted,
                "created": list(to_create),
                "deleted": list(to_delete),
            },
        )
        return replace(
            base,
            outcome=ReconcileOutcome.APPLIED,
            kind_after=plan.kind_after,
            created_key_ids=created_ids,
            deleted_key_ids=tuple(deleted),
        )

    async def _rollback_reconcile_creates(
        self, actor_user_id: int, bundle: KeyBundle, created: list[VpnKey]
    ) -> list[int]:
        """Remove what a failed reconcile created, newest first; return what stuck.

        Unlike :meth:`_rollback_partial_bundle` the bundle itself stays: it was a
        working subscription before this call and still is. A child the unwind
        cannot remove stays attached: still ``active`` (the delete never started —
        a re-run counts it as present) or ``delete_failed`` (a re-run finishes its
        removal and fills the slot afresh).
        """
        failed: list[int] = []
        for key in reversed(created):
            try:
                await self._delete_child(actor_user_id, key)
            except Exception:
                failed.append(key.id)
                logger.critical(
                    "Откат приведения бандла bundle_id=%s не смог снять ключ key_id=%s",
                    bundle.id,
                    key.id,
                    exc_info=True,
                )
        return failed

    async def _display_no_best_effort(self, bundle_id: int) -> int:
        """The «All-in-One #N» of a bundle for an error line; its id if unreadable."""
        try:
            bundle = await self.bundles.get_by_id(bundle_id)
        except Exception:
            return bundle_id
        return bundle.display_no if bundle is not None else bundle_id

    async def _bundle_owner(self, user_id: int) -> tuple[TelegramUserProfile, bool]:
        """The owner's profile and whether they are a guest (pending) user.

        A guest's bundle was issued by an admin with ``allow_pending_owner``;
        topping it up needs the same allowance, or every create would be refused.
        The per-protocol path still refuses a blocked owner either way.
        """
        user = await self.users.get_user(user_id)
        profile = TelegramUserProfile(user.telegram_user_id, user.username, user.first_name)
        return profile, user.role is UserRole.PENDING_USER

    # ── composition / availability ────────────────────────────────────

    async def _resolve_composition(
        self, kind: KeyBundleKind = KeyBundleKind.EXTENDED
    ) -> tuple[tuple[BundleMember, ...], tuple[BundleMember, ...]]:
        """Split the composition seam into (included, skipped-because-disabled).

        Relay members are asked for only for the relays that are enabled and
        marked «в подписках»: any other relay is not part of the composition at
        all (rather than "skipped"), so a deployment without a relay — or with one
        kept out of subscriptions — never sees it named here.
        """
        relays = tuple(relay.name for relay in self.relays.snapshot.for_subscriptions)
        included: list[BundleMember] = []
        skipped: list[BundleMember] = []
        for member in bundle_composition(kind, relays=relays):
            if await self._member_enabled(member):
                included.append(member)
            else:
                skipped.append(member)
        return tuple(included), tuple(skipped)

    async def _member_enabled(self, member: BundleMember) -> bool:
        """Whether *member*'s backend is switched on right now.

        Mirrors exactly what gates the single-key create path for that protocol:
        the protocol-module toggle plus the protocol's own ``.env`` flags. A
        disabled backend is a normal state, never an error. A relay member
        additionally needs its relay to be enabled right now.
        """
        if member.relay is not None and not relay_available(self.relays.snapshot, member.relay):
            return False
        # Removed from the host (uninstall marker): off whatever the toggle says. The
        # real modules service already folds this into is_enabled; asked here too so
        # a modules double without it cannot put a removed backend in a bundle.
        is_uninstalled = getattr(self.modules, "is_uninstalled", None)
        if is_uninstalled is not None and is_uninstalled(member.protocol_module):
            return False
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
        fingerprint: str | None = None,
    ) -> VpnKey:
        if member.key_type is VpnKeyType.XRAY:
            result = await self.xray.create_xray_key(
                actor_user_id,
                owner,
                note,
                expires_at=expires_at,
                allow_pending_owner=allow_pending_owner,
                fingerprint=fingerprint,
                transport=member.transport,
                xhttp_profile=member.xhttp_profile,
                relay=member.relay,
            )
            return result.key
        # Hysteria2 has no TLS fingerprint knob, so *fingerprint* is ignored here
        # rather than threaded through and dropped further down.
        if member.key_type is VpnKeyType.HYSTERIA2:
            result = await self.hysteria.issue(
                actor_user_id,
                owner,
                note,
                expires_at,
                allow_pending_owner,
                relay=member.relay,
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

    async def _create_bundle_row(
        self, user_id: int, note: str | None, kind: KeyBundleKind = KeyBundleKind.EXTENDED
    ) -> KeyBundle:
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
                    user_id=user_id, label=label, now=self.clock.now(), note=note, kind=kind
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
