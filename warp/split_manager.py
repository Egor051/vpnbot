"""WARP selective-split list management.

Read-only access goes directly to the list file (0644, readable by the bot
user). Writes go exclusively through ``vpn-bot-warp-split-apply`` (root helper)
which validates every CIDR, writes atomically, and restarts the service.
The bot never touches ip/route/iptables — all of that lives in the helper.

Two invariants are enforced here and nowhere else:

* **Every mutation is a read-modify-write under one lock.** The list is a single
  file with no compare-and-swap; two concurrent "add a prefix" flows that each
  read 108 entries and write 109 produce a file with one of the two additions
  silently missing. The composite methods below (:meth:`add_prefixes`,
  :meth:`remove_prefixes`, :meth:`reapply`, :meth:`apply_merged`) hold
  ``self._lock`` across the whole read → validate → write cycle; the background
  feed refresh takes the same lock, so it can never interleave with an admin
  typing into the panel.

* **Nothing is written that has not passed every guard.** A guard rejection
  fails the whole operation. There is no "skip the bad prefix and apply the
  rest": a partially applied routing policy is harder to notice than a refused
  one, and the most dangerous entry here (a prefix covering the WARP endpoint)
  produces a routing loop that takes the tunnel down for everyone.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from adapters.privileged_helpers import PrivilegedHelperRunner
from adapters.shell_runner import ShellRunner
from services.errors import InvalidOperation

logger = logging.getLogger(__name__)

# Static guard networks that must never appear in the split list.
# Entries are (network, reason) pairs used to generate user-facing messages.
_LOOPBACK: Final = ipaddress.IPv4Network("127.0.0.0/8")
_LINK_LOCAL: Final = ipaddress.IPv4Network("169.254.0.0/16")
_MULTICAST: Final = ipaddress.IPv4Network("224.0.0.0/4")
_WARP_TUNNEL: Final = ipaddress.IPv4Network("172.16.0.0/12")

_STATIC_GUARDS: Final[list[tuple[ipaddress.IPv4Network, str]]] = [
    (_LOOPBACK, "loopback (127.0.0.0/8)"),
    (_LINK_LOCAL, "link-local (169.254.0.0/16)"),
    (_MULTICAST, "multicast (224.0.0.0/4)"),
    (_WARP_TUNNEL, "WARP tunnel range (172.16.0.0/12) — would break the tunnel"),
]


class WarpSplitError(InvalidOperation):
    """User-facing failure from the split-list helper."""


class WarpSplitCapExceeded(WarpSplitError):
    """The candidate list is larger than WARP_SPLIT_MAX_PREFIXES.

    Carries the numbers so the caller can say *why* the list grew — a bare
    "too many prefixes" is useless when the cause is a subtraction that shattered
    99 prefixes into 262. See services.warp_split_feeds for the enriched text.
    """

    def __init__(self, *, count: int, limit: int) -> None:
        self.count = count
        self.limit = limit
        super().__init__(
            f"{count} prefixes exceeds the limit of {limit} (WARP_SPLIT_MAX_PREFIXES) — "
            "nothing was applied"
        )


@dataclass(frozen=True, slots=True)
class SplitStatus:
    """Snapshot of the split-routing state for the admin panel.

    ``intended_state`` is the operator intent read from the root-owned marker
    (``"on"`` / ``"off"``); ``n_list`` is the saved prefix count; ``n_table`` is the
    number of script-managed ``dev <iface>`` routes actually present in table T
    (``None`` when it could not be read). ``in_sync`` is True when reality matches
    intent (or when reality is unknown — we never claim drift we cannot prove).
    ``tunnel_up`` is an observer signal only; it never depends on on/off.
    """

    tunnel_up: bool
    intended_state: str  # "on" | "off"
    n_list: int
    n_table: int | None
    in_sync: bool


@dataclass(slots=True)
class CidrResult:
    """Outcome of processing one CIDR token from user input."""

    raw: str
    canonical: str = ""
    status: str = ""   # "added" | "dup" | "removed" | "not_found" | "rejected"
    note: str = ""     # human-readable detail (normalisation note or reject reason)


@dataclass(frozen=True, slots=True)
class ApplyOutcome:
    """What one apply actually did, for the audit record and the panel.

    ``unchanged`` is the byte-identity short-circuit: the rendered list matched
    the file already on disk, so the helper was never invoked and nothing was
    restarted. That path is what makes "deploy this feature, enable no feed,
    nothing happens" a property of the code rather than a hope — see
    :meth:`_apply_locked`.
    """

    count: int
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    unchanged: bool = False
    actor_user_id: int | None = None

    @property
    def changed(self) -> bool:
        return not self.unchanged

    @property
    def delta_text(self) -> str:
        return f"+{len(self.added)}/-{len(self.removed)}"


@dataclass(slots=True)
class SplitGuards:
    """The guard set a candidate list is checked against.

    Split out from the manager so the feed path and the interactive path check
    exactly the same rules, and so a test can assert on the set itself.
    """

    networks: list[tuple[ipaddress.IPv4Network, str]] = field(default_factory=list)
    endpoint_known: bool = False


class WarpSplitManager:
    """Manages the WARP selective-split prefix list.

    The manager is the single point that validates CIDR input (bot-side policy)
    and calls the privileged helper (which does syntax-safety + file write +
    systemctl restart). It never calls ip/route/iptables itself.
    """

    def __init__(
        self,
        *,
        list_path: Path,
        apply_helper_path: Path,
        awg_network: str,
        shell: ShellRunner,
        state_helper_path: Path = Path("/usr/local/sbin/vpn-bot-warp-split-state"),
        status_helper_path: Path = Path("/usr/local/sbin/vpn-bot-warp-status"),
        marker_path: Path = Path("/etc/vpn-bot/warp-split.disabled"),
        interface_name: str = "out-warp",
        max_prefixes: int = 1500,
        min_prefixlen: int = 8,
        on_applied: Callable[[ApplyOutcome], Awaitable[None]] | None = None,
        on_alert: Callable[[str], Awaitable[None]] | None = None,
    ) -> None:
        self._list_path = list_path
        self._apply_helper_path = apply_helper_path
        self._state_helper_path = state_helper_path
        self._status_helper_path = status_helper_path
        self._marker_path = marker_path
        self._interface_name = interface_name
        self._awg_network = _parse_ipv4_network(awg_network, default="10.0.0.0/24")
        self._max_prefixes = max_prefixes
        self._min_prefixlen = min_prefixlen
        self._on_applied = on_applied
        self._on_alert = on_alert
        # Always use sudo — the helper needs root to write /etc/vpn-bot/ and
        # restart systemd, regardless of whether the bot itself runs as root.
        self._runner = PrivilegedHelperRunner(shell=shell, use_sudo=True)
        # Serialises the whole read-modify-write. The list file has no
        # compare-and-swap, so two flows that each read N entries and write N+1
        # lose one of the two additions with no error anywhere.
        self._lock = asyncio.Lock()
        # Last endpoint we managed to read. Cached across calls so a momentarily
        # unreachable tunnel does not silently drop the most important guard in
        # this file — see _build_guards.
        self._endpoint_ip: ipaddress.IPv4Address | None = None

    # ── read ──────────────────────────────────────────────────────────────────

    @property
    def list_path(self) -> Path:
        """Where the routed list lives (for log and panel text only)."""
        return self._list_path

    def read_list(self) -> list[str]:
        """Return sorted canonical CIDR strings from the current list file."""
        try:
            text = self._list_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        result: list[ipaddress.IPv4Network] = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
                if net.version == 4:
                    result.append(net)
                else:
                    logger.warning(
                        "warp-split list: skipping non-IPv4 entry %r (list is IPv4-only) — "
                        "displayed count may differ from what the helper routes",
                        line,
                    )
            except ValueError:
                logger.warning("warp-split list: skipping unparseable line %r", line)
        result.sort(key=lambda n: (n.network_address, n.prefixlen))
        return [str(n) for n in result]

    def read_list_text(self) -> str | None:
        """Return the raw bytes of the list file as text, or None if absent.

        Used for the byte-identity check. Deliberately NOT ``read_list()``:
        comparing the parsed forms would call two files identical when one has a
        comment or a differently-spelled mask, and then a legitimate rewrite
        would be skipped.
        """
        try:
            return self._list_path.read_text(encoding="utf-8")
        except OSError:
            return None

    # ── apply ─────────────────────────────────────────────────────────────────

    async def apply_list(
        self, cidr_list: list[str], *, actor_user_id: int | None = None
    ) -> ApplyOutcome:
        """Validate and write *cidr_list* via the privileged helper, under the lock.

        The helper validates every entry again (defence-in-depth), writes
        atomically, and restarts vpn-bot-warp-split. Raises WarpSplitError on any
        guard rejection or helper failure — never writes a partial list.
        """
        async with self._lock:
            return await self._apply_locked(cidr_list, actor_user_id=actor_user_id)

    async def apply_computed(
        self,
        compute: Callable[[], Awaitable[Sequence[str]]],
        *,
        force: bool = False,
        actor_user_id: int | None = None,
    ) -> ApplyOutcome:
        """Run *compute* and apply its result, both under the list lock.

        Inverted control on purpose. The feed refresh reads the manual prefixes
        from the database, merges them with the feeds, and writes the file; an
        admin adding a prefix in the panel does the same three things. If only
        the write were locked, a refresh that read the manual set a moment before
        the admin's insert would apply a list the addition is missing from — and
        the addition would be gone with no error to point at. Handing the
        computation to the manager makes the whole cycle atomic by construction,
        so no caller can forget.
        """
        async with self._lock:
            prefixes = await compute()
            return await self._apply_locked(prefixes, force=force, actor_user_id=actor_user_id)

    async def reapply(self) -> ApplyOutcome:
        """Re-run the helper on the current file (recovery after manual edits).

        Passes ``force`` so the byte-identity short-circuit does not defeat the
        one button whose entire purpose is to re-run the helper on an unchanged
        file and let it reconcile table T.
        """
        async with self._lock:
            current = self.read_list()
            if not current:
                raise WarpSplitError("list is empty — nothing to re-apply")
            return await self._apply_locked(current, force=True)

    async def _apply_locked(
        self,
        cidr_list: Sequence[str],
        *,
        force: bool = False,
        actor_user_id: int | None = None,
    ) -> ApplyOutcome:
        """Apply *cidr_list*. Caller must already hold ``self._lock``."""
        if not cidr_list:
            raise WarpSplitError("refusing to write empty list (would blackhole traffic)")

        previous = self.read_list_text()
        previous_entries = set(self.read_list())
        await self.check_candidate(cidr_list)

        content = _render_list(cidr_list)
        if not force and previous is not None and content == previous:
            # Byte-for-byte identical: no helper call, no systemctl restart, no
            # audit noise. This is what guarantees that deploying the feed
            # subsystem without enabling a feed touches nothing at all.
            logger.debug("warp-split: rendered list identical to %s — skipping apply", self._list_path)
            return ApplyOutcome(count=len(cidr_list), unchanged=True, actor_user_id=actor_user_id)

        result = await self._runner.run(
            self._apply_helper_path,
            [],
            input_text=content,
            timeout=30.0,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "no output").strip()[:256]
            await self._restore_previous(previous, detail)
            raise WarpSplitError(f"apply helper failed (rc={result.returncode}): {detail}")

        new_entries = set(cidr_list)
        outcome = ApplyOutcome(
            count=len(cidr_list),
            added=tuple(sorted(new_entries - previous_entries)),
            removed=tuple(sorted(previous_entries - new_entries)),
            actor_user_id=actor_user_id,
        )
        if self._on_applied is not None:
            try:
                await self._on_applied(outcome)
            except Exception:
                # The routes are already in place; an audit-write failure must not
                # turn a successful apply into a reported failure.
                logger.warning("warp-split: apply hook failed", exc_info=True)
        return outcome

    async def _restore_previous(self, previous: str | None, detail: str) -> None:
        """Put the previous list back after a failed apply, and alert either way.

        A non-zero rc does not say whether the helper failed before the atomic
        rename (nothing written) or after it (written, but the systemctl restart
        failed). Re-applying the previous content is correct for both: in the
        first case it is a no-op rewrite, in the second it undoes the write and
        restarts on the old list.
        """
        if previous is None or not previous.strip():
            await self._alert(
                f"WARP split apply failed and there is no previous list to restore: {detail}"
            )
            return
        try:
            restore = await self._runner.run(
                self._apply_helper_path, [], input_text=previous, timeout=30.0
            )
        except Exception as exc:
            await self._alert(f"WARP split rollback itself failed ({exc}) after: {detail}")
            return
        if restore.returncode != 0:
            await self._alert(
                "WARP split apply failed AND the rollback failed "
                f"(rc={restore.returncode}) — the routed list may be inconsistent. "
                f"Original failure: {detail}"
            )
        else:
            await self._alert(f"WARP split apply failed, previous list restored. Reason: {detail}")

    async def _alert(self, text: str) -> None:
        logger.error("%s", text)
        if self._on_alert is None:
            return
        try:
            await self._on_alert(text)
        except Exception:
            logger.warning("warp-split: alert delivery failed", exc_info=True)

    # ── on / off / restart (split ROUTING, not the tunnel) ──────────────────────

    async def enable(self) -> None:
        """Turn split routing ON: clear the marker, reconcile table T → saved list.

        Operates on the routes only — the awg-quick@out-warp interface/process is
        never touched (observer model intact). Raises WarpSplitError on failure.
        """
        await self._run_state("on")

    async def disable(self) -> None:
        """Turn split routing OFF: write the marker, reconcile table T → EMPTY.

        Every ``<prefix> dev <iface>`` route is retracted so all client/proxy
        traffic egresses direct; the saved list file is preserved (re-applied on
        ``enable``) and the anti-loop/NAT/FORWARD rules are left untouched.
        """
        await self._run_state("off")

    async def restart_routes(self) -> None:
        """Restart split routing: off-reconcile (flush) then on-reconcile (re-apply).

        The final state is ON. Only table T is affected — never the tunnel.
        """
        await self._run_state("restart")

    async def _run_state(self, verb: str) -> None:
        result = await self._runner.run(self._state_helper_path, [verb], timeout=60.0)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "no output").strip()[:256]
            raise WarpSplitError(f"state helper '{verb}' failed (rc={result.returncode}): {detail}")

    # ── status (always works — both on and off, never raises) ───────────────────

    async def status(self) -> SplitStatus:
        """Return the split-routing status for the admin panel.

        Combines the operator intent (marker file, read directly — always works)
        with the saved list count and the actual table-T contents (read via the
        privileged status verb, best-effort). Never raises: any failure degrades to
        a safe, drift-free snapshot so the panel renders in every state.
        """
        intended_state = "off" if self._marker_exists() else "on"
        n_list = len(self.read_list())

        tunnel_up = False
        n_table: int | None = None
        try:
            result = await self._runner.run(
                self._state_helper_path, ["status"], timeout=15.0
            )
            if result.returncode == 0:
                facts = _parse_state_status(result.stdout)
                tunnel_up = facts.get("tunnel_up") == "1"
                raw_table = facts.get("n_table")
                if raw_table is not None:
                    try:
                        n_table = int(raw_table)
                    except ValueError:
                        n_table = None
            else:
                tunnel_up = _iface_up(self._interface_name)
        except Exception:
            logger.debug("warp-split status helper unavailable", exc_info=True)
            tunnel_up = _iface_up(self._interface_name)

        if n_table is None:
            in_sync = True  # reality unknown — do not claim a drift we can't prove
        elif intended_state == "on":
            in_sync = n_table == n_list
        else:
            in_sync = n_table == 0

        return SplitStatus(
            tunnel_up=tunnel_up,
            intended_state=intended_state,
            n_list=n_list,
            n_table=n_table,
            in_sync=in_sync,
        )

    def _marker_exists(self) -> bool:
        try:
            return self._marker_path.exists()
        except OSError:
            return False

    # ── validation ────────────────────────────────────────────────────────────

    def process_add_tokens(
        self, tokens: list[str], current: set[str]
    ) -> tuple[list[CidrResult], list[str]]:
        """Validate and classify *tokens* for a /warp_split_add call.

        Returns (results, accepted_canonicals):
        - results: one CidrResult per non-empty token
        - accepted_canonicals: canonicalised CIDRs that should be added
        """
        guards = self._build_guards()
        results: list[CidrResult] = []
        accepted: list[str] = []
        seen: set[str] = set()

        for raw in tokens:
            token = raw.strip()
            if not token:
                continue
            r = CidrResult(raw=token)
            _validate_add(token, r, current, seen, guards, self._min_prefixlen)
            results.append(r)
            if r.status == "added":
                accepted.append(r.canonical)
                seen.add(r.canonical)

        return results, accepted

    def process_del_tokens(
        self, tokens: list[str], current: list[str]
    ) -> tuple[list[CidrResult], list[str]]:
        """Validate and classify *tokens* for a /warp_split_del call.

        Returns (results, remaining_canonicals) — the list AFTER removal.
        Raises WarpSplitError if removal would empty the list.
        """
        current_set = set(current)
        results: list[CidrResult] = []
        to_remove: set[str] = set()

        for raw in tokens:
            token = raw.strip()
            if not token:
                continue
            r = CidrResult(raw=token)
            _validate_del(token, r, current_set)
            results.append(r)
            if r.status == "removed":
                to_remove.add(r.canonical)

        remaining = [c for c in current if c not in to_remove]
        if to_remove and not remaining:
            raise WarpSplitError(
                "удаление опустошит список — отказано. "
                "Для full-tunnel: выключи split (systemctl disable vpn-bot-warp-split). "
                "Для all-direct: оставь хотя бы один sentinel-префикс."
            )
        return results, remaining

    # ── candidate validation (whole-list, used by every write path) ───────────

    async def check_candidate(self, cidr_list: Sequence[str]) -> None:
        """Validate a complete candidate list; raise WarpSplitError on any fault.

        Whole-list rather than per-token because the two rules that matter most
        are properties of the list: the cap, and the fact that a single bad entry
        must sink the entire operation rather than be dropped from it.
        """
        await self.refresh_endpoint()
        guards = self.build_guards()

        if len(cidr_list) > self._max_prefixes:
            raise WarpSplitCapExceeded(count=len(cidr_list), limit=self._max_prefixes)

        for raw in cidr_list:
            token = raw.strip()
            if not token:
                continue
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise WarpSplitError(f"{token}: invalid CIDR ({exc})") from exc
            if net.version != 4:
                raise WarpSplitError(f"{token}: only IPv4 is supported")
            if net.prefixlen == 0:
                raise WarpSplitError(
                    f"{token}: default route rejected — use the WARP module toggle for full-tunnel"
                )
            if net.prefixlen < self._min_prefixlen:
                raise WarpSplitError(
                    f"{token}: prefix shorter than /{self._min_prefixlen} "
                    f"(WARP_SPLIT_MIN_PREFIXLEN) — refusing to route that much of the internet"
                )
            for guard_net, reason in guards.networks:
                if net.overlaps(guard_net):
                    raise WarpSplitError(f"{token}: overlaps {guard_net} ({reason})")

    # ── helpers ───────────────────────────────────────────────────────────────

    def build_guards(self) -> SplitGuards:
        """Assemble every network the split list must not touch.

        Ordered most-specific-cause-first so the rejection message names the real
        reason. The endpoint guard is the one that matters: the split helper pins
        ``<endpoint>/32 via <gw> dev <wan>`` in table T *before* it installs the
        per-prefix routes, and it installs them with ``ip route replace`` — so an
        exact ``<endpoint>/32`` in the list overwrites that pin and sends the
        tunnel's own packets into the tunnel. A supernet does not overwrite the
        pin (longest-prefix keeps it winning) but is rejected too: it becomes a
        loop the moment the endpoint moves, and "safe only while a /32 elsewhere
        stays alive" is not a property worth depending on.
        """
        guards = SplitGuards(networks=list(_STATIC_GUARDS))
        guards.networks.append((self._awg_network, f"AWG client subnet ({self._awg_network})"))
        wan = _wan_network()
        if wan is not None:
            net, iface = wan
            guards.networks.append((net, f"server {iface} network ({net}) — would break SSH"))
        gateway = _default_gateway()
        if gateway is not None:
            guards.networks.append(
                (
                    ipaddress.IPv4Network(f"{gateway}/32"),
                    f"default gateway ({gateway}) — would break the host's uplink",
                )
            )
        if self._endpoint_ip is not None:
            guards.endpoint_known = True
            guards.networks.append(
                (
                    ipaddress.IPv4Network(f"{self._endpoint_ip}/32"),
                    f"WARP endpoint ({self._endpoint_ip}) — would create a routing loop",
                )
            )
        return guards

    def _build_guards(self) -> list[tuple[ipaddress.IPv4Network, str]]:
        """Backwards-compatible view of :meth:`build_guards` for the token path."""
        return self.build_guards().networks

    async def refresh_endpoint(self) -> ipaddress.IPv4Address | None:
        """Read the live WARP endpoint, remembering the last value that worked.

        Goes through ``vpn-bot-warp-status`` (already in the sudoers allowlist,
        so no new privilege is introduced) rather than calling ``awg`` directly.

        A failure keeps the previously seen value instead of clearing it. Dropping
        the guard because the tunnel happens to be down right now would be exactly
        backwards: the operator is most likely to be editing the split list while
        something is broken, and that is when a loop-inducing entry must still be
        refused.
        """
        try:
            result = await self._runner.run(
                self._status_helper_path, [self._interface_name], timeout=15.0
            )
        except Exception:
            logger.debug("warp-split: endpoint probe unavailable", exc_info=True)
            return self._endpoint_ip
        if result.returncode != 0:
            logger.debug("warp-split: endpoint probe rc=%d", result.returncode)
            return self._endpoint_ip
        found = _parse_endpoint(result.stdout)
        if found is not None:
            self._endpoint_ip = found
        elif self._endpoint_ip is None:
            logger.warning(
                "warp-split: no WARP endpoint in status output — the routing-loop guard "
                "cannot run until the tunnel reports one"
            )
        return self._endpoint_ip


# ── module-level helpers ───────────────────────────────────────────────────────


def _render_list(cidr_list: Sequence[str]) -> str:
    """Render the list exactly as it is written to disk.

    One definition, used both for the write and for the byte-identity comparison
    against the existing file — if the two ever diverged, the "nothing changed"
    short-circuit would stop firing and every refresh would restart the service.
    """
    return "\n".join(cidr_list) + "\n"


def _parse_endpoint(stdout: str) -> ipaddress.IPv4Address | None:
    """Extract the peer endpoint address from ``awg show <iface>`` output.

    The line looks like ``  endpoint: 162.159.195.1:2408``. An IPv6 endpoint is
    ignored rather than mis-parsed: the split list is IPv4-only, so an IPv6
    endpoint cannot be covered by anything in it.
    """
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line.startswith("endpoint:"):
            continue
        value = line.split(":", 1)[1].strip()
        host = value.rsplit(":", 1)[0].strip()
        try:
            return ipaddress.IPv4Address(host)
        except ValueError:
            return None
    return None


def _default_gateway() -> ipaddress.IPv4Address | None:
    """Return the IPv4 default gateway from /proc/net/route, or None.

    Same pure-file-read approach as :func:`_default_route_iface`; the Gateway
    column is little-endian hex, which is why the bytes are reversed.
    """
    try:
        lines = Path("/proc/net/route").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        destination, gateway, mask = fields[1], fields[2], fields[7]
        if destination != "00000000" or mask != "00000000":
            continue
        try:
            packed = int(gateway, 16).to_bytes(4, "little")
        except ValueError:
            return None
        address = ipaddress.IPv4Address(packed)
        return None if address == ipaddress.IPv4Address("0.0.0.0") else address  # noqa: S104
    return None


def _parse_ipv4_network(value: str, *, default: str) -> ipaddress.IPv4Network:
    """Parse *value* as an IPv4 network, falling back to *default* on error.

    The split list is IPv4-only, so an IPv6 or unparseable value is rejected and
    replaced with the safe default.
    """
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return ipaddress.IPv4Network(default)
    if isinstance(net, ipaddress.IPv4Network):
        return net
    return ipaddress.IPv4Network(default)


def _validate_add(
    token: str,
    result: CidrResult,
    current: set[str],
    seen: set[str],
    guards: list[tuple[ipaddress.IPv4Network, str]],
    min_prefixlen: int = 8,
) -> None:
    if "/" not in token:
        result.status = "rejected"
        result.note = f"нет маски — укажи, напр. {token}/32"
        return

    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        result.status = "rejected"
        result.note = f"невалидный CIDR: {exc}"
        return

    if net.version != 4:
        result.status = "rejected"
        result.note = "только IPv4 (IPv6 не поддерживается)"
        return

    canonical = str(net)
    result.canonical = canonical

    # Host-bits correction notice
    if canonical != token:
        result.note = f"host-биты скорректированы: {token!r} → {canonical}"

    # Default-route guard
    if canonical == "0.0.0.0/0":
        result.status = "rejected"
        result.note = "0.0.0.0/0 отклонён — для full-tunnel используй тумблер WARP-модуля"
        return

    # Anything shorter than the floor covers a implausible share of the address
    # space for a split rule and is far more likely to be a typo than intent.
    if net.prefixlen < min_prefixlen:
        result.status = "rejected"
        result.note = (
            f"маска короче /{min_prefixlen} (WARP_SPLIT_MIN_PREFIXLEN) — "
            "слишком большой блок для split-правила"
        )
        return

    # Other static + dynamic guards
    for guard_net, reason in guards:
        if str(guard_net) == "0.0.0.0/0":
            continue  # handled above
        if net.overlaps(guard_net):
            result.status = "rejected"
            result.note = f"пересекается с {guard_net} ({reason})"
            return

    # Dedup
    if canonical in current or canonical in seen:
        result.status = "dup"
        return

    result.status = "added"


def _validate_del(token: str, result: CidrResult, current: set[str]) -> None:
    if "/" not in token:
        result.status = "not_found"
        result.note = f"нет маски — укажи, напр. {token}/32"
        return

    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        result.status = "not_found"
        result.note = f"невалидный CIDR: {exc}"
        return

    if net.version != 4:
        result.status = "not_found"
        result.note = "только IPv4"
        return

    canonical = str(net)
    result.canonical = canonical

    if canonical not in current:
        result.status = "not_found"
        return

    result.status = "removed"


def _parse_state_status(stdout: str) -> dict[str, str]:
    """Parse ``key=value`` lines emitted by ``vpn-bot-warp-split-state status``."""
    facts: dict[str, str] = {}
    for raw in stdout.splitlines():
        line = raw.strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        facts[key.strip()] = value.strip()
    return facts


def _iface_up(iface: str) -> bool:
    """Best-effort observer check: is *iface* up? Reads sysfs, never raises.

    Used only as a fallback when the privileged status verb is unavailable (e.g.
    on a dev box). Reads ``/sys/class/net/<iface>/flags`` and tests IFF_UP (0x1).
    Returns False on any error rather than guessing the tunnel is up.
    """
    try:
        flags_text = Path(f"/sys/class/net/{iface}/flags").read_text(encoding="utf-8")
    except OSError:
        return False
    try:
        return bool(int(flags_text.strip(), 16) & 0x1)
    except ValueError:
        return False


def _default_route_iface() -> str | None:
    """Return the interface that carries the IPv4 default route, or None.

    Reads ``/proc/net/route`` and returns the interface of the row whose
    Destination and Mask are both zero. Pure file read, no shell. Returns None on
    any error so the caller can fall back to a sensible default.
    """
    try:
        lines = Path("/proc/net/route").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines[1:]:  # skip the header row
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, destination, mask = fields[0], fields[1], fields[7]
        if destination == "00000000" and mask == "00000000":
            return iface
    return None


def _iface_network(iface: str) -> ipaddress.IPv4Network | None:
    """Return the IPv4 subnet configured on *iface*, or None if unavailable."""
    try:
        import fcntl
        import struct

        SIOCGIFADDR = 0x8915
        SIOCGIFNETMASK = 0x891B
        # ifreq: 16 bytes interface name (NUL-padded, name capped at 15 chars) +
        # 16 bytes padding.
        ifreq = struct.pack("16s16x", iface.encode("utf-8")[:15])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            addr_bytes = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)[20:24]
            mask_bytes = fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, ifreq)[20:24]
        finally:
            sock.close()
        addr = socket.inet_ntoa(addr_bytes)
        mask = socket.inet_ntoa(mask_bytes)
        return ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
    except Exception:
        return None


def _wan_network() -> tuple[ipaddress.IPv4Network, str] | None:
    """Detect the server's WAN subnet — the one carrying the default route.

    Falls back to ``eth0`` when the default-route interface cannot be determined,
    so legacy boxes still get the guard, while modern predictable names
    (``ens3``/``enp1s0``/…) are handled instead of silently dropping the "would
    break SSH" guard. Returns ``(network, iface_name)`` or None if unavailable.
    """
    iface = _default_route_iface() or "eth0"
    net = _iface_network(iface)
    if net is None:
        return None
    return net, iface


def parse_cidr_tokens(text: str) -> list[str]:
    """Split *text* on whitespace, commas and newlines; return non-empty tokens."""
    import re
    return [t.strip() for t in re.split(r"[\s,]+", text) if t.strip()]
