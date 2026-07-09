"""WARP selective-split list management.

Read-only access goes directly to the list file (0644, readable by the bot
user). Writes go exclusively through ``vpnbot-warp-split-apply`` (root helper)
which validates every CIDR, writes atomically, and restarts the service.
The bot never touches ip/route/iptables — all of that lives in the helper.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
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
        state_helper_path: Path = Path("/usr/local/sbin/vpnbot-warp-split-state"),
        marker_path: Path = Path("/etc/vpnbot/warp-split.disabled"),
        interface_name: str = "out-warp",
    ) -> None:
        self._list_path = list_path
        self._apply_helper_path = apply_helper_path
        self._state_helper_path = state_helper_path
        self._marker_path = marker_path
        self._interface_name = interface_name
        self._awg_network = _parse_ipv4_network(awg_network, default="10.0.0.0/24")
        # Always use sudo — the helper needs root to write /etc/vpnbot/ and
        # restart systemd, regardless of whether the bot itself runs as root.
        self._runner = PrivilegedHelperRunner(shell=shell, use_sudo=True)

    # ── read ──────────────────────────────────────────────────────────────────

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

    # ── apply ─────────────────────────────────────────────────────────────────

    async def apply_list(self, cidr_list: list[str]) -> None:
        """Write *cidr_list* to the split file via the privileged helper.

        The helper validates every entry again (defence-in-depth), writes
        atomically, and restarts vpnbot-warp-split. Raises WarpSplitError on
        failure.
        """
        if not cidr_list:
            raise WarpSplitError("refusing to write empty list (would blackhole traffic)")
        content = "\n".join(cidr_list) + "\n"
        result = await self._runner.run(
            self._apply_helper_path,
            [],
            input_text=content,
            timeout=30.0,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "no output").strip()[:256]
            raise WarpSplitError(f"apply helper failed (rc={result.returncode}): {detail}")

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
            _validate_add(token, r, current, seen, guards)
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
                "Для full-tunnel: выключи split (systemctl disable vpnbot-warp-split). "
                "Для all-direct: оставь хотя бы один sentinel-префикс."
            )
        return results, remaining

    # ── helpers ───────────────────────────────────────────────────────────────

    def _build_guards(self) -> list[tuple[ipaddress.IPv4Network, str]]:
        guards: list[tuple[ipaddress.IPv4Network, str]] = list(_STATIC_GUARDS)
        guards.append((self._awg_network, f"AWG client subnet ({self._awg_network})"))
        wan = _wan_network()
        if wan is not None:
            net, iface = wan
            guards.append((net, f"server {iface} network ({net}) — would break SSH"))
        return guards


# ── module-level helpers ───────────────────────────────────────────────────────


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
    """Parse ``key=value`` lines emitted by ``vpnbot-warp-split-state status``."""
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
