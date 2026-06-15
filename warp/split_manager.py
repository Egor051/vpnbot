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
_LOOPBACK: Final = ipaddress.ip_network("127.0.0.0/8")
_LINK_LOCAL: Final = ipaddress.ip_network("169.254.0.0/16")
_MULTICAST: Final = ipaddress.ip_network("224.0.0.0/4")
_WARP_TUNNEL: Final = ipaddress.ip_network("172.16.0.0/12")

_STATIC_GUARDS: Final[list[tuple[ipaddress.IPv4Network, str]]] = [
    (_LOOPBACK, "loopback (127.0.0.0/8)"),
    (_LINK_LOCAL, "link-local (169.254.0.0/16)"),
    (_MULTICAST, "multicast (224.0.0.0/4)"),
    (_WARP_TUNNEL, "WARP tunnel range (172.16.0.0/12) — would break the tunnel"),
]


class WarpSplitError(InvalidOperation):
    """User-facing failure from the split-list helper."""


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
    ) -> None:
        self._list_path = list_path
        self._apply_helper_path = apply_helper_path
        try:
            self._awg_network = ipaddress.ip_network(awg_network, strict=False)
        except ValueError:
            self._awg_network = ipaddress.ip_network("10.0.0.0/24")
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
        eth0 = _eth0_network()
        if eth0 is not None:
            guards.append((eth0, f"server eth0 network ({eth0}) — would break SSH"))
        return guards


# ── module-level helpers ───────────────────────────────────────────────────────


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


def _eth0_network() -> ipaddress.IPv4Network | None:
    """Detect the eth0 subnet at runtime; returns None if unavailable."""
    try:
        import fcntl
        import struct

        SIOCGIFADDR = 0x8915
        SIOCGIFNETMASK = 0x891B
        iface = b"eth0"
        # ifreq: 16 bytes interface name + 16 bytes padding
        ifreq = struct.pack("16s16x", iface)
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


def parse_cidr_tokens(text: str) -> list[str]:
    """Split *text* on whitespace, commas and newlines; return non-empty tokens."""
    import re
    return [t.strip() for t in re.split(r"[\s,]+", text) if t.strip()]
