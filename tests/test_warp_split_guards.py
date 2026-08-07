"""Whole-list guards: what may never reach /etc/vpn-bot/warp-split.list.

The rule under test is the same in every case and it is deliberately blunt: a
guard rejection fails the **entire** operation. There is no "drop the bad prefix
and apply the other 107" — a half-applied routing policy looks healthy from the
panel and is only discovered when traffic goes the wrong way.

The most important entry here is the WARP endpoint. ``vpn-bot-warp-split`` pins
``<endpoint>/32 via <gw> dev <wan>`` in table T *before* installing the
per-prefix routes, and installs them with ``ip route replace`` — so an exact
``<endpoint>/32`` in the list overwrites that pin and routes the tunnel's own
packets into the tunnel. A supernet does not overwrite the pin today (longest
prefix keeps it winning) and is refused anyway: it becomes a loop the moment the
endpoint moves, and the safety of the whole feature must not rest on a /32
staying alive somewhere else.

Offline: the privileged helper is a recording fake, the WAN/gateway probes are
patched to fixed values so the result does not depend on the box the suite runs
on, and the list file lives under ``tmp_path``.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from models.dto import ShellResult
from warp import split_manager as split_module
from warp.split_manager import (
    WarpSplitCapExceeded,
    WarpSplitError,
    WarpSplitManager,
)

AWG_NETWORK = "10.0.0.0/24"
ENDPOINT = "162.159.195.1"
WAN_NETWORK = ipaddress.IPv4Network("192.168.99.0/24")
GATEWAY = ipaddress.IPv4Address("192.168.99.1")

_STATUS_OUTPUT = f"""\
interface: out-warp
  fwmark: 0xca6c

peer: abc=
  endpoint: {ENDPOINT}:2408
  latest handshake: 8 seconds ago
"""

# A list that passes every guard, used as the "before" state so a refusal can be
# shown to have changed nothing.
BASELINE = ["8.8.8.0/24", "91.108.4.0/22"]


class GuardShell:
    """Fake ShellRunner: answers the status probe, records and performs applies."""

    def __init__(self, list_path: Path) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.list_path = list_path
        self.status_rc = 0
        self.status_stdout = _STATUS_OUTPUT

    async def run(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
        sensitive_values: tuple[str, ...] = (),
        timeout: float = 60.0,
        max_output_chars: int = 2048,
    ) -> ShellResult:
        self.calls.append((list(command), input_text))
        joined = " ".join(command)
        if "warp-status" in joined:
            return ShellResult(
                args=(), returncode=self.status_rc, stdout=self.status_stdout, stderr=""
            )
        if "split-apply" in joined:
            self.list_path.write_text(input_text or "", encoding="utf-8")
        return ShellResult(args=(), returncode=0, stdout="", stderr="")

    @property
    def applies(self) -> list[str]:
        return [text or "" for cmd, text in self.calls if "split-apply" in " ".join(cmd)]


@pytest.fixture(autouse=True)
def _fixed_host_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the WAN/gateway probes so guard results do not depend on the host.

    Without this the suite passes on a box whose uplink is 150.251.152.0/22 and
    fails on one numbered out of 8.0.0.0/8, for reasons that have nothing to do
    with the code under test.
    """
    monkeypatch.setattr(split_module, "_wan_network", lambda: (WAN_NETWORK, "eth0"))
    monkeypatch.setattr(split_module, "_default_gateway", lambda: GATEWAY)


def _manager(
    tmp_path: Path, *, max_prefixes: int = 1500, min_prefixlen: int = 8
) -> tuple[WarpSplitManager, GuardShell]:
    list_path = tmp_path / "warp-split.list"
    list_path.write_text("\n".join(BASELINE) + "\n", encoding="utf-8")
    shell = GuardShell(list_path)
    manager = WarpSplitManager(
        list_path=list_path,
        apply_helper_path=Path("/usr/local/sbin/vpn-bot-warp-split-apply"),
        awg_network=AWG_NETWORK,
        shell=shell,  # type: ignore[arg-type]
        max_prefixes=max_prefixes,
        min_prefixlen=min_prefixlen,
    )
    return manager, shell


async def _expect_refusal(
    manager: WarpSplitManager, shell: GuardShell, candidate: list[str], match: str
) -> None:
    """Apply *candidate*, assert it is refused and that nothing at all happened."""
    before = shell.list_path.read_text(encoding="utf-8")
    with pytest.raises(WarpSplitError, match=match):
        await manager.apply_list(candidate)
    assert shell.applies == [], "the helper must not be invoked for a refused list"
    assert shell.list_path.read_text(encoding="utf-8") == before


# ── the endpoint guard (routing loop) ─────────────────────────────────────────


class TestEndpointGuard:
    async def test_exact_endpoint_host_route_is_refused(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path)
        await _expect_refusal(
            manager, shell, [*BASELINE, f"{ENDPOINT}/32"], "routing loop"
        )

    @pytest.mark.parametrize("supernet", ["162.159.192.0/18", "162.159.0.0/16", "162.0.0.0/8"])
    async def test_any_supernet_covering_the_endpoint_is_refused(
        self, tmp_path: Path, supernet: str
    ) -> None:
        """Refused even though the /32 pin currently out-specifies it.

        Longest-prefix match makes this survivable *today*; it stops being
        survivable the instant Cloudflare hands out a different endpoint.
        """
        manager, shell = _manager(tmp_path)
        assert ipaddress.ip_address(ENDPOINT) in ipaddress.ip_network(supernet)
        await _expect_refusal(manager, shell, [*BASELINE, supernet], "routing loop")

    async def test_a_neighbour_that_does_not_cover_the_endpoint_is_allowed(
        self, tmp_path: Path
    ) -> None:
        manager, shell = _manager(tmp_path)
        neighbour = "162.159.196.0/22"
        assert ipaddress.ip_address(ENDPOINT) not in ipaddress.ip_network(neighbour)
        await manager.apply_list([*BASELINE, neighbour])
        assert neighbour in shell.applies[-1]

    async def test_guard_survives_a_status_probe_that_stops_working(
        self, tmp_path: Path
    ) -> None:
        """The endpoint is remembered, because a down tunnel is when this matters most.

        An operator editing the split list while WARP is broken is the likeliest
        way to install the loop; dropping the guard exactly then would be
        backwards.
        """
        manager, shell = _manager(tmp_path)
        await manager.refresh_endpoint()
        shell.status_rc = 1
        shell.status_stdout = ""
        await _expect_refusal(manager, shell, [*BASELINE, f"{ENDPOINT}/32"], "routing loop")

    async def test_endpoint_never_seen_is_reported_as_unknown(self, tmp_path: Path) -> None:
        """No endpoint, no endpoint guard — but the manager says so rather than pretending."""
        manager, shell = _manager(tmp_path)
        shell.status_stdout = "interface: out-warp\n  fwmark: 0xca6c\n"
        await manager.refresh_endpoint()
        guards = manager.build_guards()
        assert guards.endpoint_known is False
        assert not any("routing loop" in reason for _, reason in guards.networks)

    async def test_endpoint_is_in_the_guard_set_once_seen(self, tmp_path: Path) -> None:
        manager, _shell = _manager(tmp_path)
        await manager.refresh_endpoint()
        guards = manager.build_guards()
        assert guards.endpoint_known is True
        assert (ipaddress.IPv4Network(f"{ENDPOINT}/32")) in [net for net, _ in guards.networks]


# ── prefix-length floor ───────────────────────────────────────────────────────


class TestMinPrefixlen:
    @pytest.mark.parametrize("prefix", ["4.0.0.0/7", "0.0.0.0/1", "64.0.0.0/2"])
    async def test_shorter_than_the_floor_is_refused(self, tmp_path: Path, prefix: str) -> None:
        manager, shell = _manager(tmp_path)
        await _expect_refusal(manager, shell, [*BASELINE, prefix], "WARP_SPLIT_MIN_PREFIXLEN")

    async def test_exactly_the_floor_is_allowed(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path)
        await manager.apply_list([*BASELINE, "8.0.0.0/8"])
        assert "8.0.0.0/8" in shell.applies[-1]

    async def test_the_floor_is_configurable(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path, min_prefixlen=16)
        await _expect_refusal(manager, shell, ["8.0.0.0/8"], "WARP_SPLIT_MIN_PREFIXLEN")

    async def test_default_route_gets_its_own_message(self, tmp_path: Path) -> None:
        """0.0.0.0/0 is below the floor too, but "use the module toggle" is the useful answer."""
        manager, shell = _manager(tmp_path)
        await _expect_refusal(manager, shell, [*BASELINE, "0.0.0.0/0"], "default route rejected")


# ── static and host-derived guards ────────────────────────────────────────────


class TestStaticGuards:
    @pytest.mark.parametrize(
        ("prefix", "match"),
        [
            ("127.0.0.0/8", "loopback"),
            ("127.0.0.1/32", "loopback"),
            ("169.254.0.0/16", "link-local"),
            ("169.254.169.254/32", "link-local"),
            # 224.0.0.0/4 itself is refused one check earlier, by the /8 floor —
            # see test_multicast_block_is_refused_by_the_floor_first.
            ("224.0.0.0/8", "multicast"),
            ("239.255.255.250/32", "multicast"),
            ("172.16.0.0/12", "WARP tunnel"),
            ("172.20.5.0/24", "WARP tunnel"),
            ("10.0.0.0/24", "AWG client subnet"),
            ("10.0.0.7/32", "AWG client subnet"),
        ],
    )
    async def test_reserved_ranges_are_refused(
        self, tmp_path: Path, prefix: str, match: str
    ) -> None:
        manager, shell = _manager(tmp_path)
        await _expect_refusal(manager, shell, [*BASELINE, prefix], match)

    async def test_multicast_block_is_refused_by_the_floor_first(self, tmp_path: Path) -> None:
        """Two guards catch 224.0.0.0/4; the earlier one wins, and that is fine.

        Pinned so the ordering is a decision rather than an accident: whichever
        message appears, the operation is refused, which is the only property the
        rest of the subsystem depends on.
        """
        manager, shell = _manager(tmp_path)
        await _expect_refusal(
            manager, shell, [*BASELINE, "224.0.0.0/4"], "WARP_SPLIT_MIN_PREFIXLEN"
        )


class TestHostGuards:
    async def test_the_wan_subnet_is_refused(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path)
        await _expect_refusal(manager, shell, [*BASELINE, str(WAN_NETWORK)], "would break SSH")

    async def test_the_default_gateway_host_route_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A separate guard from the WAN subnet: the gateway can sit outside it.

        Point-to-point uplinks (Hetzner, Scaleway) hand out a /32 address with an
        off-subnet gateway, so the WAN guard alone would not cover it.
        """
        monkeypatch.setattr(
            split_module, "_default_gateway", lambda: ipaddress.IPv4Address("203.0.113.1")
        )
        manager, shell = _manager(tmp_path)
        await _expect_refusal(
            manager, shell, [*BASELINE, "203.0.113.1/32"], "would break the host's uplink"
        )

    async def test_a_supernet_covering_the_gateway_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            split_module, "_default_gateway", lambda: ipaddress.IPv4Address("203.0.113.1")
        )
        manager, shell = _manager(tmp_path)
        await _expect_refusal(
            manager, shell, [*BASELINE, "203.0.113.0/24"], "would break the host's uplink"
        )


# ── malformed input ───────────────────────────────────────────────────────────


class TestMalformedEntries:
    async def test_ipv6_is_refused(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path)
        await _expect_refusal(manager, shell, [*BASELINE, "2a0a:f280::/32"], "only IPv4")

    async def test_unparseable_entry_is_refused(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path)
        await _expect_refusal(manager, shell, [*BASELINE, "not-a-cidr"], "invalid CIDR")

    async def test_an_empty_list_is_refused(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path)
        await _expect_refusal(manager, shell, [], "empty list")


# ── the cap ───────────────────────────────────────────────────────────────────


class TestCap:
    async def test_over_the_cap_refuses_the_whole_list(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path, max_prefixes=5)
        candidate = [f"8.8.{n}.0/24" for n in range(6)]
        before = shell.list_path.read_text(encoding="utf-8")

        with pytest.raises(WarpSplitCapExceeded) as excinfo:
            await manager.apply_list(candidate)

        # The numbers travel with the exception so the caller can explain *why* the
        # list grew — "too many prefixes" is useless when a subtraction shattered it.
        assert excinfo.value.count == 6
        assert excinfo.value.limit == 5
        assert shell.applies == []
        assert shell.list_path.read_text(encoding="utf-8") == before

    async def test_exactly_at_the_cap_is_allowed(self, tmp_path: Path) -> None:
        manager, shell = _manager(tmp_path, max_prefixes=5)
        candidate = [f"8.8.{n}.0/24" for n in range(5)]
        await manager.apply_list(candidate)
        assert shell.applies[-1].splitlines() == candidate


# ── the no-partial-apply rule ─────────────────────────────────────────────────


async def test_one_bad_entry_sinks_the_whole_list(tmp_path: Path) -> None:
    """Not "apply the 3 good ones" — the operation fails and disk is untouched.

    This is the property the rest of the subsystem leans on: the feed refresh can
    build a candidate list without pre-filtering it, because a single dangerous
    entry cannot survive into a partially applied file.
    """
    manager, shell = _manager(tmp_path)
    candidate = ["8.8.8.0/24", "91.108.4.0/22", f"{ENDPOINT}/32", "149.154.160.0/20"]
    before = shell.list_path.read_text(encoding="utf-8")

    with pytest.raises(WarpSplitError):
        await manager.apply_list(candidate)

    assert shell.applies == []
    assert shell.list_path.read_text(encoding="utf-8") == before
    # And specifically: the three harmless prefixes did not sneak through.
    assert "149.154.160.0/20" not in before
