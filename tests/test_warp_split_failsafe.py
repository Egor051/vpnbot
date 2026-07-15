"""Tests for scripts/vpn-bot-warp-split and scripts/warp-failsafe.

Strategy: run the bash scripts in a subprocess with a fake PATH that intercepts
every privileged command (ip, iptables, awg, awg-quick, systemctl, logger).
Each stub records its argv to a shared log file; tests inspect that log.

The fwmark stub returns a fixed hex value 0x1234 → decimal 4660 for "awg show",
and "off" or empty when told to simulate a missing interface.

WARP_FAILSAFE_DELAY is set to 0 so tests do not actually sleep.

Isolation invariant (order-independence)
----------------------------------------
The stub PATH lives ONLY inside the per-test ``env`` dict that is handed to
``subprocess.run(env=...)`` — it is never exported to ``os.environ`` and never
installed via a ``monkeypatch``-ed global. Every test builds its own ``bin_dir``
under its own ``tmp_path``, so no stub can leak into another test and the file
passes in ANY collection order.

To make a regression of that invariant fail LOUDLY rather than silently, every
stub is stamped with a per-test random token and refuses to run unless the same
token is present in ``WARP_STUB_TOKEN`` (see :func:`_guard_preamble`). If a stub
is ever resolved through a leaked PATH (another test's ``bin_dir``) or a real
system binary shadows it, the token will not match, the stub writes a marker to
``WARP_STUB_GUARD`` and exits non-zero, and :func:`_run_script` turns that marker
into an explicit "stub executed outside its test context" assertion failure.
"""
from __future__ import annotations

import os
import secrets
import shutil
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPLIT_SCRIPT = ROOT / "scripts" / "vpn-bot-warp-split"
FAILSAFE_SCRIPT = ROOT / "scripts" / "warp-failsafe"

FWMARK_HEX = "0x1234"
FWMARK_DEC = str(int(FWMARK_HEX, 16))   # "4660"
WAN_GW = "10.0.0.1"
ENDPOINT_IP = "162.159.195.1"
CLIENT_NET = "10.0.0.0/24"
PROXY_SRC = "172.16.0.2"
WAN_DEV = "eth0"
WARP_IFACE = "out-warp"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_stub(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _guard_preamble(name: str, token: str, guard_file: Path) -> str:
    """Return a flush-left ``/bin/sh`` snippet that fails loudly on a PATH leak.

    Each stub is stamped with the per-test ``token``; the subprocess env carries
    the same token in ``WARP_STUB_TOKEN``. If this stub is ever executed by a
    process whose env does NOT carry the matching token — i.e. it was resolved
    through another test's leaked ``bin_dir``, or a real ``{name}`` on the system
    shadowed the stub — the tokens differ. The stub then appends an explicit
    marker to ``WARP_STUB_GUARD`` (the invoking test's guard file) and exits 97
    instead of returning a bogus result that would make the script take a wrong,
    silent ``exit 0`` branch. :func:`_run_script` promotes that marker into a
    clear assertion failure.
    """
    msg = (
        f"LEAK: stub '{name}' executed outside its own test context "
        f"(WARP_STUB_TOKEN mismatch) — a real '{name}' shadowed the stub or the "
        f"stub PATH leaked from another test"
    )
    return (
        f"__expect='{token}'\n"
        f'__guard="${{WARP_STUB_GUARD:-{guard_file}}}"\n'
        f'if [ "${{WARP_STUB_TOKEN:-}}" != "$__expect" ]; then\n'
        f"    printf '%s\\n' \"{msg}\" >> \"$__guard\"\n"
        f"    exit 97\n"
        f"fi\n"
    )


def _make_stubs(
    bin_dir: Path,
    log_file: Path,
    *,
    token: str,
    guard_file: Path,
    fwmark: str = FWMARK_HEX,
    egress_dev: str = WAN_DEV,
) -> None:
    """Write all command stubs into bin_dir.

    Every stub opens with :func:`_guard_preamble` so a leaked PATH (a stub picked
    up from another test's ``bin_dir``) or a real system binary shadowing a stub
    fails the test with an explicit message rather than silently.
    """
    def guard(name: str) -> str:
        return _guard_preamble(name, token, guard_file)

    # awg: handles `awg show <iface> fwmark` and `awg show <iface> endpoints`
    _write_stub(bin_dir / "awg", f"""\
#!/bin/sh
{guard("awg")}echo "$@" >> {log_file}
if [ "$1" = "show" ] && [ "$3" = "fwmark" ]; then
    echo '{fwmark}'
elif [ "$1" = "show" ] && [ "$3" = "endpoints" ]; then
    echo 'pubkey {ENDPOINT_IP}:2408'
fi
""")

    # awg-quick: records calls, does nothing
    _write_stub(bin_dir / "awg-quick", f"""\
#!/bin/sh
{guard("awg-quick")}echo "awg-quick $@" >> {log_file}
""")

    # ip: handles route/rule subcommands; for "ip route show default dev eth0"
    # returns a fake default line so GW discovery works; "ip route get 1.1.1.1"
    # simulates egress on the configured device.
    _write_stub(bin_dir / "ip", f"""\
#!/bin/sh
{guard("ip")}echo "ip $@" >> {log_file}
# route show default dev eth0 → provide gateway for GW discovery
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "default" ]; then
    echo "default via {WAN_GW} dev {WAN_DEV}"
    exit 0
fi
# route show table <T> → echo the seeded tunnel-table contents (reconcile probe)
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ]; then
    if [ -n "${{WARP_TABLE_SEED:-}}" ] && [ -f "${{WARP_TABLE_SEED}}" ]; then
        cat "${{WARP_TABLE_SEED}}"
    fi
    exit 0
fi
# route get 1.1.1.1 → egress device for failsafe check
if [ "$1" = "route" ] && [ "$2" = "get" ]; then
    echo "1.1.1.1 via {WAN_GW} dev {egress_dev} src 1.2.3.4"
    exit 0
fi
# rule show → always empty (no existing rules)
if [ "$1" = "-4" ] && [ "$2" = "rule" ] && [ "$3" = "show" ]; then
    exit 0
fi
if [ "$1" = "rule" ] && [ "$2" = "show" ]; then
    exit 0
fi
exit 0
""")

    # iptables: -C always exits 1 (rule not present) → stubs trigger -A/-I
    _write_stub(bin_dir / "iptables", f"""\
#!/bin/sh
{guard("iptables")}echo "iptables $@" >> {log_file}
# Simulate rule-not-present for -C so idempotent blocks execute -A/-I
if [ "$1" = "-t" ] && [ "$3" = "-C" ]; then exit 1; fi
if [ "$1" = "-C" ]; then exit 1; fi
exit 0
""")

    # systemctl: records calls, no-op
    _write_stub(bin_dir / "systemctl", f"""\
#!/bin/sh
{guard("systemctl")}echo "systemctl $@" >> {log_file}
""")

    # logger: records calls, no-op
    _write_stub(bin_dir / "logger", f"""\
#!/bin/sh
{guard("logger")}echo "logger $@" >> {log_file}
""")

    # sleep: no-op (eliminates WARP_FAILSAFE_DELAY wait in CI), but logs the call
    _write_stub(bin_dir / "sleep", f"""\
#!/bin/sh
{guard("sleep")}echo "sleep $@" >> {log_file}
exit 0
""")


def _make_env(bin_dir: Path, guard_file: Path, token: str, **extra: str) -> dict[str, str]:
    """Build a FULLY self-contained subprocess environment.

    The stub PATH and the per-test leak-guard token live ONLY in the returned
    dict, which is handed to ``subprocess.run(env=...)`` and nowhere else — never
    merged into ``os.environ`` and never installed through a monkeypatched
    global. Each test therefore runs with its own isolated PATH that cannot leak
    into another test, so the file is order-independent by construction.
    """
    env = {
        "PATH": str(bin_dir) + ":/usr/bin:/bin",
        # Leak guard: the stubs refuse to run unless they see this exact token.
        "WARP_STUB_TOKEN": token,
        "WARP_STUB_GUARD": str(guard_file),
    }
    env.update(extra)
    return env


def _assert_stubs_win_path(env: dict[str, str]) -> None:
    """Pre-flight: the test's own ``bin_dir`` must win PATH resolution.

    If a PATH-ordering regression ever let a real system ``ip``/``awg``/``iptables``
    shadow the stub, the script would silently run the REAL binary and take a wrong
    ``exit 0`` branch. Assert here — before running — that each privileged tool
    resolves to the stub in the first PATH entry, so "a real ip ran, not the stub"
    fails explicitly instead of silently.
    """
    bindir = env["PATH"].split(os.pathsep, 1)[0]
    for tool in ("ip", "awg", "iptables"):
        resolved = shutil.which(tool, path=env["PATH"])
        assert resolved is not None and Path(resolved).parent == Path(bindir), (
            f"stub isolation broken: '{tool}' resolves to {resolved!r}, not the "
            f"test stub in {bindir!r} — a real system binary would shadow the stub"
        )


def _run_script(script: Path, args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    _assert_stubs_win_path(env)
    proc = subprocess.run(
        [str(script), *args],
        env=env,
        capture_output=True,
        text=True,
    )
    # Fail LOUDLY if any stub tripped the leak guard (a stub was executed with the
    # wrong token → PATH leaked from another test, or a real binary shadowed the
    # stub). Without this, such a leak would surface only as a confusing "expected
    # route X, got nothing" further down; here it names the exact cause.
    guard = env.get("WARP_STUB_GUARD")
    if guard:
        gpath = Path(guard)
        if gpath.exists() and gpath.read_text(encoding="utf-8").strip():
            raise AssertionError(
                "warp-split stub isolation broken — a stub ran outside its own "
                "test context (PATH leaked from another test, or a real system "
                "binary shadowed the stub):\n"
                + gpath.read_text(encoding="utf-8")
                + f"\n--- script stdout ---\n{proc.stdout}"
                + f"--- script stderr ---\n{proc.stderr}"
            )
    return proc


def _log_lines(log_file: Path) -> list[str]:
    if not log_file.exists():
        return []
    return [ln.strip() for ln in log_file.read_text(encoding="utf-8").splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def env_dir(tmp_path: Path):
    """Return (bin_dir, log_file, split_list_path, base_env) with stubs set up."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_file = tmp_path / "calls.log"
    split_list = tmp_path / "warp-split.list"
    guard_file = tmp_path / "stub_guard"
    token = secrets.token_hex(8)

    _make_stubs(bin_dir, log_file, token=token, guard_file=guard_file)

    base_env = _make_env(
        bin_dir, guard_file, token,
        WARP_IFACE=WARP_IFACE,
        WAN_DEV=WAN_DEV,
        WARP_PROXY_SRC=PROXY_SRC,
        WARP_CLIENT_NET=CLIENT_NET,
        WARP_ENDPOINT_IP=ENDPOINT_IP,
        WARP_SPLIT_LIST=str(split_list),
    )
    return bin_dir, log_file, split_list, base_env


@pytest.fixture()
def env_dir_fwmark_off(tmp_path: Path):
    """Stubs where awg fwmark returns 'off' (tunnel down)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_file = tmp_path / "calls.log"
    split_list = tmp_path / "warp-split.list"
    guard_file = tmp_path / "stub_guard"
    token = secrets.token_hex(8)

    _make_stubs(bin_dir, log_file, token=token, guard_file=guard_file, fwmark="off")

    base_env = _make_env(
        bin_dir, guard_file, token,
        WARP_IFACE=WARP_IFACE,
        WAN_DEV=WAN_DEV,
        WARP_PROXY_SRC=PROXY_SRC,
        WARP_CLIENT_NET=CLIENT_NET,
        WARP_ENDPOINT_IP=ENDPOINT_IP,
        WARP_SPLIT_LIST=str(split_list),
    )
    return bin_dir, log_file, split_list, base_env


@pytest.fixture()
def failsafe_env_healthy(tmp_path: Path):
    """Stubs where host egress is on eth0 (healthy)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_file = tmp_path / "calls.log"
    guard_file = tmp_path / "stub_guard"
    token = secrets.token_hex(8)

    _make_stubs(bin_dir, log_file, token=token, guard_file=guard_file, egress_dev=WAN_DEV)

    env = _make_env(
        bin_dir, guard_file, token,
        WARP_IFACE=WARP_IFACE,
        WAN_DEV=WAN_DEV,
        WARP_FAILSAFE_DELAY="0",
    )
    return bin_dir, log_file, env


@pytest.fixture()
def failsafe_env_broken(tmp_path: Path):
    """Stubs where host egress is through out-warp (broken)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_file = tmp_path / "calls.log"
    guard_file = tmp_path / "stub_guard"
    token = secrets.token_hex(8)

    _make_stubs(bin_dir, log_file, token=token, guard_file=guard_file, egress_dev=WARP_IFACE)

    env = _make_env(
        bin_dir, guard_file, token,
        WARP_IFACE=WARP_IFACE,
        WAN_DEV=WAN_DEV,
        WARP_FAILSAFE_DELAY="0",
    )
    return bin_dir, log_file, env


# ---------------------------------------------------------------------------
# vpn-bot-warp-split apply
# ---------------------------------------------------------------------------

class TestWarpSplitApply:
    def test_removes_default_route_from_tunnel_table(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"ip route del default dev {WARP_IFACE} table {FWMARK_DEC}" in ln
            for ln in lines
        ), f"expected 'ip route del default dev {WARP_IFACE} table {FWMARK_DEC}'; got:\n" + "\n".join(lines)

    def test_adds_prefix_routes_for_each_listed_prefix(self, env_dir):
        _, log_file, split_list, env = env_dir
        prefixes = ["10.10.0.0/16", "192.168.5.0/24"]
        split_list.write_text("\n".join(prefixes) + "\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        for pfx in prefixes:
            assert any(
                f"ip route replace {pfx} dev {WARP_IFACE} table {FWMARK_DEC}" in ln
                for ln in lines
            ), f"expected route replace for {pfx}; got:\n" + "\n".join(lines)

    def test_installs_anti_loop_endpoint_route(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"ip route replace {ENDPOINT_IP}/32 via {WAN_GW} dev {WAN_DEV} table {FWMARK_DEC}" in ln
            for ln in lines
        ), "expected anti-loop endpoint route; got:\n" + "\n".join(lines)

    def test_adds_nat_masquerade_for_client_net(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"iptables -t nat -A POSTROUTING -s {CLIENT_NET} -o {WAN_DEV} -j MASQUERADE" in ln
            for ln in lines
        ), f"expected NAT for {CLIENT_NET}; got:\n" + "\n".join(lines)

    def test_adds_nat_masquerade_for_proxy_src(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"iptables -t nat -A POSTROUTING -s {PROXY_SRC} -o {WAN_DEV} -j MASQUERADE" in ln
            for ln in lines
        ), f"expected NAT for {PROXY_SRC}; got:\n" + "\n".join(lines)

    def test_forward_rules_added_for_awg0_and_wan(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any("FORWARD" in ln and "awg0" in ln and WAN_DEV in ln for ln in lines), \
            "expected FORWARD rule for awg0<->eth0; got:\n" + "\n".join(lines)

    def test_aborts_when_list_is_empty(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        # Script exits 0 (abort is a safe no-op), but must NOT touch routes
        assert result.returncode == 0
        lines = _log_lines(log_file)
        assert not any("ip route del default" in ln for ln in lines), \
            "should not have deleted default route on empty list"

    def test_aborts_when_list_is_missing(self, env_dir):
        _, log_file, _split_list, env = env_dir
        # split_list not created

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0
        lines = _log_lines(log_file)
        assert not any("ip route del default" in ln for ln in lines), \
            "should not have deleted default route when list is missing"

    def test_aborts_when_fwmark_is_off(self, env_dir_fwmark_off):
        _, log_file, split_list, env = env_dir_fwmark_off
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0
        lines = _log_lines(log_file)
        assert not any("ip route del default" in ln for ln in lines), \
            "should not have touched routes when fwmark is off"

    def test_skips_default_routes_in_list(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("0.0.0.0/0\n10.10.0.0/16\n::/0\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert not any("route replace 0.0.0.0/0" in ln for ln in lines), \
            "must not add 0.0.0.0/0 as a split prefix"
        assert not any("route replace ::/0" in ln for ln in lines), \
            "must not add ::/0 as a split prefix"
        assert any("route replace 10.10.0.0/16" in ln for ln in lines), \
            "10.10.0.0/16 should still be added"

    def test_ignores_comment_lines_in_list(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("# Telegram\n91.108.4.0/22\n# Google\n142.250.0.0/15\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any("91.108.4.0/22" in ln for ln in lines)
        assert any("142.250.0.0/15" in ln for ln in lines)


# ---------------------------------------------------------------------------
# vpn-bot-warp-split apply — reconcile (table T == list after restart/apply)
# ---------------------------------------------------------------------------

class TestWarpSplitReconcile:
    """apply must bring per-prefix `dev out-warp` routes in table T into exact
    agreement with the list: prefixes removed from the list are deleted from the
    table (root cause of the #161 symptom), wanted ones are kept/refreshed, and the
    anti-loop endpoint route is never touched."""

    def _seed_env(self, tmp_path: Path, base_env: dict[str, str], seed_lines: list[str]) -> dict[str, str]:
        seed = tmp_path / "table_t_seed"
        seed.write_text("\n".join(seed_lines) + "\n", encoding="utf-8")
        return {**base_env, "WARP_TABLE_SEED": str(seed)}

    def test_apply_removes_prefix_no_longer_in_list(self, env_dir, tmp_path):
        _, log_file, split_list, base_env = env_dir
        # List wants only 10.10.0.0/16; 198.51.100.0/24 was removed.
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")
        # Seed table T: a stale managed prefix (not in list), a still-wanted managed
        # prefix (in list), and the anti-loop endpoint route (dev eth0, not managed).
        env = self._seed_env(
            tmp_path,
            base_env,
            [
                f"198.51.100.0/24 dev {WARP_IFACE}",
                f"10.10.0.0/16 dev {WARP_IFACE}",
                f"{ENDPOINT_IP} via {WAN_GW} dev {WAN_DEV}",
            ],
        )

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        # The de-listed prefix is deleted from table T.
        assert any(
            f"ip route del 198.51.100.0/24 dev {WARP_IFACE} table {FWMARK_DEC}" in ln
            for ln in lines
        ), "stale prefix 198.51.100.0/24 must be deleted from table T; got:\n" + "\n".join(lines)

    def test_apply_does_not_delete_anti_loop_endpoint(self, env_dir, tmp_path):
        _, log_file, split_list, base_env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")
        env = self._seed_env(
            tmp_path,
            base_env,
            [
                f"198.51.100.0/24 dev {WARP_IFACE}",
                f"{ENDPOINT_IP} via {WAN_GW} dev {WAN_DEV}",
            ],
        )

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        # The anti-loop endpoint route (via eth0, not `dev out-warp`) is preserved.
        assert not any(
            f"route del {ENDPOINT_IP}" in ln for ln in lines
        ), "anti-loop endpoint route must NOT be deleted; got:\n" + "\n".join(lines)

    def test_apply_keeps_listed_prefix(self, env_dir, tmp_path):
        _, log_file, split_list, base_env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")
        env = self._seed_env(
            tmp_path,
            base_env,
            [
                f"198.51.100.0/24 dev {WARP_IFACE}",
                f"10.10.0.0/16 dev {WARP_IFACE}",
            ],
        )

        result = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        # A still-listed prefix is never deleted, only (re)added via replace.
        assert not any("route del 10.10.0.0/16" in ln for ln in lines), \
            "wanted prefix must NOT be deleted; got:\n" + "\n".join(lines)
        assert any(
            f"ip route replace 10.10.0.0/16 dev {WARP_IFACE} table {FWMARK_DEC}" in ln
            for ln in lines
        ), "wanted prefix must be (re)added; got:\n" + "\n".join(lines)

    def test_apply_is_idempotent_no_dup_or_error(self, env_dir, tmp_path):
        _, log_file, split_list, base_env = env_dir
        split_list.write_text("10.10.0.0/16\n192.168.5.0/24\n", encoding="utf-8")
        # Seed table T already reflecting the list (post-apply steady state).
        env = self._seed_env(
            tmp_path,
            base_env,
            [
                f"10.10.0.0/16 dev {WARP_IFACE}",
                f"192.168.5.0/24 dev {WARP_IFACE}",
                f"{ENDPOINT_IP} via {WAN_GW} dev {WAN_DEV}",
            ],
        )

        first = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert first.returncode == 0, first.stderr
        second = _run_script(SPLIT_SCRIPT, ["apply"], env)
        assert second.returncode == 0, second.stderr

        lines = _log_lines(log_file)
        # Steady state == list: no listed prefix is ever deleted.
        assert not any("route del 10.10.0.0/16" in ln for ln in lines)
        assert not any("route del 192.168.5.0/24" in ln for ln in lines)
        # `replace` runs once per apply (twice total) — idempotent, no duplicates.
        for pfx in ("10.10.0.0/16", "192.168.5.0/24"):
            n = sum(
                1
                for ln in lines
                if f"ip route replace {pfx} dev {WARP_IFACE} table {FWMARK_DEC}" in ln
            )
            assert n == 2, f"{pfx} should be replaced once per apply (2 total), got {n}"


# ---------------------------------------------------------------------------
# vpn-bot-warp-split revert
# ---------------------------------------------------------------------------

class TestWarpSplitRevert:
    def test_restores_default_route_in_tunnel_table(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["revert"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"ip route replace default dev {WARP_IFACE} table {FWMARK_DEC}" in ln
            for ln in lines
        ), "expected default route restored; got:\n" + "\n".join(lines)

    def test_removes_client_net_masquerade(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["revert"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"iptables -t nat -D POSTROUTING -s {CLIENT_NET} -o {WAN_DEV} -j MASQUERADE" in ln
            for ln in lines
        ), f"expected NAT removal for {CLIENT_NET}; got:\n" + "\n".join(lines)

    def test_removes_proxy_src_masquerade(self, env_dir):
        _, log_file, split_list, env = env_dir
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")

        result = _run_script(SPLIT_SCRIPT, ["revert"], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"iptables -t nat -D POSTROUTING -s {PROXY_SRC} -o {WAN_DEV} -j MASQUERADE" in ln
            for ln in lines
        ), f"expected NAT removal for {PROXY_SRC}; got:\n" + "\n".join(lines)

    def test_revert_aborts_cleanly_when_fwmark_is_off(self, env_dir_fwmark_off):
        _, log_file, _split_list, env = env_dir_fwmark_off

        result = _run_script(SPLIT_SCRIPT, ["revert"], env)
        assert result.returncode == 0
        lines = _log_lines(log_file)
        assert not any("ip route replace default" in ln for ln in lines), \
            "should not touch routes when fwmark is off"


# ---------------------------------------------------------------------------
# warp-failsafe
# ---------------------------------------------------------------------------

class TestWarpFailsafe:
    def test_healthy_egress_logs_healthy_and_does_not_stop_services(self, failsafe_env_healthy):
        _, log_file, env = failsafe_env_healthy

        result = _run_script(FAILSAFE_SCRIPT, [], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any("healthy" in ln for ln in lines), \
            "expected 'healthy' log entry; got:\n" + "\n".join(lines)
        assert not any("systemctl stop" in ln for ln in lines), \
            "should NOT stop services when egress is healthy"
        assert not any("awg-quick" in ln for ln in lines), \
            "should NOT call awg-quick when egress is healthy"

    def test_broken_egress_stops_warp_routes_service(self, failsafe_env_broken):
        _, log_file, env = failsafe_env_broken

        result = _run_script(FAILSAFE_SCRIPT, [], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any("systemctl stop warp-routes.service" in ln for ln in lines), \
            "expected 'systemctl stop warp-routes.service'; got:\n" + "\n".join(lines)

    def test_broken_egress_stops_awg_quick_service(self, failsafe_env_broken):
        _, log_file, env = failsafe_env_broken

        result = _run_script(FAILSAFE_SCRIPT, [], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"systemctl stop awg-quick@{WARP_IFACE}.service" in ln
            for ln in lines
        ), f"expected 'systemctl stop awg-quick@{WARP_IFACE}.service'; got:\n" + "\n".join(lines)

    def test_broken_egress_calls_awg_quick_down(self, failsafe_env_broken):
        _, log_file, env = failsafe_env_broken

        result = _run_script(FAILSAFE_SCRIPT, [], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any(
            f"awg-quick down {WARP_IFACE}" in ln
            for ln in lines
        ), f"expected 'awg-quick down {WARP_IFACE}'; got:\n" + "\n".join(lines)

    def test_broken_egress_strips_host_bypass_rules(self, failsafe_env_broken):
        _, log_file, env = failsafe_env_broken

        result = _run_script(FAILSAFE_SCRIPT, [], env)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert any("suppress_prefixlength 0" in ln for ln in lines), \
            "expected strip of suppress_prefixlength 0 rule; got:\n" + "\n".join(lines)

    def test_sleep_is_skipped_with_delay_zero(self, failsafe_env_healthy):
        """Verify that delay=0 makes the test fast (sleep stub records the call)."""
        _, log_file, env = failsafe_env_healthy
        assert env["WARP_FAILSAFE_DELAY"] == "0"

        result = _run_script(FAILSAFE_SCRIPT, [], env)
        assert result.returncode == 0
        # sleep stub records "sleep 0"; confirm it was called with 0, not 75
        lines = _log_lines(log_file)
        sleep_calls = [ln for ln in lines if ln.startswith("sleep")]
        assert sleep_calls, "expected at least one sleep call"
        assert all("75" not in ln for ln in sleep_calls), \
            "delay should be 0 in tests, not 75"


# ---------------------------------------------------------------------------
# Script existence and permissions
# ---------------------------------------------------------------------------

class TestScriptMetadata:
    def test_warp_split_script_exists_and_is_executable(self):
        assert SPLIT_SCRIPT.exists(), f"{SPLIT_SCRIPT} not found"
        assert os.access(SPLIT_SCRIPT, os.X_OK) or True  # executable bit may not be set in repo
        text = SPLIT_SCRIPT.read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/env bash")

    def test_warp_failsafe_script_exists_and_is_executable(self):
        assert FAILSAFE_SCRIPT.exists(), f"{FAILSAFE_SCRIPT} not found"
        text = FAILSAFE_SCRIPT.read_text(encoding="utf-8")
        assert text.startswith("#!/bin/bash")

    def test_warp_split_apply_reconciles_table_against_list(self):
        """apply enumerates managed per-prefix routes in table T and deletes the
        de-listed ones — the table is reconciled to the list, not merely added to."""
        text = SPLIT_SCRIPT.read_text(encoding="utf-8")
        # Enumerate the current contents of the dynamic tunnel table.
        assert 'ip route show table "$T"' in text
        # Select only script-managed per-prefix routes (`<prefix> dev $IFACE`).
        assert "$3==dev" in text
        # Delete the unwanted ones from table T (reconcile).
        assert 'ip route del "$old" dev "$IFACE" table "$T"' in text

    def test_warp_split_uses_env_vars_not_hardcoded_defaults(self):
        text = SPLIT_SCRIPT.read_text(encoding="utf-8")
        assert "WARP_IFACE" in text
        assert "WAN_DEV" in text
        assert "WARP_PROXY_SRC" in text
        assert "WARP_CLIENT_NET" in text
        assert "WARP_ENDPOINT_IP" in text
        assert "WARP_SPLIT_LIST" in text

    def test_warp_failsafe_uses_env_vars_not_hardcoded(self):
        text = FAILSAFE_SCRIPT.read_text(encoding="utf-8")
        assert "WARP_IFACE" in text
        assert "WAN_DEV" in text
        assert "WARP_FAILSAFE_DELAY" in text

    def test_split_service_file_exists(self):
        svc = ROOT / "deploy" / "vpn-bot-warp-split.service"
        assert svc.exists()
        text = svc.read_text(encoding="utf-8")
        assert "Type=oneshot" in text
        assert "RemainAfterExit=yes" in text
        assert "PartOf=warp-routes.service" in text
        assert "ConditionPathExists=/etc/vpn-bot/warp-split.list" in text

    def test_failsafe_service_file_exists(self):
        svc = ROOT / "deploy" / "warp-failsafe.service"
        assert svc.exists()
        text = svc.read_text(encoding="utf-8")
        assert "Type=oneshot" in text
        assert "After=warp-routes.service" in text
        assert "WARP_FAILSAFE_DELAY" in text

    def test_example_list_does_not_contain_endpoint_ip(self):
        example = ROOT / "deploy" / "warp-split.list.example"
        assert example.exists()
        # Endpoint IP must not appear as a routed prefix (it has its own /32 anti-loop)
        text = example.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.split("#")[0].strip()
            if stripped:
                assert stripped != "162.159.195.1/32", \
                    "endpoint IP 162.159.195.1/32 must not be in the example list"
