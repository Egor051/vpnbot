"""Tests for the WARP split-routing on/off/restart/status layer.

Two surfaces are covered, both with a fake PATH that intercepts every privileged
command (no real ip/awg/systemctl, no root):

  1. scripts/vpnbot-warp-split-state — the on/off/restart/status helper. It manages
     the root-owned disabled marker and delegates table-T mutation to
     vpnbot-warp-split (here stubbed so we can assert the orchestration).
  2. scripts/vpnbot-warp-split apply — the marker honour added for boot/state:
     when the marker is present, table T is reconciled to EMPTY (all-direct),
     touching ONLY the per-prefix `dev out-warp` routes; the anti-loop endpoint
     route is preserved and the saved list file is never erased.
"""
from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATE_SCRIPT = ROOT / "scripts" / "vpnbot-warp-split-state"
SPLIT_SCRIPT = ROOT / "scripts" / "vpnbot-warp-split"

FWMARK_HEX = "0x1234"
FWMARK_DEC = str(int(FWMARK_HEX, 16))  # "4660"
WAN_GW = "10.0.0.1"
ENDPOINT_IP = "162.159.195.1"
WAN_DEV = "eth0"
WARP_IFACE = "out-warp"

_LINUX_ONLY = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").exists(),
    reason="Linux-only shell helper test",
)


def _write_stub(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _log_lines(log_file: Path) -> list[str]:
    if not log_file.exists():
        return []
    return [ln.strip() for ln in log_file.read_text(encoding="utf-8").splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# vpnbot-warp-split-state — orchestration (split helper stubbed)
# ---------------------------------------------------------------------------


def _state_env(tmp_path: Path, *, fwmark: str = FWMARK_HEX, seed: list[str] | None = None) -> dict[str, str]:
    """Stub vpnbot-warp-split + awg/ip/chown; return env for the state helper."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log_file = tmp_path / "calls.log"
    marker = tmp_path / "warp-split.disabled"
    split_helper = tmp_path / "fake-warp-split"

    # Fake vpnbot-warp-split: just records every invocation.
    _write_stub(split_helper, f"""\
    #!/bin/sh
    echo "split-helper $@" >> {log_file}
    """)

    # chown stub (no root in CI) — marker write must not abort under set -e.
    _write_stub(bin_dir / "chown", "#!/bin/sh\nexit 0\n")

    # awg: `awg show out-warp fwmark`
    _write_stub(bin_dir / "awg", f"""\
    #!/bin/sh
    echo "awg $@" >> {log_file}
    if [ "$1" = "show" ] && [ "$3" = "fwmark" ]; then echo '{fwmark}'; fi
    """)

    # ip: `ip route show table <T>` → echo the seed (per-prefix routes)
    seed_file = tmp_path / "table_seed"
    seed_file.write_text("\n".join(seed or []) + "\n", encoding="utf-8")
    _write_stub(bin_dir / "ip", f"""\
    #!/bin/sh
    echo "ip $@" >> {log_file}
    if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ]; then
        cat "{seed_file}"
        exit 0
    fi
    exit 0
    """)

    return {
        "PATH": str(bin_dir) + ":/usr/bin:/bin",
        "WARP_SPLIT_DISABLED_MARKER": str(marker),
        "WARP_SPLIT_HELPER": str(split_helper),
        "WARP_IFACE": WARP_IFACE,
        "_LOG": str(log_file),
        "_MARKER": str(marker),
    }


def _run_state(verb: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    run_env = {k: v for k, v in env.items() if not k.startswith("_")}
    return subprocess.run([str(STATE_SCRIPT), verb], env=run_env, capture_output=True, text=True)


@_LINUX_ONLY
class TestSplitStateHelper:
    def test_off_writes_marker_and_applies(self, tmp_path: Path) -> None:
        env = _state_env(tmp_path)
        result = _run_state("off", env)
        assert result.returncode == 0, result.stderr
        assert Path(env["_MARKER"]).exists(), "off must write the disabled marker"
        lines = _log_lines(Path(env["_LOG"]))
        assert any("split-helper apply" in ln for ln in lines), \
            "off must reconcile via vpnbot-warp-split apply; got:\n" + "\n".join(lines)

    def test_on_removes_marker_and_applies(self, tmp_path: Path) -> None:
        env = _state_env(tmp_path)
        Path(env["_MARKER"]).write_text("disabled\n", encoding="utf-8")  # start disabled
        result = _run_state("on", env)
        assert result.returncode == 0, result.stderr
        assert not Path(env["_MARKER"]).exists(), "on must clear the disabled marker"
        lines = _log_lines(Path(env["_LOG"]))
        assert any("split-helper apply" in ln for ln in lines)

    def test_restart_is_off_then_on(self, tmp_path: Path) -> None:
        env = _state_env(tmp_path)
        result = _run_state("restart", env)
        assert result.returncode == 0, result.stderr
        # Final state is ON → marker absent.
        assert not Path(env["_MARKER"]).exists(), "restart must end in the ON state"
        lines = _log_lines(Path(env["_LOG"]))
        applies = [ln for ln in lines if "split-helper apply" in ln]
        assert len(applies) == 2, f"restart must apply twice (flush + re-apply); got {applies}"

    def test_status_reports_tunnel_and_table_and_marker(self, tmp_path: Path) -> None:
        env = _state_env(
            tmp_path,
            seed=[
                f"10.10.0.0/16 dev {WARP_IFACE}",
                f"192.168.5.0/24 dev {WARP_IFACE}",
                f"{ENDPOINT_IP} via {WAN_GW} dev {WAN_DEV}",  # anti-loop, not counted
            ],
        )
        result = _run_state("status", env)
        assert result.returncode == 0, result.stderr
        out = result.stdout
        assert "tunnel_up=1" in out
        assert "n_table=2" in out, f"only the 2 dev {WARP_IFACE} routes count; got:\n{out}"
        assert "marker=on" in out

    def test_status_marker_off_when_disabled(self, tmp_path: Path) -> None:
        env = _state_env(tmp_path)
        Path(env["_MARKER"]).write_text("disabled\n", encoding="utf-8")
        result = _run_state("status", env)
        assert "marker=off" in result.stdout

    def test_status_tunnel_down_when_fwmark_off(self, tmp_path: Path) -> None:
        env = _state_env(tmp_path, fwmark="off")
        result = _run_state("status", env)
        assert "tunnel_up=0" in result.stdout
        assert "n_table=0" in result.stdout

    def test_unknown_verb_errors(self, tmp_path: Path) -> None:
        env = _state_env(tmp_path)
        result = _run_state("bogus", env)
        assert result.returncode == 2

    def test_state_script_has_shebang_and_pins_verbs(self) -> None:
        text = STATE_SCRIPT.read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/env bash")
        for verb in ("on)", "off)", "restart)", "status)"):
            assert verb in text


# ---------------------------------------------------------------------------
# vpnbot-warp-split apply — marker honour (boot/state → table T empty)
# ---------------------------------------------------------------------------


def _make_split_stubs(bin_dir: Path, log_file: Path, *, fwmark: str = FWMARK_HEX) -> None:
    _write_stub(bin_dir / "awg", f"""\
    #!/bin/sh
    echo "awg $@" >> {log_file}
    if [ "$1" = "show" ] && [ "$3" = "fwmark" ]; then echo '{fwmark}'; fi
    """)
    _write_stub(bin_dir / "ip", f"""\
    #!/bin/sh
    echo "ip $@" >> {log_file}
    if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "default" ]; then
        echo "default via {WAN_GW} dev {WAN_DEV}"
        exit 0
    fi
    if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "table" ]; then
        if [ -n "${{WARP_TABLE_SEED:-}}" ] && [ -f "${{WARP_TABLE_SEED}}" ]; then
            cat "${{WARP_TABLE_SEED}}"
        fi
        exit 0
    fi
    exit 0
    """)
    _write_stub(bin_dir / "iptables", f"""\
    #!/bin/sh
    echo "iptables $@" >> {log_file}
    if [ "$1" = "-t" ] && [ "$3" = "-C" ]; then exit 1; fi
    if [ "$1" = "-C" ]; then exit 1; fi
    exit 0
    """)
    _write_stub(bin_dir / "systemctl", f"#!/bin/sh\necho \"systemctl $@\" >> {log_file}\n")
    _write_stub(bin_dir / "logger", f"#!/bin/sh\necho \"logger $@\" >> {log_file}\n")


@_LINUX_ONLY
class TestSplitApplyMarkerHonour:
    def _env(self, tmp_path: Path) -> tuple[Path, Path, Path, dict[str, str]]:
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(exist_ok=True)
        log_file = tmp_path / "calls.log"
        split_list = tmp_path / "warp-split.list"
        marker = tmp_path / "warp-split.disabled"
        _make_split_stubs(bin_dir, log_file)
        env = {
            "PATH": str(bin_dir) + ":/usr/bin:/bin",
            "WARP_IFACE": WARP_IFACE,
            "WAN_DEV": WAN_DEV,
            "WARP_ENDPOINT_IP": ENDPOINT_IP,
            "WARP_SPLIT_LIST": str(split_list),
            "WARP_SPLIT_DISABLED_MARKER": str(marker),
        }
        return log_file, split_list, marker, env

    def _seed(self, tmp_path: Path, env: dict[str, str], lines: list[str]) -> None:
        seed = tmp_path / "table_seed"
        seed.write_text("\n".join(lines) + "\n", encoding="utf-8")
        env["WARP_TABLE_SEED"] = str(seed)

    def test_marker_present_flushes_per_prefix_routes(self, tmp_path: Path) -> None:
        log_file, split_list, marker, env = self._env(tmp_path)
        split_list.write_text("10.10.0.0/16\n192.168.5.0/24\n", encoding="utf-8")
        marker.write_text("disabled\n", encoding="utf-8")
        self._seed(
            tmp_path,
            env,
            [
                f"10.10.0.0/16 dev {WARP_IFACE}",
                f"192.168.5.0/24 dev {WARP_IFACE}",
                f"{ENDPOINT_IP} via {WAN_GW} dev {WAN_DEV}",
            ],
        )

        result = subprocess.run([str(SPLIT_SCRIPT), "apply"], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        for pfx in ("10.10.0.0/16", "192.168.5.0/24"):
            assert any(
                f"ip route del {pfx} dev {WARP_IFACE} table {FWMARK_DEC}" in ln for ln in lines
            ), f"disabled marker must flush {pfx}; got:\n" + "\n".join(lines)

    def test_marker_present_preserves_anti_loop(self, tmp_path: Path) -> None:
        log_file, split_list, marker, env = self._env(tmp_path)
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")
        marker.write_text("disabled\n", encoding="utf-8")
        self._seed(
            tmp_path,
            env,
            [
                f"10.10.0.0/16 dev {WARP_IFACE}",
                f"{ENDPOINT_IP} via {WAN_GW} dev {WAN_DEV}",
            ],
        )

        result = subprocess.run([str(SPLIT_SCRIPT), "apply"], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

        lines = _log_lines(log_file)
        assert not any(f"route del {ENDPOINT_IP}" in ln for ln in lines), \
            "anti-loop endpoint route must NOT be deleted; got:\n" + "\n".join(lines)
        # Disabled → no per-prefix route is (re)added.
        assert not any("route replace 10.10.0.0/16" in ln for ln in lines), \
            "disabled marker must not re-add prefixes; got:\n" + "\n".join(lines)

    def test_marker_present_does_not_erase_list(self, tmp_path: Path) -> None:
        _log_file, split_list, marker, env = self._env(tmp_path)
        split_list.write_text("10.10.0.0/16\n192.168.5.0/24\n", encoding="utf-8")
        marker.write_text("disabled\n", encoding="utf-8")
        self._seed(tmp_path, env, [f"10.10.0.0/16 dev {WARP_IFACE}"])

        result = subprocess.run([str(SPLIT_SCRIPT), "apply"], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        # The saved list survives an off — it is re-applied on the next "on".
        content = split_list.read_text(encoding="utf-8")
        assert "10.10.0.0/16" in content
        assert "192.168.5.0/24" in content

    def test_marker_absent_applies_list_as_before(self, tmp_path: Path) -> None:
        log_file, split_list, _marker, env = self._env(tmp_path)
        split_list.write_text("10.10.0.0/16\n", encoding="utf-8")
        # no marker written
        self._seed(tmp_path, env, [f"{ENDPOINT_IP} via {WAN_GW} dev {WAN_DEV}"])

        result = subprocess.run([str(SPLIT_SCRIPT), "apply"], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        lines = _log_lines(log_file)
        assert any(
            f"ip route replace 10.10.0.0/16 dev {WARP_IFACE} table {FWMARK_DEC}" in ln
            for ln in lines
        ), "without the marker, apply must reconcile to the list; got:\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Deploy wiring: sudoers grant + check-nonroot + setup install the state helper
# ---------------------------------------------------------------------------


class TestStateHelperDeployWiring:
    def test_sudoers_grants_state_verbs_without_wildcard(self) -> None:
        text = (ROOT / "deploy" / "sudoers.d" / "vpnbot.example").read_text(encoding="utf-8")
        active = "\n".join(
            ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith(("#", ";"))
        )
        for verb in ("on", "off", "restart", "status"):
            assert f"/usr/local/sbin/vpnbot-warp-split-state {verb}" in active, \
                f"sudoers must pin the '{verb}' verb"
        for ln in text.splitlines():
            if "vpnbot-warp-split-state" in ln and not ln.strip().startswith("#"):
                assert "*" not in ln, "split-state verbs must not use argument wildcards"

    def test_check_nonroot_lists_state_helper(self) -> None:
        text = (ROOT / "deploy" / "check-nonroot-helper-mode.py").read_text(encoding="utf-8")
        assert "vpnbot-warp-split-state" in text

    def test_setup_installs_state_helper(self) -> None:
        text = (ROOT / "deploy" / "setup-nonroot-helper-mode.sh").read_text(encoding="utf-8")
        assert "/usr/local/sbin/vpnbot-warp-split-state" in text
        assert "vpnbot-warp-split-state" in text
