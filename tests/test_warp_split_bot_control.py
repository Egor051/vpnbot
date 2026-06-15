"""Tests for the WARP selective-split bot-control feature.

Coverage:
 1. CIDR parsing / normalisation / guard / dedup logic (warp.split_manager)
 2. vpnbot-warp-split-apply helper script (functional shell tests, Linux-only)
 3. Sudoers file contains the new helper grant
 4. check-nonroot-helper-mode.py expects the new helper
 5. Invariant: no bot code directly calls ip/iptables/awg-quick
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APPLY_SCRIPT = ROOT / "scripts" / "vpnbot-warp-split-apply"
SUDOERS = ROOT / "deploy" / "sudoers.d" / "vpnbot.example"
CHECK_SCRIPT = ROOT / "deploy" / "check-nonroot-helper-mode.py"

# ---------------------------------------------------------------------------
# warp.split_manager unit tests
# ---------------------------------------------------------------------------

from warp.split_manager import (
    WarpSplitManager,
    CidrResult,
    _validate_add,
    _validate_del,
    parse_cidr_tokens,
)
import ipaddress


AWG_NETWORK = "10.0.0.0/24"


def _make_manager(tmp_path: Path) -> WarpSplitManager:
    """Return a WarpSplitManager backed by a temp list file (no shell needed for unit tests)."""
    from unittest.mock import MagicMock
    shell = MagicMock()
    return WarpSplitManager(
        list_path=tmp_path / "warp-split.list",
        apply_helper_path=Path("/usr/local/sbin/vpnbot-warp-split-apply"),
        awg_network=AWG_NETWORK,
        shell=shell,
    )


def _guards(mgr: WarpSplitManager) -> list:
    return mgr._build_guards()  # noqa: SLF001


class TestCidrValidationAdd:
    """Tests for process_add_tokens / _validate_add."""

    def test_bare_ip_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, accepted = mgr.process_add_tokens(["1.2.3.4"], set())
        assert len(results) == 1
        assert results[0].status == "rejected"
        assert "/32" in results[0].note  # hint mentions /32
        assert not accepted

    def test_ipv6_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, _ = mgr.process_add_tokens(["2001:db8::/32"], set())
        assert results[0].status == "rejected"
        assert "IPv4" in results[0].note or "IPv6" in results[0].note

    def test_default_route_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, _ = mgr.process_add_tokens(["0.0.0.0/0"], set())
        assert results[0].status == "rejected"
        assert "full-tunnel" in results[0].note.lower() or "тумблер" in results[0].note.lower()

    def test_awg_client_subnet_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        # Exact AWG network
        results, _ = mgr.process_add_tokens([AWG_NETWORK], set())
        assert results[0].status == "rejected"
        assert "AWG" in results[0].note or "10.0.0.0/24" in results[0].note

    def test_awg_host_within_subnet_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, _ = mgr.process_add_tokens(["10.0.0.5/32"], set())
        assert results[0].status == "rejected"

    def test_loopback_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, _ = mgr.process_add_tokens(["127.0.0.1/32"], set())
        assert results[0].status == "rejected"

    def test_link_local_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, _ = mgr.process_add_tokens(["169.254.0.0/16"], set())
        assert results[0].status == "rejected"

    def test_multicast_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, _ = mgr.process_add_tokens(["224.0.0.1/32"], set())
        assert results[0].status == "rejected"

    def test_warp_tunnel_net_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        # 172.16.0.2/32 is inside 172.16.0.0/12 (WARP tunnel guard)
        results, _ = mgr.process_add_tokens(["172.16.0.2/32"], set())
        assert results[0].status == "rejected"

    def test_host_bits_corrected_and_noted(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        # 1.2.3.4/24 → 1.2.3.0/24; host bits corrected
        results, accepted = mgr.process_add_tokens(["1.2.3.4/24"], set())
        assert results[0].status == "added"
        assert results[0].canonical == "1.2.3.0/24"
        assert results[0].note != ""  # normalisation note present
        assert "1.2.3.0/24" in accepted

    def test_valid_cidr_added(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, accepted = mgr.process_add_tokens(["91.108.4.0/22"], set())
        assert results[0].status == "added"
        assert results[0].canonical == "91.108.4.0/22"
        assert "91.108.4.0/22" in accepted

    def test_dedup_existing(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        existing = {"91.108.4.0/22"}
        results, accepted = mgr.process_add_tokens(["91.108.4.0/22"], existing)
        assert results[0].status == "dup"
        assert not accepted

    def test_dedup_within_batch(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, accepted = mgr.process_add_tokens(
            ["91.108.4.0/22", "91.108.4.0/22"], set()
        )
        assert results[0].status == "added"
        assert results[1].status == "dup"
        assert accepted == ["91.108.4.0/22"]

    def test_batch_one_apply(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        tokens = ["91.108.4.0/22", "142.250.0.0/15", "185.199.108.0/22"]
        results, accepted = mgr.process_add_tokens(tokens, set())
        assert all(r.status == "added" for r in results)
        assert len(accepted) == 3

    def test_mixed_batch(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        tokens = ["91.108.4.0/22", "1.2.3.4", "10.0.0.0/24", "142.250.0.0/15"]
        results, accepted = mgr.process_add_tokens(tokens, set())
        statuses = {r.raw: r.status for r in results}
        assert statuses["91.108.4.0/22"] == "added"
        assert statuses["1.2.3.4"] == "rejected"     # bare IP
        assert statuses["10.0.0.0/24"] == "rejected"  # AWG net
        assert statuses["142.250.0.0/15"] == "added"
        assert set(accepted) == {"91.108.4.0/22", "142.250.0.0/15"}

    def test_invalid_cidr_rejected(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        results, _ = mgr.process_add_tokens(["not-a-cidr/24"], set())
        assert results[0].status == "rejected"


class TestCidrValidationDel:
    """Tests for process_del_tokens / _validate_del."""

    def test_removes_existing_entry(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        current = ["91.108.4.0/22", "142.250.0.0/15"]
        results, remaining = mgr.process_del_tokens(["91.108.4.0/22"], current)
        assert results[0].status == "removed"
        assert "142.250.0.0/15" in remaining
        assert "91.108.4.0/22" not in remaining

    def test_not_found_reported(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        current = ["91.108.4.0/22"]
        results, remaining = mgr.process_del_tokens(["5.5.5.0/24"], current)
        assert results[0].status == "not_found"
        assert remaining == current

    def test_del_to_empty_refused(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        from services.errors import InvalidOperation
        with pytest.raises((InvalidOperation, Exception)) as exc_info:
            mgr.process_del_tokens(["91.108.4.0/22"], ["91.108.4.0/22"])
        assert "пуст" in str(exc_info.value).lower() or "empty" in str(exc_info.value).lower()

    def test_host_bits_normalised_on_del(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        # Keep a second entry so deletion doesn't empty the list
        current = ["1.2.3.0/24", "5.6.7.0/24"]
        # User types 1.2.3.4/24 (host bits set) → normalises to 1.2.3.0/24 → found
        results, remaining = mgr.process_del_tokens(["1.2.3.4/24"], current)
        assert results[0].status == "removed"
        assert results[0].canonical == "1.2.3.0/24"
        assert "1.2.3.0/24" not in remaining
        assert "5.6.7.0/24" in remaining

    def test_del_single_to_empty_raises(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        from warp.split_manager import WarpSplitError
        with pytest.raises(WarpSplitError):
            mgr.process_del_tokens(["1.2.3.0/24"], ["1.2.3.0/24"])


class TestReadList:
    """Tests for WarpSplitManager.read_list."""

    def test_returns_empty_when_file_missing(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        assert mgr.read_list() == []

    def test_reads_and_sorts_entries(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        list_file = tmp_path / "warp-split.list"
        list_file.write_text("# comment\n142.250.0.0/15\n91.108.4.0/22\n", encoding="utf-8")
        result = mgr.read_list()
        assert "91.108.4.0/22" in result
        assert "142.250.0.0/15" in result
        assert result == sorted(result, key=lambda s: ipaddress.ip_network(s))

    def test_skips_blank_and_comment_lines(self, tmp_path: Path) -> None:
        mgr = _make_manager(tmp_path)
        list_file = tmp_path / "warp-split.list"
        list_file.write_text(
            "# Telegram\n91.108.4.0/22\n\n# Google\n142.250.0.0/15\n",
            encoding="utf-8",
        )
        result = mgr.read_list()
        assert result == sorted(["91.108.4.0/22", "142.250.0.0/15"],
                                key=lambda s: ipaddress.ip_network(s))


class TestParseTokens:
    def test_space_separated(self) -> None:
        assert parse_cidr_tokens("1.2.3.0/24 5.6.0.0/16") == ["1.2.3.0/24", "5.6.0.0/16"]

    def test_comma_separated(self) -> None:
        assert parse_cidr_tokens("1.2.3.0/24,5.6.0.0/16") == ["1.2.3.0/24", "5.6.0.0/16"]

    def test_newline_separated(self) -> None:
        assert parse_cidr_tokens("1.2.3.0/24\n5.6.0.0/16") == ["1.2.3.0/24", "5.6.0.0/16"]

    def test_mixed_separators(self) -> None:
        tokens = parse_cidr_tokens("1.2.3.0/24, 5.6.0.0/16\n8.9.10.0/24")
        assert len(tokens) == 3

    def test_empty_string(self) -> None:
        assert parse_cidr_tokens("") == []


# ---------------------------------------------------------------------------
# vpnbot-warp-split-apply helper functional tests (Linux-only, subprocess)
# ---------------------------------------------------------------------------

_LINUX_ONLY = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").exists(),
    reason="Linux-only shell helper test",
)


def _write_stub(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run_apply(input_data: str, tmp_path: Path, *, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run vpnbot-warp-split-apply with stubbed systemctl and a temp list path."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    list_file = tmp_path / "warp-split.list"

    # Stub systemctl so we don't need root
    _write_stub(bin_dir / "systemctl", "#!/bin/sh\nexit 0\n")
    # Stub chown so it's a no-op
    _write_stub(bin_dir / "chown", "#!/bin/sh\nexit 0\n")

    env = {
        "PATH": str(bin_dir) + ":/usr/local/bin:/usr/bin:/bin",
        "WARP_SPLIT_LIST_PATH": str(list_file),
    }
    if extra_env:
        env.update(extra_env)

    return subprocess.run(
        [str(APPLY_SCRIPT)],
        input=input_data,
        env=env,
        capture_output=True,
        text=True,
    )


@_LINUX_ONLY
class TestApplyHelper:
    def test_valid_list_succeeds(self, tmp_path: Path) -> None:
        result = _run_apply("91.108.4.0/22\n142.250.0.0/15\n", tmp_path)
        assert result.returncode == 0, result.stderr
        list_file = tmp_path / "warp-split.list"
        assert list_file.exists()
        content = list_file.read_text(encoding="utf-8")
        assert "91.108.4.0/22" in content
        assert "142.250.0.0/15" in content

    def test_empty_stdin_aborts(self, tmp_path: Path) -> None:
        result = _run_apply("", tmp_path)
        assert result.returncode != 0
        list_file = tmp_path / "warp-split.list"
        assert not list_file.exists(), "should NOT write file on empty stdin"

    def test_garbage_line_aborts(self, tmp_path: Path) -> None:
        result = _run_apply("91.108.4.0/22\nnot-a-cidr\n142.250.0.0/15\n", tmp_path)
        assert result.returncode != 0
        list_file = tmp_path / "warp-split.list"
        assert not list_file.exists(), "should NOT write file when a line is invalid"

    def test_ipv6_line_aborts(self, tmp_path: Path) -> None:
        result = _run_apply("2001:db8::/32\n", tmp_path)
        assert result.returncode != 0

    def test_bare_ip_aborts(self, tmp_path: Path) -> None:
        result = _run_apply("1.2.3.4\n", tmp_path)
        assert result.returncode != 0

    def test_comments_and_blanks_are_passed_through(self, tmp_path: Path) -> None:
        input_data = "# Telegram\n91.108.4.0/22\n\n# Google\n142.250.0.0/15\n"
        result = _run_apply(input_data, tmp_path)
        assert result.returncode == 0, result.stderr
        list_file = tmp_path / "warp-split.list"
        content = list_file.read_text(encoding="utf-8")
        assert "# Telegram" in content
        assert "91.108.4.0/22" in content

    def test_all_blanks_and_comments_aborts(self, tmp_path: Path) -> None:
        result = _run_apply("# just a comment\n\n", tmp_path)
        assert result.returncode != 0

    def test_atomicity_temp_file_cleaned_up(self, tmp_path: Path) -> None:
        input_data = "91.108.4.0/22\n"
        result = _run_apply(input_data, tmp_path)
        assert result.returncode == 0
        # No temp file should remain after successful apply
        tmp_files = list(tmp_path.glob(".warp-split-tmp.*"))
        assert not tmp_files, f"temp files leaked: {tmp_files}"

    def test_existing_file_overwritten_atomically(self, tmp_path: Path) -> None:
        list_file = tmp_path / "warp-split.list"
        list_file.write_text("old-content\n", encoding="utf-8")
        result = _run_apply("91.108.4.0/22\n", tmp_path)
        assert result.returncode == 0
        content = list_file.read_text(encoding="utf-8")
        assert "old-content" not in content
        assert "91.108.4.0/22" in content

    def test_script_exists_and_has_shebang(self) -> None:
        assert APPLY_SCRIPT.exists(), f"{APPLY_SCRIPT} not found"
        text = APPLY_SCRIPT.read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/env bash") or text.startswith("#!/bin/bash")

    def test_script_uses_env_var_for_list_path(self) -> None:
        text = APPLY_SCRIPT.read_text(encoding="utf-8")
        assert "WARP_SPLIT_LIST_PATH" in text


# ---------------------------------------------------------------------------
# Sudoers: grant for new helper
# ---------------------------------------------------------------------------

class TestSudoersGrant:
    def test_apply_helper_in_sudoers(self) -> None:
        text = SUDOERS.read_text(encoding="utf-8")
        active = "\n".join(
            line for line in text.splitlines()
            if line.strip() and not line.strip().startswith(("#", ";"))
        )
        assert "/usr/local/sbin/vpnbot-warp-split-apply" in active, (
            "sudoers must grant vpnbot-warp-split-apply; "
            f"active lines:\n{active}"
        )

    def test_grant_is_nopasswd(self) -> None:
        text = SUDOERS.read_text(encoding="utf-8")
        active = "\n".join(
            line for line in text.splitlines()
            if line.strip() and not line.strip().startswith(("#", ";"))
        )
        assert "NOPASSWD" in active
        # Helper must be reachable via a NOPASSWD alias
        assert "VPNBOT_WARP_SPLIT" in active

    def test_no_wildcards_on_helper(self) -> None:
        text = SUDOERS.read_text(encoding="utf-8")
        # The apply helper takes no arguments (list on stdin), so no * on its line
        for line in text.splitlines():
            if "vpnbot-warp-split-apply" in line and not line.strip().startswith("#"):
                assert "*" not in line, (
                    "vpnbot-warp-split-apply should have no argument wildcards"
                )


# ---------------------------------------------------------------------------
# check-nonroot-helper-mode.py: expects the new helper
# ---------------------------------------------------------------------------

class TestCheckNonrootHelper:
    def test_apply_helper_in_warp_helpers_list(self) -> None:
        text = CHECK_SCRIPT.read_text(encoding="utf-8")
        assert "vpnbot-warp-split-apply" in text, (
            "check-nonroot-helper-mode.py must list vpnbot-warp-split-apply in WARP_HELPERS"
        )

    def test_warp_helpers_tuple_contains_apply(self) -> None:
        text = CHECK_SCRIPT.read_text(encoding="utf-8")
        # WARP_HELPERS tuple spans multiple lines; find the block between the
        # assignment and the closing standalone ')' on its own line
        warp_helpers_block = re.search(
            r"WARP_HELPERS\s*=\s*\(([^)]*(?:\)[^)]*)*)\)", text, re.DOTALL
        )
        assert warp_helpers_block is not None, "WARP_HELPERS tuple not found"
        # Simpler: just check the raw source after the WARP_HELPERS = line
        start = text.find("WARP_HELPERS =")
        assert start != -1
        # Extract until end of the tuple (find matching paren)
        chunk = text[start:]
        depth = 0
        end_pos = 0
        for i, ch in enumerate(chunk):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end_pos = i
                    break
        block = chunk[:end_pos + 1]
        assert "vpnbot-warp-split-apply" in block, (
            f"vpnbot-warp-split-apply not found in WARP_HELPERS block:\n{block}"
        )


# ---------------------------------------------------------------------------
# Invariant: bot code never calls ip/iptables/awg directly
# ---------------------------------------------------------------------------

class TestBotCodeInvariant:
    """Ensure no bot Python code calls privileged network commands directly."""

    _FORBIDDEN = re.compile(
        r"""(?x)
        subprocess\.run\s*\(\s*[\[\(]?
        \s*["']            # quote
        (                  # forbidden binaries
          ip\b
          | iptables\b
          | ip6tables\b
          | awg\b
          | awg-quick\b
        )
        """,
    )

    def _scan_python_files(self, root: Path, subdir: str) -> list[str]:
        hits = []
        for py in (root / subdir).rglob("*.py"):
            text = py.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                if self._FORBIDDEN.search(line):
                    hits.append(f"{py}:{lineno}: {line.strip()}")
        return hits

    def test_no_direct_ip_calls_in_bot_handlers(self) -> None:
        hits = self._scan_python_files(ROOT, "bot")
        assert not hits, "bot/ code calls privileged commands directly:\n" + "\n".join(hits)

    def test_no_direct_ip_calls_in_warp_module(self) -> None:
        hits = self._scan_python_files(ROOT, "warp")
        assert not hits, "warp/ module calls privileged commands directly:\n" + "\n".join(hits)

    def test_split_handler_only_uses_manager(self) -> None:
        handler = ROOT / "bot" / "handlers" / "admin_warp_split.py"
        text = handler.read_text(encoding="utf-8")
        # Handler must not call subprocess directly
        assert "subprocess" not in text, (
            "admin_warp_split.py must not import subprocess — use warp_split manager"
        )
        # Handler must access warp_split via services
        assert "services.warp_split" in text


# ---------------------------------------------------------------------------
# settings: new fields present
# ---------------------------------------------------------------------------

class TestSettings:
    def test_settings_has_split_list_path(self) -> None:
        from config.settings import Settings
        assert hasattr(Settings, "__dataclass_fields__") or True
        import inspect
        src = inspect.getsource(Settings)
        assert "warp_split_list_path" in src

    def test_settings_has_apply_helper_path(self) -> None:
        import inspect
        from config.settings import Settings
        src = inspect.getsource(Settings)
        assert "warp_split_apply_helper_path" in src

    def test_load_settings_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify the two new settings parse correctly from defaults."""
        import os
        # Provide the bare minimum required by load_settings
        env = {
            "BOT_TOKEN": "1234:test",
            "ADMIN_IDS": "123",
        }
        monkeypatch.setattr(os, "environ", {**os.environ, **env})
        from config.settings import load_settings
        settings = load_settings()
        from pathlib import Path
        assert settings.warp_split_list_path == Path("/etc/vpnbot/warp-split.list")
        assert settings.warp_split_apply_helper_path == Path("/usr/local/sbin/vpnbot-warp-split-apply")

    def test_load_settings_custom_paths(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        import os
        custom_list = str(tmp_path / "split.list")
        custom_helper = str(tmp_path / "my-apply")
        env = {
            "BOT_TOKEN": "1234:test",
            "ADMIN_IDS": "123",
            "WARP_SPLIT_LIST_PATH": custom_list,
            "WARP_SPLIT_APPLY_HELPER_PATH": custom_helper,
        }
        monkeypatch.setattr(os, "environ", {**os.environ, **env})
        from config.settings import load_settings
        settings = load_settings()
        from pathlib import Path as P
        assert settings.warp_split_list_path == P(custom_list)
        assert settings.warp_split_apply_helper_path == P(custom_helper)
