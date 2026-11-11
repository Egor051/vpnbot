"""scripts/deploy.sh host roles: NODE_ROLE=main (default) | relay.

Driven through the DEPLOY_SELFTEST=1 seam with stubbed systemctl / nft / sysctl /
git / install, like the rest of the deploy suites. Pinned here:

1. **One .env parser for the role.** `env_sed_val` in deploy.sh, the copy in
   scripts/vpn-relay-apply and the HYSTERIA2_PORT pipeline of
   scripts/vpnbot-hy2-warp-mark are the same sed program and give the same answers
   (quotes, spaces, `export`, inline comments, last-wins).
2. **resolve_node_role** — absent/empty/main -> main, relay -> relay, anything else
   refused before any mutation.
3. **role_guard** in both directions.
4. **The main role is unchanged**: the role is consulted at one dispatch point only,
   before the first mutation; the role-aware shared functions produce the same
   output with NODE_ROLE absent and NODE_ROLE=main, and never show a relay piece.
5. **The relay role touches no main unit and no DB**, installs its helper through
   OUT_OF_REPO_HELPERS (role-filtered) and its unit verbatim, and **rolls back** —
   files, saved table, enable/active state, ip_forward and the conntrack sysctls
   (nf_conntrack_max, nf_conntrack_tcp_timeout_established) snapshotted in
   relay_snapshot_prestate — when the restart or the final `vpn-relay-apply check`
   fails.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SH = ROOT / "scripts" / "deploy.sh"
RELAY_HELPER_SRC = ROOT / "scripts" / "vpn-relay-apply"
HY2_MARK = ROOT / "scripts" / "vpnbot-hy2-warp-mark"
REPO_UNIT = ROOT / "deploy" / "relay" / "vpn-relay.service"
FIXTURES = ROOT / "tests" / "fixtures" / "relay"
MANUAL_UNIT = FIXTURES / "vpn-relay.manual.service"
CAPTURED_RULESET = FIXTURES / "vpn-relay.nft"
LIVE_LISTING = FIXTURES / "nft-list-live.txt"

pytestmark = pytest.mark.timeout(60)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
    path.chmod(0o755)


def _source_and_run(
    tmp_path: Path, body: str, *, env_text: str | None = "", extra_path: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Source deploy.sh through the selftest seam, then run `body`."""
    env_file = tmp_path / "dot.env"
    if env_text is not None:
        env_file.write_text(env_text, encoding="utf-8")
    driver = tmp_path / "driver.sh"
    driver.write_text(
        "set -uo pipefail\n"
        "export DEPLOY_SELFTEST=1\n"
        + (f'export PATH="{extra_path}:$PATH"\n' if extra_path else "")
        + f'source "{DEPLOY_SH}"\n'
        # Neutralise the EXIT trap's venv/worktree logic for the test environment.
        'VENV=/nonexistent; VENV_PREV=/nonexistent; WT=""; STAGE=""\n'
        f'ENV_FILE="{env_file}"\n' + body,
        encoding="utf-8",
    )
    return subprocess.run(
        ["bash", str(driver)], cwd=str(tmp_path), capture_output=True, text=True, check=False
    )


# --------------------------------------------------------------------------- #
# 1. One parser
# --------------------------------------------------------------------------- #
PARSER_MATRIX: list[tuple[str, str]] = [
    ("K=relay\n", "relay"),
    ('K="relay"\n', "relay"),
    ("K='relay'\n", "relay"),
    ("K = relay\n", "relay"),
    ("   K=relay   \n", "relay"),
    ("export K=relay\n", "relay"),
    ("  export   K = 'relay'  # a comment\n", "relay"),
    ("K=relay # inline comment\n", "relay"),
    ("K=relay#tight comment\n", "relay"),
    ('K="relay"   # quoted + comment\n', "relay"),
    ("K=main\nK=relay\n", "relay"),          # last assignment wins
    ("K=relay\nK=\n", ""),                   # ... including an empty one
    ("# K=relay\n", ""),                     # commented out
    ("#K=relay\nK=main\n", "main"),
    ("KX=relay\nXK=relay\n", ""),            # other keys are not K
    ("K=relay\r\n", "relay"),                # CRLF file
    ("", ""),
]


def _deploy_parser(tmp_path: Path, env_text: str, key: str = "K") -> str:
    proc = _source_and_run(tmp_path, f'printf "[%s]" "$(env_sed_val {key})"\n', env_text=env_text)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.removeprefix("[").removesuffix("]")


def _helper_parser(tmp_path: Path, env_text: str, key: str = "K") -> str:
    """The helper's env_sed_val, loaded on its own (the script has a main dispatch)."""
    env_file = tmp_path / "helper.env"
    env_file.write_text(env_text, encoding="utf-8")
    script = (
        "set -euo pipefail\n"
        f"source <(sed -n '/^env_sed_val() {{/,/^}}/p' \"{RELAY_HELPER_SRC}\")\n"
        f'RELAY_ENV="{env_file}"\n'
        f'printf "[%s]" "$(env_sed_val {key})"\n'
    )
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.removeprefix("[").removesuffix("]")


@pytest.mark.parametrize(("env_text", "expected"), PARSER_MATRIX)
def test_deploy_and_helper_parse_env_identically(tmp_path: Path, env_text: str, expected: str) -> None:
    assert _deploy_parser(tmp_path, env_text) == expected
    assert _helper_parser(tmp_path, env_text) == expected


def _sed_program(text: str) -> tuple[str, str]:
    """(selector expression, post-processing chain) of one parser, key spelled KEY."""
    selector = re.search(r"""sed -n (["'])(.+?)\1""", text)
    chain = re.search(r"(\| tail -n1 \| sed -e .*?-e 's/\[\[:space:\]\]\*\$//')", text)
    assert selector and chain, "parser not found"
    expr = selector.group(2).replace("${key}", "KEY").replace("HYSTERIA2_PORT", "KEY")
    return expr, chain.group(1)


def _function(text: str, name: str) -> str:
    body = text[text.index(f"{name}() {{") :]
    return body[: body.index("\n}\n")]


def test_the_three_parsers_are_one_sed_program() -> None:
    """deploy.sh and vpn-relay-apply carry the HYSTERIA2_PORT pipeline verbatim."""
    deploy = _sed_program(_function(_read(DEPLOY_SH), "env_sed_val"))
    helper = _sed_program(_function(_read(RELAY_HELPER_SRC), "env_sed_val"))
    hy2 = _sed_program(_read(HY2_MARK))
    assert deploy == helper == hy2, (deploy, helper, hy2)
    assert "export" in deploy[0] and "#.*$" in deploy[1]


def test_env_val_is_not_switched_over() -> None:
    """The main role keeps reading every key it always read with env_val; the new
    parser is used for NODE_ROLE only."""
    text = _read(DEPLOY_SH)
    calls = re.findall(r"env_sed_val\s+([A-Z_]+)", text)
    assert calls == ["NODE_ROLE"], calls
    assert "env_val() {" in text


# --------------------------------------------------------------------------- #
# 2. resolve_node_role
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("env_text", "role"),
    [
        (None, "main"),  # no .env at all
        ("", "main"),
        ("BOT_TOKEN=x\n", "main"),
        ("NODE_ROLE=\n", "main"),
        ("NODE_ROLE=main\n", "main"),
        ('NODE_ROLE="main"  # default\n', "main"),
        ("# NODE_ROLE=relay\n", "main"),
        ("NODE_ROLE=relay\n", "relay"),
        ("NODE_ROLE='relay'\n", "relay"),
        ("export NODE_ROLE = relay   # this host forwards 443\n", "relay"),
        ("NODE_ROLE=main\nNODE_ROLE=relay\n", "relay"),
    ],
)
def test_resolve_node_role(tmp_path: Path, env_text: str | None, role: str) -> None:
    proc = _source_and_run(tmp_path, 'resolve_node_role; echo "ROLE=$NODE_ROLE"\n', env_text=env_text)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().endswith(f"ROLE={role}")


@pytest.mark.parametrize("value", ["Relay", "RELAY", "relay2", "re lay", "edge", "main,relay", "'relay"])
def test_unknown_role_is_refused(tmp_path: Path, value: str) -> None:
    proc = _source_and_run(
        tmp_path, 'resolve_node_role; echo "SHOULD-NOT-REACH"\n', env_text=f"NODE_ROLE={value}\n"
    )
    assert proc.returncode == 1
    assert "SHOULD-NOT-REACH" not in proc.stdout
    assert "not a known host role" in proc.stderr and "nothing was changed" in proc.stderr


# --------------------------------------------------------------------------- #
# 3. role_guard (both directions)
# --------------------------------------------------------------------------- #
GUARD_SYSTEMCTL = r"""
echo "systemctl $*" >> "$SC_LOG"
unit="${!#}"
case "$1" in
  is-active)
    s="$(cat "$SD/$unit.active" 2>/dev/null || echo inactive)"; echo "$s"
    [[ "$s" == "active" ]]; exit ;;
  show) [[ -f "$SD/$unit.loaded" ]] && echo loaded || echo not-found; exit 0 ;;
esac
exit 0
"""


def _guard(tmp_path: Path, role: str, *, active: tuple[str, ...] = (), loaded: tuple[str, ...] = ()):
    stub, sd = tmp_path / "stub", tmp_path / "sd"
    stub.mkdir()
    sd.mkdir()
    _stub(stub / "systemctl", GUARD_SYSTEMCTL)
    for u in active:
        (sd / f"{u}.active").write_text("active", encoding="utf-8")
    for u in loaded:
        (sd / f"{u}.loaded").write_text("", encoding="utf-8")
    body = (
        f'export SD="{sd}" SC_LOG="{tmp_path / "sc.log"}"\n'
        f'NODE_ROLE="{role}"; role_guard; echo GUARD-PASSED\n'
    )
    proc = _source_and_run(tmp_path, body, extra_path=stub)
    sc = (tmp_path / "sc.log").read_text(encoding="utf-8") if (tmp_path / "sc.log").exists() else ""
    return proc, sc


@pytest.mark.parametrize("unit", ["vpn-bot.service", "xray.service"])
def test_relay_role_refuses_a_bot_server(tmp_path: Path, unit: str) -> None:
    proc, _ = _guard(tmp_path, "relay", active=(unit,), loaded=(unit,))
    assert proc.returncode == 1
    assert "GUARD-PASSED" not in proc.stdout
    assert unit in proc.stderr and "main server" in proc.stderr


def test_relay_role_passes_on_a_relay(tmp_path: Path) -> None:
    proc, sc = _guard(tmp_path, "relay", active=("vpn-relay.service",), loaded=("vpn-relay.service",))
    assert proc.returncode == 0, proc.stderr
    assert "GUARD-PASSED" in proc.stdout
    assert all(ln.split()[1] in {"is-active", "show"} for ln in sc.splitlines()), "the guard only reads"


def test_main_role_refuses_a_relay_without_vpn_bot(tmp_path: Path) -> None:
    proc, _ = _guard(tmp_path, "main", active=("vpn-relay.service",), loaded=("vpn-relay.service",))
    assert proc.returncode == 1
    assert "NODE_ROLE=relay" in proc.stderr and "nothing was changed" in proc.stderr


@pytest.mark.parametrize(
    ("active", "loaded"),
    [
        (("vpn-bot.service", "xray.service"), ("vpn-bot.service",)),  # an ordinary main server
        ((), ("vpn-bot.service",)),                                   # bot stopped
        ((), ()),                                                     # a fresh host
        (("vpn-relay.service",), ("vpn-bot.service", "vpn-relay.service")),  # both: bot exists
    ],
)
def test_main_role_passes_on_a_main_server(tmp_path: Path, active: tuple[str, ...], loaded: tuple[str, ...]) -> None:
    proc, _ = _guard(tmp_path, "main", active=active, loaded=loaded)
    assert proc.returncode == 0, proc.stderr
    assert "GUARD-PASSED" in proc.stdout


# --------------------------------------------------------------------------- #
# 4. The main role is unchanged
# --------------------------------------------------------------------------- #
def _post_seam(text: str) -> str:
    return text[text.index('if [[ "${DEPLOY_SELFTEST:-0}" == "1" ]]') :]


DISPATCH = (
    "resolve_node_role\n"
    "role_guard\n"
    'if [[ "$NODE_ROLE" == "relay" ]]; then\n'
    "  relay_deploy\n"
    "  exit 0\n"
    "fi\n"
)


def test_the_role_is_consulted_once_before_any_mutation() -> None:
    top = _post_seam(_read(DEPLOY_SH))
    assert top.count(DISPATCH) == 1
    at = top.index(DISPATCH)
    assert at < top.index("require_tools git sqlite3"), "before the main tool check"
    assert at < top.index('install -d -m700 "$BACKUP_DIR"'), "before the first mutation"
    assert at < top.index("exec {LOCK_FD}")
    code = [ln for ln in top.splitlines() if not ln.lstrip().startswith("#")]
    role_lines = [ln for ln in code if "NODE_ROLE" in ln]
    assert role_lines == ['if [[ "$NODE_ROLE" == "relay" ]]; then'], role_lines
    assert sorted(set(re.findall(r"\brelay_\w+", "\n".join(code)))) == ["relay_deploy"]


def test_main_unit_globs_never_see_the_relay_unit() -> None:
    """The main drift gate and assemble_unit_set glob deploy/*.service (top level
    only), so deploy/relay/vpn-relay.service never becomes main-host drift."""
    text = _read(DEPLOY_SH)
    assert 'for f in "$WT"/deploy/*.service; do' in text
    assert REPO_UNIT not in set((ROOT / "deploy").glob("*.service"))


def _shared_functions_output(tmp_path: Path, env_text: str | None, run: str) -> str:
    """Scan + install over the REAL registry (destinations redirected to a temp sbin),
    with the role resolved from `env_text` exactly as the deploy does it."""
    stub, sbin = tmp_path / "stub", tmp_path / "sbin"
    stub.mkdir(parents=True)
    sbin.mkdir()
    _stub(stub / "systemctl", f'echo "systemctl $*" >> "{tmp_path / "sc.log"}"\n')
    _stub(stub / "install", INSTALL_STUB)
    body = (
        "resolve_node_role\n"
        f'APP_DIR="{ROOT}"\n'
        'for i in "${!OUT_OF_REPO_HELPERS[@]}"; do\n'
        f'  OUT_OF_REPO_HELPERS[$i]="${{OUT_OF_REPO_HELPERS[$i]//\\/usr\\/local\\/sbin\\//{sbin}/}}"\n'
        "done\n"
        f'WARP_ROUTES_HELPER="{sbin}/vpn-bot-warp-routes"\n'
        'rollback() { echo "ROLLBACK_CALLED"; exit 42; }\n'
        'relay_rollback() { echo "RELAY_ROLLBACK_CALLED"; exit 43; }\n'
        f"{run}\n"
    )
    proc = _source_and_run(tmp_path, body, env_text=env_text, extra_path=stub)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    sc = (tmp_path / "sc.log").read_text(encoding="utf-8") if (tmp_path / "sc.log").exists() else ""
    installed = sorted(p.name for p in sbin.iterdir())
    out = proc.stdout + "\n--SC--\n" + sc + "\n--SBIN--\n" + " ".join(installed)
    return out.replace(str(tmp_path), "<TMP>")


INSTALL_STUB = r"""
dirs=0; args=()
while [[ $# -gt 0 ]]; do case "$1" in
  -o|-g|-m) shift 2 ;;
  -m0*) shift ;;
  -d) dirs=1; shift ;;
  *) args+=("$1"); shift ;;
esac; done
if (( dirs )); then mkdir -p "${args[@]}"; else cp "${args[0]}" "${args[1]}"; fi
"""


@pytest.mark.parametrize("run", ['scan_out_of_repo_helpers "$APP_DIR"', "install_out_of_repo_helpers"])
def test_shared_helper_functions_are_identical_without_and_with_node_role_main(
    tmp_path: Path, run: str
) -> None:
    absent = _shared_functions_output(tmp_path / "a", None, run)
    explicit = _shared_functions_output(tmp_path / "b", 'NODE_ROLE="main"  # explicit\n', run)
    assert absent == explicit
    assert "vpn-relay-apply" not in absent, "a main server never sees the relay helper"
    assert "vpn-bot-db-perms" in absent


def test_rollback_now_picks_the_rollback_of_the_role(tmp_path: Path) -> None:
    """rollback_now stays `rollback` on a main server (the relay one is relay-only)."""
    body = (
        "resolve_node_role\n"
        'rollback() { echo "MAIN-ROLLBACK"; exit 42; }\n'
        'relay_rollback() { echo "RELAY-ROLLBACK"; exit 43; }\n'
        'rollback_now "boom"\n'
    )
    proc = _source_and_run(tmp_path, body, env_text="NODE_ROLE=main\n")
    assert proc.returncode == 42 and "MAIN-ROLLBACK" in proc.stdout
    proc = _source_and_run(tmp_path, body, env_text="NODE_ROLE=relay\n")
    assert proc.returncode == 43 and "RELAY-ROLLBACK" in proc.stdout


def test_scan_on_a_relay_sees_only_the_relay_helpers(tmp_path: Path) -> None:
    """The relay data-plane helper and the host invariants check (both roles run it)."""
    out = _shared_functions_output(tmp_path, "NODE_ROLE=relay\n", 'scan_out_of_repo_helpers "$APP_DIR"')
    rows = [ln for ln in out.split("\n--SC--\n")[0].splitlines() if "|" in ln]
    assert [r.split("|")[0] for r in rows] == ["vpn-relay-apply", "vpn-bot-host-check"]
    assert all(r.endswith("|absent|required") for r in rows)


# --------------------------------------------------------------------------- #
# 5. Relay Phase 1 / Phase 2 / rollback
# --------------------------------------------------------------------------- #
RELAY_SYSTEMCTL = r"""
echo "systemctl $*" >> "$LOGS/systemctl.log"
unit="${!#}"
case "$1" in
  is-active)
    s="$(cat "$SD/$unit.active" 2>/dev/null || echo inactive)"; echo "$s"; [[ "$s" == "active" ]]; exit ;;
  is-enabled)
    [[ -f "$SD/$unit.enabled" ]] || exit 1; echo enabled; exit 0 ;;
  show) [[ -f "$SD/$unit.active" ]] && echo loaded || echo not-found; exit 0 ;;
  restart)
    rc="$(cat "$SD/restart_rc" 2>/dev/null || echo 0)"
    rm -f "$SD/table"
    # ExecStart = vpn-relay-apply apply, which sets the sysctls from .env (here its
    # defaults). A failed restart has set them too: the worst case for the rollback
    # (apply exiting 7 after its first sysctl writes).
    echo 65536 > "$SD/net.netfilter.nf_conntrack_max"
    echo 86400 > "$SD/net.netfilter.nf_conntrack_tcp_timeout_established"
    echo 1 > "$SD/forward"
    if [[ "$rc" == "0" ]]; then echo active > "$SD/$unit.active"; touch "$SD/table"
    else echo failed > "$SD/$unit.active"; fi
    exit "$rc" ;;
  start) echo active > "$SD/$unit.active"; touch "$SD/table"; exit 0 ;;
  stop) echo inactive > "$SD/$unit.active"; rm -f "$SD/table"; exit 0 ;;
  enable) echo enabled > "$SD/$unit.enabled"; exit 0 ;;
  disable) rm -f "$SD/$unit.enabled"; exit 0 ;;
esac
exit 0
"""

RELAY_NFT = r"""
echo "nft $*" >> "$LOGS/nft.log"
case "$*" in
  "list table ip vpnrelay") [[ -f "$SD/table" ]] || exit 1; cat "$LIVE_LISTING" ;;
  "-f -") cat > "$LOGS/nft-restore.nft"; touch "$SD/table" ;;
  "delete table ip vpnrelay") rm -f "$SD/table" ;;
esac
exit 0
"""

RELAY_SYSCTL = r"""
echo "sysctl $*" >> "$LOGS/sysctl.log"
# One file per key under $SD (ip_forward is $SD/forward); no file = no such key, as
# for net.netfilter.* while nf_conntrack is not loaded.
f() { if [[ "$1" == net.ipv4.ip_forward ]]; then echo "$SD/forward"; else echo "$SD/$1"; fi; }
if [[ "$1" == "-n" ]]; then p="$(f "$2")"; [[ -f "$p" ]] || exit 255; cat "$p"; exit 0; fi
for a in "$@"; do
  case "$a" in
    *=*) p="$(f "${a%%=*}")"; [[ -f "$p" ]] || exit 255
         # procps when the write fails at close(2): an error line, nothing set, exit 0
         if [[ -f "$p.eperm" ]]; then echo "sysctl: setting key \"${a%%=*}\": Operation not permitted" >&2
         else echo "${a#*=}" > "$p"; fi ;;
  esac
done
exit 0
"""

CT_MAX = "net.netfilter.nf_conntrack_max"
CT_EST = "net.netfilter.nf_conntrack_tcp_timeout_established"
# The hand-made relay never set them: kernel defaults, not the .env defaults.
KERNEL_CT = ("262144", "432000")

RELAY_GIT = r"""
echo "git $*" >> "$LOGS/git.log"
[[ "$1 $2" == "rev-parse HEAD" ]] && echo prevsha0000
exit 0
"""

# The installed copy of vpn-relay-apply (copied from the fake checkout's scripts/).
# Stands in for scripts/vpn-bot-host-check: logs its arguments, prints the rows in
# $SD/hc_rows (none by default) and a SUMMARY line counting them.
FAKE_HOST_CHECK = r"""
echo "host-check $*" >> "$LOGS/host-check.log"
rows="$(cat "$SD/hc_rows" 2>/dev/null)"
[[ -n "$rows" ]] && printf '%s\n' "$rows"
b=$(grep -c '^BEATEN|' <<< "$rows"); m=$(grep -c '^MISMATCH|' <<< "$rows"); l=$(grep -c '^LATENT|' <<< "$rows")
echo "SUMMARY|role=relay|mode=x|beaten=$b|mismatch=$m|latent=$l|accepted=0|warn=0|pending=0|info=0|ok=1"
(( b + m == 0 ))
"""

FAKE_HELPER = r"""#!/usr/bin/env bash
echo "helper $*" >> "$LOGS/helper.log"
echo "vpn-relay-apply: fake $*"
exit "$(cat "$SD/check_rc" 2>/dev/null || echo 0)"
"""


class RelayHost:
    """A fake relay host under tmp_path: /etc, /usr/local/sbin, a checkout, stubs."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.stub = tmp_path / "stub"
        self.sd = tmp_path / "state"
        self.logs = tmp_path / "logs"
        self.repo = tmp_path / "repo"
        self.sbin = tmp_path / "sbin"
        self.etc = tmp_path / "etc"
        self.backups = tmp_path / "backups"
        for d in (self.stub, self.sd, self.logs, self.repo / "scripts", self.repo / "deploy" / "relay",
                  self.sbin, self.etc / "systemd" / "system", self.etc / "sysctl.d", self.backups):
            d.mkdir(parents=True, exist_ok=True)
        self.unit = self.etc / "systemd" / "system" / "vpn-relay.service"
        self.helper = self.sbin / "vpn-relay-apply"
        self.sysctl_file = self.etc / "sysctl.d" / "90-vpn-relay.conf"
        self.legacy = self.etc / "vpn-relay.nft"
        (self.repo / "deploy" / "relay" / "vpn-relay.service").write_text(_read(REPO_UNIT), encoding="utf-8")
        (self.repo / "scripts" / "vpn-relay-apply").write_text(FAKE_HELPER, encoding="utf-8")
        (self.repo / "scripts" / "vpn-relay-apply").chmod(0o755)
        (self.repo / "scripts" / "vpn-bot-db-perms").write_text("#!/bin/sh\n", encoding="utf-8")
        _stub(self.stub / "systemctl", RELAY_SYSTEMCTL)
        _stub(self.stub / "nft", RELAY_NFT)
        _stub(self.stub / "sysctl", RELAY_SYSCTL)
        _stub(self.stub / "git", RELAY_GIT)
        _stub(self.stub / "install", INSTALL_STUB)
        _stub(self.stub / "sqlite3", f'echo "sqlite3 $*" >> "{self.logs}/sqlite3.log"\n')
        # deploy.sh Phase 1 runs this suite AS ROOT on the relay itself: nothing here
        # may reach the real nft/sysctl/systemctl, and the helper's upstream probe
        # (python3) must not leave the box. `id` pins the root code paths everywhere.
        _stub(self.stub / "id", '[[ "$1" == "-u" ]] && echo 0\n')
        _stub(self.stub / "python3", f'echo "probe $4 $5 $6" >> "{self.logs}/probe.log"\nexit 0\n')
        # The host invariants check (scripts/vpn-bot-host-check) has its own suite,
        # tests/test_host_check.py; here a fake records how the relay deploy calls it.
        self.host_root = tmp_path / "hostroot"
        self.host_root.mkdir()
        self.checker = self.stub / "fake-host-check"
        _stub(self.checker, FAKE_HOST_CHECK)
        self.set_forward("0")

    # --- host states -------------------------------------------------------
    def hand_installed(self) -> None:
        """The relay as captured on 2026-11-03: manual unit + /etc/vpn-relay.nft."""
        self.unit.write_text(_read(MANUAL_UNIT), encoding="utf-8")
        self.legacy.write_text(_read(CAPTURED_RULESET), encoding="utf-8")
        self.sysctl_file.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
        (self.sd / "vpn-relay.service.active").write_text("active", encoding="utf-8")
        (self.sd / "vpn-relay.service.enabled").write_text("enabled", encoding="utf-8")
        (self.sd / "table").touch()
        self.set_forward("1")
        self.set_conntrack(*KERNEL_CT)

    def set_forward(self, value: str) -> None:
        (self.sd / "forward").write_text(value, encoding="utf-8")

    def set_conntrack(self, ct_max: str, ct_est: str) -> None:
        (self.sd / CT_MAX).write_text(ct_max, encoding="utf-8")
        (self.sd / CT_EST).write_text(ct_est, encoding="utf-8")

    def conntrack(self) -> tuple[str, str]:
        return self.state(CT_MAX), self.state(CT_EST)

    def fail_check(self, rc: int) -> None:
        (self.sd / "check_rc").write_text(str(rc), encoding="utf-8")

    def fail_restart(self) -> None:
        (self.sd / "restart_rc").write_text("1", encoding="utf-8")

    # --- running ----------------------------------------------------------
    def run(self, body: str) -> subprocess.CompletedProcess[str]:
        prelude = (
            f'export SD="{self.sd}" LOGS="{self.logs}" LIVE_LISTING="{LIVE_LISTING}"\n'
            f'APP_DIR="{self.repo}"; cd "$APP_DIR"\n'
            f'BACKUP_DIR="{self.backups}"\n'
            f'RELAY_SYSTEM_UNIT="{self.unit}"\n'
            f'RELAY_HELPER="{self.helper}"\n'
            f'RELAY_SYSCTL_FILE="{self.sysctl_file}"\n'
            f'RELAY_LEGACY_NFT="{self.legacy}"\n'
            "OUT_OF_REPO_HELPERS=(\n"
            f'  "scripts/vpn-bot-db-perms|{self.sbin}/vpn-bot-db-perms|required"\n'
            f'  "scripts/vpn-relay-apply|{self.helper}|required|relay"\n'
            ")\n"
            # No host files here: the real registry names real /etc paths (the
            # MANAGED_HOST_FILES behaviour of both roles is tests/test_deploy_host_state.py).
            # The fence makes a forgotten override fail instead of writing /etc.
            "MANAGED_HOST_FILES=()\nUNMANAGED_SCAN_DIRS=()\n"
            f'MH_SELFTEST_ROOT="{self.tmp}"\n'
            f'HOST_CHECK_BIN="{self.checker}"; HOST_CHECK_ROOT="{self.host_root}"\n'
            f'HOST_CHECK_STATE="{self.tmp}/hc/last.json"\n'
            'NODE_ROLE=relay; TAG=abc1234\n'
        )
        return _source_and_run(self.tmp, prelude + body, env_text="NODE_ROLE=relay\n", extra_path=self.stub)

    def phase2(self) -> subprocess.CompletedProcess[str]:
        return self.run(
            'relay_snapshot_prestate\nRELAY_UNIT_STATE="$(relay_unit_state "$APP_DIR")"\n'
            "relay_phase2\necho PHASE2-RETURNED\n"
        )

    def log(self, name: str) -> list[str]:
        p = self.logs / f"{name}.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def state(self, name: str) -> str:
        p = self.sd / name
        return p.read_text(encoding="utf-8").strip() if p.exists() else "<absent>"


def _assert_no_main_piece_touched(host: RelayHost) -> None:
    for line in host.log("systemctl"):
        args = line.split()[1:]
        assert args[0] == "daemon-reload" or args[-1] == "vpn-relay.service", line
    assert host.log("sqlite3") == [], "a relay deploy never opens a database"
    assert not (host.sbin / "vpn-bot-db-perms").exists(), "a main-role helper was installed on a relay"


def test_relay_phase2_migrates_the_hand_installed_relay(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    proc = host.phase2()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PHASE2-RETURNED" in proc.stdout and "DEPLOY OK (relay)" in proc.stdout

    assert _read(host.unit) == _read(REPO_UNIT), "the unit is installed verbatim"
    assert _read(host.helper) == FAKE_HELPER, "the helper comes from OUT_OF_REPO_HELPERS"
    assert host.log("helper") == ["helper check"], "verify = vpn-relay-apply check"
    sc = [ln.removeprefix("systemctl ") for ln in host.log("systemctl")]
    mutating = [c for c in sc if c.split()[0] not in {"is-active", "is-enabled"}]
    assert mutating == ["daemon-reload", "enable --quiet vpn-relay.service", "restart vpn-relay.service"]
    assert "git reset --hard origin/main" in host.log("git")
    assert not any("prevsha" in c for c in host.log("git") if "reset" in c)

    assert not host.legacy.exists()
    renamed = list(host.etc.glob("vpn-relay.nft.pre-repo.*"))
    assert len(renamed) == 1 and _read(renamed[0]) == _read(CAPTURED_RULESET)
    _assert_no_main_piece_touched(host)


def test_relay_backup_holds_the_table_unit_and_sysctl_file(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    assert host.phase2().returncode == 0
    archives = list(host.backups.glob("backup-relay-abc1234-*.tar.gz"))
    assert len(archives) == 1
    listing = subprocess.run(["tar", "-tzf", str(archives[0])], capture_output=True, text=True, check=True).stdout
    assert "var/lib/vpn-bot-deploy/relay-table.pre-deploy.nft" in listing
    assert str(host.unit).lstrip("/") in listing
    assert str(host.sysctl_file).lstrip("/") in listing
    dump = subprocess.run(
        ["tar", "-xzOf", str(archives[0]), "./var/lib/vpn-bot-deploy/relay-table.pre-deploy.nft"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert dump == _read(LIVE_LISTING)


def test_failed_check_rolls_the_hand_installed_relay_back(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    host.fail_check(11)
    proc = host.phase2()
    assert proc.returncode == 1
    assert "PHASE2-RETURNED" not in proc.stdout
    assert "ROLLBACK REPORT (relay)" in proc.stderr
    assert "exit 11" in proc.stderr

    assert _read(host.unit) == _read(MANUAL_UNIT), "the hand-installed unit is back"
    assert not host.helper.exists(), "the helper did not exist before the deploy"
    assert _read(host.sysctl_file) == "net.ipv4.ip_forward = 1\n"
    assert _read(host.legacy) == _read(CAPTURED_RULESET), "not renamed: the deploy did not succeed"
    assert not list(host.etc.glob("vpn-relay.nft.pre-repo.*"))

    restored = _read(host.logs / "nft-restore.nft")
    assert restored == "table ip vpnrelay\ndelete table ip vpnrelay\n" + _read(LIVE_LISTING)
    assert host.state("forward") == "1"
    assert host.conntrack() == KERNEL_CT, "the pre-deploy conntrack values are back"
    assert f"sysctl -q -w {CT_MAX}=262144" in host.log("sysctl")
    assert f"sysctl -q -w {CT_EST}=432000" in host.log("sysctl")
    assert f"{CT_MAX}=262144 (pre-deploy value): rc=0" in proc.stderr
    assert host.state("vpn-relay.service.active") == "active"
    assert host.state("vpn-relay.service.enabled") == "enabled"
    resets = [c for c in host.log("git") if c.startswith("git reset")]
    assert resets == ["git reset --hard origin/main", "git reset --hard prevsha0000"]
    sc = [ln.removeprefix("systemctl ") for ln in host.log("systemctl")]
    assert "disable --quiet vpn-relay.service" not in sc, "it was enabled before"
    assert "stop vpn-relay.service" not in sc, "it was active before"
    _assert_no_main_piece_touched(host)


def test_failed_restart_rolls_the_hand_installed_relay_back_and_restarts_it(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    host.fail_restart()
    proc = host.phase2()
    assert proc.returncode == 1
    assert "restart failed" in proc.stderr
    assert host.log("helper") == [], "no check after a failed restart"
    assert _read(host.unit) == _read(MANUAL_UNIT)
    sc = [ln.removeprefix("systemctl ") for ln in host.log("systemctl")]
    assert "start vpn-relay.service" in sc, "a unit that was active is started again"
    assert sc.index("daemon-reload", sc.index("restart vpn-relay.service")) < sc.index("start vpn-relay.service"), (
        "it starts with the RESTORED unit file"
    )
    assert host.state("table") == "", "the saved table is live again"
    assert host.state("vpn-relay.service.active") == "active"
    assert host.conntrack() == KERNEL_CT, "what the failed apply set is undone"


def test_failed_check_on_a_fresh_relay_removes_everything_it_added(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)  # nothing installed, no table, forwarding off
    host.fail_check(13)
    proc = host.phase2()
    assert proc.returncode == 1
    for path in (host.unit, host.helper, host.sysctl_file):
        assert not path.exists(), f"{path} was not there before the deploy"
    assert host.state("table") == "<absent>"
    assert host.state("forward") == "0", "the restart switched it on; the rollback switches it off"
    # nf_conntrack was not loaded before the deploy: nothing to go back to.
    assert not [c for c in host.log("sysctl") if "-w" in c and "nf_conntrack" in c]
    assert f"{CT_MAX} unreadable before the deploy (nf_conntrack not loaded) — left as it is" in proc.stderr
    assert host.state("vpn-relay.service.enabled") == "<absent>"
    assert host.state("vpn-relay.service.active") == "inactive"
    sc = [ln.removeprefix("systemctl ") for ln in host.log("systemctl")]
    assert "stop vpn-relay.service" in sc and "disable --quiet vpn-relay.service" in sc
    assert sc.index("disable --quiet vpn-relay.service") < sc.index("daemon-reload", sc.index("restart vpn-relay.service")), (
        "disabled while the deploy's unit file is still there (no dangling wants link)"
    )
    assert not (host.logs / "nft-restore.nft").exists(), "no table to restore"
    _assert_no_main_piece_touched(host)


def test_rollback_reports_a_sysctl_that_did_not_take(tmp_path: Path) -> None:
    """procps `sysctl -w` can exit 0 without setting the value: the report reads it
    back instead of trusting rc."""
    host = RelayHost(tmp_path)
    host.hand_installed()
    host.fail_check(11)
    (host.sd / f"{CT_MAX}.eperm").touch()
    proc = host.phase2()
    assert proc.returncode == 1
    assert (
        f"{CT_MAX}=262144 (pre-deploy value): rc=0, now 65536 — MANUAL ACTION REQUIRED" in proc.stderr
    )
    assert f"{CT_EST}=432000 (pre-deploy value): rc=0\n" in proc.stderr


def test_prestate_snapshots_the_conntrack_sysctls(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    proc = host.run('relay_snapshot_prestate\necho "CT=[$RELAY_PRE_CT_MAX][$RELAY_PRE_CT_EST]"\n')
    assert proc.returncode == 0, proc.stderr
    assert "CT=[262144][432000]" in proc.stdout
    assert [c for c in host.log("sysctl") if " -w " in c] == [], "the snapshot only reads"
    fresh = RelayHost(tmp_path / "fresh")
    proc = fresh.run('relay_snapshot_prestate\necho "CT=[$RELAY_PRE_CT_MAX][$RELAY_PRE_CT_EST]"\n')
    assert "CT=[][]" in proc.stdout, "no nf_conntrack yet: unreadable, not an error"


def test_a_successful_deploy_keeps_the_conntrack_values_apply_set(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    proc = host.phase2()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert host.conntrack() == ("65536", "86400")
    assert [c for c in host.log("sysctl") if "-w" in c] == [], "only the rollback writes sysctls itself"


def test_a_successful_fresh_relay_is_enabled_and_has_no_legacy_file(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    proc = host.phase2()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert host.state("vpn-relay.service.enabled") == "enabled"
    assert host.state("vpn-relay.service.active") == "active"
    assert "absent" in proc.stdout  # the legacy-file line of the report
    archives = list(host.backups.glob("backup-relay-*.tar.gz"))
    listing = subprocess.run(["tar", "-tzf", str(archives[0])], capture_output=True, text=True, check=True).stdout
    assert "relay-table.pre-deploy.nft" not in listing, "there was no table to back up"


@pytest.mark.parametrize(
    ("setup", "state"),
    [("absent", "absent"), ("manual", "legacy"), ("repo", "synced"), ("edited", "differs")],
)
def test_relay_unit_state(tmp_path: Path, setup: str, state: str) -> None:
    host = RelayHost(tmp_path)
    if setup == "manual":
        host.unit.write_text(_read(MANUAL_UNIT), encoding="utf-8")
    elif setup == "repo":
        host.unit.write_text(_read(REPO_UNIT), encoding="utf-8")
    elif setup == "edited":
        host.unit.write_text(_read(REPO_UNIT) + "# local edit\n", encoding="utf-8")
    proc = host.run('relay_unit_state "$APP_DIR"; relay_unit_state_text "$(relay_unit_state "$APP_DIR")"\n')
    assert proc.stdout.splitlines()[0] == state
    if state == "legacy":
        assert "expected first transition, NOT drift" in proc.stdout


def test_relay_phase1_refuses_an_env_that_does_not_render(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    wt = tmp_path / "wt"
    (wt / "scripts").mkdir(parents=True)
    (wt / "scripts" / "vpn-relay-apply").write_text(_read(RELAY_HELPER_SRC), encoding="utf-8")
    env = tmp_path / "relay.env"
    env.write_text("NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4=999.1.1.1\n", encoding="utf-8")
    proc = host.run(f'ENV_FILE="{env}"; WT="{wt}"\nrelay_phase1\necho PHASE1-RETURNED\n')
    assert proc.returncode == 1
    assert "PHASE1-RETURNED" not in proc.stdout
    assert "RELAY_UPSTREAM_IPV4='999.1.1.1'" in proc.stdout
    assert "does not render" in proc.stderr and "nothing was changed" in proc.stderr
    assert host.log("systemctl") == [] and host.log("nft") == [] and host.log("sysctl") == []


@pytest.mark.parametrize("conntrack", [KERNEL_CT, ("65536", "86400")])
def test_relay_phase1_reports_the_first_transition_without_mutating(
    tmp_path: Path, conntrack: tuple[str, str]
) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    host.set_conntrack(*conntrack)
    wt = tmp_path / "wt"
    (wt / "scripts").mkdir(parents=True)
    (wt / "deploy" / "relay").mkdir(parents=True)
    (wt / "scripts" / "vpn-relay-apply").write_text(_read(RELAY_HELPER_SRC), encoding="utf-8")
    (wt / "deploy" / "relay" / "vpn-relay.service").write_text(_read(REPO_UNIT), encoding="utf-8")
    env = tmp_path / "relay.env"
    env.write_text(
        "NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4=150.251.152.243\nRELAY_WAN_IFACE=eth0\n", encoding="utf-8"
    )
    proc = host.run(
        f'ENV_FILE="{env}"; WT="{wt}"\nrelay_phase1\nrelay_phase1_report\necho PHASE1-RETURNED\n'
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "expected first transition, NOT drift" in out
    assert "vpn-relay-apply -> " in out and "(absent)" in out
    assert "table ip vpnrelay\ndelete table ip vpnrelay" in out.replace("    ", "")
    nft = host.log("nft")
    assert nft and all(c.startswith("nft list table") or c.startswith("nft -c") for c in nft), nft
    assert all(c.split()[1] in {"is-active", "is-enabled"} for c in host.log("systemctl"))
    assert not any("reset" in c for c in host.log("git"))
    assert _read(host.unit) == _read(MANUAL_UNIT) and host.legacy.exists()
    assert "ok: table ip vpnrelay matches" in out, "the repo renders the hand-made ruleset 1:1"
    assert f"{CT_MAX}={conntrack[0]}; {CT_EST}={conntrack[1]}" in out, "pre-state log line"
    assert f"nf_conntrack_max={conntrack[0]} nf_conntrack_tcp_timeout_established={conntrack[1]}" in out
    if conntrack == KERNEL_CT:
        # The hand-made relay never set them: the first deploy of this version does.
        assert "the table and ip_forward match; the conntrack sysctls differ from .env" in out
        assert "PASS" not in out
    else:
        assert "PASS" in out
    assert not [c for c in host.log("sysctl") if "-w" in c], "Phase 1 writes no sysctl"
    assert host.log("probe") == ["probe tcp 150.251.152.243 443"]


def test_relay_phase2_routes_every_mutation_through_the_rollback() -> None:
    """ERR is not inherited by functions, so every mutating command in relay_phase2
    after arm_relay_rollback must carry its own `|| rollback_now`."""
    text = _read(DEPLOY_SH)
    body = text[text.index("relay_phase2() {") :]
    body = body[: body.index("\n}\n")]
    armed = body[body.index("arm_relay_rollback") : body.index("  disarm")]
    for verb in ("git reset", "install -m0644", "systemctl daemon-reload", "systemctl enable", "systemctl restart"):
        idx = armed.index(verb)
        tail = armed[idx : armed.index("\n", armed.index("\n", idx) + 1) + 1]
        assert "rollback_now" in tail, f"{verb!r} is not routed to the rollback"


def test_redeploy_wrapper_needs_no_relay_branch() -> None:
    """CHECK=1 and a plain run work the same on a relay: the wrapper only fetches and
    hands over to deploy.sh, which reads the role itself."""
    text = _read(ROOT / "scripts" / "redeploy.sh")
    assert "NODE_ROLE" in text, "the wrapper documents that it is role-agnostic"
    assert "relay_deploy" not in text and "vpn-relay" not in text


def test_repo_unit_runs_the_helper_and_never_touches_input() -> None:
    unit = _read(REPO_UNIT)
    assert "ExecStart=/usr/local/sbin/vpn-relay-apply apply" in unit
    assert "ExecStop=-/usr/sbin/nft delete table ip vpnrelay" in unit
    assert "Type=oneshot" in unit and "RemainAfterExit=yes" in unit
    assert "After=network-online.target" in unit and "WantedBy=multi-user.target" in unit
    assert "/etc/vpn-relay.nft\n" not in unit.split("[Unit]", 1)[1]


def test_relay_env_example_covers_the_keys_the_helper_reads() -> None:
    example = _read(ROOT / "deploy" / "relay" / "relay.env.example")
    helper = _read(RELAY_HELPER_SRC)
    keys = set(re.findall(r"env_sed_val (RELAY_[A-Z0-9_]+)", helper))
    assert keys == {
        "RELAY_UPSTREAM_IPV4", "RELAY_FORWARD_TCP_PORTS", "RELAY_FORWARD_UDP_PORTS",
        "RELAY_WAN_IFACE", "RELAY_CHECK_SNI",
        "RELAY_CONNTRACK_MAX", "RELAY_CONNTRACK_TCP_ESTABLISHED_TIMEOUT",
    }
    for key in [*keys, "NODE_ROLE"]:
        assert re.search(rf"^#? ?{key}=", example, re.M), key
    assert "BOT_TOKEN" not in example, "no Telegram on a relay"


def test_a_successful_relay_deploy_leaves_no_rollback_trap(tmp_path: Path) -> None:
    """disarm() is a function, and bash hands a function's caller back the ERR trap it
    had on entry when the function leaves it unset — so the disarm inside relay_phase2
    never cleared the relay_rollback trap, and any failing command after DEPLOY OK
    (relay) would have rolled a healthy relay back. relay_phase2 clears it itself."""
    host = RelayHost(tmp_path)
    host.hand_installed()
    proc = host.run(
        'relay_snapshot_prestate\nRELAY_UNIT_STATE="$(relay_unit_state "$APP_DIR")"\n'
        "relay_phase2\necho TRAPS-BEGIN; trap -p ERR; echo TRAPS-END\n"
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    traps = proc.stdout.split("TRAPS-BEGIN", 1)[1].split("TRAPS-END", 1)[0]
    assert traps.strip() == "", traps
    assert "ROLLBACK" not in proc.stderr


def test_every_disarm_call_clears_the_err_trap_in_its_own_frame() -> None:
    """The same bash rule on the main path: disarm() alone leaves the rollback trap
    armed through the DEPLOY OK report, so every call site clears it inline."""
    lines = _read(DEPLOY_SH).splitlines()
    calls = [i for i, ln in enumerate(lines) if ln.strip() == "disarm"]
    assert len(calls) == 2, calls  # main Phase 2 + relay_phase2
    for i in calls:
        assert any(ln.strip() == "trap - ERR INT TERM HUP" for ln in lines[i + 1 : i + 6]), lines[i : i + 6]


# --------------------------------------------------------------------------- #
# Host invariants (scripts/vpn-bot-host-check) on a relay
# --------------------------------------------------------------------------- #
def test_relay_phase2_runs_the_host_check_and_writes_the_state(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    proc = host.phase2()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    (call,) = host.log("host-check")
    assert "--role relay" in call and call.endswith(f"--state {tmp_path}/hc/last.json")
    assert "--pre-install" not in call
    assert "host invariants  : beaten 0, mismatch 0, latent 0 (accepted 0), warn 0" in proc.stdout


def test_relay_phase2_rolls_back_on_a_beaten_host_value(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    (host.sd / "hc_rows").write_text(
        "BEATEN|sshd|passwordauthentication|/etc/ssh/sshd_config.d/50-cloud-init.conf|yes wins over no\n",
        encoding="utf-8")
    proc = host.phase2()
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "ROLLBACK REPORT (relay)" in proc.stderr
    assert "host invariants after the install: 1 BEATEN/MISMATCH finding(s)" in proc.stderr
    assert "DEPLOY OK (relay)" not in proc.stdout


def test_relay_phase1_stops_on_an_auth_latent(tmp_path: Path) -> None:
    host = RelayHost(tmp_path)
    host.hand_installed()
    (host.sd / "hc_rows").write_text(
        "LATENT|sshd|passwordauthentication|/etc/ssh/sshd_config.d/50-cloud-init.conf|winner ... gone -> yes\n",
        encoding="utf-8")
    wt = tmp_path / "wt"
    (wt / "scripts").mkdir(parents=True)
    (wt / "scripts" / "vpn-relay-apply").write_text(_read(RELAY_HELPER_SRC), encoding="utf-8")
    env = tmp_path / "relay.env"
    env.write_text("NODE_ROLE=relay\nRELAY_UPSTREAM_IPV4=150.251.152.243\nRELAY_WAN_IFACE=eth0\n", encoding="utf-8")
    proc = host.run(f'ENV_FILE="{env}"; WT="{wt}"\nrelay_phase1\necho PHASE1-RETURNED\n')
    assert proc.returncode == 1
    assert "PHASE1-RETURNED" not in proc.stdout
    assert "host invariants: 1 fatal finding(s) — nothing was changed" in proc.stderr
    (call,) = host.log("host-check")
    assert f"--repo {wt} --role relay" in call and call.endswith("--pre-install --no-state")
