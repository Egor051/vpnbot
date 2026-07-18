"""Coverage for the tracked Hysteria2 fwmark helper `scripts/vpnbot-hy2-warp-mark`.

PR-A parametrizes the helper: the fwmark `--sport` exemption port is DERIVED from
HYSTERIA2_PORT (the single source of truth the bot reads too) instead of the old
hardcoded `HYPORT=15650`, so the marking port can never drift from the port
hysteria-server actually listens on. These tests pin:

* (a) structural — the literal `HYPORT=15650` is gone and the file resolves
      HYSTERIA2_PORT instead;
* (b) the resolver returns the .env value (exercised at 15650 — the PR-A no-op
      value — and at 443 to prove it is dynamic, not a literal);
* (c) a missing / empty / non-numeric / out-of-range HYSTERIA2_PORT fails closed
      (non-zero exit) BEFORE any `ip`/`iptables` mutation — never applying a rule
      built on a bad port.

The resolver + range guard sit at top level, so they run at script load, before
apply()/flush() touch the network. We drive the real shipped script under stub
`ip`/`iptables` on PATH that log every invocation.
"""

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpnbot-hy2-warp-mark"


def _read() -> str:
    return HELPER.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# (a) structural guards
# --------------------------------------------------------------------------- #
def test_helper_exists_and_is_executable() -> None:
    assert HELPER.exists()
    assert os.access(HELPER, os.X_OK), "the tracked helper must be executable (git mode 0755)"


def test_helper_has_no_hardcoded_hyport_literal() -> None:
    text = _read()
    # No assignment of the magic port literal in any form (the whole point of PR-A).
    for line in text.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("HYPORT=15650"), "HYPORT must not be hardcoded to 15650"
    assert "HYPORT=15650" not in text


def test_helper_derives_hyport_from_hysteria2_port() -> None:
    text = _read()
    # It reads HYSTERIA2_PORT from the bot .env and assigns the resolved value.
    assert "HYSTERIA2_PORT" in text, "the helper must resolve HYSTERIA2_PORT"
    assert "HY2_ENV" in text and "/opt/vpn-service/.env" in text
    assert 'HYPORT="$port"' in text, "HYPORT must come from the resolved port, not a literal"


# --------------------------------------------------------------------------- #
# Test harness: run the real helper under logging ip/iptables stubs
# --------------------------------------------------------------------------- #
def _run(tmp_path: Path, env_content: str | None, arg: str = "apply") -> tuple[int, list[str], list[str]]:
    """Run the shipped helper with a temp HY2_ENV and stubbed network tools.

    env_content=None => point HY2_ENV at a path that does not exist.
    Returns (returncode, iptables_calls, ip_calls).
    """
    stub = tmp_path / "bin"
    stub.mkdir(parents=True, exist_ok=True)
    ipt_log = tmp_path / "iptables.log"
    ip_log = tmp_path / "ip.log"
    (stub / "iptables").write_text(
        f'#!/bin/bash\necho "$*" >> "{ipt_log}"\nexit 0\n', encoding="utf-8"
    )
    # `ip rule show` must print nothing (no pre-existing rule) so apply() proceeds;
    # every invocation is still logged so we can assert "no network touch" on the
    # fail-closed paths.
    (stub / "ip").write_text(
        f'#!/bin/bash\necho "$*" >> "{ip_log}"\nexit 0\n', encoding="utf-8"
    )
    for f in (stub / "iptables", stub / "ip"):
        f.chmod(0o755)

    if env_content is None:
        env_path = tmp_path / "does-not-exist.env"
    else:
        env_path = tmp_path / "test.env"
        env_path.write_text(env_content, encoding="utf-8")

    env = dict(os.environ)
    env["PATH"] = f"{stub}:{env['PATH']}"
    env["HY2_ENV"] = str(env_path)
    proc = subprocess.run(
        ["bash", str(HELPER), arg], env=env, capture_output=True, text=True
    )
    ipt = ipt_log.read_text().splitlines() if ipt_log.exists() else []
    ips = ip_log.read_text().splitlines() if ip_log.exists() else []
    return proc.returncode, ipt, ips


# --------------------------------------------------------------------------- #
# (b) the resolver returns the .env value and drives it into the --sport rule
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "env_content, port",
    [
        ("HYSTERIA2_PORT=15650\n", "15650"),          # the PR-A no-op value
        ("HYSTERIA2_PORT=443\n", "443"),              # proves it is dynamic, not literal
        ("  export HYSTERIA2_PORT = 8080  # inline\n", "8080"),  # export/space/comment tolerated
        ('HYSTERIA2_PORT="9000"\n', "9000"),          # quotes stripped
        ("HYSTERIA2_PORT=1\nHYSTERIA2_PORT=2\n", "2"),  # last assignment wins
    ],
)
def test_helper_resolves_port_into_sport_exemption(tmp_path: Path, env_content: str, port: str) -> None:
    _, ipt, _ = _run(tmp_path, env_content)
    # The resolver succeeded and reached the iptables logic (rc is 1 only because
    # the stubbed `ip rule show` reports no rule, tripping the verify step — the
    # port resolution itself is what we assert here).
    joined = "\n".join(ipt)
    assert f"--sport {port} -j RETURN" in joined, f"expected --sport {port}, got:\n{joined}"
    # No OTHER port leaked into the exemption.
    for other in ("15650", "443", "8080", "9000"):
        if other != port:
            assert f"--sport {other} " not in joined


# --------------------------------------------------------------------------- #
# (c) fail-closed: bad port -> non-zero exit, ZERO network mutation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "env_content",
    [
        None,                       # HY2_ENV file missing entirely
        "OTHER=1\n",               # HYSTERIA2_PORT absent
        "HYSTERIA2_PORT=\n",       # empty
        "HYSTERIA2_PORT=abc\n",    # non-numeric
        "HYSTERIA2_PORT=70000\n",  # out of range (>65535)
        "HYSTERIA2_PORT=0\n",      # out of range (<1)
    ],
)
def test_helper_fails_closed_before_touching_network(tmp_path: Path, env_content: str | None) -> None:
    rc, ipt, ips = _run(tmp_path, env_content)
    assert rc != 0, "a bad HYSTERIA2_PORT must fail loudly"
    assert rc == 3, f"expected fail-closed exit 3, got {rc}"
    assert ipt == [], f"no iptables mutation may precede the guard, got: {ipt}"
    assert ips == [], f"no ip-rule mutation may precede the guard, got: {ips}"


def test_helper_clear_also_fails_closed_on_bad_port(tmp_path: Path) -> None:
    """The guard sits at script load, so even the `clear` path refuses to run on a
    bad port (it would otherwise try to delete a --sport rule for a bogus port)."""
    rc, ipt, ips = _run(tmp_path, "HYSTERIA2_PORT=notaport\n", arg="clear")
    assert rc == 3
    assert ipt == [] and ips == []
