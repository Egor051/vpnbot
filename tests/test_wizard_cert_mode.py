"""The wizard's «cert» mode (scripts/wizard/vpn-bot-wizard-cert) end to end on a fake host.

The launcher runs the mode helper through the contract (plan → apply → verify →
rollback); the mode helper calls the REAL scripts/vpn-bot-cert (a stub in the wizard's
stub directory runs it under its own seam on the same fake root), which drives the fake
acme.sh, the systemctl / nginx stubs and real openssl (tests/cert_fakes.py).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from cert_fakes import DOMAIN, HELPER, OPENSSL, TOKEN, ZONE, CertHost, b64

ROOT = Path(__file__).resolve().parents[1]
WIZ = ROOT / "scripts" / "wizard"
LAUNCHER = WIZ / "vpn-bot-wizard"
RELOAD = "/usr/local/sbin/vpn-bot-cert deploy"

pytestmark = [
    pytest.mark.timeout(240),
    pytest.mark.skipif(OPENSSL is None, reason="needs the openssl binary"),
]


class WizardCertHost(CertHost):
    def __init__(self, tmp: Path) -> None:
        super().__init__(tmp)
        self.install_acme()
        stub = self.bin / "vpn-bot-cert"
        stub.write_text(
            f'#!/bin/bash\nprintf "%s\\n" "vpn-bot-cert $*" >> "$CALLS"\n'
            f'exec {sys.executable} -I {HELPER} --root {self.root} "$@"\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)

    def wizard(self, run_id: int, phase: str, **params: str) -> subprocess.CompletedProcess[str]:
        args = [sys.executable, "-I", str(LAUNCHER), "run", "--mode", "cert", "--run", str(run_id), "--phase", phase]
        for key, value in params.items():
            args += ["--param", f"{key}={value}"]
        env = self.env(VPN_BOT_WIZARD_SELFTEST="1", VPN_BOT_WIZARD_ROOT=str(self.root),
                       VPN_BOT_WIZARD_SELFTEST_BIN=str(self.bin))
        return subprocess.run(args, capture_output=True, text=True, env=env, timeout=200, check=False)

    def events(self, run_id: int) -> list[dict[str, Any]]:
        path = self.file(f"/var/lib/vpn-bot-wizard/{run_id}.status")
        if not path.exists():
            return []
        return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def outcome(self, run_id: int) -> str:
        """How the LAST phase in the status file ended (a plan, then its execute)."""
        done = [e for e in self.events(run_id) if e["event"] == "finished"]
        assert done, self.events(run_id)
        return str(done[-1]["outcome"])

    def plan_text(self, run_id: int) -> str:
        return next(e["text"] for e in self.events(run_id) if e["event"] == "plan")


@pytest.fixture
def host(tmp_path: Path) -> WizardCertHost:
    return WizardCertHost(tmp_path)


def test_adopt_plans_the_diff_then_adopts_and_verifies(host: WizardCertHost) -> None:
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("systemctl restart hysteria-server")})
    host.lay_out(chain, key)
    assert host.wizard(1, "plan", action="adopt").returncode == 0
    assert host.outcome(1) == "planned"
    text = host.plan_text(1)
    assert "- Le_RealFullChainPath='/etc/vpn-bot/tls/fullchain.pem'" in text
    assert f"+ Le_ReloadCmd='{RELOAD}'" in text
    assert host.conf()["Le_ReloadCmd"] == b64("systemctl restart hysteria-server"), "the plan changes nothing"
    proc = host.wizard(1, "execute", action="adopt")
    assert proc.returncode == 0, proc.stderr
    events = host.events(1)
    assert [e["outcome"] for e in events if e["event"] == "finished"][-1] == "succeeded"
    steps = [(e["step"], e["state"]) for e in events if e["event"] == "step"]
    assert ("apply", "ok") in steps and ("verify", "ok") in steps and not any(s == "rollback" for s, _ in steps)
    assert host.conf()["Le_ReloadCmd"] == b64(RELOAD) and host.conf()["Le_RealFullChainPath"] == ""
    assert [e for e in events if e["event"] == "backup"], "a backup before the change"


def test_deploy_with_nothing_to_do_is_a_noop_plan(host: WizardCertHost) -> None:
    chain, key = host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.lay_out(chain, key)
    assert host.wizard(2, "plan", action="deploy").returncode == 0
    plan = next(e for e in host.events(2) if e["event"] == "plan")
    assert plan["noop"] is True and "Nothing to do" in plan["text"]


def test_issue_plans_names_zone_and_readers_then_issues(host: WizardCertHost) -> None:
    host.token()
    names = f"{DOMAIN},www.{DOMAIN}"
    assert host.wizard(3, "plan", action="issue", names=names, zone=ZONE).returncode == 0
    text = host.plan_text(3)
    assert f"zone {ZONE}" in text and f"www.{DOMAIN}" in text and "hysteria" in text and RELOAD in text
    assert TOKEN not in text
    new_chain, _ = host.next_pair([DOMAIN, f"www.{DOMAIN}"])
    proc = host.wizard(3, "execute", action="issue", names=names, zone=ZONE)
    assert proc.returncode == 0, proc.stderr
    assert host.outcome(3) == "succeeded"
    assert host.file("/etc/hysteria/cert.pem").read_bytes() == new_chain
    log = host.file("/var/log/vpn-bot-wizard/3.log").read_text(encoding="utf-8")
    assert TOKEN not in log


def test_issue_without_the_bots_token_fails_at_the_plan(host: WizardCertHost) -> None:
    host.wizard(4, "plan", action="issue", names=DOMAIN, zone=ZONE)
    assert host.outcome(4) == "failed"
    assert "Cloudflare token" in host.plan_text(4)


def test_a_failed_renewal_rolls_the_whole_host_back(host: WizardCertHost) -> None:
    old_chain, old_key = host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.lay_out(old_chain, old_key)
    host.token()
    assert host.wizard(5, "plan", action="renew", zone=ZONE).returncode == 0
    host.next_pair([DOMAIN])
    host.flag("fail-once-restart-hysteria-server")  # the new pair: the restart fails once
    proc = host.wizard(5, "execute", action="renew", zone=ZONE)
    assert proc.returncode == 1
    assert host.outcome(5) == "rolled_back"
    # acme.sh's pair and every reader's copy are what the plan found.
    assert host.file("/root/.acme.sh/example.net_ecc/fullchain.cer").read_bytes() == old_chain
    for path in ("/etc/hysteria/cert.pem", "/etc/vpn-bot/tls/fullchain.pem"):
        assert host.file(path).read_bytes() == old_chain, path
    assert host.file("/etc/hysteria/key.pem").read_bytes() == old_key
    assert any(ln.startswith("vpn-bot-cert act") for ln in host.calls_of("vpn-bot-cert"))


@pytest.mark.parametrize(
    "param",
    ["names=Example.NET", "names=a.example.net,a.example.net", "names=a;rm -rf /", "zone=XYZ", "zone=*.example.net",
     "zone=" + "0" * 32, "action=shell"],
)
def test_the_launcher_refuses_a_bad_parameter(host: WizardCertHost, param: str) -> None:
    proc = subprocess.run(
        [sys.executable, "-I", str(LAUNCHER), "launch", "--mode", "cert", "--run", "9", "--phase", "plan", "--param", param],
        capture_output=True, text=True, timeout=60, check=False,
        env=host.env(VPN_BOT_WIZARD_SELFTEST="1", VPN_BOT_WIZARD_ROOT=str(host.root),
                     VPN_BOT_WIZARD_SELFTEST_BIN=str(host.bin)),
    )
    assert proc.returncode == 2, proc.stderr
    assert host.calls_of("vpn-bot-cert") == []


def test_the_selfcheck_cert_item_is_vpn_bot_cert_status(host: WizardCertHost) -> None:
    """certs: one item per problem the helper reports (here: the old reloadcmd and a
    reader with another copy), green when there is none."""
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("/usr/local/sbin/acme-reload.sh")})
    host.lay_out(chain, key)
    host.file("/etc/hysteria/cert.pem").write_bytes(b"stale")
    env = host.env(VPN_BOT_WIZARD_SELFTEST="1", VPN_BOT_WIZARD_ROOT=str(host.root), VPN_BOT_WIZARD_SELFTEST_BIN=str(host.bin))
    subprocess.run([sys.executable, "-I", str(WIZ / "vpn-bot-wizard-selfcheck"), "apply", "--run", "7"],
                   capture_output=True, text=True, env=env, timeout=120, check=False)
    items = {e["key"]: e["level"] for e in host.events(7) if e["event"] == "item"}
    assert items["cert:reloadcmd"] == "yellow" and items["cert:copy:hysteria"] == "yellow"
    assert "certs" not in items
    # Adopted, every copy current, the bot's token is the one acme.sh renews with.
    host.token()
    host.write("/root/.acme.sh/account.conf", f"SAVED_CF_Token='{TOKEN}'\n", 0o600)
    assert host.cert("adopt").returncode == 0
    subprocess.run([sys.executable, "-I", str(WIZ / "vpn-bot-wizard-selfcheck"), "apply", "--run", "8"],
                   capture_output=True, text=True, env=env, timeout=120, check=False)
    items8 = {e["key"]: (e["level"], e["text"]) for e in host.events(8) if e["event"] == "item"}
    assert items8["certs"][0] == "green" and "vpn-bot-cert deploy" in items8["certs"][1]
    assert not any(k.startswith("cert:") for k in items8)


def test_the_text_kinds_are_typed_the_same_in_the_bot_and_the_launcher() -> None:
    """names / zone: the launcher's table (vpn-bot-wizard-lib) and the bot's
    (services/wizard_modes.py) accept and refuse the same values."""
    import importlib.machinery
    import importlib.util

    from services.wizard_modes import MODES as BOT_MODES
    from services.wizard_modes import WizardParamError

    loader = importlib.machinery.SourceFileLoader("wizard_lib_kinds", str(WIZ / "vpn-bot-wizard-lib"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    lib = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = lib  # dataclasses look their module up while it loads
    try:
        loader.exec_module(lib)
    finally:
        sys.modules.pop(loader.name, None)
    good = {"names": ["", "example.net", "example.net,www.example.net", "*.example.net"], "zone": ["", "example.net"]}
    bad = {"names": ["Example.net", "a.example.net,a.example.net", "x", "a b", ",".join(f"n{i}.example.net" for i in range(11))],
           "zone": ["*.example.net", "0" * 32, "Example.NET", "x"]}
    for name, values in good.items():
        for value in values:
            assert lib.MODES["cert"].params[name].check(value) == BOT_MODES["cert"].params[name].coerce(name, value)
    for name, values in bad.items():
        for value in values:
            with pytest.raises(lib.WizardError):
                lib.MODES["cert"].params[name].check(value)
            with pytest.raises(WizardParamError):
                BOT_MODES["cert"].params[name].coerce(name, value)
    assert lib.validate_params("cert", ["action=issue", "names=example.net"]) == {
        "action": "issue", "names": "example.net", "zone": ""}


def test_adopt_takes_the_domain_the_screen_picked_among_several(host: WizardCertHost) -> None:
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("/usr/local/sbin/acme-reload.sh")})
    host.lay_out(chain, key)
    host.acme_domain(f"old.{DOMAIN}", conf={"Le_ReloadCmd": b64("systemctl restart hysteria-server"),
                                            "Le_RealFullChainPath": "", "Le_RealKeyPath": ""})
    assert host.wizard(11, "plan", action="adopt").returncode == 1  # ambiguous without a pick
    assert host.outcome(11) == "failed" and "more than one" in host.plan_text(11)
    assert host.wizard(12, "plan", action="adopt", names=DOMAIN).returncode == 0
    assert DOMAIN in host.plan_text(12)
    proc = host.wizard(12, "execute", action="adopt", names=DOMAIN)
    assert proc.returncode == 0, proc.stderr
    assert host.outcome(12) == "succeeded"
    assert host.conf()["Le_ReloadCmd"] == b64(RELOAD)
    assert host.conf(f"old.{DOMAIN}")["Le_ReloadCmd"] == b64("systemctl restart hysteria-server")


def test_verify_fails_when_a_reader_is_configured_to_read_another_pair(host: WizardCertHost) -> None:
    """hysteria restarted on the registry's files but configured to read another path
    would go on serving that one: the run is not a success — it is rolled back."""
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("systemctl restart hysteria-server")})
    host.lay_out(chain, key)
    host.write("/etc/hysteria/config.yaml", "tls:\n  cert: /etc/letsencrypt/live/x/fullchain.pem\n"
                                            "  key: /etc/letsencrypt/live/x/privkey.pem\n")
    assert host.wizard(13, "plan", action="adopt").returncode == 0
    assert host.wizard(13, "execute", action="adopt").returncode == 1
    assert host.outcome(13) == "rolled_back"
    result = [e for e in host.events(13) if e["event"] == "result"][-1]
    assert "does not read the registry's files" in result["text"]
    assert host.conf()["Le_ReloadCmd"] == b64("systemctl restart hysteria-server")


def test_a_plan_shown_on_another_pair_is_not_applied(host: WizardCertHost) -> None:
    """acme.sh renews between the plan and the confirmation: the plan's diff and hash no
    longer describe the run — apply refuses before the backup, nothing changes."""
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("systemctl restart hysteria-server")})
    host.lay_out(chain, key)
    assert host.wizard(14, "plan", action="adopt").returncode == 0
    host.acme_domain(conf={"Le_ReloadCmd": b64("systemctl restart hysteria-server")}, days=61)
    host.reset_calls()
    assert host.wizard(14, "execute", action="adopt").returncode == 1
    assert host.outcome(14) != "succeeded"
    assert host.conf()["Le_ReloadCmd"] == b64("systemctl restart hysteria-server")
    assert host.file("/etc/hysteria/cert.pem").read_bytes() == chain and host.actions() == []
    assert not [c for c in host.calls_of("vpn-bot-cert") if c.startswith("vpn-bot-cert adopt --domain")]


def test_the_helper_gets_the_planned_pair_to_check_under_its_lock(host: WizardCertHost) -> None:
    chain, key = host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.lay_out(chain, key)
    host.write("/etc/hysteria/cert.pem", b"stale", 0o644, ("hysteria", "hysteria"))
    assert host.wizard(15, "plan", action="deploy").returncode == 0
    assert host.wizard(15, "execute", action="deploy").returncode == 0, host.events(15)
    deploys = [c for c in host.calls_of("vpn-bot-cert") if c.startswith("vpn-bot-cert deploy --expect-pair ")]
    assert len(deploys) == 1, host.calls_of("vpn-bot-cert")


def test_adopt_among_several_bot_domains_releases_the_others_and_a_rollback_restores_them(
    host: WizardCertHost,
) -> None:
    chain, key = host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.lay_out(chain, key)
    other = f"old.{DOMAIN}"
    host.acme_domain(other, conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    assert host.wizard(16, "plan", action="adopt", names=DOMAIN).returncode == 0
    text = host.plan_text(16)
    assert "Released" in text and f"/root/.acme.sh/{other}_ecc/{other}.conf" in text and "+ Le_ReloadCmd=''" in text
    # A reader configured to read another pair: verify fails, the run is rolled back.
    host.write("/etc/hysteria/config.yaml", "tls:\n  cert: /etc/letsencrypt/live/x/fullchain.pem\n"
                                            "  key: /etc/letsencrypt/live/x/privkey.pem\n")
    assert host.wizard(16, "execute", action="adopt", names=DOMAIN).returncode == 1
    assert host.outcome(16) == "rolled_back"
    assert host.conf(other)["Le_ReloadCmd"] == b64(RELOAD), "the released domain is restored by the rollback"
    host.write("/etc/hysteria/config.yaml", "tls:\n  cert: /etc/hysteria/cert.pem\n  key: /etc/hysteria/key.pem\n")
    assert host.wizard(17, "plan", action="adopt", names=DOMAIN).returncode == 0
    assert host.wizard(17, "execute", action="adopt", names=DOMAIN).returncode == 0, host.events(17)
    assert host.outcome(17) == "succeeded"
    assert host.conf()["Le_ReloadCmd"] == b64(RELOAD) and host.conf(other)["Le_ReloadCmd"] == ""


def test_verify_fails_when_what_hysteria_reads_cannot_be_told(host: WizardCertHost) -> None:
    """hysteria's config unreadable (here: absent): what it serves is unknown — the run is
    not verified, it is rolled back."""
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("systemctl restart hysteria-server")})
    host.lay_out(chain, key)
    host.file("/etc/hysteria/config.yaml").unlink()
    assert host.wizard(18, "plan", action="adopt").returncode == 0
    assert host.wizard(18, "execute", action="adopt").returncode == 1
    assert host.outcome(18) == "rolled_back"
    result = [e for e in host.events(18) if e["event"] == "result"][-1]
    assert "cannot tell what it reads" in result["text"]
    assert host.conf()["Le_ReloadCmd"] == b64("systemctl restart hysteria-server")


def test_the_helper_runs_in_its_own_group_killed_whole_on_a_timeout(tmp_path: Path) -> None:
    """The mode helper's own timeout kills vpn-bot-cert AND the acme.sh it runs before it
    returns — the rollback that follows never races a renewal still in flight. (Driven in a
    child interpreter, as the launcher runs it: importing the mode helper here would add it
    to this process's coverage while its real runs happen in subprocesses.)"""
    import os
    import time

    stubs = tmp_path / "bin"
    stubs.mkdir()
    pidfile = tmp_path / "acme.pid"
    stub = stubs / "vpn-bot-cert"
    stub.write_text(f"#!/bin/sh\nsleep 60 &\necho $! > {pidfile}\nwait\n", encoding="utf-8")
    stub.chmod(0o755)
    driver = tmp_path / "driver.py"
    driver.write_text(
        "import importlib.machinery, importlib.util, json, sys\n"
        "from types import SimpleNamespace\n"
        "loader = importlib.machinery.SourceFileLoader('vpn_bot_wizard_cert', sys.argv[1])\n"
        "spec = importlib.util.spec_from_loader(loader.name, loader)\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules[loader.name] = mod\n"
        "loader.exec_module(mod)\n"
        "logged = []\n"
        "ctx = SimpleNamespace(log=SimpleNamespace(write=logged.append))\n"
        "rc, out = mod.run_group(ctx, ['vpn-bot-cert', 'renew', '--force'], 1)\n"
        "print(json.dumps({'rc': rc, 'out': out, 'logged': len(logged), 'budget': mod.HELPER_TIMEOUT,\n"
        "                  'step': mod.lib.MODES['cert'].timeout('apply')}))\n",
        encoding="utf-8",
    )
    env = {**os.environ, "VPN_BOT_WIZARD_SELFTEST": "1", "VPN_BOT_WIZARD_ROOT": str(tmp_path / "root"),
           "VPN_BOT_WIZARD_SELFTEST_BIN": str(stubs), "PATH": f"{stubs}:{os.environ['PATH']}"}
    proc = subprocess.run([sys.executable, "-I", str(driver), str(WIZ / "vpn-bot-wizard-cert")],
                          capture_output=True, text=True, env=env, timeout=60, check=False)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout.strip().splitlines()[-1])
    assert got["rc"] == 124 and "process group killed" in got["out"] and got["logged"] == 1
    assert got["budget"] < got["step"] - 120, "vpn-bot-cert's budget must end before the launcher's step"
    child = int(pidfile.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and os.path.exists(f"/proc/{child}"):
        time.sleep(0.05)
    assert not os.path.exists(f"/proc/{child}"), "acme.sh's process survived the timeout"


def test_adopt_releases_a_writer_and_verify_holds_the_registry_to_one_domain(host: WizardCertHost) -> None:
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("/usr/local/sbin/acme-reload.sh")})
    host.lay_out(chain, key)
    other = f"old.{DOMAIN}"
    host.acme_domain(other, conf={"Le_ReloadCmd": b64("systemctl reload nginx")})
    assert host.wizard(19, "plan", action="adopt", names=DOMAIN).returncode == 0
    text = host.plan_text(19)
    assert f"/root/.acme.sh/{other}_ecc/{other}.conf" in text and "+ Le_RealKeyPath=''" in text
    proc = host.wizard(19, "execute", action="adopt", names=DOMAIN)
    assert proc.returncode == 0, host.events(19)
    assert host.outcome(19) == "succeeded"
    assert host.conf(other)["Le_RealKeyPath"] == "" and host.conf(other)["Le_RealFullChainPath"] == ""


def test_verify_fails_when_nginx_includes_a_config_it_cannot_read(host: WizardCertHost) -> None:
    """An nginx include out of /etc/nginx (never read): what nginx serves is unknown — the
    run is not verified, it is rolled back."""
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("systemctl restart hysteria-server")})
    host.lay_out(chain, key)
    host.write("/etc/nginx/nginx.conf", "http {\n  include /srv/nginx/*.conf;\n}\n")
    host.write("/srv/nginx/tls.conf", "ssl_certificate /srv/other/fullchain.pem;\n")
    assert host.wizard(20, "plan", action="adopt").returncode == 0
    assert host.wizard(20, "execute", action="adopt").returncode == 1
    assert host.outcome(20) == "rolled_back"
    result = [e for e in host.events(20) if e["event"] == "result"][-1]
    assert "nginx: cannot tell what it reads" in result["text"]
