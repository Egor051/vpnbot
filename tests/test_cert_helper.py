"""scripts/vpn-bot-cert — the bot's certificate: the registry of its readers, deploy with a
rollback per group, the adoption of the hand-made acme.sh setup, issue / renew with the bot's
ONE Cloudflare token (docs/certificate.md).

Every test runs the helper as a subprocess under VPN_BOT_CERT_SELFTEST=1 on a fake root
(tests/cert_fakes.py): a fake acme.sh with acme.sh's on-disk contract, systemctl / nginx
stubs, and REAL certificates from the real openssl — the helper's key-matches-certificate
and SAN checks run on them. No network, no root.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
from cert_fakes import DOMAIN, HELPER, OPENSSL, TOKEN, ZONE, ZONE_ID, CertHost, b64, fp, make_pair

pytestmark = [
    pytest.mark.timeout(180),
    pytest.mark.skipif(OPENSSL is None, reason="needs the openssl binary"),
]

RELOAD = "/usr/local/sbin/vpn-bot-cert deploy"
TLS_CHAIN, TLS_KEY = "/etc/vpn-bot/tls/fullchain.pem", "/etc/vpn-bot/tls/privkey.pem"
HY_CERT, HY_KEY = "/etc/hysteria/cert.pem", "/etc/hysteria/key.pem"


@pytest.fixture
def host(tmp_path: Path) -> CertHost:
    h = CertHost(tmp_path)
    h.install_acme()
    return h


@pytest.fixture
def mod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ModuleType]:
    """The helper as a module, loaded UNDER the seam: nothing it runs can reach the host."""
    monkeypatch.setenv("VPN_BOT_CERT_SELFTEST", "1")
    (tmp_path / "no-stubs").mkdir()
    monkeypatch.setenv("VPN_BOT_CERT_SELFTEST_BIN", str(tmp_path / "no-stubs"))
    loader = importlib.machinery.SourceFileLoader("vpn_bot_cert_under_test", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    try:
        yield module
    finally:
        sys.modules.pop(loader.name, None)


def adopted_host(host: CertHost) -> tuple[bytes, bytes]:
    """A host already adopted: the bot's reloadcmd, no file targets, every copy current."""
    chain, key = host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.lay_out(chain, key)
    return chain, key


# --------------------------------------------------------------------------- #
# The registry
# --------------------------------------------------------------------------- #
def test_the_registry_is_the_hosts_readers_exactly(mod: ModuleType) -> None:
    table = {
        c.name: (c.unit, c.action, c.marker, c.check,
                 [(f.path, f.source, f.owner, f.group, oct(f.mode)) for f in c.files])
        for c in mod.CONSUMERS
    }
    assert table == {
        "hysteria": ("hysteria-server", "restart", "hysteria2", (), [
            (HY_CERT, "fullchain", "hysteria", "hysteria", "0o644"),
            (HY_KEY, "key", "hysteria", "hysteria", "0o600"),
        ]),
        "nginx": ("nginx", "reload", "", ("nginx", "-t", "-q"), [
            (TLS_CHAIN, "fullchain", "root", "vpn-bot", "0o640"),
            (TLS_KEY, "key", "root", "vpn-bot", "0o640"),
        ]),
        "subscription": ("vpn-bot-subscription", "try-restart", "", (), [
            (TLS_CHAIN, "fullchain", "root", "vpn-bot", "0o640"),
            (TLS_KEY, "key", "root", "vpn-bot", "0o640"),
        ]),
    }
    assert (mod.TLS_DIR.path, mod.TLS_DIR.owner, mod.TLS_DIR.group, mod.TLS_DIR.mode) == ("/etc/vpn-bot/tls", "root", "root", 0o755)


def test_every_consumer_reads_one_pair_and_a_shared_path_has_one_spec(mod: ModuleType) -> None:
    specs: dict[str, object] = {}
    for c in mod.CONSUMERS:
        assert sorted(f.source for f in c.files) == ["fullchain", "key"], c.name
        assert c.action in ("restart", "reload", "try-restart")
        for f in c.files:
            assert specs.setdefault(f.path, f) == f, f"{f.path}: two consumers disagree on its owner/mode"
            assert f.path.startswith(c.directory.path + "/")


def test_consumers_sharing_files_are_one_group(mod: ModuleType) -> None:
    groups = mod.groups_of(list(mod.CONSUMERS))
    assert [[c.name for c in g] for g in groups] == [["hysteria"], ["nginx", "subscription"]]


def test_the_registry_matches_the_tracked_hooks_ownership() -> None:
    """deploy/vpn-bot-acme-reload.sh's defaults are the measured host: the registry must not drift from them."""
    hook = (Path(__file__).resolve().parents[1] / "deploy" / "vpn-bot-acme-reload.sh").read_text(encoding="utf-8")
    for line in ('TLS_GROUP="${TLS_GROUP:-vpn-bot}"', 'FULLCHAIN_MODE="${FULLCHAIN_MODE:-0640}"',
                 'PRIVKEY_MODE="${PRIVKEY_MODE:-0640}"', 'HYSTERIA_OWNER="${HYSTERIA_OWNER:-hysteria}"'):
        assert line in hook
    assert "-m 0644" in hook and "-m 0600" in hook


# --------------------------------------------------------------------------- #
# Adoption of the production setup
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("reloadcmd", ["", "systemctl restart hysteria-server", "/usr/local/sbin/acme-reload.sh"])
def test_adoption_of_the_prod_conf_leaves_one_reloadcmd_and_no_file_targets(host: CertHost, reloadcmd: str) -> None:
    """Le_RealFullChainPath=/etc/vpn-bot/tls/…, Le_ReloadCmd empty / partial / the old hook:
    afterwards acme.sh copies nothing itself and calls exactly `vpn-bot-cert deploy`. The
    certificate is NOT reissued."""
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64(reloadcmd) if reloadcmd else ""})
    host.lay_out(chain, key)
    host.token()
    host.write("/root/.acme.sh/account.conf", f"SAVED_CF_Token='{TOKEN}'\n", 0o600)
    rc, st = host.json("status")
    assert rc == 0 and st["candidate"] == DOMAIN and not st["adopted"]
    level = {p["key"]: p["level"] for p in st["problems"]}["reloadcmd"]
    assert level == ("yellow" if reloadcmd.endswith("acme-reload.sh") else "red")
    proc = host.cert("adopt")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    conf = host.conf()
    assert conf["Le_ReloadCmd"] == b64(RELOAD)
    assert all(conf[k] == "" for k in ("Le_RealCertPath", "Le_RealCACertPath", "Le_RealKeyPath", "Le_RealFullChainPath"))
    reloads = [k for k in conf if k == "Le_ReloadCmd"]
    assert reloads == ["Le_ReloadCmd"]
    assert [e for e in host.acme_log() if "--issue" in e.get("argv", []) or "--renew" in e.get("argv", [])] == []
    assert host.file("/root/.acme.sh/example.net_ecc/fullchain.cer").read_bytes() == chain
    # Every copy already equalled acme.sh's: nothing restarted, the state records it.
    assert host.actions() == []
    rc, st = host.json("status")
    assert st["adopted"] and st["domain"] == DOMAIN and st["verdict"] == "ok", st["problems"]
    assert all(c["took_current"] for c in st["consumers"] if c["installed"])


def test_adoption_fixes_a_reader_the_old_reloadcmd_left_behind(host: CertHost, tmp_path: Path) -> None:
    """The incident: the reloadcmd reached only a part of the readers — hysteria kept an
    old copy. Adoption lays the current pair out to it and restarts it, and only it."""
    chain, key = host.acme_domain(conf={"Le_ReloadCmd": b64("systemctl reload nginx")})
    old_chain, old_key = make_pair(tmp_path / "old", [DOMAIN], days=20)
    host.lay_out(chain, key, hysteria=(old_chain.read_bytes(), old_key.read_bytes()))
    rc, st = host.json("status")
    problems = {p["key"]: p["level"] for p in st["problems"]}
    assert problems["copy:hysteria"] == "yellow"
    rc, plan = host.json("adopt", "--dry-run")
    assert rc == 0
    assert {g["consumers"][0]: g["act"] for g in plan["groups"]} == {"hysteria": ["hysteria"], "nginx": []}
    assert any("Le_ReloadCmd" in d and RELOAD in d for d in plan["conf_diff"])
    assert host.conf()["Le_ReloadCmd"] == b64("systemctl reload nginx"), "a dry run changes nothing"
    assert host.cert("adopt").returncode == 0
    assert host.file(HY_CERT).read_bytes() == chain and host.file(HY_KEY).read_bytes() == key
    assert host.owner(HY_KEY) == ("hysteria", "hysteria") and host.mode(HY_KEY) == 0o600
    assert host.actions() == ["systemctl restart -- hysteria-server"]


def test_adopt_refuses_an_already_adopted_or_an_ambiguous_host(host: CertHost) -> None:
    adopted_host(host)
    proc = host.cert("adopt")
    assert proc.returncode == 3 and "already" in proc.stderr


def test_adopt_refuses_two_candidates(host: CertHost) -> None:
    host.acme_domain()
    host.acme_domain("other.example.net", conf={"Le_ReloadCmd": b64("/usr/local/sbin/acme-reload.sh"),
                                                "Le_RealFullChainPath": "", "Le_RealKeyPath": ""})
    proc = host.cert("adopt")
    assert proc.returncode == 3 and "more than one" in proc.stderr
    assert host.cert("adopt", "--domain", DOMAIN).returncode == 0
    assert host.conf()["Le_ReloadCmd"] == b64(RELOAD)


def test_adoption_refuses_a_pair_that_does_not_match(host: CertHost, tmp_path: Path) -> None:
    host.acme_domain()
    _, other_key = make_pair(tmp_path / "other", [DOMAIN])
    host.file("/root/.acme.sh/example.net_ecc/example.net.key").write_bytes(other_key.read_bytes())
    proc = host.cert("adopt")
    assert proc.returncode == 3 and "does not match" in proc.stderr
    assert host.conf()["Le_ReloadCmd"] == ""


# --------------------------------------------------------------------------- #
# deploy
# --------------------------------------------------------------------------- #
def test_deploy_lays_out_every_reader_with_its_owner_and_mode(host: CertHost) -> None:
    host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    proc = host.cert("deploy")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    chain = host.file("/root/.acme.sh/example.net_ecc/fullchain.cer").read_bytes()
    for path, owner, mode in ((TLS_CHAIN, ("root", "vpn-bot"), 0o640), (TLS_KEY, ("root", "vpn-bot"), 0o640),
                              (HY_CERT, ("hysteria", "hysteria"), 0o644), (HY_KEY, ("hysteria", "hysteria"), 0o600)):
        assert host.file(path).is_file(), path
        assert host.owner(path) == owner and host.mode(path) == mode, path
    assert host.file(TLS_CHAIN).read_bytes() == chain == host.file(HY_CERT).read_bytes()
    assert host.mode("/etc/vpn-bot/tls") == 0o755
    assert host.actions() == ["systemctl restart -- hysteria-server", "systemctl reload -- nginx",
                              "systemctl try-restart -- vpn-bot-subscription"]
    assert host.calls_of("nginx") == ["nginx -t -q"]
    leftovers = [p.name for p in host.file("/etc/vpn-bot/tls").iterdir() if "vpn-bot-cert" in p.name]
    assert leftovers == []
    # Again: nothing changed, nothing is restarted.
    host.reset_calls()
    assert host.cert("deploy").returncode == 0
    assert host.actions() == []


def test_a_renewal_reaches_every_reader(host: CertHost) -> None:
    """What acme.sh does on a renewal: new files in its own directory, then the reloadcmd
    from inside it with Le_Domain set — every installed reader gets the new pair."""
    adopted_host(host)
    host.json("deploy")
    new_chain, new_key = host.next_pair([DOMAIN])
    host.reset_calls()
    proc = host.cert("renew", "--force")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for path in (TLS_CHAIN, HY_CERT):
        assert host.file(path).read_bytes() == new_chain
    assert host.file(HY_KEY).read_bytes() == new_key
    assert sorted(host.actions()) == ["systemctl reload -- nginx", "systemctl restart -- hysteria-server",
                                      "systemctl try-restart -- vpn-bot-subscription"]


def test_a_failing_reader_gets_its_old_files_back_and_the_others_keep_the_new(host: CertHost) -> None:
    old_chain, old_key = adopted_host(host)
    host.json("deploy")  # the state: every reader took the current pair
    new_chain, new_key = host.next_pair([DOMAIN])
    host.flag("fail-restart-hysteria-server")
    host.reset_calls()
    proc = host.cert("renew", "--force")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    # hysteria: rolled back to the old pair, restarted again on it.
    assert host.file(HY_CERT).read_bytes() == old_chain and host.file(HY_KEY).read_bytes() == old_key
    assert host.owner(HY_KEY) == ("hysteria", "hysteria") and host.mode(HY_KEY) == 0o600
    assert host.actions().count("systemctl restart -- hysteria-server") == 2
    # nginx + subscription: the new pair, reloaded / try-restarted once.
    assert host.file(TLS_CHAIN).read_bytes() == new_chain and host.file(TLS_KEY).read_bytes() == new_key
    assert host.actions().count("systemctl reload -- nginx") == 1
    leftovers = [p.name for p in host.file("/etc/hysteria").iterdir() if "vpn-bot-cert" in p.name]
    assert leftovers == []
    _, st = host.json("status")
    hy = next(c for c in st["consumers"] if c["name"] == "hysteria")
    assert hy["in_sync"] is False and hy["took_current"] is False
    assert {p["key"] for p in st["problems"]} >= {"copy:hysteria"}
    # The next deploy (the fix, or the next renewal) tries it again.
    (host.sd / "fail-restart-hysteria-server").unlink()
    host.reset_calls()
    assert host.cert("deploy").returncode == 0
    assert host.file(HY_CERT).read_bytes() == new_chain
    assert host.actions() == ["systemctl restart -- hysteria-server"]


def test_a_reader_that_dies_after_its_restart_is_rolled_back(host: CertHost) -> None:
    old_chain, _ = adopted_host(host)
    host.next_pair([DOMAIN])
    host.flag("dies-hysteria-server")
    rc, report = host.json("renew", "--force")
    assert rc == 1
    group = next(g for g in report["groups"] if g["consumers"] == ["hysteria"])
    assert group["result"] == "rolled_back" and "not active" in group["error"]
    assert host.file(HY_CERT).read_bytes() == old_chain


def test_nginx_t_failing_rolls_back_its_group_and_never_reloads(host: CertHost) -> None:
    old_chain, _ = adopted_host(host)
    new_chain, _ = host.next_pair([DOMAIN])
    host.flag("nginx-t-fails")
    host.reset_calls()
    rc, report = host.json("renew", "--force")
    assert rc == 1
    tls = next(g for g in report["groups"] if g["consumers"] == ["nginx", "subscription"])
    assert tls["result"] == "rolled_back" and "nginx -t" in tls["error"]
    assert host.file(TLS_CHAIN).read_bytes() == old_chain
    assert "systemctl reload -- nginx" not in host.actions()
    assert host.file(HY_CERT).read_bytes() == new_chain  # the other group keeps the new pair


def test_deploy_checks_acme_shs_pair_before_touching_anything(host: CertHost, tmp_path: Path) -> None:
    adopted_host(host)
    _, other_key = make_pair(tmp_path / "x", [DOMAIN])
    before = host.file(HY_CERT).read_bytes()
    host.file("/root/.acme.sh/example.net_ecc/example.net.key").write_bytes(other_key.read_bytes())
    host.reset_calls()
    proc = host.cert("deploy")
    assert proc.returncode == 3 and "does not match" in proc.stderr
    assert host.file(HY_CERT).read_bytes() == before and host.actions() == []


def test_deploy_refuses_a_certificate_that_does_not_cover_the_domains_names(host: CertHost) -> None:
    host.acme_domain(alt=["www.example.net"], conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "",
                                                    "Le_ReloadCmd": b64(RELOAD)})
    host.file("/root/.acme.sh/example.net_ecc/example.net.conf").write_text(
        host.file("/root/.acme.sh/example.net_ecc/example.net.conf").read_text(encoding="utf-8")
        .replace("Le_Alt='www.example.net'", "Le_Alt='www.example.net,api.example.net'"), encoding="utf-8")
    proc = host.cert("deploy")
    assert proc.returncode == 3 and "api.example.net" in proc.stderr


def test_a_reader_whose_module_is_not_installed_is_left_alone(host: CertHost) -> None:
    host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.write("/etc/vpn-bot/uninstalled/hysteria2", "")
    host.units("nginx")  # no vpn-bot-subscription unit on this host
    rc, report = host.json("deploy")
    assert rc == 0
    assert {s["consumer"]: s["why"] for s in report["skipped"]} == {
        "hysteria": "removed from this host (marker /etc/vpn-bot/uninstalled/hysteria2)",
        "subscription": "vpn-bot-subscription is not installed",
    }
    assert not host.file(HY_CERT).exists()
    assert host.actions() == ["systemctl reload -- nginx"]


def test_a_stopped_subscription_endpoint_is_never_started(host: CertHost) -> None:
    adopted_host(host)
    (host.sd / "active" / "vpn-bot-subscription").unlink()
    host.next_pair([DOMAIN])
    assert host.cert("renew", "--force").returncode == 0
    assert "systemctl try-restart -- vpn-bot-subscription" in host.actions()
    assert "systemctl restart -- vpn-bot-subscription" not in host.actions()


def test_deploy_all_acts_on_every_reader_and_dry_run_changes_nothing(host: CertHost) -> None:
    adopted_host(host)
    host.json("deploy")
    host.reset_calls()
    rc, plan = host.json("deploy", "--all", "--dry-run")
    assert rc == 0 and [g["act"] for g in plan["groups"]] == [["hysteria"], ["nginx", "subscription"]]
    assert host.actions() == []
    assert host.cert("deploy", "--all").returncode == 0
    assert len(host.actions()) == 3


def test_deploy_repairs_permissions_without_restarting(host: CertHost) -> None:
    adopted_host(host)
    host.json("deploy")
    host.file(TLS_KEY).chmod(0o644)
    host.set_owner(TLS_KEY, "root", "root")
    _, st = host.json("status")
    assert any(p["key"] == "perms:nginx" for p in st["problems"])
    host.reset_calls()
    assert host.cert("deploy").returncode == 0
    assert host.mode(TLS_KEY) == 0o640 and host.owner(TLS_KEY) == ("root", "vpn-bot")
    assert host.actions() == []


def test_deploy_without_an_adopted_domain_refuses(host: CertHost) -> None:
    host.acme_domain()
    proc = host.cert("deploy")
    assert proc.returncode == 3 and "adopt it first" in proc.stderr


# --------------------------------------------------------------------------- #
# issue / renew with the bot's token
# --------------------------------------------------------------------------- #
def test_issue_uses_the_bots_token_only_in_the_environment(host: CertHost) -> None:
    host.token()
    new_chain, _ = host.next_pair([DOMAIN, "www.example.net"])
    proc = host.cert("issue", "--names", "example.net,www.example.net", "--zone", ZONE)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    log = host.acme_log()
    issued = next(e for e in log if "--issue" in e.get("argv", []))
    assert issued["cf_token_fp"] == fp(TOKEN) and issued["cf_zone"] == ZONE_ID
    assert all(TOKEN not in " ".join(e.get("argv", [])) for e in log)
    argv = issued["argv"]
    assert argv[argv.index("--dns") + 1] == "dns_cf" and argv[argv.index("--server") + 1] == "letsencrypt"
    assert "--force" in argv and argv[argv.index("--keylength") + 1] == "ec-256"
    install = next(e for e in log if "--install-cert" in e.get("argv", []))
    assert install["argv"][install["argv"].index("--reloadcmd") + 1] == RELOAD and install["nested"]
    assert not any(flag in install["argv"] for flag in ("--key-file", "--fullchain-file", "--cert-file"))
    assert host.conf()["Le_ReloadCmd"] == b64(RELOAD)
    assert host.file(HY_CERT).read_bytes() == new_chain == host.file(TLS_CHAIN).read_bytes()
    assert TOKEN not in proc.stdout + proc.stderr


def test_issue_reissues_the_adopted_domain_and_refuses_a_name_change(host: CertHost) -> None:
    adopted_host(host)
    host.token()
    host.next_pair([DOMAIN])
    proc = host.cert("issue", "--names", "other.example.net", "--zone", ZONE)
    assert proc.returncode == 3 and "domain change" in proc.stderr
    new_chain, _ = host.next_pair([DOMAIN, f"www.{DOMAIN}"])
    proc = host.cert("issue", "--names", f"www.{DOMAIN},{DOMAIN}", "--zone", ZONE)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    issued = next(e for e in host.acme_log() if "--issue" in e.get("argv", []) and e["argv"].count("-d") == 2)
    assert issued["argv"][issued["argv"].index("-d") + 1] == DOMAIN  # the certificate's name stays first
    assert host.conf()["Le_Alt"] == f"www.{DOMAIN}" and host.file(HY_CERT).read_bytes() == new_chain


@pytest.mark.parametrize(("mode", "owner"), [(0o644, ("vpn-bot", "vpn-bot")), (0o600, ("nobody", "nogroup"))])
def test_issue_refuses_a_token_file_that_is_not_private(host: CertHost, mode: int, owner: tuple[str, str]) -> None:
    host.token(mode=mode, owner=owner)
    host.next_pair([DOMAIN])
    proc = host.cert("issue", "--names", DOMAIN, "--zone", ZONE)
    assert proc.returncode == 3 and "not private" in proc.stderr
    assert host.acme_log() == []


def test_issue_without_a_token_or_with_bad_arguments_refuses(host: CertHost) -> None:
    proc = host.cert("issue", "--names", DOMAIN, "--zone", ZONE)
    assert proc.returncode == 3 and "no Cloudflare token" in proc.stderr
    host.token()
    for names, zone in (("bad name!", ZONE), (DOMAIN, "not a zone"), (",".join(f"n{i}.example.net" for i in range(11)), ZONE),
                        ("other.example.org", ZONE), (DOMAIN, "unknown.example")):
        assert host.cert("issue", "--names", names, "--zone", zone).returncode == 3
    assert host.acme_log() == []


def test_renew_switches_acme_to_the_bots_token_first(host: CertHost) -> None:
    host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.write("/root/.acme.sh/account.conf", "SAVED_CF_Token='old_token_0123456789abcdef'\n", 0o600)
    host.token()
    _, st = host.json("status")
    dom = st["domains"][0]
    assert dom["token"] == {"source": "account", "fp": fp("old_token_0123456789abcdef"), "zone": None}
    assert any(p["key"] == "token" for p in st["problems"])
    host.next_pair([DOMAIN])
    assert host.cert("renew", "--force", "--zone", ZONE).returncode == 0
    renewed = next(e for e in host.acme_log() if "renew_with_conf_token_fp" in e)
    assert renewed == {"renew_with_conf_token_fp": fp(TOKEN), "renew_zone": ZONE_ID}
    _, st = host.json("status")
    assert st["domains"][0]["token"]["fp"] == st["token"]["fp"] == fp(TOKEN)
    assert not any(p["key"] == "token" for p in st["problems"])


def test_a_failed_acme_run_changes_no_reader(host: CertHost) -> None:
    adopted_host(host)
    host.json("deploy")
    before = host.file(HY_CERT).read_bytes()
    host.token()
    host.flag("acme-fail")
    host.reset_calls()
    proc = host.cert("renew", "--force")
    assert proc.returncode == 5 and "acme.sh --renew failed" in proc.stderr
    assert host.file(HY_CERT).read_bytes() == before and host.actions() == []


def test_acme_is_installed_from_the_pinned_release_only(host: CertHost, tmp_path: Path) -> None:
    host.file("/root/.acme.sh/acme.sh").unlink()
    src = tmp_path / "acme-src"
    (src / "dnsapi").mkdir(parents=True)
    installer = (
        "#!/bin/sh\n"
        'home=""; while [ $# -gt 0 ]; do [ "$1" = "--home" ] && home="$2"; shift; done\n'
        'mkdir -p "$home" && cp "$SD/fake-acme-wrapper" "$home/acme.sh" && chmod 755 "$home/acme.sh"\n'
    )
    (src / "acme.sh").write_text(installer, encoding="utf-8")
    (src / "dnsapi" / "dns_cf.sh").write_text("dns_cf_add() { :; }\n", encoding="utf-8")
    wrapper = host.sd / "fake-acme-wrapper"
    wrapper.write_text(f'#!/bin/bash\nVER=3.1.1\nexec {sys.executable} {host.sd / "fake_acme.py"} "$@"\n', encoding="utf-8")
    host.token()
    host.next_pair([DOMAIN])
    # The pins are the real release's: a copy that is not it is refused.
    proc = host.cert("issue", "--names", DOMAIN, "--zone", ZONE, VPN_BOT_CERT_SELFTEST_ACME_SRC=str(src))
    assert proc.returncode == 3 and "is not the pinned" in proc.stderr
    assert not host.file("/root/.acme.sh/acme.sh").exists()
    import hashlib

    pins = {rel: hashlib.sha256((src / rel).read_bytes()).hexdigest() for rel in ("acme.sh", "dnsapi/dns_cf.sh")}
    proc = host.cert("issue", "--names", DOMAIN, "--zone", ZONE, VPN_BOT_CERT_SELFTEST_ACME_SRC=str(src),
                     VPN_BOT_CERT_SELFTEST_ACME_PINS=json.dumps(pins))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert any("--set-default-ca" in e.get("argv", []) for e in host.acme_log())
    assert [ln for ln in host.calls_of("sh") if "--install" in ln]


def test_the_pins_are_a_real_release(mod: ModuleType) -> None:
    assert mod.ACME_VERSION == "3.1.1"
    for rel, (url, digest) in mod.ACME_FILES.items():
        assert url == f"https://raw.githubusercontent.com/acmesh-official/acme.sh/3.1.1/{rel}"
        assert len(digest) == 64 and digest == digest.lower()


# --------------------------------------------------------------------------- #
# status and its judgments
# --------------------------------------------------------------------------- #
def test_status_judges_the_expiry_and_the_missing_cron(host: CertHost) -> None:
    host.acme_domain(days=5, conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "", "Le_ReloadCmd": b64(RELOAD)})
    host.file("/var/spool/cron/crontabs/root").unlink()
    _, st = host.json("status")
    problems = {p["key"]: p["level"] for p in st["problems"]}
    assert problems["expiry"] == "red" and problems["cron"] == "red" and st["verdict"] == "fail"


def test_status_flags_another_domain_writing_the_registrys_files(host: CertHost) -> None:
    adopted_host(host)
    host.acme_domain("old.example.net", conf={"Le_ReloadCmd": ""})
    _, st = host.json("status")
    assert any(p["key"] == "writer" and p["level"] == "red" for p in st["problems"])


def test_status_says_what_a_reader_actually_reads(host: CertHost) -> None:
    adopted_host(host)
    host.write("/etc/hysteria/config.yaml", "tls:\n  cert: /etc/letsencrypt/live/x/fullchain.pem\n  key: /etc/hysteria/key.pem\n")
    # sites-enabled holds a symlink to sites-available, as nginx's packaging lays it out.
    host.write("/etc/nginx/sites-available/decoy", "ssl_certificate /etc/vpn-bot/tls/fullchain.pem;\n"
                                                   "ssl_certificate_key /etc/nginx/other.key;\n")
    host.file("/etc/nginx/sites-enabled").mkdir(parents=True)
    host.file("/etc/nginx/sites-enabled/decoy").symlink_to("../sites-available/decoy")
    # A link out of /etc/nginx is never followed.
    outside = host.write("/srv/other.conf", "ssl_certificate /srv/elsewhere.pem;\n")
    host.file("/etc/nginx/sites-enabled/outside").symlink_to(outside)
    _, st = host.json("status")
    keys = {p["key"] for p in st["problems"]}
    assert {"reads:hysteria", "reads:nginx"} <= keys
    nginx = next(c for c in st["consumers"] if c["name"] == "nginx")
    assert "/etc/nginx/other.key" in nginx["reads"] and "/srv/elsewhere.pem" not in nginx["reads"]


def test_nginx_reading_only_the_registrys_files_is_fine(host: CertHost) -> None:
    adopted_host(host)
    host.write("/etc/nginx/sites-available/decoy", "  ssl_certificate /etc/vpn-bot/tls/fullchain.pem;\n"
                                                   "  ssl_certificate_key /etc/vpn-bot/tls/privkey.pem;\n")
    host.file("/etc/nginx/sites-enabled").mkdir(parents=True)
    host.file("/etc/nginx/sites-enabled/decoy").symlink_to("../sites-available/decoy")
    _, st = host.json("status")
    nginx = next(c for c in st["consumers"] if c["name"] == "nginx")
    assert nginx["reads_ok"] is True


def test_selftest_refuses_commands_that_are_not_stubs_and_needs_root(host: CertHost, mod: ModuleType) -> None:
    ctx = mod.Ctx(root=str(host.root))
    rc, out = mod.run(ctx, ["true"])
    assert rc == 127 and "refused" in out
    with pytest.raises(mod.Cannot):
        mod.fence(ctx, Path("/etc/passwd"))
    import subprocess

    proc = subprocess.run([sys.executable, "-I", str(HELPER), "status"], capture_output=True, text=True,
                          env={"VPN_BOT_CERT_SELFTEST": "1", "PATH": "/usr/bin:/bin"}, check=False)
    assert proc.returncode == 2 and "needs --root" in proc.stderr


def test_conf_parsing_decodes_acmes_base64_values(mod: ModuleType) -> None:
    conf = mod.parse_conf(f"Le_Domain='a.example'\nLe_ReloadCmd='{b64('x y')}'\nexport X=\"q\"\n")
    assert conf == {"Le_Domain": "a.example", "Le_ReloadCmd": "x y", "X": "q"}
    assert mod.reload_kind(RELOAD) == "ours" and mod.reload_kind("vpn-bot-cert   deploy") == "ours"
    assert mod.reload_kind("/usr/local/sbin/acme-reload.sh") == "legacy"
    assert mod.reload_kind("systemctl restart hysteria-server") == "other" and mod.reload_kind("") == "empty"
    assert mod.covers(["*.example.net"], "a.example.net") and not mod.covers(["*.example.net"], "a.b.example.net")


def test_issue_renew_and_adopt_wait_for_an_acme_cron_run(host: CertHost) -> None:
    """acme.sh takes no lock and its cron does not take vpn-bot-cert's: while another
    acme.sh process runs, the helper does not start one of its own (waits, then refuses)."""
    adopted_host(host)
    host.token()
    host.write("/proc/4242/cmdline", b"sh\0/root/.acme.sh/acme.sh\0--cron\0--home\0/root/.acme.sh\0")
    host.write("/proc/4243/cmdline", b"/usr/bin/python3\0-m\0something.else\0")
    for args in (("renew", "--force"), ("issue", "--names", DOMAIN, "--zone", ZONE)):
        proc = host.cert(*args)
        assert proc.returncode == 3 and "acme.sh is running already" in proc.stderr and "4242" in proc.stderr
    assert host.acme_log() == []
    host.file("/proc/4242/cmdline").unlink()
    host.next_pair([DOMAIN])
    assert host.cert("renew", "--force").returncode == 0


def test_acme_cron_holds_off_the_domain_while_the_helper_works_on_it(host: CertHost) -> None:
    """acme.sh --cron renews only a domain whose Le_NextRenewTime has passed: while the
    helper's own acme.sh runs, the domain's is an hour ahead — a cron run that starts then
    skips it —, and afterwards it is acme.sh's new value, or the old one put back."""
    import time

    old_due = str(int(time.time()) - 100)  # due NOW: exactly when cron would race
    chain, key = host.acme_domain(conf={"Le_RealKeyPath": "", "Le_RealFullChainPath": "",
                                        "Le_ReloadCmd": b64(RELOAD), "Le_NextRenewTime": old_due})
    host.lay_out(chain, key)
    host.token()
    host.next_pair([DOMAIN])
    assert host.cert("renew", "--force", "--zone", ZONE).returncode == 0
    during = next(e for e in host.acme_log() if e.get("renew"))
    assert int(during["next_renew_at_call"]) >= int(time.time()) + 3000
    after = int(host.conf()["Le_NextRenewTime"])
    assert after > int(time.time()) + 50 * 86400, "acme.sh's own new value is kept"
    # A renewal that fails puts the old value back (cron renews it as before).
    conf = host.file("/root/.acme.sh/example.net_ecc/example.net.conf")
    conf.write_text(conf.read_text(encoding="utf-8").replace(f"Le_NextRenewTime='{after}'",
                                                             f"Le_NextRenewTime='{old_due}'"), encoding="utf-8")
    host.flag("acme-fail")
    assert host.cert("renew", "--force").returncode == 5
    assert host.conf()["Le_NextRenewTime"] == old_due


def test_adoption_holds_cron_off_and_puts_the_time_back(host: CertHost) -> None:
    import time

    old_due = str(int(time.time()) - 5)
    chain, key = host.acme_domain(conf={"Le_NextRenewTime": old_due})
    host.lay_out(chain, key)
    assert host.cert("adopt").returncode == 0
    during = next(e for e in host.acme_log() if e.get("install_cert"))
    assert int(during["next_renew_at_call"]) >= int(time.time()) + 3000
    assert host.conf()["Le_NextRenewTime"] == old_due


def test_nginx_with_another_vhost_still_reads_the_registry(host: CertHost) -> None:
    """Another vhost with a certificate of its own is a finding (reads_ok false), not a
    reader that misses the registry's pair (reads_registry stays true)."""
    adopted_host(host)
    host.write("/etc/nginx/conf.d/decoy.conf", "ssl_certificate /etc/vpn-bot/tls/fullchain.pem;\n"
                                               "ssl_certificate_key /etc/vpn-bot/tls/privkey.pem;\n")
    host.write("/etc/nginx/conf.d/other.conf", "ssl_certificate /srv/other/fullchain.pem;\n"
                                               "ssl_certificate_key /srv/other/privkey.pem;\n")
    _, st = host.json("status")
    nginx = next(c for c in st["consumers"] if c["name"] == "nginx")
    assert nginx["reads_ok"] is False and nginx["reads_registry"] is True
    host.write("/etc/nginx/conf.d/decoy.conf", "ssl_certificate /srv/other/fullchain.pem;\n")
    _, st = host.json("status")
    nginx = next(c for c in st["consumers"] if c["name"] == "nginx")
    assert nginx["reads_registry"] is False
