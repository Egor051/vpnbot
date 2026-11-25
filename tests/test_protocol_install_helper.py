"""scripts/vpn-bot-protocol-install — installing a protocol from the bot (docs/protocol-install.md).

Every case runs the REAL helper on a fake host (tests/install_fakes.py): every path under a
temporary root, every privileged tool a stub, the release from a local fixture — no network,
nothing that listens on the host's loopback is ever asked. The symmetry and reinstall cases
run the REAL deploy/helpers/vpn-bot-protocol-uninstall on the same root.
"""

from __future__ import annotations

import asyncio
import importlib.machinery
import importlib.util
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from install_fakes import ASSET, DOMAIN, HELPER, ROOT, UNINSTALL, InstallHost

pytestmark = [pytest.mark.timeout(240)]

EXIT_REFUSED, EXIT_VERIFY, EXIT_ROLLED_BACK = 3, 4, 6


def _load_helper() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("vpn_bot_protocol_install", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


PI = _load_helper()


@pytest.fixture
def host(tmp_path: Path) -> InstallHost:
    return InstallHost(tmp_path)


# --------------------------------------------------------------------------- #
# The manifest: what the install owns is exactly what the uninstall removes
# --------------------------------------------------------------------------- #
def _forbidden(path: str) -> bool:
    """The uninstall helper's path_forbidden(), read from its own deny-list."""
    text = UNINSTALL.read_text(encoding="utf-8")

    def words(name: str) -> list[str]:
        m = re.search(rf'readonly {name}="([^"]*)"', text, re.S)
        assert m, name
        return m.group(1).split()

    exact, trees = words("FORBIDDEN_EXACT"), words("FORBIDDEN_TREES")
    return path in exact or any(path == t or path.startswith(t + "/") for t in trees)


@pytest.mark.parametrize("proto", sorted(PI.MANIFESTS))
def test_install_manifest_is_symmetric_to_the_uninstall_manifest(host: InstallHost, proto: str) -> None:
    mine = json.loads(host.helper("manifest", proto, "--json").stdout)
    proc = host.uninstall("manifest", proto)
    assert proc.returncode == 0, proc.stderr
    theirs = json.loads(proc.stdout.strip().splitlines()[-1])
    assert set(mine["units"]) == {u["unit"] for u in theirs["units"]}
    assert set(mine["unit_files"]) == set(theirs["unit_files"])
    assert set(mine["paths"]) == set(theirs["paths"])
    assert set(mine["packages"]) == set(theirs["packages"])
    assert set(mine["users"]) == set(theirs["users"])
    assert mine["env_key"] == theirs["env_key"]
    assert mine["marker"] == f"/etc/vpn-bot/uninstalled/{proto}"
    # What it shares, the uninstall names as shared and never removes.
    shared_text = " | ".join(s["what"] for s in theirs["skipped_shared"])
    for shared in mine["shared"]:
        assert shared["what"] in shared_text, shared["what"]
        for path in shared["paths"]:
            assert _forbidden(path), f"{path} is shared but the uninstall's deny-list does not protect it"
    # The settings written to .env are not the flag the uninstall turns off.
    assert mine["env_key"] not in mine["env_settings"]


def test_every_path_the_helper_writes_is_in_the_manifest_or_shared() -> None:
    """The step functions write only what the manifest names (owned) or shares, plus .env,
    the marker and the helper's own state — a new write without a manifest entry fails here."""
    man = PI.MANIFESTS["xray"]
    allowed = set(man.unit_files) | set(man.paths) | {p for s in man.shared for p in s.paths}
    written = {PI.XRAY_BIN, PI.XRAY_SHARE, PI.XRAY_ETC, PI.XRAY_CONFIG, PI.XRAY_LOG_DIR, PI.NGINX_SITE_CONF, PI.SITE_ROOT,
               *(p.rsplit("/", 1)[0] if p.endswith(".conf") else p for p in PI.xray_unit_sources(
                   SimpleNamespace(repo=ROOT)))}
    for path in written:
        assert any(path == a or path.startswith(a + "/") for a in allowed), path


def test_installed_probes_are_the_bots() -> None:
    from services.protocol_install import HOST_PROBES, INSTALLABLE

    assert set(INSTALLABLE) == set(PI.PROTOCOLS)
    for proto in PI.PROTOCOLS:
        assert tuple(HOST_PROBES[proto]) == PI.installed_probes(proto)


def test_mode_choices_are_the_helpers_protocols() -> None:
    from services.wizard_modes import MODES

    assert set(MODES["protocol"].params["proto"].choices) == set(PI.PROTOCOLS)


# --------------------------------------------------------------------------- #
# A fresh host: plan, apply, verify
# --------------------------------------------------------------------------- #
def test_fresh_host_plan_names_every_change_and_is_stable(host: InstallHost) -> None:
    plan = host.plan()
    assert plan["ok"] and plan["state"] == "absent" and not plan["blocking"]
    acts = {(c["step"], c["target"]) for c in plan["changes"] if c["action"] not in ("keep", "skip")}
    assert ("nginx_pkg", "nginx") in acts and ("xray_config", PI.XRAY_CONFIG) in acts
    assert ("cert", "vpn-bot-cert deploy") in acts
    env = {e["key"]: e["new"] for e in plan["env"]}
    assert env["XRAY_SNI"] == DOMAIN and env["XRAY_PUBLIC_HOST"] == DOMAIN and env["XRAY_REALITY_PUBLIC_KEY"] == "<generated>"
    assert "XRAY_INBOUND_TAG" not in env, "a key already right is not rewritten"
    assert host.plan()["sha256"] == plan["sha256"]
    assert not host.file(PI.XRAY_BIN).exists(), "a plan changes nothing"


def test_fresh_install_lays_out_the_production_layout(host: InstallHost) -> None:
    env_before = host.file("/opt/vpn-service/.env").read_text()
    rc, res = host.install()
    assert rc == 0 and res["ok"], res
    # nginx: installed with policy-rc.d holding it (no :80), its default site off, then ours.
    assert (host.st / "policy_rc_d_at_install").read_text() == "held"
    assert not (host.st / "bound_80").exists()
    assert not host.file("/usr/sbin/policy-rc.d").exists(), "policy-rc.d is removed again"
    assert not host.file("/etc/nginx/sites-enabled/default").is_symlink()
    conf = host.file(PI.NGINX_SITE_CONF).read_text()
    assert "listen 127.0.0.1:8443 ssl http2;" in conf and f"server_name {DOMAIN};" in conf
    assert "ssl_protocols TLSv1.3;" in conf and "/etc/vpn-bot/tls/fullchain.pem" in conf
    assert "@" not in conf.replace("@SITE", "")
    assert host.file("/var/www/selfsteal/index.html").is_file()
    # xray: the upstream layout.
    assert host.file(PI.XRAY_BIN).stat().st_mode & 0o777 == 0o755
    assert host.file("/etc/systemd/system/xray.service.d/10-donot_touch_single_conf.conf").is_file()
    assert host.file(PI.XRAY_CONFIG).stat().st_mode & 0o777 == 0o640
    owners = host.owners()
    assert owners[PI.XRAY_CONFIG] == "nobody:nogroup", "the root model: no vpn-bot group"
    assert owners["/var/log/xray"] == "nobody:nogroup"
    assert host.units()["xray.service"] == {"active": "active", "enabled": "enabled"}
    # .env: exactly the planned keys changed, every other line byte for byte; mode kept.
    after = host.file("/opt/vpn-service/.env").read_text()
    changed = {a.split("=", 1)[0] for a, b in zip(after.splitlines(), env_before.splitlines(), strict=True) if a != b}
    assert changed == {"XRAY_PUBLIC_HOST", "XRAY_SNI", "XRAY_REALITY_PUBLIC_KEY", "XRAY_SHORT_ID", "XRAY_XHTTP_ENABLED"}
    assert host.file("/opt/vpn-service/.env").stat().st_mode & 0o777 == 0o600
    # The backup holds .env as it was, before the write.
    archive = host.file(res["backup"])
    assert archive.stat().st_mode & 0o777 == 0o600
    with tarfile.open(archive) as tar:
        member = tar.extractfile("opt/vpn-service/.env")
        assert member is not None and member.read().decode() == env_before
    # The private key never reaches the log or the report.
    priv = json.loads(host.file(PI.XRAY_CONFIG).read_text())["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
    assert priv not in host.file("/var/log/vpn-bot-protocol-install.log").read_text()
    assert priv not in json.dumps(res)
    verify = host.helper("verify", "xray", "--json")
    assert verify.returncode == 0, verify.stdout
    assert all(c["ok"] for c in host.json_of(verify)["checks"])
    status = json.loads(host.helper("status", "--json").stdout)
    assert status["protocols"]["xray"]["state"] == "installed"


def test_config_group_is_the_bots_where_it_exists(host: InstallHost) -> None:
    host.file("/etc/group").write_text("root:x:0:\nnogroup:x:65534:\nvpn-bot:x:990:\n")
    rc, _ = host.install()
    assert rc == 0
    assert host.owners()[PI.XRAY_CONFIG] == "nobody:vpn-bot"


def test_a_second_apply_is_nothing_to_do(host: InstallHost) -> None:
    assert host.install()[0] == 0
    plan = host.plan()
    assert plan["nothing_to_do"] and plan["state"] == "installed"
    rc, res = host.install()
    assert rc == 0 and res.get("nothing_to_do")


def test_apply_refuses_a_plan_that_changed(host: InstallHost) -> None:
    sha = host.plan()["sha256"]
    host.file("/usr/local/bin/xray").write_text("operator's xray")
    before = host.snapshot()
    proc = host.helper("apply", "xray", "--expect-plan", sha, "--json")
    assert proc.returncode == EXIT_REFUSED
    assert host.json_of(proc)["error"] == "plan_changed"
    assert host.snapshot() == before


def test_no_certificate_blocks_the_plan(host: InstallHost) -> None:
    host.cert(adopted=False)
    proc = host.helper("plan", "xray", "--json")
    assert proc.returncode == EXIT_REFUSED
    assert any("no certificate" in b for b in host.json_of(proc)["blocking"])


@pytest.mark.parametrize(("san", "days", "words"), [
    (["other.example.com"], 80.0, "does not cover"),
    ([DOMAIN], 3.0, "renew it first"),
])
def test_an_unusable_certificate_blocks(host: InstallHost, san: list[str], days: float, words: str) -> None:
    host.cert(san=san, days=days)
    blocking = host.json_of(host.helper("plan", "xray", "--domain", DOMAIN, "--json"))["blocking"]
    assert any(words in b for b in blocking), blocking


def test_an_env_that_contradicts_the_skeleton_blocks(host: InstallHost) -> None:
    env = host.file("/opt/vpn-service/.env")
    env.write_text(env.read_text().replace("XRAY_INBOUND_TAG=vless-in", "XRAY_INBOUND_TAG=main"))
    blocking = host.plan()["blocking"]
    assert any("XRAY_INBOUND_TAG=main" in b for b in blocking)


def test_existing_xray_and_config_are_kept(host: InstallHost) -> None:
    host.file(PI.XRAY_BIN).write_text("operator's xray")
    host.file(PI.XRAY_ETC).mkdir()
    live = {"inbounds": [{"tag": "vless-in", "settings": {"clients": [{"id": "a"}]}}]}
    host.file(PI.XRAY_CONFIG).write_text(json.dumps(live))
    plan = host.plan()
    kept = {c["target"] for c in plan["changes"] if c["action"] == "keep"}
    assert {PI.XRAY_BIN, PI.XRAY_CONFIG} <= kept
    assert not plan["env"], "the live config's keys are not known here: .env is left alone"
    assert plan["state"] == "partial"


def test_a_foreign_selfsteal_vhost_is_kept(host: InstallHost) -> None:
    host.file("/etc/nginx/conf.d").mkdir(parents=True)
    host.file("/etc/nginx/conf.d/site.conf").write_text("server {\n  listen 127.0.0.1:8443 ssl http2;\n}\n")
    plan = host.plan()
    assert any(c["target"] == PI.NGINX_SITE_CONF and c["action"] == "skip" for c in plan["changes"])
    assert any("already serves" in w for w in plan["warnings"])


def test_warp_proxy_egress_binds_the_freedom_outbound(host: InstallHost) -> None:
    host.file("/etc/amnezia").mkdir(parents=True)
    host.file("/etc/amnezia/out-warp.conf").write_text("[Interface]\nAddress = fd00::2/128, 172.16.0.2/32\n")
    env = host.file("/opt/vpn-service/.env")
    env.write_text(env.read_text() + "WARP_PROXY_EGRESS_ENABLED=true\n")
    assert host.install()[0] == 0
    config = json.loads(host.file(PI.XRAY_CONFIG).read_text())
    freedom = [o for o in config["outbounds"] if o["protocol"] == "freedom"]
    assert freedom and all(o["sendThrough"] == "172.16.0.2" for o in freedom)


# --------------------------------------------------------------------------- #
# The generated config passes the bot's reconcile without a change
# --------------------------------------------------------------------------- #
def test_generated_config_passes_the_bots_reconcile_unchanged(host: InstallHost, tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    from adapters.backup import BackupAdapter
    from adapters.clock import ClockProvider
    from adapters.xray_config import XrayConfigAdapter, apply_warp_send_through, vless_inbound_present, vless_reality_inbound_present
    from config.settings import load_settings
    from db.database import Database
    from repositories.vpn_keys import VpnKeyRepository
    from services.xray import XrayService

    assert host.install()[0] == 0
    path = host.file(PI.XRAY_CONFIG)
    raw = path.read_bytes()
    env = host.env_values()
    config = json.loads(raw)
    # 1. The bot's own serializer writes these very bytes back.
    assert (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode() == raw
    # 2. Its WARP re-assertion has nothing to change (WARP off here).
    assert apply_warp_send_through(json.loads(raw), None) is False
    # 3. The inbounds the bot builds its adapters from.
    assert vless_reality_inbound_present(path, env["XRAY_INBOUND_TAG"])
    assert vless_inbound_present(path, env["XRAY_XHTTP_INBOUND_TAG"])
    # 4. The deploy's drift check against the skeleton: no structural finding.
    proc = subprocess.run([sys.executable, str(ROOT / "deploy" / "backend-config-sync.py"), "check",
                           "--xray-config", str(path), "--awg-config", str(tmp_path / "none.conf"),
                           "--hysteria-config", str(tmp_path / "none.yaml")],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # 5. The settings the bot loads from that .env are ready for keys.
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("XRAY_CONFIG_PATH", str(path))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "vpn.db"))
    monkeypatch.setenv("LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("BOT_LOCK_PATH", str(tmp_path / "bot.lock"))
    monkeypatch.setenv("AWG_CONFIG_PATH", str(tmp_path / "awg.conf"))
    monkeypatch.setenv("BOT_TOKEN", "123456:" + "A" * 35)
    settings = load_settings()
    settings.validate_xray_ready()

    # 6. The startup reconcile (no keys yet) and the shortId check write nothing.
    class _Systemctl:
        async def xray_test_config(self, _path: Path) -> Any:
            return SimpleNamespace(ok=True)

        async def reload(self, *_: Any) -> None:
            raise AssertionError("the reconcile must not touch xray")

        restart = reload

    def adapter(tag: str, reality: bool) -> XrayConfigAdapter:
        return XrayConfigAdapter(config_path=path, service_name="xray", apply_mode="reload", inbound_tag=tag,
                                 allow_restart_on_rollback=False, backup=BackupAdapter(ClockProvider(), keep_last=0),
                                 systemctl=_Systemctl(), require_reality=reality)  # type: ignore[arg-type]

    async def run() -> None:
        db = Database(tmp_path / "vpn.db")
        await db.connect()
        await db.bootstrap()
        try:
            service = XrayService(
                vpn_keys=VpnKeyRepository(db), users=SimpleNamespace(),  # type: ignore[arg-type]
                adapter=adapter(env["XRAY_INBOUND_TAG"], True), settings=settings, clock=ClockProvider(),
                ids=SimpleNamespace(), audit=SimpleNamespace(write_best_effort=_noop),  # type: ignore[arg-type]
                xhttp_adapter=adapter(env["XRAY_XHTTP_INBOUND_TAG"], False),
            )
            summary = await service.startup_reconcile()
            assert summary["failed"] == 0
            assert await adapter(env["XRAY_INBOUND_TAG"], True).ensure_short_id(env["XRAY_SHORT_ID"]) is False
        finally:
            await db.close()

    asyncio.run(run())
    assert path.read_bytes() == raw, "the bot's reconcile changed the generated config"


async def _noop(**_: Any) -> None:
    return None


# --------------------------------------------------------------------------- #
# Rollback: a failure at ANY step puts the host back
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("proto", "step"), [(p, s) for p in PI.PROTOCOLS for s in PI.PROTO_STEPS[p]])
def test_a_failure_after_each_step_rolls_the_host_back(host: InstallHost, proto: str, step: str) -> None:
    host.marker(proto)  # a reinstall: the marker step acts too
    if proto == "hysteria2":
        host.warp()  # WARP deployed: the warp step acts too
    before = host.snapshot()
    rc, res = host.install(proto, VPN_BOT_PROTOCOL_INSTALL_SELFTEST_FAIL=step)
    assert rc == EXIT_ROLLED_BACK, res
    assert res["failed_step"] == step and res["rolled_back"] and not res["rollback_errors"]
    after = host.snapshot(skip=("/etc/vpn-bot/tls",))
    expected = host_without(before, "/etc/vpn-bot/tls")
    assert after == expected
    # The certificate's pair laid out to nginx is the registry's (shared): it may stay.
    tls = sorted(p for p in host.snapshot()["files"] if p.startswith("/etc/vpn-bot/tls"))
    assert tls in ([], ["/etc/vpn-bot/tls", "/etc/vpn-bot/tls/fullchain.pem", "/etc/vpn-bot/tls/privkey.pem"])
    journal = json.loads(host.file(f"/var/lib/vpn-bot-protocol-install/{proto}.journal.json").read_text())
    assert journal["state"] == "rolled_back"
    assert host.file(f"/etc/vpn-bot/uninstalled/{proto}").is_file(), "the marker is back"


def host_without(snap: dict[str, Any], prefix: str) -> dict[str, Any]:
    out = dict(snap)
    out["files"] = {k: v for k, v in snap["files"].items() if not k.startswith(prefix)}
    return out


@pytest.mark.parametrize(("fail", "step"), [
    ("apt-get_install", "nginx_pkg"),
    ("cert_deploy", "cert"),
    ("nginx_t", "nginx_site"),
    ("xray_test", "xray_config"),
    ("systemctl_restart_xray.service", "xray_start"),
])
def test_a_real_failure_rolls_back(host: InstallHost, fail: str, step: str) -> None:
    before = host.snapshot()
    host.fail(fail)
    rc, res = host.install()
    assert rc == EXIT_ROLLED_BACK and res["failed_step"] == step, res
    assert host.snapshot(skip=("/etc/vpn-bot/tls",)) == host_without(before, "/etc/vpn-bot/tls")
    assert "nginx" not in host.packages(), "a package installed by the run is purged again"


def test_a_download_other_than_the_pin_or_the_dgst_is_refused(host: InstallHost) -> None:
    host.release(dgst_sha="0" * 64)
    before = host.snapshot()
    rc, res = host.install()
    assert rc == EXIT_ROLLED_BACK and res["failed_step"] == "xray_bin"
    assert ".dgst" in res["detail"]
    assert host.snapshot(skip=("/etc/vpn-bot/tls",)) == host_without(before, "/etc/vpn-bot/tls")
    host2 = InstallHost(host.tmp / "pin")
    good = host2.pin
    host2.release(xray=b"tampered")
    host2.pin = good
    rc, res = host2.install()
    assert rc == EXIT_ROLLED_BACK and "pinned" in res["detail"]


def test_rollback_after_a_failed_verify_removes_the_install(host: InstallHost) -> None:
    before = host.snapshot()
    assert host.install()[0] == 0
    host.fail("openssl")
    assert host.helper("verify", "xray", "--json").returncode == EXIT_VERIFY
    proc = host.helper("rollback", "xray", "--json")
    assert proc.returncode == 0, proc.stdout
    assert host.snapshot(skip=("/etc/vpn-bot/tls",)) == host_without(before, "/etc/vpn-bot/tls")


def test_a_committed_install_is_not_rolled_back(host: InstallHost) -> None:
    assert host.install()[0] == 0
    assert host.helper("commit", "xray", "--json").returncode == 0
    proc = host.helper("rollback", "xray", "--json")
    assert proc.returncode == EXIT_REFUSED
    assert host.file(PI.XRAY_BIN).exists()


# --------------------------------------------------------------------------- #
# Reinstall after an uninstall (the REAL uninstall helper)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("proto", ["hysteria2", "socks5"])
def test_reinstall_after_uninstall_of_hysteria2_and_socks5(host: InstallHost, proto: str) -> None:
    rc, res = host.install(proto)
    assert rc == 0, res
    assert host.helper("verify", proto, "--json").returncode == 0
    assert host.helper("commit", proto, "--json").returncode == 0
    plan = json.loads(host.uninstall("plan", proto).stdout.strip().splitlines()[-1])
    assert plan["state"] == "installed" and not plan["blocking"], plan["blocking"]
    man = PI.MANIFESTS[proto]
    removed = {f["path"] for f in plan["files"] if f["state"] == "delete"}
    present_owned = {p for p in (*man.unit_files, *man.paths) if host.file(p).exists()}
    assert removed == present_owned, "the uninstall removes exactly what the install laid out"
    assert {k["name"] for k in plan["packages"] if k["state"] == "purge"} == set(man.packages)
    assert {u["name"] for u in plan["users"] if u["state"] == "delete"} == set(man.users)
    proc = host.uninstall("apply", proto, plan["sha256"])
    assert proc.returncode == 0, proc.stdout[-1500:] + proc.stderr[-1500:]
    assert host.env_values()[man.env_flag] == "false"
    assert json.loads(host.helper("status", "--json").stdout)["protocols"][proto]["state"] == "uninstalled"
    plan2 = host.plan(proto)
    assert any(c["step"] == "marker" and c["action"] == "remove" for c in plan2["changes"])
    rc, res = host.install(proto)
    assert rc == 0, res
    assert not host.file(f"/etc/vpn-bot/uninstalled/{proto}").exists()
    assert host.env_values()[man.env_flag] == "true"
    assert host.helper("verify", proto, "--json").returncode == 0


def test_hysteria2_lays_out_the_production_layout(host: InstallHost) -> None:
    rc, res = host.install("hysteria2")
    assert rc == 0, res
    passwd = host.file("/etc/passwd").read_text()
    assert "hysteria:x:992:" in passwd, "the uid vpnbot-hy2-warp-mark tags"
    assert "\nvpn-bot:x:" in passwd, "the bot's user for vpnbot-hy2-auth"
    assert host.owners()["/opt/vpn-service/data/vpn.db"] == "vpn-bot:vpn-bot", "vpn-bot-db-perms ran"
    conf = host.file(PI.HY2_CONFIG).read_text()
    secret = host.env_values()["HYSTERIA2_STATS_SECRET"]
    assert f'secret: "{secret}"' in conf and "<random-secret>" not in conf
    assert host.file(PI.HY2_CONFIG).stat().st_mode & 0o777 == 0o600 and host.owners()[PI.HY2_CONFIG] == "hysteria:hysteria"
    assert secret not in host.file("/var/log/vpn-bot-protocol-install.log").read_text()
    assert host.file(f"/etc/systemd/system/{PI.HY2_AUTH_UNIT}").read_bytes() == (ROOT / "deploy/vpnbot-hy2-auth.service").read_bytes()
    assert not host.file(PI.HY2_MARK_HELPER).exists(), "no WARP here: no mark helper"
    units = host.units()
    assert units["hysteria-server.service"]["active"] == "active" and units["vpnbot-hy2-auth.service"]["active"] == "active"
    # The repo config is what deploy/backend-config-sync.py compares: only the secret differs.
    assert conf.replace(f'secret: "{secret}"', 'secret: "<random-secret>"') == (ROOT / "deploy/hysteria/config.yaml").read_text()


def test_hysteria2_with_warp_marks_its_traffic(host: InstallHost) -> None:
    host.warp()
    rc, res = host.install("hysteria2")
    assert rc == 0, res
    assert host.file(PI.HY2_MARK_HELPER).read_bytes() == (ROOT / "scripts/vpnbot-hy2-warp-mark").read_bytes()
    assert host.file(PI.HY2_MARK_HELPER).stat().st_mode & 0o777 == 0o755
    assert host.units()[PI.HY2_MARK_UNIT] == {"active": "active", "enabled": "enabled"}
    checks = host.json_of(host.helper("verify", "hysteria2", "--json"))["checks"]
    assert any(c["key"] == f"unit:{PI.HY2_MARK_UNIT}" and c["ok"] for c in checks)


def test_hysteria_uid_taken_with_warp_blocks(host: InstallHost) -> None:
    host.warp()
    host.file("/etc/passwd").write_text(host.file("/etc/passwd").read_text() + "someone:x:992:992::/:/bin/false\n")
    assert any("uid 992 is taken" in b for b in host.plan("hysteria2")["blocking"])


def test_hysteria_release_must_match_its_hashes(host: InstallHost) -> None:
    host.hy2_release(sums_sha="1" * 64)
    rc, res = host.install("hysteria2")
    assert rc == EXIT_ROLLED_BACK and res["failed_step"] == "hy2_bin" and "hashes.txt" in res["detail"]


def test_socks5_with_warp_egress_leaves_from_the_tunnel(host: InstallHost) -> None:
    host.warp()
    env = host.file("/opt/vpn-service/.env")
    env.write_text(env.read_text() + "WARP_PROXY_EGRESS_ENABLED=true\n")
    rc, res = host.install("socks5")
    assert rc == 0, res
    conf = host.file(PI.SOCKS_CONF).read_text()
    assert "\nexternal: 172.16.0.2\n" in conf and "internal: 0.0.0.0 port = 31337" in conf
    assert host.file(PI.SOCKS_DROPIN).read_bytes() == (ROOT / "deploy/danted-warp.conf").read_bytes()
    assert (host.st / "policy_rc_d_at_install").read_text() == "held"


def test_socks5_without_warp_leaves_from_the_wan(host: InstallHost) -> None:
    rc, res = host.install("socks5")
    assert rc == 0, res
    assert "\nexternal: eth0\n" in host.file(PI.SOCKS_CONF).read_text()


def test_an_operators_danted_conf_is_kept(host: InstallHost) -> None:
    assert host.install("socks5")[0] == 0
    host.file(PI.SOCKS_CONF).write_text("# mine\n")
    plan = host.plan("socks5")
    assert any(c["target"] == PI.SOCKS_CONF and c["action"] == "keep" for c in plan["changes"])
    assert any("not this installer's" in w for w in plan["warnings"])


def test_reinstall_after_uninstall(host: InstallHost) -> None:
    assert host.install()[0] == 0
    assert host.helper("commit", "xray", "--json").returncode == 0
    plan = json.loads(host.uninstall("plan", "xray").stdout.strip().splitlines()[-1])
    assert plan["state"] == "installed" and not plan["blocking"]
    removed = {f["path"] for f in plan["files"] if f["state"] == "delete"}
    man = PI.MANIFESTS["xray"]
    assert removed == set(man.unit_files) | set(man.paths), "the uninstall removes exactly what the install laid out"
    proc = host.uninstall("apply", "xray", plan["sha256"])
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert host.file("/etc/vpn-bot/uninstalled/xray").is_file()
    assert host.file(PI.NGINX_SITE_CONF).is_file() and "nginx" in host.packages(), "nginx is shared: kept"
    status = json.loads(host.helper("status", "--json").stdout)
    assert status["protocols"]["xray"]["state"] == "uninstalled"
    # The same install again: the marker goes, LAST.
    plan2 = host.plan()
    assert [c["step"] for c in plan2["changes"] if c["action"] not in ("keep", "skip")][-1] == "marker"
    assert all(c["action"] == "keep" for c in plan2["changes"] if c["step"].startswith("nginx"))
    rc, res = host.install()
    assert rc == 0, res
    assert not host.file("/etc/vpn-bot/uninstalled/xray").exists()
    assert host.helper("verify", "xray", "--json").returncode == 0
    assert sum(c.startswith("apt-get install") for c in host.calls()) == 1, "nginx stayed: no second package install"


# --------------------------------------------------------------------------- #
# Small pure functions
# --------------------------------------------------------------------------- #
def test_parse_x25519_reads_both_output_formats() -> None:
    priv, pub = "iLNMs3bFQNewI21767HiJf-9UlGHyLWyX9p3LirWJXw", "zVECifX1_gxZpC9A--sqbV1TZ1LLSIiVh92Vi6Y-4HQ"
    assert PI.parse_x25519(f"PrivateKey: {priv}\nPassword: {pub}\nHash32: x\n") == (priv, pub)
    assert PI.parse_x25519(f"Private key: {priv}\nPublic key: {pub}\n") == (priv, pub)
    with pytest.raises(PI.Cannot):
        PI.parse_x25519("garbage")


@pytest.mark.parametrize(("private", "public"), [
    # Pairs printed by Xray v25.10.15's `xray x25519`.
    ("iLNMs3bFQNewI21767HiJf-9UlGHyLWyX9p3LirWJXw", "zVECifX1_gxZpC9A--sqbV1TZ1LLSIiVh92Vi6Y-4HQ"),
    ("iCZp7VnIze6RAvLPt8tRf0tIsLuLiYzETODLKj4l7HE", "dVH8NRXqCSVT9lhQeGugnFi2ILWMXeLvoZLspWdoJB4"),
])
def test_x25519_public_is_xrays(private: str, public: str) -> None:
    assert PI.x25519_public(private) == public


def test_a_key_pair_that_does_not_match_is_refused(host: InstallHost) -> None:
    (host.st / "x25519_wrong").write_text("1")
    rc, res = host.install()
    assert rc == EXIT_ROLLED_BACK and res["failed_step"] == "xray_config"


def test_verify_never_puts_the_private_key_on_an_argv(host: InstallHost) -> None:
    assert host.install()[0] == 0
    assert host.helper("verify", "xray", "--json").returncode == 0
    priv = json.loads(host.file(PI.XRAY_CONFIG).read_text())["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
    assert not any(priv in call for call in host.calls())


def test_dgst_line_is_read() -> None:
    assert PI.dgst_sha256("MD5= 1\nSHA2-256= " + "a" * 64 + "\n") == "a" * 64
    assert PI.dgst_sha256("SHA2-256= nothex") is None


@pytest.mark.parametrize("text", [
    "[Interface]\nAddress = 172.16.0.2/32\n",
    "[Interface]\nAddress = fd00::2/128, 172.16.0.2/32\n",
    "[Interface]\nAddress = fd00::2/128\n",
    "[Peer]\n",
])
def test_warp_address_is_the_bots(tmp_path: Path, text: str) -> None:
    from warp.proxy_egress import read_tunnel_address

    conf = tmp_path / "w.conf"
    conf.write_text(text)
    assert PI.warp_tunnel_address(conf) == read_tunnel_address(conf)


def test_edit_env_text_changes_only_the_last_assignment() -> None:
    text = "A=1\n# A=commented\nexport B = 2\nA=3 # tail\nC=x"
    out = PI.edit_env_text(text, {"A": "9", "B": "8", "D": "7"})
    assert out == "A=1\n# A=commented\nB=8\nA=9\nC=x\nD=7\n"


def test_the_skeleton_renders_without_a_placeholder_left() -> None:
    skeleton = json.loads((ROOT / "deploy" / "xray" / "config.skeleton.json").read_text())
    assert PI.check_skeleton(skeleton) == []
    config = PI.render_xray_config(skeleton, domain=DOMAIN, private_key="k" * 43, short_id="ab", xhttp_path="/p",
                                   send_through=None)
    assert not re.search(r'"<[A-Za-z0-9_-]+>"', json.dumps(config))
    assert config["inbounds"][2]["port"] == 8001 and config["inbounds"][0]["settings"]["fallbacks"][0]["dest"] == 8001


def test_the_pinned_release_is_a_version_with_two_architectures() -> None:
    assert re.fullmatch(r"v\d+\.\d+\.\d+", PI.XRAY_VERSION)
    assert set(PI.XRAY_ASSETS) == {"x86_64", "aarch64"}
    for name, sha in PI.XRAY_ASSETS.values():
        assert name.endswith(".zip") and re.fullmatch(r"[0-9a-f]{64}", sha)
    assert ASSET == PI.XRAY_ASSETS["x86_64"][0]


def test_the_helper_refuses_a_real_tool_under_the_seam(host: InstallHost) -> None:
    (host.bin / "apt-get").unlink()
    rc, res = host.install()
    assert rc == EXIT_ROLLED_BACK and res["failed_step"] == "nginx_pkg"
    assert "nginx" not in host.packages()


def test_the_wizard_mode_shows_the_helpers_steps() -> None:
    """scripts/wizard/vpn-bot-wizard-protocol lists each protocol's steps (⚪ before apply):
    the very steps, in the very order, the helper runs — and every step has its label."""
    import ast

    from i18n import en, ru

    tree = ast.parse((ROOT / "scripts" / "wizard" / "vpn-bot-wizard-protocol").read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id == "STEPS" for t in n.targets))
    assert ast.literal_eval(node.value) == {p: tuple(s) for p, s in PI.PROTO_STEPS.items()}
    for steps in PI.PROTO_STEPS.values():
        for step in steps:
            assert f"install_step_{step}" in ru.STRINGS and f"install_step_{step}" in en.STRINGS, step
