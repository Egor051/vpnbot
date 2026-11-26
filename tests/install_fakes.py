"""A fake host for scripts/vpn-bot-protocol-install (and, on the SAME root, the real
deploy/helpers/vpn-bot-protocol-uninstall — the symmetry and reinstall tests).

Every privileged tool either helper runs is one stub (STUB below, a copy per name in
``bin/``; the uninstall's seam refuses a tool whose realpath is not ``bin/<name>``):
systemctl, dpkg-query, apt-get, nginx, vpn-bot-cert, xray, ss, openssl, curl and the
uninstall's ufw / userdel / useradd / groupadd / usermod / getent / iptables-save / pgrep /
nsenter. Their state lives in ``st/`` (units.json, packages.json, calls); a file
``st/fail_<tool>_<verb>`` makes that call fail. The stubs model what the helpers rely on:
apt-get starts nginx on :80 unless a policy-rc.d holds it, `systemctl reload` of an
inactive unit fails, `nginx -t` fails while a vhost names a certificate that is not
there, `vpn-bot-cert deploy` reloads nginx (fails when it is not running) and lays the
pair out, ss/openssl/curl answer from what is running. No network, no real systemd.

The release assets come from ``releases/`` (a zip with a fake xray, its .dgst), the
pinned sha256 is handed over with _SELFTEST_PINS.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpn-bot-protocol-install"
UNINSTALL = ROOT / "deploy" / "helpers" / "vpn-bot-protocol-uninstall"
DOMAIN = "vpn.example.com"
ASSET = "Xray-linux-64.zip"

TOOLS = (
    "systemctl", "dpkg-query", "apt-get", "nginx", "vpn-bot-cert", "xray", "ss", "openssl", "curl",
    "ufw", "userdel", "useradd", "groupadd", "groupdel", "usermod", "getent", "iptables-save", "pgrep", "nsenter",
    "vpn-bot-db-perms", "hysteria", "danted", "ip", "iptables",
)
HY2_ASSET = "hysteria-linux-amd64"

STUB = r'''#!/usr/bin/env python3
import base64, hashlib, json, os, secrets, shutil, sys
from pathlib import Path

name = os.path.basename(sys.argv[0])
args = [a for a in sys.argv[1:]]
R = Path(os.environ["ROOTFS"])
ST = Path(os.environ["ST"])
with open(ST / "calls", "a", encoding="utf-8") as fh:
    fh.write(name + " " + " ".join(args) + "\n")


def load(f, default):
    p = ST / f
    return json.loads(p.read_text()) if p.is_file() else default


def save(f, data):
    (ST / f).write_text(json.dumps(data, sort_keys=True, indent=1))


def failing(*keys):
    for key in keys:
        p = ST / f"fail_{key}"
        if p.is_file():
            if p.read_text().strip() == "once":
                p.unlink()
            return True
    return False


def h(path):
    return R / path.lstrip("/")


UNITS = load("units.json", {})


def unit_file(u):
    for d in ("/etc/systemd/system", "/usr/lib/systemd/system"):
        if h(f"{d}/{u}").is_file():
            return f"{d}/{u}"
    return ""


def state(u):
    s = UNITS.setdefault(u, {"active": "inactive", "enabled": "disabled"})
    if not unit_file(u):
        s["active"] = "inactive"
    return s


def load_state(u):
    if h(f"/etc/systemd/system/{u}").is_symlink() and os.readlink(h(f"/etc/systemd/system/{u}")) == "/dev/null":
        return "masked"
    return "loaded" if unit_file(u) else "not-found"


def nginx_serving():
    s = UNITS.get("nginx.service", {})
    return (s.get("active") == "active" and h("/etc/nginx/conf.d/selfsteal.conf").is_file()
            and h("/etc/vpn-bot/tls/fullchain.pem").is_file())


def xray_config_ok(path):
    try:
        cfg = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return False
    text = json.dumps(cfg)
    return bool(cfg.get("inbounds")) and "<" not in text.replace("<-", "")


if name == "systemctl":
    a = [x for x in args if x not in ("--", "--no-block", "--quiet")]
    verb = a[0] if a else ""
    rest = a[1:]
    if failing(f"systemctl_{verb}", *(f"systemctl_{verb}_{u}" for u in rest)):
        print(f"stub: systemctl {verb} failed", file=sys.stderr); sys.exit(1)
    if verb == "show":
        prop, unit = "", ""
        i = 0
        while i < len(rest):
            if rest[i] == "-p":
                prop = rest[i + 1]; i += 2
            elif rest[i] == "--value":
                i += 1
            else:
                unit = rest[i]; i += 1
        s = state(unit)
        value = {"LoadState": load_state(unit), "ActiveState": s["active"] if load_state(unit) == "loaded" else "inactive",
                 "UnitFileState": s["enabled"] if load_state(unit) == "loaded" else "",
                 "FragmentPath": unit_file(unit)}.get(prop, "")
        print(value); save("units.json", UNITS); sys.exit(0)
    if verb == "is-enabled":
        s = state(rest[0]); print(s["enabled"] if unit_file(rest[0]) else "disabled")
        save("units.json", UNITS); sys.exit(0 if s["enabled"] == "enabled" else 1)
    if verb in ("list-units", "daemon-reload", "reset-failed"):
        save("units.json", UNITS); sys.exit(0)
    now = "--now" in rest
    units = [u for u in rest if u != "--now"]
    for u in units:
        s = state(u)
        if verb in ("enable", "start", "restart", "reload", "try-restart", "mask", "unmask") and load_state(u) == "not-found" \
                and verb not in ("try-restart",):
            print(f"Unit {u} not found.", file=sys.stderr); sys.exit(5)
        if verb == "enable":
            s["enabled"] = "enabled"
            if now:
                s["active"] = "active"
        elif verb == "disable":
            s["enabled"] = "disabled"
            if now:
                s["active"] = "inactive"
        elif verb in ("start", "restart"):
            if u == "xray.service" and not xray_config_ok(h("/usr/local/etc/xray/config.json")):
                s["active"] = "failed"; save("units.json", UNITS); sys.exit(1)
            s["active"] = "active"
        elif verb == "stop":
            s["active"] = "inactive"
        elif verb == "reload":
            if s["active"] != "active":
                print(f"{u} is not active, cannot reload.", file=sys.stderr); save("units.json", UNITS); sys.exit(1)
        elif verb == "try-restart":
            pass
        elif verb == "mask":
            os.symlink("/dev/null", h(f"/etc/systemd/system/{u}"))
        elif verb == "unmask":
            os.unlink(h(f"/etc/systemd/system/{u}"))
    save("units.json", UNITS); sys.exit(0)

PKGS = load("packages.json", {})
NGINX_FILES = ("/etc/nginx/nginx.conf", "/etc/nginx/sites-available/default", "/usr/lib/systemd/system/nginx.service",
               "/var/www/html/index.nginx-debian.html")

if name == "dpkg-query":
    if args and args[0] == "-S":
        sys.exit(1)
    fmt = args[1][3:] if len(args) > 1 and args[1].startswith("-f=") else ""
    pkg = args[2] if len(args) > 2 else None
    if pkg is None:
        for p in sorted(PKGS):
            print(fmt.replace("${db:Status-Abbrev}", "ii ").replace("${Package}", p).replace("\\n", "\n"), end="")
        sys.exit(0)
    if pkg not in PKGS:
        print(f"dpkg-query: no packages found matching {pkg}", file=sys.stderr); sys.exit(1)
    print(fmt.replace("${db:Status-Abbrev}", "ii ").replace("${Version}", PKGS[pkg]).replace("${Conffiles}", ""), end="")
    sys.exit(0)

if name == "apt-get":
    verb = next((a for a in args if not a.startswith("-")), "")
    pkgs = [a for a in args[args.index(verb) + 1:] if not a.startswith("-")] if verb else []
    if failing(f"apt-get_{verb}"):
        print("E: stub failure", file=sys.stderr); sys.exit(100)
    if verb == "install" and "nginx" in pkgs:
        held = h("/usr/sbin/policy-rc.d").is_file()
        (ST / "policy_rc_d_at_install").write_text("held" if held else "absent")
        for f in NGINX_FILES:
            h(f).parent.mkdir(parents=True, exist_ok=True); h(f).write_text(f"# {f}\n")
        for d in ("/etc/nginx/conf.d", "/etc/nginx/sites-enabled"):
            h(d).mkdir(parents=True, exist_ok=True)
        if not h("/etc/nginx/sites-enabled/default").is_symlink():
            os.symlink("/etc/nginx/sites-available/default", h("/etc/nginx/sites-enabled/default"))
        PKGS.update({"nginx": "1.24.0-2ubuntu7", "nginx-common": "1.24.0-2ubuntu7"})
        UNITS["nginx.service"] = {"enabled": "enabled", "active": "inactive" if held else "active"}
        if not held:
            (ST / "bound_80").write_text("nginx started by its postinst with the default site")
    elif verb == "install" and "dante-server" in pkgs:
        held = h("/usr/sbin/policy-rc.d").is_file()
        (ST / "policy_rc_d_at_install").write_text("held" if held else "absent")
        for f, body in (("/usr/sbin/danted", "#!/bin/sh\n"), ("/etc/danted.conf", "# package default\n"),
                        ("/usr/lib/systemd/system/danted.service", "[Unit]\n")):
            h(f).parent.mkdir(parents=True, exist_ok=True); h(f).write_text(body)
        PKGS.update({"dante-server": "1.4.3+dfsg-1"})
        UNITS["danted.service"] = {"enabled": "enabled", "active": "inactive" if held else "failed"}
    elif verb == "purge" and "-s" in args:
        for p in pkgs:
            print(f"Purg {p} [{PKGS.get(p, '0')}]")
        sys.exit(0)
    elif verb == "purge":
        if "dante-server" in pkgs:
            for f in ("/usr/sbin/danted", "/etc/danted.conf", "/usr/lib/systemd/system/danted.service"):
                h(f).unlink(missing_ok=True)
            UNITS.pop("danted.service", None)
        for p in pkgs:
            PKGS.pop(p, None)
        if "nginx" in pkgs or "nginx-common" in pkgs:
            shutil.rmtree(h("/etc/nginx"), ignore_errors=True)
            shutil.rmtree(h("/var/www/html"), ignore_errors=True)
            h("/usr/lib/systemd/system/nginx.service").unlink(missing_ok=True)
            if h("/var/www").is_dir() and not any(h("/var/www").iterdir()):
                h("/var/www").rmdir()
            UNITS.pop("nginx.service", None)
    save("packages.json", PKGS); save("units.json", UNITS); sys.exit(0)

if name == "nginx":
    if failing("nginx_t"):
        print("nginx: [emerg] stub", file=sys.stderr); sys.exit(1)
    for d in ("/etc/nginx/conf.d", "/etc/nginx/sites-enabled"):
        if not h(d).is_dir():
            continue
        for f in h(d).iterdir():
            for line in f.read_text(errors="replace").splitlines():
                line = line.strip()
                if line.startswith("ssl_certificate") and not h(line.split()[1].rstrip(";")).is_file():
                    print(f"nginx: [emerg] cannot load certificate {line.split()[1]}", file=sys.stderr); sys.exit(1)
    sys.exit(0)

if name == "vpn-bot-cert":
    if args[:1] == ["status"]:
        st = load("cert_status.json", {})
        hy = h("/etc/hysteria/cert.pem").is_file()
        st["consumers"] = [{"name": "hysteria", "installed": load_state("hysteria-server.service") == "loaded"
                            and h("/etc/hysteria").is_dir(), "in_sync": True if hy else False}]
        print(json.dumps(st)); sys.exit(0)
    if args[:1] == ["deploy"]:
        if failing("cert_deploy"):
            print(json.dumps({"ok": False, "error": "stub"})); sys.exit(1)
        if load_state("nginx.service") == "loaded" and UNITS.get("nginx.service", {}).get("active") != "active":
            print(json.dumps({"ok": False, "error": "nginx.service is not active, cannot reload"})); sys.exit(1)
        tls = h("/etc/vpn-bot/tls"); tls.mkdir(parents=True, exist_ok=True)
        (tls / "fullchain.pem").write_text("CHAIN\n"); (tls / "privkey.pem").write_text("KEY\n")
        if (load_state("hysteria-server.service") == "loaded" and h("/etc/hysteria").is_dir()
                and not h("/etc/vpn-bot/uninstalled/hysteria2").exists()):
            (h("/etc/hysteria") / "cert.pem").write_text("CHAIN\n"); (h("/etc/hysteria") / "key.pem").write_text("KEY\n")
            if not h("/etc/hysteria/config.yaml").is_file():
                print(json.dumps({"ok": False, "error": "hysteria-server failed"})); save("units.json", UNITS); sys.exit(1)
            UNITS.setdefault("hysteria-server.service", {"enabled": "disabled"})["active"] = "active"
            save("units.json", UNITS)
        print(json.dumps({"ok": True})); sys.exit(0)
    sys.exit(2)

if name == "xray":
    def pub_of(priv):
        # Real X25519 (the helper checks the pair): the helper's own function, loaded from it.
        import importlib.machinery, importlib.util
        loader = importlib.machinery.SourceFileLoader("pi_stub", os.environ["INSTALL_HELPER"])
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec); sys.modules[loader.name] = mod; loader.exec_module(mod)
        return mod.x25519_public(priv)
    if args[:1] == ["version"]:
        print("Xray 25.10.15 (stub)"); sys.exit(0)
    if args[:1] == ["x25519"]:
        priv = args[2] if len(args) > 2 and args[1] == "-i" else base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        pub = "A" * 43 if (ST / "x25519_wrong").exists() else pub_of(priv)
        print(f"PrivateKey: {priv}\nPassword: {pub}\nHash32: x"); sys.exit(0)
    if args[:2] == ["run", "-test"]:
        if failing("xray_test"):
            sys.exit(23)
        # Like v25.10.15: the log files the config names are opened, their directory must exist.
        try:
            logs = json.loads(Path(args[3]).read_text()).get("log", {})
        except (OSError, ValueError):
            logs = {}
        for key in ("access", "error"):
            if logs.get(key) and not h(logs[key]).parent.is_dir():
                print(f"Failed to start: open {logs[key]}: no such file or directory", file=sys.stderr); sys.exit(23)
        sys.exit(0 if xray_config_ok(args[3]) else 23)
    sys.exit(2)

if name == "ss" and "-Hlun" in args:
    if UNITS.get("hysteria-server.service", {}).get("active") == "active":
        print("UNCONN 0 0 *:443 *:*")
    sys.exit(0)

if name == "ss":
    if UNITS.get("hysteria-server.service", {}).get("active") == "active":
        print("LISTEN 0 4096 127.0.0.1:9999 0.0.0.0:*")
    if UNITS.get("vpnbot-hy2-auth.service", {}).get("active") == "active":
        print("LISTEN 0 4096 127.0.0.1:8444 0.0.0.0:*")
    if UNITS.get("danted.service", {}).get("active") == "active":
        print("LISTEN 0 4096 0.0.0.0:31337 0.0.0.0:*")
    if UNITS.get("xray.service", {}).get("active") == "active":
        for a in ("0.0.0.0:443", "127.0.0.1:10085", "127.0.0.1:8001"):
            print(f"LISTEN 0 4096 {a} 0.0.0.0:*")
    if nginx_serving():
        print("LISTEN 0 511 127.0.0.1:8443 0.0.0.0:*")
    sys.exit(0)

if name == "openssl":
    # As OpenSSL 3's s_client: -brief prints a summary WITHOUT the negotiated ALPN.
    if nginx_serving() and not failing("openssl"):
        if "-brief" in args:
            print("CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nVerification: OK"); sys.exit(0)
        print("---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nALPN protocol: h2\nVerify return code: 0 (ok)\n---")
        sys.exit(0)
    print("connect: Connection refused", file=sys.stderr); sys.exit(1)

if name == "curl" and args and args[-1].endswith("/healthz"):
    ok = UNITS.get("vpnbot-hy2-auth.service", {}).get("active") == "active"
    print("200" if ok else "000"); sys.exit(0 if ok else 7)

if name == "curl":
    fmt = args[args.index("-w") + 1] if "-w" in args else "%{http_code}"
    if nginx_serving():
        print(fmt.replace("%{http_code}", "200").replace("%{http_version}", "2")); sys.exit(0)
    print(fmt.replace("%{http_code}", "000").replace("%{http_version}", "0")); sys.exit(7)

def passwd_lines(db):
    f = h(f"/etc/{db}")
    return f.read_text().splitlines() if f.is_file() else []


def write_lines(db, lines):
    h(f"/etc/{db}").write_text("".join(f"{ln}\n" for ln in lines))


if name == "groupadd":
    g = args[-1]
    if any(ln.split(":")[0] == g for ln in passwd_lines("group")):
        sys.exit(9)
    gid = 990
    used = {int(ln.split(":")[2]) for ln in passwd_lines("group")}
    while gid in used:
        gid -= 1
    write_lines("group", passwd_lines("group") + [f"{g}:x:{gid}:"]); sys.exit(0)

if name == "groupdel":
    write_lines("group", [ln for ln in passwd_lines("group") if ln.split(":")[0] != args[-1]]); sys.exit(0)

if name == "useradd":
    if failing("useradd"):
        sys.exit(1)
    user = args[-1]
    if any(ln.split(":")[0] == user for ln in passwd_lines("passwd")):
        sys.exit(9)
    opts = dict(zip(args[:-1], args[1:-1] + [""]))
    used = {int(ln.split(":")[2]) for ln in passwd_lines("passwd")}
    uid = int(opts["--uid"]) if "--uid" in opts else max(u for u in range(100, 999) if u not in used)
    if uid in used:
        sys.exit(4)
    if "--user-group" in args:
        write_lines("group", passwd_lines("group") + [f"{user}:x:{uid}:"])
        gid = uid
    else:
        gname = opts.get("--gid", "nogroup")
        gid = next(int(ln.split(":")[2]) for ln in passwd_lines("group") if ln.split(":")[0] == gname)
    write_lines("passwd", passwd_lines("passwd") + [f"{user}:x:{uid}:{gid}::{opts.get('--home-dir', '/')}:{opts.get('--shell', '/bin/sh')}"])
    sys.exit(0)

if name == "userdel":
    user = args[-1]
    lines = passwd_lines("passwd")
    if not any(ln.split(":")[0] == user for ln in lines):
        sys.exit(6)
    write_lines("passwd", [ln for ln in lines if ln.split(":")[0] != user])
    write_lines("group", [ln for ln in passwd_lines("group") if ln.split(":")[0] != user]); sys.exit(0)

if name == "vpn-bot-db-perms":
    if any(ln.split(":")[0] == "vpn-bot" for ln in passwd_lines("passwd")) and h("/opt/vpn-service/data/vpn.db").exists():
        f = R / ".owners.json"
        data = json.loads(f.read_text()) if f.is_file() else {}
        data["/opt/vpn-service/data/vpn.db"] = "vpn-bot:vpn-bot"
        f.write_text(json.dumps(data, sort_keys=True))
    sys.exit(0)

if name == "hysteria":
    print("Version: v2.8.2 (stub)"); sys.exit(0)

if name == "danted":
    if failing("danted_v"):
        sys.exit(1)
    text = Path(args[-1]).read_text() if args and Path(args[-1]).is_file() else ""
    body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    sys.exit(0 if "internal: 0.0.0.0 port = " in body and "<" not in body else 1)

if name == "ip":
    print("default via 203.0.113.1 dev eth0 proto static"); sys.exit(0)

if name == "getent":
    db, key = args[0], (args[-1] if len(args) > 1 else None)
    f = h(f"/etc/{db}")
    lines = f.read_text().splitlines() if f.is_file() else []
    hits = [ln for ln in lines if key is None or ln.split(":")[0] == key or (len(ln.split(":")) > 2 and ln.split(":")[2] == key)]
    print("\n".join(hits)); sys.exit(0 if hits else 2)

if name == "ufw":
    print("Status: inactive"); sys.exit(0)
if name == "pgrep":
    sys.exit(1)
sys.exit(0)
'''


class InstallHost:
    """A fake fresh host (after scripts/install.sh): .env, no protocol, no nginx."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.st = tmp / "st"
        self.releases = tmp / "releases"
        for d in (self.root, self.bin, self.st, self.releases):
            d.mkdir(parents=True, exist_ok=True)
        for d in ("/etc/systemd/system", "/usr/local/bin", "/usr/local/etc", "/usr/local/share", "/usr/local/sbin",
                  "/usr/sbin", "/usr/lib/systemd/system", "/var/log", "/var/lib", "/var/backups", "/run", "/etc/vpn-bot",
                  "/opt/vpn-service"):
            self.file(d).mkdir(parents=True, exist_ok=True)
        self.file("/etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n")
        self.file("/etc/group").write_text("root:x:0:\nnogroup:x:65534:\n")
        self.env_text = (
            "BOT_TOKEN=123:abc\nADMIN_IDS=\nPRIVILEGE_HELPERS_ENABLED=false\n"
            "XRAY_CONFIG_PATH=/usr/local/etc/xray/config.json\nXRAY_SERVICE_NAME=xray\nXRAY_APPLY_MODE=api\n"
            "XRAY_INBOUND_TAG=vless-in\nXRAY_PUBLIC_HOST=\nXRAY_PUBLIC_PORT=443\nXRAY_REALITY_PUBLIC_KEY=\nXRAY_SNI=\n"
            "XRAY_SHORT_ID=\nXRAY_STATS_SERVER=127.0.0.1:10085\nXRAY_XHTTP_ENABLED=false\n"
            "XRAY_XHTTP_INBOUND_TAG=vless-xhttp-reality\nXRAY_XHTTP_PATH=/v1/messages/stream\n"
            "SOCKS5_ENABLED=false\nHYSTERIA2_ENABLED=false\n"
        )
        env = self.file("/opt/vpn-service/.env")
        env.write_text(self.env_text)
        env.chmod(0o600)
        for tool in TOOLS:
            path = self.bin / tool
            path.write_text(STUB, encoding="utf-8")
            path.chmod(0o755)
        wrapper = self.bin / "vpn-bot-protocol-install"
        wrapper.write_text(f'#!/bin/bash\nexec {sys.executable} -I {HELPER} "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
        self.file("/opt/vpn-service/data").mkdir(parents=True, exist_ok=True)
        self.file("/opt/vpn-service/data/vpn.db").write_bytes(b"SQLite format 3\0")
        self.cert()
        self.release()
        self.hy2_release()

    # ---------------------------------------------------------------- the host
    def file(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def cert(self, *, adopted: bool = True, san: list[str] | None = None, days: float = 80.0) -> None:
        status: dict[str, Any] = {"adopted": adopted, "domain": DOMAIN if adopted else None,
                                  "target_dir": f"/root/.acme.sh/{DOMAIN}_ecc", "domains": []}
        if adopted:
            status["domains"].append({"name": DOMAIN, "dir": f"/root/.acme.sh/{DOMAIN}_ecc", "key_ok": True,
                                      "san": san or [DOMAIN], "days_left": days})
        (self.st / "cert_status.json").write_text(json.dumps(status))

    def release(self, *, xray: bytes = b"#!/bin/sh\necho fake xray\n", dgst_sha: str | None = None) -> str:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("xray", xray)
            zf.writestr("geoip.dat", b"geoip")
            zf.writestr("geosite.dat", b"geosite")
            zf.writestr("LICENSE", b"license")
        data = buf.getvalue()
        sha = hashlib.sha256(data).hexdigest()
        (self.releases / ASSET).write_bytes(data)
        (self.releases / f"{ASSET}.dgst").write_text(
            f"MD5= 00\nSHA1= 00\nSHA2-256= {dgst_sha or sha}\nSHA2-512= 00\n", encoding="utf-8")
        self.pin = sha
        return sha

    def hy2_release(self, *, data: bytes = b"#!/bin/sh\necho fake hysteria\n", sums_sha: str | None = None) -> str:
        sha = hashlib.sha256(data).hexdigest()
        (self.releases / HY2_ASSET).write_bytes(data)
        (self.releases / "hashes.txt").write_text(
            f"{'0' * 64}  build/hysteria-android-386\n{sums_sha or sha}  build/{HY2_ASSET}\n", encoding="utf-8")
        self.hy2_pin = sha
        return sha

    def warp(self) -> None:
        self.file("/etc/amnezia").mkdir(parents=True, exist_ok=True)
        self.file("/etc/amnezia/out-warp.conf").write_text("[Interface]\nAddress = 172.16.0.2/32\n")

    def marker(self, proto: str = "xray") -> None:
        d = self.file("/etc/vpn-bot/uninstalled")
        d.mkdir(parents=True, exist_ok=True)
        (d / proto).write_text(json.dumps({"protocol": proto, "ts": "2026-11-20T00:00:00Z"}) + "\n")

    def fail(self, key: str, once: bool = False) -> None:
        (self.st / f"fail_{key}").write_text("once" if once else "always")

    def units(self) -> dict[str, dict[str, str]]:
        p = self.st / "units.json"
        return json.loads(p.read_text()) if p.is_file() else {}

    def packages(self) -> dict[str, str]:
        p = self.st / "packages.json"
        return json.loads(p.read_text()) if p.is_file() else {}

    def calls(self) -> list[str]:
        p = self.st / "calls"
        return p.read_text().splitlines() if p.is_file() else []

    def owners(self) -> dict[str, str]:
        p = self.root / ".owners.json"
        return json.loads(p.read_text()) if p.is_file() else {}

    def env_values(self) -> dict[str, str]:
        out = {}
        for line in self.file("/opt/vpn-service/.env").read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    # ---------------------------------------------------------------- running
    def base_env(self, **extra: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("VPN_BOT_", "XRAY_"))}
        env.update({
            "ROOTFS": str(self.root), "ST": str(self.st), "CALLS": str(self.st / "calls"), "INSTALL_HELPER": str(HELPER),
            "PATH": f"{self.bin}:/usr/bin:/bin", "LC_ALL": "C",
            "VPN_BOT_PROTOCOL_INSTALL_SELFTEST": "1", "VPN_BOT_PROTOCOL_INSTALL_ROOT": str(self.root),
            "VPN_BOT_PROTOCOL_INSTALL_SELFTEST_BIN": str(self.bin), "VPN_BOT_PROTOCOL_INSTALL_REPO": str(ROOT),
            "VPN_BOT_PROTOCOL_INSTALL_SELFTEST_RELEASES": str(self.releases),
            "VPN_BOT_PROTOCOL_INSTALL_SELFTEST_PINS": json.dumps({ASSET: self.pin, HY2_ASSET: self.hy2_pin}),
            "VPN_BOT_PROTOCOL_INSTALL_SELFTEST_ARCH": "x86_64",
        })
        env.update(extra)
        return env

    def helper(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, "-I", str(HELPER), *args], capture_output=True, text=True,
                              env=self.base_env(**extra), timeout=120, check=False)

    def json_of(self, proc: subprocess.CompletedProcess[str]) -> dict[str, Any]:
        objs = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.startswith("{")]
        final = [o for o in objs if "event" not in o]
        assert final, f"no JSON report (exit {proc.returncode}): {proc.stdout}\n{proc.stderr}"
        return dict(final[-1])

    def plan(self, proto: str = "xray") -> dict[str, Any]:
        return self.json_of(self.helper("plan", proto, "--json"))

    def install(self, proto: str = "xray", **extra: str) -> tuple[int, dict[str, Any]]:
        sha = self.plan(proto)["sha256"]
        proc = self.helper("apply", proto, "--expect-plan", sha, "--json", **extra)
        return proc.returncode, self.json_of(proc)

    def uninstall(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = self.base_env(VPN_BOT_UNINSTALL_ROOT=str(self.root), VPN_BOT_UNINSTALL_SELFTEST_BIN=str(self.bin))
        return subprocess.run(["bash", str(UNINSTALL), *args], capture_output=True, text=True, env=env,
                              timeout=120, check=False)

    # ---------------------------------------------------------------- comparing
    def snapshot(self, *, skip: tuple[str, ...] = ()) -> dict[str, Any]:
        """Every path under the fake root: its mode and content (a link: its target), plus
        the owners sidecar and the stubs' package and unit state."""
        ignore = ("/var/backups/vpn-bot", "/var/lib/vpn-bot-protocol-install", "/var/log/vpn-bot-protocol-install.log",
                  "/run", "/.owners.json", *skip)
        files: dict[str, Any] = {}
        for p in sorted(self.root.rglob("*")):
            rel = "/" + p.relative_to(self.root).as_posix()
            if any(rel == i or rel.startswith(i + "/") for i in ignore):
                continue
            if p.is_symlink():
                files[rel] = ("link", os.readlink(p))
            elif p.is_dir():
                files[rel] = ("dir", oct(p.stat().st_mode & 0o7777))
            else:
                files[rel] = ("file", oct(p.stat().st_mode & 0o7777), hashlib.sha256(p.read_bytes()).hexdigest())
        # root:root is every path's owner unless the sidecar says otherwise.
        owners = {k: v for k, v in self.owners().items()
                  if v != "root:root" and k in files and not any(k == i or k.startswith(i + "/") for i in ignore)}
        units = {u: s for u, s in self.units().items() if s.get("active") == "active" or s.get("enabled") == "enabled"}
        return {"files": files, "owners": owners, "packages": self.packages(), "units": units}


def clean(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
