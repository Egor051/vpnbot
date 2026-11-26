"""A fake host for scripts/vpn-bot-cert and the wizard's «cert» mode (no network, no root).

* real certificates: an EC key and a self-signed certificate per call, made by the
  real ``openssl`` (the helper's own key-matches-certificate and SAN checks run on them);
* a fake acme.sh (Python) that keeps acme.sh's on-disk contract: the domain directory
  ``<name>_ecc/`` with ``<name>.conf`` (``KEY='value'``, the reloadcmd base64-wrapped),
  ``fullchain.cer`` and ``<name>.key``; ``--install-cert`` saves every Le_Real* path and
  runs the reloadcmd from inside the domain directory with ``Le_Domain`` exported —
  exactly what acme.sh 3.1.1 does — and ``--issue`` / ``--renew`` take the next pair from
  ``$SD/next``. It logs argv and the fingerprint of CF_Token it was given, never the token;
* ``systemctl`` / ``nginx`` stubs driven by files in ``$SD``.

VPN_BOT_CERT_SELFTEST=1 re-roots every path under the fake root and refuses any command
that is not a stub here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpn-bot-cert"
OPENSSL = shutil.which("openssl")
TOKEN = "cfTOKEN_0123456789abcdefghijklmnopqrstuv"
ZONE_ID = "0123456789abcdef0123456789abcdef"
DOMAIN = "example.net"
ZONE = DOMAIN

FAKE_ACME = r'''#!/usr/bin/env python3
"""A fake acme.sh: the on-disk contract of acme.sh 3.1.1, nothing else."""
import base64, hashlib, json, os, shutil, subprocess, sys
from pathlib import Path

argv = sys.argv[1:]
sd = Path(os.environ["SD"])
with open(sd / "acme.log", "a") as fh:
    tok = os.environ.get("CF_Token", "")
    fh.write(json.dumps({"argv": argv, "cf_token_fp": hashlib.sha256(tok.encode()).hexdigest()[:8] if tok else None,
                         "cf_zone": os.environ.get("CF_Zone_ID"), "nested": bool(os.environ.get("VPN_BOT_CERT_NESTED"))}) + "\n")
if (sd / "acme-fail").exists():
    print("acme.sh: simulated failure"); sys.exit(1)

def opt(name, default=None):
    return argv[argv.index(name) + 1] if name in argv else default

home = Path(opt("--home"))
domains = [argv[i + 1] for i, a in enumerate(argv) if a == "-d"]
B64S, B64E = "__ACME_BASE64__START_", "__ACME_BASE64__END_"

def conf_path(d, ecc):
    return home / (d + ("_ecc" if ecc else "")) / f"{d}.conf"

def read_conf(path):
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("'")
    return out

def save(path, key, value, b64=False):
    if value and b64:
        value = B64S + base64.b64encode(value.encode()).decode() + B64E
    lines = [l for l in path.read_text().splitlines() if not l.startswith(key + "=")] if path.exists() else []
    lines.append(f"{key}='{value}'")
    path.write_text("\n".join(lines) + "\n")

def decode(v):
    return base64.b64decode(v[len(B64S):-len(B64E)]).decode() if v.startswith(B64S) else v

def reload(d, ecc, cmd):
    if not cmd:
        return 0
    real = os.environ["FAKE_CERT_HELPER"]
    cmd = cmd.replace("/usr/local/sbin/vpn-bot-cert", real)
    env = dict(os.environ, Le_Domain=d)
    return subprocess.run(cmd, shell=True, cwd=str(conf_path(d, ecc).parent), env=env).returncode

def take_next(d, ecc):
    ddir = conf_path(d, ecc).parent
    ddir.mkdir(parents=True, exist_ok=True)
    shutil.copy(sd / "next" / "fullchain.cer", ddir / "fullchain.cer")
    shutil.copy(sd / "next" / "key", ddir / f"{d}.key")

def log_next(d, ecc, what):
    path = conf_path(d, ecc)
    if path.exists():
        with open(sd / "acme.log", "a") as fh:
            fh.write(json.dumps({what: d, "next_renew_at_call": read_conf(path).get("Le_NextRenewTime")}) + "\n")

def renewed(d, ecc):
    # acme.sh writes the next renewal time after a certificate was issued.
    import time
    save(conf_path(d, ecc), "Le_NextRenewTime", str(int(time.time()) + 60 * 86400))

if "--set-default-ca" in argv:
    sys.exit(0)
if "--install-cert" in argv:
    d, ecc = domains[0], "--ecc" in argv
    path = conf_path(d, ecc)
    if not path.exists():
        print("not a cert name"); sys.exit(1)
    log_next(d, ecc, "install_cert")
    for key, flag in (("Le_RealCertPath", "--cert-file"), ("Le_RealCACertPath", "--ca-file"),
                      ("Le_RealKeyPath", "--key-file"), ("Le_RealFullChainPath", "--fullchain-file")):
        save(path, key, opt(flag, ""))
    save(path, "Le_ReloadCmd", opt("--reloadcmd", ""), b64=True)
    rc = reload(d, ecc, opt("--reloadcmd", ""))
    sys.exit(0 if rc == 0 else 1)
if "--issue" in argv:
    d = domains[0]
    ecc = opt("--keylength", "ec-256").startswith("ec")
    log_next(d, ecc, "issue")
    take_next(d, ecc)
    path = conf_path(d, ecc)
    save(path, "Le_Domain", d)
    save(path, "Le_Alt", ",".join(domains[1:]) or "no")
    save(path, "Le_Keylength", opt("--keylength", "ec-256"))
    save(path, "Le_API", "https://acme-v02.api.letsencrypt.org/directory")
    if os.environ.get("CF_Token") and os.environ.get("CF_Zone_ID"):
        save(path, "CF_Token", os.environ["CF_Token"])
        save(path, "CF_Zone_ID", os.environ["CF_Zone_ID"])
    renewed(d, ecc)
    sys.exit(0)
if "--renew" in argv:
    d, ecc = domains[0], "--ecc" in argv
    path = conf_path(d, ecc)
    conf = read_conf(path)
    with open(sd / "acme.log", "a") as fh:
        t = conf.get("CF_Token", "")
        fh.write(json.dumps({"renew_with_conf_token_fp": hashlib.sha256(t.encode()).hexdigest()[:8] if t else None,
                             "renew_zone": conf.get("CF_Zone_ID")}) + "\n")
    log_next(d, ecc, "renew")
    if (sd / "swap-token").exists():
        # The superadmin replaces the bot's token while acme.sh renews.
        token_file = Path(str(home)[: -len("/root/.acme.sh")]) / "etc/vpn-bot/dns_failover/cloudflare_token"
        token_file.write_text((sd / "swap-token").read_text())
    take_next(d, ecc)
    renewed(d, ecc)
    sys.exit(0 if reload(d, ecc, decode(conf.get("Le_ReloadCmd", ""))) == 0 else 1)
print("fake acme.sh: unsupported", argv); sys.exit(2)
'''

SYSTEMCTL = r'''#!/bin/bash
printf "%s\n" "systemctl $*" >> "$CALLS"
args=("$@")
verb="$1"; unit="${args[-1]}"
case "$verb" in
  cat) grep -qx -- "$unit" "$SD/units" 2>/dev/null; exit $? ;;
  is-active) [[ -f "$SD/active/$unit" ]]; exit $? ;;
  restart|reload|try-restart)
    # What acme.sh's cron would see at this moment (the domain's next renewal time).
    grep -h "^Le_NextRenewTime=" "$SD"/../root/root/.acme.sh/*/*.conf >> "$SD/next-during-action" 2>/dev/null
    [[ -f "$SD/fail-$verb-$unit" ]] && { echo "Job for $unit failed"; exit 1; }
    [[ -f "$SD/fail-once-$verb-$unit" ]] && { rm -f "$SD/fail-once-$verb-$unit"; echo "Job for $unit failed"; exit 1; }
    # As systemd: a stopped unit cannot be reloaded.
    [[ "$verb" == reload && ! -f "$SD/active/$unit" ]] && { echo "$unit.service is not active, cannot reload."; exit 1; }
    if [[ -f "$SD/dies-$unit" ]]; then rm -f "$SD/active/$unit"; exit 0; fi
    [[ "$verb" == restart ]] && { mkdir -p "$SD/active"; touch "$SD/active/$unit"; }
    exit 0 ;;
esac
exit 0
'''

NGINX = r'''#!/bin/bash
printf "%s\n" "nginx $*" >> "$CALLS"
[[ -f "$SD/nginx-t-fails" ]] && { echo "nginx: [emerg] cannot load certificate"; exit 1; }
exit 0
'''

PASS_THROUGH = '#!/bin/bash\nprintf "%s\\n" "$(basename "$0") $*" >> "$CALLS"\nexec {real} "$@"\n'


def make_pair(directory: Path, names: list[str], *, days: int = 90) -> tuple[Path, Path]:
    """A fresh EC key and a self-signed certificate for *names* (real openssl)."""
    assert OPENSSL is not None
    directory.mkdir(parents=True, exist_ok=True)
    key, cert = directory / "key", directory / "fullchain.cer"
    san = ",".join(f"DNS:{n}" for n in names)
    subprocess.run(
        [OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", str(days), "-subj", f"/CN={names[0]}",
         "-addext", f"subjectAltName={san}"],
        check=True, capture_output=True,
    )
    return cert, key


def b64(value: str) -> str:
    return "__ACME_BASE64__START_" + base64.b64encode(value.encode()).decode() + "__ACME_BASE64__END_"


class CertHost:
    """The fake root, the stubs and the call log of one test."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.sd = tmp / "sd"
        self.calls = tmp / "calls.log"
        for d in (self.root, self.bin, self.sd, self.sd / "active"):
            d.mkdir(parents=True, exist_ok=True)
        self.calls.write_text("", encoding="utf-8")
        self._stub("systemctl", SYSTEMCTL)
        self._stub("nginx", NGINX)
        assert OPENSSL is not None
        self._stub("openssl", PASS_THROUGH.format(real=OPENSSL))
        self._stub("sh", PASS_THROUGH.format(real="/bin/sh"))
        self.units("hysteria-server", "nginx", "vpn-bot-subscription")
        self.active("hysteria-server", "nginx", "vpn-bot-subscription")
        app = self.file("/opt/vpn-service")
        app.mkdir(parents=True)
        self.write("/opt/vpn-service/.env", "HYSTERIA2_SNI=example.net\nSUBSCRIPTION_TLS_CERT=/etc/vpn-bot/tls/fullchain.pem\n"
                   "SUBSCRIPTION_TLS_KEY=/etc/vpn-bot/tls/privkey.pem\n")
        self.write("/etc/hysteria/config.yaml", "listen: :443\ntls:\n  cert: /etc/hysteria/cert.pem\n  key: /etc/hysteria/key.pem\n")
        self.write("/var/spool/cron/crontabs/root", '7 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null\n')

    # ── building the host ──────────────────────────────────────────────────
    def _stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def file(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def write(self, path: str, text: str | bytes, mode: int = 0o644, owner: tuple[str, str] | None = None) -> Path:
        target = self.file(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            target.write_bytes(text)
        else:
            target.write_text(text, encoding="utf-8")
        target.chmod(mode)
        if owner is not None:
            self.set_owner(path, *owner)
        return target

    def set_owner(self, path: str, user: str, group: str) -> None:
        sidecar = self.root / ".vpn-bot-cert-owners.json"
        data = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.exists() else {}
        data[path] = [user, group]
        sidecar.write_text(json.dumps(data), encoding="utf-8")

    def owner(self, path: str) -> tuple[str, str]:
        sidecar = self.root / ".vpn-bot-cert-owners.json"
        data = json.loads(sidecar.read_text(encoding="utf-8")) if sidecar.exists() else {}
        pair = data.get(path, ["root", "root"])
        return pair[0], pair[1]

    def mode(self, path: str) -> int:
        return self.file(path).stat().st_mode & 0o7777

    def units(self, *names: str) -> None:
        (self.sd / "units").write_text("".join(f"{n}\n" for n in names), encoding="utf-8")

    def active(self, *names: str) -> None:
        for name in names:
            (self.sd / "active" / name).write_text("", encoding="utf-8")

    def flag(self, name: str) -> None:
        (self.sd / name).write_text("", encoding="utf-8")

    def install_acme(self) -> Path:
        """acme.sh at its default home: a shell wrapper (``VER=`` line, as acme.sh has it)
        around the fake."""
        fake = self.sd / "fake_acme.py"
        fake.write_text(FAKE_ACME, encoding="utf-8")
        return self.write("/root/.acme.sh/acme.sh", f'#!/bin/bash\nVER=3.1.1\nexec {sys.executable} {fake} "$@"\n', mode=0o755)

    def acme_domain(self, name: str = DOMAIN, *, alt: list[str] | None = None, conf: dict[str, str] | None = None,
                    days: int = 60, ecc: bool = True) -> tuple[bytes, bytes]:
        """A domain acme.sh issued: its pair and its conf (the prod shape by default)."""
        ddir = self.file(f"/root/.acme.sh/{name}{'_ecc' if ecc else ''}")
        cert, key = make_pair(self.tmp / f"pair-{name}-{days}", [name, *(alt or [])], days=days)
        ddir.mkdir(parents=True, exist_ok=True)
        shutil.copy(cert, ddir / "fullchain.cer")
        shutil.copy(cert, ddir / f"{name}.cer")
        shutil.copy(key, ddir / f"{name}.key")
        values = {
            "Le_Domain": name, "Le_Alt": ",".join(alt or []) or "no", "Le_Keylength": "ec-256" if ecc else "2048",
            "Le_RealCertPath": "", "Le_RealCACertPath": "", "Le_RealKeyPath": "/etc/vpn-bot/tls/privkey.pem",
            "Le_RealFullChainPath": "/etc/vpn-bot/tls/fullchain.pem", "Le_ReloadCmd": "",
            "Le_NextRenewTimeStr": "2027-01-01T00:00:00Z",
        }
        values.update(conf or {})
        (ddir / f"{name}.conf").write_text("".join(f"{k}='{v}'\n" for k, v in values.items()), encoding="utf-8")
        return (ddir / "fullchain.cer").read_bytes(), (ddir / f"{name}.key").read_bytes()

    def next_pair(self, names: list[str], days: int = 90) -> tuple[bytes, bytes]:
        cert, key = make_pair(self.sd / "next", names, days=days)
        return cert.read_bytes(), key.read_bytes()

    def lay_out(self, fullchain: bytes, key: bytes, *, hysteria: tuple[bytes, bytes] | None = None) -> None:
        """What the hand-made setup left: acme.sh's copy in /etc/vpn-bot/tls, the old hook's in /etc/hysteria."""
        self.write("/etc/vpn-bot/tls/fullchain.pem", fullchain, 0o640, ("root", "vpn-bot"))
        self.write("/etc/vpn-bot/tls/privkey.pem", key, 0o640, ("root", "vpn-bot"))
        hc, hk = hysteria or (fullchain, key)
        self.write("/etc/hysteria/cert.pem", hc, 0o644, ("hysteria", "hysteria"))
        self.write("/etc/hysteria/key.pem", hk, 0o600, ("hysteria", "hysteria"))

    def token(self, value: str = TOKEN, mode: int = 0o600, owner: tuple[str, str] = ("vpn-bot", "vpn-bot")) -> None:
        self.write("/etc/vpn-bot/dns_failover/cloudflare_token", value + "\n", mode, owner)

    # ── running ────────────────────────────────────────────────────────────
    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "VPN_BOT_CERT_SELFTEST": "1",
            "VPN_BOT_CERT_SELFTEST_BIN": str(self.bin),
            "VPN_BOT_CERT_SELFTEST_SETTLE": "0",
            "CALLS": str(self.calls),
            "SD": str(self.sd),
            "FAKE_CERT_HELPER": f"{sys.executable} -I {HELPER} --root {self.root}",
            # What Cloudflare answers for GET /zones?name= with the bot's token.
            "VPN_BOT_CERT_SELFTEST_ZONES": json.dumps({ZONE: ZONE_ID}),
            "TZ": "UTC",
            **extra,
        }

    def cert(self, *args: str, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(HELPER), "--root", str(self.root), *args],
            capture_output=True, text=True, env=self.env(**extra), timeout=120, check=False,
        )

    def json(self, *args: str, **extra: str) -> tuple[int, dict[str, Any]]:
        proc = self.cert(*args, "--json", **extra)
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
        assert lines, proc.stdout + proc.stderr
        return proc.returncode, json.loads(lines[-1])

    def calls_of(self, name: str) -> list[str]:
        return [ln for ln in self.calls.read_text(encoding="utf-8").splitlines() if ln.split(" ", 1)[0] == name]

    def actions(self) -> list[str]:
        """systemctl calls that change something (not cat / is-active)."""
        return [ln for ln in self.calls_of("systemctl") if ln.split(" ")[1] in ("restart", "reload", "try-restart")]

    def reset_calls(self) -> None:
        self.calls.write_text("", encoding="utf-8")

    def acme_log(self) -> list[dict[str, Any]]:
        path = self.sd / "acme.log"
        if not path.exists():
            return []
        return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def conf(self, name: str = DOMAIN, ecc: bool = True) -> dict[str, str]:
        text = self.file(f"/root/.acme.sh/{name}{'_ecc' if ecc else ''}/{name}.conf").read_text(encoding="utf-8")
        out = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                out[key] = value.strip().strip("'")
        return out


def fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]
