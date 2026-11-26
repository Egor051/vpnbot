"""Fixtures of the first setup's end-to-end job (tests/e2e/run_setup_e2e.sh). Not a test module.

Run as root on the CI VM BEFORE the network is closed:

  python3 setup_e2e_fixtures.py releases   the pinned Xray / Hysteria2 release files into the
                                           helper's release cache (/var/cache/vpn-bot-protocol-
                                           install, root 0700) — checked against the helper's
                                           pins here already
  python3 setup_e2e_fixtures.py acme       a test CA (trusted by the system store), the domain's
                                           pair it signed, an acme.sh home with the domain as the
                                           hand-made setup leaves it (tests/cert_fakes.py's fake
                                           acme.sh: the on-disk contract of acme.sh 3.1.1) — the
                                           setup's certificate step adopts it
  python3 setup_e2e_fixtures.py hosts IP   <domain> → IP in /etc/hosts (the name resolves here)
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = os.environ.get("E2E_DOMAIN", "vpn.e2e.test")
CACHE = Path("/var/cache/vpn-bot-protocol-install")
FAKE_HOME = Path("/var/lib/vpn-bot-e2e-acme")


def helper() -> object:
    loader = importlib.machinery.SourceFileLoader("pi_e2e", str(ROOT / "scripts" / "vpn-bot-protocol-install"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = mod
    loader.exec_module(mod)
    return mod


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 — fixed https URLs
        return bytes(response.read())


def releases() -> None:
    pi = helper()
    arch = os.uname().machine
    CACHE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(CACHE, 0o700)
    for base, assets, sums in ((pi.XRAY_RELEASE_BASE, pi.XRAY_ASSETS, None),  # type: ignore[attr-defined]
                               (pi.HY2_RELEASE_BASE, pi.HY2_ASSETS, pi.HY2_HASHES)):  # type: ignore[attr-defined]
        name, want = assets[arch]
        data = (CACHE / name).read_bytes() if (CACHE / name).is_file() else fetch(f"{base}/{name}")
        if hashlib.sha256(data).hexdigest() != want:
            raise SystemExit(f"{name}: not the pinned release")
        (CACHE / name).write_bytes(data)
        side = f"{name}.dgst" if sums is None else sums
        (CACHE / side).write_bytes(fetch(f"{base}/{side}"))
        print(f"release cache: {name} ({len(data)} bytes) + {side}")


def run(*argv: str) -> None:
    subprocess.run(argv, check=True, capture_output=True)


def acme() -> None:
    work = FAKE_HOME / "pki"
    work.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = work / "ca.key", work / "ca.crt"
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "30", "-subj", "/CN=vpnbot e2e CA")
    key, csr, crt = work / "leaf.key", work / "leaf.csr", work / "leaf.crt"
    run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
        "-out", str(csr), "-subj", f"/CN={DOMAIN}")
    ext = work / "ext.cnf"
    ext.write_text(f"subjectAltName=DNS:{DOMAIN}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(crt), "-days", "29", "-extfile", str(ext))
    Path("/usr/local/share/ca-certificates/vpnbot-e2e-ca.crt").write_bytes(ca_crt.read_bytes())
    run("update-ca-certificates")
    sys.path.insert(0, str(ROOT / "tests"))
    from cert_fakes import FAKE_ACME  # the on-disk contract of acme.sh 3.1.1

    (FAKE_HOME / "fake_acme.py").write_text(FAKE_ACME, encoding="utf-8")
    home = Path("/root/.acme.sh")
    ddir = home / f"{DOMAIN}_ecc"
    ddir.mkdir(parents=True, exist_ok=True)
    chain = crt.read_bytes() + ca_crt.read_bytes()
    (ddir / "fullchain.cer").write_bytes(chain)
    (ddir / f"{DOMAIN}.cer").write_bytes(crt.read_bytes())
    (ddir / "ca.cer").write_bytes(ca_crt.read_bytes())
    (ddir / f"{DOMAIN}.key").write_bytes(key.read_bytes())
    os.chmod(ddir / f"{DOMAIN}.key", 0o600)
    values = {
        "Le_Domain": DOMAIN, "Le_Alt": "no", "Le_Keylength": "ec-256", "Le_RealCertPath": "", "Le_RealCACertPath": "",
        "Le_RealKeyPath": "/etc/vpn-bot/tls/privkey.pem", "Le_RealFullChainPath": "/etc/vpn-bot/tls/fullchain.pem",
        "Le_ReloadCmd": "", "Le_NextRenewTimeStr": "2099-01-01T00:00:00Z",
    }
    (ddir / f"{DOMAIN}.conf").write_text("".join(f"{k}='{v}'\n" for k, v in values.items()), encoding="utf-8")
    wrapper = home / "acme.sh"
    wrapper.write_text(f'#!/bin/bash\nVER=3.1.1\nexport SD={FAKE_HOME}\nexec {sys.executable} {FAKE_HOME}/fake_acme.py "$@"\n')
    os.chmod(wrapper, 0o755)  # noqa: S103 — acme.sh itself is 0755 in its home
    # acme.sh's own renewal line in root's crontab (the self-check wants it).
    cron = Path("/var/spool/cron/crontabs/root")
    cron.parent.mkdir(parents=True, exist_ok=True)
    cron.write_text('7 0 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null\n')
    os.chmod(cron, 0o600)
    print(f"acme.sh home with {DOMAIN} (a pair of the e2e CA, trusted by the system store)")


def hosts(ip: str) -> None:
    with open("/etc/hosts", "a", encoding="utf-8") as fh:
        fh.write(f"{ip} {DOMAIN}\n")
    print(f"/etc/hosts: {DOMAIN} -> {ip}")


if __name__ == "__main__":
    verb = sys.argv[1] if len(sys.argv) > 1 else ""
    if verb == "releases":
        releases()
    elif verb == "acme":
        acme()
    elif verb == "hosts" and len(sys.argv) == 3:
        hosts(sys.argv[2])
    else:
        raise SystemExit(__doc__)
