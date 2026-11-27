"""A fake host for scripts/vpn-bot-site (and the wizard's «site» mode on the same root).

The host has the nginx vhost of the REALITY self-steal (127.0.0.1:8443, a docroot below
/var/www), a live site, .env with XRAY_SPIDER_X_POOL, the bot's database with xray keys, and
the bot's upload directory. The three commands the helper runs are stubs in ``bin/``
(STUB below): ``systemctl`` (nginx active; every call recorded), ``openssl`` (ALPN h2 and a
verified certificate) and ``curl`` (answers 200 over HTTP/2 for a file that exists in the
docroot, 404 otherwise — read from the fake root at the moment of the request). A file
``st/fail_<tool>`` makes that tool fail. No network, no real nginx, nothing outside the
temporary directory.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "vpn-bot-site"
DOMAIN = "site.example.com"
DOCROOT = "/var/www/anycastedge"
TOOLS = ("systemctl", "openssl", "curl")

VHOST = f"""# a hand-made self-steal vhost, as on the production host
server {{
    listen 127.0.0.1:8443 ssl http2;   # REALITY target
    server_name {DOMAIN};
    ssl_certificate     /etc/vpn-bot/tls/fullchain.pem;
    ssl_certificate_key /etc/vpn-bot/tls/privkey.pem;
    root {DOCROOT};
    index index.html;
    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""

HY2_CONFIG = """listen: :443
masquerade:
  type: proxy
  proxy:
    url: https://127.0.0.1:8443
    rewriteHost: false
    insecure: true
"""

STUB = r'''#!/usr/bin/env python3
import os, re, sys
from pathlib import Path

name = os.path.basename(sys.argv[0])
args = sys.argv[1:]
R = Path(os.environ["SITE_FAKE_ROOTFS"])
ST = Path(os.environ["SITE_FAKE_ST"])
with open(ST / "calls", "a", encoding="utf-8") as fh:
    fh.write(name + " " + " ".join(args) + "\n")
fail = (ST / f"fail_{name}").is_file()

if name == "systemctl":
    if fail:
        print("failed", file=sys.stderr); sys.exit(1)
    if args[:1] == ["is-active"]:
        print("active"); sys.exit(0)
    sys.exit(0)

if name == "openssl":
    if fail:
        print("verify error:num=10:certificate has expired\nNo ALPN negotiated"); sys.exit(1)
    print("CONNECTED(00000003)\nProtocol: TLSv1.3\nALPN protocol: h2\nVerification: OK")
    sys.exit(0)

if name == "curl":
    docroot = R / os.environ["SITE_FAKE_DOCROOT"].lstrip("/")
    urls = [a for a in args if a.startswith("https://")]
    for url in urls:
        path = re.sub(r"^https://[^/]+", "", url)
        rel = path.lstrip("/")
        if rel == "" or rel.endswith("/"):
            rel += "index.html"
        target = docroot / rel
        bad = (ST / "fail_curl_path").is_file() and (ST / "fail_curl_path").read_text().strip() == path
        if fail:
            print("000 0")
        elif target.is_file() and not bad:
            print("200 2")
        else:
            print("404 2")
    sys.exit(7 if fail else 0)
sys.exit(0)
'''


def tree_digest(files: Mapping[str, bytes]) -> str:
    """vpn-bot-site's Tree.digest of a tree of regular files."""
    h = hashlib.sha256()
    for rel in sorted(files):
        h.update(f"{rel}\0{hashlib.sha256(files[rel]).hexdigest()}\n".encode())
    return h.hexdigest()


def zip_bytes(files: Mapping[str, bytes], *, extra: list[zipfile.ZipInfo] | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        for info in extra or []:
            zf.writestr(info, b"")
    return buf.getvalue()


def tar_gz_bytes(files: Mapping[str, bytes], *, members: list[tuple[tarfile.TarInfo, bytes | None]] | None = None) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o777
            tar.addfile(info, io.BytesIO(data))
        for info, data in members or []:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    return gzip.compress(raw.getvalue())


SITE_V1 = {
    "index.html": b"<html><body>Anycast Edge</body></html>",
    "about.html": b"<html><body>About</body></html>",
    "blog/index.html": b"<html><body>Blog</body></html>",
    "css/style.css": b"body{margin:0}",
    "img/logo.png": b"\x89PNG\r\n\x1a\nfake",
}
SITE_V2 = {
    "index.html": b"<html><body>Anycast Edge v2</body></html>",
    "status.html": b"<html><body>Status</body></html>",
    "docs/index.html": b"<html><body>Docs</body></html>",
    "docs/api.html": b"<html><body>API</body></html>",
    "css/style.css": b"body{margin:0;color:#111}",
    "fonts/inter.woff2": b"wOF2fake",
}


class SiteHost:
    def __init__(self, tmp: Path, *, pool: str = "/,/about.html,/blog/", live: Mapping[str, bytes] | None = None) -> None:
        self.tmp = tmp
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.st = tmp / "st"
        for d in (self.root, self.bin, self.st):
            d.mkdir(parents=True, exist_ok=True)
        for tool in TOOLS:
            p = self.bin / tool
            p.write_text(STUB, encoding="utf-8")
            p.chmod(0o755)
        self.write("/etc/nginx/conf.d/anycastedge.conf", VHOST)
        self.write("/etc/hysteria/config.yaml", HY2_CONFIG)
        self.write("/opt/vpn-service/.env", f"BOT_TOKEN=1\nHYSTERIA2_SNI={DOMAIN}\nXRAY_SPIDER_X_POOL={pool}\nOTHER=x\n")
        self.file("/opt/vpn-service/.env").chmod(0o640)
        self.put_tree(DOCROOT, SITE_V1 if live is None else live)
        self.file("/run/vpn-bot/site").mkdir(parents=True, exist_ok=True)
        self.make_db()

    # ------------------------------------------------------------- the host
    def file(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def write(self, path: str, text: str) -> Path:
        p = self.file(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def put_tree(self, base: str, files: Mapping[str, bytes]) -> None:
        for rel, data in files.items():
            p = self.file(f"{base}/{rel}")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)

    def tree(self, base: str = DOCROOT) -> dict[str, bytes]:
        top = self.file(base)
        return {str(p.relative_to(top)): p.read_bytes() for p in sorted(top.rglob("*")) if p.is_file() and not p.is_symlink()}

    def env(self) -> str:
        return self.file("/opt/vpn-service/.env").read_text(encoding="utf-8")

    def pool(self) -> list[str]:
        for line in self.env().splitlines():
            if line.startswith("XRAY_SPIDER_X_POOL="):
                return [p for p in line.split("=", 1)[1].split(",") if p]
        return []

    def make_db(self) -> None:
        db = self.file("/opt/vpn-service/data/vpn.db")
        db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE vpn_keys (id INTEGER PRIMARY KEY, key_type TEXT, uuid TEXT, spider_x TEXT)")
        rows = [(1, "xray", "u-1", "/"), (2, "xray", "u-2", "/about.html"), (3, "xray", "u-3", "/blog/"),
                (4, "xray", "u-4", None), (5, "awg", None, None)]
        conn.executemany("INSERT INTO vpn_keys VALUES (?, ?, ?, ?)", rows)
        conn.commit()
        conn.close()

    def upload(self, data: bytes) -> str:
        """The bot's staging of a received document; the run's digest (16 hex)."""
        self.file("/run/vpn-bot/site/upload.bin").write_bytes(data)
        return hashlib.sha256(data).hexdigest()[:16]

    def fail(self, tool: str) -> None:
        (self.st / f"fail_{tool}").write_text("1")

    def calls(self) -> list[str]:
        p = self.st / "calls"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def state(self) -> dict[str, Any]:
        p = self.file("/var/lib/vpn-bot-site/state.json")
        return json.loads(p.read_text()) if p.exists() else {}

    def journal(self) -> dict[str, Any]:
        p = self.file("/var/lib/vpn-bot-site/journal.json")
        return json.loads(p.read_text()) if p.exists() else {}

    # ------------------------------------------------------------- running
    def base_env(self, **extra: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith(("VPN_BOT_", "SITE_FAKE_"))}
        env.update(VPN_BOT_SITE_SELFTEST="1", VPN_BOT_SITE_ROOT=str(self.root), VPN_BOT_SITE_SELFTEST_BIN=str(self.bin),
                   SITE_FAKE_ROOTFS=str(self.root), SITE_FAKE_ST=str(self.st), SITE_FAKE_DOCROOT=DOCROOT)
        env.update(extra)
        return env

    def helper(self, *args: str, **extra: str) -> tuple[int, dict[str, Any], str]:
        proc = subprocess.run([sys.executable, "-I", str(HELPER), *args, "--json"], capture_output=True, text=True,
                              env=self.base_env(**extra), timeout=120, check=False)
        objects = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.startswith("{")]
        result = next((o for o in reversed(objects) if "event" not in o), {})
        return proc.returncode, result, proc.stdout + proc.stderr

    def deploy(self, data: bytes, run_id: int = 1, **extra: str) -> tuple[int, dict[str, Any]]:
        """plan → apply → verify → commit, as the wizard's mode drives it."""
        digest = self.upload(data)
        rc, plan, _ = self.helper("plan", "deploy", "--run", str(run_id), "--digest", digest, **extra)
        if rc != 0:
            return rc, plan
        rc, result, _ = self.helper("apply", "--run", str(run_id), "--expect-plan", plan["sha256"], **extra)
        if rc != 0:
            return rc, result
        rc, result, _ = self.helper("verify", "--run", str(run_id), **extra)
        if rc != 0:
            self.helper("rollback", "--run", str(run_id), **extra)
            return rc, result
        return self.helper("commit", "--run", str(run_id), **extra)[:2]

    # ------------------------------------------------------------- the wizard's «site» mode
    def wizard(self, run_id: int, phase: str, **params: str) -> subprocess.CompletedProcess[str]:
        """The launcher's `run` of one phase (what the transient unit executes), the REAL
        mode helper calling the REAL vpn-bot-site through a wrapper in the stub directory."""
        wrapper = self.bin / "vpn-bot-site"
        if not wrapper.exists():
            wrapper.write_text(f"#!/bin/sh\nexec {sys.executable} -I {HELPER} \"$@\"\n", encoding="utf-8")
            wrapper.chmod(0o755)
        launcher = ROOT / "scripts" / "wizard" / "vpn-bot-wizard"
        args = [sys.executable, "-I", str(launcher), "run", "--mode", "site", "--run", str(run_id), "--phase", phase]
        for key, value in params.items():
            args += ["--param", f"{key}={value}"]
        env = self.base_env(VPN_BOT_WIZARD_SELFTEST="1", VPN_BOT_WIZARD_ROOT=str(self.root),
                            VPN_BOT_WIZARD_SELFTEST_BIN=str(self.bin), PATH=f"{self.bin}:{os.environ.get('PATH', '')}")
        return subprocess.run(args, capture_output=True, text=True, env=env, timeout=240, check=False)

    def events(self, run_id: int) -> list[dict[str, Any]]:
        path = self.file(f"/var/lib/vpn-bot-wizard/{run_id}.status")
        return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()] if path.exists() else []

    def outcome(self, run_id: int) -> str:
        done = [e for e in self.events(run_id) if e["event"] == "finished"]
        assert done, self.events(run_id)
        return str(done[-1]["outcome"])

    def revert(self, run_id: int, **extra: str) -> tuple[int, dict[str, Any]]:
        rc, plan, _ = self.helper("plan", "revert", "--run", str(run_id), **extra)
        if rc != 0:
            return rc, plan
        rc, result, _ = self.helper("apply", "--run", str(run_id), "--expect-plan", plan["sha256"], **extra)
        if rc != 0:
            return rc, result
        rc, result, _ = self.helper("verify", "--run", str(run_id), **extra)
        if rc != 0:
            self.helper("rollback", "--run", str(run_id), **extra)
            return rc, result
        return self.helper("commit", "--run", str(run_id), **extra)[:2]
